// Package probe defines the shared network-probe harness for cryptoscan's
// Phase 2 `probe` command (DESIGN.md §1 "Network probe contract"). It is the
// contract that the concrete TLS and SSH probers implement and that the CLI /
// eval integration drives; this package deliberately contains NO TLS or SSH
// wire logic of its own.
//
// The harness provides four things:
//
//   - Target and its parsers (ParseTarget, ParseTargets, ParseTargetFile), which
//     turn user-supplied strings into explicit host:port endpoints. Parsing is
//     deterministic and performs no DNS resolution (resolution happens at dial
//     time). Explicit targets only: a CIDR block or address range is an error,
//     never expanded (DESIGN.md: no subnet expansion, no discovery, no port
//     scanning).
//   - Finding, the projection type returned to downstream eval/report code. It
//     is an alias of scan.Finding so filesystem and network findings are
//     uniform (see the type doc for the reuse rationale).
//   - The Prober interface plus a deterministic registry mirroring internal/scan.
//   - Run, a bounded-concurrency, rate-limited, per-target-timeout runner that
//     drives a set of probers over a set of targets, aggregating findings and
//     per-target errors. A failed or unreachable target is a recorded error,
//     never a panic and never a cause to abort the batch.
//
// The package depends only on the standard library, internal/graph, and
// internal/scan (for the Finding alias). It never panics: a panicking prober is
// recovered and reported as that target's error.
package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cryptoscan/cryptoscan/internal/graph"
	"github.com/cryptoscan/cryptoscan/internal/scan"
)

// Finding is the projection type a prober returns for each proven network
// observation. It is a type alias of scan.Finding, not a redefinition, so that a
// certificate observed at a TLS endpoint and one found on disk flow through the
// exact same downstream code (eval matcher, CBOM/report emitters) with identical
// shape.
//
// Reuse-vs-redefine decision: scan.Finding is a clean standalone struct (Class,
// Path, Alias, Attrs, Provenance) whose only dependency is internal/graph, which
// this package already needs. It has no coupling to scan's scanner registry (a
// separate, unexported var), so importing scan pulls in nothing unwanted. An
// alias — rather than a structurally identical redefinition — means the two are
// the *same* type: no conversion, and downstream code written against
// scan.Finding accepts probe.Finding verbatim.
//
// For probe findings: Class is one of ClassTLSEndpoint / ClassSSHEndpoint, Path
// is "host:port", and each Provenance record uses graph.SourceProbe with
// Location set to the host:port and Detail describing what was observed on the
// wire (DESIGN.md §1 network probe contract).
type Finding = scan.Finding

// Probe finding classes (DESIGN.md §1). These match the manifest/asset
// vocabulary so eval can score probe findings uniformly.
const (
	// ClassTLSEndpoint is a TLS listener observed via handshake enumeration.
	ClassTLSEndpoint = "tls_endpoint"
	// ClassSSHEndpoint is an SSH listener observed via its wire preamble.
	ClassSSHEndpoint = "ssh_endpoint"
)

// Runner defaults (DESIGN.md §1: 5s per-connection timeout, bounded concurrency
// default 8, a global rate limit; all flag-overridable by the CLI).
const (
	// DefaultConcurrency bounds simultaneous probe calls when RunOptions leaves
	// Concurrency at 0.
	DefaultConcurrency = 8
	// DefaultTimeout is the per-target probe deadline when RunOptions leaves
	// Timeout at 0.
	DefaultTimeout = 5 * time.Second
)

// --- Target ---

// Target is a single explicitly-listed endpoint to probe. Host is a hostname or
// IP literal (IPv6 without brackets); Port is the TCP port; Raw is the original,
// trimmed input string for diagnostics and provenance. No DNS resolution is
// performed at parse time — Host is carried verbatim to the dialer.
type Target struct {
	Host string
	Port int
	Raw  string
}

// Addr returns the dial address "host:port", bracketing IPv6 hosts via
// net.JoinHostPort. It is the canonical Path/Provenance-Location value for a
// finding at this target.
func (t Target) Addr() string {
	return net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
}

// String returns Addr for readable diagnostics.
func (t Target) String() string { return t.Addr() }

// ipv4RangePrefix matches a target that begins with an IPv4 literal immediately
// followed by '-', i.e. an address range such as "10.0.0.1-10.0.0.9" or
// "10.0.0.1-9". It cannot match a hostname (a hostname cannot start with four
// dot-separated numeric labels followed by a dash), so range rejection never
// snags a legitimate domain like "1-800-flowers.com".
var ipv4RangePrefix = regexp.MustCompile(`^\d{1,3}(\.\d{1,3}){3}-`)

// ParseTarget parses a single target string into a Target. It accepts:
//
//	host:port          e.g. example.com:443
//	host               bare host, Port left 0 (unspecified — see below)
//	1.2.3.4[:port]     IPv4 literal, optional port
//	[::1]:port         bracketed IPv6 with port
//	[::1]              bracketed IPv6, no port
//	::1                bare IPv6 literal (a full address; brackets required to
//	                   add a port, since a trailing ":port" is ambiguous)
//
// When no port is present the returned Target has Port == 0, meaning
// "unspecified": ParseTargets and ParseTargetFile fill it with their defaultPort.
// A standalone ParseTarget caller that needs a concrete port should supply one
// in the string or apply a default itself. An explicitly-written port that is
// out of range [1,65535] is an error.
//
// It rejects the empty string, a whitespace-bearing or empty host, and — per the
// explicit-targets-only principle — any CIDR block ("/") or IPv4 range ("a-b"):
// those return an error instructing the caller to list targets explicitly. No
// DNS resolution is performed.
func ParseTarget(s string) (Target, error) {
	raw := strings.TrimSpace(s)
	if raw == "" {
		return Target{}, errors.New("probe: empty target")
	}
	if strings.Contains(raw, "/") {
		return Target{}, fmt.Errorf("probe: %q looks like a CIDR block or URL; targets must be explicit host:port endpoints (no subnet expansion)", raw)
	}
	if ipv4RangePrefix.MatchString(raw) {
		return Target{}, fmt.Errorf("probe: %q looks like an address range; targets must be explicit host:port endpoints (no range expansion)", raw)
	}

	host, port, hasPort, err := splitHostMaybePort(raw)
	if err != nil {
		return Target{}, err
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return Target{}, fmt.Errorf("probe: %q has an empty host", raw)
	}
	if strings.ContainsAny(host, " \t\r\n") {
		return Target{}, fmt.Errorf("probe: host %q in %q contains whitespace", host, raw)
	}
	if hasPort && (port < 1 || port > 65535) {
		return Target{}, fmt.Errorf("probe: port %d in %q out of range [1,65535]", port, raw)
	}
	if !hasPort {
		port = 0
	}
	return Target{Host: host, Port: port, Raw: raw}, nil
}

// splitHostMaybePort separates a target into host and optional port, handling
// bare IP literals and bracketed IPv6. hasPort reports whether an explicit port
// was present.
func splitHostMaybePort(s string) (host string, port int, hasPort bool, err error) {
	// A full IP literal with no port (covers "::1", "2001:db8::1", "1.2.3.4").
	if ip := net.ParseIP(s); ip != nil {
		return s, 0, false, nil
	}
	// Bracketed IPv6 with no port: "[::1]".
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		inner := s[1 : len(s)-1]
		if ip := net.ParseIP(inner); ip == nil || !strings.Contains(inner, ":") {
			return "", 0, false, fmt.Errorf("probe: %q is not a valid bracketed IPv6 address", s)
		}
		return inner, 0, false, nil
	}
	// host:port, [ipv6]:port, or a bare host with no colon.
	h, p, splitErr := net.SplitHostPort(s)
	if splitErr != nil {
		// SplitHostPort fails on a bare host ("missing port"); accept it only
		// when there is genuinely no port separator. A colon-bearing string
		// that fails here (e.g. an unbracketed IPv6 with a trailing port) is
		// malformed.
		if !strings.Contains(s, ":") {
			return s, 0, false, nil
		}
		return "", 0, false, fmt.Errorf("probe: cannot parse target %q: %w", s, splitErr)
	}
	if p == "" {
		return "", 0, false, fmt.Errorf("probe: target %q has an empty port", s)
	}
	pn, convErr := strconv.Atoi(p)
	if convErr != nil {
		return "", 0, false, fmt.Errorf("probe: port %q in %q is not a number: %w", p, s, convErr)
	}
	return h, pn, true, nil
}

// validatePort reports an error if p is not a usable TCP port.
func validatePort(p int, what string) error {
	if p < 1 || p > 65535 {
		return fmt.Errorf("probe: %s %d out of range [1,65535]", what, p)
	}
	return nil
}

// withDefaultPort returns t with its port set to defaultPort if unspecified.
func (t Target) withDefaultPort(defaultPort int) Target {
	if t.Port == 0 {
		t.Port = defaultPort
	}
	return t
}

// ParseTargets parses each argument via ParseTarget and fills any unspecified
// port with defaultPort, which must itself be in [1,65535]. The result preserves
// argument order; duplicates are not collapsed. An error on any argument aborts
// with that argument's error wrapped.
func ParseTargets(args []string, defaultPort int) ([]Target, error) {
	if err := validatePort(defaultPort, "default port"); err != nil {
		return nil, err
	}
	out := make([]Target, 0, len(args))
	for _, a := range args {
		t, err := ParseTarget(a)
		if err != nil {
			return nil, err
		}
		out = append(out, t.withDefaultPort(defaultPort))
	}
	return out, nil
}

// ParseTargetFile reads a newline-delimited target list from path (the
// --targets-file use case). Blank lines and lines whose first non-space rune is
// '#' are ignored; every other line is parsed via ParseTarget and any
// unspecified port is filled with defaultPort (which must be in [1,65535]). A
// parse error names the 1-based line number.
//
// Signature note: unlike the terse form sketched in DESIGN, this takes a
// defaultPort so file-listed bare hosts resolve to a concrete port exactly as
// ParseTargets does — keeping the two entry points consistent.
func ParseTargetFile(path string, defaultPort int) ([]Target, error) {
	if err := validatePort(defaultPort, "default port"); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("probe: reading targets file %q: %w", path, err)
	}
	var out []Target
	lines := strings.Split(string(data), "\n")
	for i, ln := range lines {
		trimmed := strings.TrimSpace(ln)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		t, perr := ParseTarget(trimmed)
		if perr != nil {
			return nil, fmt.Errorf("probe: targets file %q line %d: %w", path, i+1, perr)
		}
		out = append(out, t.withDefaultPort(defaultPort))
	}
	return out, nil
}

// --- Prober + registry ---

// Prober probes a single Target and records what it observes into the graph.
// Implementations live in sibling packages (internal/probe/tls, .../ssh); this
// package only defines the contract.
type Prober interface {
	// Scheme is a short, stable identifier for the protocol probed: "tls" or
	// "ssh". It orders probers deterministically and keys the registry.
	Scheme() string
	// Probe performs ONE target. It populates g with the Endpoint node and the
	// edges described in DESIGN.md §1 (terminates_tls_for, issued_by,
	// signs_with, ...) and returns the findings it proved. ctx carries the
	// per-target timeout/cancellation; an unreachable target must be returned as
	// an error, not a panic. The passed graph is a per-call scratch graph owned
	// by the caller, so Probe need not synchronize its writes (see Run).
	Probe(ctx context.Context, t Target, g *graph.Graph) ([]Finding, error)
}

// registry holds the process-wide set of probers keyed by Scheme. Registration
// typically happens from package init functions, so it is mutex-guarded, exactly
// as internal/scan does.
var (
	regMu    sync.Mutex
	registry = map[string]Prober{}
)

// Register adds p to the process-wide registry keyed by p.Scheme(). A nil prober
// or one with an empty scheme is ignored. Re-registering a scheme replaces the
// prior prober. All returns registered probers in scheme-sorted order.
func Register(p Prober) {
	if p == nil || p.Scheme() == "" {
		return
	}
	regMu.Lock()
	defer regMu.Unlock()
	registry[p.Scheme()] = p
}

// All returns every registered prober sorted by Scheme, for deterministic run
// order.
func All() []Prober {
	regMu.Lock()
	defer regMu.Unlock()
	out := make([]Prober, 0, len(registry))
	for _, p := range registry {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Scheme() < out[j].Scheme() })
	return out
}

// --- Runner ---

// RunOptions configures a Run. Zero values select documented defaults.
type RunOptions struct {
	// Timeout is the per-target probe deadline; 0 selects DefaultTimeout. It is
	// applied via context.WithTimeout around each Probe call.
	Timeout time.Duration
	// Concurrency bounds the number of Probe calls in flight; 0 selects
	// DefaultConcurrency. Negative is treated as the default.
	Concurrency int
	// RatePerSec caps the aggregate rate of Probe calls across all workers, in
	// calls per second; 0 (or negative) means no artificial limit beyond
	// Concurrency. The limiter spaces calls at 1/RatePerSec.
	RatePerSec float64
	// Probers is the set to run against every target. If empty, All() (the
	// process registry) is used.
	Probers []Prober
}

// TargetError records that probing a specific target failed. It wraps the
// underlying error (%w via Unwrap) so callers can inspect causes such as
// context.DeadlineExceeded.
type TargetError struct {
	Target Target
	// Scheme is the prober whose Probe call failed.
	Scheme string
	Err    error
}

// Error implements error.
func (e TargetError) Error() string {
	return fmt.Sprintf("probe %s (%s): %v", e.Target.Addr(), e.Scheme, e.Err)
}

// Unwrap exposes the underlying cause.
func (e TargetError) Unwrap() error { return e.Err }

// Result aggregates a Run. Findings is the union of every prober's findings,
// sorted by (Class, Path); Errors is one entry per failed (target, prober) pair,
// sorted by target address then scheme. Both orderings are deterministic so
// output and golden tests are stable.
type Result struct {
	Findings []Finding
	Errors   []TargetError
}

// job is one unit of work: run one prober against one target.
type job struct {
	prober Prober
	target Target
}

// Run drives every prober in opts.Probers over every target with bounded
// concurrency, a global rate limit, and a per-target timeout, aggregating the
// results into a Result. It returns a non-nil error only for a setup problem
// (nil graph, no probers, invalid options); a failed, unreachable, or panicking
// individual target is captured in Result.Errors and never aborts the batch.
//
// Graph-safety approach: internal/graph is explicitly not safe for concurrent
// use, and the Prober signature hands each Probe a *graph.Graph to write. Rather
// than serialize all probes (which would defeat concurrency) or lock a graph the
// prober writes to out of band, Run gives each Probe call its OWN fresh scratch
// graph, then merges that scratch into the shared graph g under a single mutex
// after Probe returns. Merging replays the scratch's nodes through
// g.UpsertNode and its edges through g.AddEdge, so entity resolution and
// provenance-union semantics are preserved across probers and targets — a cert
// seen at two endpoints still resolves to one node in g.
func Run(ctx context.Context, targets []Target, g *graph.Graph, opts RunOptions) (Result, error) {
	if g == nil {
		return Result{}, errors.New("probe: Run requires a non-nil graph")
	}
	probers := opts.Probers
	if len(probers) == 0 {
		probers = All()
	}
	if len(probers) == 0 {
		return Result{}, errors.New("probe: no probers configured")
	}
	if len(targets) == 0 {
		return Result{}, nil
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = DefaultConcurrency
	}
	limiter := newRateLimiter(opts.RatePerSec)

	// Build the work list deterministically (target-major, prober-minor).
	jobs := make(chan job)
	go func() {
		defer close(jobs)
		for _, t := range targets {
			for _, p := range probers {
				select {
				case <-ctx.Done():
					return
				case jobs <- job{prober: p, target: t}:
				}
			}
		}
	}()

	var (
		graphMu sync.Mutex // serializes writes into the shared graph g
		resMu   sync.Mutex // guards the accumulators below
		res     Result
		wg      sync.WaitGroup
	)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for jb := range jobs {
				// Rate limit before every dial; honour cancellation while waiting.
				if err := limiter.wait(ctx); err != nil {
					resMu.Lock()
					res.Errors = append(res.Errors, TargetError{Target: jb.target, Scheme: jb.prober.Scheme(), Err: err})
					resMu.Unlock()
					continue
				}

				pctx, cancel := context.WithTimeout(ctx, timeout)
				scratch := graph.New()
				findings, err := safeProbe(pctx, jb.prober, jb.target, scratch)
				cancel()

				// Merge the scratch graph into the shared graph under a mutex.
				graphMu.Lock()
				mergeGraph(g, scratch)
				graphMu.Unlock()

				resMu.Lock()
				if err != nil {
					res.Errors = append(res.Errors, TargetError{Target: jb.target, Scheme: jb.prober.Scheme(), Err: err})
				}
				res.Findings = append(res.Findings, findings...)
				resMu.Unlock()
			}
		}()
	}
	wg.Wait()

	sortResult(&res)
	return res, nil
}

// safeProbe invokes a prober, converting a panic into an error so a
// misbehaving (possibly third-party) prober can never abort the batch.
func safeProbe(ctx context.Context, p Prober, t Target, g *graph.Graph) (findings []Finding, err error) {
	defer func() {
		if r := recover(); r != nil {
			findings = nil
			err = fmt.Errorf("probe: prober %q panicked on %s: %v", p.Scheme(), t.Addr(), r)
		}
	}()
	return p.Probe(ctx, t, g)
}

// mergeGraph replays every node and edge of src into dst, preserving upsert /
// provenance-union semantics. Merge errors (e.g. a node-type clash from a buggy
// prober) are best-effort and dropped rather than surfaced, since a well-behaved
// prober cannot produce them.
func mergeGraph(dst, src *graph.Graph) {
	for _, n := range src.Nodes() {
		_, _ = dst.UpsertNode(n)
	}
	for _, e := range src.Edges() {
		_, _ = dst.AddEdge(e)
	}
}

// sortResult imposes the deterministic ordering documented on Result.
func sortResult(r *Result) {
	sort.SliceStable(r.Findings, func(i, j int) bool {
		if r.Findings[i].Class != r.Findings[j].Class {
			return r.Findings[i].Class < r.Findings[j].Class
		}
		if r.Findings[i].Path != r.Findings[j].Path {
			return r.Findings[i].Path < r.Findings[j].Path
		}
		return r.Findings[i].Alias < r.Findings[j].Alias
	})
	sort.SliceStable(r.Errors, func(i, j int) bool {
		ai, aj := r.Errors[i].Target.Addr(), r.Errors[j].Target.Addr()
		if ai != aj {
			return ai < aj
		}
		return r.Errors[i].Scheme < r.Errors[j].Scheme
	})
}

// --- rate limiter (stdlib only) ---
//
// A minimal, mutex-guarded, evenly-spacing limiter. It is NOT a golang.org/x
// dependency: it hands out one "slot" every interval (1/RatePerSec) by tracking
// the next permissible call time. N calls at rate R therefore take at least
// (N-1)/R seconds regardless of how many workers contend, which is exactly the
// aggregate cap Run promises.

type rateLimiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
}

// newRateLimiter returns a limiter spacing calls at 1/ratePerSec, or nil (no
// limiting) when ratePerSec <= 0.
func newRateLimiter(ratePerSec float64) *rateLimiter {
	if ratePerSec <= 0 {
		return nil
	}
	return &rateLimiter{interval: time.Duration(float64(time.Second) / ratePerSec)}
}

// wait blocks until this caller's evenly-spaced slot is due, or ctx is done. A
// nil limiter (rate unset) returns immediately.
func (l *rateLimiter) wait(ctx context.Context) error {
	if l == nil || l.interval <= 0 {
		return nil
	}
	l.mu.Lock()
	now := time.Now()
	if l.next.Before(now) {
		l.next = now
	}
	slot := l.next
	l.next = l.next.Add(l.interval)
	l.mu.Unlock()

	d := time.Until(slot)
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
