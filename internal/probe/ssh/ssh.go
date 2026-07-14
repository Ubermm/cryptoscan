// Package ssh is the Phase 2 network prober for SSH endpoints. It implements the
// probe.Prober contract (Scheme "ssh") and self-registers into the process-wide
// probe registry from init, so the CLI's `cryptoscan probe` drives it through the
// single batch driver probe.Run.
//
// For one host:port it reads only the deterministic, unauthenticated wire
// preamble of RFC 4253:
//
//   - the server identification string (the "SSH-2.0-..."/"SSH-1.99-..." banner,
//     tolerating any RFC-permitted preamble lines that precede it);
//   - after replying with a fixed client identification ("SSH-2.0-cryptoscan"),
//     the server's SSH_MSG_KEXINIT, from which the advertised algorithm
//     name-lists are parsed.
//
// It never authenticates and never completes key exchange: nothing is sent
// beyond the client identification line. Everything recorded is provable
// (principle 1) — the ssh_endpoint finding and the Endpoint graph node trace to
// this exchange with Source "probe" and Path host:port (DESIGN.md §1 network
// probe contract).
//
// # Scope limitation (SSH, this phase)
//
// We record the algorithms a server ADVERTISES in its KEXINIT — host-key,
// key-exchange, cipher, and MAC name-lists. We do NOT complete the key exchange,
// so the server's actual host-key bytes are never received: there is deliberately
// NO Key or Certificate node for an SSH endpoint in this phase, and no host-key
// fingerprint is captured. Only the advertised parameters are proven from the
// wire, so only they are reported.
//
// Connections are opened through a shared netutil.Dialer, but pacing and timeout
// belong to the single batch driver probe.Run: it owns the one rate limit
// (--rate) and stamps each target's deadline (--timeout) onto the context passed
// to Probe. Every dial and read here is bounded by THAT context, not a baked
// per-connection timeout. The package depends only on the standard library,
// internal/graph, and the sibling probe/netutil packages, and it never panics: an
// unreachable target, a non-SSH service, and any malformed/oversized/truncated
// server data are all returned as recorded errors so probe.Run keeps the batch
// going.
package ssh

import (
	"bufio"
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/cryptoscan/cryptoscan/internal/graph"
	"github.com/cryptoscan/cryptoscan/internal/probe"
	"github.com/cryptoscan/cryptoscan/internal/probe/netutil"
)

// Banner-exchange limits (RFC 4253 §4.2). The identification string is capped at
// 255 bytes including CR LF; before it a server MAY send other CR LF lines, which
// we skip up to a total byte ceiling so a non-SSH service (or a hostile one that
// never sends an SSH- line) cannot stream unboundedly.
const (
	// maxIdentLineLen bounds a single CR LF-terminated preamble/identification
	// line (RFC 4253 §4.2: max 255 bytes).
	maxIdentLineLen = 255
	// maxIdentBytes bounds the total preamble read while searching for the SSH-
	// line, so a service that never sends one is rejected deterministically.
	maxIdentBytes = 8 * 1024
	// clientIdent is the fixed client identification string we send. It is the
	// only thing this prober ever writes.
	clientIdent = "SSH-2.0-cryptoscan\r\n"
)

// init registers the default SSH prober so a blank import (from the CLI) makes it
// available to probe.All(). Registration is order-independent.
func init() { probe.Register(New()) }

// Prober is the SSH implementation of probe.Prober. The zero value is usable. It
// is safe for concurrent use across targets: a single shared Dialer is created
// once and reused. Timeouts and rate limiting are owned by probe.Run (via the
// context and its single limiter), not by this prober.
type Prober struct {
	once   sync.Once
	dialer *netutil.Dialer
}

// New returns a ready-to-use SSH prober with netutil defaults.
func New() *Prober { return &Prober{} }

// Scheme implements probe.Prober.
func (p *Prober) Scheme() string { return "ssh" }

// dial lazily builds (once) the shared ctx-aware Dialer reused across every
// target of a run.
func (p *Prober) dial() *netutil.Dialer {
	p.once.Do(func() { p.dialer = netutil.NewDialer() })
	return p.dialer
}

// Probe implements probe.Prober. It observes t, populates g with the Endpoint
// node (DESIGN.md §1), and returns the single ssh_endpoint finding. An
// unreachable target (dial failure), a reachable port that is not SSH, and any
// malformed server data are all returned as wrapped errors with no finding, so
// probe.Run records them and moves on.
func (p *Prober) Probe(ctx context.Context, t probe.Target, g *graph.Graph) ([]probe.Finding, error) {
	obs, err := p.observe(ctx, t)
	if err != nil {
		return nil, err
	}
	if err := populate(g, t, obs); err != nil {
		return nil, fmt.Errorf("ssh: %s: populating graph: %w", t.Addr(), err)
	}
	return []probe.Finding{obs.finding(t)}, nil
}

// observation is everything a single Probe learned from the wire.
type observation struct {
	banner string   // server identification string, trimmed
	kex    *kexInit // parsed SSH_MSG_KEXINIT name-lists
}

// observe dials t, performs the banner exchange, sends the client identification,
// and reads and parses the server's KEXINIT. It bounds every read against a
// connection deadline derived from ctx and the netutil timeout, and closes the
// connection promptly on ctx cancellation, so a hung server cannot hang the
// prober.
func (p *Prober) observe(ctx context.Context, t probe.Target) (*observation, error) {
	addr := t.Addr()
	conn, err := p.dial().DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("ssh: dial %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()

	// Bound every read/write with the per-target deadline probe.Run set on ctx
	// (from --timeout), and close the connection if ctx is cancelled so an
	// in-flight read unblocks immediately.
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-stop:
		}
	}()

	r := bufio.NewReader(conn)
	banner, err := readIdentification(r)
	if err != nil {
		return nil, fmt.Errorf("ssh: %s: reading identification: %w", addr, err)
	}

	if _, err := conn.Write([]byte(clientIdent)); err != nil {
		return nil, fmt.Errorf("ssh: %s: sending client identification: %w", addr, err)
	}

	payload, err := readPacket(r)
	if err != nil {
		return nil, fmt.Errorf("ssh: %s: %w", addr, err)
	}
	ki, err := parseKexInitPayload(payload)
	if err != nil {
		return nil, fmt.Errorf("ssh: %s: %w", addr, err)
	}

	return &observation{banner: banner, kex: ki}, nil
}

// nodeAttrs builds the observed-attributes map stored on the Endpoint graph node
// (DESIGN.md §1 EndpointNode SSH attrs): the banner and the advertised host-key,
// kex, cipher, and MAC name-lists (ciphers/macs are the server-to-client
// direction). Every list attribute is a non-nil slice. These are the same keys
// the Finding projects, so the node — not just the Finding — carries the
// observation (principle 2). A fresh map is returned on every call.
func (o *observation) nodeAttrs() map[string]any {
	return map[string]any{
		"banner":              o.banner,
		"host_key_algorithms": nonNil(o.kex.hostKey),
		"kex_algorithms":      nonNil(o.kex.kex),
		"ciphers":             nonNil(o.kex.encS2C),
		"macs":                nonNil(o.kex.macS2C),
	}
}

// finding projects the observation into the ssh_endpoint finding (DESIGN.md §1),
// carrying exactly the endpoint's observed attributes.
func (o *observation) finding(t probe.Target) probe.Finding {
	return probe.Finding{
		Class:      probe.ClassSSHEndpoint,
		Path:       t.Addr(),
		Attrs:      o.nodeAttrs(),
		Provenance: []graph.Provenance{prov(t)},
	}
}

// nonNil returns s, or an empty (non-nil) slice when s is nil, so finding
// attributes are always present as lists.
func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// prov is the single provenance record shared by this target's finding and node
// (Source probe, Location host:port, Detail "ssh KEXINIT").
func prov(t probe.Target) graph.Provenance {
	return graph.Provenance{Source: graph.SourceProbe, Location: t.Addr(), Detail: "ssh KEXINIT"}
}

// populate projects the observation into g per the DESIGN.md §1 network probe
// graph contract: one Endpoint node per host:port. The observed SSH parameters —
// banner and the advertised host-key/kex/cipher/MAC name-lists — are stored under
// their own keys in the EndpointNode Attrs map, so TLS and SSH observations of a
// host:port coexist without overloading shared fields. Per the package scope
// note, no Key/Certificate node is created for an SSH endpoint: the host key
// itself is never received.
func populate(g *graph.Graph, t probe.Target, o *observation) error {
	pv := prov(t)
	epID, err := graph.EndpointNodeID(t.Host, t.Port)
	if err != nil {
		return err
	}
	ep := &graph.EndpointNode{Host: t.Host, Port: t.Port, Attrs: o.nodeAttrs()}
	ep.NodeID = epID
	ep.AddProvenance(pv)
	if _, err := g.UpsertNode(ep); err != nil {
		return err
	}
	return nil
}

// readIdentification reads the server's identification string (RFC 4253 §4.2),
// skipping any CR LF preamble lines that precede the "SSH-2.0-"/"SSH-1.99-" line.
// Each line is capped at maxIdentLineLen bytes and the total preamble at
// maxIdentBytes, so a service that never sends an SSH- line (i.e. not SSH) is
// rejected with an error rather than read forever. The returned banner is the
// SSH- line with surrounding whitespace trimmed.
func readIdentification(r *bufio.Reader) (string, error) {
	total := 0
	for {
		line, n, err := readLine(r, maxIdentLineLen)
		if err != nil {
			return "", err
		}
		total += n
		if total > maxIdentBytes {
			return "", fmt.Errorf("ssh: no SSH- identification line within %d bytes", maxIdentBytes)
		}
		if strings.HasPrefix(line, "SSH-") {
			if !strings.HasPrefix(line, "SSH-2.0-") && !strings.HasPrefix(line, "SSH-1.99-") {
				return "", fmt.Errorf("ssh: unsupported protocol version line %q", line)
			}
			return strings.TrimSpace(line), nil
		}
		// A non-SSH- line is RFC-permitted preamble: skip it and keep reading,
		// still bounded by maxIdentBytes above.
	}
}

// readLine reads one LF-terminated line, returning it without the trailing CR LF
// and the number of bytes consumed (including the LF). A line whose content
// exceeds max bytes before an LF arrives is an error, so no single line can grow
// without bound.
func readLine(r *bufio.Reader, max int) (string, int, error) {
	buf := make([]byte, 0, 64)
	for {
		b, err := r.ReadByte()
		if err != nil {
			return "", 0, err
		}
		if b == '\n' {
			consumed := len(buf) + 1
			if len(buf) > 0 && buf[len(buf)-1] == '\r' {
				buf = buf[:len(buf)-1]
			}
			return string(buf), consumed, nil
		}
		buf = append(buf, b)
		if len(buf) > max {
			return "", 0, fmt.Errorf("ssh: identification line exceeds %d bytes", max)
		}
	}
}
