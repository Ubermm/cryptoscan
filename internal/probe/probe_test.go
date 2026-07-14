package probe

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Ubermm/cryptoscan/internal/graph"
)

// fakeProber is a scriptable Prober for exercising Run offline. It records
// concurrency, can sleep to trigger timeouts, and can return scripted
// findings/errors or panic.
type fakeProber struct {
	scheme string
	// sleep, if set, blocks Probe for this long (interruptible by ctx) so the
	// timeout path can be exercised.
	sleep time.Duration
	// failHosts causes Probe to return an error for those target hosts.
	failHosts map[string]bool
	// panicHost causes Probe to panic for that host.
	panicHost string

	inFlight int32
	maxSeen  int32
	calls    int32
}

func (f *fakeProber) Scheme() string { return f.scheme }

func (f *fakeProber) Probe(ctx context.Context, t Target, g *graph.Graph) ([]Finding, error) {
	atomic.AddInt32(&f.calls, 1)
	cur := atomic.AddInt32(&f.inFlight, 1)
	defer atomic.AddInt32(&f.inFlight, -1)
	for {
		old := atomic.LoadInt32(&f.maxSeen)
		if cur <= old || atomic.CompareAndSwapInt32(&f.maxSeen, old, cur) {
			break
		}
	}

	if f.panicHost != "" && t.Host == f.panicHost {
		panic("boom")
	}
	if f.sleep > 0 {
		select {
		case <-time.After(f.sleep):
		case <-ctx.Done():
			return nil, fmt.Errorf("fake %s: %w", f.scheme, ctx.Err())
		}
	}
	if f.failHosts[t.Host] {
		return nil, fmt.Errorf("fake %s: host %s unreachable", f.scheme, t.Host)
	}

	// Populate the (scratch) graph like a real prober would.
	id, err := graph.EndpointNodeID(t.Host, t.Port)
	if err == nil {
		node := &graph.EndpointNode{Host: t.Host, Port: t.Port}
		node.NodeID = id
		node.AddProvenance(graph.Provenance{Source: graph.SourceProbe, Location: t.Addr(), Detail: f.scheme})
		_, _ = g.UpsertNode(node)
	}

	fClass := ClassTLSEndpoint
	if f.scheme == "ssh" {
		fClass = ClassSSHEndpoint
	}
	return []Finding{{
		Class: fClass,
		Path:  t.Addr(),
		Attrs: map[string]any{"scheme": f.scheme},
		Provenance: []graph.Provenance{
			{Source: graph.SourceProbe, Location: t.Addr(), Detail: "observed " + f.scheme},
		},
	}}, nil
}

func mustTargets(t *testing.T, args ...string) []Target {
	t.Helper()
	ts, err := ParseTargets(args, 443)
	if err != nil {
		t.Fatalf("ParseTargets: %v", err)
	}
	return ts
}

func TestRunAllTargetsAttemptedAndFindingsSorted(t *testing.T) {
	fp := &fakeProber{scheme: "tls"}
	g := graph.New()
	targets := mustTargets(t, "c.example:1", "a.example:2", "b.example:3")

	res, err := Run(context.Background(), targets, g, RunOptions{Probers: []Prober{fp}})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := atomic.LoadInt32(&fp.calls); got != 3 {
		t.Fatalf("expected 3 probe calls, got %d", got)
	}
	if len(res.Findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(res.Findings))
	}
	// Findings must be sorted by (Class,Path).
	for i := 1; i < len(res.Findings); i++ {
		if res.Findings[i-1].Path > res.Findings[i].Path {
			t.Fatalf("findings not sorted by path: %q before %q",
				res.Findings[i-1].Path, res.Findings[i].Path)
		}
	}
	if g.NodeCount() != 3 {
		t.Fatalf("expected 3 endpoint nodes merged into shared graph, got %d", g.NodeCount())
	}
}

func TestRunErrorsAreCapturedNotFatal(t *testing.T) {
	fp := &fakeProber{scheme: "tls", failHosts: map[string]bool{"bad.example": true}}
	g := graph.New()
	targets := mustTargets(t, "ok1.example:1", "bad.example:2", "ok2.example:3")

	res, err := Run(context.Background(), targets, g, RunOptions{Probers: []Prober{fp}})
	if err != nil {
		t.Fatalf("Run returned fatal error: %v", err)
	}
	if len(res.Errors) != 1 {
		t.Fatalf("expected 1 recorded error, got %d", len(res.Errors))
	}
	if res.Errors[0].Target.Host != "bad.example" || res.Errors[0].Scheme != "tls" {
		t.Fatalf("wrong error target/scheme: %+v", res.Errors[0])
	}
	if len(res.Findings) != 2 {
		t.Fatalf("expected 2 successful findings, got %d", len(res.Findings))
	}
}

func TestRunPanicIsRecovered(t *testing.T) {
	fp := &fakeProber{scheme: "tls", panicHost: "boom.example"}
	g := graph.New()
	targets := mustTargets(t, "ok.example:1", "boom.example:2")

	res, err := Run(context.Background(), targets, g, RunOptions{Probers: []Prober{fp}})
	if err != nil {
		t.Fatalf("Run should not surface a prober panic: %v", err)
	}
	if len(res.Errors) != 1 {
		t.Fatalf("expected panic captured as 1 error, got %d: %+v", len(res.Errors), res.Errors)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected the non-panicking target to still produce a finding, got %d", len(res.Findings))
	}
}

func TestRunTimeout(t *testing.T) {
	fp := &fakeProber{scheme: "tls", sleep: 2 * time.Second}
	g := graph.New()
	targets := mustTargets(t, "slow.example:443")

	start := time.Now()
	res, err := Run(context.Background(), targets, g, RunOptions{
		Probers: []Prober{fp},
		Timeout: 50 * time.Millisecond,
	})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if elapsed > time.Second {
		t.Fatalf("timeout did not fire promptly, elapsed %v", elapsed)
	}
	if len(res.Errors) != 1 {
		t.Fatalf("expected 1 timeout error, got %d", len(res.Errors))
	}
	if !errors.Is(res.Errors[0].Err, context.DeadlineExceeded) {
		t.Fatalf("error should wrap context.DeadlineExceeded, got %v", res.Errors[0].Err)
	}
}

func TestRunConcurrencyCap(t *testing.T) {
	fp := &fakeProber{scheme: "tls", sleep: 30 * time.Millisecond}
	g := graph.New()
	args := make([]string, 20)
	for i := range args {
		args[i] = fmt.Sprintf("h%02d.example:443", i)
	}
	targets := mustTargets(t, args...)

	_, err := Run(context.Background(), targets, g, RunOptions{
		Probers:     []Prober{fp},
		Concurrency: 3,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := atomic.LoadInt32(&fp.maxSeen); got > 3 {
		t.Fatalf("concurrency cap exceeded: max in-flight %d > 3", got)
	}
	if got := atomic.LoadInt32(&fp.calls); got != 20 {
		t.Fatalf("expected all 20 targets probed, got %d", got)
	}
}

func TestRunRateLimiterSpacesCalls(t *testing.T) {
	fp := &fakeProber{scheme: "tls"}
	g := graph.New()
	const n = 5
	args := make([]string, n)
	for i := range args {
		args[i] = fmt.Sprintf("h%d.example:443", i)
	}
	targets := mustTargets(t, args...)

	const rate = 50.0 // 20ms interval
	start := time.Now()
	_, err := Run(context.Background(), targets, g, RunOptions{
		Probers:     []Prober{fp},
		Concurrency: 8, // more workers than needed; limiter must still gate
		RatePerSec:  rate,
	})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// N calls at R/sec take at least (N-1)/R. Allow a scheduling tolerance.
	wantMin := time.Duration(float64(n-1)/rate*float64(time.Second)) * 8 / 10 // 80% of ideal
	if elapsed < wantMin {
		t.Fatalf("rate limiter did not space calls: elapsed %v < %v", elapsed, wantMin)
	}
}

// TestRunConcurrentGraphWritesNoRace drives several probers over many targets
// into one shared graph. It is meaningful under `go test -race`; run with -race
// in CI. Locally -race may be unavailable (needs a C toolchain), in which case
// it still exercises correctness of the merge but not the race detector.
func TestRunConcurrentGraphWritesNoRace(t *testing.T) {
	tls := &fakeProber{scheme: "tls"}
	ssh := &fakeProber{scheme: "ssh"}
	g := graph.New()
	args := make([]string, 25)
	for i := range args {
		// Overlapping hosts so probers contend on the same endpoint nodes.
		args[i] = fmt.Sprintf("shared%02d.example:443", i%5)
	}
	targets, err := ParseTargets(args, 443)
	if err != nil {
		t.Fatalf("ParseTargets: %v", err)
	}

	res, err := Run(context.Background(), targets, g, RunOptions{
		Probers:     []Prober{tls, ssh},
		Concurrency: 8,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// 25 targets * 2 probers = 50 findings.
	if len(res.Findings) != 50 {
		t.Fatalf("expected 50 findings, got %d", len(res.Findings))
	}
	// Only 5 distinct host:port endpoints, so entity resolution should collapse
	// to 5 nodes in the shared graph.
	if g.NodeCount() != 5 {
		t.Fatalf("expected 5 merged endpoint nodes, got %d", g.NodeCount())
	}
}

func TestRunSetupErrors(t *testing.T) {
	fp := &fakeProber{scheme: "tls"}
	if _, err := Run(context.Background(), mustTargets(t, "a.example:1"), nil, RunOptions{Probers: []Prober{fp}}); err == nil {
		t.Fatal("nil graph should be a setup error")
	}
	if _, err := Run(context.Background(), mustTargets(t, "a.example:1"), graph.New(), RunOptions{Probers: nil}); err == nil {
		t.Fatal("no probers (empty registry) should be a setup error")
	}
	// No targets is not an error.
	res, err := Run(context.Background(), nil, graph.New(), RunOptions{Probers: []Prober{fp}})
	if err != nil {
		t.Fatalf("empty targets should not error: %v", err)
	}
	if len(res.Findings) != 0 || len(res.Errors) != 0 {
		t.Fatalf("empty targets should yield empty result, got %+v", res)
	}
}

// --- registry ---

func TestRegistryDeterministicOrder(t *testing.T) {
	// Save and restore the process registry so this test is isolated.
	regMu.Lock()
	saved := registry
	registry = map[string]Prober{}
	regMu.Unlock()
	defer func() {
		regMu.Lock()
		registry = saved
		regMu.Unlock()
	}()

	Register(&fakeProber{scheme: "ssh"})
	Register(&fakeProber{scheme: "tls"})
	Register(nil)                     // ignored
	Register(&fakeProber{scheme: ""}) // ignored

	all := All()
	if len(all) != 2 {
		t.Fatalf("expected 2 registered probers, got %d", len(all))
	}
	if all[0].Scheme() != "ssh" || all[1].Scheme() != "tls" {
		t.Fatalf("registry not scheme-sorted: %q, %q", all[0].Scheme(), all[1].Scheme())
	}

	// Re-registering a scheme replaces it (still 2 total).
	Register(&fakeProber{scheme: "tls"})
	if got := len(All()); got != 2 {
		t.Fatalf("re-register should not grow registry, got %d", got)
	}
}
