package tls

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/Ubermm/cryptoscan/internal/graph"
	"github.com/Ubermm/cryptoscan/internal/probe"
	"github.com/Ubermm/cryptoscan/internal/scan/certs"
)

// newTestProber returns a ready-to-use Prober. Rate limiting and timeouts are the
// harness's job (probe.Run), so a bare prober does no connection-layer pacing and
// runs fast in tests.
func newTestProber() *Prober {
	return New()
}

// target parses "host:port" into a probe.Target for driving Prober.Probe.
func target(t *testing.T, addr string) probe.Target {
	t.Helper()
	host, ps, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split %q: %v", addr, err)
	}
	port, _ := strconv.Atoi(ps)
	return probe.Target{Host: host, Port: port, Raw: addr}
}

// leafKeyCert generates a self-signed RSA leaf and returns the tls.Certificate
// plus the parsed cert (for identity assertions).
func leafKeyCert(t *testing.T, cn string) (stdtls.Certificate, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return stdtls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: parsed}, parsed
}

// startTLSServer starts an in-process TLS listener that handshakes and closes
// each connection. mutate customizes the server config (versions, curves, ...).
func startTLSServer(t *testing.T, cert stdtls.Certificate, mutate func(*stdtls.Config)) string {
	t.Helper()
	cfg := &stdtls.Config{
		Certificates: []stdtls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
	}
	if mutate != nil {
		mutate(cfg)
	}
	ln, err := stdtls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer func() { _ = conn.Close() }()
				if tc, ok := conn.(*stdtls.Conn); ok {
					_ = tc.HandshakeContext(context.Background())
				}
			}(c)
		}
	}()
	return ln.Addr().String()
}

// probeInto drives Prober.Probe against addr and returns the single tls_endpoint
// finding plus the populated graph. It fails the test on error.
func probeInto(t *testing.T, addr string) (probe.Finding, *graph.Graph) {
	t.Helper()
	g := graph.New()
	findings, err := newTestProber().Probe(context.Background(), target(t, addr), g)
	if err != nil {
		t.Fatalf("Probe(%s): %v", addr, err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1 (one tls_endpoint)", len(findings))
	}
	if findings[0].Class != probe.ClassTLSEndpoint {
		t.Fatalf("finding class = %q, want %q", findings[0].Class, probe.ClassTLSEndpoint)
	}
	return findings[0], g
}

func TestProbeBasic(t *testing.T) {
	cert, leaf := leafKeyCert(t, "basic.example.test")
	addr := startTLSServer(t, cert, nil)

	f, g := probeInto(t, addr)
	if f.Path != addr {
		t.Errorf("finding.Path = %q, want %q", f.Path, addr)
	}
	if got := f.Attrs["negotiated_protocol"]; got != "TLSv1.3" {
		t.Errorf("negotiated_protocol = %v, want TLSv1.3", got)
	}
	if got, _ := f.Attrs["negotiated_cipher_suite"].(string); got == "" {
		t.Error("negotiated_cipher_suite is empty")
	}
	if got := f.Attrs["alpn"]; got != "h2" {
		t.Errorf("alpn = %v, want h2", got)
	}
	if got := f.Attrs["peer_certs"]; got != 1 {
		t.Errorf("peer_certs = %v, want 1", got)
	}
	protos, _ := f.Attrs["protocols_supported"].([]string)
	if !containsStr(protos, "TLSv1.2") || !containsStr(protos, "TLSv1.3") {
		t.Errorf("protocols_supported = %v, want to contain TLSv1.2 and TLSv1.3", protos)
	}
	if containsStr(protos, "TLSv1") || containsStr(protos, "TLSv1.1") {
		t.Errorf("protocols_supported = %v, unexpectedly includes a legacy version (server min is 1.2)", protos)
	}
	if len(f.Provenance) != 1 || f.Provenance[0].Source != graph.SourceProbe {
		t.Errorf("provenance = %+v, want one probe record", f.Provenance)
	}

	// Graph: the presented leaf must resolve to the SAME node the fs scanner
	// derives from the same bytes (cross-surface entity resolution).
	oc, err := certs.ParseObservedCert(leaf.Raw)
	if err != nil {
		t.Fatalf("ParseObservedCert: %v", err)
	}
	certID, _ := graph.CertNodeID(oc.DERSHA256)
	if _, ok := g.Node(certID); !ok {
		t.Fatalf("certificate node %q (fs identity) not found in probe graph", certID)
	}
	keyID, _ := graph.KeyNodeID(oc.SPKISHA256)
	if _, ok := g.Node(keyID); !ok {
		t.Fatalf("key node %q not found", keyID)
	}
	epID, _ := graph.EndpointNodeID(target(t, addr).Host, target(t, addr).Port)
	if _, ok := g.Node(epID); !ok {
		t.Fatalf("endpoint node %q not found", epID)
	}
	if !hasEdge(g, graph.EdgeTerminatesTLSFor, certID, epID) {
		t.Error("missing terminates_tls_for edge leaf -> endpoint")
	}
	if !hasEdge(g, graph.EdgeSignsWith, certID, keyID) {
		t.Error("missing signs_with edge cert -> key")
	}
	// Self-signed leaf: issued_by points at the observed CA (ca:<own DER>).
	caID, _ := graph.CANodeID(oc.DERSHA256)
	if !hasEdge(g, graph.EdgeIssuedBy, certID, caID) {
		t.Errorf("missing issued_by edge to observed self-signed CA %q", caID)
	}
}

func TestProbeLegacyVersionEnumeration(t *testing.T) {
	cert, _ := leafKeyCert(t, "legacy.example.test")
	addr := startTLSServer(t, cert, func(c *stdtls.Config) {
		c.MinVersion = stdtls.VersionTLS10
		c.MaxVersion = stdtls.VersionTLS12
	})

	f, _ := probeInto(t, addr)
	protos, _ := f.Attrs["protocols_supported"].([]string)
	want := []string{"TLSv1", "TLSv1.1", "TLSv1.2"}
	if !equalStr(protos, want) {
		t.Errorf("protocols_supported = %v, want %v", protos, want)
	}
	if got := f.Attrs["negotiated_protocol"]; got != "TLSv1.2" {
		t.Errorf("negotiated_protocol = %v, want TLSv1.2", got)
	}
	if got := f.Attrs["pqc_hybrid_kex"]; got != false {
		t.Errorf("pqc_hybrid_kex = %v, want false (server caps at TLS 1.2)", got)
	}
}

func TestProbePQCHybridSupported(t *testing.T) {
	cert, _ := leafKeyCert(t, "pqc.example.test")
	// Default Go server supports X25519MLKEM768.
	addr := startTLSServer(t, cert, func(c *stdtls.Config) {
		c.MinVersion = stdtls.VersionTLS13
	})

	f, _ := probeInto(t, addr)
	if got := f.Attrs["pqc_hybrid_kex"]; got != true {
		t.Errorf("pqc_hybrid_kex = %v, want true (default server accepts X25519MLKEM768)", got)
	}
}

func TestProbePQCHybridUnsupported(t *testing.T) {
	cert, _ := leafKeyCert(t, "nopqc.example.test")
	// Restrict the server to classical X25519: the PQC probe (offering ONLY
	// X25519MLKEM768) then has no shared group and must fail.
	addr := startTLSServer(t, cert, func(c *stdtls.Config) {
		c.MinVersion = stdtls.VersionTLS13
		c.CurvePreferences = []stdtls.CurveID{stdtls.X25519}
	})

	f, _ := probeInto(t, addr)
	if got := f.Attrs["pqc_hybrid_kex"]; got != false {
		t.Errorf("pqc_hybrid_kex = %v, want false (server offers only classical X25519)", got)
	}
}

func TestProbeUnreachable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close() // nothing listens now

	findings, err := newTestProber().Probe(context.Background(), target(t, addr), graph.New())
	if err == nil {
		t.Fatal("Probe error = nil, want dial failure")
	}
	if findings != nil {
		t.Errorf("findings = %v, want nil on failure", findings)
	}
}

func TestProbePlaintextPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close() // never speaks TLS
		}
	}()

	findings, err := newTestProber().Probe(context.Background(), target(t, ln.Addr().String()), graph.New())
	if err == nil {
		t.Fatal("Probe error = nil, want 'reachable but no TLS' error")
	}
	if findings != nil {
		t.Errorf("findings = %v, want nil for a non-TLS port", findings)
	}
}

func TestProberRegisteredInRegistry(t *testing.T) {
	found := false
	for _, p := range probe.All() {
		if p.Scheme() == "tls" {
			found = true
		}
	}
	if !found {
		t.Error("tls prober not found in probe.All(); init registration failed")
	}
}

func TestProbeViaOrchestrator(t *testing.T) {
	cert, leaf := leafKeyCert(t, "orch.example.test")
	addr := startTLSServer(t, cert, nil)

	g := graph.New()
	res, err := probe.Run(context.Background(), []probe.Target{target(t, addr)}, g,
		probe.RunOptions{Probers: []probe.Prober{newTestProber()}})
	if err != nil {
		t.Fatalf("orchestrator Run: %v", err)
	}
	if len(res.Errors) != 0 {
		t.Fatalf("Run errors = %v, want none", res.Errors)
	}
	var endpointFindings int
	for _, f := range res.Findings {
		if f.Class == probe.ClassTLSEndpoint {
			endpointFindings++
		}
	}
	if endpointFindings != 1 {
		t.Errorf("tls_endpoint findings = %d, want 1", endpointFindings)
	}
	// The orchestrator merged the scratch graph: the leaf node must be present
	// under the shared fs identity key.
	oc, _ := certs.ParseObservedCert(leaf.Raw)
	certID, _ := graph.CertNodeID(oc.DERSHA256)
	if _, ok := g.Node(certID); !ok {
		t.Errorf("certificate node %q missing from merged graph", certID)
	}
}

// TestProbeHangingTargetBoundedByTimeout proves the fix for MAJOR-2: the
// per-target timeout (--timeout / RunOptions.Timeout) bounds the WHOLE target —
// all ~6 handshakes share one deadline budget threaded through ctx — rather than
// each connection getting its own baked timeout that stacks. A target that
// accepts TCP but never answers the ClientHello must cost ~1×Timeout, decisively
// under the old ~6×5s (=30s) or ~6×Timeout (=12s) failure mode.
func TestProbeHangingTargetBoundedByTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	// Accept connections and hold them open, never responding to the ClientHello.
	go func() {
		var held []net.Conn
		defer func() {
			for _, c := range held {
				_ = c.Close()
			}
		}()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			held = append(held, c)
		}
	}()

	const timeout = 2 * time.Second
	g := graph.New()
	start := time.Now()
	res, err := probe.Run(context.Background(), []probe.Target{target(t, ln.Addr().String())}, g,
		probe.RunOptions{Probers: []probe.Prober{newTestProber()}, Timeout: timeout})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("hanging target yielded %d findings, want 0", len(res.Findings))
	}
	if len(res.Errors) == 0 {
		t.Fatal("hanging target recorded no error, want one")
	}
	// One shared timeout budget => ~1×timeout. Assert a generous upper bound well
	// under the old stacking behavior.
	if elapsed > 2*timeout {
		t.Fatalf("hanging target took %v, want < %v (one shared per-target budget, not per-connection)", elapsed, 2*timeout)
	}
}

// TestProbeNoConnectionRateLimit proves the fix for MAJOR-1: with the second
// (netutil) rate limiter removed, a default prober does NO connection-layer
// pacing. A single target performs ~6 handshakes; under the old baked 20 conns/s
// limiter (burst 1) that alone forced >= 5*50ms = 250ms of spacing. With --rate
// (RunOptions.RatePerSec) unset here, the run must finish well under that floor —
// proving no hidden limiter caps throughput.
func TestProbeNoConnectionRateLimit(t *testing.T) {
	cert, _ := leafKeyCert(t, "norate.example.test")
	addr := startTLSServer(t, cert, nil)

	g := graph.New()
	start := time.Now()
	res, err := probe.Run(context.Background(), []probe.Target{target(t, addr)}, g,
		probe.RunOptions{Probers: []probe.Prober{New()}}) // default prober, RatePerSec = 0 (unlimited)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(res.Findings))
	}
	// Six localhost handshakes take single-digit ms; the old limiter floor was
	// 250ms. 200ms is a decisive upper bound that the removed limiter would fail.
	if elapsed > 200*time.Millisecond {
		t.Fatalf("single-target probe took %v; a hidden connection rate limiter is still capping throughput", elapsed)
	}
}

func TestProtoName(t *testing.T) {
	cases := map[uint16]string{
		stdtls.VersionTLS10: "TLSv1",
		stdtls.VersionTLS11: "TLSv1.1",
		stdtls.VersionTLS12: "TLSv1.2",
		stdtls.VersionTLS13: "TLSv1.3",
		0x0300:              "", // SSLv3: unmodelled
	}
	for v, want := range cases {
		if got := protoName(v); got != want {
			t.Errorf("protoName(%#04x) = %q, want %q", v, got, want)
		}
	}
}

// --- helpers ---

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func equalStr(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func hasEdge(g *graph.Graph, et graph.EdgeType, from, to string) bool {
	for _, e := range g.Edges() {
		if e.Type == et && e.From == from && e.To == to {
			return true
		}
	}
	return false
}
