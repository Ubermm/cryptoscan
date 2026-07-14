package pqc

import (
	"testing"
	"time"

	"github.com/Ubermm/cryptoscan/internal/graph"
)

// unitNow is a fixed reference time for the synthetic-graph edge-case tests.
var unitNow = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// mustEndpoint builds an Endpoint node with the given attrs.
func mustEndpoint(t *testing.T, host string, port int, attrs map[string]any) *graph.EndpointNode {
	t.Helper()
	id, err := graph.EndpointNodeID(host, port)
	if err != nil {
		t.Fatalf("endpoint id: %v", err)
	}
	e := &graph.EndpointNode{Host: host, Port: port, Attrs: attrs}
	e.NodeID = id
	return e
}

// exposureByID finds the scored exposure for a node ID.
func exposureByID(rep Report, id string) (NodeExposure, bool) {
	for _, e := range rep.Nodes {
		if e.NodeID == id {
			return e, true
		}
	}
	return NodeExposure{}, false
}

// TestHybridEndpointNotQuantumVulnerable is the key DESIGN §5 distinction: a
// hybrid X25519MLKEM768 endpoint (pqc_hybrid_kex=true) is NOT flagged
// quantum_vulnerable for its KEX, and it is counted as PQC-ready.
func TestHybridEndpointNotQuantumVulnerable(t *testing.T) {
	g := graph.New()
	hybrid := mustEndpoint(t, "hybrid.example", 443, map[string]any{
		"negotiated_protocol": "TLSv1.3",
		"protocols_supported": []string{"TLSv1.2", "TLSv1.3"},
		"pqc_hybrid_kex":      true,
	})
	classical := mustEndpoint(t, "classical.example", 443, map[string]any{
		"negotiated_protocol": "TLSv1.3",
		"protocols_supported": []string{"TLSv1.2", "TLSv1.3"},
		"pqc_hybrid_kex":      false,
	})
	if _, err := g.UpsertNode(hybrid); err != nil {
		t.Fatal(err)
	}
	if _, err := g.UpsertNode(classical); err != nil {
		t.Fatal(err)
	}

	rep := Score(g, unitNow)

	// Hybrid endpoint: no quantum_vulnerable flag, not legacy, so no exposure.
	if e, ok := exposureByID(rep, hybrid.ID()); ok {
		t.Errorf("hybrid endpoint should have no exposure, got flags %v", e.FlagNames)
	}
	// Classical endpoint: quantum_vulnerable for its classical KEX.
	e, ok := exposureByID(rep, classical.ID())
	if !ok || !e.Flags.QuantumVulnerableAlgorithm {
		t.Errorf("classical TLS endpoint must be quantum_vulnerable, got %+v (found=%v)", e.FlagNames, ok)
	}
	if e.Flags.LegacyProtocol {
		t.Errorf("TLS1.2/1.3 endpoint must not be legacy_protocol")
	}
	if rep.Summary.PQCReadyEndpoints != 1 {
		t.Errorf("PQCReadyEndpoints = %d, want 1", rep.Summary.PQCReadyEndpoints)
	}
}

// TestTLS13EndpointNotLegacy: an endpoint negotiating TLS 1.3 and supporting
// only 1.2/1.3 is not legacy_protocol.
func TestTLS13EndpointNotLegacy(t *testing.T) {
	g := graph.New()
	ep := mustEndpoint(t, "modern.example", 443, map[string]any{
		"negotiated_protocol": "TLSv1.3",
		"protocols_supported": []string{"TLSv1.2", "TLSv1.3"},
		"pqc_hybrid_kex":      false,
	})
	if _, err := g.UpsertNode(ep); err != nil {
		t.Fatal(err)
	}
	e, ok := exposureByID(Score(g, unitNow), ep.ID())
	if !ok {
		t.Fatal("expected exposure for classical TLS endpoint")
	}
	if e.Flags.LegacyProtocol {
		t.Errorf("TLS1.3 endpoint wrongly flagged legacy_protocol")
	}
}

// TestLegacyEndpointFromSupported: an endpoint that negotiated TLS 1.2 but still
// SUPPORTS TLSv1/TLSv1.1 is legacy_protocol, and it is counted as a legacy
// endpoint in the summary.
func TestLegacyEndpointFromSupported(t *testing.T) {
	g := graph.New()
	ep := mustEndpoint(t, "legacy.example", 443, map[string]any{
		"negotiated_protocol": "TLSv1.2",
		"protocols_supported": []string{"TLSv1", "TLSv1.1", "TLSv1.2"},
		"pqc_hybrid_kex":      false,
	})
	if _, err := g.UpsertNode(ep); err != nil {
		t.Fatal(err)
	}
	rep := Score(g, unitNow)
	e, ok := exposureByID(rep, ep.ID())
	if !ok || !e.Flags.LegacyProtocol {
		t.Errorf("endpoint supporting TLSv1/1.1 must be legacy_protocol, got %+v (found=%v)", e.FlagNames, ok)
	}
	if e.Severity != SeverityHigh {
		t.Errorf("legacy+quantum endpoint severity = %s, want high", e.Severity)
	}
	if rep.Summary.LegacyEndpoints != 1 {
		t.Errorf("LegacyEndpoints = %d, want 1", rep.Summary.LegacyEndpoints)
	}
}

// TestExpiringBoundary exercises the 90-day window boundary: a cert 89 days out
// is expiring, one 91 days out is not, and one already past is expired (not
// expiring).
func TestExpiringBoundary(t *testing.T) {
	mkCert := func(id string, notAfter time.Time) *graph.CertificateNode {
		c := &graph.CertificateNode{
			Subject:            "CN=" + id,
			Algorithm:          "RSA",
			KeySize:            2048,
			SignatureAlgorithm: "SHA256-RSA",
			NotBefore:          unitNow.Add(-24 * time.Hour),
			NotAfter:           notAfter,
		}
		c.NodeID = "cert:" + id
		return c
	}

	in89 := mkCert("in89", unitNow.Add(89*24*time.Hour))
	out91 := mkCert("out91", unitNow.Add(91*24*time.Hour))
	past := mkCert("past", unitNow.Add(-24*time.Hour))

	g := graph.New()
	for _, c := range []*graph.CertificateNode{in89, out91, past} {
		if _, err := g.UpsertNode(c); err != nil {
			t.Fatal(err)
		}
	}
	rep := Score(g, unitNow)

	e89, _ := exposureByID(rep, in89.ID())
	if !e89.Flags.Expiring || e89.Flags.Expired {
		t.Errorf("89-day cert: want expiring, got %v", e89.FlagNames)
	}
	e91, _ := exposureByID(rep, out91.ID())
	if e91.Flags.Expiring || e91.Flags.Expired {
		t.Errorf("91-day cert: want neither expiring nor expired, got %v", e91.FlagNames)
	}
	ePast, _ := exposureByID(rep, past.ID())
	if !ePast.Flags.Expired || ePast.Flags.Expiring {
		t.Errorf("past cert: want expired only, got %v", ePast.FlagNames)
	}
}

// TestNotYetValid: a cert whose NotBefore is in the future is flagged
// not_yet_valid (informational, low severity).
func TestNotYetValid(t *testing.T) {
	c := &graph.CertificateNode{
		Subject:            "CN=future",
		Algorithm:          "ECDSA",
		KeySize:            256,
		SignatureAlgorithm: "ECDSA-SHA256",
		NotBefore:          unitNow.Add(30 * 24 * time.Hour),
		NotAfter:           unitNow.Add(365 * 24 * time.Hour),
	}
	c.NodeID = "cert:future"
	g := graph.New()
	if _, err := g.UpsertNode(c); err != nil {
		t.Fatal(err)
	}
	e, ok := exposureByID(Score(g, unitNow), c.ID())
	if !ok || !e.Flags.NotYetValid {
		t.Errorf("expected not_yet_valid flag, got %+v (found=%v)", e.FlagNames, ok)
	}
	// ECDSA is quantum_vulnerable, so overall severity is High, not Low.
	if e.Severity != SeverityHigh {
		t.Errorf("severity = %s, want high (quantum_vulnerable dominates)", e.Severity)
	}
}

// TestSSHEndpointKEX: an SSH endpoint offering only classical KEX is
// quantum_vulnerable; one offering a PQC hybrid KEX is not.
func TestSSHEndpointKEX(t *testing.T) {
	g := graph.New()
	classical := mustEndpoint(t, "ssh-classical.example", 22, map[string]any{
		"banner":         "SSH-2.0-OpenSSH_8.0",
		"kex_algorithms": []string{"curve25519-sha256", "diffie-hellman-group14-sha1"},
	})
	pqc := mustEndpoint(t, "ssh-pqc.example", 22, map[string]any{
		"banner":         "SSH-2.0-OpenSSH_9.0",
		"kex_algorithms": []string{"sntrup761x25519-sha512@openssh.com", "curve25519-sha256"},
	})
	for _, e := range []*graph.EndpointNode{classical, pqc} {
		if _, err := g.UpsertNode(e); err != nil {
			t.Fatal(err)
		}
	}
	rep := Score(g, unitNow)

	ec, ok := exposureByID(rep, classical.ID())
	if !ok || !ec.Flags.QuantumVulnerableAlgorithm {
		t.Errorf("classical SSH endpoint must be quantum_vulnerable, got %+v (found=%v)", ec.FlagNames, ok)
	}
	if _, ok := exposureByID(rep, pqc.ID()); ok {
		t.Errorf("PQC SSH endpoint should have no exposure")
	}
}

// TestWeakKeyOnlyRSA: weak_key is RSA-specific. A 256-bit ECDSA key is strong
// (not weak_key) even though its bit count is < 2048.
func TestWeakKeyOnlyRSA(t *testing.T) {
	g := graph.New()
	ec := &graph.KeyNode{Algorithm: "ECDSA", KeySize: 256}
	ec.NodeID = "key:ec"
	rsa := &graph.KeyNode{Algorithm: "RSA", KeySize: 1024}
	rsa.NodeID = "key:rsa"
	for _, k := range []*graph.KeyNode{ec, rsa} {
		if _, err := g.UpsertNode(k); err != nil {
			t.Fatal(err)
		}
	}
	rep := Score(g, unitNow)
	if e, _ := exposureByID(rep, ec.ID()); e.Flags.WeakKey {
		t.Errorf("256-bit ECDSA key must not be weak_key")
	}
	if e, _ := exposureByID(rep, rsa.ID()); !e.Flags.WeakKey {
		t.Errorf("1024-bit RSA key must be weak_key")
	}
}

// TestNilGraph: Score(nil, now) returns an empty, well-formed Report.
func TestNilGraph(t *testing.T) {
	rep := Score(nil, unitNow)
	if len(rep.Nodes) != 0 {
		t.Errorf("nil graph: want no nodes, got %d", len(rep.Nodes))
	}
	if rep.Summary.TotalNodes != 0 || rep.Summary.ByFlag == nil {
		t.Errorf("nil graph: unexpected summary %+v", rep.Summary)
	}
}

// TestFlagsHelpers exercises Flags.Names / Severity / Any directly.
func TestFlagsHelpers(t *testing.T) {
	var empty Flags
	if empty.Any() {
		t.Errorf("empty flags should report Any()=false")
	}
	if empty.Severity() != SeverityLow {
		t.Errorf("empty flags severity = %s, want low", empty.Severity())
	}
	f := Flags{WeakKey: true, QuantumVulnerableAlgorithm: true, Expiring: true}
	if !f.Any() {
		t.Errorf("flags should report Any()=true")
	}
	if f.Severity() != SeverityCritical {
		t.Errorf("weak_key must drive severity to critical, got %s", f.Severity())
	}
	names := f.Names()
	want := []string{FlagExpiring, FlagQuantumVulnerable, FlagWeakKey}
	if len(names) != len(want) {
		t.Fatalf("Names() = %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Errorf("Names()[%d] = %s, want %s (must be sorted)", i, names[i], want[i])
		}
	}
}
