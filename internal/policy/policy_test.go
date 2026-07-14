package policy

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/cryptoscan/cryptoscan/internal/graph"
	"github.com/cryptoscan/cryptoscan/internal/pqc"
)

// refNow is the fixed reference time used for every test so expiry flags are
// reproducible.
var refNow = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// hex64 returns a valid 64-hex-char SHA-256 string derived from n, for building
// distinct synthetic node IDs.
func hex64(n int) string { return fmt.Sprintf("%064x", n) }

// --- synthetic node builders (NodeID is a promoted exported field) ---

func certNode(t *testing.T, n int, c *graph.CertificateNode) *graph.CertificateNode {
	t.Helper()
	id, err := graph.CertNodeID(hex64(n))
	if err != nil {
		t.Fatalf("CertNodeID: %v", err)
	}
	c.NodeID = id
	return c
}

func endpointNode(t *testing.T, host string, port int, attrs map[string]any) *graph.EndpointNode {
	t.Helper()
	id, err := graph.EndpointNodeID(host, port)
	if err != nil {
		t.Fatalf("EndpointNodeID: %v", err)
	}
	e := &graph.EndpointNode{Host: host, Port: port, Attrs: attrs}
	e.NodeID = id
	return e
}

func configNode(t *testing.T, path string, attrs map[string]any) *graph.ConfigFileNode {
	t.Helper()
	id, err := graph.FileNodeID(path)
	if err != nil {
		t.Fatalf("FileNodeID: %v", err)
	}
	c := &graph.ConfigFileNode{Path: path, Format: "tls_config", Attrs: attrs}
	c.NodeID = id
	return c
}

// buildGraph upserts every node into a fresh graph.
func buildGraph(t *testing.T, nodes ...graph.Node) *graph.Graph {
	t.Helper()
	g := graph.New()
	for _, n := range nodes {
		if _, err := g.UpsertNode(n); err != nil {
			t.Fatalf("UpsertNode %s: %v", n.ID(), err)
		}
	}
	return g
}

// evalTokens is the full pipeline used by most tests: parse tokens, score the
// graph with pqc (the same Report the CLI passes), evaluate, return the Result.
func evalTokens(t *testing.T, g *graph.Graph, tokens ...string) Result {
	t.Helper()
	ths, err := ParseThresholds(tokens)
	if err != nil {
		t.Fatalf("ParseThresholds(%v): %v", tokens, err)
	}
	return Evaluate(g, pqc.Score(g, refNow), ths)
}

// tokensTripped returns the set of tokens that produced at least one breach.
func tokensTripped(r Result) map[string]int {
	m := map[string]int{}
	for _, b := range r.Breaches {
		m[b.Token]++
	}
	return m
}

// --- fixtures ---

func sha1Cert(t *testing.T) *graph.CertificateNode {
	return certNode(t, 1, &graph.CertificateNode{
		Subject: "CN=sha1.example.test", Algorithm: "RSA", KeySize: 2048,
		SignatureAlgorithm: "SHA1-RSA",
		NotAfter:           refNow.Add(365 * 24 * time.Hour),
	})
}

func md5Cert(t *testing.T) *graph.CertificateNode {
	return certNode(t, 2, &graph.CertificateNode{
		Subject: "CN=md5.example.test", Algorithm: "RSA", KeySize: 2048,
		SignatureAlgorithm: "MD5-RSA",
		NotAfter:           refNow.Add(365 * 24 * time.Hour),
	})
}

func rsa1024Cert(t *testing.T) *graph.CertificateNode {
	return certNode(t, 3, &graph.CertificateNode{
		Subject: "CN=rsa1024.example.test", Algorithm: "RSA", KeySize: 1024,
		SignatureAlgorithm: "SHA256-RSA",
		NotAfter:           refNow.Add(365 * 24 * time.Hour),
	})
}

func expiredCert(t *testing.T) *graph.CertificateNode {
	return certNode(t, 4, &graph.CertificateNode{
		Subject: "CN=expired.example.test", Algorithm: "RSA", KeySize: 2048,
		SignatureAlgorithm: "SHA256-RSA",
		NotBefore:          time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:           time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC),
	})
}

// strongCert is a modern ECDSA-P384 cert that trips none of the weak tokens.
func strongCert(t *testing.T) *graph.CertificateNode {
	return certNode(t, 5, &graph.CertificateNode{
		Subject: "CN=strong.example.test", Algorithm: "ECDSA", KeySize: 384,
		SignatureAlgorithm: "ECDSA-SHA384",
		NotAfter:           refNow.Add(3650 * 24 * time.Hour),
	})
}

// --- tests ---

// TestProtocolTokensAreVersionSpecific is the headline: a TLS 1.0 endpoint trips
// tls10 (and legacy-tls) but NOT tls11 or ssl3.
func TestProtocolTokensAreVersionSpecific(t *testing.T) {
	ep := endpointNode(t, "tls10.example.test", 443, map[string]any{
		"negotiated_protocol": "TLSv1.2",
		"protocols_supported": []string{"TLSv1", "TLSv1.2"},
	})
	g := buildGraph(t, ep)

	if r := evalTokens(t, g, "tls10"); !r.Breached() {
		t.Error("tls10 should trip on a TLS-1.0-allowing endpoint")
	}
	if r := evalTokens(t, g, "tls11"); r.Breached() {
		t.Errorf("tls11 must NOT trip (endpoint does not allow TLS 1.1): %+v", r.Breaches)
	}
	if r := evalTokens(t, g, "ssl3"); r.Breached() {
		t.Errorf("ssl3 must NOT trip: %+v", r.Breaches)
	}
	if r := evalTokens(t, g, "legacy-tls"); !r.Breached() {
		t.Error("legacy-tls should trip (union includes TLS 1.0)")
	}
}

// TestConfigProtocolResolution checks tls_config nodes via both the explicit
// protocols set and the min_protocol floor.
func TestConfigProtocolResolution(t *testing.T) {
	// Explicit protocols set including TLSv1.
	protoCfg := configNode(t, "/etc/nginx/legacy.conf", map[string]any{
		"protocols": []string{"TLSv1", "TLSv1.1", "TLSv1.2"},
	})
	// min_protocol floor at TLSv1 (admits TLS 1.0).
	minLowCfg := configNode(t, "/etc/openssl-low.cnf", map[string]any{
		"min_protocol": "TLSv1",
	})
	// min_protocol floor at TLSv1.2 (does NOT admit TLS 1.0).
	minHighCfg := configNode(t, "/etc/openssl-high.cnf", map[string]any{
		"min_protocol": "TLSv1.2",
	})

	if r := evalTokens(t, buildGraph(t, protoCfg), "tls10"); !r.Breached() {
		t.Error("explicit protocols set with TLSv1 should trip tls10")
	}
	if r := evalTokens(t, buildGraph(t, protoCfg), "tls11"); !r.Breached() {
		t.Error("explicit protocols set with TLSv1.1 should trip tls11")
	}
	if r := evalTokens(t, buildGraph(t, minLowCfg), "tls10"); !r.Breached() {
		t.Error("min_protocol=TLSv1 should trip tls10")
	}
	if r := evalTokens(t, buildGraph(t, minHighCfg), "tls10"); r.Breached() {
		t.Errorf("min_protocol=TLSv1.2 must NOT trip tls10: %+v", r.Breaches)
	}
	// min_protocol=TLSv1.2 is still not legacy.
	if r := evalTokens(t, buildGraph(t, minHighCfg), "legacy-tls"); r.Breached() {
		t.Errorf("min_protocol=TLSv1.2 must NOT trip legacy-tls: %+v", r.Breaches)
	}
}

// TestSignatureTokens checks sha1/md5/weak-signature discrimination.
func TestSignatureTokens(t *testing.T) {
	g := buildGraph(t, sha1Cert(t), md5Cert(t))

	sha1 := tokensTripped(evalTokens(t, g, "sha1"))
	if sha1["sha1"] != 1 {
		t.Errorf("sha1 count = %d, want 1", sha1["sha1"])
	}
	md5 := tokensTripped(evalTokens(t, g, "md5"))
	if md5["md5"] != 1 {
		t.Errorf("md5 count = %d, want 1", md5["md5"])
	}
	// weak-signature is the union: both certs.
	weak := tokensTripped(evalTokens(t, g, "weak-signature"))
	if weak["weak-signature"] != 2 {
		t.Errorf("weak-signature count = %d, want 2", weak["weak-signature"])
	}
	// sha1 must not match the md5 cert and vice versa.
	for _, b := range evalTokens(t, g, "sha1").Breaches {
		if b.Detail != "signature=SHA1-RSA" {
			t.Errorf("sha1 breach detail = %q, want signature=SHA1-RSA", b.Detail)
		}
	}
}

// TestKeyAndExpiryTokens checks rsa1024/weak-key and expired.
func TestKeyAndExpiryTokens(t *testing.T) {
	g := buildGraph(t, rsa1024Cert(t), expiredCert(t))

	for _, tok := range []string{"rsa1024", "weak-key"} {
		got := tokensTripped(evalTokens(t, g, tok))
		if got[tok] != 1 {
			t.Errorf("%s count = %d, want 1", tok, got[tok])
		}
	}
	rsaBreach := evalTokens(t, g, "rsa1024").Breaches
	if len(rsaBreach) != 1 || rsaBreach[0].Detail != "RSA 1024-bit" {
		t.Errorf("rsa1024 breach = %+v, want detail RSA 1024-bit", rsaBreach)
	}

	exp := evalTokens(t, g, "expired")
	if !exp.Breached() || exp.Breaches[0].Detail != "notAfter=2021-01-01" {
		t.Errorf("expired breach = %+v, want notAfter=2021-01-01", exp.Breaches)
	}
}

// TestQuantumVulnerable trips on any classical asymmetric asset.
func TestQuantumVulnerable(t *testing.T) {
	g := buildGraph(t, strongCert(t)) // ECDSA is still quantum-vulnerable
	r := evalTokens(t, g, "quantum-vulnerable")
	if !r.Breached() {
		t.Error("quantum-vulnerable should trip on an ECDSA cert")
	}
}

// TestNoFalsePositives: a modern strong ECDSA cert trips none of the weak tokens.
func TestNoFalsePositives(t *testing.T) {
	g := buildGraph(t, strongCert(t))
	for _, tok := range []string{"sha1", "md5", "weak-signature", "rsa1024", "weak-key", "expired", "expiring", "tls10", "tls11", "ssl3", "legacy-tls"} {
		if r := evalTokens(t, g, tok); r.Breached() {
			t.Errorf("token %q falsely tripped on strong cert: %+v", tok, r.Breaches)
		}
	}
}

// TestMultipleTokensUnion: multiple tokens against a mixed estate produce the
// union of breaches.
func TestMultipleTokensUnion(t *testing.T) {
	g := buildGraph(t, sha1Cert(t), rsa1024Cert(t), expiredCert(t), strongCert(t))
	r := evalTokens(t, g, "sha1", "rsa1024", "expired")
	got := tokensTripped(r)
	want := map[string]int{"sha1": 1, "rsa1024": 1, "expired": 1}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("union tokens = %v, want %v", got, want)
	}
}

// TestCaseInsensitivity: tokens are accepted regardless of case.
func TestCaseInsensitivity(t *testing.T) {
	g := buildGraph(t, sha1Cert(t))
	for _, tok := range []string{"SHA1", "Sha1", "sHa1"} {
		ths, err := ParseThresholds([]string{tok})
		if err != nil {
			t.Fatalf("ParseThresholds(%q): %v", tok, err)
		}
		if len(ths) != 1 || ths[0].Token != "sha1" {
			t.Fatalf("token %q normalized to %+v, want canonical sha1", tok, ths)
		}
		if !Evaluate(g, pqc.Score(g, refNow), ths).Breached() {
			t.Errorf("token %q did not trip", tok)
		}
	}
}

// TestParseErrors: unknown/junk tokens are rejected with a message listing the
// valid tokens; blanks are ignored; repeats are de-duplicated.
func TestParseErrors(t *testing.T) {
	if _, err := ParseThresholds([]string{"not-a-token"}); err == nil {
		t.Error("expected error for junk token")
	} else if !containsAll(err.Error(), "unknown", "sha1", "tls10") {
		t.Errorf("error message %q should name the invalid token and list valid ones", err.Error())
	}

	// Blank and whitespace-only entries are skipped.
	ths, err := ParseThresholds([]string{"", "  ", "sha1"})
	if err != nil {
		t.Fatalf("blank handling errored: %v", err)
	}
	if len(ths) != 1 {
		t.Fatalf("blanks not skipped: got %d thresholds", len(ths))
	}

	// Repeats de-duplicate.
	ths, err = ParseThresholds([]string{"sha1", "SHA1", "sha1"})
	if err != nil {
		t.Fatalf("dedupe errored: %v", err)
	}
	if len(ths) != 1 {
		t.Errorf("repeats not de-duplicated: got %d thresholds", len(ths))
	}

	// Empty input yields no thresholds and no breach.
	ths, _ = ParseThresholds(nil)
	if Evaluate(buildGraph(t, sha1Cert(t)), pqc.Score(buildGraph(t, sha1Cert(t)), refNow), ths).Breached() {
		t.Error("empty threshold set must never breach")
	}
}

// TestDeterminism: the same inputs always yield an identical Result (order and
// content), independent of run.
func TestDeterminism(t *testing.T) {
	g := buildGraph(t, sha1Cert(t), md5Cert(t), rsa1024Cert(t), expiredCert(t))
	tokens := []string{"weak-signature", "rsa1024", "expired"}

	first := evalTokens(t, g, tokens...)
	for i := 0; i < 5; i++ {
		got := evalTokens(t, g, tokens...)
		if !reflect.DeepEqual(first, got) {
			t.Fatalf("non-deterministic Result on run %d:\n first %+v\n got   %+v", i, first, got)
		}
	}
	// Breaches must be sorted by (token, nodeID, detail).
	for i := 1; i < len(first.Breaches); i++ {
		a, b := first.Breaches[i-1], first.Breaches[i]
		if a.Token > b.Token || (a.Token == b.Token && a.NodeID > b.NodeID) {
			t.Errorf("breaches not sorted at %d: %+v before %+v", i, a, b)
		}
	}
}

// TestNilGraph: a nil graph never breaches.
func TestNilGraph(t *testing.T) {
	ths, _ := ParseThresholds([]string{"sha1"})
	if Evaluate(nil, pqc.Report{}, ths).Breached() {
		t.Error("nil graph must not breach")
	}
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		found := false
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
