package pqc

import (
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/Ubermm/cryptoscan/internal/graph"
	"github.com/Ubermm/cryptoscan/internal/scan/certs"
	"github.com/Ubermm/cryptoscan/internal/scan/config"
)

// corpusNow is the fixed reference time used for every corpus assertion. It sits
// after the expired fixture's 2021 NotAfter and well before the 2035 NotAfter of
// the valid certs, so `expired` and `expiring` are deterministic (CLAUDE.md /
// DESIGN.md: the library never reads the wall clock).
var corpusNow = time.Date(2026, 7, 14, 0, 0, 0, 0, time.UTC)

// buildCorpusGraph runs both filesystem scanners over testdata/corpus into one
// graph, exactly as a real `cryptoscan fs` invocation would.
func buildCorpusGraph(t *testing.T) *graph.Graph {
	t.Helper()
	root := filepath.Join("..", "..", "testdata", "corpus")
	if _, err := filepath.Abs(root); err != nil {
		t.Fatalf("resolve corpus root: %v", err)
	}
	g := graph.New()
	if _, err := certs.New().ScanIntoGraph(root, g); err != nil {
		t.Fatalf("certs scan: %v", err)
	}
	if _, err := config.ScanIntoGraph(root, g); err != nil {
		t.Fatalf("config scan: %v", err)
	}
	return g
}

// flagCount tallies how many summary Counts a given flag has (0 if absent).
func flagCount(counts []Count, name string) int {
	for _, c := range counts {
		if c.Name == name {
			return c.Count
		}
	}
	return 0
}

// TestScoreCorpusGroundTruth asserts exact, ground-truth-derived counts against
// the known corpus (manifests/certs.yaml, manifests/configs.yaml). The numbers
// are locked, not `> 0`.
func TestScoreCorpusGroundTruth(t *testing.T) {
	g := buildCorpusGraph(t)
	rep := Score(g, corpusNow)
	s := rep.Summary

	// Entity resolution collapses the PEM/DER/keystore copies of each fixture to
	// one node per distinct DER (Certificate) / SPKI (Key): 13 distinct certs and
	// 13 distinct keys in the corpus.
	if got := flagCount(s.ByNodeType, "Certificate"); got != 13 {
		t.Errorf("flagged Certificate nodes = %d, want 13", got)
	}
	if got := flagCount(s.ByNodeType, "Key"); got != 13 {
		t.Errorf("flagged Key nodes = %d, want 13", got)
	}

	// CertificateRequest: the 2 corpus CSRs (rsa-2048.csr = RSA-2048,
	// ecdsa-p256.csr = ECDSA P-256) are now first-class CertificateRequest nodes.
	// Both keys share their SPKI with an existing cert's Key node (entity
	// resolution), so no NEW Key node is added — Key stays 13 — but 2 new
	// CertificateRequest nodes are scored and both are quantum-vulnerable.
	if got := flagCount(s.ByNodeType, "CertificateRequest"); got != 2 {
		t.Errorf("flagged CertificateRequest nodes = %d, want 2", got)
	}

	// quantum_vulnerable: every certificate, key, and CSR in the corpus is RSA/
	// ECDSA/Ed25519 (all Shor-breakable) -> 13 certs + 13 keys + 2 CSRs = 28.
	if got := flagCount(s.ByFlag, FlagQuantumVulnerable); got != 28 {
		t.Errorf("quantum_vulnerable count = %d, want 28", got)
	}
	if s.QuantumVulnerableAssets != 28 {
		t.Errorf("Summary.QuantumVulnerableAssets = %d, want 28", s.QuantumVulnerableAssets)
	}

	// weak_key: only the RSA-1024 fixture is < 2048 bits, flagged on BOTH its
	// Certificate node and its Key node -> 2.
	if got := flagCount(s.ByFlag, FlagWeakKey); got != 2 {
		t.Errorf("weak_key count = %d, want 2", got)
	}

	// weak_signature: the SHA-1 and MD5 certs -> 2.
	if got := flagCount(s.ByFlag, FlagWeakSignature); got != 2 {
		t.Errorf("weak_signature count = %d, want 2", got)
	}

	// expired: only rsa-2048-expired (NotAfter 2021) -> 1; valid 2035 certs not.
	if got := flagCount(s.ByFlag, FlagExpired); got != 1 {
		t.Errorf("expired count = %d, want 1", got)
	}
	if s.Expired != 1 {
		t.Errorf("Summary.Expired = %d, want 1", s.Expired)
	}

	// expiring: no fixture's NotAfter falls inside the 90-day window of corpusNow.
	if got := flagCount(s.ByFlag, FlagExpiring); got != 0 {
		t.Errorf("expiring count = %d, want 0", got)
	}
	if s.Expiring != 0 {
		t.Errorf("Summary.Expiring = %d, want 0", s.Expiring)
	}

	// legacy_protocol: exactly the five sub-TLS-1.2 config fixtures.
	if got := flagCount(s.ByFlag, FlagLegacyProtocol); got != 5 {
		t.Errorf("legacy_protocol count = %d, want 5", got)
	}
	if got := flagCount(s.ByNodeType, "ConfigFile"); got != 5 {
		t.Errorf("flagged ConfigFile nodes = %d, want 5", got)
	}

	// No probe endpoints in an fs-only graph.
	if s.LegacyEndpoints != 0 {
		t.Errorf("Summary.LegacyEndpoints = %d, want 0", s.LegacyEndpoints)
	}
	if s.PQCReadyEndpoints != 0 {
		t.Errorf("Summary.PQCReadyEndpoints = %d, want 0", s.PQCReadyEndpoints)
	}

	if s.FlaggedNodes != len(rep.Nodes) {
		t.Errorf("Summary.FlaggedNodes = %d, want len(Nodes) = %d", s.FlaggedNodes, len(rep.Nodes))
	}
}

// TestCorpusSpecificNodes pins the identity of the flagged nodes, not just the
// counts: the exact certs behind weak_key / weak_signature / expired, and the
// exact set of legacy config files (vs the modern ones that must stay clean).
func TestCorpusSpecificNodes(t *testing.T) {
	g := buildCorpusGraph(t)
	rep := Score(g, corpusNow)

	// Collect flagged labels/paths per flag.
	weakKeyCNs := map[string]bool{}
	weakSigCNs := map[string]bool{}
	expiredCNs := map[string]bool{}
	legacyPaths := map[string]bool{}
	for _, e := range rep.Nodes {
		if e.Flags.WeakKey && e.NodeType == graph.NodeCertificate {
			weakKeyCNs[e.Label] = true
		}
		if e.Flags.WeakSignature {
			weakSigCNs[e.Label] = true
		}
		if e.Flags.Expired {
			expiredCNs[e.Label] = true
		}
		if e.Flags.LegacyProtocol && e.NodeType == graph.NodeConfigFile {
			legacyPaths[e.Label] = true
		}
	}

	if !weakKeyCNs["rsa1024.example.test"] {
		t.Errorf("weak_key: expected rsa1024.example.test flagged, got %v", keys(weakKeyCNs))
	}
	for _, cn := range []string{"rsa2048.example.test", "rsa4096.example.test"} {
		if weakKeyCNs[cn] {
			t.Errorf("weak_key: %s must NOT be flagged (>= 2048)", cn)
		}
	}

	wantSig := map[string]bool{"sha1.example.test": true, "md5.example.test": true}
	if !reflect.DeepEqual(weakSigCNs, wantSig) {
		t.Errorf("weak_signature certs = %v, want %v", keys(weakSigCNs), keys(wantSig))
	}

	wantExpired := map[string]bool{"expired.example.test": true}
	if !reflect.DeepEqual(expiredCNs, wantExpired) {
		t.Errorf("expired certs = %v, want %v", keys(expiredCNs), keys(wantExpired))
	}

	wantLegacy := map[string]bool{
		"configs/nginx/legacy.conf":       true,
		"configs/nginx/multi-server.conf": true,
		"configs/apache/legacy.conf":      true,
		"configs/openssl/legacy.cnf":      true,
		"configs/haproxy/legacy.cfg":      true,
	}
	if !reflect.DeepEqual(legacyPaths, wantLegacy) {
		t.Errorf("legacy configs = %v, want %v", keys(legacyPaths), keys(wantLegacy))
	}

	// The modern config fixtures must be present in the graph AND unflagged.
	modern := []string{
		"configs/nginx/modern.conf",
		"configs/nginx/ssl-params.conf",
		"configs/apache/modern.conf",
		"configs/apache/vhosts.conf",
		"configs/openssl/modern.cnf",
		"configs/haproxy/modern.cfg",
	}
	present := configPaths(g)
	for _, p := range modern {
		if !present[p] {
			t.Errorf("modern config %s not found as a ConfigFile node", p)
		}
		if legacyPaths[p] {
			t.Errorf("modern config %s wrongly flagged legacy_protocol", p)
		}
	}
}

// TestScoreDeterministic verifies Score is a pure function of (graph, now):
// scoring the same graph twice yields identical Reports.
func TestScoreDeterministic(t *testing.T) {
	g := buildCorpusGraph(t)
	a := Score(g, corpusNow)
	b := Score(g, corpusNow)
	if !reflect.DeepEqual(a, b) {
		t.Fatal("Score is not deterministic: two runs differ")
	}
}

// TestScoreReadOnly verifies scoring does not mutate the graph (principle 2).
func TestScoreReadOnly(t *testing.T) {
	g := buildCorpusGraph(t)
	before := g.NodeCount()
	beforeEdges := g.EdgeCount()
	_ = Score(g, corpusNow)
	if g.NodeCount() != before || g.EdgeCount() != beforeEdges {
		t.Errorf("Score mutated the graph: nodes %d->%d, edges %d->%d",
			before, g.NodeCount(), beforeEdges, g.EdgeCount())
	}
}

// configPaths returns the set of ConfigFile node display paths in g.
func configPaths(g *graph.Graph) map[string]bool {
	out := map[string]bool{}
	for _, n := range g.Nodes() {
		if c, ok := n.(*graph.ConfigFileNode); ok {
			out[c.Path] = true
		}
	}
	return out
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
