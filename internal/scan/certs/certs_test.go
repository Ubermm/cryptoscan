package certs

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/cryptoscan/cryptoscan/internal/corpus"
	"github.com/cryptoscan/cryptoscan/internal/eval"
	"github.com/cryptoscan/cryptoscan/internal/graph"
)

// corpusRoot is the repo's ground-truth corpus, four levels up from this
// package (internal/scan/certs -> repo root).
func corpusRoot() string {
	return filepath.Join("..", "..", "..", "testdata", "corpus")
}

// TestEvalScorecard is the definition-of-done check: run the scanner against the
// corpus and assert the cert-side classes score precision 1.0 AND recall 1.0.
func TestEvalScorecard(t *testing.T) {
	root := corpusRoot()
	c, err := corpus.LoadDir(root)
	if err != nil {
		t.Fatalf("load corpus: %v", err)
	}

	findings, err := New().Scan(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	sc, err := eval.Score(c, findings, true)
	if err != nil {
		t.Fatalf("score: %v", err)
	}

	// Classes this scanner owns.
	want := map[string]bool{
		"certificate": true,
		"private_key": true,
		"public_key":  true,
		"csr":         true,
	}
	seen := map[string]bool{}
	for _, row := range sc.Classes {
		if !want[row.Class] {
			continue
		}
		seen[row.Class] = true
		if row.Precision != 1.0 || row.Recall != 1.0 {
			t.Errorf("class %s: precision=%.3f recall=%.3f (want 1.000/1.000); tp=%d fp=%d fn=%d",
				row.Class, row.Precision, row.Recall, row.TP, row.FP, row.FN)
		} else {
			t.Logf("class %-12s precision=%.3f recall=%.3f (tp=%d fp=%d fn=%d, found=%d)",
				row.Class, row.Precision, row.Recall, row.TP, row.FP, row.FN, row.Found)
		}
	}
	for cls := range want {
		if !seen[cls] {
			t.Errorf("class %s not present in scorecard", cls)
		}
	}

	// No false positives at all (includes everything under negatives/).
	for _, fp := range sc.FalsePositives {
		if want[fp.Class] {
			t.Errorf("false positive: class=%s path=%s alias=%s (%s)", fp.Class, fp.Path, fp.Alias, fp.Detail)
		}
	}
	// No false negatives in owned classes.
	for _, fn := range sc.FalseNegatives {
		if want[fn.Class] {
			t.Errorf("false negative: id=%s class=%s path=%s alias=%s mismatches=%v", fn.ID, fn.Class, fn.Path, fn.Alias, fn.Mismatches)
		}
	}
}

// TestNegativesSilent asserts the scanner reports nothing at all for any file
// under negatives/ (DESIGN.md §3: anything there is a false positive).
func TestNegativesSilent(t *testing.T) {
	root := corpusRoot()
	findings, err := New().Scan(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	for _, f := range findings {
		if hasNegativePrefix(f.Path) {
			t.Errorf("finding under negatives/: class=%s path=%s alias=%s", f.Class, f.Path, f.Alias)
		}
	}
}

func hasNegativePrefix(p string) bool {
	return p == "negatives" || len(p) >= len("negatives/") && p[:len("negatives/")] == "negatives/"
}

// TestScanIntoGraphCSR checks that a parsed CSR becomes a first-class
// CertificateRequest node (DESIGN.md §1): the node exists with its attributes,
// signs_with links it to a Key node, stored_in links it to its file, and the flat
// csr Finding (the eval contract) is unchanged.
func TestScanIntoGraphCSR(t *testing.T) {
	root := corpusRoot()
	g := graph.New()
	findings, err := New().ScanIntoGraph(root, g)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	// The flat Finding contract must be untouched: 2 csr findings, class "csr",
	// carrying algorithm/key_size/subject_cn (never mutated into a node-only shape).
	var csrFindings int
	for _, f := range findings {
		if f.Class == "csr" {
			csrFindings++
			if f.Attrs["algorithm"] == nil || f.Attrs["subject_cn"] == nil {
				t.Errorf("csr finding at %s missing algorithm/subject_cn attrs: %v", f.Path, f.Attrs)
			}
		}
	}
	if csrFindings != 2 {
		t.Errorf("csr findings = %d, want 2", csrFindings)
	}

	// Collect CertificateRequest nodes and index Key node IDs.
	var csrNodes []*graph.CertificateRequestNode
	keyIDs := map[string]bool{}
	for _, n := range g.Nodes() {
		switch v := n.(type) {
		case *graph.CertificateRequestNode:
			csrNodes = append(csrNodes, v)
		case *graph.KeyNode:
			keyIDs[v.ID()] = true
		}
	}
	if len(csrNodes) != 2 {
		t.Fatalf("CertificateRequest nodes = %d, want 2", len(csrNodes))
	}
	for _, c := range csrNodes {
		if c.SPKISHA256 == "" || c.Algorithm == "" || c.Subject == "" {
			t.Errorf("CSR node %s missing attrs: %+v", c.ID(), c)
		}
		if len(c.Provenance()) == 0 {
			t.Errorf("CSR node %s has no provenance", c.ID())
		}
	}

	// Every CSR node must have a signs_with edge to a real Key node and a
	// stored_in edge to a file node.
	signsWith := map[string]string{}
	storedIn := map[string]bool{}
	for _, e := range g.Edges() {
		if !strings.HasPrefix(e.From, "csr:") {
			continue
		}
		switch e.Type {
		case graph.EdgeSignsWith:
			signsWith[e.From] = e.To
		case graph.EdgeStoredIn:
			storedIn[e.From] = true
		}
	}
	for _, c := range csrNodes {
		to, ok := signsWith[c.ID()]
		if !ok {
			t.Errorf("CSR %s has no signs_with edge", c.ID())
		} else if !keyIDs[to] {
			t.Errorf("CSR %s signs_with %s, which is not a Key node", c.ID(), to)
		}
		if !storedIn[c.ID()] {
			t.Errorf("CSR %s has no stored_in edge", c.ID())
		}
	}
}

// TestScanIntoGraphPopulates checks the graph projection: every certificate and
// key finding produces the expected node types and edges.
func TestScanIntoGraphPopulates(t *testing.T) {
	root := corpusRoot()
	g := graph.New()
	findings, err := New().ScanIntoGraph(root, g)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("no findings")
	}

	var certNodes, keyNodes, caNodes int
	for _, n := range g.Nodes() {
		switch n.Type() {
		case graph.NodeCertificate:
			certNodes++
		case graph.NodeKey:
			keyNodes++
		case graph.NodeCA:
			caNodes++
		}
		if len(n.Provenance()) == 0 {
			t.Errorf("node %s has no provenance", n.ID())
		}
	}
	if certNodes == 0 || keyNodes == 0 || caNodes == 0 {
		t.Errorf("graph missing node types: certs=%d keys=%d cas=%d", certNodes, keyNodes, caNodes)
	}

	var signsWith, storedIn, issuedBy int
	for _, e := range g.Edges() {
		switch e.Type {
		case graph.EdgeSignsWith:
			signsWith++
		case graph.EdgeStoredIn:
			storedIn++
		case graph.EdgeIssuedBy:
			issuedBy++
		}
		if len(e.Provenance) == 0 {
			t.Errorf("edge %s %s->%s has no provenance", e.Type, e.From, e.To)
		}
	}
	if signsWith == 0 || storedIn == 0 || issuedBy == 0 {
		t.Errorf("graph missing edge types: signs_with=%d stored_in=%d issued_by=%d", signsWith, storedIn, issuedBy)
	}

	// The 3-level chain: leaf's issuer cert (intermediate) is observed, so the
	// leaf must have an observed CA edge to a ca:<sha> node, not a ca:dn: node.
	var observedCA bool
	for _, n := range g.Nodes() {
		if ca, ok := n.(*graph.CANode); ok && ca.Observed {
			observedCA = true
		}
	}
	if !observedCA {
		t.Error("expected at least one observed CA node (leaf/intermediate chain)")
	}
}
