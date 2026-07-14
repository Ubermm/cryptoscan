package certs

import (
	"path/filepath"
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
