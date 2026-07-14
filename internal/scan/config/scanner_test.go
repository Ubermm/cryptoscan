package config

import (
	"path/filepath"
	"testing"

	"github.com/Ubermm/cryptoscan/internal/corpus"
	"github.com/Ubermm/cryptoscan/internal/eval"
	"github.com/Ubermm/cryptoscan/internal/graph"
)

// corpusRoot is the repo corpus relative to this package (internal/scan/config).
const corpusRoot = "../../../testdata/corpus"

// TestIntegrationScorecard is the Definition-of-Done gate: scoring this
// scanner's findings against the ground-truth corpus must yield perfect
// precision and recall for tls_config (12/12) and ssh_config (3/3), with zero
// false positives anywhere (including negatives/ and the cert-side classes).
func TestIntegrationScorecard(t *testing.T) {
	c, err := corpus.LoadDir(corpusRoot)
	if err != nil {
		t.Fatalf("load corpus: %v", err)
	}

	findings, err := Scanner{}.Scan(corpusRoot)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	// Non-strict scoring: the ship gate is precision-only (DESIGN.md §3). The
	// cert-side classes score recall 0 here because only THIS scanner runs (the
	// certs scanner is a sibling); that is expected and not our concern. Our
	// contract is: tls_config and ssh_config perfect, and zero false positives
	// anywhere — including negatives/ and every cert/key file.
	sc, err := eval.Score(c, findings, false)
	if err != nil {
		t.Fatalf("score: %v", err)
	}

	if len(sc.FalsePositives) != 0 {
		for _, fp := range sc.FalsePositives {
			t.Errorf("false positive: class=%s path=%s detail=%s", fp.Class, fp.Path, fp.Detail)
		}
	}

	want := map[string]struct{ tp, expected int }{
		"tls_config": {12, 12},
		"ssh_config": {3, 3},
	}
	seen := map[string]bool{}
	for _, row := range sc.Classes {
		w, ok := want[row.Class]
		if !ok {
			// Any class we do not own must carry zero findings and thus zero FPs
			// from this scanner.
			if row.FP != 0 {
				t.Errorf("class %s: %d false positives from config scanner", row.Class, row.FP)
			}
			continue
		}
		seen[row.Class] = true
		if row.TP != w.tp || row.Expected != w.expected {
			t.Errorf("%s: TP=%d Expected=%d, want TP=%d Expected=%d", row.Class, row.TP, row.Expected, w.tp, w.expected)
		}
		if row.FP != 0 {
			t.Errorf("%s: FP=%d, want 0", row.Class, row.FP)
		}
		if row.Precision != 1.0 {
			t.Errorf("%s: precision=%.3f, want 1.000", row.Class, row.Precision)
		}
		if row.Recall != 1.0 {
			t.Errorf("%s: recall=%.3f, want 1.000", row.Class, row.Recall)
		}
	}
	for class := range want {
		if !seen[class] {
			t.Errorf("class %s never appeared in scorecard", class)
		}
	}

	// Report tls_config/ssh_config false negatives only (ours to answer for).
	for _, fn := range sc.FalseNegatives {
		if fn.Class == "tls_config" || fn.Class == "ssh_config" {
			t.Errorf("false negative: id=%s class=%s path=%s mismatches=%v", fn.ID, fn.Class, fn.Path, fn.Mismatches)
		}
	}
	if !sc.Gate.Pass {
		t.Errorf("precision gate did not pass: %+v", sc.Gate)
	}
}

// TestScanIntoGraphMatchesScan verifies the graph variant returns identical
// findings and populates ConfigFile nodes + references edges with resolved paths.
func TestScanIntoGraphMatchesScan(t *testing.T) {
	g := graph.New()
	findings, err := ScanIntoGraph(corpusRoot, g)
	if err != nil {
		t.Fatalf("ScanIntoGraph: %v", err)
	}
	plain, err := Scanner{}.Scan(corpusRoot)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(findings) != len(plain) {
		t.Fatalf("ScanIntoGraph returned %d findings, Scan returned %d", len(findings), len(plain))
	}

	// nginx/legacy.conf must reference certs/rsa-2048-selfsigned.pem via a
	// relative ref resolved against the config's directory.
	legacyID, err := graph.FileNodeID(filepath.Join(corpusRoot, "configs/nginx/legacy.conf"))
	if err != nil {
		t.Fatalf("FileNodeID: %v", err)
	}
	certID, err := graph.FileNodeID(filepath.Join(corpusRoot, "certs/rsa-2048-selfsigned.pem"))
	if err != nil {
		t.Fatalf("FileNodeID cert: %v", err)
	}

	found := false
	for _, e := range g.Edges() {
		if e.Type == graph.EdgeReferences && e.From == legacyID && e.To == certID {
			found = true
			if len(e.Provenance) == 0 || e.Provenance[0].Line == 0 {
				t.Errorf("references edge missing line provenance: %+v", e.Provenance)
			}
		}
	}
	if !found {
		t.Errorf("expected references edge nginx/legacy.conf -> certs/rsa-2048-selfsigned.pem")
	}

	// The referenced cert file must exist as a node with a cleaned relative path.
	if n, ok := g.Node(certID); ok {
		cf, ok := n.(*graph.ConfigFileNode)
		if !ok {
			t.Fatalf("cert node is %T, want *ConfigFileNode", n)
		}
		if cf.Path != "certs/rsa-2048-selfsigned.pem" {
			t.Errorf("referenced node path = %q, want certs/rsa-2048-selfsigned.pem", cf.Path)
		}
	} else {
		t.Errorf("referenced cert node not found")
	}
}
