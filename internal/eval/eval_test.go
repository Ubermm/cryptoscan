package eval

import (
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cryptoscan/cryptoscan/internal/corpus"
	"github.com/cryptoscan/cryptoscan/internal/scan"
)

// --- expectation matcher (DESIGN.md §2 semantics) ---

func TestCheckExpect(t *testing.T) {
	tests := []struct {
		name         string
		expect       corpus.Expect
		attrs        map[string]any
		wantMismatch []string // keys expected to mismatch, in sorted order
	}{
		{
			name:   "scalar exact match",
			expect: corpus.Expect{"subject_cn": "example.com"},
			attrs:  map[string]any{"subject_cn": "example.com"},
		},
		{
			name:         "scalar exact is case-sensitive for non-algorithm keys",
			expect:       corpus.Expect{"subject_cn": "Example.com"},
			attrs:        map[string]any{"subject_cn": "example.com"},
			wantMismatch: []string{"subject_cn"},
		},
		{
			name:   "algorithm name case-insensitive",
			expect: corpus.Expect{"algorithm": "RSA"},
			attrs:  map[string]any{"algorithm": "rsa"},
		},
		{
			name:   "signature_algorithm case-insensitive",
			expect: corpus.Expect{"signature_algorithm": "SHA256-RSA"},
			attrs:  map[string]any{"signature_algorithm": "sha256-rsa"},
		},
		{
			name:         "algorithm value mismatch",
			expect:       corpus.Expect{"algorithm": "RSA"},
			attrs:        map[string]any{"algorithm": "ECDSA"},
			wantMismatch: []string{"algorithm"},
		},
		{
			name:   "numeric int vs int",
			expect: corpus.Expect{"key_size": 2048},
			attrs:  map[string]any{"key_size": 2048},
		},
		{
			name:   "numeric int expect vs float64 attr (YAML decoding tolerance)",
			expect: corpus.Expect{"key_size": 2048},
			attrs:  map[string]any{"key_size": float64(2048)},
		},
		{
			name:   "numeric float expect vs int attr",
			expect: corpus.Expect{"key_size": float64(384)},
			attrs:  map[string]any{"key_size": 384},
		},
		{
			name:         "numeric value mismatch",
			expect:       corpus.Expect{"key_size": 2048},
			attrs:        map[string]any{"key_size": 1024},
			wantMismatch: []string{"key_size"},
		},
		{
			name:         "numeric expect vs non-numeric attr",
			expect:       corpus.Expect{"key_size": 2048},
			attrs:        map[string]any{"key_size": "2048ish"},
			wantMismatch: []string{"key_size"},
		},
		{
			name:         "NaN attr does not match",
			expect:       corpus.Expect{"key_size": 2048},
			attrs:        map[string]any{"key_size": math.NaN()},
			wantMismatch: []string{"key_size"},
		},
		{
			name:   "bool match",
			expect: corpus.Expect{"self_signed": true},
			attrs:  map[string]any{"self_signed": true},
		},
		{
			name:         "bool mismatch",
			expect:       corpus.Expect{"expired": false},
			attrs:        map[string]any{"expired": true},
			wantMismatch: []string{"expired"},
		},
		{
			name:         "bool expect vs string attr",
			expect:       corpus.Expect{"self_signed": true},
			attrs:        map[string]any{"self_signed": "true"},
			wantMismatch: []string{"self_signed"},
		},
		{
			name:   "list exact set match order-insensitive",
			expect: corpus.Expect{"protocols": []any{"TLSv1.2", "TLSv1.3"}},
			attrs:  map[string]any{"protocols": []string{"TLSv1.3", "TLSv1.2"}},
		},
		{
			name:         "list exact set fails on extra element",
			expect:       corpus.Expect{"protocols": []any{"TLSv1.2"}},
			attrs:        map[string]any{"protocols": []string{"TLSv1.2", "TLSv1.3"}},
			wantMismatch: []string{"protocols"},
		},
		{
			name:         "list exact set fails on missing element",
			expect:       corpus.Expect{"protocols": []any{"TLSv1.2", "TLSv1.3"}},
			attrs:        map[string]any{"protocols": []string{"TLSv1.2"}},
			wantMismatch: []string{"protocols"},
		},
		{
			name:         "list exact set respects multiplicity",
			expect:       corpus.Expect{"protocols": []any{"TLSv1.2", "TLSv1.2"}},
			attrs:        map[string]any{"protocols": []string{"TLSv1.2", "TLSv1.3"}},
			wantMismatch: []string{"protocols"},
		},
		{
			name:         "list expect vs scalar attr",
			expect:       corpus.Expect{"protocols": []any{"TLSv1.2"}},
			attrs:        map[string]any{"protocols": "TLSv1.2"},
			wantMismatch: []string{"protocols"},
		},
		{
			name:   "_contains subset passes on superset",
			expect: corpus.Expect{"ciphers_contains": []any{"RC4-SHA"}},
			attrs:  map[string]any{"ciphers": []string{"AES128-SHA", "RC4-SHA", "DES-CBC3-SHA"}},
		},
		{
			name:         "_contains fails when element absent",
			expect:       corpus.Expect{"ciphers_contains": []any{"RC4-SHA", "NULL-MD5"}},
			attrs:        map[string]any{"ciphers": []string{"RC4-SHA"}},
			wantMismatch: []string{"ciphers_contains"},
		},
		{
			name:         "_contains checks the suffix-stripped attr key",
			expect:       corpus.Expect{"ciphers_contains": []any{"RC4-SHA"}},
			attrs:        map[string]any{"ciphers_contains": []string{"RC4-SHA"}}, // wrong key on purpose
			wantMismatch: []string{"ciphers_contains"},
		},
		{
			name:         "_contains vs scalar attr is a mismatch not an error",
			expect:       corpus.Expect{"ciphers_contains": []any{"RC4-SHA"}},
			attrs:        map[string]any{"ciphers": "RC4-SHA"},
			wantMismatch: []string{"ciphers_contains"},
		},
		{
			name:         "declared key missing from attrs",
			expect:       corpus.Expect{"spki_sha256": "abc123"},
			attrs:        map[string]any{},
			wantMismatch: []string{"spki_sha256"},
		},
		{
			name:   "only declared keys checked (extra attrs ignored)",
			expect: corpus.Expect{"algorithm": "RSA"},
			attrs:  map[string]any{"algorithm": "RSA", "key_size": 512, "junk": "x"},
		},
		{
			name:   "empty expect always matches",
			expect: corpus.Expect{},
			attrs:  map[string]any{"anything": "at all"},
		},
		{
			name:         "multiple mismatches reported in sorted key order",
			expect:       corpus.Expect{"key_size": 2048, "algorithm": "RSA"},
			attrs:        map[string]any{"key_size": 1024, "algorithm": "ECDSA"},
			wantMismatch: []string{"algorithm", "key_size"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mm, err := checkExpect(tc.expect, tc.attrs)
			if err != nil {
				t.Fatalf("checkExpect: %v", err)
			}
			var keys []string
			for _, m := range mm {
				keys = append(keys, m.Key)
			}
			if len(keys) != len(tc.wantMismatch) {
				t.Fatalf("mismatched keys = %v, want %v", keys, tc.wantMismatch)
			}
			for i := range keys {
				if keys[i] != tc.wantMismatch[i] {
					t.Errorf("mismatch[%d] = %q, want %q", i, keys[i], tc.wantMismatch[i])
				}
			}
		})
	}
}

func TestCheckExpectMalformedContains(t *testing.T) {
	// `_contains` with a scalar expectation value is malformed (loader rejects
	// nested maps but a scalar `_contains` is a semantic error caught here).
	_, err := checkExpect(corpus.Expect{"ciphers_contains": "RC4-SHA"},
		map[string]any{"ciphers": []string{"RC4-SHA"}})
	if err == nil {
		t.Fatal("expected error for scalar `_contains` expectation, got nil")
	}
}

// --- path normalization ---

func TestNormPath(t *testing.T) {
	tests := []struct{ in, want string }{
		{"certs/rsa.pem", "certs/rsa.pem"},
		{"certs\\rsa.pem", "certs/rsa.pem"},
		{"./certs/rsa.pem", "certs/rsa.pem"},
		{"Certs/RSA.pem", "certs/rsa.pem"},
		{"configs//nginx/legacy.conf", "configs/nginx/legacy.conf"},
	}
	for _, tc := range tests {
		if got := normPath(tc.in); got != tc.want {
			t.Errorf("normPath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// --- scoring (DESIGN.md §3) ---

// testCorpus declares 3 certificates (one inside a keystore via alias), one
// tls_config, and one negative.
func testCorpus(t *testing.T) *corpus.Corpus {
	t.Helper()
	frag := &corpus.Fragment{
		Version: 1,
		Assets: []corpus.Asset{
			{ID: "cert-a", Class: "certificate", Path: "certs/a.pem",
				Expect: corpus.Expect{"algorithm": "RSA", "key_size": 2048}},
			{ID: "cert-b", Class: "certificate", Path: "certs/b.pem",
				Expect: corpus.Expect{"algorithm": "ECDSA", "curve": "P-256"}},
			{ID: "cert-ks", Class: "certificate", Path: "keystores/store.p12", Alias: "server",
				Expect: corpus.Expect{"algorithm": "RSA"}},
			{ID: "nginx-legacy", Class: "tls_config", Path: "configs/nginx/legacy.conf",
				Expect: corpus.Expect{
					"protocols":        []any{"TLSv1", "TLSv1.2"},
					"ciphers_contains": []any{"RC4-SHA"},
				}},
		},
		Negatives: []corpus.Negative{
			{ID: "neg-fake", Path: "negatives/fake.pem"},
		},
	}
	c, err := corpus.Merge(frag)
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	return c
}

func TestScorePerfectScan(t *testing.T) {
	c := testCorpus(t)
	findings := []scan.Finding{
		{Class: "certificate", Path: "certs/a.pem",
			Attrs: map[string]any{"algorithm": "RSA", "key_size": 2048}},
		{Class: "certificate", Path: "certs/b.pem",
			Attrs: map[string]any{"algorithm": "ecdsa", "curve": "P-256"}}, // ci algorithm
		{Class: "certificate", Path: "keystores\\store.p12", Alias: "server", // backslash path
			Attrs: map[string]any{"algorithm": "RSA"}},
		{Class: "tls_config", Path: "configs/nginx/legacy.conf",
			Attrs: map[string]any{
				"protocols": []string{"TLSv1.2", "TLSv1"}, // order-insensitive
				"ciphers":   []string{"RC4-SHA", "AES128-SHA"},
			}},
	}
	sc, err := Score(c, findings, false)
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	if got := sc.Totals; got.TP != 4 || got.FP != 0 || got.FN != 0 {
		t.Fatalf("totals TP/FP/FN = %d/%d/%d, want 4/0/0", got.TP, got.FP, got.FN)
	}
	if sc.Totals.Precision != 1.0 || sc.Totals.Recall != 1.0 || sc.Totals.F1 != 1.0 {
		t.Errorf("totals P/R/F1 = %v/%v/%v, want 1/1/1",
			sc.Totals.Precision, sc.Totals.Recall, sc.Totals.F1)
	}
	if !sc.Gate.Pass {
		t.Error("gate should pass on a perfect scan")
	}
}

func TestScoreAliasDistinguishesFindings(t *testing.T) {
	c := testCorpus(t)
	// Wrong alias: the declared slot has alias "server"; this finding does not
	// match it, so it is an FP and the asset stays an FN.
	findings := []scan.Finding{
		{Class: "certificate", Path: "keystores/store.p12", Alias: "wrong",
			Attrs: map[string]any{"algorithm": "RSA"}},
	}
	sc, err := Score(c, findings, false)
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	certs := classRow(t, sc, "certificate")
	if certs.FP != 1 {
		t.Errorf("certificate FP = %d, want 1 (alias mismatch)", certs.FP)
	}
	if certs.FN != 3 {
		t.Errorf("certificate FN = %d, want 3", certs.FN)
	}
	if len(sc.FalsePositives) != 1 || sc.FalsePositives[0].Alias != "wrong" {
		t.Errorf("false positives = %+v, want single alias=wrong entry", sc.FalsePositives)
	}
}

func TestScoreNegativeDirIsAlwaysFP(t *testing.T) {
	c := testCorpus(t)
	findings := []scan.Finding{
		// Declared negative file.
		{Class: "certificate", Path: "negatives/fake.pem", Attrs: map[string]any{"algorithm": "RSA"}},
		// Undeclared file, but still under negatives/.
		{Class: "tls_config", Path: "negatives\\sneaky.conf", Attrs: map[string]any{}},
	}
	sc, err := Score(c, findings, false)
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	if got := sc.Totals.FP; got != 2 {
		t.Fatalf("totals FP = %d, want 2", got)
	}
	if len(sc.FalsePositives) != 2 {
		t.Fatalf("false positives = %+v, want 2", sc.FalsePositives)
	}
	if !strings.Contains(sc.FalsePositives[0].Detail, "negatives/") ||
		!strings.Contains(sc.FalsePositives[0].Detail, "neg-fake") {
		t.Errorf("declared negative FP detail = %q, want mention of negatives/ and neg-fake",
			sc.FalsePositives[0].Detail)
	}
}

func TestScoreMismatchIsFNWithDetail(t *testing.T) {
	c := testCorpus(t)
	findings := []scan.Finding{
		{Class: "certificate", Path: "certs/a.pem",
			Attrs: map[string]any{"algorithm": "RSA", "key_size": 1024}}, // wrong key_size
	}
	sc, err := Score(c, findings, false)
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	certs := classRow(t, sc, "certificate")
	if certs.TP != 0 || certs.FP != 0 || certs.FN != 3 {
		t.Fatalf("certificate TP/FP/FN = %d/%d/%d, want 0/0/3", certs.TP, certs.FP, certs.FN)
	}
	var withMismatch *FalseNegative
	for i := range sc.FalseNegatives {
		if sc.FalseNegatives[i].ID == "cert-a" {
			withMismatch = &sc.FalseNegatives[i]
		}
	}
	if withMismatch == nil || withMismatch.NotFound() {
		t.Fatalf("cert-a should be an FN with mismatches, got %+v", sc.FalseNegatives)
	}
	m := withMismatch.Mismatches[0]
	if m.Key != "key_size" || m.Expected != "2048" || m.Got != "1024" {
		t.Errorf("mismatch = %+v, want key_size expected 2048 got 1024", m)
	}
}

func TestScoreZeroFindingsPhase0(t *testing.T) {
	// Phase 0 reality: no scanners registered, zero findings. Recall is 0 for
	// classes with declared assets, precision is 1.0 (no false claims), gate
	// passes non-strict and fails strict.
	c := testCorpus(t)

	sc, err := Score(c, nil, false)
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	certs := classRow(t, sc, "certificate")
	if certs.Precision != 1.0 || certs.Recall != 0.0 || certs.F1 != 0.0 {
		t.Errorf("certificate P/R/F1 = %v/%v/%v, want 1/0/0", certs.Precision, certs.Recall, certs.F1)
	}
	if !sc.Gate.Pass {
		t.Error("non-strict gate must pass with zero findings")
	}
	if len(sc.FalseNegatives) != 4 {
		t.Errorf("false negatives = %d, want 4 (all declared assets)", len(sc.FalseNegatives))
	}

	strictSc, err := Score(c, nil, true)
	if err != nil {
		t.Fatalf("Score strict: %v", err)
	}
	if strictSc.Gate.Pass {
		t.Error("strict gate must fail on recall shortfall")
	}
	if len(strictSc.Gate.RecallShortfalls) == 0 {
		t.Error("strict gate should list recall shortfalls")
	}
	if len(strictSc.Gate.PrecisionViolations) != 0 {
		t.Errorf("no precision violations expected, got %v", strictSc.Gate.PrecisionViolations)
	}
}

func TestScorePrecisionGate(t *testing.T) {
	c := testCorpus(t)
	// One TP + one FP for certificate → precision 0.5 < 0.95 → gate fails.
	findings := []scan.Finding{
		{Class: "certificate", Path: "certs/a.pem",
			Attrs: map[string]any{"algorithm": "RSA", "key_size": 2048}},
		{Class: "certificate", Path: "certs/undeclared.pem",
			Attrs: map[string]any{"algorithm": "RSA"}},
	}
	sc, err := Score(c, findings, false)
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	if sc.Gate.Pass {
		t.Fatal("gate should fail at precision 0.5")
	}
	if len(sc.Gate.PrecisionViolations) != 1 ||
		!strings.Contains(sc.Gate.PrecisionViolations[0], "certificate") {
		t.Errorf("precision violations = %v, want one for certificate", sc.Gate.PrecisionViolations)
	}
}

func TestScoreFPOnlyClassDoesNotGate(t *testing.T) {
	// A class with zero declared assets can never gate (DESIGN.md §3 gates
	// only classes with declared assets), but its FPs still appear.
	c := testCorpus(t)
	findings := []scan.Finding{
		{Class: "csr", Path: "keys/undeclared.csr", Attrs: map[string]any{}},
	}
	sc, err := Score(c, findings, false)
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	if !sc.Gate.Pass {
		t.Error("gate must ignore classes without declared assets")
	}
	row := classRow(t, sc, "csr")
	if row.Expected != 0 || row.FP != 1 || row.Precision != 0.0 {
		t.Errorf("csr row = %+v, want expected 0, FP 1, precision 0", row)
	}
}

func TestScoreDuplicateFindingsForOneSlotCountOnce(t *testing.T) {
	c := testCorpus(t)
	findings := []scan.Finding{
		{Class: "certificate", Path: "certs/a.pem",
			Attrs: map[string]any{"algorithm": "RSA", "key_size": 2048}},
		{Class: "certificate", Path: "CERTS/A.PEM", // same slot, different case
			Attrs: map[string]any{"algorithm": "RSA", "key_size": 2048}},
	}
	sc, err := Score(c, findings, false)
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	certs := classRow(t, sc, "certificate")
	if certs.TP != 1 || certs.FP != 0 {
		t.Errorf("certificate TP/FP = %d/%d, want 1/0 (dedupe same slot)", certs.TP, certs.FP)
	}
	if certs.Found != 2 {
		t.Errorf("certificate Found = %d, want 2 (raw findings)", certs.Found)
	}
}

func TestScoreRejectsDuplicateSlots(t *testing.T) {
	frag := &corpus.Fragment{Version: 1, Assets: []corpus.Asset{
		{ID: "a", Class: "certificate", Path: "certs/x.pem"},
		{ID: "b", Class: "certificate", Path: "certs\\X.PEM"}, // same normalized slot
	}}
	c, err := corpus.Merge(frag)
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	if _, err := Score(c, nil, false); err == nil {
		t.Fatal("expected duplicate-slot error, got nil")
	}
}

func TestScoreNilCorpus(t *testing.T) {
	if _, err := Score(nil, nil, false); err == nil {
		t.Fatal("expected error for nil corpus, got nil")
	}
}

func classRow(t *testing.T, sc *Scorecard, class string) ClassScore {
	t.Helper()
	for _, r := range sc.Classes {
		if r.Class == class {
			return r
		}
	}
	t.Fatalf("class %q not in scorecard: %+v", class, sc.Classes)
	return ClassScore{}
}

// --- fake scanner against a synthetic temp-dir corpus ---

type scriptedScanner struct {
	name     string
	findings []scan.Finding
}

func (s scriptedScanner) Name() string                        { return s.name }
func (s scriptedScanner) Scan(string) ([]scan.Finding, error) { return s.findings, nil }

func TestFakeScannerOnTempDirCorpus(t *testing.T) {
	root := t.TempDir()
	manifests := filepath.Join(root, "manifests")
	if err := os.MkdirAll(manifests, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(manifests, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("certs.yaml", `version: 1
assets:
  - id: cert-good
    class: certificate
    path: certs/good.pem
    expect:
      algorithm: RSA
      key_size: 2048
      self_signed: true
  - id: cert-missed
    class: certificate
    path: certs/missed.pem
    expect:
      algorithm: ECDSA
  - id: cert-wrong-field
    class: certificate
    path: certs/wrong.pem
    expect:
      algorithm: RSA
      key_size: 4096
  - id: ks-entry
    class: private_key
    path: keystores/store.p12
    alias: server
    expect:
      algorithm: RSA
`)
	write("configs.yaml", `version: 1
assets:
  - id: nginx-legacy
    class: tls_config
    path: configs/nginx/legacy.conf
    expect:
      protocols: [TLSv1, TLSv1.2]
      ciphers_contains: ["RC4-SHA"]
`)
	write("negatives.yaml", `version: 1
negatives:
  - id: neg-1
    path: negatives/fake.pem
`)

	c, err := corpus.LoadDir(root)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}

	fake := scriptedScanner{name: "fake", findings: []scan.Finding{
		// TP: everything matches.
		{Class: "certificate", Path: "certs/good.pem",
			Attrs: map[string]any{"algorithm": "rsa", "key_size": float64(2048), "self_signed": true}},
		// FN-with-mismatch: found but key_size is wrong.
		{Class: "certificate", Path: "certs/wrong.pem",
			Attrs: map[string]any{"algorithm": "RSA", "key_size": 2048}},
		// TP via container alias.
		{Class: "private_key", Path: "keystores/store.p12", Alias: "server",
			Attrs: map[string]any{"algorithm": "RSA"}},
		// TP tls_config: exact set + subset.
		{Class: "tls_config", Path: "configs/nginx/legacy.conf",
			Attrs: map[string]any{
				"protocols": []string{"TLSv1.2", "TLSv1"},
				"ciphers":   []string{"RC4-SHA", "AES256-SHA"},
			}},
		// FP: negative fixture.
		{Class: "certificate", Path: "negatives/fake.pem",
			Attrs: map[string]any{"algorithm": "RSA"}},
		// FP: undeclared path.
		{Class: "tls_config", Path: "configs/nginx/undeclared.conf", Attrs: map[string]any{}},
		// cert-missed is never reported -> plain FN.
	}}

	findings, err := fake.Scan(root)
	if err != nil {
		t.Fatalf("fake.Scan: %v", err)
	}
	sc, err := Score(c, findings, false)
	if err != nil {
		t.Fatalf("Score: %v", err)
	}

	// certificate: expected 3, found 3 (good, wrong, negative-FP), TP 1,
	// FP 1 (negatives/fake.pem), FN 2 (missed + wrong-field).
	cert := classRow(t, sc, "certificate")
	if cert.Expected != 3 || cert.Found != 3 || cert.TP != 1 || cert.FP != 1 || cert.FN != 2 {
		t.Errorf("certificate row = %+v, want expected 3, found 3, TP 1, FP 1, FN 2", cert)
	}
	if cert.Precision != 0.5 {
		t.Errorf("certificate precision = %v, want 0.5", cert.Precision)
	}
	if want := 1.0 / 3.0; math.Abs(cert.Recall-want) > 1e-12 {
		t.Errorf("certificate recall = %v, want %v", cert.Recall, want)
	}
	if wantF1 := 2 * 0.5 * (1.0 / 3.0) / (0.5 + 1.0/3.0); math.Abs(cert.F1-wantF1) > 1e-12 {
		t.Errorf("certificate F1 = %v, want %v", cert.F1, wantF1)
	}

	pk := classRow(t, sc, "private_key")
	if pk.TP != 1 || pk.FP != 0 || pk.FN != 0 || pk.Precision != 1.0 || pk.Recall != 1.0 {
		t.Errorf("private_key row = %+v, want perfect 1/0/0", pk)
	}

	tls := classRow(t, sc, "tls_config")
	if tls.TP != 1 || tls.FP != 1 || tls.FN != 0 {
		t.Errorf("tls_config row = %+v, want TP 1, FP 1, FN 0", tls)
	}

	if sc.Totals.TP != 3 || sc.Totals.FP != 2 || sc.Totals.FN != 2 {
		t.Errorf("totals TP/FP/FN = %d/%d/%d, want 3/2/2",
			sc.Totals.TP, sc.Totals.FP, sc.Totals.FN)
	}

	// Both certificate (0.5) and tls_config (0.5) violate the precision gate.
	if sc.Gate.Pass {
		t.Error("gate should fail")
	}
	if len(sc.Gate.PrecisionViolations) != 2 {
		t.Errorf("precision violations = %v, want 2", sc.Gate.PrecisionViolations)
	}
}
