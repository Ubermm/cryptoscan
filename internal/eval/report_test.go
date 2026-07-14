package eval

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/Ubermm/cryptoscan/internal/corpus"
	"github.com/Ubermm/cryptoscan/internal/scan"
)

var update = flag.Bool("update", false, "rewrite golden files with current output")

// goldenScorecard produces a scorecard exercising every table section: TPs,
// an alias FP, a negatives FP, an FN with mismatches, a plain not-found FN,
// and a failing gate.
func goldenScorecard(t *testing.T) *Scorecard {
	t.Helper()
	frag := &corpus.Fragment{
		Version: 1,
		Assets: []corpus.Asset{
			{ID: "cert-rsa", Class: "certificate", Path: "certs/rsa.pem",
				Expect: corpus.Expect{"algorithm": "RSA", "key_size": 2048}},
			{ID: "cert-weak", Class: "certificate", Path: "certs/weak.pem",
				Expect: corpus.Expect{"algorithm": "RSA", "key_size": 1024, "self_signed": true}},
			{ID: "cert-missing", Class: "certificate", Path: "certs/missing.pem",
				Expect: corpus.Expect{"algorithm": "Ed25519"}},
			{ID: "ks-cert", Class: "certificate", Path: "keystores/store.jks", Alias: "trust",
				Expect: corpus.Expect{"algorithm": "ECDSA"}},
			{ID: "nginx-legacy", Class: "tls_config", Path: "configs/nginx/legacy.conf",
				Expect: corpus.Expect{
					"protocols":        []any{"TLSv1", "TLSv1.2"},
					"ciphers_contains": []any{"RC4-SHA"},
				}},
			{ID: "sshd-legacy", Class: "ssh_config", Path: "configs/ssh/sshd_config",
				Expect: corpus.Expect{"host_key_types": []any{"rsa", "dsa"}}},
		},
		Negatives: []corpus.Negative{{ID: "neg-fake", Path: "negatives/fake.pem"}},
	}
	c, err := corpus.Merge(frag)
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	c.Root = "testdata/corpus"

	findings := []scan.Finding{
		{Class: "certificate", Path: "certs/rsa.pem",
			Attrs: map[string]any{"algorithm": "RSA", "key_size": 2048}},
		{Class: "certificate", Path: "certs/weak.pem", // mismatched key_size + self_signed
			Attrs: map[string]any{"algorithm": "RSA", "key_size": 2048, "self_signed": false}},
		{Class: "certificate", Path: "keystores/store.jks", Alias: "trust",
			Attrs: map[string]any{"algorithm": "ECDSA"}},
		{Class: "certificate", Path: "negatives/fake.pem", // FP under negatives/
			Attrs: map[string]any{"algorithm": "RSA"}},
		{Class: "tls_config", Path: "configs/nginx/legacy.conf",
			Attrs: map[string]any{
				"protocols": []string{"TLSv1", "TLSv1.2"},
				"ciphers":   []string{"RC4-SHA", "AES128-SHA"},
			}},
		{Class: "tls_config", Path: "configs/nginx/rogue.conf", // undeclared FP
			Attrs: map[string]any{}},
		// sshd-legacy and cert-missing are never found.
	}

	sc, err := Score(c, findings, false)
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	return sc
}

func TestWriteTableGolden(t *testing.T) {
	sc := goldenScorecard(t)

	var buf bytes.Buffer
	if err := sc.WriteTable(&buf); err != nil {
		t.Fatalf("WriteTable: %v", err)
	}
	compareGolden(t, filepath.Join("testdata", "golden", "scorecard.txt"), buf.Bytes())
}

func TestWriteJSONGolden(t *testing.T) {
	sc := goldenScorecard(t)

	var buf bytes.Buffer
	if err := sc.WriteJSON(&buf); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	// The JSON must be valid and decode back to the same shape.
	var round Scorecard
	if err := json.Unmarshal(buf.Bytes(), &round); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if round.Totals != sc.Totals {
		t.Errorf("round-tripped totals = %+v, want %+v", round.Totals, sc.Totals)
	}
	compareGolden(t, filepath.Join("testdata", "golden", "scorecard.json"), buf.Bytes())
}

// compareGolden compares got with the golden file, rewriting it under -update.
// Comparison is newline-normalized so checkouts with CRLF translation still
// pass.
func compareGolden(t *testing.T, path string, got []byte) {
	t.Helper()
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s (run `go test ./internal/eval -update` to create): %v", path, err)
	}
	norm := func(b []byte) string { return string(bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))) }
	if norm(got) != norm(want) {
		t.Errorf("output differs from golden %s\n--- got ---\n%s\n--- want ---\n%s", path, got, want)
	}
}
