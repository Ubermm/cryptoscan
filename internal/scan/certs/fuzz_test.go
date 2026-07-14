package certs

import (
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

// seedFiles reads every file under the given corpus subdirectories, returning
// their raw bytes for use as fuzz seeds.
func seedFiles(t *testing.T, subdirs ...string) [][]byte {
	t.Helper()
	var out [][]byte
	for _, sub := range subdirs {
		dir := filepath.Join(corpusRoot(), sub)
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			b, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err == nil {
				out = append(out, b)
			}
		}
	}
	return out
}

// runOnBytes writes data to a temp file and scans it, asserting only that the
// scanner does not panic and does not error. It is the shared fuzz body.
func runOnBytes(t *testing.T, name string, data []byte) {
	t.Helper()
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, name), data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := New().Scan(tmp); err != nil {
		t.Fatalf("scan errored on fuzz input: %v", err)
	}
}

// FuzzPEM feeds arbitrary bytes through the PEM path. Seeds: every corpus PEM
// plus the intentionally-broken fake-cert.pem and truncated.pem. Invariant: no
// panic, no error (malformed input just yields no finding).
func FuzzPEM(f *testing.F) {
	for _, b := range seedFiles(&testing.T{}, "certs", "keys", "negatives") {
		f.Add(b)
	}
	// Ensure the two broken PEM fixtures are seeded even if the helper above is
	// skipped for any reason.
	for _, name := range []string{"fake-cert.pem", "truncated.pem"} {
		if b, err := os.ReadFile(filepath.Join(corpusRoot(), "negatives", name)); err == nil {
			f.Add(b)
		}
	}
	f.Add([]byte("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n"))
	f.Add([]byte(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{0x30, 0x00}})))

	f.Fuzz(func(t *testing.T, data []byte) {
		runOnBytes(t, "fuzz.pem", data)
	})
}

// FuzzDER feeds arbitrary bytes through the binary/DER path. Seeds: the real
// .der certs plus notreallyder.der. Invariant: no panic, no error.
func FuzzDER(f *testing.F) {
	// Real DER certs.
	dir := filepath.Join(corpusRoot(), "certs")
	if entries, err := os.ReadDir(dir); err == nil {
		for _, e := range entries {
			if filepath.Ext(e.Name()) == ".der" {
				if b, err := os.ReadFile(filepath.Join(dir, e.Name())); err == nil {
					f.Add(b)
				}
			}
		}
	}
	if b, err := os.ReadFile(filepath.Join(corpusRoot(), "negatives", "notreallyder.der")); err == nil {
		f.Add(b)
	}
	f.Add([]byte{0x30, 0x82, 0x01, 0x00})
	f.Add([]byte{0x30, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		runOnBytes(t, "fuzz.der", data)
	})
}
