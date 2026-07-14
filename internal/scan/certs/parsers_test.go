package certs

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Ubermm/cryptoscan/internal/scan"
)

// scanCorpus runs the scanner once and indexes findings by (class, path, alias)
// for assertion.
func scanCorpus(t *testing.T) map[string]scan.Finding {
	t.Helper()
	findings, err := New().Scan(corpusRoot())
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	m := make(map[string]scan.Finding, len(findings))
	for _, f := range findings {
		m[f.Class+"|"+f.Path+"|"+f.Alias] = f
	}
	return m
}

// TestPerAssetAttributes spot-checks representative assets across every parser
// path (PEM cert, DER cert, keys, CSR, keystores) for the attributes the
// manifest keys on.
func TestPerAssetAttributes(t *testing.T) {
	m := scanCorpus(t)

	cases := []struct {
		name  string
		key   string
		attrs map[string]any
	}{
		{
			name:  "PEM RSA self-signed",
			key:   "certificate|certs/rsa-2048-selfsigned.pem|",
			attrs: map[string]any{"algorithm": "RSA", "key_size": 2048, "signature_algorithm": "SHA256-RSA", "self_signed": true, "expired": false, "subject_cn": "rsa2048.example.test"},
		},
		{
			name:  "PEM expired",
			key:   "certificate|certs/rsa-2048-expired.pem|",
			attrs: map[string]any{"expired": true, "self_signed": true},
		},
		{
			name:  "PEM SHA1 signature",
			key:   "certificate|certs/rsa-2048-sha1.pem|",
			attrs: map[string]any{"signature_algorithm": "SHA1-RSA"},
		},
		{
			name:  "PEM MD5 signature",
			key:   "certificate|certs/rsa-2048-md5.pem|",
			attrs: map[string]any{"signature_algorithm": "MD5-RSA"},
		},
		{
			name:  "PEM ECDSA P-384",
			key:   "certificate|certs/ecdsa-p384.pem|",
			attrs: map[string]any{"algorithm": "ECDSA", "key_size": 384, "curve": "P-384", "signature_algorithm": "ECDSA-SHA384"},
		},
		{
			name:  "PEM Ed25519",
			key:   "certificate|certs/ed25519.pem|",
			attrs: map[string]any{"algorithm": "Ed25519", "key_size": 256, "signature_algorithm": "Ed25519"},
		},
		{
			name:  "DER cert",
			key:   "certificate|certs/rsa-2048-selfsigned.der|",
			attrs: map[string]any{"algorithm": "RSA", "key_size": 2048, "self_signed": true},
		},
		{
			name:  "chain leaf alias 0",
			key:   "certificate|certs/leaf-chain.pem|0",
			attrs: map[string]any{"subject_cn": "example.test", "self_signed": false},
		},
		{
			name:  "chain intermediate alias 1",
			key:   "certificate|certs/leaf-chain.pem|1",
			attrs: map[string]any{"subject_cn": "cryptoscan Test Intermediate CA", "self_signed": false},
		},
		{
			name:  "single-cert file has empty alias",
			key:   "certificate|certs/leaf.pem|",
			attrs: map[string]any{"subject_cn": "example.test"},
		},
		{
			name:  "PKCS1 private key",
			key:   "private_key|keys/rsa-2048.key|",
			attrs: map[string]any{"algorithm": "RSA", "key_size": 2048, "spki_sha256": "02baa34fee27de0a122887f422fd2172bbc986f2f916df715356cbaaa58aae04"},
		},
		{
			name:  "PKCS8 EC private key",
			key:   "private_key|keys/ecdsa-p256-pkcs8.key|",
			attrs: map[string]any{"algorithm": "ECDSA", "key_size": 256, "curve": "P-256"},
		},
		{
			name:  "Ed25519 private key",
			key:   "private_key|keys/ed25519.key|",
			attrs: map[string]any{"algorithm": "Ed25519", "key_size": 256},
		},
		{
			name:  "RSA public key",
			key:   "public_key|keys/rsa-2048-pub.pem|",
			attrs: map[string]any{"algorithm": "RSA", "key_size": 2048},
		},
		{
			name:  "RSA CSR",
			key:   "csr|keys/rsa-2048.csr|",
			attrs: map[string]any{"algorithm": "RSA", "key_size": 2048, "subject_cn": "csr-rsa2048.example.test"},
		},
		{
			name:  "ECDSA CSR",
			key:   "csr|keys/ecdsa-p256.csr|",
			attrs: map[string]any{"algorithm": "ECDSA", "curve": "P-256", "subject_cn": "csr-ecdsa-p256.example.test"},
		},
		{
			name:  "PKCS12 cert alias",
			key:   "certificate|keystores/rsa2048.p12|rsa2048",
			attrs: map[string]any{"algorithm": "RSA", "key_size": 2048, "self_signed": true},
		},
		{
			name:  "PKCS12 key alias",
			key:   "private_key|keystores/rsa2048.p12|rsa2048",
			attrs: map[string]any{"algorithm": "RSA", "key_size": 2048},
		},
		{
			name:  "JKS trusted ECDSA",
			key:   "certificate|keystores/truststore.jks|ecp256",
			attrs: map[string]any{"algorithm": "ECDSA", "curve": "P-256"},
		},
		{
			name:  "JKS trusted RSA-4096",
			key:   "certificate|keystores/truststore.jks|rsa4096",
			attrs: map[string]any{"algorithm": "RSA", "key_size": 4096},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, ok := m[tc.key]
			if !ok {
				t.Fatalf("finding %q not emitted", tc.key)
			}
			for k, want := range tc.attrs {
				got := f.Attrs[k]
				if !equalAttr(want, got) {
					t.Errorf("attr %q = %v (%T), want %v (%T)", k, got, got, want, want)
				}
			}
		})
	}
}

// TestEncryptedKeyHasNoAttrs asserts the encrypted PKCS#8 key is reported as a
// private_key with an empty attribute set (only the provable fact).
func TestEncryptedKeyHasNoAttrs(t *testing.T) {
	m := scanCorpus(t)
	f, ok := m["private_key|keys/rsa-2048-encrypted.key|"]
	if !ok {
		t.Fatal("encrypted key not reported as private_key")
	}
	if len(f.Attrs) != 0 {
		t.Errorf("encrypted key attrs = %v, want empty", f.Attrs)
	}
}

// TestProvenance asserts every finding carries at least one fs provenance
// record pointing at its own path (principle 1).
func TestProvenance(t *testing.T) {
	findings, err := New().Scan(corpusRoot())
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	for _, f := range findings {
		if len(f.Provenance) == 0 {
			t.Errorf("finding %s/%s has no provenance", f.Class, f.Path)
			continue
		}
		p := f.Provenance[0]
		if p.Source != "fs" || p.Location != f.Path {
			t.Errorf("finding %s: provenance = %+v, want fs/%s", f.Path, p, f.Path)
		}
	}
}

// TestNegativesTable scans a directory containing only one negative fixture at a
// time and asserts zero findings — each look-alike individually.
func TestNegativesTable(t *testing.T) {
	negDir := filepath.Join(corpusRoot(), "negatives")
	entries, err := os.ReadDir(negDir)
	if err != nil {
		t.Fatalf("read negatives: %v", err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		t.Run(name, func(t *testing.T) {
			tmp := t.TempDir()
			data, err := os.ReadFile(filepath.Join(negDir, name))
			if err != nil {
				t.Fatalf("read %s: %v", name, err)
			}
			if err := os.WriteFile(filepath.Join(tmp, name), data, 0o600); err != nil {
				t.Fatalf("write temp: %v", err)
			}
			findings, err := New().Scan(tmp)
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			if len(findings) != 0 {
				t.Errorf("%s produced %d findings, want 0: %+v", name, len(findings), findings)
			}
		})
	}
}

// TestOversizedFileSkipped confirms the size cap skips large files.
func TestOversizedFileSkipped(t *testing.T) {
	tmp := t.TempDir()
	// A > maxFileSize file whose head is a valid PEM-ish header. It must be
	// skipped without being read/parsed.
	big := make([]byte, maxFileSize+1)
	copy(big, []byte("-----BEGIN CERTIFICATE-----\n"))
	if err := os.WriteFile(filepath.Join(tmp, "big.pem"), big, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	findings, err := New().Scan(tmp)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("oversized file produced findings: %+v", findings)
	}
}

// TestEmptyRoot confirms an empty tree yields no findings and no error.
func TestEmptyRoot(t *testing.T) {
	findings, err := New().Scan(t.TempDir())
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("empty root produced findings: %+v", findings)
	}
}

// equalAttr compares expected/actual attribute values, tolerating int width.
func equalAttr(want, got any) bool {
	switch w := want.(type) {
	case int:
		if g, ok := got.(int); ok {
			return g == w
		}
		return false
	case bool:
		g, ok := got.(bool)
		return ok && g == w
	case string:
		g, ok := got.(string)
		return ok && g == w
	default:
		return want == got
	}
}
