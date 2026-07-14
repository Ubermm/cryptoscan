package certs

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"testing"
	"time"
)

// TestParseObservedCertMatchesFSExtraction asserts the exported probe entry
// point derives the same identity keys and attributes as the internal fs path,
// so a cert seen at an endpoint and on disk resolves to ONE node (DESIGN.md §1).
func TestParseObservedCertMatchesFSExtraction(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "observed.example.test"},
		NotBefore:    time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	oc, err := ParseObservedCert(der)
	if err != nil {
		t.Fatalf("ParseObservedCert: %v", err)
	}

	wantDER := hex.EncodeToString(sha256Sum(der))
	if oc.DERSHA256 != wantDER {
		t.Errorf("DERSHA256 = %q, want %q", oc.DERSHA256, wantDER)
	}
	// Attrs must equal the internal fs extraction for the same parsed cert.
	want := certAttrs(oc.Cert)
	if oc.Attrs["algorithm"] != want["algorithm"] || oc.Attrs["key_size"] != want["key_size"] {
		t.Errorf("Attrs algo/size mismatch: got %v/%v", oc.Attrs["algorithm"], oc.Attrs["key_size"])
	}
	if oc.SPKISHA256 != want["spki_sha256"] {
		t.Errorf("SPKISHA256 = %q, want %q", oc.SPKISHA256, want["spki_sha256"])
	}
	if oc.SPKISHA256 == "" {
		t.Error("SPKISHA256 is empty")
	}
}

func TestParseObservedCertRejectsGarbage(t *testing.T) {
	for _, in := range [][]byte{nil, {}, []byte("not der"), {0x30, 0x00}} {
		if oc, err := ParseObservedCert(in); err == nil {
			t.Errorf("ParseObservedCert(% x) = %+v, nil err; want error", in, oc)
		}
	}
}

func sha256Sum(b []byte) []byte { h := sha256.Sum256(b); return h[:] }
