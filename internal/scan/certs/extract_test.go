package certs

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// makeCert builds a self-signed RSA certificate with the given validity window
// and returns the parsed *x509.Certificate. It fails the test on any error.
func makeCert(t *testing.T, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "future.example.test"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return c
}

// TestCertAttrsNotYetValid asserts the not_yet_valid flag is derived from
// notBefore relative to now, independently of the expired flag.
func TestCertAttrsNotYetValid(t *testing.T) {
	now := time.Now()

	cases := []struct {
		name            string
		notBefore       time.Time
		notAfter        time.Time
		wantNotYetValid bool
		wantExpired     bool
	}{
		{
			name:            "future notBefore",
			notBefore:       now.Add(24 * time.Hour),
			notAfter:        now.Add(48 * time.Hour),
			wantNotYetValid: true,
			wantExpired:     false,
		},
		{
			name:            "currently valid",
			notBefore:       now.Add(-24 * time.Hour),
			notAfter:        now.Add(24 * time.Hour),
			wantNotYetValid: false,
			wantExpired:     false,
		},
		{
			name:            "already expired",
			notBefore:       now.Add(-48 * time.Hour),
			notAfter:        now.Add(-24 * time.Hour),
			wantNotYetValid: false,
			wantExpired:     true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			attrs := certAttrs(makeCert(t, tc.notBefore, tc.notAfter))
			if got := attrs["not_yet_valid"]; got != tc.wantNotYetValid {
				t.Errorf("not_yet_valid = %v, want %v", got, tc.wantNotYetValid)
			}
			if got := attrs["expired"]; got != tc.wantExpired {
				t.Errorf("expired = %v, want %v", got, tc.wantExpired)
			}
		})
	}
}
