package certs

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"

	"github.com/Ubermm/cryptoscan/internal/graph"
	keystore "github.com/pavlo-v-chernykh/keystore-go/v4"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// processPKCS12 decodes a PKCS#12 file with an EMPTY password (the corpus
// rsa2048.p12 is password-less). Each safe bag becomes a Finding keyed by its
// friendlyName alias. A file that fails the empty-password decode yields nothing
// — without the password we cannot prove its contents (principle 1).
func (r *run) processPKCS12(rel string, data []byte) bool {
	blocks, err := safeToPEM(data, "")
	if err != nil || len(blocks) == 0 {
		return false
	}
	emitted := false
	for _, b := range blocks {
		alias := b.Headers["friendlyName"]
		prov := graph.Provenance{Source: graph.SourceFS, Location: rel, Line: 0, Detail: "pkcs12:" + b.Type}
		switch b.Type {
		case "CERTIFICATE":
			if c, err := parseCertStrict(b.Bytes); err == nil {
				r.emitCert(rel, alias, prov, b.Bytes, c)
				emitted = true
			}
		case "PRIVATE KEY":
			// ToPEM re-marshals keys as PKCS#1 (RSA) or SEC1 (EC); try both, then
			// PKCS#8 for anything else it may emit.
			if pub, ok := parseAnyPrivateKeyPub(b.Bytes); ok {
				r.emitPrivateKey(rel, alias, prov, pub)
				emitted = true
			}
		}
	}
	return emitted
}

// safeToPEM calls pkcs12.ToPEM but converts a panic (defensive: third-party
// parser on adversarial bytes) into an error so the walk never crashes.
func safeToPEM(data []byte, password string) (blocks []*pem.Block, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			blocks, err = nil, errPanic
		}
	}()
	return pkcs12.ToPEM(data, password)
}

// parseAnyPrivateKeyPub extracts the public key from a private key in PKCS#1,
// SEC1, or PKCS#8 DER form.
func parseAnyPrivateKeyPub(der []byte) (any, bool) {
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return &k.PublicKey, true
	}
	if k, err := x509.ParseECPrivateKey(der); err == nil {
		return &k.PublicKey, true
	}
	if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		if pub, ok := privateKeyPub(k); ok {
			return pub, true
		}
	}
	return nil, false
}

// processJKS reads trusted-certificate entries from a Java KeyStore. The store
// password only guards store integrity, so trusted certs are readable without
// it: keystore-go populates the entry map as it reads, before the final digest
// check, so we ignore the digest error and harvest the trusted-cert entries.
// Private-key entries are per-entry encrypted and cannot be decrypted, so they
// are skipped (deterministic: we can only report what we can parse).
func (r *run) processJKS(rel string, data []byte) bool {
	ks, err := safeJKSLoad(data)
	if err != nil {
		return false
	}
	emitted := false
	for _, alias := range ks.Aliases() {
		if !ks.IsTrustedCertificateEntry(alias) {
			continue
		}
		entry, err := ks.GetTrustedCertificateEntry(alias)
		if err != nil {
			continue
		}
		c, err := parseCertStrict(entry.Certificate.Content)
		if err != nil {
			continue
		}
		prov := graph.Provenance{Source: graph.SourceFS, Location: rel, Line: 0, Detail: "jks:trustedCertEntry"}
		r.emitCert(rel, alias, prov, entry.Certificate.Content, c)
		emitted = true
	}
	return emitted
}

// safeJKSLoad loads a JKS with an empty store password. The magic-number check
// inside Load rejects non-JKS input; the trailing digest mismatch (expected,
// since we do not supply the real store password) is ignored because the
// trusted-cert entries were already read into the store. Panics are recovered.
func safeJKSLoad(data []byte) (ks keystore.KeyStore, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			err = errPanic
		}
	}()
	ks = keystore.New()
	loadErr := ks.Load(bytes.NewReader(data), nil)
	// A digest mismatch (wrong/empty store password) is expected and fine — the
	// trusted-cert entries are plaintext and already parsed. Only a hard failure
	// with zero readable aliases means this was not a usable JKS.
	if loadErr != nil && len(ks.Aliases()) == 0 {
		return ks, loadErr
	}
	return ks, nil
}
