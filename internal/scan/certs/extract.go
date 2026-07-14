package certs

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"time"
)

// pubKeyInfo derives the provable public-key attributes (algorithm, key size in
// bits, and curve name) from a parsed public key. It reports ok=false for key
// types cryptoscan does not model, so callers can skip rather than guess.
//
// key_size follows the manifest contract (DESIGN.md §2): RSA modulus bit
// length, ECDSA curve bit size, Ed25519 fixed at 256.
func pubKeyInfo(pub any) (algo string, size int, curve string, ok bool) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return "RSA", k.N.BitLen(), "", true
	case *ecdsa.PublicKey:
		return "ECDSA", k.Curve.Params().BitSize, k.Curve.Params().Name, true
	case ed25519.PublicKey:
		return "Ed25519", 256, "", true
	default:
		return "", 0, "", false
	}
}

// spkiSHA256FromPub marshals pub to its canonical SubjectPublicKeyInfo DER and
// returns the lowercase hex SHA-256 of that DER — the Key node identity and the
// manifest spki_sha256 value (DESIGN.md §1 entity resolution).
func spkiSHA256FromPub(pub any) (string, bool) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", false
	}
	return hexSHA256(der), true
}

// hexSHA256 returns the lowercase hex SHA-256 of b.
func hexSHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// signer is satisfied by every stdlib private key type (rsa/ecdsa/ed25519):
// it exposes the corresponding public key.
type signer interface {
	Public() crypto.PublicKey
}

// certAttrs builds the certificate Finding.Attrs from a parsed x509 certificate.
// Every value is deterministically derived from the certificate bytes
// (principle 1): nothing is inferred. self_signed is a byte comparison of the
// raw issuer and subject DNs — deliberately NOT a signature check, because MD5/
// SHA-1 self-signed certs in the corpus would be rejected by the stdlib
// signature verifier as insecure, yet are still genuinely self-signed.
func certAttrs(c *x509.Certificate) map[string]any {
	attrs := map[string]any{
		"signature_algorithm": c.SignatureAlgorithm.String(),
		"subject_cn":          c.Subject.CommonName,
		"self_signed":         bytesEqual(c.RawIssuer, c.RawSubject),
		"expired":             c.NotAfter.Before(time.Now()),
		"not_yet_valid":       c.NotBefore.After(time.Now()),
		"not_before":          c.NotBefore.UTC().Format(time.RFC3339),
		"not_after":           c.NotAfter.UTC().Format(time.RFC3339),
		// spki_sha256 is hashed over the SPKI exactly as stored in the cert.
		"spki_sha256": hexSHA256(c.RawSubjectPublicKeyInfo),
	}
	if algo, size, curve, ok := pubKeyInfo(c.PublicKey); ok {
		attrs["algorithm"] = algo
		attrs["key_size"] = size
		attrs["curve"] = curve
	}
	return attrs
}

// keyAttrs builds public/private key Finding.Attrs from a parsed public key.
func keyAttrs(pub any) (map[string]any, bool) {
	algo, size, curve, ok := pubKeyInfo(pub)
	if !ok {
		return nil, false
	}
	spki, ok := spkiSHA256FromPub(pub)
	if !ok {
		return nil, false
	}
	return map[string]any{
		"algorithm":   algo,
		"key_size":    size,
		"curve":       curve,
		"spki_sha256": spki,
	}, true
}

// csrAttrs builds CSR Finding.Attrs from a parsed certificate request.
func csrAttrs(r *x509.CertificateRequest) (map[string]any, bool) {
	algo, size, curve, ok := pubKeyInfo(r.PublicKey)
	if !ok {
		return nil, false
	}
	return map[string]any{
		"algorithm":  algo,
		"key_size":   size,
		"curve":      curve,
		"subject_cn": r.Subject.CommonName,
	}, true
}

// encryptedPrivateKeyInfo mirrors the RFC 5958 EncryptedPrivateKeyInfo ASN.1
// structure: SEQUENCE { encryptionAlgorithm AlgorithmIdentifier, encryptedData
// OCTET STRING }. We do not decrypt (we lack the password), but successfully
// unmarshalling this structure — with no trailing bytes — PROVES the bytes are
// an encrypted private key (principle 1), which is the only claim we make.
type encryptedPrivateKeyInfo struct {
	Algo          asn1.RawValue
	EncryptedData []byte
}

// isEncryptedPrivateKey reports whether der is a structurally valid RFC 5958
// EncryptedPrivateKeyInfo. The algorithm identifier must itself be a SEQUENCE
// (an AlgorithmIdentifier), which rejects arbitrary two-field SEQUENCEs.
func isEncryptedPrivateKey(der []byte) bool {
	var info encryptedPrivateKeyInfo
	rest, err := asn1.Unmarshal(der, &info)
	if err != nil || len(rest) != 0 {
		return false
	}
	// Tag 16 == SEQUENCE (class universal, constructed): the AlgorithmIdentifier.
	return info.Algo.Class == asn1.ClassUniversal && info.Algo.Tag == asn1.TagSequence
}

// privateKeyPub extracts the public key from a parsed private key value of any
// stdlib type via the crypto.Signer-style Public() method.
func privateKeyPub(priv any) (crypto.PublicKey, bool) {
	s, ok := priv.(signer)
	if !ok {
		return nil, false
	}
	return s.Public(), true
}

// bytesEqual is a tiny helper kept local to avoid importing bytes solely for
// one call site in attribute extraction.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
