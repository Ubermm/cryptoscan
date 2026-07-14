package cbom

import (
	"strconv"
	"strings"
)

// This file derives deduplicated CycloneDX "algorithm" cryptographic-asset
// components from the algorithm/size/curve attributes proven on Certificate and
// Key nodes, and from certificate signature-algorithm strings. Every algorithm a
// certificate or key points at (via certificateProperties.signatureAlgorithmRef /
// relatedCryptoMaterialProperties.algorithmRef) resolves to one of these shared
// components, keyed by a stable bom-ref so identical algorithms deduplicate.

// primitiveFor maps a bare asymmetric algorithm name to its CycloneDX
// algorithmProperties.primitive enum value (DESIGN.md principle 3 covers exactly
// these asymmetric families). An unknown name yields "unknown".
func primitiveFor(algo string) string {
	switch strings.ToUpper(strings.TrimSpace(algo)) {
	case "RSA":
		return "pke"
	case "ECDSA", "DSA", "ED25519", "EDDSA":
		return "signature"
	case "DH", "ECDH", "X25519":
		return "key-agree"
	default:
		return "unknown"
	}
}

// cryptoFunctionsFor returns the definitional cryptographic functions of a
// primitive (what the primitive is for), one of the CycloneDX cryptoFunctions
// enum sets. It describes the primitive, not an observed use.
func cryptoFunctionsFor(primitive string) []string {
	switch primitive {
	case "pke":
		return []string{"encrypt", "decrypt"}
	case "signature":
		return []string{"sign", "verify"}
	case "key-agree":
		return []string{"keygen"}
	case "hash":
		return []string{"digest"}
	default:
		return nil
	}
}

// quantumVulnerableBase reports whether a bare algorithm name is one of the
// Shor-breakable asymmetric families (DESIGN.md §5). Such an algorithm has NIST
// quantum security level 0 (no post-quantum protection).
func quantumVulnerableBase(algo string) bool {
	switch strings.ToUpper(strings.TrimSpace(algo)) {
	case "RSA", "ECDSA", "ECDH", "DH", "DSA", "ED25519", "EDDSA", "X25519":
		return true
	default:
		return false
	}
}

// keyAlgorithm builds the algorithm component and bom-ref for a key/certificate
// public-key algorithm from its proven (algorithm, size, curve). ok is false
// when algo is empty (nothing proven — no component emitted).
func keyAlgorithm(algo string, size int, curve string) (ref string, comp component, ok bool) {
	algo = strings.TrimSpace(algo)
	if algo == "" {
		return "", component{}, false
	}
	primitive := primitiveFor(algo)
	name := algorithmName(algo, size, curve)

	props := &algorithmProperties{
		Primitive:       primitive,
		Curve:           curve,
		CryptoFunctions: cryptoFunctionsFor(primitive),
	}
	if size > 0 {
		props.ParameterSetIdentifier = strconv.Itoa(size)
	}
	if quantumVulnerableBase(algo) {
		props.NISTQuantumSecurityLevel = intPtr(0)
	}

	ref = "alg:" + slug(name)
	comp = component{
		Type:   "cryptographic-asset",
		BOMRef: ref,
		Name:   name,
		CryptoProperties: &cryptoProperties{
			AssetType:           "algorithm",
			AlgorithmProperties: props,
		},
	}
	return ref, comp, true
}

// signatureAlgorithm builds the algorithm component and bom-ref for a
// certificate signature algorithm string (e.g. "SHA256-RSA"). ok is false for an
// empty/unknown-shaped string.
func signatureAlgorithm(sig string) (ref string, comp component, ok bool) {
	sig = strings.TrimSpace(sig)
	if sig == "" || strings.EqualFold(sig, "unknown") {
		return "", component{}, false
	}
	props := &algorithmProperties{
		Primitive:       "signature",
		CryptoFunctions: cryptoFunctionsFor("signature"),
	}
	// A signature algorithm inherits its quantum exposure from the asymmetric
	// primitive it is built on (RSA/ECDSA/DSA/EdDSA); the SignatureAlgorithm
	// string names that primitive as a substring.
	if signatureIsQuantumVulnerable(sig) {
		props.NISTQuantumSecurityLevel = intPtr(0)
	}
	ref = "alg:sig:" + slug(sig)
	comp = component{
		Type:   "cryptographic-asset",
		BOMRef: ref,
		Name:   sig,
		CryptoProperties: &cryptoProperties{
			AssetType:           "algorithm",
			AlgorithmProperties: props,
		},
	}
	return ref, comp, true
}

// signatureIsQuantumVulnerable reports whether a signature-algorithm string is
// built on a Shor-breakable asymmetric primitive.
func signatureIsQuantumVulnerable(sig string) bool {
	s := strings.ToUpper(sig)
	for _, base := range []string{"RSA", "ECDSA", "DSA", "ED25519", "EDDSA"} {
		if strings.Contains(s, base) {
			return true
		}
	}
	return false
}

// algorithmName builds the human-facing, dedup-stable name for a public-key
// algorithm: "RSA-2048", "ECDSA-P-256", "Ed25519", etc.
func algorithmName(algo string, size int, curve string) string {
	up := strings.ToUpper(strings.TrimSpace(algo))
	switch up {
	case "RSA", "DSA", "DH":
		if size > 0 {
			return up + "-" + strconv.Itoa(size)
		}
		return up
	case "ECDSA", "ECDH":
		if curve != "" {
			return up + "-" + curve
		}
		if size > 0 {
			return up + "-" + strconv.Itoa(size)
		}
		return up
	case "ED25519", "EDDSA":
		return "Ed25519"
	case "X25519":
		return "X25519"
	default:
		if size > 0 {
			return algo + "-" + strconv.Itoa(size)
		}
		return algo
	}
}

// slug lowercases s and replaces every run of non-alphanumeric characters with a
// single '-', producing a stable, collision-resistant bom-ref suffix.
func slug(s string) string {
	var b strings.Builder
	prevDash := false
	for _, r := range strings.ToLower(s) {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			prevDash = false
		default:
			if !prevDash {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}

func intPtr(i int) *int { return &i }
