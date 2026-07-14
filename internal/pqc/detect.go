package pqc

import (
	"strings"
	"time"

	"github.com/cryptoscan/cryptoscan/internal/graph"
)

// quantumVulnerableAlgorithms is the DESIGN.md §5 set of asymmetric primitives
// breakable by Shor's algorithm, keyed by upper-cased algorithm name for
// case-insensitive membership. All of these are public-key primitives whose
// hardness assumption (integer factorisation or discrete log) collapses under a
// cryptographically relevant quantum computer.
var quantumVulnerableAlgorithms = map[string]bool{
	"RSA":     true,
	"ECDSA":   true,
	"ECDH":    true,
	"DH":      true,
	"DSA":     true,
	"ED25519": true,
	"EDDSA":   true,
	"X25519":  true,
}

// protoRank orders the TLS/SSL protocol tokens low-to-high using the canonical
// spellings the config and probe layers emit (DESIGN.md §2). A protocol strictly
// below TLSv1.2 is "legacy".
var protoRank = map[string]int{
	"SSLV3":   0,
	"TLSV1":   1,
	"TLSV1.1": 2,
	"TLSV1.2": 3,
	"TLSV1.3": 4,
}

const legacyProtoCeil = 3 // rank of TLSv1.2; anything below is legacy

// pqcKEXAlgorithms lists the post-quantum / hybrid key-exchange names that mark
// a surface as PQC-protected for its key establishment (so it is NOT flagged
// quantum_vulnerable). Kept deliberately small and explicit — matched
// case-insensitively — so the distinction stays provable, not guessed.
var pqcKEXAlgorithms = map[string]bool{
	"SNTRUP761X25519-SHA512@OPENSSH.COM": true, // OpenSSH hybrid
	"MLKEM768X25519-SHA256":              true, // draft OpenSSH ML-KEM hybrid
	"X25519MLKEM768":                     true, // TLS hybrid group name
	"X25519KYBER768DRAFT00":              true, // earlier TLS hybrid spelling
}

// flagsForNode dispatches to the per-type flag computation.
func flagsForNode(n graph.Node, now time.Time) Flags {
	switch v := n.(type) {
	case *graph.CertificateNode:
		return certFlags(v, now)
	case *graph.KeyNode:
		return keyFlags(v)
	case *graph.EndpointNode:
		return endpointFlags(v)
	case *graph.ConfigFileNode:
		return configFlags(v)
	default:
		return Flags{}
	}
}

// certFlags computes the exposure flags for a Certificate node from its proven
// attributes. Every predicate reads an attribute the scanner already extracted
// from the DER bytes.
func certFlags(c *graph.CertificateNode, now time.Time) Flags {
	var f Flags
	f.QuantumVulnerableAlgorithm = isQuantumVulnerableAlgo(c.Algorithm)
	f.WeakSignature = isWeakSignature(c.SignatureAlgorithm)
	f.WeakKey = isWeakRSAKey(c.Algorithm, c.KeySize)

	if !c.NotAfter.IsZero() {
		if !c.NotAfter.After(now) {
			// NotAfter at or before now -> expired.
			f.Expired = true
		} else if c.NotAfter.Before(now.Add(ExpiringWindow)) {
			// Not expired, but within the look-ahead window.
			f.Expiring = true
		}
	}
	if !c.NotBefore.IsZero() && c.NotBefore.After(now) {
		f.NotYetValid = true
	}
	return f
}

// keyFlags computes the exposure flags for a standalone Key node. A key has no
// signature or validity window, so only the algorithm-based flags apply.
func keyFlags(k *graph.KeyNode) Flags {
	return Flags{
		QuantumVulnerableAlgorithm: isQuantumVulnerableAlgo(k.Algorithm),
		WeakKey:                    isWeakRSAKey(k.Algorithm, k.KeySize),
	}
}

// endpointFlags computes the exposure flags for an Endpoint node from its
// observed-attributes map (DESIGN.md §1 EndpointNode.Attrs).
//
// Quantum vulnerability of an endpoint is about its KEY EXCHANGE, not a stored
// key:
//
//   - A TLS endpoint establishes keys with a classical (EC)DHE/RSA exchange and
//     is therefore quantum-vulnerable UNLESS it negotiated a hybrid PQC group
//     (pqc_hybrid_kex=true), in which case the exchange already carries
//     post-quantum protection and the endpoint is NOT flagged. This is the
//     hybrid distinction DESIGN.md §5 calls out explicitly.
//   - An SSH endpoint is quantum-vulnerable when every offered KexAlgorithm is
//     classical; if it offers a known PQC/hybrid KEX it is treated as
//     PQC-protected and not flagged.
func endpointFlags(e *graph.EndpointNode) Flags {
	var f Flags
	switch {
	case isTLSEndpoint(e.Attrs):
		if !boolAttr(e.Attrs, "pqc_hybrid_kex") {
			f.QuantumVulnerableAlgorithm = true
		}
		f.LegacyProtocol = tlsEndpointLegacy(e.Attrs)
	case isSSHEndpoint(e.Attrs):
		f.QuantumVulnerableAlgorithm = sshKEXClassicalOnly(e.Attrs)
	}
	return f
}

// configFlags computes the exposure flags for a ConfigFile node. Only the
// legacy_protocol flag applies, and only to tls_config files: the flag is set
// when the node's RESOLVED protocol set (carried on Attrs by the config scanner)
// admits SSLv3/TLSv1/TLSv1.1. The resolution is read off the node, never
// re-derived from raw directives here (DESIGN.md §1). See configLegacy.
func configFlags(c *graph.ConfigFileNode) Flags {
	return Flags{LegacyProtocol: configLegacy(c)}
}

// --- predicates ---

// isQuantumVulnerableAlgo reports whether algo names a Shor-breakable asymmetric
// primitive (case-insensitive).
func isQuantumVulnerableAlgo(algo string) bool {
	return quantumVulnerableAlgorithms[strings.ToUpper(strings.TrimSpace(algo))]
}

// isWeakRSAKey reports whether the algorithm is RSA and the key is shorter than
// 2048 bits. A zero/unknown size is not treated as weak (nothing was proven).
func isWeakRSAKey(algo string, keySize int) bool {
	return strings.EqualFold(strings.TrimSpace(algo), "RSA") && keySize > 0 && keySize < 2048
}

// isWeakSignature reports whether a certificate signature algorithm string is
// SHA-1, MD5, or MD2 based (e.g. "SHA1-RSA", "MD5-RSA", "ECDSA-SHA1"). The x509
// SignatureAlgorithm.String() spellings use "SHA1"/"MD5"/"MD2" without a dash,
// and "SHA1" cannot collide with the SHA-2 spellings ("SHA256"/"SHA384"/...).
func isWeakSignature(sigAlgo string) bool {
	s := strings.ToUpper(sigAlgo)
	return strings.Contains(s, "SHA1") || strings.Contains(s, "MD5") || strings.Contains(s, "MD2")
}

// isTLSEndpoint reports whether an attrs map carries TLS observations.
func isTLSEndpoint(attrs map[string]any) bool {
	if attrs == nil {
		return false
	}
	if _, ok := attrs["negotiated_protocol"]; ok {
		return true
	}
	if _, ok := attrs["protocols_supported"]; ok {
		return true
	}
	if _, ok := attrs["pqc_hybrid_kex"]; ok {
		return true
	}
	return false
}

// isSSHEndpoint reports whether an attrs map carries SSH observations.
func isSSHEndpoint(attrs map[string]any) bool {
	if attrs == nil {
		return false
	}
	if _, ok := attrs["kex_algorithms"]; ok {
		return true
	}
	if _, ok := attrs["host_key_algorithms"]; ok {
		return true
	}
	if _, ok := attrs["banner"]; ok {
		return true
	}
	return false
}

// tlsEndpointLegacy reports whether a TLS endpoint negotiated or supports a
// protocol below TLS 1.2.
func tlsEndpointLegacy(attrs map[string]any) bool {
	if isLegacyProto(strAttr(attrs, "negotiated_protocol")) {
		return true
	}
	for _, p := range strListAttr(attrs, "protocols_supported") {
		if isLegacyProto(p) {
			return true
		}
	}
	return false
}

// sshKEXClassicalOnly reports whether an SSH endpoint offers key-exchange
// algorithms and none of them is a known PQC/hybrid KEX (so the whole offer is
// classical and quantum-vulnerable). An endpoint with no kex_algorithms proves
// nothing and is not flagged.
func sshKEXClassicalOnly(attrs map[string]any) bool {
	kex := strListAttr(attrs, "kex_algorithms")
	if len(kex) == 0 {
		return false
	}
	for _, k := range kex {
		if pqcKEXAlgorithms[strings.ToUpper(strings.TrimSpace(k))] {
			return false
		}
	}
	return true
}

// isLegacyProto reports whether a protocol token names a version below TLS 1.2
// (SSLv3/TLSv1/TLSv1.1). Unrecognised tokens are not legacy (nothing proven).
func isLegacyProto(tok string) bool {
	r, ok := protoRank[strings.ToUpper(strings.TrimSpace(tok))]
	return ok && r < legacyProtoCeil
}

// --- attribute helpers (nil-safe) ---

func boolAttr(m map[string]any, k string) bool {
	if m == nil {
		return false
	}
	v, ok := m[k].(bool)
	return ok && v
}

func strAttr(m map[string]any, k string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[k].(string); ok {
		return v
	}
	return ""
}

// strListAttr reads a string-slice attribute, tolerating both []string and the
// []any shape a decoded map may carry.
func strListAttr(m map[string]any, k string) []string {
	if m == nil {
		return nil
	}
	switch v := m[k].(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}
