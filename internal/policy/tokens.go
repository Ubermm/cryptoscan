package policy

import (
	"strconv"
	"strings"

	"github.com/cryptoscan/cryptoscan/internal/graph"
	"github.com/cryptoscan/cryptoscan/internal/pqc"
)

// tokenSpec is one entry in the token vocabulary: its canonical name, a one-line
// description (for docs/help), and the predicate that decides whether a given
// node breaches the threshold. match returns (breached, detail); detail is the
// provable evidence string surfaced in a Breach.
//
// The predicate receives the node's pqc.NodeExposure (and whether one exists) so
// tokens whose condition is EXACTLY a pinned PQC flag reuse that flag verbatim —
// keeping the gate aligned with pqc — while finer tokens (sha1 vs md5, tls10 vs
// tls11) read the node's proven attributes directly.
type tokenSpec struct {
	token string
	desc  string
	match func(n graph.Node, exp pqc.NodeExposure, hasExp bool) (bool, string)
}

// vocabulary is the authoritative token table, keyed by canonical lower-case
// token. Aliases (weak-key→rsa1024, weak-signature→sha1∪md5, legacy-tls→union)
// are distinct entries sharing the documented semantics.
var vocabulary = map[string]*tokenSpec{
	"tls10": {
		token: "tls10",
		desc:  "an Endpoint or tls_config that allows TLS 1.0 (TLSv1)",
		match: matchProtocol("TLSv1"),
	},
	"tls11": {
		token: "tls11",
		desc:  "an Endpoint or tls_config that allows TLS 1.1 (TLSv1.1)",
		match: matchProtocol("TLSv1.1"),
	},
	"ssl3": {
		token: "ssl3",
		desc:  "an Endpoint or tls_config that allows SSLv3",
		match: matchProtocol("SSLv3"),
	},
	"legacy-tls": {
		token: "legacy-tls",
		desc:  "an Endpoint or tls_config that allows any protocol below TLS 1.2",
		match: matchLegacyTLS,
	},
	"sha1": {
		token: "sha1",
		desc:  "a certificate or CSR with a SHA-1 signature algorithm",
		match: matchSignatureContains("SHA1"),
	},
	"md5": {
		token: "md5",
		desc:  "a certificate or CSR with an MD5 signature algorithm",
		match: matchSignatureContains("MD5"),
	},
	"weak-signature": {
		token: "weak-signature",
		desc:  "a certificate or CSR with a weak signature (SHA-1, MD5, or MD2)",
		match: matchWeakSignature,
	},
	"rsa1024": {
		token: "rsa1024",
		desc:  "an RSA key or certificate below 2048 bits (the weak_key condition)",
		match: matchWeakKey,
	},
	"weak-key": {
		token: "weak-key",
		desc:  "alias of rsa1024 (an RSA key or certificate below 2048 bits)",
		match: matchWeakKey,
	},
	"expired": {
		token: "expired",
		desc:  "an expired certificate",
		match: matchExpired,
	},
	"expiring": {
		token: "expiring",
		desc:  "a certificate expiring within the PQC look-ahead window (90 days)",
		match: matchExpiring,
	},
	"quantum-vulnerable": {
		token: "quantum-vulnerable",
		desc:  "any quantum-vulnerable asset (classical asymmetric key material or a non-hybrid key exchange)",
		match: matchQuantumVulnerable,
	},
}

// --- flag-based predicates (condition is exactly a pinned PQC flag) ---

// matchWeakKey trips on the pinned weak_key flag (RSA below 2048 bits). Shared by
// the rsa1024 and weak-key tokens.
func matchWeakKey(n graph.Node, exp pqc.NodeExposure, hasExp bool) (bool, string) {
	if !hasExp || !exp.Flags.WeakKey {
		return false, ""
	}
	return true, keyDetail(n)
}

// matchWeakSignature trips on the pinned weak_signature flag (SHA-1/MD5/MD2).
func matchWeakSignature(n graph.Node, exp pqc.NodeExposure, hasExp bool) (bool, string) {
	if !hasExp || !exp.Flags.WeakSignature {
		return false, ""
	}
	return true, signatureDetail(n)
}

// matchExpired trips on the pinned expired flag.
func matchExpired(n graph.Node, exp pqc.NodeExposure, hasExp bool) (bool, string) {
	if !hasExp || !exp.Flags.Expired {
		return false, ""
	}
	return true, expiryDetail(n)
}

// matchExpiring trips on the pinned expiring flag.
func matchExpiring(n graph.Node, exp pqc.NodeExposure, hasExp bool) (bool, string) {
	if !hasExp || !exp.Flags.Expiring {
		return false, ""
	}
	return true, expiryDetail(n)
}

// matchQuantumVulnerable trips on the pinned quantum_vulnerable_algorithm flag.
func matchQuantumVulnerable(n graph.Node, exp pqc.NodeExposure, hasExp bool) (bool, string) {
	if !hasExp || !exp.Flags.QuantumVulnerableAlgorithm {
		return false, ""
	}
	return true, quantumDetail(n)
}

// --- attribute-based predicates (finer than the pinned flags) ---

// matchSignatureContains builds a predicate that trips when a certificate/CSR
// signature algorithm contains the given (upper-cased) needle — the way sha1 and
// md5 are distinguished, which the coarse weak_signature flag cannot do.
func matchSignatureContains(needle string) func(graph.Node, pqc.NodeExposure, bool) (bool, string) {
	needle = strings.ToUpper(needle)
	return func(n graph.Node, _ pqc.NodeExposure, _ bool) (bool, string) {
		sig := certSignatureAlgo(n)
		if sig != "" && strings.Contains(strings.ToUpper(sig), needle) {
			return true, "signature=" + sig
		}
		return false, ""
	}
}

// matchProtocol builds a predicate that trips when an Endpoint or tls_config
// ConfigFile ALLOWS the given specific protocol version. The version set is read
// from the node's proven attributes (never collapsed to "legacy"), so tls10 and
// tls11 are independently gateable.
func matchProtocol(version string) func(graph.Node, pqc.NodeExposure, bool) (bool, string) {
	return func(n graph.Node, _ pqc.NodeExposure, _ bool) (bool, string) {
		return protocolAllowed(n, version)
	}
}

// matchLegacyTLS trips when an Endpoint or tls_config allows ANY protocol below
// TLS 1.2 — the union of ssl3, tls10, and tls11.
func matchLegacyTLS(n graph.Node, _ pqc.NodeExposure, _ bool) (bool, string) {
	var allowed []string
	for _, v := range []string{"SSLv3", "TLSv1", "TLSv1.1"} {
		if ok, _ := protocolAllowed(n, v); ok {
			allowed = append(allowed, v)
		}
	}
	if len(allowed) == 0 {
		return false, ""
	}
	return true, "allows " + strings.Join(allowed, ",")
}

// protocolAllowed reports whether node n admits the specific protocol version,
// reading the resolved attributes the scanner/probe recorded:
//
//   - Endpoint: version is allowed if it is the negotiated_protocol or appears in
//     the enumerated protocols_supported set.
//   - ConfigFile (tls_config): if an explicit resolved `protocols` set is present
//     it is authoritative (version allowed iff it is a member); otherwise a
//     `min_protocol` floor admits every version at or above it.
//
// The comparison is case-insensitive against the canonical spellings
// (SSLv3/TLSv1/TLSv1.1/TLSv1.2/TLSv1.3). A node carrying neither shape (an SSH
// endpoint, an sshd_config, a bare reference node) never matches.
func protocolAllowed(n graph.Node, version string) (bool, string) {
	switch v := n.(type) {
	case *graph.EndpointNode:
		if eqFold(strAttr(v.Attrs, "negotiated_protocol"), version) {
			return true, "negotiated_protocol=" + version
		}
		for _, p := range strListAttr(v.Attrs, "protocols_supported") {
			if eqFold(p, version) {
				return true, "protocols_supported includes " + version
			}
		}
	case *graph.ConfigFileNode:
		if protos := strListAttr(v.Attrs, "protocols"); len(protos) > 0 {
			for _, p := range protos {
				if eqFold(p, version) {
					return true, "protocols includes " + version
				}
			}
			return false, "" // explicit set present and version not in it
		}
		if mp := strAttr(v.Attrs, "min_protocol"); mp != "" {
			mr, vr := protoRank(mp), protoRank(version)
			if mr >= 0 && vr >= 0 && vr >= mr {
				return true, "min_protocol=" + mp + " admits " + version
			}
		}
	}
	return false, ""
}

// --- detail builders ---

// certSignatureAlgo returns the signature algorithm of a Certificate or CSR node,
// or "" for any other node type.
func certSignatureAlgo(n graph.Node) string {
	switch v := n.(type) {
	case *graph.CertificateNode:
		return v.SignatureAlgorithm
	case *graph.CertificateRequestNode:
		return v.SignatureAlgorithm
	default:
		return ""
	}
}

// signatureDetail renders "signature=<algo>" for a cert/CSR, else "".
func signatureDetail(n graph.Node) string {
	if sig := certSignatureAlgo(n); sig != "" {
		return "signature=" + sig
	}
	return ""
}

// keyDetail renders the algorithm and key size of any key-bearing node
// (Certificate, CSR, or Key), e.g. "RSA 1024-bit".
func keyDetail(n graph.Node) string {
	var algo string
	var size int
	switch v := n.(type) {
	case *graph.CertificateNode:
		algo, size = v.Algorithm, v.KeySize
	case *graph.CertificateRequestNode:
		algo, size = v.Algorithm, v.KeySize
	case *graph.KeyNode:
		algo, size = v.Algorithm, v.KeySize
	}
	if algo == "" {
		algo = "key"
	}
	if size > 0 {
		return algo + " " + strconv.Itoa(size) + "-bit"
	}
	return algo
}

// expiryDetail renders "notAfter=<RFC3339 date>" for a Certificate, else "".
func expiryDetail(n graph.Node) string {
	if c, ok := n.(*graph.CertificateNode); ok && !c.NotAfter.IsZero() {
		return "notAfter=" + c.NotAfter.UTC().Format("2006-01-02")
	}
	return ""
}

// quantumDetail renders a short reason for a quantum-vulnerable node: the
// asymmetric algorithm for key material, or the surface kind for an endpoint.
func quantumDetail(n graph.Node) string {
	switch v := n.(type) {
	case *graph.CertificateNode:
		return "algorithm=" + v.Algorithm
	case *graph.CertificateRequestNode:
		return "algorithm=" + v.Algorithm
	case *graph.KeyNode:
		return "algorithm=" + v.Algorithm
	case *graph.EndpointNode:
		return "classical key exchange"
	default:
		return ""
	}
}

// labelFor picks a human-friendly node label: the pqc exposure's label when the
// node is flagged (the common case, since every match is also flagged), else a
// locally-computed fallback so the summary is never blank.
func labelFor(n graph.Node, exp pqc.NodeExposure, hasExp bool) string {
	if hasExp && exp.Label != "" {
		return exp.Label
	}
	switch v := n.(type) {
	case *graph.CertificateNode:
		if v.Subject != "" {
			return v.Subject
		}
	case *graph.CertificateRequestNode:
		if v.Subject != "" {
			return v.Subject
		}
	case *graph.EndpointNode:
		if v.Host != "" && v.Port > 0 {
			return v.Host + ":" + strconv.Itoa(v.Port)
		}
	case *graph.ConfigFileNode:
		if v.Path != "" {
			return v.Path
		}
	}
	return n.ID()
}

// --- small helpers ---

// protoRanks orders the TLS/SSL protocol tokens low-to-high (mirrors the config/
// probe canonical spellings). A negative rank means "unrecognised".
var protoRanks = map[string]int{
	"SSLV3":   0,
	"TLSV1":   1,
	"TLSV1.1": 2,
	"TLSV1.2": 3,
	"TLSV1.3": 4,
}

func protoRank(s string) int {
	if r, ok := protoRanks[strings.ToUpper(strings.TrimSpace(s))]; ok {
		return r
	}
	return -1
}

func eqFold(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
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
