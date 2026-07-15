// Package report is the Phase 3 auditor-report emitter for cryptoscan. It renders
// the human-facing cryptographic estate report in two formats — Markdown and JSON
// — as a deterministic projection of the graph data model (internal/graph) joined
// with the post-quantum exposure scoring (internal/pqc).
//
// # Principle fidelity (binding)
//
//   - Deterministic / provable (CLAUDE.md principle 1). The library NEVER calls
//     time.Now(): the generation timestamp is injected via Options.Now. Every
//     field of every finding traces to a proven graph attribute or provenance
//     record; nothing is guessed.
//   - Graph-primary (principle 2). Findings are projections of the graph: Write*
//     iterates graph nodes and joins each crypto-asset node with its pqc exposure.
//     The graph, not the finding list, is the primary structure.
//   - Asymmetric-first ranking (principle 3). Findings are ordered by PQC severity
//     descending, then by an asymmetric-first asset-type rank (certificates and
//     key material above endpoints and configs), then by node ID for stability.
//   - PCI-QSA finding schema (principle 4, verbatim). Every finding carries these
//     fields in this exact order: type, algorithm, key_size, location(s), expiry,
//     issuer/CA, pqc_exposure — plus the exposure severity.
//
// The package depends only on the standard library, internal/graph and
// internal/pqc. It never panics: an empty or nil graph yields a valid report with
// zero findings and a zero summary.
package report

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Ubermm/cryptoscan/internal/graph"
	"github.com/Ubermm/cryptoscan/internal/pqc"
)

// DefaultTitle is the Markdown report heading used when Options.Title is empty.
const DefaultTitle = "cryptoscan cryptographic estate report"

// rfc3339 is the single timestamp layout used for generated_at and cert expiry,
// so both emitters render dates identically.
const rfc3339 = time.RFC3339

// Options carries the render-time configuration shared by both emitters.
//
// Now is the report generation timestamp. It is rendered as the report's
// generated_at value (RFC 3339, UTC) and is the ONLY clock the emitters read —
// the library never calls time.Now() (principle 1), so output is reproducible.
// Callers should pass the same reference time they gave pqc.Score so the
// expiry-state annotations stay consistent with the exposure flags.
//
// Title overrides the Markdown report heading; an empty Title selects
// DefaultTitle. It is unused by the JSON emitter.
type Options struct {
	Now   time.Time
	Title string
}

// finding is the internal, fully-resolved projection of one crypto-asset node.
// The exported JSON/Markdown shapes are rendered from it; its field order mirrors
// the principle-4 schema.
type finding struct {
	nodeID    string
	typ       string   // principle-4 field 1
	algorithm string   // field 2
	keySize   string   // field 3
	locations []string // field 4 (multi-surface: every provenance location)
	expiry    string   // field 5
	issuer    string   // field 6
	pqcFlags  []string // field 7
	severity  string   // exposure severity label ("none" when unflagged)

	typeRank int  // asymmetric-first rank for stable ordering (principle 3)
	sevRank  int  // pqc severity value for ordering; -1 when unflagged
	flagged  bool // whether the node carries any exposure flag
}

// typeRanks encodes the asymmetric-first ordering (principle 3): certificates and
// key material rank above network/protocol surfaces. Lower is more urgent.
var typeRanks = map[string]int{
	"certificate":  0,
	"private_key":  1,
	"public_key":   2,
	"csr":          3,
	"tls_endpoint": 4,
	"ssh_endpoint": 5,
	"tls_config":   6,
	"ssh_config":   7,
}

// buildFindings projects every crypto-asset node in g into a finding, joining it
// with its pqc exposure. Nodes that are not crypto assets in the principle-4
// vocabulary (CA/Service/Library/KMS nodes, filesystem-container and bare
// reference ConfigFile nodes, and endpoints with no observed protocol) are
// skipped. The result is sorted by severity descending, then asymmetric-first
// type rank, then node ID.
func buildFindings(g *graph.Graph, exposure pqc.Report) []finding {
	byID := make(map[string]pqc.NodeExposure, len(exposure.Nodes))
	for _, e := range exposure.Nodes {
		byID[e.NodeID] = e
	}

	// A ConfigFile that has ConfigEndpoint children defers to those endpoints: its
	// file-level tls_config finding is SUPPRESSED so the report names the precise
	// weak vhost instead of the whole file (the endpoints are strictly more
	// informative). Endpoint-less configs (openssl.cnf, ssh_config, bare include
	// snippets) have no such children and keep their file-level finding.
	suppressedFiles := filesWithEndpoints(g)

	var out []finding
	if g != nil {
		for _, n := range g.Nodes() {
			if cf, ok := n.(*graph.ConfigFileNode); ok && suppressedFiles[cf.ID()] {
				continue
			}
			typ, ok := findingType(n)
			if !ok {
				continue
			}
			f := finding{
				nodeID:    n.ID(),
				typ:       typ,
				typeRank:  typeRanks[typ],
				algorithm: algorithmFor(n),
				keySize:   keySizeFor(n),
				locations: locationsFor(n),
				issuer:    issuerFor(n),
			}
			exp, flagged := byID[n.ID()]
			f.flagged = flagged
			if flagged {
				f.pqcFlags = exp.FlagNames
				f.severity = exp.Severity.String()
				f.sevRank = int(exp.Severity)
			} else {
				f.pqcFlags = []string{}
				f.severity = "none"
				f.sevRank = -1
			}
			f.expiry = expiryFor(n, exp.Flags, flagged)
			out = append(out, f)
		}
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].sevRank != out[j].sevRank {
			return out[i].sevRank > out[j].sevRank
		}
		if out[i].typeRank != out[j].typeRank {
			return out[i].typeRank < out[j].typeRank
		}
		return out[i].nodeID < out[j].nodeID
	})
	return out
}

// findingType maps a node to its principle-4 asset type, reporting false for node
// kinds that are not emitted as findings.
//
// A CSR is carried as a first-class CertificateRequest node (DESIGN.md §1), so it
// surfaces here as its own "csr" type rather than collapsing into the public_key
// finding of the Key node it signs_with.
func findingType(n graph.Node) (string, bool) {
	switch v := n.(type) {
	case *graph.CertificateNode:
		return "certificate", true
	case *graph.CertificateRequestNode:
		return "csr", true
	case *graph.KeyNode:
		if v.HasPrivate {
			return "private_key", true
		}
		return "public_key", true
	case *graph.EndpointNode:
		switch {
		case isTLSAttrs(v.Attrs):
			return "tls_endpoint", true
		case isSSHAttrs(v.Attrs):
			return "ssh_endpoint", true
		default:
			return "", false
		}
	case *graph.ConfigFileNode:
		switch v.Format {
		case "nginx", "apache", "openssl", "haproxy":
			return "tls_config", true
		case "sshd":
			return "ssh_config", true
		default:
			// "fs" storage-container nodes and bare "" reference-target nodes are
			// not crypto assets themselves; the cert/key they hold is the finding.
			return "", false
		}
	case *graph.ConfigEndpointNode:
		// A ConfigEndpoint is one server/vhost/frontend-bind block of a config: it
		// surfaces as the SAME principle-4 type as the file (tls_config) but NAMES
		// the specific endpoint in its location, so an auditor sees which vhost is
		// weak — the per-endpoint attribution DESIGN.md §1 calls for.
		return "tls_config", true
	default:
		return "", false
	}
}

// filesWithEndpoints returns the set of ConfigFile node IDs that have at least one
// ConfigEndpoint child, discovered from the graph's `stored_in` edges
// (cfgendpoint → file). The report suppresses the file-level tls_config finding for
// these files (their endpoints carry the precise attribution). Mirrors the
// identically-named suppression in internal/pqc.
func filesWithEndpoints(g *graph.Graph) map[string]bool {
	out := map[string]bool{}
	if g == nil {
		return out
	}
	for _, e := range g.Edges() {
		if e.Type == graph.EdgeStoredIn && strings.HasPrefix(e.From, "cfgendpoint:") {
			out[e.To] = true
		}
	}
	return out
}

// algorithmFor renders the principle-4 "algorithm" field: the asset's public-key
// algorithm for certs/keys (curve-qualified for ECDSA), and the observed
// protocol/cipher context for endpoints and configs.
func algorithmFor(n graph.Node) string {
	switch v := n.(type) {
	case *graph.CertificateNode:
		return algoWithCurve(v.Algorithm, "", v.KeySize)
	case *graph.CertificateRequestNode:
		return algoWithCurve(v.Algorithm, v.Curve, v.KeySize)
	case *graph.KeyNode:
		return algoWithCurve(v.Algorithm, v.Curve, v.KeySize)
	case *graph.EndpointNode:
		if isTLSAttrs(v.Attrs) {
			return tlsContext(v.Attrs)
		}
		return sshContext(v.Attrs)
	case *graph.ConfigFileNode:
		if v.Format == "sshd" {
			return sshConfigContext(v.Attrs)
		}
		return tlsConfigContext(v.Attrs)
	case *graph.ConfigEndpointNode:
		// The endpoint's resolved protocol set, rendered like a file-level
		// tls_config (no new column): the algorithm cell shows the protocols so a
		// legacy block's "TLSv1, TLSv1.1, TLSv1.2" is visible at a glance.
		return tlsConfigContext(v.Attrs)
	default:
		return ""
	}
}

// algoWithCurve renders an asymmetric algorithm, qualifying ECDSA with its named
// curve (from an explicit curve attr, else inferred from the key size).
func algoWithCurve(algo, curve string, keySize int) string {
	algo = strings.TrimSpace(algo)
	if algo == "" {
		return ""
	}
	if curve == "" && strings.EqualFold(algo, "ECDSA") {
		curve = curveForSize(keySize)
	}
	if curve != "" {
		return algo + " (" + curve + ")"
	}
	return algo
}

// curveForSize maps a NIST P-curve key size to its canonical curve name. An
// unrecognised size yields "" (nothing is asserted).
func curveForSize(size int) string {
	switch size {
	case 256:
		return "P-256"
	case 384:
		return "P-384"
	case 521:
		return "P-521"
	default:
		return ""
	}
}

// tlsContext renders the negotiated protocol/cipher of a TLS endpoint, falling
// back to the supported-protocol set. A hybrid PQC key exchange is noted.
func tlsContext(attrs map[string]any) string {
	var parts []string
	if p := strAttr(attrs, "negotiated_protocol"); p != "" {
		parts = append(parts, p)
	} else if ps := strListAttr(attrs, "protocols_supported"); len(ps) > 0 {
		parts = append(parts, strings.Join(ps, ", "))
	}
	if c := strAttr(attrs, "negotiated_cipher_suite"); c != "" {
		parts = append(parts, c)
	}
	s := strings.Join(parts, " / ")
	if boolAttr(attrs, "pqc_hybrid_kex") {
		if s != "" {
			s += " "
		}
		s += "(hybrid PQC KEX)"
	}
	return s
}

// sshContext renders the key-exchange / host-key context of an SSH endpoint.
func sshContext(attrs map[string]any) string {
	if kex := strListAttr(attrs, "kex_algorithms"); len(kex) > 0 {
		return "kex: " + strings.Join(kex, ", ")
	}
	if hk := strListAttr(attrs, "host_key_algorithms"); len(hk) > 0 {
		return "host key: " + strings.Join(hk, ", ")
	}
	return strAttr(attrs, "banner")
}

// tlsConfigContext renders the resolved protocol floor of a tls_config node.
func tlsConfigContext(attrs map[string]any) string {
	if protos := strListAttr(attrs, "protocols"); len(protos) > 0 {
		return strings.Join(protos, ", ")
	}
	if mp := strAttr(attrs, "min_protocol"); mp != "" {
		return "min " + mp
	}
	return strAttr(attrs, "cipher_string")
}

// sshConfigContext renders the key-exchange / host-key context of an ssh_config
// node.
func sshConfigContext(attrs map[string]any) string {
	if kex := strListAttr(attrs, "kex_algorithms"); len(kex) > 0 {
		return "kex: " + strings.Join(kex, ", ")
	}
	if hk := strListAttr(attrs, "host_key_types"); len(hk) > 0 {
		return "host key: " + strings.Join(hk, ", ")
	}
	return ""
}

// keySizeFor renders the principle-4 "key_size" field: the bit length (or curve
// strength) for certs/keys, empty for protocol surfaces.
func keySizeFor(n graph.Node) string {
	switch v := n.(type) {
	case *graph.CertificateNode:
		if v.KeySize > 0 {
			return strconv.Itoa(v.KeySize)
		}
	case *graph.CertificateRequestNode:
		if v.KeySize > 0 {
			return strconv.Itoa(v.KeySize)
		}
	case *graph.KeyNode:
		if v.KeySize > 0 {
			return strconv.Itoa(v.KeySize)
		}
	}
	return ""
}

// locationsFor renders the principle-4 "location" field as EVERY surface at which
// the asset resolves — this is where cross-surface entity resolution shows in the
// report. Each provenance record becomes one location string: "path:line" (or
// "path") for fs/config surfaces and "host:port" for probe surfaces. Entries are
// de-duplicated and ordered deterministically (fs, then config, then probe; then
// lexically), so a certificate stored on disk AND observed at an endpoint lists
// both locations on its single finding.
func locationsFor(n graph.Node) []string {
	if ce, ok := n.(*graph.ConfigEndpointNode); ok {
		return configEndpointLocations(ce)
	}
	type loc struct {
		rank int
		text string
	}
	seen := map[string]bool{}
	var locs []loc
	for _, p := range n.Provenance() {
		text := p.Location
		if text == "" {
			continue
		}
		rank := 1 // config
		switch p.Source {
		case graph.SourceFS:
			rank = 0
			if p.Line > 0 {
				text += ":" + strconv.Itoa(p.Line)
			}
		case graph.SourceProbe:
			rank = 2 // host:port, already canonical
		default: // config
			if p.Line > 0 {
				text += ":" + strconv.Itoa(p.Line)
			}
		}
		if seen[text] {
			continue
		}
		seen[text] = true
		locs = append(locs, loc{rank: rank, text: text})
	}
	sort.Slice(locs, func(i, j int) bool {
		if locs[i].rank != locs[j].rank {
			return locs[i].rank < locs[j].rank
		}
		return locs[i].text < locs[j].text
	})
	out := make([]string, 0, len(locs))
	for _, l := range locs {
		out = append(out, l.text)
	}
	return out
}

// configEndpointLocations renders the principle-4 "location" field for a
// ConfigEndpoint: the endpoint IDENTITY (server_name:port) followed by the config
// file:line it was resolved from, e.g.
// "legacy.internal.example.com:8443 (configs/realworld/mixed-vhosts.conf:11)".
// This is the auditor-facing "which vhost is weak" attribution — the identity
// names the block, the parenthesised file:line proves where.
func configEndpointLocations(ce *graph.ConfigEndpointNode) []string {
	fileLine := ce.Path
	for _, p := range ce.Provenance() {
		if p.Source == graph.SourceConfig && p.Location != "" {
			fileLine = p.Location
			if p.Line > 0 {
				fileLine += ":" + strconv.Itoa(p.Line)
			}
			break
		}
	}
	ident := endpointIdentity(ce)
	if ident == "" {
		return []string{fileLine}
	}
	if fileLine == "" {
		return []string{ident}
	}
	return []string{ident + " (" + fileLine + ")"}
}

// endpointIdentity builds the server_name:port identity of a ConfigEndpoint,
// falling back to the first listen/bind token, then to path#index — so every
// endpoint (including a haproxy bind with no server_name) is always nameable.
func endpointIdentity(ce *graph.ConfigEndpointNode) string {
	names := strListAttr(ce.Attrs, "server_name")
	port := intAttr(ce.Attrs, "port")
	if len(names) > 0 && names[0] != "" {
		if port > 0 {
			return names[0] + ":" + strconv.Itoa(port)
		}
		return names[0]
	}
	if listens := strListAttr(ce.Attrs, "listen"); len(listens) > 0 && listens[0] != "" {
		return listens[0]
	}
	if ce.Path != "" {
		return ce.Path + "#" + strconv.Itoa(ce.BlockIndex)
	}
	return ce.ID()
}

// intAttr reads an integer attribute, tolerating the native int the scanner stores
// and the float64 a JSON round-trip would produce. A missing/other-typed key is 0.
func intAttr(m map[string]any, k string) int {
	if m == nil {
		return 0
	}
	switch v := m[k].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	default:
		return 0
	}
}

// expiryFor renders the principle-4 "expiry" field: a certificate's notAfter
// (RFC 3339, UTC), annotated with its validity state from the exposure flags.
// Non-certificate assets have no expiry.
func expiryFor(n graph.Node, flags pqc.Flags, flagged bool) string {
	c, ok := n.(*graph.CertificateNode)
	if !ok {
		return ""
	}
	var s string
	if !c.NotAfter.IsZero() {
		s = c.NotAfter.UTC().Format(rfc3339)
	}
	if flagged {
		switch {
		case flags.Expired:
			s = appendState(s, "expired")
		case flags.Expiring:
			s = appendState(s, "expiring")
		}
		if flags.NotYetValid {
			s = appendState(s, "not yet valid")
		}
	}
	return s
}

func appendState(base, state string) string {
	if base == "" {
		return "(" + state + ")"
	}
	return base + " (" + state + ")"
}

// issuerFor renders the principle-4 "issuer/CA" field: the certificate issuer DN,
// annotated when the certificate is self-signed (issuer == subject). Non-cert
// assets have no issuer.
func issuerFor(n graph.Node) string {
	if _, ok := n.(*graph.CertificateRequestNode); ok {
		// A CSR has no issuer/CA — it is an unsigned request for one.
		return "N/A (certificate request)"
	}
	c, ok := n.(*graph.CertificateNode)
	if !ok {
		return ""
	}
	if c.SelfSigned {
		if c.Issuer != "" {
			return c.Issuer + " (self-signed)"
		}
		return "self-signed"
	}
	return c.Issuer
}

// --- attribute helpers (nil-safe) ---

func strAttr(m map[string]any, k string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[k].(string); ok {
		return v
	}
	return ""
}

func boolAttr(m map[string]any, k string) bool {
	if m == nil {
		return false
	}
	v, ok := m[k].(bool)
	return ok && v
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

func isTLSAttrs(attrs map[string]any) bool {
	if attrs == nil {
		return false
	}
	for _, k := range []string{"negotiated_protocol", "protocols_supported", "pqc_hybrid_kex", "negotiated_cipher_suite"} {
		if _, ok := attrs[k]; ok {
			return true
		}
	}
	return false
}

func isSSHAttrs(attrs map[string]any) bool {
	if attrs == nil {
		return false
	}
	for _, k := range []string{"kex_algorithms", "host_key_algorithms", "banner"} {
		if _, ok := attrs[k]; ok {
			return true
		}
	}
	return false
}
