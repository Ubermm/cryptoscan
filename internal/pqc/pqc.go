// Package pqc is the Phase 3 post-quantum exposure scoring library for
// cryptoscan. It is a pure, deterministic projection of the graph data model
// (internal/graph): given a populated *graph.Graph and a caller-supplied
// reference time, Score computes the per-node PQC exposure flags pinned by
// docs/DESIGN.md §5, ranks each exposed node by a small severity enum
// (asymmetric-first, CLAUDE.md principle 3), and rolls the whole estate up into
// a deterministic Summary.
//
// # Design constraints (binding)
//
//   - Read-only projection (principle 2). Score never mutates the graph; it
//     only reads node attributes. Findings, reports and the CBOM are all
//     projections of the graph, never the primary structure.
//   - Provable only (principle 1). Every flag is derived from an attribute the
//     scanner already proved from bytes/handshake — an algorithm name, a key
//     size, a signature algorithm, a validity date, an observed protocol set,
//     or the hybrid-KEX bit. Nothing is guessed.
//   - Deterministic clock. The library NEVER calls time.Now(); the caller passes
//     the reference `now`, so expiry flags and tests are reproducible.
//   - Standard library + internal only. No new dependencies.
//
// The package emits no serialized format and wires no CLI: it produces the
// Report struct that later output agents (CBOM / auditor report) consume.
package pqc

import (
	"sort"
	"strings"
	"time"

	"github.com/Ubermm/cryptoscan/internal/graph"
)

// ExpiringWindow is the look-ahead window used for the `expiring` flag: a
// certificate whose NotAfter falls within this window of the reference time
// (but is not already expired) is flagged expiring. DESIGN.md §5 pins it at 90
// days.
const ExpiringWindow = 90 * 24 * time.Hour

// Severity is a small, totally-ordered exposure ranking. Higher values are more
// urgent; Report.Nodes is sorted by Severity descending (then node ID ascending)
// so the most urgent exposures surface first. The ordering encodes CLAUDE.md
// principle 3 (asymmetric-first): the asymmetric/signature flags occupy the top
// two tiers, above the time-bound and informational concerns.
type Severity int

// Severity levels, ascending. The mapping from flags to severity is documented
// on flagSeverity and reproduced here:
//
//   - SeverityCritical: weak_key or weak_signature — asymmetric key material or
//     a certificate signature that is breakable with TODAY'S compute (RSA < 2048,
//     SHA-1/MD5). The highest tier because the exposure is already exploitable.
//   - SeverityHigh: quantum_vulnerable_algorithm, expired, or legacy_protocol —
//     the asymmetric quantum-exposure lens (principle 3) plus active protocol or
//     validity failures.
//   - SeverityMedium: expiring — an operational, time-bound warning.
//   - SeverityLow: not_yet_valid only — informational.
//
// A node's severity is the maximum tier over the flags that are true for it.
const (
	SeverityLow Severity = iota
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

// String renders a Severity as a stable lowercase label.
func (s Severity) String() string {
	switch s {
	case SeverityCritical:
		return "critical"
	case SeverityHigh:
		return "high"
	case SeverityMedium:
		return "medium"
	case SeverityLow:
		return "low"
	default:
		return "unknown"
	}
}

// Flag names are the DESIGN.md §5 identifiers, exported so consumers (and the
// Summary maps) use one canonical spelling.
const (
	FlagQuantumVulnerable = "quantum_vulnerable_algorithm"
	FlagLegacyProtocol    = "legacy_protocol"
	FlagWeakSignature     = "weak_signature"
	FlagWeakKey           = "weak_key"
	FlagExpiring          = "expiring"
	FlagExpired           = "expired"
	FlagNotYetValid       = "not_yet_valid"
)

// Flags is the set of DESIGN.md §5 PQC exposure booleans computed for a single
// node. Every field is provable from that node's attributes.
type Flags struct {
	// QuantumVulnerableAlgorithm: the node uses an asymmetric primitive breakable
	// by Shor's algorithm — algorithm ∈ {RSA, ECDSA, ECDH, DH, DSA, Ed25519,
	// EdDSA, X25519} for Certificate/Key nodes, or a classical (non-hybrid) key
	// exchange for an Endpoint. A hybrid endpoint (pqc_hybrid_kex=true) is NOT
	// flagged: its key exchange already carries post-quantum protection.
	QuantumVulnerableAlgorithm bool
	// LegacyProtocol: an Endpoint negotiating or supporting a protocol below
	// TLS 1.2, or a tls_config whose enabled protocol set includes SSLv3/TLSv1/
	// TLSv1.1.
	LegacyProtocol bool
	// WeakSignature: the certificate signature algorithm is SHA-1 or MD5 based.
	WeakSignature bool
	// WeakKey: an RSA key shorter than 2048 bits.
	WeakKey bool
	// Expiring: a certificate whose NotAfter is within ExpiringWindow of `now`
	// and not already expired.
	Expiring bool
	// Expired: a certificate whose NotAfter is at or before `now`.
	Expired bool
	// NotYetValid: a certificate whose NotBefore is after `now` (informational).
	NotYetValid bool
}

// Any reports whether at least one flag is set.
func (f Flags) Any() bool {
	return f.QuantumVulnerableAlgorithm || f.LegacyProtocol || f.WeakSignature ||
		f.WeakKey || f.Expiring || f.Expired || f.NotYetValid
}

// Names returns the names of the set flags, sorted for deterministic output.
func (f Flags) Names() []string {
	var out []string
	if f.QuantumVulnerableAlgorithm {
		out = append(out, FlagQuantumVulnerable)
	}
	if f.LegacyProtocol {
		out = append(out, FlagLegacyProtocol)
	}
	if f.WeakSignature {
		out = append(out, FlagWeakSignature)
	}
	if f.WeakKey {
		out = append(out, FlagWeakKey)
	}
	if f.Expiring {
		out = append(out, FlagExpiring)
	}
	if f.Expired {
		out = append(out, FlagExpired)
	}
	if f.NotYetValid {
		out = append(out, FlagNotYetValid)
	}
	sort.Strings(out)
	return out
}

// Severity is the node severity implied by the set flags: the maximum tier over
// every true flag (see flagSeverity). A Flags with nothing set reports
// SeverityLow, but such nodes are never emitted as exposures.
func (f Flags) Severity() Severity {
	sev := SeverityLow
	for _, name := range f.Names() {
		if s := flagSeverity(name); s > sev {
			sev = s
		}
	}
	return sev
}

// flagSeverity maps a single flag to its severity tier (see the Severity
// constants). It is the one place the flag→tier policy lives.
func flagSeverity(flag string) Severity {
	switch flag {
	case FlagWeakKey, FlagWeakSignature:
		return SeverityCritical
	case FlagQuantumVulnerable, FlagExpired, FlagLegacyProtocol:
		return SeverityHigh
	case FlagExpiring:
		return SeverityMedium
	case FlagNotYetValid:
		return SeverityLow
	default:
		return SeverityLow
	}
}

// NodeExposure is the per-node scoring result: which node, a human-readable
// label, the flags true for it, and the derived severity.
type NodeExposure struct {
	// NodeID is the graph node identity (e.g. "cert:<hex>", "endpoint:host:port").
	NodeID string
	// NodeType is the graph node kind.
	NodeType graph.NodeType
	// Label is a human-friendly identifier: a certificate's subject CN, a key's
	// algorithm/size, an endpoint's host:port, or a config file's path.
	Label string
	// Flags are the exposure booleans set for this node.
	Flags Flags
	// FlagNames is Flags.Names() precomputed (sorted) for convenient consumption.
	FlagNames []string
	// Severity is Flags.Severity().
	Severity Severity
}

// Count is a single (name, count) pair used in the Summary's sorted tallies.
type Count struct {
	Name  string
	Count int
}

// Summary is the estate-level rollup. Every field is deterministic; the slice
// tallies are sorted by Name so output is reproducible.
type Summary struct {
	// TotalNodes is the number of scored (relevant-type) nodes considered:
	// Certificate, CertificateRequest, Key, Endpoint, and ConfigFile nodes.
	TotalNodes int
	// FlaggedNodes is the number of those nodes with at least one flag set (i.e.
	// len(Report.Nodes)).
	FlaggedNodes int
	// ByFlag tallies how many nodes set each flag, sorted by flag name.
	ByFlag []Count
	// ByNodeType tallies flagged nodes per node type, sorted by type name.
	ByNodeType []Count
	// BySeverity tallies flagged nodes per severity label, sorted by label.
	BySeverity []Count
	// QuantumVulnerableAssets is the count of nodes flagged quantum_vulnerable.
	QuantumVulnerableAssets int
	// LegacyEndpoints is the count of Endpoint nodes flagged legacy_protocol.
	LegacyEndpoints int
	// Expired / Expiring are counts of certificates flagged expired / expiring.
	Expired  int
	Expiring int
	// PQCReadyEndpoints is the count of Endpoint nodes advertising a hybrid PQC
	// key exchange (pqc_hybrid_kex=true) — the post-quantum-ready surfaces.
	PQCReadyEndpoints int
}

// Report is the full scoring output: the flagged nodes (sorted by severity
// descending, then node ID ascending) and the estate Summary.
type Report struct {
	Nodes   []NodeExposure
	Summary Summary
}

// Score projects g into a PQC exposure Report as of the reference time `now`.
// It is read-only (the graph is never mutated) and fully deterministic: the same
// (graph, now) always yields an identical Report, and no wall clock is read.
//
// Only Certificate, CertificateRequest, Key, Endpoint, and ConfigFile nodes are
// scored; other node types (CA, Service, CryptoLibrary, KMSEntry) carry no
// algorithm/protocol attributes and never produce a flag. A node is emitted in Report.Nodes only
// when at least one flag is true for it; every relevant node (flagged or not) is
// counted in Summary.TotalNodes.
func Score(g *graph.Graph, now time.Time) Report {
	var rep Report
	if g == nil {
		rep.Summary = summarize(nil)
		return rep
	}

	// A ConfigFile with ConfigEndpoint children defers its legacy_protocol flag to
	// those endpoints (per-endpoint attribution is more precise) — see
	// filesWithEndpoints. Computed once, up front.
	suppressed := filesWithEndpoints(g)

	byFlag := map[string]int{}
	byType := map[string]int{}
	bySev := map[string]int{}
	var (
		quantum   int
		legacyEP  int
		expired   int
		expiring  int
		pqcReady  int
		total     int
		exposures []NodeExposure
	)

	for _, n := range g.Nodes() {
		if !relevant(n.Type()) {
			continue
		}
		total++

		// Count PQC-ready endpoints independently of the flag set: a hybrid
		// endpoint is not "exposed" for its KEX but is still worth surfacing.
		if e, ok := n.(*graph.EndpointNode); ok && boolAttr(e.Attrs, "pqc_hybrid_kex") {
			pqcReady++
		}

		flags := flagsForNode(n, now)
		// Double-count suppression: a ConfigFile that has ConfigEndpoint children
		// carries no file-level flag — the endpoints do (precise attribution).
		if n.Type() == graph.NodeConfigFile && suppressed[n.ID()] {
			flags = Flags{}
		}
		if !flags.Any() {
			continue
		}

		exp := NodeExposure{
			NodeID:    n.ID(),
			NodeType:  n.Type(),
			Label:     labelFor(n),
			Flags:     flags,
			FlagNames: flags.Names(),
			Severity:  flags.Severity(),
		}
		exposures = append(exposures, exp)

		byType[string(n.Type())]++
		bySev[flags.Severity().String()]++
		for _, name := range exp.FlagNames {
			byFlag[name]++
		}
		if flags.QuantumVulnerableAlgorithm {
			quantum++
		}
		if flags.LegacyProtocol && n.Type() == graph.NodeEndpoint {
			legacyEP++
		}
		if flags.Expired {
			expired++
		}
		if flags.Expiring {
			expiring++
		}
	}

	sort.Slice(exposures, func(i, j int) bool {
		if exposures[i].Severity != exposures[j].Severity {
			return exposures[i].Severity > exposures[j].Severity
		}
		return exposures[i].NodeID < exposures[j].NodeID
	})

	rep.Nodes = exposures
	rep.Summary = Summary{
		TotalNodes:              total,
		FlaggedNodes:            len(exposures),
		ByFlag:                  toCounts(byFlag),
		ByNodeType:              toCounts(byType),
		BySeverity:              toCounts(bySev),
		QuantumVulnerableAssets: quantum,
		LegacyEndpoints:         legacyEP,
		Expired:                 expired,
		Expiring:                expiring,
		PQCReadyEndpoints:       pqcReady,
	}
	return rep
}

// summarize builds an empty-but-non-nil Summary (used for the nil-graph path).
func summarize(_ []NodeExposure) Summary {
	return Summary{
		ByFlag:     []Count{},
		ByNodeType: []Count{},
		BySeverity: []Count{},
	}
}

// relevant reports whether a node type participates in PQC scoring.
func relevant(t graph.NodeType) bool {
	switch t {
	case graph.NodeCertificate, graph.NodeCertificateRequest, graph.NodeKey,
		graph.NodeEndpoint, graph.NodeConfigFile, graph.NodeConfigEndpoint:
		return true
	default:
		return false
	}
}

// filesWithEndpoints returns the set of ConfigFile node IDs that have at least
// one ConfigEndpoint child, discovered from the graph's `stored_in` edges
// (cfgendpoint → file). These files' per-endpoint attribution is more precise
// than a file-level flag, so Score suppresses the file-level legacy_protocol flag
// for them (the endpoints carry it) — avoiding double-counting a single weak block
// as both a file finding and an endpoint finding. A config file with NO endpoint
// children (openssl.cnf, ssh_config, a bare include snippet) is absent from this
// set and keeps its file-level flag.
func filesWithEndpoints(g *graph.Graph) map[string]bool {
	out := map[string]bool{}
	for _, e := range g.Edges() {
		if e.Type == graph.EdgeStoredIn && strings.HasPrefix(e.From, "cfgendpoint:") {
			out[e.To] = true
		}
	}
	return out
}

// toCounts turns a name→count map into a Name-sorted slice for deterministic
// output. A nil/empty map yields an empty (non-nil) slice.
func toCounts(m map[string]int) []Count {
	out := make([]Count, 0, len(m))
	for k, v := range m {
		out = append(out, Count{Name: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
