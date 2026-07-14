// Package policy is the deterministic threshold-gate evaluator for cryptoscan's
// `--fail-on` policy flag. Given the scanned *graph.Graph and the PQC exposure
// Report already computed for it (internal/pqc), it decides — purely, with no
// I/O and no wall clock — whether the estate trips any of a caller-supplied set
// of risk THRESHOLDS, and lists every breach with provable, sorted detail.
//
// # Design constraints (binding)
//
//   - Deterministic / provable only (CLAUDE.md principle 1). Every breach traces
//     to a concrete graph node attribute the scanner already proved: a
//     certificate signature algorithm, an RSA key size, a certificate validity
//     date, or a resolved protocol set on an Endpoint/ConfigFile node. Nothing is
//     guessed; the same (graph, report, thresholds) always yields an identical
//     Result.
//   - Graph-primary (principle 2). Thresholds are projections of the graph, read
//     through the public graph/pqc APIs. The package never mutates the graph and
//     performs no I/O.
//   - Standard library + internal only. No new dependencies.
//
// # Token vocabulary
//
// Thresholds are named by short, case-insensitive tokens. Each maps to a
// predicate over a graph node (and, where the condition is exactly a pinned PQC
// flag, that node's pqc.NodeExposure). See tokens.go for the authoritative table;
// the tokens are:
//
//	tls10             an Endpoint or tls_config that ALLOWS TLS 1.0 (TLSv1)
//	tls11             an Endpoint or tls_config that ALLOWS TLS 1.1
//	ssl3              an Endpoint or tls_config that ALLOWS SSLv3
//	legacy-tls        any of the above (union: any sub-TLS-1.2 protocol allowed)
//	sha1              a certificate/CSR with a SHA-1 signature algorithm
//	md5               a certificate/CSR with an MD5 signature algorithm
//	weak-signature    sha1 ∪ md5 (the pinned weak_signature flag: SHA-1/MD5/MD2)
//	rsa1024           an RSA key/cert below 2048 bits (the weak_key condition)
//	weak-key          alias of rsa1024
//	expired           any expired certificate
//	expiring          any certificate expiring within the pqc look-ahead window
//	quantum-vulnerable any quantum_vulnerable_algorithm asset (all classical
//	                  asymmetric material + non-hybrid key exchange)
//
// The protocol-version tokens (tls10/tls11/ssl3) read the ACTUAL protocol set
// from the node's attributes — an Endpoint's negotiated_protocol /
// protocols_supported, a ConfigFile's resolved protocols / min_protocol — so a
// caller may gate on TLS 1.0 specifically while tolerating TLS 1.1, rather than
// collapsing every sub-1.2 version into one "legacy" bucket.
package policy

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Ubermm/cryptoscan/internal/graph"
	"github.com/Ubermm/cryptoscan/internal/pqc"
)

// Threshold is one parsed policy gate: a canonical token plus its predicate.
// Construct only via ParseThresholds (the predicate is unexported); pass the
// resulting slice to Evaluate.
type Threshold struct {
	// Token is the canonical (lower-case) token name, e.g. "tls10".
	Token string
	spec  *tokenSpec
}

// Breach is a single (threshold, node) violation: the token that tripped, the
// offending graph node's identity and human label, and a short provable detail
// (the signature algorithm, key size, protocol evidence, or expiry date that
// caused the match).
type Breach struct {
	// Token is the canonical token that tripped (e.g. "sha1").
	Token string
	// NodeID is the offending graph node's identity key.
	NodeID string
	// NodeType is the offending node's kind.
	NodeType graph.NodeType
	// Label is a human-friendly identifier for the node (cert CN, key
	// algorithm/size, endpoint host:port, or config-file path).
	Label string
	// Detail is the provable evidence for the breach (e.g. "signature=SHA1-RSA",
	// "RSA 1024-bit", "protocols_supported includes TLSv1", "notAfter=2021-01-01").
	Detail string
}

// Result is the outcome of Evaluate: every breach across all thresholds, sorted
// deterministically by (token, node ID, detail).
type Result struct {
	// Breaches lists every (threshold, node) violation, stably sorted.
	Breaches []Breach
}

// Breached reports whether any threshold was tripped.
func (r Result) Breached() bool { return len(r.Breaches) > 0 }

// CountByToken tallies breaches per token, sorted by token name. It is a
// convenience for callers rendering a summary; the underlying Breaches slice
// remains the source of truth.
func (r Result) CountByToken() []TokenCount {
	m := map[string]int{}
	for _, b := range r.Breaches {
		m[b.Token]++
	}
	out := make([]TokenCount, 0, len(m))
	for tok, c := range m {
		out = append(out, TokenCount{Token: tok, Count: c})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Token < out[j].Token })
	return out
}

// TokenCount is a (token, count) pair produced by Result.CountByToken.
type TokenCount struct {
	Token string
	Count int
}

// Describe returns the one-line description of a token, or "" if the token is
// unknown. It is used to render the token vocabulary in CLI help.
func Describe(token string) string {
	if spec, ok := vocabulary[strings.ToLower(strings.TrimSpace(token))]; ok {
		return spec.desc
	}
	return ""
}

// ValidTokens returns the accepted token names in sorted order, for help text
// and error messages.
func ValidTokens() []string {
	out := make([]string, 0, len(vocabulary))
	for tok := range vocabulary {
		out = append(out, tok)
	}
	sort.Strings(out)
	return out
}

// ParseThresholds resolves a list of token strings into Thresholds. Tokens are
// matched case-insensitively and trimmed; blank entries are ignored and repeats
// are de-duplicated (first occurrence wins, preserving order). An unknown token
// is a usage error whose message lists every valid token.
func ParseThresholds(tokens []string) ([]Threshold, error) {
	var out []Threshold
	seen := map[string]bool{}
	for _, raw := range tokens {
		tok := strings.ToLower(strings.TrimSpace(raw))
		if tok == "" {
			continue
		}
		spec, ok := vocabulary[tok]
		if !ok {
			return nil, fmt.Errorf("unknown --fail-on token %q: valid tokens are %s",
				raw, strings.Join(ValidTokens(), ", "))
		}
		if seen[tok] {
			continue
		}
		seen[tok] = true
		out = append(out, Threshold{Token: tok, spec: spec})
	}
	return out, nil
}

// Evaluate applies every threshold to every relevant node of g and returns the
// breaches. It is pure and deterministic: g is read (never mutated), exposure is
// the pqc.Report already computed for g at the caller's reference time (reused so
// flag-based tokens stay perfectly aligned with the pinned PQC flags), and the
// output is stably sorted by (token, node ID, detail).
//
// A nil graph or an empty threshold set yields an un-breached Result.
func Evaluate(g *graph.Graph, exposure pqc.Report, thresholds []Threshold) Result {
	if g == nil || len(thresholds) == 0 {
		return Result{}
	}

	// Index the exposure by node ID so a flag-based predicate can look up the
	// node's pinned PQC flags in O(1). Nodes with no flags are simply absent.
	expByID := make(map[string]pqc.NodeExposure, len(exposure.Nodes))
	for _, e := range exposure.Nodes {
		expByID[e.NodeID] = e
	}

	var breaches []Breach
	// g.Nodes() is already sorted by ID, so iteration is deterministic.
	for _, n := range g.Nodes() {
		exp, hasExp := expByID[n.ID()]
		for _, th := range thresholds {
			matched, detail := th.spec.match(n, exp, hasExp)
			if !matched {
				continue
			}
			breaches = append(breaches, Breach{
				Token:    th.Token,
				NodeID:   n.ID(),
				NodeType: n.Type(),
				Label:    labelFor(n, exp, hasExp),
				Detail:   detail,
			})
		}
	}

	sort.SliceStable(breaches, func(i, j int) bool {
		if breaches[i].Token != breaches[j].Token {
			return breaches[i].Token < breaches[j].Token
		}
		if breaches[i].NodeID != breaches[j].NodeID {
			return breaches[i].NodeID < breaches[j].NodeID
		}
		return breaches[i].Detail < breaches[j].Detail
	})
	return Result{Breaches: breaches}
}
