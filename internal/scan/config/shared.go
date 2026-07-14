package config

import "strings"

// knownProtocols is the canonical spelling of every protocol token the config
// classes use (configs.yaml conventions header). canonProto normalises a token
// to one of these so add/remove operations match regardless of input case.
var knownProtocols = []string{"SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"}

// tlsOrder is the low-to-high ordering used to render a protocol set and to
// apply an ssl-min-ver floor. SSLv3 sorts below TLSv1.
var tlsOrder = []string{"SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"}

// canonProto returns the canonical spelling of a protocol token, or the token
// unchanged when it is not recognised (so unusual tokens are preserved, not
// silently dropped).
func canonProto(tok string) string {
	for _, p := range knownProtocols {
		if strings.EqualFold(tok, p) {
			return p
		}
	}
	return tok
}

// protocolSet is an ordered set of protocol tokens.
type protocolSet map[string]bool

// sorted renders the set in canonical low-to-high order, appending any
// unrecognised members afterwards in insertion-independent (map) order made
// deterministic by the caller only for known tokens.
func (s protocolSet) sorted() []string {
	out := make([]string, 0, len(s))
	seen := map[string]bool{}
	for _, p := range tlsOrder {
		if s[p] {
			out = append(out, p)
			seen[p] = true
		}
	}
	// Any non-standard tokens (rare) appended in sorted order for determinism.
	var extra []string
	for p := range s {
		if !seen[p] {
			extra = append(extra, p)
		}
	}
	sortStrings(extra)
	return append(out, extra...)
}

// sortStrings is a tiny insertion sort (avoids importing sort for one call and
// keeps the helper allocation-free for the short slices seen here).
func sortStrings(xs []string) {
	for i := 1; i < len(xs); i++ {
		for j := i; j > 0 && xs[j-1] > xs[j]; j-- {
			xs[j-1], xs[j] = xs[j], xs[j-1]
		}
	}
}

// splitFields splits a line into whitespace-separated fields, treating single-
// and double-quoted spans as one field (quotes removed). Used by the line-based
// parsers (apache, sshd, haproxy) so quoted arguments stay intact.
func splitFields(s string) []string {
	var out []string
	var b strings.Builder
	var quote rune
	started := false
	flush := func() {
		if started {
			out = append(out, b.String())
			b.Reset()
			started = false
		}
	}
	for _, c := range s {
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			} else {
				b.WriteRune(c)
			}
		case c == '\'' || c == '"':
			quote = c
			started = true
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
			flush()
		default:
			b.WriteRune(c)
			started = true
		}
	}
	flush()
	return out
}

// splitList splits a ':'-delimited value (cipher lists) into non-empty tokens,
// preserving order.
func splitList(s string) []string {
	parts := strings.Split(s, ":")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// splitCommaList splits a ','-delimited value (ssh algorithm lists) into
// non-empty trimmed tokens, preserving order.
func splitCommaList(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// appendUnique appends v to xs if not already present, preserving order.
func appendUnique(xs []string, v string) []string {
	for _, x := range xs {
		if x == v {
			return xs
		}
	}
	return append(xs, v)
}
