package config

import (
	"strings"

	"github.com/cryptoscan/cryptoscan/internal/graph"
)

// opensslProtocols is the exact, unquoted set a MinProtocol value may take
// (grammar ^(SSLv3|TLSv1(\.[123])?|DTLSv1(\.2)?)$). A quoted value such as
// "TLSv1.2" — as a Python string literal would write it — is not in this set,
// so it fails the value-shape check.
var opensslProtocols = map[string]bool{
	"SSLv3":    true,
	"TLSv1":    true,
	"TLSv1.1":  true,
	"TLSv1.2":  true,
	"TLSv1.3":  true,
	"DTLSv1":   true,
	"DTLSv1.2": true,
}

// opensslEntry is one `key = value` assignment recorded with its containing
// section and line, so detection can test section membership and reachability.
type opensslEntry struct {
	section string
	key     string
	val     string
	line    int
}

// parseOpenSSL claims a file as an openssl.cnf (class tls_config) only when ALL
// of the following hold — the shape a genuine system OpenSSL config has and a
// stray INI file (a `.gitconfig` with a `[tls]` block) or a Python class body
// does not:
//
//   - INI STRUCTURE: the file has at least one `[section]` header and parses as
//     `[section]` headers plus `key = value` assignments. `class TLS:` is not a
//     section header, so a Python file exposes zero sections and is rejected.
//   - POINTER IDIOM (reachability): the MinProtocol/CipherString assignment sits
//     inside a section reachable from an `openssl_conf` root key by following the
//     section-name pointer chain (openssl_conf = default_conf; [default_conf]
//     ssl_conf = ssl_sect; [ssl_sect] system_default = system_default_sect;
//     [system_default_sect] MinProtocol = ...). A `.gitconfig` `[tls]` section
//     that nothing points at is unreachable and is rejected.
//   - VALUE SHAPE: a MinProtocol value must be one of opensslProtocols, written
//     unquoted. CipherString carries an opaque cipher string and is accepted for
//     its shape by virtue of the assignment alone.
//
// Only the first '=' splits a line, so values may contain further '=' (e.g.
// DEFAULT@SECLEVEL=2). Key names match exactly (OpenSSL is case-sensitive here).
func parseOpenSSL(text string) *parseResult {
	var entries []opensslEntry
	sectionExists := map[string]bool{"": true} // "" is the default/global section
	hasSectionHeader := false
	current := ""

	for i, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			end := strings.IndexByte(line, ']')
			if end < 0 {
				continue
			}
			current = strings.TrimSpace(line[1:end])
			sectionExists[current] = true
			hasSectionHeader = true
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		key := strings.TrimSpace(line[:eq])
		val := strings.TrimSpace(line[eq+1:])
		entries = append(entries, opensslEntry{section: current, key: key, val: val, line: i + 1})
	}

	if !hasSectionHeader {
		return nil
	}

	reachable := reachableOpenSSLSections(entries, sectionExists)

	var minProtocol, cipherString string
	var minLine, cipherLine int
	for _, e := range entries {
		if !reachable[e.section] {
			continue
		}
		switch e.key {
		case "MinProtocol":
			if minProtocol == "" && opensslProtocols[e.val] {
				minProtocol, minLine = e.val, e.line
			}
		case "CipherString":
			if cipherString == "" {
				cipherString, cipherLine = e.val, e.line
			}
		}
	}

	if minProtocol == "" && cipherString == "" {
		return nil
	}

	var directives []graph.Directive
	attrs := map[string]any{}
	if minProtocol != "" {
		attrs["min_protocol"] = minProtocol
		directives = append(directives, graph.Directive{Name: "MinProtocol", Value: minProtocol, Line: minLine})
	}
	if cipherString != "" {
		attrs["cipher_string"] = cipherString
		directives = append(directives, graph.Directive{Name: "CipherString", Value: cipherString, Line: cipherLine})
	}

	return &parseResult{
		format:     "openssl",
		class:      "tls_config",
		attrs:      attrs,
		directives: directives,
	}
}

// reachableOpenSSLSections returns the set of section names reachable from an
// `openssl_conf` root key by following pointers — assignments whose value names
// an existing section. The default/global section "" is a valid pointer origin
// (openssl_conf itself lives there), but it is only reachable as a target if
// something explicitly points at "", which nothing does; MinProtocol therefore
// never counts from the global section.
func reachableOpenSSLSections(entries []opensslEntry, sectionExists map[string]bool) map[string]bool {
	// adjacency: section -> sections it points at (via a value that names a section)
	adj := map[string][]string{}
	var roots []string
	for _, e := range entries {
		if sectionExists[e.val] {
			adj[e.section] = append(adj[e.section], e.val)
		}
		if e.key == "openssl_conf" && sectionExists[e.val] {
			roots = append(roots, e.val)
		}
	}

	reachable := map[string]bool{}
	var queue []string
	for _, r := range roots {
		if !reachable[r] {
			reachable[r] = true
			queue = append(queue, r)
		}
	}
	for len(queue) > 0 {
		s := queue[0]
		queue = queue[1:]
		for _, next := range adj[s] {
			if !reachable[next] {
				reachable[next] = true
				queue = append(queue, next)
			}
		}
	}
	return reachable
}
