package config

import (
	"strings"

	"github.com/Ubermm/cryptoscan/internal/graph"
)

// apacheLine is one logical directive line (after comment stripping and
// backslash continuation joining), with the physical line it started on.
type apacheLine struct {
	text string
	line int
}

// apacheLogicalLines splits Apache config text into logical lines: '#'-comment
// lines (leading whitespace allowed) are dropped, and a trailing '\' continues
// onto the next physical line. Line numbers refer to where the logical line
// started.
func apacheLogicalLines(text string) []apacheLine {
	var out []apacheLine
	phys := strings.Split(text, "\n")

	var buf strings.Builder
	startLine := 0
	continuing := false

	for i, raw := range phys {
		l := strings.TrimRight(raw, "\r")
		if !continuing {
			trimmed := strings.TrimLeft(l, " \t")
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			startLine = i + 1
			buf.Reset()
		}
		if strings.HasSuffix(l, "\\") {
			buf.WriteString(strings.TrimSuffix(l, "\\"))
			continuing = true
			continue
		}
		buf.WriteString(l)
		continuing = false
		out = append(out, apacheLine{text: buf.String(), line: startLine})
	}
	if continuing {
		out = append(out, apacheLine{text: buf.String(), line: startLine})
	}
	return out
}

// apacheBase is the full protocol set implied by the Apache token `all`
// (configs.yaml convention header, Apache 2.4 semantics).
var apacheBase = []string{"SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"}

// resolveApacheProtocols evaluates one SSLProtocol argument list into an enabled
// set using Apache 2.4 semantics: `all` = the full base set, `-all` clears,
// `+X` adds, `-X` removes, a bare token adds; all applied left to right.
func resolveApacheProtocols(tokens []string) protocolSet {
	s := protocolSet{}
	for _, t := range tokens {
		if t == "" {
			continue
		}
		switch {
		case strings.EqualFold(t, "all"):
			for _, p := range apacheBase {
				s[p] = true
			}
		case strings.HasPrefix(t, "+"):
			name := t[1:]
			if strings.EqualFold(name, "all") {
				for _, p := range apacheBase {
					s[p] = true
				}
			} else {
				s[canonProto(name)] = true
			}
		case strings.HasPrefix(t, "-"):
			name := t[1:]
			if strings.EqualFold(name, "all") {
				for k := range s {
					delete(s, k)
				}
			} else {
				delete(s, canonProto(name))
			}
		default:
			s[canonProto(t)] = true
		}
	}
	return s
}

// parseApache claims a file when it contains at least one active Apache crypto
// directive (SSLProtocol, SSLCipherSuite, SSLCertificateFile,
// SSLCertificateKeyFile). Directive names match case-insensitively.
func parseApache(text string) *parseResult {
	protocols := protocolSet{}
	var ciphers, certRefs []string
	var directives []graph.Directive
	var refs []pathRef
	crypto := false

	for _, ln := range apacheLogicalLines(text) {
		fields := splitFields(ln.text)
		if len(fields) == 0 {
			continue
		}
		name := fields[0]
		args := fields[1:]

		switch {
		case strings.EqualFold(name, "SSLProtocol"):
			crypto = true
			for p := range resolveApacheProtocols(args) {
				protocols[p] = true
			}
			directives = append(directives, graph.Directive{Name: "SSLProtocol", Value: strings.Join(args, " "), Line: ln.line})
		case strings.EqualFold(name, "SSLCipherSuite"):
			crypto = true
			if len(args) > 0 {
				for _, c := range splitList(args[0]) {
					ciphers = appendUnique(ciphers, c)
				}
				directives = append(directives, graph.Directive{Name: "SSLCipherSuite", Value: args[0], Line: ln.line})
			}
		case strings.EqualFold(name, "SSLCertificateFile"):
			crypto = true
			if len(args) > 0 {
				certRefs = appendUnique(certRefs, args[0])
				refs = append(refs, pathRef{raw: args[0], line: ln.line, kind: "SSLCertificateFile"})
				directives = append(directives, graph.Directive{Name: "SSLCertificateFile", Value: args[0], Line: ln.line})
			}
		case strings.EqualFold(name, "SSLCertificateKeyFile"):
			crypto = true
			if len(args) > 0 {
				refs = append(refs, pathRef{raw: args[0], line: ln.line, kind: "SSLCertificateKeyFile"})
				directives = append(directives, graph.Directive{Name: "SSLCertificateKeyFile", Value: args[0], Line: ln.line})
			}
		}
	}

	if !crypto {
		return nil
	}

	attrs := map[string]any{}
	if len(protocols) > 0 {
		attrs["protocols"] = protocols.sorted()
	}
	if len(ciphers) > 0 {
		attrs["ciphers"] = ciphers
	}
	if len(certRefs) > 0 {
		attrs["cert_refs"] = certRefs
	}

	return &parseResult{
		format:     "apache",
		class:      "tls_config",
		attrs:      attrs,
		directives: directives,
		refs:       refs,
	}
}
