package config

import (
	"strings"

	"github.com/cryptoscan/cryptoscan/internal/graph"
)

// nginxStatement is one directive: its whitespace-separated words and the line
// on which the first word appeared.
type nginxStatement struct {
	words []string
	line  int
}

// nginxTokenize turns nginx config text into a flat list of directives. It is a
// real tokenizer: it honours '#' comments (to end of line, outside quotes),
// single/double quoted strings (kept as one word, quotes stripped), and treats
// '{', '}' and ';' as statement terminators. Block nesting is intentionally
// flattened — every ssl_* directive is collected regardless of the server block
// it lives in, which is exactly the per-file union the manifest expects. Any
// unterminated directive, block or quote is flushed at EOF without panicking.
func nginxTokenize(text string) []nginxStatement {
	var stmts []nginxStatement
	var words []string
	var b strings.Builder
	stmtLine, wordLine, line := 0, 0, 1

	emitWord := func() {
		if b.Len() > 0 {
			if len(words) == 0 {
				stmtLine = wordLine
			}
			words = append(words, b.String())
			b.Reset()
		}
	}
	emitStmt := func() {
		emitWord()
		if len(words) > 0 {
			stmts = append(stmts, nginxStatement{words: words, line: stmtLine})
			words = nil
		}
	}

	runes := []rune(text)
	for i := 0; i < len(runes); {
		c := runes[i]
		switch {
		case c == '\n':
			line++
			i++
		case c == '#':
			for i < len(runes) && runes[i] != '\n' {
				i++
			}
		case c == '\'' || c == '"':
			if b.Len() == 0 {
				wordLine = line
			}
			quote := c
			i++
			for i < len(runes) && runes[i] != quote {
				if runes[i] == '\n' {
					line++
				}
				b.WriteRune(runes[i])
				i++
			}
			if i < len(runes) {
				i++ // consume closing quote
			}
			// Quoted content stays in the builder and is flushed by the normal
			// emitWord path at the next delimiter.
		case c == ';' || c == '{' || c == '}':
			emitStmt()
			i++
		case c == ' ' || c == '\t' || c == '\r':
			emitWord()
			i++
		default:
			if b.Len() == 0 {
				wordLine = line
			}
			b.WriteRune(c)
			i++
		}
	}
	emitStmt()
	return stmts
}

// parseNginx claims a file when it contains at least one active nginx crypto
// directive (ssl_protocols, ssl_ciphers, ssl_certificate, ssl_certificate_key).
func parseNginx(text string) *parseResult {
	stmts := nginxTokenize(text)

	var protocols, ciphers, certRefs []string
	var directives []graph.Directive
	var refs []pathRef
	crypto := false

	for _, s := range stmts {
		if len(s.words) == 0 {
			continue
		}
		name := s.words[0]
		args := s.words[1:]
		switch name {
		case "ssl_protocols":
			crypto = true
			for _, a := range args {
				protocols = appendUnique(protocols, canonProto(a))
			}
			directives = append(directives, graph.Directive{Name: name, Value: strings.Join(args, " "), Line: s.line})
		case "ssl_ciphers":
			crypto = true
			if len(args) > 0 {
				for _, cph := range splitList(args[0]) {
					ciphers = appendUnique(ciphers, cph)
				}
				directives = append(directives, graph.Directive{Name: name, Value: args[0], Line: s.line})
			}
		case "ssl_certificate":
			crypto = true
			if len(args) > 0 {
				certRefs = appendUnique(certRefs, args[0])
				refs = append(refs, pathRef{raw: args[0], line: s.line, kind: name})
				directives = append(directives, graph.Directive{Name: name, Value: args[0], Line: s.line})
			}
		case "ssl_certificate_key":
			crypto = true
			if len(args) > 0 {
				refs = append(refs, pathRef{raw: args[0], line: s.line, kind: name})
				directives = append(directives, graph.Directive{Name: name, Value: args[0], Line: s.line})
			}
		case "include":
			if len(args) > 0 {
				// Noted for provenance; included files are NOT merged (each is
				// scanned as its own asset).
				directives = append(directives, graph.Directive{Name: name, Value: args[0], Line: s.line})
			}
		}
	}

	if !crypto {
		return nil
	}

	attrs := map[string]any{}
	if len(protocols) > 0 {
		attrs["protocols"] = protocols
	}
	if len(ciphers) > 0 {
		attrs["ciphers"] = ciphers
	}
	if len(certRefs) > 0 {
		attrs["cert_refs"] = certRefs
	}

	return &parseResult{
		format:     "nginx",
		class:      "tls_config",
		attrs:      attrs,
		directives: directives,
		refs:       refs,
	}
}
