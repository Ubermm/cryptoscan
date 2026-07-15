package config

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// maxIncludeDepth bounds include recursion so a pathological chain (or a cycle
// that somehow evades the seen-set) cannot spin forever (issue #3).
const maxIncludeDepth = 8

// foldIncludes resolves an endpoint's include directives relative to the
// including config file and folds the included TLS directives into the endpoint's
// still-empty fields (issue #3): a protocol/cipher policy split into a shared
// snippet is attributed back to the server that pulled it in. Resolution is
// deterministic (glob matches sorted), cycle-guarded (a file is folded at most
// once per endpoint), and depth-bounded; a missing target is skipped rather than
// panicking. It is a no-op for endpoints with no includes.
func foldIncludes(format, configDisk string, ep *endpointResult) {
	if len(ep.includes) == 0 {
		return
	}
	seen := map[string]bool{cleanDisk(configDisk): true}
	foldIncludeList(format, configDisk, ep.includes, ep, 1, seen)
}

// foldIncludeList resolves each include target (relative to baseDisk's directory,
// glob-expanded) and folds it into ep. seen guards against cycles and repeats.
func foldIncludeList(format, baseDisk string, includes []string, ep *endpointResult, depth int, seen map[string]bool) {
	if depth > maxIncludeDepth {
		return
	}
	dir := filepath.Dir(baseDisk)
	for _, inc := range includes {
		for _, target := range resolveIncludeTargets(dir, inc) {
			ct := cleanDisk(target)
			if seen[ct] {
				continue // cycle / already folded — note and continue
			}
			seen[ct] = true
			data, err := os.ReadFile(target) //nolint:gosec // corpus path is developer-controlled
			if err != nil || len(data) == 0 || len(data) > maxConfigSize {
				continue // missing/oversize target: note + continue, never panic
			}
			if isBinary(data) {
				continue
			}
			foldSnippet(format, target, string(data), ep, depth, seen)
		}
	}
}

// resolveIncludeTargets turns one include argument into the concrete file paths it
// names, relative to dir. A glob (containing '*', '?', or '[') is expanded via
// filepath.Glob and the matches are sorted for determinism; a plain path is
// returned as-is (its existence is checked when read).
func resolveIncludeTargets(dir, inc string) []string {
	native := filepath.FromSlash(inc)
	var base string
	if filepath.IsAbs(native) || isAbsPosix(inc) {
		base = native
	} else {
		base = filepath.Join(dir, native)
	}
	if strings.ContainsAny(base, "*?[") {
		matches, err := filepath.Glob(base)
		if err != nil || len(matches) == 0 {
			return nil
		}
		sort.Strings(matches)
		return matches
	}
	return []string{base}
}

// foldSnippet folds an included snippet's TLS directives into ep (only fields ep
// has not already set win, so an outer/own directive keeps priority), then
// recurses into any nested includes the snippet declares.
func foldSnippet(format, disk, text string, ep *endpointResult, depth int, seen map[string]bool) {
	switch format {
	case "nginx":
		sc := scanNginxSnippet(text)
		mergeSnippetScope(ep, sc)
		foldIncludeList(format, disk, sc.includes, ep, depth+1, seen)
	case "apache":
		var s apacheScope
		for _, ln := range apacheLogicalLines(text) {
			fields := splitFields(ln.text)
			if len(fields) == 0 {
				continue
			}
			applyApacheDirective(&s, fields[0], fields[1:], ln.line)
		}
		mergeApacheSnippet(ep, &s)
		foldIncludeList(format, disk, s.includes, ep, depth+1, seen)
	}
}

// snippetScope is the flat set of TLS directives extracted from an nginx snippet.
type snippetScope struct {
	protocols   []string
	ciphers     []string
	certRef     string
	certLine    int
	keyRef      string
	keyLine     int
	dhparam     string
	ecdhCurve   string
	clientCert  string
	trustedCert string
	includes    []string
}

// scanNginxSnippet extracts the TLS directives from a flat nginx snippet (no
// block model needed — snippets are directive lists) using the same tokenizer as
// the file parser.
func scanNginxSnippet(text string) snippetScope {
	var sc snippetScope
	for _, s := range nginxTokenize(text) {
		if len(s.words) == 0 {
			continue
		}
		name := s.words[0]
		args := s.words[1:]
		switch name {
		case "ssl_protocols":
			for _, a := range args {
				sc.protocols = appendUnique(sc.protocols, canonProto(a))
			}
		case "ssl_ciphers":
			if len(args) > 0 {
				for _, c := range splitList(args[0]) {
					sc.ciphers = appendUnique(sc.ciphers, c)
				}
			}
		case "ssl_certificate":
			if len(args) > 0 && sc.certRef == "" {
				sc.certRef = args[0]
				sc.certLine = s.line
			}
		case "ssl_certificate_key":
			if len(args) > 0 && sc.keyRef == "" {
				sc.keyRef = args[0]
				sc.keyLine = s.line
			}
		case "ssl_dhparam":
			if len(args) > 0 {
				sc.dhparam = args[0]
			}
		case "ssl_ecdh_curve":
			if len(args) > 0 {
				sc.ecdhCurve = args[0]
			}
		case "ssl_client_certificate":
			if len(args) > 0 {
				sc.clientCert = args[0]
			}
		case "ssl_trusted_certificate":
			if len(args) > 0 {
				sc.trustedCert = args[0]
			}
		case "include":
			if len(args) > 0 {
				sc.includes = append(sc.includes, args[0])
			}
		}
	}
	return sc
}

// mergeSnippetScope folds an nginx snippet's directives into ep's empty fields.
// Cert/key refs (issue #6) fold in exactly like protocols/ciphers: an included
// ssl_certificate is attributed back to the endpoint that pulled it in, but only
// when the endpoint has none of its own (own/outer directives keep priority). This
// applies across MULTIPLE includes — there is no first-include short-circuit; each
// snippet fills whatever fields remain empty.
func mergeSnippetScope(ep *endpointResult, sc snippetScope) {
	if len(ep.protocols) == 0 {
		ep.protocols = sc.protocols
	}
	if len(ep.ciphers) == 0 {
		ep.ciphers = sc.ciphers
	}
	if ep.certRef() == "" && sc.certRef != "" {
		ep.certRefs = appendUnique(ep.certRefs, sc.certRef)
		ep.refs = append(ep.refs, pathRef{raw: sc.certRef, line: sc.certLine, kind: "ssl_certificate"})
	}
	if !ep.hasKeyRef && sc.keyRef != "" {
		ep.hasKeyRef = true
		ep.refs = append(ep.refs, pathRef{raw: sc.keyRef, line: sc.keyLine, kind: "ssl_certificate_key"})
	}
	if ep.dhparam == "" {
		ep.dhparam = sc.dhparam
	}
	if ep.ecdhCurve == "" {
		ep.ecdhCurve = sc.ecdhCurve
	}
	if len(ep.caRefs) == 0 && sc.clientCert != "" {
		ep.caRefs = appendUnique(ep.caRefs, sc.clientCert)
	}
	if len(ep.trustedRefs) == 0 && sc.trustedCert != "" {
		ep.trustedRefs = appendUnique(ep.trustedRefs, sc.trustedCert)
	}
}

// mergeApacheSnippet folds an apache snippet scope into ep's empty fields,
// including cert/key refs (issue #6) so an SSLCertificateFile split into an
// Include is attributed back to the vhost that pulled it in. Own/outer directives
// keep priority; multiple includes each fill whatever remains empty.
func mergeApacheSnippet(ep *endpointResult, s *apacheScope) {
	if len(ep.protocols) == 0 && s.protocolsSet {
		ep.protocols = s.protocols.sorted()
	}
	if len(ep.ciphers) == 0 {
		ep.ciphers = firstNonEmptyList(nil, s.ciphers)
	}
	if ep.certRef() == "" && s.certRef != "" {
		ep.certRefs = appendUnique(ep.certRefs, s.certRef)
		ep.refs = append(ep.refs, pathRef{raw: s.certRef, line: s.certLine, kind: "SSLCertificateFile"})
	}
	if !ep.hasKeyRef && s.keyRef != "" {
		ep.hasKeyRef = true
		ep.refs = append(ep.refs, pathRef{raw: s.keyRef, line: s.keyLine, kind: "SSLCertificateKeyFile"})
	}
	if ep.dhparam == "" {
		ep.dhparam = s.dhparam
	}
	if ep.ecdhCurve == "" {
		ep.ecdhCurve = s.ecdhCurve
	}
	if len(ep.caRefs) == 0 {
		ep.caRefs = firstNonEmptyList(nil, s.caRefs)
	}
	if len(ep.trustedRefs) == 0 {
		ep.trustedRefs = firstNonEmptyList(nil, s.trustedRefs)
	}
}

// cleanDisk returns the cleaned absolute form of a path for cycle-guard keys.
func cleanDisk(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		return filepath.Clean(abs)
	}
	return filepath.Clean(p)
}
