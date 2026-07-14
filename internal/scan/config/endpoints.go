package config

import (
	"strconv"
	"strings"
)

// endpointResult is one TLS-terminating server/vhost/frontend-bind block resolved
// on its own. It carries the block's identity (server names, listen/bind
// addr:port, port) and its RESOLVED crypto state (protocols, ciphers, cert/key
// refs, and the quantum-relevant dhparam/ecdh_curve plus mTLS trust anchors). The
// includes field records any include directives in the block's effective scope so
// the graph-population step can fold their directives in (issue #3); refs holds
// the cert/key references used to build `references` edges. This mirrors the
// per-file parseResult but at block granularity — the per-endpoint attribution
// DESIGN.md §1 (ConfigEndpoint) calls for.
type endpointResult struct {
	blockIndex  int
	serverNames []string
	listens     []string
	port        int
	protocols   []string
	ciphers     []string
	certRefs    []string
	dhparam     string
	ecdhCurve   string
	caRefs      []string
	trustedRefs []string
	includes    []string
	line        int
	refs        []pathRef
	hasKeyRef   bool
}

// attrs renders the endpoint's resolved state as the ConfigEndpoint node Attrs
// map, omitting empty values so a downstream consumer only sees what was proven.
func (e *endpointResult) attrs() map[string]any {
	m := map[string]any{}
	if len(e.serverNames) > 0 {
		m["server_name"] = e.serverNames
	}
	if len(e.listens) > 0 {
		m["listen"] = e.listens
	}
	if e.port > 0 {
		m["port"] = e.port
	}
	if len(e.protocols) > 0 {
		m["protocols"] = e.protocols
	}
	if len(e.ciphers) > 0 {
		m["ciphers"] = e.ciphers
	}
	if len(e.certRefs) > 0 {
		m["cert_refs"] = e.certRefs
	}
	if e.dhparam != "" {
		m["dhparam"] = e.dhparam
	}
	if e.ecdhCurve != "" {
		m["ecdh_curve"] = e.ecdhCurve
	}
	if len(e.caRefs) > 0 {
		m["ca_refs"] = e.caRefs
	}
	if len(e.trustedRefs) > 0 {
		m["trusted_refs"] = e.trustedRefs
	}
	return m
}

// parsePort extracts the numeric port from a listen/bind address token. It reads
// the digits after the final ':' (so "[::]:443", "*:443", ":443" and "1.2.3.4:8443"
// all yield the port), or the whole token when it is a bare numeric port. A token
// with no port yields 0.
func parsePort(token string) int {
	s := token
	if i := strings.LastIndex(token, ":"); i >= 0 {
		s = token[i+1:]
	}
	s = strings.TrimSpace(s)
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return 0
}

// --- nginx ------------------------------------------------------------------

// nginxBraceToken is a tokenized nginx statement that, unlike nginxTokenize,
// preserves '{' and '}' as their own single-word statements so brace depth (and
// therefore the enclosing server{} block) can be reconstructed.
func nginxBraceTokens(text string) []nginxStatement {
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
	emitBrace := func(brace string, at int) {
		emitStmt()
		stmts = append(stmts, nginxStatement{words: []string{brace}, line: at})
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
				i++
			}
		case c == ';':
			emitStmt()
			i++
		case c == '{':
			emitBrace("{", line)
			i++
		case c == '}':
			emitBrace("}", line)
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

// nginxScope holds the ssl_* state applied within one brace frame. The *Set flags
// distinguish "explicitly set here" from "inherited", so a server{} value
// overrides an http{} default (nearest-frame-wins).
type nginxScope struct {
	protocols    []string
	protocolsSet bool
	ciphers      []string
	ciphersSet   bool
	certRef      string
	certLine     int
	keyRef       string
	keyLine      int
	dhparam      string
	ecdhCurve    string
	clientCert   string
	trustedCert  string
	includes     []string
}

// nginxFrame is one brace-nesting level. server frames additionally collect the
// listen/server_name directives that give the endpoint its identity.
type nginxFrame struct {
	kind        string
	line        int
	scope       nginxScope
	listens     []string
	ports       []int
	sslListen   bool // any listen carried the `ssl` flag
	sslPort     int
	serverNames []string
}

// nginxEndpoints walks the brace-structured directives and returns one
// endpointResult per TLS-terminating server{} block. http{}-level ssl_* settings
// are inherited defaults; a server{} block's own directives override them. include
// directives in the block's effective scope are recorded (not yet resolved).
func nginxEndpoints(text string) []*endpointResult {
	stmts := nginxBraceTokens(text)
	var out []*endpointResult
	stack := []*nginxFrame{{kind: "main"}}
	pendingKind := ""
	idx := 0

	top := func() *nginxFrame { return stack[len(stack)-1] }

	for _, s := range stmts {
		if len(s.words) == 0 {
			continue
		}
		w0 := s.words[0]
		switch w0 {
		case "{":
			stack = append(stack, &nginxFrame{kind: pendingKind, line: s.line})
			pendingKind = ""
			continue
		case "}":
			if len(stack) > 1 {
				f := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				if f.kind == "server" {
					if ep := nginxFinishServer(f, stack, &idx); ep != nil {
						out = append(out, ep)
					}
				}
			}
			continue
		}

		pendingKind = w0
		f := top()
		args := s.words[1:]
		switch w0 {
		case "ssl_protocols":
			f.scope.protocolsSet = true
			for _, a := range args {
				f.scope.protocols = appendUnique(f.scope.protocols, canonProto(a))
			}
		case "ssl_ciphers":
			if len(args) > 0 {
				f.scope.ciphersSet = true
				for _, c := range splitList(args[0]) {
					f.scope.ciphers = appendUnique(f.scope.ciphers, c)
				}
			}
		case "ssl_certificate":
			if len(args) > 0 {
				f.scope.certRef = args[0]
				f.scope.certLine = s.line
			}
		case "ssl_certificate_key":
			if len(args) > 0 {
				f.scope.keyRef = args[0]
				f.scope.keyLine = s.line
			}
		case "ssl_dhparam":
			if len(args) > 0 {
				f.scope.dhparam = args[0]
			}
		case "ssl_ecdh_curve":
			if len(args) > 0 {
				f.scope.ecdhCurve = args[0]
			}
		case "ssl_client_certificate":
			if len(args) > 0 {
				f.scope.clientCert = args[0]
			}
		case "ssl_trusted_certificate":
			if len(args) > 0 {
				f.scope.trustedCert = args[0]
			}
		case "include":
			if len(args) > 0 {
				f.scope.includes = append(f.scope.includes, args[0])
			}
		case "listen":
			if len(args) > 0 {
				f.listens = append(f.listens, args[0])
				p := parsePort(args[0])
				f.ports = append(f.ports, p)
				ssl := false
				for _, a := range args[1:] {
					if strings.EqualFold(a, "ssl") {
						ssl = true
					}
				}
				if ssl {
					f.sslListen = true
					if f.sslPort == 0 {
						f.sslPort = p
					}
				}
			}
		case "server_name":
			f.serverNames = append(f.serverNames, args...)
		}
	}

	return out
}

// nginxFinishServer resolves a closed server frame against its ancestors and, when
// TLS-terminating, returns its endpointResult. ancestors is the still-open frame
// stack (outermost..enclosing), consulted for inherited ssl_* defaults.
func nginxFinishServer(f *nginxFrame, ancestors []*nginxFrame, idx *int) *endpointResult {
	// Effective scope: this frame first, then enclosing frames (nearest wins).
	chain := []*nginxFrame{f}
	for i := len(ancestors) - 1; i >= 0; i-- {
		chain = append(chain, ancestors[i])
	}

	ep := &endpointResult{serverNames: f.serverNames, listens: f.listens, line: f.line}
	for _, fr := range chain {
		sc := fr.scope
		if len(ep.protocols) == 0 && sc.protocolsSet {
			ep.protocols = sc.protocols
		}
		if len(ep.ciphers) == 0 && sc.ciphersSet {
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
		if ep.dhparam == "" && sc.dhparam != "" {
			ep.dhparam = sc.dhparam
		}
		if ep.ecdhCurve == "" && sc.ecdhCurve != "" {
			ep.ecdhCurve = sc.ecdhCurve
		}
		if len(ep.caRefs) == 0 && sc.clientCert != "" {
			ep.caRefs = appendUnique(ep.caRefs, sc.clientCert)
		}
		if len(ep.trustedRefs) == 0 && sc.trustedCert != "" {
			ep.trustedRefs = appendUnique(ep.trustedRefs, sc.trustedCert)
		}
		ep.includes = append(ep.includes, sc.includes...)
	}

	tls := f.sslListen || len(ep.certRefs) > 0
	if !tls {
		return nil
	}
	if f.sslPort > 0 {
		ep.port = f.sslPort
	} else if len(f.ports) > 0 {
		ep.port = f.ports[0]
	}
	ep.blockIndex = *idx
	*idx++
	return ep
}

// certRef / hasKeyRef helpers keep nginxFinishServer readable while endpointResult
// stays a plain data carrier. certRef reports the first collected cert ref.
func (e *endpointResult) certRef() string {
	if len(e.certRefs) > 0 {
		return e.certRefs[0]
	}
	return ""
}
