package config

import "strings"

// --- apache -----------------------------------------------------------------

// apacheScope holds the SSL* state of one <VirtualHost> (or the outside-vhost
// defaults). protocolsSet marks an explicit SSLProtocol so a vhost overrides the
// defaults; hasSSL/sslEngine decide whether the vhost is TLS-terminating.
type apacheScope struct {
	port         int
	listen       string
	serverNames  []string
	protocols    protocolSet
	protocolsSet bool
	ciphers      []string
	certRef      string
	certLine     int
	keyRef       string
	keyLine      int
	caRefs       []string
	trustedRefs  []string
	dhparam      string
	ecdhCurve    string
	includes     []string
	hasSSL       bool
	sslEngine    bool
}

// apacheEndpoints walks the logical lines and returns one endpointResult per
// TLS-terminating <VirtualHost>. Directives outside any vhost are defaults
// inherited by every vhost (nearest-wins).
func apacheEndpoints(text string) []*endpointResult {
	var defaults apacheScope
	var cur *apacheScope
	var out []*endpointResult
	idx := 0

	for _, ln := range apacheLogicalLines(text) {
		fields := splitFields(ln.text)
		if len(fields) == 0 {
			continue
		}
		name := fields[0]
		args := fields[1:]

		if strings.EqualFold(name, "<VirtualHost") {
			addr := ""
			if len(args) > 0 {
				addr = strings.TrimRight(args[0], ">")
			}
			cur = &apacheScope{port: parsePort(addr), listen: addr}
			continue
		}
		if strings.EqualFold(name, "</VirtualHost>") {
			if cur != nil {
				if ep := apacheFinishVhost(cur, &defaults, &idx); ep != nil {
					out = append(out, ep)
				}
				cur = nil
			}
			continue
		}

		target := &defaults
		if cur != nil {
			target = cur
		}
		applyApacheDirective(target, name, args, ln.line)
	}
	return out
}

// applyApacheDirective folds one directive into the scope it belongs to.
func applyApacheDirective(s *apacheScope, name string, args []string, line int) {
	switch {
	case strings.EqualFold(name, "ServerName"):
		if len(args) > 0 {
			s.serverNames = appendUnique(s.serverNames, args[0])
		}
	case strings.EqualFold(name, "SSLEngine"):
		if len(args) > 0 && strings.EqualFold(args[0], "on") {
			s.sslEngine = true
		}
	case strings.EqualFold(name, "SSLProtocol"):
		s.hasSSL = true
		s.protocolsSet = true
		s.protocols = resolveApacheProtocols(args)
	case strings.EqualFold(name, "SSLCipherSuite"):
		s.hasSSL = true
		if len(args) > 0 {
			for _, c := range splitList(args[0]) {
				s.ciphers = appendUnique(s.ciphers, c)
			}
		}
	case strings.EqualFold(name, "SSLCertificateFile"):
		s.hasSSL = true
		if len(args) > 0 {
			s.certRef = args[0]
			s.certLine = line
		}
	case strings.EqualFold(name, "SSLCertificateKeyFile"):
		s.hasSSL = true
		if len(args) > 0 {
			s.keyRef = args[0]
			s.keyLine = line
		}
	case strings.EqualFold(name, "SSLCACertificateFile"), strings.EqualFold(name, "SSLCACertificatePath"):
		s.hasSSL = true
		if len(args) > 0 {
			s.caRefs = appendUnique(s.caRefs, args[0])
		}
	case strings.EqualFold(name, "SSLCertificateChainFile"):
		s.hasSSL = true
		if len(args) > 0 {
			s.trustedRefs = appendUnique(s.trustedRefs, args[0])
		}
	case strings.EqualFold(name, "SSLOpenSSLConfCmd"):
		if len(args) >= 2 {
			switch {
			case strings.EqualFold(args[0], "DHParameters"):
				s.dhparam = args[1]
			case strings.EqualFold(args[0], "Curves"), strings.EqualFold(args[0], "ECDHCurve"):
				s.ecdhCurve = args[1]
			}
		}
	case strings.EqualFold(name, "Include"), strings.EqualFold(name, "IncludeOptional"):
		if len(args) > 0 {
			s.includes = append(s.includes, args[0])
		}
	}
}

// apacheFinishVhost resolves a vhost against the outside-vhost defaults and, when
// TLS-terminating, returns its endpointResult.
func apacheFinishVhost(v, defaults *apacheScope, idx *int) *endpointResult {
	tls := v.hasSSL || v.sslEngine
	if !tls {
		return nil
	}
	ep := &endpointResult{
		serverNames: v.serverNames,
		listens:     []string{v.listen},
		port:        v.port,
		blockIndex:  *idx,
	}

	switch {
	case v.protocolsSet:
		ep.protocols = v.protocols.sorted()
	case defaults.protocolsSet:
		ep.protocols = defaults.protocols.sorted()
	}

	ep.ciphers = firstNonEmptyList(v.ciphers, defaults.ciphers)

	if ref := firstNonEmpty(v.certRef, defaults.certRef); ref != "" {
		line := v.certLine
		if v.certRef == "" {
			line = defaults.certLine
		}
		ep.certRefs = appendUnique(ep.certRefs, ref)
		ep.refs = append(ep.refs, pathRef{raw: ref, line: line, kind: "SSLCertificateFile"})
	}
	if ref := firstNonEmpty(v.keyRef, defaults.keyRef); ref != "" {
		line := v.keyLine
		if v.keyRef == "" {
			line = defaults.keyLine
		}
		ep.hasKeyRef = true
		ep.refs = append(ep.refs, pathRef{raw: ref, line: line, kind: "SSLCertificateKeyFile"})
	}
	ep.dhparam = firstNonEmpty(v.dhparam, defaults.dhparam)
	ep.ecdhCurve = firstNonEmpty(v.ecdhCurve, defaults.ecdhCurve)
	ep.caRefs = firstNonEmptyList(v.caRefs, defaults.caRefs)
	ep.trustedRefs = firstNonEmptyList(v.trustedRefs, defaults.trustedRefs)
	ep.includes = append(append([]string{}, v.includes...), defaults.includes...)

	*idx++
	return ep
}

// --- haproxy ----------------------------------------------------------------

// haproxyEndpoints walks the config and returns one endpointResult per
// TLS-terminating `bind` in a frontend/listen section. The global
// ssl-default-bind-options / ssl-min-ver / ssl-default-bind-ciphers form the base
// each bind starts from; a bind's own ssl-min-ver / ssl-max-ver / no-tlsv1x /
// ciphers override that base (issue #5).
func haproxyEndpoints(text string) []*endpointResult {
	base := protocolSet{}
	for _, p := range haproxyBase {
		base[p] = true
	}
	var baseCiphers []string
	var out []*endpointResult
	idx := 0
	section := ""

	for _, raw := range strings.Split(text, "\n") {
		l := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(l)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := splitFields(trimmed)
		if len(fields) == 0 {
			continue
		}
		kw := fields[0]
		args := fields[1:]

		// A column-0 keyword starts a new section.
		if len(l) > 0 && l[0] != ' ' && l[0] != '\t' {
			section = strings.ToLower(kw)
			continue
		}

		switch {
		case strings.EqualFold(kw, "ssl-default-bind-options"):
			for _, opt := range args {
				if proto, ok := haproxyNoOption[strings.ToLower(opt)]; ok {
					delete(base, proto)
				}
			}
		case strings.EqualFold(kw, "ssl-min-ver"):
			if len(args) > 0 {
				applyMinVer(base, canonProto(args[0]))
			}
		case strings.EqualFold(kw, "ssl-max-ver"):
			if len(args) > 0 {
				applyMaxVer(base, canonProto(args[0]))
			}
		case strings.EqualFold(kw, "ssl-default-bind-ciphers"):
			if len(args) > 0 {
				for _, c := range splitList(args[0]) {
					baseCiphers = appendUnique(baseCiphers, c)
				}
			}
		case strings.EqualFold(kw, "bind") && (section == "frontend" || section == "listen"):
			if ep := haproxyBind(args, base, baseCiphers, &idx); ep != nil {
				out = append(out, ep)
			}
		}
	}
	return out
}

// haproxyBind resolves one `bind` line into an endpointResult when it is
// TLS-terminating (an `ssl` keyword present). Its protocol set is the global base
// with the bind's own no-tlsv1x / ssl-min-ver / ssl-max-ver overrides applied.
func haproxyBind(args []string, base protocolSet, baseCiphers []string, idx *int) *endpointResult {
	if len(args) == 0 {
		return nil
	}
	addr := args[0]
	protos := protocolSet{}
	for p := range base {
		protos[p] = true
	}
	ssl := false
	crt := ""
	var ciphers []string
	for i := 1; i < len(args); i++ {
		a := args[i]
		switch {
		case strings.EqualFold(a, "ssl"):
			ssl = true
		case strings.EqualFold(a, "crt") && i+1 < len(args):
			crt = args[i+1]
			i++
		case strings.EqualFold(a, "ssl-min-ver") && i+1 < len(args):
			applyMinVer(protos, canonProto(args[i+1]))
			i++
		case strings.EqualFold(a, "ssl-max-ver") && i+1 < len(args):
			applyMaxVer(protos, canonProto(args[i+1]))
			i++
		case strings.EqualFold(a, "ciphers") && i+1 < len(args):
			for _, c := range splitList(args[i+1]) {
				ciphers = appendUnique(ciphers, c)
			}
			i++
		default:
			if proto, ok := haproxyNoOption[strings.ToLower(a)]; ok {
				delete(protos, proto)
			}
		}
	}
	if !ssl {
		return nil
	}
	ep := &endpointResult{
		listens:    []string{addr},
		port:       parsePort(addr),
		protocols:  protos.sorted(),
		blockIndex: *idx,
	}
	ep.ciphers = firstNonEmptyList(ciphers, baseCiphers)
	if crt != "" {
		ep.certRefs = appendUnique(ep.certRefs, crt)
		ep.refs = append(ep.refs, pathRef{raw: crt, kind: "crt"})
	}
	*idx++
	return ep
}

// applyMaxVer removes every enabled protocol strictly above ceiling (per tlsOrder).
func applyMaxVer(s protocolSet, ceiling string) {
	idx := -1
	for i, p := range tlsOrder {
		if p == ceiling {
			idx = i
			break
		}
	}
	if idx < 0 {
		return
	}
	for i := idx + 1; i < len(tlsOrder); i++ {
		delete(s, tlsOrder[i])
	}
}

// firstNonEmpty returns a if non-empty, else b.
func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// firstNonEmptyList returns a if non-empty, else b.
func firstNonEmptyList(a, b []string) []string {
	if len(a) > 0 {
		return a
	}
	return b
}
