package config

import (
	"strings"

	"github.com/cryptoscan/cryptoscan/internal/graph"
)

// haproxyBase is the protocol range HAProxy enables by default in modern builds
// (configs.yaml convention header): TLSv1.0..TLSv1.3; SSLv3 is off by default.
var haproxyBase = []string{"TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"}

// haproxyNoOption maps an ssl-default-bind-options `no-*` token to the protocol
// it disables. no-sslv3 maps to a version not in the base, so it is a no-op.
var haproxyNoOption = map[string]string{
	"no-tlsv10": "TLSv1",
	"no-tlsv11": "TLSv1.1",
	"no-tlsv12": "TLSv1.2",
	"no-tlsv13": "TLSv1.3",
	"no-sslv3":  "SSLv3",
}

// parseHAProxy claims a file when it contains an active ssl-default-bind-options,
// ssl-default-bind-ciphers, ssl-min-ver, or a `bind ... ssl crt <path>` line.
// Protocols are the TLSv1..TLSv1.3 base minus any versions disabled by
// no-tlsv1x options and below any ssl-min-ver floor.
func parseHAProxy(text string) *parseResult {
	enabled := protocolSet{}
	for _, p := range haproxyBase {
		enabled[p] = true
	}

	var ciphers, certRefs []string
	var directives []graph.Directive
	var refs []pathRef
	crypto := false

	for i, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := splitFields(line)
		if len(fields) == 0 {
			continue
		}
		keyword := fields[0]
		args := fields[1:]
		lineNo := i + 1

		switch {
		case strings.EqualFold(keyword, "ssl-default-bind-options"):
			crypto = true
			for _, opt := range args {
				if proto, ok := haproxyNoOption[strings.ToLower(opt)]; ok {
					delete(enabled, proto)
				}
			}
			directives = append(directives, graph.Directive{Name: "ssl-default-bind-options", Value: strings.Join(args, " "), Line: lineNo})
		case strings.EqualFold(keyword, "ssl-min-ver"):
			crypto = true
			if len(args) > 0 {
				applyMinVer(enabled, canonProto(args[0]))
				directives = append(directives, graph.Directive{Name: "ssl-min-ver", Value: args[0], Line: lineNo})
			}
		case strings.EqualFold(keyword, "ssl-default-bind-ciphers"):
			crypto = true
			if len(args) > 0 {
				for _, c := range splitList(args[0]) {
					ciphers = appendUnique(ciphers, c)
				}
				directives = append(directives, graph.Directive{Name: "ssl-default-bind-ciphers", Value: args[0], Line: lineNo})
			}
		case strings.EqualFold(keyword, "bind"):
			if crt, ok := bindCertRef(args); ok {
				crypto = true
				certRefs = appendUnique(certRefs, crt)
				refs = append(refs, pathRef{raw: crt, line: lineNo, kind: "crt"})
				directives = append(directives, graph.Directive{Name: "bind", Value: strings.Join(args, " "), Line: lineNo})
			}
		}
	}

	if !crypto {
		return nil
	}

	attrs := map[string]any{
		"protocols": enabled.sorted(),
	}
	if len(ciphers) > 0 {
		attrs["ciphers"] = ciphers
	}
	if len(certRefs) > 0 {
		attrs["cert_refs"] = certRefs
	}

	return &parseResult{
		format:     "haproxy",
		class:      "tls_config",
		attrs:      attrs,
		directives: directives,
		refs:       refs,
	}
}

// bindCertRef returns the certificate path from a `bind` argument list when the
// bind is TLS-terminating (an `ssl` keyword present) and carries a `crt <path>`.
func bindCertRef(args []string) (string, bool) {
	hasSSL := false
	crt := ""
	for i, a := range args {
		if strings.EqualFold(a, "ssl") {
			hasSSL = true
		}
		if strings.EqualFold(a, "crt") && i+1 < len(args) {
			crt = args[i+1]
		}
	}
	if hasSSL && crt != "" {
		return crt, true
	}
	return "", false
}

// applyMinVer removes every enabled protocol strictly below floor (per tlsOrder).
func applyMinVer(s protocolSet, floor string) {
	idx := -1
	for i, p := range tlsOrder {
		if p == floor {
			idx = i
			break
		}
	}
	if idx < 0 {
		return
	}
	for i := 0; i < idx; i++ {
		delete(s, tlsOrder[i])
	}
}
