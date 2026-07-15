package pqc

import (
	"strconv"
	"strings"

	"github.com/Ubermm/cryptoscan/internal/graph"
)

// configLegacy reports whether a tls_config ConfigFile node admits a protocol
// below TLS 1.2 (SSLv3/TLSv1/TLSv1.1).
//
// The config scanner already RESOLVES each format's enabled protocol set (nginx
// multi-block union; Apache all/±X semantics; openssl MinProtocol floor; haproxy
// base − no-tlsv1x − ssl-min-ver floor) and carries the result on the node's
// Attrs — the SAME resolved values it emits on the Finding. This reads those
// resolved attrs instead of re-deriving the resolution from raw directives, so
// there is one source of truth (DESIGN.md §1: consumers MUST NOT re-derive
// protocol resolution). Two shapes carry the protocol floor:
//
//   - `protocols`: the resolved enabled set (nginx/apache/haproxy). Legacy if any
//     member is below TLS 1.2.
//   - `min_protocol`: the openssl MinProtocol floor. Legacy if the floor itself
//     is below TLS 1.2.
//
// A node without either attr (an sshd_config, a bare ssl_certificate-only nginx
// file, an "fs"/reference node) proves no protocol floor and is not legacy.
func configLegacy(c *graph.ConfigFileNode) bool {
	for _, p := range strListAttr(c.Attrs, "protocols") {
		if isLegacyProto(p) {
			return true
		}
	}
	return isLegacyProto(strAttr(c.Attrs, "min_protocol"))
}

// labelFor builds a human-readable label for a node.
func labelFor(n graph.Node) string {
	switch v := n.(type) {
	case *graph.CertificateNode:
		if cn := commonName(v.Subject); cn != "" {
			return cn
		}
		if v.Subject != "" {
			return v.Subject
		}
		return v.ID()
	case *graph.CertificateRequestNode:
		if cn := commonName(v.Subject); cn != "" {
			return cn
		}
		if v.Subject != "" {
			return v.Subject
		}
		return v.ID()
	case *graph.KeyNode:
		algo := v.Algorithm
		if algo == "" {
			algo = "key"
		}
		if v.KeySize > 0 {
			return algo + " " + strconv.Itoa(v.KeySize) + "-bit key"
		}
		return algo + " key"
	case *graph.EndpointNode:
		if v.Host != "" && v.Port > 0 {
			return v.Host + ":" + strconv.Itoa(v.Port)
		}
		return v.ID()
	case *graph.ConfigFileNode:
		if v.Path != "" {
			return v.Path
		}
		return v.ID()
	case *graph.ConfigEndpointNode:
		return configEndpointLabel(v)
	default:
		return n.ID()
	}
}

// configEndpointLabel builds a human-readable identity for a ConfigEndpoint:
// server_name:port when both are known (the auditor-facing "which vhost"), falling
// back to the first listen/bind token, then to the file path with the block index
// (path#idx) so the endpoint is always nameable even for a bind with no
// server_name (haproxy). The port is appended to a server_name only when proven.
func configEndpointLabel(e *graph.ConfigEndpointNode) string {
	names := strListAttr(e.Attrs, "server_name")
	port := intAttr(e.Attrs, "port")
	if len(names) > 0 && names[0] != "" {
		if port > 0 {
			return names[0] + ":" + strconv.Itoa(port)
		}
		return names[0]
	}
	if listens := strListAttr(e.Attrs, "listen"); len(listens) > 0 && listens[0] != "" {
		return listens[0]
	}
	if e.Path != "" {
		return e.Path + "#" + strconv.Itoa(e.BlockIndex)
	}
	return e.ID()
}

// commonName extracts the CN component from an RFC 2253 / pkix DN string such as
// "CN=example.test,O=Acme". Returns "" when no CN is present.
func commonName(dn string) string {
	for _, part := range splitDN(dn) {
		if strings.HasPrefix(strings.ToUpper(part), "CN=") {
			return strings.TrimSpace(part[3:])
		}
	}
	return ""
}

// splitDN splits a DN on unescaped commas.
func splitDN(dn string) []string {
	var out []string
	var b strings.Builder
	escaped := false
	for _, r := range dn {
		switch {
		case escaped:
			b.WriteRune(r)
			escaped = false
		case r == '\\':
			b.WriteRune(r)
			escaped = true
		case r == ',':
			out = append(out, strings.TrimSpace(b.String()))
			b.Reset()
		default:
			b.WriteRune(r)
		}
	}
	if b.Len() > 0 {
		out = append(out, strings.TrimSpace(b.String()))
	}
	return out
}
