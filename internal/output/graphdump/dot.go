package graphdump

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/Ubermm/cryptoscan/internal/graph"
)

// WriteDOT writes g to w as a Graphviz DOT digraph.
//
// Nodes and edges are emitted in the graph's deterministic order (nodes sorted
// by ID, edges sorted by (type, from, to)). Each node's DOT identifier is a
// short, safe token derived by hashing its graph ID (see dotID), so arbitrary
// characters in a graph ID — Windows path separators, colons, quotes — can never
// break the DOT syntax. The human-readable identity lives in the node label,
// which is escaped (dotEscape) so quotes, backslashes, and control characters in
// malformed attributes cannot break the output or cause a panic. Edge labels are
// the edge type. The function does not panic on any graph, including an empty one
// (which yields a valid empty digraph).
//
// Node shape/color legend (style=filled), keyed by NodeType:
//
//	Certificate    box            #cfe8ff  (light blue)
//	CertificateRequest component  #b9d6ff  (blue)
//	Key            ellipse        #ffe9a8  (gold)
//	Endpoint       box            #c9f2d0  (green)
//	Service        hexagon        #e3d7ff  (lavender)
//	ConfigFile     note           #fff4c2  (yellow)
//	CryptoLibrary  tab            #d9d9d9  (grey)
//	CA             doubleoctagon  #ffd0a8  (orange)
//	KMSEntry       cylinder       #f8c6d8  (pink)
//	(unknown)      box            #ffffff  (white)
//
// Node label lines: Certificate = "Certificate", subject CN, short DER hash;
// Key = "Key", algorithm+size/curve, short SPKI hash; Endpoint = "Endpoint",
// host:port; ConfigFile = "ConfigFile", base filename; CA = "CA", DN; Service,
// CryptoLibrary, KMSEntry = type + their identity.
func WriteDOT(w io.Writer, g *graph.Graph) error {
	var b strings.Builder
	b.WriteString("digraph cryptoscan {\n")
	b.WriteString("  rankdir=LR;\n")
	b.WriteString("  node [style=filled, fontname=\"sans-serif\"];\n")

	for _, n := range g.Nodes() {
		shape, color := dotStyle(n.Type())
		b.WriteString("  \"")
		b.WriteString(dotID(n.ID()))
		b.WriteString("\" [label=\"")
		b.WriteString(dotLabel(n))
		b.WriteString("\", shape=")
		b.WriteString(shape)
		b.WriteString(", fillcolor=\"")
		b.WriteString(color)
		b.WriteString("\"];\n")
	}

	for _, e := range g.Edges() {
		b.WriteString("  \"")
		b.WriteString(dotID(e.From))
		b.WriteString("\" -> \"")
		b.WriteString(dotID(e.To))
		b.WriteString("\" [label=\"")
		b.WriteString(dotEscape(string(e.Type)))
		b.WriteString("\"];\n")
	}

	b.WriteString("}\n")

	if _, err := io.WriteString(w, b.String()); err != nil {
		return fmt.Errorf("graphdump: writing graph DOT: %w", err)
	}
	return nil
}

// dotID hashes a graph node ID to a short, DOT-safe identifier token. Two
// distinct graph IDs map to distinct tokens (SHA-256, 64-bit prefix), and the
// same graph ID always maps to the same token, so edges and nodes reference the
// same vertices deterministically without depending on the ID's characters.
func dotID(graphID string) string {
	sum := sha256.Sum256([]byte(graphID))
	return "n" + hex.EncodeToString(sum[:8])
}

// dotStyle returns the (shape, fillcolor) pair for a node type. See the WriteDOT
// legend. Unknown types fall back to a white box so the writer never fails.
func dotStyle(t graph.NodeType) (shape, color string) {
	switch t {
	case graph.NodeCertificate:
		return "box", "#cfe8ff"
	case graph.NodeCertificateRequest:
		return "component", "#b9d6ff"
	case graph.NodeKey:
		return "ellipse", "#ffe9a8"
	case graph.NodeEndpoint:
		return "box", "#c9f2d0"
	case graph.NodeService:
		return "hexagon", "#e3d7ff"
	case graph.NodeConfigFile:
		return "note", "#fff4c2"
	case graph.NodeCryptoLibrary:
		return "tab", "#d9d9d9"
	case graph.NodeCA:
		return "doubleoctagon", "#ffd0a8"
	case graph.NodeKMSEntry:
		return "cylinder", "#f8c6d8"
	default:
		return "box", "#ffffff"
	}
}

// dotLabel builds a node's DOT label: a type line plus short identity line(s),
// each individually escaped and joined with the DOT newline escape (\n).
func dotLabel(n graph.Node) string {
	parts := nodeLabelParts(n)
	escaped := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		escaped = append(escaped, dotEscape(p))
	}
	if len(escaped) == 0 {
		escaped = append(escaped, dotEscape(string(n.Type())))
	}
	return strings.Join(escaped, `\n`)
}

// nodeLabelParts returns the unescaped label lines for a node: element 0 is the
// type name, the rest are the short human-readable identity. It reads only the
// concrete node's fields (falling back to the node ID) and never panics.
func nodeLabelParts(n graph.Node) []string {
	switch v := n.(type) {
	case *graph.CertificateNode:
		cn := commonName(v.Subject)
		if cn == "" {
			cn = "cert"
		}
		return []string{"Certificate", cn, shortHash(v.ID())}
	case *graph.CertificateRequestNode:
		cn := commonName(v.Subject)
		if cn == "" {
			cn = "csr"
		}
		return []string{"CertificateRequest", cn, shortHash(v.ID())}
	case *graph.KeyNode:
		desc := v.Algorithm
		switch {
		case v.Curve != "":
			desc = strings.TrimSpace(v.Algorithm + " " + v.Curve)
		case v.KeySize > 0:
			desc = strings.TrimSpace(fmt.Sprintf("%s %d", v.Algorithm, v.KeySize))
		}
		if desc == "" {
			desc = "key"
		}
		return []string{"Key", desc, shortHash(v.ID())}
	case *graph.EndpointNode:
		hp := strings.TrimPrefix(v.ID(), "endpoint:")
		if hp == "" {
			hp = fmt.Sprintf("%s:%d", v.Host, v.Port)
		}
		return []string{"Endpoint", hp}
	case *graph.ServiceNode:
		name := v.Name
		if name == "" {
			name = v.Kind
		}
		return []string{"Service", name}
	case *graph.ConfigFileNode:
		base := v.Path
		if base == "" {
			base = strings.TrimPrefix(v.ID(), "file:")
		}
		if base != "" {
			base = filepath.Base(base)
		}
		return []string{"ConfigFile", base}
	case *graph.CryptoLibraryNode:
		return []string{"CryptoLibrary", strings.TrimSpace(v.Name + "@" + v.Version)}
	case *graph.CANode:
		dn := v.DN
		if dn == "" {
			dn = strings.TrimPrefix(v.ID(), "ca:")
		}
		return []string{"CA", dn}
	case *graph.KMSEntryNode:
		return []string{"KMSEntry", strings.TrimSpace(v.Provider + ":" + v.KeyID)}
	default:
		return []string{string(n.Type()), n.ID()}
	}
}

// shortHash returns the trailing hash of an ID (the part after the last colon),
// truncated to 12 characters, for a compact but recognizable label.
func shortHash(id string) string {
	h := id
	if i := strings.LastIndex(id, ":"); i >= 0 {
		h = id[i+1:]
	}
	if len(h) > 12 {
		h = h[:12]
	}
	return h
}

// commonName extracts the CN value from a subject/issuer DN string, or returns
// the whole string when no CN component is present.
func commonName(subject string) string {
	for _, part := range strings.Split(subject, ",") {
		part = strings.TrimSpace(part)
		if len(part) >= 3 && strings.EqualFold(part[:3], "CN=") {
			return strings.TrimSpace(part[3:])
		}
	}
	return subject
}

// dotEscape escapes a string for use inside a double-quoted DOT label. Backslash
// and double-quote are backslash-escaped; carriage returns are dropped; newlines
// and tabs and any other control characters collapse to a single space so a
// malformed attribute value can never break the label or inject DOT syntax.
func dotEscape(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\r':
			// drop
		case '\n', '\t':
			b.WriteByte(' ')
		default:
			if r < 0x20 {
				b.WriteByte(' ')
			} else {
				b.WriteRune(r)
			}
		}
	}
	return b.String()
}
