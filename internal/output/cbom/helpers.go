package cbom

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"

	"github.com/Ubermm/cryptoscan/internal/graph"
	"github.com/Ubermm/cryptoscan/internal/pqc"
)

// --- exposure → properties ---

// indexExposure keys the per-node exposures by node ID for O(1) lookup.
func indexExposure(r pqc.Report) map[string]pqc.NodeExposure {
	m := make(map[string]pqc.NodeExposure, len(r.Nodes))
	for _, e := range r.Nodes {
		m[e.NodeID] = e
	}
	return m
}

// pqcProperties builds the sorted CycloneDX properties recording a node's PQC
// exposure: one "cryptoscan:pqc:<flag>"="true" per set flag (DESIGN.md §5
// spellings) plus "cryptoscan:pqc:severity". A node with no exposure yields nil.
func pqcProperties(exp map[string]pqc.NodeExposure, id string) []property {
	e, ok := exp[id]
	if !ok {
		return nil
	}
	props := make([]property, 0, len(e.FlagNames)+1)
	for _, f := range e.FlagNames {
		props = append(props, property{Name: pqcNS + f, Value: "true"})
	}
	props = append(props, property{Name: pqcNS + "severity", Value: e.Severity.String()})
	sortProps(props)
	return props
}

// summaryProperties renders the estate-level PQC rollup as sorted metadata
// properties. Every value is a string so the property store stays uniform.
func summaryProperties(s pqc.Summary) []property {
	props := []property{
		{Name: summaryNS + "total_nodes", Value: strconv.Itoa(s.TotalNodes)},
		{Name: summaryNS + "flagged_nodes", Value: strconv.Itoa(s.FlaggedNodes)},
		{Name: summaryNS + "quantum_vulnerable_assets", Value: strconv.Itoa(s.QuantumVulnerableAssets)},
		{Name: summaryNS + "legacy_endpoints", Value: strconv.Itoa(s.LegacyEndpoints)},
		{Name: summaryNS + "expired", Value: strconv.Itoa(s.Expired)},
		{Name: summaryNS + "expiring", Value: strconv.Itoa(s.Expiring)},
		{Name: summaryNS + "pqc_ready_endpoints", Value: strconv.Itoa(s.PQCReadyEndpoints)},
	}
	for _, c := range s.BySeverity {
		props = append(props, property{Name: summaryNS + "severity:" + c.Name, Value: strconv.Itoa(c.Count)})
	}
	for _, c := range s.ByFlag {
		props = append(props, property{Name: summaryNS + "flag:" + c.Name, Value: strconv.Itoa(c.Count)})
	}
	sortProps(props)
	return props
}

// mergeProps concatenates two property slices and returns them sorted; a nil
// result is returned when both inputs are empty (so omitempty drops the field).
func mergeProps(a, b []property) []property {
	if len(a) == 0 && len(b) == 0 {
		return nil
	}
	out := make([]property, 0, len(a)+len(b))
	out = append(out, a...)
	out = append(out, b...)
	sortProps(out)
	return out
}

// appendListProp appends a single property whose value is the comma-joined list,
// but only when the list is non-empty (an empty observation proves nothing).
func appendListProp(props []property, name string, list []string) []property {
	if len(list) == 0 {
		return props
	}
	return append(props, property{Name: name, Value: strings.Join(list, ",")})
}

// sortProps orders properties by (name, value) for deterministic output.
func sortProps(p []property) {
	sort.Slice(p, func(i, j int) bool {
		if p[i].Name != p[j].Name {
			return p[i].Name < p[j].Name
		}
		return p[i].Value < p[j].Value
	})
}

// sortedKeys returns the keys of a set, sorted; nil for an empty/nil set.
func sortedKeys(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// --- serial number ---

// serialNumber resolves the BOM serial per Options: an explicit value wins; an
// OmitSerial request yields ""; otherwise a deterministic urn:uuid is derived
// from the graph's node and edge identities so the same graph always produces the
// same serial without a random source.
func serialNumber(g *graph.Graph, opts Options) string {
	if opts.OmitSerial {
		return ""
	}
	if opts.SerialNumber != "" {
		return opts.SerialNumber
	}
	return derivedSerial(g)
}

// derivedSerial hashes the sorted node IDs and edge keys into a stable
// RFC-4122-shaped urn:uuid string (the CycloneDX serialNumber pattern).
func derivedSerial(g *graph.Graph) string {
	h := sha256.New()
	if g != nil {
		for _, n := range g.Nodes() {
			h.Write([]byte(n.ID()))
			h.Write([]byte{0})
		}
		for _, e := range g.Edges() {
			h.Write([]byte(string(e.Type) + "\x00" + e.From + "\x00" + e.To))
			h.Write([]byte{0})
		}
	}
	sum := h.Sum(nil)
	b := sum[:16]
	return "urn:uuid:" + hex.EncodeToString(b[0:4]) + "-" + hex.EncodeToString(b[4:6]) + "-" +
		hex.EncodeToString(b[6:8]) + "-" + hex.EncodeToString(b[8:10]) + "-" + hex.EncodeToString(b[10:16])
}

// --- node naming ---

func certName(c *graph.CertificateNode) string {
	if cn := commonName(c.Subject); cn != "" {
		return cn
	}
	if c.Subject != "" {
		return c.Subject
	}
	return c.ID()
}

func csrName(c *graph.CertificateRequestNode) string {
	if cn := commonName(c.Subject); cn != "" {
		return cn
	}
	if c.Subject != "" {
		return c.Subject
	}
	return c.ID()
}

func keyName(k *graph.KeyNode) string {
	algo := k.Algorithm
	if algo == "" {
		algo = "key"
	}
	if k.KeySize > 0 {
		return algo + " " + strconv.Itoa(k.KeySize) + "-bit key"
	}
	return algo + " key"
}

func endpointName(e *graph.EndpointNode) string {
	if e.Host != "" && e.Port > 0 {
		return e.Host + ":" + strconv.Itoa(e.Port)
	}
	return e.ID()
}

func configName(f *graph.ConfigFileNode) string {
	if f.Path != "" {
		return f.Path
	}
	return f.ID()
}

// configEndpointName names a ConfigEndpoint by its server name(s) and listen
// address, falling back to the file path + block index, then the node ID.
func configEndpointName(e *graph.ConfigEndpointNode) string {
	sn := listAttr(e.Attrs, "server_name")
	lis := listAttr(e.Attrs, "listen")
	name := strings.Join(sn, ",")
	listen := strings.Join(lis, ",")
	switch {
	case name != "" && listen != "":
		return name + " (" + listen + ")"
	case name != "":
		return name
	case listen != "":
		return listen
	case e.Path != "":
		return e.Path + "#" + strconv.Itoa(e.BlockIndex)
	default:
		return e.ID()
	}
}

func caName(c *graph.CANode) string {
	if cn := commonName(c.DN); cn != "" {
		return cn
	}
	if c.DN != "" {
		return c.DN
	}
	return c.ID()
}

// keyMaterialType maps a Key node's observed public/private state to the
// CycloneDX relatedCryptoMaterialProperties.type enum.
func keyMaterialType(k *graph.KeyNode) string {
	switch {
	case k.HasPrivate:
		return "private-key"
	case k.HasPublic:
		return "public-key"
	default:
		return "key"
	}
}

// commonName extracts the CN from a pkix DN string, else "".
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

// --- attribute helpers (nil-safe) ---

func isTLS(m map[string]any) bool {
	if m == nil {
		return false
	}
	for _, k := range []string{"negotiated_protocol", "protocols_supported", "pqc_hybrid_kex"} {
		if _, ok := m[k]; ok {
			return true
		}
	}
	return false
}

func isSSH(m map[string]any) bool {
	if m == nil {
		return false
	}
	for _, k := range []string{"kex_algorithms", "host_key_algorithms", "banner"} {
		if _, ok := m[k]; ok {
			return true
		}
	}
	return false
}

func strAttr(m map[string]any, k string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[k].(string); ok {
		return v
	}
	return ""
}

func boolAttr(m map[string]any, k string) bool {
	if m == nil {
		return false
	}
	v, ok := m[k].(bool)
	return ok && v
}

// listAttr reads a string-list attribute, tolerating both []string and the
// []any shape a decoded map may carry.
func listAttr(m map[string]any, k string) []string {
	if m == nil {
		return nil
	}
	switch v := m[k].(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// isHex reports whether s is all lowercase/uppercase hex digits.
func isHex(s string) bool {
	_, err := hex.DecodeString(s)
	return err == nil
}
