package graph

// Source identifies how a node or edge was observed. It is one of the fixed
// values fs, probe, or config (DESIGN.md Provenance).
type Source string

// Provenance sources.
const (
	SourceFS     Source = "fs"     // observed while scanning a filesystem path
	SourceProbe  Source = "probe"  // observed during a network handshake
	SourceConfig Source = "config" // observed while parsing a config directive
)

// validSources is the closed set of allowed provenance sources.
var validSources = map[Source]bool{
	SourceFS:     true,
	SourceProbe:  true,
	SourceConfig: true,
}

// Valid reports whether s is a known provenance source.
func (s Source) Valid() bool { return validSources[s] }

// Provenance is a single evidence record attached to a node or edge. Every
// finding must trace to at least one Provenance (DESIGN.md principle 1).
//
// Fields mirror DESIGN.md §1: Source (fs|probe|config), a Location (file path
// for fs/config, host for probe), a Line number (0 when not applicable), and a
// free-form Detail string.
type Provenance struct {
	Source   Source `json:"source"`
	Location string `json:"location"`       // path (fs/config) or host (probe)
	Line     int    `json:"line,omitempty"` // 0 when not applicable
	Detail   string `json:"detail,omitempty"`
}

// EdgeType enumerates the fixed directed relationships between nodes
// (DESIGN.md §1 edge table). Directions are fixed.
type EdgeType string

// Edge types. The From→To direction of each is fixed by DESIGN.md and is the
// caller's responsibility to honour.
const (
	// EdgeIssuedBy links Certificate → CA (issuer relationship).
	EdgeIssuedBy EdgeType = "issued_by"
	// EdgeTerminatesTLSFor links Certificate → Endpoint (cert presented in a
	// handshake at that endpoint).
	EdgeTerminatesTLSFor EdgeType = "terminates_tls_for"
	// EdgeStoredIn links Certificate/Key → ConfigFile (asset physically
	// located in a file/keystore).
	EdgeStoredIn EdgeType = "stored_in"
	// EdgeReferences links ConfigFile → Certificate/Key/ConfigFile (a config
	// directive points at a path).
	EdgeReferences EdgeType = "references"
	// EdgeSignsWith links Certificate/CertificateRequest → Key (the cert's or
	// CSR's subject public key / signing key linkage). Edge validation is
	// type-agnostic on the endpoints (AddEdge checks only the edge type and
	// non-empty From/To), so a CertificateRequest source is accepted.
	EdgeSignsWith EdgeType = "signs_with"
)

// validEdgeTypes is the closed set of allowed edge types.
var validEdgeTypes = map[EdgeType]bool{
	EdgeIssuedBy:         true,
	EdgeTerminatesTLSFor: true,
	EdgeStoredIn:         true,
	EdgeReferences:       true,
	EdgeSignsWith:        true,
}

// Valid reports whether t is a known edge type.
func (t EdgeType) Valid() bool { return validEdgeTypes[t] }

// Edge is a directed, typed relationship between two nodes identified by their
// IDs. Identity is the (Type, From, To) triple; provenance is additive.
type Edge struct {
	Type       EdgeType     `json:"type"`
	From       string       `json:"from"`
	To         string       `json:"to"`
	Provenance []Provenance `json:"provenance,omitempty"`
}

// key returns the dedupe key for an edge: identical (Type, From, To) triples
// are the same edge regardless of provenance.
func (e Edge) key() string {
	return string(e.Type) + "\x00" + e.From + "\x00" + e.To
}
