package graph

import (
	"encoding/hex"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// NodeType enumerates the node kinds in the graph data model (DESIGN.md §1
// node table). The string values are the exact type names from that table.
type NodeType string

// Node types.
const (
	NodeCertificate        NodeType = "Certificate"
	NodeCertificateRequest NodeType = "CertificateRequest"
	NodeKey                NodeType = "Key"
	NodeEndpoint           NodeType = "Endpoint"
	NodeService            NodeType = "Service"
	NodeConfigFile         NodeType = "ConfigFile"
	NodeConfigEndpoint     NodeType = "ConfigEndpoint"
	NodeCryptoLibrary      NodeType = "CryptoLibrary"
	NodeCA                 NodeType = "CA"
	NodeKMSEntry           NodeType = "KMSEntry"
)

// Node is the common interface implemented by every typed node struct. Concrete
// nodes embed baseNode for identity and provenance handling.
//
// mergeFrom is unexported so that merging only ever happens through
// Graph.UpsertNode, which guarantees the two nodes share an ID and type.
type Node interface {
	// ID returns the node's stable identity key (e.g. "cert:<hex>").
	ID() string
	// Type returns the node's NodeType.
	Type() NodeType
	// Provenance returns the evidence records attached to this node.
	Provenance() []Provenance
	// AddProvenance appends provenance records, unioning duplicates away.
	AddProvenance(...Provenance)

	// mergeFrom folds another node's attributes and provenance into this one.
	// The other node is guaranteed by the caller to have the same ID; a type
	// mismatch returns an error rather than panicking.
	mergeFrom(other Node) error
}

// baseNode carries identity and provenance shared by all node types.
type baseNode struct {
	NodeID string       `json:"id"`
	Prov   []Provenance `json:"provenance,omitempty"`
}

// ID implements Node.
func (b *baseNode) ID() string { return b.NodeID }

// Provenance implements Node.
func (b *baseNode) Provenance() []Provenance { return b.Prov }

// AddProvenance appends records, skipping any that are already present so that
// merges produce a set union rather than duplicates.
func (b *baseNode) AddProvenance(ps ...Provenance) {
	for _, p := range ps {
		if !containsProv(b.Prov, p) {
			b.Prov = append(b.Prov, p)
		}
	}
}

func containsProv(list []Provenance, p Provenance) bool {
	for _, x := range list {
		if x == p {
			return true
		}
	}
	return false
}

// --- Concrete node types (DESIGN.md §1 core attributes) ---

// CertificateNode identifies a certificate by the SHA-256 of its DER encoding.
type CertificateNode struct {
	baseNode
	Subject            string    `json:"subject,omitempty"`
	Issuer             string    `json:"issuer,omitempty"`
	Serial             string    `json:"serial,omitempty"`
	Algorithm          string    `json:"algorithm,omitempty"`
	KeySize            int       `json:"key_size,omitempty"`
	SignatureAlgorithm string    `json:"signature_algorithm,omitempty"`
	NotBefore          time.Time `json:"not_before,omitempty"`
	NotAfter           time.Time `json:"not_after,omitempty"`
	SAN                []string  `json:"san,omitempty"`
	SPKISHA256         string    `json:"spki_sha256,omitempty"`
	SelfSigned         bool      `json:"self_signed,omitempty"`
}

// Type implements Node.
func (*CertificateNode) Type() NodeType { return NodeCertificate }

func (c *CertificateNode) mergeFrom(other Node) error {
	o, ok := other.(*CertificateNode)
	if !ok {
		return typeMismatch(c, other)
	}
	mergeString(&c.Subject, o.Subject)
	mergeString(&c.Issuer, o.Issuer)
	mergeString(&c.Serial, o.Serial)
	mergeString(&c.Algorithm, o.Algorithm)
	mergeInt(&c.KeySize, o.KeySize)
	mergeString(&c.SignatureAlgorithm, o.SignatureAlgorithm)
	mergeTime(&c.NotBefore, o.NotBefore)
	mergeTime(&c.NotAfter, o.NotAfter)
	mergeStringSet(&c.SAN, o.SAN)
	mergeString(&c.SPKISHA256, o.SPKISHA256)
	mergeBool(&c.SelfSigned, o.SelfSigned)
	c.AddProvenance(o.Prov...)
	return nil
}

// CertificateRequestNode identifies a PKCS#10 certificate signing request (CSR)
// by the SHA-256 of its DER encoding (DESIGN.md §1). A CSR is a distinct crypto
// asset — proof-of-possession of a key — not a Certificate and not merely a Key;
// it `signs_with` the Key node derived from its SPKI. It mirrors CertificateNode's
// typed-field style (no Attrs map, matching the other cert-ish nodes).
type CertificateRequestNode struct {
	baseNode
	Subject            string `json:"subject,omitempty"`
	Algorithm          string `json:"algorithm,omitempty"`
	KeySize            int    `json:"key_size,omitempty"`
	Curve              string `json:"curve,omitempty"`
	SignatureAlgorithm string `json:"signature_algorithm,omitempty"`
	SPKISHA256         string `json:"spki_sha256,omitempty"`
}

// Type implements Node.
func (*CertificateRequestNode) Type() NodeType { return NodeCertificateRequest }

func (c *CertificateRequestNode) mergeFrom(other Node) error {
	o, ok := other.(*CertificateRequestNode)
	if !ok {
		return typeMismatch(c, other)
	}
	mergeString(&c.Subject, o.Subject)
	mergeString(&c.Algorithm, o.Algorithm)
	mergeInt(&c.KeySize, o.KeySize)
	mergeString(&c.Curve, o.Curve)
	mergeString(&c.SignatureAlgorithm, o.SignatureAlgorithm)
	mergeString(&c.SPKISHA256, o.SPKISHA256)
	c.AddProvenance(o.Prov...)
	return nil
}

// KeyNode identifies a public/private key by the SHA-256 of its SPKI.
type KeyNode struct {
	baseNode
	Algorithm  string `json:"algorithm,omitempty"`
	KeySize    int    `json:"key_size,omitempty"`
	Curve      string `json:"curve,omitempty"`
	HasPublic  bool   `json:"has_public,omitempty"`
	HasPrivate bool   `json:"has_private,omitempty"`
}

// Type implements Node.
func (*KeyNode) Type() NodeType { return NodeKey }

func (k *KeyNode) mergeFrom(other Node) error {
	o, ok := other.(*KeyNode)
	if !ok {
		return typeMismatch(k, other)
	}
	mergeString(&k.Algorithm, o.Algorithm)
	mergeInt(&k.KeySize, o.KeySize)
	mergeString(&k.Curve, o.Curve)
	mergeBool(&k.HasPublic, o.HasPublic)
	mergeBool(&k.HasPrivate, o.HasPrivate)
	k.AddProvenance(o.Prov...)
	return nil
}

// EndpointNode identifies a network endpoint by host:port (DESIGN.md §1). Beyond
// its identity fields (Host, Port) it carries an Attrs map of observed parameters
// recorded by a probe, keyed by the network-probe-contract attribute names:
//
//   - TLS: negotiated_protocol, negotiated_cipher_suite, alpn,
//     protocols_supported, pqc_hybrid_kex
//   - SSH: banner, host_key_algorithms, kex_algorithms, ciphers, macs
//
// The map keeps TLS and SSH parameters distinct instead of overloading a shared
// set of typed fields, and it makes the node — not just the projected Finding —
// the primary carrier of what a probe observed (principle 2). The earlier typed
// Protocols/CipherSuites/ALPN fields are subsumed by these attribute keys and
// have been removed to avoid two sources of truth.
type EndpointNode struct {
	baseNode
	Host  string         `json:"host,omitempty"`
	Port  int            `json:"port,omitempty"`
	Attrs map[string]any `json:"attrs,omitempty"`
}

// Type implements Node.
func (*EndpointNode) Type() NodeType { return NodeEndpoint }

func (e *EndpointNode) mergeFrom(other Node) error {
	o, ok := other.(*EndpointNode)
	if !ok {
		return typeMismatch(e, other)
	}
	mergeString(&e.Host, o.Host)
	mergeInt(&e.Port, o.Port)
	mergeAttrs(&e.Attrs, o.Attrs)
	e.AddProvenance(o.Prov...)
	return nil
}

// ServiceNode identifies a service by name (e.g. nginx, sshd).
type ServiceNode struct {
	baseNode
	Name string `json:"name,omitempty"`
	Kind string `json:"kind,omitempty"`
}

// Type implements Node.
func (*ServiceNode) Type() NodeType { return NodeService }

func (s *ServiceNode) mergeFrom(other Node) error {
	o, ok := other.(*ServiceNode)
	if !ok {
		return typeMismatch(s, other)
	}
	mergeString(&s.Name, o.Name)
	mergeString(&s.Kind, o.Kind)
	s.AddProvenance(o.Prov...)
	return nil
}

// ConfigFileNode identifies a config or keystore file by cleaned absolute path
// (DESIGN.md §1). Beyond its identity fields (Path, Format) and the raw
// Directives of interest with their line numbers, it carries an Attrs map of the
// RESOLVED observed values the config scanner computed for this file — the SAME
// values it emits on the corresponding Finding, keyed by the config-finding
// attribute names:
//
//   - tls_config: protocols, ciphers, cert_refs, min_protocol, cipher_string
//   - ssh_config: host_key_types, host_key_refs, kex_algorithms, ciphers, macs
//
// The node — not just the projected Finding — is the single source of truth for
// resolved config state (principle 2): downstream consumers (pqc scoring, report,
// CBOM) read these attrs and MUST NOT re-derive protocol resolution from the raw
// Directives. The map keeps the per-class attribute sets distinct instead of
// overloading typed fields, mirroring EndpointNode.Attrs.
type ConfigFileNode struct {
	baseNode
	Path       string         `json:"path,omitempty"`
	Format     string         `json:"format,omitempty"`
	Directives []Directive    `json:"directives,omitempty"`
	Attrs      map[string]any `json:"attrs,omitempty"`
}

// Directive is a single directive of interest found in a config file, with the
// line at which it was observed.
type Directive struct {
	Name  string `json:"name"`
	Value string `json:"value,omitempty"`
	Line  int    `json:"line,omitempty"`
}

// Type implements Node.
func (*ConfigFileNode) Type() NodeType { return NodeConfigFile }

func (f *ConfigFileNode) mergeFrom(other Node) error {
	o, ok := other.(*ConfigFileNode)
	if !ok {
		return typeMismatch(f, other)
	}
	mergeString(&f.Path, o.Path)
	mergeString(&f.Format, o.Format)
	for _, d := range o.Directives {
		if !containsDirective(f.Directives, d) {
			f.Directives = append(f.Directives, d)
		}
	}
	mergeAttrs(&f.Attrs, o.Attrs)
	f.AddProvenance(o.Prov...)
	return nil
}

func containsDirective(list []Directive, d Directive) bool {
	for _, x := range list {
		if x == d {
			return true
		}
	}
	return false
}

// ConfigEndpointNode identifies a single server/vhost/frontend/bind block within
// a config file, resolved on its own (DESIGN.md §1). Its node ID is
// `cfgendpoint:` + cleaned file path + `#` + block index, so every TLS-terminating
// block in a multi-block file is a distinct node. It mirrors ConfigFileNode's
// shape: identity fields (Path, BlockIndex) plus an Attrs map of the per-block
// RESOLVED values — server_name(s), listen/bind address:port(s), protocols,
// ciphers, cert_refs, and the quantum-relevant params (dhparam, ecdh_curve) and
// mTLS trust anchors (ca_refs, trusted_refs) where present. Attrs keys:
//
//	server_name  ([]string), listen ([]string, addr:port), port (int),
//	protocols ([]string), ciphers ([]string), cert_refs ([]string),
//	dhparam (string), ecdh_curve (string), ca_refs ([]string),
//	trusted_refs ([]string)
//
// This is per-endpoint attribution: a weak protocol is provable against THIS
// block's host:port, not merely the file. The node `references` its Cert/Key
// nodes and is `stored_in` its ConfigFile. Attrs merge with mergeAttrs
// (existing-wins), exactly like EndpointNode/ConfigFileNode.
type ConfigEndpointNode struct {
	baseNode
	Path       string         `json:"path,omitempty"`
	BlockIndex int            `json:"block_index"`
	Attrs      map[string]any `json:"attrs,omitempty"`
}

// Type implements Node.
func (*ConfigEndpointNode) Type() NodeType { return NodeConfigEndpoint }

func (e *ConfigEndpointNode) mergeFrom(other Node) error {
	o, ok := other.(*ConfigEndpointNode)
	if !ok {
		return typeMismatch(e, other)
	}
	mergeString(&e.Path, o.Path)
	mergeInt(&e.BlockIndex, o.BlockIndex)
	mergeAttrs(&e.Attrs, o.Attrs)
	e.AddProvenance(o.Prov...)
	return nil
}

// CryptoLibraryNode identifies a crypto library by name@version.
type CryptoLibraryNode struct {
	baseNode
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
}

// Type implements Node.
func (*CryptoLibraryNode) Type() NodeType { return NodeCryptoLibrary }

func (l *CryptoLibraryNode) mergeFrom(other Node) error {
	o, ok := other.(*CryptoLibraryNode)
	if !ok {
		return typeMismatch(l, other)
	}
	mergeString(&l.Name, o.Name)
	mergeString(&l.Version, o.Version)
	l.AddProvenance(o.Prov...)
	return nil
}

// CANode identifies a certificate authority, either by the DER SHA-256 of its
// observed cert or by a normalized issuer DN when the CA cert was not observed.
type CANode struct {
	baseNode
	DN       string `json:"dn,omitempty"`
	Observed bool   `json:"observed,omitempty"`
}

// Type implements Node.
func (*CANode) Type() NodeType { return NodeCA }

func (c *CANode) mergeFrom(other Node) error {
	o, ok := other.(*CANode)
	if !ok {
		return typeMismatch(c, other)
	}
	mergeString(&c.DN, o.DN)
	mergeBool(&c.Observed, o.Observed)
	c.AddProvenance(o.Prov...)
	return nil
}

// KMSEntryNode identifies a key managed by an external KMS/provider.
type KMSEntryNode struct {
	baseNode
	Provider  string `json:"provider,omitempty"`
	KeyID     string `json:"key_id,omitempty"`
	Algorithm string `json:"algorithm,omitempty"`
}

// Type implements Node.
func (*KMSEntryNode) Type() NodeType { return NodeKMSEntry }

func (k *KMSEntryNode) mergeFrom(other Node) error {
	o, ok := other.(*KMSEntryNode)
	if !ok {
		return typeMismatch(k, other)
	}
	mergeString(&k.Provider, o.Provider)
	mergeString(&k.KeyID, o.KeyID)
	mergeString(&k.Algorithm, o.Algorithm)
	k.AddProvenance(o.Prov...)
	return nil
}

// --- merge helpers ---
//
// Merge semantics (DESIGN.md "Entity resolution"): the existing value wins when
// already set; otherwise the incoming value fills the gap. Booleans merge with
// OR (an asset observed as e.g. both public and private key material is both).
// String lists merge as ordered set unions.

func mergeString(dst *string, src string) {
	if *dst == "" && src != "" {
		*dst = src
	}
}

func mergeInt(dst *int, src int) {
	if *dst == 0 && src != 0 {
		*dst = src
	}
}

func mergeBool(dst *bool, src bool) {
	if src {
		*dst = true
	}
}

func mergeTime(dst *time.Time, src time.Time) {
	if dst.IsZero() && !src.IsZero() {
		*dst = src
	}
}

func mergeStringSet(dst *[]string, src []string) {
	for _, s := range src {
		if !containsString(*dst, s) {
			*dst = append(*dst, s)
		}
	}
}

// mergeAttrs folds src into *dst as a key union with existing-wins semantics: a
// key already present in *dst keeps its value, and only keys missing from *dst
// are filled from src. This mirrors the scalar merge convention (mergeString/
// mergeInt), where the value already resident in the graph wins and an incoming
// upsert only fills gaps — applied per attribute key so a TLS probe and an SSH
// probe of the same host:port union their distinct keys without clobbering.
func mergeAttrs(dst *map[string]any, src map[string]any) {
	if len(src) == 0 {
		return
	}
	if *dst == nil {
		*dst = make(map[string]any, len(src))
	}
	for k, v := range src {
		if _, ok := (*dst)[k]; !ok {
			(*dst)[k] = v
		}
	}
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func typeMismatch(have, got Node) error {
	return fmt.Errorf("graph: cannot merge %s node into %s node (id %q)",
		got.Type(), have.Type(), have.ID())
}

// --- ID constructors ---
//
// All constructors validate their inputs and return an error rather than
// panicking on malformed data (CLAUDE.md: no panics in library code).

// hexSHA256 validates that s is a 64-char hex SHA-256 and returns it lowercased.
func hexSHA256(s, kind string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return "", fmt.Errorf("graph: empty %s hash", kind)
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return "", fmt.Errorf("graph: %s hash is not valid hex: %w", kind, err)
	}
	if len(b) != 32 {
		return "", fmt.Errorf("graph: %s hash must be 32 bytes (64 hex chars), got %d", kind, len(b))
	}
	return s, nil
}

// CertNodeID builds a Certificate node ID from the SHA-256 of the cert's DER
// encoding (hex).
func CertNodeID(derSHA256 string) (string, error) {
	h, err := hexSHA256(derSHA256, "certificate DER")
	if err != nil {
		return "", err
	}
	return "cert:" + h, nil
}

// CSRNodeID builds a CertificateRequest node ID from the SHA-256 of the CSR's
// DER encoding (hex) — DESIGN.md §1: `csr:` + hex.
func CSRNodeID(derSHA256 string) (string, error) {
	h, err := hexSHA256(derSHA256, "CSR DER")
	if err != nil {
		return "", err
	}
	return "csr:" + h, nil
}

// KeyNodeID builds a Key node ID from the SHA-256 of the key's SPKI (hex).
func KeyNodeID(spkiSHA256 string) (string, error) {
	h, err := hexSHA256(spkiSHA256, "key SPKI")
	if err != nil {
		return "", err
	}
	return "key:" + h, nil
}

// EndpointNodeID builds an Endpoint node ID from host and port. IPv6 hosts are
// bracketed via net.JoinHostPort.
func EndpointNodeID(host string, port int) (string, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return "", fmt.Errorf("graph: empty endpoint host")
	}
	if port < 1 || port > 65535 {
		return "", fmt.Errorf("graph: endpoint port %d out of range [1,65535]", port)
	}
	return "endpoint:" + net.JoinHostPort(host, strconv.Itoa(port)), nil
}

// FileNodeID builds a ConfigFile node ID from a filesystem path. The path is
// cleaned and made absolute so the same file resolves to a single node
// (DESIGN.md §1). Uses the platform's path semantics via path/filepath.
func FileNodeID(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", fmt.Errorf("graph: empty file path")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("graph: cannot resolve absolute path for %q: %w", path, err)
	}
	return "file:" + filepath.Clean(abs), nil
}

// ConfigEndpointID builds a ConfigEndpoint node ID from a config file path and a
// zero-based block index (DESIGN.md §1: `cfgendpoint:` + cleaned file path + `#`
// + block index). The path is cleaned and made absolute the same way FileNodeID
// does, so a block's endpoint node and its ConfigFile node share the same path
// anchor. A negative index is rejected.
func ConfigEndpointID(cleanPath string, blockIndex int) (string, error) {
	if strings.TrimSpace(cleanPath) == "" {
		return "", fmt.Errorf("graph: empty config endpoint path")
	}
	if blockIndex < 0 {
		return "", fmt.Errorf("graph: config endpoint block index %d is negative", blockIndex)
	}
	abs, err := filepath.Abs(cleanPath)
	if err != nil {
		return "", fmt.Errorf("graph: cannot resolve absolute path for %q: %w", cleanPath, err)
	}
	return "cfgendpoint:" + filepath.Clean(abs) + "#" + strconv.Itoa(blockIndex), nil
}

// ServiceNodeID builds a Service node ID from its name (DESIGN.md §1:
// `service:` + name), e.g. ServiceNodeID("nginx") -> "service:nginx".
func ServiceNodeID(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", fmt.Errorf("graph: empty service name")
	}
	return "service:" + name, nil
}

// CryptoLibraryNodeID builds a CryptoLibrary node ID from its name and version
// (DESIGN.md §1: `lib:` + name@version), e.g. CryptoLibraryNodeID("openssl",
// "3.0.2") -> "lib:openssl@3.0.2". The name is required; an empty version is
// permitted (an observed-but-unversioned library) and renders as "lib:name@".
func CryptoLibraryNodeID(name, version string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", fmt.Errorf("graph: empty crypto library name")
	}
	return "lib:" + name + "@" + strings.TrimSpace(version), nil
}

// KMSEntryNodeID builds a KMSEntry node ID from its provider and key id
// (DESIGN.md §1: `kms:` + provider + key id). Provider and key id are joined by
// a colon, e.g. KMSEntryNodeID("aws-kms", "arn:...:key/abc") ->
// "kms:aws-kms:arn:...:key/abc". Both parts are required.
func KMSEntryNodeID(provider, keyID string) (string, error) {
	provider = strings.TrimSpace(provider)
	if provider == "" {
		return "", fmt.Errorf("graph: empty KMS provider")
	}
	keyID = strings.TrimSpace(keyID)
	if keyID == "" {
		return "", fmt.Errorf("graph: empty KMS key id")
	}
	return "kms:" + provider + ":" + keyID, nil
}

// CANodeID builds a CA node ID from the DER SHA-256 of the observed CA cert.
func CANodeID(derSHA256 string) (string, error) {
	h, err := hexSHA256(derSHA256, "CA DER")
	if err != nil {
		return "", err
	}
	return "ca:" + h, nil
}

// CADNNodeID builds a CA node ID from a normalized issuer DN, used when the CA
// certificate itself was not observed.
func CADNNodeID(dn string) (string, error) {
	dn = strings.TrimSpace(dn)
	if dn == "" {
		return "", fmt.Errorf("graph: empty CA distinguished name")
	}
	return "ca:dn:" + dn, nil
}
