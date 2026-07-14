// Package cbom emits a CycloneDX 1.6 Cryptographic Bill of Materials (CBOM) as
// JSON — the standards-native output required by CLAUDE.md principle 4. The BOM
// is a faithful, deterministic projection of the cryptoscan graph
// (internal/graph, principle 2): every component, algorithm, protocol surface,
// and dependency traces to a proven node or edge, and the attached PQC exposure
// (internal/pqc) is carried as documented CycloneDX properties.
//
// # Mapping (graph → CycloneDX 1.6)
//
//   - Certificate node  → component type "cryptographic-asset",
//     cryptoProperties.assetType "certificate"; certificateProperties (subject/
//     issuer names, validity window, certificateFormat "X.509",
//     signatureAlgorithmRef, subjectPublicKeyRef); the DER SHA-256 fingerprint in
//     component.hashes (SHA-256). bom-ref = the "cert:<derhash>" node ID.
//   - Key node          → assetType "related-crypto-material";
//     relatedCryptoMaterialProperties (type public-key/private-key, size,
//     algorithmRef, id = SPKI hash). bom-ref = the "key:<spki>" node ID.
//   - CertificateRequest → assetType "related-crypto-material" (the documented
//     pragmatic fit for a PKCS#10 CSR); relatedCryptoMaterialProperties (type
//     public-key, id = SPKI hash, algorithmRef), a "cryptoscan:asset:type=csr"
//     marker property, and a "cryptoscan:csr:*" note. Its signs_with → Key is a
//     dependency. bom-ref = the "csr:<derhash>" node ID.
//   - Distinct algorithms (public-key + certificate signature) → assetType
//     "algorithm" components, deduplicated by a stable "alg:*" bom-ref, referenced
//     from certificates/keys via the typed *Ref fields.
//   - Endpoint node     → assetType "protocol"; protocolProperties (type tls|ssh,
//     version, TLS cipherSuites); SSH KEXINIT name-lists and TLS alpn/
//     protocols_supported as namespaced properties. bom-ref = the endpoint node ID.
//   - CA node           → assetType "certificate" (subjectName = DN).
//   - ConfigFile node   → component "data" (parsed server config) or "file" (bare
//     storage), with resolved tls/ssh config state as namespaced properties.
//   - Edges             → CycloneDX dependencies: issued_by (cert dependsOn CA),
//     terminates_tls_for (endpoint dependsOn cert), references (config dependsOn
//     asset), stored_in (file provides asset); signs_with is captured by
//     subjectPublicKeyRef.
//   - PQC exposure      → per-component properties "cryptoscan:pqc:<flag>"="true"
//     plus "cryptoscan:pqc:severity"; the estate rollup in metadata.properties.
//
// # Determinism
//
// The library never reads the wall clock or a random source. Options injects the
// timestamp and serial number. Components and dependencies are sorted by bom-ref/
// ref, algorithm components are deduplicated, and every property/list is sorted,
// so two Writes of the same (graph, exposure, opts) are byte-identical.
package cbom

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cryptoscan/cryptoscan/internal/graph"
	"github.com/cryptoscan/cryptoscan/internal/pqc"
)

// DefaultToolVersion is the cryptoscan tool version recorded in metadata.tools
// when Options.ToolVersion is empty (semver from v0.1.0, per CLAUDE.md).
const DefaultToolVersion = "0.1.0"

// propNS is the documented property namespace for cryptoscan-specific data
// attached to an otherwise standards-native BOM.
const (
	pqcNS     = "cryptoscan:pqc:"
	summaryNS = "cryptoscan:pqc:summary:"
	tlsNS     = "cryptoscan:tls:"
	sshNS     = "cryptoscan:ssh:"
	cfgNS     = "cryptoscan:config:"
	assetNS   = "cryptoscan:asset:"
	csrNS     = "cryptoscan:csr:"
)

// Options controls the deterministic, injectable parts of a Write. The zero
// Options is valid: it omits the timestamp, derives a content-based serial
// number, and uses DefaultToolVersion.
type Options struct {
	// Timestamp, when non-zero, is emitted as metadata.timestamp (RFC 3339, UTC).
	// A zero value omits the field entirely so output stays deterministic without
	// a clock. The library never calls time.Now().
	Timestamp time.Time

	// SerialNumber, when non-empty, is used verbatim as the BOM serialNumber (it
	// must match the CycloneDX urn:uuid form). When empty and OmitSerial is false,
	// a deterministic serial is derived from the graph content.
	SerialNumber string

	// OmitSerial, when true, suppresses serialNumber entirely.
	OmitSerial bool

	// ToolVersion overrides the recorded cryptoscan tool version.
	ToolVersion string
}

// Write emits g as a CycloneDX 1.6 CBOM (JSON) to w, projecting the graph and
// attaching the PQC exposure. It is deterministic (see the package doc) and never
// panics on any graph, including nil/empty (which yields a valid minimal BOM). It
// returns an error only if encoding or writing fails.
func Write(w io.Writer, g *graph.Graph, exposure pqc.Report, opts Options) error {
	doc := build(g, exposure, opts)

	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("cbom: marshaling BOM: %w", err)
	}
	out = append(out, '\n')
	if _, err := w.Write(out); err != nil {
		return fmt.Errorf("cbom: writing BOM: %w", err)
	}
	return nil
}

// build assembles the in-memory BOM document from the graph and exposure.
func build(g *graph.Graph, exposure pqc.Report, opts Options) *bom {
	toolVersion := opts.ToolVersion
	if toolVersion == "" {
		toolVersion = DefaultToolVersion
	}

	doc := &bom{
		Schema:      "http://cyclonedx.org/schema/bom-1.6.schema.json",
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.6",
		Version:     1,
		Metadata: &metadata{
			Tools: &tools{Components: []component{{
				Type:    "application",
				Name:    "cryptoscan",
				Version: toolVersion,
			}}},
			Properties: summaryProperties(exposure.Summary),
		},
	}
	if !opts.Timestamp.IsZero() {
		doc.Metadata.Timestamp = opts.Timestamp.UTC().Format(time.RFC3339)
	}
	if serial := serialNumber(g, opts); serial != "" {
		doc.SerialNumber = serial
	}

	if g == nil {
		return doc
	}

	expByNode := indexExposure(exposure)
	algs := map[string]component{}
	var comps []component

	for _, n := range g.Nodes() {
		switch v := n.(type) {
		case *graph.CertificateNode:
			comps = append(comps, certComponent(g, v, algs, expByNode))
		case *graph.CertificateRequestNode:
			comps = append(comps, csrComponent(v, algs, expByNode))
		case *graph.KeyNode:
			comps = append(comps, keyComponent(v, algs, expByNode))
		case *graph.EndpointNode:
			comps = append(comps, endpointComponent(v, expByNode))
		case *graph.ConfigFileNode:
			comps = append(comps, configComponent(v, expByNode))
		case *graph.CANode:
			comps = append(comps, caComponent(v))
		}
	}

	// Fold in the deduplicated algorithm components.
	for _, c := range algs {
		comps = append(comps, c)
	}
	sort.Slice(comps, func(i, j int) bool { return comps[i].BOMRef < comps[j].BOMRef })
	doc.Components = comps

	doc.Dependencies = dependencies(g)
	return doc
}

// certComponent projects a Certificate node, registering its public-key and
// signature algorithm components in algs and linking them via the typed refs.
func certComponent(g *graph.Graph, c *graph.CertificateNode, algs map[string]component, exp map[string]pqc.NodeExposure) component {
	cp := &certificateProperties{
		SubjectName:       c.Subject,
		IssuerName:        c.Issuer,
		CertificateFormat: "X.509",
	}
	if !c.NotBefore.IsZero() {
		cp.NotValidBefore = c.NotBefore.UTC().Format(time.RFC3339)
	}
	if !c.NotAfter.IsZero() {
		cp.NotValidAfter = c.NotAfter.UTC().Format(time.RFC3339)
	}
	if ref, comp, ok := signatureAlgorithm(c.SignatureAlgorithm); ok {
		register(algs, ref, comp)
		cp.SignatureAlgorithmRef = ref
	}
	// subjectPublicKeyRef mirrors signs_with: point at the Key component when a
	// Key node exists for this cert's SPKI (it does whenever the SPKI parsed). The
	// cert's public-key algorithm is represented once, on that shared Key
	// component (which carries the curve), reached transitively via this ref — so
	// it is not registered again here (that would duplicate the algorithm under a
	// curveless name).
	if keyID, err := graph.KeyNodeID(c.SPKISHA256); err == nil {
		if _, ok := g.Node(keyID); ok {
			cp.SubjectPublicKeyRef = keyID
		}
	}

	comp := component{
		Type:   "cryptographic-asset",
		BOMRef: c.ID(),
		Name:   certName(c),
		CryptoProperties: &cryptoProperties{
			AssetType:             "certificate",
			CertificateProperties: cp,
		},
	}
	if fp := strings.TrimSpace(strings.TrimPrefix(c.ID(), "cert:")); len(fp) == 64 && isHex(fp) {
		comp.Hashes = []hash{{Alg: "SHA-256", Content: fp}}
	}
	comp.Properties = pqcProperties(exp, c.ID())
	return comp
}

// keyComponent projects a Key node, registering its algorithm component.
func keyComponent(k *graph.KeyNode, algs map[string]component, exp map[string]pqc.NodeExposure) component {
	rcm := &relatedCryptoMaterialProperties{
		Type: keyMaterialType(k),
		ID:   strings.TrimPrefix(k.ID(), "key:"),
		Size: k.KeySize,
	}
	if ref, comp, ok := keyAlgorithm(k.Algorithm, k.KeySize, k.Curve); ok {
		register(algs, ref, comp)
		rcm.AlgorithmRef = ref
	}
	comp := component{
		Type:   "cryptographic-asset",
		BOMRef: k.ID(),
		Name:   keyName(k),
		CryptoProperties: &cryptoProperties{
			AssetType:                       "related-crypto-material",
			RelatedCryptoMaterialProperties: rcm,
		},
	}
	comp.Properties = pqcProperties(exp, k.ID())
	return comp
}

// csrComponent projects a CertificateRequest (PKCS#10 CSR) node. A CSR has no
// native CycloneDX assetType; the pragmatic, documented fit is
// related-crypto-material carrying the subject public key it proves possession of
// (type public-key, id = SPKI hash, algorithmRef = the key's algorithm), marked
// with a "cryptoscan:asset:type=csr" property and a namespaced note that it is a
// PKCS#10 request so the CSR is not mistaken for a bare public key. The
// signs_with CSR→Key linkage is carried in the dependency graph (see
// dependencies), analogous to a certificate's subjectPublicKeyRef.
func csrComponent(c *graph.CertificateRequestNode, algs map[string]component, exp map[string]pqc.NodeExposure) component {
	rcm := &relatedCryptoMaterialProperties{
		Type: "public-key",
		ID:   c.SPKISHA256,
	}
	if ref, comp, ok := keyAlgorithm(c.Algorithm, c.KeySize, c.Curve); ok {
		register(algs, ref, comp)
		rcm.AlgorithmRef = ref
	}
	props := []property{
		{Name: assetNS + "type", Value: "csr"},
		{Name: csrNS + "note", Value: "PKCS#10 certificate signing request"},
	}
	if c.SignatureAlgorithm != "" {
		props = append(props, property{Name: csrNS + "signature_algorithm", Value: c.SignatureAlgorithm})
	}
	comp := component{
		Type:   "cryptographic-asset",
		BOMRef: c.ID(),
		Name:   csrName(c),
		CryptoProperties: &cryptoProperties{
			AssetType:                       "related-crypto-material",
			RelatedCryptoMaterialProperties: rcm,
		},
	}
	comp.Properties = mergeProps(props, pqcProperties(exp, c.ID()))
	return comp
}

// endpointComponent projects an Endpoint node into a protocol component.
func endpointComponent(e *graph.EndpointNode, exp map[string]pqc.NodeExposure) component {
	pp := &protocolProperties{}
	var props []property

	switch {
	case isTLS(e.Attrs):
		pp.Type = "tls"
		pp.Version = strAttr(e.Attrs, "negotiated_protocol")
		if cs := strAttr(e.Attrs, "negotiated_cipher_suite"); cs != "" {
			pp.CipherSuites = []cipherSuite{{Name: cs}}
		}
		props = appendListProp(props, tlsNS+"protocols_supported", listAttr(e.Attrs, "protocols_supported"))
		props = appendListProp(props, tlsNS+"alpn", listAttr(e.Attrs, "alpn"))
		if _, ok := e.Attrs["pqc_hybrid_kex"]; ok {
			props = append(props, property{Name: tlsNS + "pqc_hybrid_kex", Value: strconv.FormatBool(boolAttr(e.Attrs, "pqc_hybrid_kex"))})
		}
	case isSSH(e.Attrs):
		pp.Type = "ssh"
		if b := strAttr(e.Attrs, "banner"); b != "" {
			props = append(props, property{Name: sshNS + "banner", Value: b})
		}
		for _, key := range []string{"host_key_algorithms", "kex_algorithms", "ciphers", "macs"} {
			props = appendListProp(props, sshNS+key, listAttr(e.Attrs, key))
		}
	default:
		pp.Type = "other"
	}

	comp := component{
		Type:   "cryptographic-asset",
		BOMRef: e.ID(),
		Name:   endpointName(e),
		CryptoProperties: &cryptoProperties{
			AssetType:          "protocol",
			ProtocolProperties: pp,
		},
	}
	comp.Properties = mergeProps(props, pqcProperties(exp, e.ID()))
	return comp
}

// configComponent projects a ConfigFile node. Parsed server configs (nginx,
// apache, haproxy, openssl, sshd) become "data" components carrying their
// resolved tls/ssh state as properties; bare on-disk storage nodes (Format "fs")
// become "file" components. Either way the config-sourced findings are traceable.
func configComponent(f *graph.ConfigFileNode, exp map[string]pqc.NodeExposure) component {
	typ := "data"
	if strings.EqualFold(f.Format, "fs") {
		typ = "file"
	}
	var props []property
	if f.Format != "" {
		props = append(props, property{Name: cfgNS + "format", Value: f.Format})
	}
	// Resolved config attrs (the single source of truth per DESIGN.md §1).
	for _, key := range []string{"protocols", "ciphers", "cert_refs", "host_key_types", "host_key_refs", "kex_algorithms", "macs"} {
		props = appendListProp(props, cfgNS+key, listAttr(f.Attrs, key))
	}
	for _, key := range []string{"min_protocol", "cipher_string"} {
		if s := strAttr(f.Attrs, key); s != "" {
			props = append(props, property{Name: cfgNS + key, Value: s})
		}
	}
	comp := component{
		Type:       typ,
		BOMRef:     f.ID(),
		Name:       configName(f),
		Properties: mergeProps(props, pqcProperties(exp, f.ID())),
	}
	return comp
}

// caComponent projects a CA node into a minimal certificate cryptographic-asset
// carrying its distinguished name.
func caComponent(c *graph.CANode) component {
	return component{
		Type:   "cryptographic-asset",
		BOMRef: c.ID(),
		Name:   caName(c),
		CryptoProperties: &cryptoProperties{
			AssetType:             "certificate",
			CertificateProperties: &certificateProperties{SubjectName: c.DN},
		},
	}
}

// dependencies projects the graph edges into a deterministic CycloneDX
// dependency graph. Every first-class asset node (cert/key/CA/endpoint/config)
// gets a dependency entry so the asset set is fully enumerated; algorithm
// components are leaf definitions referenced via the typed *Ref fields only.
func dependencies(g *graph.Graph) []dependency {
	dependsOn := map[string]map[string]bool{}
	provides := map[string]map[string]bool{}
	refs := map[string]bool{}

	ensure := func(id string) {
		if !refs[id] {
			refs[id] = true
		}
	}
	addDep := func(from, to string) {
		if dependsOn[from] == nil {
			dependsOn[from] = map[string]bool{}
		}
		dependsOn[from][to] = true
	}
	addProv := func(from, to string) {
		if provides[from] == nil {
			provides[from] = map[string]bool{}
		}
		provides[from][to] = true
	}

	// Enumerate every first-class asset node.
	for _, n := range g.Nodes() {
		switch n.Type() {
		case graph.NodeCertificate, graph.NodeCertificateRequest, graph.NodeKey, graph.NodeEndpoint, graph.NodeConfigFile, graph.NodeCA:
			ensure(n.ID())
		}
	}

	for _, e := range g.Edges() {
		switch e.Type {
		case graph.EdgeIssuedBy: // cert -> CA : cert depends on CA
			ensure(e.From)
			addDep(e.From, e.To)
		case graph.EdgeSignsWith: // CSR -> key : csr depends on key. A cert's
			// signs_with is carried via certificateProperties.subjectPublicKeyRef,
			// not here, so only CSR sources contribute a dependency edge.
			if strings.HasPrefix(e.From, "csr:") {
				ensure(e.From)
				addDep(e.From, e.To)
			}
		case graph.EdgeTerminatesTLSFor: // cert -> endpoint : endpoint depends on cert
			ensure(e.To)
			addDep(e.To, e.From)
		case graph.EdgeReferences: // config -> asset : config depends on asset
			ensure(e.From)
			addDep(e.From, e.To)
		case graph.EdgeStoredIn: // asset -> file : file provides asset
			ensure(e.To)
			addProv(e.To, e.From)
		}
	}

	out := make([]dependency, 0, len(refs))
	for ref := range refs {
		out = append(out, dependency{
			Ref:       ref,
			DependsOn: sortedKeys(dependsOn[ref]),
			Provides:  sortedKeys(provides[ref]),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Ref < out[j].Ref })
	return out
}

// register inserts comp under ref if not already present (dedupe).
func register(algs map[string]component, ref string, comp component) {
	if _, ok := algs[ref]; !ok {
		algs[ref] = comp
	}
}
