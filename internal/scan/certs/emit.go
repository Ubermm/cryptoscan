package certs

import (
	"crypto/x509"
	"encoding/hex"
	"math/big"

	"github.com/Ubermm/cryptoscan/internal/graph"
	"github.com/Ubermm/cryptoscan/internal/scan"
)

// mkFinding builds a scan.Finding with a single provenance record.
func mkFinding(class, path, alias string, attrs map[string]any, prov graph.Provenance) scan.Finding {
	return scan.Finding{
		Class:      class,
		Path:       path,
		Alias:      alias,
		Attrs:      attrs,
		Provenance: []graph.Provenance{prov},
	}
}

// emitCert records a certificate Finding and upserts its Certificate + Key
// nodes and the signs_with / stored_in edges. The certRec is stashed for the
// issuer-resolution post-pass.
//
// The cert→node/attrs work is delegated to UpsertCertGraph, the single code
// path shared with the network prober, so a cert seen on disk and at an
// endpoint can never drift to different identities (DESIGN.md §1). The fs
// scanner adds the stored_in edge on top; the prober adds terminates_tls_for.
func (r *run) emitCert(rel, alias string, prov graph.Provenance, der []byte, c *x509.Certificate) {
	oc := observedFrom(der, c)

	r.findings = append(r.findings, mkFinding("certificate", rel, alias, oc.Attrs, prov))
	r.certs = append(r.certs, certRec{cert: c, derSHA: oc.DERSHA256, prov: prov})

	certID, _, err := UpsertCertGraph(r.g, oc, prov)
	if err != nil {
		return
	}
	r.storedIn(certID, rel, prov)
}

// emitPrivateKey records a private-key Finding and merges its Key node
// (HasPrivate) plus a stored_in edge.
func (r *run) emitPrivateKey(rel, alias string, prov graph.Provenance, pub any) {
	attrs, ok := keyAttrs(pub)
	if !ok {
		return
	}
	r.findings = append(r.findings, mkFinding("private_key", rel, alias, attrs, prov))
	keyID := upsertKeyNode(r.g, strAttr(attrs, "spki_sha256"), strAttr(attrs, "algorithm"), intAttr(attrs, "key_size"), strAttr(attrs, "curve"), false, true, prov)
	if keyID != "" {
		r.storedIn(keyID, rel, prov)
	}
}

// emitPublicKey records a public-key Finding and merges its Key node
// (HasPublic) plus a stored_in edge.
func (r *run) emitPublicKey(rel, alias string, prov graph.Provenance, pub any) {
	attrs, ok := keyAttrs(pub)
	if !ok {
		return
	}
	r.findings = append(r.findings, mkFinding("public_key", rel, alias, attrs, prov))
	keyID := upsertKeyNode(r.g, strAttr(attrs, "spki_sha256"), strAttr(attrs, "algorithm"), intAttr(attrs, "key_size"), strAttr(attrs, "curve"), true, false, prov)
	if keyID != "" {
		r.storedIn(keyID, rel, prov)
	}
}

// emitEncryptedKey records an encrypted private key. The only provable fact is
// that it IS an encrypted private key, so no algorithm attributes are attached
// and no Key node is created (the SPKI is unrecoverable without the password).
func (r *run) emitEncryptedKey(rel, alias string, prov graph.Provenance) {
	r.findings = append(r.findings, mkFinding("private_key", rel, alias, map[string]any{}, prov))
}

// emitCSR records a certificate-signing-request Finding and projects the CSR
// into the graph as a first-class CertificateRequest node (identified by the
// SHA-256 of its DER encoding), joined to the Key node its subject public key
// implies via a signs_with edge and to its containing file via stored_in. This
// mirrors emitCert's cert→graph shape (the cert is stored_in the file; its key is
// linked via signs_with), so a CSR is no longer indistinguishable from a bare
// public key downstream (DESIGN.md §1). The Finding (class csr) is unchanged.
func (r *run) emitCSR(rel, alias string, prov graph.Provenance, csr *x509.CertificateRequest) {
	attrs, ok := csrAttrs(csr)
	if !ok {
		return
	}
	r.findings = append(r.findings, mkFinding("csr", rel, alias, attrs, prov))

	spki, ok := spkiSHA256FromPub(csr.PublicKey)
	if !ok {
		return
	}
	csrID, err := graph.CSRNodeID(hexSHA256(csr.Raw))
	if err != nil {
		return
	}
	cn := &graph.CertificateRequestNode{
		Subject:            csr.Subject.String(),
		Algorithm:          strAttr(attrs, "algorithm"),
		KeySize:            intAttr(attrs, "key_size"),
		Curve:              strAttr(attrs, "curve"),
		SignatureAlgorithm: csr.SignatureAlgorithm.String(),
		SPKISHA256:         spki,
	}
	cn.NodeID = csrID
	cn.AddProvenance(prov)
	if _, err := r.g.UpsertNode(cn); err != nil {
		return
	}
	keyID := upsertKeyNode(r.g, spki, strAttr(attrs, "algorithm"), intAttr(attrs, "key_size"), strAttr(attrs, "curve"), true, false, prov)
	if keyID != "" {
		_, _ = r.g.AddEdge(graph.Edge{Type: graph.EdgeSignsWith, From: csrID, To: keyID, Provenance: []graph.Provenance{prov}})
	}
	r.storedIn(csrID, rel, prov)
}

// upsertKeyNode merges a Key node identified by its SPKI SHA-256 into g and
// returns its node ID (empty if the SPKI is invalid). Public/private
// observations union. It is a free function (not a *run method) so the network
// prober shares the exact same Key-node code path as the fs scanner.
func upsertKeyNode(g *graph.Graph, spki, algo string, size int, curve string, hasPublic, hasPrivate bool, prov graph.Provenance) string {
	if spki == "" {
		return ""
	}
	keyID, err := graph.KeyNodeID(spki)
	if err != nil {
		return ""
	}
	kn := &graph.KeyNode{Algorithm: algo, KeySize: size, Curve: curve, HasPublic: hasPublic, HasPrivate: hasPrivate}
	kn.NodeID = keyID
	kn.AddProvenance(prov)
	if _, err := g.UpsertNode(kn); err != nil {
		return ""
	}
	return keyID
}

// storedIn upserts the containing file node and links asset → file (stored_in).
// The node ID is anchored at the real on-disk path (r.curDisk) so it matches the
// config scanner's file node for the same physical file; the node's display Path
// stays corpus-root-relative (rel).
func (r *run) storedIn(assetID, rel string, prov graph.Provenance) {
	fileID, err := graph.FileNodeID(r.curDisk)
	if err != nil {
		return
	}
	fn := &graph.ConfigFileNode{Path: rel, Format: "fs"}
	fn.NodeID = fileID
	fn.AddProvenance(prov)
	if _, err := r.g.UpsertNode(fn); err != nil {
		return
	}
	_, _ = r.g.AddEdge(graph.Edge{Type: graph.EdgeStoredIn, From: assetID, To: fileID, Provenance: []graph.Provenance{prov}})
}

func serialString(n *big.Int) string {
	if n == nil {
		return ""
	}
	return hex.EncodeToString(n.Bytes())
}

func strAttr(m map[string]any, k string) string {
	if v, ok := m[k].(string); ok {
		return v
	}
	return ""
}

func intAttr(m map[string]any, k string) int {
	if v, ok := m[k].(int); ok {
		return v
	}
	return 0
}

func boolAttr(m map[string]any, k string) bool {
	if v, ok := m[k].(bool); ok {
		return v
	}
	return false
}
