package certs

import (
	"crypto/x509"
	"encoding/hex"
	"math/big"

	"github.com/cryptoscan/cryptoscan/internal/graph"
	"github.com/cryptoscan/cryptoscan/internal/scan"
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
func (r *run) emitCert(rel, alias string, prov graph.Provenance, der []byte, c *x509.Certificate) {
	derSHA := hexSHA256(der)
	attrs := certAttrs(c)
	spki, _ := attrs["spki_sha256"].(string)

	r.findings = append(r.findings, mkFinding("certificate", rel, alias, attrs, prov))
	r.certs = append(r.certs, certRec{cert: c, derSHA: derSHA, prov: prov})

	// Certificate node.
	certID, err := graph.CertNodeID(derSHA)
	if err != nil {
		return
	}
	cn := &graph.CertificateNode{
		Subject:            c.Subject.String(),
		Issuer:             c.Issuer.String(),
		Serial:             serialString(c.SerialNumber),
		Algorithm:          strAttr(attrs, "algorithm"),
		KeySize:            intAttr(attrs, "key_size"),
		SignatureAlgorithm: c.SignatureAlgorithm.String(),
		NotBefore:          c.NotBefore,
		NotAfter:           c.NotAfter,
		SAN:                c.DNSNames,
		SPKISHA256:         spki,
		SelfSigned:         bytesEqual(c.RawIssuer, c.RawSubject),
	}
	cn.NodeID = certID
	cn.AddProvenance(prov)
	if _, err := r.g.UpsertNode(cn); err != nil {
		return
	}

	// Key node + signs_with edge (Certificate → Key).
	keyID := r.upsertKeyNode(spki, strAttr(attrs, "algorithm"), intAttr(attrs, "key_size"), strAttr(attrs, "curve"), true, false, prov)
	if keyID != "" {
		_, _ = r.g.AddEdge(graph.Edge{Type: graph.EdgeSignsWith, From: certID, To: keyID, Provenance: []graph.Provenance{prov}})
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
	keyID := r.upsertKeyNode(strAttr(attrs, "spki_sha256"), strAttr(attrs, "algorithm"), intAttr(attrs, "key_size"), strAttr(attrs, "curve"), false, true, prov)
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
	keyID := r.upsertKeyNode(strAttr(attrs, "spki_sha256"), strAttr(attrs, "algorithm"), intAttr(attrs, "key_size"), strAttr(attrs, "curve"), true, false, prov)
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

// emitCSR records a certificate-signing-request Finding and merges the Key node
// its public key implies (HasPublic) plus a stored_in edge.
func (r *run) emitCSR(rel, alias string, prov graph.Provenance, csr *x509.CertificateRequest) {
	attrs, ok := csrAttrs(csr)
	if !ok {
		return
	}
	r.findings = append(r.findings, mkFinding("csr", rel, alias, attrs, prov))
	if spki, ok := spkiSHA256FromPub(csr.PublicKey); ok {
		keyID := r.upsertKeyNode(spki, strAttr(attrs, "algorithm"), intAttr(attrs, "key_size"), strAttr(attrs, "curve"), true, false, prov)
		if keyID != "" {
			r.storedIn(keyID, rel, prov)
		}
	}
}

// upsertKeyNode merges a Key node identified by its SPKI SHA-256 and returns its
// node ID (empty if the SPKI is invalid). Public/private observations union.
func (r *run) upsertKeyNode(spki, algo string, size int, curve string, hasPublic, hasPrivate bool, prov graph.Provenance) string {
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
	if _, err := r.g.UpsertNode(kn); err != nil {
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
