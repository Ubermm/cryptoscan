package certs

import (
	"crypto/x509"

	"github.com/Ubermm/cryptoscan/internal/graph"
)

// ObservedCert is the strict, deterministic projection of a single presented
// DER certificate: the parsed certificate, its two graph identity keys, and the
// attribute map that lines up with the manifest `expect` keys (DESIGN.md §2).
//
// It exists so that a network prober (internal/probe/tls) records exactly what
// the filesystem scanner records for the same bytes, without re-implementing the
// extraction — a certificate seen at an endpoint and on disk therefore resolves
// to the SAME Certificate node (DER SHA-256) and Key node (SPKI SHA-256), which
// is the cross-surface entity-resolution promise (DESIGN.md §1).
type ObservedCert struct {
	// Cert is the parsed certificate (strict x509 parse, trailing bytes rejected).
	Cert *x509.Certificate
	// DERSHA256 is the lowercase hex SHA-256 of the DER encoding — the
	// Certificate node identity (graph.CertNodeID input).
	DERSHA256 string
	// SPKISHA256 is the lowercase hex SHA-256 of the SubjectPublicKeyInfo — the
	// Key node identity (graph.KeyNodeID input). It equals Attrs["spki_sha256"].
	SPKISHA256 string
	// Attrs holds the certificate attributes keyed to the manifest `expect`
	// keys, identical to what the filesystem scanner emits for the same bytes
	// (algorithm, key_size, curve, signature_algorithm, spki_sha256, subject_cn,
	// self_signed, expired, not_yet_valid, not_before, not_after). The map is
	// freshly allocated, so the caller may mutate it.
	Attrs map[string]any
}

// observedFrom builds an ObservedCert from a DER blob and its already-parsed
// certificate, without re-parsing. It is the single point where the DER SHA-256,
// SPKI SHA-256, and attribute map are derived, so ParseObservedCert (wire bytes)
// and emitCert (on-disk bytes) can never diverge.
func observedFrom(der []byte, c *x509.Certificate) *ObservedCert {
	attrs := certAttrs(c)
	spki, _ := attrs["spki_sha256"].(string)
	return &ObservedCert{
		Cert:       c,
		DERSHA256:  hexSHA256(der),
		SPKISHA256: spki,
		Attrs:      attrs,
	}
}

// ParseObservedCert parses a single DER-encoded certificate with the exact
// strict code path the filesystem scanner uses and returns its identity keys and
// attributes. It returns an error (never a panic) for bytes that are not a valid
// certificate, so callers can skip rather than guess (principle 1).
//
// This is the reuse point for the network prober: it must NOT duplicate the
// attribute-extraction logic in extract.go.
func ParseObservedCert(der []byte) (*ObservedCert, error) {
	c, err := parseCertStrict(der)
	if err != nil {
		return nil, err
	}
	return observedFrom(der, c), nil
}

// certNode builds the Certificate node for an observed cert. Structural fields
// come from the parsed certificate; algorithm/size/self_signed come from the
// shared attribute extraction (oc.Attrs) — exactly the fields the fs scanner
// records, so both surfaces produce an identical node.
func certNode(oc *ObservedCert) *graph.CertificateNode {
	c := oc.Cert
	return &graph.CertificateNode{
		Subject:            c.Subject.String(),
		Issuer:             c.Issuer.String(),
		Serial:             serialString(c.SerialNumber),
		Algorithm:          strAttr(oc.Attrs, "algorithm"),
		KeySize:            intAttr(oc.Attrs, "key_size"),
		SignatureAlgorithm: c.SignatureAlgorithm.String(),
		NotBefore:          c.NotBefore,
		NotAfter:           c.NotAfter,
		SAN:                c.DNSNames,
		SPKISHA256:         oc.SPKISHA256,
		SelfSigned:         boolAttr(oc.Attrs, "self_signed"),
	}
}

// UpsertCertGraph upserts oc's Certificate node and its Key node (joined by a
// signs_with edge) into g using prov, returning the Certificate and Key node
// IDs (keyID is empty when the SPKI is unusable). It is the single cert→graph
// code path shared by the filesystem scanner (which then adds stored_in) and
// the network prober (which then adds terminates_tls_for), guaranteeing that a
// certificate observed on disk and at an endpoint resolves to ONE node
// (DESIGN.md §1 entity resolution). An error is returned only when the
// Certificate node itself cannot be built or upserted.
func UpsertCertGraph(g *graph.Graph, oc *ObservedCert, prov graph.Provenance) (certID, keyID string, err error) {
	certID, err = graph.CertNodeID(oc.DERSHA256)
	if err != nil {
		return "", "", err
	}
	cn := certNode(oc)
	cn.NodeID = certID
	cn.AddProvenance(prov)
	if _, err = g.UpsertNode(cn); err != nil {
		return "", "", err
	}
	keyID = upsertKeyNode(g, oc.SPKISHA256, strAttr(oc.Attrs, "algorithm"), intAttr(oc.Attrs, "key_size"), strAttr(oc.Attrs, "curve"), true, false, prov)
	if keyID != "" {
		_, _ = g.AddEdge(graph.Edge{Type: graph.EdgeSignsWith, From: certID, To: keyID, Provenance: []graph.Provenance{prov}})
	}
	return certID, keyID, nil
}

// LinkChainIssuers links each certificate in chain to its issuer CA node,
// mirroring the fs scanner's issuer post-pass (certs.go resolveIssuers) but
// scoped to a single presented chain: if the issuer's certificate is itself
// present in chain, the edge targets ca:<issuer DER SHA-256> (observed=true);
// otherwise ca:dn:<issuer DN> (observed=false). Nothing is inferred beyond what
// the chain proves. Malformed individual entries are skipped, never fatal.
func LinkChainIssuers(g *graph.Graph, chain []*ObservedCert, prov graph.Provenance) {
	subjectToSHA := make(map[string]string, len(chain))
	for _, oc := range chain {
		key := string(oc.Cert.RawSubject)
		if _, ok := subjectToSHA[key]; !ok {
			subjectToSHA[key] = oc.DERSHA256
		}
	}
	for _, oc := range chain {
		certID, err := graph.CertNodeID(oc.DERSHA256)
		if err != nil {
			continue
		}
		var (
			caID     string
			observed bool
			buildErr error
		)
		if issuerSHA, ok := subjectToSHA[string(oc.Cert.RawIssuer)]; ok {
			caID, buildErr = graph.CANodeID(issuerSHA)
			observed = true
		} else {
			caID, buildErr = graph.CADNNodeID(oc.Cert.Issuer.String())
		}
		if buildErr != nil {
			continue
		}
		ca := &graph.CANode{DN: oc.Cert.Issuer.String(), Observed: observed}
		ca.NodeID = caID
		ca.AddProvenance(prov)
		if _, err := g.UpsertNode(ca); err != nil {
			continue
		}
		_, _ = g.AddEdge(graph.Edge{Type: graph.EdgeIssuedBy, From: certID, To: caID, Provenance: []graph.Provenance{prov}})
	}
}
