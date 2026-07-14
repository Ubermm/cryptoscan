// Package certs is the Phase 1 filesystem scanner for X.509 certificates,
// private/public keys, CSRs, and keystores (PKCS#12, JKS). It walks a directory
// tree and emits one scan.Finding per cryptographic asset it can PROVE exists
// by parsing the bytes — never by trusting a filename extension (principle 1,
// CLAUDE.md / DESIGN.md). Malformed input yields no finding, silently; the
// scanner never panics and never aborts a walk on a single bad file.
//
// Every certificate and standalone key is also projected into the graph data
// model (DESIGN.md §1): Certificate nodes keyed by DER SHA-256, Key nodes keyed
// by SPKI SHA-256, joined by signs_with / stored_in / issued_by edges with full
// provenance. Findings are the flat projection the eval harness scores; the
// graph is the primary structure real consumers use.
package certs

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Ubermm/cryptoscan/internal/graph"
	"github.com/Ubermm/cryptoscan/internal/scan"
)

// maxFileSize caps the bytes read per candidate file. A single certificate,
// key, CSR, or keystore is far smaller than this; anything larger is not a
// cert-shaped file and is skipped deterministically rather than read into
// memory. It is the shared scan.MaxFileSize (8 MiB) so the certs and config
// scanners apply an identical, documented ceiling (robustness requirement).
const maxFileSize = scan.MaxFileSize

// init registers this scanner in the process-wide registry so a blank import
// (e.g. from cmd/eval) makes it available to scan.All(). Registration is
// order-independent — the registry is a map keyed by Name and All() sorts — so
// there is no init-order fragility (mirrors internal/scan/config).
func init() { scan.Register(New()) }

// Scanner implements scan.Scanner for on-disk cryptographic assets.
type Scanner struct{}

// New returns a ready-to-use certificate/key/keystore Scanner.
func New() *Scanner { return &Scanner{} }

// Name implements scan.Scanner.
func (*Scanner) Name() string { return "certs" }

// Scan implements scan.Scanner. It delegates to ScanIntoGraph with a throwaway
// graph, since the eval harness consumes Findings only (DESIGN.md §3).
func (s *Scanner) Scan(root string) ([]scan.Finding, error) {
	return s.ScanIntoGraph(root, graph.New())
}

// ScanIntoGraph walks root, populates g with the certificate/key/CA subgraph,
// and returns the flat Findings. An operational error (an unwalkable root) is
// returned; individual unreadable or malformed files are skipped, not fatal.
func (s *Scanner) ScanIntoGraph(root string, g *graph.Graph) ([]scan.Finding, error) {
	if g == nil {
		g = graph.New()
	}
	r := &run{root: root, g: g}

	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// Unreadable entry: collect and keep walking (robustness).
			r.walkErrs = append(r.walkErrs, err)
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			// Symlinks and other non-regular files are not followed.
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			r.walkErrs = append(r.walkErrs, ierr)
			return nil
		}
		if info.Size() > maxFileSize {
			return nil
		}
		r.processFile(path)
		return nil
	})
	if walkErr != nil {
		return r.findings, walkErr
	}

	r.resolveIssuers()
	return r.findings, nil
}

// run holds the mutable state of a single scan.
type run struct {
	root     string
	g        *graph.Graph
	findings []scan.Finding
	certs    []certRec // every certificate observed, for issuer resolution
	walkErrs []error   //nolint:unused // reserved for a future --debug surface
	// curDisk is the on-disk path of the file currently being processed. It is
	// the anchor for the file's node ID (graph.FileNodeID) so that the ID
	// matches the config scanner's referenced-file nodes for the SAME physical
	// file — the two must agree for the cross-scanner references join to work
	// (DESIGN.md §1 entity resolution). Finding/provenance paths stay
	// corpus-root-relative; only the node ID uses the real path.
	curDisk string
}

// certRec remembers a parsed certificate so the post-pass can resolve issuers.
type certRec struct {
	cert   *x509.Certificate
	derSHA string
	prov   graph.Provenance
}

// rel converts an absolute/host path to a corpus-root-relative, forward-slash
// path for Finding.Path and provenance (scan.Finding contract).
func (r *run) rel(path string) string {
	rp, err := filepath.Rel(r.root, path)
	if err != nil {
		rp = path
	}
	return filepath.ToSlash(rp)
}

// processFile reads one file and dispatches it to the PEM path or, if it holds
// no PEM blocks at all, the binary path (DER / PKCS#12 / JKS). It never returns
// an error: unreadable or unparseable files simply produce no findings.
func (r *run) processFile(path string) {
	data, err := readCapped(path)
	if err != nil {
		r.walkErrs = append(r.walkErrs, err)
		return
	}
	r.curDisk = path
	rel := r.rel(path)
	if r.processPEM(rel, data) {
		return
	}
	r.processBinary(rel, data)
}

// --- PEM path ---

// processPEM iterates every PEM block in data (DESIGN.md: multi-block files).
// It returns true if at least one PEM block was present, in which case the file
// is considered PEM and the binary path is not attempted. A block that fails
// strict parsing contributes no finding but still marks the file as PEM.
func (r *run) processPEM(rel string, data []byte) bool {
	// First pass: how many CERTIFICATE blocks? Positional aliases ("0","1",...)
	// are only assigned when there is more than one cert in the file.
	certCount := 0
	for rest := data; ; {
		block, rem := pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			certCount++
		}
		rest = rem
	}
	if certCount == 0 {
		// Could still be a single-block key/CSR/pubkey file; re-scan to confirm
		// any block decoded at all.
		if block, _ := pem.Decode(data); block == nil {
			return false
		}
	}

	// Second pass: process each block with its BEGIN-line number and alias.
	certIdx := 0
	for cur := data; ; {
		block, rem := pem.Decode(cur)
		if block == nil {
			break
		}
		line := beginLine(data, cur, block.Type)
		alias := ""
		if block.Type == "CERTIFICATE" && certCount > 1 {
			alias = strconv.Itoa(certIdx)
		}
		if block.Type == "CERTIFICATE" {
			certIdx++
		}
		r.handleBlock(rel, alias, line, block)
		cur = rem
	}
	return true
}

// handleBlock parses a single PEM block by type and emits any proven asset.
func (r *run) handleBlock(rel, alias string, line int, block *pem.Block) {
	prov := graph.Provenance{Source: graph.SourceFS, Location: rel, Line: line, Detail: block.Type}
	switch block.Type {
	case "CERTIFICATE":
		if c, err := parseCertStrict(block.Bytes); err == nil {
			r.emitCert(rel, alias, prov, block.Bytes, c)
		}
	case "CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST":
		if csr, err := x509.ParseCertificateRequest(block.Bytes); err == nil && csr.CheckSignature() == nil {
			r.emitCSR(rel, alias, prov, csr)
		}
	case "RSA PRIVATE KEY":
		if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
			r.emitPrivateKey(rel, alias, prov, &k.PublicKey)
		}
	case "EC PRIVATE KEY":
		if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
			r.emitPrivateKey(rel, alias, prov, &k.PublicKey)
		}
	case "PRIVATE KEY":
		if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
			if pub, ok := privateKeyPub(k); ok {
				r.emitPrivateKey(rel, alias, prov, pub)
			}
		}
	case "ENCRYPTED PRIVATE KEY":
		if isEncryptedPrivateKey(block.Bytes) {
			r.emitEncryptedKey(rel, alias, prov)
		}
	case "PUBLIC KEY":
		if pub, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
			r.emitPublicKey(rel, alias, prov, pub)
		}
	case "RSA PUBLIC KEY":
		if pub, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
			r.emitPublicKey(rel, alias, prov, pub)
		}
	}
}

// --- binary path ---

// processBinary attempts, in order, DER X.509 (cert/CSR/keys), PKCS#12, and JKS.
// The first format that yields a proven asset wins; a file matching none yields
// nothing. Provenance uses Line 0 (binary, no line semantics).
func (r *run) processBinary(rel string, data []byte) {
	if r.processDER(rel, data) {
		return
	}
	if r.processPKCS12(rel, data) {
		return
	}
	r.processJKS(rel, data)
}

// processDER handles a file that is exactly one DER object with no trailing
// bytes. It tries certificate, then CSR, then private/public key encodings.
func (r *run) processDER(rel string, data []byte) bool {
	if !isSingleDER(data) {
		return false
	}
	prov := graph.Provenance{Source: graph.SourceFS, Location: rel, Line: 0, Detail: "der"}

	if c, err := parseCertStrict(data); err == nil {
		r.emitCert(rel, "", prov, data, c)
		return true
	}
	if csr, err := x509.ParseCertificateRequest(data); err == nil && csr.CheckSignature() == nil {
		r.emitCSR(rel, "", prov, csr)
		return true
	}
	if k, err := x509.ParsePKCS8PrivateKey(data); err == nil {
		if pub, ok := privateKeyPub(k); ok {
			r.emitPrivateKey(rel, "", prov, pub)
			return true
		}
	}
	if k, err := x509.ParsePKCS1PrivateKey(data); err == nil {
		r.emitPrivateKey(rel, "", prov, &k.PublicKey)
		return true
	}
	if k, err := x509.ParseECPrivateKey(data); err == nil {
		r.emitPrivateKey(rel, "", prov, &k.PublicKey)
		return true
	}
	if pub, err := x509.ParsePKIXPublicKey(data); err == nil {
		r.emitPublicKey(rel, "", prov, pub)
		return true
	}
	if isEncryptedPrivateKey(data) {
		r.emitEncryptedKey(rel, "", prov)
		return true
	}
	return false
}

// parseCertStrict parses a DER certificate. It is a thin wrapper so every call
// site rejects the same way; x509.ParseCertificate already rejects trailing
// data and malformed structures.
func parseCertStrict(der []byte) (*x509.Certificate, error) {
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	if c == nil {
		return nil, errors.New("certs: nil certificate")
	}
	return c, nil
}

// --- issuer resolution post-pass ---

// resolveIssuers links every observed Certificate to a CA node. If the issuer's
// certificate was itself observed in this scan, the edge points at ca:<its DER
// SHA-256> (observed=true); otherwise at ca:dn:<issuer DN> (observed=false).
// This is the "observed-issuer resolution" required by the graph contract.
func (r *run) resolveIssuers() {
	// Index observed certs by their raw subject DN bytes.
	subjectToSHA := make(map[string]string, len(r.certs))
	for _, rec := range r.certs {
		key := string(rec.cert.RawSubject)
		if _, ok := subjectToSHA[key]; !ok {
			subjectToSHA[key] = rec.derSHA
		}
	}

	for _, rec := range r.certs {
		certID, err := graph.CertNodeID(rec.derSHA)
		if err != nil {
			continue
		}
		var caID string
		var observed bool
		if issuerSHA, ok := subjectToSHA[string(rec.cert.RawIssuer)]; ok {
			caID, err = graph.CANodeID(issuerSHA)
			observed = true
		} else {
			caID, err = graph.CADNNodeID(rec.cert.Issuer.String())
		}
		if err != nil {
			continue
		}
		ca := &graph.CANode{DN: rec.cert.Issuer.String(), Observed: observed}
		ca.NodeID = caID
		ca.AddProvenance(rec.prov)
		_, _ = r.g.UpsertNode(ca)
		_, _ = r.g.AddEdge(graph.Edge{Type: graph.EdgeIssuedBy, From: certID, To: caID, Provenance: []graph.Provenance{rec.prov}})
	}
}

// --- misc helpers ---

// beginLine returns the 1-based line number of the "-----BEGIN <type>-----"
// header for the block pem.Decode just consumed from cur (a suffix of data).
// It is a best-effort provenance aid; 0 is returned if the marker is not found.
func beginLine(data, cur []byte, blockType string) int {
	consumed := len(data) - len(cur)
	if consumed < 0 || consumed > len(data) {
		return 0
	}
	marker := "-----BEGIN " + blockType
	idx := strings.Index(string(cur), marker)
	if idx < 0 {
		return 0
	}
	off := consumed + idx
	return 1 + strings.Count(string(data[:off]), "\n")
}
