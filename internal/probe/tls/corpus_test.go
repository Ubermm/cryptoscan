package tls

import (
	"context"
	"crypto/sha256"
	stdtls "crypto/tls"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/Ubermm/cryptoscan/internal/graph"
	"github.com/Ubermm/cryptoscan/internal/probe"
	"github.com/Ubermm/cryptoscan/internal/scan/certs"
)

// These are the two INTEGRATION-level entity-resolution assertions the DESIGN
// contract calls THE promise (docs/DESIGN.md §1 network probe contract): a
// certificate seen at a TLS endpoint and the SAME bytes seen on disk resolve to
// ONE Certificate node (keyed by DER SHA-256), and one certificate presented at
// two endpoints is still ONE node with two terminates_tls_for edges. Unlike the
// unit tests in tls_test.go (which generate a cert in-process), these drive REAL
// corpus fixtures so the cross-surface identity is proven on identical bytes.

// corpusDir resolves testdata/corpus relative to this package's working
// directory (tests run in internal/probe/tls, so the corpus is three levels up).
// It skips with a clear message only if the corpus is genuinely absent.
func corpusDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join("..", "..", "..", "testdata", "corpus"))
	if err != nil {
		t.Fatalf("resolve corpus dir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "certs")); err != nil {
		t.Skipf("corpus fixtures unavailable at %s: %v", dir, err)
	}
	return dir
}

// fixtureServerCert loads a corpus cert+key pair into a tls.Certificate for an
// in-process server presenting exactly those bytes.
func fixtureServerCert(t *testing.T, corpus, certRel, keyRel string) stdtls.Certificate {
	t.Helper()
	cert, err := stdtls.LoadX509KeyPair(filepath.Join(corpus, certRel), filepath.Join(corpus, keyRel))
	if err != nil {
		t.Fatalf("load fixture %s + %s: %v", certRel, keyRel, err)
	}
	return cert
}

// fixtureLeafDER reads the corpus cert PEM and returns the DER of its first
// CERTIFICATE block — the exact bytes the fs scanner hashes for identity. This
// is computed independently of the prober's own parse path.
func fixtureLeafDER(t *testing.T, corpus, certRel string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(corpus, certRel))
	if err != nil {
		t.Fatalf("read fixture %s: %v", certRel, err)
	}
	for rest := data; ; {
		block, rem := pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			return block.Bytes
		}
		rest = rem
	}
	t.Fatalf("fixture %s has no CERTIFICATE PEM block", certRel)
	return nil
}

// expectedCertID computes the Certificate node ID directly from DER bytes:
// sha256(DER) -> hex -> graph.CertNodeID. This is the fs scanner's identity for
// the file, derived without touching the prober or certs.ParseObservedCert.
func expectedCertID(t *testing.T, der []byte) string {
	t.Helper()
	sum := sha256.Sum256(der)
	id, err := graph.CertNodeID(hex.EncodeToString(sum[:]))
	if err != nil {
		t.Fatalf("CertNodeID: %v", err)
	}
	return id
}

// countNodesByType returns how many nodes of nt are in g.
func countNodesByType(g *graph.Graph, nt graph.NodeType) int {
	n := 0
	for _, nd := range g.Nodes() {
		if nd.Type() == nt {
			n++
		}
	}
	return n
}

// countEdgesByType returns how many edges of et are in g.
func countEdgesByType(g *graph.Graph, et graph.EdgeType) int {
	n := 0
	for _, e := range g.Edges() {
		if e.Type == et {
			n++
		}
	}
	return n
}

// TestCorpusCrossSurfaceNodeIdentity proves the core DESIGN promise on a REAL
// corpus fixture: the certificate the prober observes at a TLS endpoint resolves
// to EXACTLY the Certificate node the fs scanner derives from the same file's
// DER bytes, and re-scanning that same file on disk into the SAME graph adds no
// new Certificate node — it lands one node bearing BOTH a terminates_tls_for
// edge (probe) and a stored_in edge (fs).
func TestCorpusCrossSurfaceNodeIdentity(t *testing.T) {
	corpus := corpusDir(t)

	cases := []struct {
		name    string
		certRel string
		keyRel  string
	}{
		{"rsa2048", filepath.Join("certs", "rsa-2048-selfsigned.pem"), filepath.Join("keys", "rsa-2048.key")},
		{"ecdsap256", filepath.Join("certs", "ecdsa-p256.pem"), filepath.Join("keys", "ecdsa-p256.key")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			serverCert := fixtureServerCert(t, corpus, tc.certRel, tc.keyRel)
			der := fixtureLeafDER(t, corpus, tc.certRel)
			wantCertID := expectedCertID(t, der)

			// In-process TLS server presenting the fixture, MinVersion TLS 1.2.
			addr := startTLSServer(t, serverCert, func(c *stdtls.Config) {
				c.MinVersion = stdtls.VersionTLS12
			})
			tgt := target(t, addr)

			// Probe into g.
			g := graph.New()
			if _, err := newTestProber().Probe(context.Background(), tgt, g); err != nil {
				t.Fatalf("Probe(%s): %v", addr, err)
			}

			// The probe created a Certificate node with EXACTLY the fs identity.
			nd, ok := g.Node(wantCertID)
			if !ok {
				t.Fatalf("probe graph missing Certificate node %q (fs DER identity)", wantCertID)
			}
			if nd.Type() != graph.NodeCertificate {
				t.Fatalf("node %q has type %s, want Certificate", wantCertID, nd.Type())
			}

			// ... with a terminates_tls_for edge to the endpoint node.
			epID, err := graph.EndpointNodeID(tgt.Host, tgt.Port)
			if err != nil {
				t.Fatalf("EndpointNodeID: %v", err)
			}
			if !hasEdge(g, graph.EdgeTerminatesTLSFor, wantCertID, epID) {
				t.Fatalf("missing terminates_tls_for edge %s -> %s", wantCertID, epID)
			}

			// Now run the fs certs scanner over a temp dir holding the SAME
			// fixture file, into the SAME graph. The cert must resolve to the
			// same node — Certificate node count must NOT increase.
			certsBefore := countNodesByType(g, graph.NodeCertificate)

			scanDir := t.TempDir()
			diskCert := filepath.Join(scanDir, "cert.pem")
			if data, rerr := os.ReadFile(filepath.Join(corpus, tc.certRel)); rerr != nil {
				t.Fatalf("read fixture for fs scan: %v", rerr)
			} else if werr := os.WriteFile(diskCert, data, 0o600); werr != nil {
				t.Fatalf("write temp fixture: %v", werr)
			}
			if _, err := certs.New().ScanIntoGraph(scanDir, g); err != nil {
				t.Fatalf("ScanIntoGraph: %v", err)
			}

			certsAfter := countNodesByType(g, graph.NodeCertificate)
			if certsAfter != certsBefore {
				t.Fatalf("Certificate node count changed %d -> %d; fs scan did not resolve to the SAME node", certsBefore, certsAfter)
			}

			// The ONE node now bears BOTH edges: terminates_tls_for (probe) and
			// stored_in (fs, cert -> the on-disk file node).
			fileID, err := graph.FileNodeID(diskCert)
			if err != nil {
				t.Fatalf("FileNodeID: %v", err)
			}
			if !hasEdge(g, graph.EdgeTerminatesTLSFor, wantCertID, epID) {
				t.Errorf("terminates_tls_for edge lost after fs scan (%s -> %s)", wantCertID, epID)
			}
			if !hasEdge(g, graph.EdgeStoredIn, wantCertID, fileID) {
				t.Errorf("missing stored_in edge %s -> %s after fs scan", wantCertID, fileID)
			}
		})
	}
}

// TestCorpusOneCertTwoEndpoints proves cross-target entity resolution plus the
// probe.Run graph merge: the SAME fixture cert presented on two ports yields
// exactly ONE Certificate node, TWO distinct Endpoint nodes, and TWO
// terminates_tls_for edges (cert -> each endpoint).
func TestCorpusOneCertTwoEndpoints(t *testing.T) {
	corpus := corpusDir(t)
	certRel := filepath.Join("certs", "rsa-2048-selfsigned.pem")
	keyRel := filepath.Join("keys", "rsa-2048.key")

	serverCert := fixtureServerCert(t, corpus, certRel, keyRel)
	wantCertID := expectedCertID(t, fixtureLeafDER(t, corpus, certRel))

	mutate := func(c *stdtls.Config) { c.MinVersion = stdtls.VersionTLS12 }
	addr1 := startTLSServer(t, serverCert, mutate)
	addr2 := startTLSServer(t, serverCert, mutate)
	if addr1 == addr2 {
		t.Fatalf("both servers bound the same address %q", addr1)
	}
	tgt1, tgt2 := target(t, addr1), target(t, addr2)

	g := graph.New()
	res, err := probe.Run(context.Background(), []probe.Target{tgt1, tgt2}, g,
		probe.RunOptions{Probers: []probe.Prober{newTestProber()}})
	if err != nil {
		t.Fatalf("probe.Run: %v", err)
	}
	if len(res.Errors) != 0 {
		t.Fatalf("Run errors = %v, want none", res.Errors)
	}

	if got := countNodesByType(g, graph.NodeCertificate); got != 1 {
		t.Errorf("Certificate nodes = %d, want 1 (one cert on two ports is ONE node)", got)
	}
	if _, ok := g.Node(wantCertID); !ok {
		t.Errorf("merged graph missing the shared Certificate node %q", wantCertID)
	}
	if got := countNodesByType(g, graph.NodeEndpoint); got != 2 {
		t.Errorf("Endpoint nodes = %d, want 2 (two distinct host:port)", got)
	}
	if got := countEdgesByType(g, graph.EdgeTerminatesTLSFor); got != 2 {
		t.Errorf("terminates_tls_for edges = %d, want 2", got)
	}

	epID1, err := graph.EndpointNodeID(tgt1.Host, tgt1.Port)
	if err != nil {
		t.Fatalf("EndpointNodeID 1: %v", err)
	}
	epID2, err := graph.EndpointNodeID(tgt2.Host, tgt2.Port)
	if err != nil {
		t.Fatalf("EndpointNodeID 2: %v", err)
	}
	if epID1 == epID2 {
		t.Fatalf("endpoint IDs collided: %q", epID1)
	}
	if !hasEdge(g, graph.EdgeTerminatesTLSFor, wantCertID, epID1) {
		t.Errorf("missing terminates_tls_for edge %s -> %s", wantCertID, epID1)
	}
	if !hasEdge(g, graph.EdgeTerminatesTLSFor, wantCertID, epID2) {
		t.Errorf("missing terminates_tls_for edge %s -> %s", wantCertID, epID2)
	}
}
