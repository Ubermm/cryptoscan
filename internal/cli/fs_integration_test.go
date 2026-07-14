package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/Ubermm/cryptoscan/internal/graph"
	"github.com/Ubermm/cryptoscan/internal/scan/certs"
	"github.com/Ubermm/cryptoscan/internal/scan/config"
)

// corpusRoot locates the ground-truth corpus relative to this package.
func corpusRoot(t *testing.T) string {
	t.Helper()
	root := filepath.Join("..", "..", "testdata", "corpus")
	if _, err := os.Stat(root); err != nil {
		t.Fatalf("corpus not found at %q: %v", root, err)
	}
	return root
}

// buildGraph runs both Phase 1 scanners into one graph and resolves the
// references join, exactly as the fs command does.
func buildGraph(t *testing.T, root string) *graph.Graph {
	t.Helper()
	g := graph.New()
	if _, err := certs.New().ScanIntoGraph(root, g); err != nil {
		t.Fatalf("certs scan: %v", err)
	}
	if _, err := config.ScanIntoGraph(root, g); err != nil {
		t.Fatalf("config scan: %v", err)
	}
	g.ResolveReferences()
	return g
}

// fileID is the graph node ID for a corpus-relative path.
func fileID(t *testing.T, root, rel string) string {
	t.Helper()
	id, err := graph.FileNodeID(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("FileNodeID(%q): %v", rel, err)
	}
	return id
}

// certIDsInFile returns the Certificate node ID for every CERTIFICATE PEM block
// (or the raw DER object) in a corpus file, computed independently of the
// scanner from the fixture bytes — so asserting against it is a real check.
func certIDsInFile(t *testing.T, root, rel string) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read %q: %v", rel, err)
	}
	var ids []string
	rest := data
	sawPEM := false
	for {
		block, rem := pem.Decode(rest)
		if block == nil {
			break
		}
		sawPEM = true
		if block.Type == "CERTIFICATE" {
			ids = append(ids, certID(t, block.Bytes))
		}
		rest = rem
	}
	if !sawPEM {
		// Raw DER file.
		ids = append(ids, certID(t, data))
	}
	return ids
}

func certID(t *testing.T, der []byte) string {
	t.Helper()
	sum := sha256.Sum256(der)
	id, err := graph.CertNodeID(hex.EncodeToString(sum[:]))
	if err != nil {
		t.Fatalf("CertNodeID: %v", err)
	}
	return id
}

// hasReferencesTo reports whether a `references` edge From→To exists, and
// returns its provenance for provenance-preservation assertions.
func hasReferencesTo(g *graph.Graph, from, to string) (bool, []graph.Provenance) {
	for _, e := range g.Edges() {
		if e.Type == graph.EdgeReferences && e.From == from && e.To == to {
			return true, e.Provenance
		}
	}
	return false, nil
}

// storedInFiles returns the set of file node IDs an asset is stored_in.
func storedInFiles(g *graph.Graph, assetID string) []string {
	var out []string
	for _, e := range g.Edges() {
		if e.Type == graph.EdgeStoredIn && e.From == assetID {
			out = append(out, e.To)
		}
	}
	sort.Strings(out)
	return out
}

// TestFsResolvedReferences is the Phase 1 headline: after both scanners populate
// one graph and the resolver runs, config files carry `references` edges to the
// exact Certificate nodes they point at, identified by DER hash.
func TestFsResolvedReferences(t *testing.T) {
	root := corpusRoot(t)
	g := buildGraph(t, root)

	// nginx legacy.conf -> Certificate node of certs/rsa-2048-selfsigned.pem.
	nginxLegacy := fileID(t, root, "configs/nginx/legacy.conf")
	rsaCertIDs := certIDsInFile(t, root, "certs/rsa-2048-selfsigned.pem")
	if len(rsaCertIDs) != 1 {
		t.Fatalf("rsa-2048-selfsigned.pem: want 1 cert, got %d", len(rsaCertIDs))
	}
	ok, prov := hasReferencesTo(g, nginxLegacy, rsaCertIDs[0])
	if !ok {
		t.Fatalf("no references edge nginx legacy.conf -> %s", rsaCertIDs[0])
	}
	// Provenance must be preserved from the config directive (config source,
	// pointing at the config file).
	if len(prov) == 0 {
		t.Fatal("resolved references edge has no provenance")
	}
	foundConfigProv := false
	for _, p := range prov {
		if p.Source == graph.SourceConfig && strings.Contains(filepath.ToSlash(p.Location), "nginx/legacy.conf") {
			foundConfigProv = true
		}
	}
	if !foundConfigProv {
		t.Errorf("references edge provenance %+v missing config-directive record", prov)
	}

	// modern.conf -> ecdsa-p256.pem cert.
	nginxModern := fileID(t, root, "configs/nginx/modern.conf")
	ecdsaCertIDs := certIDsInFile(t, root, "certs/ecdsa-p256.pem")
	if ok, _ := hasReferencesTo(g, nginxModern, ecdsaCertIDs[0]); !ok {
		t.Errorf("no references edge nginx modern.conf -> ecdsa cert %s", ecdsaCertIDs[0])
	}

	// with-include.conf -> leaf-chain.pem, which holds TWO certs: the config
	// must resolve to BOTH, and both must be stored_in the ONE leaf-chain file.
	nginxInclude := fileID(t, root, "configs/nginx/with-include.conf")
	chainCertIDs := certIDsInFile(t, root, "certs/leaf-chain.pem")
	if len(chainCertIDs) != 2 {
		t.Fatalf("leaf-chain.pem: want 2 certs, got %d", len(chainCertIDs))
	}
	chainFile := fileID(t, root, "certs/leaf-chain.pem")
	if chainCertIDs[0] == chainCertIDs[1] {
		t.Fatalf("leaf-chain certs are not distinct nodes: %s", chainCertIDs[0])
	}
	for _, cid := range chainCertIDs {
		if ok, _ := hasReferencesTo(g, nginxInclude, cid); !ok {
			t.Errorf("no references edge with-include.conf -> chain cert %s", cid)
		}
		// Each chain cert must be stored_in the ONE leaf-chain file node (it may
		// legitimately also appear standalone elsewhere — the leaf and the
		// intermediate each have their own single-cert PEM too, which is exactly
		// the entity-resolution merge working).
		if !contains(storedInFiles(g, cid), chainFile) {
			t.Errorf("chain cert %s not stored_in leaf-chain file %s", cid, chainFile)
		}
	}

	// The leaf-chain FILE node must have exactly TWO Certificate nodes stored in
	// it (the two blocks), proving one file -> two cert nodes.
	certsInChainFile := 0
	for _, e := range g.Edges() {
		if e.Type != graph.EdgeStoredIn || e.To != chainFile {
			continue
		}
		if n, ok := g.Node(e.From); ok && n.Type() == graph.NodeCertificate {
			certsInChainFile++
		}
	}
	if certsInChainFile != 2 {
		t.Errorf("leaf-chain file has %d cert nodes stored_in, want 2", certsInChainFile)
	}
}

func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

// TestFsSSHHostKeysUnresolved asserts that references to files never scanned —
// sshd HostKey paths under /etc/ssh — stay as bare file references and are NOT
// joined to any Certificate/Key node (no guessing).
func TestFsSSHHostKeysUnresolved(t *testing.T) {
	root := corpusRoot(t)
	g := buildGraph(t, root)

	sshdDefault := fileID(t, root, "configs/ssh/default_sshd_config")

	// The /etc/ssh host-key file nodes must exist as reference targets but have
	// no cert/key stored in them, so they resolve to nothing.
	hostKeyPath, err := graph.FileNodeID("/etc/ssh/ssh_host_rsa_key")
	if err != nil {
		t.Fatalf("FileNodeID: %v", err)
	}
	if ok, _ := hasReferencesTo(g, sshdDefault, hostKeyPath); !ok {
		t.Fatalf("expected bare file reference sshd -> %s", hostKeyPath)
	}

	// No references edge from the sshd config may point at a Certificate/Key.
	for _, e := range g.Edges() {
		if e.Type != graph.EdgeReferences || e.From != sshdDefault {
			continue
		}
		n, ok := g.Node(e.To)
		if !ok {
			continue
		}
		if t2 := n.Type(); t2 == graph.NodeCertificate || t2 == graph.NodeKey {
			t.Errorf("sshd host key resolved to %s node %s, want unresolved", t2, e.To)
		}
	}
}

// TestEntityResolutionIdentity is the core DESIGN promise: the same certificate
// parsed from a PEM file, a DER file, and inside a PKCS#12 keystore is ONE
// Certificate node (same DER hash) with stored_in edges to THREE file nodes.
func TestEntityResolutionIdentity(t *testing.T) {
	root := corpusRoot(t)
	g := buildGraph(t, root)

	ids := certIDsInFile(t, root, "certs/rsa-2048-selfsigned.der")
	if len(ids) != 1 {
		t.Fatalf("der file: want 1 cert, got %d", len(ids))
	}
	certNodeID := ids[0]

	// The PEM must hash to the same node ID (identity via DER SHA-256).
	pemIDs := certIDsInFile(t, root, "certs/rsa-2048-selfsigned.pem")
	if len(pemIDs) != 1 || pemIDs[0] != certNodeID {
		t.Fatalf("pem cert ID %v != der cert ID %s", pemIDs, certNodeID)
	}

	// Exactly one node with this ID exists, and it is a Certificate.
	n, ok := g.Node(certNodeID)
	if !ok {
		t.Fatalf("certificate node %s not in graph", certNodeID)
	}
	if n.Type() != graph.NodeCertificate {
		t.Fatalf("node %s is %s, want Certificate", certNodeID, n.Type())
	}

	// stored_in THREE files: PEM, DER, and the PKCS#12 keystore.
	want := []string{
		fileID(t, root, "certs/rsa-2048-selfsigned.der"),
		fileID(t, root, "certs/rsa-2048-selfsigned.pem"),
		fileID(t, root, "keystores/rsa2048.p12"),
	}
	sort.Strings(want)
	got := storedInFiles(g, certNodeID)
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("stored_in files:\n got  %v\n want %v", got, want)
	}
}

// TestFsCommandOutput runs the fs command through cobra and asserts the output
// is well-structured and deterministically ordered. Absolute paths and node
// counts are not golden-compared (they are environment/phase sensitive); instead
// the structure and ordering guarantees are asserted.
func TestFsCommandOutput(t *testing.T) {
	root := corpusRoot(t)

	var out bytes.Buffer
	cmd := newRootCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"fs", root})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("fs command errored: %v", err)
	}
	got := out.String()

	for _, want := range []string{
		"Findings by class:",
		"Findings:",
		"CLASS", "PATH", "DETAIL", "FLAGS",
		"total",
		"Graph nodes:",
		"Graph edges:",
		"Resolved references (config -> cert/key):",
		"legacy-tls",
		"expired",
		"weak-sig",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("fs output missing %q", want)
		}
	}

	// The findings table rows must be sorted by (class, path). Extract the data
	// rows and confirm non-decreasing order.
	var rows []string
	inTable := false
	for _, line := range strings.Split(got, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "Findings:" {
			inTable = true
			continue
		}
		if inTable {
			if strings.HasPrefix(trimmed, "CLASS") {
				continue
			}
			if trimmed == "" || strings.HasPrefix(trimmed, "Graph") {
				break
			}
			rows = append(rows, trimmed)
		}
	}
	if len(rows) == 0 {
		t.Fatal("no findings-table rows parsed")
	}
	for i := 1; i < len(rows); i++ {
		if rows[i-1] > rows[i] {
			t.Errorf("findings table not sorted: %q before %q", rows[i-1], rows[i])
		}
	}
}

// TestFsCommandQuiet asserts --quiet prints the counts block and the one-line
// graph summary but omits the full findings table.
func TestFsCommandQuiet(t *testing.T) {
	root := corpusRoot(t)

	var out bytes.Buffer
	cmd := newRootCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"fs", "--quiet", root})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("fs --quiet errored: %v", err)
	}
	got := out.String()

	if !strings.Contains(got, "Findings by class:") {
		t.Error("quiet output missing class counts")
	}
	if !strings.Contains(got, "resolved references") {
		t.Error("quiet output missing one-line graph summary")
	}
	if strings.Contains(got, "Findings:") || strings.Contains(got, "DETAIL") {
		t.Error("quiet output should omit the findings table")
	}
}

// TestFsCommandBadRoot asserts a non-existent path fails (exit 1 via Execute),
// never panics.
func TestFsCommandBadRoot(t *testing.T) {
	var out bytes.Buffer
	cmd := newRootCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"fs", filepath.Join(t.TempDir(), "does-not-exist")})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error for non-existent root, got nil")
	}
}
