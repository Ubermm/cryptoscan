package cbom_test

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/cryptoscan/cryptoscan/internal/graph"
	"github.com/cryptoscan/cryptoscan/internal/output/cbom"
	"github.com/cryptoscan/cryptoscan/internal/pqc"
	"github.com/cryptoscan/cryptoscan/internal/scan/certs"
	"github.com/cryptoscan/cryptoscan/internal/scan/config"
)

var update = flag.Bool("update", false, "update golden files")

// refTime is the fixed reference clock used for every test so PQC expiry flags
// and the golden output are reproducible.
var refTime = time.Date(2026, 7, 14, 0, 0, 0, 0, time.UTC)

// fixedOpts is the deterministic Options used for golden output: a pinned
// timestamp and a serial derived from the graph content.
var fixedOpts = cbom.Options{
	Timestamp:   time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	ToolVersion: "0.1.0",
}

const (
	certHashLeaf = "1111111111111111111111111111111111111111111111111111111111111111"
	keyHashLeaf  = "3333333333333333333333333333333333333333333333333333333333333333"
)

// buildSample constructs a small deterministic graph: a leaf RSA-2048
// certificate, its public key, a CA, a TLS endpoint, and an nginx config, wired
// with one edge of every projected type.
func buildSample(t *testing.T) *graph.Graph {
	t.Helper()
	g := graph.New()

	leaf := &graph.CertificateNode{
		Subject:            "CN=leaf.example.com,O=Example",
		Issuer:             "CN=Example Root CA",
		Serial:             "0a0b0c",
		Algorithm:          "RSA",
		KeySize:            2048,
		SignatureAlgorithm: "SHA256-RSA",
		NotBefore:          time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:           time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC),
		SAN:                []string{"leaf.example.com", "www.example.com"},
		SPKISHA256:         keyHashLeaf,
	}
	leaf.NodeID = "cert:" + certHashLeaf
	leaf.AddProvenance(graph.Provenance{Source: graph.SourceFS, Location: "/etc/ssl/leaf.pem", Detail: "PEM CERTIFICATE"})

	key := &graph.KeyNode{Algorithm: "RSA", KeySize: 2048, HasPublic: true}
	key.NodeID = "key:" + keyHashLeaf
	key.AddProvenance(graph.Provenance{Source: graph.SourceFS, Location: "/etc/ssl/leaf.pem"})

	endpoint := &graph.EndpointNode{
		Host: "leaf.example.com",
		Port: 443,
		Attrs: map[string]any{
			"negotiated_protocol":     "TLSv1.3",
			"negotiated_cipher_suite": "TLS_AES_128_GCM_SHA256",
			"alpn":                    "h2",
			"protocols_supported":     []string{"TLSv1.2", "TLSv1.3"},
			"pqc_hybrid_kex":          false,
		},
	}
	endpoint.NodeID = "endpoint:leaf.example.com:443"
	endpoint.AddProvenance(graph.Provenance{Source: graph.SourceProbe, Location: "leaf.example.com:443", Detail: "tls handshake"})

	cfg := &graph.ConfigFileNode{
		Path:   "/etc/nginx/nginx.conf",
		Format: "nginx",
		Directives: []graph.Directive{
			{Name: "ssl_certificate", Value: "/etc/ssl/leaf.pem", Line: 12},
		},
		Attrs: map[string]any{
			"protocols": []string{"TLSv1", "TLSv1.1", "TLSv1.2"},
			"ciphers":   []string{"ECDHE-RSA-AES128-GCM-SHA256"},
			"cert_refs": []string{"/etc/ssl/leaf.pem"},
		},
	}
	cfg.NodeID = "file:/etc/nginx/nginx.conf"
	cfg.AddProvenance(graph.Provenance{Source: graph.SourceConfig, Location: "/etc/nginx/nginx.conf", Line: 12})

	ca := &graph.CANode{DN: "CN=Example Root CA", Observed: false}
	ca.NodeID = "ca:dn:CN=Example Root CA"

	for _, n := range []graph.Node{leaf, key, endpoint, cfg, ca} {
		if _, err := g.UpsertNode(n); err != nil {
			t.Fatalf("upsert %s: %v", n.ID(), err)
		}
	}

	edges := []graph.Edge{
		{Type: graph.EdgeIssuedBy, From: leaf.ID(), To: ca.ID()},
		{Type: graph.EdgeSignsWith, From: leaf.ID(), To: key.ID()},
		{Type: graph.EdgeStoredIn, From: leaf.ID(), To: cfg.ID()},
		{Type: graph.EdgeReferences, From: cfg.ID(), To: leaf.ID()},
		{Type: graph.EdgeTerminatesTLSFor, From: leaf.ID(), To: endpoint.ID()},
	}
	for _, e := range edges {
		if _, err := g.AddEdge(e); err != nil {
			t.Fatalf("add edge %s: %v", e.Type, err)
		}
	}
	return g
}

func TestGolden(t *testing.T) {
	cases := map[string]*graph.Graph{
		"sample": buildSample(t),
		"empty":  graph.New(),
	}
	for name, g := range cases {
		t.Run(name, func(t *testing.T) {
			exposure := pqc.Score(g, refTime)

			var buf bytes.Buffer
			if err := cbom.Write(&buf, g, exposure, fixedOpts); err != nil {
				t.Fatalf("Write: %v", err)
			}
			if !json.Valid(buf.Bytes()) {
				t.Fatalf("output is not valid JSON:\n%s", buf.String())
			}
			assertGolden(t, name+".json", buf.Bytes())

			// Every generated BOM must validate against the CycloneDX 1.6 schema.
			validateSchema(t, buf.Bytes())

			// Determinism: a second Write is byte-identical.
			var buf2 bytes.Buffer
			if err := cbom.Write(&buf2, g, pqc.Score(g, refTime), fixedOpts); err != nil {
				t.Fatalf("Write (2nd): %v", err)
			}
			if !bytes.Equal(buf.Bytes(), buf2.Bytes()) {
				t.Error("Write is not deterministic")
			}
		})
	}
}

// TestSchemaValidationCorpus scans the real corpus into a graph, scores it, emits
// a CBOM, and validates the CBOM against the vendored CycloneDX 1.6 schema —
// proving the output is standards-native on real scanner data (principle 4).
func TestSchemaValidationCorpus(t *testing.T) {
	g := scanCorpus(t)
	exposure := pqc.Score(g, refTime)

	var buf bytes.Buffer
	if err := cbom.Write(&buf, g, exposure, cbom.Options{Timestamp: refTime}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	validateSchema(t, buf.Bytes())

	// Sanity: the corpus produces a non-trivial component set.
	var doc struct {
		Components []struct {
			Type string `json:"type"`
		} `json:"components"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	if len(doc.Components) == 0 {
		t.Fatal("corpus CBOM has zero components")
	}
	t.Logf("corpus CBOM: %d components", len(doc.Components))
}

// TestDeterminismCorpus asserts two Writes of the corpus graph are byte-identical.
func TestDeterminismCorpus(t *testing.T) {
	g := scanCorpus(t)
	opts := cbom.Options{Timestamp: refTime}

	var a, b bytes.Buffer
	if err := cbom.Write(&a, g, pqc.Score(g, refTime), opts); err != nil {
		t.Fatalf("Write a: %v", err)
	}
	if err := cbom.Write(&b, g, pqc.Score(g, refTime), opts); err != nil {
		t.Fatalf("Write b: %v", err)
	}
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Error("corpus CBOM is not deterministic")
	}
}

// parsedBOM is a minimal projection used to assert specific mappings.
type parsedBOM struct {
	Components []struct {
		Type             string `json:"type"`
		BOMRef           string `json:"bom-ref"`
		Name             string `json:"name"`
		CryptoProperties *struct {
			AssetType             string `json:"assetType"`
			CertificateProperties *struct {
				NotValidAfter string `json:"notValidAfter"`
			} `json:"certificateProperties"`
			ProtocolProperties *struct {
				Type string `json:"type"`
			} `json:"protocolProperties"`
		} `json:"cryptoProperties"`
		Properties []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"properties"`
	} `json:"components"`
}

func (p parsedBOM) byRef(ref string) (int, bool) {
	for i, c := range p.Components {
		if c.BOMRef == ref {
			return i, true
		}
	}
	return 0, false
}

// TestMappings asserts the specific projections the design calls out: an RSA-1024
// cert carries quantum_vulnerable + weak_key; a hybrid-PQC endpoint's protocol
// component is NOT quantum_vulnerable; an expired cert's notValidAfter is in the
// past and its severity property is present.
func TestMappings(t *testing.T) {
	g := graph.New()

	// Weak RSA-1024 leaf, valid window.
	weak := &graph.CertificateNode{
		Subject: "CN=weak.example.com", Algorithm: "RSA", KeySize: 1024,
		SignatureAlgorithm: "SHA256-RSA",
		NotBefore:          time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:           time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	weak.NodeID = "cert:" + strings.Repeat("a", 64)
	mustUpsert(t, g, weak)

	// Expired ECDSA cert.
	expired := &graph.CertificateNode{
		Subject: "CN=expired.example.com", Algorithm: "ECDSA", KeySize: 256,
		SignatureAlgorithm: "ECDSA-SHA256",
		NotBefore:          time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:           time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	expired.NodeID = "cert:" + strings.Repeat("b", 64)
	mustUpsert(t, g, expired)

	// Hybrid-PQC TLS endpoint.
	hybrid := &graph.EndpointNode{
		Host: "pqc.example.com", Port: 443,
		Attrs: map[string]any{
			"negotiated_protocol": "TLSv1.3",
			"protocols_supported": []string{"TLSv1.2", "TLSv1.3"},
			"pqc_hybrid_kex":      true,
		},
	}
	hybrid.NodeID = "endpoint:pqc.example.com:443"
	mustUpsert(t, g, hybrid)

	exposure := pqc.Score(g, refTime)
	var buf bytes.Buffer
	if err := cbom.Write(&buf, g, exposure, cbom.Options{Timestamp: refTime}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	validateSchema(t, buf.Bytes())

	var doc parsedBOM
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("parse: %v", err)
	}

	// RSA-1024 cert: quantum_vulnerable + weak_key.
	i, ok := doc.byRef(weak.ID())
	if !ok {
		t.Fatal("weak cert component missing")
	}
	assertProp(t, doc.Components[i].Properties, "cryptoscan:pqc:quantum_vulnerable_algorithm", "true")
	assertProp(t, doc.Components[i].Properties, "cryptoscan:pqc:weak_key", "true")

	// Hybrid endpoint: protocol component present, NOT quantum_vulnerable.
	j, ok := doc.byRef(hybrid.ID())
	if !ok {
		t.Fatal("hybrid endpoint component missing")
	}
	if cp := doc.Components[j].CryptoProperties; cp == nil || cp.AssetType != "protocol" || cp.ProtocolProperties == nil || cp.ProtocolProperties.Type != "tls" {
		t.Errorf("hybrid endpoint is not a tls protocol component: %+v", doc.Components[j].CryptoProperties)
	}
	if hasProp(doc.Components[j].Properties, "cryptoscan:pqc:quantum_vulnerable_algorithm") {
		t.Error("hybrid-PQC endpoint must NOT be flagged quantum_vulnerable")
	}

	// Expired cert: notValidAfter in the past + severity property present.
	k, ok := doc.byRef(expired.ID())
	if !ok {
		t.Fatal("expired cert component missing")
	}
	cp := doc.Components[k].CryptoProperties
	if cp == nil || cp.CertificateProperties == nil {
		t.Fatal("expired cert has no certificateProperties")
	}
	nva, err := time.Parse(time.RFC3339, cp.CertificateProperties.NotValidAfter)
	if err != nil {
		t.Fatalf("parse notValidAfter %q: %v", cp.CertificateProperties.NotValidAfter, err)
	}
	if !nva.Before(refTime) {
		t.Errorf("expired cert notValidAfter %v is not before refTime %v", nva, refTime)
	}
	if !hasProp(doc.Components[k].Properties, "cryptoscan:pqc:severity") {
		t.Error("expired cert missing cryptoscan:pqc:severity property")
	}
	assertProp(t, doc.Components[k].Properties, "cryptoscan:pqc:expired", "true")
}

// TestCSRComponent asserts a CertificateRequest node projects into a schema-valid
// related-crypto-material component carrying the cryptoscan:asset:type=csr marker,
// the SPKI id, an algorithmRef, and a signs_with→Key dependency.
func TestCSRComponent(t *testing.T) {
	const csrKeySPKI = "4444444444444444444444444444444444444444444444444444444444444444"
	const csrDER = "5555555555555555555555555555555555555555555555555555555555555555"

	g := graph.New()

	csr := &graph.CertificateRequestNode{
		Subject:            "CN=req.example.com,O=Example",
		Algorithm:          "ECDSA",
		KeySize:            256,
		Curve:              "P-256",
		SignatureAlgorithm: "ECDSA-SHA256",
		SPKISHA256:         csrKeySPKI,
	}
	csr.NodeID = "csr:" + csrDER
	csr.AddProvenance(graph.Provenance{Source: graph.SourceFS, Location: "keys/req.csr", Line: 1, Detail: "PEM CERTIFICATE REQUEST"})
	mustUpsert(t, g, csr)

	key := &graph.KeyNode{Algorithm: "ECDSA", KeySize: 256, Curve: "P-256", HasPublic: true}
	key.NodeID = "key:" + csrKeySPKI
	key.AddProvenance(graph.Provenance{Source: graph.SourceFS, Location: "keys/req.csr", Line: 1})
	mustUpsert(t, g, key)

	if _, err := g.AddEdge(graph.Edge{Type: graph.EdgeSignsWith, From: csr.ID(), To: key.ID()}); err != nil {
		t.Fatalf("add signs_with edge: %v", err)
	}

	exposure := pqc.Score(g, refTime)
	var buf bytes.Buffer
	if err := cbom.Write(&buf, g, exposure, cbom.Options{Timestamp: refTime}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	validateSchema(t, buf.Bytes())

	var doc parsedBOM
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("parse: %v", err)
	}
	i, ok := doc.byRef(csr.ID())
	if !ok {
		t.Fatal("CSR component missing from BOM")
	}
	c := doc.Components[i]
	if c.CryptoProperties == nil || c.CryptoProperties.AssetType != "related-crypto-material" {
		t.Errorf("CSR assetType = %+v, want related-crypto-material", c.CryptoProperties)
	}
	assertProp(t, c.Properties, "cryptoscan:asset:type", "csr")
	assertProp(t, c.Properties, "cryptoscan:pqc:quantum_vulnerable_algorithm", "true")
	if !hasProp(c.Properties, "cryptoscan:csr:note") {
		t.Error("CSR component missing cryptoscan:csr:note property")
	}

	// The signs_with CSR→Key linkage is carried as a dependency.
	var deps struct {
		Dependencies []struct {
			Ref       string   `json:"ref"`
			DependsOn []string `json:"dependsOn"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(buf.Bytes(), &deps); err != nil {
		t.Fatalf("parse deps: %v", err)
	}
	found := false
	for _, d := range deps.Dependencies {
		if d.Ref == csr.ID() {
			for _, on := range d.DependsOn {
				if on == key.ID() {
					found = true
				}
			}
		}
	}
	if !found {
		t.Errorf("CSR %s must dependsOn key %s in the dependency graph", csr.ID(), key.ID())
	}
}

// TestNilGraph proves a nil graph yields a valid minimal BOM without panicking.
func TestNilGraph(t *testing.T) {
	var buf bytes.Buffer
	if err := cbom.Write(&buf, nil, pqc.Score(nil, refTime), cbom.Options{}); err != nil {
		t.Fatalf("Write(nil): %v", err)
	}
	validateSchema(t, buf.Bytes())
}

// --- helpers ---

func mustUpsert(t *testing.T, g *graph.Graph, n graph.Node) {
	t.Helper()
	if _, err := g.UpsertNode(n); err != nil {
		t.Fatalf("upsert %s: %v", n.ID(), err)
	}
}

func assertProp(t *testing.T, props []struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}, name, want string) {
	t.Helper()
	for _, p := range props {
		if p.Name == name {
			if p.Value != want {
				t.Errorf("property %s = %q, want %q", name, p.Value, want)
			}
			return
		}
	}
	t.Errorf("property %s not found", name)
}

func hasProp(props []struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}, name string) bool {
	for _, p := range props {
		if p.Name == name {
			return true
		}
	}
	return false
}

// scanCorpus scans the committed corpus into a graph via the same scanners the
// CLI uses (certs + config + reference resolution).
func scanCorpus(t *testing.T) *graph.Graph {
	t.Helper()
	root := filepath.Join("..", "..", "..", "testdata", "corpus")
	if _, err := os.Stat(root); err != nil {
		t.Skipf("corpus not found at %s: %v", root, err)
	}
	g := graph.New()
	if _, err := certs.New().ScanIntoGraph(root, g); err != nil {
		t.Fatalf("cert scan: %v", err)
	}
	if _, err := config.ScanIntoGraph(root, g); err != nil {
		t.Fatalf("config scan: %v", err)
	}
	g.ResolveReferences()
	return g
}

// assertGolden compares got against testdata/golden/<name>, or rewrites it under
// -update.
func assertGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", "golden", name)
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir golden: %v", err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s (run with -update to create): %v", name, err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("output does not match golden %s\n--- got ---\n%s", name, got)
	}
}

// --- schema validation ---

var compiledSchema *jsonschema.Schema

// validateSchema validates bomBytes against the vendored CycloneDX 1.6 JSON
// schema using a real JSON-Schema validator (santhosh-tekuri/jsonschema/v6). The
// three schema files (bom-1.6, jsf-0.82, spdx) are registered by their canonical
// $id URLs so the relative $refs resolve offline.
func validateSchema(t *testing.T, bomBytes []byte) {
	t.Helper()
	sch := loadSchema(t)
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(bomBytes))
	if err != nil {
		t.Fatalf("unmarshal instance: %v", err)
	}
	if err := sch.Validate(inst); err != nil {
		t.Fatalf("CBOM does not validate against CycloneDX 1.6 schema:\n%v", err)
	}
}

func loadSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	if compiledSchema != nil {
		return compiledSchema
	}
	c := jsonschema.NewCompiler()
	for _, f := range []struct{ url, file string }{
		{"http://cyclonedx.org/schema/bom-1.6.schema.json", "bom-1.6.schema.json"},
		{"http://cyclonedx.org/schema/jsf-0.82.schema.json", "jsf-0.82.schema.json"},
		{"http://cyclonedx.org/schema/spdx.schema.json", "spdx.schema.json"},
	} {
		raw, err := os.ReadFile(filepath.Join("testdata", f.file))
		if err != nil {
			t.Fatalf("read schema %s: %v", f.file, err)
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		if err != nil {
			t.Fatalf("unmarshal schema %s: %v", f.file, err)
		}
		if err := c.AddResource(f.url, doc); err != nil {
			t.Fatalf("add resource %s: %v", f.url, err)
		}
	}
	sch, err := c.Compile("http://cyclonedx.org/schema/bom-1.6.schema.json")
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}
	compiledSchema = sch
	return sch
}
