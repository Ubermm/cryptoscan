package report_test

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cryptoscan/cryptoscan/internal/graph"
	"github.com/cryptoscan/cryptoscan/internal/output/report"
	"github.com/cryptoscan/cryptoscan/internal/pqc"
	"github.com/cryptoscan/cryptoscan/internal/scan/certs"
	"github.com/cryptoscan/cryptoscan/internal/scan/config"
)

var update = flag.Bool("update", false, "update golden files")

// fixedNow is the deterministic reference time for every test (and the goldens).
var fixedNow = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

const (
	hashLeaf    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	hashExpired = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	hashRSA1024 = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	hashSHA1    = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	hashKey     = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
)

// buildSampleGraph constructs a small, fully deterministic estate exercising the
// principle-4 schema: an expired cert, an RSA-1024 (weak-key) cert, a SHA-1-signed
// cert, a self-signed cert, a standalone RSA key, a TLS endpoint, a legacy
// tls_config, and — crucially — a leaf certificate observed on BOTH disk and at
// an endpoint (entity resolution → one node carrying two provenance surfaces).
func buildSampleGraph(t *testing.T) *graph.Graph {
	t.Helper()
	g := graph.New()

	far := time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC)
	past := time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
	before := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

	// Leaf cert: seen on disk AND at the endpoint — the multi-location case.
	leaf := &graph.CertificateNode{
		Subject: "CN=leaf.example.com,O=Example", Issuer: "CN=Example Issuing CA,O=Example",
		Algorithm: "RSA", KeySize: 2048, SignatureAlgorithm: "SHA256-RSA",
		NotBefore: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: far,
		SAN: []string{"leaf.example.com"}, SPKISHA256: hashKey,
	}
	leaf.NodeID = "cert:" + hashLeaf
	leaf.AddProvenance(graph.Provenance{Source: graph.SourceFS, Location: "certs/leaf.pem", Detail: "PEM CERTIFICATE"})
	leaf.AddProvenance(graph.Provenance{Source: graph.SourceProbe, Location: "leaf.example.com:443", Detail: "tls handshake"})

	expired := &graph.CertificateNode{
		Subject: "CN=old.example.com", Issuer: "CN=old.example.com",
		Algorithm: "RSA", KeySize: 2048, SignatureAlgorithm: "SHA256-RSA",
		NotBefore: before, NotAfter: past, SelfSigned: true,
	}
	expired.NodeID = "cert:" + hashExpired
	expired.AddProvenance(graph.Provenance{Source: graph.SourceFS, Location: "certs/expired.pem"})

	weak := &graph.CertificateNode{
		Subject: "CN=weak.example.com", Issuer: "CN=weak.example.com",
		Algorithm: "RSA", KeySize: 1024, SignatureAlgorithm: "SHA256-RSA",
		NotBefore: before, NotAfter: far, SelfSigned: true,
	}
	weak.NodeID = "cert:" + hashRSA1024
	weak.AddProvenance(graph.Provenance{Source: graph.SourceFS, Location: "certs/rsa-1024.pem"})

	sha1 := &graph.CertificateNode{
		Subject: "CN=sha1.example.com", Issuer: "CN=Example Issuing CA,O=Example",
		Algorithm: "RSA", KeySize: 2048, SignatureAlgorithm: "SHA1-RSA",
		NotBefore: before, NotAfter: far,
	}
	sha1.NodeID = "cert:" + hashSHA1
	sha1.AddProvenance(graph.Provenance{Source: graph.SourceFS, Location: "certs/sha1.pem"})

	key := &graph.KeyNode{Algorithm: "RSA", KeySize: 2048, HasPrivate: true}
	key.NodeID = "key:" + hashKey
	key.AddProvenance(graph.Provenance{Source: graph.SourceFS, Location: "certs/server.key"})

	endpoint := &graph.EndpointNode{
		Host: "leaf.example.com", Port: 443,
		Attrs: map[string]any{
			"negotiated_protocol":     "TLSv1.3",
			"negotiated_cipher_suite": "TLS_AES_128_GCM_SHA256",
			"protocols_supported":     []string{"TLSv1.2", "TLSv1.3"},
			"pqc_hybrid_kex":          false,
		},
	}
	endpoint.NodeID = "endpoint:leaf.example.com:443"
	endpoint.AddProvenance(graph.Provenance{Source: graph.SourceProbe, Location: "leaf.example.com:443", Detail: "tls handshake"})

	cfg := &graph.ConfigFileNode{
		Path: "configs/nginx/legacy.conf", Format: "nginx",
		Directives: []graph.Directive{{Name: "ssl_protocols", Value: "TLSv1 TLSv1.1 TLSv1.2", Line: 12}},
		Attrs:      map[string]any{"protocols": []string{"TLSv1", "TLSv1.1", "TLSv1.2"}},
	}
	cfg.NodeID = "file:/corpus/configs/nginx/legacy.conf"
	cfg.AddProvenance(graph.Provenance{Source: graph.SourceConfig, Location: "configs/nginx/legacy.conf", Line: 12, Detail: "ssl_protocols"})

	for _, n := range []graph.Node{leaf, expired, weak, sha1, key, endpoint, cfg} {
		if _, err := g.UpsertNode(n); err != nil {
			t.Fatalf("upsert %s: %v", n.ID(), err)
		}
	}
	return g
}

func TestWriteGolden(t *testing.T) {
	g := buildSampleGraph(t)
	exposure := pqc.Score(g, fixedNow)
	opts := report.Options{Now: fixedNow, Title: "cryptoscan estate report — sample"}

	var md bytes.Buffer
	if err := report.WriteMarkdown(&md, g, exposure, opts); err != nil {
		t.Fatalf("WriteMarkdown: %v", err)
	}
	assertGolden(t, "sample.md", md.Bytes())

	var js bytes.Buffer
	if err := report.WriteJSON(&js, g, exposure, opts); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	if !json.Valid(js.Bytes()) {
		t.Fatalf("WriteJSON output is not valid JSON:\n%s", js.String())
	}
	assertGolden(t, "sample.json", js.Bytes())
}

// TestSchemaFieldOrder asserts the principle-4 field names AND their order in the
// emitted JSON (a raw-token scan, since Go maps would hide ordering).
func TestSchemaFieldOrder(t *testing.T) {
	g := buildSampleGraph(t)
	exposure := pqc.Score(g, fixedNow)
	var js bytes.Buffer
	if err := report.WriteJSON(&js, g, exposure, report.Options{Now: fixedNow}); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	// Order of first-appearance of the finding keys must be exactly the schema.
	want := []string{"type", "algorithm", "key_size", "locations", "expiry", "issuer", "pqc_exposure", "severity"}
	s := js.String()
	idx := strings.Index(s, `"findings"`)
	if idx < 0 {
		t.Fatal("no findings array in JSON")
	}
	seg := s[idx:]
	last := -1
	for _, k := range want {
		at := strings.Index(seg, `"`+k+`"`)
		if at < 0 {
			t.Fatalf("finding key %q missing from JSON", k)
		}
		if at <= last {
			t.Fatalf("finding key %q out of principle-4 order", k)
		}
		last = at
	}
}

// TestEntityResolutionMultiLocation is the headline entity-resolution assertion:
// a certificate stored on disk AND presented at an endpoint is ONE finding that
// lists BOTH locations.
func TestEntityResolutionMultiLocation(t *testing.T) {
	g := buildSampleGraph(t)
	exposure := pqc.Score(g, fixedNow)
	var js bytes.Buffer
	if err := report.WriteJSON(&js, g, exposure, report.Options{Now: fixedNow}); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	var doc struct {
		Findings []struct {
			Type      string   `json:"type"`
			Issuer    string   `json:"issuer"`
			Locations []string `json:"locations"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(js.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	var found bool
	for _, f := range doc.Findings {
		if f.Type == "certificate" && strings.Contains(f.Issuer, "Issuing CA") && !strings.Contains(f.Issuer, "self-signed") {
			// The leaf is the only non-self-signed CA-issued cert with 2 locations.
			if len(f.Locations) == 2 &&
				f.Locations[0] == "certs/leaf.pem" &&
				f.Locations[1] == "leaf.example.com:443" {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("no single certificate finding listed BOTH fs and probe locations; got %+v", doc.Findings)
	}
}

func TestDeterministic(t *testing.T) {
	g := buildSampleGraph(t)
	exposure := pqc.Score(g, fixedNow)
	opts := report.Options{Now: fixedNow}

	for _, name := range []string{"md", "json"} {
		var a, b bytes.Buffer
		write := report.WriteMarkdown
		if name == "json" {
			write = report.WriteJSON
		}
		if err := write(&a, g, exposure, opts); err != nil {
			t.Fatalf("%s write 1: %v", name, err)
		}
		if err := write(&b, g, exposure, opts); err != nil {
			t.Fatalf("%s write 2: %v", name, err)
		}
		if !bytes.Equal(a.Bytes(), b.Bytes()) {
			t.Errorf("%s output is not deterministic", name)
		}
	}
}

func TestEmptyAndNilGraph(t *testing.T) {
	for _, g := range []*graph.Graph{nil, graph.New()} {
		exposure := pqc.Score(g, fixedNow)
		opts := report.Options{Now: fixedNow}

		var js bytes.Buffer
		if err := report.WriteJSON(&js, g, exposure, opts); err != nil {
			t.Fatalf("WriteJSON: %v", err)
		}
		var doc struct {
			Findings []json.RawMessage `json:"findings"`
			Summary  struct {
				TotalFindings int `json:"total_findings"`
			} `json:"summary"`
		}
		if err := json.Unmarshal(js.Bytes(), &doc); err != nil {
			t.Fatalf("unmarshal empty: %v", err)
		}
		if len(doc.Findings) != 0 || doc.Summary.TotalFindings != 0 {
			t.Errorf("empty graph must yield zero findings, got %d", len(doc.Findings))
		}
		if !strings.Contains(js.String(), `"findings": []`) {
			t.Errorf("empty findings must render as [], not null:\n%s", js.String())
		}

		var md bytes.Buffer
		if err := report.WriteMarkdown(&md, g, exposure, opts); err != nil {
			t.Fatalf("WriteMarkdown: %v", err)
		}
		if !strings.Contains(md.String(), "No cryptographic assets found") {
			t.Errorf("empty Markdown must note absence of assets:\n%s", md.String())
		}
	}
}

// --- corpus test ---

func corpusRoot(t *testing.T) string {
	t.Helper()
	root := filepath.Join("..", "..", "..", "testdata", "corpus")
	if _, err := os.Stat(root); err != nil {
		t.Skipf("corpus not present at %s: %v", root, err)
	}
	return root
}

func scanCorpus(t *testing.T, root string) *graph.Graph {
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

type corpusFinding struct {
	Type        string   `json:"type"`
	Algorithm   string   `json:"algorithm"`
	KeySize     string   `json:"key_size"`
	Locations   []string `json:"locations"`
	Expiry      string   `json:"expiry"`
	Issuer      string   `json:"issuer"`
	PQCExposure []string `json:"pqc_exposure"`
	Severity    string   `json:"severity"`
}

func TestCorpusReport(t *testing.T) {
	root := corpusRoot(t)
	g := scanCorpus(t, root)
	exposure := pqc.Score(g, fixedNow)

	var js bytes.Buffer
	if err := report.WriteJSON(&js, g, exposure, report.Options{Now: fixedNow}); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	if !json.Valid(js.Bytes()) {
		t.Fatalf("corpus JSON invalid:\n%s", js.String())
	}
	var doc struct {
		Findings []corpusFinding `json:"findings"`
	}
	if err := json.Unmarshal(js.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// helper: find a finding whose any location contains substr.
	find := func(substr string) *corpusFinding {
		for i := range doc.Findings {
			for _, loc := range doc.Findings[i].Locations {
				if strings.Contains(loc, substr) {
					return &doc.Findings[i]
				}
			}
		}
		return nil
	}
	has := func(flags []string, want string) bool {
		for _, f := range flags {
			if f == want {
				return true
			}
		}
		return false
	}

	// rsa-1024 -> weak_key + key_size 1024 + self-signed issuer noted.
	if f := find("certs/rsa-1024-selfsigned.pem"); f == nil {
		t.Error("rsa-1024 cert finding not found")
	} else {
		if f.KeySize != "1024" {
			t.Errorf("rsa-1024 key_size = %q, want 1024", f.KeySize)
		}
		if !has(f.PQCExposure, pqc.FlagWeakKey) {
			t.Errorf("rsa-1024 missing weak_key flag, got %v", f.PQCExposure)
		}
		if !strings.Contains(f.Issuer, "self-signed") {
			t.Errorf("rsa-1024 self-signed cert must note issuer==subject, got issuer %q", f.Issuer)
		}
		if f.Severity != "critical" {
			t.Errorf("rsa-1024 severity = %q, want critical", f.Severity)
		}
	}

	// expired cert -> expiry in the past + expired flag.
	if f := find("certs/rsa-2048-expired.pem"); f == nil {
		t.Error("expired cert finding not found")
	} else {
		if !has(f.PQCExposure, pqc.FlagExpired) {
			t.Errorf("expired cert missing expired flag, got %v", f.PQCExposure)
		}
		if !strings.Contains(f.Expiry, "(expired)") {
			t.Errorf("expired cert expiry must be annotated expired, got %q", f.Expiry)
		}
		// The notAfter date must be before the reference time.
		datePart := strings.TrimSpace(strings.Split(f.Expiry, " ")[0])
		ts, err := time.Parse(time.RFC3339, datePart)
		if err != nil {
			t.Errorf("expired cert expiry not RFC3339: %q", f.Expiry)
		} else if !ts.Before(fixedNow) {
			t.Errorf("expired cert notAfter %v is not in the past", ts)
		}
	}

	// sha1 cert -> weak_signature.
	if f := find("certs/rsa-2048-sha1.pem"); f == nil {
		t.Error("sha1 cert finding not found")
	} else if !has(f.PQCExposure, pqc.FlagWeakSignature) {
		t.Errorf("sha1 cert missing weak_signature flag, got %v", f.PQCExposure)
	}

	// legacy nginx config -> legacy_protocol on a tls_config.
	if f := find("configs/nginx/legacy.conf"); f == nil {
		t.Error("legacy nginx config finding not found")
	} else {
		if f.Type != "tls_config" {
			t.Errorf("nginx legacy type = %q, want tls_config", f.Type)
		}
		if !has(f.PQCExposure, pqc.FlagLegacyProtocol) {
			t.Errorf("nginx legacy config missing legacy_protocol flag, got %v", f.PQCExposure)
		}
	}

	// Findings must be severity-ordered (critical >= high >= medium >= low >= none).
	rank := map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}
	for i := 1; i < len(doc.Findings); i++ {
		if rank[doc.Findings[i-1].Severity] < rank[doc.Findings[i].Severity] {
			t.Errorf("findings not severity-ordered at %d: %q before %q",
				i, doc.Findings[i-1].Severity, doc.Findings[i].Severity)
		}
	}
}

// TestNoWallClock asserts the library never reads the wall clock (principle 1).
func TestNoWallClock(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for i, line := range strings.Split(string(data), "\n") {
			code := strings.TrimSpace(line)
			if strings.HasPrefix(code, "//") {
				continue // skip prose/doc comments (which mention the ban)
			}
			if strings.Contains(code, "time.Now(") {
				t.Errorf("%s:%d calls time.Now(); the library must take an injected clock", f, i+1)
			}
		}
	}
}

// assertGolden compares got against testdata/golden/<name>, or rewrites it when
// -update is passed.
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
		t.Errorf("output does not match golden %s\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
	}
}
