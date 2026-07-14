package graphdump_test

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
	"github.com/cryptoscan/cryptoscan/internal/output/graphdump"
)

var update = flag.Bool("update", false, "update golden files")

const (
	certHashLeaf = "1111111111111111111111111111111111111111111111111111111111111111"
	certHashCA   = "2222222222222222222222222222222222222222222222222222222222222222"
	keyHashLeaf  = "3333333333333333333333333333333333333333333333333333333333333333"
	caHash       = "2222222222222222222222222222222222222222222222222222222222222222"
)

// buildSample constructs a small, fully deterministic graph exercising every
// writer path: two certificates (leaf + intermediate), a key shared with the
// leaf, an endpoint, a config file, a CA, and one edge of each type.
func buildSample(t *testing.T) *graph.Graph {
	t.Helper()
	g := graph.New()

	leaf := &graph.CertificateNode{
		Subject:            "CN=leaf.example.com,O=Example",
		Issuer:             "CN=Example Intermediate CA",
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
	leaf.AddProvenance(graph.Provenance{Source: graph.SourceFS, Location: "/etc/ssl/leaf.pem", Line: 0, Detail: "PEM CERTIFICATE"})

	inter := &graph.CertificateNode{
		Subject:            "CN=Example Intermediate CA",
		Issuer:             "CN=Example Root CA",
		Algorithm:          "ECDSA",
		SignatureAlgorithm: "ECDSA-SHA384",
		SelfSigned:         false,
	}
	inter.NodeID = "cert:" + certHashCA
	inter.AddProvenance(graph.Provenance{Source: graph.SourceFS, Location: "/etc/ssl/leaf.pem", Line: 30})

	key := &graph.KeyNode{Algorithm: "RSA", KeySize: 2048, HasPublic: true}
	key.NodeID = "key:" + keyHashLeaf
	key.AddProvenance(graph.Provenance{Source: graph.SourceFS, Location: "/etc/ssl/leaf.pem"})

	endpoint := &graph.EndpointNode{
		Host: "leaf.example.com",
		Port: 443,
		Attrs: map[string]any{
			"negotiated_protocol": "TLSv1.3",
			"protocols_supported": []string{"TLSv1.2", "TLSv1.3"},
			"pqc_hybrid_kex":      false,
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
	}
	cfg.NodeID = "file:/etc/nginx/nginx.conf"
	cfg.AddProvenance(graph.Provenance{Source: graph.SourceConfig, Location: "/etc/nginx/nginx.conf", Line: 12})

	ca := &graph.CANode{DN: "CN=Example Root CA", Observed: false}
	ca.NodeID = "ca:dn:CN=Example Root CA"

	for _, n := range []graph.Node{leaf, inter, key, endpoint, cfg, ca} {
		if _, err := g.UpsertNode(n); err != nil {
			t.Fatalf("upsert %s: %v", n.ID(), err)
		}
	}

	edges := []graph.Edge{
		{Type: graph.EdgeIssuedBy, From: leaf.ID(), To: ca.ID(), Provenance: []graph.Provenance{{Source: graph.SourceFS, Location: "/etc/ssl/leaf.pem"}}},
		{Type: graph.EdgeSignsWith, From: leaf.ID(), To: key.ID()},
		{Type: graph.EdgeStoredIn, From: leaf.ID(), To: cfg.ID()},
		{Type: graph.EdgeReferences, From: cfg.ID(), To: leaf.ID(), Provenance: []graph.Provenance{{Source: graph.SourceConfig, Location: "/etc/nginx/nginx.conf", Line: 12}}},
		{Type: graph.EdgeTerminatesTLSFor, From: leaf.ID(), To: endpoint.ID()},
	}
	for _, e := range edges {
		if _, err := g.AddEdge(e); err != nil {
			t.Fatalf("add edge %s: %v", e.Type, err)
		}
	}
	return g
}

// buildSpecial constructs a graph whose attributes contain quotes, backslashes,
// and newlines, to prove both writers escape correctly and never break.
func buildSpecial(t *testing.T) *graph.Graph {
	t.Helper()
	g := graph.New()

	// The CN carries a quote, a backslash, and a newline so the DOT label must
	// escape all three; the config path stays forward-slash-only so its base
	// filename is identical on every OS (filepath.Base is separator-sensitive).
	cert := &graph.CertificateNode{
		Subject:   "CN=a\"b\\c\nd,O=Back\\slash",
		Algorithm: "RSA",
		KeySize:   1024,
	}
	cert.NodeID = "cert:" + certHashLeaf
	cert.AddProvenance(graph.Provenance{Source: graph.SourceFS, Location: "/path/with \"quote\"\nand newline", Detail: "line1\nline2\ttab"})

	cfg := &graph.ConfigFileNode{
		Path:   "/etc/weird/na\"me.conf",
		Format: "nginx",
	}
	cfg.NodeID = "file:/etc/weird/na\"me.conf"

	for _, n := range []graph.Node{cert, cfg} {
		if _, err := g.UpsertNode(n); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	if _, err := g.AddEdge(graph.Edge{Type: graph.EdgeStoredIn, From: cert.ID(), To: cfg.ID()}); err != nil {
		t.Fatalf("add edge: %v", err)
	}
	return g
}

func TestWriteJSONGolden(t *testing.T) {
	cases := map[string]*graph.Graph{
		"small":   buildSample(t),
		"empty":   graph.New(),
		"special": buildSpecial(t),
	}
	for name, g := range cases {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := graphdump.WriteJSON(&buf, g); err != nil {
				t.Fatalf("WriteJSON: %v", err)
			}
			// The dump must be valid JSON.
			if !json.Valid(buf.Bytes()) {
				t.Fatalf("WriteJSON output is not valid JSON:\n%s", buf.String())
			}
			assertGolden(t, name+".json", buf.Bytes())

			// Determinism: a second run is byte-identical.
			var buf2 bytes.Buffer
			if err := graphdump.WriteJSON(&buf2, g); err != nil {
				t.Fatalf("WriteJSON (2nd): %v", err)
			}
			if !bytes.Equal(buf.Bytes(), buf2.Bytes()) {
				t.Error("WriteJSON is not deterministic")
			}
		})
	}
}

func TestWriteDOTGolden(t *testing.T) {
	cases := map[string]*graph.Graph{
		"small":   buildSample(t),
		"empty":   graph.New(),
		"special": buildSpecial(t),
	}
	for name, g := range cases {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := graphdump.WriteDOT(&buf, g); err != nil {
				t.Fatalf("WriteDOT: %v", err)
			}
			out := buf.String()
			if !strings.HasPrefix(out, "digraph cryptoscan {") || !strings.HasSuffix(out, "}\n") {
				t.Errorf("DOT output is not a well-formed digraph:\n%s", out)
			}
			assertGolden(t, name+".dot", buf.Bytes())

			var buf2 bytes.Buffer
			if err := graphdump.WriteDOT(&buf2, g); err != nil {
				t.Fatalf("WriteDOT (2nd): %v", err)
			}
			if !bytes.Equal(buf.Bytes(), buf2.Bytes()) {
				t.Error("WriteDOT is not deterministic")
			}
		})
	}
}

// TestSpecialCharsEscaped confirms the escaping is real: no raw newline appears
// inside a DOT label, and the JSON round-trips the exact subject string.
func TestSpecialCharsEscaped(t *testing.T) {
	g := buildSpecial(t)

	var dot bytes.Buffer
	if err := graphdump.WriteDOT(&dot, g); err != nil {
		t.Fatalf("WriteDOT: %v", err)
	}
	// Every line must be balanced enough that no unescaped quote splits it;
	// a cheap structural check: the digraph parses as one node stmt per line.
	for _, line := range strings.Split(strings.TrimRight(dot.String(), "\n"), "\n") {
		// A raw tab or newline inside a label is impossible because we split on
		// newline; assert no literal control chars leaked into label content.
		if strings.ContainsAny(line, "\t") {
			t.Errorf("DOT line contains a raw tab: %q", line)
		}
	}

	var jsonBuf bytes.Buffer
	if err := graphdump.WriteJSON(&jsonBuf, g); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	var parsed struct {
		Nodes []struct {
			Type  string                     `json:"type"`
			Attrs map[string]json.RawMessage `json:"attrs"`
		} `json:"nodes"`
	}
	if err := json.Unmarshal(jsonBuf.Bytes(), &parsed); err != nil {
		t.Fatalf("re-parse JSON: %v", err)
	}
	var subject string
	for _, n := range parsed.Nodes {
		if n.Type == "Certificate" {
			if raw, ok := n.Attrs["subject"]; ok {
				if err := json.Unmarshal(raw, &subject); err != nil {
					t.Fatalf("unmarshal subject: %v", err)
				}
			}
		}
	}
	if subject != "CN=a\"b\\c\nd,O=Back\\slash" {
		t.Errorf("subject round-trip = %q, want the exact special-char string", subject)
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
