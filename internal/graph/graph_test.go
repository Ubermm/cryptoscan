package graph

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	hashA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	hashB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func mustCertID(t *testing.T, der string) string {
	t.Helper()
	id, err := CertNodeID(der)
	if err != nil {
		t.Fatalf("CertNodeID(%q): %v", der, err)
	}
	return id
}

// --- ID helper tests ---

func TestIDHelpers(t *testing.T) {
	tests := []struct {
		name    string
		got     func() (string, error)
		want    string
		wantErr bool
	}{
		{
			name: "cert lowercases and prefixes",
			got:  func() (string, error) { return CertNodeID(strings.ToUpper(hashA)) },
			want: "cert:" + hashA,
		},
		{
			name: "cert trims whitespace",
			got:  func() (string, error) { return CertNodeID("  " + hashA + "\n") },
			want: "cert:" + hashA,
		},
		{
			name: "key prefixes",
			got:  func() (string, error) { return KeyNodeID(hashB) },
			want: "key:" + hashB,
		},
		{
			name: "ca by der",
			got:  func() (string, error) { return CANodeID(hashA) },
			want: "ca:" + hashA,
		},
		{
			name: "ca by dn",
			got:  func() (string, error) { return CADNNodeID("CN=Example Root CA") },
			want: "ca:dn:CN=Example Root CA",
		},
		{
			name: "endpoint host:port",
			got:  func() (string, error) { return EndpointNodeID("example.com", 443) },
			want: "endpoint:example.com:443",
		},
		{
			name: "endpoint ipv6 bracketed",
			got:  func() (string, error) { return EndpointNodeID("::1", 8443) },
			want: "endpoint:[::1]:8443",
		},
		{
			name:    "cert rejects short hash",
			got:     func() (string, error) { return CertNodeID("deadbeef") },
			wantErr: true,
		},
		{
			name:    "cert rejects non-hex",
			got:     func() (string, error) { return CertNodeID(strings.Repeat("z", 64)) },
			wantErr: true,
		},
		{
			name:    "cert rejects empty",
			got:     func() (string, error) { return CertNodeID("") },
			wantErr: true,
		},
		{
			name:    "endpoint rejects empty host",
			got:     func() (string, error) { return EndpointNodeID("", 443) },
			wantErr: true,
		},
		{
			name:    "endpoint rejects port 0",
			got:     func() (string, error) { return EndpointNodeID("h", 0) },
			wantErr: true,
		},
		{
			name:    "endpoint rejects port too big",
			got:     func() (string, error) { return EndpointNodeID("h", 70000) },
			wantErr: true,
		},
		{
			name:    "ca dn rejects empty",
			got:     func() (string, error) { return CADNNodeID("   ") },
			wantErr: true,
		},
		{
			name:    "file rejects empty",
			got:     func() (string, error) { return FileNodeID("") },
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.got()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestFileNodeIDCleansAndAbsolutizes(t *testing.T) {
	// Relative, uncleaned path must become an absolute, cleaned "file:" ID.
	id, err := FileNodeID(filepath.Join("a", "b", "..", "c", "cert.pem"))
	if err != nil {
		t.Fatalf("FileNodeID: %v", err)
	}
	p := strings.TrimPrefix(id, "file:")
	if p == id {
		t.Fatalf("missing file: prefix in %q", id)
	}
	if !filepath.IsAbs(p) {
		t.Errorf("path %q is not absolute", p)
	}
	if strings.Contains(p, ".."+string(filepath.Separator)) {
		t.Errorf("path %q was not cleaned", p)
	}
	if !strings.HasSuffix(p, filepath.Join("a", "c", "cert.pem")) {
		t.Errorf("path %q does not end with cleaned suffix", p)
	}
}

// --- upsert / merge tests ---

func TestUpsertNodeMerge(t *testing.T) {
	id := mustCertID(t, hashA)

	t.Run("fills empty attributes and unions provenance", func(t *testing.T) {
		g := New()

		first := &CertificateNode{
			baseNode:  baseNode{NodeID: id},
			Subject:   "CN=example.com",
			Algorithm: "RSA",
			SAN:       []string{"example.com"},
			NotAfter:  time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC),
		}
		first.AddProvenance(Provenance{Source: SourceFS, Location: "/a/cert.pem", Line: 0})

		if _, err := g.UpsertNode(first); err != nil {
			t.Fatalf("first upsert: %v", err)
		}

		second := &CertificateNode{
			baseNode:   baseNode{NodeID: id},
			Issuer:     "CN=Root CA", // fills empty
			Subject:    "CN=IGNORED", // existing wins
			KeySize:    2048,         // fills empty
			SAN:        []string{"www.example.com", "example.com"},
			SelfSigned: true,
		}
		second.AddProvenance(Provenance{Source: SourceProbe, Location: "example.com:443"})

		resident, err := g.UpsertNode(second)
		if err != nil {
			t.Fatalf("second upsert: %v", err)
		}

		if g.NodeCount() != 1 {
			t.Fatalf("expected 1 node after merge, got %d", g.NodeCount())
		}
		c, ok := resident.(*CertificateNode)
		if !ok {
			t.Fatalf("resident is %T, want *CertificateNode", resident)
		}
		if c.Subject != "CN=example.com" {
			t.Errorf("Subject = %q, want existing value to win", c.Subject)
		}
		if c.Issuer != "CN=Root CA" {
			t.Errorf("Issuer = %q, want filled from second", c.Issuer)
		}
		if c.KeySize != 2048 {
			t.Errorf("KeySize = %d, want 2048", c.KeySize)
		}
		if !c.SelfSigned {
			t.Errorf("SelfSigned = false, want true (OR merge)")
		}
		if len(c.SAN) != 2 {
			t.Errorf("SAN = %v, want set union of size 2", c.SAN)
		}
		if len(c.Provenance()) != 2 {
			t.Errorf("provenance = %v, want 2 unioned records", c.Provenance())
		}
	})

	t.Run("duplicate provenance is deduped", func(t *testing.T) {
		g := New()
		p := Provenance{Source: SourceFS, Location: "/a/cert.pem", Line: 12}

		n1 := &CertificateNode{baseNode: baseNode{NodeID: id}}
		n1.AddProvenance(p)
		if _, err := g.UpsertNode(n1); err != nil {
			t.Fatalf("upsert n1: %v", err)
		}
		n2 := &CertificateNode{baseNode: baseNode{NodeID: id}}
		n2.AddProvenance(p) // identical
		resident, err := g.UpsertNode(n2)
		if err != nil {
			t.Fatalf("upsert n2: %v", err)
		}
		if got := len(resident.Provenance()); got != 1 {
			t.Errorf("provenance count = %d, want 1 after dedupe", got)
		}
	})

	t.Run("type conflict on same ID errors", func(t *testing.T) {
		g := New()
		if _, err := g.UpsertNode(&CertificateNode{baseNode: baseNode{NodeID: id}}); err != nil {
			t.Fatalf("seed: %v", err)
		}
		_, err := g.UpsertNode(&KeyNode{baseNode: baseNode{NodeID: id}})
		if err == nil {
			t.Fatal("expected type-conflict error, got nil")
		}
	})

	t.Run("nil and empty-ID nodes error", func(t *testing.T) {
		g := New()
		if _, err := g.UpsertNode(nil); err == nil {
			t.Error("expected error for nil node")
		}
		if _, err := g.UpsertNode(&CertificateNode{}); err == nil {
			t.Error("expected error for empty-ID node")
		}
	})
}

// --- edge dedupe tests ---

func TestAddEdge(t *testing.T) {
	certID := mustCertID(t, hashA)
	caID, err := CANodeID(hashB)
	if err != nil {
		t.Fatalf("CANodeID: %v", err)
	}

	t.Run("identical edges dedupe and union provenance", func(t *testing.T) {
		g := New()
		e := Edge{Type: EdgeIssuedBy, From: certID, To: caID}
		e.Provenance = []Provenance{{Source: SourceFS, Location: "/a/cert.pem"}}

		if _, err := g.AddEdge(e); err != nil {
			t.Fatalf("first AddEdge: %v", err)
		}

		e2 := Edge{Type: EdgeIssuedBy, From: certID, To: caID}
		e2.Provenance = []Provenance{
			{Source: SourceFS, Location: "/a/cert.pem"}, // dup
			{Source: SourceProbe, Location: "example.com:443"},
		}
		resident, err := g.AddEdge(e2)
		if err != nil {
			t.Fatalf("second AddEdge: %v", err)
		}
		if g.EdgeCount() != 1 {
			t.Fatalf("edge count = %d, want 1", g.EdgeCount())
		}
		if got := len(resident.Provenance); got != 2 {
			t.Errorf("provenance = %d, want 2 after union", got)
		}
	})

	t.Run("different type is a distinct edge", func(t *testing.T) {
		g := New()
		if _, err := g.AddEdge(Edge{Type: EdgeIssuedBy, From: certID, To: caID}); err != nil {
			t.Fatalf("AddEdge issued_by: %v", err)
		}
		if _, err := g.AddEdge(Edge{Type: EdgeSignsWith, From: certID, To: caID}); err != nil {
			t.Fatalf("AddEdge signs_with: %v", err)
		}
		if g.EdgeCount() != 2 {
			t.Errorf("edge count = %d, want 2 distinct edges", g.EdgeCount())
		}
	})

	t.Run("invalid edges error", func(t *testing.T) {
		g := New()
		if _, err := g.AddEdge(Edge{Type: "bogus", From: certID, To: caID}); err == nil {
			t.Error("expected error for unknown edge type")
		}
		if _, err := g.AddEdge(Edge{Type: EdgeIssuedBy, From: "", To: caID}); err == nil {
			t.Error("expected error for empty From")
		}
		if _, err := g.AddEdge(Edge{Type: EdgeIssuedBy, From: certID, To: ""}); err == nil {
			t.Error("expected error for empty To")
		}
	})
}

// --- deterministic ordering ---

func TestDeterministicOrder(t *testing.T) {
	g := New()
	ids := []string{"cert:" + hashB, "cert:" + hashA, "key:" + hashA}
	for _, id := range ids {
		var n Node
		if strings.HasPrefix(id, "cert:") {
			n = &CertificateNode{baseNode: baseNode{NodeID: id}}
		} else {
			n = &KeyNode{baseNode: baseNode{NodeID: id}}
		}
		if _, err := g.UpsertNode(n); err != nil {
			t.Fatalf("upsert %q: %v", id, err)
		}
	}
	nodes := g.Nodes()
	for i := 1; i < len(nodes); i++ {
		if nodes[i-1].ID() > nodes[i].ID() {
			t.Errorf("nodes not sorted: %q before %q", nodes[i-1].ID(), nodes[i].ID())
		}
	}
}
