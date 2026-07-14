package graph

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestConfigEndpointID is a table-driven check of the ID constructor: it prefixes
// `cfgendpoint:`, cleans + absolutizes the path, appends `#<index>`, and rejects
// an empty path or a negative index.
func TestConfigEndpointID(t *testing.T) {
	cleanAbs := func(p string) string {
		abs, _ := filepath.Abs(p)
		return filepath.Clean(abs)
	}

	tests := []struct {
		name    string
		path    string
		index   int
		want    string
		wantErr bool
	}{
		{
			name:  "basic block 0",
			path:  "/etc/nginx/nginx.conf",
			index: 0,
			want:  "cfgendpoint:" + cleanAbs("/etc/nginx/nginx.conf") + "#0",
		},
		{
			name:  "higher index",
			path:  "/etc/nginx/nginx.conf",
			index: 2,
			want:  "cfgendpoint:" + cleanAbs("/etc/nginx/nginx.conf") + "#2",
		},
		{
			name:  "cleans dot segments",
			path:  filepath.Join("a", "b", "..", "c", "site.conf"),
			index: 1,
			want:  "cfgendpoint:" + cleanAbs(filepath.Join("a", "c", "site.conf")) + "#1",
		},
		{name: "empty path", path: "", index: 0, wantErr: true},
		{name: "blank path", path: "   ", index: 0, wantErr: true},
		{name: "negative index", path: "/etc/nginx/nginx.conf", index: -1, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ConfigEndpointID(tc.path, tc.index)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ConfigEndpointID(%q,%d) = %q, want error", tc.path, tc.index, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ConfigEndpointID(%q,%d): %v", tc.path, tc.index, err)
			}
			if got != tc.want {
				t.Errorf("ConfigEndpointID(%q,%d) = %q, want %q", tc.path, tc.index, got, tc.want)
			}
			if !strings.HasPrefix(got, "cfgendpoint:") {
				t.Errorf("id %q missing cfgendpoint: prefix", got)
			}
		})
	}
}

// TestUpsertConfigEndpointMerge covers the ConfigEndpointNode Attrs merge (key
// union, existing-wins), matching the ConfigFileNode/EndpointNode rule.
func TestUpsertConfigEndpointMerge(t *testing.T) {
	id, err := ConfigEndpointID("/etc/nginx/nginx.conf", 1)
	if err != nil {
		t.Fatalf("ConfigEndpointID: %v", err)
	}
	g := New()

	first := &ConfigEndpointNode{
		baseNode:   baseNode{NodeID: id},
		Path:       "configs/nginx/nginx.conf",
		BlockIndex: 1,
		Attrs: map[string]any{
			"server_name": []string{"b.example.com"},
			"protocols":   []string{"TLSv1", "TLSv1.1", "TLSv1.2"},
			"port":        8443,
		},
	}
	first.AddProvenance(Provenance{Source: SourceConfig, Location: "configs/nginx/nginx.conf", Line: 30})
	if _, err := g.UpsertNode(first); err != nil {
		t.Fatalf("first upsert: %v", err)
	}

	second := &ConfigEndpointNode{
		baseNode:   baseNode{NodeID: id},
		Path:       "configs/nginx/nginx.conf",
		BlockIndex: 1,
		Attrs: map[string]any{
			"protocols": []string{"IGNORED"},              // existing wins
			"ciphers":   []string{"ECDHE-RSA-AES128-SHA"}, // new key filled
		},
	}
	second.AddProvenance(Provenance{Source: SourceConfig, Location: "configs/nginx/nginx.conf", Line: 40})

	resident, err := g.UpsertNode(second)
	if err != nil {
		t.Fatalf("second upsert: %v", err)
	}
	if g.NodeCount() != 1 {
		t.Fatalf("node count = %d, want 1 after merge", g.NodeCount())
	}
	ce, ok := resident.(*ConfigEndpointNode)
	if !ok {
		t.Fatalf("resident is %T, want *ConfigEndpointNode", resident)
	}
	if ce.BlockIndex != 1 {
		t.Errorf("block index = %d, want 1", ce.BlockIndex)
	}
	if got, _ := ce.Attrs["protocols"].([]string); len(got) != 3 || got[0] != "TLSv1" {
		t.Errorf("protocols = %v, want existing 3-element list to win", ce.Attrs["protocols"])
	}
	if got, _ := ce.Attrs["ciphers"].([]string); len(got) != 1 {
		t.Errorf("ciphers = %v, want it filled from the second upsert", ce.Attrs["ciphers"])
	}
	if len(ce.Provenance()) != 2 {
		t.Errorf("provenance = %v, want 2 unioned records", ce.Provenance())
	}
}

// TestConfigEndpointEdges confirms a ConfigEndpoint is accepted as a `references`
// source (→ Cert/Key) and a `stored_in` source (→ ConfigFile).
func TestConfigEndpointEdges(t *testing.T) {
	epID, err := ConfigEndpointID("/etc/nginx/nginx.conf", 0)
	if err != nil {
		t.Fatalf("ConfigEndpointID: %v", err)
	}
	fileID, err := FileNodeID("/etc/nginx/nginx.conf")
	if err != nil {
		t.Fatalf("FileNodeID: %v", err)
	}
	certID := mustCertID(t, hashA)
	keyID, err := KeyNodeID(hashB)
	if err != nil {
		t.Fatalf("KeyNodeID: %v", err)
	}

	g := New()
	edges := []Edge{
		{Type: EdgeStoredIn, From: epID, To: fileID},
		{Type: EdgeReferences, From: epID, To: certID},
		{Type: EdgeReferences, From: epID, To: keyID},
	}
	for _, e := range edges {
		if _, err := g.AddEdge(e); err != nil {
			t.Errorf("AddEdge %s %s->%s: %v", e.Type, e.From, e.To, err)
		}
	}
	if g.EdgeCount() != 3 {
		t.Errorf("edge count = %d, want 3", g.EdgeCount())
	}
}
