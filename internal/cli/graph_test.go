package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestGraphDumpOverCorpus scans the real corpus into the shared graph, dumps it
// as JSON and DOT, and asserts the dumps are consistent with the scanned graph
// (node/edge counts) rather than brittle-goldening the whole corpus.
func TestGraphDumpOverCorpus(t *testing.T) {
	root := corpusRoot(t)
	g, _, _, err := scanFilesystem(root)
	if err != nil {
		t.Fatalf("scanFilesystem: %v", err)
	}
	wantNodes := g.NodeCount()
	wantEdges := g.EdgeCount()
	if wantNodes == 0 || wantEdges == 0 {
		t.Fatalf("corpus produced an empty graph (%d nodes, %d edges)", wantNodes, wantEdges)
	}

	// JSON via the command in json mode.
	var jsonBuf bytes.Buffer
	if err := runGraph(&jsonBuf, root, "json", ""); err != nil {
		t.Fatalf("runGraph json: %v", err)
	}
	var parsed struct {
		Nodes []json.RawMessage `json:"nodes"`
		Edges []json.RawMessage `json:"edges"`
	}
	if err := json.Unmarshal(jsonBuf.Bytes(), &parsed); err != nil {
		t.Fatalf("graph JSON does not parse: %v", err)
	}
	if len(parsed.Nodes) != wantNodes {
		t.Errorf("JSON node count = %d, want %d (from fs scan)", len(parsed.Nodes), wantNodes)
	}
	if len(parsed.Edges) != wantEdges {
		t.Errorf("JSON edge count = %d, want %d (from fs scan)", len(parsed.Edges), wantEdges)
	}

	// DOT via the command in dot mode: non-empty and one node stmt per graph node.
	var dotBuf bytes.Buffer
	if err := runGraph(&dotBuf, root, "dot", ""); err != nil {
		t.Fatalf("runGraph dot: %v", err)
	}
	dot := dotBuf.String()
	if !strings.HasPrefix(dot, "digraph cryptoscan {") {
		t.Fatal("DOT output is not a digraph")
	}
	nodeStmts := strings.Count(dot, ", shape=")
	if nodeStmts != wantNodes {
		t.Errorf("DOT node statements = %d, want %d", nodeStmts, wantNodes)
	}
	edgeStmts := strings.Count(dot, "\" -> \"")
	if edgeStmts != wantEdges {
		t.Errorf("DOT edge statements = %d, want %d", edgeStmts, wantEdges)
	}
}

// TestGraphCommandJSON runs `graph <corpus> --format json` through cobra and
// asserts exit 0, valid JSON, and determinism across two runs.
func TestGraphCommandJSON(t *testing.T) {
	root := corpusRoot(t)

	run := func() string {
		var out bytes.Buffer
		cmd := newRootCmd()
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		cmd.SetArgs([]string{"graph", "--format", "json", root})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("graph json errored: %v", err)
		}
		return out.String()
	}

	first := run()
	if !json.Valid([]byte(first)) {
		t.Fatalf("graph json output invalid:\n%s", first)
	}
	if second := run(); first != second {
		t.Error("graph json output is not deterministic across runs")
	}
}

// TestGraphCommandDOT runs `graph <corpus> --format dot` and asserts a
// well-formed, deterministic digraph.
func TestGraphCommandDOT(t *testing.T) {
	root := corpusRoot(t)

	run := func() string {
		var out bytes.Buffer
		cmd := newRootCmd()
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		cmd.SetArgs([]string{"graph", "--format", "dot", root})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("graph dot errored: %v", err)
		}
		return out.String()
	}

	first := run()
	if !strings.HasPrefix(first, "digraph cryptoscan {") || !strings.HasSuffix(first, "}\n") {
		t.Fatalf("graph dot output not a well-formed digraph:\n%s", first)
	}
	if second := run(); first != second {
		t.Error("graph dot output is not deterministic across runs")
	}
}

// TestGraphCommandDefaultsToJSON confirms the default --format is json.
func TestGraphCommandDefaultsToJSON(t *testing.T) {
	root := corpusRoot(t)
	var out bytes.Buffer
	cmd := newRootCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"graph", root})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("graph (default) errored: %v", err)
	}
	if !json.Valid(out.Bytes()) {
		t.Errorf("default output is not JSON:\n%s", out.String())
	}
}

// TestGraphCommandOutputFile confirms --output writes the dump to a file and
// stdout stays empty.
func TestGraphCommandOutputFile(t *testing.T) {
	root := corpusRoot(t)
	outPath := filepath.Join(t.TempDir(), "graph.json")

	var stdout bytes.Buffer
	cmd := newRootCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	cmd.SetArgs([]string{"graph", "--output", outPath, root})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("graph --output errored: %v", err)
	}
	if strings.TrimSpace(stdout.String()) != "" {
		t.Errorf("stdout should be empty when --output is set, got:\n%s", stdout.String())
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output file: %v", err)
	}
	if !json.Valid(data) {
		t.Errorf("output file is not valid JSON:\n%s", data)
	}
}

// TestGraphCommandBadFormat asserts an unknown --format is a usage error (exit 1
// via Execute), never a panic.
func TestGraphCommandBadFormat(t *testing.T) {
	root := corpusRoot(t)
	var out bytes.Buffer
	cmd := newRootCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"graph", "--format", "yaml", root})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error for unknown format, got nil")
	}
}

// TestGraphCommandBadPath asserts a non-existent path fails (exit 1), no panic.
func TestGraphCommandBadPath(t *testing.T) {
	var out bytes.Buffer
	cmd := newRootCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"graph", filepath.Join(t.TempDir(), "does-not-exist")})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error for non-existent path, got nil")
	}
}
