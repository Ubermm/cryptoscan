package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// This file drives the single-scan multi-output --emit capability on `fs`: one
// scan of the corpus feeds several projections written to files and/or stdout,
// plus the usage-error rules (duplicate stdout, duplicate format, mutual
// exclusion with --format/--output, unknown format) and the emit-then-gate
// composition with --fail-on.

// TestFsEmitCBOMAndReportToFiles asserts a single `fs --emit cbom=… --emit
// report=…` writes BOTH files from one invocation: the cbom is valid CycloneDX
// JSON and the report is the Markdown auditor report; exit 0 and stdout is empty
// (both targets are files). Correctness of both outputs from one call is the
// single-scan assertion (one runFs builds one graph and feeds both emitters).
func TestFsEmitCBOMAndReportToFiles(t *testing.T) {
	root := corpusRoot(t)
	dir := t.TempDir()
	cbomPath := filepath.Join(dir, "c.json")
	reportPath := filepath.Join(dir, "r.md")

	out, code := runCmd(t, "fs", root,
		"--emit", "cbom="+cbomPath,
		"--emit", "report="+reportPath)
	if code != 0 {
		t.Fatalf("fs --emit cbom= report= exit = %d, want 0\noutput:\n%s", code, out)
	}
	if strings.TrimSpace(out) != "" {
		t.Errorf("stdout should be empty when every emit targets a file, got:\n%s", out)
	}

	cbomData, err := os.ReadFile(cbomPath)
	if err != nil {
		t.Fatalf("read cbom file: %v", err)
	}
	var doc struct {
		BOMFormat   string            `json:"bomFormat"`
		SpecVersion string            `json:"specVersion"`
		Components  []json.RawMessage `json:"components"`
	}
	if err := json.Unmarshal(cbomData, &doc); err != nil {
		t.Fatalf("cbom file is not valid JSON: %v\n%s", err, cbomData)
	}
	if doc.BOMFormat != "CycloneDX" || doc.SpecVersion != "1.6" {
		t.Errorf("cbom bomFormat/specVersion = %q/%q, want CycloneDX/1.6", doc.BOMFormat, doc.SpecVersion)
	}
	if len(doc.Components) < 5 {
		t.Errorf("cbom components = %d, want a non-trivial set (>=5)", len(doc.Components))
	}

	reportData, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("read report file: %v", err)
	}
	rs := string(reportData)
	for _, want := range []string{
		"# cryptoscan cryptographic estate report",
		"## Findings",
		"| Severity | Type | Algorithm | Key size | Location(s) | Expiry | Issuer / CA | PQC exposure |",
	} {
		if !strings.Contains(rs, want) {
			t.Errorf("report file missing %q\n%s", want, rs)
		}
	}
}

// TestFsEmitReportJSONToStdout asserts `--emit report-json=-` writes the report
// JSON to stdout (parses, carries the schema), exit 0.
func TestFsEmitReportJSONToStdout(t *testing.T) {
	root := corpusRoot(t)
	out, code := runCmd(t, "fs", root, "--emit", "report-json=-")
	if code != 0 {
		t.Fatalf("fs --emit report-json=- exit = %d, want 0\noutput:\n%s", code, out)
	}
	var doc struct {
		GeneratedAt string `json:"generated_at"`
		Findings    []any  `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("stdout report-json does not parse: %v\n%s", err, out)
	}
	if doc.GeneratedAt == "" || len(doc.Findings) == 0 {
		t.Errorf("stdout report-json missing generated_at/findings:\n%s", out)
	}
}

// TestFsEmitTableAndFile mixes one stdout target (table) with one file target
// (cbom): the table lands on stdout, the cbom in the file, exit 0.
func TestFsEmitTableAndFile(t *testing.T) {
	root := corpusRoot(t)
	cbomPath := filepath.Join(t.TempDir(), "c.json")

	out, code := runCmd(t, "fs", root, "--emit", "table=-", "--emit", "cbom="+cbomPath)
	if code != 0 {
		t.Fatalf("fs --emit table=- cbom= exit = %d, want 0\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "Findings by class:") || !strings.Contains(out, "Graph nodes:") {
		t.Errorf("stdout missing the table summary:\n%s", out)
	}
	data, err := os.ReadFile(cbomPath)
	if err != nil {
		t.Fatalf("read cbom file: %v", err)
	}
	if !json.Valid(data) || !strings.Contains(string(data), "CycloneDX") {
		t.Errorf("cbom file not a valid CycloneDX BOM:\n%s", data)
	}
}

// TestFsEmitTwoStdoutTargets: two emits targeting stdout (-) is a usage error
// (exit 1) — two writers would interleave.
func TestFsEmitTwoStdoutTargets(t *testing.T) {
	root := corpusRoot(t)
	out, code := runCmd(t, "fs", root, "--emit", "table=-", "--emit", "report=-")
	if code != 1 {
		t.Errorf("two stdout emits exit = %d, want 1\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "stdout") {
		t.Errorf("expected a stdout-conflict message, got:\n%s", out)
	}
}

// TestFsEmitDuplicateFormat: the same format emitted twice is a usage error.
func TestFsEmitDuplicateFormat(t *testing.T) {
	root := corpusRoot(t)
	a := filepath.Join(t.TempDir(), "a.json")
	b := filepath.Join(t.TempDir(), "b.json")
	out, code := runCmd(t, "fs", root, "--emit", "cbom="+a, "--emit", "cbom="+b)
	if code != 1 {
		t.Errorf("duplicate-format emit exit = %d, want 1\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "already requested") {
		t.Errorf("expected a duplicate-format message, got:\n%s", out)
	}
}

// TestFsEmitWithFormatMutualExclusion: --emit combined with --format is a usage
// error.
func TestFsEmitWithFormatMutualExclusion(t *testing.T) {
	root := corpusRoot(t)
	out, code := runCmd(t, "fs", root, "--emit", "cbom=-", "--format", "cbom")
	if code != 1 {
		t.Errorf("--emit with --format exit = %d, want 1\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "cannot be combined") {
		t.Errorf("expected a mutual-exclusion message, got:\n%s", out)
	}
}

// TestFsEmitWithOutputMutualExclusion: --emit combined with --output is a usage
// error too.
func TestFsEmitWithOutputMutualExclusion(t *testing.T) {
	root := corpusRoot(t)
	out, code := runCmd(t, "fs", root, "--emit", "cbom=-", "--output", filepath.Join(t.TempDir(), "x"))
	if code != 1 {
		t.Errorf("--emit with --output exit = %d, want 1\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "cannot be combined") {
		t.Errorf("expected a mutual-exclusion message, got:\n%s", out)
	}
}

// TestFsEmitUnknownFormat: an unknown emit format is a usage error listing the
// valid formats.
func TestFsEmitUnknownFormat(t *testing.T) {
	root := corpusRoot(t)
	out, code := runCmd(t, "fs", root, "--emit", "yaml=x")
	if code != 1 {
		t.Errorf("--emit yaml=x exit = %d, want 1\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "unknown format") || !strings.Contains(out, "report-json") {
		t.Errorf("expected an unknown-format message listing valid formats, got:\n%s", out)
	}
}

// TestFsEmitMissingEquals: a spec without '=' is a usage error.
func TestFsEmitMissingEquals(t *testing.T) {
	root := corpusRoot(t)
	out, code := runCmd(t, "fs", root, "--emit", "cbom")
	if code != 1 {
		t.Errorf("--emit cbom (no =) exit = %d, want 1\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "want format=dest") {
		t.Errorf("expected a format=dest message, got:\n%s", out)
	}
}

// TestFsEmitQuietOnlyTableAllowed: --quiet is accepted when the sole emit is
// table (it shapes that summary), but rejected alongside a machine emit.
func TestFsEmitQuietOnlyTableAllowed(t *testing.T) {
	root := corpusRoot(t)

	// Allowed: sole emit is table.
	out, code := runCmd(t, "fs", root, "--emit", "table=-", "--quiet")
	if code != 0 {
		t.Fatalf("--emit table=- --quiet exit = %d, want 0\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "Findings by class:") {
		t.Errorf("quiet table emit missing class counts:\n%s", out)
	}
	if strings.Contains(out, "Findings:") || strings.Contains(out, "DETAIL") {
		t.Errorf("quiet table emit should omit the findings table:\n%s", out)
	}

	// Rejected: a machine emit alongside --quiet.
	out, code = runCmd(t, "fs", root, "--emit", "cbom=-", "--quiet")
	if code != 1 {
		t.Errorf("--emit cbom=- --quiet exit = %d, want 1\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "--quiet with --emit") {
		t.Errorf("expected a quiet+emit message, got:\n%s", out)
	}
}

// TestFsEmitThenGate: --emit cbom=<file> with a --fail-on token the corpus trips
// writes the file in full AND exits 4 AND prints the breach summary to stderr —
// the gate never suppresses an emit.
func TestFsEmitThenGate(t *testing.T) {
	root := corpusRoot(t)
	cbomPath := filepath.Join(t.TempDir(), "c.json")

	code, stdout, stderr := runFailOn(t, "fs", root, "--emit", "cbom="+cbomPath, "--fail-on", "sha1")
	if code != 4 {
		t.Fatalf("emit + --fail-on sha1 exit = %d, want 4\nstderr: %s", code, stderr)
	}
	data, err := os.ReadFile(cbomPath)
	if err != nil {
		t.Fatalf("cbom emit file not written despite breach: %v", err)
	}
	if !json.Valid(data) || !strings.Contains(string(data), "CycloneDX") {
		t.Errorf("cbom emit file not a valid CycloneDX BOM:\n%s", data)
	}
	if strings.TrimSpace(stdout) != "" {
		t.Errorf("stdout should be empty (cbom went to a file), got:\n%s", stdout)
	}
	if !strings.Contains(stderr, "policy:") || !strings.Contains(stderr, "sha1") {
		t.Errorf("stderr missing the sha1 breach summary:\n%s", stderr)
	}
}
