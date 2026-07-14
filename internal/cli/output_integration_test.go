package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// This file drives the Phase 3 output wiring on `fs` and `probe`: the new
// --format (table|cbom|report|report-json) and --output flags. It asserts
// structure and key fields, not golden bytes — the emitters run with the real
// wall clock here, so timestamps vary; the byte-level determinism is covered in
// the emitter packages' own tests where the clock is fixed.

// runCmd executes the root command with args, returning stdout+stderr and the
// exit code (mirroring Execute's mapping).
func runCmd(t *testing.T, args ...string) (string, int) {
	t.Helper()
	var out bytes.Buffer
	root := newRootCmd()
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(args)
	err := root.Execute()
	code := 0
	if err != nil {
		code = 1
		// Errors are silenced on the command tree (SilenceErrors); the real
		// Execute prints them. Mirror that here so message assertions can see it.
		out.WriteString("cryptoscan: " + err.Error() + "\n")
	}
	return out.String(), code
}

// TestFsCBOMOutput asserts `fs <corpus> --format cbom` emits a structurally valid
// CycloneDX 1.6 BOM with a non-trivial components array, exit 0.
func TestFsCBOMOutput(t *testing.T) {
	root := corpusRoot(t)
	out, code := runCmd(t, "fs", "--format", "cbom", root)
	if code != 0 {
		t.Fatalf("fs --format cbom exit = %d, want 0\noutput:\n%s", code, out)
	}

	var doc struct {
		BOMFormat   string            `json:"bomFormat"`
		SpecVersion string            `json:"specVersion"`
		Components  []json.RawMessage `json:"components"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("cbom output does not parse as JSON: %v\noutput:\n%s", err, out)
	}
	if doc.BOMFormat != "CycloneDX" {
		t.Errorf("bomFormat = %q, want CycloneDX", doc.BOMFormat)
	}
	if doc.SpecVersion != "1.6" {
		t.Errorf("specVersion = %q, want 1.6", doc.SpecVersion)
	}
	if len(doc.Components) < 5 {
		t.Errorf("components array has %d entries, want a non-trivial set (>=5)", len(doc.Components))
	}
}

// TestFsReportMarkdown asserts `fs <corpus> --format report` emits the Markdown
// auditor report: the summary section, the principle-4 finding columns, and a
// known rsa-1024 weak_key row.
func TestFsReportMarkdown(t *testing.T) {
	root := corpusRoot(t)
	out, code := runCmd(t, "fs", "--format", "report", root)
	if code != 0 {
		t.Fatalf("fs --format report exit = %d, want 0\noutput:\n%s", code, out)
	}

	// Summary section + the 7 principle-4 columns (as the Markdown table header).
	for _, want := range []string{
		"# cryptoscan cryptographic estate report",
		"## Estate summary",
		"### PQC exposure by flag",
		"## Findings",
		"| Severity | Type | Algorithm | Key size | Location(s) | Expiry | Issuer / CA | PQC exposure |",
		"certificate",
		"weak_key",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report markdown missing %q\noutput:\n%s", want, out)
		}
	}

	// A concrete known row: the rsa-1024 self-signed cert must surface as an RSA
	// 1024 certificate flagged weak_key.
	if !containsRowWith(out, "1024", "weak_key") {
		t.Errorf("no findings row mentioning both 1024 and weak_key\noutput:\n%s", out)
	}
}

// containsRowWith reports whether some line contains every needle.
func containsRowWith(s string, needles ...string) bool {
	for _, line := range strings.Split(s, "\n") {
		all := true
		for _, n := range needles {
			if !strings.Contains(line, n) {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}

// TestFsReportJSON asserts `fs <corpus> --format report-json` parses and carries
// the exact summary + findings field names of the principle-4 schema.
func TestFsReportJSON(t *testing.T) {
	root := corpusRoot(t)
	out, code := runCmd(t, "fs", "--format", "report-json", root)
	if code != 0 {
		t.Fatalf("fs --format report-json exit = %d, want 0\noutput:\n%s", code, out)
	}

	var doc struct {
		GeneratedAt string `json:"generated_at"`
		Summary     struct {
			TotalFindings int   `json:"total_findings"`
			ByType        []any `json:"by_type"`
			ByFlag        []any `json:"by_flag"`
			QuantumVuln   int   `json:"quantum_vulnerable"`
		} `json:"summary"`
		Findings []struct {
			Type        string   `json:"type"`
			Algorithm   string   `json:"algorithm"`
			KeySize     string   `json:"key_size"`
			Locations   []string `json:"locations"`
			Expiry      string   `json:"expiry"`
			Issuer      string   `json:"issuer"`
			PQCExposure []string `json:"pqc_exposure"`
			Severity    string   `json:"severity"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("report-json output does not parse: %v\noutput:\n%s", err, out)
	}
	if doc.GeneratedAt == "" {
		t.Error("report-json missing generated_at")
	}
	if len(doc.Findings) == 0 {
		t.Fatal("report-json has no findings")
	}
	if doc.Summary.TotalFindings != len(doc.Findings) {
		t.Errorf("summary.total_findings = %d, want %d (len findings)", doc.Summary.TotalFindings, len(doc.Findings))
	}

	// Exact field-name check: a raw parse to confirm the principle-4 keys exist
	// on a finding object verbatim.
	var raw struct {
		Findings []map[string]json.RawMessage `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	for _, key := range []string{"type", "algorithm", "key_size", "locations", "expiry", "issuer", "pqc_exposure", "severity"} {
		if _, ok := raw.Findings[0][key]; !ok {
			t.Errorf("finding object missing field %q", key)
		}
	}

	// Known finding: an rsa-1024 certificate flagged weak_key.
	found := false
	for _, f := range doc.Findings {
		if f.Type == "certificate" && f.KeySize == "1024" && containsStr(f.PQCExposure, "weak_key") {
			found = true
			break
		}
	}
	if !found {
		t.Error("report-json missing an rsa-1024 certificate with weak_key exposure")
	}
}

func containsStr(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

// TestFsCBOMToOutputFile asserts --output writes the CBOM to a file and leaves
// stdout empty, exit 0.
func TestFsCBOMToOutputFile(t *testing.T) {
	root := corpusRoot(t)
	outPath := filepath.Join(t.TempDir(), "cbom.json")

	out, code := runCmd(t, "fs", "--format", "cbom", "--output", outPath, root)
	if code != 0 {
		t.Fatalf("fs --format cbom --output exit = %d, want 0\noutput:\n%s", code, out)
	}
	if strings.TrimSpace(out) != "" {
		t.Errorf("stdout should be empty when --output is set, got:\n%s", out)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output file: %v", err)
	}
	if !json.Valid(data) {
		t.Fatalf("output file is not valid JSON:\n%s", data)
	}
	if !strings.Contains(string(data), `"bomFormat": "CycloneDX"`) {
		t.Errorf("output file is not a CycloneDX BOM:\n%s", data)
	}
}

// TestFsBadFormat asserts an unknown --format value is a usage error (exit 1)
// with a clear message, never a panic.
func TestFsBadFormat(t *testing.T) {
	root := corpusRoot(t)
	out, code := runCmd(t, "fs", "--format", "yaml", root)
	if code != 1 {
		t.Errorf("fs --format yaml exit = %d, want 1", code)
	}
	if !strings.Contains(out, "unknown --format") {
		t.Errorf("expected a clear unknown-format message, got:\n%s", out)
	}
}

// TestFsQuietWithMachineFormat asserts --quiet combined with a machine format is
// a usage error (documented: --quiet only shapes the table summary).
func TestFsQuietWithMachineFormat(t *testing.T) {
	root := corpusRoot(t)
	out, code := runCmd(t, "fs", "--format", "cbom", "--quiet", root)
	if code != 1 {
		t.Errorf("fs --format cbom --quiet exit = %d, want 1", code)
	}
	if !strings.Contains(out, "--quiet only applies to --format table") {
		t.Errorf("expected the --quiet/format incompatibility message, got:\n%s", out)
	}
}

// TestProbeReportJSON drives `probe <tlsAddr> --format report-json` against an
// in-process TLS server and asserts a tls_endpoint finding appears, exit 0.
func TestProbeReportJSON(t *testing.T) {
	root := corpusRoot(t)
	tlsAddr := startCorpusTLSServer(t, root, "certs/rsa-2048-selfsigned.pem", "keys/rsa-2048.key")

	out, code := runCmd(t, "probe", "--timeout", "3s", "--format", "report-json", tlsAddr)
	if code != 0 {
		t.Fatalf("probe --format report-json exit = %d, want 0\noutput:\n%s", code, out)
	}

	var doc struct {
		Findings []struct {
			Type string `json:"type"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("probe report-json does not parse: %v\noutput:\n%s", err, out)
	}
	found := false
	for _, f := range doc.Findings {
		if f.Type == "tls_endpoint" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("probe report-json missing a tls_endpoint finding\noutput:\n%s", out)
	}
}

// TestProbeCBOMOutput drives `probe <tlsAddr> --format cbom` against an
// in-process TLS server and asserts a valid CycloneDX BOM, exit 0.
func TestProbeCBOMOutput(t *testing.T) {
	root := corpusRoot(t)
	tlsAddr := startCorpusTLSServer(t, root, "certs/rsa-2048-selfsigned.pem", "keys/rsa-2048.key")

	out, code := runCmd(t, "probe", "--timeout", "3s", "--format", "cbom", tlsAddr)
	if code != 0 {
		t.Fatalf("probe --format cbom exit = %d, want 0\noutput:\n%s", code, out)
	}
	var doc struct {
		BOMFormat   string `json:"bomFormat"`
		SpecVersion string `json:"specVersion"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("probe cbom does not parse: %v\noutput:\n%s", err, out)
	}
	if doc.BOMFormat != "CycloneDX" || doc.SpecVersion != "1.6" {
		t.Errorf("probe cbom bomFormat/specVersion = %q/%q, want CycloneDX/1.6", doc.BOMFormat, doc.SpecVersion)
	}
}
