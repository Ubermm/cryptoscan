package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/Ubermm/cryptoscan/internal/graph"
	"github.com/Ubermm/cryptoscan/internal/pqc"
)

// WriteMarkdown renders the auditor report for g and its pqc exposure to w as a
// clean, auditor-readable Markdown document: a title, an estate-summary section
// (assets by type, PQC-flag tallies, and the headline counts), then a findings
// table whose columns are the principle-4 schema (type, algorithm, key size,
// location(s), expiry, issuer/CA, PQC exposure) prefixed by the severity.
//
// Findings are a projection of the graph (principle 2), ordered by PQC severity
// descending then asymmetric-first (principle 3). The output is byte-for-byte
// deterministic for a given (graph, exposure, opts) and ends with a trailing
// newline. An empty or nil graph yields a valid report with zero findings. The
// function never panics.
func WriteMarkdown(w io.Writer, g *graph.Graph, exposure pqc.Report, opts Options) error {
	findings := buildFindings(g, exposure)

	var b strings.Builder

	title := opts.Title
	if title == "" {
		title = DefaultTitle
	}
	fmt.Fprintf(&b, "# %s\n\n", title)
	fmt.Fprintf(&b, "_Generated at %s_\n\n", opts.Now.UTC().Format(rfc3339))

	writeMarkdownSummary(&b, findings, exposure.Summary)
	writeMarkdownFindings(&b, findings)

	if _, err := io.WriteString(w, b.String()); err != nil {
		return fmt.Errorf("report: writing report Markdown: %w", err)
	}
	return nil
}

// writeMarkdownSummary renders the estate-summary section.
func writeMarkdownSummary(b *strings.Builder, findings []finding, s pqc.Summary) {
	b.WriteString("## Estate summary\n\n")
	fmt.Fprintf(b, "Assets scored: %d (flagged with at least one PQC exposure: %d)\n\n",
		s.TotalNodes, s.FlaggedNodes)

	// Assets by finding type.
	b.WriteString("### Assets by type\n\n")
	byType := map[string]int{}
	for _, f := range findings {
		byType[f.typ]++
	}
	if len(byType) == 0 {
		b.WriteString("_No cryptographic assets found._\n\n")
	} else {
		b.WriteString("| Type | Count |\n| --- | ---: |\n")
		types := make([]string, 0, len(byType))
		for t := range byType {
			types = append(types, t)
		}
		sort.Strings(types)
		for _, t := range types {
			fmt.Fprintf(b, "| %s | %d |\n", t, byType[t])
		}
		fmt.Fprintf(b, "| **total** | **%d** |\n", len(findings))
		b.WriteString("\n")
	}

	// PQC exposure flag tallies.
	b.WriteString("### PQC exposure by flag\n\n")
	if len(s.ByFlag) == 0 {
		b.WriteString("_No PQC exposures flagged._\n\n")
	} else {
		b.WriteString("| Flag | Count |\n| --- | ---: |\n")
		for _, c := range s.ByFlag {
			fmt.Fprintf(b, "| %s | %d |\n", c.Name, c.Count)
		}
		b.WriteString("\n")
	}

	// Headline counts (mirror pqc.Report.Summary).
	b.WriteString("### Headline exposure\n\n")
	fmt.Fprintf(b, "- Quantum-vulnerable assets: %d\n", s.QuantumVulnerableAssets)
	fmt.Fprintf(b, "- Legacy-protocol (< TLS 1.2) endpoints/configs: %d\n", flagCount(s.ByFlag, pqc.FlagLegacyProtocol))
	fmt.Fprintf(b, "- Expired certificates: %d\n", s.Expired)
	fmt.Fprintf(b, "- Expiring certificates (within 90 days): %d\n", s.Expiring)
	fmt.Fprintf(b, "- PQC-ready (hybrid KEX) endpoints: %d\n", s.PQCReadyEndpoints)
	b.WriteString("\n")
}

// writeMarkdownFindings renders the findings table (or an empty-state note).
func writeMarkdownFindings(b *strings.Builder, findings []finding) {
	b.WriteString("## Findings\n\n")
	if len(findings) == 0 {
		b.WriteString("_No cryptographic assets found._\n")
		return
	}
	b.WriteString("Ordered by PQC severity (descending), then asymmetric-first.\n\n")
	b.WriteString("| Severity | Type | Algorithm | Key size | Location(s) | Expiry | Issuer / CA | PQC exposure |\n")
	b.WriteString("| --- | --- | --- | --- | --- | --- | --- | --- |\n")
	for _, f := range findings {
		fmt.Fprintf(b, "| %s | %s | %s | %s | %s | %s | %s | %s |\n",
			cell(f.severity),
			cell(f.typ),
			cell(f.algorithm),
			cell(f.keySize),
			cell(strings.Join(f.locations, "; ")),
			cell(f.expiry),
			cell(f.issuer),
			cell(strings.Join(f.pqcFlags, ", ")),
		)
	}
}

// cell sanitises a value for a Markdown table cell: pipes are escaped and any
// embedded newline/tab becomes a space, so a cell can never break the table.
func cell(s string) string {
	if s == "" {
		return "-"
	}
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	return s
}
