package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/Ubermm/cryptoscan/internal/graph"
	"github.com/Ubermm/cryptoscan/internal/pqc"
)

// jsonReport is the top-level JSON document:
// {generated_at, summary, findings:[...]}.
type jsonReport struct {
	GeneratedAt string        `json:"generated_at"`
	Summary     jsonSummary   `json:"summary"`
	Findings    []jsonFinding `json:"findings"`
}

// jsonFinding is the on-disk shape of one finding. The field order is the
// principle-4 PCI-QSA schema VERBATIM — type, algorithm, key_size, location(s),
// expiry, issuer, pqc_exposure — with the exposure severity appended.
type jsonFinding struct {
	Type        string   `json:"type"`
	Algorithm   string   `json:"algorithm"`
	KeySize     string   `json:"key_size"`
	Locations   []string `json:"locations"`
	Expiry      string   `json:"expiry"`
	Issuer      string   `json:"issuer"`
	PQCExposure []string `json:"pqc_exposure"`
	Severity    string   `json:"severity"`
}

// jsonCount is a stable (name, count) pair for the summary tallies.
type jsonCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// jsonSummary mirrors pqc.Report.Summary plus the finding-type tally, all sorted
// for reproducibility.
type jsonSummary struct {
	TotalFindings     int         `json:"total_findings"`
	ByType            []jsonCount `json:"by_type"`
	TotalAssetsScored int         `json:"total_assets_scored"`
	FlaggedAssets     int         `json:"flagged_assets"`
	ByFlag            []jsonCount `json:"by_flag"`
	BySeverity        []jsonCount `json:"by_severity"`
	QuantumVulnerable int         `json:"quantum_vulnerable"`
	LegacyProtocol    int         `json:"legacy_protocol"`
	LegacyEndpoints   int         `json:"legacy_endpoints"`
	Expired           int         `json:"expired"`
	Expiring          int         `json:"expiring"`
	PQCReadyEndpoints int         `json:"pqc_ready_endpoints"`
}

// WriteJSON renders the auditor report for g and its pqc exposure to w as a
// stable, pretty-printed JSON document of the form
// {"generated_at":...,"summary":{...},"findings":[...]}.
//
// Findings are a projection of the graph (principle 2), one per crypto-asset
// node, ordered by PQC severity descending then asymmetric-first (principle 3).
// Each finding object carries the principle-4 fields in their fixed order. The
// output is byte-for-byte deterministic for a given (graph, exposure, opts) and
// ends with a trailing newline. An empty or nil graph yields an empty findings
// array and a zero summary. The function never panics.
func WriteJSON(w io.Writer, g *graph.Graph, exposure pqc.Report, opts Options) error {
	findings := buildFindings(g, exposure)

	doc := jsonReport{
		GeneratedAt: opts.Now.UTC().Format(rfc3339),
		Summary:     buildJSONSummary(findings, exposure.Summary),
		Findings:    make([]jsonFinding, 0, len(findings)),
	}
	for _, f := range findings {
		doc.Findings = append(doc.Findings, jsonFinding{
			Type:        f.typ,
			Algorithm:   f.algorithm,
			KeySize:     f.keySize,
			Locations:   nonNil(f.locations),
			Expiry:      f.expiry,
			Issuer:      f.issuer,
			PQCExposure: nonNil(f.pqcFlags),
			Severity:    f.severity,
		})
	}

	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("report: marshaling report JSON: %w", err)
	}
	out = append(out, '\n')
	if _, err := w.Write(out); err != nil {
		return fmt.Errorf("report: writing report JSON: %w", err)
	}
	return nil
}

// buildJSONSummary assembles the estate summary from the projected findings (the
// finding-type tally) and the pqc estate rollup (everything else).
func buildJSONSummary(findings []finding, s pqc.Summary) jsonSummary {
	byType := map[string]int{}
	for _, f := range findings {
		byType[f.typ]++
	}
	return jsonSummary{
		TotalFindings:     len(findings),
		ByType:            toJSONCounts(byType),
		TotalAssetsScored: s.TotalNodes,
		FlaggedAssets:     s.FlaggedNodes,
		ByFlag:            countsFrom(s.ByFlag),
		BySeverity:        countsFrom(s.BySeverity),
		QuantumVulnerable: s.QuantumVulnerableAssets,
		LegacyProtocol:    flagCount(s.ByFlag, pqc.FlagLegacyProtocol),
		LegacyEndpoints:   s.LegacyEndpoints,
		Expired:           s.Expired,
		Expiring:          s.Expiring,
		PQCReadyEndpoints: s.PQCReadyEndpoints,
	}
}

// countsFrom converts a []pqc.Count (already Name-sorted) into []jsonCount.
func countsFrom(cs []pqc.Count) []jsonCount {
	out := make([]jsonCount, 0, len(cs))
	for _, c := range cs {
		out = append(out, jsonCount{Name: c.Name, Count: c.Count})
	}
	return out
}

// toJSONCounts turns a name→count map into a Name-sorted []jsonCount.
func toJSONCounts(m map[string]int) []jsonCount {
	out := make([]jsonCount, 0, len(m))
	for k, v := range m {
		out = append(out, jsonCount{Name: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// flagCount looks up a single flag's tally in a pqc ByFlag slice (0 if absent).
func flagCount(cs []pqc.Count, name string) int {
	for _, c := range cs {
		if c.Name == name {
			return c.Count
		}
	}
	return 0
}

// nonNil replaces a nil slice with an empty one so JSON renders [] not null.
func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
