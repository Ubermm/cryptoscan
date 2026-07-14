package cli

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/cryptoscan/cryptoscan/internal/graph"
	"github.com/cryptoscan/cryptoscan/internal/scan"
	"github.com/cryptoscan/cryptoscan/internal/scan/certs"
	"github.com/cryptoscan/cryptoscan/internal/scan/config"
)

// newFsCmd is the local filesystem scanner (Phase 1). It runs the certificate/
// key and server-config scanners into ONE shared graph, resolves cross-scanner
// config→certificate/key references, and prints a deterministic human summary.
//
// This summary is interim: Phase 3 replaces it with the CycloneDX CBOM and the
// auditor report. It is kept simple but real so the wiring is exercised end to
// end from Phase 1.
func newFsCmd() *cobra.Command {
	var quiet bool
	cmd := &cobra.Command{
		Use:   "fs <path>",
		Short: "Scan a local filesystem path for cryptographic assets",
		Long: "Scan a local filesystem path for cryptographic assets.\n\n" +
			"Recursively walks <path> and reports certificates, keys, keystores " +
			"(JKS/PKCS#12), and server TLS configs (nginx, apache, sshd, " +
			"openssl.cnf, haproxy) it can prove by parsing the bytes.\n\n" +
			"Limits: each regular file larger than 8 MiB is skipped without being " +
			"read; directories, symlinks, and other non-regular files are not " +
			"followed. Unreadable or malformed files are skipped silently and " +
			"never abort the scan.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFs(cmd.OutOrStdout(), args[0], quiet)
		},
	}
	cmd.Flags().BoolVar(&quiet, "quiet", false, "print per-class counts only")
	return cmd
}

// runFs scans root with both Phase 1 scanners into one graph, resolves the
// references join, and writes the summary to w. It returns an error only when a
// scanner could not walk root at all (mapped to exit 1 by Execute); individual
// unreadable/malformed files are skipped by the scanners themselves.
func runFs(w io.Writer, root string, quiet bool) error {
	g := graph.New()

	var findings []scan.Finding
	certFindings, err := certs.New().ScanIntoGraph(root, g)
	if err != nil {
		return fmt.Errorf("scanning %q: %w", root, err)
	}
	findings = append(findings, certFindings...)

	cfgFindings, err := config.ScanIntoGraph(root, g)
	if err != nil {
		return fmt.Errorf("scanning %q: %w", root, err)
	}
	findings = append(findings, cfgFindings...)

	resolved := g.ResolveReferences()

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Class != findings[j].Class {
			return findings[i].Class < findings[j].Class
		}
		if findings[i].Path != findings[j].Path {
			return findings[i].Path < findings[j].Path
		}
		return findings[i].Alias < findings[j].Alias
	})

	writeClassCounts(w, findings)
	if !quiet {
		writeFindingsTable(w, findings)
	}
	writeGraphStats(w, g, resolved, quiet)
	return nil
}

// writeClassCounts prints the per-class finding tally and the total.
func writeClassCounts(w io.Writer, findings []scan.Finding) {
	counts := map[string]int{}
	for _, f := range findings {
		counts[f.Class]++
	}
	classes := make([]string, 0, len(counts))
	for c := range counts {
		classes = append(classes, c)
	}
	sort.Strings(classes)

	fmt.Fprintln(w, "Findings by class:")
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, c := range classes {
		fmt.Fprintf(tw, "  %s\t%d\n", c, counts[c])
	}
	fmt.Fprintf(tw, "  %s\t%d\n", "total", len(findings))
	_ = tw.Flush()
}

// writeFindingsTable prints the class / path[:alias] / detail / flags table.
func writeFindingsTable(w io.Writer, findings []scan.Finding) {
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Findings:")
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  CLASS\tPATH\tDETAIL\tFLAGS")
	for _, f := range findings {
		loc := f.Path
		if f.Alias != "" {
			loc += ":" + f.Alias
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n", f.Class, loc, findingDetail(f), strings.Join(findingFlags(f), ","))
	}
	_ = tw.Flush()
}

// writeGraphStats prints node/edge counts by type plus the resolved-references
// join count. In quiet mode only the one-line totals + resolved count are shown.
func writeGraphStats(w io.Writer, g *graph.Graph, resolved int, quiet bool) {
	fmt.Fprintln(w)
	if quiet {
		fmt.Fprintf(w, "Graph: %d nodes, %d edges, %d resolved references\n", g.NodeCount(), g.EdgeCount(), resolved)
		return
	}

	nodeByType := map[string]int{}
	for _, n := range g.Nodes() {
		nodeByType[string(n.Type())]++
	}
	edgeByType := map[string]int{}
	for _, e := range g.Edges() {
		edgeByType[string(e.Type)]++
	}

	fmt.Fprintf(w, "Graph nodes: %d\n", g.NodeCount())
	writeSortedCounts(w, nodeByType)
	fmt.Fprintf(w, "Graph edges: %d\n", g.EdgeCount())
	writeSortedCounts(w, edgeByType)
	fmt.Fprintf(w, "Resolved references (config -> cert/key): %d\n", resolved)
}

// writeSortedCounts renders a key->count map in sorted key order, aligned.
func writeSortedCounts(w io.Writer, m map[string]int) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, k := range keys {
		fmt.Fprintf(tw, "  %s\t%d\n", k, m[k])
	}
	_ = tw.Flush()
}

// findingDetail renders the class-appropriate "what is it" column: algorithm and
// key size/curve for asset classes, protocol set for tls/ssh configs.
func findingDetail(f scan.Finding) string {
	switch f.Class {
	case "certificate", "private_key", "public_key", "csr":
		algo := strAttr(f.Attrs, "algorithm")
		if algo == "" {
			return "(encrypted)"
		}
		if curve := strAttr(f.Attrs, "curve"); curve != "" {
			return algo + " " + curve
		}
		if size := intAttr(f.Attrs, "key_size"); size > 0 {
			return fmt.Sprintf("%s %d", algo, size)
		}
		return algo
	case "tls_config":
		if protos := strListAttr(f.Attrs, "protocols"); len(protos) > 0 {
			return strings.Join(protos, ",")
		}
		if mp := strAttr(f.Attrs, "min_protocol"); mp != "" {
			return "min " + mp
		}
		return ""
	case "ssh_config":
		return strings.Join(strListAttr(f.Attrs, "host_key_types"), ",")
	default:
		return ""
	}
}

// findingFlags derives the interim risk flags provable from the finding's
// attributes (a subset of DESIGN.md §5, which Phase 3 formalises).
func findingFlags(f scan.Finding) []string {
	var flags []string
	switch f.Class {
	case "certificate":
		if boolAttr(f.Attrs, "expired") {
			flags = append(flags, "expired")
		}
		if boolAttr(f.Attrs, "not_yet_valid") {
			flags = append(flags, "not_yet_valid")
		}
		if sig := strings.ToUpper(strAttr(f.Attrs, "signature_algorithm")); strings.Contains(sig, "SHA1") || strings.Contains(sig, "MD5") {
			flags = append(flags, "weak-sig")
		}
		if strAttr(f.Attrs, "algorithm") == "RSA" {
			if size := intAttr(f.Attrs, "key_size"); size > 0 && size < 2048 {
				flags = append(flags, "weak-key")
			}
		}
	case "private_key", "public_key":
		if strAttr(f.Attrs, "algorithm") == "RSA" {
			if size := intAttr(f.Attrs, "key_size"); size > 0 && size < 2048 {
				flags = append(flags, "weak-key")
			}
		}
	case "tls_config":
		for _, p := range strListAttr(f.Attrs, "protocols") {
			if legacyProtocol(p) {
				flags = append(flags, "legacy-tls")
				break
			}
		}
		if mp := strAttr(f.Attrs, "min_protocol"); legacyProtocol(mp) {
			flags = append(flags, "legacy-tls")
		}
	}
	return flags
}

// legacyProtocol reports whether a protocol token is below TLS 1.2.
func legacyProtocol(p string) bool {
	switch strings.ToUpper(p) {
	case "SSLV3", "TLSV1", "TLSV1.1":
		return true
	default:
		return false
	}
}

// --- attribute accessors (findings carry map[string]any) ---

func strAttr(m map[string]any, k string) string {
	if v, ok := m[k].(string); ok {
		return v
	}
	return ""
}

func intAttr(m map[string]any, k string) int {
	switch v := m[k].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	default:
		return 0
	}
}

func boolAttr(m map[string]any, k string) bool {
	v, _ := m[k].(bool)
	return v
}

func strListAttr(m map[string]any, k string) []string {
	switch v := m[k].(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			out = append(out, fmt.Sprintf("%v", e))
		}
		return out
	default:
		return nil
	}
}
