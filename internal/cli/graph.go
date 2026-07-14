package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Ubermm/cryptoscan/internal/graph"
	"github.com/Ubermm/cryptoscan/internal/output/graphdump"
	"github.com/Ubermm/cryptoscan/internal/scan"
	"github.com/Ubermm/cryptoscan/internal/scan/certs"
	"github.com/Ubermm/cryptoscan/internal/scan/config"
)

// scanFilesystem runs both Phase 1 filesystem scanners (certificate/key and
// server-config) into ONE shared graph, resolves the cross-scanner
// config→certificate/key references join, and returns the graph, the flat list
// of findings, and the resolved-reference count.
//
// It is the single scan-into-graph path shared by the `fs` and `graph` commands
// so both observe an identical graph. It returns an error only when a scanner
// could not walk root at all; individual unreadable/malformed files are skipped
// by the scanners themselves.
func scanFilesystem(root string) (g *graph.Graph, findings []scan.Finding, resolved int, err error) {
	g = graph.New()

	certFindings, err := certs.New().ScanIntoGraph(root, g)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("scanning %q: %w", root, err)
	}
	findings = append(findings, certFindings...)

	cfgFindings, err := config.ScanIntoGraph(root, g)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("scanning %q: %w", root, err)
	}
	findings = append(findings, cfgFindings...)

	resolved = g.ResolveReferences()
	return g, findings, resolved, nil
}

// newGraphCmd is the Phase 3 graph-dump command. It scans a filesystem path into
// the shared graph (the exact same path the `fs` command uses) and serializes the
// resulting graph deterministically as JSON (default) or Graphviz DOT.
//
// It is filesystem-based by design in Phase 3; dumping a network/probe graph can
// be layered on later without changing this command's contract.
func newGraphCmd() *cobra.Command {
	var format, output string
	cmd := &cobra.Command{
		Use:   "graph <path>",
		Short: "Dump the cryptographic asset graph scanned from a filesystem path",
		Long: "Scan a local filesystem path for cryptographic assets and dump the " +
			"resulting graph.\n\n" +
			"Runs the same scanners as `cryptoscan fs` (certificates, keys, keystores, " +
			"and server TLS configs) into one graph, resolves config→asset references, " +
			"and serializes every node and edge deterministically.\n\n" +
			"Formats: --format json (default) emits a stable {nodes,edges} object; " +
			"--format dot emits a Graphviz digraph. Output goes to stdout unless " +
			"--output <file> is given.\n\n" +
			"This command is filesystem-based (Phase 3); it does not probe the network.",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGraph(cmd.OutOrStdout(), args[0], format, output)
		},
	}
	f := cmd.Flags()
	f.StringVar(&format, "format", "json", "output format: json or dot")
	f.StringVar(&output, "output", "", "write to this file instead of stdout")
	return cmd
}

// runGraph validates the format, scans root into the shared graph, and writes the
// serialized dump to stdout or --output. It returns an error (mapped to exit 1 by
// Execute) on an invalid format, a scan failure, or an output-write failure; it
// never panics.
func runGraph(stdout io.Writer, root, format, output string) error {
	format = strings.ToLower(strings.TrimSpace(format))
	switch format {
	case "json", "dot":
	default:
		return fmt.Errorf("unknown --format %q: want \"json\" or \"dot\"", format)
	}

	g, _, _, err := scanFilesystem(root)
	if err != nil {
		return err
	}

	// Route through writeToDest so the graph dump shares the stdout/--output
	// handling AND the broken-pipe behaviour (piping `graph --format dot|json`
	// into head/less closes the pipe early and must exit 0, not 1).
	return writeToDest(stdout, output, func(w io.Writer) error {
		switch format {
		case "json":
			return graphdump.WriteJSON(w, g)
		case "dot":
			return graphdump.WriteDOT(w, g)
		default:
			return fmt.Errorf("internal error: runGraph reached write with format %q", format)
		}
	})
}
