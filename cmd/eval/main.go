// Command eval is the cryptoscan scorecard harness (DESIGN.md §3, CLAUDE.md
// "Definition of done"). It loads the ground-truth corpus, runs every
// registered scanner (via internal/scan) against it, matches the findings, and
// prints a per-asset-class precision/recall/F1 scorecard.
//
// Exit codes:
//
//	0  gate passed
//	1  gate failed (a class with declared assets scored below 0.95 precision,
//	   or --strict and a recall shortfall)
//	2  operational error (bad corpus, scanner failure, bad flags)
//
// In Phase 0 no scanners are registered yet: the harness runs cleanly, reports
// a full recall shortfall, and — since no false claims are made — the gate
// passes and the process exits 0 (unless --strict).
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/Ubermm/cryptoscan/internal/corpus"
	"github.com/Ubermm/cryptoscan/internal/eval"
	"github.com/Ubermm/cryptoscan/internal/graph"
	"github.com/Ubermm/cryptoscan/internal/scan"
	"github.com/Ubermm/cryptoscan/internal/scan/config"

	// Blank import registers the certs filesystem scanner in the scan registry
	// (via package init) so scan.All() exercises it. The config scanner is
	// imported by name (below) both for registration and to populate a graph with
	// ConfigEndpoint nodes for per-endpoint scoring.
	_ "github.com/Ubermm/cryptoscan/internal/scan/certs"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("eval", flag.ContinueOnError)
	fs.SetOutput(stderr)
	corpusDir := fs.String("corpus", "testdata/corpus", "path to the ground-truth corpus root")
	strict := fs.Bool("strict", false, "also fail the gate on recall shortfalls")
	format := fs.String("format", "table", "output format: table | json")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	switch *format {
	case "table", "json":
	default:
		fmt.Fprintf(stderr, "eval: unknown --format %q (want table|json)\n", *format)
		return 2
	}

	c, err := corpus.LoadDir(*corpusDir)
	if err != nil {
		fmt.Fprintf(stderr, "eval: %v\n", err)
		return 2
	}

	var findings []scan.Finding
	for _, s := range scan.All() {
		fnd, err := s.Scan(*corpusDir)
		if err != nil {
			fmt.Fprintf(stderr, "eval: scanner %q failed: %v\n", s.Name(), err)
			return 2
		}
		findings = append(findings, fnd...)
	}

	// Populate a graph with the config scanner so its ConfigEndpoint nodes can be
	// scored per-endpoint (the file-level findings above are scored as before).
	emitted, err := emittedEndpoints(*corpusDir)
	if err != nil {
		fmt.Fprintf(stderr, "eval: %v\n", err)
		return 2
	}

	sc, err := eval.ScoreAll(c, findings, emitted, *strict)
	if err != nil {
		fmt.Fprintf(stderr, "eval: %v\n", err)
		return 2
	}

	switch *format {
	case "json":
		if err := sc.WriteJSON(stdout); err != nil {
			fmt.Fprintf(stderr, "eval: %v\n", err)
			return 2
		}
	default:
		if err := sc.WriteTable(stdout); err != nil {
			fmt.Fprintf(stderr, "eval: %v\n", err)
			return 2
		}
	}

	if !sc.Gate.Pass {
		return 1
	}
	return 0
}

// emittedEndpoints scans the corpus into a graph via the config scanner and
// projects every ConfigEndpoint node into an eval.EmittedEndpoint for
// per-endpoint scoring. It keeps the eval package free of a graph dependency.
func emittedEndpoints(root string) ([]eval.EmittedEndpoint, error) {
	g := graph.New()
	if _, err := config.ScanIntoGraph(root, g); err != nil {
		return nil, fmt.Errorf("config graph scan: %w", err)
	}
	var out []eval.EmittedEndpoint
	for _, n := range g.Nodes() {
		ep, ok := n.(*graph.ConfigEndpointNode)
		if !ok {
			continue
		}
		listens := attrStrList(ep.Attrs, "listen")
		listen := ""
		if len(listens) > 0 {
			listen = listens[0]
		}
		out = append(out, eval.EmittedEndpoint{
			File:        ep.Path,
			ServerNames: attrStrList(ep.Attrs, "server_name"),
			Listen:      listen,
			Port:        attrInt(ep.Attrs, "port"),
			Attrs:       ep.Attrs,
		})
	}
	return out, nil
}

// attrStrList reads a []string attribute, nil-safe.
func attrStrList(m map[string]any, k string) []string {
	if v, ok := m[k].([]string); ok {
		return v
	}
	return nil
}

// attrInt reads an int attribute, nil-safe.
func attrInt(m map[string]any, k string) int {
	if v, ok := m[k].(int); ok {
		return v
	}
	return 0
}
