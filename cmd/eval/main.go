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

	"github.com/cryptoscan/cryptoscan/internal/corpus"
	"github.com/cryptoscan/cryptoscan/internal/eval"
	"github.com/cryptoscan/cryptoscan/internal/scan"
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

	sc, err := eval.Score(c, findings, *strict)
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
