package cli

import (
	"context"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/Ubermm/cryptoscan/internal/graph"
	"github.com/Ubermm/cryptoscan/internal/policy"
	"github.com/Ubermm/cryptoscan/internal/pqc"
	"github.com/Ubermm/cryptoscan/internal/probe"

	// Blank-import the concrete probers so their init() functions register them
	// into the process-wide probe registry that probe.All() reads. The wiring
	// lives HERE — the CLI is the single place that assembles the probe set — and
	// is deliberately NOT pulled in transitively via cmd/eval.
	_ "github.com/Ubermm/cryptoscan/internal/probe/ssh"
	_ "github.com/Ubermm/cryptoscan/internal/probe/tls"
)

const (
	// defaultProbePort is applied to a bare host (no :port). 443 is the TLS
	// default; SSH endpoints must be listed with an explicit :22 (see Long help).
	defaultProbePort = 443
	// defaultProbeRate bounds probe operations per second by default; 0 disables.
	defaultProbeRate = 10.0
)

// newProbeCmd is the Phase 2 network scanner. It probes ONLY the explicitly
// listed targets (no discovery, no subnet or range expansion), running every
// registered prober (TLS, SSH) against each target through the shared batch
// driver probe.Run, into one graph. The human summary it prints is interim:
// Phase 3 replaces it with the CycloneDX CBOM and the auditor report.
func newProbeCmd() *cobra.Command {
	var opts probeCmdOptions
	cmd := &cobra.Command{
		Use:   "probe [flags] <target>...",
		Short: "Probe explicitly listed network endpoints for TLS/SSH crypto parameters",
		Long: "Probe explicitly listed network endpoints and record the cryptographic\n" +
			"parameters they present on the wire.\n\n" +
			"Targets are given as positional arguments and/or a --targets-file (one per\n" +
			"line; blank lines and lines beginning with # are ignored). Each target is a\n" +
			"host:port, a bare host, or an IP literal (bracket IPv6 to add a port, e.g.\n" +
			"[::1]:443). A bare host with no port defaults to :" + fmt.Sprint(defaultProbePort) + ". Only explicit\n" +
			"targets are probed: a CIDR block or address range is rejected, never expanded.\n\n" +
			"Every registered prober runs against every target, so a target is probed for\n" +
			"BOTH TLS and SSH regardless of what it actually speaks; a prober that meets\n" +
			"the wrong service records a non-fatal error (expected) and the run continues.\n" +
			"Because of this, an SSH endpoint must be given an EXPLICIT :22 (e.g.\n" +
			"host:22) — a bare host would be probed on the default port " + fmt.Sprint(defaultProbePort) + " and the SSH\n" +
			"prober would simply record a non-matching-service error.\n\n" +
			"No trust validation is performed: the presented TLS chain and the advertised\n" +
			"SSH algorithms are RECORDED, not judged. Nothing is authenticated.\n\n" +
			"Output: --format table (default) / cbom / report / report-json with --output\n" +
			"<file> select a single projection, exactly as `fs`. For multiple outputs from\n" +
			"ONE probe, --emit <format>=<dest> is repeatable (dest: a file path, or - for\n" +
			"stdout); at most one --emit may target stdout, no format twice, and --emit is\n" +
			"mutually exclusive with --format/--output.\n\n" +
			failOnLongHelp +
			"Exit status is 0 when at least one target was probed, 1 on a usage error or\n" +
			"when no target could be probed at all, and 4 when a --fail-on policy threshold\n" +
			"is breached (see exit codes below).\n\n" +
			exitCodeLongHelp,
		Args:         cobra.ArbitraryArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			// The command layer supplies the REAL clock once; the emitters and
			// pqc.Score consume it (they never call time.Now themselves). The
			// Changed flags let runProbe reject --emit combined with --format/--output.
			opts.formatSet = cmd.Flags().Changed("format")
			opts.outputSet = cmd.Flags().Changed("output")
			return runProbe(cmd.OutOrStdout(), cmd.ErrOrStderr(), args, opts, time.Now())
		},
	}
	f := cmd.Flags()
	f.StringVar(&opts.targetsFile, "targets-file", "", "read newline-delimited targets from a file")
	f.DurationVar(&opts.timeout, "timeout", probe.DefaultTimeout, "per-target probe timeout")
	f.IntVar(&opts.concurrency, "concurrency", probe.DefaultConcurrency, "maximum simultaneous probes")
	f.Float64Var(&opts.rate, "rate", defaultProbeRate, "maximum probe operations per second (0 = unlimited)")
	f.BoolVar(&opts.quiet, "quiet", false, "print per-class counts and a one-line graph summary only (table format only)")
	f.BoolVar(&opts.verbose, "verbose", false, "list every per-target probe error in full")
	f.StringVar(&opts.format, "format", formatTable, scanFormatHelp)
	f.StringVar(&opts.output, "output", "", "write to this file instead of stdout")
	f.StringArrayVar(&opts.emit, "emit", nil, emitFlagHelp)
	f.StringSliceVar(&opts.failOn, "fail-on", nil, failOnFlagHelp)
	return cmd
}

// probeCmdOptions carries the parsed flag values for runProbe.
type probeCmdOptions struct {
	targetsFile string
	timeout     time.Duration
	concurrency int
	rate        float64
	quiet       bool
	verbose     bool
	format      string
	output      string
	emit        []string
	failOn      []string
	formatSet   bool
	outputSet   bool
}

// runProbe gathers the targets, runs every registered prober against them into
// one graph, and writes a deterministic human summary to w. It returns an error
// (mapped to exit 1 by Execute) only on a usage problem — no targets, a bad
// target, an unreadable targets file — or when NO target could be probed at all
// (every prober failed against every target). A target reachable by one prober
// but not the other is a success; the non-matching prober's error is expected.
func runProbe(stdout, stderr io.Writer, args []string, opts probeCmdOptions, now time.Time) error {
	// Resolve the output target set FIRST so a bad --format/--emit fails fast as a
	// usage error (exit 1) before touching the network.
	targets, err := resolveOutputTargets(opts.emit, opts.format, opts.output, opts.quiet, opts.formatSet, opts.outputSet)
	if err != nil {
		return err
	}
	// Parse the policy thresholds BEFORE probing so an invalid --fail-on token
	// fails fast as a usage error (exit 1) without touching the network.
	thresholds, err := policy.ParseThresholds(opts.failOn)
	if err != nil {
		return err
	}

	probeTargets, err := gatherTargets(args, opts.targetsFile)
	if err != nil {
		return err
	}
	if len(probeTargets) == 0 {
		return fmt.Errorf("no targets: pass one or more host:port arguments and/or --targets-file")
	}

	g := graph.New()
	res, err := probe.Run(context.Background(), probeTargets, g, probe.RunOptions{
		Timeout:     opts.timeout,
		Concurrency: opts.concurrency,
		RatePerSec:  opts.rate,
	})
	if err != nil {
		return fmt.Errorf("probe run: %w", err)
	}

	// Exit 1 only when nothing at all could be probed. With every prober run
	// against every target, zero findings means every (target, prober) failed.
	noProbeErr := fmt.Errorf("no target could be probed (%d probe error(s) across %d target(s))", len(res.Errors), len(probeTargets))
	// The legacy single-table path prints its (empty) summary THEN reports the
	// no-target error, preserving prior behaviour. Any machine format — and every
	// --emit run — instead surfaces the error before emitting, since an empty
	// BOM/report is not a useful artifact.
	legacyTablePrint := len(opts.emit) == 0 && len(targets) == 1 && targets[0].format == formatTable
	if len(res.Findings) == 0 && !legacyTablePrint {
		return noProbeErr
	}

	// Score once when either a machine format or the policy gate needs it, and
	// share that single Report across every emitter and the gate.
	var exposure pqc.Report
	if needScore(targets, len(thresholds) > 0) {
		exposure = pqc.Score(g, now)
	}

	if err := writeEmitTargets(stdout, targets, func(w io.Writer, f string) error {
		if f == formatTable {
			writeClassCounts(w, res.Findings)
			if !opts.quiet {
				writeProbeFindingsTable(w, res.Findings)
			}
			writeProbeGraphStats(w, g, opts.quiet)
			if !opts.quiet {
				writeProbeErrors(w, res.Errors, opts.verbose)
			}
			if len(res.Findings) == 0 {
				return noProbeErr
			}
			return nil
		}
		return emitGraphOutput(w, g, exposure, f, now)
	}); err != nil {
		return err
	}

	// Output written; gate after it (a breach prints to stderr, exit 4).
	return gateOnPolicy(stderr, g, exposure, thresholds)
}

// gatherTargets parses the positional args (if any) then the --targets-file (if
// set), each with the default port applied to bare hosts, and returns them in
// that order. Any parse error is returned verbatim (mapped to exit 1).
func gatherTargets(args []string, targetsFile string) ([]probe.Target, error) {
	var targets []probe.Target
	if len(args) > 0 {
		ts, err := probe.ParseTargets(args, defaultProbePort)
		if err != nil {
			return nil, err
		}
		targets = append(targets, ts...)
	}
	if targetsFile != "" {
		ts, err := probe.ParseTargetFile(targetsFile, defaultProbePort)
		if err != nil {
			return nil, err
		}
		targets = append(targets, ts...)
	}
	return targets, nil
}

// writeProbeFindingsTable prints the target / class / key-params table. Findings
// arrive already sorted by (Class, Path) from probe.Run, so output is stable.
func writeProbeFindingsTable(w io.Writer, findings []probe.Finding) {
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Findings:")
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  TARGET\tCLASS\tDETAIL")
	for _, f := range findings {
		fmt.Fprintf(tw, "  %s\t%s\t%s\n", f.Path, f.Class, probeFindingDetail(f))
	}
	_ = tw.Flush()
}

// probeFindingDetail renders the class-appropriate key parameters for a probe
// finding: TLS shows the negotiated protocol/cipher, supported protocols, the
// hybrid-PQC flag, and the peer-cert count; SSH shows the banner and the
// advertised host-key/kex/cipher/MAC name-lists.
func probeFindingDetail(f probe.Finding) string {
	switch f.Class {
	case probe.ClassTLSEndpoint:
		var b strings.Builder
		proto := dashIfEmpty(strAttr(f.Attrs, "negotiated_protocol"))
		cipher := dashIfEmpty(strAttr(f.Attrs, "negotiated_cipher_suite"))
		fmt.Fprintf(&b, "%s / %s", proto, cipher)
		if protos := strListAttr(f.Attrs, "protocols_supported"); len(protos) > 0 {
			fmt.Fprintf(&b, "; protocols=[%s]", strings.Join(protos, ","))
		}
		fmt.Fprintf(&b, "; pqc=%t; peer_certs=%d", boolAttr(f.Attrs, "pqc_hybrid_kex"), intAttr(f.Attrs, "peer_certs"))
		return b.String()
	case probe.ClassSSHEndpoint:
		var b strings.Builder
		b.WriteString(dashIfEmpty(strAttr(f.Attrs, "banner")))
		b.WriteString(sshListDetail(f.Attrs, "hostkeys", "host_key_algorithms"))
		b.WriteString(sshListDetail(f.Attrs, "kex", "kex_algorithms"))
		b.WriteString(sshListDetail(f.Attrs, "ciphers", "ciphers"))
		b.WriteString(sshListDetail(f.Attrs, "macs", "macs"))
		return b.String()
	default:
		return ""
	}
}

// sshListDetail renders "; label=[a,b]" for a non-empty name-list attribute, or
// "" when the list is absent/empty.
func sshListDetail(m map[string]any, label, key string) string {
	v := strListAttr(m, key)
	if len(v) == 0 {
		return ""
	}
	return fmt.Sprintf("; %s=[%s]", label, strings.Join(v, ","))
}

// dashIfEmpty renders "-" for an empty string so table cells never collapse.
func dashIfEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// writeProbeGraphStats prints node/edge counts by type (including Endpoint nodes
// and terminates_tls_for edges when present). In quiet mode only the one-line
// totals are shown.
func writeProbeGraphStats(w io.Writer, g *graph.Graph, quiet bool) {
	fmt.Fprintln(w)
	if quiet {
		fmt.Fprintf(w, "Graph: %d nodes, %d edges\n", g.NodeCount(), g.EdgeCount())
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
}

// writeProbeErrors summarises the per-target probe errors. A single line reports
// the count (these are largely expected: with every prober run against every
// target, a TLS-only endpoint always yields an SSH error and vice versa);
// --verbose lists each (target, scheme, cause). Errors is already sorted by
// probe.Run for deterministic output.
func writeProbeErrors(w io.Writer, errs []probe.TargetError, verbose bool) {
	if len(errs) == 0 {
		return
	}
	fmt.Fprintln(w)
	if verbose {
		fmt.Fprintf(w, "Probe errors (%d):\n", len(errs))
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  TARGET\tSCHEME\tERROR")
		for _, e := range errs {
			fmt.Fprintf(tw, "  %s\t%s\t%v\n", e.Target.Addr(), e.Scheme, e.Err)
		}
		_ = tw.Flush()
		return
	}
	fmt.Fprintf(w, "Probe errors: %d probe attempt(s) failed (expected for non-matching services; use --verbose to list)\n", len(errs))
}
