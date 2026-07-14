package cli

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/cryptoscan/cryptoscan/internal/graph"
	"github.com/cryptoscan/cryptoscan/internal/policy"
	"github.com/cryptoscan/cryptoscan/internal/pqc"
)

// failOnFlagHelp is the reusable --fail-on flag usage string for fs/probe.
const failOnFlagHelp = "comma-separated policy tokens; exit 4 if any is breached " +
	"(e.g. sha1,rsa1024,tls10). See --help for the token list. Empty = disabled."

// failOnLongHelp documents the --fail-on token vocabulary in each command's Long
// help. The token list is derived from the policy package so it never drifts.
var failOnLongHelp = "Policy gate: --fail-on <tokens> evaluates threshold tokens " +
	"AFTER the output above is fully written and exits 4 if any is breached (the " +
	"report is never suppressed). A concise breach summary is printed to STDERR. " +
	"Tokens (comma-separated, case-insensitive, repeatable):\n" + failOnTokenList() + "\n\n"

// exitCodeLongHelp documents the exit-code scheme in each command's Long help.
const exitCodeLongHelp = "Exit codes: 0 = clean; 1 = operational/usage error; " +
	"2 = cobra usage; 4 = a --fail-on policy threshold was breached."

// failOnTokenList renders the policy vocabulary as an indented "token — desc"
// block for the Long help.
func failOnTokenList() string {
	var b strings.Builder
	for _, tok := range policy.ValidTokens() {
		fmt.Fprintf(&b, "  %s — %s\n", tok, policy.Describe(tok))
	}
	return strings.TrimRight(b.String(), "\n")
}

// gateOnPolicy applies the parsed --fail-on thresholds to the scanned graph AFTER
// the requested output has already been written. When a threshold is breached it
// writes a concise, deterministic summary to stderr (NOT stdout, which may carry
// machine output) and returns errThresholdBreached, which Execute maps to exit 4.
// An empty threshold set, or no breach, returns nil (exit unaffected).
//
// exposure is the pqc.Report already computed once for g at the command's
// reference time and shared with the emitter, so the gate never re-scores.
func gateOnPolicy(stderr io.Writer, g *graph.Graph, exposure pqc.Report, thresholds []policy.Threshold) error {
	if len(thresholds) == 0 {
		return nil
	}
	result := policy.Evaluate(g, exposure, thresholds)
	if !result.Breached() {
		return nil
	}
	writeBreachSummary(stderr, result)
	return errThresholdBreached
}

// writeBreachSummary prints the policy breach report to w (stderr). It leads with
// a per-token tally, then lists every offending asset (token, node type, label,
// detail) in the Result's already-deterministic order.
func writeBreachSummary(w io.Writer, result policy.Result) {
	fmt.Fprintf(w, "policy: %d threshold breach(es) across %d asset finding(s)\n",
		len(result.CountByToken()), len(result.Breaches))

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, tc := range result.CountByToken() {
		fmt.Fprintf(tw, "  %s\t%d\n", tc.Token, tc.Count)
	}
	_ = tw.Flush()

	fmt.Fprintln(w, "Breaches:")
	tw = tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  TOKEN\tTYPE\tASSET\tDETAIL")
	for _, b := range result.Breaches {
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n", b.Token, b.NodeType, b.Label, b.Detail)
	}
	_ = tw.Flush()
}
