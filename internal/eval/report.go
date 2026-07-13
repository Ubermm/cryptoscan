package eval

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

// WriteJSON renders the scorecard as indented JSON.
func (sc *Scorecard) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(sc); err != nil {
		return fmt.Errorf("eval: encode json: %w", err)
	}
	return nil
}

// WriteTable renders the aligned scorecard table: a per-class row, a totals row,
// the PASS/FAIL gate line, and the detailed false-positive / false-negative
// (mismatch and not-found) listings. Output ordering is fully deterministic.
func (sc *Scorecard) WriteTable(w io.Writer) error {
	var b strings.Builder

	b.WriteString("cryptoscan eval scorecard\n")
	corpus := sc.Corpus
	if corpus == "" {
		corpus = "(none)"
	}
	fmt.Fprintf(&b, "corpus: %s\n\n", corpus)

	tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "CLASS\tEXPECTED\tFOUND\tTP\tFP\tFN\tPRECISION\tRECALL\tF1")
	for _, r := range sc.Classes {
		fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%d\t%d\t%.3f\t%.3f\t%.3f\n",
			r.Class, r.Expected, r.Found, r.TP, r.FP, r.FN, r.Precision, r.Recall, r.F1)
	}
	t := sc.Totals
	fmt.Fprintf(tw, "TOTAL\t%d\t%d\t%d\t%d\t%d\t%.3f\t%.3f\t%.3f\n",
		t.Expected, t.Found, t.TP, t.FP, t.FN, t.Precision, t.Recall, t.F1)
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("eval: render table: %w", err)
	}

	b.WriteString("\n")
	b.WriteString(sc.gateLine())
	b.WriteString("\n")

	// False positives.
	b.WriteString("\nFalse positives:\n")
	if len(sc.FalsePositives) == 0 {
		b.WriteString("  (none)\n")
	} else {
		for _, fp := range sc.FalsePositives {
			loc := fp.Path
			if fp.Alias != "" {
				loc += " [alias=" + fp.Alias + "]"
			}
			fmt.Fprintf(&b, "  %s  %s  %s\n", fp.Class, loc, fp.Detail)
		}
	}

	// Field mismatches (located but wrong).
	var mismatches, notFound []FalseNegative
	for _, fn := range sc.FalseNegatives {
		if fn.NotFound() {
			notFound = append(notFound, fn)
		} else {
			mismatches = append(mismatches, fn)
		}
	}

	b.WriteString("\nField mismatches (false negatives):\n")
	if len(mismatches) == 0 {
		b.WriteString("  (none)\n")
	} else {
		for _, fn := range mismatches {
			loc := fn.Path
			if fn.Alias != "" {
				loc += " [alias=" + fn.Alias + "]"
			}
			fmt.Fprintf(&b, "  %s (%s)  %s\n", fn.ID, fn.Class, loc)
			for _, m := range fn.Mismatches {
				fmt.Fprintf(&b, "      %s: expected %s, got %s\n", m.Key, m.Expected, m.Got)
			}
		}
	}

	// Not-found declared assets (recall gaps).
	b.WriteString("\nNot found (false negatives):\n")
	if len(notFound) == 0 {
		b.WriteString("  (none)\n")
	} else {
		for _, fn := range notFound {
			loc := fn.Path
			if fn.Alias != "" {
				loc += " [alias=" + fn.Alias + "]"
			}
			fmt.Fprintf(&b, "  %s (%s)  %s\n", fn.ID, fn.Class, loc)
		}
	}

	_, err := io.WriteString(w, b.String())
	return err
}

// gateLine is the single PASS/FAIL summary line.
func (sc *Scorecard) gateLine() string {
	if sc.Gate.Pass {
		return fmt.Sprintf("GATE: PASS (>= %.2f precision on all classes with declared assets)", precisionGate)
	}
	var reasons []string
	if len(sc.Gate.PrecisionViolations) > 0 {
		reasons = append(reasons, "precision: "+strings.Join(sc.Gate.PrecisionViolations, "; "))
	}
	if len(sc.Gate.RecallShortfalls) > 0 {
		reasons = append(reasons, "recall: "+strings.Join(sc.Gate.RecallShortfalls, "; "))
	}
	return "GATE: FAIL (" + strings.Join(reasons, " | ") + ")"
}
