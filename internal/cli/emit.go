package cli

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/cryptoscan/cryptoscan/internal/graph"
	"github.com/cryptoscan/cryptoscan/internal/output/cbom"
	"github.com/cryptoscan/cryptoscan/internal/output/report"
	"github.com/cryptoscan/cryptoscan/internal/pqc"
)

// Output-format tokens shared by the `fs` and `probe` commands. `table` is each
// command's existing interim human summary; the other three are the Phase 3
// standards-native / auditor projections of the scanned graph.
const (
	formatTable      = "table"
	formatCBOM       = "cbom"
	formatReport     = "report"
	formatReportJSON = "report-json"
)

// scanFormats lists the accepted --format values in help/error order.
var scanFormats = []string{formatTable, formatCBOM, formatReport, formatReportJSON}

// scanFormatHelp is the reusable --format flag usage string for fs/probe.
const scanFormatHelp = "output format: table, cbom, report, or report-json"

// normalizeScanFormat lower-cases and trims a --format value and validates it
// against scanFormats. An unknown value is a usage error (mapped to exit 1).
func normalizeScanFormat(format string) (string, error) {
	f := strings.ToLower(strings.TrimSpace(format))
	switch f {
	case formatTable, formatCBOM, formatReport, formatReportJSON:
		return f, nil
	default:
		return "", fmt.Errorf("unknown --format %q: want one of %s", format, strings.Join(scanFormats, ", "))
	}
}

// checkQuietFormat enforces the documented rule that --quiet only shapes the
// `table` summary. Combining it with a machine format is a usage error rather
// than a silently ignored flag, so callers get an explicit signal.
func checkQuietFormat(format string, quiet bool) error {
	if quiet && format != formatTable {
		return fmt.Errorf("--quiet only applies to --format table, not --format %s", format)
	}
	return nil
}

// emitGraphOutput writes the machine-format projection (cbom | report |
// report-json) of g to w. It is the single place the CLI supplies the REAL
// clock: `now` is passed to pqc.Score AND into each emitter's injectable Options
// (cbom Timestamp, report Now) so the libraries stay clock-free for tests while
// the command provides wall time. The CBOM serial is left to the emitter's
// deterministic content-based default (Options.SerialNumber unset).
func emitGraphOutput(w io.Writer, g *graph.Graph, format string, now time.Time) error {
	exposure := pqc.Score(g, now)
	switch format {
	case formatCBOM:
		return cbom.Write(w, g, exposure, cbom.Options{Timestamp: now})
	case formatReport:
		return report.WriteMarkdown(w, g, exposure, report.Options{Now: now})
	case formatReportJSON:
		return report.WriteJSON(w, g, exposure, report.Options{Now: now})
	default:
		return fmt.Errorf("internal error: emitGraphOutput called with format %q", format)
	}
}

// writeToDest runs fn against stdout, or against a freshly created --output file
// that is closed afterwards. A create failure, the fn's own write error, or a
// close failure are each wrapped (mapped to exit 1); fn's error takes priority
// so a write failure is not masked by a successful close.
//
// One write error is deliberately NOT fatal: when writing to stdout and the
// reader on the other end of the pipe (head, less, jq, ...) closes early, fn
// returns a broken-pipe error. Like standard Unix tools, that is swallowed —
// writeToDest returns nil (exit 0) with nothing printed. Every other write error
// (disk full, an unwritable --output file, ...) still surfaces as a real error.
func writeToDest(stdout io.Writer, output string, fn func(io.Writer) error) error {
	if output == "" {
		if err := fn(stdout); err != nil {
			if isBrokenPipe(err) {
				return nil
			}
			return err
		}
		return nil
	}
	file, err := os.Create(output)
	if err != nil {
		return fmt.Errorf("creating output file %q: %w", output, err)
	}
	writeErr := fn(file)
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return fmt.Errorf("closing output file %q: %w", output, closeErr)
	}
	return nil
}
