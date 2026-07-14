package cli

import (
	"fmt"
	"io"
	"strings"
)

// emitFlagHelp is the reusable --emit flag usage string for fs/probe.
const emitFlagHelp = "emit one format to one destination as format=dest " +
	"(format: table, cbom, report, report-json; dest: a file path, or - for " +
	"stdout). Repeatable: one scan feeds every requested output. Mutually " +
	"exclusive with --format/--output."

// emitTarget is one resolved --emit request: a validated output format and the
// destination it is written to. dest == "" means stdout (the spec's "-"),
// otherwise it is a file path — the same convention writeToDest already uses for
// --output, so a target routes straight through it.
type emitTarget struct {
	format string // normalized: table | cbom | report | report-json
	dest   string // "" = stdout ("-"); otherwise a file path
}

// parseEmitSpec parses one `format=dest` --emit value. The split is on the FIRST
// '=' so a destination path may itself contain '='. The format is validated
// against scanFormats and the destination must be non-empty ("-" selects stdout,
// stored as ""). Every failure is a usage error (mapped to exit 1) with a message
// that names the offending spec and the valid formats.
func parseEmitSpec(spec string) (emitTarget, error) {
	i := strings.IndexByte(spec, '=')
	if i < 0 {
		return emitTarget{}, fmt.Errorf("invalid --emit %q: want format=dest (e.g. cbom=cbom.json or report=-)", spec)
	}
	rawFormat, dest := spec[:i], spec[i+1:]
	format := strings.ToLower(strings.TrimSpace(rawFormat))
	switch format {
	case formatTable, formatCBOM, formatReport, formatReportJSON:
	default:
		return emitTarget{}, fmt.Errorf("invalid --emit %q: unknown format %q, want one of %s", spec, rawFormat, strings.Join(scanFormats, ", "))
	}
	if dest == "" {
		return emitTarget{}, fmt.Errorf("invalid --emit %q: empty destination (use - for stdout or a file path)", spec)
	}
	if dest == "-" {
		dest = ""
	}
	return emitTarget{format: format, dest: dest}, nil
}

// resolveEmitTargets parses every --emit spec into an ordered target list and
// enforces the coherence rules that make a single-scan multi-output run safe:
//
//   - the same format may not be emitted twice (a plain typo, and ambiguous);
//   - at most ONE emit may target stdout ("-"), since two stdout writers would
//     interleave into unusable output;
//   - --quiet only shapes the human `table` summary, so it is allowed with
//     --emit only when the SOLE emit is table (matching --quiet's rule for
//     --format: it is a usage error alongside any machine format).
//
// Targets are returned in the order given so emit ordering is deterministic. Any
// violation is a usage error (exit 1).
func resolveEmitTargets(specs []string, quiet bool) ([]emitTarget, error) {
	targets := make([]emitTarget, 0, len(specs))
	seenFormat := map[string]bool{}
	stdoutUsed := false
	for _, spec := range specs {
		t, err := parseEmitSpec(spec)
		if err != nil {
			return nil, err
		}
		if seenFormat[t.format] {
			return nil, fmt.Errorf("--emit %s: format %q already requested; each format may be emitted at most once", spec, t.format)
		}
		seenFormat[t.format] = true
		if t.dest == "" {
			if stdoutUsed {
				return nil, fmt.Errorf("--emit %s: more than one emit targets stdout (-); at most one emit may write to stdout", spec)
			}
			stdoutUsed = true
		}
		targets = append(targets, t)
	}
	if quiet && (len(targets) != 1 || targets[0].format != formatTable) {
		return nil, fmt.Errorf("--quiet with --emit is only allowed when the sole emit is table (it shapes only the human summary)")
	}
	return targets, nil
}

// resolveOutputTargets resolves the output target set shared by the fs and probe
// commands from the two mutually exclusive selection modes:
//
//   - --emit format=dest (repeatable): one scan feeds every target. When any
//     --emit is present, combining it with an explicitly set --format or --output
//     is a usage error (they specify format+dest twice, ambiguously).
//   - --format (+ --output): the pre-existing single-output behaviour, used when
//     no --emit is given. --quiet is validated against the chosen format exactly
//     as before, and --output "" means stdout.
//
// formatSet/outputSet report whether the user explicitly set those flags (cobra's
// Changed), so their defaults don't spuriously trip the mutual-exclusion check.
func resolveOutputTargets(emit []string, format, output string, quiet, formatSet, outputSet bool) ([]emitTarget, error) {
	if len(emit) > 0 {
		if formatSet || outputSet {
			return nil, fmt.Errorf("--emit cannot be combined with --format/--output; --emit already specifies format=dest")
		}
		return resolveEmitTargets(emit, quiet)
	}
	f, err := normalizeScanFormat(format)
	if err != nil {
		return nil, err
	}
	if err := checkQuietFormat(f, quiet); err != nil {
		return nil, err
	}
	return []emitTarget{{format: f, dest: output}}, nil
}

// needScore reports whether the PQC exposure must be computed for this run: the
// gate needs it, or at least one target is a machine format (the human `table`
// summary derives its interim flags directly from findings and never needs it).
func needScore(targets []emitTarget, gate bool) bool {
	if gate {
		return true
	}
	for _, t := range targets {
		if t.format != formatTable {
			return true
		}
	}
	return false
}

// writeEmitTargets writes every resolved emit target from ONE already-built graph
// by calling emitOne(w, format) into each target's destination. Each target is
// routed through writeToDest so it shares the stdout/file handling and the
// broken-pipe swallow on a "-" (stdout) target. A file-write failure stops the
// run and surfaces as a real error (exit 1); the caller has already scanned and
// scored once, so no output is recomputed per target.
func writeEmitTargets(stdout io.Writer, targets []emitTarget, emitOne func(w io.Writer, format string) error) error {
	for _, t := range targets {
		t := t
		if err := writeToDest(stdout, t.dest, func(w io.Writer) error {
			return emitOne(w, t.format)
		}); err != nil {
			return err
		}
	}
	return nil
}
