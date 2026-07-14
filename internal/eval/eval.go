// Package eval matches scanner Findings against the ground-truth corpus and
// scores them into a per-asset-class precision/recall/F1 scorecard
// (DESIGN.md §2 matching semantics, §3 TP/FN/FP definitions and the ship gate).
//
// It is a pure library: no filesystem access, no process exit. cmd/eval wires
// the loader and scanners to it and renders the result. The package depends
// only on the standard library, internal/corpus, and internal/scan, and never
// panics — malformed expectations surface as errors.
package eval

import (
	"fmt"
	"math"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/Ubermm/cryptoscan/internal/corpus"
	"github.com/Ubermm/cryptoscan/internal/scan"
)

// precisionGate is the ship gate: no class with declared assets may score below
// this precision (DESIGN.md §3, CLAUDE.md "Definition of done").
const precisionGate = 0.95

// classAcc accumulates the per-class TP/FP/FN tallies during scoring.
type classAcc struct {
	expected, found, tp, fp, fn int
}

// Mismatch records one declared expectation that a matched finding failed to
// satisfy. It turns an otherwise-located asset into a false negative
// (DESIGN.md §3).
type Mismatch struct {
	Key      string `json:"key"`
	Expected string `json:"expected"`
	Got      string `json:"got"`
}

// FalsePositive is a scanner finding at a (class, path[, alias]) not declared in
// any fragment — including anything at all under negatives/ (DESIGN.md §3).
type FalsePositive struct {
	Class  string `json:"class"`
	Path   string `json:"path"`
	Alias  string `json:"alias,omitempty"`
	Detail string `json:"detail"`
}

// FalseNegative is a declared asset that was not found, or was found with one or
// more mismatched fields. Mismatches is empty for a not-found asset.
type FalseNegative struct {
	ID         string     `json:"id"`
	Class      string     `json:"class"`
	Path       string     `json:"path"`
	Alias      string     `json:"alias,omitempty"`
	Mismatches []Mismatch `json:"mismatches,omitempty"`
}

// NotFound reports whether this false negative was never located (as opposed to
// located with a field mismatch).
func (fn FalseNegative) NotFound() bool { return len(fn.Mismatches) == 0 }

// ClassScore is the scorecard row for one asset class.
type ClassScore struct {
	Class     string  `json:"class"`
	Expected  int     `json:"expected"`
	Found     int     `json:"found"` // raw findings the scanner emitted for this class
	TP        int     `json:"tp"`
	FP        int     `json:"fp"`
	FN        int     `json:"fn"`
	Precision float64 `json:"precision"`
	Recall    float64 `json:"recall"`
	F1        float64 `json:"f1"`
}

// Totals is the aggregate (micro-averaged) row across all classes.
type Totals struct {
	Expected  int     `json:"expected"`
	Found     int     `json:"found"`
	TP        int     `json:"tp"`
	FP        int     `json:"fp"`
	FN        int     `json:"fn"`
	Precision float64 `json:"precision"`
	Recall    float64 `json:"recall"`
	F1        float64 `json:"f1"`
}

// Gate is the ship-gate verdict (DESIGN.md §3).
type Gate struct {
	Strict              bool     `json:"strict"`
	Pass                bool     `json:"pass"`
	PrecisionViolations []string `json:"precision_violations,omitempty"`
	RecallShortfalls    []string `json:"recall_shortfalls,omitempty"`
}

// Scorecard is the full evaluation result: per-class rows, totals, the detailed
// FP/FN lists, and the gate verdict. All slices are deterministically ordered.
type Scorecard struct {
	Corpus         string          `json:"corpus"`
	Classes        []ClassScore    `json:"classes"`
	Totals         Totals          `json:"totals"`
	FalsePositives []FalsePositive `json:"false_positives"`
	FalseNegatives []FalseNegative `json:"false_negatives"`
	Gate           Gate            `json:"gate"`
}

// normPath canonicalises a corpus-relative path for comparison: backslashes to
// forward slashes, path.Clean, leading "./" stripped, and lower-cased so
// matching is case-insensitive (Windows-safe, DESIGN.md §3 note).
func normPath(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	p = path.Clean(p)
	p = strings.TrimPrefix(p, "./")
	return strings.ToLower(p)
}

// matchKey identifies a declared asset / finding slot by class, normalized path,
// and alias.
func matchKey(class, p, alias string) string {
	return class + "\x00" + normPath(p) + "\x00" + alias
}

// EndpointClass is the scorecard class name for per-endpoint (ConfigEndpoint)
// attribution, scored separately from the file-level tls_config class.
const EndpointClass = "tls_config_endpoint"

// EmittedEndpoint is one ConfigEndpoint node projected for scoring: the config
// file it belongs to, its identity (server names, listen, port), and its resolved
// Attrs (protocols, ciphers, cert_refs, dhparam, ecdh_curve, ...). cmd/eval builds
// these from the graph so the eval package stays free of a graph dependency.
type EmittedEndpoint struct {
	File        string
	ServerNames []string
	Listen      string
	Port        int
	Attrs       map[string]any
}

// Score matches findings against the corpus and computes the scorecard. It is the
// file-level entry point (no per-endpoint scoring); ScoreAll folds in
// ConfigEndpoint attribution. strict controls only the gate (recall shortfalls
// gate iff strict); the counts are identical either way. It returns an error for
// malformed expectations or a corpus that declares the same (class, path, alias)
// slot twice.
func Score(c *corpus.Corpus, findings []scan.Finding, strict bool) (*Scorecard, error) {
	return ScoreAll(c, findings, nil, strict)
}

// ScoreAll is Score plus per-endpoint scoring: emitted ConfigEndpoint nodes are
// matched against the endpoints:[] ground truth declared on tls_config assets and
// tallied as the EndpointClass row (its own TP/FP/FN, precision/recall/F1, and it
// participates in the ship gate). The file-level classes are scored exactly as
// Score does. A nil emitted slice yields no EndpointClass row (identical to Score).
func ScoreAll(c *corpus.Corpus, findings []scan.Finding, emitted []EmittedEndpoint, strict bool) (*Scorecard, error) {
	if c == nil {
		return nil, fmt.Errorf("eval: nil corpus")
	}

	// Index declared assets by match key; reject ambiguous duplicate slots.
	assetByKey := make(map[string]*corpus.Asset, len(c.Assets))
	for i := range c.Assets {
		a := &c.Assets[i]
		k := matchKey(a.Class, a.Path, a.Alias)
		if prev, dup := assetByKey[k]; dup {
			return nil, fmt.Errorf("eval: assets %q and %q declare the same (class=%s, path=%s, alias=%q) slot",
				prev.ID, a.ID, a.Class, normPath(a.Path), a.Alias)
		}
		assetByKey[k] = a
	}

	// Negative paths (normalized) for id lookup in FP detail.
	negByPath := make(map[string]string, len(c.Negatives))
	for _, n := range c.Negatives {
		negByPath[normPath(n.Path)] = n.ID
	}

	// Per-class accumulators. classes tracks every class that has either a
	// declared asset or an emitted finding, so FP-only classes still show up.
	classes := map[string]*classAcc{}
	get := func(class string) *classAcc {
		a := classes[class]
		if a == nil {
			a = &classAcc{}
			classes[class] = a
		}
		return a
	}
	for i := range c.Assets {
		get(c.Assets[i].Class).expected++
	}

	// Per-asset outcome (keyed by asset ID).
	assetFound := map[string]bool{}
	assetMismatch := map[string][]Mismatch{}

	var fps []FalsePositive

	for _, f := range findings {
		np := normPath(f.Path)
		ca := get(f.Class)
		ca.found++

		// Anything at all under negatives/ is a false positive (DESIGN.md §3).
		if np == "negatives" || strings.HasPrefix(np, "negatives/") {
			detail := "under negatives/"
			if id := negByPath[np]; id != "" {
				detail = "under negatives/ (" + id + ")"
			}
			ca.fp++
			fps = append(fps, FalsePositive{Class: f.Class, Path: np, Alias: f.Alias, Detail: detail})
			continue
		}

		k := matchKey(f.Class, f.Path, f.Alias)
		asset, ok := assetByKey[k]
		if !ok {
			ca.fp++
			fps = append(fps, FalsePositive{Class: f.Class, Path: np, Alias: f.Alias, Detail: "undeclared (class, path, alias)"})
			continue
		}

		// Declared slot located. The first finding for a slot determines its
		// outcome; extra findings for the same slot are the same declared asset
		// and are neither TP nor FP (deduped).
		if assetFound[asset.ID] {
			continue
		}
		assetFound[asset.ID] = true
		mm, err := checkExpect(asset.Expect, f.Attrs)
		if err != nil {
			return nil, fmt.Errorf("eval: asset %q: %w", asset.ID, err)
		}
		if len(mm) > 0 {
			assetMismatch[asset.ID] = mm
		}
	}

	// Resolve each declared asset into TP / FN.
	var fns []FalseNegative
	for i := range c.Assets {
		a := &c.Assets[i]
		ca := get(a.Class)
		switch {
		case !assetFound[a.ID]:
			ca.fn++
			fns = append(fns, FalseNegative{ID: a.ID, Class: a.Class, Path: normPath(a.Path), Alias: a.Alias})
		case len(assetMismatch[a.ID]) > 0:
			ca.fn++
			fns = append(fns, FalseNegative{ID: a.ID, Class: a.Class, Path: normPath(a.Path), Alias: a.Alias, Mismatches: assetMismatch[a.ID]})
		default:
			ca.tp++
		}
	}

	// Per-endpoint (ConfigEndpoint) scoring as its own EndpointClass row. Only
	// evaluated when there are declared or emitted endpoints, so the plain Score
	// path (emitted == nil, no endpoints declared) produces no extra class.
	if err := scoreEndpoints(c, emitted, get, &fps, &fns); err != nil {
		return nil, err
	}

	// Deterministic ordering of detail lists.
	sort.Slice(fps, func(i, j int) bool {
		if fps[i].Class != fps[j].Class {
			return fps[i].Class < fps[j].Class
		}
		if fps[i].Path != fps[j].Path {
			return fps[i].Path < fps[j].Path
		}
		return fps[i].Alias < fps[j].Alias
	})
	sort.Slice(fns, func(i, j int) bool {
		if fns[i].Class != fns[j].Class {
			return fns[i].Class < fns[j].Class
		}
		return fns[i].ID < fns[j].ID
	})

	// Build sorted class rows + totals + gate.
	names := make([]string, 0, len(classes))
	for name := range classes {
		names = append(names, name)
	}
	sort.Strings(names)

	sc := &Scorecard{
		Corpus:         c.Root,
		FalsePositives: fps,
		FalseNegatives: fns,
		Gate:           Gate{Strict: strict, Pass: true},
	}

	var tot Totals
	for _, name := range names {
		a := classes[name]
		row := ClassScore{
			Class:     name,
			Expected:  a.expected,
			Found:     a.found,
			TP:        a.tp,
			FP:        a.fp,
			FN:        a.fn,
			Precision: precision(a.tp, a.fp),
			Recall:    recall(a.tp, a.expected),
			F1:        f1(precision(a.tp, a.fp), recall(a.tp, a.expected)),
		}
		sc.Classes = append(sc.Classes, row)

		tot.Expected += a.expected
		tot.Found += a.found
		tot.TP += a.tp
		tot.FP += a.fp
		tot.FN += a.fn

		// Gate only considers classes with declared assets (DESIGN.md §3).
		if a.expected > 0 {
			if row.Precision < precisionGate {
				sc.Gate.Pass = false
				sc.Gate.PrecisionViolations = append(sc.Gate.PrecisionViolations,
					fmt.Sprintf("%s precision %.3f < %.2f", name, row.Precision, precisionGate))
			}
			if strict && row.Recall < 1.0 {
				sc.Gate.RecallShortfalls = append(sc.Gate.RecallShortfalls,
					fmt.Sprintf("%s recall %.3f < 1.000", name, row.Recall))
			}
		}
	}
	tot.Precision = precision(tot.TP, tot.FP)
	tot.Recall = recall(tot.TP, tot.Expected)
	tot.F1 = f1(tot.Precision, tot.Recall)
	sc.Totals = tot

	if strict && len(sc.Gate.RecallShortfalls) > 0 {
		sc.Gate.Pass = false
	}

	return sc, nil
}

// precision returns tp/(tp+fp); with no findings at all (tp+fp==0) it is 1.0 —
// a class that made no false claims has perfect precision (documented in
// DESIGN.md §3 handling).
func precision(tp, fp int) float64 {
	if tp+fp == 0 {
		return 1.0
	}
	return float64(tp) / float64(tp+fp)
}

// recall returns tp/expected; with nothing to find (expected==0) it is 1.0.
func recall(tp, expected int) float64 {
	if expected == 0 {
		return 1.0
	}
	return float64(tp) / float64(expected)
}

func f1(p, r float64) float64 {
	if p+r == 0 {
		return 0
	}
	return 2 * p * r / (p + r)
}

// declaredEndpoint is one endpoints:[] ground-truth entry flattened with its
// owning asset's file path and a port parsed from its listen string.
type declaredEndpoint struct {
	id         string
	file       string
	serverName string
	listen     string
	port       int
	expect     corpus.Expect
}

// scoreEndpoints tallies the EndpointClass row: each declared endpoint is matched
// (by server_name+port, or by listen) against an emitted ConfigEndpoint and scored
// TP/FN on its expectations; any emitted endpoint matching no declared endpoint is
// an FP. It appends to fps/fns and updates the accumulator via get. When there are
// neither declared nor emitted endpoints it does nothing (no EndpointClass row).
func scoreEndpoints(c *corpus.Corpus, emitted []EmittedEndpoint, get func(string) *classAcc, fps *[]FalsePositive, fns *[]FalseNegative) error {
	var declared []declaredEndpoint
	for i := range c.Assets {
		a := &c.Assets[i]
		for j, ep := range a.Endpoints {
			name := ep.Name
			if name == "" {
				name = strconv.Itoa(j)
			}
			declared = append(declared, declaredEndpoint{
				id:         a.ID + "/" + name,
				file:       a.Path,
				serverName: ep.ServerName,
				listen:     ep.Listen,
				port:       parsePort(ep.Listen),
				expect:     ep.Expect,
			})
		}
	}
	if len(declared) == 0 && len(emitted) == 0 {
		return nil
	}

	ep := get(EndpointClass)
	ep.expected = len(declared)
	ep.found = len(emitted)

	consumed := make([]bool, len(emitted))
	for _, d := range declared {
		matched := -1
		for ei := range emitted {
			if consumed[ei] {
				continue
			}
			if endpointIdentityMatch(d, emitted[ei]) {
				matched = ei
				break
			}
		}
		if matched < 0 {
			ep.fn++
			*fns = append(*fns, FalseNegative{ID: d.id, Class: EndpointClass, Path: normPath(d.file)})
			continue
		}
		consumed[matched] = true
		mm, err := checkExpect(d.expect, emitted[matched].Attrs)
		if err != nil {
			return fmt.Errorf("eval: endpoint %q: %w", d.id, err)
		}
		if len(mm) > 0 {
			ep.fn++
			*fns = append(*fns, FalseNegative{ID: d.id, Class: EndpointClass, Path: normPath(d.file), Mismatches: mm})
		} else {
			ep.tp++
		}
	}

	for ei := range emitted {
		if consumed[ei] {
			continue
		}
		np := normPath(emitted[ei].File)
		detail := "undeclared config endpoint"
		if np == "negatives" || strings.HasPrefix(np, "negatives/") {
			detail = "under negatives/"
		}
		ep.fp++
		*fps = append(*fps, FalsePositive{Class: EndpointClass, Path: np, Detail: detail})
	}
	return nil
}

// endpointIdentityMatch reports whether a declared endpoint identifies the same
// server/vhost/bind as an emitted ConfigEndpoint: same file, and either a
// server_name+port match or (when neither is given) a listen-string match.
func endpointIdentityMatch(d declaredEndpoint, e EmittedEndpoint) bool {
	if normPath(d.file) != normPath(e.File) {
		return false
	}
	if d.serverName != "" && !containsFold(e.ServerNames, d.serverName) {
		return false
	}
	if d.port != 0 && e.Port != 0 && d.port != e.Port {
		return false
	}
	if d.serverName == "" && d.port == 0 {
		return d.listen != "" && d.listen == e.Listen
	}
	return true
}

// parsePort reads the numeric port after the final ':' of a listen token (or the
// whole token when it is a bare port); 0 when none is present.
func parsePort(token string) int {
	s := token
	if i := strings.LastIndex(token, ":"); i >= 0 {
		s = token[i+1:]
	}
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0
	}
	return n
}

// containsFold reports whether list contains s, case-insensitively.
func containsFold(list []string, s string) bool {
	for _, x := range list {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

// --- expectation matching (DESIGN.md §2) ---

// algorithmKeys are the scalar expect keys whose values name an algorithm and
// therefore compare case-insensitively (DESIGN.md §2).
var algorithmKeys = map[string]bool{
	"algorithm":           true,
	"signature_algorithm": true,
}

// checkExpect compares every declared expectation against the finding's Attrs
// and returns the mismatches. Only declared keys are checked; scanners may
// extract more. It returns an error only for a genuinely malformed expectation
// value (which the loader also rejects), never for an ordinary mismatch.
func checkExpect(expect corpus.Expect, attrs map[string]any) ([]Mismatch, error) {
	keys := make([]string, 0, len(expect))
	for k := range expect {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var out []Mismatch
	for _, k := range keys {
		exp := expect[k]

		subset := strings.HasSuffix(k, "_contains")
		attrKey := k
		if subset {
			attrKey = strings.TrimSuffix(k, "_contains")
		}

		got, present := attrs[attrKey]
		if !present {
			out = append(out, Mismatch{Key: k, Expected: formatVal(exp), Got: "<missing>"})
			continue
		}

		ok, err := valueMatches(k, subset, exp, got)
		if err != nil {
			return nil, err
		}
		if !ok {
			out = append(out, Mismatch{Key: k, Expected: formatVal(exp), Got: formatVal(got)})
		}
	}
	return out, nil
}

// valueMatches applies the DESIGN.md §2 rule appropriate to the value shape:
// subset for `_contains`, exact-set for lists, tolerant numeric/bool/string for
// scalars (case-insensitive for algorithm-name keys).
func valueMatches(key string, subset bool, exp, got any) (bool, error) {
	expList, expIsList := toStrList(exp)

	if subset {
		if !expIsList {
			return false, fmt.Errorf("expect key %q: `_contains` requires a list value (got %T)", key, exp)
		}
		gotList, ok := toStrList(got)
		if !ok {
			return false, nil // scalar where a list was needed → mismatch, not error
		}
		return isSubset(expList, gotList), nil
	}

	if expIsList {
		gotList, ok := toStrList(got)
		if !ok {
			return false, nil
		}
		return sameSet(expList, gotList), nil
	}

	// Scalar. Numeric compare tolerant of int/float YAML decoding.
	if ef, eok := toFloat(exp); eok {
		if gf, gok := toFloat(got); gok {
			return ef == gf, nil
		}
		return false, nil
	}
	if eb, eok := exp.(bool); eok {
		gb, gok := got.(bool)
		return gok && eb == gb, nil
	}
	es, gs := fmt.Sprintf("%v", exp), fmt.Sprintf("%v", got)
	if algorithmKeys[key] {
		return strings.EqualFold(es, gs), nil
	}
	return es == gs, nil
}

func isSubset(want, have []string) bool {
	set := make(map[string]bool, len(have))
	for _, h := range have {
		set[h] = true
	}
	for _, w := range want {
		if !set[w] {
			return false
		}
	}
	return true
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	ca := map[string]int{}
	for _, x := range a {
		ca[x]++
	}
	for _, x := range b {
		ca[x]--
		if ca[x] < 0 {
			return false
		}
	}
	for _, n := range ca {
		if n != 0 {
			return false
		}
	}
	return true
}

// toFloat reports v as a float64 when it is any numeric type (YAML decodes ints
// as int and floats as float64; findings may use either).
func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case int:
		return float64(n), true
	case int8:
		return float64(n), true
	case int16:
		return float64(n), true
	case int32:
		return float64(n), true
	case int64:
		return float64(n), true
	case uint:
		return float64(n), true
	case uint8:
		return float64(n), true
	case uint16:
		return float64(n), true
	case uint32:
		return float64(n), true
	case uint64:
		return float64(n), true
	case float32:
		return float64(n), true
	case float64:
		if math.IsNaN(n) || math.IsInf(n, 0) {
			return 0, false
		}
		return n, true
	default:
		return 0, false
	}
}

// toStrList converts a list value ([]any or []string) to []string, rendering
// each element with fmt. Non-list values return ok=false.
func toStrList(v any) ([]string, bool) {
	switch l := v.(type) {
	case []string:
		return append([]string(nil), l...), true
	case []any:
		out := make([]string, len(l))
		for i, e := range l {
			out[i] = fmt.Sprintf("%v", e)
		}
		return out, true
	default:
		return nil, false
	}
}

// formatVal renders an expectation or extracted value for the mismatch report.
// Lists are sorted for stable output; scalars use their natural form.
func formatVal(v any) string {
	if l, ok := toStrList(v); ok {
		s := append([]string(nil), l...)
		sort.Strings(s)
		return "[" + strings.Join(s, ", ") + "]"
	}
	if b, ok := v.(bool); ok {
		return strconv.FormatBool(b)
	}
	return fmt.Sprintf("%v", v)
}
