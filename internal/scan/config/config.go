// Package config is the Phase 1 server-config scanner for cryptoscan. It walks
// a corpus/filesystem root and, for every recognised server-config file, emits
// a deterministic, line-level-provable Finding (internal/scan) plus, on demand,
// the corresponding ConfigFile nodes and `references` edges in the graph
// (internal/graph, DESIGN.md §1).
//
// # Formats
//
// Five formats are parsed, each by a real tokenizer/line parser that records
// directive line numbers — never a regex over the whole file (CLAUDE.md
// principle: "proper directive parsing, not regex soup"):
//
//   - nginx      (class tls_config): nested {}-blocks, ';'-terminated
//     directives, '#' comments, quoted strings. Extracts ssl_protocols (union
//     across server blocks), ssl_ciphers (':'-split), ssl_certificate /
//     ssl_certificate_key refs, and notes `include` (included files are NOT
//     merged; each is scanned as its own asset).
//   - apache     (class tls_config): line directives + <VirtualHost> containers,
//     '\'-continuation, '#' comments. SSLProtocol is resolved with Apache 2.4
//     all/+/- semantics (see resolveApacheProtocols); SSLCipherSuite is
//     ':'-split; SSLCertificateFile refs are collected. Union across vhosts.
//   - sshd_config (class ssh_config): case-insensitive keyword-argument lines,
//     '#' comments. HostKey -> host_key_refs (verbatim) + host_key_types
//     (derived from ssh_host_<type>_key stems); KexAlgorithms/Ciphers/MACs are
//     ','-split into kex_algorithms/ciphers/macs. Absent keywords omit attrs.
//     Detection is guarded against prose/source false positives (see sshd.go):
//     a crypto directive counts only when its value parses under that
//     directive's grammar — HostKey a single path-like token containing a
//     separator, the algorithm lists a single comma-separated argument of ssh
//     algorithm-name tokens (charset A-Za-z0-9@.-+=) — AND the file exhibits at
//     least two DISTINCT sshd_config keywords from the full sshd_config(5)
//     vocabulary (Port, ListenAddress, Subsystem, ...), not merely a crypto
//     keyword echoed in a sentence or a struct field.
//   - openssl.cnf (class tls_config): INI sections, key = value. MinProtocol ->
//     min_protocol, CipherString -> cipher_string (exact scalars). Detection is
//     guarded (see openssl.go): the file must have a real `[section]` header,
//     the MinProtocol/CipherString assignment must sit in a section reachable
//     from an `openssl_conf` root key via the section-name pointer chain, and a
//     MinProtocol value must be an unquoted protocol token (SSLv3/TLSv1[.1-3]/
//     DTLSv1[.2]). A `.gitconfig` `[tls]` block nothing points at, or a Python
//     `class TLS:` body (no section header, quoted value), is rejected.
//   - haproxy    (class tls_config): sections + line directives.
//     ssl-default-bind-options (no-tlsv1x subtract from the TLSv1..TLSv1.3
//     base), optional ssl-min-ver, ssl-default-bind-ciphers (':'-split),
//     `bind ... ssl crt <path>` -> cert_refs (deduped).
//
// # Deterministic, content-based detection (principle 1)
//
// A file is reported as class X only if it (a) parses structurally as that
// format AND (b) contains at least one recognised crypto-relevant directive as
// an ACTIVE (non-comment) directive. The signature directives of the five
// formats are mutually exclusive by spelling — nginx uses lower_snake ssl_*,
// Apache uses SSLProtocol/SSLCipherSuite/SSLCertificateFile, sshd uses
// HostKey/KexAlgorithms/Ciphers/MACs, openssl uses MinProtocol/CipherString,
// haproxy uses ssl-default-bind-*/`bind ... ssl crt` — so at most one parser
// claims a given file. Should two ever claim the same file (a detection bug),
// the tie is resolved deterministically by the fixed priority order in
// parsers (nginx, apache, sshd, openssl, haproxy). Files with no active crypto
// directive (e.g. an nginx config whose ssl_* lines are all commented), and
// non-config files (PEM/DER/JSON/Python/Markdown), satisfy no parser and yield
// nothing. Binary files (a NUL byte in the head) are skipped outright.
//
// # Graph handoff
//
// ScanIntoGraph upserts one ConfigFile node per recognised file (id via
// graph.FileNodeID of the on-disk path; carrying format, the extracted
// directives with per-directive line provenance, and — as the node's Attrs — the
// SAME resolved values the file's Finding exposes, from one computed source, so
// downstream consumers read resolved config state off the node instead of
// re-deriving it) and, for every certificate or key path reference, emits a
// `references` edge ConfigFile -> ConfigFile-node-of-the-referenced-file. Relative refs are resolved against the config file's
// own directory and cleaned to a corpus-root-relative path; absolute refs
// (e.g. /etc/ssh/ssh_host_rsa_key) are kept as written. The integration owner
// later joins these referenced-file nodes to Certificate nodes
// (references -> Certificate) using the resolved path + line provenance.
//
// The package depends only on the standard library and internal/graph +
// internal/scan, and never panics: malformed input is skipped silently and the
// walk continues (CLAUDE.md: no panics on malformed input, ever).
package config

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/Ubermm/cryptoscan/internal/graph"
	"github.com/Ubermm/cryptoscan/internal/scan"
)

// maxConfigSize caps the bytes a single file may have before it is skipped, so
// a pathological input can never exhaust memory during a walk. It is the shared
// scan.MaxFileSize (8 MiB), identical to the certs scanner's ceiling.
const maxConfigSize = scan.MaxFileSize

func init() { scan.Register(New()) }

// Scanner is the server-config scanner. It implements scan.Scanner.
type Scanner struct{}

// New returns a ready-to-use config Scanner.
func New() Scanner { return Scanner{} }

// Name implements scan.Scanner.
func (Scanner) Name() string { return "config" }

// Scan implements scan.Scanner: it walks root and returns one Finding per
// recognised config file. It returns an operational error only when root itself
// cannot be accessed; unreadable or malformed individual files are skipped.
func (Scanner) Scan(root string) ([]scan.Finding, error) {
	hits, err := walk(root)
	if err != nil {
		return nil, err
	}
	out := make([]scan.Finding, 0, len(hits))
	for _, h := range hits {
		out = append(out, h.finding())
	}
	return out, nil
}

// ScanIntoGraph walks root, returns the same Findings as Scan, and additionally
// populates g with a ConfigFile node per recognised file and a `references`
// edge for every certificate/key path reference (see the package doc for the
// handoff contract). It returns an operational error only for an inaccessible
// root or a nil graph.
func ScanIntoGraph(root string, g *graph.Graph) ([]scan.Finding, error) {
	if g == nil {
		return nil, fmt.Errorf("config: nil graph")
	}
	hits, err := walk(root)
	if err != nil {
		return nil, err
	}
	out := make([]scan.Finding, 0, len(hits))
	for _, h := range hits {
		out = append(out, h.finding())
		populate(root, h, g)
	}
	return out, nil
}

// pathRef is a certificate/key file reference discovered in a directive, with
// its verbatim value, the line it appeared on, and the directive that carried
// it (used as edge provenance detail and to decide the cert_refs attr).
type pathRef struct {
	raw  string
	line int
	kind string
}

// parseResult is what a format parser returns when it claims a file: the
// detected format/class, the manifest-shaped attrs, the directives of interest
// (with line numbers) for the graph node, and every cert/key ref for edges.
type parseResult struct {
	format     string
	class      string
	attrs      map[string]any
	directives []graph.Directive
	refs       []pathRef
}

// parsers is the fixed-priority detection order. Signatures are mutually
// exclusive, so the order only matters as a documented tie-break.
var parsers = []struct {
	name string
	fn   func(string) *parseResult
}{
	{"nginx", parseNginx},
	{"apache", parseApache},
	{"sshd", parseSSHD},
	{"openssl", parseOpenSSL},
	{"haproxy", parseHAProxy},
}

// hit is one recognised file: its parse result, corpus-root-relative path
// (forward slashes), and on-disk path (for node IDs / ref resolution).
type hit struct {
	res  *parseResult
	rel  string
	disk string
}

// walk visits every file under root and collects the recognised ones. A missing
// or unreadable root is an operational error; per-file errors are skipped so a
// single bad file never aborts the walk.
func walk(root string) ([]hit, error) {
	if _, err := os.Stat(root); err != nil {
		return nil, fmt.Errorf("config: cannot access root %q: %w", root, err)
	}

	var hits []hit
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil // skip unreadable entry, keep walking
		}
		if d.IsDir() {
			return nil
		}
		res := detectFile(p)
		if res == nil {
			return nil
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			rel = p
		}
		hits = append(hits, hit{res: res, rel: filepath.ToSlash(rel), disk: p})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("config: walk %q: %w", root, err)
	}
	return hits, nil
}

// detectFile reads a file and runs content-based detection. Unreadable, oversize
// and binary files return nil (skip).
func detectFile(p string) *parseResult {
	data, err := os.ReadFile(p) //nolint:gosec // corpus path is developer-controlled
	if err != nil || len(data) == 0 || len(data) > maxConfigSize {
		return nil
	}
	if isBinary(data) {
		return nil
	}
	return detect(string(data))
}

// detect returns the first format that claims text (priority order), or nil.
func detect(text string) *parseResult {
	for _, pr := range parsers {
		if res := pr.fn(text); res != nil {
			return res
		}
	}
	return nil
}

// isBinary reports whether data looks non-textual: a NUL byte in the first 8 KiB
// is a reliable, deterministic signal that a file is not a text config.
func isBinary(data []byte) bool {
	head := data
	if len(head) > 8192 {
		head = head[:8192]
	}
	for _, b := range head {
		if b == 0 {
			return true
		}
	}
	return false
}

// finding projects a hit into a scan.Finding, attaching one Provenance record
// per directive of interest (config source, file location, directive line).
func (h hit) finding() scan.Finding {
	prov := make([]graph.Provenance, 0, len(h.res.directives))
	for _, d := range h.res.directives {
		prov = append(prov, graph.Provenance{
			Source:   graph.SourceConfig,
			Location: h.rel,
			Line:     d.Line,
			Detail:   d.Name,
		})
	}
	if len(prov) == 0 {
		prov = append(prov, graph.Provenance{Source: graph.SourceConfig, Location: h.rel})
	}
	return scan.Finding{
		Class:      h.res.class,
		Path:       h.rel,
		Attrs:      h.res.attrs,
		Provenance: prov,
	}
}

// populate upserts the ConfigFile node for a hit and a `references` edge for
// each cert/key ref. Any per-node/edge error is swallowed (robustness): the
// graph is best-effort, the Findings are the scored contract.
func populate(root string, h hit, g *graph.Graph) {
	fromID, err := graph.FileNodeID(h.disk)
	if err != nil {
		return
	}
	node := &graph.ConfigFileNode{
		Path:       h.rel,
		Format:     h.res.format,
		Directives: h.res.directives,
		Attrs:      h.res.attrs,
	}
	node.NodeID = fromID
	for _, d := range h.res.directives {
		node.AddProvenance(graph.Provenance{
			Source:   graph.SourceConfig,
			Location: h.rel,
			Line:     d.Line,
			Detail:   d.Name,
		})
	}
	if _, err := g.UpsertNode(node); err != nil {
		return
	}

	for _, ref := range h.res.refs {
		toID, toRel, ok := resolveRef(root, h.disk, ref.raw)
		if !ok {
			continue
		}
		target := &graph.ConfigFileNode{Path: toRel}
		target.NodeID = toID
		target.AddProvenance(graph.Provenance{
			Source:   graph.SourceConfig,
			Location: h.rel,
			Line:     ref.line,
			Detail:   "referenced by " + ref.kind,
		})
		if _, err := g.UpsertNode(target); err != nil {
			continue
		}
		_, _ = g.AddEdge(graph.Edge{
			Type: graph.EdgeReferences,
			From: fromID,
			To:   toID,
			Provenance: []graph.Provenance{{
				Source:   graph.SourceConfig,
				Location: h.rel,
				Line:     ref.line,
				Detail:   ref.kind,
			}},
		})
	}
}

// resolveRef turns a raw cert/key reference into a target ConfigFile node ID and
// a display path. Relative refs are resolved against the config file's own
// directory and, when they stay under root, cleaned to a corpus-root-relative
// forward-slash path (configs/nginx/legacy.conf + "../../certs/x.pem" ->
// certs/x.pem). Absolute refs are kept verbatim as the display path. ok is
// false only when a stable node ID cannot be built.
func resolveRef(root, configDisk, raw string) (id, rel string, ok bool) {
	native := filepath.FromSlash(raw)
	if filepath.IsAbs(native) || isAbsPosix(raw) {
		nid, err := graph.FileNodeID(raw)
		if err != nil {
			return "", "", false
		}
		return nid, raw, true
	}

	targetDisk := filepath.Join(filepath.Dir(configDisk), native)
	nid, err := graph.FileNodeID(targetDisk)
	if err != nil {
		return "", "", false
	}
	display := raw
	if r, rerr := filepath.Rel(root, targetDisk); rerr == nil {
		slash := filepath.ToSlash(r)
		if !isEscaping(slash) {
			display = slash
		}
	}
	return nid, display, true
}

// isAbsPosix reports whether raw is an absolute POSIX path (leading '/'), which
// filepath.IsAbs does not recognise on Windows.
func isAbsPosix(raw string) bool {
	return len(raw) > 0 && raw[0] == '/'
}

// isEscaping reports whether a relative path climbs above its base.
func isEscaping(slash string) bool {
	return slash == ".." || len(slash) >= 3 && slash[:3] == "../"
}
