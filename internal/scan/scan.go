// Package scan defines the scanner-facing contract that the eval harness
// (cmd/eval) and, in later phases, the real filesystem/network scanners share.
//
// A Scanner walks a corpus root and returns a flat list of Findings. Each
// Finding is a projection of what will become graph nodes (DESIGN.md §1); the
// eval harness scores Findings against the ground-truth manifest
// (internal/corpus, DESIGN.md §2–§3). Real scanners will additionally populate
// the graph, but eval consumes Findings only.
//
// The package depends only on the standard library and internal/graph, and it
// never panics: registration is defensive and returns via the registry rather
// than crashing on bad input.
package scan

import (
	"sort"
	"sync"

	"github.com/Ubermm/cryptoscan/internal/graph"
)

// MaxFileSize is the shared per-file byte cap every filesystem scanner applies
// before reading a candidate file. Any regular file larger than this is skipped
// deterministically (never read into memory), so a pathological input cannot
// exhaust memory during a walk. A certificate, key, CSR, keystore, or server
// config is far smaller than this; 8 MiB is a fixed, documented ceiling shared
// by the certs and config scanners so their skip behaviour is identical.
const MaxFileSize = 8 << 20 // 8 MiB

// Finding is a single cryptographic asset a scanner has proven to exist. The
// keys of Attrs line up with the manifest `expect` keys (DESIGN.md §2), so the
// eval matcher can compare them directly: algorithm, key_size, curve,
// signature_algorithm, spki_sha256, subject_cn, self_signed, expired,
// protocols, ciphers, cert_refs, host_key_types, host_key_refs,
// kex_algorithms, macs, min_protocol, cipher_string, and so on. Scanners may populate more attributes
// than any asset declares; only declared keys are checked.
type Finding struct {
	// Class is the asset class (DESIGN.md §2): certificate, private_key,
	// public_key, csr, tls_config, ssh_config.
	Class string
	// Path is the finding location relative to the corpus root, using forward
	// slashes regardless of host OS.
	Path string
	// Alias is the entry name inside a JKS/PKCS#12 container, or "" when the
	// finding is a plain file.
	Alias string
	// Attrs holds the extracted fields keyed to match manifest `expect` keys.
	Attrs map[string]any
	// Provenance is the evidence trail proving the finding (DESIGN.md §1).
	Provenance []graph.Provenance
}

// Scanner discovers cryptographic assets under a corpus/filesystem root.
type Scanner interface {
	// Name is a short, stable identifier (e.g. "certs", "nginx"), used for
	// deterministic ordering and diagnostics.
	Name() string
	// Scan walks root and returns every proven Finding. It returns an error
	// only for operational failures (e.g. unreadable root); an absence of
	// findings is not an error.
	Scan(root string) ([]Finding, error)
}

// registry holds the process-wide set of scanners keyed by Name. Registration
// typically happens from package init functions, so it is guarded by a mutex.
var (
	regMu    sync.Mutex
	registry = map[string]Scanner{}
)

// Register adds s to the process-wide registry, keyed by s.Name(). A nil
// scanner or one with an empty name is ignored. Re-registering an existing name
// replaces the prior scanner. All() returns registered scanners in a
// deterministic (name-sorted) order.
func Register(s Scanner) {
	if s == nil || s.Name() == "" {
		return
	}
	regMu.Lock()
	defer regMu.Unlock()
	registry[s.Name()] = s
}

// All returns every registered scanner sorted by Name, for deterministic
// evaluation order.
func All() []Scanner {
	regMu.Lock()
	defer regMu.Unlock()
	out := make([]Scanner, 0, len(registry))
	for _, s := range registry {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}
