// Package corpus loads and merges the ground-truth manifest fragments that
// describe the test corpus (docs/DESIGN.md §2). It is the contract the eval
// harness (cmd/eval) scores scanner output against.
//
// This Phase 0 scaffold defines the version-1 schema and the fragment-merge
// semantics (duplicate asset IDs are a load error). It depends only on the
// standard library and gopkg.in/yaml.v3.
package corpus

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"gopkg.in/yaml.v3"
)

// SchemaVersion is the only manifest schema version currently understood.
const SchemaVersion = 1

// ValidClasses is the closed set of asset classes (DESIGN.md §2). Keystore
// files are not their own class: each JKS/PKCS#12 entry is declared as a
// certificate/private_key asset with a container + alias.
var ValidClasses = map[string]bool{
	"certificate": true,
	"private_key": true,
	"public_key":  true,
	"csr":         true,
	"tls_config":  true,
	"ssh_config":  true,
}

// Fragment is one *.yaml file under manifests/. Independent contributors add
// fragments so they never merge-conflict; the loader merges them.
type Fragment struct {
	Version   int        `yaml:"version"`
	Assets    []Asset    `yaml:"assets,omitempty"`
	Negatives []Negative `yaml:"negatives,omitempty"`
}

// Asset is a declared, expected finding. IDs are unique across all fragments.
type Asset struct {
	ID        string `yaml:"id"`
	Class     string `yaml:"class"`
	Path      string `yaml:"path"`
	Container string `yaml:"container,omitempty"` // pem | der | jks | pkcs12
	Alias     string `yaml:"alias,omitempty"`     // entry alias inside jks/pkcs12
	Expect    Expect `yaml:"expect,omitempty"`
}

// Expect holds the fields that MUST match for an asset to count as a true
// positive. It is an open map so contributors can declare class-specific keys
// (e.g. host_key_types, min_protocol, cipher_string) without a schema change;
// the eval matcher checks only the keys that are present. Values are scalars
// (string/int/bool/float) or lists of scalars; a nested mapping is rejected at
// load time. Keys suffixed `_contains` are subset matches, everything else is
// an exact scalar or exact-set match (DESIGN.md §2).
type Expect map[string]any

// Negative is a crypto look-alike; the scanner must report nothing for it.
type Negative struct {
	ID   string `yaml:"id"`
	Path string `yaml:"path"`
	Note string `yaml:"note,omitempty"`
}

// Corpus is the merged view of all fragments.
type Corpus struct {
	// Root is the corpus root directory as passed to LoadDir (empty when the
	// corpus was assembled via Merge directly). Asset/negative paths are
	// relative to it.
	Root      string
	Assets    []Asset
	Negatives []Negative
}

// ParseFragment decodes a single manifest fragment and validates its version.
func ParseFragment(data []byte) (*Fragment, error) {
	var f Fragment
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("corpus: parse fragment: %w", err)
	}
	if f.Version != SchemaVersion {
		return nil, fmt.Errorf("corpus: unsupported manifest version %d (want %d)", f.Version, SchemaVersion)
	}
	return &f, nil
}

// validateExpect rejects malformed expectation values so the matcher can assume
// every value is a scalar (string/int/bool/float) or a list of scalars. A
// nested mapping, or a list containing one, is a load error.
func validateExpect(e Expect) error {
	for k, v := range e {
		if err := validExpectValue(v); err != nil {
			return fmt.Errorf("expect key %q: %w", k, err)
		}
	}
	return nil
}

func validExpectValue(v any) error {
	switch vv := v.(type) {
	case nil, string, bool, int, int64, uint64, float64, float32:
		return nil
	case []any:
		for i, elem := range vv {
			switch elem.(type) {
			case string, bool, int, int64, uint64, float64, float32:
			default:
				return fmt.Errorf("list element %d is not a scalar (got %T)", i, elem)
			}
		}
		return nil
	default:
		return fmt.Errorf("value must be a scalar or list of scalars (got %T)", v)
	}
}

// Merge folds fragments into one Corpus. Duplicate asset or negative IDs across
// fragments are a load error (docs/DESIGN.md §2).
func Merge(fragments ...*Fragment) (*Corpus, error) {
	c := &Corpus{}
	seen := make(map[string]string) // id -> source description

	for i, f := range fragments {
		if f == nil {
			continue
		}
		src := fmt.Sprintf("fragment #%d", i)
		for _, a := range f.Assets {
			if a.ID == "" {
				return nil, fmt.Errorf("corpus: %s has an asset with empty id", src)
			}
			if prev, dup := seen[a.ID]; dup {
				return nil, fmt.Errorf("corpus: duplicate id %q (in %s and %s)", a.ID, prev, src)
			}
			if a.Class == "" {
				return nil, fmt.Errorf("corpus: asset %q (%s) has empty class", a.ID, src)
			}
			if !ValidClasses[a.Class] {
				return nil, fmt.Errorf("corpus: asset %q (%s) has unknown class %q", a.ID, src, a.Class)
			}
			if a.Path == "" {
				return nil, fmt.Errorf("corpus: asset %q (%s) has empty path", a.ID, src)
			}
			if err := validateExpect(a.Expect); err != nil {
				return nil, fmt.Errorf("corpus: asset %q (%s): %w", a.ID, src, err)
			}
			seen[a.ID] = src
			c.Assets = append(c.Assets, a)
		}
		for _, n := range f.Negatives {
			if n.ID == "" {
				return nil, fmt.Errorf("corpus: %s has a negative with empty id", src)
			}
			if prev, dup := seen[n.ID]; dup {
				return nil, fmt.Errorf("corpus: duplicate id %q (in %s and %s)", n.ID, prev, src)
			}
			seen[n.ID] = src
			c.Negatives = append(c.Negatives, n)
		}
	}
	return c, nil
}

// LoadDir reads and merges every *.yaml / *.yml fragment under
// <root>/manifests/, in sorted filename order for deterministic errors.
func LoadDir(root string) (*Corpus, error) {
	manifestDir := filepath.Join(root, "manifests")
	entries, err := os.ReadDir(manifestDir)
	if err != nil {
		return nil, fmt.Errorf("corpus: read manifests dir: %w", err)
	}

	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		switch filepath.Ext(e.Name()) {
		case ".yaml", ".yml":
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	fragments := make([]*Fragment, 0, len(names))
	for _, name := range names {
		p := filepath.Join(manifestDir, name)
		data, err := os.ReadFile(p) //nolint:gosec // corpus path is developer-controlled
		if err != nil {
			return nil, fmt.Errorf("corpus: read %s: %w", name, err)
		}
		f, err := ParseFragment(data)
		if err != nil {
			return nil, fmt.Errorf("corpus: %s: %w", name, err)
		}
		fragments = append(fragments, f)
	}
	c, err := Merge(fragments...)
	if err != nil {
		return nil, err
	}
	c.Root = root
	return c, nil
}
