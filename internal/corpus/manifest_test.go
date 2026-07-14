package corpus

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseFragmentVersion(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr bool
	}{
		{
			name: "valid version 1",
			yaml: "version: 1\nassets: []\n",
		},
		{
			name:    "wrong version",
			yaml:    "version: 2\n",
			wantErr: true,
		},
		{
			name:    "missing version",
			yaml:    "assets: []\n",
			wantErr: true,
		},
		{
			name:    "malformed yaml",
			yaml:    "version: 1\nassets: [::::\n",
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseFragment([]byte(tc.yaml))
			if tc.wantErr != (err != nil) {
				t.Fatalf("ParseFragment err = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}

func TestMergeDuplicateIDErrors(t *testing.T) {
	f1 := &Fragment{Version: 1, Assets: []Asset{{ID: "dup", Class: "certificate", Path: "a.pem"}}}
	f2 := &Fragment{Version: 1, Assets: []Asset{{ID: "dup", Class: "certificate", Path: "b.pem"}}}
	if _, err := Merge(f1, f2); err == nil {
		t.Fatal("expected duplicate-id error, got nil")
	}

	ok := &Fragment{Version: 1, Assets: []Asset{{ID: "unique", Class: "certificate", Path: "c.pem"}}}
	c, err := Merge(f1, ok)
	if err != nil {
		t.Fatalf("unexpected error merging distinct ids: %v", err)
	}
	if len(c.Assets) != 2 {
		t.Errorf("merged assets = %d, want 2", len(c.Assets))
	}
}

// TestMergeDuplicateIDMessage checks the error phrasing is sensible for both a
// cross-fragment collision and a within-a-single-fragment repeat (the latter
// must not read as "fragment #0 and fragment #0").
func TestMergeDuplicateIDMessage(t *testing.T) {
	// Within one fragment.
	single := &Fragment{Version: 1, Assets: []Asset{
		{ID: "dup", Class: "certificate", Path: "a.pem"},
		{ID: "dup", Class: "certificate", Path: "b.pem"},
	}}
	_, err := Merge(single)
	if err == nil {
		t.Fatal("expected within-fragment duplicate-id error, got nil")
	}
	if got := err.Error(); !strings.Contains(got, "more than once") || strings.Contains(got, "and fragment") {
		t.Errorf("within-fragment message = %q, want 'more than once' and no 'X and fragment Y'", got)
	}

	// Across two fragments.
	a := &Fragment{Version: 1, Assets: []Asset{{ID: "dup", Class: "certificate", Path: "a.pem"}}}
	b := &Fragment{Version: 1, Assets: []Asset{{ID: "dup", Class: "certificate", Path: "b.pem"}}}
	_, err = Merge(a, b)
	if err == nil {
		t.Fatal("expected cross-fragment duplicate-id error, got nil")
	}
	if got := err.Error(); !strings.Contains(got, "fragment #0 and fragment #1") {
		t.Errorf("cross-fragment message = %q, want it to name both fragments", got)
	}
}

func TestMergeValidation(t *testing.T) {
	tests := []struct {
		name  string
		asset Asset
	}{
		{"unknown class", Asset{ID: "x", Class: "wildcard", Path: "a.pem"}},
		{"empty class", Asset{ID: "x", Path: "a.pem"}},
		{"empty path", Asset{ID: "x", Class: "certificate"}},
		{"nested expect value", Asset{ID: "x", Class: "certificate", Path: "a.pem",
			Expect: Expect{"algorithm": map[string]any{"nested": true}}}},
		{"list with nested element", Asset{ID: "x", Class: "tls_config", Path: "a.conf",
			Expect: Expect{"protocols": []any{"TLSv1.2", map[string]any{}}}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := &Fragment{Version: 1, Assets: []Asset{tc.asset}}
			if _, err := Merge(f); err == nil {
				t.Fatalf("Merge accepted invalid asset %+v", tc.asset)
			}
		})
	}
}

func TestExpectIsOpenMap(t *testing.T) {
	f, err := ParseFragment([]byte(`version: 1
assets:
  - id: sshd
    class: ssh_config
    path: configs/ssh/sshd_config
    expect:
      host_key_types: [rsa, ed25519]
      min_protocol: TLSv1.2
      key_size: 2048
      self_signed: true
`))
	if err != nil {
		t.Fatalf("ParseFragment: %v", err)
	}
	e := f.Assets[0].Expect
	if got, ok := e["host_key_types"].([]any); !ok || len(got) != 2 {
		t.Errorf("host_key_types = %#v, want 2-element list", e["host_key_types"])
	}
	if e["min_protocol"] != "TLSv1.2" {
		t.Errorf("min_protocol = %#v, want TLSv1.2", e["min_protocol"])
	}
	if e["key_size"] != 2048 {
		t.Errorf("key_size = %#v (%T), want int 2048", e["key_size"], e["key_size"])
	}
	if e["self_signed"] != true {
		t.Errorf("self_signed = %#v, want true", e["self_signed"])
	}
}

func TestLoadDir(t *testing.T) {
	root := t.TempDir()
	manifests := filepath.Join(root, "manifests")
	if err := os.MkdirAll(manifests, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(manifests, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("certs.yaml", "version: 1\nassets:\n  - id: rsa-2048\n    class: certificate\n    path: certs/rsa.pem\n")
	write("negatives.yaml", "version: 1\nnegatives:\n  - id: fake-pem\n    path: negatives/fake.txt\n")
	write("notes.txt", "ignored, not a manifest")

	c, err := LoadDir(root)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if len(c.Assets) != 1 || c.Assets[0].ID != "rsa-2048" {
		t.Errorf("assets = %+v, want one rsa-2048", c.Assets)
	}
	if len(c.Negatives) != 1 || c.Negatives[0].ID != "fake-pem" {
		t.Errorf("negatives = %+v, want one fake-pem", c.Negatives)
	}
	if c.Root != root {
		t.Errorf("Root = %q, want %q", c.Root, root)
	}
}
