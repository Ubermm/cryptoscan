package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestVersionCommand(t *testing.T) {
	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"version"})

	if err := root.Execute(); err != nil {
		t.Fatalf("version command errored: %v", err)
	}
	got := strings.TrimSpace(out.String())
	want := "cryptoscan " + version
	if got != want {
		t.Errorf("version output = %q, want %q", got, want)
	}
}

func TestExecuteExitCodes(t *testing.T) {
	// version -> 0. (Execute builds its own root; args come from os.Args in
	// production, so here we only assert the success path is reachable.)
	if code := runWithArgs(t, "version"); code != 0 {
		t.Errorf("version exit code = %d, want 0", code)
	}
}

// runWithArgs is a small helper mirroring Execute's exit-code mapping for a
// constructed root, so we can assert codes without touching os.Args.
func runWithArgs(t *testing.T, args ...string) int {
	t.Helper()
	root := newRootCmd()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs(args)
	err := root.Execute()
	switch {
	case err == nil:
		return 0
	case errors.Is(err, errNotImplemented):
		return 2
	default:
		return 1
	}
}
