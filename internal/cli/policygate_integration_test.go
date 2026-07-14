package cli

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// runFailOn drives a scan command through Execute's exit-code mapping, returning
// the exit code plus captured stdout and stderr separately (the gate summary must
// land on stderr, never stdout).
func runFailOn(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errBuf bytes.Buffer
	root := newRootCmd()
	root.SetOut(&out)
	root.SetErr(&errBuf)
	root.SetArgs(args)
	err := root.Execute()

	// Mirror Execute()'s exit-code mapping AND its stderr printing so the test
	// observes exactly what the real binary would emit (the root has
	// SilenceErrors set, so cobra itself prints nothing).
	switch {
	case err == nil:
		code = 0
	case errors.Is(err, errThresholdBreached):
		// Summary already written to stderr by the command; nothing more printed.
		code = 4
	case errors.Is(err, errNotImplemented):
		fmt.Fprintln(&errBuf, err)
		code = 2
	default:
		fmt.Fprintln(&errBuf, "cryptoscan:", err)
		code = 1
	}
	return code, out.String(), errBuf.String()
}

// TestFailOnSHA1Breaches: fs over the corpus with --fail-on sha1 exits 4, the
// full table still prints to stdout, and stderr names the SHA-1 asset.
func TestFailOnSHA1Breaches(t *testing.T) {
	root := corpusRoot(t)
	code, stdout, stderr := runFailOn(t, "fs", root, "--fail-on", "sha1")

	if code != 4 {
		t.Fatalf("exit code = %d, want 4\nstderr: %s", code, stderr)
	}
	// The requested report is written IN FULL before the gate fails.
	if !strings.Contains(stdout, "Findings by class:") || !strings.Contains(stdout, "Graph nodes:") {
		t.Errorf("stdout missing the normal table output:\n%s", stdout)
	}
	// The breach summary is on stderr, not stdout.
	if strings.Contains(stdout, "policy:") {
		t.Error("breach summary leaked to stdout")
	}
	if !strings.Contains(stderr, "policy:") || !strings.Contains(stderr, "sha1") {
		t.Errorf("stderr missing the sha1 breach summary:\n%s", stderr)
	}
	if !strings.Contains(stderr, "SHA1-RSA") {
		t.Errorf("stderr should name the SHA-1 signature detail:\n%s", stderr)
	}
}

// TestFailOnRSA1024Breaches: the rsa-1024 fixture trips rsa1024.
func TestFailOnRSA1024Breaches(t *testing.T) {
	root := corpusRoot(t)
	code, _, stderr := runFailOn(t, "fs", root, "--fail-on", "rsa1024")
	if code != 4 {
		t.Fatalf("exit code = %d, want 4\nstderr: %s", code, stderr)
	}
	if !strings.Contains(stderr, "rsa1024") || !strings.Contains(stderr, "1024-bit") {
		t.Errorf("stderr missing rsa1024 breach detail:\n%s", stderr)
	}
}

// TestFailOnTLS10Breaches: the legacy configs allow TLS 1.0.
func TestFailOnTLS10Breaches(t *testing.T) {
	root := corpusRoot(t)
	code, _, stderr := runFailOn(t, "fs", root, "--fail-on", "tls10")
	if code != 4 {
		t.Fatalf("exit code = %d, want 4\nstderr: %s", code, stderr)
	}
	if !strings.Contains(stderr, "tls10") || !strings.Contains(stderr, "TLSv1") {
		t.Errorf("stderr missing tls10 breach detail:\n%s", stderr)
	}
}

// TestFailOnExpiredBreaches: the expired fixture trips expired.
func TestFailOnExpiredBreaches(t *testing.T) {
	root := corpusRoot(t)
	code, _, stderr := runFailOn(t, "fs", root, "--fail-on", "expired")
	if code != 4 {
		t.Fatalf("exit code = %d, want 4\nstderr: %s", code, stderr)
	}
	if !strings.Contains(stderr, "expired") {
		t.Errorf("stderr missing expired breach:\n%s", stderr)
	}
}

// TestFailOnCombinedTokens: sha1,rsa1024,tls10 all trip; exit 4; each token is
// tallied on stderr.
func TestFailOnCombinedTokens(t *testing.T) {
	root := corpusRoot(t)
	code, _, stderr := runFailOn(t, "fs", root, "--fail-on", "sha1,rsa1024,tls10")
	if code != 4 {
		t.Fatalf("exit code = %d, want 4\nstderr: %s", code, stderr)
	}
	for _, tok := range []string{"sha1", "rsa1024", "tls10"} {
		if !strings.Contains(stderr, tok) {
			t.Errorf("stderr missing token %q:\n%s", tok, stderr)
		}
	}
}

// TestFailOnCleanDir: a directory containing only a strong modern cert trips
// nothing for a weak token, so the command exits 0.
func TestFailOnCleanDir(t *testing.T) {
	root := corpusRoot(t)
	clean := t.TempDir()
	copyFile(t, filepath.Join(root, "certs", "ecdsa-p384.pem"), filepath.Join(clean, "ecdsa-p384.pem"))

	code, stdout, stderr := runFailOn(t, "fs", clean, "--fail-on", "sha1")
	if code != 0 {
		t.Fatalf("clean dir exit code = %d, want 0\nstderr: %s", code, stderr)
	}
	if !strings.Contains(stdout, "Findings by class:") {
		t.Errorf("clean-dir stdout missing table:\n%s", stdout)
	}
	if strings.Contains(stderr, "policy:") {
		t.Errorf("clean dir should print no breach summary, got:\n%s", stderr)
	}
}

// TestFailOnInvalidToken: an unknown token is a usage error (exit 1) whose
// message lists valid tokens; no scan output is produced.
func TestFailOnInvalidToken(t *testing.T) {
	root := corpusRoot(t)
	code, _, stderr := runFailOn(t, "fs", root, "--fail-on", "bogus")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1\nstderr: %s", code, stderr)
	}
	if !strings.Contains(stderr, "unknown --fail-on token") || !strings.Contains(stderr, "sha1") {
		t.Errorf("stderr should reject the token and list valid ones:\n%s", stderr)
	}
}

// TestFailOnWithCBOMOutput: the CBOM file is written AND the gate fails (exit 4)
// AND the breach summary lands on stderr — gating never suppresses the report.
func TestFailOnWithCBOMOutput(t *testing.T) {
	root := corpusRoot(t)
	outFile := filepath.Join(t.TempDir(), "cbom.json")

	code, stdout, stderr := runFailOn(t, "fs", root, "--fail-on", "sha1", "--format", "cbom", "--output", outFile)
	if code != 4 {
		t.Fatalf("exit code = %d, want 4\nstderr: %s", code, stderr)
	}
	// The CBOM file must exist and contain CycloneDX content.
	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("CBOM output file not written: %v", err)
	}
	if !strings.Contains(string(data), "bomFormat") && !strings.Contains(string(data), "CycloneDX") {
		t.Errorf("CBOM file missing expected content:\n%s", string(data))
	}
	// stdout is empty (output went to the file); breach summary on stderr.
	if strings.TrimSpace(stdout) != "" {
		t.Errorf("stdout should be empty with --output, got:\n%s", stdout)
	}
	if !strings.Contains(stderr, "policy:") || !strings.Contains(stderr, "sha1") {
		t.Errorf("stderr missing breach summary:\n%s", stderr)
	}
}

// TestFailOnDisabledWhenEmpty: without --fail-on, the corpus scan exits 0 even
// though it contains weak assets (the gate is opt-in).
func TestFailOnDisabledWhenEmpty(t *testing.T) {
	root := corpusRoot(t)
	code, _, stderr := runFailOn(t, "fs", root)
	if code != 0 {
		t.Fatalf("no --fail-on exit code = %d, want 0\nstderr: %s", code, stderr)
	}
}

// copyFile copies src to dst byte-for-byte.
func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read %s: %v", src, err)
	}
	if err := os.WriteFile(dst, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", dst, err)
	}
}
