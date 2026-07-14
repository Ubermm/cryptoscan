package cli

import (
	"context"
	stdtls "crypto/tls"
	"encoding/json"
	"net"
	"path/filepath"
	"strings"
	"testing"
)

// This file closes the coverage gap where `probe --fail-on` wires the shared
// policy gate but has no direct test (the `fs` gate is covered by
// policygate_integration_test.go; the probe wiring itself was untested). It
// stands up an in-process TLS server pinned to TLS 1.0 — an offline, ephemeral
// listener, no network, no sleeps — so the probed endpoint genuinely allows
// TLSv1 and the `tls10` token PROVABLY trips on the Endpoint node the probe
// builds. It drives the command through the same Execute/exit-code path the fs
// gate tests use (runFailOn), asserting exit 4, the report emitted on stdout
// BEFORE the gate fails (emit-then-gate), and the breach summary on stderr.

// startTLS10Server serves the corpus cert+key over TLS on an ephemeral loopback
// port, pinned to MinVersion==MaxVersion==TLS 1.0. This mirrors
// startCorpusTLSServer (probe_integration_test.go) but pins the legacy protocol
// so the endpoint's enumerated protocols_supported includes "TLSv1" — the exact
// attribute the tls10 policy token reads. Returns "host:port".
func startTLS10Server(t *testing.T, root, certRel, keyRel string) string {
	t.Helper()
	cert, err := stdtls.LoadX509KeyPair(
		filepath.Join(root, filepath.FromSlash(certRel)),
		filepath.Join(root, filepath.FromSlash(keyRel)))
	if err != nil {
		t.Fatalf("load fixture %s + %s: %v", certRel, keyRel, err)
	}
	cfg := &stdtls.Config{
		Certificates: []stdtls.Certificate{cert},
		MinVersion:   stdtls.VersionTLS10,
		MaxVersion:   stdtls.VersionTLS10,
	}
	ln, err := stdtls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer func() { _ = conn.Close() }()
				if tc, ok := conn.(*stdtls.Conn); ok {
					_ = tc.HandshakeContext(context.Background())
				}
			}(c)
		}
	}()
	return ln.Addr().String()
}

// TestProbeFailOnTLS10Breaches is the probe-side twin of TestFailOnTLS10Breaches
// (fs): a probed endpoint that allows TLS 1.0 trips --fail-on tls10 and exits 4,
// while the requested report-json output is still written to stdout in full
// before the gate fails, and the breach summary lands on stderr naming the
// endpoint and the tls10/TLSv1 evidence.
func TestProbeFailOnTLS10Breaches(t *testing.T) {
	root := corpusRoot(t)
	tlsAddr := startTLS10Server(t, root, "certs/rsa-2048-selfsigned.pem", "keys/rsa-2048.key")

	code, stdout, stderr := runFailOn(t, "probe", "--timeout", "3s",
		"--format", "report-json", "--fail-on", "tls10", tlsAddr)

	// Exit exactly 4, via the same errThresholdBreached mapping the fs gate uses.
	if code != 4 {
		t.Fatalf("exit code = %d, want 4\nstderr: %s", code, stderr)
	}

	// Emit-then-gate: the requested report-json is on stdout IN FULL, parses, and
	// carries the tls_endpoint finding — the gate never suppresses the report.
	var doc struct {
		Findings []struct {
			Type string `json:"type"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("stdout is not valid report-json: %v\nstdout:\n%s", err, stdout)
	}
	found := false
	for _, f := range doc.Findings {
		if f.Type == "tls_endpoint" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("report-json on stdout missing a tls_endpoint finding:\n%s", stdout)
	}

	// The breach summary is on stderr, never leaking onto stdout (which carries
	// the machine report).
	if strings.Contains(stdout, "policy:") {
		t.Error("breach summary leaked onto stdout")
	}
	if !strings.Contains(stderr, "policy:") || !strings.Contains(stderr, "tls10") {
		t.Errorf("stderr missing the tls10 breach summary:\n%s", stderr)
	}
	// The provable evidence (protocols_supported includes TLSv1) and the offending
	// endpoint (host:port) are both named on stderr.
	if !strings.Contains(stderr, "TLSv1") {
		t.Errorf("stderr should name the TLSv1 protocol evidence:\n%s", stderr)
	}
	if !strings.Contains(stderr, tlsAddr) {
		t.Errorf("stderr should name the offending endpoint %q:\n%s", tlsAddr, stderr)
	}
}

// TestProbeFailOnCleanExitsZero is the control: the SAME probe of the SAME
// TLS-1.0 endpoint WITHOUT --fail-on exits 0 (the gate is opt-in), and probing
// it with a token the endpoint does NOT trip (tls11 — only TLS 1.0 is allowed)
// also exits 0 with no breach summary.
func TestProbeFailOnCleanExitsZero(t *testing.T) {
	root := corpusRoot(t)
	tlsAddr := startTLS10Server(t, root, "certs/rsa-2048-selfsigned.pem", "keys/rsa-2048.key")

	// (a) No --fail-on at all: gate disabled, exit 0.
	code, stdout, stderr := runFailOn(t, "probe", "--timeout", "3s",
		"--format", "report-json", tlsAddr)
	if code != 0 {
		t.Fatalf("no --fail-on exit code = %d, want 0\nstderr: %s", code, stderr)
	}
	if !strings.Contains(stdout, "tls_endpoint") {
		t.Errorf("stdout missing tls_endpoint finding:\n%s", stdout)
	}
	if strings.Contains(stderr, "policy:") {
		t.Errorf("no --fail-on should print no breach summary, got:\n%s", stderr)
	}

	// (b) A non-tripped token (tls11): this endpoint allows only TLS 1.0, so the
	// gate is armed but not breached — exit 0, no breach summary.
	code, _, stderr = runFailOn(t, "probe", "--timeout", "3s",
		"--format", "report-json", "--fail-on", "tls11", tlsAddr)
	if code != 0 {
		t.Fatalf("--fail-on tls11 (not tripped) exit code = %d, want 0\nstderr: %s", code, stderr)
	}
	if strings.Contains(stderr, "policy:") {
		t.Errorf("untriggered token should print no breach summary, got:\n%s", stderr)
	}
}
