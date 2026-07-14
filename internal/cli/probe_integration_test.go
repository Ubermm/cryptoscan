package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	stdtls "crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Ubermm/cryptoscan/internal/graph"
	"github.com/Ubermm/cryptoscan/internal/probe"
)

// This file drives `cryptoscan probe` end-to-end against in-process TLS and SSH
// servers built from corpus fixtures (offline, deterministic — CI never touches
// the network). It asserts BOTH the command's stdout/exit contract (via cobra
// Execute) and the merged graph the command builds (via the same probe.Run over
// probe.All() the command calls, so the graph assertions mirror the real path).

// --- in-process TLS server -------------------------------------------------

// startCorpusTLSServer serves the corpus cert+key over TLS on an ephemeral
// loopback port, accepting connections in a loop (both the TLS and SSH probers
// dial it, since every prober runs against every target). Returns "host:port".
func startCorpusTLSServer(t *testing.T, root, certRel, keyRel string) string {
	t.Helper()
	cert, err := stdtls.LoadX509KeyPair(
		filepath.Join(root, filepath.FromSlash(certRel)),
		filepath.Join(root, filepath.FromSlash(keyRel)))
	if err != nil {
		t.Fatalf("load fixture %s + %s: %v", certRel, keyRel, err)
	}
	cfg := &stdtls.Config{
		Certificates: []stdtls.Certificate{cert},
		MinVersion:   stdtls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"},
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

// --- in-process SSH server (minimal, local to this test) -------------------
//
// A hand-rolled server that emits an identification banner then an
// SSH_MSG_KEXINIT, enough for the SSH prober's unauthenticated wire read. The
// wire builders mirror the (unexported) ones in internal/probe/ssh's own tests.

const (
	sshMsgKexInit = 20
	sshCookieLen  = 16
)

func sshNameList(names []string) []byte {
	s := strings.Join(names, ",")
	b := make([]byte, 4+len(s))
	binary.BigEndian.PutUint32(b, uint32(len(s)))
	copy(b[4:], s)
	return b
}

func sshKexInitPayload(lists [10][]string) []byte {
	var buf bytes.Buffer
	buf.WriteByte(sshMsgKexInit)
	buf.Write(make([]byte, sshCookieLen))
	for _, l := range lists {
		buf.Write(sshNameList(l))
	}
	buf.WriteByte(0)              // first_kex_packet_follows
	buf.Write([]byte{0, 0, 0, 0}) // reserved
	return buf.Bytes()
}

func sshFramePacket(payload []byte) []byte {
	const block = 8
	pad := block - ((4 + 1 + len(payload)) % block)
	if pad < 4 {
		pad += block
	}
	packetLen := 1 + len(payload) + pad
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.BigEndian, uint32(packetLen))
	buf.WriteByte(byte(pad))
	buf.Write(payload)
	buf.Write(make([]byte, pad))
	return buf.Bytes()
}

func sshSampleLists() [10][]string {
	return [10][]string{
		{"curve25519-sha256", "ecdh-sha2-nistp256"},                 // kex
		{"ssh-ed25519", "rsa-sha2-512"},                             // host key
		{"aes128-ctr", "aes256-gcm@openssh.com"},                    // enc c2s
		{"aes256-gcm@openssh.com", "chacha20-poly1305@openssh.com"}, // enc s2c
		{"hmac-sha2-256"},                                           // mac c2s
		{"hmac-sha2-512", "hmac-sha2-256"},                          // mac s2c
		{"none"},                                                    // comp c2s
		{"none"},                                                    // comp s2c
		{},                                                          // lang c2s
		{},                                                          // lang s2c
	}
}

// startSSHServer serves the banner + KEXINIT frame on every accepted connection.
func startSSHServer(t *testing.T, banner string, lists [10][]string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	frame := sshFramePacket(sshKexInitPayload(lists))
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_, _ = c.Write([]byte(banner + "\r\n"))
				_, _ = c.Write(frame)
				if tc, ok := c.(*net.TCPConn); ok {
					_ = tc.CloseWrite()
				}
				_, _ = io.Copy(io.Discard, c)
			}(conn)
		}
	}()
	return ln.Addr().String()
}

// --- helpers ---------------------------------------------------------------

func hostPort(t *testing.T, addr string) (string, int) {
	t.Helper()
	h, ps, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split %q: %v", addr, err)
	}
	p, _ := strconv.Atoi(ps)
	return h, p
}

func target(t *testing.T, addr string) probe.Target {
	t.Helper()
	h, p := hostPort(t, addr)
	return probe.Target{Host: h, Port: p, Raw: addr}
}

// corpusLeafCertID computes the Certificate node ID from the fixture's first
// CERTIFICATE PEM block, independently of the prober's parse path.
func corpusLeafCertID(t *testing.T, root, certRel string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(certRel)))
	if err != nil {
		t.Fatalf("read fixture %s: %v", certRel, err)
	}
	for rest := data; ; {
		block, rem := pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			sum := sha256.Sum256(block.Bytes)
			id, err := graph.CertNodeID(hex.EncodeToString(sum[:]))
			if err != nil {
				t.Fatalf("CertNodeID: %v", err)
			}
			return id
		}
		rest = rem
	}
	t.Fatalf("fixture %s has no CERTIFICATE block", certRel)
	return ""
}

func hasEdge(g *graph.Graph, et graph.EdgeType, from, to string) bool {
	for _, e := range g.Edges() {
		if e.Type == et && e.From == from && e.To == to {
			return true
		}
	}
	return false
}

func endpointNode(t *testing.T, g *graph.Graph, tgt probe.Target) *graph.EndpointNode {
	t.Helper()
	id, err := graph.EndpointNodeID(tgt.Host, tgt.Port)
	if err != nil {
		t.Fatalf("EndpointNodeID: %v", err)
	}
	n, ok := g.Node(id)
	if !ok {
		t.Fatalf("endpoint node %q not found", id)
	}
	ep, ok := n.(*graph.EndpointNode)
	if !ok {
		t.Fatalf("node %q is %T, want *graph.EndpointNode", id, n)
	}
	return ep
}

// --- tests -----------------------------------------------------------------

// TestProbeCommandEndToEnd is the Phase 2 headline: `probe <tlsAddr> <sshAddr>`
// through cobra Execute yields a tls_endpoint and an ssh_endpoint finding, exit
// 0, and a graph with two Endpoint nodes carrying the right per-scheme attrs and
// a terminates_tls_for edge from the leaf cert to its TLS endpoint.
func TestProbeCommandEndToEnd(t *testing.T) {
	root := corpusRoot(t)
	certRel := "certs/rsa-2048-selfsigned.pem"
	keyRel := "keys/rsa-2048.key"

	tlsAddr := startCorpusTLSServer(t, root, certRel, keyRel)
	banner := "SSH-2.0-OpenSSH_9.6"
	lists := sshSampleLists()
	sshAddr := startSSHServer(t, banner, lists)

	// (1) Command contract: stdout + exit 0 via cobra Execute.
	var out bytes.Buffer
	cmd := newRootCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"probe", "--timeout", "3s", tlsAddr, sshAddr})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("probe command errored: %v\noutput:\n%s", err, out.String())
	}
	got := out.String()
	for _, want := range []string{
		"Findings by class:",
		"tls_endpoint",
		"ssh_endpoint",
		"Findings:",
		"TARGET", "CLASS", "DETAIL",
		"Graph nodes:",
		"Endpoint",
		"Graph edges:",
		"terminates_tls_for",
		banner,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("probe output missing %q\noutput:\n%s", want, got)
		}
	}

	// (2) Graph contract: drive the same probe.Run(probe.All()) the command uses.
	tlsTgt, sshTgt := target(t, tlsAddr), target(t, sshAddr)
	g := graph.New()
	res, err := probe.Run(context.Background(), []probe.Target{tlsTgt, sshTgt}, g,
		probe.RunOptions{Timeout: 3 * time.Second, RatePerSec: -1})
	if err != nil {
		t.Fatalf("probe.Run: %v", err)
	}

	// Exactly one tls_endpoint and one ssh_endpoint finding.
	var tlsN, sshN int
	for _, f := range res.Findings {
		switch f.Class {
		case probe.ClassTLSEndpoint:
			tlsN++
		case probe.ClassSSHEndpoint:
			sshN++
		}
	}
	if tlsN != 1 || sshN != 1 {
		t.Fatalf("findings: tls=%d ssh=%d, want 1 and 1 (findings=%+v)", tlsN, sshN, res.Findings)
	}

	// Two Endpoint nodes.
	epCount := 0
	for _, n := range g.Nodes() {
		if n.Type() == graph.NodeEndpoint {
			epCount++
		}
	}
	if epCount != 2 {
		t.Errorf("Endpoint nodes = %d, want 2", epCount)
	}

	// TLS endpoint node carries TLS attrs.
	tlsEP := endpointNode(t, g, tlsTgt)
	if got := tlsEP.Attrs["negotiated_protocol"]; got == "" || got == nil {
		t.Errorf("tls endpoint negotiated_protocol = %v, want non-empty", got)
	}
	if _, ok := tlsEP.Attrs["pqc_hybrid_kex"].(bool); !ok {
		t.Errorf("tls endpoint missing pqc_hybrid_kex bool attr: %#v", tlsEP.Attrs)
	}
	if protos, _ := tlsEP.Attrs["protocols_supported"].([]string); len(protos) == 0 {
		t.Errorf("tls endpoint protocols_supported = %v, want non-empty", protos)
	}
	if _, ok := tlsEP.Attrs["banner"]; ok {
		t.Errorf("tls endpoint unexpectedly has an ssh banner attr: %#v", tlsEP.Attrs)
	}

	// SSH endpoint node carries SSH attrs.
	sshEP := endpointNode(t, g, sshTgt)
	if got := sshEP.Attrs["banner"]; got != banner {
		t.Errorf("ssh endpoint banner = %v, want %q", got, banner)
	}
	if got, _ := sshEP.Attrs["host_key_algorithms"].([]string); !reflect.DeepEqual(got, lists[1]) {
		t.Errorf("ssh endpoint host_key_algorithms = %v, want %v", got, lists[1])
	}
	if got, _ := sshEP.Attrs["ciphers"].([]string); !reflect.DeepEqual(got, lists[3]) {
		t.Errorf("ssh endpoint ciphers = %v, want %v", got, lists[3])
	}

	// terminates_tls_for edge from the leaf cert node to the TLS endpoint node.
	leafID := corpusLeafCertID(t, root, certRel)
	tlsEPID, err := graph.EndpointNodeID(tlsTgt.Host, tlsTgt.Port)
	if err != nil {
		t.Fatalf("EndpointNodeID: %v", err)
	}
	if !hasEdge(g, graph.EdgeTerminatesTLSFor, leafID, tlsEPID) {
		t.Errorf("missing terminates_tls_for edge %s -> %s", leafID, tlsEPID)
	}
}

// TestProbeCommandQuiet asserts --quiet prints the counts block and a one-line
// graph summary but omits the findings table.
func TestProbeCommandQuiet(t *testing.T) {
	root := corpusRoot(t)
	tlsAddr := startCorpusTLSServer(t, root, "certs/rsa-2048-selfsigned.pem", "keys/rsa-2048.key")

	var out bytes.Buffer
	cmd := newRootCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"probe", "--quiet", "--timeout", "3s", tlsAddr})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("probe --quiet errored: %v\n%s", err, out.String())
	}
	got := out.String()
	if !strings.Contains(got, "Findings by class:") {
		t.Error("quiet output missing class counts")
	}
	if !strings.Contains(got, "Graph:") {
		t.Error("quiet output missing one-line graph summary")
	}
	if strings.Contains(got, "Findings:") || strings.Contains(got, "DETAIL") {
		t.Error("quiet output should omit the findings table")
	}
}

// TestProbeCommandUsageError asserts a bad target is a usage error (exit 1 via
// Execute) and never panics.
func TestProbeCommandUsageError(t *testing.T) {
	if code := runWithArgs(t, "probe", "10.0.0.0/24"); code != 1 {
		t.Errorf("CIDR target exit code = %d, want 1 (usage error)", code)
	}
	if code := runWithArgs(t, "probe"); code != 1 {
		t.Errorf("no-targets exit code = %d, want 1 (usage error)", code)
	}
}

// TestProbeCommandAllUnreachable asserts that when no target can be probed at
// all (a closed port), the command exits 1.
func TestProbeCommandAllUnreachable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close() // definitely-closed port

	if code := runWithArgs(t, "probe", "--timeout", "1s", addr); code != 1 {
		t.Errorf("all-unreachable exit code = %d, want 1", code)
	}
}
