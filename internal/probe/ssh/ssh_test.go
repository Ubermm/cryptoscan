package ssh

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cryptoscan/cryptoscan/internal/graph"
	"github.com/cryptoscan/cryptoscan/internal/probe"
)

// --- wire-format builders (test-only) --------------------------------------

// nameListBytes encodes an RFC 4251 name-list: uint32 length + comma-joined names.
func nameListBytes(names []string) []byte {
	s := strings.Join(names, ",")
	b := make([]byte, 4+len(s))
	binary.BigEndian.PutUint32(b, uint32(len(s)))
	copy(b[4:], s)
	return b
}

// buildKexInitPayload assembles a well-formed SSH_MSG_KEXINIT payload from the
// ten name-lists in RFC order.
func buildKexInitPayload(lists [10][]string) []byte {
	var buf bytes.Buffer
	buf.WriteByte(msgKexInit)
	buf.Write(make([]byte, cookieLen)) // 16-byte cookie
	for _, l := range lists {
		buf.Write(nameListBytes(l))
	}
	buf.WriteByte(0)              // first_kex_packet_follows
	buf.Write([]byte{0, 0, 0, 0}) // reserved uint32
	return buf.Bytes()
}

// framePacket wraps payload in RFC 4253 §6 packet framing with valid padding
// (>= 4 bytes, total a multiple of 8).
func framePacket(payload []byte) []byte {
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
	buf.Write(make([]byte, pad)) // deterministic zero padding
	return buf.Bytes()
}

// sampleLists returns a representative set of ten name-lists.
func sampleLists() [10][]string {
	return [10][]string{
		{"curve25519-sha256", "ecdh-sha2-nistp256"},                 // kex_algorithms
		{"ssh-ed25519", "rsa-sha2-512"},                             // server_host_key_algorithms
		{"aes128-ctr", "aes256-gcm@openssh.com"},                    // enc c2s
		{"aes256-gcm@openssh.com", "chacha20-poly1305@openssh.com"}, // enc s2c
		{"hmac-sha2-256"},                                           // mac c2s
		{"hmac-sha2-512", "hmac-sha2-256"},                          // mac s2c
		{"none"},                                                    // comp c2s
		{"none", "zlib@openssh.com"},                                // comp s2c
		{},                                                          // lang c2s (empty)
		{},                                                          // lang s2c (empty)
	}
}

// --- in-process SSH server -------------------------------------------------

// serverScript describes the bytes a fake SSH server writes to an accepted
// connection, in order.
type serverScript struct {
	preamble []string // CR LF preamble lines written before the banner
	banner   string   // identification line (CR LF appended); "" writes none
	frame    []byte   // raw bytes written after the banner (KEXINIT or garbage)
	rawOnly  []byte   // if non-nil, write exactly this and nothing else
}

// startServer listens on a loopback port and serves one connection per the
// script, then drains the client until it closes. It returns the target; the
// listener is closed via t.Cleanup. Readiness is guaranteed by Listen returning
// before Addr is read (no sleeps).
func startServer(t *testing.T, s serverScript) probe.Target {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		if s.rawOnly != nil {
			_, _ = conn.Write(s.rawOnly)
		} else {
			for _, p := range s.preamble {
				_, _ = conn.Write([]byte(p + "\r\n"))
			}
			if s.banner != "" {
				_, _ = conn.Write([]byte(s.banner + "\r\n"))
			}
			_, _ = conn.Write(s.frame)
		}
		// Half-close (send FIN) so the client sees EOF after consuming the
		// scripted bytes — a truncated/non-SSH stream then errors promptly
		// instead of waiting for the read deadline — while the read side stays
		// open to accept the client's identification write below.
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		// Drain the client's identification write until it closes.
		_, _ = io.Copy(io.Discard, conn)
	}()

	host, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}
	port, _ := strconv.Atoi(portStr)
	return probe.Target{Host: host, Port: port, Raw: ln.Addr().String()}
}

func mustProbe(t *testing.T, tgt probe.Target) ([]probe.Finding, *graph.Graph, error) {
	t.Helper()
	g := graph.New()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	f, err := New().Probe(ctx, tgt, g)
	return f, g, err
}

// --- happy-path Probe tests ------------------------------------------------

func TestProbe_PlainBanner(t *testing.T) {
	lists := sampleLists()
	banner := "SSH-2.0-OpenSSH_9.6"
	tgt := startServer(t, serverScript{banner: banner, frame: framePacket(buildKexInitPayload(lists))})

	findings, g, err := mustProbe(t, tgt)
	if err != nil {
		t.Fatalf("Probe: unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Class != probe.ClassSSHEndpoint {
		t.Errorf("class = %q, want %q", f.Class, probe.ClassSSHEndpoint)
	}
	if f.Path != tgt.Addr() {
		t.Errorf("path = %q, want %q", f.Path, tgt.Addr())
	}
	if f.Alias != "" {
		t.Errorf("alias = %q, want empty", f.Alias)
	}
	assertAttr(t, f, "banner", banner)
	assertAttr(t, f, "host_key_algorithms", lists[1])
	assertAttr(t, f, "kex_algorithms", lists[0])
	assertAttr(t, f, "ciphers", lists[3])
	assertAttr(t, f, "macs", lists[5])

	assertProvenance(t, f.Provenance, tgt)
	assertEndpointNode(t, g, tgt, banner, lists[3])
}

func TestProbe_PreambleBanner(t *testing.T) {
	lists := sampleLists()
	banner := "SSH-2.0-Go"
	tgt := startServer(t, serverScript{
		preamble: []string{"This is a restricted system.", "Authorized users only."},
		banner:   banner,
		frame:    framePacket(buildKexInitPayload(lists)),
	})

	findings, g, err := mustProbe(t, tgt)
	if err != nil {
		t.Fatalf("Probe: unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	assertAttr(t, findings[0], "banner", banner)
	assertAttr(t, findings[0], "kex_algorithms", lists[0])
	assertEndpointNode(t, g, tgt, banner, lists[3])
}

func TestProbe_SSH199Banner(t *testing.T) {
	lists := sampleLists()
	banner := "SSH-1.99-OpenSSH_3.9"
	tgt := startServer(t, serverScript{banner: banner, frame: framePacket(buildKexInitPayload(lists))})

	findings, _, err := mustProbe(t, tgt)
	if err != nil {
		t.Fatalf("Probe: unexpected error: %v", err)
	}
	assertAttr(t, findings[0], "banner", banner)
}

// --- robustness Probe tests ------------------------------------------------

func TestProbe_NonSSHService(t *testing.T) {
	// An HTTP error response is not an SSH banner: no line begins with "SSH-".
	tgt := startServer(t, serverScript{rawOnly: []byte("HTTP/1.1 400 Bad Request\r\n\r\n")})

	findings, g, err := mustProbe(t, tgt)
	if err == nil {
		t.Fatalf("want error for non-SSH service, got nil")
	}
	if findings != nil {
		t.Errorf("want no findings, got %d", len(findings))
	}
	assertNoEndpointNode(t, g, tgt)
}

func TestProbe_TruncatedKexInit(t *testing.T) {
	// Announce a packet then send fewer bytes than the length header promises.
	full := framePacket(buildKexInitPayload(sampleLists()))
	tgt := startServer(t, serverScript{banner: "SSH-2.0-x", frame: full[:6]})

	findings, _, err := mustProbe(t, tgt)
	if err == nil {
		t.Fatalf("want error for truncated KEXINIT, got nil")
	}
	if findings != nil {
		t.Errorf("want no findings, got %d", len(findings))
	}
}

func TestProbe_WrongMessageType(t *testing.T) {
	payload := buildKexInitPayload(sampleLists())
	payload[0] = 21 // SSH_MSG_NEWKEYS, not KEXINIT
	tgt := startServer(t, serverScript{banner: "SSH-2.0-x", frame: framePacket(payload)})

	_, _, err := mustProbe(t, tgt)
	if err == nil {
		t.Fatalf("want error for wrong message type, got nil")
	}
}

func TestProbe_OversizedPacket(t *testing.T) {
	// A packet_length header above maxPacketLen must be rejected before any body
	// read, so the server need not even send a body.
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], maxPacketLen+1)
	tgt := startServer(t, serverScript{banner: "SSH-2.0-x", frame: hdr[:]})

	_, _, err := mustProbe(t, tgt)
	if err == nil {
		t.Fatalf("want error for oversized packet, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds maximum") {
		t.Errorf("error = %v, want it to mention the max-packet bound", err)
	}
}

func TestProbe_Unreachable(t *testing.T) {
	// Bind then immediately close a listener to obtain a definitely-closed port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	_ = ln.Close()

	tgt := probe.Target{Host: host, Port: port}
	findings, _, err := mustProbe(t, tgt)
	if err == nil {
		t.Fatalf("want error for unreachable target, got nil")
	}
	if findings != nil {
		t.Errorf("want no findings, got %d", len(findings))
	}
}

// --- end-to-end through probe.Run ------------------------------------------

func TestProbeRun_EndToEnd(t *testing.T) {
	lists := sampleLists()
	banner := "SSH-2.0-OpenSSH_9.6"
	tgt := startServer(t, serverScript{banner: banner, frame: framePacket(buildKexInitPayload(lists))})

	g := graph.New()
	res, err := probe.Run(context.Background(), []probe.Target{tgt}, g, probe.RunOptions{
		Probers: []probe.Prober{New()},
		Timeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatalf("probe.Run: %v", err)
	}
	if len(res.Errors) != 0 {
		t.Fatalf("want no target errors, got %v", res.Errors)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(res.Findings))
	}
	if res.Findings[0].Class != probe.ClassSSHEndpoint {
		t.Errorf("class = %q, want %q", res.Findings[0].Class, probe.ClassSSHEndpoint)
	}
	assertEndpointNode(t, g, tgt, banner, lists[3])
}

// --- parser unit tests (table-driven) --------------------------------------

func TestParseKexInit_Valid(t *testing.T) {
	lists := sampleLists()
	ki, err := parseKexInit(framePacket(buildKexInitPayload(lists)))
	if err != nil {
		t.Fatalf("parseKexInit: %v", err)
	}
	if !reflect.DeepEqual(ki.kex, lists[0]) {
		t.Errorf("kex = %v, want %v", ki.kex, lists[0])
	}
	if !reflect.DeepEqual(ki.hostKey, lists[1]) {
		t.Errorf("hostKey = %v, want %v", ki.hostKey, lists[1])
	}
	if !reflect.DeepEqual(ki.encS2C, lists[3]) {
		t.Errorf("encS2C = %v, want %v", ki.encS2C, lists[3])
	}
	if !reflect.DeepEqual(ki.macS2C, lists[5]) {
		t.Errorf("macS2C = %v, want %v", ki.macS2C, lists[5])
	}
	// Empty language lists must be non-nil empty slices.
	if ki.langS2C == nil || len(ki.langS2C) != 0 {
		t.Errorf("langS2C = %v, want non-nil empty", ki.langS2C)
	}
}

func TestParseKexInit_Malformed(t *testing.T) {
	valid := framePacket(buildKexInitPayload(sampleLists()))

	// Payload with an over-long name-list length (claims 0xffffffff bytes).
	overrun := func() []byte {
		var buf bytes.Buffer
		buf.WriteByte(msgKexInit)
		buf.Write(make([]byte, cookieLen))
		buf.Write([]byte{0xff, 0xff, 0xff, 0xff}) // name-list length overruns
		return framePacket(buf.Bytes())
	}()

	// Payload whose first name-list contains a non-printable byte.
	nonPrintable := func() []byte {
		var buf bytes.Buffer
		buf.WriteByte(msgKexInit)
		buf.Write(make([]byte, cookieLen))
		buf.Write(nameListBytes([]string{"ok"}))
		// overwrite one name byte with 0x01 after building the frame below
		p := buf.Bytes()
		p[cookieLen+1+4] = 0x01 // first byte of "ok"
		return framePacket(p)
	}()

	// A raw oversized length header.
	oversized := func() []byte {
		var hdr [4]byte
		binary.BigEndian.PutUint32(hdr[:], maxPacketLen+1)
		return hdr[:]
	}()

	// A length header below the minimum.
	tooSmall := func() []byte {
		var hdr [4]byte
		binary.BigEndian.PutUint32(hdr[:], 1)
		return hdr[:]
	}()

	// padding_length larger than the packet body.
	badPadding := func() []byte {
		var buf bytes.Buffer
		_ = binary.Write(&buf, binary.BigEndian, uint32(3))
		buf.WriteByte(200) // padding_length way over packetLen
		buf.Write([]byte{msgKexInit, 0})
		return buf.Bytes()
	}()

	cases := []struct {
		name string
		in   []byte
	}{
		{"empty", nil},
		{"length-header-only", valid[:4]},
		{"truncated-body", valid[:8]},
		{"wrong-msg-type", func() []byte { p := buildKexInitPayload(sampleLists()); p[0] = 5; return framePacket(p) }()},
		{"name-list-overrun", overrun},
		{"non-printable-name", nonPrintable},
		{"oversized-length", oversized},
		{"below-min-length", tooSmall},
		{"bad-padding", badPadding},
		{"garbage", []byte{0x00, 0x00, 0x00, 0x10, 0xde, 0xad, 0xbe, 0xef}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseKexInit(tc.in); err == nil {
				t.Errorf("parseKexInit(%s): want error, got nil", tc.name)
			}
		})
	}
}

// --- fuzz ------------------------------------------------------------------

func FuzzParseKexInit(f *testing.F) {
	f.Add(framePacket(buildKexInitPayload(sampleLists())))
	f.Add([]byte(nil))
	f.Add([]byte{0x00, 0x00, 0x00, 0x02, 0x00, msgKexInit})
	var big [4]byte
	binary.BigEndian.PutUint32(big[:], maxPacketLen+1)
	f.Add(big[:])
	f.Add([]byte("SSH-2.0-not-a-packet"))
	f.Add(framePacket([]byte{msgKexInit}))

	f.Fuzz(func(t *testing.T, data []byte) {
		// The contract is only "no panic"; a returned error is fine.
		_, _ = parseKexInit(data)
	})
}

// --- assertion helpers -----------------------------------------------------

func assertAttr(t *testing.T, f probe.Finding, key string, want any) {
	t.Helper()
	got, ok := f.Attrs[key]
	if !ok {
		t.Errorf("attr %q missing", key)
		return
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("attr %q = %#v, want %#v", key, got, want)
	}
}

func assertProvenance(t *testing.T, ps []graph.Provenance, tgt probe.Target) {
	t.Helper()
	if len(ps) != 1 {
		t.Fatalf("want 1 provenance record, got %d", len(ps))
	}
	p := ps[0]
	if p.Source != graph.SourceProbe {
		t.Errorf("prov source = %q, want %q", p.Source, graph.SourceProbe)
	}
	if p.Location != tgt.Addr() {
		t.Errorf("prov location = %q, want %q", p.Location, tgt.Addr())
	}
	if p.Detail != "ssh KEXINIT" {
		t.Errorf("prov detail = %q, want %q", p.Detail, "ssh KEXINIT")
	}
}

func assertEndpointNode(t *testing.T, g *graph.Graph, tgt probe.Target, banner string, ciphers []string) {
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
	if ep.Host != tgt.Host || ep.Port != tgt.Port {
		t.Errorf("node host:port = %s:%d, want %s:%d", ep.Host, ep.Port, tgt.Host, tgt.Port)
	}
	if got := ep.Attrs["banner"]; got != banner {
		t.Errorf("node attrs[banner] = %v, want %q", got, banner)
	}
	if got, _ := ep.Attrs["ciphers"].([]string); !reflect.DeepEqual(got, ciphers) {
		t.Errorf("node attrs[ciphers] = %v, want %v", got, ciphers)
	}
	found := false
	for _, p := range ep.Provenance() {
		if p.Source == graph.SourceProbe && p.Location == tgt.Addr() && p.Detail == "ssh KEXINIT" {
			found = true
		}
	}
	if !found {
		t.Errorf("node provenance %v missing probe record for %s", ep.Provenance(), tgt.Addr())
	}
}

func assertNoEndpointNode(t *testing.T, g *graph.Graph, tgt probe.Target) {
	t.Helper()
	id, err := graph.EndpointNodeID(tgt.Host, tgt.Port)
	if err != nil {
		return
	}
	if _, ok := g.Node(id); ok {
		t.Errorf("endpoint node %q unexpectedly present", id)
	}
}
