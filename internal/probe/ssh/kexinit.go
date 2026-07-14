package ssh

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Wire-format limits and message ids (RFC 4253 §6, §7.1). Every read below is
// bounded against these so no malformed, truncated, or oversized server data can
// drive an unbounded allocation, an out-of-range slice, or a panic.
const (
	// maxPacketLen caps the RFC 4253 packet_length field. A larger header is
	// rejected as malformed before any body allocation, so a hostile server
	// cannot make us allocate arbitrary memory. 64 KiB is far above a real
	// KEXINIT (a few hundred bytes) yet a hard, documented ceiling.
	maxPacketLen = 64 * 1024
	// minPacketLen is the smallest legal packet: one padding_length byte plus at
	// least one payload byte (the message id).
	minPacketLen = 2
	// msgKexInit is SSH_MSG_KEXINIT, the first message id we require in the
	// packet payload (RFC 4253 §7.1).
	msgKexInit = 20
	// cookieLen is the fixed 16-byte KEXINIT cookie.
	cookieLen = 16
)

// errTruncated marks a read that ran past the end of the available bytes. It is
// wrapped with context by the caller so the surfaced error still reads cleanly.
var errTruncated = errors.New("ssh: unexpected end of data")

// kexInit is the parsed set of algorithm name-lists a server advertises in its
// SSH_MSG_KEXINIT (RFC 4253 §7.1), in wire order.
type kexInit struct {
	kex      []string // kex_algorithms
	hostKey  []string // server_host_key_algorithms
	encC2S   []string // encryption_algorithms_client_to_server
	encS2C   []string // encryption_algorithms_server_to_client
	macC2S   []string // mac_algorithms_client_to_server
	macS2C   []string // mac_algorithms_server_to_client
	compC2S  []string // compression_algorithms_client_to_server
	compS2C  []string // compression_algorithms_server_to_client
	langC2S  []string // languages_client_to_server
	langS2C  []string // languages_server_to_client
	firstKex bool     // first_kex_packet_follows
}

// readPacket reads exactly one unencrypted SSH binary packet (RFC 4253 §6) from
// r and returns its payload. The packet framing is:
//
//	uint32    packet_length          (length of the rest of the packet)
//	byte      padding_length
//	byte[n1]  payload                (n1 = packet_length - padding_length - 1)
//	byte[n2]  random padding         (n2 = padding_length)
//
// There is no MAC and the stream is not yet encrypted at this stage. Every field
// is bounds-checked: the length header is rejected if below minPacketLen or above
// maxPacketLen (before any allocation), and padding_length is rejected if it
// would leave a non-positive payload. A short read surfaces as a wrapped error,
// never a panic.
func readPacket(r io.Reader) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, fmt.Errorf("ssh: reading packet length: %w", err)
	}
	packetLen := binary.BigEndian.Uint32(lenBuf[:])
	if packetLen < minPacketLen {
		return nil, fmt.Errorf("ssh: packet length %d below minimum %d", packetLen, minPacketLen)
	}
	if packetLen > maxPacketLen {
		return nil, fmt.Errorf("ssh: packet length %d exceeds maximum %d", packetLen, maxPacketLen)
	}
	body := make([]byte, packetLen)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, fmt.Errorf("ssh: reading packet body: %w", err)
	}
	paddingLen := int(body[0])
	// payload occupies body[1 : packetLen-paddingLen]; guard the split so a
	// padding_length larger than the packet cannot produce a negative bound.
	payloadEnd := int(packetLen) - paddingLen
	if payloadEnd < 1 || payloadEnd > int(packetLen) {
		return nil, fmt.Errorf("ssh: padding length %d invalid for packet length %d", paddingLen, packetLen)
	}
	return body[1:payloadEnd], nil
}

// parseKexInit reads one packet from frame (which begins at the packet_length
// field) and parses its payload as an SSH_MSG_KEXINIT. It is the single entry
// point exercised by the fuzz target, so it composes the packet framing and the
// KEXINIT payload parse behind one bounded, panic-free call.
func parseKexInit(frame []byte) (*kexInit, error) {
	payload, err := readPacket(bytes.NewReader(frame))
	if err != nil {
		return nil, err
	}
	return parseKexInitPayload(payload)
}

// parseKexInitPayload parses a decoded packet payload as an SSH_MSG_KEXINIT
// (RFC 4253 §7.1): a message id (must be 20), a 16-byte cookie, ten name-lists
// in the fixed RFC order, a boolean first_kex_packet_follows, and a reserved
// uint32. Every field is read through cursor, which bounds each access against
// the remaining payload, so truncation or an over-long name-list length is a
// wrapped error rather than a panic.
func parseKexInitPayload(payload []byte) (*kexInit, error) {
	if len(payload) == 0 {
		return nil, fmt.Errorf("ssh: empty KEXINIT payload")
	}
	c := &cursor{b: payload}
	msg, _ := c.byte() // safe: len > 0 checked above
	if msg != msgKexInit {
		return nil, fmt.Errorf("ssh: expected SSH_MSG_KEXINIT (%d), got message id %d", msgKexInit, msg)
	}
	if _, err := c.fixed(cookieLen); err != nil {
		return nil, fmt.Errorf("ssh: reading KEXINIT cookie: %w", err)
	}

	var ki kexInit
	lists := []struct {
		name string
		dst  *[]string
	}{
		{"kex_algorithms", &ki.kex},
		{"server_host_key_algorithms", &ki.hostKey},
		{"encryption_algorithms_client_to_server", &ki.encC2S},
		{"encryption_algorithms_server_to_client", &ki.encS2C},
		{"mac_algorithms_client_to_server", &ki.macC2S},
		{"mac_algorithms_server_to_client", &ki.macS2C},
		{"compression_algorithms_client_to_server", &ki.compC2S},
		{"compression_algorithms_server_to_client", &ki.compS2C},
		{"languages_client_to_server", &ki.langC2S},
		{"languages_server_to_client", &ki.langS2C},
	}
	for _, l := range lists {
		names, err := c.nameList()
		if err != nil {
			return nil, fmt.Errorf("ssh: reading %s: %w", l.name, err)
		}
		*l.dst = names
	}

	first, err := c.byte()
	if err != nil {
		return nil, fmt.Errorf("ssh: reading first_kex_packet_follows: %w", err)
	}
	ki.firstKex = first != 0
	if _, err := c.uint32(); err != nil {
		return nil, fmt.Errorf("ssh: reading reserved field: %w", err)
	}
	// Any trailing bytes (there should be none) are ignored: they cannot affect
	// the advertised algorithm lists we already parsed.
	return &ki, nil
}

// cursor is a bounds-checked forward reader over a byte slice. Every accessor
// verifies the requested span fits in the remaining bytes before advancing, so a
// malformed length can never index out of range.
type cursor struct {
	b   []byte
	off int
}

func (c *cursor) byte() (byte, error) {
	if c.off >= len(c.b) {
		return 0, errTruncated
	}
	v := c.b[c.off]
	c.off++
	return v, nil
}

func (c *cursor) uint32() (uint32, error) {
	if len(c.b)-c.off < 4 {
		return 0, errTruncated
	}
	v := binary.BigEndian.Uint32(c.b[c.off : c.off+4])
	c.off += 4
	return v, nil
}

// fixed returns the next n bytes. The remaining-length check is written as
// n > len-off (never off+n) so a huge n cannot overflow int on 32-bit builds.
func (c *cursor) fixed(n int) ([]byte, error) {
	if n < 0 || n > len(c.b)-c.off {
		return nil, errTruncated
	}
	v := c.b[c.off : c.off+n]
	c.off += n
	return v, nil
}

// nameList reads an RFC 4251 name-list: a uint32 byte-length followed by that
// many bytes of comma-separated printable-ASCII names. An empty list yields a
// non-nil empty slice.
func (c *cursor) nameList() ([]string, error) {
	n, err := c.uint32()
	if err != nil {
		return nil, err
	}
	raw, err := c.fixed(int(n))
	if err != nil {
		return nil, fmt.Errorf("name-list of %d bytes overruns packet: %w", n, err)
	}
	return splitNameList(raw)
}

// splitNameList validates that raw contains only printable ASCII (plus the comma
// separator) and splits it into names. RFC 4251 §5 requires name-list elements
// to be printable US-ASCII and never contain a comma.
func splitNameList(raw []byte) ([]string, error) {
	for _, ch := range raw {
		if ch == ',' {
			continue
		}
		if ch < 0x20 || ch > 0x7e {
			return nil, fmt.Errorf("ssh: name-list contains non-printable byte 0x%02x", ch)
		}
	}
	if len(raw) == 0 {
		return []string{}, nil
	}
	return strings.Split(string(raw), ","), nil
}
