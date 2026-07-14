package certs

import (
	"encoding/asn1"
	"errors"
	"io"
	"os"
)

// errPanic marks a recovered panic from a third-party parser so the walk can
// treat it as an ordinary "this file did not parse" outcome (no panics ever).
var errPanic = errors.New("certs: recovered panic in third-party parser")

// readCapped reads up to maxFileSize+1 bytes from path. The size check in the
// walk already skips oversized files; this bounds reads defensively in case the
// file grows between stat and open (robustness: never unboundedly allocate).
func readCapped(path string) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // scanner is explicitly pointed at this tree
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(io.LimitReader(f, maxFileSize+1))
}

// isSingleDER reports whether data is exactly one well-formed ASN.1 DER object
// with no trailing bytes. This rejects "looks like DER" files that carry
// trailing garbage (e.g. negatives/notreallyder.der), satisfying the "parses
// cleanly and COMPLETELY" requirement before any x509 parse is attempted.
func isSingleDER(data []byte) bool {
	if len(data) < 2 || data[0] != 0x30 { // top-level cert/CSR/key is a SEQUENCE
		return false
	}
	var raw asn1.RawValue
	rest, err := asn1.Unmarshal(data, &raw)
	if err != nil || len(rest) != 0 {
		return false
	}
	return raw.Class == asn1.ClassUniversal && raw.Tag == asn1.TagSequence
}
