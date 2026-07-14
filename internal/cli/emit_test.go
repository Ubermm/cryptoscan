package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// errWriter is a fake io.Writer that fails every write with a fixed error. It
// lets the emit path be driven with a broken-pipe (or any other) write failure
// without actually breaking a real OS pipe.
type errWriter struct{ err error }

func (w errWriter) Write(p []byte) (int, error) { return 0, w.err }

// TestWriteToDestSwallowsBrokenPipe asserts that when the stdout writer fails
// with a broken-pipe error, writeToDest returns nil (exit 0) — matching how
// standard Unix tools behave when piped into `head`/`less`.
func TestWriteToDestSwallowsBrokenPipe(t *testing.T) {
	brokenPipes := []struct {
		name string
		err  error
	}{
		{"wrapped EPIPE", fmt.Errorf("cbom: writing BOM: write /dev/stdout: %w", syscall.EPIPE)},
		{"windows ERROR_NO_DATA", fmt.Errorf("write /dev/stdout: %w", syscall.Errno(232))},
		{"windows ERROR_BROKEN_PIPE", fmt.Errorf("write /dev/stdout: %w", syscall.Errno(109))},
	}
	for _, bp := range brokenPipes {
		t.Run(bp.name, func(t *testing.T) {
			w := errWriter{err: bp.err}
			// fn writes to w and surfaces w's error, exactly like the real emitters.
			err := writeToDest(w, "", func(out io.Writer) error {
				_, e := out.Write([]byte("some machine output"))
				return e
			})
			if err != nil {
				t.Fatalf("writeToDest with broken pipe = %v, want nil", err)
			}
		})
	}
}

// TestWriteToDestPropagatesRealWriteError asserts that a NON-broken-pipe write
// failure (e.g. disk full) is still returned as a real error (exit 1), never
// swallowed.
func TestWriteToDestPropagatesRealWriteError(t *testing.T) {
	diskFull := fmt.Errorf("write /dev/stdout: %w", syscall.ENOSPC)
	w := errWriter{err: diskFull}
	err := writeToDest(w, "", func(out io.Writer) error {
		_, e := out.Write([]byte("some machine output"))
		return e
	})
	if err == nil {
		t.Fatal("writeToDest with disk-full error = nil, want the error propagated")
	}
	if !errors.Is(err, syscall.ENOSPC) {
		t.Errorf("writeToDest error = %v, want it to wrap ENOSPC", err)
	}
}

// TestWriteToDestOutputFileUnwritable asserts the --output error path still
// exits 1: creating a file under a path whose parent does not exist fails, and
// that error is returned (not swallowed as a broken pipe).
func TestWriteToDestOutputFileUnwritable(t *testing.T) {
	// A file path whose parent directory does not exist -> os.Create fails.
	bad := filepath.Join(t.TempDir(), "no-such-dir", "out.json")
	err := writeToDest(io.Discard, bad, func(out io.Writer) error {
		_, e := out.Write([]byte("x"))
		return e
	})
	if err == nil {
		t.Fatal("writeToDest to an uncreatable --output path = nil, want an error")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("writeToDest error = %v, want it to wrap a create failure", err)
	}
}
