package cli

import (
	"errors"
	"syscall"
)

// brokenPipeErrnos are the non-EPIPE OS errnos that mean the read end of our
// stdout pipe was closed before we finished writing. On Windows a broken pipe is
// NOT reported as syscall.EPIPE but as a Windows errno:
//
//   - 109 = ERROR_BROKEN_PIPE ("The pipe has been closed").
//   - 232 = ERROR_NO_DATA ("The pipe is being closed"); this is the one observed
//     here as "write /dev/stdout: The pipe has been ended." when piping into a
//     reader such as `head`/`more` that exits early.
//
// The numeric literals are used deliberately: syscall.ERROR_NO_DATA is not
// exported by the standard syscall package on Go 1.26, and referencing any
// windows-only constant would not compile on the linux CI target. These values
// are Windows-specific; they are not valid write() errnos on Unix (where a
// broken pipe is EPIPE, matched separately below), so listing them on every
// platform is harmless and keeps the classifier — and its test — portable.
var brokenPipeErrnos = []syscall.Errno{
	109, // ERROR_BROKEN_PIPE
	232, // ERROR_NO_DATA — "The pipe has been ended."
}

// isBrokenPipe reports whether err is a broken-/closed-pipe write error: the
// reader on the other end of our stdout pipe (head, less, jq, ...) exited before
// we finished writing. Standard Unix tools treat this as a silent, non-fatal
// condition, so the CLI does the same — a machine-format command piped into
// `head` must exit 0 with no error line on stderr.
//
// Detection is cross-platform: on Unix the write error wraps syscall.EPIPE; on
// Windows it wraps one of brokenPipeErrnos. Only broken-pipe conditions match; a
// genuine write failure such as "disk full" (ENOSPC) or a permission error is
// NOT swallowed and must still surface as a real error (exit 1).
func isBrokenPipe(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.EPIPE) {
		return true
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		for _, e := range brokenPipeErrnos {
			if errno == e {
				return true
			}
		}
	}
	return false
}
