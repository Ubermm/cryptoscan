package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
	"testing"
)

// TestIsBrokenPipe checks the cross-platform broken-pipe classifier: it must
// recognise a wrapped syscall.EPIPE (Unix) and the Windows broken-pipe errnos
// (109 ERROR_BROKEN_PIPE, 232 ERROR_NO_DATA) while rejecting unrelated errors.
// The Windows errnos are constructed directly as syscall.Errno so this test runs
// on every platform, not just Windows.
func TestIsBrokenPipe(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"epipe direct", syscall.EPIPE, true},
		{"epipe wrapped", fmt.Errorf("write /dev/stdout: %w", syscall.EPIPE), true},
		{"epipe double wrapped", fmt.Errorf("cbom: %w", fmt.Errorf("writing BOM: %w", syscall.EPIPE)), true},
		{"windows ERROR_BROKEN_PIPE (109)", syscall.Errno(109), true},
		{"windows ERROR_NO_DATA (232)", syscall.Errno(232), true},
		{"windows ERROR_NO_DATA wrapped", fmt.Errorf("write /dev/stdout: %w", syscall.Errno(232)), true},
		{"generic error", errors.New("boom"), false},
		{"permission error", fmt.Errorf("open x: %w", syscall.EACCES), false},
		{"os.ErrPermission", fmt.Errorf("bad: %w", os.ErrPermission), false},
		{"disk full ENOSPC", fmt.Errorf("write file: %w", syscall.ENOSPC), false},
		{"unrelated errno", syscall.Errno(2), false}, // ENOENT / ERROR_FILE_NOT_FOUND
		{"io.ErrClosedPipe (not a syscall)", io.ErrClosedPipe, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isBrokenPipe(tt.err); got != tt.want {
				t.Errorf("isBrokenPipe(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}
