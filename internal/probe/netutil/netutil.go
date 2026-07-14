// Package netutil holds the shared connection-layer plumbing used by the Phase 2
// probers (internal/probe/tls, internal/probe/ssh): a context-aware dialer that
// honors the caller's context deadline.
//
// It deliberately owns NO policy of its own. Rate limiting, concurrency, and the
// per-target timeout all belong to the single batch driver probe.Run, which holds
// the ONE rate limiter (from --rate), the ONE concurrency bound (from
// --concurrency), and the per-target deadline (from --timeout). probe.Run stamps
// that deadline onto the context it hands each Probe, and the prober threads that
// context into every DialContext — so the Dialer honors exactly the harness's
// timeout instead of competing with a baked default of its own. A second limiter
// or a second timeout here would silently cap throughput or multiply a hang
// across a target's several handshakes, which is precisely what this package must
// not do.
//
// The package depends only on the standard library and never panics.
package netutil

import (
	"context"
	"net"
	"time"
)

// Dialer opens TCP (or other stream) connections, honoring the deadline of the
// context passed to DialContext. It carries no rate limiter: connection pacing is
// the harness's job (probe.Run's single rate limiter). It is safe for concurrent
// use.
type Dialer struct {
	// Timeout optionally shortens a single dial. Zero (the default) imposes no
	// dial timeout of its own, so the context deadline set by probe.Run governs;
	// a positive value is applied on top of the context via WithTimeout, i.e. the
	// EARLIER of the two deadlines wins. It never lengthens the context deadline.
	Timeout time.Duration

	base net.Dialer
}

// NewDialer returns a ready-to-use Dialer that relies entirely on the context
// deadline for cancellation and timeout.
func NewDialer() *Dialer { return &Dialer{} }

// DialContext dials addr honoring ctx's deadline. If Timeout > 0 it also applies
// that as an upper bound on this single dial (the earlier deadline wins). The
// context carries the per-target timeout owned by probe.Run.
func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if d.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, d.Timeout)
		defer cancel()
	}
	return d.base.DialContext(ctx, network, addr)
}
