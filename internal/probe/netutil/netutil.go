// Package netutil holds the shared connection-layer plumbing used by the Phase 2
// probers (internal/probe/tls today; internal/probe/ssh can adopt it later): a
// context-aware dialer with a per-connection timeout and a token-bucket rate
// limiter that caps the rate of new connections process-wide.
//
// Target-level fan-out is deliberately NOT here — that is the job of the single
// batch driver probe.Run. Rate limiting lives at the connection layer because
// one target performs several handshakes (the TLS prober does one per version),
// so limiting per connection is the meaningful global cap.
//
// Every knob lives on Options and has a sane default (DESIGN.md §1 network probe
// contract: 5s per-connection timeout, a global connection rate limit; all
// flag-overridable). Concurrency is retained on Options as the shared default a
// caller can feed into probe.Run's RunOptions. The package depends only on the
// standard library and never panics.
package netutil

import (
	"context"
	"net"
	"time"
)

// Default tuning values (DESIGN.md network probe contract). Each is applied by
// Options.Normalize when the corresponding field is left at its zero value.
const (
	DefaultTimeout     = 5 * time.Second
	DefaultConcurrency = 8
	DefaultRate        = 20.0 // new connections per second
	DefaultBurst       = 1    // token-bucket burst; 1 == strictly spaced
)

// Options configures dialing, concurrency, and rate limiting for network probes.
// The zero value is usable: Normalize fills every field with its documented
// default. All values are meant to be flag-overridable by the CLI.
type Options struct {
	// Timeout bounds a single connection attempt (dial, and — for the TLS
	// prober — the handshake). Zero selects DefaultTimeout; a negative value
	// disables the timeout.
	Timeout time.Duration
	// Concurrency is the maximum number of tasks Run executes at once. Zero
	// selects DefaultConcurrency; values < 1 after defaulting are clamped to 1.
	Concurrency int
	// Rate is the maximum number of new connections opened per second across the
	// whole probe, enforced by the shared RateLimiter a Dialer carries. Zero
	// selects DefaultRate; a negative value disables rate limiting.
	Rate float64
	// Burst is the token-bucket capacity: how many connections may be opened
	// back-to-back before the steady Rate applies. Zero selects DefaultBurst.
	Burst int
}

// Normalize returns a copy of o with zero-valued fields replaced by their
// defaults. Sentinel "disabled" values (negative Timeout, non-positive Rate) are
// preserved so callers can opt out explicitly.
func (o Options) Normalize() Options {
	if o.Timeout == 0 {
		o.Timeout = DefaultTimeout
	}
	if o.Concurrency == 0 {
		o.Concurrency = DefaultConcurrency
	}
	if o.Concurrency < 1 {
		o.Concurrency = 1
	}
	if o.Rate == 0 {
		o.Rate = DefaultRate
	}
	if o.Burst == 0 {
		o.Burst = DefaultBurst
	}
	if o.Burst < 1 {
		o.Burst = 1
	}
	return o
}

// NewRateLimiter builds the token-bucket limiter implied by o (after
// Normalize). A non-positive Rate yields a nil-behaving limiter that never
// blocks (RateLimiter.Wait handles a nil receiver).
func (o Options) NewRateLimiter() *RateLimiter {
	o = o.Normalize()
	if o.Rate <= 0 {
		return nil
	}
	return NewRateLimiter(o.Rate, o.Burst)
}

// NewDialer builds a Dialer from o (after Normalize), wiring in a freshly
// created shared rate limiter. Reuse one Dialer across every connection that
// should share a rate budget (e.g. all handshakes of every target in a probe.Run).
func (o Options) NewDialer() *Dialer {
	o = o.Normalize()
	return &Dialer{Timeout: o.Timeout, Limiter: o.NewRateLimiter()}
}

// Dialer opens TCP (or other stream) connections with a per-connection timeout
// and an optional shared rate limit. It is safe for concurrent use.
type Dialer struct {
	// Timeout bounds a single dial. Zero or negative means no dial timeout is
	// imposed here (the passed context still applies).
	Timeout time.Duration
	// Limiter, when non-nil, must grant a token before each dial proceeds, which
	// is how the global connection rate limit is enforced. A nil Limiter never
	// blocks.
	Limiter *RateLimiter

	base net.Dialer
}

// DialContext waits for a rate-limit token (if a Limiter is set), then dials
// addr with the per-connection timeout applied on top of ctx. A rate-limit wait
// that is cut short by ctx cancellation returns ctx's error and never opens a
// connection.
func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if d.Limiter != nil {
		if err := d.Limiter.Wait(ctx); err != nil {
			return nil, err
		}
	}
	if d.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, d.Timeout)
		defer cancel()
	}
	return d.base.DialContext(ctx, network, addr)
}
