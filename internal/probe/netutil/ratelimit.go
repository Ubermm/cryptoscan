package netutil

import (
	"context"
	"sync"
	"time"
)

// RateLimiter is a token-bucket limiter that caps the average rate of an event
// (here: opening a new connection) to Rate per second while permitting short
// bursts up to Burst. It is safe for concurrent use.
//
// The implementation is the classic reservation bucket: tokens accrue at Rate
// and each Wait consumes one, letting the balance go negative to reserve future
// capacity. Because reservation happens under the lock, concurrent waiters are
// serialized onto a deterministic schedule (no thundering herd), which also
// makes the timing testable.
type RateLimiter struct {
	mu     sync.Mutex
	rate   float64   // tokens (permits) per second
	max    float64   // bucket capacity (burst)
	tokens float64   // current balance; may be negative (reserved ahead)
	last   time.Time // last time the balance was refilled
}

// NewRateLimiter returns a limiter granting ratePerSec tokens per second with a
// bucket capacity of burst (clamped to at least 1). The bucket starts full, so
// the first burst permits are granted without waiting. A ratePerSec <= 0 yields
// nil (an unlimited limiter — Wait tolerates a nil receiver).
func NewRateLimiter(ratePerSec float64, burst int) *RateLimiter {
	if ratePerSec <= 0 {
		return nil
	}
	if burst < 1 {
		burst = 1
	}
	return &RateLimiter{
		rate:   ratePerSec,
		max:    float64(burst),
		tokens: float64(burst),
		last:   time.Now(),
	}
}

// Wait blocks until a token is available or ctx is done. A nil limiter returns
// immediately (subject only to an already-cancelled ctx). On ctx cancellation it
// returns ctx.Err() without having consumed the pending sleep.
func (r *RateLimiter) Wait(ctx context.Context) error {
	if r == nil {
		return ctx.Err()
	}

	wait := r.reserve(time.Now())
	if wait <= 0 {
		return ctx.Err()
	}

	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// reserve refills the bucket for the time elapsed since the last call, consumes
// one token (allowing the balance to go negative), and returns how long the
// caller must sleep before that token is actually available (0 if immediately).
func (r *RateLimiter) reserve(now time.Time) time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()

	if elapsed := now.Sub(r.last).Seconds(); elapsed > 0 {
		r.tokens += elapsed * r.rate
		if r.tokens > r.max {
			r.tokens = r.max
		}
		r.last = now
	}

	r.tokens--
	if r.tokens >= 0 {
		return 0
	}
	// The balance is negative: this permit is reserved -tokens/rate into the
	// future. Concurrent callers each subtract one more, so they queue onto
	// distinct, increasing wake times.
	return time.Duration(-r.tokens / r.rate * float64(time.Second))
}
