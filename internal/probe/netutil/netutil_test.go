package netutil

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

func TestOptionsNormalize(t *testing.T) {
	got := Options{}.Normalize()
	if got.Timeout != DefaultTimeout {
		t.Errorf("Timeout = %v, want %v", got.Timeout, DefaultTimeout)
	}
	if got.Concurrency != DefaultConcurrency {
		t.Errorf("Concurrency = %d, want %d", got.Concurrency, DefaultConcurrency)
	}
	if got.Rate != DefaultRate {
		t.Errorf("Rate = %v, want %v", got.Rate, DefaultRate)
	}
	if got.Burst != DefaultBurst {
		t.Errorf("Burst = %d, want %d", got.Burst, DefaultBurst)
	}

	// Sentinels: negative timeout and non-positive rate are preserved (opt-out),
	// but a sub-1 concurrency/burst is clamped up to 1.
	sent := Options{Timeout: -1, Concurrency: -5, Rate: -1, Burst: -3}.Normalize()
	if sent.Timeout != -1 {
		t.Errorf("negative Timeout not preserved: %v", sent.Timeout)
	}
	if sent.Rate != -1 {
		t.Errorf("negative Rate not preserved: %v", sent.Rate)
	}
	if sent.Concurrency != 1 {
		t.Errorf("Concurrency clamp = %d, want 1", sent.Concurrency)
	}
	if sent.Burst != 1 {
		t.Errorf("Burst clamp = %d, want 1", sent.Burst)
	}
}

// TestRateLimiterReserve exercises the token-bucket math deterministically by
// driving reserve with a controlled clock — no real sleeping, no flakiness.
func TestRateLimiterReserve(t *testing.T) {
	// rate 1000/s => 1ms per token; burst 2 => bucket starts with 2 tokens.
	r := NewRateLimiter(1000, 2)
	t0 := time.Now()

	if w := r.reserve(t0); w != 0 {
		t.Fatalf("reserve #1 wait = %v, want 0 (burst token)", w)
	}
	if w := r.reserve(t0); w != 0 {
		t.Fatalf("reserve #2 wait = %v, want 0 (burst token)", w)
	}
	// Bucket now empty: third permit is reserved 1ms out, fourth 2ms out.
	if w := r.reserve(t0); w != time.Millisecond {
		t.Fatalf("reserve #3 wait = %v, want 1ms", w)
	}
	if w := r.reserve(t0); w != 2*time.Millisecond {
		t.Fatalf("reserve #4 wait = %v, want 2ms", w)
	}
	// Advance the clock 1ms => one token refills; balance was -2, becomes -1,
	// consuming leaves -2 again => 2ms wait.
	if w := r.reserve(t0.Add(time.Millisecond)); w != 2*time.Millisecond {
		t.Fatalf("reserve #5 wait = %v, want 2ms", w)
	}
}

func TestRateLimiterNilUnlimited(t *testing.T) {
	var r *RateLimiter // nil == unlimited
	if err := r.Wait(context.Background()); err != nil {
		t.Fatalf("nil limiter Wait = %v, want nil", err)
	}
	// A nil limiter still surfaces an already-cancelled context.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := r.Wait(ctx); err == nil {
		t.Fatal("nil limiter Wait with cancelled ctx = nil, want ctx error")
	}
}

func TestRateLimiterWaitCancel(t *testing.T) {
	r := NewRateLimiter(1, 1) // 1/s: after the burst token, waits ~1s
	if err := r.Wait(context.Background()); err != nil {
		t.Fatalf("first Wait (burst) = %v, want nil", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := r.Wait(ctx); err == nil {
		t.Fatal("second Wait = nil, want ctx deadline error")
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("Wait blocked %v past ctx deadline; should have returned promptly", elapsed)
	}
}

// TestRateLimiterWaitSpacing is a coarse integration check: it asserts only a
// lower bound on elapsed time (waits can only be >= requested), so it is not
// timing-flaky.
func TestRateLimiterWaitSpacing(t *testing.T) {
	r := NewRateLimiter(100, 1) // 10ms per token, burst 1
	const n = 4                 // 1 immediate + 3 spaced => >= 30ms
	start := time.Now()
	for i := 0; i < n; i++ {
		if err := r.Wait(context.Background()); err != nil {
			t.Fatalf("Wait #%d: %v", i, err)
		}
	}
	if elapsed := time.Since(start); elapsed < 25*time.Millisecond {
		t.Fatalf("elapsed %v for %d waits at 100/s, want >= ~30ms", elapsed, n)
	}
}

func TestDialerSuccessAndTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_ = c.Close()
	}()

	d := &Dialer{Timeout: time.Second}
	conn, err := d.DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("DialContext to open listener: %v", err)
	}
	_ = conn.Close()
	wg.Wait()
}

func TestDialerRefused(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close() // now nothing listens on addr

	d := &Dialer{Timeout: 500 * time.Millisecond}
	if conn, err := d.DialContext(context.Background(), "tcp", addr); err == nil {
		_ = conn.Close()
		t.Fatal("DialContext to closed port = nil error, want failure")
	}
}

func TestDialerHonorsCancelledContext(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d := &Dialer{Timeout: time.Second, Limiter: NewRateLimiter(1000, 1)}
	if conn, err := d.DialContext(ctx, "tcp", ln.Addr().String()); err == nil {
		_ = conn.Close()
		t.Fatal("DialContext with cancelled ctx = nil error, want ctx error")
	}
}
