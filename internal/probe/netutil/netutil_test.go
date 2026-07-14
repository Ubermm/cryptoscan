package netutil

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

func TestDialerSuccessAndClose(t *testing.T) {
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

	d := NewDialer()
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

// TestDialerHonorsContextDeadline proves the Dialer relies on the context
// deadline (the per-target timeout probe.Run sets) rather than any baked timeout
// of its own: an already-expired context fails the dial immediately.
func TestDialerHonorsContextDeadline(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d := NewDialer()
	if conn, err := d.DialContext(ctx, "tcp", ln.Addr().String()); err == nil {
		_ = conn.Close()
		t.Fatal("DialContext with cancelled ctx = nil error, want ctx error")
	}
}
