package probe

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseTarget(t *testing.T) {
	tests := []struct {
		name     string
		in       string
		wantHost string
		wantPort int // 0 means unspecified
		wantErr  bool
	}{
		{name: "host and port", in: "example.com:443", wantHost: "example.com", wantPort: 443},
		{name: "bare host unspecified port", in: "example.com", wantHost: "example.com", wantPort: 0},
		{name: "trims whitespace", in: "  example.com:22  ", wantHost: "example.com", wantPort: 22},
		{name: "ipv4 with port", in: "192.0.2.10:8443", wantHost: "192.0.2.10", wantPort: 8443},
		{name: "ipv4 bare", in: "192.0.2.10", wantHost: "192.0.2.10", wantPort: 0},
		{name: "bracketed ipv6 with port", in: "[2001:db8::1]:443", wantHost: "2001:db8::1", wantPort: 443},
		{name: "bracketed ipv6 loopback with port", in: "[::1]:22", wantHost: "::1", wantPort: 22},
		{name: "bracketed ipv6 no port", in: "[::1]", wantHost: "::1", wantPort: 0},
		{name: "bare ipv6 literal", in: "2001:db8::1", wantHost: "2001:db8::1", wantPort: 0},
		{name: "port 1 boundary", in: "h:1", wantHost: "h", wantPort: 1},
		{name: "port 65535 boundary", in: "h:65535", wantHost: "h", wantPort: 65535},

		{name: "empty", in: "", wantErr: true},
		{name: "whitespace only", in: "   ", wantErr: true},
		{name: "port zero explicit", in: "h:0", wantErr: true},
		{name: "port too high", in: "h:70000", wantErr: true},
		{name: "port negative", in: "h:-1", wantErr: true},
		{name: "port not a number", in: "h:https", wantErr: true},
		{name: "empty host", in: ":443", wantErr: true},
		{name: "empty port after colon", in: "example.com:", wantErr: true},
		{name: "cidr rejected", in: "10.0.0.0/24", wantErr: true},
		{name: "url-ish rejected", in: "https://example.com", wantErr: true},
		{name: "ipv4 range rejected", in: "10.0.0.1-10.0.0.9", wantErr: true},
		{name: "ipv4 short range rejected", in: "10.0.0.1-9", wantErr: true},
		{name: "unbracketed ipv6 with trailing port is malformed", in: "2001:db8::1:port", wantErr: true},
		{name: "bad bracketed non-ipv6", in: "[not-an-ip]", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseTarget(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseTarget(%q) = %+v, want error", tt.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseTarget(%q) unexpected error: %v", tt.in, err)
			}
			if got.Host != tt.wantHost || got.Port != tt.wantPort {
				t.Fatalf("ParseTarget(%q) = host %q port %d, want host %q port %d",
					tt.in, got.Host, got.Port, tt.wantHost, tt.wantPort)
			}
			if got.Raw != strings.TrimSpace(tt.in) {
				t.Fatalf("ParseTarget(%q).Raw = %q, want trimmed input", tt.in, got.Raw)
			}
		})
	}
}

// A range that resembles a hostname with hyphens must NOT be rejected as a range.
func TestParseTargetHyphenHostname(t *testing.T) {
	got, err := ParseTarget("1-800-flowers.example.com:443")
	if err != nil {
		t.Fatalf("hyphenated hostname wrongly rejected: %v", err)
	}
	if got.Host != "1-800-flowers.example.com" || got.Port != 443 {
		t.Fatalf("got host %q port %d", got.Host, got.Port)
	}
}

func TestTargetAddr(t *testing.T) {
	tests := []struct {
		host string
		port int
		want string
	}{
		{"example.com", 443, "example.com:443"},
		{"2001:db8::1", 443, "[2001:db8::1]:443"},
		{"::1", 22, "[::1]:22"},
	}
	for _, tt := range tests {
		got := Target{Host: tt.host, Port: tt.port}.Addr()
		if got != tt.want {
			t.Fatalf("Target{%q,%d}.Addr() = %q, want %q", tt.host, tt.port, got, tt.want)
		}
	}
}

func TestParseTargets(t *testing.T) {
	got, err := ParseTargets([]string{"a.com", "b.com:22", "[::1]"}, 443)
	if err != nil {
		t.Fatalf("ParseTargets: %v", err)
	}
	want := []Target{
		{Host: "a.com", Port: 443, Raw: "a.com"},
		{Host: "b.com", Port: 22, Raw: "b.com:22"},
		{Host: "::1", Port: 443, Raw: "[::1]"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d targets, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("target %d = %+v, want %+v", i, got[i], want[i])
		}
	}

	// Invalid default port rejected.
	if _, err := ParseTargets([]string{"a.com"}, 0); err == nil {
		t.Fatal("ParseTargets with default port 0 should error")
	}
	if _, err := ParseTargets([]string{"a.com", "bad/cidr/24"}, 443); err == nil {
		t.Fatal("ParseTargets should propagate a per-arg error")
	}
}

func TestParseTargetFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "targets.txt")
	content := "" +
		"# a comment line\n" +
		"\n" +
		"   \n" +
		"example.com\n" +
		"   host.example:8443   \n" +
		"# another comment\n" +
		"[2001:db8::5]:993\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	got, err := ParseTargetFile(path, 443)
	if err != nil {
		t.Fatalf("ParseTargetFile: %v", err)
	}
	want := []Target{
		{Host: "example.com", Port: 443, Raw: "example.com"},
		{Host: "host.example", Port: 8443, Raw: "host.example:8443"},
		{Host: "2001:db8::5", Port: 993, Raw: "[2001:db8::5]:993"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d targets, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("target %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestParseTargetFileErrors(t *testing.T) {
	if _, err := ParseTargetFile(filepath.Join(t.TempDir(), "missing.txt"), 443); err == nil {
		t.Fatal("missing file should error")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "bad.txt")
	if err := os.WriteFile(path, []byte("good.com\n10.0.0.0/24\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := ParseTargetFile(path, 443)
	if err == nil {
		t.Fatal("CIDR line should cause an error")
	}
	if !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("error should name the offending line, got: %v", err)
	}
}
