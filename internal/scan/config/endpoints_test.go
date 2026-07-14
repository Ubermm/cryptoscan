package config

import (
	"reflect"
	"sort"
	"testing"
)

func epByServer(eps []*endpointResult, name string) *endpointResult {
	for _, e := range eps {
		for _, s := range e.serverNames {
			if s == name {
				return e
			}
		}
	}
	return nil
}

func epByPort(eps []*endpointResult, port int) *endpointResult {
	for _, e := range eps {
		if e.port == port {
			return e
		}
	}
	return nil
}

func sortEqual(a, b []string) bool {
	ac := append([]string(nil), a...)
	bc := append([]string(nil), b...)
	sort.Strings(ac)
	sort.Strings(bc)
	return reflect.DeepEqual(ac, bc)
}

// TestNginxEndpoints proves per-server attribution: a multi-server file splits
// its TLS versions across the correct host:port, a plain-HTTP block emits no
// endpoint, http{}-level defaults are inherited, and the new ssl_ecdh_curve is
// captured per endpoint.
func TestNginxEndpoints(t *testing.T) {
	multi := `http {
  server { listen 443 ssl; server_name a.example.com; ssl_protocols TLSv1.2 TLSv1.3; ssl_certificate a.pem; }
  server { listen 8443 ssl; server_name b.example.com; ssl_protocols TLSv1 TLSv1.1 TLSv1.2; ssl_certificate b.pem; }
  server { listen 80; server_name c.example.com; }
}`
	eps := nginxEndpoints(multi)
	if len(eps) != 2 {
		t.Fatalf("multi-server endpoints = %d, want 2 (block C is plain HTTP)", len(eps))
	}
	a := epByServer(eps, "a.example.com")
	b := epByServer(eps, "b.example.com")
	if a == nil || b == nil {
		t.Fatalf("missing endpoint: a=%v b=%v", a, b)
	}
	if a.port != 443 || !sortEqual(a.protocols, []string{"TLSv1.2", "TLSv1.3"}) {
		t.Errorf("a: port=%d protocols=%v, want 443 [TLSv1.2 TLSv1.3]", a.port, a.protocols)
	}
	if b.port != 8443 || !sortEqual(b.protocols, []string{"TLSv1", "TLSv1.1", "TLSv1.2"}) {
		t.Errorf("b: port=%d protocols=%v, want 8443 [TLSv1 TLSv1.1 TLSv1.2]", b.port, b.protocols)
	}
	// TLS 1.0/1.1 must be attributed to b ONLY.
	if contains(a.protocols, "TLSv1") {
		t.Error("TLS 1.0 must not be attributed to a.example.com")
	}

	// http{}-level default inheritance + new ssl_ecdh_curve.
	inherit := `http {
  ssl_protocols TLSv1.2 TLSv1.3;
  server { listen 443 ssl; server_name x.example.com; ssl_certificate x.pem; ssl_ecdh_curve X25519:secp384r1; }
}`
	eps = nginxEndpoints(inherit)
	if len(eps) != 1 {
		t.Fatalf("inherit endpoints = %d, want 1", len(eps))
	}
	if !sortEqual(eps[0].protocols, []string{"TLSv1.2", "TLSv1.3"}) {
		t.Errorf("inherited protocols = %v, want [TLSv1.2 TLSv1.3]", eps[0].protocols)
	}
	if eps[0].ecdhCurve != "X25519:secp384r1" {
		t.Errorf("ecdh_curve = %q, want X25519:secp384r1", eps[0].ecdhCurve)
	}
}

func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

// TestApacheEndpoints proves per-vhost attribution: only the TLS vhost yields an
// endpoint, with the right port/server_name and Apache 2.4 protocol resolution.
func TestApacheEndpoints(t *testing.T) {
	in := `<VirtualHost *:80>
  ServerName plain.example.com
</VirtualHost>
<VirtualHost *:443>
  ServerName app.example.com
  SSLEngine on
  SSLProtocol -all +TLSv1.2
  SSLCipherSuite ECDHE-RSA-AES128-GCM-SHA256
  SSLCertificateFile leaf.pem
</VirtualHost>`
	eps := apacheEndpoints(in)
	if len(eps) != 1 {
		t.Fatalf("apache endpoints = %d, want 1 (only the :443 vhost is TLS)", len(eps))
	}
	e := eps[0]
	if e.port != 443 || !sortEqual(e.protocols, []string{"TLSv1.2"}) {
		t.Errorf("port=%d protocols=%v, want 443 [TLSv1.2]", e.port, e.protocols)
	}
	if !contains(e.serverNames, "app.example.com") {
		t.Errorf("server_name = %v, want app.example.com", e.serverNames)
	}
	if !sortEqual(e.certRefs, []string{"leaf.pem"}) {
		t.Errorf("cert_refs = %v, want [leaf.pem]", e.certRefs)
	}
}

// TestHAProxyEndpoints proves per-bind attribution: each TLS bind is its own
// endpoint with global options as its base, and a per-bind ssl-min-ver overrides
// that base for that bind only (issue #5). A non-ssl bind emits nothing.
func TestHAProxyEndpoints(t *testing.T) {
	in := `global
  ssl-default-bind-options no-sslv3 no-tlsv10
frontend f
  bind :80
  bind :443 ssl crt a.pem
  bind :8443 ssl crt b.pem ssl-min-ver TLSv1.2
backend b
  server s 127.0.0.1:9000`
	eps := haproxyEndpoints(in)
	if len(eps) != 2 {
		t.Fatalf("haproxy endpoints = %d, want 2 (the :80 bind has no ssl)", len(eps))
	}
	e443 := epByPort(eps, 443)
	e8443 := epByPort(eps, 8443)
	if e443 == nil || e8443 == nil {
		t.Fatalf("missing bind endpoint: 443=%v 8443=%v", e443, e8443)
	}
	// base = TLSv1.1..TLSv1.3 (no-tlsv10 removed TLSv1).
	if !sortEqual(e443.protocols, []string{"TLSv1.1", "TLSv1.2", "TLSv1.3"}) {
		t.Errorf("bind :443 protocols = %v, want [TLSv1.1 TLSv1.2 TLSv1.3]", e443.protocols)
	}
	// per-bind ssl-min-ver TLSv1.2 floors this bind only.
	if !sortEqual(e8443.protocols, []string{"TLSv1.2", "TLSv1.3"}) {
		t.Errorf("bind :8443 protocols = %v, want [TLSv1.2 TLSv1.3] (per-bind min-ver)", e8443.protocols)
	}
	if !sortEqual(e443.certRefs, []string{"a.pem"}) || !sortEqual(e8443.certRefs, []string{"b.pem"}) {
		t.Errorf("cert_refs mismatch: 443=%v 8443=%v", e443.certRefs, e8443.certRefs)
	}
}
