package config

import (
	"reflect"
	"sort"
	"testing"
)

// strs returns the []string attr under key, or nil.
func strs(res *parseResult, key string) []string {
	if res == nil {
		return nil
	}
	v, ok := res.attrs[key]
	if !ok {
		return nil
	}
	s, _ := v.([]string)
	return s
}

func sortedEqual(a, b []string) bool {
	ac := append([]string(nil), a...)
	bc := append([]string(nil), b...)
	sort.Strings(ac)
	sort.Strings(bc)
	return reflect.DeepEqual(ac, bc)
}

func TestParseNginx(t *testing.T) {
	tests := []struct {
		name      string
		in        string
		claim     bool
		protocols []string
		ciphers   []string
		certRefs  []string
	}{
		{
			name:      "basic server block",
			in:        "server {\n ssl_protocols TLSv1.2 TLSv1.3;\n ssl_ciphers 'A:B:C';\n ssl_certificate /c.pem;\n}",
			claim:     true,
			protocols: []string{"TLSv1.2", "TLSv1.3"},
			ciphers:   []string{"A", "B", "C"},
			certRefs:  []string{"/c.pem"},
		},
		{
			name:      "union across blocks and cert dedupe",
			in:        "http {\n server { ssl_protocols TLSv1.2 TLSv1.3; ssl_certificate x.pem; }\n server { ssl_protocols TLSv1 TLSv1.1 TLSv1.2; ssl_certificate x.pem; }\n}",
			claim:     true,
			protocols: []string{"TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"},
			certRefs:  []string{"x.pem"},
		},
		{
			name:      "top-level directives (include snippet)",
			in:        "ssl_protocols TLSv1.2 TLSv1.3;\nssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384';\n",
			claim:     true,
			protocols: []string{"TLSv1.2", "TLSv1.3"},
			ciphers:   []string{"ECDHE-ECDSA-AES256-GCM-SHA384"},
		},
		{
			name:     "cert only, no protocols",
			in:       "server { ssl_certificate leaf-chain.pem; ssl_certificate_key k.key; include ssl-params.conf; }",
			claim:    true,
			certRefs: []string{"leaf-chain.pem"},
		},
		{
			name:  "all ssl commented out",
			in:    "server {\n # ssl_protocols TLSv1.2;\n # ssl_certificate x.pem;\n listen 80;\n}",
			claim: false,
		},
		{
			name:  "comment inside quoted cipher kept",
			in:    "ssl_ciphers 'ECDHE#NOTACOMMENT:AES128-SHA';",
			claim: true, ciphers: []string{"ECDHE#NOTACOMMENT", "AES128-SHA"},
		},
		{
			name:  "weird whitespace and tabs",
			in:    "\tssl_protocols\t TLSv1.2   TLSv1.3 ;\n",
			claim: true, protocols: []string{"TLSv1.2", "TLSv1.3"},
		},
		{
			name:  "unterminated block does not panic",
			in:    "server { ssl_protocols TLSv1.2;",
			claim: true, protocols: []string{"TLSv1.2"},
		},
		{
			name:  "unterminated quote does not panic",
			in:    "ssl_ciphers 'A:B",
			claim: true, ciphers: []string{"A", "B"},
		},
		{name: "no crypto directives", in: "server { listen 80; server_name x; }", claim: false},
		{name: "empty", in: "", claim: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := parseNginx(tc.in)
			if (res != nil) != tc.claim {
				t.Fatalf("claim = %v, want %v", res != nil, tc.claim)
			}
			if !tc.claim {
				return
			}
			if tc.protocols != nil && !sortedEqual(strs(res, "protocols"), tc.protocols) {
				t.Errorf("protocols = %v, want %v", strs(res, "protocols"), tc.protocols)
			}
			if tc.ciphers != nil && !sortedEqual(strs(res, "ciphers"), tc.ciphers) {
				t.Errorf("ciphers = %v, want %v", strs(res, "ciphers"), tc.ciphers)
			}
			if tc.certRefs != nil && !sortedEqual(strs(res, "cert_refs"), tc.certRefs) {
				t.Errorf("cert_refs = %v, want %v", strs(res, "cert_refs"), tc.certRefs)
			}
		})
	}
}

func TestResolveApacheProtocols(t *testing.T) {
	tests := []struct {
		in   []string
		want []string
	}{
		{[]string{"all", "-SSLv3"}, []string{"TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"}},
		{[]string{"-all", "+TLSv1.2", "+TLSv1.3"}, []string{"TLSv1.2", "TLSv1.3"}},
		{[]string{"-all", "+TLSv1.2"}, []string{"TLSv1.2"}},
		{[]string{"TLSv1.2", "TLSv1.3"}, []string{"TLSv1.2", "TLSv1.3"}},
		{[]string{"all"}, []string{"SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"}},
	}
	for _, tc := range tests {
		got := resolveApacheProtocols(tc.in).sorted()
		if !sortedEqual(got, tc.want) {
			t.Errorf("resolveApacheProtocols(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestParseApache(t *testing.T) {
	tests := []struct {
		name      string
		in        string
		claim     bool
		protocols []string
		ciphers   []string
		certRefs  []string
	}{
		{
			name:      "vhost with all -SSLv3",
			in:        "<VirtualHost *:443>\n SSLProtocol all -SSLv3\n SSLCipherSuite RC4-SHA:HIGH\n SSLCertificateFile ../c.pem\n</VirtualHost>",
			claim:     true,
			protocols: []string{"TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"},
			ciphers:   []string{"RC4-SHA", "HIGH"},
			certRefs:  []string{"../c.pem"},
		},
		{
			name:      "case-insensitive directive name",
			in:        "sslprotocol -all +TLSv1.2\n",
			claim:     true,
			protocols: []string{"TLSv1.2"},
		},
		{
			name:      "continuation line",
			in:        "SSLCipherSuite ECDHE-RSA-AES128-GCM-SHA256:\\\nECDHE-RSA-AES256-GCM-SHA384\nSSLProtocol -all +TLSv1.2\n",
			claim:     true,
			protocols: []string{"TLSv1.2"},
			ciphers:   []string{"ECDHE-RSA-AES128-GCM-SHA256", "ECDHE-RSA-AES256-GCM-SHA384"},
		},
		{
			name:  "comment lines ignored",
			in:    "# SSLProtocol all\n#SSLCertificateFile x.pem\nServerName x\n",
			claim: false,
		},
		{name: "no crypto", in: "<VirtualHost *:80>\nServerName x\n</VirtualHost>", claim: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := parseApache(tc.in)
			if (res != nil) != tc.claim {
				t.Fatalf("claim = %v, want %v", res != nil, tc.claim)
			}
			if !tc.claim {
				return
			}
			if tc.protocols != nil && !sortedEqual(strs(res, "protocols"), tc.protocols) {
				t.Errorf("protocols = %v, want %v", strs(res, "protocols"), tc.protocols)
			}
			if tc.ciphers != nil && !sortedEqual(strs(res, "ciphers"), tc.ciphers) {
				t.Errorf("ciphers = %v, want %v", strs(res, "ciphers"), tc.ciphers)
			}
			if tc.certRefs != nil && !sortedEqual(strs(res, "cert_refs"), tc.certRefs) {
				t.Errorf("cert_refs = %v, want %v", strs(res, "cert_refs"), tc.certRefs)
			}
		})
	}
}

func TestParseSSHD(t *testing.T) {
	tests := []struct {
		name  string
		in    string
		claim bool
		types []string
		refs  []string
		kex   []string
		ciph  []string
		macs  []string
	}{
		{
			name:  "hostkeys plus structural keyword",
			in:    "Port 22\nHostKey /etc/ssh/ssh_host_rsa_key\nHostKey /etc/ssh/ssh_host_ecdsa_key\nHostKey /etc/ssh/ssh_host_ed25519_key\n",
			claim: true,
			types: []string{"rsa", "ecdsa", "ed25519"},
			refs:  []string{"/etc/ssh/ssh_host_rsa_key", "/etc/ssh/ssh_host_ecdsa_key", "/etc/ssh/ssh_host_ed25519_key"},
		},
		{
			name:  "full hardened set case-insensitive keyword",
			in:    "hostkey /etc/ssh/ssh_host_ed25519_key\nKexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org\nciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com\nMACs hmac-sha2-256-etm@openssh.com\n",
			claim: true,
			types: []string{"ed25519"},
			refs:  []string{"/etc/ssh/ssh_host_ed25519_key"},
			kex:   []string{"curve25519-sha256", "curve25519-sha256@libssh.org"},
			ciph:  []string{"chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com"},
			macs:  []string{"hmac-sha2-256-etm@openssh.com"},
		},
		{
			name:  "dsa type derived (with structural keyword)",
			in:    "Port 22\nHostKey /etc/ssh/ssh_host_dsa_key\n",
			claim: true,
			types: []string{"dsa"},
			refs:  []string{"/etc/ssh/ssh_host_dsa_key"},
		},
		{
			name:  "comments and non-crypto keywords ignored",
			in:    "# HostKey /etc/ssh/ssh_host_rsa_key\nPort 22\nPermitRootLogin no\n",
			claim: false,
		},
		{
			// STRUCTURE: only HostKey appears (one distinct keyword). A
			// hostkey-only fragment no longer satisfies structure on its own.
			name:  "hostkey-only fragment insufficient structure",
			in:    "HostKey /etc/ssh/ssh_host_rsa_key\nHostKey /etc/ssh/ssh_host_ecdsa_key\n",
			claim: false,
		},
		{
			// PROBE 1: prose leading with HostKey. Value has no path separator
			// and only one distinct keyword appears.
			name:  "probe prose hostkey",
			in:    "HostKey algorithms are important for server security.\n",
			claim: false,
		},
		{
			// PROBE 2: prose leading with Ciphers. Multi-word value is not a
			// single algorithm-list argument.
			name:  "probe prose ciphers",
			in:    "Ciphers used during World War II were mechanical.\n",
			claim: false,
		},
		{
			// PROBE 3: prose leading with MACs.
			name:  "probe prose macs",
			in:    "MACs are hardware network addresses.\n",
			claim: false,
		},
		{
			// PROBE 4: prose leading with KexAlgorithms.
			name:  "probe prose kex",
			in:    "KexAlgorithms determine the key exchange method.\n",
			claim: false,
		},
		{
			// PROBE 5: Go struct. Three distinct sshd keywords (Ciphers, MACs,
			// HostKey) so structure passes, but no crypto value validates:
			// "[]string" has brackets, "string" has no separator.
			name:  "probe go struct",
			in:    "type Config struct {\n\tCiphers []string\n\tMACs []string\n\tHostKey string\n}\n",
			claim: false,
		},
		{name: "empty", in: "", claim: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := parseSSHD(tc.in)
			if (res != nil) != tc.claim {
				t.Fatalf("claim = %v, want %v", res != nil, tc.claim)
			}
			if !tc.claim {
				return
			}
			if res.class != "ssh_config" {
				t.Errorf("class = %q, want ssh_config", res.class)
			}
			if tc.types != nil && !sortedEqual(strs(res, "host_key_types"), tc.types) {
				t.Errorf("host_key_types = %v, want %v", strs(res, "host_key_types"), tc.types)
			}
			if tc.refs != nil && !sortedEqual(strs(res, "host_key_refs"), tc.refs) {
				t.Errorf("host_key_refs = %v, want %v", strs(res, "host_key_refs"), tc.refs)
			}
			if tc.kex != nil && !sortedEqual(strs(res, "kex_algorithms"), tc.kex) {
				t.Errorf("kex_algorithms = %v, want %v", strs(res, "kex_algorithms"), tc.kex)
			}
			if tc.ciph != nil && !sortedEqual(strs(res, "ciphers"), tc.ciph) {
				t.Errorf("ciphers = %v, want %v", strs(res, "ciphers"), tc.ciph)
			}
			if tc.macs != nil && !sortedEqual(strs(res, "macs"), tc.macs) {
				t.Errorf("macs = %v, want %v", strs(res, "macs"), tc.macs)
			}
			// KexAlgorithms/Ciphers/MACs must be omitted when absent.
			if tc.kex == nil {
				if _, ok := res.attrs["kex_algorithms"]; ok {
					t.Errorf("kex_algorithms present but should be omitted")
				}
			}
		})
	}
}

func TestParseOpenSSL(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		claim   bool
		minProt string
		cipher  string
	}{
		{
			name:    "modern pointer chain, @ in cipher value",
			in:      "openssl_conf = default_conf\n[ default_conf ]\nssl_conf = ssl_sect\n[ ssl_sect ]\nsystem_default = system_default_sect\n[ system_default_sect ]\nMinProtocol = TLSv1.2\nCipherString = DEFAULT@SECLEVEL=2\n",
			claim:   true,
			minProt: "TLSv1.2",
			cipher:  "DEFAULT@SECLEVEL=2",
		},
		{
			name:    "legacy pointer chain, colon and equals in cipher",
			in:      "openssl_conf = default_conf\n[ default_conf ]\nssl_conf = ssl_sect\n[ ssl_sect ]\nsystem_default = system_default_sect\n[ system_default_sect ]\nMinProtocol = TLSv1\nCipherString = DEFAULT:@SECLEVEL=0\n",
			claim:   true,
			minProt: "TLSv1",
			cipher:  "DEFAULT:@SECLEVEL=0",
		},
		{
			name:   "cipher-only reachable section",
			in:     "openssl_conf = default_conf\n[ default_conf ]\nssl_conf = ssl_sect\n[ ssl_sect ]\nCipherString = HIGH:!aNULL\n",
			claim:  true,
			cipher: "HIGH:!aNULL",
		},
		{
			// No [section] header at all: not an INI/openssl.cnf.
			name:  "bare assignment, no section header",
			in:    "MinProtocol = TLSv1\nCipherString = DEFAULT:@SECLEVEL=0\n",
			claim: false,
		},
		{
			// PROBE 7 shape: a [tls] section not reachable from openssl_conf.
			name:  "section not reachable from openssl_conf",
			in:    "[tls]\nMinProtocol = TLSv1\n",
			claim: false,
		},
		{
			// Reachable section but a quoted (non-grammar) MinProtocol value.
			name:  "reachable but quoted protocol value",
			in:    "openssl_conf = default_conf\n[ default_conf ]\nssl_conf = ssl_sect\n[ ssl_sect ]\nsystem_default = system_default_sect\n[ system_default_sect ]\nMinProtocol = \"TLSv1.2\"\n",
			claim: false,
		},
		{
			name:  "unrelated ini keys not claimed",
			in:    "openssl_conf = default_conf\ndefault_bits = 2048\n[req]\nprompt = no\n",
			claim: false,
		},
		{name: "empty", in: "", claim: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := parseOpenSSL(tc.in)
			if (res != nil) != tc.claim {
				t.Fatalf("claim = %v, want %v", res != nil, tc.claim)
			}
			if !tc.claim {
				return
			}
			if got := res.attrs["min_protocol"]; got != any(tc.minProt) && tc.minProt != "" {
				t.Errorf("min_protocol = %v, want %v", got, tc.minProt)
			}
			if got := res.attrs["cipher_string"]; got != any(tc.cipher) && tc.cipher != "" {
				t.Errorf("cipher_string = %v, want %v", got, tc.cipher)
			}
		})
	}
}

func TestParseHAProxy(t *testing.T) {
	tests := []struct {
		name      string
		in        string
		claim     bool
		protocols []string
		ciphers   []string
		certRefs  []string
	}{
		{
			name:      "no options keeps full base",
			in:        "global\n ssl-default-bind-ciphers A:B:DES-CBC3-SHA\nfrontend f\n bind :443 ssl crt r.pem\n",
			claim:     true,
			protocols: []string{"TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"},
			ciphers:   []string{"A", "B", "DES-CBC3-SHA"},
			certRefs:  []string{"r.pem"},
		},
		{
			name:      "no-tlsv10/11 removes lower two; crt dedupe",
			in:        "global\n ssl-default-bind-options no-sslv3 no-tlsv10 no-tlsv11\nfrontend f\n bind :443 ssl crt leaf.pem\n bind :8443 ssl crt leaf.pem\n",
			claim:     true,
			protocols: []string{"TLSv1.2", "TLSv1.3"},
			certRefs:  []string{"leaf.pem"},
		},
		{
			name:      "ssl-min-ver floor",
			in:        "global\n ssl-min-ver TLSv1.2\n bind :443 ssl crt x.pem\n",
			claim:     true,
			protocols: []string{"TLSv1.2", "TLSv1.3"},
			certRefs:  []string{"x.pem"},
		},
		{
			name:  "plain bind without ssl not claimed",
			in:    "frontend f\n bind :80\n default_backend b\n",
			claim: false,
		},
		{name: "empty", in: "", claim: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := parseHAProxy(tc.in)
			if (res != nil) != tc.claim {
				t.Fatalf("claim = %v, want %v", res != nil, tc.claim)
			}
			if !tc.claim {
				return
			}
			if tc.protocols != nil && !sortedEqual(strs(res, "protocols"), tc.protocols) {
				t.Errorf("protocols = %v, want %v", strs(res, "protocols"), tc.protocols)
			}
			if tc.ciphers != nil && !sortedEqual(strs(res, "ciphers"), tc.ciphers) {
				t.Errorf("ciphers = %v, want %v", strs(res, "ciphers"), tc.ciphers)
			}
			if tc.certRefs != nil && !sortedEqual(strs(res, "cert_refs"), tc.certRefs) {
				t.Errorf("cert_refs = %v, want %v", strs(res, "cert_refs"), tc.certRefs)
			}
		})
	}
}
