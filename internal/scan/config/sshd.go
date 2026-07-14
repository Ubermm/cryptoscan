package config

import (
	"strings"

	"github.com/cryptoscan/cryptoscan/internal/graph"
)

// sshdKeywords is the recognised sshd_config(5) option vocabulary (OpenSSH),
// lowercased for the case-insensitive match sshd itself uses. It is consulted
// only for STRUCTURE validation: a file is treated as an sshd_config only when
// it carries at least two DISTINCT keywords from this set. That defeats prose
// ("Ciphers used during World War II ...") and source code (a Go struct with a
// HostKey field) that merely echo one crypto keyword — neither exhibits the
// surrounding sshd option vocabulary a real config does.
var sshdKeywords = map[string]bool{
	"acceptenv": true, "addressfamily": true, "allowagentforwarding": true,
	"allowgroups": true, "allowstreamlocalforwarding": true, "allowtcpforwarding": true,
	"allowusers": true, "authenticationmethods": true, "authorizedkeyscommand": true,
	"authorizedkeyscommanduser": true, "authorizedkeysfile": true,
	"authorizedprincipalscommand": true, "authorizedprincipalscommanduser": true,
	"authorizedprincipalsfile": true, "banner": true, "casignaturealgorithms": true,
	"challengeresponseauthentication": true, "channeltimeout": true, "chrootdirectory": true,
	"ciphers": true, "clientalivecountmax": true, "clientaliveinterval": true,
	"compression": true, "denygroups": true, "denyusers": true, "disableforwarding": true,
	"exposeauthinfo": true, "fingerprinthash": true, "forcecommand": true,
	"gatewayports": true, "gssapiauthentication": true, "gssapicleanupcredentials": true,
	"gssapistrictacceptorcheck": true, "hostbasedacceptedalgorithms": true,
	"hostbasedauthentication": true, "hostbasedusesnamefrompacketonly": true,
	"hostcertificate": true, "hostkey": true, "hostkeyagent": true, "hostkeyalgorithms": true,
	"ignorerhosts": true, "ignoreuserknownhosts": true, "include": true, "ipqos": true,
	"kbdinteractiveauthentication": true, "kerberosauthentication": true,
	"kerberosgetafstoken": true, "kerberosorlocalpasswd": true, "kerberosticketcleanup": true,
	"kexalgorithms": true, "listenaddress": true, "logingracetime": true, "loglevel": true,
	"logverbose": true, "macs": true, "match": true, "maxauthtries": true, "maxsessions": true,
	"maxstartups": true, "modulifile": true, "passwordauthentication": true,
	"permitemptypasswords": true, "permitlisten": true, "permitopen": true,
	"permitrootlogin": true, "permittty": true, "permittunnel": true,
	"permituserenvironment": true, "permituserrc": true, "persourcemaxstartups": true,
	"persourcenetblocksize": true, "pidfile": true, "port": true, "printlastlog": true,
	"printmotd": true, "protocol": true, "pubkeyacceptedalgorithms": true,
	"pubkeyauthentication": true, "pubkeyauthoptions": true, "rekeylimit": true,
	"requiredrsasize": true, "revokedkeys": true, "rdomain": true, "securitykeyprovider": true,
	"setenv": true, "streamlocalbindmask": true, "streamlocalbindunlink": true,
	"strictmodes": true, "subsystem": true, "syslogfacility": true, "tcpkeepalive": true,
	"trustedusercakeys": true, "usedns": true, "usepam": true, "versionaddendum": true,
	"x11displayoffset": true, "x11forwarding": true, "x11uselocalhost": true,
	"xauthlocation": true,
}

// hostKeyType derives the key type from a standard HostKey filename stem
// (ssh_host_<type>_key -> <type>) and reports whether it is a recognised type.
// Only rsa/ecdsa/ed25519/dsa are recognised (configs.yaml convention header).
func hostKeyType(ref string) (string, bool) {
	base := ref
	if i := strings.LastIndexAny(base, "/\\"); i >= 0 {
		base = base[i+1:]
	}
	if !strings.HasPrefix(base, "ssh_host_") || !strings.HasSuffix(base, "_key") {
		return "", false
	}
	mid := strings.TrimSuffix(strings.TrimPrefix(base, "ssh_host_"), "_key")
	switch mid {
	case "rsa", "ecdsa", "ed25519", "dsa":
		return mid, true
	default:
		return "", false
	}
}

// isSSHAlgoToken reports whether t is a single ssh algorithm-name token: the
// charset OpenSSH allows in Ciphers/MACs/KexAlgorithms names (letters, digits,
// and @ . - + =), with no spaces or brackets. "[]string" (a Go type) fails on
// the brackets; "used" passes the charset but is rejected upstream because a
// real directive carries exactly one whitespace-delimited argument.
func isSSHAlgoToken(t string) bool {
	if t == "" {
		return false
	}
	for _, r := range t {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r == '@' || r == '.' || r == '-' || r == '+' || r == '=':
		default:
			return false
		}
	}
	return true
}

// isSSHAlgoList reports whether v parses as a comma-separated list of ssh
// algorithm-name tokens (the grammar of a Ciphers/MACs/KexAlgorithms value).
func isSSHAlgoList(v string) bool {
	toks := splitCommaList(v)
	if len(toks) == 0 {
		return false
	}
	for _, t := range toks {
		if !isSSHAlgoToken(t) {
			return false
		}
	}
	return true
}

// isHostKeyPath reports whether v is a single path-like token containing a path
// separator, as a real HostKey value is (/etc/ssh/ssh_host_rsa_key). Bare words
// like "string" (a Go field type) or "algorithms" (prose) carry no separator
// and are rejected.
func isHostKeyPath(v string) bool {
	return v != "" && strings.ContainsAny(v, "/\\")
}

// parseSSHD claims a file as an sshd_config only when BOTH hold:
//
//   - VALUE SHAPE: at least one crypto directive (HostKey, KexAlgorithms,
//     Ciphers, MACs) appears as `keyword value` with exactly one argument whose
//     value parses under that directive's grammar — HostKey a path-like token
//     with a separator, the algorithm lists a comma-separated set of ssh
//     algorithm-name tokens. A directive whose value fails its grammar is
//     ignored (it is not a real directive), so a Go struct field or a prose
//     sentence contributes no crypto signal.
//   - STRUCTURE: at least two DISTINCT sshd_config keywords from sshdKeywords
//     occur in the file. Repeated HostKey lines collapse to one distinct
//     keyword, so a hostkey-only fragment does not satisfy structure on its own;
//     a real sshd_config carries Port/ListenAddress/Subsystem/... alongside.
//
// Keywords match case-insensitively; a line is keyword + argument(s).
func parseSSHD(text string) *parseResult {
	var hostKeyRefs, hostKeyTypes, kex, ciphers, macs []string
	var directives []graph.Directive
	var refs []pathRef
	distinct := map[string]bool{}
	crypto := false

	for i, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := splitFields(line)
		if len(fields) < 2 {
			continue
		}
		keyword := fields[0]
		lineNo := i + 1

		// Structure: any recognised keyword line contributes to the distinct set
		// (crypto keywords included), regardless of whether its value validates.
		if sshdKeywords[strings.ToLower(keyword)] {
			distinct[strings.ToLower(keyword)] = true
		}

		switch {
		case strings.EqualFold(keyword, "HostKey"):
			if len(fields) != 2 || !isHostKeyPath(fields[1]) {
				continue
			}
			crypto = true
			ref := fields[1]
			hostKeyRefs = appendUnique(hostKeyRefs, ref)
			if t, ok := hostKeyType(ref); ok {
				hostKeyTypes = appendUnique(hostKeyTypes, t)
			}
			refs = append(refs, pathRef{raw: ref, line: lineNo, kind: "HostKey"})
			directives = append(directives, graph.Directive{Name: "HostKey", Value: ref, Line: lineNo})
		case strings.EqualFold(keyword, "KexAlgorithms"):
			if len(fields) != 2 || !isSSHAlgoList(fields[1]) {
				continue
			}
			crypto = true
			for _, v := range splitCommaList(fields[1]) {
				kex = appendUnique(kex, v)
			}
			directives = append(directives, graph.Directive{Name: "KexAlgorithms", Value: fields[1], Line: lineNo})
		case strings.EqualFold(keyword, "Ciphers"):
			if len(fields) != 2 || !isSSHAlgoList(fields[1]) {
				continue
			}
			crypto = true
			for _, v := range splitCommaList(fields[1]) {
				ciphers = appendUnique(ciphers, v)
			}
			directives = append(directives, graph.Directive{Name: "Ciphers", Value: fields[1], Line: lineNo})
		case strings.EqualFold(keyword, "MACs"):
			if len(fields) != 2 || !isSSHAlgoList(fields[1]) {
				continue
			}
			crypto = true
			for _, v := range splitCommaList(fields[1]) {
				macs = appendUnique(macs, v)
			}
			directives = append(directives, graph.Directive{Name: "MACs", Value: fields[1], Line: lineNo})
		}
	}

	if !crypto || len(distinct) < 2 {
		return nil
	}

	attrs := map[string]any{}
	if len(hostKeyTypes) > 0 {
		attrs["host_key_types"] = hostKeyTypes
	}
	if len(hostKeyRefs) > 0 {
		attrs["host_key_refs"] = hostKeyRefs
	}
	if len(kex) > 0 {
		attrs["kex_algorithms"] = kex
	}
	if len(ciphers) > 0 {
		attrs["ciphers"] = ciphers
	}
	if len(macs) > 0 {
		attrs["macs"] = macs
	}

	return &parseResult{
		format:     "sshd",
		class:      "ssh_config",
		attrs:      attrs,
		directives: directives,
		refs:       refs,
	}
}
