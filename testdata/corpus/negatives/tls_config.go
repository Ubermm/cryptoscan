// Package tlsconfig is a decoy Go source file used as a corpus negative. Its
// struct field names collide with sshd_config crypto keywords (Ciphers, MACs,
// HostKey); the config scanner must not classify Go source as an sshd_config,
// because the field values ("[]string", "string") fail the ssh algorithm-name
// and HostKey-path value grammars.
package tlsconfig

// Config is an ordinary application settings struct that happens to name its
// fields after ssh crypto keywords.
type Config struct {
	Ciphers []string
	MACs    []string
	HostKey string
}
