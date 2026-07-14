package config

import (
	"os"
	"path/filepath"
	"testing"
)

// negativeFiles are the crypto look-alikes; every parser (and detection as a
// whole) must produce nothing for each of them. The prose/source/gitconfig/
// python probes exercise the tightened sshd + openssl detectors specifically.
var negativeFiles = []string{
	"negatives/blob.b64",
	"negatives/config.json",
	"negatives/disabled-nginx.conf",
	"negatives/fake-cert.pem",
	"negatives/key_loader.py",
	"negatives/notreallyder.der",
	"negatives/README.md",
	"negatives/truncated.pem",
	"negatives/prose-hostkey.txt",
	"negatives/prose-ciphers.md",
	"negatives/prose-macs.txt",
	"negatives/prose-kex.rst",
	"negatives/tls_config.go",
	"negatives/settings.py",
	"negatives/weird.gitconfig",
}

// readCorpusFile reads a corpus file relative to the corpus root, failing the
// test if it cannot be read.
func readCorpusFile(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(corpusRoot, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return b
}

// TestNegativesProduceNothing asserts full-file detection (all five parsers)
// yields nil for every negative fixture — the decoys must not satisfy any parser.
func TestNegativesProduceNothing(t *testing.T) {
	for _, rel := range negativeFiles {
		rel := rel
		t.Run(rel, func(t *testing.T) {
			data := readCorpusFile(t, rel)
			// detectFile applies the binary/size guards + all parsers.
			if res := detect(string(data)); res != nil {
				t.Errorf("%s claimed as format %q class %q attrs=%v", rel, res.format, res.class, res.attrs)
			}
		})
	}
}

// corpusSeeds collects every file under configs/ and the negatives listed above
// as fuzz seeds (per the task: every corpus config + all 8 negatives).
func corpusSeeds(t testing.TB) [][]byte {
	t.Helper()
	var seeds [][]byte
	configsDir := filepath.Join(corpusRoot, "configs")
	err := filepath.WalkDir(configsDir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		b, rerr := os.ReadFile(p)
		if rerr == nil {
			seeds = append(seeds, b)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk configs: %v", err)
	}
	for _, rel := range negativeFiles {
		if b, rerr := os.ReadFile(filepath.Join(corpusRoot, filepath.FromSlash(rel))); rerr == nil {
			seeds = append(seeds, b)
		}
	}
	// A few adversarial literals for structural edge cases.
	seeds = append(seeds,
		[]byte("server {"),
		[]byte("ssl_ciphers 'A:B"),
		[]byte("<VirtualHost *:443>\nSSLProtocol\n"),
		[]byte("MinProtocol ="),
		[]byte("bind ssl crt"),
		[]byte("HostKey"),
		[]byte("{}{}{};;;###"),
	)
	return seeds
}

func addSeeds(f *testing.F, seeds [][]byte) {
	for _, s := range seeds {
		f.Add(string(s))
	}
}

// Each fuzz target only needs to prove the parser never panics; the parsers are
// pure functions of their input string.

func FuzzNginx(f *testing.F) {
	addSeeds(f, corpusSeeds(f))
	f.Fuzz(func(_ *testing.T, s string) { _ = parseNginx(s) })
}

func FuzzApache(f *testing.F) {
	addSeeds(f, corpusSeeds(f))
	f.Fuzz(func(_ *testing.T, s string) { _ = parseApache(s) })
}

func FuzzSSHD(f *testing.F) {
	addSeeds(f, corpusSeeds(f))
	f.Fuzz(func(_ *testing.T, s string) { _ = parseSSHD(s) })
}

func FuzzOpenSSL(f *testing.F) {
	addSeeds(f, corpusSeeds(f))
	f.Fuzz(func(_ *testing.T, s string) { _ = parseOpenSSL(s) })
}

func FuzzHAProxy(f *testing.F) {
	addSeeds(f, corpusSeeds(f))
	f.Fuzz(func(_ *testing.T, s string) { _ = parseHAProxy(s) })
}

// FuzzDetect exercises the full detection path (all parsers + guards).
func FuzzDetect(f *testing.F) {
	addSeeds(f, corpusSeeds(f))
	f.Fuzz(func(_ *testing.T, s string) { _ = detect(s) })
}
