# cryptoscan

> ⚠️ **Pre-release — Phase 1.** The local filesystem scanner works, but the CLI
> surface, flags, and output are still changing without notice until v0.1.0. Not
> ready for production use.

Open source cryptographic estate scanner. cryptoscan discovers cryptographic
assets — certificates, TLS configurations, keys, and crypto API usage — across
your files and endpoints, then produces a standards-native Cryptographic Bill of
Materials (CycloneDX 1.6 CBOM) plus a post-quantum (PQC) readiness report.
Think "Snyk for cryptography": every finding is deterministic and traces back to
a specific file, line, config directive, certificate field, or network
handshake — no guessing.

## What works today (Phase 1)

`cryptoscan fs <path>` scans a local directory tree and reports, for every asset
it can prove by parsing the bytes:

- **Certificates, keys, keystores** — X.509 certs (PEM/DER), public/private keys
  (PKCS#1/PKCS#8/EC/Ed25519), CSRs, and keystores (JKS, PKCS#12), with
  algorithm, key size/curve, signature algorithm, validity window, and SPKI
  fingerprint.
- **Server TLS configs** — nginx, Apache, sshd_config, openssl.cnf, and HAProxy,
  parsed with real directive parsers (no regex soup), extracting protocols,
  cipher suites, and certificate/key references.
- **A graph with entity resolution** — the same certificate or key seen in
  multiple places resolves to one node; config directives that point at a
  certificate/key file are joined to that asset.

## 30-second quickstart

```sh
# Build the static binary (Go 1.26+).
go build -o cryptoscan ./cmd/cryptoscan

# Scan a directory tree for cryptographic assets.
./cryptoscan fs /path/to/scan
```

The output is a per-class finding tally, a findings table with interim risk
flags (`expired`, `not_yet_valid`, `weak-sig`, `weak-key`, `legacy-tls`), and
graph node/edge counts. Files larger than 8 MiB, symlinks, and non-regular files
are skipped; unreadable or malformed files are skipped silently.

## Not yet

- **Network probing** (`cryptoscan probe`) — Phase 2.
- **CBOM + auditor report output** (CycloneDX 1.6, PQC scoring) — Phase 3.
- **GitHub composite action / CI scorecard** — Phase 4.

See [`CLAUDE.md`](./CLAUDE.md) and [`docs/DESIGN.md`](./docs/DESIGN.md) for the
binding design contract, and [`CONTRIBUTING.md`](./CONTRIBUTING.md) to get
started.

## License

Apache-2.0. See [`LICENSE`](./LICENSE).
