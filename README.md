# cryptoscan

> ⚠️ **Pre-release — Phase 3.** The local filesystem scanner, the network
> probe, and the output layer (CBOM, auditor report, PQC scoring, graph dump)
> all work, but the CLI surface, flags, and output are still changing without
> notice until v0.1.0. Not ready for production use.

Open source cryptographic estate scanner. cryptoscan discovers cryptographic
assets — certificates, TLS configurations, keys, and crypto API usage — across
your files and endpoints, then produces a standards-native Cryptographic Bill of
Materials (CycloneDX 1.6 CBOM) plus a post-quantum (PQC) readiness report.
Think "Snyk for cryptography": every finding is deterministic and traces back to
a specific file, line, config directive, certificate field, or network
handshake — no guessing.

## What works today (Phases 1–2)

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

`cryptoscan probe <target>...` observes network endpoints you list **explicitly**
(no discovery, no subnet or range expansion, no port scanning) and records what
they present on the wire:

- **TLS** — a primary handshake (negotiated protocol, cipher suite, ALPN), a
  per-version enumeration (TLS 1.0–1.3) into `protocols_supported`, hybrid
  post-quantum detection (accepts the `X25519MLKEM768` group), and the presented
  certificate chain — parsed with the **same** strict code path as `fs`.
- **SSH** — the server banner and the algorithms advertised in its KEXINIT
  (host-key, key-exchange, cipher, MAC name-lists). Nothing is authenticated and
  no key exchange is completed.
- **Cross-surface entity resolution** — a certificate seen on the wire and one on
  disk resolve to the **same** graph node (DER SHA-256 / SPKI identity).

## 30-second quickstart

```sh
# Build the static binary (Go 1.26+).
go build -o cryptoscan ./cmd/cryptoscan

# Scan a directory tree for cryptographic assets.
./cryptoscan fs /path/to/scan

# Probe explicitly listed endpoints (bare host defaults to :443; give SSH :22).
./cryptoscan probe example.com:443 github.com:22
```

By default `fs` prints a per-class finding tally, a findings table with interim
risk flags (`expired`, `not_yet_valid`, `weak-sig`, `weak-key`, `legacy-tls`),
and graph node/edge counts. Files larger than 8 MiB, symlinks, and non-regular
files are skipped; unreadable or malformed files are skipped silently. `probe`
prints the observed endpoints and a graph summary; a single `--rate` governs its
throughput, `--timeout` bounds each target, and `--concurrency` bounds
simultaneous probes.

## Output

Both `fs` and `probe` take `--format` and `--output <file>` (default stdout).
`--format table` (the default) is the human summary above; the other three
formats are standards-native / auditor projections of the scanned graph. The
timestamp in each machine format is the real wall clock at scan time.
`--quiet` shapes only the `table` summary and is rejected with a machine format.

```sh
# CycloneDX 1.6 CBOM (JSON) for a directory tree — pipe it to any CBOM tool.
./cryptoscan fs /path/to/scan --format cbom > estate.cbom.json

# Auditor report: Markdown (report) or JSON (report-json).
# Findings carry the PCI-QSA schema: type, algorithm, key size, location(s),
# expiry, issuer/CA, and the PQC exposure flags, ranked asymmetric-first.
./cryptoscan fs /path/to/scan --format report          # human Markdown
./cryptoscan fs /path/to/scan --format report-json -o report.json

# The same formats apply to probed network assets.
./cryptoscan probe example.com:443 --format report-json
```

`cryptoscan graph <path>` dumps the raw asset graph itself (nodes + edges) for
tooling or visualization:

```sh
# Graphviz DOT (render with `dot -Tsvg`), or a stable {nodes,edges} JSON object.
./cryptoscan graph /path/to/scan --format dot | dot -Tsvg -o estate.svg
./cryptoscan graph /path/to/scan --format json > graph.json
```

## Not yet

- **GitHub composite action / CI scorecard** — Phase 4.

The output layer (CycloneDX 1.6 CBOM, auditor report, PQC scoring, and the
`graph` dump) is **done** as of Phase 3.

### Known limitations

- **CSRs surface as `public_key` in the graph projection.** The graph node model
  doesn't yet carry CSR-ness, so a certificate-signing request resolves to a
  public-key node in the CBOM/report graph projection. The eval harness still
  classifies `csr` correctly at the finding level; only the graph-derived output
  collapses it into `public_key`.
- **`fs` and `probe` cover separate surfaces.** `graph`, CBOM, and report from
  `fs` describe filesystem assets; `probe` describes network assets. A single
  combined estate scan across both surfaces in one invocation (with the
  cross-surface entity resolution the graph already supports) is a later
  enhancement.

See [`CLAUDE.md`](./CLAUDE.md) and [`docs/DESIGN.md`](./docs/DESIGN.md) for the
binding design contract, and [`CONTRIBUTING.md`](./CONTRIBUTING.md) to get
started.

## License

Apache-2.0. See [`LICENSE`](./LICENSE).
