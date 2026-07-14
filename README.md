# cryptoscan

> ⚠️ **Pre-release — Phase 4.** The local filesystem scanner, the network
> probe, the output layer (CBOM, auditor report, PQC scoring, graph dump), and
> the GitHub composite action all work, but the CLI surface, flags, and output
> are still changing without notice until v0.1.0. Not ready for production use.

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

## GitHub Action

cryptoscan ships a composite action (`action.yml` at the repo root) that scans a
checked-out repository, uploads the CycloneDX 1.6 CBOM as a workflow artifact,
writes the auditor report to the job summary, and can optionally fail the build
on a crypto-policy breach.

```yaml
# .github/workflows/crypto.yml
name: crypto
on: [push, pull_request]
permissions:
  contents: read
jobs:
  cryptoscan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: cryptoscan/cryptoscan@main   # pin @vX once a release is tagged
        with:
          path: .
          fail-on: sha1,rsa1024,tls10       # empty = report only, never fail
```

What it does, in order (so evidence is recorded even when the gate trips):

1. Runs `cryptoscan fs <path> --format cbom` and captures the exit code
   **without** aborting the job.
2. Appends the Markdown auditor report (`--format report`) to the job summary
   (`always()`).
3. Uploads the CBOM JSON as an artifact (`always()`, when `upload-artifact` is
   `true`).
4. **Last**, fails the job if the scan reported a breach — so the artifact and
   summary are already attached to the run.

### Inputs

| Input | Default | Description |
| --- | --- | --- |
| `path` | `.` | Directory to scan. |
| `fail-on` | `""` | Comma-separated policy tokens; empty = report only, never fail. |
| `version` | `latest` | cryptoscan version to `go install`. |
| `cbom-path` | `cbom.json` | Where the CBOM JSON is written. |
| `artifact-name` | `cryptoscan-cbom` | Uploaded artifact name. |
| `upload-artifact` | `true` | Whether to upload the CBOM artifact. |

Valid `fail-on` tokens: `tls10`, `tls11`, `ssl3`, `legacy-tls`, `sha1`, `md5`,
`weak-signature`, `rsa1024`, `weak-key`, `expired`, `expiring`,
`quantum-vulnerable`.

### Exit-code / fail-on semantics

`cryptoscan fs` always emits the requested output first, then exits **4** if any
`--fail-on` threshold is breached (a breach summary is printed to stderr). Exit
codes: **0** clean · **1** operational/usage error · **2** CLI-argument error ·
**4** policy breach. The action distinguishes a breach (4) from an operational
error (1) in the failing step's log, and surfaces the raw code as the
`exit-code` output.

> **Pre-release note.** The action installs cryptoscan with
> `go install github.com/cryptoscan/cryptoscan/cmd/cryptoscan@<version>`, which
> requires the module to be published to the Go proxy. Until a release is tagged
> and the module is published, pin `@main` and let the action build from source,
> or install the binary yourself. The `action-selftest.yml` workflow exercises
> the exact command sequence against `testdata/corpus` using a **locally built**
> binary, so the action's logic is proven end-to-end today.

## Not yet

- **A tagged release + published module.** Consumers pin `@main` until then.

The output layer (CycloneDX 1.6 CBOM, auditor report, PQC scoring, and the
`graph` dump) shipped in Phase 3, and the GitHub composite action in Phase 4.

### Known limitations

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
