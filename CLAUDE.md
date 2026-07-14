# cryptoscan

Open source cryptographic estate scanner. Discovers cryptographic assets
(certificates, TLS configurations, keys, crypto API usage) and produces a
Cryptographic Bill of Materials (CBOM) plus a PQC-readiness report.
"Snyk for cryptography." Launching publicly on GitHub and Hacker News:
code quality, docs, and test rigor matter.

## Non-negotiable principles

1. **DETERMINISTIC ONLY.** No LLM calls, no ML, no heuristic guessing in the
   detection path. Every finding must trace to a specific file, line, config
   directive, certificate field, or network handshake. If we cannot prove a
   finding, we do not report it.

2. **GRAPH-SHAPED DATA MODEL from day one.** Internal representation is nodes
   (Certificate, Key, Endpoint, Service, ConfigFile, CryptoLibrary, CA,
   KMSEntry) and edges (issued_by, terminates_tls_for, stored_in, references,
   signs_with). Findings are projections of the graph, never the primary
   structure. Entity resolution is designed in from the start: the same
   certificate seen at an endpoint and in a local PEM file must resolve to
   ONE node (key: SHA-256 fingerprint of the public key / SPKI hash).

3. **ASYMMETRIC-FIRST.** RSA, ECDSA, ECDH, DH, key exchange, signatures,
   certificates are the priority findings (quantum-relevant). Symmetric and
   hashing findings are recorded but ranked lower.

4. **STANDARDS-NATIVE OUTPUT.** Emit CycloneDX 1.6 CBOM (JSON). Also emit a
   human report with exactly this schema per finding: type, algorithm,
   key size/strength, location (host/file/line), expiry, issuer/CA, plus a
   PQC exposure flag. This schema came from PCI QSAs verbatim; do not deviate.

5. **Language: Go.** Single static binary, cobra CLI, zero runtime deps.
   Apache-2.0 license.

## Engineering standards

- Table-driven tests for every parser. Golden-file tests for outputs.
- **No panics on malformed input, ever.** Fuzz the cert and config parsers
  (native Go fuzzing) with seeds from the negative fixtures.
- Config parsing is proper directive parsing, never regex soup.
- CI via GitHub Actions: lint (golangci-lint), test, eval scorecard printed
  in the CI summary.
- README: 60-second quickstart, an honest "what it does NOT do yet" section,
  and the scorecard table. CONTRIBUTING.md. Semver from v0.1.0.

## Definition of done (every phase)

`cmd/eval` runs the scanner against `testdata/corpus/`, computes
precision/recall/F1 per asset class against `corpus.yaml`, and outputs a
scorecard table. **No phase ships below 0.95 precision on its asset class.**

## Phase plan (STOP after each phase for owner review)

- Phase 0: ground-truth corpus + eval harness (built first)
- Phase 1: local scanners (certs/keys/keystores + config parsers), `cryptoscan fs <path>`
- Phase 2: network scanner, `cryptoscan probe`
- Phase 3: output layer (CycloneDX 1.6 CBOM, auditor report, PQC scoring, `cryptoscan graph`)
- Phase 4: GitHub composite action

## Repo conventions

- Go module: `github.com/Ubermm/cryptoscan`
- Layout: `cmd/cryptoscan` (CLI), `cmd/eval` (scorecard harness),
  `internal/graph` (node/edge model + entity resolution),
  `internal/scan/...` (scanners), `internal/output/...` (emitters),
  `testdata/corpus/` (fixtures + corpus.yaml).
- See `docs/DESIGN.md` for the graph schema and corpus.yaml contract —
  it is binding for all contributors and agents.
- Errors: wrap with `%w`, no `log.Fatal` outside `main`, no `panic` in
  library code.
- Windows dev environment; everything must also build/test on linux/amd64
  (CI target). Use `filepath` correctly; no hardcoded path separators.
