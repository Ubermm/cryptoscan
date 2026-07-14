# Contributing to cryptoscan

Thanks for your interest. cryptoscan is Apache-2.0 licensed and built in the
open. This guide covers the essentials; the binding design contract lives in
[`CLAUDE.md`](./CLAUDE.md) and [`docs/DESIGN.md`](./docs/DESIGN.md). Read those
first — if code and the design contract disagree, the contract wins.

## Guiding principle: deterministic only

Every finding must trace to concrete evidence — a file, line, config directive,
certificate field, or network handshake. **No LLMs, no ML, no heuristic
guessing in the detection path.** If a finding cannot be proven, it is not
reported. Provenance is required on every graph node and edge. Contributions
that add nondeterministic detection will not be merged.

## Development setup

Requirements:

- Go 1.26 or newer (single static binary, stdlib-first)
- `git`
- `golangci-lint` v2 (for linting)
- OpenSSL 3.x (only if regenerating fixtures under `testdata/corpus/gen/`)

Clone and build:

```sh
git clone https://github.com/Ubermm/cryptoscan
cd cryptoscan
go build ./...
```

## Running tests

```sh
go test ./...          # all packages
go test -race ./...    # what CI runs
go vet ./...
gofmt -l .             # should print nothing
golangci-lint run
```

Every parser gets table-driven tests; every output emitter gets golden-file
tests. The certificate and config parsers are fuzzed with native Go fuzzing,
seeded from the negative fixtures. **No panics on malformed input, ever** —
library code returns errors instead.

The fuzz targets live next to the parsers: `FuzzPEM` / `FuzzDER` in
`internal/scan/certs`, and `FuzzNginx`, `FuzzApache`, `FuzzSSHD`, `FuzzOpenSSL`,
`FuzzHAProxy`, `FuzzDetect` in `internal/scan/config`. Their seed corpora run as
ordinary unit tests under `go test ./...`. To fuzz for real, run one target at a
time (Go fuzzing allows a single `-fuzz` target per package):

```sh
go test ./internal/scan/certs  -run=^$ -fuzz=FuzzPEM   -fuzztime=30s
go test ./internal/scan/config -run=^$ -fuzz=FuzzNginx -fuzztime=30s
```

Any crasher Go writes under `testdata/fuzz/` should be committed as a
regression seed.

## Running the eval scorecard

`cmd/eval` runs the scanner against the ground-truth corpus in
`testdata/corpus/`, compares findings to `corpus.yaml` (and its
`manifests/` fragments), and prints a per-asset-class precision / recall / F1
scorecard.

```sh
go run ./cmd/eval
```

Flags: `--corpus <dir>` (default `testdata/corpus`), `--strict`, `--format table|json`. CI prints its output to the job summary.

## The ship gate: 0.95 precision

**No phase ships below 0.95 precision on its asset class.** `cmd/eval` exits
non-zero when any class with declared assets falls under that bar. Recall
shortfalls are reported and gate only under `--strict`. Anything found under
`testdata/corpus/negatives/` counts as a false positive — the scanner must emit
nothing there.

## Commits, licensing, and sign-off

- Semantic versioning starting at v0.1.0.
- Wrap errors with `%w`; no `log.Fatal` outside `main`; no `panic` in library
  code.
- Use `path/filepath` for paths — the project develops on Windows and must also
  build and test on linux/amd64 (the CI target). No hardcoded separators.
- A DCO-style `Signed-off-by` trailer is **not** required.
- By contributing you agree your contributions are licensed under Apache-2.0.
