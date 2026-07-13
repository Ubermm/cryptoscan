# cryptoscan

> ⚠️ **Pre-release — Phase 0.** Scaffolding only. The CLI surface exists but the
> scanners are not implemented yet. Interfaces, flags, and output will change
> without notice until v0.1.0. Not ready for use.

Open source cryptographic estate scanner. cryptoscan discovers cryptographic
assets — certificates, TLS configurations, keys, and crypto API usage — across
your files and endpoints, then produces a standards-native Cryptographic Bill of
Materials (CycloneDX 1.6 CBOM) plus a post-quantum (PQC) readiness report.
Think "Snyk for cryptography": every finding is deterministic and traces back to
a specific file, line, config directive, certificate field, or network
handshake — no guessing.

A full README with a 60-second quickstart, an honest "what it does NOT do yet"
section, and the eval scorecard table lands in a later phase. Until then, see
[`CLAUDE.md`](./CLAUDE.md) and [`docs/DESIGN.md`](./docs/DESIGN.md) for the
design contract, and [`CONTRIBUTING.md`](./CONTRIBUTING.md) to get started.

## License

Apache-2.0. See [`LICENSE`](./LICENSE).
