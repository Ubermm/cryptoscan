# cryptoscan design contract

This document is binding for all contributors (human or agent). If an
implementation decision contradicts this file, this file wins; change the
file first, then the code.

## 1. Graph data model (`internal/graph`)

The graph is the primary data structure. Findings, reports, and the CBOM are
projections of it.

### Node types

| Type          | Identity key (node ID)                          | Core attributes |
|---------------|--------------------------------------------------|-----------------|
| Certificate   | `cert:` + SHA-256 of DER encoding (hex)          | subject, issuer, serial, algorithm, key_size, signature_algorithm, not_before, not_after, san, spki_sha256, self_signed |
| Key           | `key:` + SPKI SHA-256 (hex)                      | algorithm, key_size, curve, public/private |
| Endpoint      | `endpoint:` + host:port                          | host, port, plus an observed-attributes map (`attrs`) holding what a probe recorded — TLS: negotiated_protocol, negotiated_cipher_suite, alpn, protocols_supported, pqc_hybrid_kex; SSH: banner, host_key_algorithms, kex_algorithms, ciphers, macs. The map keeps TLS and SSH parameters distinct instead of overloading shared fields, and keeps the node (not just the Finding) as the primary carrier per principle 2. |
| Service       | `service:` + name                                | name, kind (nginx, apache, sshd, ...) |
| ConfigFile    | `file:` + cleaned absolute path                  | path, format, directives of interest w/ line numbers, plus a resolved observed-attributes map (`attrs`) — the SAME resolved values the config scanner emits on its Finding (tls_config: protocols, ciphers, cert_refs, min_protocol, cipher_string; ssh_config: host_key_types, host_key_refs, kex_algorithms, ciphers, macs). The node is the single source of truth for resolved config state (principle 2); downstream consumers (pqc scoring, report, CBOM) read these attrs and MUST NOT re-derive protocol resolution from raw directives. |
| CryptoLibrary | `lib:` + name@version                            | name, version |
| CA            | `ca:` + SHA-256 of DER (subject cert) or `ca:dn:` + normalized issuer DN when the CA cert itself was not observed | dn, observed (bool) |
| KMSEntry      | `kms:` + provider + key id                       | provider, key_id, algorithm |

### Entity resolution

- A certificate observed anywhere (PEM file, DER file, JKS entry, PKCS#12
  entry, TLS handshake) resolves to ONE Certificate node via its DER SHA-256.
- Every Certificate node links (edge `signs_with` semantics below) to a Key
  node derived from its SPKI; a bare public/private key found on disk with
  the same SPKI SHA-256 merges into that same Key node. This is how a key
  seen at an endpoint and in a local PEM resolves together even across
  re-issued certificates.
- Node upsert = merge attributes + union of provenance records. Never
  duplicate a node with the same ID.
- Renewed/re-issued certificates are deliberately distinct Certificate
  nodes sharing one Key node. Key reuse across renewals (multiple
  Certificate nodes `signs_with` the same Key node across validity
  windows) is itself a planned finding — "unrotated key" — in a later
  phase. (Owner-approved 2026-07-13.)

### Provenance (required on every node and edge)

`[]Provenance{ Source (fs|probe|config), Path or Host, Line (0 if n/a), Detail }`
— this is what makes findings provable (principle 1).

### Edge types (directions are fixed)

| Edge                | From → To                  | Meaning |
|---------------------|----------------------------|---------|
| `issued_by`         | Certificate → CA           | issuer relationship |
| `terminates_tls_for`| Certificate → Endpoint     | cert presented in handshake at endpoint |
| `stored_in`         | Certificate/Key → ConfigFile (file/keystore node) | asset physically located in file |
| `references`        | ConfigFile → Certificate/Key/ConfigFile | config directive points at a path (e.g. `ssl_certificate`) |
| `signs_with`        | Certificate → Key          | cert's subject public key / signing key linkage |

### Scanner limits

Every filesystem scanner (certs and config) applies one shared, documented
per-file byte cap: `scan.MaxFileSize` = **8 MiB**. A regular file larger than
the cap is skipped deterministically — it is never read into memory — so a
pathological input cannot exhaust memory during a walk. Certificates, keys,
CSRs, keystores, and server configs are all far smaller than this ceiling, so
the cap never suppresses a genuine asset; it only rejects files too large to be
one. Directories, symlinks, and other non-regular files are not followed, and
files with a NUL byte in their head are treated as binary and skipped by the
config scanner. Skips are silent and never abort the walk.

### Network probe contract (Phase 2)

`cryptoscan probe` observes network surfaces; it probes ONLY explicitly
listed targets (no subnet expansion, no discovery, no port scanning).
Sane defaults: a 5s per-TARGET timeout (`--timeout`) that bounds a target's
whole probe — every handshake of a target shares that one deadline budget, so a
hanging target costs ~1×`--timeout`, never a multiple across the TLS version
enumeration; bounded concurrency (`--concurrency`, default 8); and ONE global
rate limit (`--rate`, default 10/s, 0 = unlimited) owned solely by the batch
driver — there is no second connection-layer limiter. Every value is
flag-overridable, and a shell glob or wildcard target (`*`, `?`) is rejected
with the same explicit-targets-only error as a CIDR block or range.

Finding classes (probe findings use `Path` = `host:port`, Source `probe`):

- `tls_endpoint` attrs: `negotiated_protocol`, `negotiated_cipher_suite`,
  `alpn`, `protocols_supported` (list from per-version handshake
  enumeration, TLS 1.0–1.3; spellings match §2: "TLSv1", "TLSv1.1", …),
  `pqc_hybrid_kex` (bool: server accepts the X25519MLKEM768 group when it
  is the only group offered), `peer_certs` count. The presented chain is
  parsed with the same strict code path as the fs scanner.
- `ssh_endpoint` attrs: `banner` (server version string), and from the
  server's KEXINIT: `host_key_algorithms`, `kex_algorithms`, `ciphers`,
  `macs`. Read deterministically from the wire preamble — no
  authentication is attempted, nothing is sent beyond a client banner
  and (if required to elicit KEXINIT) a client KEXINIT.

Graph: one Endpoint node per host:port; `terminates_tls_for`
Certificate → Endpoint for the leaf (chain certs get `issued_by` links);
Certificate/Key nodes reuse the fs identity keys (DER SHA-256 / SPKI),
so a cert seen at an endpoint and on disk is ONE node — the cross-surface
entity-resolution promise.

Testing: probes are verified against in-process TLS/SSH servers built
from corpus fixtures (deterministic, offline). CI never probes live
hosts. Wire-format parsers (SSH KEXINIT) are fuzzed like every parser.

## 2. Corpus & ground truth (`testdata/corpus/`)

Layout:

```
testdata/corpus/
  manifests/          # one or more *.yaml fragments, merged by the loader
  certs/              # PEM/DER certs, chains
  keys/               # private/public keys, CSRs
  keystores/          # JKS, PKCS#12
  configs/{nginx,apache,ssh,openssl,haproxy}/
  negatives/          # crypto look-alikes; scanner must report NOTHING here
  gen/                # generator scripts (openssl / Go) used to build fixtures
```

The manifest is split into fragments under `manifests/` (e.g.
`certs.yaml`, `configs.yaml`, `negatives.yaml`) so independent contributors
never merge-conflict. The loader (`internal/corpus`) reads and merges all
fragments; duplicate asset `id`s are a load error.

### Manifest fragment schema (version 1)

```yaml
version: 1
assets:
  - id: rsa-2048-selfsigned          # unique across ALL fragments
    class: certificate               # see asset classes below
    path: certs/rsa-2048-selfsigned.pem   # relative to corpus root
    container: pem                   # pem | der | jks | pkcs12
    alias: ""                        # entry alias inside jks/pkcs12, else empty
    expect:                          # only declare fields that MUST match
      algorithm: RSA                 # RSA | ECDSA | Ed25519 | DH | DSA
      key_size: 2048                 # bits; for ECDSA the curve size (256/384)
      curve: ""                      # P-256 | P-384 | "" if n/a
      signature_algorithm: SHA256-RSA
      spki_sha256: "<hex>"           # required for certificate/private_key/public_key
      subject_cn: example.com
      self_signed: true
      expired: false
  - id: nginx-tls10-enabled
    class: tls_config
    path: configs/nginx/tls10.conf
    expect:
      protocols: [TLSv1, TLSv1.1, TLSv1.2]      # exact set
      ciphers_contains: ["RC4-SHA"]             # subset match
      cert_refs: ["../../certs/rsa-2048-selfsigned.pem"]  # exact set, as written in the config
negatives:
  - id: fake-pem-header
    path: negatives/fake-pem-header.txt
    note: base64 blob wrapped in bogus PEM-like headers
```

### Asset classes

`certificate`, `private_key`, `public_key`, `csr`,
`tls_config` (nginx/apache/haproxy/openssl.cnf), `ssh_config`.

Keystore files are not their own class: each entry inside a JKS/PKCS#12 is
declared as a `certificate`/`private_key` asset with `container` + `alias`.

### Expectation matching semantics

- Scalar `expect` fields: exact match (case-insensitive for algorithm names).
- List fields: exact set match, except keys suffixed `_contains` (subset).
- Only declared fields are checked; scanners may extract more.

## 3. Eval harness (`cmd/eval`)

For each asset class:

- **TP**: a declared asset whose (path [, alias]) is found by the scanner
  with every declared `expect` field matching.
- **FN**: a declared asset not found, or found with a mismatched field
  (mismatches are listed in the output).
- **FP**: a scanner finding of that class at a (path [, alias]) not declared
  in any fragment — including anything at all under `negatives/`.

Outputs a scorecard table: per-class precision / recall / F1 and totals,
plus an exit code: non-zero if any class with declared assets scores
below **0.95 precision** (the ship gate) — recall shortfalls are reported
but only gate when `--strict` is passed.

`cmd/eval` consumes the scanner via its Go API (`internal/scan/...`), not by
shelling out, so line-level provenance is asserted too where declared.

## 4. Fixture generation rules

- Fixtures are committed as static files; generation scripts live in
  `testdata/corpus/gen/` for provenance and regeneration.
- Certificates: generated with OpenSSL 3.x or Go crypto; validity windows
  chosen deterministically (expired certs use fixed past dates like
  2020-01-01..2021-01-01; valid certs use far-future notAfter like
  2035-01-01 so tests don't rot).
- `spki_sha256` in manifests must be computed from the actual fixture
  (e.g. `openssl x509 -pubkey -noout | openssl pkey -pubin -outform DER |
  openssl dgst -sha256`), never hand-typed.
- Negative fixtures must be plausible: realistic base64 blobs, PEM-ish
  headers with invalid body, config comments mentioning algorithms, README
  text about RSA. The scanner must emit zero findings for all of them.

## 5. PQC exposure flags (pinned early; implemented Phase 3)

Per-node boolean flags, all provable from graph attributes:

- `quantum_vulnerable_algorithm`: algorithm ∈ {RSA, ECDSA, ECDH, DH, DSA, Ed25519, EdDSA, X25519}
- `legacy_protocol`: endpoint/config allows < TLS 1.2
- `weak_signature`: SHA-1 (or MD5) signature algorithm
- `weak_key`: RSA < 2048 bits
- `expiring`/`expired`: notAfter within 90 days / past
- `not_yet_valid`: notBefore in the future (certificate not yet in its validity
  window)
