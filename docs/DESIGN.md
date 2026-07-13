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
| Endpoint      | `endpoint:` + host:port                          | host, port, protocols, cipher_suites, alpn |
| Service       | `service:` + name                                | name, kind (nginx, apache, sshd, ...) |
| ConfigFile    | `file:` + cleaned absolute path                  | path, format, directives of interest w/ line numbers |
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
