# TLS Operations Runbook (prose only, no real crypto assets)

This document discusses cryptography in prose. It contains **no** parseable
certificates, keys, or machine-readable config directives, and the scanner
must produce zero findings for it.

## Certificate rotation

Rotate the public-facing certificate every 90 days. The current leaf is an
RSA-2048 certificate signed with SHA256-RSA; we plan to migrate the edge to
ECDSA P-256 to shrink handshake size. Staging still pins an older
self-signed certificate for smoke tests.

## Protocol deprecation

TLS 1.0 and TLS 1.1 were deprecated across the fleet in 2021. Production now
negotiates TLS 1.2 and TLS 1.3 only. SSLv3 has been disabled everywhere for
years and should never reappear in a config review.

## Cipher suites

For TLS 1.2 we prefer `ECDHE-ECDSA-AES256-GCM-SHA384` and
`ECDHE-RSA-AES128-GCM-SHA256`. We explicitly forbid anything mentioning RC4,
3DES (`DES-CBC3-SHA`), or NULL. For TLS 1.3 the stack negotiates
`TLS_AES_256_GCM_SHA384` automatically.

## Post-quantum notes

We are tracking `sntrup761x25519-sha512@openssh.com` for SSH key exchange and
evaluating hybrid KEMs for TLS. None of this is deployed yet.
