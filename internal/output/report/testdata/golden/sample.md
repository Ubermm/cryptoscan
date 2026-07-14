# cryptoscan estate report — sample

_Generated at 2026-01-01T00:00:00Z_

## Estate summary

Assets scored: 7 (flagged with at least one PQC exposure: 7)

### Assets by type

| Type | Count |
| --- | ---: |
| certificate | 4 |
| private_key | 1 |
| tls_config | 1 |
| tls_endpoint | 1 |
| **total** | **7** |

### PQC exposure by flag

| Flag | Count |
| --- | ---: |
| expired | 1 |
| legacy_protocol | 1 |
| quantum_vulnerable_algorithm | 6 |
| weak_key | 1 |
| weak_signature | 1 |

### Headline exposure

- Quantum-vulnerable assets: 6
- Legacy-protocol (< TLS 1.2) endpoints/configs: 1
- Expired certificates: 1
- Expiring certificates (within 90 days): 0
- PQC-ready (hybrid KEX) endpoints: 0

## Findings

Ordered by PQC severity (descending), then asymmetric-first.

| Severity | Type | Algorithm | Key size | Location(s) | Expiry | Issuer / CA | PQC exposure |
| --- | --- | --- | --- | --- | --- | --- | --- |
| critical | certificate | RSA | 1024 | certs/rsa-1024.pem | 2035-01-01T00:00:00Z | CN=weak.example.com (self-signed) | quantum_vulnerable_algorithm, weak_key |
| critical | certificate | RSA | 2048 | certs/sha1.pem | 2035-01-01T00:00:00Z | CN=Example Issuing CA,O=Example | quantum_vulnerable_algorithm, weak_signature |
| high | certificate | RSA | 2048 | certs/leaf.pem; leaf.example.com:443 | 2035-01-01T00:00:00Z | CN=Example Issuing CA,O=Example | quantum_vulnerable_algorithm |
| high | certificate | RSA | 2048 | certs/expired.pem | 2021-01-01T00:00:00Z (expired) | CN=old.example.com (self-signed) | expired, quantum_vulnerable_algorithm |
| high | private_key | RSA | 2048 | certs/server.key | - | - | quantum_vulnerable_algorithm |
| high | tls_endpoint | TLSv1.3 / TLS_AES_128_GCM_SHA256 | - | leaf.example.com:443 | - | - | quantum_vulnerable_algorithm |
| high | tls_config | TLSv1, TLSv1.1, TLSv1.2 | - | configs/nginx/legacy.conf:12 | - | - | legacy_protocol |
