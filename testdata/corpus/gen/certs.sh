#!/usr/bin/env bash
#
# certs.sh — deterministic regenerator for the cryptoscan certificate/key/
# keystore ground-truth corpus (Phase 0).
#
# Requires: OpenSSL 3.x and keytool (JDK) on PATH.
# Produces (relative to testdata/corpus/):
#   certs/      PEM + DER certificates and the leaf+intermediate chain
#   keys/       private keys (PKCS#1 / PKCS#8 / SEC1 / encrypted), public keys, CSRs
#   keystores/  a password-less PKCS#12 and a JKS truststore
#   manifests/certs.yaml  ground-truth manifest fragment (schema version 1)
#
# Determinism notes:
#   * Validity windows are pinned to fixed absolute dates (see START/END below),
#     NOT to `-days` offsets, so fixtures never rot and the expired cert is
#     always genuinely expired. OpenSSL 3.2's `openssl x509` cannot set an
#     arbitrary notBefore/notAfter (that landed in 3.5), so we sign through
#     `openssl ca` (with `-selfsign` for self-signed certs), which accepts
#     explicit `-startdate`/`-enddate`.
#   * Key *material* is freshly generated each run (RSA/EC keygen is inherently
#     random); every spki_sha256 in the manifest is computed from the actual
#     bytes on disk by this script, so the manifest can never drift from the
#     fixtures. Re-running converges to a valid, self-consistent corpus.
#
# The script is idempotent in outcome: it wipes and rebuilds all generated
# assets and the manifest fragment on every run.
set -euo pipefail

# Git Bash / MSYS auto-converts POSIX paths to Windows paths for native tools
# (needed so /tmp file paths reach the native OpenSSL), but it would also
# mangle "/CN=..." subjects and extension strings. Exclude only those prefixes
# from conversion; leave path conversion on for everything else. A no-op on
# Linux CI (the variable is simply ignored there).
export MSYS2_ARG_CONV_EXCL='/CN=;/O=;/OU=;/C=;/ST=;/L=;/emailAddress=;subjectAltName=;basicConstraints=;keyUsage='

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
GEN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORPUS="$(cd "${GEN_DIR}/.." && pwd)"
CERTS="${CORPUS}/certs"
KEYS="${CORPUS}/keys"
KS="${CORPUS}/keystores"
MANI="${CORPUS}/manifests/certs.yaml"

mkdir -p "${CERTS}" "${KEYS}" "${KS}" "${CORPUS}/manifests"

# Scratch CA workspace (index/serial/newcerts) — never committed.
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

# Pinned validity windows.
VALID_START="20250101000000Z"
VALID_END="20350101000000Z"     # notAfter >= 2035 so tests do not rot
EXP_START="20200101000000Z"
EXP_END="20210101000000Z"       # notAfter in the past -> genuinely expired

# ---------------------------------------------------------------------------
# OpenSSL CA config (shared by every signing operation)
# ---------------------------------------------------------------------------
cat > "${WORK}/ca.cnf" <<'EOF'
[ ca ]
default_ca = CA_default

[ CA_default ]
dir              = .
database         = ./index.txt
serial           = ./serial
new_certs_dir    = ./newcerts
default_md       = sha256
policy           = pol_any
copy_extensions  = copy
unique_subject   = no
rand_serial      = no
preserve         = no
email_in_dn      = no

[ pol_any ]
commonName             = optional
countryName            = optional
stateOrProvinceName    = optional
organizationName       = optional
organizationalUnitName = optional
EOF

: > "${WORK}/index.txt"
echo 1000 > "${WORK}/serial"
mkdir -p "${WORK}/newcerts"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# selfsign KEY CSR OUT START END [MD]
# Self-signs CSR with its own key via `openssl ca -selfsign`.
selfsign() {
  local key="$1" csr="$2" out="$3" start="$4" end="$5" md="${6:-}"
  local mdopt=()
  [ -n "${md}" ] && mdopt=(-md "${md}")
  ( cd "${WORK}" && openssl ca -config ca.cnf -selfsign -keyfile "${key}" \
      -in "${csr}" -out "${out}" -batch -notext \
      -startdate "${start}" -enddate "${end}" "${mdopt[@]}" ) >/dev/null 2>&1
}

# casign CAKEY CACERT CSR OUT START END [MD]
# Signs CSR with an issuing CA key/cert.
casign() {
  local cakey="$1" cacert="$2" csr="$3" out="$4" start="$5" end="$6" md="${7:-}"
  local mdopt=()
  [ -n "${md}" ] && mdopt=(-md "${md}")
  ( cd "${WORK}" && openssl ca -config ca.cnf -keyfile "${cakey}" -cert "${cacert}" \
      -in "${csr}" -out "${out}" -batch -notext \
      -startdate "${start}" -enddate "${end}" "${mdopt[@]}" ) >/dev/null 2>&1
}

hexdigest() { openssl dgst -sha256 | awk '{print $NF}' | tr 'A-F' 'a-f'; }
spki_cert_pem() { openssl x509 -in "$1" -pubkey -noout | openssl pkey -pubin -outform DER | hexdigest; }
spki_cert_der() { openssl x509 -inform DER -in "$1" -pubkey -noout | openssl pkey -pubin -outform DER | hexdigest; }
spki_key()      { openssl pkey -in "$1" -pubout -outform DER | hexdigest; }
spki_pub()      { openssl pkey -pubin -in "$1" -outform DER | hexdigest; }
spki_csr()      { openssl req -in "$1" -pubkey -noout | openssl pkey -pubin -outform DER | hexdigest; }

# ---------------------------------------------------------------------------
# Clean previously generated fixtures (keep dirs)
# ---------------------------------------------------------------------------
rm -f "${CERTS}"/*.pem "${CERTS}"/*.der \
      "${KEYS}"/*.key "${KEYS}"/*.pem "${KEYS}"/*.csr \
      "${KS}"/*.p12 "${KS}"/*.jks "${MANI}" 2>/dev/null || true

# ===========================================================================
# KEYS (generated first so certs and key files share SPKI where intended)
# ===========================================================================

# -- RSA 2048 shared key: backs rsa-2048-selfsigned cert + all rsa-2048 assets
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "${WORK}/rsa2048.pk8" 2>/dev/null
openssl rsa -in "${WORK}/rsa2048.pk8" -traditional -out "${KEYS}/rsa-2048.key" 2>/dev/null            # PKCS#1
openssl pkey -in "${WORK}/rsa2048.pk8" -out "${KEYS}/rsa-2048-pkcs8.key" 2>/dev/null                  # PKCS#8
openssl pkey -in "${WORK}/rsa2048.pk8" -pubout -out "${KEYS}/rsa-2048-pub.pem" 2>/dev/null            # SPKI pub

# -- EC P-256 shared key: backs ecdsa-p256 cert + all ec256 assets
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "${WORK}/ec256.pk8" 2>/dev/null
openssl ec -in "${WORK}/ec256.pk8" -out "${KEYS}/ecdsa-p256.key" 2>/dev/null                          # SEC1
openssl pkey -in "${WORK}/ec256.pk8" -out "${KEYS}/ecdsa-p256-pkcs8.key" 2>/dev/null                  # PKCS#8
openssl pkey -in "${WORK}/ec256.pk8" -pubout -out "${KEYS}/ecdsa-p256-pub.pem" 2>/dev/null            # SPKI pub

# -- Ed25519 key (PKCS#8 only)
openssl genpkey -algorithm ED25519 -out "${KEYS}/ed25519.key" 2>/dev/null

# -- Encrypted RSA-2048 PKCS#8 key (AES-256-CBC, password "changeit")
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "${WORK}/rsaenc.pk8" 2>/dev/null
openssl pkcs8 -topk8 -in "${WORK}/rsaenc.pk8" -v2 aes-256-cbc -passout pass:changeit \
  -out "${KEYS}/rsa-2048-encrypted.key" 2>/dev/null

# -- CSRs (standalone assets)
openssl req -new -key "${WORK}/rsa2048.pk8" -subj "/CN=csr-rsa2048.example.test" \
  -out "${KEYS}/rsa-2048.csr" 2>/dev/null
openssl req -new -key "${WORK}/ec256.pk8" -subj "/CN=csr-ecdsa-p256.example.test" \
  -out "${KEYS}/ecdsa-p256.csr" 2>/dev/null

# ===========================================================================
# CERTIFICATES
# ===========================================================================

# Convenience: gen a fresh key of a given kind into WORK
genkey() { # genkey OUT KIND
  case "$2" in
    rsa1024) openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:1024 -out "$1" 2>/dev/null ;;
    rsa2048) openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$1" 2>/dev/null ;;
    rsa4096) openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out "$1" 2>/dev/null ;;
    ec256)   openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null ;;
    ec384)   openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out "$1" 2>/dev/null ;;
    ed)      openssl genpkey -algorithm ED25519 -out "$1" 2>/dev/null ;;
  esac
}

# -- Simple self-signed leaf certs (no CA extensions) ------------------------
# RSA 1024
genkey "${WORK}/k_rsa1024" rsa1024
openssl req -new -key "${WORK}/k_rsa1024" -subj "/CN=rsa1024.example.test" -out "${WORK}/rsa1024.csr" 2>/dev/null
selfsign "k_rsa1024" "rsa1024.csr" "rsa-1024-selfsigned.pem" "${VALID_START}" "${VALID_END}" sha256
cp "${WORK}/rsa-1024-selfsigned.pem" "${CERTS}/rsa-1024-selfsigned.pem"

# RSA 2048 (shared key) — REQUIRED filename
openssl req -new -key "${WORK}/rsa2048.pk8" -subj "/CN=rsa2048.example.test" -out "${WORK}/rsa2048.csr" 2>/dev/null
selfsign "rsa2048.pk8" "rsa2048.csr" "rsa-2048-selfsigned.pem" "${VALID_START}" "${VALID_END}" sha256
cp "${WORK}/rsa-2048-selfsigned.pem" "${CERTS}/rsa-2048-selfsigned.pem"

# RSA 4096
genkey "${WORK}/k_rsa4096" rsa4096
openssl req -new -key "${WORK}/k_rsa4096" -subj "/CN=rsa4096.example.test" -out "${WORK}/rsa4096.csr" 2>/dev/null
selfsign "k_rsa4096" "rsa4096.csr" "rsa-4096-selfsigned.pem" "${VALID_START}" "${VALID_END}" sha256
cp "${WORK}/rsa-4096-selfsigned.pem" "${CERTS}/rsa-4096-selfsigned.pem"

# ECDSA P-256 (shared key) — REQUIRED filename
openssl req -new -key "${WORK}/ec256.pk8" -subj "/CN=ecdsa-p256.example.test" -out "${WORK}/ec256.csr" 2>/dev/null
selfsign "ec256.pk8" "ec256.csr" "ecdsa-p256.pem" "${VALID_START}" "${VALID_END}" sha256
cp "${WORK}/ecdsa-p256.pem" "${CERTS}/ecdsa-p256.pem"

# ECDSA P-384 (signed with sha384 -> ECDSA-SHA384)
genkey "${WORK}/k_ec384" ec384
openssl req -new -key "${WORK}/k_ec384" -subj "/CN=ecdsa-p384.example.test" -out "${WORK}/ec384.csr" 2>/dev/null
selfsign "k_ec384" "ec384.csr" "ecdsa-p384.pem" "${VALID_START}" "${VALID_END}" sha384
cp "${WORK}/ecdsa-p384.pem" "${CERTS}/ecdsa-p384.pem"

# Ed25519 (md ignored)
openssl req -new -key "${KEYS}/ed25519.key" -subj "/CN=ed25519.example.test" -out "${WORK}/ed.csr" 2>/dev/null
selfsign "$(cd "${KEYS}" && pwd)/ed25519.key" "ed.csr" "ed25519.pem" "${VALID_START}" "${VALID_END}"
cp "${WORK}/ed25519.pem" "${CERTS}/ed25519.pem"

# EXPIRED RSA 2048 (pinned past window)
genkey "${WORK}/k_exp" rsa2048
openssl req -new -key "${WORK}/k_exp" -subj "/CN=expired.example.test" -out "${WORK}/exp.csr" 2>/dev/null
selfsign "k_exp" "exp.csr" "rsa-2048-expired.pem" "${EXP_START}" "${EXP_END}" sha256
cp "${WORK}/rsa-2048-expired.pem" "${CERTS}/rsa-2048-expired.pem"

# SHA-1 signed RSA 2048 -> SHA1-RSA
genkey "${WORK}/k_sha1" rsa2048
openssl req -new -key "${WORK}/k_sha1" -subj "/CN=sha1.example.test" -out "${WORK}/sha1.csr" 2>/dev/null
selfsign "k_sha1" "sha1.csr" "rsa-2048-sha1.pem" "${VALID_START}" "${VALID_END}" sha1
cp "${WORK}/rsa-2048-sha1.pem" "${CERTS}/rsa-2048-sha1.pem"

# MD5 signed RSA 2048 -> MD5-RSA (skip silently if unsupported)
HAVE_MD5=0
genkey "${WORK}/k_md5" rsa2048
openssl req -new -key "${WORK}/k_md5" -subj "/CN=md5.example.test" -out "${WORK}/md5.csr" 2>/dev/null
if selfsign "k_md5" "md5.csr" "rsa-2048-md5.pem" "${VALID_START}" "${VALID_END}" md5 \
   && [ -s "${WORK}/rsa-2048-md5.pem" ]; then
  cp "${WORK}/rsa-2048-md5.pem" "${CERTS}/rsa-2048-md5.pem"
  HAVE_MD5=1
fi

# Long SAN list (5 DNS + IP), self-signed RSA 2048
genkey "${WORK}/k_san" rsa2048
openssl req -new -key "${WORK}/k_san" -subj "/CN=multi-san.example.test" \
  -addext "subjectAltName=DNS:a.example.test,DNS:b.example.test,DNS:c.example.test,DNS:d.example.test,DNS:e.example.test,IP:192.0.2.10" \
  -out "${WORK}/san.csr" 2>/dev/null
selfsign "k_san" "san.csr" "multi-san.pem" "${VALID_START}" "${VALID_END}" sha256
cp "${WORK}/multi-san.pem" "${CERTS}/multi-san.pem"

# -- 3-level chain: root CA -> intermediate CA -> leaf ----------------------
genkey "${WORK}/root.key" rsa2048
openssl req -new -key "${WORK}/root.key" -subj "/CN=cryptoscan Test Root CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" -out "${WORK}/root.csr" 2>/dev/null
selfsign "root.key" "root.csr" "root-ca.pem" "${VALID_START}" "${VALID_END}" sha256
cp "${WORK}/root-ca.pem" "${CERTS}/root-ca.pem"

genkey "${WORK}/inter.key" rsa2048
openssl req -new -key "${WORK}/inter.key" -subj "/CN=cryptoscan Test Intermediate CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" -out "${WORK}/inter.csr" 2>/dev/null
casign "root.key" "root-ca.pem" "inter.csr" "intermediate-ca.pem" "${VALID_START}" "${VALID_END}" sha256
cp "${WORK}/intermediate-ca.pem" "${CERTS}/intermediate-ca.pem"

genkey "${WORK}/leaf.key" rsa2048
openssl req -new -key "${WORK}/leaf.key" -subj "/CN=example.test" \
  -addext "subjectAltName=DNS:example.test,DNS:www.example.test" -out "${WORK}/leaf.csr" 2>/dev/null
casign "inter.key" "intermediate-ca.pem" "leaf.csr" "leaf.pem" "${VALID_START}" "${VALID_END}" sha256
cp "${WORK}/leaf.pem" "${CERTS}/leaf.pem"

# Combined chain file (leaf + intermediate) — REQUIRED filename
cat "${CERTS}/leaf.pem" "${CERTS}/intermediate-ca.pem" > "${CERTS}/leaf-chain.pem"

# -- DER encodings (separate assets) ----------------------------------------
openssl x509 -in "${CERTS}/rsa-2048-selfsigned.pem" -outform DER -out "${CERTS}/rsa-2048-selfsigned.der"
openssl x509 -in "${CERTS}/ecdsa-p256.pem"          -outform DER -out "${CERTS}/ecdsa-p256.der"
openssl x509 -in "${CERTS}/ed25519.pem"             -outform DER -out "${CERTS}/ed25519.der"

# ===========================================================================
# KEYSTORES
# ===========================================================================
# Password-less PKCS#12 with the RSA-2048 cert + key (alias rsa2048)
rm -f "${KS}/rsa2048.p12"
openssl pkcs12 -export -passout pass: -name rsa2048 \
  -inkey "${KEYS}/rsa-2048.key" -in "${CERTS}/rsa-2048-selfsigned.pem" \
  -out "${KS}/rsa2048.p12" 2>/dev/null

# JKS truststore (storepass "changeit") with 2 trusted cert entries
rm -f "${KS}/truststore.jks"
keytool -importcert -noprompt -keystore "${KS}/truststore.jks" -storetype JKS \
  -storepass changeit -alias ecp256  -file "${CERTS}/ecdsa-p256.pem"          >/dev/null 2>&1
keytool -importcert -noprompt -keystore "${KS}/truststore.jks" -storetype JKS \
  -storepass changeit -alias rsa4096 -file "${CERTS}/rsa-4096-selfsigned.pem" >/dev/null 2>&1

# ===========================================================================
# MANIFEST FRAGMENT
# ===========================================================================
# Compute all SPKI values from the actual files (never hand-typed).
SPKI_RSA1024=$(spki_cert_pem "${CERTS}/rsa-1024-selfsigned.pem")
SPKI_RSA2048=$(spki_cert_pem "${CERTS}/rsa-2048-selfsigned.pem")
SPKI_RSA4096=$(spki_cert_pem "${CERTS}/rsa-4096-selfsigned.pem")
SPKI_EC256=$(spki_cert_pem "${CERTS}/ecdsa-p256.pem")
SPKI_EC384=$(spki_cert_pem "${CERTS}/ecdsa-p384.pem")
SPKI_ED=$(spki_cert_pem "${CERTS}/ed25519.pem")
SPKI_EXP=$(spki_cert_pem "${CERTS}/rsa-2048-expired.pem")
SPKI_SHA1=$(spki_cert_pem "${CERTS}/rsa-2048-sha1.pem")
SPKI_SAN=$(spki_cert_pem "${CERTS}/multi-san.pem")
SPKI_ROOT=$(spki_cert_pem "${CERTS}/root-ca.pem")
SPKI_INTER=$(spki_cert_pem "${CERTS}/intermediate-ca.pem")
SPKI_LEAF=$(spki_cert_pem "${CERTS}/leaf.pem")
SPKI_RSA2048_DER=$(spki_cert_der "${CERTS}/rsa-2048-selfsigned.der")
SPKI_EC256_DER=$(spki_cert_der "${CERTS}/ecdsa-p256.der")
SPKI_ED_DER=$(spki_cert_der "${CERTS}/ed25519.der")

SPKI_KEY_RSA2048=$(spki_key "${KEYS}/rsa-2048.key")
SPKI_KEY_RSA2048_PK8=$(spki_key "${KEYS}/rsa-2048-pkcs8.key")
SPKI_KEY_EC256=$(spki_key "${KEYS}/ecdsa-p256.key")
SPKI_KEY_EC256_PK8=$(spki_key "${KEYS}/ecdsa-p256-pkcs8.key")
SPKI_KEY_ED=$(spki_key "${KEYS}/ed25519.key")
SPKI_PUB_RSA2048=$(spki_pub "${KEYS}/rsa-2048-pub.pem")
SPKI_PUB_EC256=$(spki_pub "${KEYS}/ecdsa-p256-pub.pem")

if [ "${HAVE_MD5}" = "1" ]; then
  SPKI_MD5=$(spki_cert_pem "${CERTS}/rsa-2048-md5.pem")
fi

{
cat <<EOF
# cryptoscan corpus manifest fragment — certificates, keys, keystores.
# GENERATED by testdata/corpus/gen/certs.sh — do not edit by hand.
# All spki_sha256 values are computed from the actual fixture bytes by the
# generator (openssl pubkey -> DER -> sha256), lowercase hex, no colons.
#
# Keystore passwords: PKCS#12 rsa2048.p12 has an EMPTY export password;
# JKS truststore.jks store password is "changeit".
version: 1
assets:
  # ---- self-signed RSA certs ----
  - id: cert-rsa-1024-selfsigned
    class: certificate
    path: certs/rsa-1024-selfsigned.pem
    container: pem
    alias: ""
    expect:
      algorithm: RSA
      key_size: 1024
      curve: ""
      signature_algorithm: SHA256-RSA
      spki_sha256: "${SPKI_RSA1024}"
      subject_cn: rsa1024.example.test
      self_signed: true
      expired: false
  - id: cert-rsa-2048-selfsigned
    class: certificate
    path: certs/rsa-2048-selfsigned.pem
    container: pem
    alias: ""
    expect:
      algorithm: RSA
      key_size: 2048
      curve: ""
      signature_algorithm: SHA256-RSA
      spki_sha256: "${SPKI_RSA2048}"
      subject_cn: rsa2048.example.test
      self_signed: true
      expired: false
  - id: cert-rsa-4096-selfsigned
    class: certificate
    path: certs/rsa-4096-selfsigned.pem
    container: pem
    alias: ""
    expect:
      algorithm: RSA
      key_size: 4096
      curve: ""
      signature_algorithm: SHA256-RSA
      spki_sha256: "${SPKI_RSA4096}"
      subject_cn: rsa4096.example.test
      self_signed: true
      expired: false
  # ---- self-signed ECDSA / Ed25519 ----
  - id: cert-ecdsa-p256
    class: certificate
    path: certs/ecdsa-p256.pem
    container: pem
    alias: ""
    expect:
      algorithm: ECDSA
      key_size: 256
      curve: P-256
      signature_algorithm: ECDSA-SHA256
      spki_sha256: "${SPKI_EC256}"
      subject_cn: ecdsa-p256.example.test
      self_signed: true
      expired: false
  - id: cert-ecdsa-p384
    class: certificate
    path: certs/ecdsa-p384.pem
    container: pem
    alias: ""
    expect:
      algorithm: ECDSA
      key_size: 384
      curve: P-384
      signature_algorithm: ECDSA-SHA384
      spki_sha256: "${SPKI_EC384}"
      subject_cn: ecdsa-p384.example.test
      self_signed: true
      expired: false
  - id: cert-ed25519
    class: certificate
    path: certs/ed25519.pem
    container: pem
    alias: ""
    expect:
      algorithm: Ed25519
      key_size: 256
      curve: ""
      signature_algorithm: Ed25519
      spki_sha256: "${SPKI_ED}"
      subject_cn: ed25519.example.test
      self_signed: true
      expired: false
  # ---- weak / expired ----
  - id: cert-rsa-2048-expired
    class: certificate
    path: certs/rsa-2048-expired.pem
    container: pem
    alias: ""
    expect:
      algorithm: RSA
      key_size: 2048
      curve: ""
      signature_algorithm: SHA256-RSA
      spki_sha256: "${SPKI_EXP}"
      subject_cn: expired.example.test
      self_signed: true
      expired: true
  - id: cert-rsa-2048-sha1
    class: certificate
    path: certs/rsa-2048-sha1.pem
    container: pem
    alias: ""
    expect:
      algorithm: RSA
      key_size: 2048
      curve: ""
      signature_algorithm: SHA1-RSA
      spki_sha256: "${SPKI_SHA1}"
      subject_cn: sha1.example.test
      self_signed: true
      expired: false
EOF

if [ "${HAVE_MD5}" = "1" ]; then
cat <<EOF
  - id: cert-rsa-2048-md5
    class: certificate
    path: certs/rsa-2048-md5.pem
    container: pem
    alias: ""
    expect:
      algorithm: RSA
      key_size: 2048
      curve: ""
      signature_algorithm: MD5-RSA
      spki_sha256: "${SPKI_MD5}"
      subject_cn: md5.example.test
      self_signed: true
      expired: false
EOF
fi

cat <<EOF
  # ---- long SAN list ----
  - id: cert-multi-san
    class: certificate
    path: certs/multi-san.pem
    container: pem
    alias: ""
    expect:
      algorithm: RSA
      key_size: 2048
      curve: ""
      signature_algorithm: SHA256-RSA
      spki_sha256: "${SPKI_SAN}"
      subject_cn: multi-san.example.test
      self_signed: true
      expired: false
  # ---- 3-level chain ----
  - id: cert-root-ca
    class: certificate
    path: certs/root-ca.pem
    container: pem
    alias: ""
    expect:
      algorithm: RSA
      key_size: 2048
      curve: ""
      signature_algorithm: SHA256-RSA
      spki_sha256: "${SPKI_ROOT}"
      subject_cn: cryptoscan Test Root CA
      self_signed: true
      expired: false
  - id: cert-intermediate-ca
    class: certificate
    path: certs/intermediate-ca.pem
    container: pem
    alias: ""
    expect:
      algorithm: RSA
      key_size: 2048
      curve: ""
      signature_algorithm: SHA256-RSA
      spki_sha256: "${SPKI_INTER}"
      subject_cn: cryptoscan Test Intermediate CA
      self_signed: false
      expired: false
  - id: cert-leaf
    class: certificate
    path: certs/leaf.pem
    container: pem
    alias: ""
    expect:
      algorithm: RSA
      key_size: 2048
      curve: ""
      signature_algorithm: SHA256-RSA
      spki_sha256: "${SPKI_LEAF}"
      subject_cn: example.test
      self_signed: false
      expired: false
  # ---- combined chain file (leaf + intermediate); keyed by path+alias ----
  - id: cert-chain-leaf
    class: certificate
    path: certs/leaf-chain.pem
    container: pem
    alias: "0"
    expect:
      algorithm: RSA
      key_size: 2048
      curve: ""
      signature_algorithm: SHA256-RSA
      spki_sha256: "${SPKI_LEAF}"
      subject_cn: example.test
      self_signed: false
      expired: false
  - id: cert-chain-intermediate
    class: certificate
    path: certs/leaf-chain.pem
    container: pem
    alias: "1"
    expect:
      algorithm: RSA
      key_size: 2048
      curve: ""
      signature_algorithm: SHA256-RSA
      spki_sha256: "${SPKI_INTER}"
      subject_cn: cryptoscan Test Intermediate CA
      self_signed: false
      expired: false
  # ---- DER encodings ----
  - id: cert-rsa-2048-der
    class: certificate
    path: certs/rsa-2048-selfsigned.der
    container: der
    alias: ""
    expect:
      algorithm: RSA
      key_size: 2048
      curve: ""
      signature_algorithm: SHA256-RSA
      spki_sha256: "${SPKI_RSA2048_DER}"
      subject_cn: rsa2048.example.test
      self_signed: true
      expired: false
  - id: cert-ecdsa-p256-der
    class: certificate
    path: certs/ecdsa-p256.der
    container: der
    alias: ""
    expect:
      algorithm: ECDSA
      key_size: 256
      curve: P-256
      signature_algorithm: ECDSA-SHA256
      spki_sha256: "${SPKI_EC256_DER}"
      subject_cn: ecdsa-p256.example.test
      self_signed: true
      expired: false
  - id: cert-ed25519-der
    class: certificate
    path: certs/ed25519.der
    container: der
    alias: ""
    expect:
      algorithm: Ed25519
      key_size: 256
      curve: ""
      signature_algorithm: Ed25519
      spki_sha256: "${SPKI_ED_DER}"
      subject_cn: ed25519.example.test
      self_signed: true
      expired: false
  # ==== PRIVATE KEYS ====
  - id: key-rsa-2048-pkcs1
    class: private_key
    path: keys/rsa-2048.key
    container: pem
    alias: ""
    expect:
      algorithm: RSA
      key_size: 2048
      curve: ""
      spki_sha256: "${SPKI_KEY_RSA2048}"
  - id: key-rsa-2048-pkcs8
    class: private_key
    path: keys/rsa-2048-pkcs8.key
    container: pem
    alias: ""
    expect:
      algorithm: RSA
      key_size: 2048
      curve: ""
      spki_sha256: "${SPKI_KEY_RSA2048_PK8}"
  - id: key-ecdsa-p256-sec1
    class: private_key
    path: keys/ecdsa-p256.key
    container: pem
    alias: ""
    expect:
      algorithm: ECDSA
      key_size: 256
      curve: P-256
      spki_sha256: "${SPKI_KEY_EC256}"
  - id: key-ecdsa-p256-pkcs8
    class: private_key
    path: keys/ecdsa-p256-pkcs8.key
    container: pem
    alias: ""
    expect:
      algorithm: ECDSA
      key_size: 256
      curve: P-256
      spki_sha256: "${SPKI_KEY_EC256_PK8}"
  - id: key-ed25519-pkcs8
    class: private_key
    path: keys/ed25519.key
    container: pem
    alias: ""
    expect:
      algorithm: Ed25519
      key_size: 256
      curve: ""
      spki_sha256: "${SPKI_KEY_ED}"
  # Encrypted PKCS#8 (AES-256-CBC, password "changeit"). Only provable fact
  # without the password is that this IS an encrypted private key; the inner
  # key algorithm/size/SPKI are not recoverable, so no expect fields.
  - id: key-rsa-2048-encrypted
    class: private_key
    path: keys/rsa-2048-encrypted.key
    container: pem
    alias: ""
    expect: {}
  # ==== PUBLIC KEYS ====
  - id: pub-rsa-2048
    class: public_key
    path: keys/rsa-2048-pub.pem
    container: pem
    alias: ""
    expect:
      algorithm: RSA
      key_size: 2048
      curve: ""
      spki_sha256: "${SPKI_PUB_RSA2048}"
  - id: pub-ecdsa-p256
    class: public_key
    path: keys/ecdsa-p256-pub.pem
    container: pem
    alias: ""
    expect:
      algorithm: ECDSA
      key_size: 256
      curve: P-256
      spki_sha256: "${SPKI_PUB_EC256}"
  # ==== CSRs ====
  - id: csr-rsa-2048
    class: csr
    path: keys/rsa-2048.csr
    container: pem
    alias: ""
    expect:
      algorithm: RSA
      key_size: 2048
      curve: ""
      subject_cn: csr-rsa2048.example.test
  - id: csr-ecdsa-p256
    class: csr
    path: keys/ecdsa-p256.csr
    container: pem
    alias: ""
    expect:
      algorithm: ECDSA
      key_size: 256
      curve: P-256
      subject_cn: csr-ecdsa-p256.example.test
  # ==== KEYSTORE ENTRIES ====
  # Password-less PKCS#12 (empty export password): one cert + one key, alias "rsa2048".
  - id: p12-rsa2048-cert
    class: certificate
    path: keystores/rsa2048.p12
    container: pkcs12
    alias: rsa2048
    expect:
      algorithm: RSA
      key_size: 2048
      curve: ""
      signature_algorithm: SHA256-RSA
      spki_sha256: "${SPKI_RSA2048}"
      subject_cn: rsa2048.example.test
      self_signed: true
      expired: false
  - id: p12-rsa2048-key
    class: private_key
    path: keystores/rsa2048.p12
    container: pkcs12
    alias: rsa2048
    expect:
      algorithm: RSA
      key_size: 2048
      curve: ""
      spki_sha256: "${SPKI_KEY_RSA2048}"
  # JKS truststore (store password "changeit"): two trusted cert entries.
  - id: jks-ecp256
    class: certificate
    path: keystores/truststore.jks
    container: jks
    alias: ecp256
    expect:
      algorithm: ECDSA
      key_size: 256
      curve: P-256
      signature_algorithm: ECDSA-SHA256
      spki_sha256: "${SPKI_EC256}"
      subject_cn: ecdsa-p256.example.test
      self_signed: true
      expired: false
  - id: jks-rsa4096
    class: certificate
    path: keystores/truststore.jks
    container: jks
    alias: rsa4096
    expect:
      algorithm: RSA
      key_size: 4096
      curve: ""
      signature_algorithm: SHA256-RSA
      spki_sha256: "${SPKI_RSA4096}"
      subject_cn: rsa4096.example.test
      self_signed: true
      expired: false
EOF
} > "${MANI}"

echo "Generated fixtures under ${CORPUS}"
echo "Manifest: ${MANI}"
[ "${HAVE_MD5}" = "1" ] && echo "MD5-signed cert: included" || echo "MD5-signed cert: skipped (openssl refused md5)"
