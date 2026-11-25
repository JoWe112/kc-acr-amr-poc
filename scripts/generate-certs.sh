#!/usr/bin/env bash
#
# generate-certs.sh — creates every certificate the local POC needs.
#
# Output (in ./certs, git-ignored):
#   ca-standard.{crt,key}       "Test CA Standard"   -> LoA 2 (loa2)
#   ca-high.{crt,key}           "Test CA High Trust" -> LoA 3 (loa3)
#   ca-unmapped.{crt,key}       "Test CA Unmapped"   -> trusted by TLS, but NOT in the
#                               LoA mapping. Used to exercise the fail-closed branch.
#   server.{crt,key}            TLS server certificate for https://localhost:8443
#   truststore.p12              PKCS#12 truststore with all three CAs (Keycloak mTLS)
#   testuser-standard.{p12,pem,key,crt}   client certificate from "Test CA Standard"
#   testuser-high.{p12,pem,key,crt}       client certificate from "Test CA High Trust"
#   testuser-unmapped.{p12,pem,key,crt}   client certificate from "Test CA Unmapped"
#
# All client certificates use CN=testuser so that the X.509 authenticator in
# Keycloak maps them to the same pre-provisioned user ("testuser").
#
# Usage: scripts/generate-certs.sh [--force]
#   --force   regenerate even if certs/ already contains a CA.
#
# Test-only material: the private keys are unencrypted and the PKCS#12 password
# is the well-known value "changeit". Never use these files outside the POC.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${ROOT_DIR}/certs"
P12_PASS="${P12_PASS:-changeit}"
DAYS_CA=3650
DAYS_LEAF=825
ORG="Example Org"
COUNTRY="SE"

if [[ -f "${OUT}/ca-standard.crt" && "${1:-}" != "--force" ]]; then
  echo "certs/ already populated — use --force to regenerate." >&2
  exit 0
fi

rm -rf "${OUT}"
mkdir -p "${OUT}"
cd "${OUT}"

# create_ca <file-prefix> <common name>
# Self-signed root CA with the extensions a real issuing CA would carry.
create_ca() {
  local prefix="$1" cn="$2"
  openssl req -x509 -new -nodes -newkey rsa:3072 -sha256 -days "${DAYS_CA}" \
    -keyout "${prefix}.key" -out "${prefix}.crt" \
    -subj "/C=${COUNTRY}/O=${ORG}/CN=${cn}" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash" 2>/dev/null
  echo "  CA      ${cn}  ->  ${prefix}.crt"
}

# create_leaf <file-prefix> <ca-prefix> <subject> <extfile-content>
# Issues a leaf certificate signed by the given CA.
create_leaf() {
  local prefix="$1" ca="$2" subj="$3" ext="$4"
  openssl req -new -nodes -newkey rsa:2048 -sha256 \
    -keyout "${prefix}.key" -out "${prefix}.csr" -subj "${subj}" 2>/dev/null
  printf '%s\n' "${ext}" > "${prefix}.ext"
  openssl x509 -req -sha256 -days "${DAYS_LEAF}" \
    -in "${prefix}.csr" -CA "${ca}.crt" -CAkey "${ca}.key" -CAcreateserial \
    -extfile "${prefix}.ext" -out "${prefix}.crt" 2>/dev/null
  rm -f "${prefix}.csr" "${prefix}.ext"
}

echo "Generating test CAs..."
create_ca ca-standard "Test CA Standard"
create_ca ca-high     "Test CA High Trust"
create_ca ca-unmapped "Test CA Unmapped"

echo "Generating server certificate (localhost)..."
create_leaf server ca-standard "/C=${COUNTRY}/O=${ORG}/CN=localhost" \
"basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,DNS:keycloak,IP:127.0.0.1"
# Server cert + issuing CA so clients can build the chain.
cat server.crt ca-standard.crt > server-chain.crt

echo "Generating client certificates for testuser..."
for variant in standard high unmapped; do
  create_leaf "testuser-${variant}" "ca-${variant}" \
    "/C=${COUNTRY}/O=${ORG}/CN=testuser/emailAddress=testuser@example.org" \
"basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
subjectAltName=email:testuser@example.org"
  # .pem = certificate + private key in one file (curl/Bruno friendly)
  cat "testuser-${variant}.crt" "testuser-${variant}.key" > "testuser-${variant}.pem"
  # .p12 = browser import format; legacy-compatible algorithms for Firefox/macOS
  openssl pkcs12 -export -name "testuser (${variant})" \
    -inkey "testuser-${variant}.key" -in "testuser-${variant}.crt" \
    -certfile "ca-${variant}.crt" \
    -keypbe AES-256-CBC -certpbe AES-256-CBC -macalg sha256 \
    -passout "pass:${P12_PASS}" -out "testuser-${variant}.p12"
  echo "  client  testuser-${variant}.p12 / .pem  (issuer: $(openssl x509 -in "testuser-${variant}.crt" -noout -issuer -nameopt RFC2253 | sed 's/^issuer=//'))"
done

echo "Building truststore.p12 (all three CAs)..."
# keytool is not needed: OpenSSL 3 can write a trusted-cert-only PKCS#12 that Java reads.
openssl pkcs12 -export -nokeys \
  -in <(cat ca-standard.crt ca-high.crt ca-unmapped.crt) \
  -jdktrust anyExtendedKeyUsage \
  -passout "pass:${P12_PASS}" -out truststore.p12

# Keycloak runs with an arbitrary UID in the container: make files world-readable
# (test material only).
chmod 0644 ./*
rm -f ./*.srl

echo
echo "Issuer DNs to use in the Keycloak LoA mapping (RFC 2253):"
for ca in ca-standard ca-high ca-unmapped; do
  printf '  %-12s %s\n' "${ca}" "$(openssl x509 -in "${ca}.crt" -noout -subject -nameopt RFC2253 | sed 's/^subject=//')"
done
echo
echo "Done. PKCS#12 password: ${P12_PASS}"
