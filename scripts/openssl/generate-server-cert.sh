#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

require_ca

SERVER_PASSWORD_FILE="${OUT_DIR}/server-keystore.password"
TRUST_PASSWORD_FILE="${OUT_DIR}/server-truststore.password"
create_password_file "${SERVER_PASSWORD_FILE}"
create_password_file "${TRUST_PASSWORD_FILE}"
SERVER_PASS="$(read_password "${SERVER_PASSWORD_FILE}")"
TRUST_PASS="$(read_password "${TRUST_PASSWORD_FILE}")"

log "Generating server key + CSR"
openssl req -new -newkey "rsa:${KEY_LEN}" -sha256 -nodes \
    -subj "/CN=server/O=TLS Demo" \
    -keyout "${OUT_DIR}/server.key" \
    -out "${OUT_DIR}/server.csr"

log "Signing server certificate with the Demo Root CA"
openssl x509 -req -in "${OUT_DIR}/server.csr" \
    -CA "${OUT_DIR}/ca.crt" \
    -CAkey "${OUT_DIR}/ca.key" \
    -CAcreateserial \
    -out "${OUT_DIR}/server.crt" \
    -days "${DAYS_LEAF}" -sha256 \
    -extfile "${CONFIG}" -extensions server_ext

cat "${OUT_DIR}/server.crt" "${OUT_DIR}/ca.crt" > "${OUT_DIR}/server-chain.crt"

log "Packaging server PKCS12 keystore"
openssl pkcs12 -export \
    -name server \
    -inkey "${OUT_DIR}/server.key" \
    -in "${OUT_DIR}/server.crt" \
    -certfile "${OUT_DIR}/ca.crt" \
    -out "${OUT_DIR}/server.p12" \
    -passout "pass:${SERVER_PASS}"

log "Creating server trust store (trusts Demo Root CA, used to validate clients)"
keytool -importcert -noprompt \
    -alias demo-root-ca \
    -file "${OUT_DIR}/ca.crt" \
    -keystore "${OUT_DIR}/server-truststore.p12" \
    -storetype PKCS12 \
    -storepass "${TRUST_PASS}" >/dev/null

log "Server certificate done:"
openssl x509 -in "${OUT_DIR}/server.crt" -noout -subject -issuer -dates \
    -text | sed -n '/X509v3 extensions/,/Signature Algorithm/p'
