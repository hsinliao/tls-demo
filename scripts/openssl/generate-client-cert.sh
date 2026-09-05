#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

require_ca

CLIENT_PASSWORD_FILE="${OUT_DIR}/client-keystore.password"
TRUST_PASSWORD_FILE="${OUT_DIR}/client-truststore.password"
create_password_file "${CLIENT_PASSWORD_FILE}"
create_password_file "${TRUST_PASSWORD_FILE}"
CLIENT_PASS="$(read_password "${CLIENT_PASSWORD_FILE}")"
TRUST_PASS="$(read_password "${TRUST_PASSWORD_FILE}")"

log "Generating client key + CSR"
openssl req -new -newkey "rsa:${KEY_LEN}" -sha256 -nodes \
    -subj "/CN=client/O=TLS Demo" \
    -keyout "${OUT_DIR}/client.key" \
    -out "${OUT_DIR}/client.csr"

log "Signing client certificate with the Demo Root CA"
openssl x509 -req -in "${OUT_DIR}/client.csr" \
    -CA "${OUT_DIR}/ca.crt" \
    -CAkey "${OUT_DIR}/ca.key" \
    -CAcreateserial \
    -out "${OUT_DIR}/client.crt" \
    -days "${DAYS_LEAF}" -sha256 \
    -extfile "${CONFIG}" -extensions client_ext

cat "${OUT_DIR}/client.crt" "${OUT_DIR}/ca.crt" > "${OUT_DIR}/client-chain.crt"

log "Packaging client PKCS12 keystore"
openssl pkcs12 -export \
    -name client \
    -inkey "${OUT_DIR}/client.key" \
    -in "${OUT_DIR}/client.crt" \
    -certfile "${OUT_DIR}/ca.crt" \
    -out "${OUT_DIR}/client.p12" \
    -passout "pass:${CLIENT_PASS}"

log "Creating client trust store (trusts Demo Root CA, used to validate the server)"
keytool -importcert -noprompt \
    -alias demo-root-ca \
    -file "${OUT_DIR}/ca.crt" \
    -keystore "${OUT_DIR}/client-truststore.p12" \
    -storetype PKCS12 \
    -storepass "${TRUST_PASS}" >/dev/null

log "Client certificate done:"
openssl x509 -in "${OUT_DIR}/client.crt" -noout -subject -issuer -dates \
    -text | sed -n '/X509v3 extensions/,/Signature Algorithm/p'
