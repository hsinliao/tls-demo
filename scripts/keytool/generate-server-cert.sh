#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

require_ca

CA_PASS="$(read_password "${OUT_DIR}/ca.password")"
SERVER_PASSWORD_FILE="${OUT_DIR}/server-keystore.password"
TRUST_PASSWORD_FILE="${OUT_DIR}/server-truststore.password"
create_password_file "${SERVER_PASSWORD_FILE}"
create_password_file "${TRUST_PASSWORD_FILE}"
SERVER_PASS="$(read_password "${SERVER_PASSWORD_FILE}")"
TRUST_PASS="$(read_password "${TRUST_PASSWORD_FILE}")"

SERVER_SAN="SAN=dns:localhost,dns:server,ip:127.0.0.1"
SERVER_KU="KU=digitalSignature,keyEncipherment"
SERVER_EKU="EKU=serverAuth"
LEAF_BC="BC:c=ca:false"

log "Generating server private-key placeholder in ${STORE_TYPE} store"
"${KEYTOOL}" -genkeypair \
    -alias server -keyalg RSA -keysize "${KEY_LEN}" \
    -dname "CN=server,O=TLS Demo" \
    -validity "${DAYS_LEAF}" \
    -storetype "${STORE_TYPE}" \
    -keystore "${OUT_DIR}/server.p12" \
    -storepass "${SERVER_PASS}" \
    -ext "${LEAF_BC}" \
    -ext "${SERVER_KU}" \
    -ext "${SERVER_EKU}" \
    -ext "${SERVER_SAN}" >/dev/null

log "Importing Demo Root CA as trust anchor into server keystore"
"${KEYTOOL}" -importcert -noprompt \
    -alias demo-root-ca \
    -file "${OUT_DIR}/ca.crt" \
    -keystore "${OUT_DIR}/server.p12" \
    -storepass "${SERVER_PASS}" >/dev/null

log "Creating server CSR"
"${KEYTOOL}" -certreq \
    -alias server \
    -keystore "${OUT_DIR}/server.p12" \
    -storepass "${SERVER_PASS}" \
    -file "${OUT_DIR}/server.csr" >/dev/null

log "Signing server certificate with the Demo Root CA"
"${KEYTOOL}" -gencert \
    -alias demo-root-ca \
    -keystore "${OUT_DIR}/ca.p12" \
    -storepass "${CA_PASS}" \
    -infile "${OUT_DIR}/server.csr" \
    -outfile "${OUT_DIR}/server.crt" \
    -rfc -validity "${DAYS_LEAF}" \
    -ext "${LEAF_BC}" \
    -ext "${SERVER_KU}" \
    -ext "${SERVER_EKU}" \
    -ext "${SERVER_SAN}" >/dev/null

log "Installing certificate reply (chain) into server.p12"
"${KEYTOOL}" -importcert -noprompt \
    -alias server \
    -file "${OUT_DIR}/server.crt" \
    -keystore "${OUT_DIR}/server.p12" \
    -storepass "${SERVER_PASS}" >/dev/null

cat "${OUT_DIR}/server.crt" "${OUT_DIR}/ca.crt" > "${OUT_DIR}/server-chain.crt"

log "Creating server trust store (validates clients)"
"${KEYTOOL}" -importcert -noprompt \
    -alias demo-root-ca \
    -file "${OUT_DIR}/ca.crt" \
    -keystore "${OUT_DIR}/server-truststore.p12" \
    -storetype "${STORE_TYPE}" \
    -storepass "${TRUST_PASS}" >/dev/null

log "Server certificate done:"
openssl x509 -in "${OUT_DIR}/server.crt" -noout -subject -issuer -dates \
    -text | sed -n '/X509v3 extensions/,/Signature Algorithm/p'
