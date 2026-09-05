#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

require_ca

CA_PASS="$(read_password "${OUT_DIR}/ca.password")"
CLIENT_PASSWORD_FILE="${OUT_DIR}/client-keystore.password"
TRUST_PASSWORD_FILE="${OUT_DIR}/client-truststore.password"
create_password_file "${CLIENT_PASSWORD_FILE}"
create_password_file "${TRUST_PASSWORD_FILE}"
CLIENT_PASS="$(read_password "${CLIENT_PASSWORD_FILE}")"
TRUST_PASS="$(read_password "${TRUST_PASSWORD_FILE}")"

CLIENT_SAN="SAN=dns:client"
CLIENT_KU="KU=digitalSignature"
CLIENT_EKU="EKU=clientAuth"
LEAF_BC="BC:c=ca:false"

log "Generating client private-key placeholder in ${STORE_TYPE} store"
"${KEYTOOL}" -genkeypair \
    -alias client -keyalg RSA -keysize "${KEY_LEN}" \
    -dname "CN=client,O=TLS Demo" \
    -validity "${DAYS_LEAF}" \
    -storetype "${STORE_TYPE}" \
    -keystore "${OUT_DIR}/client.p12" \
    -storepass "${CLIENT_PASS}" \
    -ext "${LEAF_BC}" \
    -ext "${CLIENT_KU}" \
    -ext "${CLIENT_EKU}" \
    -ext "${CLIENT_SAN}" >/dev/null

log "Importing Demo Root CA as trust anchor into client keystore"
"${KEYTOOL}" -importcert -noprompt \
    -alias demo-root-ca \
    -file "${OUT_DIR}/ca.crt" \
    -keystore "${OUT_DIR}/client.p12" \
    -storepass "${CLIENT_PASS}" >/dev/null

log "Creating client CSR"
"${KEYTOOL}" -certreq \
    -alias client \
    -keystore "${OUT_DIR}/client.p12" \
    -storepass "${CLIENT_PASS}" \
    -file "${OUT_DIR}/client.csr" >/dev/null

log "Signing client certificate with the Demo Root CA"
"${KEYTOOL}" -gencert \
    -alias demo-root-ca \
    -keystore "${OUT_DIR}/ca.p12" \
    -storepass "${CA_PASS}" \
    -infile "${OUT_DIR}/client.csr" \
    -outfile "${OUT_DIR}/client.crt" \
    -rfc -validity "${DAYS_LEAF}" \
    -ext "${LEAF_BC}" \
    -ext "${CLIENT_KU}" \
    -ext "${CLIENT_EKU}" \
    -ext "${CLIENT_SAN}" >/dev/null

log "Installing certificate reply (chain) into client.p12"
"${KEYTOOL}" -importcert -noprompt \
    -alias client \
    -file "${OUT_DIR}/client.crt" \
    -keystore "${OUT_DIR}/client.p12" \
    -storepass "${CLIENT_PASS}" >/dev/null

cat "${OUT_DIR}/client.crt" "${OUT_DIR}/ca.crt" > "${OUT_DIR}/client-chain.crt"

log "Creating client trust store (validates the server)"
"${KEYTOOL}" -importcert -noprompt \
    -alias demo-root-ca \
    -file "${OUT_DIR}/ca.crt" \
    -keystore "${OUT_DIR}/client-truststore.p12" \
    -storetype "${STORE_TYPE}" \
    -storepass "${TRUST_PASS}" >/dev/null

log "Client certificate done:"
openssl x509 -in "${OUT_DIR}/client.crt" -noout -subject -issuer -dates \
    -text | sed -n '/X509v3 extensions/,/Signature Algorithm/p'
