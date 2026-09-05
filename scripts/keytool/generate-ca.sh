#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

CA_PASSWORD_FILE="${OUT_DIR}/ca.password"
create_password_file "${CA_PASSWORD_FILE}"
CA_PASS="$(read_password "${CA_PASSWORD_FILE}")"

log "Generating Demo Root CA keystore (${STORE_TYPE})"
"${KEYTOOL}" -genkeypair \
    -alias demo-root-ca \
    -keyalg RSA -keysize "${KEY_LEN}" \
    -dname "CN=Demo Root CA,O=TLS Demo" \
    -validity "${DAYS_CA}" \
    -storetype "${STORE_TYPE}" \
    -keystore "${OUT_DIR}/ca.p12" \
    -storepass "${CA_PASS}" \
    -ext "BC:c=ca:true,pathlen:1" \
    -ext "KU:c=keyCertSign,cRLSign" >/dev/null

"${KEYTOOL}" -exportcert -rfc \
    -alias demo-root-ca \
    -keystore "${OUT_DIR}/ca.p12" \
    -storepass "${CA_PASS}" \
    -file "${OUT_DIR}/ca.crt" >/dev/null

log "CA created:"
openssl x509 -in "${OUT_DIR}/ca.crt" -noout -subject -dates
