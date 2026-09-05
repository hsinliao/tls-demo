#!/usr/bin/env bash
#
# Shared helpers for the keytool certificate scripts.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
OUT_DIR="${TLS_CERT_DIR:-${PROJECT_ROOT}/certs/keytool}"

# Default to PKCS12. For legacy interop set KEYSTORE_TYPE=JKS.
STORE_TYPE="${KEYSTORE_TYPE:-PKCS12}"
KEYTOOL="${KEYTOOL:-keytool}"

DAYS_CA="${DAYS_CA:-3650}"
DAYS_LEAF="${DAYS_LEAF:-825}"
KEY_LEN="${KEY_LEN:-2048}"

umask 077
mkdir -p "${OUT_DIR}"

log() {
    printf '[tls-demo] %s\n' "$*"
}

create_password_file() {
    local file="$1"
    if [[ -f "${file}" ]]; then
        log "Reusing existing password file ${file}"
        return
    fi
    openssl rand -hex 24 > "${file}"
    chmod 600 "${file}"
    log "Created password file ${file} (mode 600)"
}

read_password() {
    tr -d '\n\r' < "$1"
}

require_ca() {
    if [[ ! -f "${OUT_DIR}/ca.p12" || ! -f "${OUT_DIR}/ca.crt" ]]; then
        log "Root CA keystore not found. Run scripts/keytool/generate-ca.sh first."
        exit 1
    fi
}
