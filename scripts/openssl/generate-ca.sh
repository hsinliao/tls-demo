#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

log "Generating Demo Root CA in ${OUT_DIR}"
openssl req -x509 -new -newkey "rsa:${KEY_LEN}" -sha256 -nodes \
    -config "${CONFIG}" \
    -keyout "${OUT_DIR}/ca.key" \
    -out "${OUT_DIR}/ca.crt" \
    -days "${DAYS_CA}" \
    -extensions ca_ext

log "CA created:"
openssl x509 -in "${OUT_DIR}/ca.crt" -noout -subject -dates
