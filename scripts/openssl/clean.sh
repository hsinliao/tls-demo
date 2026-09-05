#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
OUT_DIR="${TLS_CERT_DIR:-${PROJECT_ROOT}/certs/openssl}"

if [[ "${OUT_DIR}" != *"/certs/openssl" && "${OUT_DIR}" != *"/certs/openssl/" ]]; then
    echo "Refusing to clean unexpected directory: ${OUT_DIR}" >&2
    exit 1
fi

rm -f \
    "${OUT_DIR}/ca.key" "${OUT_DIR}/ca.crt" "${OUT_DIR}/ca.srl" \
    "${OUT_DIR}/server.key" "${OUT_DIR}/server.csr" "${OUT_DIR}/server.crt" \
    "${OUT_DIR}/server-chain.crt" \
    "${OUT_DIR}/client.key" "${OUT_DIR}/client.csr" "${OUT_DIR}/client.crt" \
    "${OUT_DIR}/client-chain.crt" \
    "${OUT_DIR}/server.p12" "${OUT_DIR}/client.p12" \
    "${OUT_DIR}/server-truststore.p12" "${OUT_DIR}/client-truststore.p12" \
    "${OUT_DIR}/server-keystore.password" "${OUT_DIR}/server-truststore.password" \
    "${OUT_DIR}/client-keystore.password" "${OUT_DIR}/client-truststore.password"

echo "OpenSSL demo certificate material removed from ${OUT_DIR}"
