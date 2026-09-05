#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

"${SCRIPT_DIR}/clean.sh"
"${SCRIPT_DIR}/generate-ca.sh"
"${SCRIPT_DIR}/generate-server-cert.sh"
"${SCRIPT_DIR}/generate-client-cert.sh"

echo
echo "keytool demo certificates generated under certs/keytool (${KEYSTORE_TYPE:-PKCS12}):"
echo "  ca.p12 / ca.crt                    Demo Root CA"
echo "  server.p12 / client.p12            identity stores"
echo "  server-chain.crt / client-chain.crt"
echo "  server-truststore.p12 / client-truststore.p12"
echo "  *.password                         local demo secrets (chmod 600)"
echo
echo "Set KEYSTORE_TYPE=JKS to generate legacy JKS-compatible stores instead."
