#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

"${SCRIPT_DIR}/clean.sh"
"${SCRIPT_DIR}/generate-ca.sh"
"${SCRIPT_DIR}/generate-server-cert.sh"
"${SCRIPT_DIR}/generate-client-cert.sh"

echo
echo "OpenSSL demo certificates generated under certs/openssl:"
echo "  ca.key / ca.crt                      Demo Root CA"
echo "  server.key / server.crt / chain      server identity"
echo "  client.key / client.crt / chain      client identity"
echo "  server.p12 / client.p12              PKCS12 identity stores"
echo "  server-truststore.p12                CA trusted by the server"
echo "  client-truststore.p12                CA trusted by the client"
echo "  *.password                           local demo secrets (chmod 600)"
