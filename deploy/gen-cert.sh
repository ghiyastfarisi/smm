#!/usr/bin/env bash
# Self-signed certificate for the release profile's TLS edge (docker-compose.release.yml), local verification only.
# Production replaces deploy/tls/cert.pem + key.pem with a CA-issued pair for the SITE_URL host.
# Usage: bash deploy/gen-cert.sh [host]   (default localhost; re-run to replace)
set -euo pipefail
cd "$(dirname "$0")"
host=${1:-localhost}
mkdir -p tls
(umask 077; openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 825 \
  -subj "/CN=$host" -addext "subjectAltName=DNS:$host,IP:127.0.0.1" \
  -keyout tls/key.pem -out tls/cert.pem 2>/dev/null)
chmod 644 tls/cert.pem tls/key.pem   # read by the nginx worker (uid 101) in the tls container
echo "deploy/tls/cert.pem + key.pem for $host (self-signed; trust it in node with NODE_EXTRA_CA_CERTS=deploy/tls/cert.pem)"
