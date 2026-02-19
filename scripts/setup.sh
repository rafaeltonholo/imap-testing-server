#!/usr/bin/env bash
set -euo pipefail

# Generates a self-signed TLS certificate for local development.
# Run this once after a fresh clone before starting the containers.

SSL_DIR="$(cd "$(dirname "$0")/.." && pwd)/ssl"
mkdir -p "$SSL_DIR"

if [[ -f "$SSL_DIR/tls.crt" && -f "$SSL_DIR/tls.key" ]]; then
  echo "SSL certificates already exist in ssl/. Skipping generation."
  echo "To regenerate, delete ssl/tls.crt and ssl/tls.key first."
  exit 0
fi

openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout "$SSL_DIR/tls.key" \
  -out "$SSL_DIR/tls.crt" \
  -subj "/CN=localhost" 2>/dev/null

echo "SSL certificates generated in ssl/."
echo "You can now run: docker-compose up -d"
