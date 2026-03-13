#!/usr/bin/env bash
set -euo pipefail

echo "=== Validating docker-compose.yml ==="

if ! command -v docker-compose &>/dev/null && ! docker compose version &>/dev/null 2>&1; then
  echo "SKIP: docker-compose not available"
  exit 0
fi

docker-compose config --quiet
echo "PASS: docker-compose.yml is valid"
