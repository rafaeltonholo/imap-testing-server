#!/bin/sh
set -eu

local_dashboard_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
local_repository_root=$(CDPATH= cd -- "$local_dashboard_root/.." && pwd -P)
local_fixture_root="$local_dashboard_root/dashboard-server/testResources/stalwart-gate0b"
local_project=mail-sandbox-stalwart-gate
local_dashboard_project=mail-sandbox-dashboard

unset COMPOSE_FILE COMPOSE_PROJECT_NAME COMPOSE_PROFILES COMPOSE_PROJECT_DIR
unset DOCKER_CONTEXT DOCKER_TLS_VERIFY DOCKER_CERT_PATH
export DOCKER_HOST=unix:///var/run/docker.sock
export COMPOSE_DISABLE_ENV_FILE=1

cd "$local_repository_root"
docker compose -p "$local_project" -f "$local_fixture_root/compose.yml" down
docker compose \
  -p "$local_dashboard_project" \
  -f "$local_repository_root/docker-compose.yml" \
  -f "$local_dashboard_root/docker-compose.local-providers.yml" \
  stop dovecot postfix oauth2-mock

if test "${1:-}" = '--reset-stalwart'; then
  cd "$local_dashboard_root"
  STALWART_GATE_CLEANUP=1 \
  "$local_dashboard_root/kotlin" test \
    --include-module dashboard-server \
    --include-classes \
    'mail.sandbox.dashboard.server.gate.stalwart.StalwartGateCleanupLiveTest'
fi
