#!/bin/sh
set -eu

local_dashboard_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
local_repository_root=$(CDPATH= cd -- "$local_dashboard_root/.." && pwd -P)
local_kotlin="$local_dashboard_root/kotlin"
local_fixture_root="$local_dashboard_root/dashboard-server/testResources/stalwart-gate0b"
local_base_compose="$local_fixture_root/compose.yml"
local_recovery_compose="$local_fixture_root/compose.recovery.yml"
local_runtime_root="$local_dashboard_root/.runtime/stalwart-gate0b"
local_recovery_env="$local_runtime_root/recovery.env"
local_fixture_secrets="$local_runtime_root/fixture-secrets"
local_store_marker="$local_runtime_root/data/CURRENT"
local_ready_marker="$local_runtime_root/dashboard-ready"
local_project=mail-sandbox-stalwart-gate
local_base_url=http://127.0.0.1:18443

unset COMPOSE_FILE COMPOSE_PROJECT_NAME COMPOSE_PROFILES COMPOSE_PROJECT_DIR
unset DOCKER_CONTEXT DOCKER_TLS_VERIFY DOCKER_CERT_PATH
export DOCKER_HOST=unix:///var/run/docker.sock
export COMPOSE_DISABLE_ENV_FILE=1

if test -f "$local_fixture_secrets" &&
  test -f "$local_store_marker" &&
  test -f "$local_ready_marker"; then
  cd "$local_repository_root"
  docker compose -p "$local_project" -f "$local_base_compose" up -d --wait
  exit 0
fi

if test -f "$local_fixture_secrets" ||
  test -f "$local_ready_marker" ||
  { test -d "$local_runtime_root/data" &&
    find "$local_runtime_root/data" -mindepth 1 -maxdepth 1 -print -quit | grep -q .; }; then
  printf '%s\n' \
    'The dedicated dashboard Stalwart store is incomplete.' \
    'Run ./stop-local.sh --reset-stalwart, then retry.' >&2
  exit 1
fi

cd "$local_dashboard_root"
STALWART_GATE_PREPARE=1 \
"$local_kotlin" test \
  --include-module dashboard-server \
  --include-classes \
  'mail.sandbox.dashboard.server.gate.stalwart.StalwartFixturePrepareLiveTest'

cd "$local_repository_root"
STALWART_GATE_RECOVERY_ENV_FILE="$local_recovery_env" \
docker compose -p "$local_project" \
  -f "$local_base_compose" \
  -f "$local_recovery_compose" \
  up -d --wait

cd "$local_dashboard_root"
STALWART_LIVE_TESTS=1 \
STALWART_BASE_URL="$local_base_url" \
STALWART_GATE_FIXTURE_SECRETS_FILE="$local_fixture_secrets" \
"$local_kotlin" test \
  --include-module dashboard-server \
  --include-classes \
  'mail.sandbox.dashboard.server.gate.stalwart.StalwartBootstrapLiveTest'

cd "$local_repository_root"
docker compose -p "$local_project" -f "$local_base_compose" stop stalwart
docker compose -p "$local_project" \
  -f "$local_base_compose" \
  up -d --wait --force-recreate

cd "$local_dashboard_root"
STALWART_LIVE_TESTS=1 \
STALWART_BASE_URL="$local_base_url" \
STALWART_GATE_FIXTURE_SECRETS_FILE="$local_fixture_secrets" \
"$local_kotlin" test \
  --include-module dashboard-server \
  --include-classes \
  'mail.sandbox.dashboard.server.gate.stalwart.StalwartRecoveryRetirementLiveTest'

umask 077
: > "$local_ready_marker"

printf '%s\n' 'Dedicated Stalwart provider ready at http://127.0.0.1:18443'
