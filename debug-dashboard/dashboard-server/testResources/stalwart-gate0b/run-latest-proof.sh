#!/bin/sh
set -eu

gate_script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
gate_repository_root=$(CDPATH= cd -- "$gate_script_directory/../../../.." && pwd -P)
gate_dashboard_root="$gate_repository_root/debug-dashboard"
gate_kotlin="$gate_dashboard_root/kotlin"
gate_base_compose="$gate_script_directory/compose.yml"
gate_recovery_compose="$gate_script_directory/compose.recovery.yml"
gate_runtime_root="$gate_dashboard_root/.runtime/stalwart-gate0b"
gate_recovery_env="$gate_runtime_root/recovery.env"
gate_fixture_secrets="$gate_runtime_root/fixture-secrets"
gate_credential_root="$gate_runtime_root/credential-store"
gate_project='mail-sandbox-stalwart-gate'
gate_base_url='http://127.0.0.1:18443'

cleanup_gate0b() {
  gate_incoming_status=$?
  gate_cleanup_status=0
  trap - EXIT INT TERM
  (
    cd "$gate_dashboard_root"
    STALWART_GATE_CLEANUP=1 \
    "$gate_kotlin" test \
      --include-module dashboard-server \
      --include-classes \
      'mail.sandbox.dashboard.server.gate.stalwart.StalwartGateCleanupLiveTest'
  ) || gate_cleanup_status=$?
  if test "$gate_incoming_status" -ne 0; then
    exit "$gate_incoming_status"
  fi
  exit "$gate_cleanup_status"
}

trap cleanup_gate0b EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

rg -F -q '127.0.0.1:18443:8080' "$gate_base_compose"
rg -F -q '127.0.0.1:18587:8587' "$gate_base_compose"

cd "$gate_dashboard_root"
STALWART_GATE_PREPARE=1 \
"$gate_kotlin" test \
  --include-module dashboard-server \
  --include-classes \
  'mail.sandbox.dashboard.server.gate.stalwart.StalwartFixturePrepareLiveTest'

cd "$gate_repository_root"
STALWART_GATE_RECOVERY_ENV_FILE="$gate_recovery_env" \
docker compose -p "$gate_project" \
  -f "$gate_base_compose" \
  -f "$gate_recovery_compose" \
  config --no-env-resolution --quiet
STALWART_GATE_RECOVERY_ENV_FILE="$gate_recovery_env" \
docker compose -p "$gate_project" \
  -f "$gate_base_compose" \
  -f "$gate_recovery_compose" \
  up -d --wait

cd "$gate_dashboard_root"
STALWART_LIVE_TESTS=1 \
STALWART_BASE_URL="$gate_base_url" \
STALWART_GATE_FIXTURE_SECRETS_FILE="$gate_fixture_secrets" \
"$gate_kotlin" test \
  --include-module dashboard-server \
  --include-classes \
  'mail.sandbox.dashboard.server.gate.stalwart.StalwartBootstrapLiveTest'

cd "$gate_repository_root"
docker compose -p "$gate_project" \
  -f "$gate_base_compose" \
  stop stalwart
docker compose -p "$gate_project" \
  -f "$gate_base_compose" \
  up -d --wait --force-recreate
gate_environment="$(docker compose -p "$gate_project" \
  -f "$gate_base_compose" \
  exec -T stalwart /usr/bin/env)"
if printf '%s\n' "$gate_environment" | rg -q '^STALWART_RECOVERY_'; then
  exit 1
fi

cd "$gate_dashboard_root"
STALWART_LIVE_TESTS=1 \
STALWART_BASE_URL="$gate_base_url" \
STALWART_GATE_FIXTURE_SECRETS_FILE="$gate_fixture_secrets" \
"$gate_kotlin" test \
  --include-module dashboard-server \
  --include-classes \
  'mail.sandbox.dashboard.server.gate.stalwart.StalwartRecoveryRetirementLiveTest'

STALWART_LIVE_TESTS=1 \
STALWART_BASE_URL="$gate_base_url" \
STALWART_GATE_FIXTURE_SECRETS_FILE="$gate_fixture_secrets" \
"$gate_kotlin" test \
  --include-module dashboard-server \
  --include-classes \
  'mail.sandbox.dashboard.server.gate.stalwart.StalwartRawBlobCompatibilityLiveTest'

STALWART_LIVE_TESTS=1 \
STALWART_BASE_URL="$gate_base_url" \
STALWART_GATE_FIXTURE_SECRETS_FILE="$gate_fixture_secrets" \
"$gate_kotlin" test \
  --include-module dashboard-server \
  --include-classes \
  'mail.sandbox.dashboard.server.gate.stalwart.StalwartPermissionMatrixLiveTest'

STALWART_LIVE_TESTS=1 \
STALWART_BASE_URL="$gate_base_url" \
STALWART_GATE_FIXTURE_SECRETS_FILE="$gate_fixture_secrets" \
"$gate_kotlin" test \
  --include-module dashboard-server \
  --include-classes \
  'mail.sandbox.dashboard.server.gate.stalwart.StalwartAppPasswordSemanticsLiveTest'

STALWART_LIVE_TESTS=1 \
STALWART_BASE_URL="$gate_base_url" \
STALWART_GATE_FIXTURE_SECRETS_FILE="$gate_fixture_secrets" \
STALWART_GATE_CREDENTIAL_ROOT="$gate_credential_root" \
"$gate_kotlin" test \
  --include-module dashboard-server \
  --include-classes \
  'mail.sandbox.dashboard.server.gate.stalwart.StalwartMailAccessLifecycleLiveTest'

STALWART_LIVE_TESTS=1 \
STALWART_BASE_URL="$gate_base_url" \
STALWART_GATE_FIXTURE_SECRETS_FILE="$gate_fixture_secrets" \
STALWART_GATE_CREDENTIAL_ROOT="$gate_credential_root" \
STALWART_GATE_RESTART_PHASE=staged \
"$gate_kotlin" test \
  --include-module dashboard-server \
  --include-classes \
  'mail.sandbox.dashboard.server.gate.stalwart.StalwartMailAccessRestartPrepareLiveTest'
STALWART_LIVE_TESTS=1 \
STALWART_BASE_URL="$gate_base_url" \
STALWART_GATE_FIXTURE_SECRETS_FILE="$gate_fixture_secrets" \
STALWART_GATE_CREDENTIAL_ROOT="$gate_credential_root" \
STALWART_GATE_RESTART_PHASE=staged \
"$gate_kotlin" test \
  --include-module dashboard-server \
  --include-classes \
  'mail.sandbox.dashboard.server.gate.stalwart.StalwartMailAccessRestartReconcileLiveTest'

STALWART_LIVE_TESTS=1 \
STALWART_BASE_URL="$gate_base_url" \
STALWART_GATE_FIXTURE_SECRETS_FILE="$gate_fixture_secrets" \
STALWART_GATE_CREDENTIAL_ROOT="$gate_credential_root" \
STALWART_GATE_RESTART_PHASE=retiring \
"$gate_kotlin" test \
  --include-module dashboard-server \
  --include-classes \
  'mail.sandbox.dashboard.server.gate.stalwart.StalwartMailAccessRestartPrepareLiveTest'
STALWART_LIVE_TESTS=1 \
STALWART_BASE_URL="$gate_base_url" \
STALWART_GATE_FIXTURE_SECRETS_FILE="$gate_fixture_secrets" \
STALWART_GATE_CREDENTIAL_ROOT="$gate_credential_root" \
STALWART_GATE_RESTART_PHASE=retiring \
"$gate_kotlin" test \
  --include-module dashboard-server \
  --include-classes \
  'mail.sandbox.dashboard.server.gate.stalwart.StalwartMailAccessRestartReconcileLiveTest'

STALWART_LIVE_TESTS=1 \
STALWART_BASE_URL="$gate_base_url" \
STALWART_GATE_FIXTURE_SECRETS_FILE="$gate_fixture_secrets" \
STALWART_GATE_CREDENTIAL_ROOT="$gate_credential_root" \
STALWART_GATE_RESTART_PHASE=removal-pending \
"$gate_kotlin" test \
  --include-module dashboard-server \
  --include-classes \
  'mail.sandbox.dashboard.server.gate.stalwart.StalwartMailAccessRestartPrepareLiveTest'
STALWART_LIVE_TESTS=1 \
STALWART_BASE_URL="$gate_base_url" \
STALWART_GATE_FIXTURE_SECRETS_FILE="$gate_fixture_secrets" \
STALWART_GATE_CREDENTIAL_ROOT="$gate_credential_root" \
STALWART_GATE_RESTART_PHASE=removal-pending \
"$gate_kotlin" test \
  --include-module dashboard-server \
  --include-classes \
  'mail.sandbox.dashboard.server.gate.stalwart.StalwartMailAccessRestartReconcileLiveTest'

STALWART_LIVE_TESTS=1 \
STALWART_BASE_URL="$gate_base_url" \
STALWART_GATE_FIXTURE_SECRETS_FILE="$gate_fixture_secrets" \
"$gate_kotlin" test \
  --include-module dashboard-server \
  --include-classes \
  'mail.sandbox.dashboard.server.gate.stalwart.StalwartMailMutationLiveTest'

STALWART_LIVE_TESTS=1 \
STALWART_BASE_URL="$gate_base_url" \
STALWART_GATE_FIXTURE_SECRETS_FILE="$gate_fixture_secrets" \
"$gate_kotlin" test \
  --include-module dashboard-server \
  --include-classes \
  'mail.sandbox.dashboard.server.gate.stalwart.StalwartRegistryRoutingDeletionLiveTest'
