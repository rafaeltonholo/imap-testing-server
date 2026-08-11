#!/bin/sh
set -eu

acceptance_dashboard_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
acceptance_repository_root=$(CDPATH= cd -- "$acceptance_dashboard_root/.." && pwd -P)
acceptance_compose_file="$acceptance_repository_root/docker-compose.yml"
acceptance_runtime_root="$acceptance_dashboard_root/.runtime/acceptance"

if test "$#" -ne 0; then
  printf '%s\n' 'Usage: DASHBOARD_SINGLE_STACK_LIVE_TESTS=1 ./debug-dashboard/run-live-acceptance.sh' >&2
  exit 2
fi
if test "${DASHBOARD_SINGLE_STACK_LIVE_TESTS-}" != 1; then
  printf '%s\n' 'DASHBOARD_SINGLE_STACK_LIVE_TESTS=1 is required for live acceptance' >&2
  exit 2
fi

acceptance_git_top=$(git -C "$acceptance_repository_root" rev-parse --show-toplevel) || exit 1
acceptance_git_common=$(git -C "$acceptance_repository_root" rev-parse --git-common-dir) || exit 1
case "$acceptance_git_common" in
  /*) acceptance_git_common_absolute=$acceptance_git_common ;;
  *) acceptance_git_common_absolute="$acceptance_repository_root/$acceptance_git_common" ;;
esac
acceptance_git_common_absolute=$(CDPATH= cd -- "$acceptance_git_common_absolute" && pwd -P) || exit 1
if test "$acceptance_git_top" != "$acceptance_repository_root" ||
  test "$acceptance_git_common_absolute" != "$acceptance_repository_root/.git" ||
  test ! -d "$acceptance_repository_root/.git" ||
  test -L "$acceptance_repository_root/.git"; then
  printf '%s\n' 'Live acceptance must run from the primary checkout' >&2
  exit 1
fi

unset COMPOSE_FILE COMPOSE_PROJECT_NAME COMPOSE_PROFILES COMPOSE_PROJECT_DIR
unset DOCKER_CONTEXT DOCKER_TLS_VERIFY DOCKER_CERT_PATH
export COMPOSE_DISABLE_ENV_FILE=1
export DOCKER_HOST=unix:///var/run/docker.sock

acceptance_services=$(docker compose -f "$acceptance_compose_file" ps --status running --services) || exit 1
for acceptance_service in oauth2-mock dovecot postfix stalwart; do
  if ! printf '%s\n' "$acceptance_services" | grep -Fx "$acceptance_service" >/dev/null; then
    printf '%s\n' "Root Compose service is not running: $acceptance_service" >&2
    exit 1
  fi
done

acceptance_stalwart_state=$(
  python3 "$acceptance_repository_root/scripts/stalwart_runtime_state.py" classify \
    --repository "$acceptance_repository_root"
) || exit 1
if test "$acceptance_stalwart_state" != current; then
  printf '%s\n' 'Stalwart must have a validated current runtime receipt' >&2
  exit 1
fi
python3 "$acceptance_repository_root/scripts/capture_stalwart_v015.py" verify \
  --receipt "$acceptance_dashboard_root/.runtime/stalwart-migration/latest-source.json" || exit 1

acceptance_random=$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n')
case "$acceptance_random" in
  ???????*) ;;
  *) printf '%s\n' 'Could not generate a unique acceptance suffix' >&2; exit 1 ;;
esac
acceptance_prefix="dashboard-acceptance-$(date +%s)-$acceptance_random"
acceptance_run_root="$acceptance_runtime_root/$acceptance_prefix"
acceptance_snapshot="$acceptance_run_root/baseline.json"
mkdir -p "$acceptance_run_root"
chmod 0700 "$acceptance_runtime_root" "$acceptance_run_root"

export DASHBOARD_SINGLE_STACK_RUN_PREFIX="$acceptance_prefix"
export DASHBOARD_SINGLE_STACK_SNAPSHOT="$acceptance_snapshot"
export DASHBOARD_SINGLE_STACK_DOVECOT_IMAP_ENDPOINT=127.0.0.1:1143
export DASHBOARD_SINGLE_STACK_DOVECOT_POP3_ENDPOINT=127.0.0.1:1110
export DASHBOARD_SINGLE_STACK_POSTFIX_DELIVERY_ENDPOINT=127.0.0.1:1025
export DASHBOARD_SINGLE_STACK_POSTFIX_SUBMISSION_ENDPOINT=127.0.0.1:1587
export DASHBOARD_SINGLE_STACK_OAUTH2_ENDPOINT=http://127.0.0.1:8080
export DASHBOARD_SINGLE_STACK_STALWART_JMAP_ENDPOINT=http://127.0.0.1:8443
export DASHBOARD_SINGLE_STACK_STALWART_SMTP_ENDPOINT=127.0.0.1:8587
export DASHBOARD_STALWART_RUNTIME_STATE=CURRENT

acceptance_preservation_required=1
acceptance_finalize() {
  acceptance_status=$?
  trap - 0 1 2 15
  if test "$acceptance_preservation_required" -eq 1; then
    export DASHBOARD_SINGLE_STACK_PRESERVATION_MODE=compare
    if ! "$acceptance_dashboard_root/kotlin" test \
      --include-module dashboard-server \
      --include-classes 'mail.sandbox.dashboard.server.acceptance.SingleStackPreservationTest'; then
      acceptance_status=1
    fi
  fi
  exit "$acceptance_status"
}
trap acceptance_finalize 0
trap 'exit 129' 1
trap 'exit 130' 2
trap 'exit 143' 15

cd "$acceptance_dashboard_root"
export DASHBOARD_SINGLE_STACK_PRESERVATION_MODE=capture
./kotlin test \
  --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.acceptance.SingleStackPreservationTest'

unset DASHBOARD_SINGLE_STACK_PRESERVATION_MODE
./kotlin test \
  --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.acceptance.SingleStackUsabilityLiveTest'
