#!/bin/sh
set -u

dashboard_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
dashboard_repository_root=$(CDPATH= cd -- "$dashboard_root/.." && pwd -P)
dashboard_kotlin="$dashboard_root/kotlin"
dashboard_stalwart_status="$dashboard_root/stalwart-status.sh"
dashboard_runtime_root="$dashboard_root/.runtime"
dashboard_pid_file="$dashboard_runtime_root/dashboard-server.pid"
dashboard_compose_file="$dashboard_repository_root/docker-compose.yml"
dashboard_users_script="$dashboard_repository_root/scripts/users_file.py"
dashboard_stalwart_bootstrap="$dashboard_repository_root/scripts/bootstrap_stalwart_v016.py"
dashboard_stalwart_runtime_state=UNAVAILABLE

unset COMPOSE_FILE COMPOSE_PROJECT_NAME COMPOSE_PROFILES COMPOSE_PROJECT_DIR
unset DOCKER_CONTEXT DOCKER_TLS_VERIFY DOCKER_CERT_PATH
export DOCKER_HOST=unix:///var/run/docker.sock
export COMPOSE_DISABLE_ENV_FILE=1

dashboard_wait_for_dovecot() {
  dashboard_attempt=1
  while test "$dashboard_attempt" -le 30; do
    if python3 "$dashboard_users_script" verify; then
      return 0
    fi
    dashboard_attempt=$((dashboard_attempt + 1))
    sleep 1
  done
  return 1
}

dashboard_wait_for_stalwart() {
  dashboard_attempt=1
  while test "$dashboard_attempt" -le 30; do
    if curl -fsS --max-time 1 http://127.0.0.1:8443/healthz/ready >/dev/null; then
      return 0
    fi
    dashboard_attempt=$((dashboard_attempt + 1))
    sleep 1
  done
  return 1
}

dashboard_start_current_stalwart() {
  if ! docker compose -f "$dashboard_compose_file" up -d stalwart; then
    return 1
  fi
  dashboard_wait_for_stalwart
}

mkdir -p "$dashboard_runtime_root"
chmod 0700 "$dashboard_runtime_root"

if test -f "$dashboard_pid_file" && test ! -L "$dashboard_pid_file"; then
  dashboard_existing_pid=$(sed -n 's/^pid=//p' "$dashboard_pid_file")
  case "$dashboard_existing_pid" in
    ''|*[!0-9]*) ;;
    *)
      if kill -0 "$dashboard_existing_pid" 2>/dev/null; then
        printf '%s\n' "Dashboard already running with PID $dashboard_existing_pid" >&2
        exit 1
      fi
      ;;
  esac
  rm -f "$dashboard_pid_file"
elif test -e "$dashboard_pid_file" || test -L "$dashboard_pid_file"; then
  printf '%s\n' 'Dashboard PID path is invalid' >&2
  exit 1
fi

dashboard_tls_ready=1
if test ! -f "$dashboard_repository_root/ssl/tls.crt" ||
  test ! -f "$dashboard_repository_root/ssl/tls.key"; then
  if ! python3 "$dashboard_repository_root/scripts/setup.py"; then
    dashboard_tls_ready=0
    printf '%s\n' 'Dovecot TLS setup failed; continuing with Stalwart diagnostics' >&2
  fi
fi

dashboard_users_ready=1
if ! python3 "$dashboard_users_script" bootstrap-defaults \
  --defer-provider-verification --lifecycle dashboard-start-local; then
  dashboard_users_ready=0
  printf '%s\n' 'Dovecot users bootstrap failed; continuing in degraded mode' >&2
fi

if dashboard_classified_stalwart_state=$(
  "$dashboard_stalwart_status" --machine 2>/dev/null
); then
  :
else
  dashboard_classified_stalwart_state=unavailable
fi

if test "$dashboard_tls_ready" -eq 1 && test "$dashboard_users_ready" -eq 1; then
  if docker compose -f "$dashboard_compose_file" up -d oauth2-mock dovecot postfix; then
    if ! dashboard_wait_for_dovecot; then
      printf '%s\n' 'Dovecot verification failed; continuing in degraded mode' >&2
    fi
  else
    printf '%s\n' 'Dovecot/Postfix/OAuth startup failed; continuing in degraded mode' >&2
  fi
fi

case "$dashboard_classified_stalwart_state" in
  current)
    if dashboard_start_current_stalwart; then
      dashboard_stalwart_runtime_state=CURRENT
    else
      dashboard_stalwart_runtime_state=UNAVAILABLE
      printf '%s\n' 'Stalwart startup or readiness failed; continuing in degraded mode' >&2
    fi
    ;;
  fresh)
    if python3 "$dashboard_stalwart_bootstrap" initialize-fresh \
      --repository "$dashboard_repository_root"; then
      if dashboard_post_initialization_state=$(
        "$dashboard_stalwart_status" --machine 2>/dev/null
      ) && test "$dashboard_post_initialization_state" = current; then
        if dashboard_start_current_stalwart; then
          dashboard_stalwart_runtime_state=CURRENT
        else
          dashboard_stalwart_runtime_state=UNAVAILABLE
          printf '%s\n' \
            'Stalwart startup or readiness failed; continuing in degraded mode' >&2
        fi
      else
        dashboard_stalwart_runtime_state=INITIALIZATION_FAILED
        printf '%s\n' \
          'Stalwart initialization did not publish a current receipt; continuing degraded' >&2
      fi
    else
      dashboard_stalwart_runtime_state=INITIALIZATION_FAILED
      printf '%s\n' 'Stalwart initialization failed; continuing in degraded mode' >&2
    fi
    ;;
  migration-required)
    dashboard_stalwart_runtime_state=MIGRATION_REQUIRED
    printf '%s\n' \
      'Stalwart upgrade required.' \
      'Follow docs/stalwart-v016-migration.md; migration requires explicit authorization.' \
      'Capture command (do not run without authorization):' \
      'python3 scripts/capture_stalwart_v015.py capture --source-service stalwart' >&2
    ;;
  invalid)
    dashboard_stalwart_runtime_state=INVALID
    printf '%s\n' \
      'Stalwart runtime state is invalid; run ./debug-dashboard/stalwart-status.sh' >&2
    ;;
  *)
    dashboard_stalwart_runtime_state=UNAVAILABLE
    printf '%s\n' 'Stalwart state classification failed; continuing in degraded mode' >&2
    ;;
esac

export DASHBOARD_STALWART_RUNTIME_STATE="$dashboard_stalwart_runtime_state"

cd "$dashboard_root"
if ! "$dashboard_kotlin" build --module dashboard-web; then
  printf '%s\n' 'Dashboard web build failed' >&2
  exit 1
fi

export DASHBOARD_WEB_ASSETS="$dashboard_root/build/tasks/_dashboard-web_linkWasmJs"
export DASHBOARD_WEB_RESOURCES="$dashboard_root/build/artifacts/PreparedComposeResourcesDirArtifact/dashboard-webcommon"
export DASHBOARD_WEB_ENTRY=dashboard-web.mjs

dashboard_started=$(ps -p "$$" -o lstart= | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
if test -z "$dashboard_started"; then
  printf '%s\n' 'Could not record dashboard process identity' >&2
  exit 1
fi
dashboard_pid_temporary="$dashboard_pid_file.tmp.$$"
umask 077
{
  printf 'pid=%s\n' "$$"
  printf 'started=%s\n' "$dashboard_started"
  printf 'repository=%s\n' "$dashboard_repository_root"
} > "$dashboard_pid_temporary"
mv "$dashboard_pid_temporary" "$dashboard_pid_file"

dashboard_remove_own_pid() {
  if test -f "$dashboard_pid_file" &&
    test "$(sed -n 's/^pid=//p' "$dashboard_pid_file")" = "$$"; then
    rm -f "$dashboard_pid_file"
  fi
}
trap dashboard_remove_own_pid 0 1 2 15

printf '%s\n' 'Mail Flight Recorder: http://127.0.0.1:50734'
exec "$dashboard_kotlin" run \
  --module dashboard-server \
  --working-dir="$dashboard_repository_root"
