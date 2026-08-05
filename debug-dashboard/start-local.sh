#!/bin/sh
set -eu

dashboard_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
dashboard_repository_root=$(CDPATH= cd -- "$dashboard_root/.." && pwd -P)
dashboard_kotlin="$dashboard_root/kotlin"
dashboard_compose_project=mail-sandbox-dashboard
dashboard_provider_root="$dashboard_root/.runtime/local-providers"
dashboard_dovecot_runtime="$dashboard_provider_root/dovecot"
dashboard_provider_vmail="$dashboard_provider_root/vmail"
dashboard_provider_logs="$dashboard_provider_root/logs"

unset COMPOSE_FILE COMPOSE_PROJECT_NAME COMPOSE_PROFILES COMPOSE_PROJECT_DIR
unset DOCKER_CONTEXT DOCKER_TLS_VERIFY DOCKER_CERT_PATH
export DOCKER_HOST=unix:///var/run/docker.sock
export COMPOSE_DISABLE_ENV_FILE=1

if test ! -f "$dashboard_repository_root/ssl/tls.crt" ||
  test ! -f "$dashboard_repository_root/ssl/tls.key"; then
  python3 "$dashboard_repository_root/scripts/setup.py"
fi

# Keep the dashboard's disposable accounts and mail separate from the normal sandbox.
mkdir -p \
  "$dashboard_dovecot_runtime" \
  "$dashboard_provider_vmail" \
  "$dashboard_provider_logs"
chmod 0700 "$dashboard_provider_root"
chmod 0700 "$dashboard_dovecot_runtime"
# The container's local vmail user (UID 1000) creates per-account Maildirs.
chmod 0777 "$dashboard_provider_vmail"

cd "$dashboard_repository_root"
docker compose \
  -p "$dashboard_compose_project" \
  -f "$dashboard_repository_root/docker-compose.yml" \
  -f "$dashboard_root/docker-compose.local-providers.yml" \
  up -d --wait dovecot postfix oauth2-mock
"$dashboard_root/start-local-stalwart.sh"

cd "$dashboard_root"
"$dashboard_kotlin" build --module dashboard-web

export DASHBOARD_WEB_ASSETS="$dashboard_root/build/tasks/_dashboard-web_linkWasmJs"
export DASHBOARD_WEB_RESOURCES="$dashboard_root/build/artifacts/PreparedComposeResourcesDirArtifact/dashboard-webcommon"
export DASHBOARD_WEB_ENTRY=dashboard-web.mjs
export DASHBOARD_STALWART_BASE_URL=http://127.0.0.1:18443
export DASHBOARD_STALWART_FIXTURE_SECRETS="$dashboard_root/.runtime/stalwart-gate0b/fixture-secrets"

printf '%s\n' 'Mail Flight Recorder: http://127.0.0.1:50734'
exec "$dashboard_kotlin" run \
  --module dashboard-server \
  --working-dir="$dashboard_repository_root"
