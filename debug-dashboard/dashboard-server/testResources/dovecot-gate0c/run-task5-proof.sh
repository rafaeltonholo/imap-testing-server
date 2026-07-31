#!/bin/bash -p

if [[ "$-" != *p* ]]; then
  printf '%s\n' \
    "Task 5 proof: invoke this lifecycle directly; privileged startup is required" \
    >&2
  /usr/bin/false
else
readonly TASK5_TRUSTED_PATH="/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin"

if [[ "$#" -ne 0 ]]; then
  printf '%s\n' "Task 5 proof: this fixed lifecycle accepts no arguments" >&2
  exit 2
fi

for TASK5_STARTUP_ENVIRONMENT_NAME in $(compgen -e); do
  case "$TASK5_STARTUP_ENVIRONMENT_NAME" in
    DOVECOT_* | COMPOSE_* | DOCKER_*)
      printf '%s\n' \
        "Task 5 proof: refusing ambient DOVECOT_, COMPOSE_, or DOCKER_ overrides" \
        >&2
      exit 2
      ;;
  esac
done
unset TASK5_STARTUP_ENVIRONMENT_NAME

if [[ "${TASK5_CLEAN_STAGE-}" != "1" ]]; then
  TASK5_STARTUP_TMPDIR="${TMPDIR:-/tmp}"
  if [[ -z "${HOME-}" ]] ||
    [[ "$HOME" != /* ]] ||
    [[ "$HOME" == *$'\n'* ]] ||
    [[ "$HOME" == *$'\r'* ]] ||
    [[ "$TASK5_STARTUP_TMPDIR" != /* ]] ||
    [[ "$TASK5_STARTUP_TMPDIR" == *$'\n'* ]] ||
    [[ "$TASK5_STARTUP_TMPDIR" == *$'\r'* ]]; then
    printf '%s\n' \
      "Task 5 proof: HOME and TMPDIR must be absolute single-line paths" \
      >&2
    exit 2
  fi

  exec /usr/bin/env -i \
    HOME="$HOME" \
    TMPDIR="$TASK5_STARTUP_TMPDIR" \
    PATH="$TASK5_TRUSTED_PATH" \
    TASK5_CLEAN_STAGE=1 \
    /bin/bash --noprofile --norc -p "$0"
fi

TASK5_CLEAN_ENVIRONMENT_VALID=1
while IFS= read -r -d '' TASK5_CLEAN_ENVIRONMENT_ENTRY; do
  TASK5_CLEAN_ENVIRONMENT_NAME="${TASK5_CLEAN_ENVIRONMENT_ENTRY%%=*}"
  case "$TASK5_CLEAN_ENVIRONMENT_NAME" in
    HOME | PATH | PWD | SHLVL | TASK5_CLEAN_STAGE | TMPDIR | _)
      ;;
    *)
      TASK5_CLEAN_ENVIRONMENT_VALID=0
      ;;
  esac
done < <(/usr/bin/env -0)

if [[ "$TASK5_CLEAN_ENVIRONMENT_VALID" -ne 1 ]] ||
  [[ "$PATH" != "$TASK5_TRUSTED_PATH" ]] ||
  [[ -z "${HOME-}" ]] ||
  [[ "$HOME" != /* ]] ||
  [[ "$HOME" == *$'\n'* ]] ||
  [[ "$HOME" == *$'\r'* ]] ||
  [[ -z "${TMPDIR-}" ]] ||
  [[ "$TMPDIR" != /* ]] ||
  [[ "$TMPDIR" == *$'\n'* ]] ||
  [[ "$TMPDIR" == *$'\r'* ]] ||
  [[ -n "$(trap -p DEBUG RETURN ERR)" ]] ||
  [[ -n "$(declare -F)" ]]; then
  printf '%s\n' "Task 5 proof: clean startup validation failed" >&2
  exit 2
fi
unset \
  TASK5_CLEAN_ENVIRONMENT_ENTRY \
  TASK5_CLEAN_ENVIRONMENT_NAME \
  TASK5_CLEAN_ENVIRONMENT_VALID \
  TASK5_CLEAN_STAGE \
  TASK5_STARTUP_TMPDIR

hash -r
trap - DEBUG RETURN ERR

set +x
set +a
set +E
set +T
set -euo pipefail

unset BASH_ENV CDPATH ENV GLOBIGNORE
unset TASK5_LIFECYCLE_LOCK_TOKEN TASK5_PROOF_ROOT_TOKEN token actual_token
TASK5_LIFECYCLE_LOCK_TOKEN=""
TASK5_PROOF_ROOT_TOKEN=""
export -n TASK5_LIFECYCLE_LOCK_TOKEN TASK5_PROOF_ROOT_TOKEN
export -n BASHOPTS
export -n SHELLOPTS

task5_error() {
  printf 'Task 5 proof: %s\n' "$1" >&2
}

if [[ "$#" -ne 0 ]]; then
  task5_error "this fixed lifecycle accepts no arguments"
  exit 2
fi

TASK5_SCRIPT_INPUT="$0"
if [[ -L "$TASK5_SCRIPT_INPUT" ]]; then
  task5_error "refusing a symbolic lifecycle script"
  exit 2
fi
if [[ "$(basename -- "$TASK5_SCRIPT_INPUT")" != "run-task5-proof.sh" ]]; then
  task5_error "unexpected lifecycle script name"
  exit 2
fi

TASK5_SCRIPT_LOGICAL_DIRECTORY="$(
  cd -- "$(dirname -- "$TASK5_SCRIPT_INPUT")"
  pwd -L
)"
TASK5_SCRIPT_DIRECTORY="$(
  cd -P -- "$(dirname -- "$TASK5_SCRIPT_INPUT")"
  pwd
)"
if [[ "$TASK5_SCRIPT_LOGICAL_DIRECTORY" != "$TASK5_SCRIPT_DIRECTORY" ]]; then
  task5_error "refusing a symbolic repository layout"
  exit 2
fi

TASK5_REPOSITORY_ROOT="$(
  cd -P -- "$TASK5_SCRIPT_DIRECTORY/../../../.."
  pwd
)"
TASK5_EXPECTED_SCRIPT_DIRECTORY="$TASK5_REPOSITORY_ROOT/debug-dashboard/dashboard-server/testResources/dovecot-gate0c"
TASK5_SCRIPT_PATH="$TASK5_SCRIPT_DIRECTORY/run-task5-proof.sh"
TASK5_DASHBOARD_ROOT="$TASK5_REPOSITORY_ROOT/debug-dashboard"
TASK5_KOTLIN="$TASK5_DASHBOARD_ROOT/kotlin"
TASK5_BASE_COMPOSE="$TASK5_REPOSITORY_ROOT/docker-compose.yml"
TASK5_PROOF_COMPOSE_RELATIVE="debug-dashboard/dashboard-server/testResources/dovecot-gate0c/compose.task5-proof.yml"
TASK5_PROOF_COMPOSE="$TASK5_REPOSITORY_ROOT/$TASK5_PROOF_COMPOSE_RELATIVE"
TASK5_NETWORK_ISOLATION_HELPER="$TASK5_SCRIPT_DIRECTORY/network-isolation-check.py"
TASK5_NETWORK_ISOLATION_TEST_RELATIVE="debug-dashboard/dashboard-server/testResources/dovecot-gate0c/test_network_isolation_check.py"
TASK5_NETWORK_ISOLATION_TEST="$TASK5_REPOSITORY_ROOT/$TASK5_NETWORK_ISOLATION_TEST_RELATIVE"
TASK5_RUNTIME_ROOT="$TASK5_DASHBOARD_ROOT/.runtime"
TASK5_PROOF_ROOT="$TASK5_RUNTIME_ROOT/task5-proof"
TASK5_PROOF_OWNER_MARKER="$TASK5_PROOF_ROOT/.task5-proof-owner"
readonly TASK5_EXEC_TRANSPORT_LIVE_CLASS="mail.sandbox.dashboard.server.gate.dovecot.DovecotOperatorExecTransportLiveTest"
readonly TASK5_LIFECYCLE_LOCK="/private/tmp/mail-sandbox-task5-proof.lifecycle.lock"
readonly TASK5_LIFECYCLE_LOCK_PARENT="${TASK5_LIFECYCLE_LOCK%/*}"
readonly TASK5_LIFECYCLE_LOCK_OWNER="$TASK5_LIFECYCLE_LOCK/owner"

task5_directory_is_exact_physical() {
  local directory="$1"
  local physical

  if [[ ! -d "$directory" ]] || [[ -L "$directory" ]]; then
    return 1
  fi
  if physical="$(
    trap '' INT TERM
    cd -P -- "$directory"
    pwd
  )"; then
    [[ "$physical" == "$directory" ]]
    return
  fi
  return 1
}

task5_proof_ancestors_are_safe() {
  task5_directory_is_exact_physical "$TASK5_REPOSITORY_ROOT" &&
    task5_directory_is_exact_physical "$TASK5_DASHBOARD_ROOT" &&
    task5_directory_is_exact_physical "$TASK5_RUNTIME_ROOT"
}

task5_proof_root_is_safe_for_deletion() {
  [[ "$TASK5_PROOF_ROOT" == "$TASK5_RUNTIME_ROOT/task5-proof" ]] &&
    [[ "$TASK5_RUNTIME_ROOT" == "$TASK5_REPOSITORY_ROOT/debug-dashboard/.runtime" ]] &&
    task5_proof_ancestors_are_safe &&
    task5_directory_is_exact_physical "$TASK5_PROOF_ROOT"
}

if [[ "$TASK5_SCRIPT_DIRECTORY" != "$TASK5_EXPECTED_SCRIPT_DIRECTORY" ]] ||
  [[ ! -f "$TASK5_SCRIPT_PATH" ]] ||
  [[ -L "$TASK5_SCRIPT_PATH" ]] ||
  [[ ! -f "$TASK5_DASHBOARD_ROOT/project.yaml" ]] ||
  [[ -L "$TASK5_DASHBOARD_ROOT/project.yaml" ]] ||
  [[ ! -f "$TASK5_KOTLIN" ]] ||
  [[ -L "$TASK5_KOTLIN" ]] ||
  [[ ! -x "$TASK5_KOTLIN" ]] ||
  [[ ! -f "$TASK5_BASE_COMPOSE" ]] ||
  [[ -L "$TASK5_BASE_COMPOSE" ]] ||
  [[ ! -f "$TASK5_PROOF_COMPOSE" ]] ||
  [[ -L "$TASK5_PROOF_COMPOSE" ]] ||
  [[ ! -f "$TASK5_NETWORK_ISOLATION_HELPER" ]] ||
  [[ -L "$TASK5_NETWORK_ISOLATION_HELPER" ]] ||
  [[ ! -f "$TASK5_NETWORK_ISOLATION_TEST" ]] ||
  [[ -L "$TASK5_NETWORK_ISOLATION_TEST" ]] ||
  ! task5_directory_is_exact_physical "$TASK5_SCRIPT_DIRECTORY" ||
  ! task5_proof_ancestors_are_safe; then
  task5_error "canonical non-symbolic repository layout validation failed"
  exit 2
fi

for TASK5_ENVIRONMENT_NAME in $(compgen -e); do
  case "$TASK5_ENVIRONMENT_NAME" in
    DOVECOT_* | COMPOSE_* | DOCKER_*)
      task5_error "refusing ambient DOVECOT_, COMPOSE_, or DOCKER_ overrides"
      exit 2
      ;;
  esac
done
unset TASK5_ENVIRONMENT_NAME

export DOCKER_HOST=unix:///var/run/docker.sock

TASK5_PROJECT_FILTER="label=com.docker.compose.project=mail-sandbox-task5-proof"
TASK5_FIXED_CONTAINER_NAMES=(
  mail-sandbox-task5-proof-dovecot-1
  mail-sandbox-task5-proof-dovecot-operator-1
  mail-sandbox-task5-proof-postfix-1
  mail-sandbox-task5-proof-oauth2-mock-1
)
TASK5_FIXED_NETWORK_NAMES=(
  mail-sandbox-task5-proof_default
  mail-sandbox-task5-proof_operator-ingress
)
TASK5_FIXED_VOLUME_NAMES=(
  mail-sandbox-task5-proof_task5-proof-vmail
  mail-sandbox-task5-proof_task5-proof-logs
)
TASK5_HEALTH_INSPECT_FORMAT='{{.Id}} {{.State.StartedAt}} {{.State.Status}} {{with (index .State "Health")}}{{.Status}}{{else}}none{{end}} {{.RestartCount}}'
TASK5_BASELINE_DIRECTORY=""
TASK5_BASELINE_DIRECTORY_CREATED=0
TASK5_BASELINE_READY=0
TASK5_LIFECYCLE_LOCK_CREATION_ATTEMPTED=0
TASK5_LIFECYCLE_LOCK_DIRECTORY_CREATED=0
TASK5_LIFECYCLE_LOCK_ACQUIRED=0
TASK5_LIFECYCLE_LOCK_IDENTITY=""
TASK5_LIFECYCLE_LOCK_MARKER_IDENTITY=""
TASK5_PROOF_ROOT_CREATION_ATTEMPTED=0
TASK5_PROOF_ROOT_DIRECTORY_CREATED=0
TASK5_PROOF_ROOT_OWNED=0
TASK5_PROOF_ROOT_IDENTITY=""
TASK5_PROOF_ROOT_MARKER_IDENTITY=""
TASK5_PROOF_ROOT_REMOVED=0
TASK5_PROOF_START_ATTEMPTED=0
TASK5_BOOTSTRAP_ADDED=0
TASK5_CLEANUP_STATUS=0
TASK5_PENDING_SIGNAL_STATUS=0
TASK5_SIGNAL_GENERATION=0
TASK5_SIGNAL_DEFER_DEPTH=0
TASK5_CLEANUP_IN_PROGRESS=0

task5_record_signal() {
  local signal_status="$1"

  TASK5_SIGNAL_GENERATION=$((TASK5_SIGNAL_GENERATION + 1))
  if [[ "$TASK5_PENDING_SIGNAL_STATUS" -eq 0 ]]; then
    TASK5_PENDING_SIGNAL_STATUS="$signal_status"
  fi
  if [[ "$TASK5_SIGNAL_DEFER_DEPTH" -eq 0 ]] &&
    [[ "$TASK5_CLEANUP_IN_PROGRESS" -eq 0 ]]; then
    exit "$TASK5_PENDING_SIGNAL_STATUS"
  fi
  return 0
}

task5_run_with_signal_deferral() {
  local operation_status

  TASK5_SIGNAL_DEFER_DEPTH=$((TASK5_SIGNAL_DEFER_DEPTH + 1))
  if "$@"; then
    operation_status=0
  else
    operation_status="$?"
  fi
  TASK5_SIGNAL_DEFER_DEPTH=$((TASK5_SIGNAL_DEFER_DEPTH - 1))

  if [[ "$operation_status" -ne 0 ]]; then
    return "$operation_status"
  fi
  if [[ "$TASK5_PENDING_SIGNAL_STATUS" -ne 0 ]] &&
    [[ "$TASK5_SIGNAL_DEFER_DEPTH" -eq 0 ]] &&
    [[ "$TASK5_CLEANUP_IN_PROGRESS" -eq 0 ]]; then
    exit "$TASK5_PENDING_SIGNAL_STATUS"
  fi
  return 0
}

task5_compose() {
  docker compose \
    --project-name mail-sandbox-task5-proof \
    --file docker-compose.yml \
    --file "$TASK5_PROOF_COMPOSE_RELATIVE" \
    "$@"
}

task5_path_identity() {
  trap '' INT TERM
  stat -f '%d:%i' "$1" 2>/dev/null
}

task5_path_mode() {
  trap '' INT TERM
  stat -f '%Lp' "$1" 2>/dev/null
}

task5_path_size() {
  trap '' INT TERM
  stat -f '%z' "$1" 2>/dev/null
}

task5_marker_matches() {
  local marker="$1"
  local token="$2"
  local expected_identity="$3"
  local actual_identity
  local actual_size
  local actual_token

  export -n token
  export -n actual_token
  if [[ -z "$token" ]] ||
    [[ -z "$expected_identity" ]] ||
    [[ ! -f "$marker" ]] ||
    [[ -L "$marker" ]] ||
    [[ "$(task5_path_mode "$marker")" != "600" ]]; then
    return 1
  fi
  if ! actual_identity="$(task5_path_identity "$marker")" ||
    [[ "$actual_identity" != "$expected_identity" ]]; then
    return 1
  fi
  if ! actual_size="$(task5_path_size "$marker")" ||
    [[ "$actual_size" != "$((${#token} + 1))" ]]; then
    return 1
  fi
  if ! IFS= read -r actual_token < "$marker" ||
    [[ "$actual_token" != "$token" ]]; then
    return 1
  fi
  return 0
}

task5_generate_ownership_token() {
  local token

  export -n token
  if ! token="$(
    trap '' INT TERM
    openssl rand -hex 24
  )" ||
    [[ "${#token}" -ne 48 ]] ||
    [[ "$token" == *[!0-9a-f]* ]]; then
    task5_error "could not generate a lifecycle ownership token"
    return 1
  fi
  printf '%s' "$token"
}

task5_generate_lifecycle_lock_token() {
  local token

  export -n token
  if ! token="$(
    trap '' INT TERM
    openssl rand -hex 32
  )" ||
    [[ "${#token}" -ne 64 ]] ||
    [[ "$token" == *[!0-9a-f]* ]]; then
    task5_error "could not generate a lifecycle lock token"
    return 1
  fi
  printf '%s' "$token"
}

task5_lifecycle_lock_is_owned() {
  local actual_identity

  if [[ "$TASK5_LIFECYCLE_LOCK_ACQUIRED" -ne 1 ]] ||
    ! task5_directory_is_exact_physical "$TASK5_LIFECYCLE_LOCK_PARENT" ||
    ! task5_directory_is_exact_physical "$TASK5_LIFECYCLE_LOCK" ||
    [[ "$(task5_path_mode "$TASK5_LIFECYCLE_LOCK")" != "700" ]]; then
    return 1
  fi
  if ! actual_identity="$(task5_path_identity "$TASK5_LIFECYCLE_LOCK")" ||
    [[ "$actual_identity" != "$TASK5_LIFECYCLE_LOCK_IDENTITY" ]]; then
    return 1
  fi
  task5_marker_matches \
    "$TASK5_LIFECYCLE_LOCK_OWNER" \
    "$TASK5_LIFECYCLE_LOCK_TOKEN" \
    "$TASK5_LIFECYCLE_LOCK_MARKER_IDENTITY"
}

task5_proof_root_is_owned() {
  local actual_identity

  if ! task5_lifecycle_lock_is_owned ||
    [[ "$TASK5_PROOF_ROOT_OWNED" -ne 1 ]] ||
    [[ "$TASK5_PROOF_ROOT" != "$TASK5_RUNTIME_ROOT/task5-proof" ]] ||
    ! task5_proof_root_is_safe_for_deletion ||
    [[ "$(task5_path_mode "$TASK5_PROOF_ROOT")" != "700" ]]; then
    return 1
  fi
  if ! actual_identity="$(task5_path_identity "$TASK5_PROOF_ROOT")" ||
    [[ "$actual_identity" != "$TASK5_PROOF_ROOT_IDENTITY" ]]; then
    return 1
  fi
  task5_marker_matches \
    "$TASK5_PROOF_OWNER_MARKER" \
    "$TASK5_PROOF_ROOT_TOKEN" \
    "$TASK5_PROOF_ROOT_MARKER_IDENTITY"
}

task5_require_lifecycle_lock_ownership() {
  if task5_lifecycle_lock_is_owned; then
    return 0
  fi
  task5_error "lifecycle lock ownership was lost before $1"
  return 1
}

task5_require_proof_root_ownership() {
  if task5_proof_root_is_owned; then
    return 0
  fi
  task5_error "proof-root ownership was lost before $1"
  return 1
}

task5_compose_with_lock() {
  task5_require_lifecycle_lock_ownership "Docker Compose $1" || return 1
  task5_compose "$@"
}

task5_acquire_lifecycle_lock_body() {
  local token
  local mkdir_status

  export -n token
  if ! task5_directory_is_exact_physical "$TASK5_LIFECYCLE_LOCK_PARENT"; then
    task5_error "daemon-global lifecycle lock parent is unsafe"
    return 1
  fi
  if ! token="$(task5_generate_lifecycle_lock_token)"; then
    return 1
  fi

  TASK5_LIFECYCLE_LOCK_CREATION_ATTEMPTED=1
  if (
    trap '' INT TERM
    umask 077
    mkdir -m 700 "$TASK5_LIFECYCLE_LOCK"
  ); then
    :
  else
    mkdir_status="$?"
    task5_error \
      "the daemon-global lifecycle lock is already held, stale, or unsafe"
    return "$mkdir_status"
  fi
  TASK5_LIFECYCLE_LOCK_DIRECTORY_CREATED=1

  if ! TASK5_LIFECYCLE_LOCK_IDENTITY="$(
    task5_path_identity "$TASK5_LIFECYCLE_LOCK"
  )" ||
    [[ -z "$TASK5_LIFECYCLE_LOCK_IDENTITY" ]] ||
    [[ "$(task5_path_mode "$TASK5_LIFECYCLE_LOCK")" != "700" ]]; then
    task5_error "created lifecycle lock identity is unsafe"
    return 1
  fi
  if ! (
    trap '' INT TERM
    umask 077
    set -o noclobber
    printf '%s\n' "$token" > "$TASK5_LIFECYCLE_LOCK_OWNER"
  ); then
    task5_error "could not publish exclusive lifecycle ownership"
    return 1
  fi
  if ! TASK5_LIFECYCLE_LOCK_MARKER_IDENTITY="$(
    task5_path_identity "$TASK5_LIFECYCLE_LOCK_OWNER"
  )" ||
    [[ -z "$TASK5_LIFECYCLE_LOCK_MARKER_IDENTITY" ]]; then
    task5_error "created lifecycle owner marker is unsafe"
    return 1
  fi

  TASK5_LIFECYCLE_LOCK_TOKEN="$token"
  TASK5_LIFECYCLE_LOCK_ACQUIRED=1
  if ! task5_lifecycle_lock_is_owned; then
    TASK5_LIFECYCLE_LOCK_ACQUIRED=0
    task5_error "lifecycle lock ownership validation failed"
    return 1
  fi
}

task5_acquire_lifecycle_lock() {
  task5_run_with_signal_deferral task5_acquire_lifecycle_lock_body
}

task5_create_owned_proof_root_body() {
  local token
  local mkdir_status

  export -n token
  task5_require_lifecycle_lock_ownership "proof-root creation" || return 1
  if ! task5_proof_ancestors_are_safe ||
    [[ -e "$TASK5_PROOF_ROOT" ]] ||
    [[ -L "$TASK5_PROOF_ROOT" ]]; then
    task5_error "the exact proof root must be absent with safe ancestors"
    return 1
  fi
  if ! token="$(task5_generate_ownership_token)"; then
    return 1
  fi

  task5_require_lifecycle_lock_ownership "exclusive proof-root mkdir" ||
    return 1
  TASK5_PROOF_ROOT_CREATION_ATTEMPTED=1
  if (
    trap '' INT TERM
    umask 077
    mkdir "$TASK5_PROOF_ROOT"
  ); then
    :
  else
    mkdir_status="$?"
    task5_error "exclusive proof-root creation failed"
    return "$mkdir_status"
  fi
  TASK5_PROOF_ROOT_DIRECTORY_CREATED=1

  if ! TASK5_PROOF_ROOT_IDENTITY="$(
    task5_path_identity "$TASK5_PROOF_ROOT"
  )" ||
    [[ -z "$TASK5_PROOF_ROOT_IDENTITY" ]] ||
    [[ "$(task5_path_mode "$TASK5_PROOF_ROOT")" != "700" ]]; then
    task5_error "created proof-root identity is unsafe"
    return 1
  fi
  task5_require_lifecycle_lock_ownership "proof-root owner publication" ||
    return 1
  if ! (
    trap '' INT TERM
    umask 077
    set -o noclobber
    printf '%s\n' "$token" > "$TASK5_PROOF_OWNER_MARKER"
  ); then
    task5_error "could not publish exclusive proof-root ownership"
    return 1
  fi
  if ! TASK5_PROOF_ROOT_MARKER_IDENTITY="$(
    task5_path_identity "$TASK5_PROOF_OWNER_MARKER"
  )" ||
    [[ -z "$TASK5_PROOF_ROOT_MARKER_IDENTITY" ]]; then
    task5_error "created proof-root owner marker is unsafe"
    return 1
  fi

  TASK5_PROOF_ROOT_TOKEN="$token"
  TASK5_PROOF_ROOT_OWNED=1
  task5_require_proof_root_ownership "proof-root child creation" || return 1
  (
    trap '' INT TERM
    umask 077
    mkdir \
      "$TASK5_PROOF_ROOT/dovecot" \
      "$TASK5_PROOF_ROOT/ssl"
  )
  task5_require_proof_root_ownership "proof-root child validation" ||
    return 1
  task5_require_mode "$TASK5_PROOF_ROOT/dovecot" 700 || return 1
  task5_require_mode "$TASK5_PROOF_ROOT/ssl" 700 || return 1
}

task5_create_owned_proof_root() {
  task5_run_with_signal_deferral task5_create_owned_proof_root_body
}

task5_lines_contain_exact_name() {
  local lines="$1"
  local exact_name="$2"
  local line

  while IFS= read -r line; do
    if [[ "$line" == "$exact_name" ]]; then
      return 0
    fi
  done <<< "$lines"
  return 1
}

task5_inventory_is_empty() {
  local description="$1"
  local containers="query-failed"
  local networks="query-failed"
  local volumes="query-failed"
  local container_names="query-failed"
  local network_names="query-failed"
  local volume_names="query-failed"
  local exact_name
  local queries_succeeded=1
  local exact_name_collision=0

  if containers="$(
    docker ps --all --quiet --filter "$TASK5_PROJECT_FILTER"
  )"; then
    :
  else
    queries_succeeded=0
  fi
  if networks="$(
    docker network ls --quiet --filter "$TASK5_PROJECT_FILTER"
  )"; then
    :
  else
    queries_succeeded=0
  fi
  if volumes="$(
    docker volume ls --quiet --filter "$TASK5_PROJECT_FILTER"
  )"; then
    :
  else
    queries_succeeded=0
  fi
  if container_names="$(
    docker ps --all --format '{{.Names}}'
  )"; then
    :
  else
    queries_succeeded=0
  fi
  if network_names="$(
    docker network ls --format '{{.Name}}'
  )"; then
    :
  else
    queries_succeeded=0
  fi
  if volume_names="$(
    docker volume ls --format '{{.Name}}'
  )"; then
    :
  else
    queries_succeeded=0
  fi

  for exact_name in "${TASK5_FIXED_CONTAINER_NAMES[@]}"; do
    if task5_lines_contain_exact_name "$container_names" "$exact_name"; then
      exact_name_collision=1
    fi
  done
  for exact_name in "${TASK5_FIXED_NETWORK_NAMES[@]}"; do
    if task5_lines_contain_exact_name "$network_names" "$exact_name"; then
      exact_name_collision=1
    fi
  done
  for exact_name in "${TASK5_FIXED_VOLUME_NAMES[@]}"; do
    if task5_lines_contain_exact_name "$volume_names" "$exact_name"; then
      exact_name_collision=1
    fi
  done

  if [[ "$queries_succeeded" -ne 1 ]] ||
    [[ -n "$containers" ]] ||
    [[ -n "$networks" ]] ||
    [[ -n "$volumes" ]] ||
    [[ "$exact_name_collision" -ne 0 ]]; then
    task5_error "$description resource inventory failed or was not empty"
    return 1
  fi
  return 0
}

task5_require_mode() {
  local path="$1"
  local expected="$2"
  local actual

  if actual="$(task5_path_mode "$path")" &&
    [[ "$actual" == "$expected" ]]; then
    return 0
  fi
  task5_error "unexpected permissions on fixed proof path"
  return 1
}

task5_record_cleanup_failure() {
  local description="$1"
  task5_error "cleanup failed: $description"
  if [[ "$TASK5_CLEANUP_STATUS" -eq 0 ]]; then
    TASK5_CLEANUP_STATUS=1
  fi
}

task5_allocate_baseline_directory_body() {
  local allocation_status
  local chmod_status

  if TASK5_BASELINE_DIRECTORY="$(
    trap '' INT TERM
    umask 077
    mktemp -d "${TMPDIR:-/tmp}/mail-sandbox-task5-baseline.XXXXXX"
  )"; then
    :
  else
    allocation_status="$?"
    task5_error "baseline directory allocation failed"
    return "$allocation_status"
  fi
  if [[ -z "$TASK5_BASELINE_DIRECTORY" ]]; then
    task5_error "baseline directory allocation returned an empty path"
    return 1
  fi
  TASK5_BASELINE_DIRECTORY_CREATED=1

  if (
    trap '' INT TERM
    chmod 700 "$TASK5_BASELINE_DIRECTORY"
  ); then
    :
  else
    chmod_status="$?"
    task5_error "baseline directory mode establishment failed"
    return "$chmod_status"
  fi
  task5_require_mode "$TASK5_BASELINE_DIRECTORY" 700
}

task5_allocate_baseline_directory() {
  task5_run_with_signal_deferral task5_allocate_baseline_directory_body
}

task5_remove_unready_baseline() {
  if [[ "$TASK5_BASELINE_DIRECTORY_CREATED" -ne 1 ]] ||
    [[ -z "$TASK5_BASELINE_DIRECTORY" ]]; then
    return
  fi

  if ! rm -f -- \
    "$TASK5_BASELINE_DIRECTORY/ids.unsorted" \
    "$TASK5_BASELINE_DIRECTORY/ids" \
    "$TASK5_BASELINE_DIRECTORY/before" \
    "$TASK5_BASELINE_DIRECTORY/after"; then
    task5_record_cleanup_failure \
      "could not remove incomplete baseline files"
    return
  fi
  if ! rmdir "$TASK5_BASELINE_DIRECTORY"; then
    task5_record_cleanup_failure "could not remove incomplete baseline directory"
  fi
}

task5_compare_baseline() {
  local after="$TASK5_BASELINE_DIRECTORY/after"
  local container_id
  local inspections_succeeded=1
  local comparison_succeeded=0

  if ! : > "$after"; then
    task5_record_cleanup_failure "could not create after-state baseline"
    return
  fi

  while IFS= read -r container_id; do
    if [[ -z "$container_id" ]]; then
      continue
    fi
    if docker inspect \
      --format "$TASK5_HEALTH_INSPECT_FORMAT" \
      "$container_id" >> "$after"; then
      :
    else
      inspections_succeeded=0
      task5_record_cleanup_failure "could not inspect a baseline container"
    fi
  done < "$TASK5_BASELINE_DIRECTORY/ids"

  if cmp "$TASK5_BASELINE_DIRECTORY/before" "$after"; then
    comparison_succeeded=1
  else
    task5_record_cleanup_failure "a pre-existing container changed"
  fi

  if [[ "$inspections_succeeded" -eq 1 ]] &&
    [[ "$comparison_succeeded" -eq 1 ]]; then
    printf '%s\n' "baseline-match"
    if ! rm -f -- \
      "$TASK5_BASELINE_DIRECTORY/ids.unsorted" \
      "$TASK5_BASELINE_DIRECTORY/ids" \
      "$TASK5_BASELINE_DIRECTORY/before" \
      "$after"; then
      task5_record_cleanup_failure \
        "could not remove matched baseline files"
      return
    fi
    if ! rmdir "$TASK5_BASELINE_DIRECTORY"; then
      task5_record_cleanup_failure "could not remove matched baseline directory"
    fi
  else
    task5_error "baseline evidence retained at $TASK5_BASELINE_DIRECTORY"
  fi
}

task5_lifecycle_lock_contains_only_owner_marker() (
  local entries

  shopt -s nullglob dotglob
  entries=("$TASK5_LIFECYCLE_LOCK"/*)
  [[ "${#entries[@]}" -eq 1 ]] &&
    [[ "${entries[0]}" == "$TASK5_LIFECYCLE_LOCK_OWNER" ]]
)

task5_release_lifecycle_lock() {
  if ! task5_lifecycle_lock_is_owned ||
    ! task5_lifecycle_lock_contains_only_owner_marker; then
    return 1
  fi
  if ! rm -f -- "$TASK5_LIFECYCLE_LOCK_OWNER" ||
    ! rmdir "$TASK5_LIFECYCLE_LOCK"; then
    return 1
  fi
  TASK5_LIFECYCLE_LOCK_ACQUIRED=0
  return 0
}

task5_cleanup() {
  local lock_is_current=0
  local resources_absent=0
  local root_disposition_complete=0

  TASK5_CLEANUP_STATUS=0

  if [[ "$TASK5_LIFECYCLE_LOCK_ACQUIRED" -ne 1 ]]; then
    if [[ "$TASK5_LIFECYCLE_LOCK_CREATION_ATTEMPTED" -eq 1 ]] &&
      {
        [[ "$TASK5_LIFECYCLE_LOCK_DIRECTORY_CREATED" -eq 1 ]] ||
          [[ -e "$TASK5_LIFECYCLE_LOCK" ]] ||
          [[ -L "$TASK5_LIFECYCLE_LOCK" ]]
      }; then
      task5_record_cleanup_failure \
        "partial lifecycle lock is retained without inferred ownership"
    fi
    task5_remove_unready_baseline
    return "$TASK5_CLEANUP_STATUS"
  fi

  if ! cd -- "$TASK5_REPOSITORY_ROOT"; then
    task5_record_cleanup_failure "could not enter the canonical repository"
  fi

  if task5_lifecycle_lock_is_owned; then
    lock_is_current=1
  else
    task5_record_cleanup_failure \
      "lifecycle lock ownership changed; cleanup mutations are forbidden"
  fi

  if [[ "$TASK5_BOOTSTRAP_ADDED" -eq 1 ]]; then
    if [[ "$lock_is_current" -eq 1 ]] &&
      task5_proof_root_is_owned; then
      if (
        cd -- "$TASK5_DASHBOARD_ROOT"
        "$TASK5_KOTLIN" run \
          --module dashboard-server \
          --main-class mail.sandbox.dashboard.server.gate.dovecot.EligibilityFileCli \
          -- task5-proof remove task5-bootstrap@local.test
      ); then
        :
      else
        task5_record_cleanup_failure "could not remove bootstrap eligibility"
      fi
    else
      task5_record_cleanup_failure \
        "refusing bootstrap removal without exact lock and proof-root ownership"
    fi
  fi

  if [[ "$TASK5_PROOF_START_ATTEMPTED" -eq 1 ]]; then
    if [[ "$lock_is_current" -ne 1 ]]; then
      task5_record_cleanup_failure \
        "refusing fixed project down without lifecycle lock ownership"
    elif task5_compose_with_lock down --volumes --remove-orphans; then
      :
    else
      task5_record_cleanup_failure "fixed project down failed"
    fi
  fi

  if task5_inventory_is_empty "cleanup"; then
    resources_absent=1
  else
    task5_record_cleanup_failure "fixed project resources remain or are unknown"
  fi

  if [[ "$TASK5_PROOF_ROOT_CREATION_ATTEMPTED" -eq 1 ]]; then
    if [[ "$TASK5_PROOF_ROOT_OWNED" -ne 1 ]]; then
      if [[ "$TASK5_PROOF_ROOT_DIRECTORY_CREATED" -eq 1 ]]; then
        task5_record_cleanup_failure \
          "partial proof root is retained without inferred ownership"
      else
        task5_record_cleanup_failure \
          "proof-root ownership was never established; foreign path retained"
      fi
    elif [[ "$resources_absent" -ne 1 ]]; then
      task5_record_cleanup_failure \
        "refusing proof-root deletion without absent resources"
    elif task5_proof_root_is_owned; then
      if rm -rf -- "$TASK5_PROOF_ROOT" &&
        [[ ! -e "$TASK5_PROOF_ROOT" ]] &&
        [[ ! -L "$TASK5_PROOF_ROOT" ]]; then
        TASK5_PROOF_ROOT_REMOVED=1
        root_disposition_complete=1
      else
        task5_record_cleanup_failure "could not remove the exact proof root"
      fi
    else
      task5_record_cleanup_failure \
        "owned proof root disappeared or changed; path retained"
    fi
  elif [[ ! -e "$TASK5_PROOF_ROOT" ]] &&
    [[ ! -L "$TASK5_PROOF_ROOT" ]]; then
    root_disposition_complete=1
  else
    task5_record_cleanup_failure \
      "an unowned proof root appeared before lifecycle creation"
  fi

  if [[ "$TASK5_BASELINE_READY" -eq 1 ]]; then
    task5_compare_baseline
  else
    task5_remove_unready_baseline
  fi

  if [[ "$TASK5_CLEANUP_STATUS" -eq 0 ]] &&
    [[ "$resources_absent" -eq 1 ]] &&
    [[ "$root_disposition_complete" -eq 1 ]] &&
    [[ "$TASK5_PROOF_ROOT_REMOVED" -eq "$TASK5_PROOF_ROOT_CREATION_ATTEMPTED" ]]; then
    if ! task5_release_lifecycle_lock; then
      task5_record_cleanup_failure \
        "exact lifecycle lock release failed; evidence retained"
    fi
  fi

  return "$TASK5_CLEANUP_STATUS"
}

task5_on_exit() {
  TASK5_CLEANUP_IN_PROGRESS=1
  TASK5_SIGNAL_DEFER_DEPTH=$((TASK5_SIGNAL_DEFER_DEPTH + 1))
  local primary_status="$1"
  local cleanup_status
  local cleanup_pid
  local cleanup_isolation_failed=0
  local wait_generation

  trap - EXIT
  trap 'task5_record_signal 130' INT
  trap 'task5_record_signal 143' TERM
  set +e

  if set -m; then
    (
      trap - EXIT
      set +m
      trap '' INT TERM
      task5_cleanup
    ) </dev/null &
    cleanup_pid="$!"
    if ! set +m; then
      cleanup_isolation_failed=1
      task5_error \
        "cleanup failed: could not disable parent job-control monitoring"
    fi

    while :; do
      wait_generation="$TASK5_SIGNAL_GENERATION"
      wait "$cleanup_pid"
      cleanup_status="$?"
      if [[ "$TASK5_SIGNAL_GENERATION" -ne "$wait_generation" ]] &&
        {
          [[ "$cleanup_status" -eq 130 ]] ||
            [[ "$cleanup_status" -eq 143 ]]
        }; then
        continue
      fi
      break
    done
    if [[ "$cleanup_isolation_failed" -ne 0 ]]; then
      cleanup_status=1
    fi
  else
    task5_error \
      "cleanup failed: could not enable cleanup process-group isolation"
    (
      trap - EXIT
      trap '' INT TERM
      task5_cleanup
    ) </dev/null
    cleanup_status=1
  fi

  if [[ "$primary_status" -ne 0 ]]; then
    if [[ "$TASK5_PENDING_SIGNAL_STATUS" -ne 0 ]] &&
      [[ "$TASK5_PENDING_SIGNAL_STATUS" -ne "$primary_status" ]]; then
      task5_error \
        "primary failure $primary_status preserved; deferred signal $TASK5_PENDING_SIGNAL_STATUS observed during mandatory cleanup"
    fi
    if [[ "$cleanup_status" -ne 0 ]]; then
      task5_error "primary failure $primary_status preserved; cleanup also failed"
    fi
    exit "$primary_status"
  fi
  if [[ "$TASK5_PENDING_SIGNAL_STATUS" -ne 0 ]]; then
    if [[ "$cleanup_status" -ne 0 ]]; then
      task5_error \
        "deferred signal $TASK5_PENDING_SIGNAL_STATUS preserved; cleanup also failed"
    fi
    exit "$TASK5_PENDING_SIGNAL_STATUS"
  fi
  if [[ "$cleanup_status" -ne 0 ]]; then
    exit "$cleanup_status"
  fi
  exit 0
}

trap 'task5_on_exit $?' EXIT
trap 'task5_record_signal 130' INT
trap 'task5_record_signal 143' TERM

cd -- "$TASK5_REPOSITORY_ROOT"

task5_acquire_lifecycle_lock
task5_inventory_is_empty "initial"

task5_allocate_baseline_directory

if docker ps --quiet > "$TASK5_BASELINE_DIRECTORY/ids.unsorted"; then
  :
else
  task5_error "baseline container list failed"
  false
fi
LC_ALL=C sort \
  "$TASK5_BASELINE_DIRECTORY/ids.unsorted" \
  > "$TASK5_BASELINE_DIRECTORY/ids"
: > "$TASK5_BASELINE_DIRECTORY/before"
while IFS= read -r TASK5_CONTAINER_ID; do
  if [[ -z "$TASK5_CONTAINER_ID" ]]; then
    continue
  fi
  if docker inspect \
    --format "$TASK5_HEALTH_INSPECT_FORMAT" \
    "$TASK5_CONTAINER_ID" >> "$TASK5_BASELINE_DIRECTORY/before"; then
    :
  else
    task5_error "baseline container inspection failed"
    false
  fi
done < "$TASK5_BASELINE_DIRECTORY/ids"
unset TASK5_CONTAINER_ID
TASK5_BASELINE_READY=1

for TASK5_PROOF_PORT in 1993 21995 2993 21025 28080; do
  if lsof -nP -iTCP:"$TASK5_PROOF_PORT" -sTCP:LISTEN >/dev/null 2>&1; then
    task5_error "port $TASK5_PROOF_PORT is occupied; nothing will be stopped"
    false
  else
    TASK5_LSOF_STATUS="$?"
    if [[ "$TASK5_LSOF_STATUS" -ne 1 ]]; then
      task5_error "port $TASK5_PROOF_PORT could not be queried"
      false
    fi
  fi
done
unset TASK5_PROOF_PORT TASK5_LSOF_STATUS

task5_require_lifecycle_lock_ownership "non-live configuration checks"
(
  cd -- "$TASK5_DASHBOARD_ROOT"
  task5_require_lifecycle_lock_ownership "non-live Kotlin checks"
  "$TASK5_KOTLIN" test \
    --include-module dashboard-server \
    --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotOperatorConfigTest \
    --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotOperatorCredentialStoreTest \
    --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotOperatorProcessTransportTest \
    --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotOperatorApplicationLeaseRegistryTest \
    --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotOperatorBoundedExchangeTest \
    --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotTask6TopologyProofTest \
    --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotTask6OperatorProcessInventoryTest \
    --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotTask6ProcessProofTest \
    --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotOperatorExecTransportLiveTest \
    --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotTask5ProofLifecycleTest
)
task5_require_lifecycle_lock_ownership "network isolation Python checks"
python3 -m unittest "$TASK5_NETWORK_ISOLATION_TEST_RELATIVE"
task5_require_lifecycle_lock_ownership "base Compose config"
COMPOSE_DISABLE_ENV_FILE=1 docker compose --file docker-compose.yml config --quiet
task5_require_lifecycle_lock_ownership "proof Compose config"
COMPOSE_DISABLE_ENV_FILE=1 task5_compose config --quiet

export DOVECOT_LIVE_TESTS=1
export DOVECOT_LIVE_PROFILE=task5-proof
export COMPOSE_PROJECT_NAME=mail-sandbox-task5-proof
export COMPOSE_FILE="docker-compose.yml:$TASK5_PROOF_COMPOSE_RELATIVE"
export COMPOSE_DISABLE_ENV_FILE=1

task5_create_owned_proof_root

task5_require_proof_root_ownership "TLS material creation"
(
  umask 077
  openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 1 \
    -subj /CN=localhost \
    -addext subjectAltName=DNS:localhost \
    -keyout "$TASK5_PROOF_ROOT/ssl/tls.key" \
    -out "$TASK5_PROOF_ROOT/ssl/tls.crt"
)
task5_require_proof_root_ownership "TLS material permission update"
chmod 600 \
  "$TASK5_PROOF_ROOT/ssl/tls.crt" \
  "$TASK5_PROOF_ROOT/ssl/tls.key"
if [[ ! -f "$TASK5_PROOF_ROOT/ssl/tls.crt" ]] ||
  [[ -L "$TASK5_PROOF_ROOT/ssl/tls.crt" ]] ||
  [[ ! -f "$TASK5_PROOF_ROOT/ssl/tls.key" ]] ||
  [[ -L "$TASK5_PROOF_ROOT/ssl/tls.key" ]]; then
  task5_error "TLS material is not fixed regular-file input"
  false
fi
task5_require_mode "$TASK5_PROOF_ROOT/ssl/tls.crt" 600
task5_require_mode "$TASK5_PROOF_ROOT/ssl/tls.key" 600
task5_require_proof_root_ownership "TLS certificate hostname verification"
openssl verify -CAfile "$TASK5_PROOF_ROOT/ssl/tls.crt" -verify_hostname localhost "$TASK5_PROOF_ROOT/ssl/tls.crt"

task5_require_lifecycle_lock_ownership "ordinary proof services start"
TASK5_PROOF_START_ATTEMPTED=1
task5_compose_with_lock \
  up --detach --build --force-recreate --wait \
  oauth2-mock dovecot postfix

task5_require_proof_root_ownership "proof preflight"
(
  cd -- "$TASK5_DASHBOARD_ROOT"
  "$TASK5_KOTLIN" run \
    --module dashboard-server \
    --main-class mail.sandbox.dashboard.server.gate.dovecot.EligibilityFileCli \
    -- task5-proof preflight
)

task5_require_proof_root_ownership "bootstrap eligibility creation"
if openssl rand -hex 32 |
  (
    cd -- "$TASK5_DASHBOARD_ROOT"
    "$TASK5_KOTLIN" run \
      --module dashboard-server \
      --main-class mail.sandbox.dashboard.server.gate.dovecot.EligibilityFileCli \
      -- task5-proof add task5-bootstrap@local.test
  ); then
  TASK5_BOOTSTRAP_ADDED=1
else
  task5_error "bootstrap eligibility creation failed"
  false
fi

task5_require_proof_root_ownership "operator credential bootstrap"
(
  cd -- "$TASK5_DASHBOARD_ROOT"
  "$TASK5_KOTLIN" run \
    --module dashboard-server \
    --main-class mail.sandbox.dashboard.server.gate.dovecot.DovecotOperatorCredentialStoreCli \
    -- bootstrap-task5-proof
)

task5_require_lifecycle_lock_ownership "isolated operator start"
task5_compose_with_lock \
  --profile dovecot-operator \
  up --detach --build --force-recreate --no-deps --wait \
  dovecot-operator
task5_compose_with_lock \
  --profile dovecot-operator \
  ps oauth2-mock dovecot postfix dovecot-operator

task5_require_proof_root_ownership "operator preflight checkpoint"
(
  cd -- "$TASK5_DASHBOARD_ROOT"
  TASK5_OPERATOR_EXEC_PROOF_MODE=preflight \
    "$TASK5_KOTLIN" test \
      --include-module dashboard-server \
      --include-classes "$TASK5_EXEC_TRANSPORT_LIVE_CLASS"
)

task5_require_proof_root_ownership "startup live test"
(
  cd -- "$TASK5_DASHBOARD_ROOT"
  "$TASK5_KOTLIN" test \
    --include-module dashboard-server \
    --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotOperatorStartupLiveTest
)

task5_require_proof_root_ownership "network isolation live test"
(
  cd -- "$TASK5_DASHBOARD_ROOT"
  "$TASK5_KOTLIN" test \
    --include-module dashboard-server \
    --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotIsolationLiveTest
)

task5_require_proof_root_ownership "operator rotation live test"
(
  cd -- "$TASK5_DASHBOARD_ROOT"
  "$TASK5_KOTLIN" test \
    --include-module dashboard-server \
    --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotOperatorRotationLiveTest
)

task5_require_proof_root_ownership "operator process lifecycle live test"
(
  cd -- "$TASK5_DASHBOARD_ROOT"
  "$TASK5_KOTLIN" test \
    --include-module dashboard-server \
    --include-classes "$TASK5_EXEC_TRANSPORT_LIVE_CLASS"
)

task5_require_proof_root_ownership "final zero-process inventory"
(
  cd -- "$TASK5_DASHBOARD_ROOT"
  TASK5_OPERATOR_EXEC_PROOF_MODE=inventory-only \
    "$TASK5_KOTLIN" test \
      --include-module dashboard-server \
      --include-classes "$TASK5_EXEC_TRANSPORT_LIVE_CLASS"
)

printf '%s\n' "Task 5 proof completed; mandatory cleanup follows."
fi
