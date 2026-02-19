#!/usr/bin/env bash
# Shared helpers — source this file, do not execute directly.
# Usage: source "$(dirname "$0")/lib.sh"

DOCKER_CONTAINER="${DOCKER_CONTAINER:-dovecot-dev}"

# inject_mail EMAIL FILE_PATH [MAILBOX] [DELAY_SECS]
#   Copies FILE_PATH into the container and saves it via doveadm.
#   MAILBOX defaults to INBOX. DELAY_SECS (default 0) adds a sleep after
#   injection to avoid Dovecot file-lock conflicts when calling in a loop.
inject_mail() {
  local email="$1"
  local file_path="$2"
  local mailbox="${3:-INBOX}"
  local delay="${4:-0}"
  local base
  base=$(basename "$file_path")

  docker cp "$file_path" "${DOCKER_CONTAINER}:/tmp/${base}"
  docker exec -i "$DOCKER_CONTAINER" \
    doveadm save -u "$email" -m "$mailbox" "/tmp/${base}" >/dev/null 2>&1 || {
    echo "Warning: failed to save /tmp/${base} into ${email} ${mailbox}"
  }

  [[ "$delay" != "0" ]] && sleep "$delay"
}
