#!/bin/sh
set -u

dashboard_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
dashboard_repository_root=$(CDPATH= cd -- "$dashboard_root/.." && pwd -P)
dashboard_pid_file="$dashboard_root/.runtime/dashboard-server.pid"

if test "$#" -ne 0; then
  printf '%s\n' 'Usage: ./debug-dashboard/stop-local.sh' >&2
  exit 2
fi

if test ! -e "$dashboard_pid_file"; then
  printf '%s\n' 'Dashboard is not running'
  exit 0
fi
if test -L "$dashboard_pid_file" || test ! -f "$dashboard_pid_file"; then
  printf '%s\n' 'Dashboard PID file is invalid' >&2
  exit 1
fi
if test "$(wc -l < "$dashboard_pid_file" | tr -d ' ')" != 3; then
  printf '%s\n' 'Dashboard PID file is malformed' >&2
  exit 1
fi

dashboard_pid=$(sed -n 's/^pid=//p' "$dashboard_pid_file")
dashboard_started=$(sed -n 's/^started=//p' "$dashboard_pid_file")
dashboard_recorded_repository=$(sed -n 's/^repository=//p' "$dashboard_pid_file")
case "$dashboard_pid" in
  ''|0|*[!0-9]*)
    printf '%s\n' 'Dashboard PID file contains an invalid PID' >&2
    exit 1
    ;;
esac
if test "$dashboard_recorded_repository" != "$dashboard_repository_root"; then
  printf '%s\n' 'Dashboard PID file belongs to another repository' >&2
  exit 1
fi

if ! dashboard_active_started=$(
  ps -p "$dashboard_pid" -o lstart= 2>/dev/null |
    sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
); then
  rm -f "$dashboard_pid_file"
  printf '%s\n' 'Removed stale dashboard PID file'
  exit 0
fi
if test -z "$dashboard_active_started"; then
  rm -f "$dashboard_pid_file"
  printf '%s\n' 'Removed stale dashboard PID file'
  exit 0
fi
if test "$dashboard_active_started" != "$dashboard_started"; then
  printf '%s\n' 'Dashboard PID was reused by another process; refusing to signal it' >&2
  exit 1
fi

if ! kill "$dashboard_pid"; then
  printf '%s\n' 'Could not stop the recorded dashboard process' >&2
  exit 1
fi
rm -f "$dashboard_pid_file"
printf '%s\n' "Stopped dashboard PID $dashboard_pid"
