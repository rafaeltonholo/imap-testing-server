#!/bin/sh
set -u

dashboard_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
dashboard_repository_root=$(CDPATH= cd -- "$dashboard_root/.." && pwd -P)
dashboard_classifier="$dashboard_repository_root/scripts/stalwart_runtime_state.py"
dashboard_machine=0

case "${1:-}" in
  '') ;;
  --machine) dashboard_machine=1 ;;
  --help)
    printf '%s\n' 'Usage: ./debug-dashboard/stalwart-status.sh [--machine]'
    exit 0
    ;;
  *)
    printf '%s\n' 'Usage: ./debug-dashboard/stalwart-status.sh [--machine]' >&2
    exit 2
    ;;
esac
if test "$#" -gt 1; then
  printf '%s\n' 'Usage: ./debug-dashboard/stalwart-status.sh [--machine]' >&2
  exit 2
fi

dashboard_state=$(
  python3 "$dashboard_classifier" classify --repository "$dashboard_repository_root"
) || exit 1

case "$dashboard_state" in
  fresh|current|migration-required|invalid) ;;
  *)
    printf '%s\n' 'Stalwart classifier returned an unknown state' >&2
    exit 1
    ;;
esac

if test "$dashboard_machine" -eq 1; then
  printf '%s\n' "$dashboard_state"
  exit 0
fi

case "$dashboard_state" in
  fresh)
    printf '%s\n' 'Stalwart state: fresh (normal startup may initialize it)'
    ;;
  current)
    printf '%s\n' 'Stalwart state: current'
    ;;
  migration-required)
    printf '%s\n' \
      'Stalwart upgrade required.' \
      'Follow docs/stalwart-v016-migration.md; migration requires explicit authorization.'
    ;;
  invalid)
    printf '%s\n' \
      'Stalwart state: invalid. Inspect failure evidence before any provider action.'
    ;;
esac
