#!/bin/sh
set -eu

usage() {
  printf '%s\n' \
    'Usage: reset-local-accounts.sh --dovecot-defaults [--yes]' \
    '' \
    'Replace config/users with config/users.defaults and verify Dovecot.'
}

reset_defaults=0
assume_yes=0
for argument in "$@"; do
  case "$argument" in
    --dovecot-defaults) reset_defaults=1 ;;
    --yes) assume_yes=1 ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'Unknown argument: %s\n' "$argument" >&2; usage >&2; exit 2 ;;
  esac
done

if test "$reset_defaults" -ne 1; then
  printf '%s\n' 'Refusing reset without --dovecot-defaults.' >&2
  usage >&2
  exit 2
fi

confirmation='replace config/users from config/users.defaults'
if test "$assume_yes" -ne 1; then
  printf "Type exactly '%s' to continue: " "$confirmation"
  IFS= read -r answer
  if test "$answer" != "$confirmation"; then
    printf '%s\n' 'Aborted.'
    exit 1
  fi
fi

dashboard_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
repository_root=$(CDPATH= cd -- "$dashboard_root/.." && pwd -P)

docker compose \
  -f "$repository_root/docker-compose.yml" \
  up -d oauth2-mock dovecot
python3 "$repository_root/scripts/users_file.py" reset-defaults
