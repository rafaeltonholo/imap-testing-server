#!/usr/bin/env bash
set -euo pipefail

DOCKER_CONTAINER="${DOCKER_CONTAINER:-dovecot-dev}"
EMAIL=""
FOLDER=""

print_usage() {
  cat <<EOF
Usage: $0 --email EMAIL --folder FOLDER

Options:
  --email EMAIL    The email address to create the folder for
  --folder FOLDER  The folder name to create (e.g. INBOX.Archive)
  -h | --help      Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --email)   EMAIL="$2";  shift 2 ;;
    --folder)  FOLDER="$2"; shift 2 ;;
    -h|--help) print_usage; exit 0 ;;
    *) echo "Unknown arg: $1"; print_usage; exit 1 ;;
  esac
done

if [[ -z "$EMAIL" ]]; then
  echo "Error: --email is required."
  print_usage; exit 2
fi

if [[ -z "$FOLDER" ]]; then
  echo "Error: --folder is required."
  print_usage; exit 2
fi

docker exec -i "$DOCKER_CONTAINER" doveadm mailbox create -u "$EMAIL" "$FOLDER"
echo "Created mailbox '$FOLDER' for $EMAIL"
