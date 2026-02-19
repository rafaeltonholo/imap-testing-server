#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"

EMAIL=""
MESSAGE_PATH=""
FOLDER="INBOX"

print_usage() {
  cat <<EOF
Usage: $0 --email EMAIL --message MESSAGE_PATH [--folder FOLDER]

Options:
  --email EMAIL          The email address that will receive the message
  --message MESSAGE_PATH Path to the .eml file to inject
  --folder FOLDER        Target mailbox (default: INBOX)
  -h | --help            Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --email)    EMAIL="$2";        shift 2 ;;
    --message)  MESSAGE_PATH="$2"; shift 2 ;;
    --folder)   FOLDER="$2";       shift 2 ;;
    -h|--help)  print_usage; exit 0 ;;
    *) echo "Unknown arg: $1"; print_usage; exit 1 ;;
  esac
done

if [[ -z "$EMAIL" ]]; then
  echo "Error: --email is required."
  print_usage; exit 2
fi

if [[ -z "$MESSAGE_PATH" ]]; then
  echo "Error: --message is required."
  print_usage; exit 2
fi

inject_mail "$EMAIL" "$MESSAGE_PATH" "$FOLDER"

echo "All done. Tip: check mails in container with:"
echo "  docker exec -it $DOCKER_CONTAINER doveadm fetch -u $EMAIL 'hdr.subject' mailbox INBOX"
echo "Or open your mail client with the new account."

exit 0
