#!/usr/bin/env bash
set -euo pipefail

# Defaults
DOCKER_CONTAINER="dovecot-dev"
# Parse args
EMAIL=""
MESSAGE_PATH=""

print_usage() {
  cat <<EOF
Usage: $0 --email EMAIL 

Options:
  --email EMAIL                The email address that will receive the message
  --message MESSAGE_PATH       The message path
  -h | --help                  Show this help
EOF
}

# Simple arg loop
while [[ $# -gt 0 ]]; do
  case "$1" in
    --email)
      EMAIL="$2"; shift 2 ;;
    --message)
      MESSAGE_PATH="$2"; shift 2 ;;
    -h|--help)
      print_usage; exit 0 ;;
    *)
      echo "Unknown arg: $1"; print_usage; exit 1 ;;
  esac
done


# Validate
if [[ -z "$EMAIL" ]]; then
  echo "Error: --email is required."
  print_usage
  exit 2
fi

# Validate
if [[ -z "$MESSAGE_PATH" ]]; then
  echo "Error: --message is required."
  print_usage
  exit 2
fi

base=$(basename "$MESSAGE_PATH")
# copy into container's /tmp and save
docker cp "$MESSAGE_PATH" "${DOCKER_CONTAINER}:/tmp/$base"
# use doveadm save reading from file
docker exec -i "$DOCKER_CONTAINER" doveadm save -u "$EMAIL" -m INBOX "/tmp/$base" >/dev/null 2>&1 || {
  echo "Warning: failed to save /tmp/$base into $EMAIL INBOX"
}

echo "All done. Tip: check mails in container with:"
echo "  docker exec -it $DOCKER_CONTAINER doveadm fetch -u $EMAIL 'hdr.subject' mailbox INBOX"
echo "Or open your mail client with the new account."

exit 0

