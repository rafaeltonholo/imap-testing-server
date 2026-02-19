#!/usr/bin/env bash
set -euo pipefail

# create-and-feed-account.sh
# Usage:
#   ./create-and-feed-account.sh --email alice@local.test [--password secret] [--feed|--no-feed] [--only-feed]
#
# Examples:
#   ./create-and-feed-account.sh --email alice@local.test
#   ./create-and-feed-account.sh --email bob@local.test --password hunter2 --no-feed
#   ./create-and-feed-account.sh --email alice@local.test --only-feed
#
# Notes:
#  - Expects your Dovecot docker container to be named "dovecot-dev"
#  - Expects project layout where ./config/users is the passwd-file
#  - Mail files are read from ./mails/*.eml and are injected into INBOX
#  - Maildir is created under ./vmail/<user>/Maildir and chowned to 1000:1000 (container uid)
#  - Passwords are stored in config/users as {PLAIN}<password> (dev-only)
#  - The script will overwrite an existing user line for the same email
#  - Running with --only-feed requires the user to already exist in config/users

# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"

USERS_FILE="./config/users"
VMAIL_DIR="./vmail"
MAILS_DIR="./mails"
DEFAULT_PASSWORD="secret"
INJECTION_DELAY="2.5"
CREATE_USER=true
DO_FEED=true
ONLY_FEED=false

EMAIL=""
PASSWORD="$DEFAULT_PASSWORD"

print_usage() {
  cat <<EOF
Usage: $0 --email EMAIL [--password PASS] [--feed|--no-feed] [--only-feed]

Options:
  --email EMAIL        The email address to create / feed (required)
  --password PASS      Plain text password for account (default: $DEFAULT_PASSWORD)
  --feed               Feed mails from $MAILS_DIR into the account after creation (default)
  --no-feed            Do not feed mails after creation
  --only-feed          Do NOT create or update account; only feed mails into existing account
  -h | --help          Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --email)     EMAIL="$2";    shift 2 ;;
    --password)  PASSWORD="$2"; shift 2 ;;
    --feed)      DO_FEED=true;  shift ;;
    --no-feed)   DO_FEED=false; shift ;;
    --only-feed) ONLY_FEED=true; CREATE_USER=false; shift ;;
    -h|--help)   print_usage; exit 0 ;;
    *) echo "Unknown arg: $1"; print_usage; exit 1 ;;
  esac
done

if [[ -z "$EMAIL" ]]; then
  echo "Error: --email is required."
  print_usage; exit 2
fi

if [[ "$ONLY_FEED" == "true" && ! -f "$USERS_FILE" ]]; then
  echo "Error: users file '$USERS_FILE' not found. Cannot only-feed without users file."
  exit 2
fi

mkdir -p "$(dirname "$USERS_FILE")"
mkdir -p "$VMAIL_DIR"
mkdir -p "$MAILS_DIR"

echo "=== create-and-feed-account.sh ==="
echo "Target email: $EMAIL"
echo "Password: (hidden)"
echo "Create user: $CREATE_USER"
echo "Feed mails: $DO_FEED"
echo "Only-feed: $ONLY_FEED"
echo "Dovecot container: $DOCKER_CONTAINER"
echo "Users file: $USERS_FILE"
echo "Maildir root: $VMAIL_DIR"
echo "Mail source dir: $MAILS_DIR"
echo "----------------------------------"

# Helper: returns 0 (true) if EMAIL already has a line in the users file
user_exists() {
  grep -E -q "^${EMAIL}:" "$USERS_FILE" 2>/dev/null || return 1
}

# 1) Create or update user (unless only-feed)
if [[ "$CREATE_USER" == "true" ]]; then
  echo "Creating / updating user in $USERS_FILE..."
  # {PLAIN} stores the password in cleartext — acceptable for local dev only
  NEW_LINE="${EMAIL}:{PLAIN}${PASSWORD}"

  if user_exists; then
    echo "User already exists — updating password line."
    # awk rewrites the file in-place: replaces the matching email line, passes everything else through
    awk -v email="$EMAIL" -v newline="$NEW_LINE" 'BEGIN{FS=OFS=":"}
      $1==email { print newline; next }
      { print }
    ' "$USERS_FILE" > "${USERS_FILE}.tmp" && mv "${USERS_FILE}.tmp" "$USERS_FILE"
  else
    echo "Adding new user to $USERS_FILE"
    echo "$NEW_LINE" >> "$USERS_FILE"
  fi

  echo "Ensuring Maildir exists under $VMAIL_DIR/$EMAIL/Maildir ..."
  mkdir -p "$VMAIL_DIR/$EMAIL/Maildir"
  # The Dovecot container runs as UID/GID 1000; the host directory must match so it can read/write mail
  if chown 1000:1000 "$VMAIL_DIR/$EMAIL" -R 2>/dev/null; then
    echo "Set ownership to 1000:1000 for $VMAIL_DIR/$EMAIL"
  else
    echo "Warning: couldn't chown $VMAIL_DIR/$EMAIL to 1000:1000 (you may need sudo)"
  fi

  echo "Creating default mailboxes (INBOX.Sent, INBOX.Drafts, INBOX.Trash) inside container..."
  docker exec -i "$DOCKER_CONTAINER" doveadm mailbox create -u "$EMAIL" INBOX >/dev/null 2>&1 || true
  docker exec -i "$DOCKER_CONTAINER" doveadm mailbox create -u "$EMAIL" "INBOX.Sent" >/dev/null 2>&1 || true
  docker exec -i "$DOCKER_CONTAINER" doveadm mailbox create -u "$EMAIL" "INBOX.Drafts" >/dev/null 2>&1 || true
  docker exec -i "$DOCKER_CONTAINER" doveadm mailbox create -u "$EMAIL" "INBOX.Trash" >/dev/null 2>&1 || true

  echo "User creation / update complete."
fi

# 2) Feed mails (if requested)
if [[ "$DO_FEED" == "true" ]]; then
  echo "Feeding EML files from $MAILS_DIR into user $EMAIL ..."
  FOUND=0
  shopt -s nullglob
  for f in "$MAILS_DIR"/*.eml; do
    FOUND=1
    echo " - injecting $(basename "$f") -> INBOX"
    inject_mail "$EMAIL" "$f" "INBOX" "$INJECTION_DELAY"
  done
  shopt -u nullglob

  if [[ $FOUND -eq 0 ]]; then
    echo "No .eml files found in $MAILS_DIR. Nothing injected."
  else
    echo "Finished feeding messages."
  fi
else
  echo "Skipping feeding as requested (--no-feed)."
fi

echo "All done. Tip: check mails in container with:"
echo "  docker exec -it $DOCKER_CONTAINER doveadm fetch -u $EMAIL 'hdr.subject' mailbox INBOX"
echo "Or open your mail client with the new account."

exit 0
