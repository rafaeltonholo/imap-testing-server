#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MAILS_DIR="$(cd "$SCRIPT_DIR/../mails/threads" && pwd)"

EMAIL=""
THREAD_ID=""
FOLDER="INBOX"
DELAY="${INJECTION_DELAY:-2.5}"
SENT_DATE=""

print_usage() {
  cat <<EOF
Usage: $0 --thread THREAD_ID --email EMAIL [--folder FOLDER] [--date DATE] [--delay SECS]

Send all .eml files in a thread folder to a mailbox, in order.

Options:
  --thread THREAD_ID   Thread folder name under mails/threads/ (required)
  --email EMAIL        Target email address (required)
  --folder FOLDER      Target mailbox (default: INBOX)
  --date DATE          Override the Date header in each .eml with this value.
                       Accepts any format understood by the \`date\` command,
                       e.g. "2026-03-05 14:30:00" or "now". If omitted, the
                       original Date header in each file is kept as-is.
  --delay SECS         Seconds between injections (default: $DELAY)
  -h | --help          Show this help

Available threads:
$(ls -1 "$MAILS_DIR" 2>/dev/null | sed 's/^/  /')

Example:
  $0 --thread api-v2-migration --email dev@local.test
  $0 --thread api-v2-migration --email dev@local.test --date "2026-03-05 10:00:00"
  $0 --thread api-v2-migration --email dev@local.test --date now --delay 1
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --thread) THREAD_ID="$2"; shift 2 ;;
    --email)  EMAIL="$2";     shift 2 ;;
    --folder) FOLDER="$2";    shift 2 ;;
    --date)   SENT_DATE="$2"; shift 2 ;;
    --delay)  DELAY="$2";     shift 2 ;;
    -h|--help) print_usage; exit 0 ;;
    *) echo "Unknown arg: $1"; print_usage; exit 1 ;;
  esac
done

if [[ -z "$THREAD_ID" ]]; then
  echo "Error: --thread is required."
  print_usage; exit 2
fi

if [[ -z "$EMAIL" ]]; then
  echo "Error: --email is required."
  print_usage; exit 2
fi

THREAD_DIR="$MAILS_DIR/$THREAD_ID"
if [[ ! -d "$THREAD_DIR" ]]; then
  echo "Error: thread directory not found: $THREAD_DIR"
  echo "Available threads:"
  ls -1 "$MAILS_DIR" 2>/dev/null | sed 's/^/  /'
  exit 2
fi

# Glob sorts alphabetically, so 01_*, 02_*, ... preserves send order
FILES=()
for f in "$THREAD_DIR"/*.eml; do
  [[ -f "$f" ]] && FILES+=("$f")
done

if [[ ${#FILES[@]} -eq 0 ]]; then
  echo "Error: no .eml files found in $THREAD_DIR"
  exit 2
fi

echo "Sending thread '$THREAD_ID' (${#FILES[@]} emails) to $EMAIL ..."

# If --date is set, compute the base epoch and an increment per message (60s apart)
BASE_EPOCH=""
if [[ -n "$SENT_DATE" ]]; then
  if [[ "$SENT_DATE" == "now" ]]; then
    BASE_EPOCH=$(date +%s)
  else
    # Try macOS date (-j -f) first, then fall back to GNU date (-d)
    BASE_EPOCH=$(date -j -f "%Y-%m-%d %H:%M:%S" "$SENT_DATE" +%s 2>/dev/null) || \
    BASE_EPOCH=$(date -d "$SENT_DATE" +%s 2>/dev/null) || {
      echo "Error: could not parse date '$SENT_DATE'"
      exit 2
    }
  fi
fi

COUNTER=0
TOTAL=${#FILES[@]}
for eml_file in "${FILES[@]}"; do
  COUNTER=$((COUNTER + 1))
  base=$(basename "$eml_file")
  echo "  [$COUNTER/$TOTAL] $base"

  if [[ -n "$BASE_EPOCH" ]]; then
    # Each message is 60 seconds after the previous one
    MSG_EPOCH=$((BASE_EPOCH + (COUNTER - 1) * 60))
    # Format as RFC 2822 date
    # Convert epoch back to RFC 2822 string: macOS (-r epoch) vs GNU (-d @epoch)
    MSG_DATE=$(date -r "$MSG_EPOCH" "+%a, %d %b %Y %H:%M:%S %z" 2>/dev/null) || \
    MSG_DATE=$(date -d "@$MSG_EPOCH" "+%a, %d %b %Y %H:%M:%S %z" 2>/dev/null)

    # Rewrite the Date header in a temp copy so the original .eml stays untouched
    TMP_FILE=$(mktemp)
    sed "s/^Date: .*/Date: $MSG_DATE/" "$eml_file" > "$TMP_FILE"
    inject_mail "$EMAIL" "$TMP_FILE" "$FOLDER" "$DELAY"
    rm -f "$TMP_FILE"
  else
    inject_mail "$EMAIL" "$eml_file" "$FOLDER" "$DELAY"
  fi
done

echo ""
echo "Done! Sent $TOTAL emails from thread '$THREAD_ID' to $EMAIL."
echo "Check with:"
echo "  docker exec -it $DOCKER_CONTAINER doveadm fetch -u $EMAIL 'hdr.subject' mailbox $FOLDER"
