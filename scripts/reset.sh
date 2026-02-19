#!/usr/bin/env bash
set -euo pipefail

# Wipes all mail from vmail/ and restores config/users to the last committed state.
# Useful for returning to a clean slate during development.
#
# config/users is restored via git, so whatever is committed in the repo
# becomes the "default" — no values are hardcoded here.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VMAIL_DIR="$ROOT/vmail"
USERS_FILE="$ROOT/config/users"

echo "This will:"
echo "  - Delete all mail under vmail/"
echo "  - Restore config/users to its last committed state (git checkout)"
echo ""
read -r -p "Are you sure? [y/N] " confirm
[[ "$confirm" =~ ^[Yy]$ ]] || { echo "Aborted."; exit 0; }

# Clear vmail contents but keep the directory itself and any .gitkeep markers
find "$VMAIL_DIR" -mindepth 1 ! -name ".gitkeep" -delete 2>/dev/null || true

# Restore the users file to whatever is committed in the repo.
# This means "default users" are whatever you have tracked in git — no duplicated list here.
if git -C "$ROOT" checkout HEAD -- config/users 2>/dev/null; then
  echo "config/users restored from git."
else
  echo "Warning: could not restore config/users from git. File left as-is."
fi

echo "Reset complete."
echo "Run 'docker compose restart dovecot' to apply the restored users file."
