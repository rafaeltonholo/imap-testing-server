#!/usr/bin/env python3
"""Wipe all mail from vmail/ and restore config/users to the last committed state."""

import shutil
import subprocess
import sys
from lib import ROOT_DIR, VMAIL_DIR, USERS_FILE


def main():
    print("This will:")
    print("  - Delete all mail under vmail/")
    print("  - Restore config/users to its last committed state (git checkout)")
    print()

    confirm = input("Are you sure? [y/N] ").strip().lower()
    if confirm != "y":
        print("Aborted.")
        return

    # Clear vmail contents but keep the directory and .gitkeep
    if VMAIL_DIR.exists():
        for child in VMAIL_DIR.iterdir():
            if child.name == ".gitkeep":
                continue
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()

    # Restore the users file from git
    result = subprocess.run(
        ["git", "-C", str(ROOT_DIR), "checkout", "HEAD", "--", "config/users"],
        capture_output=True,
    )
    if result.returncode == 0:
        print("config/users restored from git.")
    else:
        print("Warning: could not restore config/users from git. File left as-is.")

    print("Reset complete.")
    print("Run 'docker compose restart dovecot' to apply the restored users file.")


if __name__ == "__main__":
    main()
