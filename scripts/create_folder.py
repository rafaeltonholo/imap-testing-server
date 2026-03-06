#!/usr/bin/env python3
"""Create a mailbox folder for a user."""

import argparse
from lib import create_mailbox


def main():
    parser = argparse.ArgumentParser(description="Create a mailbox folder for a user.")
    parser.add_argument("--email", required=True, help="Target email address")
    parser.add_argument("--folder", required=True, help="Folder name (e.g. INBOX.Archive)")
    args = parser.parse_args()

    create_mailbox(args.email, args.folder)
    print(f"Created mailbox '{args.folder}' for {args.email}")


if __name__ == "__main__":
    main()
