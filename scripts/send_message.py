#!/usr/bin/env python3
"""Inject a specific .eml file into a user's mailbox."""

import argparse
import sys
from lib import DOCKER_CONTAINER, inject_mail


def main():
    parser = argparse.ArgumentParser(description="Inject a .eml file into a mailbox.")
    parser.add_argument("--email", required=True, help="Target email address")
    parser.add_argument("--message", required=True, help="Path to the .eml file")
    parser.add_argument("--folder", default="INBOX", help="Target mailbox (default: INBOX)")
    args = parser.parse_args()

    inject_mail(args.email, args.message, args.folder)

    print("All done. Tip: check mails in container with:")
    print(f"  docker exec -it {DOCKER_CONTAINER} doveadm fetch -u {args.email} 'hdr.subject' mailbox INBOX")


if __name__ == "__main__":
    main()
