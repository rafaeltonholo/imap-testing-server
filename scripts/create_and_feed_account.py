#!/usr/bin/env python3
"""Create a Dovecot user account and optionally seed their inbox with .eml files."""

import argparse
import subprocess

from lib import (
    DOCKER_CONTAINER,
    MAILS_DIR,
    VMAIL_DIR,
    create_mailbox,
    inject_mail,
)
from users_file import upsert_user

DEFAULT_PASSWORD = "secret"
DEFAULT_MAILBOXES = ["INBOX", "INBOX.Sent", "INBOX.Drafts", "INBOX.Trash"]
INJECTION_DELAY = 2.5


def create_or_update_user(email: str, password: str) -> None:
    """Add or update a user in the passwd-file and create their Maildir."""
    VMAIL_DIR.mkdir(parents=True, exist_ok=True)
    upsert_user(email, password)
    print("  Canonical Dovecot auth record updated and verified.")

    maildir = VMAIL_DIR / email / "Maildir"
    maildir.mkdir(parents=True, exist_ok=True)
    print(f"  Maildir ensured at {maildir}")

    # The Dovecot container runs as UID/GID 1000
    try:
        subprocess.run(
            ["chown", "-R", "1000:1000", str(VMAIL_DIR / email)],
            check=True, capture_output=True,
        )
        print(f"  Ownership set to 1000:1000 for {VMAIL_DIR / email}")
    except (subprocess.CalledProcessError, PermissionError):
        print(f"  Warning: couldn't chown {VMAIL_DIR / email} (you may need sudo)")

    print("  Creating default mailboxes ...")
    for mb in DEFAULT_MAILBOXES:
        create_mailbox(email, mb)


def feed_mails(email: str) -> None:
    """Inject all .eml files from mails/ into the user's INBOX."""
    eml_files = sorted(MAILS_DIR.glob("*.eml"))
    if not eml_files:
        print(f"  No .eml files found in {MAILS_DIR}. Nothing injected.")
        return

    print(f"  Feeding {len(eml_files)} .eml files into {email} ...")
    for f in eml_files:
        print(f"    - {f.name} -> INBOX")
        inject_mail(email, f, "INBOX", INJECTION_DELAY)
    print("  Finished feeding messages.")


def main():
    parser = argparse.ArgumentParser(
        description="Create a Dovecot user and optionally seed their inbox.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  %(prog)s --email dev@local.test
  %(prog)s --email dev@local.test --password mypass --no-feed
  %(prog)s --email dev@local.test --only-feed
""",
    )
    parser.add_argument("--email", required=True, help="Email address for the account")
    parser.add_argument("--password", default=DEFAULT_PASSWORD,
                        help=f"Plain text password (default: {DEFAULT_PASSWORD})")
    feed_group = parser.add_mutually_exclusive_group()
    feed_group.add_argument("--feed", action="store_true", default=True,
                            help="Feed mails after creation (default)")
    feed_group.add_argument("--no-feed", action="store_true",
                            help="Do not feed mails after creation")
    feed_group.add_argument("--only-feed", action="store_true",
                            help="Skip account creation, only feed mails")
    args = parser.parse_args()

    should_create = not args.only_feed
    should_feed = not args.no_feed

    print(f"Target email:      {args.email}")
    print(f"Create user:       {should_create}")
    print(f"Feed mails:        {should_feed}")
    print(f"Dovecot container: {DOCKER_CONTAINER}")
    print("-" * 40)

    if should_create:
        print("Creating / updating user ...")
        create_or_update_user(args.email, args.password)

    if should_feed:
        feed_mails(args.email)
    else:
        print("Skipping feeding as requested (--no-feed).")

    print()
    print("All done. Tip: check mails in container with:")
    print(f"  docker exec -it {DOCKER_CONTAINER} doveadm fetch -u {args.email} 'hdr.subject' mailbox INBOX")


if __name__ == "__main__":
    main()
