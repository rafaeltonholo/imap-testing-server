#!/usr/bin/env python3
"""Send all .eml files in a thread folder to a mailbox, in order."""

import argparse
import re
import sys
import tempfile
from pathlib import Path

from lib import (
    DOCKER_CONTAINER,
    THREADS_DIR,
    inject_mail,
    parse_date_arg,
    epoch_to_rfc2822,
)


def list_threads() -> list[str]:
    if not THREADS_DIR.exists():
        return []
    return sorted(d.name for d in THREADS_DIR.iterdir() if d.is_dir())


def rewrite_date(eml_path: Path, new_date: str) -> Path:
    """Create a temp copy of an .eml with the Date header replaced."""
    content = eml_path.read_text()
    content = re.sub(r"^Date: .*$", f"Date: {new_date}", content, count=1, flags=re.MULTILINE)
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".eml", delete=False)
    tmp.write(content)
    tmp.close()
    return Path(tmp.name)


def main():
    threads = list_threads()
    threads_display = "\n".join(f"  {t}" for t in threads) if threads else "  (none)"

    parser = argparse.ArgumentParser(
        description="Send all .eml files in a thread folder to a mailbox, in order.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""\
available threads:
{threads_display}

examples:
  %(prog)s --thread api-v2-migration --email dev@local.test
  %(prog)s --thread api-v2-migration --email dev@local.test --date now --delay 1
  %(prog)s --thread api-v2-migration --email dev@local.test --date "2026-03-05 10:00:00"
""",
    )
    parser.add_argument("--thread", required=True, help="Thread folder name under mails/threads/")
    parser.add_argument("--email", required=True, help="Target email address")
    parser.add_argument("--folder", default="INBOX", help="Target mailbox (default: INBOX)")
    parser.add_argument("--date", default=None,
                        help='Override Date headers. "now" or "YYYY-MM-DD HH:MM:SS". '
                             "If omitted, original dates are kept.")
    parser.add_argument("--delay", type=float, default=2.5,
                        help="Seconds between injections (default: 2.5)")
    args = parser.parse_args()

    thread_dir = THREADS_DIR / args.thread
    if not thread_dir.is_dir():
        print(f"Error: thread directory not found: {thread_dir}", file=sys.stderr)
        print(f"Available threads:\n{threads_display}", file=sys.stderr)
        sys.exit(2)

    # Sorted glob gives us 01_*, 02_*, ... in order
    files = sorted(thread_dir.glob("*.eml"))
    if not files:
        print(f"Error: no .eml files found in {thread_dir}", file=sys.stderr)
        sys.exit(2)

    total = len(files)
    print(f"Sending thread '{args.thread}' ({total} emails) to {args.email} ...")

    base_epoch = parse_date_arg(args.date) if args.date else None

    for i, eml_file in enumerate(files, 1):
        print(f"  [{i}/{total}] {eml_file.name}")

        if base_epoch is not None:
            # Space messages 60 seconds apart from the base date
            msg_date = epoch_to_rfc2822(base_epoch + (i - 1) * 60)
            tmp_path = rewrite_date(eml_file, msg_date)
            try:
                inject_mail(args.email, tmp_path, args.folder, args.delay)
            finally:
                tmp_path.unlink(missing_ok=True)
        else:
            inject_mail(args.email, eml_file, args.folder, args.delay)

    print()
    print(f"Done! Sent {total} emails from thread '{args.thread}' to {args.email}.")
    print("Check with:")
    print(f"  docker exec -it {DOCKER_CONTAINER} doveadm fetch -u {args.email} 'hdr.subject' mailbox {args.folder}")


if __name__ == "__main__":
    main()
