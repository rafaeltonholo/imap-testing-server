#!/usr/bin/env python3
"""Convert Outlook .msg files to .eml format and optionally inject into Dovecot.

Requires the 'extract-msg' package (installed in .venv).
Usage:
    ../.venv/bin/python3 convert_msg.py mails/debugging/failing.msg.Heute.meistgelesen.msg
    ../.venv/bin/python3 convert_msg.py mails/debugging/*.msg --inject --email dev@local.test
    ../.venv/bin/python3 convert_msg.py mails/debugging/*.msg --output-dir mails/converted/
"""

import argparse
import sys
from pathlib import Path

try:
    import extract_msg
except ImportError:
    print("Error: 'extract-msg' is required. Install it with:", file=sys.stderr)
    print("  .venv/bin/pip install extract-msg", file=sys.stderr)
    sys.exit(1)

# Allow importing lib.py from the scripts directory
sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib import MAILS_DIR, inject_mail


def convert_msg_to_eml(msg_path: Path, output_dir: Path) -> Path:
    """Convert a .msg file to .eml and return the output path."""
    msg = extract_msg.Message(str(msg_path))
    eml = msg.asEmailMessage()

    stem = msg_path.stem
    if stem.endswith(".msg"):
        stem = stem[:-4]
    eml_path = output_dir / f"{stem}.eml"

    output_dir.mkdir(parents=True, exist_ok=True)
    eml_path.write_text(eml.as_string())

    subject = msg.subject or "(no subject)"
    print(f"  Converted: {msg_path.name} -> {eml_path.name}")
    print(f"    Subject: {subject}")
    print(f"    From:    {msg.sender}")
    msg.close()
    return eml_path


def main():
    parser = argparse.ArgumentParser(description="Convert .msg files to .eml format.")
    parser.add_argument("files", nargs="+", type=Path, help="One or more .msg files to convert")
    parser.add_argument("--output-dir", type=Path, default=None,
                        help="Output directory for .eml files (default: same directory as input)")
    parser.add_argument("--inject", action="store_true",
                        help="Also inject the converted .eml into Dovecot")
    parser.add_argument("--email", default=None,
                        help="Target email address for injection (required with --inject)")
    parser.add_argument("--folder", default="INBOX",
                        help="Target mailbox folder (default: INBOX)")
    args = parser.parse_args()

    if args.inject and not args.email:
        parser.error("--email is required when using --inject")

    converted = []
    for msg_path in args.files:
        if not msg_path.exists():
            print(f"  Skipping: {msg_path} (not found)", file=sys.stderr)
            continue
        out_dir = args.output_dir or msg_path.parent
        eml_path = convert_msg_to_eml(msg_path, out_dir)
        converted.append(eml_path)

    if args.inject:
        print(f"\nInjecting {len(converted)} message(s) into {args.email} / {args.folder}...")
        for eml_path in converted:
            ok = inject_mail(args.email, eml_path, args.folder)
            status = "OK" if ok else "FAILED"
            print(f"  [{status}] {eml_path.name}")

    print(f"\nDone. {len(converted)} file(s) converted.")


if __name__ == "__main__":
    main()
