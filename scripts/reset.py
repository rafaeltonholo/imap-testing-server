#!/usr/bin/env python3
"""Explicitly destroy all local provider data, then restore Dovecot defaults."""

from __future__ import annotations

import argparse
from pathlib import Path
import shutil
import stat
import subprocess
import sys
from typing import Sequence

from lib import ROOT_DIR, STALWART_DATA_DIR, VMAIL_DIR
from users_file import reset_defaults


DESTROY_FLAG = "--destroy-all-provider-data"
CONFIRMATION = "destroy vmail/, stalwart-data/, config/users"


class ResetError(RuntimeError):
    pass


def _clear_runtime_directory(directory: Path) -> None:
    if not directory.exists() and not directory.is_symlink():
        return
    metadata = directory.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ResetError(f"refusing unsafe runtime directory: {directory}")
    for child in directory.iterdir():
        if child.name == ".gitkeep":
            continue
        if child.is_symlink() or not child.is_dir():
            child.unlink()
        else:
            shutil.rmtree(child)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument(
        DESTROY_FLAG,
        action="store_true",
        help="authorize deletion of vmail/, stalwart-data/, and replacement of config/users",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.destroy_all_provider_data:
        print(f"Refusing reset without {DESTROY_FLAG}.", file=sys.stderr)
        return 2

    print("This permanently deletes vmail/ and stalwart-data/, then replaces config/users.")
    answer = input(f"Type exactly '{CONFIRMATION}' to continue: ")
    if answer != CONFIRMATION:
        print("Aborted.")
        return 1

    _clear_runtime_directory(VMAIL_DIR)
    _clear_runtime_directory(STALWART_DATA_DIR)

    subprocess.run(
        [
            "docker",
            "compose",
            "-f",
            str(ROOT_DIR / "docker-compose.yml"),
            "up",
            "-d",
            "oauth2-mock",
            "dovecot",
        ],
        check=True,
    )
    reset_defaults()
    print("Provider data destroyed; config/users defaults restored and fully verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
