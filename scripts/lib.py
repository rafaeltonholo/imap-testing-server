"""Shared helpers for all scripts. Import this module — do not run directly."""

import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from email.utils import formatdate, parseaddr

# ---------------------------------------------------------------------------
# Project paths
# ---------------------------------------------------------------------------

ROOT_DIR = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = ROOT_DIR / "scripts"
CONFIG_DIR = ROOT_DIR / "config"
MAILS_DIR = ROOT_DIR / "mails"
THREADS_DIR = MAILS_DIR / "threads"
VMAIL_DIR = ROOT_DIR / "vmail"
SSL_DIR = ROOT_DIR / "ssl"
USERS_FILE = CONFIG_DIR / "users"

# ---------------------------------------------------------------------------
# Docker / Dovecot
# ---------------------------------------------------------------------------

import os

DOCKER_CONTAINER = os.environ.get("DOCKER_CONTAINER", "dovecot-dev")
DEFAULT_INJECTION_DELAY = 2.5


def docker_exec(cmd: list[str], *, check: bool = True, capture: bool = False) -> subprocess.CompletedProcess:
    """Run a command inside the Dovecot container."""
    full_cmd = ["docker", "exec", "-i", DOCKER_CONTAINER] + cmd
    return subprocess.run(full_cmd, check=check, capture_output=capture, text=True)


def docker_cp(src: str, dest: str) -> None:
    """Copy a file into the container."""
    subprocess.run(["docker", "cp", src, f"{DOCKER_CONTAINER}:{dest}"], check=True, capture_output=True)


def inject_mail(email: str, file_path: str | Path, mailbox: str = "INBOX", delay: float = 0) -> bool:
    """Copy an .eml file into the container and save it via doveadm.

    Returns True on success, False on failure (prints a warning).
    """
    file_path = Path(file_path)
    container_path = f"/tmp/{file_path.name}"
    docker_cp(str(file_path), container_path)
    result = docker_exec(
        ["doveadm", "save", "-u", email, "-m", mailbox, container_path],
        check=False, capture=True,
    )
    if result.returncode != 0:
        print(f"  Warning: failed to save {file_path.name} into {email} {mailbox}")
        return False
    if delay > 0:
        time.sleep(delay)
    return True


def create_mailbox(email: str, folder: str) -> None:
    """Create a mailbox folder for a user (idempotent)."""
    docker_exec(["doveadm", "mailbox", "create", "-u", email, folder], check=False, capture=True)


# ---------------------------------------------------------------------------
# Address helpers
# ---------------------------------------------------------------------------

def display_name(addr: str) -> str:
    """Extract the display name from an address, falling back to the local part."""
    name, email = parseaddr(addr)
    if name:
        return name
    return email.split("@")[0].capitalize()


def make_slug(text: str, max_len: int = 30) -> str:
    """Turn the first few words of text into a filename-safe slug."""
    words = re.sub(r"[^a-z0-9 ]", "", text.lower()).split()[:4]
    return "-".join(words)[:max_len]


# ---------------------------------------------------------------------------
# Date helpers
# ---------------------------------------------------------------------------

def parse_date_arg(date_str: str) -> float:
    """Parse a user-supplied date string into a Unix epoch.

    Accepts "now" or "YYYY-MM-DD HH:MM:SS".
    """
    if date_str.lower() == "now":
        return time.time()
    from datetime import datetime
    try:
        dt = datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
        return dt.timestamp()
    except ValueError:
        print(f"Error: could not parse date '{date_str}'. Use 'now' or 'YYYY-MM-DD HH:MM:SS'.", file=sys.stderr)
        sys.exit(2)


def epoch_to_rfc2822(epoch: float) -> str:
    """Convert a Unix epoch to an RFC 2822 date string."""
    return formatdate(epoch, localtime=True)
