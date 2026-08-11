#!/usr/bin/env python3
"""Capture and independently prove the stopped Stalwart v0.15 source store.

This tool is intentionally self-contained and stdlib-only.  It is the safety
gate before the repository's normal Compose model can move to Stalwart v0.16.
"""

from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import time
import tomllib
from typing import Any, Callable, Generic, Iterator, NamedTuple, TypeVar
import urllib.error
import urllib.parse
import urllib.request


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
RUNTIME_RELATIVE = Path("debug-dashboard") / ".runtime"
BACKUPS_RELATIVE = RUNTIME_RELATIVE / "stalwart-backups"
MIGRATION_RELATIVE = RUNTIME_RELATIVE / "stalwart-migration"
CANONICAL_RUNTIME_RELATIVE = (
    Path("captures") / "debug-dashboard" / "stalwart-v015"
)
CANONICAL_BACKUPS_NAME = "backups"
CANONICAL_MIGRATION_NAME = "migration"
LATEST_RECEIPT_NAME = "latest-source.json"
RECEIPT_SCHEMA = "mail-sandbox.stalwart-v015-source.v1"
LEGACY_CONFIG_TARGET = "/opt/stalwart/etc/config.toml"
LEGACY_DATA_TARGET = "/opt/stalwart/data"
V016_IMAGE_REFERENCE = (
    "stalwartlabs/stalwart:v0.16.17@"
    "sha256:a8108e19bd927e172d4d8c128907b8dfc93fd180ae8ee07dccdd42cb97eb9dfa"
)
V016_CONFIG_ROOT_TARGET = "/etc/stalwart"
V016_DATA_TARGET = "/var/lib/stalwart"
ROLLBACK_SERVICE = "stalwart-rollback"
ROLLBACK_PARENT_TARGET = "/opt/stalwart"
ROLLBACK_CONFIG_TARGET = LEGACY_CONFIG_TARGET
ROLLBACK_DATA_TARGET = LEGACY_DATA_TARGET
ROLLBACK_TMPFS = "/opt/stalwart:rw,noexec,nosuid,nodev,mode=0700"
ROLLBACK_NETWORK = "default"
ROLLBACK_LABEL_KEY = "mail.sandbox.stalwart.rollback"
ROLLBACK_LABEL_VALUE = "v015"
ROLLBACK_EXCLUDED_PORTS = {8443, 18443, 18587}
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
PROJECT_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
SERVICE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
VERSION_015_PATTERN = re.compile(r"^v?0\.15\.[0-9]+(?:[-+][A-Za-z0-9_.-]+)?$")
BACKUP_NAME_PATTERN = re.compile(
    r"^stalwart-v015-[0-9]{8}T[0-9]{6}Z-[a-z0-9]{8}$",
)
ROLLBACK_REFRESH_NEXT_NAME = ".rollback-data.next"
ROLLBACK_REFRESH_PREVIOUS_NAME = ".rollback-data.previous"
ROLLBACK_ACTIVATION_NAME = "rollback-activation.json"
ROLLBACK_ACTIVATION_INTENT_NAME = "rollback-activation-intent.json"
ROLLBACK_ACTIVATION_SCHEMA = (
    "mail-sandbox.stalwart-v015-rollback-activation.v1"
)
ROLLBACK_ACTIVATION_INTENT_SCHEMA = (
    "mail-sandbox.stalwart-v015-rollback-activation-intent.v1"
)

T = TypeVar("T")


class CaptureError(RuntimeError):
    """A safety validation failed."""


class CommandError(CaptureError):
    """A list-form subprocess failed without exposing captured output."""

    def __init__(
        self,
        args: list[str],
        returncode: int | None,
        *,
        timed_out: bool = False,
    ) -> None:
        self.args_list = list(args)
        self.returncode = returncode
        if timed_out:
            super().__init__("external command timed out")
        else:
            super().__init__(f"external command failed with exit status {returncode}")


class CommandResult(NamedTuple):
    stdout: str
    stderr: str


@dataclass(frozen=True, repr=False)
class VerifiedRollbackEndpoint:
    """Credential-bearing endpoint valid only for one verified callback."""

    base_url: str
    username: str
    password: str
    version: str

    def __post_init__(self) -> None:
        try:
            parsed = urllib.parse.urlsplit(self.base_url)
            port = parsed.port
        except ValueError as exc:
            raise CaptureError("verified rollback endpoint is malformed") from exc
        if (
            port is None
            or port <= 1024
            or port > 65535
            or self.base_url != f"http://127.0.0.1:{port}"
            or not self.username
            or not self.password
            or not VERSION_015_PATTERN.fullmatch(self.version)
        ):
            raise CaptureError("verified rollback endpoint is malformed")

    def __repr__(self) -> str:
        return (
            "VerifiedRollbackEndpoint("
            f"base_url={self.base_url!r}, username={self.username!r}, "
            f"password=<redacted>, version={self.version!r})"
        )


@dataclass(frozen=True)
class VerifiedRollbackProof:
    management_status: int
    proved_at: str
    version: str

    def as_dict(self) -> dict[str, object]:
        return {
            "management_status": self.management_status,
            "proved_at": self.proved_at,
            "version": self.version,
        }


@dataclass(frozen=True, repr=False)
class VerifiedRollbackResult(Generic[T]):
    value: T
    proof: VerifiedRollbackProof

    def __repr__(self) -> str:
        return f"VerifiedRollbackResult(value=<redacted>, proof={self.proof!r})"


@dataclass(frozen=True)
class VerifiedRollbackActivation:
    """Safe public handle for one verified, still-running rollback copy."""

    proof_path: Path
    base_url: str
    proof: VerifiedRollbackProof


def run_command(args: list[str]) -> CommandResult:
    """Run an external command in list form and retain, but never echo, output."""
    if not isinstance(args, list) or not all(isinstance(item, str) for item in args):
        raise CaptureError("all external commands must use list-form string arguments")
    timeout = 30
    if args[:2] == ["docker", "exec"]:
        timeout = 15
    elif args[:2] == ["docker", "compose"]:
        if "stop" in args:
            timeout = 45
        elif "up" in args or "down" in args:
            timeout = 90
    try:
        completed = subprocess.run(
            args,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise CommandError(args, None, timed_out=True) from exc
    except OSError as exc:
        raise CommandError(args, 127) from exc
    if completed.returncode != 0:
        raise CommandError(args, completed.returncode)
    return CommandResult(completed.stdout, completed.stderr)


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _open_regular_readonly(path: Path, label: str) -> tuple[int, os.stat_result]:
    path = _require_plain_absolute(path, label)
    _require_no_symlink_components(path, label)
    before = _require_not_symlink(path, label)
    if not stat.S_ISREG(before.st_mode):
        raise CaptureError(f"{label} must be a regular file")
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError as exc:
        raise CaptureError(f"{label} changed or became a symlink") from exc
    opened = os.fstat(descriptor)
    if (
        not stat.S_ISREG(opened.st_mode)
        or opened.st_dev != before.st_dev
        or opened.st_ino != before.st_ino
    ):
        os.close(descriptor)
        raise CaptureError(f"{label} changed before it could be opened safely")
    return descriptor, opened


def _sha256_regular_file(path: Path) -> tuple[str, os.stat_result]:
    digest = hashlib.sha256()
    descriptor, opened = _open_regular_readonly(path, "hash input")
    try:
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(descriptor)
    except OSError as exc:
        raise CaptureError("hash input could not be read safely") from exc
    finally:
        os.close(descriptor)
    if _file_identity(after) != _file_identity(opened):
        raise CaptureError("hash input changed while it was read")
    return digest.hexdigest(), after


def sha256_file(path: Path) -> str:
    return _sha256_regular_file(path)[0]


def copy_regular_file_0600(source: Path, destination: Path) -> None:
    source_descriptor, source_before = _open_regular_readonly(
        source,
        "config copy source",
    )
    destination_descriptor: int | None = None
    destination_identity: tuple[int, int] | None = None
    completed = False
    try:
        _require_no_symlink_components(
            destination.parent,
            "config copy destination parent",
        )
        _require_directory(destination.parent, "config copy destination parent")
        if destination.exists() or destination.is_symlink():
            raise CaptureError("config copy destination already exists")
        try:
            destination_descriptor = os.open(
                destination,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                0o600,
            )
        except OSError as exc:
            raise CaptureError("config copy destination could not be created safely") from exc
        destination_stat = os.fstat(destination_descriptor)
        if not stat.S_ISREG(destination_stat.st_mode):
            raise CaptureError("config copy destination is not a regular file")
        destination_identity = (destination_stat.st_dev, destination_stat.st_ino)
        os.fchmod(destination_descriptor, 0o600)
        copied = 0
        while True:
            chunk = os.read(source_descriptor, 1024 * 1024)
            if not chunk:
                break
            remaining = memoryview(chunk)
            while remaining:
                written = os.write(destination_descriptor, remaining)
                if written <= 0:
                    raise CaptureError("config copy destination write did not progress")
                copied += written
                remaining = remaining[written:]
        os.fsync(destination_descriptor)
        source_after = os.fstat(source_descriptor)
        destination_after = os.fstat(destination_descriptor)
        if _file_identity(source_after) != _file_identity(source_before):
            raise CaptureError("config copy source changed while it was read")
        if (
            copied != source_before.st_size
            or destination_after.st_size != copied
            or stat.S_IMODE(destination_after.st_mode) != 0o600
        ):
            raise CaptureError("config copy destination is incomplete")
        completed = True
    except OSError as exc:
        raise CaptureError("config copy failed safely") from exc
    finally:
        os.close(source_descriptor)
        if destination_descriptor is not None:
            os.close(destination_descriptor)
        if not completed and destination_identity is not None:
            try:
                metadata = destination.lstat()
                if (
                    not stat.S_ISLNK(metadata.st_mode)
                    and (metadata.st_dev, metadata.st_ino) == destination_identity
                ):
                    destination.unlink()
                    fsync_directory(destination.parent)
            except FileNotFoundError:
                pass


def read_regular_bytes(path: Path, label: str, *, maximum: int) -> bytes:
    descriptor, before = _open_regular_readonly(path, label)
    chunks: list[bytes] = []
    total = 0
    try:
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                raise CaptureError(f"{label} is unreasonably large")
            chunks.append(chunk)
        after = os.fstat(descriptor)
    except OSError as exc:
        raise CaptureError(f"{label} could not be read safely") from exc
    finally:
        os.close(descriptor)
    if _file_identity(after) != _file_identity(before):
        raise CaptureError(f"{label} changed while it was read")
    return b"".join(chunks)


def fsync_directory(path: Path) -> None:
    _require_directory(path, "directory sync target")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def fsync_tree(root: Path) -> None:
    _require_directory(root, "tree sync root")
    files: list[Path] = []
    directories: list[Path] = [root]
    for path in root.rglob("*"):
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise CaptureError("tree sync refuses symlinks")
        if stat.S_ISREG(metadata.st_mode):
            files.append(path)
        elif stat.S_ISDIR(metadata.st_mode):
            directories.append(path)
        else:
            raise CaptureError("tree sync refuses non-regular entries")
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    for path in sorted(files):
        descriptor = os.open(path, os.O_RDONLY | no_follow)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    for path in sorted(directories, key=lambda item: len(item.parts), reverse=True):
        fsync_directory(path)


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.lstat().st_mode)


def _require_plain_absolute(path: Path, label: str) -> Path:
    if not path.is_absolute() or ".." in path.parts:
        raise CaptureError(f"{label} must be an absolute path without traversal")
    return path


def _paths_overlap(left: Path, right: Path) -> bool:
    return (
        left == right
        or left in right.parents
        or right in left.parents
    )


def _require_not_symlink(path: Path, label: str) -> os.stat_result:
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise CaptureError(f"{label} does not exist") from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise CaptureError(f"{label} must not be a symlink")
    return metadata


def _require_no_symlink_components(
    path: Path,
    label: str,
    *,
    allow_missing: bool = False,
) -> None:
    path = _require_plain_absolute(path, label)
    current = Path(path.anchor)
    missing_parent = False
    for component in path.parts[1:]:
        current = current / component
        if missing_parent:
            continue
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            if not allow_missing:
                raise CaptureError(f"{label} does not exist")
            missing_parent = True
            continue
        if stat.S_ISLNK(metadata.st_mode):
            raise CaptureError(f"{label} has a symlink path component")


def _require_components_below(root: Path, path: Path, label: str) -> None:
    root = _require_plain_absolute(root, f"{label} root")
    path = _require_plain_absolute(path, label)
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise CaptureError(f"{label} must stay below its approved root") from exc
    _require_no_symlink_components(root, f"{label} root")
    _require_no_symlink_components(path, label)
    current = root
    root_metadata = _require_not_symlink(current, f"{label} root")
    if not stat.S_ISDIR(root_metadata.st_mode):
        raise CaptureError(f"{label} root must be a directory")
    for component in relative.parts:
        current = current / component
        _require_not_symlink(current, label)


def _require_regular(path: Path, label: str) -> None:
    metadata = _require_not_symlink(path, label)
    if not stat.S_ISREG(metadata.st_mode):
        raise CaptureError(f"{label} must be a regular file")


def _require_directory(path: Path, label: str) -> None:
    metadata = _require_not_symlink(path, label)
    if not stat.S_ISDIR(metadata.st_mode):
        raise CaptureError(f"{label} must be a directory")


def _require_regular_0600(path: Path, label: str) -> None:
    _require_regular(path, label)
    metadata = path.lstat()
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise CaptureError(f"{label} must have mode 0600")
    if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
        raise CaptureError(f"{label} must be owned by the current user")


def _require_directory_0700(path: Path, label: str) -> None:
    _require_directory(path, label)
    metadata = path.lstat()
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        raise CaptureError(f"{label} must have mode 0700")
    if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
        raise CaptureError(f"{label} must be owned by the current user")


def ensure_owner_directory(path: Path) -> None:
    """Create or tighten a tool-owned runtime directory."""
    path = _require_plain_absolute(path, "owner directory")
    _require_no_symlink_components(path, "owner directory", allow_missing=True)
    missing: list[Path] = []
    candidate = path
    while not candidate.exists() and not candidate.is_symlink():
        missing.append(candidate)
        candidate = candidate.parent
    _require_directory(candidate, "owner directory ancestor")
    for directory in reversed(missing):
        parent = directory.parent
        _require_directory(parent, "owner directory parent")
        os.mkdir(directory, 0o700)
        descriptor = os.open(
            directory,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            os.fchmod(descriptor, 0o700)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        fsync_directory(parent)
    _require_directory(path, "owner directory")
    _require_no_symlink_components(path, "owner directory")
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        os.fchmod(descriptor, 0o700)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _require_directory_0700(path, "owner directory")


@contextmanager
def _advisory_lock(path: Path, contention_message: str) -> Iterator[None]:
    """Hold a crash-safe advisory lock in an owner-only runtime directory."""
    path = _require_plain_absolute(path, "operation lock")
    ensure_owner_directory(path.parent)
    _require_no_symlink_components(path.parent, "operation lock parent")
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise CaptureError("operation lock could not be opened safely") from exc
    locked = False
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise CaptureError("operation lock must be a unique regular file")
        if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
            raise CaptureError("operation lock must be owned by the current user")
        os.fchmod(descriptor, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise CaptureError(contention_message) from exc
        locked = True
        os.ftruncate(descriptor, 0)
        os.write(descriptor, f"{os.getpid()}\n".encode("ascii"))
        os.fsync(descriptor)
        fsync_directory(path.parent)
        yield
    finally:
        if locked:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def write_bytes_0600_atomic(target: Path, content: bytes) -> None:
    if target.is_symlink():
        raise CaptureError(f"{target.name} target must not be a symlink")
    if target.exists() and not stat.S_ISREG(target.lstat().st_mode):
        raise CaptureError(f"{target.name} target must be a regular file")
    ensure_owner_directory(target.parent)
    temporary = target.parent / f".{target.name}.{secrets.token_hex(8)}.tmp"
    descriptor: int | None = None
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            descriptor = None
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
        fsync_directory(target.parent)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary.exists() and not temporary.is_symlink():
            temporary.unlink()
    _require_regular_0600(target, target.name)


def write_json_0600_atomic(target: Path, value: object) -> None:
    write_bytes_0600_atomic(target, _canonical_json_bytes(value) + b"\n")


def make_receipt_envelope(payload: dict[str, object]) -> dict[str, object]:
    return {
        "payload": payload,
        "payload_sha256": sha256_bytes(_canonical_json_bytes(payload)),
    }


def validate_receipt_envelope(envelope: object) -> dict[str, object]:
    if not isinstance(envelope, dict):
        raise CaptureError("receipt must contain a JSON object")
    if set(envelope) != {"payload", "payload_sha256"}:
        raise CaptureError("receipt envelope has unexpected fields")
    payload = envelope.get("payload")
    expected = envelope.get("payload_sha256")
    if not isinstance(payload, dict) or not isinstance(expected, str):
        raise CaptureError("receipt envelope is malformed")
    actual = sha256_bytes(_canonical_json_bytes(payload))
    if not secrets.compare_digest(actual, expected):
        raise CaptureError("receipt payload digest does not match")
    return payload


def manifest_tree(root: Path) -> dict[str, object]:
    _require_directory(root, "manifest root")
    entries: list[dict[str, object]] = []
    file_count = 0
    directory_count = 0
    total_bytes = 0
    paths = sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix())
    for path in paths:
        relative = path.relative_to(root).as_posix()
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise CaptureError(f"data manifest refuses symlink entry: {relative}")
        if stat.S_ISDIR(metadata.st_mode):
            directory_count += 1
            entries.append(
                {
                    "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
                    "path": relative,
                    "type": "directory",
                },
            )
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise CaptureError(f"data manifest refuses non-regular entry: {relative}")
        digest, hashed_metadata = _sha256_regular_file(path)
        if _file_identity(hashed_metadata) != _file_identity(metadata):
            raise CaptureError(f"data manifest entry changed while hashing: {relative}")
        file_count += 1
        total_bytes += hashed_metadata.st_size
        entries.append(
            {
                "mode": f"{stat.S_IMODE(hashed_metadata.st_mode):04o}",
                "path": relative,
                "sha256": digest,
                "size": hashed_metadata.st_size,
                "type": "file",
            },
        )
    return {
        "algorithm": "sha256",
        "directory_count": directory_count,
        "entries": entries,
        "file_count": file_count,
        "total_bytes": total_bytes,
    }


def copy_tree(source: Path, destination: Path) -> None:
    if destination.exists() or destination.is_symlink():
        raise CaptureError("copy destination already exists")
    shutil.copytree(source, destination, symlinks=True, copy_function=shutil.copy2)
    destination.chmod(0o700)


def _safe_remove_generated_tree(path: Path, approved_parent: Path) -> None:
    _require_no_symlink_components(approved_parent, "generated-tree parent")
    _require_no_symlink_components(path, "generated tree", allow_missing=True)
    if path.parent != approved_parent or path.name in {"", ".", ".."}:
        raise CaptureError("refusing broad generated-tree cleanup")
    if not path.exists() and not path.is_symlink():
        return
    metadata = _require_not_symlink(path, "generated tree")
    if not stat.S_ISDIR(metadata.st_mode):
        raise CaptureError("generated tree cleanup target must be a directory")
    shutil.rmtree(path)


def is_pinned_image(reference: object) -> bool:
    if not isinstance(reference, str) or "@" not in reference:
        return False
    repository, digest = reference.rsplit("@", 1)
    return bool(repository and digest.startswith("sha256:") and SHA256_PATTERN.fullmatch(digest[7:]))


def build_rollback_definition(
    *,
    image_digest: str,
    port: int,
    project: str,
) -> dict[str, object]:
    return {
        "services": {
            ROLLBACK_SERVICE: {
                "env_file": ["./rollback.env"],
                "image": image_digest,
                "labels": {
                    ROLLBACK_LABEL_KEY: ROLLBACK_LABEL_VALUE,
                },
                "ports": [
                    {
                        "host_ip": "127.0.0.1",
                        "protocol": "tcp",
                        "published": port,
                        "target": 8443,
                    },
                ],
                "restart": "no",
                "tmpfs": [ROLLBACK_TMPFS],
                "volumes": [
                    {
                        "read_only": True,
                        "source": "./config.toml",
                        "target": ROLLBACK_CONFIG_TARGET,
                        "type": "bind",
                    },
                    {
                        "read_only": False,
                        "source": "./rollback-data",
                        "target": ROLLBACK_DATA_TARGET,
                        "type": "bind",
                    },
                ],
            },
        },
        "x-mail-sandbox": {
            "project": project,
            "purpose": "stopped-v0.15-rollback-proof",
        },
    }


def validate_rollback_definition(definition: object, backup_root: Path) -> dict[str, object]:
    if not isinstance(definition, dict):
        raise CaptureError("rollback definition must be a JSON object")
    if set(definition) != {"services", "x-mail-sandbox"}:
        raise CaptureError("rollback definition has unexpected top-level fields")
    extension = definition.get("x-mail-sandbox")
    services = definition.get("services")
    if (
        not isinstance(extension, dict)
        or set(extension) != {"project", "purpose"}
        or extension.get("purpose") != "stopped-v0.15-rollback-proof"
        or not isinstance(services, dict)
    ):
        raise CaptureError("rollback definition is incomplete")
    project = extension.get("project")
    if (
        not isinstance(project, str)
        or not PROJECT_PATTERN.fullmatch(project)
        or not project.startswith("mail-sandbox-stalwart-rollback-")
        or project == "mail-sandbox-stalwart-gate"
    ):
        raise CaptureError("rollback project is not isolated")
    if set(services) != {ROLLBACK_SERVICE}:
        raise CaptureError("rollback definition must contain exactly one service")
    service = services[ROLLBACK_SERVICE]
    if not isinstance(service, dict):
        raise CaptureError("rollback service is malformed")
    allowed_service_keys = {
        "env_file",
        "image",
        "labels",
        "ports",
        "restart",
        "tmpfs",
        "volumes",
    }
    if set(service) != allowed_service_keys:
        raise CaptureError("rollback service contains unexpected runtime options")
    image = service.get("image")
    if not is_pinned_image(image):
        raise CaptureError("rollback image must use an immutable repository digest")
    if service.get("restart") != "no":
        raise CaptureError("rollback service must not restart automatically")
    if service.get("labels") != {ROLLBACK_LABEL_KEY: ROLLBACK_LABEL_VALUE}:
        raise CaptureError("rollback service isolation label is missing")
    if service.get("tmpfs") != [ROLLBACK_TMPFS]:
        raise CaptureError("rollback must suppress the image volume with the exact parent tmpfs")
    if any(key in service for key in ("container_name", "network_mode", "privileged")):
        raise CaptureError("rollback service contains an unsafe runtime option")
    expected_volumes = [
        {
            "read_only": True,
            "source": "./config.toml",
            "target": ROLLBACK_CONFIG_TARGET,
            "type": "bind",
        },
        {
            "read_only": False,
            "source": "./rollback-data",
            "target": ROLLBACK_DATA_TARGET,
            "type": "bind",
        },
    ]
    if service.get("volumes") != expected_volumes:
        raise CaptureError("rollback mounts must bind only the backup config and working copy")
    if service.get("env_file") != ["./rollback.env"]:
        raise CaptureError("rollback secret must come from the backup-local env file")
    ports = service.get("ports")
    if not isinstance(ports, list) or len(ports) != 1 or not isinstance(ports[0], dict):
        raise CaptureError("rollback definition must publish exactly one port")
    port = ports[0]
    published = port.get("published")
    if (
        port.get("host_ip") != "127.0.0.1"
        or port.get("target") != 8443
        or port.get("protocol") != "tcp"
        or not isinstance(published, int)
        or published <= 1024
        or published > 65535
        or published in ROLLBACK_EXCLUDED_PORTS
    ):
        raise CaptureError("rollback port must be a distinct unprivileged loopback port")
    for relative, kind in (
        ("config.toml", "file"),
        ("rollback.env", "file"),
        ("rollback-data", "directory"),
    ):
        candidate = backup_root / relative
        if kind == "file":
            _require_regular(candidate, f"rollback {relative}")
        else:
            _require_directory(candidate, f"rollback {relative}")
    return service


def _load_json_text(value: str, label: str) -> object:
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError) as exc:
        raise CaptureError(f"{label} did not return valid JSON") from exc


def _single_json_record(value: str, label: str) -> dict[str, object]:
    parsed = _load_json_text(value, label)
    if not isinstance(parsed, list) or len(parsed) != 1 or not isinstance(parsed[0], dict):
        raise CaptureError(f"{label} must resolve exactly one record")
    return parsed[0]


def _repository_from_image_reference(reference: str) -> str:
    without_digest = reference.split("@", 1)[0]
    slash = without_digest.rfind("/")
    colon = without_digest.rfind(":")
    if colon > slash:
        without_digest = without_digest[:colon]
    if not without_digest:
        raise CaptureError("source image reference is malformed")
    return without_digest


def _parse_admin_config(path: Path) -> str:
    try:
        document = tomllib.loads(
            read_regular_bytes(
                path,
                "source TOML",
                maximum=10 * 1024 * 1024,
            ).decode("utf-8"),
        )
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise CaptureError("source TOML could not be parsed safely") from exc
    authentication = document.get("authentication")
    if not isinstance(authentication, dict):
        raise CaptureError("source TOML has no fallback administrator")
    fallback = authentication.get("fallback-admin")
    if not isinstance(fallback, dict):
        raise CaptureError("source TOML has no fallback administrator")
    username = fallback.get("user")
    secret_reference = fallback.get("secret")
    if not isinstance(username, str) or not username or username != username.strip():
        raise CaptureError("source fallback administrator name is invalid")
    if secret_reference != "%{env:ADMIN_SECRET}%":
        raise CaptureError("source fallback administrator is not bound to ADMIN_SECRET")
    return username


def _extract_admin_secret(environment: object) -> str:
    if not isinstance(environment, list):
        raise CaptureError("source environment is unavailable")
    matches = [
        item.split("=", 1)[1]
        for item in environment
        if isinstance(item, str) and item.startswith("ADMIN_SECRET=") and "=" in item
    ]
    if len(matches) != 1 or not matches[0] or "\n" in matches[0] or "\r" in matches[0]:
        raise CaptureError("source ADMIN_SECRET is unavailable for isolated rollback proof")
    return matches[0]


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        request: urllib.request.Request,
        file_pointer: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> None:
        return None


def _default_management_probe(url: str, username: str, secret: str) -> int:
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
    except ValueError:
        return 0
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or parsed.username is not None
        or parsed.password is not None
        or port is None
        or port <= 1024
        or port > 65535
    ):
        return 0
    token = base64.b64encode(f"{username}:{secret}".encode("utf-8")).decode("ascii")
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "Authorization": f"Basic {token}",
        },
        method="GET",
    )
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _NoRedirectHandler(),
    )
    try:
        with opener.open(request, timeout=3) as response:
            status = response.status
            body = response.read(1024 * 1024)
    except urllib.error.HTTPError as exc:
        return exc.code
    except (urllib.error.URLError, TimeoutError, OSError):
        return 0
    if status != 200:
        return status
    try:
        json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return 0
    return status


def _default_port_allocator(excluded: set[int]) -> int:
    preferred = 28443
    if preferred not in excluded:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as candidate:
                candidate.bind(("127.0.0.1", preferred))
            return preferred
        except OSError:
            pass
    for _ in range(20):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as candidate:
            candidate.bind(("127.0.0.1", 0))
            port = int(candidate.getsockname()[1])
        if port > 1024 and port not in excluded:
            return port
    raise CaptureError("could not allocate a distinct loopback rollback port")


def _port_is_available(port: int) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as candidate:
            candidate.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False


class CaptureApplication:
    """Orchestrates capture with injectable command and localhost HTTP edges."""

    def __init__(
        self,
        *,
        repository_root: Path = REPOSITORY_ROOT,
        runner: Callable[[list[str]], CommandResult] = run_command,
        management_probe: Callable[[str, str, str], int] = _default_management_probe,
        port_allocator: Callable[[set[int]], int] = _default_port_allocator,
        port_checker: Callable[[int], bool] = _port_is_available,
        clock: Callable[[], str] | None = None,
        nonce: Callable[[], str] | None = None,
        tree_copier: Callable[[Path, Path], None] = copy_tree,
        receipt_writer: Callable[[Path, object], None] = write_json_0600_atomic,
        tree_sync: Callable[[Path], None] = fsync_tree,
        directory_sync: Callable[[Path], None] = fsync_directory,
    ) -> None:
        self.repository_root = Path(os.path.abspath(repository_root))
        self.runner = runner
        self.management_probe = management_probe
        self.port_allocator = port_allocator
        self.port_checker = port_checker
        self.clock = clock or (
            lambda: time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        )
        self.nonce = nonce or (lambda: secrets.token_hex(4))
        self.tree_copier = tree_copier
        self.receipt_writer = receipt_writer
        self.tree_sync = tree_sync
        self.directory_sync = directory_sync

    @property
    def runtime_root(self) -> Path:
        return self.repository_root / RUNTIME_RELATIVE

    @property
    def backups_root(self) -> Path:
        return self.repository_root / BACKUPS_RELATIVE

    @property
    def migration_root(self) -> Path:
        return self.repository_root / MIGRATION_RELATIVE

    @property
    def latest_receipt(self) -> Path:
        return self.migration_root / LATEST_RECEIPT_NAME

    @staticmethod
    def _canonical_paths(source_root: Path) -> tuple[Path, Path, Path, Path]:
        runtime_root = source_root / CANONICAL_RUNTIME_RELATIVE
        backups_root = runtime_root / CANONICAL_BACKUPS_NAME
        migration_root = runtime_root / CANONICAL_MIGRATION_NAME
        latest_receipt = migration_root / LATEST_RECEIPT_NAME
        return runtime_root, backups_root, migration_root, latest_receipt

    def _validate_canonical_storage(
        self,
        source_root: Path,
        *,
        create: bool,
    ) -> tuple[Path, Path, Path, Path]:
        source_root = _require_plain_absolute(source_root, "canonical source checkout")
        _require_no_symlink_components(source_root, "canonical source checkout")
        _require_directory(source_root, "canonical source checkout")
        source_git = source_root / ".git"
        _require_no_symlink_components(source_git, "canonical source Git directory")
        _require_directory(source_git, "canonical source Git directory")
        source_common = self._git_common_directory(source_root)
        invocation_common = self._git_common_directory(self.repository_root)
        if (
            source_common != invocation_common
            or source_common != source_git.resolve()
        ):
            raise CaptureError(
                "canonical storage requires the primary checkout of the current Git repository",
            )
        ignored_relative = CANONICAL_RUNTIME_RELATIVE.as_posix()
        try:
            self.runner(
                [
                    "git",
                    "-C",
                    str(source_root),
                    "check-ignore",
                    "--quiet",
                    "--",
                    ignored_relative,
                ],
            )
        except CommandError as exc:
            raise CaptureError("canonical capture root is not proven ignored by Git") from exc
        runtime_root, backups_root, migration_root, latest_receipt = self._canonical_paths(
            source_root,
        )
        _require_no_symlink_components(
            runtime_root,
            "canonical capture root",
            allow_missing=create,
        )
        if create:
            ensure_owner_directory(runtime_root)
            ensure_owner_directory(backups_root)
            ensure_owner_directory(migration_root)
        else:
            _require_directory_0700(runtime_root, "canonical capture root")
            _require_directory_0700(backups_root, "canonical backups directory")
            _require_directory_0700(migration_root, "canonical migration directory")
        return runtime_root, backups_root, migration_root, latest_receipt

    def _git_common_directory(self, working_directory: Path) -> Path:
        result = self.runner(
            [
                "git",
                "-C",
                str(working_directory),
                "rev-parse",
                "--path-format=absolute",
                "--git-common-dir",
            ],
        )
        value = result.stdout.strip()
        if not value:
            raise CaptureError("Compose working directory is not in a Git repository")
        candidate = Path(value)
        if not candidate.is_absolute():
            candidate = working_directory / candidate
        return candidate.resolve()

    def _inspect_many(self, container_ids: list[str]) -> list[dict[str, object]]:
        if not container_ids:
            return []
        result = self.runner(["docker", "inspect", *container_ids])
        parsed = _load_json_text(result.stdout, "docker inspect")
        if not isinstance(parsed, list) or not all(isinstance(item, dict) for item in parsed):
            raise CaptureError("docker inspect returned an invalid record set")
        return parsed

    def _inspect_one(self, container_id: str) -> dict[str, object]:
        return _single_json_record(
            self.runner(["docker", "inspect", container_id]).stdout,
            "docker inspect",
        )

    @staticmethod
    def _mount_by_target(record: dict[str, object], target: str) -> dict[str, object] | None:
        mounts = record.get("Mounts")
        if not isinstance(mounts, list):
            return None
        matches = [
            item
            for item in mounts
            if isinstance(item, dict) and item.get("Destination") == target
        ]
        if len(matches) > 1:
            raise CaptureError(f"source has duplicate mount target {target}")
        return matches[0] if matches else None

    def _validate_source_record(
        self,
        record: dict[str, object],
        source_service: str,
    ) -> dict[str, object]:
        container_id = record.get("Id")
        if not isinstance(container_id, str) or not re.fullmatch(r"[0-9a-f]{12,64}", container_id):
            raise CaptureError("source container identity is invalid")
        state = record.get("State")
        if not isinstance(state, dict) or state.get("Running") is not True:
            raise CaptureError("source candidate must be running")
        config = record.get("Config")
        if not isinstance(config, dict):
            raise CaptureError("source container config is unavailable")
        labels = config.get("Labels")
        if not isinstance(labels, dict):
            raise CaptureError("source Compose labels are unavailable")
        project = labels.get("com.docker.compose.project")
        service = labels.get("com.docker.compose.service")
        working_value = labels.get("com.docker.compose.project.working_dir")
        config_files_value = labels.get("com.docker.compose.project.config_files")
        if not isinstance(project, str) or not PROJECT_PATTERN.fullmatch(project):
            raise CaptureError("source Compose project label is unsafe")
        if service != source_service or not SERVICE_PATTERN.fullmatch(source_service):
            raise CaptureError("source Compose service label is unsafe")
        if not isinstance(working_value, str) or not working_value:
            raise CaptureError("source Compose working-directory label is unsafe")
        working_directory = _require_plain_absolute(
            Path(working_value),
            "source Compose working directory",
        )
        working_metadata = _require_not_symlink(
            working_directory,
            "source Compose working directory",
        )
        if not stat.S_ISDIR(working_metadata.st_mode):
            raise CaptureError("source Compose working directory must be a directory")
        if not isinstance(config_files_value, str) or not config_files_value:
            raise CaptureError("source Compose config-files label is unsafe")
        config_files: list[Path] = []
        for raw in config_files_value.split(","):
            candidate = _require_plain_absolute(Path(raw), "source Compose config file")
            _require_components_below(working_directory, candidate, "source Compose config file")
            _require_regular(candidate, "source Compose config file")
            config_files.append(candidate)
        if config_files != [working_directory / "docker-compose.yml"]:
            raise CaptureError("source Compose config-files label is not the exact legacy file")
        expected_config = working_directory / "stalwart" / "config.toml"
        expected_data = working_directory / "stalwart-data"
        config_mount = self._mount_by_target(record, LEGACY_CONFIG_TARGET)
        data_mount = self._mount_by_target(record, LEGACY_DATA_TARGET)
        if not isinstance(config_mount, dict) or not isinstance(data_mount, dict):
            raise CaptureError("legacy source mount targets are incomplete")
        if config_mount.get("Type") != "bind" or data_mount.get("Type") != "bind":
            raise CaptureError("legacy source mounts must be bind mounts")
        config_source = Path(str(config_mount.get("Source", "")))
        data_source = Path(str(data_mount.get("Source", "")))
        if config_source != expected_config or data_source != expected_data:
            raise CaptureError("source mount source paths do not match the resolved Compose root")
        _require_components_below(working_directory, config_source, "source config mount source")
        _require_components_below(working_directory, data_source, "source data mount source")
        _require_regular(config_source, "source config mount source")
        _require_directory(data_source, "source data mount source")
        if config_mount.get("RW") is not False:
            raise CaptureError("source config mount must be read-only")
        if data_mount.get("RW") is not True:
            raise CaptureError("source has an unsafe read-only data mount")
        current_common = self._git_common_directory(self.repository_root)
        source_common = self._git_common_directory(working_directory)
        if current_common != source_common:
            raise CaptureError("source Compose service is from a different Git repository")
        image_reference = config.get("Image")
        image_id = record.get("Image")
        if not isinstance(image_reference, str) or not image_reference:
            raise CaptureError("source image reference is unavailable")
        if (
            not isinstance(image_id, str)
            or not image_id.startswith("sha256:")
            or not SHA256_PATTERN.fullmatch(image_id[7:])
        ):
            raise CaptureError("source immutable image ID is invalid")
        return {
            "admin_secret": _extract_admin_secret(config.get("Env")),
            "compose_config_files": config_files,
            "compose_project": project,
            "compose_service": service,
            "compose_working_directory": working_directory,
            "config_source": config_source,
            "container_id": container_id,
            "data_source": data_source,
            "image_id": image_id,
            "image_reference": image_reference,
        }

    def resolve_source_service(self, source_service: str) -> dict[str, object]:
        if not SERVICE_PATTERN.fullmatch(source_service):
            raise CaptureError("source service name is unsafe")
        result = self.runner(
            [
                "docker",
                "ps",
                "--filter",
                "status=running",
                "--filter",
                f"label=com.docker.compose.service={source_service}",
                "--format",
                "{{.ID}}",
            ],
        )
        container_ids = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        if any(not re.fullmatch(r"[0-9a-f]{12,64}", value) for value in container_ids):
            raise CaptureError("source service resolution returned an invalid container ID")
        if len(container_ids) != len(set(container_ids)):
            raise CaptureError("source service resolution returned duplicate identities")
        records = self._inspect_many(container_ids)
        legacy_candidates: list[dict[str, object]] = []
        for record in records:
            config_mount = self._mount_by_target(record, LEGACY_CONFIG_TARGET)
            data_mount = self._mount_by_target(record, LEGACY_DATA_TARGET)
            if config_mount is None and data_mount is None:
                continue
            legacy_candidates.append(self._validate_source_record(record, source_service))
        if not legacy_candidates:
            raise CaptureError("expected exactly one running legacy v0.15 source service")
        if len(legacy_candidates) != 1:
            raise CaptureError("legacy source service resolution is ambiguous")
        source = legacy_candidates[0]
        version = self.runner(
            [
                "docker",
                "exec",
                str(source["container_id"]),
                "/usr/local/bin/stalwart",
                "--version",
            ],
        ).stdout.strip()
        if not VERSION_015_PATTERN.fullmatch(version):
            raise CaptureError("source service must report a v0.15.x version")
        source["version"] = version.removeprefix("v")
        repository = _repository_from_image_reference(str(source["image_reference"]))
        image_record = _single_json_record(
            self.runner(
                ["docker", "image", "inspect", str(source["image_id"])],
            ).stdout,
            "docker image inspect",
        )
        repo_digests = image_record.get("RepoDigests")
        matches = (
            [
                value
                for value in repo_digests
                if isinstance(value, str)
                and value.startswith(repository + "@sha256:")
                and is_pinned_image(value)
            ]
            if isinstance(repo_digests, list)
            else []
        )
        if len(set(matches)) != 1:
            raise CaptureError("source image has no unique immutable repository digest")
        if image_record.get("Id") != source["image_id"]:
            raise CaptureError("source image ID changed during resolution")
        source["image_digest"] = matches[0]
        source["admin_username"] = _parse_admin_config(Path(source["config_source"]))
        return source

    @staticmethod
    def _compose_prefix(source: dict[str, object]) -> list[str]:
        command = [
            "docker",
            "compose",
            "--project-directory",
            str(source["compose_working_directory"]),
            "-p",
            str(source["compose_project"]),
        ]
        for config_file in source["compose_config_files"]:
            command.extend(["-f", str(config_file)])
        return command

    def _stop_source(self, source: dict[str, object]) -> None:
        command = self._compose_prefix(source)
        command.extend(["stop", "--timeout", "30", str(source["compose_service"])])
        self.runner(command)
        self._require_source_stopped(source)

    def _require_source_stopped(self, source: dict[str, object]) -> dict[str, object]:
        record = self._inspect_one(str(source["container_id"]))
        state = record.get("State")
        if not isinstance(state, dict) or state.get("Running") is not False:
            raise CaptureError("recorded source container must remain stopped")
        running = self.runner(
            [
                "docker",
                "ps",
                "--filter",
                "status=running",
                "--filter",
                f"label=com.docker.compose.project={source['compose_project']}",
                "--filter",
                f"label=com.docker.compose.service={source['compose_service']}",
                "--format",
                "{{.ID}}",
            ],
        )
        running_ids = [line.strip() for line in running.stdout.splitlines() if line.strip()]
        if running_ids:
            raise CaptureError("source Compose service still has a running container")
        return record

    def _ensure_source_stopped(self, source: dict[str, object]) -> None:
        try:
            self._require_source_stopped(source)
            return
        except CaptureError:
            pass
        self._stop_source(source)

    @contextmanager
    def _capture_lock(self, migration_root: Path) -> Iterator[None]:
        with _advisory_lock(
            migration_root / ".capture.lock",
            "another capture operation is already running",
        ):
            yield

    @contextmanager
    def _rollback_proof_lock(self, backup_root: Path) -> Iterator[None]:
        _require_directory_0700(backup_root, "source backup")
        with _advisory_lock(
            backup_root / ".rollback-proof.lock",
            "another rollback proof operation is already running",
        ):
            yield

    @contextmanager
    def _global_rollback_proof_lock(self, migration_root: Path) -> Iterator[None]:
        with _advisory_lock(
            migration_root / ".rollback-global.lock",
            "another rollback proof operation is already running",
        ):
            yield

    @staticmethod
    def _rollback_prefix(backup_root: Path, project: str) -> list[str]:
        return [
            "docker",
            "compose",
            "--project-directory",
            str(backup_root),
            "-p",
            project,
            "-f",
            str(backup_root / "rollback.compose.json"),
        ]

    def _validate_resolved_rollback(
        self,
        backup_root: Path,
        definition: dict[str, object],
    ) -> None:
        validate_rollback_definition(definition, backup_root)
        project = str(definition["x-mail-sandbox"]["project"])
        command = self._rollback_prefix(backup_root, project)
        command.extend(["config", "--quiet", "--no-env-resolution"])
        self.runner(command)

    def _rollback_running(self, backup_root: Path, project: str) -> bool:
        command = self._rollback_prefix(backup_root, project)
        command.extend(["ps", "--status", "running", "-q", ROLLBACK_SERVICE])
        return bool(self.runner(command).stdout.strip())

    def _refresh_rollback_data(
        self,
        backup_root: Path,
        expected_manifest: dict[str, object],
    ) -> None:
        _require_directory_0700(backup_root, "source backup")
        source_data = backup_root / "source-data"
        rollback_data = backup_root / "rollback-data"
        next_data = backup_root / ROLLBACK_REFRESH_NEXT_NAME
        previous_data = backup_root / ROLLBACK_REFRESH_PREVIOUS_NAME
        if (
            source_data.parent != backup_root
            or source_data.name != "source-data"
            or rollback_data.parent != backup_root
            or rollback_data.name != "rollback-data"
            or next_data.parent != backup_root
            or next_data.name != ROLLBACK_REFRESH_NEXT_NAME
            or previous_data.parent != backup_root
            or previous_data.name != ROLLBACK_REFRESH_PREVIOUS_NAME
        ):
            raise CaptureError("rollback refresh paths are not exact approved siblings")
        _require_directory_0700(source_data, "archival source data")
        if manifest_tree(source_data) != expected_manifest:
            raise CaptureError("archival source data manifest is partial or mismatched")

        for path, label in (
            (rollback_data, "rollback working data"),
            (next_data, "rollback refresh candidate"),
            (previous_data, "previous rollback working data"),
        ):
            if path.exists() or path.is_symlink():
                _require_directory_0700(path, label)

        if not rollback_data.exists():
            if previous_data.exists():
                os.replace(previous_data, rollback_data)
            elif next_data.exists():
                os.replace(next_data, rollback_data)
            else:
                os.mkdir(rollback_data, 0o700)
            self.directory_sync(backup_root)
        _require_directory_0700(rollback_data, "rollback working data")
        for sibling in (next_data, previous_data):
            if sibling.exists() or sibling.is_symlink():
                _safe_remove_generated_tree(sibling, backup_root)
                self.directory_sync(backup_root)

        try:
            self.tree_copier(source_data, next_data)
            next_data.chmod(0o700)
            _require_directory_0700(next_data, "rollback refresh candidate")
            if manifest_tree(next_data) != expected_manifest:
                raise CaptureError(
                    "rollback working-copy refresh candidate is partial or mismatched",
                )
            self.tree_sync(next_data)
            self.directory_sync(backup_root)
        except BaseException as exc:
            cleanup_error: BaseException | None = None
            if next_data.exists() or next_data.is_symlink():
                try:
                    _safe_remove_generated_tree(next_data, backup_root)
                    self.directory_sync(backup_root)
                except BaseException as cleanup_exc:
                    cleanup_error = cleanup_exc
            if cleanup_error is not None:
                raise CaptureError(
                    "rollback working-copy refresh candidate cleanup failed",
                ) from cleanup_error
            if isinstance(exc, CaptureError):
                raise exc
            raise CaptureError("rollback working-copy refresh failed") from exc

        previous_moved = False
        next_published = False
        try:
            os.replace(rollback_data, previous_data)
            previous_moved = True
            self.directory_sync(backup_root)
            os.replace(next_data, rollback_data)
            next_published = True
            self.directory_sync(backup_root)
            _require_directory_0700(rollback_data, "rollback working data")
            if manifest_tree(rollback_data) != expected_manifest:
                raise CaptureError(
                    "published rollback working-copy manifest is partial or mismatched",
                )
        except BaseException as exc:
            restore_error: BaseException | None = None
            try:
                if previous_moved:
                    if next_published and (
                        rollback_data.exists() or rollback_data.is_symlink()
                    ):
                        _safe_remove_generated_tree(rollback_data, backup_root)
                    os.replace(previous_data, rollback_data)
                    previous_moved = False
                    self.directory_sync(backup_root)
                if next_data.exists() or next_data.is_symlink():
                    _safe_remove_generated_tree(next_data, backup_root)
                    self.directory_sync(backup_root)
            except BaseException as restore_exc:
                restore_error = restore_exc
            if restore_error is not None:
                raise CaptureError(
                    "rollback working-copy publication failed and the old tree "
                    "could not be restored",
                ) from restore_error
            raise CaptureError("rollback working-copy publication failed") from exc

        try:
            _safe_remove_generated_tree(previous_data, backup_root)
            self.directory_sync(backup_root)
        except BaseException as exc:
            raise CaptureError("superseded rollback working-copy cleanup failed") from exc

    @staticmethod
    def _validate_actual_rollback_container(
        record: dict[str, object],
        backup_root: Path,
        definition: dict[str, object],
        expected_image_id: str,
        expected_admin_secret: str,
        expected_running: bool = True,
    ) -> str:
        state = record.get("State")
        config = record.get("Config")
        if (
            not isinstance(state, dict)
            or state.get("Running") is not expected_running
        ):
            raise CaptureError("rollback container running state is unexpected")
        if not isinstance(config, dict):
            raise CaptureError("rollback container config is unavailable")
        project = definition["x-mail-sandbox"]["project"]
        labels = config.get("Labels")
        if (
            not isinstance(labels, dict)
            or labels.get("com.docker.compose.project") != project
            or labels.get("com.docker.compose.service") != ROLLBACK_SERVICE
            or labels.get(ROLLBACK_LABEL_KEY) != ROLLBACK_LABEL_VALUE
        ):
            raise CaptureError("rollback container Compose identity is unsafe")
        if config.get("Image") != definition["services"][ROLLBACK_SERVICE]["image"]:
            raise CaptureError("rollback container did not use the pinned image")
        if record.get("Image") != expected_image_id:
            raise CaptureError("rollback container image ID does not match the captured source")
        try:
            observed_admin_secret = _extract_admin_secret(config.get("Env"))
        except CaptureError as exc:
            raise CaptureError(
                "rollback container environment secret is unavailable",
            ) from exc
        if not secrets.compare_digest(
            observed_admin_secret,
            expected_admin_secret,
        ):
            raise CaptureError(
                "rollback container environment secret does not match the backup",
            )
        mounts = record.get("Mounts")
        if not isinstance(mounts, list) or len(mounts) != 2:
            raise CaptureError("rollback container mounts are unavailable")
        host_config = record.get("HostConfig")
        tmpfs = host_config.get("Tmpfs") if isinstance(host_config, dict) else None
        if not isinstance(tmpfs, dict) or set(tmpfs) != {ROLLBACK_PARENT_TARGET}:
            raise CaptureError("rollback container parent tmpfs is missing")
        tmpfs_options = {
            option
            for option in str(tmpfs[ROLLBACK_PARENT_TARGET]).split(",")
            if option
        }
        if tmpfs_options != {"rw", "noexec", "nosuid", "nodev", "mode=0700"}:
            raise CaptureError("rollback container parent tmpfs options are unsafe")
        expected = {
            ROLLBACK_CONFIG_TARGET: (backup_root / "config.toml", False),
            ROLLBACK_DATA_TARGET: (backup_root / "rollback-data", True),
        }
        observed: set[str] = set()
        for mount in mounts:
            if not isinstance(mount, dict):
                continue
            target = mount.get("Destination")
            if target not in expected:
                raise CaptureError("rollback container has an unexpected mount")
            expected_source, expected_rw = expected[str(target)]
            source = mount.get("Source")
            if (
                mount.get("Type") != "bind"
                or not isinstance(source, str)
                or Path(source).resolve() != expected_source.resolve()
                or mount.get("RW") is not expected_rw
            ):
                raise CaptureError("rollback container mount does not match the backup")
            observed.add(str(target))
        if observed != set(expected):
            raise CaptureError("rollback container mounts are incomplete")
        network = record.get("NetworkSettings")
        mappings = network.get("Ports") if isinstance(network, dict) else None
        networks = network.get("Networks") if isinstance(network, dict) else None
        if (
            not isinstance(networks, dict)
            or len(networks) != 1
            or not isinstance(next(iter(networks.values())), dict)
        ):
            raise CaptureError("rollback container must use exactly one isolated network")
        network_id = next(iter(networks.values())).get("NetworkID")
        if not isinstance(network_id, str) or not SHA256_PATTERN.fullmatch(network_id):
            raise CaptureError("rollback container network identity is invalid")
        port_entries = mappings.get("8443/tcp") if isinstance(mappings, dict) else None
        expected_port = definition["services"][ROLLBACK_SERVICE]["ports"][0]["published"]
        if (
            not isinstance(port_entries, list)
            or len(port_entries) != 1
            or not isinstance(port_entries[0], dict)
            or port_entries[0].get("HostIp") != "127.0.0.1"
            or port_entries[0].get("HostPort") != str(expected_port)
        ):
            raise CaptureError("rollback container port is not isolated on loopback")
        return network_id

    def _validate_actual_rollback_network(self, network_id: str, project: str) -> None:
        record = _single_json_record(
            self.runner(["docker", "network", "inspect", network_id]).stdout,
            "docker network inspect",
        )
        labels = record.get("Labels")
        if (
            record.get("Id") != network_id
            or record.get("Internal") is not False
            or not isinstance(labels, dict)
            or labels.get("com.docker.compose.project") != project
            or labels.get("com.docker.compose.network") != ROLLBACK_NETWORK
        ):
            raise CaptureError("rollback network is not the expected unique Compose bridge")

    def _running_rollback_census(self) -> list[str]:
        result = self.runner(
            [
                "docker",
                "ps",
                "--no-trunc",
                "--filter",
                "status=running",
                "--filter",
                f"label={ROLLBACK_LABEL_KEY}={ROLLBACK_LABEL_VALUE}",
                "--format",
                "{{.ID}}",
            ],
        )
        ids = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        if (
            any(not SHA256_PATTERN.fullmatch(container_id) for container_id in ids)
            or len(ids) != len(set(ids))
        ):
            raise CaptureError("global rollback copy lookup returned unsafe identities")
        return ids

    def _require_running_rollback_census(self, expected_id: str | None) -> None:
        ids = self._running_rollback_census()
        expected = set() if expected_id is None else {expected_id}
        if set(ids) != expected:
            if expected_id is None and ids:
                raise CaptureError("a rollback copy is already running")
            raise CaptureError("global rollback copy census does not match the isolated proof")

    def _prove_backup(
        self,
        backup_root: Path,
        migration_root: Path,
        definition: dict[str, object],
        expected_manifest: dict[str, object],
        admin_username: str,
        admin_secret: str,
        expected_image_id: str,
    ) -> dict[str, object]:
        with self._global_rollback_proof_lock(migration_root):
            result = self._run_verified_rollback_runtime(
                backup_root,
                definition,
                expected_manifest,
                admin_username,
                admin_secret,
                expected_image_id,
                operation=lambda _endpoint: None,
            )
        return result.proof.as_dict()

    def _rollback_container_ids(self, prefix: list[str]) -> list[str]:
        ps = [*prefix, "ps", "--all", "-q", ROLLBACK_SERVICE]
        ids = [
            line.strip()
            for line in self.runner(ps).stdout.splitlines()
            if line.strip()
        ]
        if (
            any(not re.fullmatch(r"[0-9a-f]{12,64}", value) for value in ids)
            or len(ids) != len(set(ids))
        ):
            raise CaptureError(
                "rollback Compose project returned unsafe container identities",
            )
        return ids

    def _rollback_container_id(self, prefix: list[str]) -> str:
        ids = self._rollback_container_ids(prefix)
        if len(ids) != 1:
            raise CaptureError(
                "rollback Compose project did not resolve exactly one container",
            )
        return ids[0]

    def _rollback_version(self, container_id: str) -> str:
        return self.runner(
            [
                "docker",
                "exec",
                container_id,
                "/usr/local/bin/stalwart",
                "--version",
            ],
        ).stdout.strip()

    def _revalidate_verified_rollback(
        self,
        *,
        prefix: list[str],
        expected_container_id: str,
        expected_network_id: str,
        backup_root: Path,
        definition: dict[str, object],
        expected_image_id: str,
        project: str,
        endpoint: VerifiedRollbackEndpoint,
    ) -> None:
        container_id = self._rollback_container_id(prefix)
        if container_id != expected_container_id:
            raise CaptureError("verified rollback container identity changed")
        self._require_running_rollback_census(expected_container_id)
        record = self._inspect_one(expected_container_id)
        network_id = self._validate_actual_rollback_container(
            record,
            backup_root,
            definition,
            expected_image_id,
            endpoint.password,
        )
        if network_id != expected_network_id:
            raise CaptureError("verified rollback network identity changed")
        self._validate_actual_rollback_network(network_id, project)
        observed_version = self._rollback_version(expected_container_id)
        if (
            not VERSION_015_PATTERN.fullmatch(observed_version)
            or observed_version.removeprefix("v") != endpoint.version
        ):
            raise CaptureError("verified rollback version changed during operation")
        management_status = self.management_probe(
            f"{endpoint.base_url}/api/principal?type=individual",
            endpoint.username,
            endpoint.password,
        )
        if management_status != 200:
            raise CaptureError(
                "verified rollback management read failed after operation",
            )

    def _run_verified_rollback_runtime(
        self,
        backup_root: Path,
        definition: dict[str, object],
        expected_manifest: dict[str, object],
        admin_username: str,
        admin_secret: str,
        expected_image_id: str,
        *,
        operation: Callable[[VerifiedRollbackEndpoint], T],
    ) -> VerifiedRollbackResult[T]:
        if not callable(operation):
            raise CaptureError("verified rollback operation must be callable")
        self._require_running_rollback_census(None)
        validate_rollback_definition(definition, backup_root)
        project = str(definition["x-mail-sandbox"]["project"])
        port = int(definition["services"][ROLLBACK_SERVICE]["ports"][0]["published"])
        self._validate_resolved_rollback(backup_root, definition)
        prefix = self._rollback_prefix(backup_root, project)
        if self._rollback_container_ids(prefix):
            raise CaptureError(
                "an isolated rollback Compose container already exists",
            )
        if not self.port_checker(port):
            raise CaptureError("recorded rollback loopback port is already in use")
        self._refresh_rollback_data(backup_root, expected_manifest)
        primary_error: BaseException | None = None
        proof: VerifiedRollbackProof | None = None
        callback_completed = False
        try:
            up = [
                *prefix,
                "up",
                "-d",
                "--pull",
                "never",
                "--no-build",
                "--force-recreate",
                ROLLBACK_SERVICE,
            ]
            self.runner(up)
            container_id = self._rollback_container_id(prefix)
            self._require_running_rollback_census(container_id)
            record = self._inspect_one(container_id)
            network_id = self._validate_actual_rollback_container(
                record,
                backup_root,
                definition,
                expected_image_id,
                admin_secret,
            )
            self._validate_actual_rollback_network(network_id, project)
            deadline = time.monotonic() + 60
            last_version = ""
            management_status = 0
            while time.monotonic() < deadline:
                try:
                    last_version = self._rollback_version(container_id)
                except CaptureError:
                    last_version = ""
                if VERSION_015_PATTERN.fullmatch(last_version):
                    management_status = self.management_probe(
                        f"http://127.0.0.1:{port}/api/principal?type=individual",
                        admin_username,
                        admin_secret,
                    )
                    if management_status == 200:
                        proof = VerifiedRollbackProof(
                            management_status=200,
                            proved_at=self.clock(),
                            version=last_version.removeprefix("v"),
                        )
                        break
                    if management_status in {401, 403}:
                        break
                time.sleep(0.25)
            if proof is None:
                if not VERSION_015_PATTERN.fullmatch(last_version):
                    raise CaptureError("rollback copy did not report a v0.15.x version")
                raise CaptureError(
                    f"rollback management read failed with HTTP status {management_status}",
                )
            endpoint = VerifiedRollbackEndpoint(
                base_url=f"http://127.0.0.1:{port}",
                username=admin_username,
                password=admin_secret,
                version=proof.version,
            )
            callback_value = operation(endpoint)
            callback_completed = True
            self._revalidate_verified_rollback(
                prefix=prefix,
                expected_container_id=container_id,
                expected_network_id=network_id,
                backup_root=backup_root,
                definition=definition,
                expected_image_id=expected_image_id,
                project=project,
                endpoint=endpoint,
            )
        except BaseException as exc:
            primary_error = exc
        cleanup_error: BaseException | None = None
        try:
            self.runner([*prefix, "down"])
            self._require_running_rollback_census(None)
            if self._rollback_container_ids(prefix):
                raise CaptureError(
                    "isolated rollback Compose container remained after cleanup",
                )
            if self._rollback_running(backup_root, project):
                raise CaptureError("isolated rollback container remained running after cleanup")
            self._refresh_rollback_data(backup_root, expected_manifest)
        except BaseException as exc:
            cleanup_error = exc
        if cleanup_error is not None:
            raise CaptureError("isolated rollback cleanup did not complete safely") from cleanup_error
        if primary_error is not None:
            raise primary_error
        assert proof is not None and callback_completed
        return VerifiedRollbackResult(value=callback_value, proof=proof)

    def _build_payload(
        self,
        *,
        source: dict[str, object],
        final_root: Path,
        manifest: dict[str, object],
        config_digest: str,
        definition: dict[str, object],
        proof: dict[str, object],
        compose_digest: str,
        environment_digest: str,
        capture_id: str,
        canonical_latest_receipt: Path,
    ) -> dict[str, object]:
        return {
            "backup": {
                "canonical_latest_receipt": str(canonical_latest_receipt),
                "config_path": "config.toml",
                "environment_path": "rollback.env",
                "environment_sha256": environment_digest,
                "receipt_path": "source-receipt.json",
                "rollback_compose_path": "rollback.compose.json",
                "rollback_compose_sha256": compose_digest,
                "rollback_data_path": "rollback-data",
                "root": str(final_root),
                "source_data_path": "source-data",
            },
            "capture_id": capture_id,
            "captured_at": self.clock(),
            "data_manifest": manifest,
            "rollback": {
                "host_ip": "127.0.0.1",
                "image_digest": source["image_digest"],
                "port": definition["services"][ROLLBACK_SERVICE]["ports"][0]["published"],
                "project": definition["x-mail-sandbox"]["project"],
                "proof": proof,
                "service": ROLLBACK_SERVICE,
            },
            "schema": RECEIPT_SCHEMA,
            "source": {
                "compose_config_files": [
                    str(path) for path in source["compose_config_files"]
                ],
                "compose_project": source["compose_project"],
                "compose_service": source["compose_service"],
                "compose_working_directory": str(source["compose_working_directory"]),
                "config_path": str(source["config_source"]),
                "config_sha256": config_digest,
                "container_id": source["container_id"],
                "data_path": str(source["data_source"]),
                "image_digest": source["image_digest"],
                "image_id": source["image_id"],
                "image_reference": source["image_reference"],
                "stopped": True,
                "version": source["version"],
            },
        }

    @staticmethod
    def _read_existing_latest(path: Path, label: str) -> bytes | None:
        if path.is_symlink():
            raise CaptureError(f"{label} must not be a symlink")
        if not path.exists():
            return None
        _require_regular_0600(path, label)
        return path.read_bytes()

    def _restore_latest(self, path: Path, previous: bytes | None) -> None:
        if previous is None:
            if path.is_symlink():
                path.unlink()
                self.directory_sync(path.parent)
            elif path.exists():
                _require_regular(path, "failed latest source receipt")
                path.unlink()
                self.directory_sync(path.parent)
            return
        if path.is_symlink():
            path.unlink()
            self.directory_sync(path.parent)
        write_bytes_0600_atomic(path, previous)

    def _publish_latest_receipts(
        self,
        envelope: dict[str, object],
        canonical_latest: Path,
        previous_canonical: bytes | None,
        previous_local: bytes | None,
    ) -> Path:
        ensure_owner_directory(self.runtime_root)
        ensure_owner_directory(self.migration_root)
        targets = (canonical_latest, self.latest_receipt)
        previous = {
            canonical_latest: previous_canonical,
            self.latest_receipt: previous_local,
        }
        try:
            for target in targets:
                self.receipt_writer(target, envelope)
                _require_regular_0600(target, "latest source receipt")
                try:
                    published = json.loads(target.read_text(encoding="utf-8"))
                except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise CaptureError("published latest source receipt is invalid") from exc
                if published != envelope:
                    raise CaptureError("published latest source receipt does not match")
            self.verify(canonical_latest)
            self.verify(self.latest_receipt)
        except BaseException as exc:
            cleanup_error: BaseException | None = None
            for target in reversed(targets):
                try:
                    self._restore_latest(target, previous[target])
                except BaseException as restore_exc:
                    cleanup_error = cleanup_error or restore_exc
            if cleanup_error is not None:
                raise CaptureError(
                    "latest source receipt publication cleanup failed",
                ) from cleanup_error
            raise CaptureError("latest source receipt publication failed") from exc
        return self.latest_receipt

    def capture(self, source_service: str) -> Path:
        initial_source = self.resolve_source_service(source_service)
        source_root = Path(initial_source["compose_working_directory"])
        (
            _canonical_runtime,
            canonical_backups,
            canonical_migration,
            canonical_latest,
        ) = self._validate_canonical_storage(source_root, create=True)
        source: dict[str, object] | None = None
        stop_attempted = False
        partial_root: Path | None = None
        promoted = False
        with self._capture_lock(canonical_migration):
            try:
                source = self.resolve_source_service(source_service)
                if (
                    source["container_id"] != initial_source["container_id"]
                    or source["compose_working_directory"]
                    != initial_source["compose_working_directory"]
                    or source["image_id"] != initial_source["image_id"]
                    or source["image_digest"] != initial_source["image_digest"]
                ):
                    raise CaptureError("source identity changed before the canonical capture lock")
                previous_canonical = self._read_existing_latest(
                    canonical_latest,
                    "existing canonical latest source receipt",
                )
                previous_local = self._read_existing_latest(
                    self.latest_receipt,
                    "existing local latest source receipt",
                )
                capture_id = f"{self.clock()}-{self.nonce()}"
                final_name = f"stalwart-v015-{capture_id}"
                if not BACKUP_NAME_PATTERN.fullmatch(final_name):
                    raise CaptureError("generated backup identity is invalid")
                final_root = canonical_backups / final_name
                partial_root = canonical_backups / f".partial-{capture_id}"
                if (
                    final_root.exists()
                    or final_root.is_symlink()
                    or partial_root.exists()
                    or partial_root.is_symlink()
                ):
                    raise CaptureError("generated capture target already exists")
                partial_root.mkdir(mode=0o700)
                self.directory_sync(canonical_backups)
                _require_directory_0700(partial_root, "partial backup directory")
                stop_attempted = True
                self._stop_source(source)
                config_source = Path(source["config_source"])
                data_source = Path(source["data_source"])
                config_before = sha256_file(config_source)
                manifest_before = manifest_tree(data_source)
                config_copy = partial_root / "config.toml"
                try:
                    copy_regular_file_0600(config_source, config_copy)
                    self.tree_copier(data_source, partial_root / "source-data")
                except (OSError, shutil.Error, CaptureError) as exc:
                    raise CaptureError("stopped source copy failed or was partial") from exc
                (partial_root / "source-data").chmod(0o700)
                copied_manifest = manifest_tree(partial_root / "source-data")
                self._require_source_stopped(source)
                config_after = sha256_file(config_source)
                manifest_after = manifest_tree(data_source)
                if (
                    config_before != config_after
                    or config_before != sha256_file(config_copy)
                    or manifest_before != manifest_after
                    or manifest_before != copied_manifest
                ):
                    raise CaptureError("stopped source changed or backup manifest is partial")
                self.tree_copier(
                    partial_root / "source-data",
                    partial_root / "rollback-data",
                )
                (partial_root / "rollback-data").chmod(0o700)
                if manifest_tree(partial_root / "rollback-data") != manifest_before:
                    raise CaptureError("rollback working-copy manifest is partial")
                environment = f"ADMIN_SECRET={source['admin_secret']}\n".encode("utf-8")
                write_bytes_0600_atomic(partial_root / "rollback.env", environment)
                port = self.port_allocator(set(ROLLBACK_EXCLUDED_PORTS))
                if (
                    not isinstance(port, int)
                    or port <= 1024
                    or port > 65535
                    or port in ROLLBACK_EXCLUDED_PORTS
                    or not self.port_checker(port)
                ):
                    raise CaptureError("allocated rollback port is not safely available")
                project = f"mail-sandbox-stalwart-rollback-{self.nonce()}"
                definition = build_rollback_definition(
                    image_digest=str(source["image_digest"]),
                    port=port,
                    project=project,
                )
                validate_rollback_definition(definition, partial_root)
                compose_path = partial_root / "rollback.compose.json"
                write_json_0600_atomic(compose_path, definition)
                proof = self._prove_backup(
                    partial_root,
                    canonical_migration,
                    definition,
                    manifest_before,
                    str(source["admin_username"]),
                    str(source["admin_secret"]),
                    str(source["image_id"]),
                )
                self._require_source_stopped(source)
                if (
                    manifest_tree(data_source) != manifest_before
                    or sha256_file(config_source) != config_before
                ):
                    raise CaptureError("source changed after it was stopped")
                payload = self._build_payload(
                    source=source,
                    final_root=final_root,
                    manifest=manifest_before,
                    config_digest=config_before,
                    definition=definition,
                    proof=proof,
                    compose_digest=sha256_file(compose_path),
                    environment_digest=sha256_file(partial_root / "rollback.env"),
                    capture_id=capture_id,
                    canonical_latest_receipt=canonical_latest,
                )
                envelope = make_receipt_envelope(payload)
                self.receipt_writer(partial_root / "source-receipt.json", envelope)
                self.tree_sync(partial_root)
                os.replace(partial_root, final_root)
                promoted = True
                self.directory_sync(canonical_backups)
                self.verify(final_root / "source-receipt.json")
                self._require_source_stopped(source)
                return self._publish_latest_receipts(
                    envelope,
                    canonical_latest,
                    previous_canonical,
                    previous_local,
                )
            finally:
                stop_error: BaseException | None = None
                if stop_attempted and source is not None:
                    try:
                        self._ensure_source_stopped(source)
                    except BaseException as exc:
                        stop_error = exc
                cleanup_error: BaseException | None = None
                if (
                    partial_root is not None
                    and not promoted
                    and (partial_root.exists() or partial_root.is_symlink())
                ):
                    try:
                        _safe_remove_generated_tree(partial_root, canonical_backups)
                        self.directory_sync(canonical_backups)
                    except BaseException as exc:
                        cleanup_error = exc
                if stop_error is not None:
                    raise CaptureError("source stopped invariant could not be restored") from stop_error
                if cleanup_error is not None:
                    raise CaptureError("partial capture cleanup failed safely") from cleanup_error

    def _read_receipt(
        self,
        receipt_path: Path,
    ) -> tuple[Path, bytes, dict[str, object], dict[str, object]]:
        candidate = Path(receipt_path)
        if not candidate.is_absolute():
            candidate = self.repository_root / candidate
        candidate = Path(os.path.abspath(candidate))
        _require_regular_0600(candidate, "source receipt")
        content = read_regular_bytes(
            candidate,
            "source receipt",
            maximum=50 * 1024 * 1024,
        )
        try:
            envelope = json.loads(content.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CaptureError("source receipt is not valid JSON") from exc
        payload = validate_receipt_envelope(envelope)
        if payload.get("schema") != RECEIPT_SCHEMA:
            raise CaptureError("source receipt schema is unsupported")
        return candidate, content, envelope, payload

    def _validate_recorded_source(
        self,
        source: dict[str, object],
        expected_manifest: dict[str, object],
    ) -> None:
        required_string_fields = (
            "compose_project",
            "compose_service",
            "compose_working_directory",
            "config_path",
            "config_sha256",
            "container_id",
            "data_path",
            "image_digest",
            "image_id",
            "image_reference",
            "version",
        )
        if any(not isinstance(source.get(field), str) for field in required_string_fields):
            raise CaptureError("receipt source identity is incomplete")
        if source.get("stopped") is not True:
            raise CaptureError("receipt does not bind a stopped source")
        if not re.fullmatch(r"[0-9a-f]{64}", str(source["container_id"])):
            raise CaptureError("receipt source container identity is invalid")
        if (
            not str(source["image_id"]).startswith("sha256:")
            or not SHA256_PATTERN.fullmatch(str(source["image_id"])[7:])
        ):
            raise CaptureError("receipt source image ID is invalid")
        if not SHA256_PATTERN.fullmatch(str(source["config_sha256"])):
            raise CaptureError("receipt source TOML digest is invalid")
        if not VERSION_015_PATTERN.fullmatch(str(source["version"])):
            raise CaptureError("receipt source version is not v0.15.x")
        if not is_pinned_image(source["image_digest"]):
            raise CaptureError("receipt source image digest is not immutable")
        if not PROJECT_PATTERN.fullmatch(str(source["compose_project"])):
            raise CaptureError("receipt source Compose project is unsafe")
        if not SERVICE_PATTERN.fullmatch(str(source["compose_service"])):
            raise CaptureError("receipt source Compose service is unsafe")
        working_directory = _require_plain_absolute(
            Path(str(source["compose_working_directory"])),
            "receipt source working directory",
        )
        config_path = _require_plain_absolute(
            Path(str(source["config_path"])),
            "receipt source config",
        )
        data_path = _require_plain_absolute(
            Path(str(source["data_path"])),
            "receipt source data",
        )
        if (
            config_path != working_directory / "stalwart" / "config.toml"
            or data_path != working_directory / "stalwart-data"
        ):
            raise CaptureError("receipt source paths do not match the legacy runtime model")
        _require_no_symlink_components(
            working_directory,
            "receipt source working directory",
            allow_missing=True,
        )
        _require_no_symlink_components(
            config_path,
            "receipt source config",
            allow_missing=True,
        )
        _require_no_symlink_components(
            data_path,
            "receipt source data",
            allow_missing=True,
        )
        config_files = source.get("compose_config_files")
        if config_files != [str(working_directory / "docker-compose.yml")]:
            raise CaptureError("receipt source Compose files are missing")
        for raw in config_files:
            if not isinstance(raw, str):
                raise CaptureError("receipt source Compose file is malformed")
            config_file = _require_plain_absolute(Path(raw), "receipt source Compose file")
            _require_no_symlink_components(
                config_file,
                "receipt source Compose file",
                allow_missing=True,
            )
        image_record = _single_json_record(
            self.runner(["docker", "image", "inspect", str(source["image_id"])]).stdout,
            "docker image inspect",
        )
        repo_digests = image_record.get("RepoDigests")
        if (
            image_record.get("Id") != source["image_id"]
            or not isinstance(repo_digests, list)
            or source["image_digest"] not in repo_digests
        ):
            raise CaptureError("recorded immutable source image is unavailable")
        try:
            record = self._inspect_one(str(source["container_id"]))
        except CommandError:
            lookup = self.runner(
                [
                    "docker",
                    "ps",
                    "-a",
                    "--no-trunc",
                    "--filter",
                    f"id={source['container_id']}",
                    "--format",
                    "{{.ID}}",
                ],
            )
            if lookup.stdout.strip():
                raise CaptureError("recorded source container could not be inspected")
        else:
            state = record.get("State")
            config = record.get("Config")
            if not isinstance(state, dict) or state.get("Running") is not False:
                raise CaptureError("recorded source container must remain stopped")
            if not isinstance(config, dict):
                raise CaptureError("recorded source container config is unavailable")
            labels = config.get("Labels")
            if (
                not isinstance(labels, dict)
                or labels.get("com.docker.compose.project") != source["compose_project"]
                or labels.get("com.docker.compose.service") != source["compose_service"]
                or labels.get("com.docker.compose.project.working_dir")
                != source["compose_working_directory"]
                or labels.get("com.docker.compose.project.config_files")
                != ",".join(config_files)
            ):
                raise CaptureError("recorded source Compose identity no longer matches")
            if (
                config.get("Image") != source["image_reference"]
                or record.get("Image") != source["image_id"]
            ):
                raise CaptureError("recorded source image identity no longer matches")
            config_mount = self._mount_by_target(record, LEGACY_CONFIG_TARGET)
            data_mount = self._mount_by_target(record, LEGACY_DATA_TARGET)
            if (
                not isinstance(config_mount, dict)
                or config_mount.get("Source") != str(config_path)
                or config_mount.get("RW") is not False
                or not isinstance(data_mount, dict)
                or data_mount.get("Source") != str(data_path)
                or data_mount.get("RW") is not True
            ):
                raise CaptureError("recorded source mounts no longer match")
        self._validate_running_stalwart_writers(source, config_files)

    def _validate_running_stalwart_writers(
        self,
        source: dict[str, object],
        config_files: list[str],
    ) -> None:
        result = self.runner(
            [
                "docker",
                "ps",
                "--no-trunc",
                "--filter",
                "status=running",
                "--format",
                "{{.ID}}",
            ],
        )
        ids = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        if (
            any(not SHA256_PATTERN.fullmatch(container_id) for container_id in ids)
            or len(ids) != len(set(ids))
        ):
            raise CaptureError("running Stalwart lookup returned unsafe identities")
        records = self._inspect_many(ids)
        observed_ids = [record.get("Id") for record in records]
        if len(records) != len(ids) or set(observed_ids) != set(ids):
            raise CaptureError("running Stalwart identities changed during inspection")
        working_directory = Path(str(source["compose_working_directory"]))
        legacy_config = Path(str(source["config_path"]))
        data_path = Path(str(source["data_path"]))
        v016_config_root = working_directory / "stalwart"
        v016_legacy_child_config = v016_config_root / "config.json"
        protected_store_paths = {
            legacy_config,
            data_path,
            v016_config_root,
            v016_legacy_child_config,
        }
        for record in records:
            state = record.get("State")
            config = record.get("Config")
            mounts = record.get("Mounts")
            if (
                not isinstance(state, dict)
                or state.get("Running") is not True
                or not isinstance(config, dict)
                or not isinstance(mounts, list)
                or not all(isinstance(mount, dict) for mount in mounts)
            ):
                raise CaptureError("running Stalwart candidate is malformed")
            mount_sources: set[Path] = set()
            writable_mount_sources: set[Path] = set()
            for mount in mounts:
                raw_source = mount.get("Source")
                if raw_source == "":
                    continue
                if not isinstance(raw_source, str):
                    if mount.get("RW") is True:
                        raise CaptureError("running Stalwart candidate is malformed")
                    continue
                normalized_source = Path(os.path.normpath(raw_source))
                if not normalized_source.is_absolute():
                    if mount.get("RW") is True:
                        raise CaptureError(
                            "running writable mount source must be an absolute path",
                        )
                    continue
                mount_sources.add(normalized_source)
                if mount.get("RW") is True:
                    writable_mount_sources.add(normalized_source)
            uses_captured_image = (
                record.get("Image") == source["image_id"]
                or config.get("Image") in {source["image_reference"], source["image_digest"]}
            )
            touches_recorded_store = (
                bool(mount_sources.intersection(protected_store_paths))
                or any(
                    _paths_overlap(mount_source, protected_path)
                    for mount_source in writable_mount_sources
                    for protected_path in protected_store_paths
                )
            )
            if not uses_captured_image and not touches_recorded_store:
                continue
            labels = config.get("Labels")
            expected_mounts = {
                V016_CONFIG_ROOT_TARGET: (v016_config_root, False),
                V016_DATA_TARGET: (data_path, True),
            }
            observed_mounts: dict[str, tuple[Path, object]] = {}
            exact_bind_set = len(mounts) == len(expected_mounts)
            for mount in mounts:
                destination = mount.get("Destination")
                raw_source = mount.get("Source")
                if (
                    not isinstance(destination, str)
                    or not isinstance(raw_source, str)
                    or mount.get("Type") != "bind"
                    or destination in observed_mounts
                ):
                    exact_bind_set = False
                    observed_mounts = {}
                    break
                observed_mounts[destination] = (Path(raw_source), mount.get("RW"))
            exact_v016 = (
                config.get("Image") == V016_IMAGE_REFERENCE
                and isinstance(record.get("Image"), str)
                and str(record["Image"]).startswith("sha256:")
                and SHA256_PATTERN.fullmatch(str(record["Image"])[7:]) is not None
                and isinstance(labels, dict)
                and labels.get("com.docker.compose.project") == source["compose_project"]
                and labels.get("com.docker.compose.service") == source["compose_service"]
                and labels.get("com.docker.compose.project.working_dir")
                == source["compose_working_directory"]
                and labels.get("com.docker.compose.project.config_files")
                == ",".join(config_files)
                and exact_bind_set
                and observed_mounts == expected_mounts
            )
            if not exact_v016:
                raise CaptureError("a legacy or unsafe Stalwart writer is running on the recorded store")

    def _verify_parsed_receipt(
        self,
        receipt: Path,
        envelope: dict[str, object],
        payload: dict[str, object],
        *,
        require_clean_rollback_data: bool = True,
    ) -> dict[str, object]:
        backup = payload.get("backup")
        rollback = payload.get("rollback")
        source = payload.get("source")
        manifest = payload.get("data_manifest")
        capture_id = payload.get("capture_id")
        if (
            not isinstance(backup, dict)
            or not isinstance(rollback, dict)
            or not isinstance(source, dict)
            or not isinstance(manifest, dict)
            or not isinstance(capture_id, str)
        ):
            raise CaptureError("source receipt payload is incomplete")
        source_working_value = source.get("compose_working_directory")
        if not isinstance(source_working_value, str):
            raise CaptureError("source receipt has no canonical source checkout")
        source_root = _require_plain_absolute(
            Path(source_working_value),
            "receipt canonical source checkout",
        )
        (
            canonical_runtime,
            canonical_backups,
            canonical_migration,
            canonical_latest,
        ) = self._validate_canonical_storage(source_root, create=False)
        expected_backup_name = f"stalwart-v015-{capture_id}"
        if (
            not BACKUP_NAME_PATTERN.fullmatch(expected_backup_name)
            or backup.get("root") != str(canonical_backups / expected_backup_name)
        ):
            raise CaptureError("source receipt backup path is outside the approved root")
        backup_root = Path(str(backup["root"]))
        if backup_root.parent != canonical_backups:
            raise CaptureError("source receipt backup path is too broad")
        _require_directory_0700(canonical_runtime, "canonical capture directory")
        _require_directory_0700(canonical_backups, "canonical Stalwart backups directory")
        _require_directory_0700(canonical_migration, "canonical Stalwart migration directory")
        _require_components_below(canonical_backups, backup_root, "source backup")
        _require_directory_0700(backup_root, "source backup")
        expected_paths = {
            "canonical_latest_receipt": str(canonical_latest),
            "config_path": "config.toml",
            "environment_path": "rollback.env",
            "receipt_path": "source-receipt.json",
            "rollback_compose_path": "rollback.compose.json",
            "rollback_data_path": "rollback-data",
            "source_data_path": "source-data",
        }
        if any(backup.get(key) != value for key, value in expected_paths.items()):
            raise CaptureError("source receipt artifact paths are malformed")
        backup_receipt = backup_root / "source-receipt.json"
        allowed_receipts = {self.latest_receipt, canonical_latest, backup_receipt}
        if receipt not in allowed_receipts:
            raise CaptureError("receipt path is not the approved latest or backup receipt")
        if receipt == self.latest_receipt:
            _require_directory_0700(self.runtime_root, "local dashboard runtime directory")
            _require_directory_0700(self.migration_root, "Stalwart migration directory")
        _require_regular_0600(backup_receipt, "backup source receipt")
        try:
            backup_envelope = json.loads(backup_receipt.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CaptureError("backup source receipt is invalid") from exc
        validate_receipt_envelope(backup_envelope)
        if backup_envelope != envelope:
            raise CaptureError("latest and backup source receipts do not match")
        if receipt != backup_receipt:
            _require_regular_0600(canonical_latest, "canonical latest source receipt")
            try:
                canonical_envelope = json.loads(canonical_latest.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise CaptureError("canonical latest source receipt is invalid") from exc
            validate_receipt_envelope(canonical_envelope)
            if canonical_envelope != envelope:
                raise CaptureError("local and canonical latest source receipts do not match")
        config_copy = backup_root / "config.toml"
        environment_file = backup_root / "rollback.env"
        compose_file = backup_root / "rollback.compose.json"
        source_data = backup_root / "source-data"
        rollback_data = backup_root / "rollback-data"
        for path, label in (
            (config_copy, "backup TOML"),
            (environment_file, "rollback secret file"),
            (compose_file, "rollback definition"),
        ):
            _require_regular_0600(path, label)
        _require_directory_0700(source_data, "archival source data")
        if require_clean_rollback_data or rollback_data.exists() or rollback_data.is_symlink():
            _require_directory_0700(rollback_data, "rollback working data")
        if sha256_file(config_copy) != source.get("config_sha256"):
            raise CaptureError("backup TOML digest does not match the receipt")
        if sha256_file(environment_file) != backup.get("environment_sha256"):
            raise CaptureError("rollback environment digest does not match the receipt")
        if sha256_file(compose_file) != backup.get("rollback_compose_sha256"):
            raise CaptureError("rollback definition digest does not match the receipt")
        if manifest_tree(source_data) != manifest:
            raise CaptureError("archival source data manifest does not match the receipt")
        if require_clean_rollback_data and manifest_tree(rollback_data) != manifest:
            raise CaptureError("rollback working data manifest does not match the receipt")
        try:
            definition = json.loads(compose_file.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CaptureError("rollback definition is not valid JSON") from exc
        validate_rollback_definition(definition, backup_root)
        definition_service = definition["services"][ROLLBACK_SERVICE]
        definition_port = definition_service["ports"][0]["published"]
        if (
            rollback.get("service") != ROLLBACK_SERVICE
            or rollback.get("project") != definition["x-mail-sandbox"]["project"]
            or rollback.get("host_ip") != "127.0.0.1"
            or rollback.get("port") != definition_port
            or rollback.get("image_digest") != definition_service["image"]
            or rollback.get("image_digest") != source.get("image_digest")
        ):
            raise CaptureError("rollback receipt fields do not match the pinned definition")
        proof = rollback.get("proof")
        if (
            not isinstance(proof, dict)
            or proof.get("management_status") != 200
            or not isinstance(proof.get("version"), str)
            or not VERSION_015_PATTERN.fullmatch(str(proof["version"]))
        ):
            raise CaptureError("rollback proof is missing or invalid")
        try:
            environment_lines = environment_file.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError) as exc:
            raise CaptureError("rollback secret file cannot be read safely") from exc
        if (
            len(environment_lines) != 1
            or not environment_lines[0].startswith("ADMIN_SECRET=")
            or not environment_lines[0].split("=", 1)[1]
        ):
            raise CaptureError("rollback secret file is malformed")
        self._validate_recorded_source(source, manifest)
        return payload

    def verify(self, receipt_path: Path) -> dict[str, object]:
        receipt, _content, envelope, payload = self._read_receipt(receipt_path)
        return self._verify_parsed_receipt(receipt, envelope, payload)

    def _verify_bound_receipt(
        self,
        receipt_path: Path,
        *,
        expected_receipt_sha256: str,
        expected_content: bytes | None = None,
        require_clean_rollback_data: bool = True,
    ) -> tuple[Path, bytes, dict[str, object]]:
        if (
            not isinstance(expected_receipt_sha256, str)
            or not SHA256_PATTERN.fullmatch(expected_receipt_sha256)
        ):
            raise CaptureError("expected receipt SHA-256 digest is invalid")
        receipt, content, envelope, payload = self._read_receipt(receipt_path)
        observed = sha256_bytes(content)
        if not secrets.compare_digest(observed, expected_receipt_sha256):
            raise CaptureError("source receipt digest does not match the expected receipt")
        if expected_content is not None and not secrets.compare_digest(
            content,
            expected_content,
        ):
            raise CaptureError("source receipt bytes changed after they were bound")
        return (
            receipt,
            content,
            self._verify_parsed_receipt(
                receipt,
                envelope,
                payload,
                require_clean_rollback_data=require_clean_rollback_data,
            ),
        )

    @staticmethod
    def _activation_proof_path(backup_root: Path) -> Path:
        proof_path = backup_root / ROLLBACK_ACTIVATION_NAME
        if (
            proof_path.parent != backup_root
            or proof_path.name != ROLLBACK_ACTIVATION_NAME
        ):
            raise CaptureError("rollback activation proof path is unsafe")
        return proof_path

    @staticmethod
    def _activation_intent_path(backup_root: Path) -> Path:
        intent_path = backup_root / ROLLBACK_ACTIVATION_INTENT_NAME
        if (
            intent_path.parent != backup_root
            or intent_path.name != ROLLBACK_ACTIVATION_INTENT_NAME
        ):
            raise CaptureError("rollback activation intent path is unsafe")
        return intent_path

    def _build_activation_intent(
        self,
        *,
        payload: dict[str, object],
        expected_receipt_sha256: str,
    ) -> dict[str, object]:
        backup = payload["backup"]
        rollback = payload["rollback"]
        source = payload["source"]
        return {
            "attempted_at": self.clock(),
            "backup_root": str(backup["root"]),
            "base_url": f"http://127.0.0.1:{rollback['port']}",
            "config_sha256": source["config_sha256"],
            "environment_sha256": backup["environment_sha256"],
            "image_digest": source["image_digest"],
            "image_id": source["image_id"],
            "project": rollback["project"],
            "rollback_compose_sha256": backup["rollback_compose_sha256"],
            "schema": ROLLBACK_ACTIVATION_INTENT_SCHEMA,
            "service": ROLLBACK_SERVICE,
            "source_manifest_sha256": sha256_bytes(
                _canonical_json_bytes(payload["data_manifest"]),
            ),
            "source_receipt_sha256": expected_receipt_sha256,
        }

    def _read_activation_intent(
        self,
        intent_path: Path,
        *,
        payload: dict[str, object],
        expected_receipt_sha256: str,
    ) -> tuple[dict[str, object], bytes]:
        _require_regular_0600(intent_path, "rollback activation intent")
        content = read_regular_bytes(
            intent_path,
            "rollback activation intent",
            maximum=1024 * 1024,
        )
        try:
            envelope = json.loads(content.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CaptureError("rollback activation intent is not valid JSON") from exc
        intent = validate_receipt_envelope(envelope)
        expected = self._build_activation_intent(
            payload=payload,
            expected_receipt_sha256=expected_receipt_sha256,
        )
        expected_fields = set(expected)
        if set(intent) != expected_fields:
            raise CaptureError("rollback activation intent identity is malformed")
        expected.pop("attempted_at")
        if any(intent.get(key) != value for key, value in expected.items()):
            raise CaptureError(
                "rollback activation intent identity does not match the source receipt",
            )
        if not isinstance(intent.get("attempted_at"), str) or not intent["attempted_at"]:
            raise CaptureError("rollback activation intent identity is malformed")
        return intent, content

    @staticmethod
    def _build_activation_payload(
        *,
        payload: dict[str, object],
        expected_receipt_sha256: str,
        container_id: str,
        network_id: str,
        proof: VerifiedRollbackProof,
    ) -> dict[str, object]:
        backup = payload["backup"]
        rollback = payload["rollback"]
        source = payload["source"]
        return {
            "activated_at": proof.proved_at,
            "backup_root": str(backup["root"]),
            "base_url": f"http://127.0.0.1:{rollback['port']}",
            "container_id": container_id,
            "image_digest": source["image_digest"],
            "image_id": source["image_id"],
            "management_status": proof.management_status,
            "network_id": network_id,
            "project": rollback["project"],
            "schema": ROLLBACK_ACTIVATION_SCHEMA,
            "service": ROLLBACK_SERVICE,
            "source_receipt_sha256": expected_receipt_sha256,
            "version": proof.version,
        }

    @staticmethod
    def _read_rollback_runtime_inputs(
        backup_root: Path,
    ) -> tuple[dict[str, object], str, str]:
        compose_file = backup_root / "rollback.compose.json"
        try:
            definition = json.loads(
                read_regular_bytes(
                    compose_file,
                    "rollback definition",
                    maximum=4 * 1024 * 1024,
                ).decode("utf-8"),
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CaptureError("rollback definition is not valid JSON") from exc
        environment_lines = read_regular_bytes(
            backup_root / "rollback.env",
            "rollback secret file",
            maximum=64 * 1024,
        ).decode("utf-8").splitlines()
        if (
            len(environment_lines) != 1
            or not environment_lines[0].startswith("ADMIN_SECRET=")
            or not environment_lines[0].split("=", 1)[1]
        ):
            raise CaptureError("rollback secret file is malformed")
        return (
            definition,
            _parse_admin_config(backup_root / "config.toml"),
            environment_lines[0].split("=", 1)[1],
        )

    def _read_activation_proof(
        self,
        proof_path: Path,
        *,
        payload: dict[str, object],
        expected_receipt_sha256: str,
    ) -> tuple[dict[str, object], bytes]:
        _require_regular_0600(proof_path, "rollback activation proof")
        content = read_regular_bytes(
            proof_path,
            "rollback activation proof",
            maximum=1024 * 1024,
        )
        try:
            envelope = json.loads(content.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CaptureError("rollback activation proof is not valid JSON") from exc
        activation = validate_receipt_envelope(envelope)
        expected_fields = {
            "activated_at",
            "backup_root",
            "base_url",
            "container_id",
            "image_digest",
            "image_id",
            "management_status",
            "network_id",
            "project",
            "schema",
            "service",
            "source_receipt_sha256",
            "version",
        }
        if set(activation) != expected_fields:
            raise CaptureError("rollback activation proof identity is malformed")
        backup_root = Path(str(payload["backup"]["root"]))
        rollback = payload["rollback"]
        source = payload["source"]
        expected_base_url = (
            f"http://127.0.0.1:{rollback['port']}"
        )
        expected_identity = {
            "backup_root": str(backup_root),
            "base_url": expected_base_url,
            "image_digest": source["image_digest"],
            "image_id": source["image_id"],
            "management_status": 200,
            "project": rollback["project"],
            "schema": ROLLBACK_ACTIVATION_SCHEMA,
            "service": ROLLBACK_SERVICE,
            "source_receipt_sha256": expected_receipt_sha256,
            "version": str(source["version"]).removeprefix("v"),
        }
        if any(
            activation.get(key) != value
            for key, value in expected_identity.items()
        ):
            raise CaptureError(
                "rollback activation proof identity does not match the source receipt",
            )
        if (
            not isinstance(activation.get("activated_at"), str)
            or not activation["activated_at"]
            or not isinstance(activation.get("container_id"), str)
            or not SHA256_PATTERN.fullmatch(str(activation["container_id"]))
            or not isinstance(activation.get("network_id"), str)
            or not SHA256_PATTERN.fullmatch(str(activation["network_id"]))
        ):
            raise CaptureError("rollback activation proof identity is malformed")
        return activation, content

    def _remove_activation_proof(
        self,
        proof_path: Path,
        *,
        expected_content: bytes | None = None,
    ) -> None:
        if proof_path.is_symlink():
            raise CaptureError("rollback activation proof must not be a symlink")
        _require_regular_0600(proof_path, "rollback activation proof")
        if expected_content is not None:
            observed = read_regular_bytes(
                proof_path,
                "rollback activation proof",
                maximum=1024 * 1024,
            )
            if not secrets.compare_digest(observed, expected_content):
                raise CaptureError(
                    "rollback activation proof changed during deactivation",
                )
        proof_path.unlink()
        self.directory_sync(proof_path.parent)

    def _remove_activation_intent(
        self,
        intent_path: Path,
        *,
        expected_content: bytes | None = None,
    ) -> None:
        if intent_path.is_symlink():
            raise CaptureError("rollback activation intent must not be a symlink")
        _require_regular_0600(intent_path, "rollback activation intent")
        if expected_content is not None:
            observed = read_regular_bytes(
                intent_path,
                "rollback activation intent",
                maximum=1024 * 1024,
            )
            if not secrets.compare_digest(observed, expected_content):
                raise CaptureError(
                    "rollback activation intent changed during reconciliation",
                )
        intent_path.unlink()
        self.directory_sync(intent_path.parent)

    def _discard_failed_activation_proof(
        self,
        proof_path: Path,
    ) -> None:
        try:
            metadata = proof_path.lstat()
        except FileNotFoundError:
            return
        if stat.S_ISDIR(metadata.st_mode):
            raise CaptureError(
                "failed rollback activation left an unsafe proof directory",
            )
        proof_path.unlink()
        self.directory_sync(proof_path.parent)

    def _prove_activation_runtime(
        self,
        *,
        prefix: list[str],
        container_id: str,
        backup_root: Path,
        definition: dict[str, object],
        expected_image_id: str,
        project: str,
        port: int,
        admin_username: str,
        admin_secret: str,
    ) -> tuple[VerifiedRollbackProof, VerifiedRollbackEndpoint, str]:
        network_id = self._rebind_verified_rollback_structure(
            prefix=prefix,
            expected_container_id=container_id,
            expected_network_id=None,
            backup_root=backup_root,
            definition=definition,
            expected_image_id=expected_image_id,
            expected_admin_secret=admin_secret,
            project=project,
        )
        proof, endpoint = self._prove_activation_runtime_health(
            container_id=container_id,
            port=port,
            admin_username=admin_username,
            admin_secret=admin_secret,
        )
        self._revalidate_verified_rollback(
            prefix=prefix,
            expected_container_id=container_id,
            expected_network_id=network_id,
            backup_root=backup_root,
            definition=definition,
            expected_image_id=expected_image_id,
            project=project,
            endpoint=endpoint,
        )
        return proof, endpoint, network_id

    def _prove_activation_runtime_health(
        self,
        *,
        container_id: str,
        port: int,
        admin_username: str,
        admin_secret: str,
    ) -> tuple[VerifiedRollbackProof, VerifiedRollbackEndpoint]:
        deadline = time.monotonic() + 60
        last_version = ""
        management_status = 0
        while time.monotonic() < deadline:
            try:
                last_version = self._rollback_version(container_id)
            except CaptureError:
                last_version = ""
            if VERSION_015_PATTERN.fullmatch(last_version):
                management_status = self.management_probe(
                    (
                        f"http://127.0.0.1:{port}"
                        "/api/principal?type=individual"
                    ),
                    admin_username,
                    admin_secret,
                )
                if management_status == 200:
                    break
                if management_status in {401, 403}:
                    break
            time.sleep(0.25)
        if not VERSION_015_PATTERN.fullmatch(last_version):
            raise CaptureError("rollback copy did not report a v0.15.x version")
        if management_status != 200:
            raise CaptureError(
                "rollback management read failed with HTTP status "
                f"{management_status}",
            )
        proof = VerifiedRollbackProof(
            management_status=200,
            proved_at=self.clock(),
            version=last_version.removeprefix("v"),
        )
        endpoint = VerifiedRollbackEndpoint(
            base_url=f"http://127.0.0.1:{port}",
            username=admin_username,
            password=admin_secret,
            version=proof.version,
        )
        return proof, endpoint

    def _rebind_verified_rollback_structure(
        self,
        *,
        prefix: list[str],
        expected_container_id: str,
        expected_network_id: str | None,
        backup_root: Path,
        definition: dict[str, object],
        expected_image_id: str,
        expected_admin_secret: str,
        project: str,
    ) -> str:
        container_id = self._rollback_container_id(prefix)
        if container_id != expected_container_id:
            raise CaptureError("verified rollback container identity changed")
        self._require_running_rollback_census(expected_container_id)
        record = self._inspect_one(expected_container_id)
        network_id = self._validate_actual_rollback_container(
            record,
            backup_root,
            definition,
            expected_image_id,
            expected_admin_secret,
        )
        if (
            expected_network_id is not None
            and network_id != expected_network_id
        ):
            raise CaptureError("verified rollback network identity changed")
        self._validate_actual_rollback_network(network_id, project)
        return network_id

    def _revalidate_verified_rollback_health(
        self,
        *,
        expected_container_id: str,
        endpoint: VerifiedRollbackEndpoint,
    ) -> None:
        observed_version = self._rollback_version(expected_container_id)
        if (
            not VERSION_015_PATTERN.fullmatch(observed_version)
            or observed_version.removeprefix("v") != endpoint.version
        ):
            raise CaptureError("verified rollback version changed during operation")
        management_status = self.management_probe(
            f"{endpoint.base_url}/api/principal?type=individual",
            endpoint.username,
            endpoint.password,
        )
        if management_status != 200:
            raise CaptureError(
                "verified rollback management read failed after operation",
            )

    def _reconcile_owned_runtime_to_inactive(
        self,
        *,
        prefix: list[str],
        container_id: str,
        network_id: str,
        backup_root: Path,
        definition: dict[str, object],
        expected_image_id: str,
        admin_secret: str,
        project: str,
        expected_manifest: dict[str, object],
        receipt: Path,
        expected_receipt_sha256: str,
        bound_content: bytes,
        proof_path: Path,
        proof_existed_before: bool,
        proof_content: bytes | None,
        proof_write_attempted: bool,
        intent_path: Path,
        intent_content: bytes,
        intent_removal_attempted: bool,
    ) -> None:
        self._rebind_verified_rollback_structure(
            prefix=prefix,
            expected_container_id=container_id,
            expected_network_id=network_id,
            backup_root=backup_root,
            definition=definition,
            expected_image_id=expected_image_id,
            expected_admin_secret=admin_secret,
            project=project,
        )
        try:
            self.runner([*prefix, "down"])
            self._require_running_rollback_census(None)
            if self._rollback_container_ids(prefix):
                raise CaptureError(
                    "isolated rollback Compose container remained "
                    "after reconciliation",
                )
            if self._rollback_running(backup_root, project):
                raise CaptureError(
                    "isolated rollback container remained running "
                    "after reconciliation",
                )
            self._refresh_rollback_data(
                backup_root,
                expected_manifest,
            )
            self._verify_bound_receipt(
                receipt,
                expected_receipt_sha256=expected_receipt_sha256,
                expected_content=bound_content,
            )
            intent_present = intent_path.exists() or intent_path.is_symlink()
            if not intent_present and not intent_removal_attempted:
                raise CaptureError(
                    "rollback activation intent disappeared before an owned "
                    "removal attempt",
                )
            if proof_path.exists() or proof_path.is_symlink():
                if proof_content is not None:
                    self._remove_activation_proof(
                        proof_path,
                        expected_content=proof_content,
                    )
                elif proof_write_attempted and not proof_existed_before:
                    try:
                        self._discard_failed_activation_proof(proof_path)
                    except Exception:
                        # The runtime is already down and refreshed; retry one
                        # transient unlink failure before preserving the intent
                        # and proof artifact.
                        self._discard_failed_activation_proof(proof_path)
                else:
                    raise CaptureError(
                        "an unbound rollback activation proof appeared "
                        "during reconciliation",
                    )
            if intent_present:
                self._remove_activation_intent(
                    intent_path,
                    expected_content=intent_content,
                )
        except BaseException as exc:
            raise CaptureError(
                "rollback reconciliation cleanup did not complete safely",
            ) from exc

    def activate_verified_rollback(
        self,
        receipt_path: Path,
        *,
        expected_receipt_sha256: str,
    ) -> VerifiedRollbackActivation:
        receipt, bound_content, payload = self._verify_bound_receipt(
            receipt_path,
            expected_receipt_sha256=expected_receipt_sha256,
        )
        backup_root = Path(str(payload["backup"]["root"]))
        source_root = Path(str(payload["source"]["compose_working_directory"]))
        _, _, canonical_migration, _ = self._validate_canonical_storage(
            source_root,
            create=False,
        )
        with self._rollback_proof_lock(backup_root):
            with self._global_rollback_proof_lock(canonical_migration):
                _receipt, _locked_content, locked_payload = self._verify_bound_receipt(
                    receipt,
                    expected_receipt_sha256=expected_receipt_sha256,
                    expected_content=bound_content,
                )
                proof_path = self._activation_proof_path(backup_root)
                intent_path = self._activation_intent_path(backup_root)
                if proof_path.exists() or proof_path.is_symlink():
                    raise CaptureError(
                        "a rollback activation proof already exists",
                    )
                if intent_path.exists() or intent_path.is_symlink():
                    raise CaptureError(
                        "a rollback activation intent already exists; "
                        "run reconcile-rollback",
                    )
                definition, admin_username, admin_secret = (
                    self._read_rollback_runtime_inputs(backup_root)
                )
                self._require_running_rollback_census(None)
                validate_rollback_definition(definition, backup_root)
                project = str(definition["x-mail-sandbox"]["project"])
                port = int(
                    definition["services"][ROLLBACK_SERVICE]["ports"][0]["published"],
                )
                self._validate_resolved_rollback(backup_root, definition)
                prefix = self._rollback_prefix(backup_root, project)
                if self._rollback_container_ids(prefix):
                    raise CaptureError(
                        "an isolated rollback Compose container already exists",
                    )
                if not self.port_checker(port):
                    raise CaptureError(
                        "recorded rollback loopback port is already in use",
                    )
                self._refresh_rollback_data(
                    backup_root,
                    locked_payload["data_manifest"],
                )
                up_attempted = False
                intent_write_attempted = False
                intent_content: bytes | None = None
                container_id: str | None = None
                proof_write_attempted = False
                proof_content: bytes | None = None
                primary_error: BaseException | None = None
                try:
                    intent_write_attempted = True
                    self.receipt_writer(
                        intent_path,
                        make_receipt_envelope(
                            self._build_activation_intent(
                                payload=locked_payload,
                                expected_receipt_sha256=expected_receipt_sha256,
                            ),
                        ),
                    )
                    _intent, intent_content = self._read_activation_intent(
                        intent_path,
                        payload=locked_payload,
                        expected_receipt_sha256=expected_receipt_sha256,
                    )
                    up_attempted = True
                    self.runner(
                        [
                            *prefix,
                            "up",
                            "-d",
                            "--pull",
                            "never",
                            "--no-build",
                            "--force-recreate",
                            ROLLBACK_SERVICE,
                        ],
                    )
                    container_id = self._rollback_container_id(prefix)
                    proof, endpoint, network_id = self._prove_activation_runtime(
                        prefix=prefix,
                        container_id=container_id,
                        backup_root=backup_root,
                        definition=definition,
                        expected_image_id=str(
                            locked_payload["source"]["image_id"],
                        ),
                        project=project,
                        port=port,
                        admin_username=admin_username,
                        admin_secret=admin_secret,
                    )
                    self._verify_bound_receipt(
                        receipt,
                        expected_receipt_sha256=expected_receipt_sha256,
                        expected_content=bound_content,
                        require_clean_rollback_data=False,
                    )
                    activation_payload = self._build_activation_payload(
                        payload=locked_payload,
                        expected_receipt_sha256=expected_receipt_sha256,
                        container_id=container_id,
                        network_id=network_id,
                        proof=proof,
                    )
                    proof_write_attempted = True
                    self.receipt_writer(
                        proof_path,
                        make_receipt_envelope(activation_payload),
                    )
                    _activation, proof_content = self._read_activation_proof(
                        proof_path,
                        payload=locked_payload,
                        expected_receipt_sha256=expected_receipt_sha256,
                    )
                    self._remove_activation_intent(
                        intent_path,
                        expected_content=intent_content,
                    )
                    return VerifiedRollbackActivation(
                        proof_path=proof_path,
                        base_url=endpoint.base_url,
                        proof=proof,
                    )
                except BaseException as exc:
                    primary_error = exc
                cleanup_error: BaseException | None = None
                if up_attempted or intent_write_attempted:
                    cleanup_failures: list[BaseException] = []
                    down_succeeded = not up_attempted
                    if up_attempted:
                        try:
                            self.runner([*prefix, "down"])
                            down_succeeded = True
                        except BaseException as exc:
                            cleanup_failures.append(exc)
                    running_ids: list[str] | None = None
                    try:
                        running_ids = self._running_rollback_census()
                        if running_ids:
                            cleanup_failures.append(
                                CaptureError(
                                    "global rollback copy census is not empty "
                                    "after activation cleanup",
                                ),
                            )
                    except BaseException as exc:
                        cleanup_failures.append(exc)
                    own_copy_stopped = (
                        down_succeeded
                        and running_ids is not None
                        and (
                            container_id is None
                            or container_id not in running_ids
                        )
                    )
                    try:
                        remaining_compose_ids = self._rollback_container_ids(
                            prefix,
                        )
                        if remaining_compose_ids:
                            cleanup_failures.append(
                                CaptureError(
                                    "isolated rollback Compose container "
                                    "remained after activation cleanup",
                                ),
                            )
                    except BaseException as exc:
                        cleanup_failures.append(exc)
                    if own_copy_stopped:
                        try:
                            if self._rollback_running(backup_root, project):
                                raise CaptureError(
                                    "isolated rollback container remained running "
                                    "after activation cleanup",
                                )
                        except BaseException as exc:
                            cleanup_failures.append(exc)
                            own_copy_stopped = False
                    if own_copy_stopped:
                        try:
                            self._refresh_rollback_data(
                                backup_root,
                                locked_payload["data_manifest"],
                            )
                        except BaseException as exc:
                            cleanup_failures.append(exc)
                    if not cleanup_failures and own_copy_stopped:
                        try:
                            self._verify_bound_receipt(
                                receipt,
                                expected_receipt_sha256=expected_receipt_sha256,
                                expected_content=bound_content,
                            )
                        except BaseException as exc:
                            cleanup_failures.append(exc)
                    if (
                        not cleanup_failures
                        and own_copy_stopped
                        and proof_content is None
                        and (proof_path.exists() or proof_path.is_symlink())
                    ):
                        if not proof_write_attempted:
                            cleanup_failures.append(
                                CaptureError(
                                    "an unbound rollback activation proof "
                                    "appeared during activation cleanup",
                                ),
                            )
                        else:
                            try:
                                try:
                                    self._discard_failed_activation_proof(
                                        proof_path,
                                    )
                                except Exception:
                                    # Retry one transient unlink failure while
                                    # the durable intent still claims the attempt.
                                    self._discard_failed_activation_proof(
                                        proof_path,
                                    )
                            except BaseException as exc:
                                cleanup_failures.append(exc)
                    if (
                        not cleanup_failures
                        and own_copy_stopped
                        and (intent_path.exists() or intent_path.is_symlink())
                    ):
                        try:
                            self._remove_activation_intent(
                                intent_path,
                                expected_content=intent_content,
                            )
                        except BaseException as exc:
                            cleanup_failures.append(exc)
                    if (
                        not cleanup_failures
                        and own_copy_stopped
                        and proof_content is not None
                        and (proof_path.exists() or proof_path.is_symlink())
                    ):
                        try:
                            self._remove_activation_proof(
                                proof_path,
                                expected_content=proof_content,
                            )
                        except BaseException as exc:
                            cleanup_failures.append(exc)
                    if cleanup_failures:
                        cleanup_error = cleanup_failures[0]
                if cleanup_error is not None:
                    raise CaptureError(
                        "rollback activation cleanup did not complete safely",
                    ) from cleanup_error
                assert primary_error is not None
                raise primary_error

    def reconcile_verified_rollback(
        self,
        receipt_path: Path,
        *,
        expected_receipt_sha256: str,
    ) -> VerifiedRollbackActivation | None:
        receipt, bound_content, payload = self._verify_bound_receipt(
            receipt_path,
            expected_receipt_sha256=expected_receipt_sha256,
            require_clean_rollback_data=False,
        )
        backup_root = Path(str(payload["backup"]["root"]))
        source_root = Path(str(payload["source"]["compose_working_directory"]))
        _, _, canonical_migration, _ = self._validate_canonical_storage(
            source_root,
            create=False,
        )
        with self._rollback_proof_lock(backup_root):
            with self._global_rollback_proof_lock(canonical_migration):
                _receipt, _locked_content, locked_payload = self._verify_bound_receipt(
                    receipt,
                    expected_receipt_sha256=expected_receipt_sha256,
                    expected_content=bound_content,
                    require_clean_rollback_data=False,
                )
                proof_path = self._activation_proof_path(backup_root)
                intent_path = self._activation_intent_path(backup_root)
                proof_exists = proof_path.exists() or proof_path.is_symlink()
                intent_exists = intent_path.exists() or intent_path.is_symlink()
                activation: dict[str, object] | None = None
                proof_content: bytes | None = None
                intent_content: bytes | None = None
                if proof_exists:
                    activation, proof_content = self._read_activation_proof(
                        proof_path,
                        payload=locked_payload,
                        expected_receipt_sha256=expected_receipt_sha256,
                    )
                if intent_exists:
                    _intent, intent_content = self._read_activation_intent(
                        intent_path,
                        payload=locked_payload,
                        expected_receipt_sha256=expected_receipt_sha256,
                    )

                definition, admin_username, admin_secret = (
                    self._read_rollback_runtime_inputs(backup_root)
                )
                validate_rollback_definition(definition, backup_root)
                project = str(definition["x-mail-sandbox"]["project"])
                port = int(
                    definition["services"][ROLLBACK_SERVICE]["ports"][0]["published"],
                )
                prefix = self._rollback_prefix(backup_root, project)
                compose_ids = self._rollback_container_ids(prefix)
                running_ids = self._running_rollback_census()

                if activation is None and not intent_exists:
                    if compose_ids or running_ids:
                        raise CaptureError(
                            "an unclaimed rollback runtime cannot be reconciled",
                        )
                    self._refresh_rollback_data(
                        backup_root,
                        locked_payload["data_manifest"],
                    )
                    self._verify_bound_receipt(
                        receipt,
                        expected_receipt_sha256=expected_receipt_sha256,
                        expected_content=bound_content,
                    )
                    return None

                expected_container_id = (
                    str(activation["container_id"])
                    if activation is not None
                    else None
                )
                if expected_container_id is not None and compose_ids not in (
                    [],
                    [expected_container_id],
                ):
                    raise CaptureError(
                        "rollback activation container identity changed",
                    )
                if len(compose_ids) > 1:
                    raise CaptureError(
                        "rollback activation container identity changed",
                    )

                if running_ids:
                    if len(compose_ids) != 1 or set(running_ids) != {compose_ids[0]}:
                        raise CaptureError(
                            "rollback activation container identity changed",
                        )
                    container_id = compose_ids[0]
                    if (
                        expected_container_id is not None
                        and container_id != expected_container_id
                    ):
                        raise CaptureError(
                            "rollback activation container identity changed",
                        )
                    expected_image_id = str(
                        locked_payload["source"]["image_id"],
                    )
                    expected_network_id = (
                        str(activation["network_id"])
                        if activation is not None
                        else None
                    )
                    network_id = self._rebind_verified_rollback_structure(
                        prefix=prefix,
                        expected_container_id=container_id,
                        expected_network_id=expected_network_id,
                        backup_root=backup_root,
                        definition=definition,
                        expected_image_id=expected_image_id,
                        expected_admin_secret=admin_secret,
                        project=project,
                    )
                    proof_write_attempted = False
                    intent_removal_attempted = False
                    if activation is not None:
                        endpoint = VerifiedRollbackEndpoint(
                            base_url=str(activation["base_url"]),
                            username=admin_username,
                            password=admin_secret,
                            version=str(activation["version"]),
                        )
                        proof = VerifiedRollbackProof(
                            management_status=int(activation["management_status"]),
                            proved_at=str(activation["activated_at"]),
                            version=str(activation["version"]),
                        )
                    else:
                        proof = None
                        endpoint = None

                    health_error: BaseException | None = None
                    try:
                        if activation is not None:
                            self._revalidate_verified_rollback_health(
                                expected_container_id=container_id,
                                endpoint=endpoint,
                            )
                        else:
                            proof, endpoint = (
                                self._prove_activation_runtime_health(
                                    container_id=container_id,
                                    port=port,
                                    admin_username=admin_username,
                                    admin_secret=admin_secret,
                                )
                            )
                    except BaseException as exc:
                        health_error = exc
                    if health_error is not None:
                        if not intent_exists or intent_content is None:
                            raise health_error
                        self._reconcile_owned_runtime_to_inactive(
                            prefix=prefix,
                            container_id=container_id,
                            network_id=network_id,
                            backup_root=backup_root,
                            definition=definition,
                            expected_image_id=expected_image_id,
                            admin_secret=admin_secret,
                            project=project,
                            expected_manifest=locked_payload["data_manifest"],
                            receipt=receipt,
                            expected_receipt_sha256=expected_receipt_sha256,
                            bound_content=bound_content,
                            proof_path=proof_path,
                            proof_existed_before=proof_exists,
                            proof_content=proof_content,
                            proof_write_attempted=proof_write_attempted,
                            intent_path=intent_path,
                            intent_content=intent_content,
                            intent_removal_attempted=intent_removal_attempted,
                        )
                        if isinstance(health_error, Exception):
                            return None
                        raise health_error

                    assert proof is not None and endpoint is not None
                    if activation is None:
                        network_id = self._rebind_verified_rollback_structure(
                            prefix=prefix,
                            expected_container_id=container_id,
                            expected_network_id=network_id,
                            backup_root=backup_root,
                            definition=definition,
                            expected_image_id=expected_image_id,
                            expected_admin_secret=admin_secret,
                            project=project,
                        )
                        health_error = None
                        try:
                            self._revalidate_verified_rollback_health(
                                expected_container_id=container_id,
                                endpoint=endpoint,
                            )
                        except BaseException as exc:
                            health_error = exc
                        if health_error is not None:
                            if not intent_exists or intent_content is None:
                                raise health_error
                            self._reconcile_owned_runtime_to_inactive(
                                prefix=prefix,
                                container_id=container_id,
                                network_id=network_id,
                                backup_root=backup_root,
                                definition=definition,
                                expected_image_id=expected_image_id,
                                admin_secret=admin_secret,
                                project=project,
                                expected_manifest=locked_payload["data_manifest"],
                                receipt=receipt,
                                expected_receipt_sha256=expected_receipt_sha256,
                                bound_content=bound_content,
                                proof_path=proof_path,
                                proof_existed_before=proof_exists,
                                proof_content=proof_content,
                                proof_write_attempted=proof_write_attempted,
                                intent_path=intent_path,
                                intent_content=intent_content,
                                intent_removal_attempted=(
                                    intent_removal_attempted
                                ),
                            )
                            if isinstance(health_error, Exception):
                                return None
                            raise health_error

                    promotion_error: BaseException | None = None
                    try:
                        if activation is None:
                            self._verify_bound_receipt(
                                receipt,
                                expected_receipt_sha256=expected_receipt_sha256,
                                expected_content=bound_content,
                                require_clean_rollback_data=False,
                            )
                            proof_write_attempted = True
                            activation_payload = self._build_activation_payload(
                                payload=locked_payload,
                                expected_receipt_sha256=(
                                    expected_receipt_sha256
                                ),
                                container_id=container_id,
                                network_id=network_id,
                                proof=proof,
                            )
                            self.receipt_writer(
                                proof_path,
                                make_receipt_envelope(
                                    activation_payload,
                                ),
                            )
                            activation, proof_content = (
                                self._read_activation_proof(
                                    proof_path,
                                    payload=locked_payload,
                                    expected_receipt_sha256=(
                                        expected_receipt_sha256
                                    ),
                                )
                            )
                            if activation != activation_payload:
                                raise CaptureError(
                                    "rollback activation proof identity "
                                    "changed during publication",
                                )
                        if intent_exists:
                            assert intent_content is not None
                            intent_removal_attempted = True
                            self._remove_activation_intent(
                                intent_path,
                                expected_content=intent_content,
                            )
                        return VerifiedRollbackActivation(
                            proof_path=proof_path,
                            base_url=endpoint.base_url,
                            proof=proof,
                        )
                    except BaseException as exc:
                        promotion_error = exc

                    assert promotion_error is not None
                    if not intent_exists or intent_content is None:
                        raise promotion_error
                    self._reconcile_owned_runtime_to_inactive(
                        prefix=prefix,
                        container_id=container_id,
                        network_id=network_id,
                        backup_root=backup_root,
                        definition=definition,
                        expected_image_id=expected_image_id,
                        admin_secret=admin_secret,
                        project=project,
                        expected_manifest=locked_payload["data_manifest"],
                        receipt=receipt,
                        expected_receipt_sha256=expected_receipt_sha256,
                        bound_content=bound_content,
                        proof_path=proof_path,
                        proof_existed_before=proof_exists,
                        proof_content=proof_content,
                        proof_write_attempted=proof_write_attempted,
                        intent_path=intent_path,
                        intent_content=intent_content,
                        intent_removal_attempted=intent_removal_attempted,
                    )
                    raise promotion_error

                if compose_ids:
                    container_id = compose_ids[0]
                    if (
                        expected_container_id is not None
                        and container_id != expected_container_id
                    ):
                        raise CaptureError(
                            "rollback activation container identity changed",
                        )
                    record = self._inspect_one(container_id)
                    network_id = self._validate_actual_rollback_container(
                        record,
                        backup_root,
                        definition,
                        str(locked_payload["source"]["image_id"]),
                        admin_secret,
                        expected_running=False,
                    )
                    if (
                        activation is not None
                        and network_id != activation["network_id"]
                    ):
                        raise CaptureError(
                            "rollback activation network identity changed",
                        )
                    self._validate_actual_rollback_network(network_id, project)

                self.runner([*prefix, "down"])
                self._require_running_rollback_census(None)
                if self._rollback_container_ids(prefix):
                    raise CaptureError(
                        "isolated rollback Compose container remained "
                        "after reconciliation",
                    )
                if self._rollback_running(backup_root, project):
                    raise CaptureError(
                        "isolated rollback container remained running "
                        "after reconciliation",
                    )
                self._refresh_rollback_data(
                    backup_root,
                    locked_payload["data_manifest"],
                )
                self._verify_bound_receipt(
                    receipt,
                    expected_receipt_sha256=expected_receipt_sha256,
                    expected_content=bound_content,
                )
                if proof_exists:
                    self._remove_activation_proof(
                        proof_path,
                        expected_content=proof_content,
                    )
                if intent_exists:
                    self._remove_activation_intent(
                        intent_path,
                        expected_content=intent_content,
                    )
                return None

    def deactivate_verified_rollback(
        self,
        receipt_path: Path,
        *,
        expected_receipt_sha256: str,
    ) -> None:
        receipt, bound_content, payload = self._verify_bound_receipt(
            receipt_path,
            expected_receipt_sha256=expected_receipt_sha256,
            require_clean_rollback_data=False,
        )
        backup_root = Path(str(payload["backup"]["root"]))
        source_root = Path(str(payload["source"]["compose_working_directory"]))
        _, _, canonical_migration, _ = self._validate_canonical_storage(
            source_root,
            create=False,
        )
        with self._rollback_proof_lock(backup_root):
            with self._global_rollback_proof_lock(canonical_migration):
                _receipt, _locked_content, locked_payload = self._verify_bound_receipt(
                    receipt,
                    expected_receipt_sha256=expected_receipt_sha256,
                    expected_content=bound_content,
                    require_clean_rollback_data=False,
                )
                proof_path = self._activation_proof_path(backup_root)
                activation, proof_content = self._read_activation_proof(
                    proof_path,
                    payload=locked_payload,
                    expected_receipt_sha256=expected_receipt_sha256,
                )
                intent_path = self._activation_intent_path(backup_root)
                intent_exists = intent_path.exists() or intent_path.is_symlink()
                intent_content: bytes | None = None
                if intent_exists:
                    _intent, intent_content = self._read_activation_intent(
                        intent_path,
                        payload=locked_payload,
                        expected_receipt_sha256=expected_receipt_sha256,
                    )
                definition, _admin_username, admin_secret = (
                    self._read_rollback_runtime_inputs(backup_root)
                )
                validate_rollback_definition(definition, backup_root)
                project = str(definition["x-mail-sandbox"]["project"])
                if activation["project"] != project:
                    raise CaptureError(
                        "rollback activation proof project identity changed",
                    )
                prefix = self._rollback_prefix(backup_root, project)
                try:
                    running_ids = self._running_rollback_census()
                    expected_container_id = str(activation["container_id"])
                    compose_ids = self._rollback_container_ids(prefix)
                    if compose_ids not in ([], [expected_container_id]):
                        raise CaptureError(
                            "rollback activation container identity changed",
                        )
                    if running_ids:
                        if set(running_ids) != {expected_container_id}:
                            raise CaptureError(
                                "rollback activation container identity changed",
                            )
                        if compose_ids != [expected_container_id]:
                            raise CaptureError(
                                "rollback activation container identity changed",
                            )
                        record = self._inspect_one(expected_container_id)
                        network_id = self._validate_actual_rollback_container(
                            record,
                            backup_root=backup_root,
                            definition=definition,
                            expected_image_id=str(
                                locked_payload["source"]["image_id"],
                            ),
                            expected_admin_secret=admin_secret,
                        )
                        if network_id != activation["network_id"]:
                            raise CaptureError(
                                "rollback activation network identity changed",
                            )
                        self._validate_actual_rollback_network(network_id, project)
                    elif compose_ids:
                        record = self._inspect_one(expected_container_id)
                        network_id = self._validate_actual_rollback_container(
                            record,
                            backup_root,
                            definition,
                            str(locked_payload["source"]["image_id"]),
                            admin_secret,
                            expected_running=False,
                        )
                        if network_id != activation["network_id"]:
                            raise CaptureError(
                                "rollback activation network identity changed",
                            )
                        self._validate_actual_rollback_network(
                            network_id,
                            project,
                        )
                    self.runner([*prefix, "down"])
                    self._require_running_rollback_census(None)
                    if self._rollback_container_ids(prefix):
                        raise CaptureError(
                            "isolated rollback Compose container remained "
                            "after deactivation",
                        )
                    if self._rollback_running(backup_root, project):
                        raise CaptureError(
                            "isolated rollback container remained running "
                            "after deactivation",
                        )
                    self._refresh_rollback_data(
                        backup_root,
                        locked_payload["data_manifest"],
                    )
                    self._verify_bound_receipt(
                        receipt,
                        expected_receipt_sha256=expected_receipt_sha256,
                        expected_content=bound_content,
                    )
                    if intent_exists:
                        self._remove_activation_intent(
                            intent_path,
                            expected_content=intent_content,
                        )
                    self._remove_activation_proof(
                        proof_path,
                        expected_content=proof_content,
                    )
                except BaseException as exc:
                    if (
                        isinstance(exc, CaptureError)
                        and "identity" in str(exc)
                    ):
                        raise
                    raise CaptureError(
                        "verified rollback deactivation did not complete safely",
                    ) from exc

    def run_verified_rollback(
        self,
        receipt_path: Path,
        *,
        expected_receipt_sha256: str,
        operation: Callable[[VerifiedRollbackEndpoint], T],
    ) -> VerifiedRollbackResult[T]:
        if not callable(operation):
            raise CaptureError("verified rollback operation must be callable")
        receipt, bound_content, payload = self._verify_bound_receipt(
            receipt_path,
            expected_receipt_sha256=expected_receipt_sha256,
        )
        backup_root = Path(str(payload["backup"]["root"]))
        source_root = Path(str(payload["source"]["compose_working_directory"]))
        _, _, canonical_migration, _ = self._validate_canonical_storage(
            source_root,
            create=False,
        )
        with self._rollback_proof_lock(backup_root):
            with self._global_rollback_proof_lock(canonical_migration):
                _receipt, _locked_content, locked_payload = self._verify_bound_receipt(
                    receipt,
                    expected_receipt_sha256=expected_receipt_sha256,
                    expected_content=bound_content,
                )
                definition, admin_username, admin_secret = (
                    self._read_rollback_runtime_inputs(backup_root)
                )
                result = self._run_verified_rollback_runtime(
                    backup_root,
                    definition,
                    locked_payload["data_manifest"],
                    admin_username,
                    admin_secret,
                    str(locked_payload["source"]["image_id"]),
                    operation=operation,
                )
                self._verify_bound_receipt(
                    receipt,
                    expected_receipt_sha256=expected_receipt_sha256,
                    expected_content=bound_content,
                )
                return result

    def prove_rollback(self, receipt_path: Path) -> dict[str, object]:
        _receipt, content, _envelope, _payload = self._read_receipt(receipt_path)
        result = self.run_verified_rollback(
            receipt_path,
            expected_receipt_sha256=sha256_bytes(content),
            operation=lambda _endpoint: None,
        )
        return result.proof.as_dict()


def _build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Capture and verify the stopped Stalwart v0.15 source store.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    capture_parser = subparsers.add_parser(
        "capture",
        help="capture the running v0.15 Compose source and prove an isolated rollback",
    )
    capture_parser.add_argument("--source-service", required=True)
    for name in ("prove-rollback", "verify"):
        subparser = subparsers.add_parser(name)
        subparser.add_argument("--receipt", required=True, type=Path)
    for name in (
        "activate-rollback",
        "deactivate-rollback",
        "reconcile-rollback",
    ):
        subparser = subparsers.add_parser(name)
        subparser.add_argument("--receipt", required=True, type=Path)
        subparser.add_argument(
            "--expected-receipt-sha256",
            required=True,
            dest="expected_receipt_sha256",
        )
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _build_argument_parser().parse_args(argv)
    application = CaptureApplication()
    try:
        if arguments.command == "capture":
            receipt = application.capture(arguments.source_service)
            print(f"verified source receipt: {receipt}")
            print("source Stalwart state: stopped")
            return 0
        receipt = arguments.receipt
        if not receipt.is_absolute():
            receipt = Path.cwd() / receipt
        if arguments.command == "activate-rollback":
            activation = application.activate_verified_rollback(
                receipt,
                expected_receipt_sha256=arguments.expected_receipt_sha256,
            )
            print(
                "verified rollback active: "
                f"version={activation.proof.version} "
                f"management_status={activation.proof.management_status} "
                f"base_url={activation.base_url}",
            )
            print(f"activation proof: {activation.proof_path}")
            print("captured source Stalwart state: stopped")
            return 0
        if arguments.command == "deactivate-rollback":
            application.deactivate_verified_rollback(
                receipt,
                expected_receipt_sha256=arguments.expected_receipt_sha256,
            )
            print("verified rollback deactivated and working data refreshed")
            print("captured source Stalwart state: stopped")
            return 0
        if arguments.command == "reconcile-rollback":
            activation = application.reconcile_verified_rollback(
                receipt,
                expected_receipt_sha256=arguments.expected_receipt_sha256,
            )
            if activation is None:
                print("rollback reconciliation complete: inactive")
            else:
                print(
                    "rollback reconciliation complete: active "
                    f"version={activation.proof.version} "
                    f"management_status={activation.proof.management_status} "
                    f"base_url={activation.base_url}",
                )
                print(f"activation proof: {activation.proof_path}")
            print("captured source Stalwart state: stopped")
            return 0
        if arguments.command == "prove-rollback":
            proof = application.prove_rollback(receipt)
            print(
                "rollback proof verified: "
                f"version={proof['version']} management_status={proof['management_status']}",
            )
            print("source Stalwart state: stopped")
            return 0
        payload = application.verify(receipt)
        print(f"verified source receipt: {receipt}")
        print(
            "captured source: "
            f"version={payload['source']['version']} "
            f"image={payload['source']['image_digest']}",
        )
        print("source Stalwart state: stopped")
        return 0
    except CaptureError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
