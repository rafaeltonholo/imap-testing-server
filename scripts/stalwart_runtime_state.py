#!/usr/bin/env python3
"""Read-only Stalwart startup classification and receipt primitives.

``classify_repository`` never creates, removes, or rewrites filesystem state and
never invokes Docker.  The fresh-store bootstrap owns the separate, explicit
``publish_current_receipt`` mutation after it has proved the current runtime.
"""

from __future__ import annotations

import argparse
from enum import Enum
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys


CURRENT_IMAGE = (
    "stalwartlabs/stalwart:v0.16.17@"
    "sha256:a8108e19bd927e172d4d8c128907b8dfc93fd180ae8ee07dccdd42cb97eb9dfa"
)
CURRENT_IMAGE_DIGEST = (
    "sha256:a8108e19bd927e172d4d8c128907b8dfc93fd180ae8ee07dccdd42cb97eb9dfa"
)
LEGACY_IMAGE = (
    "stalwartlabs/stalwart:v0.15@"
    "sha256:dcf575db2d53d9ef86d6ced8abe4ba491984659a0f8862cc6079ee7b41c3c568"
)
CURRENT_CONFIG_BYTES = (
    b'{\n'
    b'  "@type": "RocksDb",\n'
    b'  "path": "/var/lib/stalwart/"\n'
    b'}'
)
CURRENT_CONFIG_SHA256 = hashlib.sha256(CURRENT_CONFIG_BYTES).hexdigest()
RECEIPT_SCHEMA = "mail-sandbox.stalwart-current-runtime.v1"
RECEIPT_RELATIVE = (
    Path("debug-dashboard") / ".runtime" / "stalwart" / "current.json"
)
MAXIMUM_RECEIPT_BYTES = 64 * 1024
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")


class RuntimeState(Enum):
    FRESH = "fresh"
    CURRENT = "current"
    MIGRATION_REQUIRED = "migration-required"
    INVALID = "invalid"


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate key")
        value[key] = item
    return value


def _repository_path(value: Path) -> Path:
    path = Path(value)
    if not path.is_absolute() or Path(os.path.normpath(path)) != path:
        raise ValueError("repository must be a normalized absolute path")
    return path


def _plain_directory(path: Path) -> os.stat_result | None:
    try:
        named = path.lstat()
        resolved = path.stat()
    except OSError:
        return None
    if (
        stat.S_ISLNK(named.st_mode)
        or not stat.S_ISDIR(named.st_mode)
        or (named.st_dev, named.st_ino) != (resolved.st_dev, resolved.st_ino)
    ):
        return None
    return named


def _plain_regular(path: Path, maximum: int) -> tuple[bytes, os.stat_result] | None:
    try:
        before = path.lstat()
        if (
            stat.S_ISLNK(before.st_mode)
            or not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size > maximum
        ):
            return None
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
                or opened.st_size != before.st_size
            ):
                return None
            chunks: list[bytes] = []
            remaining = maximum + 1
            while remaining:
                chunk = os.read(descriptor, min(64 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            content = b"".join(chunks)
            after_open = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        after = path.lstat()
    except OSError:
        return None
    if (
        len(content) > maximum
        or (after_open.st_dev, after_open.st_ino, after_open.st_size)
        != (opened.st_dev, opened.st_ino, opened.st_size)
        or (after.st_dev, after.st_ino, after.st_size)
        != (opened.st_dev, opened.st_ino, opened.st_size)
        or stat.S_ISLNK(after.st_mode)
    ):
        return None
    return content, after


def _service_block(compose: str, service: str) -> str | None:
    lines = compose.splitlines()
    header = f"  {service}:"
    try:
        start = lines.index(header)
    except ValueError:
        return None
    end = len(lines)
    for index in range(start + 1, len(lines)):
        line = lines[index]
        if line.startswith("  ") and not line.startswith("    ") and line.strip():
            end = index
            break
    return "\n".join(lines[start:end])


def _has_port(block: str, host: int, target: int) -> bool:
    short = re.compile(
        rf"['\"]?127\.0\.0\.1:{host}:{target}['\"]?",
    )
    if short.search(block):
        return True
    host_ip = re.search(r"host_ip:\s*['\"]?127\.0\.0\.1['\"]?", block)
    published = re.search(rf"published:\s*['\"]?{host}['\"]?", block)
    container = re.search(rf"target:\s*{target}(?:\s|$)", block)
    return host_ip is not None and published is not None and container is not None


def _compose_kind(repository: Path) -> tuple[str, str] | None:
    snapshot = _plain_regular(repository / "docker-compose.yml", 4 * 1024 * 1024)
    if snapshot is None:
        return None
    content = snapshot[0]
    try:
        text = content.decode("utf-8", "strict")
    except UnicodeError:
        return None
    block = _service_block(text, "stalwart")
    if block is None:
        return None
    compose_sha256 = hashlib.sha256(content).hexdigest()
    if f"image: {LEGACY_IMAGE}" in block:
        return "legacy", compose_sha256
    if (
        f"image: {CURRENT_IMAGE}" not in block
        or not _has_port(block, 8443, 8080)
        or not _has_port(block, 8587, 587)
        or "/etc/stalwart" not in block
        or "/var/lib/stalwart" not in block
        or "config.toml" in block
        or "ADMIN_SECRET" in block
        or "STALWART_RECOVERY_" in block
    ):
        return None
    return "current", compose_sha256


def _store_identity(metadata: os.stat_result) -> list[int]:
    return [
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IMODE(metadata.st_mode),
        metadata.st_uid,
        metadata.st_gid,
    ]


def _store_state(repository: Path) -> tuple[str, os.stat_result | None]:
    store = repository / "stalwart-data"
    try:
        named = store.lstat()
    except FileNotFoundError:
        return "absent", None
    except OSError:
        return "invalid", None
    if stat.S_ISLNK(named.st_mode) or not stat.S_ISDIR(named.st_mode):
        return "invalid", None
    try:
        empty = next(store.iterdir(), None) is None
        after = store.lstat()
    except OSError:
        return "invalid", None
    if (
        stat.S_ISLNK(after.st_mode)
        or not stat.S_ISDIR(after.st_mode)
        or (after.st_dev, after.st_ino) != (named.st_dev, named.st_ino)
    ):
        return "invalid", None
    return ("empty" if empty else "nonempty"), after


def _receipt_payload(repository: Path, store: os.stat_result, compose_sha256: str) -> dict[str, object]:
    return {
        "compose_sha256": compose_sha256,
        "config_sha256": CURRENT_CONFIG_SHA256,
        "image_digest": CURRENT_IMAGE_DIGEST,
        "image_reference": CURRENT_IMAGE,
        "schema": RECEIPT_SCHEMA,
        "store_identity": _store_identity(store),
        "store_path": "stalwart-data",
    }


def _valid_receipt(
    repository: Path,
    store: os.stat_result,
    compose_sha256: str,
) -> bool:
    receipt = repository / RECEIPT_RELATIVE
    snapshot = _plain_regular(receipt, MAXIMUM_RECEIPT_BYTES)
    if snapshot is None or stat.S_IMODE(snapshot[1].st_mode) != 0o600:
        return False
    content = snapshot[0]
    if not content.endswith(b"\n") or content.count(b"\n") != 1:
        return False
    try:
        envelope = json.loads(
            content[:-1].decode("utf-8", "strict"),
            object_pairs_hook=_strict_object,
            parse_float=lambda _value: (_ for _ in ()).throw(ValueError()),
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except (UnicodeError, json.JSONDecodeError, ValueError):
        return False
    if not isinstance(envelope, dict) or set(envelope) != {"payload", "payload_sha256"}:
        return False
    payload = envelope.get("payload")
    digest = envelope.get("payload_sha256")
    if (
        not isinstance(payload, dict)
        or type(digest) is not str
        or SHA256_PATTERN.fullmatch(digest) is None
        or not secrets.compare_digest(hashlib.sha256(_canonical_json(payload)).hexdigest(), digest)
    ):
        return False
    return payload == _receipt_payload(repository, store, compose_sha256)


def classify_repository(repository: Path) -> RuntimeState:
    """Classify fixed repository state without any Docker call or mutation."""
    try:
        root = _repository_path(repository)
    except ValueError:
        return RuntimeState.INVALID
    root_metadata = _plain_directory(root)
    if root_metadata is None:
        return RuntimeState.INVALID
    receipt = root / RECEIPT_RELATIVE
    store_kind, store = _store_state(root)
    if store_kind == "invalid":
        return RuntimeState.INVALID
    if store_kind in {"absent", "empty"}:
        try:
            receipt_present = receipt.lstat() is not None
        except FileNotFoundError:
            receipt_present = False
        except OSError:
            return RuntimeState.INVALID
        return RuntimeState.INVALID if receipt_present else RuntimeState.FRESH
    assert store is not None
    compose = _compose_kind(root)
    if compose is None:
        return RuntimeState.INVALID
    compose_kind, compose_sha256 = compose
    if compose_kind == "legacy":
        try:
            receipt.lstat()
        except FileNotFoundError:
            return RuntimeState.MIGRATION_REQUIRED
        except OSError:
            return RuntimeState.INVALID
        return RuntimeState.INVALID
    config = _plain_regular(root / "stalwart" / "config.json", 1024)
    if config is None or config[0] != CURRENT_CONFIG_BYTES:
        return RuntimeState.INVALID
    return (
        RuntimeState.CURRENT
        if _valid_receipt(root, store, compose_sha256)
        else RuntimeState.INVALID
    )


def publish_current_receipt(repository: Path) -> Path:
    """Atomically publish one no-overwrite receipt after external live proofs."""
    root = _repository_path(repository)
    if _plain_directory(root) is None:
        raise ValueError("repository is invalid")
    store_kind, store = _store_state(root)
    compose = _compose_kind(root)
    config = _plain_regular(root / "stalwart" / "config.json", 1024)
    if (
        store_kind != "nonempty"
        or store is None
        or compose is None
        or compose[0] != "current"
        or config is None
        or config[0] != CURRENT_CONFIG_BYTES
    ):
        raise ValueError("current runtime receipt prerequisites are absent")
    receipt = root / RECEIPT_RELATIVE
    parent = receipt.parent
    if _plain_directory(parent) is None:
        raise ValueError("runtime receipt directory is invalid")
    payload = _receipt_payload(root, store, compose[1])
    envelope = {
        "payload": payload,
        "payload_sha256": hashlib.sha256(_canonical_json(payload)).hexdigest(),
    }
    content = _canonical_json(envelope) + b"\n"
    temporary = parent / f".{receipt.name}.{os.getpid()}.tmp"
    descriptor = -1
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        written = 0
        while written < len(content):
            written += os.write(descriptor, content[written:])
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.link(temporary, receipt)
        temporary.unlink()
        directory = os.open(parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OSError as error:
        raise ValueError("current runtime receipt could not be published") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    return receipt


def _absolute_path(value: str) -> Path:
    path = Path(value)
    try:
        return _repository_path(path)
    except ValueError as error:
        raise argparse.ArgumentTypeError(str(error)) from None


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Classify the local Stalwart runtime.")
    commands = parser.add_subparsers(dest="command", required=True)
    classify = commands.add_parser("classify", help="print the read-only runtime state")
    classify.add_argument("--repository", required=True, type=_absolute_path)
    return parser


def main(argv: list[str] | None = None) -> int:
    options = _argument_parser().parse_args(sys.argv[1:] if argv is None else argv)
    if options.command != "classify":
        return 1
    print(classify_repository(options.repository).value)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
