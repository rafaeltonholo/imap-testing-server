#!/usr/bin/env python3
"""Safely manage the canonical local Dovecot passwd-file authority."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import hashlib
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from typing import Callable, Iterator, Sequence

if __package__:
    from .lib import ROOT_DIR, USERS_FILE, docker_exec
else:
    from lib import ROOT_DIR, USERS_FILE, docker_exec


DEFAULTS_FILE = ROOT_DIR / "config" / "users.defaults"
START_LOCAL_LIFECYCLE = "dashboard-start-local"
JOURNAL_PREFIX = "users-mutation-journal-v1"
Runner = Callable[..., object]

_LOCAL_PART = r"[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*"
_DOMAIN_LABEL = r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"
_ADDRESS = re.compile(rf"{_LOCAL_PART}@{_DOMAIN_LABEL}(?:\.{_DOMAIN_LABEL})+")
_JOURNAL = re.compile(
    rf"{JOURNAL_PREFIX} "
    r"before=(?P<before>absent|sha256:[0-9a-f]{64}) "
    r"after=sha256:(?P<after>[0-9a-f]{64})\n"
)


class UsersFileError(RuntimeError):
    """The users authority or its Dovecot projection is unsafe or invalid."""


@dataclass(frozen=True)
class UserRecord:
    address: str
    password_field: str


@dataclass(frozen=True)
class MutationJournal:
    before_digest: str | None
    after_digest: str


def _validate_address(address: str) -> None:
    if address != address.casefold() or _ADDRESS.fullmatch(address) is None:
        raise UsersFileError(f"address is malformed or not canonical: {address!r}")


def _validate_record(record: UserRecord) -> None:
    _validate_address(record.address)
    if not record.password_field.startswith("{PLAIN}"):
        raise UsersFileError(f"unsupported password scheme for {record.address}")
    password = record.password_field.removeprefix("{PLAIN}")
    if not password:
        raise UsersFileError(f"empty PLAIN password for {record.address}")
    if any(character in password for character in ("\0", "\n", "\r", ":")):
        raise UsersFileError(f"unsafe PLAIN password for {record.address}")


def parse_records(document: str) -> list[UserRecord]:
    """Parse the strict eight-column passwd-file representation."""
    records: list[UserRecord] = []
    seen: set[str] = set()
    for line_number, line in enumerate(document.splitlines(), start=1):
        fields = line.split(":")
        if len(fields) != 8 or any(fields[index] for index in range(2, 8)):
            raise UsersFileError(f"line {line_number} is not a canonical eight-field record")
        record = UserRecord(fields[0], fields[1])
        _validate_record(record)
        canonical = record.address.casefold()
        if canonical in seen:
            raise UsersFileError(f"duplicate canonical address: {record.address}")
        seen.add(canonical)
        records.append(record)
    if document != serialize_records(records):
        raise UsersFileError("users document is not canonically serialized")
    return records


def serialize_records(records: Sequence[UserRecord]) -> str:
    """Serialize records into the one accepted passwd-file representation."""
    seen: set[str] = set()
    lines: list[str] = []
    for record in records:
        _validate_record(record)
        canonical = record.address.casefold()
        if canonical in seen:
            raise UsersFileError(f"duplicate canonical address: {record.address}")
        seen.add(canonical)
        lines.append(f"{record.address}:{record.password_field}::::::")
    return "".join(f"{line}\n" for line in lines)


def _require_regular_file(path: Path, *, require_mode: bool) -> os.stat_result:
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise UsersFileError(f"required file is missing: {path}") from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise UsersFileError(f"refusing symlink: {path}")
    if not stat.S_ISREG(metadata.st_mode):
        raise UsersFileError(f"not a regular file: {path}")
    if require_mode and stat.S_IMODE(metadata.st_mode) != 0o600:
        raise UsersFileError(f"{path} must have mode 0600")
    return metadata


def _require_parent_directory(path: Path) -> None:
    try:
        metadata = path.parent.lstat()
    except FileNotFoundError as exc:
        raise UsersFileError(f"parent directory is missing: {path.parent}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise UsersFileError(f"unsafe parent directory: {path.parent}")


def _read_regular_bytes(path: Path, *, require_mode: bool) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise UsersFileError(f"cannot safely open regular file: {path}") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise UsersFileError(f"not a regular file: {path}")
        if require_mode and stat.S_IMODE(metadata.st_mode) != 0o600:
            raise UsersFileError(f"{path} must have mode 0600")
        chunks: list[bytes] = []
        while chunk := os.read(descriptor, 65536):
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _read_users(path: Path) -> tuple[list[UserRecord], bytes]:
    raw = _read_regular_bytes(path, require_mode=True)
    try:
        document = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise UsersFileError(f"{path} is not valid UTF-8") from exc
    return parse_records(document), raw


def _read_defaults(path: Path) -> tuple[list[UserRecord], bytes]:
    raw = _read_regular_bytes(path, require_mode=False)
    try:
        records = parse_records(raw.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise UsersFileError(f"{path} is not valid UTF-8") from exc
    if not records:
        raise UsersFileError(f"defaults file is empty: {path}")
    canonical = serialize_records(records).encode("utf-8")
    if raw != canonical:
        raise UsersFileError(f"defaults file is not canonically serialized: {path}")
    return records, raw


def _lock_path(users_path: Path) -> Path:
    return users_path.with_name(f"{users_path.name}.lock")


def _read_lock_state(descriptor: int) -> str:
    os.lseek(descriptor, 0, os.SEEK_SET)
    raw = os.read(descriptor, 512)
    try:
        return raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise UsersFileError("users.lock contains invalid mutation journal") from exc


def _digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _encode_journal(before: bytes | None, after: bytes) -> str:
    before_field = "absent" if before is None else f"sha256:{_digest(before)}"
    return f"{JOURNAL_PREFIX} before={before_field} after=sha256:{_digest(after)}\n"


def _parse_journal(state: str) -> MutationJournal:
    match = _JOURNAL.fullmatch(state)
    if match is None:
        raise UsersFileError("users.lock contains invalid mutation journal")
    before_field = match.group("before")
    before_digest = None if before_field == "absent" else before_field.removeprefix("sha256:")
    after_digest = match.group("after")
    if before_digest == after_digest:
        raise UsersFileError("users.lock contains invalid mutation journal")
    return MutationJournal(before_digest, after_digest)


def _write_lock_state(descriptor: int, state: str) -> None:
    encoded = state.encode("ascii")
    os.lseek(descriptor, 0, os.SEEK_SET)
    os.ftruncate(descriptor, 0)
    if encoded:
        os.write(descriptor, encoded)
    os.fsync(descriptor)


@contextmanager
def _locked(users_path: Path, *, allow_pending: bool = False) -> Iterator[int]:
    _require_parent_directory(users_path)
    lock_path = _lock_path(users_path)
    if lock_path.exists() or lock_path.is_symlink():
        _require_regular_file(lock_path, require_mode=True)
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(lock_path, flags, 0o600)
    except OSError as exc:
        raise UsersFileError(f"cannot safely open lock file: {lock_path}") from exc
    try:
        fcntl.lockf(descriptor, fcntl.LOCK_EX)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600:
            raise UsersFileError(f"{lock_path} must be a regular file with mode 0600")
        state = _read_lock_state(descriptor)
        if state:
            _parse_journal(state)
        if state and not allow_pending:
            raise UsersFileError("Dovecot verification is pending; run the verify command first")
        yield descriptor
    finally:
        os.close(descriptor)


def _fsync_directory(directory: Path) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    descriptor = os.open(directory, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_write(users_path: Path, content: bytes) -> None:
    _require_parent_directory(users_path)
    prefix = f"{users_path.name}.tmp-"
    descriptor = -1
    temporary_path: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=prefix,
            dir=users_path.parent,
        )
        temporary_path = Path(temporary_name)
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            descriptor = -1
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, users_path)
        temporary_path = None
        _fsync_directory(users_path.parent)
        _require_regular_file(users_path, require_mode=True)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def _active_authority(users_path: Path) -> tuple[str | None, list[UserRecord] | None]:
    if not users_path.exists() and not users_path.is_symlink():
        return None, None
    records, raw = _read_users(users_path)
    return _digest(raw), records


def _classify_active_authority(
    users_path: Path,
    journal: MutationJournal,
) -> tuple[str, list[UserRecord] | None]:
    active_digest, records = _active_authority(users_path)
    if active_digest == journal.after_digest:
        return "after", records
    if active_digest == journal.before_digest:
        return "before", records
    return "indeterminate", records


def _result_detail(result: object) -> str:
    stderr = getattr(result, "stderr", "") or ""
    stdout = getattr(result, "stdout", "") or ""
    return str(stderr or stdout).strip() or f"exit {getattr(result, 'returncode', 'unknown')}"


def _run_doveadm(runner: Runner, command: list[str], **kwargs: object) -> object:
    try:
        result = runner(command, **kwargs)
    except Exception as exc:
        raise UsersFileError(str(exc)) from exc
    if getattr(result, "returncode", 0) != 0:
        raise UsersFileError(_result_detail(result))
    return result


def reload_and_verify(
    records: Sequence[UserRecord],
    *,
    runner: Runner = docker_exec,
    deleted_address: str | None = None,
    exact: bool = False,
    reload: bool = True,
) -> None:
    """Reload Dovecot and prove its root-service user projection."""
    if reload:
        _run_doveadm(runner, ["doveadm", "reload"])
    for record in records:
        _run_doveadm(runner, ["doveadm", "user", record.address], capture=True)
    if exact:
        result = _run_doveadm(runner, ["doveadm", "user", "*"], capture=True)
        projected = [line.strip() for line in str(getattr(result, "stdout", "")).splitlines() if line.strip()]
        expected = [record.address for record in records]
        if sorted(projected) != sorted(expected) or len(projected) != len(set(projected)):
            raise UsersFileError(
                f"full Dovecot projection mismatch: expected {sorted(expected)!r}, got {sorted(projected)!r}"
            )
    if deleted_address is not None:
        try:
            result = runner(["doveadm", "user", deleted_address], check=False, capture=True)
        except Exception as exc:
            raise UsersFileError(str(exc)) from exc
        if getattr(result, "returncode", 0) == 0:
            raise UsersFileError(f"deleted user still projects from Dovecot: {deleted_address}")


def _durable_projection(
    records: Sequence[UserRecord],
    *,
    runner: Runner,
    deleted_address: str | None = None,
    exact: bool = False,
) -> None:
    try:
        reload_and_verify(
            records,
            runner=runner,
            deleted_address=deleted_address,
            exact=exact,
        )
    except UsersFileError as exc:
        raise UsersFileError(
            f"users file mutation is durable, but Dovecot projection failed: {exc}"
        ) from exc


def _mutate_users(
    users_path: Path,
    transform: Callable[[list[UserRecord]], list[UserRecord]],
    *,
    runner: Runner,
    missing_only: bool = False,
    exact: bool = False,
    defer_provider_verification: bool = False,
    deleted_address: str | None = None,
    verify_even_unchanged: bool = False,
) -> bool:
    """Run the only locked users-authority mutation sequence."""
    with _locked(users_path) as descriptor:
        destination_exists = users_path.exists() or users_path.is_symlink()
        if destination_exists and missing_only:
            _require_regular_file(users_path, require_mode=True)
            return False
        if destination_exists:
            records, original = _read_users(users_path)
        else:
            records, original = [], None
        updated = transform(list(records))
        rendered = serialize_records(updated).encode("utf-8")
        changed = rendered != (original if original is not None else b"")
        if changed:
            journal = MutationJournal(
                before_digest=None if original is None else _digest(original),
                after_digest=_digest(rendered),
            )
            _write_lock_state(descriptor, _encode_journal(original, rendered))
            try:
                _atomic_write(users_path, rendered)
            except Exception as exc:
                try:
                    position, _ = _classify_active_authority(users_path, journal)
                except Exception as state_error:
                    raise UsersFileError(
                        "users authority write outcome is indeterminate; "
                        "pending verification retained"
                    ) from state_error
                if position == "before":
                    _write_lock_state(descriptor, "")
                    raise UsersFileError(
                        f"users authority mutation was not applied; safe to retry: {exc}"
                    ) from exc
                if position == "after":
                    raise UsersFileError(
                        "users authority mutation is durable; "
                        f"provider verification is pending: {exc}"
                    ) from exc
                raise UsersFileError(
                    "users authority write outcome is indeterminate; "
                    "pending verification retained"
                ) from exc
            if not defer_provider_verification:
                _durable_projection(
                    updated,
                    runner=runner,
                    deleted_address=deleted_address,
                    exact=exact,
                )
                _write_lock_state(descriptor, "")
        elif verify_even_unchanged:
            reload_and_verify(
                updated,
                runner=runner,
                deleted_address=deleted_address,
                exact=exact,
            )
        elif deleted_address is not None:
            reload_and_verify(
                updated,
                runner=runner,
                deleted_address=deleted_address,
                exact=exact,
                reload=False,
            )
        return changed


def bootstrap_defaults(
    users_path: Path = USERS_FILE,
    defaults_path: Path = DEFAULTS_FILE,
    *,
    defer_provider_verification: bool = False,
    lifecycle: str | None = None,
    runner: Runner = docker_exec,
) -> bool:
    """Create the authority from defaults only when the destination is absent."""
    if defer_provider_verification and lifecycle != START_LOCAL_LIFECYCLE:
        raise UsersFileError(
            f"deferred provider verification is reserved for lifecycle {START_LOCAL_LIFECYCLE!r}"
        )
    if not defer_provider_verification and lifecycle is not None:
        raise UsersFileError("lifecycle is valid only with deferred provider verification")

    def load_defaults(records: list[UserRecord]) -> list[UserRecord]:
        del records
        defaults, _ = _read_defaults(defaults_path)
        return defaults

    return _mutate_users(
        users_path,
        load_defaults,
        runner=runner,
        missing_only=True,
        exact=True,
        defer_provider_verification=defer_provider_verification,
    )


def reset_defaults(
    users_path: Path = USERS_FILE,
    defaults_path: Path = DEFAULTS_FILE,
    *,
    runner: Runner = docker_exec,
) -> bool:
    """Atomically replace only the auth authority with tracked defaults."""
    def load_defaults(records: list[UserRecord]) -> list[UserRecord]:
        del records
        defaults, _ = _read_defaults(defaults_path)
        return defaults

    return _mutate_users(
        users_path,
        load_defaults,
        runner=runner,
        exact=True,
        verify_even_unchanged=True,
    )


def upsert_user(
    address: str,
    password: str,
    users_path: Path = USERS_FILE,
    *,
    runner: Runner = docker_exec,
) -> bool:
    """Insert or replace one canonical address while preserving every other record."""
    replacement = UserRecord(address, f"{{PLAIN}}{password}")
    _validate_record(replacement)

    def transform(records: list[UserRecord]) -> list[UserRecord]:
        for index, record in enumerate(records):
            if record.address == address:
                records[index] = replacement
                return records
        records.append(replacement)
        return records

    return _mutate_users(users_path, transform, runner=runner)


def delete_user(
    address: str,
    users_path: Path = USERS_FILE,
    *,
    runner: Runner = docker_exec,
) -> bool:
    """Delete only one auth record; mailbox and provider data are out of scope."""
    _validate_address(address)
    return _mutate_users(
        users_path,
        lambda records: [record for record in records if record.address != address],
        runner=runner,
        deleted_address=address,
        exact=True,
    )


def verification_pending(users_path: Path = USERS_FILE) -> bool:
    with _locked(users_path, allow_pending=True) as descriptor:
        return bool(_read_lock_state(descriptor))


def verify_users(users_path: Path = USERS_FILE, *, runner: Runner = docker_exec) -> None:
    """Verify the full projection and recover or discharge a pending journal."""
    with _locked(users_path, allow_pending=True) as descriptor:
        state = _read_lock_state(descriptor)
        if state:
            journal = _parse_journal(state)
            try:
                position, records = _classify_active_authority(users_path, journal)
            except Exception as exc:
                raise UsersFileError(
                    "users authority state is indeterminate; pending verification retained"
                ) from exc
            if position == "indeterminate":
                raise UsersFileError(
                    "users authority state is indeterminate; pending verification retained"
                )
            if position == "before":
                if records is not None:
                    reload_and_verify(records, runner=runner, exact=True)
                _write_lock_state(descriptor, "")
                raise UsersFileError(
                    "users authority mutation was not applied; safe to retry"
                )
            if records is None:
                raise UsersFileError(
                    "users authority state is indeterminate; pending verification retained"
                )
            if position == "after":
                try:
                    _fsync_directory(users_path.parent)
                except Exception as exc:
                    raise UsersFileError(
                        "users authority recovery durability is pending; "
                        f"parent directory fsync failed: {exc}"
                    ) from exc
        else:
            records, _ = _read_users(users_path)
        reload_and_verify(records, runner=runner, exact=True)
        _write_lock_state(descriptor, "")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--users-file", type=Path, default=USERS_FILE)
    parser.add_argument("--defaults-file", type=Path, default=DEFAULTS_FILE)
    commands = parser.add_subparsers(dest="command", required=True)

    bootstrap = commands.add_parser(
        "bootstrap-defaults",
        help="create missing users from defaults",
        allow_abbrev=False,
    )
    bootstrap.add_argument("--defer-provider-verification", action="store_true")
    bootstrap.add_argument("--lifecycle", choices=[START_LOCAL_LIFECYCLE])
    commands.add_parser("reset-defaults", help="replace users with defaults and verify")
    upsert = commands.add_parser("upsert", help="insert or update one user")
    upsert.add_argument("address")
    upsert.add_argument("password")
    delete = commands.add_parser("delete", help="delete one auth record")
    delete.add_argument("address")
    commands.add_parser("verify", help="reload and verify the complete projection")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "bootstrap-defaults":
            changed = bootstrap_defaults(
                args.users_file,
                args.defaults_file,
                defer_provider_verification=args.defer_provider_verification,
                lifecycle=args.lifecycle,
            )
            print("created config/users" if changed else "config/users already exists; preserved")
        elif args.command == "reset-defaults":
            reset_defaults(args.users_file, args.defaults_file)
            print("config/users reset and verified")
        elif args.command == "upsert":
            upsert_user(args.address, args.password, args.users_file)
            print(f"upserted and verified {args.address}")
        elif args.command == "delete":
            delete_user(args.address, args.users_file)
            print(f"deleted auth record and verified absence: {args.address}")
        else:
            verify_users(args.users_file)
            print("config/users projection verified")
    except UsersFileError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
