#!/usr/bin/env python3
"""Crash-recoverable Stalwart v0.16.14 bootstrap and offline planner.

The pure planner remains import-safe and stdlib-only.  Live Registry, migration
runtime, and Kotlin routing operations are reachable only through the explicit
``bootstrap`` command or injected orchestration dependencies.  Secret-bearing
buffers are kept out of plans, receipts, errors, and command arguments.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import signal
import stat
import subprocess
import sys
import time
from typing import BinaryIO, Callable, Mapping, Sequence


SERVER_VERSION = "0.16.14"
MANAGEMENT_ADDRESS = "dashboard-management@local.test"
MANAGEMENT_LOCAL_PART = "dashboard-management"
MANAGEMENT_KEY_DESCRIPTION = "mail-sandbox/debug-dashboard/management"
IP_RESTRICTION_DECISION = (
    "disabled-local-only-loopback-network-isolation"
)
MANIFEST_SCHEMA = "mail-sandbox.stalwart-v016-bootstrap-manifest.v1"
PROTECTED_ACCOUNTS_SCHEMA = (
    "mail-sandbox.stalwart-v016-protected-accounts.v1"
)
ATTEMPT_SCHEMA = "mail-sandbox.stalwart-v016-bootstrap-attempt.v1"
ACCOUNT_CHECKPOINT_SCHEMA = (
    "mail-sandbox.stalwart-v016-bootstrap-account.v1"
)
KEY_CHECKPOINT_SCHEMA = "mail-sandbox.stalwart-v016-bootstrap-key.v2"
REPLACEMENT_CHECKPOINT_SCHEMA = (
    "mail-sandbox.stalwart-v016-bootstrap-replacement.v1"
)
PROOF_SCHEMA = "mail-sandbox.stalwart-v016-bootstrap-proof.v1"
FINAL_RECEIPT_SCHEMA = "mail-sandbox.stalwart-v016-bootstrap-receipt.v2"
ROUTING_PROOF_SCHEMA = (
    "mail-sandbox.stalwart-v016-bootstrap-routing-proof.v1"
)
ROUTING_INTENT_SCHEMA = (
    "mail-sandbox.stalwart-v016-routing-intent.v1"
)
ROUTING_INPUT_SCHEMA = "mail-sandbox.stalwart-v016-routing-input.v1"
ROUTING_VERIFIER_SCHEMA = (
    "mail-sandbox.stalwart-v016-routing-verifier.v1"
)
ROUTING_VERIFIER_MAIN = (
    "mail.sandbox.dashboard.server.gate.stalwart."
    "StalwartRoutingProofCliKt"
)
MAXIMUM_IDENTITY_COMPONENT = (1 << 64) - 1

MANAGEMENT_PERMISSIONS = (
    "authenticate",
    "sysAccountGet",
    "sysAccountQuery",
    "sysAccountCreate",
    "sysAccountUpdate",
    "sysAccountDestroy",
    "sysDomainGet",
    "sysDomainQuery",
    "sysDomainCreate",
    "sysTaskGet",
    "sysTaskQuery",
)
ROUTING_MAIL_PERMISSIONS = (
    "authenticate",
    "jmapMailboxGet",
    "jmapMailboxCreate",
    "jmapMailboxUpdate",
    "jmapMailboxDestroy",
    "jmapEmailGet",
    "jmapEmailQuery",
    "jmapEmailUpdate",
    "jmapEmailDestroy",
    "jmapEmailImport",
    "jmapIdentityGet",
    "jmapEmailSubmissionGet",
    "jmapEmailSubmissionCreate",
    "jmapBlobGet",
    "jmapBlobUpload",
)
FORBIDDEN_PERMISSION_FRAGMENTS = (
    "impersonate",
    "jmap",
    "imap",
    "pop3",
    "smtp",
    "email",
    "blob",
    "identity",
    "submission",
    "sysAccountPassword",
    "sysApiKey",
    "sysAppPassword",
)
REQUIRED_QUERY_TYPES = (
    "NetworkListener",
    "Domain",
    "SystemSettings",
    "MtaRoute",
    "SieveSystemScript",
    "MtaStageRcpt",
    "Account",
    "ApiKey",
)
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DOMAIN_ID_REFERENCE = "Domain:local.test:id"
SIEVE_RELATIVE_PATH = "stalwart/protected-recipients.sieve"
KEY_OWNERSHIP_PREFIX = (
    "mail-sandbox/debug-dashboard/management/bootstrap-"
)
ACCOUNT_OWNERSHIP_PREFIX = (
    "mail-sandbox/debug-dashboard/account/bootstrap-"
)
TIMESTAMP_PATTERN = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",
)
SAFE_ID_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,255}")
INVOCATION_PATTERN = re.compile(r"[0-9a-f]{32}")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
MAXIMUM_JSON_SIZE = 4 * 1024 * 1024
MAXIMUM_ASSET_SIZE = 1024 * 1024
MAXIMUM_KEY_SIZE = 4096
ROUTING_PROCESS_IO_CHUNK_SIZE = 64 * 1024
ROUTING_PROCESS_TERMINATION_GRACE_SECONDS = 0.25
ROUTING_PROCESS_REAP_TIMEOUT_SECONDS = 1.0


class BootstrapError(RuntimeError):
    """A fixed bootstrap or reconciliation invariant was not satisfied."""


def _permission_map() -> dict[str, bool]:
    return {permission: True for permission in MANAGEMENT_PERMISSIONS}


def _account_permissions() -> dict[str, object]:
    return {
        "@type": "Replace",
        "disabledPermissions": {},
        "enabledPermissions": _permission_map(),
    }


def _key_permissions() -> dict[str, object]:
    return {
        "@type": "Replace",
        "permissions": _permission_map(),
    }


CANONICAL_SIEVE_TEXT = (
    'require ["envelope", "reject"];\n'
    "\n"
    'if envelope :is "to" "dashboard-management@local.test" {\n'
    '    reject "550 5.7.1 Recipient is reserved for dashboard management.";\n'
    "}\n"
    "\n"
    'if envelope :matches "to" "dashboard-management+*@local.test" {\n'
    '    reject "550 5.7.1 Recipient is reserved for dashboard management.";\n'
    "}\n"
)
CANONICAL_SIEVE_BYTES = CANONICAL_SIEVE_TEXT.encode("ascii")


def _manifest_records() -> tuple[dict[str, object], ...]:
    return (
        {
            "deferred_capabilities": ["directory", "tracer"],
            "kind": "metadata",
            "policy_input": SIEVE_RELATIVE_PATH,
            "schema": MANIFEST_SCHEMA,
        },
        {
            "desired": {
                "bind": {"[::]:8080": True},
                "name": "http",
                "protocol": "http",
                "tlsImplicit": False,
                "useTls": False,
            },
            "kind": "object",
            "lookup": {"name": "http"},
            "object_type": "NetworkListener",
        },
        {
            "desired": {
                "aliases": {},
                "allowRelaying": False,
                "catchAllAddress": None,
                "certificateManagement": {"@type": "Manual"},
                "directoryId": None,
                "dkimManagement": {"@type": "Manual"},
                "dnsManagement": {"@type": "Manual"},
                "isEnabled": True,
                "name": "local.test",
                "subAddressing": {"@type": "Enabled"},
            },
            "kind": "object",
            "lookup": {"name": "local.test"},
            "object_type": "Domain",
        },
        {
            "desired": {
                "defaultDomainId": {"$ref": DOMAIN_ID_REFERENCE},
                "defaultHostname": "stalwart.local.test",
            },
            "kind": "object",
            "lookup": {"id": "singleton"},
            "object_type": "SystemSettings",
        },
        {
            "desired": {
                "@type": "Local",
                "description": "mail-sandbox local-only delivery",
                "name": "local",
            },
            "kind": "object",
            "lookup": {"name": "local"},
            "object_type": "MtaRoute",
        },
        {
            "desired": {
                "contents": {"$asset": SIEVE_RELATIVE_PATH},
                "description": (
                    "Reject delivery to the protected dashboard management "
                    "recipient."
                ),
                "isActive": True,
                "name": "mail-sandbox-protected-recipients",
            },
            "kind": "object",
            "lookup": {"name": "mail-sandbox-protected-recipients"},
            "object_type": "SieveSystemScript",
        },
        {
            "desired": {
                "allowRelaying": {
                    "else": "false",
                    "match": {},
                },
                "script": {
                    "else": "'mail-sandbox-protected-recipients'",
                    "match": {},
                },
            },
            "kind": "object",
            "lookup": {"id": "singleton"},
            "object_type": "MtaStageRcpt",
        },
        {
            "desired": {
                "@type": "User",
                "aliases": {},
                "description": MANAGEMENT_KEY_DESCRIPTION,
                "domainId": {"$ref": DOMAIN_ID_REFERENCE},
                "name": MANAGEMENT_LOCAL_PART,
                "permissions": _account_permissions(),
                "roles": {"@type": "User"},
            },
            "kind": "object",
            "lookup": {"address": MANAGEMENT_ADDRESS},
            "object_type": "Account",
        },
        {
            "account": MANAGEMENT_ADDRESS,
            "allowed_ips": {},
            "description": MANAGEMENT_KEY_DESCRIPTION,
            "ip_restriction_decision": IP_RESTRICTION_DECISION,
            "kind": "api_key_intent",
            "permissions": _key_permissions(),
        },
    )


def _canonical_json_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError):
        raise BootstrapError("JSON value is not canonicalizable") from None


CANONICAL_MANIFEST_BYTES = b"".join(
    _canonical_json_bytes(record) + b"\n"
    for record in _manifest_records()
)
PERMISSIONS_SHA256 = hashlib.sha256(
    _canonical_json_bytes(list(MANAGEMENT_PERMISSIONS)),
).hexdigest()


def _redacted_repr(name: str) -> str:
    return f"{name}(<redacted>)"


@dataclass(frozen=True, repr=False)
class BootstrapPaths:
    repository_root: Path
    manifest: Path
    sieve: Path
    apply_receipt: Path
    attempt: Path
    account: Path
    replacement: Path
    key: Path
    proof: Path
    routing_intent: Path
    routing_proof: Path
    final_receipt: Path
    management_key: Path
    protected_accounts: Path
    routing_input: Path
    routing_sender_password: Path
    routing_recipient_password: Path

    @classmethod
    def for_repository(cls, repository_root: Path) -> "BootstrapPaths":
        if not isinstance(repository_root, Path):
            raise BootstrapError("repository root must be a Path")
        runtime = repository_root / "debug-dashboard" / ".runtime"
        bootstrap_root = runtime / "stalwart"
        return cls(
            repository_root=repository_root,
            manifest=repository_root / "stalwart" / "bootstrap-v016.ndjson",
            sieve=repository_root / "stalwart" / "protected-recipients.sieve",
            apply_receipt=runtime / "stalwart-migration" / "apply.json",
            attempt=bootstrap_root / "bootstrap-attempt.json",
            account=bootstrap_root / "bootstrap-account.json",
            replacement=bootstrap_root / "bootstrap-replacement.json",
            key=bootstrap_root / "bootstrap-key.json",
            proof=bootstrap_root / "bootstrap-proof.json",
            routing_intent=bootstrap_root / "bootstrap-routing-intent.json",
            routing_proof=bootstrap_root / "bootstrap-routing-proof.json",
            final_receipt=bootstrap_root / "bootstrap.json",
            management_key=runtime
            / "secrets"
            / "stalwart-management-api-key",
            protected_accounts=bootstrap_root / "protected-accounts.json",
            routing_input=bootstrap_root / "bootstrap-routing-input.json",
            routing_sender_password=runtime
            / "secrets"
            / "stalwart-routing-sender-password",
            routing_recipient_password=runtime
            / "secrets"
            / "stalwart-routing-recipient-password",
        )

    def __repr__(self) -> str:
        return _redacted_repr(type(self).__name__)


@dataclass(frozen=True, repr=False)
class FileBinding:
    path: Path
    sha256: str
    size: int
    identity: tuple[int, int, int, int, int, int]

    def __repr__(self) -> str:
        return _redacted_repr(type(self).__name__)


@dataclass(frozen=True, repr=False)
class SecretFileBinding:
    path: Path
    size: int
    identity: tuple[int, int, int, int, int, int, int, int]

    def __repr__(self) -> str:
        return _redacted_repr(type(self).__name__)


_TASK6_VALIDATION_MARKER = object()
_FINAL_BOOTSTRAP_VALIDATION_MARKER = object()


@dataclass(frozen=True, repr=False)
class ValidatedApplyReceipt:
    binding: FileBinding
    payload_sha256: str
    _marker: object

    def __repr__(self) -> str:
        return _redacted_repr(type(self).__name__)


@dataclass(frozen=True, repr=False)
class DesiredObject:
    object_type: str
    _lookup_json: str
    _desired_json: str

    def lookup_dict(self) -> dict[str, object]:
        return json.loads(self._lookup_json)

    def desired_dict(self) -> dict[str, object]:
        value = json.loads(self._desired_json)
        if self.object_type == "Account":
            value["permissions"]["enabledPermissions"] = _permission_map()
        return value

    def __repr__(self) -> str:
        return _redacted_repr(type(self).__name__)


@dataclass(frozen=True, repr=False)
class ApiKeyIntent:
    account: str
    description: str
    ip_restriction_decision: str
    _permissions_json: str
    _allowed_ips_json: str

    def permissions_dict(self) -> dict[str, object]:
        value = json.loads(self._permissions_json)
        value["permissions"] = _permission_map()
        return value

    def allowed_ips_dict(self) -> dict[str, object]:
        return json.loads(self._allowed_ips_json)

    def __repr__(self) -> str:
        return _redacted_repr(type(self).__name__)


@dataclass(frozen=True, repr=False)
class DesiredState:
    paths: BootstrapPaths
    manifest: FileBinding
    sieve: FileBinding
    objects: tuple[DesiredObject, ...]
    api_key_intent: ApiKeyIntent
    deferred_capabilities: tuple[str, ...]

    def object(self, object_type: str) -> DesiredObject:
        matches = tuple(
            item for item in self.objects if item.object_type == object_type
        )
        if len(matches) != 1:
            raise BootstrapError("desired object type is absent or ambiguous")
        return matches[0]

    def __repr__(self) -> str:
        return _redacted_repr(type(self).__name__)


@dataclass(frozen=True, repr=False)
class BootstrapInputs:
    desired: DesiredState
    validated_apply: ValidatedApplyReceipt

    @property
    def apply_receipt(self) -> FileBinding:
        return self.validated_apply.binding

    def __repr__(self) -> str:
        return _redacted_repr(type(self).__name__)


def _json_text(value: object) -> str:
    return _canonical_json_bytes(value).decode("utf-8")


def _identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
    )


def _secret_identity(
    metadata: os.stat_result,
) -> tuple[int, int, int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _normalized_absolute(path: Path, label: str) -> Path:
    if (
        not isinstance(path, Path)
        or not path.is_absolute()
        or Path(os.path.normpath(str(path))) != path
    ):
        raise BootstrapError(f"{label} must be a normalized absolute path")
    return path


def _require_real_root(root: Path) -> None:
    _normalized_absolute(root, "repository root")
    try:
        metadata = root.lstat()
    except OSError:
        raise BootstrapError("repository root is unavailable") from None
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise BootstrapError("repository root must be a real directory")


def _require_no_symlink_components(
    root: Path,
    path: Path,
    label: str,
) -> None:
    _require_real_root(root)
    _normalized_absolute(path, label)
    try:
        relative = path.relative_to(root)
    except ValueError:
        raise BootstrapError(f"{label} is outside the repository root") from None
    if relative == Path("."):
        raise BootstrapError(f"{label} is too broad")
    current = root
    for part in relative.parts:
        current = current / part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            return
        except OSError:
            raise BootstrapError(f"{label} could not be inspected") from None
        if stat.S_ISLNK(metadata.st_mode):
            raise BootstrapError(f"{label} must not contain symlinks")


def _validate_fixed_paths(paths: BootstrapPaths) -> None:
    if not isinstance(paths, BootstrapPaths):
        raise BootstrapError("bootstrap paths are malformed")
    root = _normalized_absolute(paths.repository_root, "repository root")
    if paths != BootstrapPaths.for_repository(root):
        raise BootstrapError("bootstrap paths differ from the fixed layout")
    _require_real_root(root)


def _require_owner_runtime_directories(paths: BootstrapPaths) -> None:
    runtime = paths.repository_root / "debug-dashboard" / ".runtime"
    for directory, label in (
        (runtime, "dashboard runtime directory"),
        (runtime / "stalwart", "Stalwart runtime directory"),
        (runtime / "secrets", "runtime secrets directory"),
        (runtime / "stalwart-migration", "migration runtime directory"),
    ):
        _require_no_symlink_components(
            paths.repository_root,
            directory,
            label,
        )
        try:
            metadata = directory.lstat()
        except OSError:
            raise BootstrapError(f"{label} is unavailable") from None
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise BootstrapError(f"{label} must be a real mode-0700 directory")


def _open_regular(
    path: Path,
    *,
    root: Path,
    label: str,
    required_mode: int,
) -> tuple[int, os.stat_result]:
    _require_no_symlink_components(root, path, label)
    try:
        before = path.lstat()
    except OSError:
        raise BootstrapError(f"{label} is unavailable") from None
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or stat.S_IMODE(before.st_mode) != required_mode
        or before.st_nlink != 1
    ):
        raise BootstrapError(f"{label} has unsafe type, mode, or links")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise BootstrapError(f"{label} could not be opened safely") from None
    try:
        opened = os.fstat(descriptor)
    except OSError:
        os.close(descriptor)
        raise BootstrapError(f"{label} could not be inspected safely") from None
    if (
        not stat.S_ISREG(opened.st_mode)
        or stat.S_IMODE(opened.st_mode) != required_mode
        or opened.st_nlink != 1
        or _identity(opened) != _identity(before)
    ):
        os.close(descriptor)
        raise BootstrapError(f"{label} changed while opening")
    return descriptor, opened


def _snapshot_regular(
    path: Path,
    *,
    root: Path,
    label: str,
    required_mode: int,
    maximum: int,
) -> tuple[FileBinding, bytes]:
    descriptor, opened = _open_regular(
        path,
        root=root,
        label=label,
        required_mode=required_mode,
    )
    content = bytearray()
    try:
        while True:
            chunk = os.read(descriptor, min(65536, maximum + 1 - len(content)))
            if not chunk:
                break
            content.extend(chunk)
            if len(content) > maximum:
                raise BootstrapError(f"{label} is too large")
    except OSError:
        raise BootstrapError(f"{label} could not be read safely") from None
    finally:
        try:
            os.close(descriptor)
        except OSError:
            raise BootstrapError(f"{label} could not be closed safely") from None
    try:
        after = path.lstat()
    except OSError:
        raise BootstrapError(f"{label} changed while reading") from None
    if (
        _identity(after) != _identity(opened)
        or after.st_size != len(content)
        or opened.st_size != len(content)
    ):
        raise BootstrapError(f"{label} changed while reading")
    raw = bytes(content)
    binding = FileBinding(
        path=path,
        sha256=hashlib.sha256(raw).hexdigest(),
        size=len(raw),
        identity=_identity(after),
    )
    return binding, raw


def _snapshot_secret(
    path: Path,
    *,
    root: Path,
) -> SecretFileBinding:
    descriptor, opened = _open_regular(
        path,
        root=root,
        label="management key file",
        required_mode=0o600,
    )
    try:
        after_open = os.fstat(descriptor)
    except OSError:
        raise BootstrapError("management key file could not be inspected") from None
    finally:
        try:
            os.close(descriptor)
        except OSError:
            raise BootstrapError("management key file could not be closed") from None
    try:
        after = path.lstat()
    except OSError:
        raise BootstrapError("management key file changed") from None
    if (
        _secret_identity(opened) != _secret_identity(after_open)
        or _secret_identity(after_open) != _secret_identity(after)
        or after.st_size < 5
        or after.st_size > MAXIMUM_KEY_SIZE
    ):
        raise BootstrapError("management key file is malformed or changed")
    return SecretFileBinding(
        path=path,
        size=after.st_size,
        identity=_secret_identity(after),
    )


def _path_present(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    except OSError:
        raise BootstrapError("runtime path could not be inspected") from None
    return True


def _reject_constant(_value: str) -> object:
    raise BootstrapError("non-finite JSON number is forbidden")


def _reject_float(_value: str) -> object:
    raise BootstrapError("JSON floating-point numbers are forbidden")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise BootstrapError("duplicate JSON object key")
        result[key] = value
    return result


def _strict_json_bytes(content: bytes, label: str) -> object:
    try:
        text = content.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, BootstrapError):
        raise BootstrapError(f"{label} contains malformed JSON") from None
    return value


def _validate_task6_file_metadata(
    value: object,
    *,
    expected_name: str,
    label: str,
) -> None:
    if (
        not isinstance(value, dict)
        or set(value) != {"identity", "name", "sha256", "size"}
        or value.get("name") != expected_name
        or type(value.get("sha256")) is not str
        or SHA256_PATTERN.fullmatch(value["sha256"]) is None
        or type(value.get("size")) is not int
        or value["size"] < 0
        or not isinstance(value.get("identity"), list)
        or len(value["identity"]) != 6
        or any(
            type(item) is not int or item < 0
            for item in value["identity"]
        )
    ):
        raise BootstrapError(f"{label} metadata is malformed")


def _validate_task6_file_list(
    value: object,
    *,
    expected_names: tuple[str, ...],
    label: str,
) -> None:
    if not isinstance(value, list) or len(value) != len(expected_names):
        raise BootstrapError(f"{label} metadata is malformed")
    for item, name in zip(value, expected_names, strict=True):
        _validate_task6_file_metadata(
            item,
            expected_name=name,
            label=label,
        )


def _validate_task6_apply_payload(payload: object) -> dict[str, object]:
    if not isinstance(payload, dict) or set(payload) != {
        "applied_at",
        "artifacts",
        "attempt",
        "inputs",
        "post_apply_proof",
        "runtime_artifacts",
        "schema",
        "summary",
    }:
        raise BootstrapError("Task 6 apply receipt is malformed")
    _validate_time(payload.get("applied_at"), "Task 6 apply time")
    if payload.get("schema") != "mail-sandbox.stalwart-v016-apply.v2":
        raise BootstrapError("Task 6 apply receipt schema is unsupported")
    _validate_task6_file_list(
        payload.get("inputs"),
        expected_names=(
            "latest-source.json",
            "migrate_v016.py",
            "dry-run.json",
            "reviewed.json",
            "docker-compose.stalwart-migration.yml",
            "docker-compose.yml",
        ),
        label="Task 6 apply input",
    )
    _validate_task6_file_list(
        payload.get("artifacts"),
        expected_names=(
            "settings.json",
            "principals.json",
            "config.json",
            "export.json",
            "unmigrated.txt",
        ),
        label="Task 6 apply artifact",
    )
    _validate_task6_file_metadata(
        payload.get("attempt"),
        expected_name="apply-attempt.json",
        label="Task 6 apply attempt",
    )
    proof = payload.get("post_apply_proof")
    if (
        not isinstance(proof, dict)
        or set(proof) != {
            "management_status",
            "operation_count",
            "operations_sha256",
            "server_version",
        }
        or proof.get("server_version") != SERVER_VERSION
        or type(proof.get("management_status")) is not int
        or proof["management_status"] != 200
        or type(proof.get("operation_count")) is not int
        or proof["operation_count"] <= 0
        or type(proof.get("operations_sha256")) is not str
        or SHA256_PATTERN.fullmatch(proof["operations_sha256"]) is None
    ):
        raise BootstrapError("Task 6 post-apply proof is malformed")
    summary = payload.get("summary")
    if (
        not isinstance(summary, dict)
        or set(summary) != {"created", "destroyed", "failed", "updated"}
        or any(
            type(summary.get(name)) is not int or summary[name] < 0
            for name in summary
        )
        or summary["failed"] != 0
    ):
        raise BootstrapError("Task 6 apply summary is not successful")
    runtime = payload.get("runtime_artifacts")
    if (
        not isinstance(runtime, dict)
        or set(runtime) != {
            "config",
            "config_directory_identity",
            "recovery_environment",
        }
        or not isinstance(runtime.get("config_directory_identity"), list)
        or len(runtime["config_directory_identity"]) != 6
        or any(
            type(item) is not int or item < 0
            for item in runtime["config_directory_identity"]
        )
    ):
        raise BootstrapError("Task 6 runtime commitment is malformed")
    _validate_task6_file_metadata(
        runtime.get("config"),
        expected_name="config.json",
        label="Task 6 runtime config",
    )
    recovery = runtime.get("recovery_environment")
    if (
        not isinstance(recovery, dict)
        or set(recovery) != {"identity", "name", "size"}
        or recovery.get("name") != "recovery.env"
        or type(recovery.get("size")) is not int
        or recovery["size"] < 32
        or not isinstance(recovery.get("identity"), list)
        or len(recovery["identity"]) != 6
        or any(
            type(item) is not int or item < 0
            for item in recovery["identity"]
        )
    ):
        raise BootstrapError("Task 6 recovery commitment is malformed")
    return payload


def validate_task6_apply_receipt(
    paths: BootstrapPaths,
    *,
    validator: object,
) -> ValidatedApplyReceipt:
    """Bind a stable receipt accepted by the authoritative Task 6 validator.

    The callback is an explicit integration seam.  Production must supply the
    full Task 6 validator; this planner neither weakens nor substitutes it.
    """
    _validate_fixed_paths(paths)
    _require_owner_runtime_directories(paths)
    if not callable(validator):
        raise BootstrapError("authoritative Task 6 validator is unavailable")
    before, content = _snapshot_regular(
        paths.apply_receipt,
        root=paths.repository_root,
        label="migration apply receipt",
        required_mode=0o600,
        maximum=MAXIMUM_JSON_SIZE,
    )
    if not content.endswith(b"\n") or content.count(b"\n") != 1:
        raise BootstrapError("Task 6 apply receipt is not canonical JSON")
    parsed = _strict_json_bytes(content[:-1], "Task 6 apply receipt")
    if _canonical_json_bytes(parsed) + b"\n" != content:
        raise BootstrapError("Task 6 apply receipt is not canonical JSON")
    _validate_task6_apply_payload(parsed)
    try:
        validated = validator(paths.apply_receipt)
    except Exception:
        raise BootstrapError(
            "authoritative Task 6 apply validation failed safely",
        ) from None
    if (
        not isinstance(validated, dict)
        or _canonical_json_bytes(validated)
        != _canonical_json_bytes(parsed)
    ):
        raise BootstrapError(
            "authoritative Task 6 validator returned different evidence",
        )
    after, after_content = _snapshot_regular(
        paths.apply_receipt,
        root=paths.repository_root,
        label="migration apply receipt",
        required_mode=0o600,
        maximum=MAXIMUM_JSON_SIZE,
    )
    if before != after or content != after_content:
        raise BootstrapError("Task 6 apply receipt changed during validation")
    return ValidatedApplyReceipt(
        binding=after,
        payload_sha256=hashlib.sha256(
            _canonical_json_bytes(parsed),
        ).hexdigest(),
        _marker=_TASK6_VALIDATION_MARKER,
    )


def _parse_manifest(content: bytes) -> tuple[dict[str, object], ...]:
    if not content or not content.endswith(b"\n") or b"\r" in content:
        raise BootstrapError("bootstrap manifest is not canonical NDJSON")
    lines = content[:-1].split(b"\n")
    parsed: list[dict[str, object]] = []
    for line in lines:
        value = _strict_json_bytes(line, "bootstrap manifest record")
        if (
            not isinstance(value, dict)
            or _canonical_json_bytes(value) != line
        ):
            raise BootstrapError("bootstrap manifest record is not canonical")
        parsed.append(value)
    expected = _manifest_records()
    if (
        content != CANONICAL_MANIFEST_BYTES
        or len(parsed) != len(expected)
        or _canonical_json_bytes(parsed) != _canonical_json_bytes(expected)
    ):
        raise BootstrapError("bootstrap manifest differs from the fixed contract")
    return tuple(parsed)


def _validate_permissions() -> None:
    if (
        len(MANAGEMENT_PERMISSIONS) != len(set(MANAGEMENT_PERMISSIONS))
        or any(
            "*" in permission
            or any(fragment in permission for fragment in FORBIDDEN_PERMISSION_FRAGMENTS)
            for permission in MANAGEMENT_PERMISSIONS
        )
    ):
        raise BootstrapError("management permission set is unsafe")


def load_desired_state(paths: BootstrapPaths) -> DesiredState:
    """Load the two fixed, tracked inputs without performing any live action."""
    _validate_fixed_paths(paths)
    manifest, manifest_content = _snapshot_regular(
        paths.manifest,
        root=paths.repository_root,
        label="bootstrap manifest",
        required_mode=0o644,
        maximum=MAXIMUM_ASSET_SIZE,
    )
    sieve, sieve_content = _snapshot_regular(
        paths.sieve,
        root=paths.repository_root,
        label="protected-recipient Sieve policy",
        required_mode=0o644,
        maximum=MAXIMUM_ASSET_SIZE,
    )
    records = _parse_manifest(manifest_content)
    if sieve_content != CANONICAL_SIEVE_BYTES:
        raise BootstrapError("protected-recipient Sieve policy is not canonical")
    _validate_permissions()

    desired_objects: list[DesiredObject] = []
    for record in records[1:-1]:
        object_type = record.get("object_type")
        lookup = record.get("lookup")
        desired = record.get("desired")
        if (
            type(object_type) is not str
            or not isinstance(lookup, dict)
            or not isinstance(desired, dict)
        ):
            raise BootstrapError("desired object record is malformed")
        desired_copy = json.loads(_json_text(desired))
        if object_type == "SieveSystemScript":
            if desired_copy.get("contents") != {"$asset": SIEVE_RELATIVE_PATH}:
                raise BootstrapError("Sieve object does not bind the fixed policy")
            desired_copy["contents"] = CANONICAL_SIEVE_TEXT
        if object_type == "Account":
            desired_copy["permissions"]["enabledPermissions"] = _permission_map()
        desired_objects.append(
            DesiredObject(
                object_type=object_type,
                _lookup_json=_json_text(lookup),
                _desired_json=_json_text(desired_copy),
            ),
        )
    intent = records[-1]
    if intent.get("kind") != "api_key_intent":
        raise BootstrapError("management API-key intent is absent")
    permissions = intent.get("permissions")
    allowed_ips = intent.get("allowed_ips")
    if not isinstance(permissions, dict) or not isinstance(allowed_ips, dict):
        raise BootstrapError("management API-key intent is malformed")
    permissions_copy = json.loads(_json_text(permissions))
    permissions_copy["permissions"] = _permission_map()
    metadata = records[0]
    deferred = metadata.get("deferred_capabilities")
    if (
        not isinstance(deferred, list)
        or any(type(item) is not str for item in deferred)
    ):
        raise BootstrapError("deferred capability metadata is malformed")
    return DesiredState(
        paths=paths,
        manifest=manifest,
        sieve=sieve,
        objects=tuple(desired_objects),
        api_key_intent=ApiKeyIntent(
            account=MANAGEMENT_ADDRESS,
            description=MANAGEMENT_KEY_DESCRIPTION,
            ip_restriction_decision=IP_RESTRICTION_DECISION,
            _permissions_json=_json_text(permissions_copy),
            _allowed_ips_json=_json_text(allowed_ips),
        ),
        deferred_capabilities=tuple(deferred),
    )


def load_bootstrap_inputs(
    paths: BootstrapPaths,
    *,
    validated_apply: ValidatedApplyReceipt | None = None,
) -> BootstrapInputs:
    desired = load_desired_state(paths)
    _require_owner_runtime_directories(paths)
    if (
        not isinstance(validated_apply, ValidatedApplyReceipt)
        or validated_apply._marker is not _TASK6_VALIDATION_MARKER
        or validated_apply.binding.path != paths.apply_receipt
    ):
        raise BootstrapError(
            "authoritative Task 6 apply validation is required",
        )
    apply_receipt, content = _snapshot_regular(
        paths.apply_receipt,
        root=paths.repository_root,
        label="migration apply receipt",
        required_mode=0o600,
        maximum=MAXIMUM_JSON_SIZE,
    )
    if apply_receipt != validated_apply.binding:
        raise BootstrapError("validated Task 6 apply receipt changed")
    parsed = _strict_json_bytes(content[:-1], "Task 6 apply receipt")
    if (
        not content.endswith(b"\n")
        or content.count(b"\n") != 1
        or hashlib.sha256(_canonical_json_bytes(parsed)).hexdigest()
        != validated_apply.payload_sha256
    ):
        raise BootstrapError("validated Task 6 apply receipt is stale")
    return BootstrapInputs(
        desired=desired,
        validated_apply=validated_apply,
    )


def _contains_sensitive_field(value: object) -> bool:
    if isinstance(value, dict):
        for key, nested in value.items():
            lowered = key.lower()
            if lowered in {
                "secret",
                "password",
                "token",
                "rawkey",
                "raw_key",
            }:
                return True
            if _contains_sensitive_field(nested):
                return True
    elif isinstance(value, list):
        return any(_contains_sensitive_field(item) for item in value)
    return False


def _validate_json_tree(value: object) -> None:
    if value is None or type(value) in {str, bool, int}:
        return
    if isinstance(value, list):
        for item in value:
            _validate_json_tree(item)
        return
    if isinstance(value, dict):
        for key, nested in value.items():
            if type(key) is not str:
                raise BootstrapError("JSON object key is malformed")
            _validate_json_tree(nested)
        return
    raise BootstrapError("JSON value has an unsupported type")


@dataclass(frozen=True, repr=False)
class ObservedObject:
    object_type: str
    object_id: str
    _value_json: str

    @classmethod
    def from_mapping(
        cls,
        object_type: str,
        object_id: str,
        value: Mapping[str, object],
    ) -> "ObservedObject":
        if (
            type(object_type) is not str
            or object_type not in REQUIRED_QUERY_TYPES
            or object_type == "ApiKey"
            or type(object_id) is not str
            or SAFE_ID_PATTERN.fullmatch(object_id) is None
            or not isinstance(value, Mapping)
        ):
            raise BootstrapError("observed object is malformed")
        copied = dict(value)
        _validate_json_tree(copied)
        if _contains_sensitive_field(copied):
            raise BootstrapError("observed projection contains a secret field")
        return cls(
            object_type=object_type,
            object_id=object_id,
            _value_json=_json_text(copied),
        )

    def value_dict(self) -> dict[str, object]:
        return json.loads(self._value_json)

    def __repr__(self) -> str:
        return _redacted_repr(type(self).__name__)


@dataclass(frozen=True, repr=False)
class CredentialProjection:
    account_id: str
    credential_id: str
    credential_type: str
    description: str | None
    _permissions_json: str | None
    _allowed_ips_json: str

    @classmethod
    def from_mapping(
        cls,
        *,
        account_id: str,
        credential_id: str,
        credential_type: str,
        description: str | None,
        permissions: Mapping[str, object] | None,
        allowed_ips: Mapping[str, object],
    ) -> "CredentialProjection":
        if (
            type(account_id) is not str
            or SAFE_ID_PATTERN.fullmatch(account_id) is None
            or type(credential_id) is not str
            or SAFE_ID_PATTERN.fullmatch(credential_id) is None
            or type(credential_type) is not str
            or re.fullmatch(r"[A-Za-z][A-Za-z0-9]{0,31}", credential_type)
            is None
            or (
                description is not None
                and (
                    type(description) is not str
                    or not description
                    or len(description) > 512
                )
            )
            or (
                permissions is not None
                and not isinstance(permissions, Mapping)
            )
            or not isinstance(allowed_ips, Mapping)
        ):
            raise BootstrapError("credential projection is malformed")
        permission_copy = (
            None if permissions is None else dict(permissions)
        )
        allowed_copy = dict(allowed_ips)
        _validate_json_tree(permission_copy)
        _validate_json_tree(allowed_copy)
        if (
            _contains_sensitive_field(permission_copy)
            or _contains_sensitive_field(allowed_copy)
        ):
            raise BootstrapError("credential projection contains a secret")
        return cls(
            account_id=account_id,
            credential_id=credential_id,
            credential_type=credential_type,
            description=description,
            _permissions_json=(
                None
                if permission_copy is None
                else _json_text(permission_copy)
            ),
            _allowed_ips_json=_json_text(allowed_copy),
        )

    def permissions_dict(self) -> dict[str, object] | None:
        return (
            None
            if self._permissions_json is None
            else json.loads(self._permissions_json)
        )

    def allowed_ips_dict(self) -> dict[str, object]:
        return json.loads(self._allowed_ips_json)

    def __repr__(self) -> str:
        return _redacted_repr(type(self).__name__)


RemoteKey = CredentialProjection


@dataclass(frozen=True, repr=False)
class ObservedState:
    queried_types: tuple[str, ...]
    objects: tuple[ObservedObject, ...]
    api_keys: tuple[CredentialProjection, ...]

    def __post_init__(self) -> None:
        if (
            type(self.queried_types) is not tuple
            or any(type(item) is not str for item in self.queried_types)
            or type(self.objects) is not tuple
            or any(not isinstance(item, ObservedObject) for item in self.objects)
            or type(self.api_keys) is not tuple
            or any(
                not isinstance(item, CredentialProjection)
                for item in self.api_keys
            )
        ):
            raise BootstrapError("observed state is malformed")

    def __repr__(self) -> str:
        return _redacted_repr(type(self).__name__)


@dataclass(frozen=True, repr=False)
class AccountOwnership:
    invocation_id: str
    account_id: str
    domain_id: str
    temporary_account_description: str
    orphan_key_description: str

    def __post_init__(self) -> None:
        expected = KEY_OWNERSHIP_PREFIX + self.invocation_id
        expected_account = ACCOUNT_OWNERSHIP_PREFIX + self.invocation_id
        if (
            type(self.invocation_id) is not str
            or INVOCATION_PATTERN.fullmatch(self.invocation_id) is None
            or type(self.account_id) is not str
            or SAFE_ID_PATTERN.fullmatch(self.account_id) is None
            or type(self.domain_id) is not str
            or SAFE_ID_PATTERN.fullmatch(self.domain_id) is None
            or self.temporary_account_description != expected_account
            or self.orphan_key_description != expected
        ):
            raise BootstrapError("account ownership checkpoint is malformed")

    def __repr__(self) -> str:
        return _redacted_repr(type(self).__name__)


@dataclass(frozen=True, repr=False)
class Action:
    kind: str
    object_type: str
    object_id: str | None
    _changes_json: str = "{}"

    def changes_dict(self) -> dict[str, object]:
        return json.loads(self._changes_json)

    def __repr__(self) -> str:
        return (
            "Action("
            f"kind={self.kind!r}, object_type={self.object_type!r}, "
            "object_id=<redacted>, changes=<redacted>)"
        )


@dataclass(frozen=True, repr=False)
class ReconciliationPlan:
    state: str
    actions: tuple[Action, ...]

    def __repr__(self) -> str:
        return _redacted_repr(type(self).__name__)


def _resolve_references(value: object, domain_id: str) -> object:
    if isinstance(value, dict):
        if set(value) == {"$ref"}:
            if value["$ref"] != DOMAIN_ID_REFERENCE:
                raise BootstrapError("desired state contains an unknown reference")
            return domain_id
        return {
            key: _resolve_references(nested, domain_id)
            for key, nested in value.items()
        }
    if isinstance(value, list):
        return [_resolve_references(item, domain_id) for item in value]
    return value


def _target_matches(
    desired: DesiredObject,
    observed: ObservedObject,
    domain_id: str | None,
) -> bool:
    value = observed.value_dict()
    if observed.object_type != desired.object_type:
        return False
    lookup = desired.lookup_dict()
    if desired.object_type in {"SystemSettings", "MtaStageRcpt"}:
        return observed.object_id == "singleton"
    if desired.object_type == "Account":
        return value.get("name") == MANAGEMENT_LOCAL_PART
    for key, expected in lookup.items():
        if key == "id":
            if observed.object_id != expected:
                return False
        elif value.get(key) != expected:
            return False
    return True


def _validate_compatible_types(
    expected: object,
    actual: object,
    *,
    path: str,
) -> None:
    if expected is None:
        return
    if isinstance(expected, dict):
        if not isinstance(actual, dict):
            raise BootstrapError(f"observed {path} has a conflicting type")
        for key, nested in expected.items():
            if key in actual:
                _validate_compatible_types(
                    nested,
                    actual[key],
                    path=f"{path}/{key}",
                )
        return
    if isinstance(expected, list):
        if not isinstance(actual, list):
            raise BootstrapError(f"observed {path} has a conflicting type")
        return
    if type(expected) is not type(actual):
        raise BootstrapError(f"observed {path} has a conflicting type")


_EXACT_TOP_LEVEL_FIELDS: dict[str, frozenset[str]] = {
    "NetworkListener": frozenset({"bind"}),
    "Domain": frozenset(
        {
            "aliases",
            "allowRelaying",
            "catchAllAddress",
            "directoryId",
        },
    ),
    "MtaStageRcpt": frozenset({"allowRelaying", "script"}),
    "Account": frozenset(
        {
            "@type",
            "aliases",
            "description",
            "domainId",
            "name",
            "permissions",
            "roles",
        },
    ),
}


def _compatible_nested_patch(
    expected: dict[str, object],
    observed: dict[str, object],
    *,
    prefix: str,
) -> dict[str, object]:
    patch: dict[str, object] = {}
    for key, nested_expected in expected.items():
        path = f"{prefix}/{key}"
        if key not in observed:
            patch[path] = nested_expected
            continue
        nested_observed = observed[key]
        if isinstance(nested_expected, dict) and isinstance(
            nested_observed,
            dict,
        ):
            patch.update(
                _compatible_nested_patch(
                    nested_expected,
                    nested_observed,
                    prefix=path,
                ),
            )
        elif nested_observed != nested_expected:
            patch[path] = nested_expected
    return patch


def _desired_patch(
    desired: dict[str, object],
    observed: dict[str, object],
    *,
    object_type: str,
) -> dict[str, object]:
    patch: dict[str, object] = {}
    exact_fields = _EXACT_TOP_LEVEL_FIELDS.get(object_type, frozenset())
    for key, expected in desired.items():
        if key not in observed:
            patch[key] = expected
            continue
        actual = observed[key]
        if key in exact_fields:
            if actual != expected:
                patch[key] = expected
        elif isinstance(expected, dict) and isinstance(actual, dict):
            patch.update(
                _compatible_nested_patch(
                    expected,
                    actual,
                    prefix=key,
                ),
            )
        elif actual != expected:
            patch[key] = expected
    return patch


def plan_reconciliation(
    desired: DesiredState,
    observed: ObservedState,
    *,
    ownership: AccountOwnership | None,
    attempt: AttemptCheckpoint | None = None,
) -> ReconciliationPlan:
    """Plan query-first create/patch/no-op actions without performing them."""
    if not isinstance(desired, DesiredState) or not isinstance(
        observed,
        ObservedState,
    ):
        raise BootstrapError("reconciliation inputs are malformed")
    if observed.queried_types != REQUIRED_QUERY_TYPES:
        raise BootstrapError("all fixed object types must be queried first")
    if ownership is not None and not isinstance(ownership, AccountOwnership):
        raise BootstrapError("management ownership is malformed")
    if attempt is not None and not isinstance(attempt, AttemptCheckpoint):
        raise BootstrapError("bootstrap attempt is malformed")
    if (
        attempt is not None
        and ownership is not None
        and attempt.invocation_id != ownership.invocation_id
    ):
        raise BootstrapError("attempt and Account ownership differ")

    by_type: dict[str, list[ObservedObject]] = {
        object_type: [] for object_type in REQUIRED_QUERY_TYPES[:-1]
    }
    for item in observed.objects:
        if item.object_type not in by_type:
            raise BootstrapError("observed object type is outside the fixed query")
        by_type[item.object_type].append(item)

    domains = [
        item
        for item in by_type["Domain"]
        if item.value_dict().get("name") == "local.test"
    ]
    if len(domains) > 1:
        raise BootstrapError("local.test Domain query is ambiguous")
    domain_id = domains[0].object_id if domains else None
    actions: list[Action] = []
    domain_requery_required = False
    for target in desired.objects:
        if domain_id is None and target.object_type in {
            "SystemSettings",
            "Account",
        }:
            if target.object_type == "Account" and any(
                item.value_dict().get("name") == MANAGEMENT_LOCAL_PART
                for item in by_type["Account"]
            ):
                raise BootstrapError(
                    "management Account preexists before Domain ownership is known",
                )
            actions.append(
                Action(
                    kind="requery-after-domain-create",
                    object_type=target.object_type,
                    object_id=None,
                ),
            )
            domain_requery_required = True
            continue
        candidates = [
            item
            for item in by_type[target.object_type]
            if _target_matches(target, item, domain_id)
        ]
        if target.object_type == "Account":
            name_conflicts = [
                item
                for item in by_type["Account"]
                if item.value_dict().get("name") == MANAGEMENT_LOCAL_PART
                and item not in candidates
            ]
            if name_conflicts:
                raise BootstrapError(
                    "management Account name resolves to a conflicting Domain",
                )
        if len(candidates) > 1:
            raise BootstrapError(
                f"{target.object_type} query is duplicate or ambiguous",
            )
        assert domain_id is not None or target.object_type not in {
            "SystemSettings",
            "Account",
        }
        resolved = _resolve_references(
            target.desired_dict(),
            domain_id if domain_id is not None else "",
        )
        if not isinstance(resolved, dict):
            raise BootstrapError("resolved desired object is malformed")
        if not candidates:
            if target.object_type == "Account" and ownership is not None:
                raise BootstrapError("owned management Account is unexpectedly absent")
            if target.object_type == "Account":
                if attempt is None:
                    raise BootstrapError(
                        "durable attempt is required before Account creation",
                    )
                resolved["description"] = (
                    attempt.account_ownership_description
                )
            actions.append(
                Action(
                    kind=(
                        "create-with-ownership-marker"
                        if target.object_type == "Account"
                        else "create"
                    ),
                    object_type=target.object_type,
                    object_id=None,
                    _changes_json=_json_text(resolved),
                ),
            )
            continue
        current = candidates[0]
        current_value = current.value_dict()
        if target.object_type == "Account":
            if ownership is None:
                if (
                    attempt is not None
                    and current_value.get("domainId") == domain_id
                    and current_value.get("description")
                    == attempt.account_ownership_description
                ):
                    actions.append(
                        Action(
                            kind="checkpoint-account-before-finalize",
                            object_type="Account",
                            object_id=current.object_id,
                        ),
                    )
                    continue
                raise BootstrapError(
                    "management Account preexists without durable ownership",
                )
            if (
                current.object_id != ownership.account_id
                or current_value.get("domainId") != ownership.domain_id
                or domain_id != ownership.domain_id
            ):
                raise BootstrapError(
                    "management Account differs from its ownership checkpoint",
                )
        if "@type" in resolved and current_value.get("@type") not in {
            None,
            resolved["@type"],
        }:
            raise BootstrapError(
                f"{target.object_type} has a conflicting registry type",
            )
        _validate_compatible_types(
            resolved,
            current_value,
            path=target.object_type,
        )
        patch = _desired_patch(
            resolved,
            current_value,
            object_type=target.object_type,
        )
        actions.append(
            Action(
                kind="noop" if not patch else "patch",
                object_type=target.object_type,
                object_id=current.object_id,
                _changes_json=_json_text(patch),
            ),
        )
    return ReconciliationPlan(
        state=(
            "domain-create-requery-required"
            if domain_requery_required
            else (
                "account-ownership-checkpoint-required"
                if any(
                    action.kind == "checkpoint-account-before-finalize"
                    for action in actions
                )
                else (
                    "account-create-with-ownership-marker-planned"
                    if any(
                        action.kind == "create-with-ownership-marker"
                        for action in actions
                    )
                    else (
                        "reconciled"
                        if all(action.kind == "noop" for action in actions)
                        else "reconciliation-planned"
                    )
                )
            )
        ),
        actions=tuple(actions),
    )


def _file_metadata(binding: FileBinding) -> dict[str, object]:
    return {
        "identity": list(binding.identity),
        "name": binding.path.name,
        "sha256": binding.sha256,
        "size": binding.size,
    }


def _secret_metadata(binding: SecretFileBinding) -> dict[str, object]:
    return {
        "identity": list(binding.identity),
        "name": binding.path.name,
        "size": binding.size,
    }


def _validate_time(value: object, label: str) -> str:
    if type(value) is not str or TIMESTAMP_PATTERN.fullmatch(value) is None:
        raise BootstrapError(f"{label} is malformed")
    return value


def _validate_id(value: object, label: str) -> str:
    if type(value) is not str or SAFE_ID_PATTERN.fullmatch(value) is None:
        raise BootstrapError(f"{label} is malformed")
    return value


def _validate_invocation(value: object) -> str:
    if type(value) is not str or INVOCATION_PATTERN.fullmatch(value) is None:
        raise BootstrapError("bootstrap invocation ID is malformed")
    return value


def _binding_from_metadata(
    value: object,
    *,
    path: Path,
    require_digest: bool,
    label: str,
) -> FileBinding | SecretFileBinding:
    keys = {"identity", "name", "size"}
    if require_digest:
        keys.add("sha256")
    if (
        not isinstance(value, dict)
        or set(value) != keys
        or value.get("name") != path.name
        or type(value.get("size")) is not int
        or value["size"] < 0
        or not isinstance(value.get("identity"), list)
        or len(value["identity"]) != (6 if require_digest else 8)
        or any(
            type(item) is not int
            or item < 0
            or item > MAXIMUM_IDENTITY_COMPONENT
            for item in value["identity"]
        )
    ):
        raise BootstrapError(f"{label} metadata is malformed")
    identity = tuple(value["identity"])
    if require_digest:
        digest = value.get("sha256")
        if type(digest) is not str or SHA256_PATTERN.fullmatch(digest) is None:
            raise BootstrapError(f"{label} digest is malformed")
        return FileBinding(
            path=path,
            sha256=digest,
            size=value["size"],
            identity=identity,
        )
    return SecretFileBinding(
        path=path,
        size=value["size"],
        identity=identity,
    )


def _same_public_binding(
    metadata: object,
    binding: FileBinding,
    label: str,
) -> None:
    parsed = _binding_from_metadata(
        metadata,
        path=binding.path,
        require_digest=True,
        label=label,
    )
    if parsed != binding:
        raise BootstrapError(f"{label} changed or is stale")


def _read_envelope(
    path: Path,
    *,
    root: Path,
    label: str,
) -> tuple[dict[str, object], FileBinding]:
    binding, content = _snapshot_regular(
        path,
        root=root,
        label=label,
        required_mode=0o600,
        maximum=MAXIMUM_JSON_SIZE,
    )
    if not content.endswith(b"\n") or content.count(b"\n") != 1:
        raise BootstrapError(f"{label} is not canonical JSON")
    value = _strict_json_bytes(content[:-1], label)
    if (
        not isinstance(value, dict)
        or set(value) != {"payload", "payload_sha256"}
        or not isinstance(value.get("payload"), dict)
        or type(value.get("payload_sha256")) is not str
        or SHA256_PATTERN.fullmatch(value["payload_sha256"]) is None
        or _canonical_json_bytes(value) + b"\n" != content
    ):
        raise BootstrapError(f"{label} envelope is malformed")
    payload = value["payload"]
    digest = hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()
    if not secrets.compare_digest(digest, value["payload_sha256"]):
        raise BootstrapError(f"{label} payload digest differs")
    return payload, binding


def _inputs_metadata(inputs: BootstrapInputs) -> dict[str, object]:
    return {
        "manifest": _file_metadata(inputs.desired.manifest),
        "sieve": _file_metadata(inputs.desired.sieve),
    }


def build_attempt_payload(
    inputs: BootstrapInputs,
    *,
    started_at: str,
    invocation_id: str,
) -> dict[str, object]:
    if not isinstance(inputs, BootstrapInputs):
        raise BootstrapError("bootstrap inputs are malformed")
    _validate_time(started_at, "bootstrap start time")
    _validate_invocation(invocation_id)
    return {
        "account_ownership_description": (
            ACCOUNT_OWNERSHIP_PREFIX + invocation_id
        ),
        "apply_receipt": _file_metadata(inputs.apply_receipt),
        "inputs": _inputs_metadata(inputs),
        "invocation_id": invocation_id,
        "ip_restriction_decision": IP_RESTRICTION_DECISION,
        "permissions_sha256": PERMISSIONS_SHA256,
        "schema": ATTEMPT_SCHEMA,
        "started_at": started_at,
    }


@dataclass(frozen=True, repr=False)
class AttemptCheckpoint:
    binding: FileBinding
    started_at: str
    invocation_id: str
    account_ownership_description: str

    def __repr__(self) -> str:
        return _redacted_repr(type(self).__name__)


def _validate_attempt(
    payload: dict[str, object],
    binding: FileBinding,
    inputs: BootstrapInputs,
) -> AttemptCheckpoint:
    expected_keys = {
        "account_ownership_description",
        "apply_receipt",
        "inputs",
        "invocation_id",
        "ip_restriction_decision",
        "permissions_sha256",
        "schema",
        "started_at",
    }
    started_at = _validate_time(payload.get("started_at"), "bootstrap start time")
    invocation = _validate_invocation(payload.get("invocation_id"))
    expected = build_attempt_payload(
        inputs,
        started_at=started_at,
        invocation_id=invocation,
    )
    if (
        set(payload) != expected_keys
        or _canonical_json_bytes(payload) != _canonical_json_bytes(expected)
    ):
        raise BootstrapError("bootstrap attempt checkpoint is malformed")
    return AttemptCheckpoint(
        binding,
        started_at,
        invocation,
        ACCOUNT_OWNERSHIP_PREFIX + invocation,
    )


def build_account_checkpoint_payload(
    attempt: AttemptCheckpoint,
    *,
    created_at: str,
    account_id: str,
    domain_id: str,
    observed_description: str,
) -> dict[str, object]:
    if not isinstance(attempt, AttemptCheckpoint):
        raise BootstrapError("attempt checkpoint is malformed")
    _validate_time(created_at, "account checkpoint time")
    _validate_id(account_id, "management Account ID")
    _validate_id(domain_id, "local Domain ID")
    if observed_description != attempt.account_ownership_description:
        raise BootstrapError(
            "management Account lacks the invocation ownership marker",
        )
    return {
        "account_id": account_id,
        "created_at": created_at,
        "domain_id": domain_id,
        "invocation_id": attempt.invocation_id,
        "temporary_account_description": (
            attempt.account_ownership_description
        ),
        "orphan_key_description": KEY_OWNERSHIP_PREFIX + attempt.invocation_id,
        "schema": ACCOUNT_CHECKPOINT_SCHEMA,
    }


@dataclass(frozen=True, repr=False)
class AccountCheckpoint:
    binding: FileBinding
    created_at: str
    ownership: AccountOwnership

    def __repr__(self) -> str:
        return _redacted_repr(type(self).__name__)


def _validate_account(
    payload: dict[str, object],
    binding: FileBinding,
    attempt: AttemptCheckpoint,
) -> AccountCheckpoint:
    created_at = _validate_time(
        payload.get("created_at"),
        "account checkpoint time",
    )
    account_id = _validate_id(
        payload.get("account_id"),
        "management Account ID",
    )
    domain_id = _validate_id(payload.get("domain_id"), "local Domain ID")
    expected = build_account_checkpoint_payload(
        attempt,
        created_at=created_at,
        account_id=account_id,
        domain_id=domain_id,
        observed_description=payload.get(
            "temporary_account_description",
        ),  # type: ignore[arg-type]
    )
    if (
        set(payload) != set(expected)
        or _canonical_json_bytes(payload) != _canonical_json_bytes(expected)
    ):
        raise BootstrapError("management Account checkpoint is malformed")
    return AccountCheckpoint(
        binding=binding,
        created_at=created_at,
        ownership=AccountOwnership(
            invocation_id=attempt.invocation_id,
            account_id=account_id,
            domain_id=domain_id,
            temporary_account_description=(
                attempt.account_ownership_description
            ),
            orphan_key_description=expected["orphan_key_description"],
        ),
    )


def build_replacement_checkpoint_payload(
    account: AccountCheckpoint,
    *,
    created_at: str,
    orphan_credential_id: str,
) -> dict[str, object]:
    if not isinstance(account, AccountCheckpoint):
        raise BootstrapError("replacement checkpoint Account is malformed")
    _validate_time(created_at, "replacement checkpoint time")
    _validate_id(orphan_credential_id, "orphan credential ID")
    return {
        "account_checkpoint": _file_metadata(account.binding),
        "account_id": account.ownership.account_id,
        "created_at": created_at,
        "invocation_id": account.ownership.invocation_id,
        "orphan_credential_id": orphan_credential_id,
        "schema": REPLACEMENT_CHECKPOINT_SCHEMA,
    }


@dataclass(frozen=True, repr=False)
class ReplacementCheckpoint:
    binding: FileBinding
    created_at: str
    account_id: str
    orphan_credential_id: str

    def __repr__(self) -> str:
        return _redacted_repr(type(self).__name__)


def _validate_replacement(
    payload: dict[str, object],
    binding: FileBinding,
    account: AccountCheckpoint,
) -> ReplacementCheckpoint:
    created_at = _validate_time(
        payload.get("created_at"),
        "replacement checkpoint time",
    )
    orphan_id = _validate_id(
        payload.get("orphan_credential_id"),
        "orphan credential ID",
    )
    expected = build_replacement_checkpoint_payload(
        account,
        created_at=created_at,
        orphan_credential_id=orphan_id,
    )
    if (
        set(payload) != set(expected)
        or _canonical_json_bytes(payload) != _canonical_json_bytes(expected)
    ):
        raise BootstrapError("replacement checkpoint is malformed")
    return ReplacementCheckpoint(
        binding=binding,
        created_at=created_at,
        account_id=account.ownership.account_id,
        orphan_credential_id=orphan_id,
    )


@dataclass(frozen=True, repr=False)
class ExactAuthenticationProof:
    account_id: str
    username: str
    status: int
    server_version: str

    def __repr__(self) -> str:
        return _redacted_repr(type(self).__name__)


def validate_exact_authentication(
    *,
    account_id: str,
    username: str,
    status: int,
    server_version: str,
) -> ExactAuthenticationProof:
    _validate_id(account_id, "authenticated Account ID")
    if (
        username != MANAGEMENT_ADDRESS
        or type(status) is not int
        or status != 200
        or server_version != SERVER_VERSION
    ):
        raise BootstrapError("exact account/key authentication failed")
    return ExactAuthenticationProof(
        account_id=account_id,
        username=username,
        status=status,
        server_version=server_version,
    )


def _authentication_metadata(
    proof: ExactAuthenticationProof,
) -> dict[str, object]:
    return {
        "account_id": proof.account_id,
        "server_version": proof.server_version,
        "status": proof.status,
        "username": proof.username,
    }


@dataclass(frozen=True, repr=False)
class KeyAdoptionProof:
    account_id: str
    credential_id: str
    _authentication_json: str
    _credential_inventory_json: str

    def authentication(self) -> dict[str, object]:
        return json.loads(self._authentication_json)

    def credential_inventory(self) -> list[dict[str, object]]:
        return json.loads(self._credential_inventory_json)

    def __repr__(self) -> str:
        return _redacted_repr(type(self).__name__)


def validate_key_adoption(
    inputs: BootstrapInputs,
    account: AccountCheckpoint,
    *,
    credentials: Sequence[CredentialProjection],
    authentication_status: int,
    authenticated_account_id: str,
    authenticated_username: str,
    server_version: str,
) -> KeyAdoptionProof:
    if (
        not isinstance(inputs, BootstrapInputs)
        or not isinstance(account, AccountCheckpoint)
        or not isinstance(credentials, (tuple, list))
        or len(credentials) != 1
        or any(
            not isinstance(item, CredentialProjection)
            for item in credentials
        )
    ):
        raise BootstrapError("local key adoption inventory is not exact")
    credential = credentials[0]
    if (
        credential.account_id != account.ownership.account_id
        or credential.credential_type != "ApiKey"
        or credential.description not in {
            MANAGEMENT_KEY_DESCRIPTION,
            account.ownership.orphan_key_description,
        }
        or credential.permissions_dict()
        != inputs.desired.api_key_intent.permissions_dict()
        or credential.allowed_ips_dict()
        != inputs.desired.api_key_intent.allowed_ips_dict()
    ):
        raise BootstrapError("local key adoption inventory is not exact")
    authentication = validate_exact_authentication(
        account_id=authenticated_account_id,
        username=authenticated_username,
        status=authentication_status,
        server_version=server_version,
    )
    if authentication.account_id != account.ownership.account_id:
        raise BootstrapError("local key authenticated a different Account")
    return KeyAdoptionProof(
        account_id=credential.account_id,
        credential_id=credential.credential_id,
        _authentication_json=_json_text(
            _authentication_metadata(authentication),
        ),
        _credential_inventory_json=_json_text(
            [_credential_metadata(credential)],
        ),
    )


def build_key_checkpoint_payload(
    account: AccountCheckpoint,
    management_key: SecretFileBinding,
    *,
    created_at: str,
    credential_id: str,
    origin: str,
    adoption_proof: KeyAdoptionProof | None,
) -> dict[str, object]:
    if not isinstance(account, AccountCheckpoint) or not isinstance(
        management_key,
        SecretFileBinding,
    ):
        raise BootstrapError("key checkpoint inputs are malformed")
    _validate_time(created_at, "key checkpoint time")
    _validate_id(credential_id, "management credential ID")
    if origin not in {"created", "adopted"}:
        raise BootstrapError("management key origin is malformed")
    if origin == "created" and adoption_proof is not None:
        raise BootstrapError("created key must not contain adoption evidence")
    if origin == "adopted" and (
        not isinstance(adoption_proof, KeyAdoptionProof)
        or adoption_proof.account_id != account.ownership.account_id
        or adoption_proof.credential_id != credential_id
    ):
        raise BootstrapError(
            "adopted key requires exact authentication evidence",
        )
    return {
        "account_checkpoint": _file_metadata(account.binding),
        "account_id": account.ownership.account_id,
        "adoption_evidence": (
            None
            if adoption_proof is None
            else {
                "authentication": adoption_proof.authentication(),
                "credential_inventory": (
                    adoption_proof.credential_inventory()
                ),
            }
        ),
        "created_at": created_at,
        "credential_id": credential_id,
        "final_description": MANAGEMENT_KEY_DESCRIPTION,
        "invocation_id": account.ownership.invocation_id,
        "ip_restriction_decision": IP_RESTRICTION_DECISION,
        "key_file": _secret_metadata(management_key),
        "origin": origin,
        "permissions_sha256": PERMISSIONS_SHA256,
        "schema": KEY_CHECKPOINT_SCHEMA,
        "temporary_description": account.ownership.orphan_key_description,
    }


@dataclass(frozen=True, repr=False)
class KeyCheckpoint:
    binding: FileBinding
    created_at: str
    account_id: str
    credential_id: str
    key_file: SecretFileBinding
    ip_restriction_decision: str
    origin: str
    temporary_description: str

    def __repr__(self) -> str:
        return _redacted_repr(type(self).__name__)


def _validate_replacement_key_transition(
    replacement: ReplacementCheckpoint | None,
    key: KeyCheckpoint | None,
) -> None:
    if replacement is None or key is None:
        return
    if (
        replacement.account_id != key.account_id
        or replacement.orphan_credential_id == key.credential_id
    ):
        raise BootstrapError(
            "replacement key does not advance beyond the revoked orphan",
        )


def _validate_key(
    payload: dict[str, object],
    binding: FileBinding,
    account: AccountCheckpoint,
    paths: BootstrapPaths,
    current_key: SecretFileBinding | None,
    inputs: BootstrapInputs,
    replacement: ReplacementCheckpoint | None,
) -> KeyCheckpoint:
    created_at = _validate_time(payload.get("created_at"), "key checkpoint time")
    credential_id = _validate_id(
        payload.get("credential_id"),
        "management credential ID",
    )
    committed = _binding_from_metadata(
        payload.get("key_file"),
        path=paths.management_key,
        require_digest=False,
        label="management key file",
    )
    if not isinstance(committed, SecretFileBinding):
        raise BootstrapError("management key commitment is malformed")
    origin = payload.get("origin")
    adoption_value = payload.get("adoption_evidence")
    adoption: KeyAdoptionProof | None
    if origin == "created":
        if adoption_value is not None:
            raise BootstrapError("created key adoption evidence is malformed")
        adoption = None
    elif origin == "adopted":
        if (
            not isinstance(adoption_value, dict)
            or set(adoption_value)
            != {"authentication", "credential_inventory"}
            or not isinstance(adoption_value.get("authentication"), dict)
            or not isinstance(
                adoption_value.get("credential_inventory"),
                list,
            )
            or len(adoption_value["credential_inventory"]) != 1
            or not isinstance(
                adoption_value["credential_inventory"][0],
                dict,
            )
        ):
            raise BootstrapError("adopted key evidence is malformed")
        authentication = adoption_value["authentication"]
        credential_value = adoption_value["credential_inventory"][0]
        if set(credential_value) != {
            "account_id",
            "allowed_ips",
            "credential_id",
            "credential_type",
            "description",
            "permissions",
        }:
            raise BootstrapError("adopted key inventory is malformed")
        credential = CredentialProjection.from_mapping(
            account_id=credential_value.get("account_id"),  # type: ignore[arg-type]
            credential_id=credential_value.get("credential_id"),  # type: ignore[arg-type]
            credential_type=credential_value.get("credential_type"),  # type: ignore[arg-type]
            description=credential_value.get("description"),  # type: ignore[arg-type]
            permissions=credential_value.get("permissions"),  # type: ignore[arg-type]
            allowed_ips=credential_value.get("allowed_ips"),  # type: ignore[arg-type]
        )
        adoption = validate_key_adoption(
            inputs,
            account,
            credentials=(credential,),
            authentication_status=authentication.get("status"),  # type: ignore[arg-type]
            authenticated_account_id=authentication.get("account_id"),  # type: ignore[arg-type]
            authenticated_username=authentication.get("username"),  # type: ignore[arg-type]
            server_version=authentication.get("server_version"),  # type: ignore[arg-type]
        )
    else:
        raise BootstrapError("management key origin is malformed")
    expected = build_key_checkpoint_payload(
        account,
        committed,
        created_at=created_at,
        credential_id=credential_id,
        origin=origin,
        adoption_proof=adoption,
    )
    if (
        set(payload) != set(expected)
        or _canonical_json_bytes(payload) != _canonical_json_bytes(expected)
    ):
        raise BootstrapError("management key checkpoint is malformed")
    if current_key is not None and current_key != committed:
        raise BootstrapError("management key file differs from its commitment")
    key = KeyCheckpoint(
        binding=binding,
        created_at=created_at,
        account_id=account.ownership.account_id,
        credential_id=credential_id,
        key_file=committed,
        ip_restriction_decision=IP_RESTRICTION_DECISION,
        origin=origin,
        temporary_description=account.ownership.orphan_key_description,
    )
    _validate_replacement_key_transition(replacement, key)
    return key


def _safe_object_projections(
    inputs: BootstrapInputs,
    account: AccountCheckpoint,
    key: KeyCheckpoint,
    object_ids: Mapping[str, str],
) -> list[dict[str, object]]:
    required = {item.object_type for item in inputs.desired.objects} | {"ApiKey"}
    if (
        not isinstance(account, AccountCheckpoint)
        or set(object_ids) != required
        or any(
            type(value) is not str or SAFE_ID_PATTERN.fullmatch(value) is None
            for value in object_ids.values()
        )
        or account.ownership.account_id != key.account_id
        or object_ids["Account"] != key.account_id
        or object_ids["ApiKey"] != key.credential_id
        or object_ids["Domain"] != account.ownership.domain_id
    ):
        raise BootstrapError("safe object IDs are malformed")
    domain_id = account.ownership.domain_id
    projections: list[dict[str, object]] = []
    for item in inputs.desired.objects:
        resolved = _resolve_references(item.desired_dict(), domain_id)
        projections.append(
            {
                "id": object_ids[item.object_type],
                "object_type": item.object_type,
                "value": resolved,
            },
        )
    projections.append(
        {
            "id": key.credential_id,
            "object_type": "ApiKey",
            "value": {
                "accountId": key.account_id,
                "allowedIps": inputs.desired.api_key_intent.allowed_ips_dict(),
                "credentialType": "ApiKey",
                "description": MANAGEMENT_KEY_DESCRIPTION,
                "permissions": (
                    inputs.desired.api_key_intent.permissions_dict()
                ),
            },
        },
    )
    return projections


def _preserved_object_projections() -> list[dict[str, object]]:
    return [
        {
            "id": "singleton",
            "object_type": "MtaOutboundStrategy",
            "value": {
                "connection": {"else": "'default'", "match": {}},
                "route": {
                    "else": "'mx'",
                    "match": {
                        "0": {
                            "if": "is_local_domain(rcpt_domain)",
                            "then": "'local'",
                        },
                    },
                },
                "schedule": {
                    "else": "'remote'",
                    "match": {
                        "0": {
                            "if": "is_local_domain(rcpt_domain)",
                            "then": "'local'",
                        },
                        "1": {
                            "if": "source == 'dsn'",
                            "then": "'dsn'",
                        },
                        "2": {
                            "if": "source == 'report'",
                            "then": "'report'",
                        },
                    },
                },
                "tls": {
                    "else": "'default'",
                    "match": {
                        "0": {
                            "if": "retry_num > 0 && last_error == 'tls'",
                            "then": "'invalid-tls'",
                        },
                    },
                },
            },
        },
    ]


def _credential_metadata(
    credential: CredentialProjection,
) -> dict[str, object]:
    return {
        "account_id": credential.account_id,
        "allowed_ips": credential.allowed_ips_dict(),
        "credential_id": credential.credential_id,
        "credential_type": credential.credential_type,
        "description": credential.description,
        "permissions": credential.permissions_dict(),
    }


def _exact_management_credential(
    inputs: BootstrapInputs,
    key: KeyCheckpoint,
    credential: CredentialProjection,
    *,
    allowed_descriptions: frozenset[str],
) -> bool:
    return (
        credential.account_id == key.account_id
        and credential.credential_id == key.credential_id
        and credential.credential_type == "ApiKey"
        and credential.description in allowed_descriptions
        and credential.permissions_dict()
        == inputs.desired.api_key_intent.permissions_dict()
        and credential.allowed_ips_dict()
        == inputs.desired.api_key_intent.allowed_ips_dict()
    )


@dataclass(frozen=True, repr=False)
class ExecutorObservationProof:
    account_id: str
    domain_id: str
    credential_id: str
    server_version: str
    _safe_objects_json: str
    _preserved_objects_json: str
    _credential_inventory_json: str
    _authentication_json: str

    def safe_objects(self) -> list[dict[str, object]]:
        return json.loads(self._safe_objects_json)

    def preserved_objects(self) -> list[dict[str, object]]:
        return json.loads(self._preserved_objects_json)

    def credential_inventory(self) -> list[dict[str, object]]:
        return json.loads(self._credential_inventory_json)

    def authentication(self) -> dict[str, object]:
        return json.loads(self._authentication_json)

    def __repr__(self) -> str:
        return _redacted_repr(type(self).__name__)


def validate_executor_observation(
    inputs: BootstrapInputs,
    account: AccountCheckpoint,
    key: KeyCheckpoint,
    *,
    safe_objects: Sequence[Mapping[str, object]],
    preserved_objects: Sequence[Mapping[str, object]],
    credentials: Sequence[CredentialProjection],
    authentication_status: int,
    authenticated_account_id: str,
    authenticated_username: str,
    server_version: str,
) -> ExecutorObservationProof:
    """Validate the executor's complete fetched final-state projection."""
    if (
        not isinstance(inputs, BootstrapInputs)
        or not isinstance(account, AccountCheckpoint)
        or not isinstance(key, KeyCheckpoint)
        or account.ownership.account_id != key.account_id
        or not isinstance(safe_objects, (tuple, list))
        or not isinstance(preserved_objects, (tuple, list))
        or not isinstance(credentials, (tuple, list))
        or any(not isinstance(item, Mapping) for item in safe_objects)
        or any(not isinstance(item, Mapping) for item in preserved_objects)
        or any(
            not isinstance(item, CredentialProjection)
            for item in credentials
        )
        or len(credentials) != 1
    ):
        raise BootstrapError("executor observation is incomplete")
    credential = credentials[0]
    if not _exact_management_credential(
        inputs,
        key,
        credential,
        allowed_descriptions=frozenset({MANAGEMENT_KEY_DESCRIPTION}),
    ):
        raise BootstrapError(
            "final credential inventory is not exactly one intended API key",
        )
    copied_safe_objects = [
        json.loads(_json_text(dict(item))) for item in safe_objects
    ]
    ids = _extract_object_ids(copied_safe_objects)
    expected_objects = _safe_object_projections(inputs, account, key, ids)
    if (
        _canonical_json_bytes(copied_safe_objects)
        != _canonical_json_bytes(expected_objects)
    ):
        raise BootstrapError(
            "executor safe object projections differ from desired state",
        )
    copied_preserved_objects = [
        json.loads(_json_text(dict(item))) for item in preserved_objects
    ]
    expected_preserved_objects = _preserved_object_projections()
    if (
        _canonical_json_bytes(copied_preserved_objects)
        != _canonical_json_bytes(expected_preserved_objects)
    ):
        raise BootstrapError(
            "preserved MtaOutboundStrategy differs from the pinned default",
        )
    authentication = validate_exact_authentication(
        account_id=authenticated_account_id,
        username=authenticated_username,
        status=authentication_status,
        server_version=server_version,
    )
    if (
        authentication.account_id != key.account_id
    ):
        raise BootstrapError("executor authenticated a different Account")
    return ExecutorObservationProof(
        account_id=key.account_id,
        domain_id=account.ownership.domain_id,
        credential_id=key.credential_id,
        server_version=SERVER_VERSION,
        _safe_objects_json=_json_text(expected_objects),
        _preserved_objects_json=_json_text(expected_preserved_objects),
        _credential_inventory_json=_json_text(
            [_credential_metadata(credential)],
        ),
        _authentication_json=_json_text(
            _authentication_metadata(authentication),
        ),
    )


def build_proof_payload(
    inputs: BootstrapInputs,
    account: AccountCheckpoint,
    key: KeyCheckpoint,
    *,
    proven_at: str,
    executor_proof: ExecutorObservationProof,
) -> dict[str, object]:
    if (
        not isinstance(inputs, BootstrapInputs)
        or not isinstance(account, AccountCheckpoint)
        or not isinstance(key, KeyCheckpoint)
        or account.ownership.account_id != key.account_id
    ):
        raise BootstrapError("proof inputs are malformed")
    _validate_time(proven_at, "bootstrap proof time")
    if (
        not isinstance(executor_proof, ExecutorObservationProof)
        or executor_proof.account_id != key.account_id
        or executor_proof.domain_id != account.ownership.domain_id
        or executor_proof.credential_id != key.credential_id
        or executor_proof.server_version != SERVER_VERSION
    ):
        raise BootstrapError("executor observation proof is malformed")
    return {
        "authentication": executor_proof.authentication(),
        "credential_inventory": executor_proof.credential_inventory(),
        "ip_restriction_decision": IP_RESTRICTION_DECISION,
        "key_checkpoint": _file_metadata(key.binding),
        "permissions_sha256": PERMISSIONS_SHA256,
        "proven_at": proven_at,
        "preserved_objects": executor_proof.preserved_objects(),
        "safe_objects": executor_proof.safe_objects(),
        "schema": PROOF_SCHEMA,
        "server_version": SERVER_VERSION,
    }


@dataclass(frozen=True, repr=False)
class BootstrapProof:
    binding: FileBinding
    proven_at: str
    account_id: str
    credential_id: str
    server_version: str
    _safe_objects_json: str
    _preserved_objects_json: str
    _credential_inventory_json: str
    _authentication_json: str

    def safe_objects(self) -> list[dict[str, object]]:
        return json.loads(self._safe_objects_json)

    def preserved_objects(self) -> list[dict[str, object]]:
        return json.loads(self._preserved_objects_json)

    def authentication(self) -> dict[str, object]:
        return json.loads(self._authentication_json)

    def credential_inventory(self) -> list[dict[str, object]]:
        return json.loads(self._credential_inventory_json)

    def __repr__(self) -> str:
        return _redacted_repr(type(self).__name__)


def _extract_object_ids(value: object) -> dict[str, str]:
    if not isinstance(value, list):
        raise BootstrapError("safe object projections are malformed")
    result: dict[str, str] = {}
    for projection in value:
        if (
            not isinstance(projection, dict)
            or set(projection) != {"id", "object_type", "value"}
            or type(projection.get("object_type")) is not str
            or not isinstance(projection.get("value"), dict)
        ):
            raise BootstrapError("safe object projection is malformed")
        object_type = projection["object_type"]
        object_id = _validate_id(projection.get("id"), "safe object ID")
        if object_type in result:
            raise BootstrapError("safe object projection is duplicate")
        if _contains_sensitive_field(projection["value"]):
            raise BootstrapError("safe object projection contains a secret")
        result[object_type] = object_id
    return result


def _validate_proof(
    payload: dict[str, object],
    binding: FileBinding,
    inputs: BootstrapInputs,
    account: AccountCheckpoint,
    key: KeyCheckpoint,
) -> BootstrapProof:
    proven_at = _validate_time(payload.get("proven_at"), "bootstrap proof time")
    ids = _extract_object_ids(payload.get("safe_objects"))
    authentication = payload.get("authentication")
    inventory = payload.get("credential_inventory")
    if (
        not isinstance(authentication, dict)
        or not isinstance(inventory, list)
        or len(inventory) != 1
        or not isinstance(inventory[0], dict)
    ):
        raise BootstrapError("authentication proof is malformed")
    credential_value = inventory[0]
    if set(credential_value) != {
        "account_id",
        "allowed_ips",
        "credential_id",
        "credential_type",
        "description",
        "permissions",
    }:
        raise BootstrapError("credential inventory is malformed")
    credential = CredentialProjection.from_mapping(
        account_id=credential_value.get("account_id"),  # type: ignore[arg-type]
        credential_id=credential_value.get("credential_id"),  # type: ignore[arg-type]
        credential_type=credential_value.get("credential_type"),  # type: ignore[arg-type]
        description=credential_value.get("description"),  # type: ignore[arg-type]
        permissions=credential_value.get("permissions"),  # type: ignore[arg-type]
        allowed_ips=credential_value.get("allowed_ips"),  # type: ignore[arg-type]
    )
    executor_proof = validate_executor_observation(
        inputs,
        account,
        key,
        safe_objects=payload.get("safe_objects"),  # type: ignore[arg-type]
        preserved_objects=payload.get("preserved_objects"),  # type: ignore[arg-type]
        credentials=(credential,),
        authentication_status=authentication.get("status"),  # type: ignore[arg-type]
        authenticated_account_id=authentication.get("account_id"),  # type: ignore[arg-type]
        authenticated_username=authentication.get("username"),  # type: ignore[arg-type]
        server_version=payload.get("server_version"),  # type: ignore[arg-type]
    )
    expected = build_proof_payload(
        inputs,
        account,
        key,
        proven_at=proven_at,
        executor_proof=executor_proof,
    )
    if (
        set(payload) != set(expected)
        or _canonical_json_bytes(payload) != _canonical_json_bytes(expected)
    ):
        raise BootstrapError("bootstrap proof checkpoint is malformed")
    return BootstrapProof(
        binding=binding,
        proven_at=proven_at,
        account_id=key.account_id,
        credential_id=key.credential_id,
        server_version=SERVER_VERSION,
        _safe_objects_json=_json_text(expected["safe_objects"]),
        _preserved_objects_json=_json_text(expected["preserved_objects"]),
        _credential_inventory_json=_json_text(
            expected["credential_inventory"],
        ),
        _authentication_json=_json_text(expected["authentication"]),
    )


@dataclass(frozen=True, repr=False)
class ProtectedAccounts:
    binding: FileBinding
    account_id: str

    def __repr__(self) -> str:
        return _redacted_repr(type(self).__name__)


def _load_protected_accounts(
    paths: BootstrapPaths,
    *,
    expected_account_id: str,
) -> ProtectedAccounts:
    binding, content = _snapshot_regular(
        paths.protected_accounts,
        root=paths.repository_root,
        label="protected Account IDs",
        required_mode=0o600,
        maximum=MAXIMUM_JSON_SIZE,
    )
    if not content.endswith(b"\n") or content.count(b"\n") != 1:
        raise BootstrapError("protected Account IDs are not canonical JSON")
    value = _strict_json_bytes(content[:-1], "protected Account IDs")
    if (
        not isinstance(value, dict)
        or set(value) != {"account_ids", "schema"}
        or value.get("schema") != PROTECTED_ACCOUNTS_SCHEMA
        or not isinstance(value.get("account_ids"), list)
        or len(value["account_ids"]) != 1
        or type(value["account_ids"][0]) is not str
        or value["account_ids"][0] != expected_account_id
        or SAFE_ID_PATTERN.fullmatch(value["account_ids"][0]) is None
        or _canonical_json_bytes(value) + b"\n" != content
    ):
        raise BootstrapError("protected Account IDs differ from the exact proof")
    return ProtectedAccounts(binding, expected_account_id)


@dataclass(frozen=True, repr=False)
class RoutingIntent:
    binding: FileBinding
    invocation_id: str
    domain_id: str
    _actors_json: str

    def actors(self) -> dict[str, dict[str, object]]:
        return json.loads(self._actors_json)

    def __repr__(self) -> str:
        return _redacted_repr(type(self).__name__)


@dataclass(frozen=True, repr=False)
class RoutingProof:
    binding: FileBinding
    proven_at: str
    invocation_id: str
    management_account_id: str
    management_credential_id: str
    preserved_objects_sha256: str

    def __repr__(self) -> str:
        return _redacted_repr(type(self).__name__)


@dataclass(frozen=True, repr=False)
class FinalReceipt:
    binding: FileBinding
    completed_at: str
    account_id: str
    credential_id: str
    ip_restriction_decision: str
    server_version: str

    def __repr__(self) -> str:
        return _redacted_repr(type(self).__name__)


@dataclass(frozen=True, repr=False)
class CheckpointState:
    inputs: BootstrapInputs
    attempt: AttemptCheckpoint | None
    account: AccountCheckpoint | None
    replacement: ReplacementCheckpoint | None
    key: KeyCheckpoint | None
    proof: BootstrapProof | None
    routing_intent: RoutingIntent | None
    routing_proof: RoutingProof | None
    final_receipt: FinalReceipt | None
    management_key: SecretFileBinding | None
    protected_accounts: ProtectedAccounts | None

    def __repr__(self) -> str:
        return _redacted_repr(type(self).__name__)


@dataclass(frozen=True, repr=False)
class ValidatedFinalBootstrap:
    final_receipt: FileBinding
    apply_receipt: FileBinding
    bootstrap_proof: FileBinding
    routing_proof: FileBinding
    protected_accounts: FileBinding
    bootstrap_receipt_sha256: str
    apply_receipt_sha256: str
    bootstrap_proof_sha256: str
    management_account_id: str
    management_api_key_id: str
    ip_restriction_decision: str
    permissions_sha256: str
    protected_accounts_sha256: str
    safe_objects_sha256: str
    preserved_objects_sha256: str
    routing_proof_sha256: str
    listener_id: str
    listener_name: str
    listener_bind: tuple[str, ...]
    listener_protocol: str
    listener_use_tls: bool
    listener_tls_implicit: bool
    account_projection_sha256: str
    api_key_projection_sha256: str
    management_key_name: str
    management_key_size: int
    management_key_identity: tuple[
        int,
        int,
        int,
        int,
        int,
        int,
        int,
        int,
    ]
    _marker: object

    def __repr__(self) -> str:
        return _redacted_repr(type(self).__name__)


def _routing_mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise BootstrapError(f"{label} is malformed")
    copied = json.loads(_json_text(dict(value)))
    if not isinstance(copied, dict):
        raise BootstrapError(f"{label} is malformed")
    _validate_json_tree(copied)
    if _contains_sensitive_field(copied):
        raise BootstrapError(f"{label} contains a secret")
    return copied


def _routing_actor(
    value: object,
    *,
    role: str,
    invocation_id: str,
) -> dict[str, object]:
    actor = _routing_mapping(value, f"routing {role} actor")
    if set(actor) != {
        "account_id",
        "address",
        "app_password_credential_id",
    }:
        raise BootstrapError(f"routing {role} actor is malformed")
    account_id = _validate_id(
        actor.get("account_id"),
        f"routing {role} Account ID",
    )
    credential_id = _validate_id(
        actor.get("app_password_credential_id"),
        f"routing {role} AppPassword ID",
    )
    expected = {
        "account_id": account_id,
        "address": (
            f"dashboard-routing-{role}-{invocation_id}@local.test"
        ),
        "app_password_credential_id": credential_id,
    }
    if _canonical_json_bytes(actor) != _canonical_json_bytes(expected):
        raise BootstrapError(f"routing {role} actor is malformed")
    return expected


def _routing_rejection_probe(
    value: object,
    *,
    name: str,
    recipient: str,
    enhanced_status: str,
) -> dict[str, object]:
    probe = _routing_mapping(value, f"{name} routing probe")
    expected_keys = {
        "delivery_status",
        "enhanced_status",
        "queue_accepted",
        "recipient",
        "smtp_code",
        "submission_created",
        "submission_id",
        "undo_status",
    }
    if set(probe) != expected_keys:
        raise BootstrapError(f"{name} routing probe is malformed")
    submission_id = _validate_id(
        probe.get("submission_id"),
        f"{name} submission ID",
    )
    expected = {
        "delivery_status": "no",
        "enhanced_status": enhanced_status,
        "queue_accepted": False,
        "recipient": recipient,
        "smtp_code": 550,
        "submission_created": True,
        "submission_id": submission_id,
        "undo_status": "pending",
    }
    if _canonical_json_bytes(probe) != _canonical_json_bytes(expected):
        raise BootstrapError(f"{name} routing probe did not reject safely")
    return expected


def _routing_probes(
    value: object,
    *,
    invocation_id: str,
    recipient_actor: Mapping[str, object],
    message_id: str,
) -> dict[str, object]:
    probes = _routing_mapping(value, "routing probes")
    if set(probes) != {
        "external",
        "protected_exact",
        "protected_subaddress",
        "registered_local",
        "unregistered_local",
    }:
        raise BootstrapError("routing probe inventory is incomplete")
    registered = _routing_mapping(
        probes.get("registered_local"),
        "registered-local routing probe",
    )
    if set(registered) != {
        "arrival",
        "delivery_status",
        "enhanced_status",
        "queue_accepted",
        "recipient",
        "smtp_code",
        "submission_created",
        "submission_id",
        "undo_status",
    }:
        raise BootstrapError("registered-local routing probe is malformed")
    submission_id = _validate_id(
        registered.get("submission_id"),
        "registered-local submission ID",
    )
    arrival = _routing_mapping(
        registered.get("arrival"),
        "registered-local arrival",
    )
    if (
        set(arrival)
        != {"account_id", "matching_email_ids", "message_id"}
        or not isinstance(arrival.get("matching_email_ids"), list)
        or len(arrival["matching_email_ids"]) != 1
    ):
        raise BootstrapError("registered-local arrival is malformed")
    email_id = _validate_id(
        arrival["matching_email_ids"][0],
        "registered-local Email ID",
    )
    expected_registered = {
        "arrival": {
            "account_id": recipient_actor["account_id"],
            "matching_email_ids": [email_id],
            "message_id": message_id,
        },
        "delivery_status": "unknown",
        "enhanced_status": "2.1.5",
        "queue_accepted": True,
        "recipient": recipient_actor["address"],
        "smtp_code": 250,
        "submission_created": True,
        "submission_id": submission_id,
        "undo_status": "final",
    }
    if (
        _canonical_json_bytes(registered)
        != _canonical_json_bytes(expected_registered)
    ):
        raise BootstrapError("registered-local delivery proof is not exact")
    expected = {
        "external": _routing_rejection_probe(
            probes.get("external"),
            name="external",
            recipient=f"dashboard-routing-{invocation_id}@example.invalid",
            enhanced_status="5.1.2",
        ),
        "protected_exact": _routing_rejection_probe(
            probes.get("protected_exact"),
            name="protected-exact",
            recipient=MANAGEMENT_ADDRESS,
            enhanced_status="5.7.1",
        ),
        "protected_subaddress": _routing_rejection_probe(
            probes.get("protected_subaddress"),
            name="protected-subaddress",
            recipient=(
                f"dashboard-management+routing-{invocation_id}@local.test"
            ),
            enhanced_status="5.7.1",
        ),
        "registered_local": expected_registered,
        "unregistered_local": _routing_rejection_probe(
            probes.get("unregistered_local"),
            name="unregistered-local",
            recipient=(
                f"dashboard-routing-missing-{invocation_id}@local.test"
            ),
            enhanced_status="5.1.2",
        ),
    }
    submission_ids = [
        item["submission_id"]
        for item in expected.values()
        if isinstance(item, dict)
    ]
    if len(set(submission_ids)) != len(submission_ids):
        raise BootstrapError("routing submission IDs are not distinct")
    return expected


def _routing_access_removal(
    value: object,
    *,
    recipient_actor: Mapping[str, object],
) -> dict[str, object]:
    removal = _routing_mapping(value, "routing recipient access removal")
    if set(removal) != {
        "authentication_status",
        "credential_id",
        "projected_state",
        "readiness_preflight",
    }:
        raise BootstrapError("routing recipient access removal is malformed")
    authentication_status = removal.get("authentication_status")
    preflight = _routing_mapping(
        removal.get("readiness_preflight"),
        "routing readiness preflight",
    )
    expected = {
        "authentication_status": authentication_status,
        "credential_id": recipient_actor["app_password_credential_id"],
        "projected_state": "enrollmentRequired",
        "readiness_preflight": {
            "submission_calls": 0,
            "upload_calls": 0,
        },
    }
    if (
        type(authentication_status) is not int
        or authentication_status not in {401, 403}
        or set(preflight) != {"submission_calls", "upload_calls"}
        or type(preflight.get("submission_calls")) is not int
        or type(preflight.get("upload_calls")) is not int
        or _canonical_json_bytes(removal) != _canonical_json_bytes(expected)
    ):
        raise BootstrapError(
            "routing readiness was not blocked before network calls",
        )
    return expected


def _routing_cleanup(
    value: object,
    *,
    sender_actor: Mapping[str, object],
    recipient_actor: Mapping[str, object],
) -> dict[str, object]:
    cleanup = _routing_mapping(value, "routing cleanup")
    if set(cleanup) != {
        "account_get_not_found",
        "address_queries",
        "destroyed_account_ids",
    }:
        raise BootstrapError("routing cleanup proof is malformed")
    expected_ids = [
        sender_actor["account_id"],
        recipient_actor["account_id"],
    ]
    expected = {
        "account_get_not_found": expected_ids,
        "address_queries": [
            {"address": sender_actor["address"], "ids": []},
            {"address": recipient_actor["address"], "ids": []},
        ],
        "destroyed_account_ids": expected_ids,
    }
    if _canonical_json_bytes(cleanup) != _canonical_json_bytes(expected):
        raise BootstrapError("routing cleanup proof is not exact")
    return expected


def _routing_account_projection(
    address: str,
    domain_id: str,
) -> dict[str, object]:
    _validate_id(domain_id, "routing Domain ID")
    local_part, separator, domain = address.partition("@")
    if (
        separator != "@"
        or not local_part
        or domain != "local.test"
    ):
        raise BootstrapError("routing actor address is malformed")
    return {
        "@type": "User",
        "domainId": domain_id,
        "name": local_part,
        "permissions": {"@type": "Inherit"},
        "roles": {"@type": "User"},
    }


def _routing_intent_actor(
    role: str,
    invocation_id: str,
    domain_id: str,
) -> dict[str, object]:
    address = _actor_address(role, invocation_id)
    return {
        "address": address,
        "projection": _routing_account_projection(
            address,
            domain_id,
        ),
    }


def build_routing_intent_payload(
    state: CheckpointState,
) -> dict[str, object]:
    """Build the secret-free ownership intent committed before actor create."""
    if (
        not isinstance(state, CheckpointState)
        or state.attempt is None
        or state.account is None
        or state.proof is None
        or state.routing_intent is not None
        or state.routing_proof is not None
        or state.final_receipt is not None
        or state.account.ownership.invocation_id
        != state.attempt.invocation_id
        or state.proof.account_id != state.account.ownership.account_id
    ):
        raise BootstrapError(
            "routing ownership intent prerequisites are incomplete",
        )
    invocation_id = state.attempt.invocation_id
    domain_id = state.account.ownership.domain_id
    return {
        "account_checkpoint": _file_metadata(state.account.binding),
        "actors": {
            role: _routing_intent_actor(
                role,
                invocation_id,
                domain_id,
            )
            for role in ("recipient", "sender")
        },
        "attempt_checkpoint": _file_metadata(state.attempt.binding),
        "bootstrap_proof": _file_metadata(state.proof.binding),
        "domain_id": domain_id,
        "invocation_id": invocation_id,
        "schema": ROUTING_INTENT_SCHEMA,
    }


def _validate_routing_intent(
    payload: dict[str, object],
    binding: FileBinding,
    state_without_intent: CheckpointState,
) -> RoutingIntent:
    expected = build_routing_intent_payload(state_without_intent)
    if (
        set(payload) != set(expected)
        or _canonical_json_bytes(payload) != _canonical_json_bytes(expected)
    ):
        raise BootstrapError(
            "routing ownership intent checkpoint is malformed or stale",
        )
    return RoutingIntent(
        binding=binding,
        invocation_id=expected["invocation_id"],  # type: ignore[arg-type]
        domain_id=expected["domain_id"],  # type: ignore[arg-type]
        _actors_json=_json_text(expected["actors"]),
    )


def build_routing_proof_payload(
    state: CheckpointState,
    *,
    proven_at: str,
    actors: Mapping[str, object],
    message_id: str,
    probes: Mapping[str, object],
    recipient_access_removed: Mapping[str, object],
    cleanup: Mapping[str, object],
) -> dict[str, object]:
    """Validate normalized live routing evidence and build its fixed payload."""
    _validate_time(proven_at, "routing proof time")
    if (
        not isinstance(state, CheckpointState)
        or state.attempt is None
        or state.account is None
        or state.key is None
        or state.proof is None
        or state.routing_intent is None
        or state.routing_proof is not None
        or state.final_receipt is not None
        or state.proof.account_id != state.key.account_id
        or state.proof.credential_id != state.key.credential_id
    ):
        raise BootstrapError("routing proof prerequisites are incomplete")
    invocation_id = state.attempt.invocation_id
    actor_values = _routing_mapping(actors, "routing actors")
    if set(actor_values) != {"recipient", "sender"}:
        raise BootstrapError("routing actors are malformed")
    sender = _routing_actor(
        actor_values.get("sender"),
        role="sender",
        invocation_id=invocation_id,
    )
    recipient = _routing_actor(
        actor_values.get("recipient"),
        role="recipient",
        invocation_id=invocation_id,
    )
    if (
        sender["account_id"] == recipient["account_id"]
        or state.proof.account_id
        in {sender["account_id"], recipient["account_id"]}
    ):
        raise BootstrapError(
            "routing actors must use distinct disposable Accounts",
        )
    expected_message_id = (
        f"<mail-sandbox-routing-{invocation_id}@local.test>"
    )
    if message_id != expected_message_id:
        raise BootstrapError("routing Message-ID is malformed")
    expected_actors = {"recipient": recipient, "sender": sender}
    expected_probes = _routing_probes(
        probes,
        invocation_id=invocation_id,
        recipient_actor=recipient,
        message_id=expected_message_id,
    )
    expected_removal = _routing_access_removal(
        recipient_access_removed,
        recipient_actor=recipient,
    )
    expected_cleanup = _routing_cleanup(
        cleanup,
        sender_actor=sender,
        recipient_actor=recipient,
    )
    preserved_objects_sha256 = hashlib.sha256(
        _canonical_json_bytes(state.proof.preserved_objects()),
    ).hexdigest()
    return {
        "actors": expected_actors,
        "bootstrap_proof": _file_metadata(state.proof.binding),
        "cleanup": expected_cleanup,
        "invocation_id": invocation_id,
        "management_account_id": state.proof.account_id,
        "management_credential_id": state.proof.credential_id,
        "message_id": expected_message_id,
        "preserved_objects_sha256": preserved_objects_sha256,
        "probes": expected_probes,
        "proven_at": proven_at,
        "recipient_access_removed": expected_removal,
        "routing_intent": _file_metadata(state.routing_intent.binding),
        "schema": ROUTING_PROOF_SCHEMA,
        "server_version": SERVER_VERSION,
    }


def _validate_routing_proof(
    payload: dict[str, object],
    binding: FileBinding,
    state_without_routing: CheckpointState,
) -> RoutingProof:
    proven_at = _validate_time(payload.get("proven_at"), "routing proof time")
    expected = build_routing_proof_payload(
        state_without_routing,
        proven_at=proven_at,
        actors=payload.get("actors"),  # type: ignore[arg-type]
        message_id=payload.get("message_id"),  # type: ignore[arg-type]
        probes=payload.get("probes"),  # type: ignore[arg-type]
        recipient_access_removed=payload.get(  # type: ignore[arg-type]
            "recipient_access_removed",
        ),
        cleanup=payload.get("cleanup"),  # type: ignore[arg-type]
    )
    if (
        set(payload) != set(expected)
        or _canonical_json_bytes(payload) != _canonical_json_bytes(expected)
    ):
        raise BootstrapError("routing proof checkpoint is malformed or stale")
    return RoutingProof(
        binding=binding,
        proven_at=proven_at,
        invocation_id=expected["invocation_id"],  # type: ignore[arg-type]
        management_account_id=expected["management_account_id"],  # type: ignore[arg-type]
        management_credential_id=expected["management_credential_id"],  # type: ignore[arg-type]
        preserved_objects_sha256=expected["preserved_objects_sha256"],  # type: ignore[arg-type]
    )


def build_final_receipt_payload(
    inputs: BootstrapInputs,
    state: CheckpointState,
    *,
    completed_at: str,
) -> dict[str, object]:
    _validate_time(completed_at, "bootstrap completion time")
    if (
        not isinstance(inputs, BootstrapInputs)
        or not isinstance(state, CheckpointState)
        or state.inputs != inputs
        or state.attempt is None
        or state.account is None
        or state.key is None
        or state.proof is None
        or state.routing_intent is None
        or state.routing_proof is None
        or state.routing_proof.management_account_id != state.proof.account_id
        or state.routing_proof.management_credential_id
        != state.proof.credential_id
        or state.management_key is None
        or state.management_key != state.key.key_file
        or state.protected_accounts is None
        or state.protected_accounts.account_id != state.proof.account_id
        or state.final_receipt is not None
    ):
        raise BootstrapError("final receipt prerequisites are incomplete")
    checkpoints = {
        "account": _file_metadata(state.account.binding),
        "attempt": _file_metadata(state.attempt.binding),
        "key": _file_metadata(state.key.binding),
        "proof": _file_metadata(state.proof.binding),
        "routing_intent": _file_metadata(state.routing_intent.binding),
    }
    if state.replacement is not None:
        checkpoints["replacement"] = _file_metadata(
            state.replacement.binding,
        )
    return {
        "apply_receipt": _file_metadata(inputs.apply_receipt),
        "authentication": state.proof.authentication(),
        "checkpoints": checkpoints,
        "completed_at": completed_at,
        "credential_inventory": state.proof.credential_inventory(),
        "inputs": _inputs_metadata(inputs),
        "ip_restriction_decision": IP_RESTRICTION_DECISION,
        "management": {
            "account_id": state.proof.account_id,
            "address": MANAGEMENT_ADDRESS,
            "credential_id": state.proof.credential_id,
            "key_file": _secret_metadata(state.management_key),
        },
        "permissions_sha256": PERMISSIONS_SHA256,
        "protected_accounts": _file_metadata(
            state.protected_accounts.binding,
        ),
        "preserved_objects": state.proof.preserved_objects(),
        "routing_proof": _file_metadata(state.routing_proof.binding),
        "safe_objects": state.proof.safe_objects(),
        "schema": FINAL_RECEIPT_SCHEMA,
        "server_version": SERVER_VERSION,
    }


def _validate_final_receipt(
    payload: dict[str, object],
    binding: FileBinding,
    inputs: BootstrapInputs,
    state_without_final: CheckpointState,
) -> FinalReceipt:
    completed_at = _validate_time(
        payload.get("completed_at"),
        "bootstrap completion time",
    )
    ip_restriction_decision = payload.get("ip_restriction_decision")
    if (
        type(ip_restriction_decision) is not str
        or state_without_final.key is None
        or ip_restriction_decision
        != state_without_final.key.ip_restriction_decision
    ):
        raise BootstrapError(
            "final bootstrap receipt binds a different IP restriction decision",
        )
    expected = build_final_receipt_payload(
        inputs,
        state_without_final,
        completed_at=completed_at,
    )
    if (
        set(payload) != set(expected)
        or _canonical_json_bytes(payload) != _canonical_json_bytes(expected)
    ):
        raise BootstrapError("final bootstrap receipt is malformed or stale")
    assert state_without_final.proof is not None
    return FinalReceipt(
        binding=binding,
        completed_at=completed_at,
        account_id=state_without_final.proof.account_id,
        credential_id=state_without_final.proof.credential_id,
        ip_restriction_decision=ip_restriction_decision,
        server_version=SERVER_VERSION,
    )


def _revalidate_inputs(inputs: BootstrapInputs) -> None:
    if (
        not isinstance(inputs.validated_apply, ValidatedApplyReceipt)
        or inputs.validated_apply._marker is not _TASK6_VALIDATION_MARKER
    ):
        raise BootstrapError("Task 6 apply validation token is malformed")
    _require_owner_runtime_directories(inputs.desired.paths)
    current_desired = load_desired_state(inputs.desired.paths)
    current_apply, _ = _snapshot_regular(
        inputs.desired.paths.apply_receipt,
        root=inputs.desired.paths.repository_root,
        label="migration apply receipt",
        required_mode=0o600,
        maximum=MAXIMUM_JSON_SIZE,
    )
    if (
        current_desired != inputs.desired
        or current_apply != inputs.apply_receipt
    ):
        raise BootstrapError("bootstrap inputs changed after validation")


def _revalidate_loaded_state(
    state: CheckpointState,
    *,
    initially_present: Mapping[str, bool],
) -> None:
    _revalidate_inputs(state.inputs)
    paths = state.inputs.desired.paths
    expected: tuple[tuple[str, Path, FileBinding | None, str], ...] = (
        (
            "attempt",
            paths.attempt,
            None if state.attempt is None else state.attempt.binding,
            "bootstrap attempt checkpoint",
        ),
        (
            "account",
            paths.account,
            None if state.account is None else state.account.binding,
            "bootstrap Account checkpoint",
        ),
        (
            "replacement",
            paths.replacement,
            None if state.replacement is None else state.replacement.binding,
            "bootstrap replacement checkpoint",
        ),
        (
            "key",
            paths.key,
            None if state.key is None else state.key.binding,
            "bootstrap key checkpoint",
        ),
        (
            "proof",
            paths.proof,
            None if state.proof is None else state.proof.binding,
            "bootstrap proof checkpoint",
        ),
        (
            "routing_intent",
            paths.routing_intent,
            (
                None
                if state.routing_intent is None
                else state.routing_intent.binding
            ),
            "routing ownership intent checkpoint",
        ),
        (
            "routing",
            paths.routing_proof,
            (
                None
                if state.routing_proof is None
                else state.routing_proof.binding
            ),
            "bootstrap routing proof",
        ),
        (
            "final",
            paths.final_receipt,
            (
                None
                if state.final_receipt is None
                else state.final_receipt.binding
            ),
            "final bootstrap receipt",
        ),
        (
            "protected",
            paths.protected_accounts,
            (
                None
                if state.protected_accounts is None
                else state.protected_accounts.binding
            ),
            "protected Account IDs",
        ),
    )
    for name, path, binding, label in expected:
        current_presence = _path_present(path)
        if current_presence != initially_present[name]:
            raise BootstrapError("runtime checkpoint inventory changed while loading")
        if binding is not None:
            current, _ = _snapshot_regular(
                path,
                root=paths.repository_root,
                label=label,
                required_mode=0o600,
                maximum=MAXIMUM_JSON_SIZE,
            )
            if current != binding:
                raise BootstrapError(f"{label} changed while loading state")
    current_key = (
        _snapshot_secret(paths.management_key, root=paths.repository_root)
        if _path_present(paths.management_key)
        else None
    )
    if current_key != state.management_key:
        raise BootstrapError("management key path changed while loading state")


def load_checkpoint_state(inputs: BootstrapInputs) -> CheckpointState:
    """Validate every present fixed checkpoint and return frozen safe state."""
    if not isinstance(inputs, BootstrapInputs):
        raise BootstrapError("bootstrap inputs are malformed")
    _revalidate_inputs(inputs)
    paths = inputs.desired.paths
    management_key = (
        _snapshot_secret(paths.management_key, root=paths.repository_root)
        if _path_present(paths.management_key)
        else None
    )
    present = {
        "attempt": _path_present(paths.attempt),
        "account": _path_present(paths.account),
        "replacement": _path_present(paths.replacement),
        "key": _path_present(paths.key),
        "proof": _path_present(paths.proof),
        "routing_intent": _path_present(paths.routing_intent),
        "routing": _path_present(paths.routing_proof),
        "final": _path_present(paths.final_receipt),
        "protected": _path_present(paths.protected_accounts),
    }
    if (
        (present["account"] and not present["attempt"])
        or (present["replacement"] and not present["account"])
        or (present["key"] and not present["account"])
        or (present["proof"] and not present["key"])
        or (present["routing_intent"] and not present["proof"])
        or (present["routing"] and not present["routing_intent"])
        or (present["final"] and not present["routing"])
        or (present["final"] and not present["protected"])
        or (present["protected"] and not present["proof"])
    ):
        raise BootstrapError("bootstrap checkpoint sequence contains a hole")

    attempt: AttemptCheckpoint | None = None
    account: AccountCheckpoint | None = None
    replacement: ReplacementCheckpoint | None = None
    key: KeyCheckpoint | None = None
    proof: BootstrapProof | None = None
    routing_intent: RoutingIntent | None = None
    routing: RoutingProof | None = None
    protected: ProtectedAccounts | None = None
    final: FinalReceipt | None = None

    if present["attempt"]:
        payload, binding = _read_envelope(
            paths.attempt,
            root=paths.repository_root,
            label="bootstrap attempt checkpoint",
        )
        attempt = _validate_attempt(payload, binding, inputs)
    if present["account"]:
        assert attempt is not None
        payload, binding = _read_envelope(
            paths.account,
            root=paths.repository_root,
            label="bootstrap Account checkpoint",
        )
        account = _validate_account(payload, binding, attempt)
    if present["replacement"]:
        assert account is not None
        payload, binding = _read_envelope(
            paths.replacement,
            root=paths.repository_root,
            label="bootstrap replacement checkpoint",
        )
        replacement = _validate_replacement(
            payload,
            binding,
            account,
        )
    if present["key"]:
        assert account is not None
        payload, binding = _read_envelope(
            paths.key,
            root=paths.repository_root,
            label="bootstrap key checkpoint",
        )
        key = _validate_key(
            payload,
            binding,
            account,
            paths,
            management_key,
            inputs,
            replacement,
        )
    if present["proof"]:
        assert key is not None
        payload, binding = _read_envelope(
            paths.proof,
            root=paths.repository_root,
            label="bootstrap proof checkpoint",
        )
        assert account is not None
        proof = _validate_proof(payload, binding, inputs, account, key)
    if present["protected"]:
        assert proof is not None
        protected = _load_protected_accounts(
            paths,
            expected_account_id=proof.account_id,
        )

    _validate_replacement_key_transition(replacement, key)
    state = CheckpointState(
        inputs=inputs,
        attempt=attempt,
        account=account,
        replacement=replacement,
        key=key,
        proof=proof,
        routing_intent=None,
        routing_proof=None,
        final_receipt=None,
        management_key=management_key,
        protected_accounts=protected,
    )
    if present["routing_intent"]:
        payload, binding = _read_envelope(
            paths.routing_intent,
            root=paths.repository_root,
            label="routing ownership intent checkpoint",
        )
        routing_intent = _validate_routing_intent(
            payload,
            binding,
            state,
        )
        state = CheckpointState(
            inputs=inputs,
            attempt=attempt,
            account=account,
            replacement=replacement,
            key=key,
            proof=proof,
            routing_intent=routing_intent,
            routing_proof=None,
            final_receipt=None,
            management_key=management_key,
            protected_accounts=protected,
        )
    if present["routing"]:
        payload, binding = _read_envelope(
            paths.routing_proof,
            root=paths.repository_root,
            label="bootstrap routing proof",
        )
        routing = _validate_routing_proof(payload, binding, state)
        state = CheckpointState(
            inputs=inputs,
            attempt=attempt,
            account=account,
            replacement=replacement,
            key=key,
            proof=proof,
            routing_intent=routing_intent,
            routing_proof=routing,
            final_receipt=None,
            management_key=management_key,
            protected_accounts=protected,
        )
    if present["final"]:
        payload, binding = _read_envelope(
            paths.final_receipt,
            root=paths.repository_root,
            label="final bootstrap receipt",
        )
        final = _validate_final_receipt(payload, binding, inputs, state)
        state = CheckpointState(
            inputs=inputs,
            attempt=attempt,
            account=account,
            replacement=replacement,
            key=key,
            proof=proof,
            routing_intent=routing_intent,
            routing_proof=routing,
            final_receipt=final,
            management_key=management_key,
            protected_accounts=protected,
        )
    _revalidate_loaded_state(state, initially_present=present)
    return state


def validate_final_bootstrap_for_retirement(
    paths: BootstrapPaths,
    *,
    task6_validator: object,
) -> ValidatedFinalBootstrap:
    """Revalidate the full chain and return a frozen, secret-free trust token."""
    validated_apply = validate_task6_apply_receipt(
        paths,
        validator=task6_validator,
    )
    inputs = load_bootstrap_inputs(
        paths,
        validated_apply=validated_apply,
    )
    state = load_checkpoint_state(inputs)
    if (
        state.attempt is None
        or state.account is None
        or state.key is None
        or state.proof is None
        or state.routing_intent is None
        or state.routing_proof is None
        or state.final_receipt is None
        or state.protected_accounts is None
        or state.management_key is None
        or state.management_key != state.key.key_file
        or state.final_receipt.ip_restriction_decision
        != state.key.ip_restriction_decision
        or state.final_receipt.ip_restriction_decision
        != IP_RESTRICTION_DECISION
    ):
        raise BootstrapError("final bootstrap validation is incomplete")
    safe_objects = state.proof.safe_objects()
    by_type = {
        item["object_type"]: item
        for item in safe_objects
        if isinstance(item, dict)
        and type(item.get("object_type")) is str
    }
    if (
        len(by_type) != len(safe_objects)
        or set(by_type)
        != {item.object_type for item in inputs.desired.objects} | {"ApiKey"}
    ):
        raise BootstrapError("validated safe object projections are incomplete")
    listener = by_type["NetworkListener"]
    listener_value = listener.get("value")
    if (
        type(listener.get("id")) is not str
        or not isinstance(listener_value, dict)
        or set(listener_value)
        != {
            "bind",
            "name",
            "protocol",
            "tlsImplicit",
            "useTls",
        }
        or not isinstance(listener_value.get("bind"), dict)
        or any(
            type(name) is not str
            or value is not True
            for name, value in listener_value["bind"].items()
        )
        or type(listener_value.get("name")) is not str
        or type(listener_value.get("protocol")) is not str
        or type(listener_value.get("useTls")) is not bool
        or type(listener_value.get("tlsImplicit")) is not bool
    ):
        raise BootstrapError("validated listener projection is malformed")
    preserved_objects_sha256 = hashlib.sha256(
        _canonical_json_bytes(state.proof.preserved_objects()),
    ).hexdigest()
    if (
        state.routing_proof.preserved_objects_sha256
        != preserved_objects_sha256
    ):
        raise BootstrapError("routing proof binds different preserved objects")
    account_projection_sha256 = hashlib.sha256(
        _canonical_json_bytes(by_type["Account"]),
    ).hexdigest()
    api_key_projection_sha256 = hashlib.sha256(
        _canonical_json_bytes(by_type["ApiKey"]),
    ).hexdigest()
    return ValidatedFinalBootstrap(
        final_receipt=state.final_receipt.binding,
        apply_receipt=inputs.apply_receipt,
        bootstrap_proof=state.proof.binding,
        routing_proof=state.routing_proof.binding,
        protected_accounts=state.protected_accounts.binding,
        bootstrap_receipt_sha256=state.final_receipt.binding.sha256,
        apply_receipt_sha256=inputs.apply_receipt.sha256,
        bootstrap_proof_sha256=state.proof.binding.sha256,
        management_account_id=state.proof.account_id,
        management_api_key_id=state.proof.credential_id,
        ip_restriction_decision=(
            state.final_receipt.ip_restriction_decision
        ),
        permissions_sha256=PERMISSIONS_SHA256,
        protected_accounts_sha256=state.protected_accounts.binding.sha256,
        safe_objects_sha256=hashlib.sha256(
            _canonical_json_bytes(safe_objects),
        ).hexdigest(),
        preserved_objects_sha256=preserved_objects_sha256,
        routing_proof_sha256=state.routing_proof.binding.sha256,
        listener_id=listener["id"],  # type: ignore[arg-type]
        listener_name=listener_value["name"],  # type: ignore[arg-type]
        listener_bind=tuple(sorted(listener_value["bind"])),
        listener_protocol=listener_value["protocol"],  # type: ignore[arg-type]
        listener_use_tls=listener_value["useTls"],  # type: ignore[arg-type]
        listener_tls_implicit=listener_value["tlsImplicit"],  # type: ignore[arg-type]
        account_projection_sha256=account_projection_sha256,
        api_key_projection_sha256=api_key_projection_sha256,
        management_key_name=state.management_key.path.name,
        management_key_size=state.management_key.size,
        management_key_identity=state.management_key.identity,
        _marker=_FINAL_BOOTSTRAP_VALIDATION_MARKER,
    )


@dataclass(frozen=True, repr=False)
class CrashRecoveryPlan:
    state: str
    actions: tuple[Action, ...]

    def __repr__(self) -> str:
        return _redacted_repr(type(self).__name__)


def _crash_action(
    kind: str,
    *,
    object_type: str,
    object_id: str | None = None,
) -> Action:
    return Action(kind, object_type, object_id)


def plan_crash_recovery(
    state: CheckpointState,
    *,
    remote_keys: Sequence[RemoteKey],
) -> CrashRecoveryPlan:
    """Plan checkpoint recovery without authenticating or mutating anything."""
    if not isinstance(state, CheckpointState) or not isinstance(
        remote_keys,
        (tuple, list),
    ) or any(not isinstance(item, RemoteKey) for item in remote_keys):
        raise BootstrapError("crash-recovery inputs are malformed")
    _validate_replacement_key_transition(state.replacement, state.key)
    if state.final_receipt is not None:
        return CrashRecoveryPlan("validated-final", ())
    if state.attempt is None:
        return CrashRecoveryPlan(
            "start",
            (_crash_action("write-attempt", object_type="Checkpoint"),),
        )
    if state.account is None:
        return CrashRecoveryPlan(
            "reconcile-read-only",
            (
                _crash_action(
                    "query-only-reconciliation",
                    object_type="Registry",
                ),
            ),
        )
    if state.key is not None and state.management_key is None:
        return CrashRecoveryPlan(
            "manual-reconciliation-required",
            (
                _crash_action(
                    "stop-missing-checkpointed-secret",
                    object_type="Checkpoint",
                ),
            ),
        )
    if state.proof is not None:
        actions: list[Action] = []
        if state.protected_accounts is None:
            actions.append(
                _crash_action(
                    "write-protected-account-ids",
                    object_type="Checkpoint",
                ),
            )
        if state.routing_proof is None:
            actions.append(
                _crash_action(
                    "run-routing-proof",
                    object_type="Checkpoint",
                ),
            )
            return CrashRecoveryPlan(
                "routing-proof-required",
                tuple(actions),
            )
        actions.append(
            _crash_action("write-final-receipt", object_type="Checkpoint"),
        )
        return CrashRecoveryPlan("finalize", tuple(actions))

    if state.key is not None:
        if (
            state.management_key == state.key.key_file
        ):
            matches = [
                item
                for item in remote_keys
                if item.account_id == state.key.account_id
                and item.credential_id == state.key.credential_id
            ]
            if len(matches) > 1:
                raise BootstrapError("exact management API key is ambiguous")
            if matches and not _exact_management_credential(
                state.inputs,
                state.key,
                matches[0],
                allowed_descriptions=frozenset(
                    {
                        MANAGEMENT_KEY_DESCRIPTION,
                        state.key.temporary_description,
                    },
                ),
            ):
                raise BootstrapError(
                    "exact management API key has conflicting safe fields",
                )
            return CrashRecoveryPlan(
                "verify-exact-key",
                (
                    _crash_action(
                        "authenticate-exact-key",
                        object_type="ApiKey",
                        object_id=state.key.credential_id,
                    ),
                ),
            )
        raise BootstrapError("management key file differs from its commitment")

    if state.management_key is not None:
        return CrashRecoveryPlan(
            "authenticate-for-future-adoption",
            (
                _crash_action(
                    "authenticate-local-secret-for-future-adoption",
                    object_type="ApiKey",
                ),
            ),
        )

    ownership = state.account.ownership
    unowned_final = [
        item
        for item in remote_keys
        if item.account_id == ownership.account_id
        and item.description == MANAGEMENT_KEY_DESCRIPTION
    ]
    if unowned_final:
        raise BootstrapError(
            "final-description management key lacks a durable checkpoint",
        )
    described_orphans = [
        item
        for item in remote_keys
        if item.account_id == ownership.account_id
        and item.description == ownership.orphan_key_description
    ]
    if any(
        item.credential_type != "ApiKey"
        or item.permissions_dict()
        != state.inputs.desired.api_key_intent.permissions_dict()
        or item.allowed_ips_dict()
        != state.inputs.desired.api_key_intent.allowed_ips_dict()
        for item in described_orphans
    ):
        raise BootstrapError(
            "bootstrap orphan description has conflicting safe fields",
        )
    orphans = described_orphans
    if len(orphans) > 1:
        raise BootstrapError("bootstrap-owned orphan API key is ambiguous")
    if orphans:
        orphan = orphans[0]
        if state.replacement is None:
            return CrashRecoveryPlan(
                "revoke-orphan-and-replace-once",
                (
                    _crash_action(
                        "write-replacement-checkpoint",
                        object_type="Checkpoint",
                    ),
                    _crash_action(
                        "revoke-exact-bootstrap-orphan",
                        object_type="ApiKey",
                        object_id=orphan.credential_id,
                    ),
                    _crash_action(
                        "create-one-replacement",
                        object_type="ApiKey",
                    ),
                ),
            )
        if (
            orphan.credential_id
            == state.replacement.orphan_credential_id
        ):
            return CrashRecoveryPlan(
                "resume-authorized-replacement",
                (
                    _crash_action(
                        "revoke-exact-bootstrap-orphan",
                        object_type="ApiKey",
                        object_id=orphan.credential_id,
                    ),
                    _crash_action(
                        "create-one-replacement",
                        object_type="ApiKey",
                    ),
                ),
            )
        return CrashRecoveryPlan(
            "replacement-limit-stop",
            (
                _crash_action(
                    "revoke-exact-bootstrap-orphan",
                    object_type="ApiKey",
                    object_id=orphan.credential_id,
                ),
                _crash_action(
                    "require-new-invocation",
                    object_type="Checkpoint",
                ),
            ),
        )
    if state.replacement is not None:
        return CrashRecoveryPlan(
            "resume-authorized-replacement",
            (
                _crash_action(
                    "create-one-replacement",
                    object_type="ApiKey",
                ),
            ),
        )
    return CrashRecoveryPlan(
        "resume-exact-account",
        (
            _crash_action(
                "create-initial-bootstrap-key",
                object_type="ApiKey",
            ),
        ),
    )


@dataclass(frozen=True)
class RoutingCommandResult:
    returncode: int
    stdout: bytes
    stderr: bytes


@dataclass
class BootstrapOrchestratorDependencies:
    """All live dependencies for one offline-testable bootstrap run."""

    acquire_operation_lock: object
    ensure_owner_directory: object
    migration_paths_factory: object
    build_task6_validator: object
    run_migration_runtime: object
    state_runner: object
    runtime_runner: object
    basic_credential_factory: object
    bearer_credential_factory: object
    registry_client_factory: object
    registry_not_found_error: object
    routing_runner: object
    clock: object
    invocation_factory: object
    password_factory: object

    def __repr__(self) -> str:
        return _redacted_repr(type(self).__name__)


def _load_sibling_module(filename: str, module_name: str) -> object:
    path = Path(__file__).resolve().parent / filename
    existing = sys.modules.get(module_name)
    if existing is not None:
        return existing
    specification = importlib.util.spec_from_file_location(module_name, path)
    if specification is None or specification.loader is None:
        raise BootstrapError("bootstrap production dependency is unavailable")
    module = importlib.util.module_from_spec(specification)
    sys.modules[module_name] = module
    try:
        specification.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(module_name, None)
        raise BootstrapError(
            "bootstrap production dependency is unavailable",
        ) from None
    return module


class _RoutingProcessFailure(Exception):
    """One fixed routing child-process invariant was not satisfied."""


def _raise_routing_cleanup_outcome(
    interruption: BaseException | None,
    failed: bool,
) -> None:
    if interruption is not None:
        if failed:
            try:
                interruption.add_note(
                    "routing verifier cleanup failed safely",
                )
            except BaseException:
                pass
        raise interruption
    if failed:
        raise _RoutingProcessFailure


def _close_routing_process_streams(
    process: subprocess.Popen[bytes],
    streams: tuple[BinaryIO | None, BinaryIO | None, BinaryIO | None],
) -> None:
    interruption: BaseException | None = None
    failed = False
    for name, stream in zip(
        ("stdin", "stdout", "stderr"),
        streams,
        strict=True,
    ):
        if stream is not None:
            try:
                stream.close()
            except BaseException as error:
                if isinstance(error, Exception):
                    failed = True
                elif interruption is None:
                    interruption = error
        try:
            if getattr(process, name, None) is stream:
                setattr(process, name, None)
        except BaseException as error:
            if isinstance(error, Exception):
                failed = True
            elif interruption is None:
                interruption = error
    _raise_routing_cleanup_outcome(interruption, failed)


def _signal_routing_process_group(
    process: subprocess.Popen[bytes],
    group_signal: int,
) -> None:
    interruption: BaseException | None = None
    try:
        os.killpg(process.pid, group_signal)
        return
    except BaseException as error:
        if not isinstance(error, Exception):
            interruption = error
    try:
        if group_signal == signal.SIGTERM:
            process.terminate()
        else:
            process.kill()
    except BaseException as error:
        _raise_routing_cleanup_outcome(
            interruption
            if interruption is not None
            else (error if not isinstance(error, Exception) else None),
            isinstance(error, Exception),
        )
    _raise_routing_cleanup_outcome(interruption, False)


def _bounded_routing_cleanup_pause() -> None:
    deadline = (
        time.monotonic() + ROUTING_PROCESS_TERMINATION_GRACE_SECONDS
    )
    interruption: BaseException | None = None
    failed = False
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            time.sleep(remaining)
        except BaseException as error:
            if isinstance(error, Exception):
                failed = True
            elif interruption is None:
                interruption = error
            continue
    _raise_routing_cleanup_outcome(interruption, failed)


def _routing_process_group_exists(
    process: subprocess.Popen[bytes],
) -> bool:
    try:
        os.killpg(process.pid, 0)
    except ProcessLookupError:
        return False
    except BaseException:
        raise
    return True


def _wait_for_routing_process_group_exit(
    process: subprocess.Popen[bytes],
) -> None:
    deadline = time.monotonic() + ROUTING_PROCESS_REAP_TIMEOUT_SECONDS
    interruption: BaseException | None = None
    failed = False
    while True:
        try:
            exists = _routing_process_group_exists(process)
        except BaseException as error:
            exists = True
            if isinstance(error, Exception):
                failed = True
            elif interruption is None:
                interruption = error
        if not exists:
            _raise_routing_cleanup_outcome(interruption, failed)
            return
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _raise_routing_cleanup_outcome(interruption, True)
            return
        try:
            time.sleep(min(0.01, remaining))
        except BaseException as error:
            if isinstance(error, Exception):
                failed = True
            elif interruption is None:
                interruption = error


def _terminate_routing_process_group(
    process: subprocess.Popen[bytes],
    streams: tuple[BinaryIO | None, BinaryIO | None, BinaryIO | None],
) -> None:
    interruption: BaseException | None = None
    failed = False

    def run_cleanup_step(
        step: Callable[..., object],
        *args: object,
    ) -> None:
        nonlocal interruption, failed
        try:
            step(*args)
        except BaseException as error:
            if isinstance(error, Exception):
                failed = True
            elif interruption is None:
                interruption = error

    run_cleanup_step(
        _signal_routing_process_group,
        process,
        signal.SIGTERM,
    )
    run_cleanup_step(_close_routing_process_streams, process, streams)
    run_cleanup_step(_bounded_routing_cleanup_pause)
    run_cleanup_step(
        _signal_routing_process_group,
        process,
        signal.SIGKILL,
    )
    direct_process_reaped = False
    for _attempt in range(2):
        try:
            process.wait(timeout=ROUTING_PROCESS_REAP_TIMEOUT_SECONDS)
            direct_process_reaped = True
            break
        except subprocess.TimeoutExpired:
            failed = True
        except BaseException as error:
            if isinstance(error, Exception):
                failed = True
            elif interruption is None:
                interruption = error
        run_cleanup_step(
            _signal_routing_process_group,
            process,
            signal.SIGKILL,
        )
    if not direct_process_reaped:
        try:
            direct_process_reaped = process.poll() is not None
        except BaseException as error:
            if isinstance(error, Exception):
                failed = True
            elif interruption is None:
                interruption = error
        if not direct_process_reaped:
            failed = True
    if direct_process_reaped:
        run_cleanup_step(_wait_for_routing_process_group_exit, process)
    _raise_routing_cleanup_outcome(interruption, failed)


def _finish_successful_routing_process(
    process: subprocess.Popen[bytes],
    streams: tuple[BinaryIO | None, BinaryIO | None, BinaryIO | None],
) -> None:
    interruption: BaseException | None = None
    failed = False
    residual_process_group = True
    try:
        residual_process_group = _routing_process_group_exists(process)
    except BaseException as error:
        if isinstance(error, Exception):
            failed = True
        else:
            interruption = error
    try:
        if residual_process_group:
            _terminate_routing_process_group(process, streams)
            failed = True
        else:
            _close_routing_process_streams(process, streams)
    except BaseException as error:
        if isinstance(error, Exception):
            failed = True
        elif interruption is None:
            interruption = error
    _raise_routing_cleanup_outcome(interruption, failed)


def _routing_stream_descriptor(stream: BinaryIO) -> int:
    descriptor = stream.fileno()
    if type(descriptor) is not int or descriptor < 0:
        raise _RoutingProcessFailure
    return descriptor


def _communicate_with_routing_process(
    process: subprocess.Popen[bytes],
    streams: tuple[BinaryIO, BinaryIO, BinaryIO],
    *,
    stdin: bytes,
    timeout: int,
) -> tuple[bytes, bytes]:
    stdin_stream, stdout_stream, stderr_stream = streams
    selector = selectors.DefaultSelector()
    input_view = memoryview(stdin)
    stdout = bytearray()
    stderr = bytearray()
    stream_by_descriptor: dict[int, BinaryIO] = {}
    deadline = time.monotonic() + timeout

    def register(
        stream: BinaryIO,
        events: int,
        name: str,
    ) -> int:
        descriptor = _routing_stream_descriptor(stream)
        os.set_blocking(descriptor, False)
        selector.register(descriptor, events, name)
        stream_by_descriptor[descriptor] = stream
        return descriptor

    def close_registered(descriptor: int) -> None:
        try:
            selector.unregister(descriptor)
        except (KeyError, ValueError):
            pass
        stream = stream_by_descriptor.pop(descriptor, None)
        if stream is not None:
            stream.close()

    try:
        stdin_descriptor = register(
            stdin_stream,
            selectors.EVENT_WRITE,
            "stdin",
        )
        register(stdout_stream, selectors.EVENT_READ, "stdout")
        register(stderr_stream, selectors.EVENT_READ, "stderr")
        input_offset = 0
        if not stdin:
            close_registered(stdin_descriptor)

        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _RoutingProcessFailure
            events = selector.select(remaining)
            if not events:
                continue
            for key, _mask in events:
                descriptor = key.fd
                if key.data == "stdin":
                    try:
                        written = os.write(
                            descriptor,
                            input_view[input_offset:],
                        )
                    except BrokenPipeError:
                        close_registered(descriptor)
                        continue
                    if written <= 0:
                        raise _RoutingProcessFailure
                    input_offset += written
                    if input_offset == len(input_view):
                        close_registered(descriptor)
                    continue

                output = stdout if key.data == "stdout" else stderr
                read_size = min(
                    ROUTING_PROCESS_IO_CHUNK_SIZE,
                    MAXIMUM_JSON_SIZE - len(output) + 1,
                )
                chunk = os.read(descriptor, read_size)
                if not chunk:
                    close_registered(descriptor)
                    continue
                if len(output) + len(chunk) > MAXIMUM_JSON_SIZE:
                    raise _RoutingProcessFailure
                output.extend(chunk)

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise _RoutingProcessFailure
        try:
            process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            raise _RoutingProcessFailure from None
        return bytes(stdout), bytes(stderr)
    finally:
        input_view.release()
        selector.close()


def _production_routing_runner(
    args: list[str],
    *,
    stdin: bytes,
    cwd: Path,
    timeout: int,
) -> RoutingCommandResult:
    if (
        not isinstance(args, list)
        or not args
        or any(type(item) is not str or not item for item in args)
        or type(stdin) is not bytes
        or not isinstance(cwd, Path)
        or type(timeout) is not int
        or timeout <= 0
    ):
        raise BootstrapError("routing verifier dispatch is malformed")
    process: subprocess.Popen[bytes] | None = None
    streams: tuple[
        BinaryIO | None,
        BinaryIO | None,
        BinaryIO | None,
    ] = (None, None, None)
    try:
        process = subprocess.Popen(
            args,
            stdin=subprocess.PIPE,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        streams = (process.stdin, process.stdout, process.stderr)
        if any(stream is None for stream in streams):
            raise _RoutingProcessFailure
        stdin_stream, stdout_stream, stderr_stream = streams
        assert stdin_stream is not None
        assert stdout_stream is not None
        assert stderr_stream is not None
        stdout, stderr = _communicate_with_routing_process(
            process,
            (stdin_stream, stdout_stream, stderr_stream),
            stdin=stdin,
            timeout=timeout,
        )
    except Exception:
        if process is not None:
            try:
                _terminate_routing_process_group(process, streams)
            except BaseException as cleanup_error:
                if not isinstance(cleanup_error, Exception):
                    raise
        raise BootstrapError("routing verifier failed safely") from None
    except BaseException as interruption:
        if process is not None:
            try:
                _terminate_routing_process_group(process, streams)
            except BaseException:
                try:
                    interruption.add_note(
                        "routing verifier cleanup failed safely",
                    )
                except BaseException:
                    pass
        raise
    try:
        _finish_successful_routing_process(process, streams)
    except Exception:
        raise BootstrapError("routing verifier failed safely") from None
    return RoutingCommandResult(
        returncode=process.returncode,
        stdout=stdout,
        stderr=stderr,
    )


def _production_clock() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _production_password() -> bytearray:
    return bytearray(secrets.token_urlsafe(32).encode("ascii"))


def production_orchestrator_dependencies() -> BootstrapOrchestratorDependencies:
    """Load the fixed sibling runtime and Registry modules without side effects."""
    migration = _load_sibling_module(
        "stalwart_v016.py",
        "_mail_sandbox_stalwart_v016",
    )
    registry = _load_sibling_module(
        "stalwart_v016_registry.py",
        "_mail_sandbox_stalwart_v016_registry",
    )
    try:
        return BootstrapOrchestratorDependencies(
            acquire_operation_lock=migration.acquire_stalwart_operation_lock,
            ensure_owner_directory=migration.ensure_owner_directory,
            migration_paths_factory=migration.MigrationPaths.for_repository,
            build_task6_validator=(
                migration.build_bootstrap_apply_receipt_validator
            ),
            run_migration_runtime=migration.run_validated_migration_runtime,
            state_runner=migration.run_command,
            runtime_runner=migration.run_redacted_command,
            basic_credential_factory=registry.BasicCredential,
            bearer_credential_factory=registry.BearerCredential,
            registry_client_factory=registry.RegistryClient,
            registry_not_found_error=registry.RegistryNotFoundError,
            routing_runner=_production_routing_runner,
            clock=_production_clock,
            invocation_factory=lambda: secrets.token_hex(16),
            password_factory=_production_password,
        )
    except AttributeError:
        raise BootstrapError(
            "bootstrap production dependency is unavailable",
        ) from None


def _callable_dependency(value: object, label: str) -> object:
    if not callable(value):
        raise BootstrapError(f"{label} dependency is unavailable")
    return value


def _validate_orchestrator_dependencies(
    dependencies: BootstrapOrchestratorDependencies,
) -> None:
    if not isinstance(dependencies, BootstrapOrchestratorDependencies):
        raise BootstrapError("bootstrap dependencies are malformed")
    for name in (
        "acquire_operation_lock",
        "ensure_owner_directory",
        "migration_paths_factory",
        "build_task6_validator",
        "run_migration_runtime",
        "state_runner",
        "runtime_runner",
        "basic_credential_factory",
        "bearer_credential_factory",
        "registry_client_factory",
        "routing_runner",
        "clock",
        "invocation_factory",
        "password_factory",
    ):
        _callable_dependency(
            getattr(dependencies, name),
            name.replace("_", " "),
        )
    if (
        not isinstance(dependencies.registry_not_found_error, type)
        or not issubclass(dependencies.registry_not_found_error, BaseException)
    ):
        raise BootstrapError(
            "Registry not-found dependency is unavailable",
        )


def _assert_operation_lock(
    operation_lock: object,
    repository_root: Path,
) -> None:
    validator = getattr(operation_lock, "assert_valid_for", None)
    if not callable(validator):
        raise BootstrapError("Stalwart operation lock token is malformed")
    try:
        validator(repository_root)
    except BootstrapError:
        raise
    except BaseException:
        raise BootstrapError(
            "Stalwart operation lock namespace changed",
        ) from None


def _wipe_mutable(value: bytearray) -> None:
    if type(value) is bytearray:
        for index in range(len(value)):
            value[index] = 0


def _fsync_directory(path: Path) -> None:
    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        os.fsync(descriptor)
    except OSError:
        raise BootstrapError("runtime directory could not be synced") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _write_new_mutable_0600(
    target: Path,
    content: bytearray,
    *,
    root: Path,
    maximum: int,
) -> None:
    if (
        type(content) is not bytearray
        or not content
        or len(content) > maximum
    ):
        raise BootstrapError("new runtime file content is malformed")
    _require_no_symlink_components(root, target.parent, "runtime file parent")
    if _path_present(target):
        raise BootstrapError("new runtime file already exists")
    descriptor: int | None = None
    view: memoryview | None = None
    temporary: Path | None = None
    published = False
    try:
        for _attempt in range(8):
            candidate = (
                target.parent
                / f".{target.name}.{secrets.token_hex(16)}.tmp"
            )
            try:
                descriptor = os.open(
                    candidate,
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0),
                    0o600,
                )
                temporary = candidate
                break
            except FileExistsError:
                continue
        if descriptor is None or temporary is None:
            raise BootstrapError(
                "new runtime temporary file could not be allocated",
            )
        view = memoryview(content)
        offset = 0
        while offset < len(view):
            written = os.write(descriptor, view[offset:])
            if written <= 0:
                raise BootstrapError("new runtime file write did not progress")
            offset += written
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or metadata.st_uid != os.getuid()
            or metadata.st_size != len(content)
        ):
            raise BootstrapError("new runtime file is unsafe")
        os.close(descriptor)
        descriptor = None
        try:
            os.link(
                temporary,
                target,
                follow_symlinks=False,
            )
        except FileExistsError:
            raise BootstrapError("new runtime file already exists") from None
        published = True
        temporary.unlink()
        temporary = None
        _fsync_directory(target.parent)
        current = target.lstat()
        if (
            stat.S_ISLNK(current.st_mode)
            or not stat.S_ISREG(current.st_mode)
            or stat.S_IMODE(current.st_mode) != 0o600
            or current.st_nlink != 1
            or current.st_uid != os.getuid()
            or current.st_size != len(content)
        ):
            raise BootstrapError("published runtime file is unsafe")
    except BootstrapError:
        raise
    except OSError:
        raise BootstrapError("new runtime file could not be published") from None
    finally:
        if view is not None:
            view.release()
        if descriptor is not None:
            os.close(descriptor)
        if temporary is not None:
            try:
                temporary.unlink()
            except OSError:
                pass
        if published and not _path_present(target):
            raise BootstrapError("published runtime file disappeared")


def _write_new_bytes_0600(
    target: Path,
    content: bytes,
    *,
    root: Path,
    maximum: int = MAXIMUM_JSON_SIZE,
) -> None:
    if type(content) is not bytes:
        raise BootstrapError("new runtime JSON content is malformed")
    mutable = bytearray(content)
    try:
        _write_new_mutable_0600(
            target,
            mutable,
            root=root,
            maximum=maximum,
        )
    finally:
        _wipe_mutable(mutable)


def _write_new_envelope_0600(
    target: Path,
    payload: Mapping[str, object],
    *,
    root: Path,
) -> None:
    copied = dict(payload)
    _validate_json_tree(copied)
    if _contains_sensitive_field(copied):
        raise BootstrapError("checkpoint payload contains a secret")
    encoded = _canonical_json_bytes(copied)
    envelope = {
        "payload": copied,
        "payload_sha256": hashlib.sha256(encoded).hexdigest(),
    }
    _write_new_bytes_0600(
        target,
        _canonical_json_bytes(envelope) + b"\n",
        root=root,
    )


def _write_new_canonical_json_0600(
    target: Path,
    payload: Mapping[str, object],
    *,
    root: Path,
) -> None:
    copied = dict(payload)
    _validate_json_tree(copied)
    if _contains_sensitive_field(copied):
        raise BootstrapError("runtime JSON contains a secret")
    _write_new_bytes_0600(
        target,
        _canonical_json_bytes(copied) + b"\n",
        root=root,
    )


def _read_secret_mutable(
    binding: SecretFileBinding,
    *,
    root: Path,
) -> bytearray:
    if not isinstance(binding, SecretFileBinding):
        raise BootstrapError("secret file commitment is malformed")
    descriptor, before = _open_regular(
        binding.path,
        root=root,
        label="management API key",
        required_mode=0o600,
    )
    if before.st_size <= 0 or before.st_size > MAXIMUM_KEY_SIZE:
        os.close(descriptor)
        raise BootstrapError("management API key size is invalid")
    result = bytearray(before.st_size)
    view = memoryview(result)
    try:
        offset = 0
        while offset < len(result):
            current = view[offset:]
            try:
                read = os.readv(descriptor, [current])
            finally:
                current.release()
            if read <= 0:
                raise BootstrapError("management API key is truncated")
            offset += read
        trailing = bytearray(1)
        trailing_view = memoryview(trailing)
        try:
            extra = os.readv(descriptor, [trailing_view])
        finally:
            trailing_view.release()
            _wipe_mutable(trailing)
        if extra:
            raise BootstrapError("management API key changed while reading")
        after = os.fstat(descriptor)
        try:
            named = binding.path.lstat()
        except OSError:
            raise BootstrapError(
                "management API key changed while reading",
            ) from None
        if (
            _secret_identity(before) != _secret_identity(after)
            or _secret_identity(named) != _secret_identity(after)
            or _secret_identity(after) != binding.identity
            or after.st_size != binding.size
        ):
            raise BootstrapError("management API key changed while reading")
        return result
    except BaseException:
        _wipe_mutable(result)
        raise
    finally:
        view.release()
        os.close(descriptor)


def _safe_unlink_0600(path: Path, *, root: Path) -> None:
    descriptor, opened = _open_regular(
        path,
        root=root,
        label="routing handoff file",
        required_mode=0o600,
    )
    try:
        if opened.st_size <= 0 or opened.st_size > MAXIMUM_JSON_SIZE:
            raise BootstrapError("routing handoff file size is invalid")
        current = path.lstat()
        if _identity(current) != _identity(opened):
            raise BootstrapError("routing handoff file changed before removal")
        path.unlink()
        after = os.fstat(descriptor)
        if (
            after.st_dev != opened.st_dev
            or after.st_ino != opened.st_ino
            or after.st_mode != opened.st_mode
            or after.st_uid != opened.st_uid
            or after.st_gid != opened.st_gid
            or after.st_size != opened.st_size
            or after.st_nlink != 0
        ):
            raise BootstrapError("routing handoff file changed during removal")
        os.close(descriptor)
        descriptor = -1
        _fsync_directory(path.parent)
    except BootstrapError:
        raise
    except OSError:
        raise BootstrapError("routing handoff file could not be removed") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _prepare_orchestrator_directories(
    repository_root: Path,
    dependencies: BootstrapOrchestratorDependencies,
) -> None:
    dashboard = repository_root / "debug-dashboard"
    runtime = dashboard / ".runtime"
    ensure = dependencies.ensure_owner_directory
    for directory in (
        runtime,
        runtime / "stalwart",
        runtime / "secrets",
        runtime / "stalwart-migration",
    ):
        ensure(
            directory,
            trusted_root=repository_root,
            owner_root=runtime,
        )
    paths = BootstrapPaths.for_repository(repository_root)
    _require_owner_runtime_directories(paths)


def _timestamp(dependencies: BootstrapOrchestratorDependencies) -> str:
    return _validate_time(dependencies.clock(), "bootstrap event time")


def _invocation_id(
    dependencies: BootstrapOrchestratorDependencies,
) -> str:
    return _validate_invocation(dependencies.invocation_factory())


def _split_recovery_credential(
    value: memoryview,
) -> tuple[str, bytearray, bytearray]:
    if not isinstance(value, memoryview) or value.ndim != 1:
        raise BootstrapError("recovery credential lease is malformed")
    separator = -1
    for index, item in enumerate(value):
        if item == ord(":"):
            if separator != -1:
                raise BootstrapError("recovery credential lease is malformed")
            separator = index
    if separator <= 0 or separator >= len(value) - 1:
        raise BootstrapError("recovery credential lease is malformed")
    username = bytearray(value[:separator])
    password = bytearray(value[separator + 1 :])
    try:
        if (
            len(username) > 255
            or len(password) > MAXIMUM_KEY_SIZE
            or any(item < 0x21 or item > 0x7E for item in username)
            or any(item in {0, 10, 13} for item in password)
        ):
            raise BootstrapError("recovery credential lease is malformed")
        username_text = username.decode("ascii", "strict")
        return username_text, username, password
    except BaseException:
        _wipe_mutable(username)
        _wipe_mutable(password)
        raise


def _registry_value_without_id(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise BootstrapError("Registry object projection is malformed")
    copied = json.loads(_json_text(value))
    if not isinstance(copied, dict):
        raise BootstrapError("Registry object projection is malformed")
    copied.pop("id", None)
    return copied


def _complete_account_credentials(
    account_id: str,
    account_value: dict[str, object],
) -> tuple[CredentialProjection, ...]:
    credential_map = account_value.pop("credentials", None)
    if not isinstance(credential_map, dict):
        raise BootstrapError("Account credential inventory is unavailable")
    result: list[CredentialProjection] = []
    seen: set[str] = set()
    for map_key in sorted(credential_map):
        if type(map_key) is not str:
            raise BootstrapError("Account credential inventory is malformed")
        raw = credential_map[map_key]
        if not isinstance(raw, dict):
            raise BootstrapError("Account credential inventory is malformed")
        item = json.loads(_json_text(raw))
        if not isinstance(item, dict):
            raise BootstrapError("Account credential inventory is malformed")
        masked = item.pop("secret", None)
        if (
            masked is not None
            and (
                type(masked) is not str
                or masked != "****"
            )
        ):
            raise BootstrapError("Account credential inventory exposed a secret")
        credential_type = item.get("@type")
        credential_id = item.get("credentialId")
        description = item.get("description")
        permissions = item.get("permissions")
        allowed_ips = item.get("allowedIps")
        if (
            type(credential_id) is not str
            or credential_id in seen
            or type(credential_type) is not str
            or description is not None
            and type(description) is not str
            or permissions is not None
            and not isinstance(permissions, dict)
            or not isinstance(allowed_ips, dict)
        ):
            raise BootstrapError("Account credential inventory is malformed")
        seen.add(credential_id)
        result.append(
            CredentialProjection.from_mapping(
                account_id=account_id,
                credential_id=credential_id,
                credential_type=credential_type,
                description=description,
                permissions=permissions,
                allowed_ips=allowed_ips,
            ),
        )
    return tuple(result)


def _desired_query_name(desired: DesiredObject) -> str | None:
    lookup = desired.lookup_dict()
    name = lookup.get("name")
    if name is not None and type(name) is not str:
        raise BootstrapError("desired Registry lookup is malformed")
    if desired.object_type == "Account":
        return MANAGEMENT_LOCAL_PART
    return name


def _query_registry_state(
    client: object,
    inputs: BootstrapInputs,
    dependencies: BootstrapOrchestratorDependencies,
) -> ObservedState:
    session = client.discover()
    if (
        getattr(session, "api_path", None) != "/jmap/"
        or type(getattr(session, "account_id", None)) is not str
        or type(getattr(session, "username", None)) is not str
    ):
        raise BootstrapError("Registry discovery returned a malformed session")
    objects: list[ObservedObject] = []
    credentials: list[CredentialProjection] = []
    for desired in inputs.desired.objects:
        object_type = desired.object_type
        name = _desired_query_name(desired)
        if name is None:
            try:
                fetched = client.get_singleton(object_type)
            except dependencies.registry_not_found_error:
                continue
            raw_value = _registry_value_without_id(fetched.value())
            objects.append(
                ObservedObject.from_mapping(
                    object_type,
                    fetched.object_id,
                    raw_value,
                ),
            )
            continue
        ids = client.query_named_ids(object_type, name)
        if not isinstance(ids, tuple):
            raise BootstrapError("Registry query result is malformed")
        for object_id in ids:
            fetched = client.get_one(object_type, object_id)
            raw_value = _registry_value_without_id(fetched.value())
            if object_type == "Account":
                credentials.extend(
                    _complete_account_credentials(
                        object_id,
                        raw_value,
                    ),
                )
            objects.append(
                ObservedObject.from_mapping(
                    object_type,
                    object_id,
                    raw_value,
                ),
            )
    return ObservedState(
        queried_types=REQUIRED_QUERY_TYPES,
        objects=tuple(objects),
        api_keys=tuple(credentials),
    )


def _observed_one(
    observed: ObservedState,
    object_type: str,
    *,
    name: str | None = None,
) -> ObservedObject:
    matches = [
        item
        for item in observed.objects
        if item.object_type == object_type
        and (
            name is None
            or item.value_dict().get("name") == name
        )
    ]
    if len(matches) != 1:
        raise BootstrapError(
            f"{object_type} projection is absent or ambiguous",
        )
    return matches[0]


def _validate_mutation_result(
    result: object,
    *,
    operation: str,
    object_type: str,
    object_id: str | None = None,
) -> str:
    actual_id = getattr(result, "object_id", None)
    if (
        getattr(result, "operation", None) != operation
        or getattr(result, "object_type", None) != object_type
        or type(actual_id) is not str
        or SAFE_ID_PATTERN.fullmatch(actual_id) is None
        or object_id is not None
        and actual_id != object_id
    ):
        raise BootstrapError("Registry mutation result is malformed")
    return actual_id


def _publish_account_checkpoint(
    inputs: BootstrapInputs,
    state: CheckpointState,
    observed: ObservedState,
    dependencies: BootstrapOrchestratorDependencies,
) -> None:
    if state.attempt is None or state.account is not None:
        raise BootstrapError("Account checkpoint prerequisites are malformed")
    account = _observed_one(
        observed,
        "Account",
        name=MANAGEMENT_LOCAL_PART,
    )
    domain = _observed_one(observed, "Domain", name="local.test")
    value = account.value_dict()
    payload = build_account_checkpoint_payload(
        state.attempt,
        created_at=_timestamp(dependencies),
        account_id=account.object_id,
        domain_id=domain.object_id,
        observed_description=value.get("description"),  # type: ignore[arg-type]
    )
    _write_new_envelope_0600(
        inputs.desired.paths.account,
        payload,
        root=inputs.desired.paths.repository_root,
    )


def _execute_reconciliation_actions(
    client: object,
    plan: ReconciliationPlan,
) -> bool:
    dispatched = False
    for action in plan.actions:
        if action.kind in {
            "noop",
            "requery-after-domain-create",
        }:
            continue
        if action.kind in {"checkpoint-account-before-finalize"}:
            raise BootstrapError(
                "Account checkpoint dispatch was ordered incorrectly",
            )
        if action.kind in {"create", "create-with-ownership-marker"}:
            result = client.create(
                action.object_type,
                action.changes_dict(),
            )
            _validate_mutation_result(
                result,
                operation="create",
                object_type=action.object_type,
            )
            dispatched = True
            continue
        if action.kind == "patch" and action.object_id is not None:
            result = client.update(
                action.object_type,
                action.object_id,
                action.changes_dict(),
            )
            _validate_mutation_result(
                result,
                operation="update",
                object_type=action.object_type,
                object_id=action.object_id,
            )
            dispatched = True
            continue
        raise BootstrapError("reconciliation action is not executable")
    return dispatched


def _reconcile_registry_objects(
    client: object,
    inputs: BootstrapInputs,
    dependencies: BootstrapOrchestratorDependencies,
) -> tuple[CheckpointState, ObservedState]:
    for _round in range(32):
        state = load_checkpoint_state(inputs)
        observed = _query_registry_state(client, inputs, dependencies)
        plan = plan_reconciliation(
            inputs.desired,
            observed,
            ownership=(
                None
                if state.account is None
                else state.account.ownership
            ),
            attempt=state.attempt,
        )
        if any(
            action.kind == "checkpoint-account-before-finalize"
            for action in plan.actions
        ):
            _publish_account_checkpoint(
                inputs,
                state,
                observed,
                dependencies,
            )
            continue
        dispatched = _execute_reconciliation_actions(client, plan)
        if dispatched or plan.state == "domain-create-requery-required":
            continue
        if (
            plan.state != "reconciled"
            or state.account is None
            or any(action.kind != "noop" for action in plan.actions)
        ):
            raise BootstrapError("Registry reconciliation did not converge")
        return state, observed
    raise BootstrapError("Registry reconciliation exceeded its fixed bound")


def _publish_attempt(
    inputs: BootstrapInputs,
    dependencies: BootstrapOrchestratorDependencies,
) -> None:
    state = load_checkpoint_state(inputs)
    if state.attempt is not None:
        return
    payload = build_attempt_payload(
        inputs,
        started_at=_timestamp(dependencies),
        invocation_id=_invocation_id(dependencies),
    )
    _write_new_envelope_0600(
        inputs.desired.paths.attempt,
        payload,
        root=inputs.desired.paths.repository_root,
    )


def _open_bearer_client(
    state: CheckpointState,
    dependencies: BootstrapOrchestratorDependencies,
) -> object:
    if (
        state.account is None
        or state.management_key is None
    ):
        raise BootstrapError("management authentication prerequisites are absent")
    raw = _read_secret_mutable(
        state.management_key,
        root=state.inputs.desired.paths.repository_root,
    )
    credential: object | None = None
    try:
        credential = dependencies.bearer_credential_factory(raw)
    finally:
        _wipe_mutable(raw)
    try:
        return dependencies.registry_client_factory(
            credential,
            expected_username=MANAGEMENT_ADDRESS,
            expected_account_id=state.account.ownership.account_id,
            timeout_seconds=5.0,
        )
    except BaseException:
        close = getattr(credential, "close", None)
        if callable(close):
            close()
        raise


def _authenticate_management_key(
    state: CheckpointState,
    dependencies: BootstrapOrchestratorDependencies,
) -> ExactAuthenticationProof:
    client = _open_bearer_client(state, dependencies)
    with client:
        session = client.discover()
    return validate_exact_authentication(
        account_id=getattr(session, "account_id", None),  # type: ignore[arg-type]
        username=getattr(session, "username", None),  # type: ignore[arg-type]
        status=200,
        server_version=SERVER_VERSION,
    )


def _publish_created_key(
    client: object,
    state: CheckpointState,
    dependencies: BootstrapOrchestratorDependencies,
) -> None:
    if (
        state.account is None
        or state.key is not None
        or state.management_key is not None
    ):
        raise BootstrapError("management API key creation is not authorized")
    account = state.account
    creation = client.create_api_key(
        account.ownership.account_id,
        {
            "allowedIps": (
                state.inputs.desired.api_key_intent.allowed_ips_dict()
            ),
            "description": account.ownership.orphan_key_description,
            "permissions": (
                state.inputs.desired.api_key_intent.permissions_dict()
            ),
        },
    )
    secret: bytearray | None = None
    try:
        if (
            getattr(creation, "account_id", None)
            != account.ownership.account_id
            or type(getattr(creation, "credential_id", None)) is not str
        ):
            raise BootstrapError("management API key creation is malformed")
        secret = creation.secret.copy_bytes()
        _write_new_mutable_0600(
            state.inputs.desired.paths.management_key,
            secret,
            root=state.inputs.desired.paths.repository_root,
            maximum=MAXIMUM_KEY_SIZE,
        )
        key_binding = _snapshot_secret(
            state.inputs.desired.paths.management_key,
            root=state.inputs.desired.paths.repository_root,
        )
        payload = build_key_checkpoint_payload(
            account,
            key_binding,
            created_at=_timestamp(dependencies),
            credential_id=creation.credential_id,
            origin="created",
            adoption_proof=None,
        )
        _write_new_envelope_0600(
            state.inputs.desired.paths.key,
            payload,
            root=state.inputs.desired.paths.repository_root,
        )
    finally:
        if secret is not None:
            _wipe_mutable(secret)
        close = getattr(creation, "close", None)
        if callable(close):
            close()


def _publish_adopted_key(
    state: CheckpointState,
    observed: ObservedState,
    dependencies: BootstrapOrchestratorDependencies,
) -> None:
    if (
        state.account is None
        or state.key is not None
        or state.management_key is None
    ):
        raise BootstrapError("management API key adoption is not authorized")
    authentication = _authenticate_management_key(state, dependencies)
    adoption = validate_key_adoption(
        state.inputs,
        state.account,
        credentials=observed.api_keys,
        authentication_status=authentication.status,
        authenticated_account_id=authentication.account_id,
        authenticated_username=authentication.username,
        server_version=authentication.server_version,
    )
    payload = build_key_checkpoint_payload(
        state.account,
        state.management_key,
        created_at=_timestamp(dependencies),
        credential_id=adoption.credential_id,
        origin="adopted",
        adoption_proof=adoption,
    )
    _write_new_envelope_0600(
        state.inputs.desired.paths.key,
        payload,
        root=state.inputs.desired.paths.repository_root,
    )


def _publish_replacement_checkpoint(
    state: CheckpointState,
    orphan_credential_id: str,
    dependencies: BootstrapOrchestratorDependencies,
) -> None:
    if state.account is None or state.replacement is not None:
        raise BootstrapError("API key replacement is not authorized")
    payload = build_replacement_checkpoint_payload(
        state.account,
        created_at=_timestamp(dependencies),
        orphan_credential_id=orphan_credential_id,
    )
    _write_new_envelope_0600(
        state.inputs.desired.paths.replacement,
        payload,
        root=state.inputs.desired.paths.repository_root,
    )


def _revoke_key(
    client: object,
    state: CheckpointState,
    credential_id: str,
) -> None:
    if state.account is None:
        raise BootstrapError("API key revocation is not authorized")
    result = client.destroy(
        "ApiKey",
        credential_id,
        account_id=state.account.ownership.account_id,
    )
    _validate_mutation_result(
        result,
        operation="destroy",
        object_type="ApiKey",
        object_id=credential_id,
    )


def _final_object_ids(
    inputs: BootstrapInputs,
    observed: ObservedState,
    account: AccountCheckpoint,
    key: KeyCheckpoint,
) -> dict[str, str]:
    result: dict[str, str] = {}
    for desired in inputs.desired.objects:
        matches = [
            item
            for item in observed.objects
            if _target_matches(
                desired,
                item,
                account.ownership.domain_id,
            )
        ]
        if len(matches) != 1:
            raise BootstrapError("final Registry projection is incomplete")
        result[desired.object_type] = matches[0].object_id
    result["ApiKey"] = key.credential_id
    return result


def _preserved_strategy_projection(
    client: object,
) -> list[dict[str, object]]:
    fetched = client.get_singleton("MtaOutboundStrategy")
    value = _registry_value_without_id(fetched.value())
    projection = [
        {
            "id": fetched.object_id,
            "object_type": "MtaOutboundStrategy",
            "value": value,
        },
    ]
    if (
        _canonical_json_bytes(projection)
        != _canonical_json_bytes(_preserved_object_projections())
    ):
        raise BootstrapError(
            "preserved MtaOutboundStrategy differs from the pinned default",
        )
    return projection


def _publish_bootstrap_proof(
    client: object,
    state: CheckpointState,
    observed: ObservedState,
    dependencies: BootstrapOrchestratorDependencies,
) -> None:
    if (
        state.account is None
        or state.key is None
        or state.proof is not None
    ):
        raise BootstrapError("bootstrap proof is not authorized")
    key = state.key
    if len(observed.api_keys) != 1:
        raise BootstrapError(
            "final credential inventory is not exactly one intended API key",
        )
    credential = observed.api_keys[0]
    if credential.description != MANAGEMENT_KEY_DESCRIPTION:
        result = client.update(
            "ApiKey",
            key.credential_id,
            {"description": MANAGEMENT_KEY_DESCRIPTION},
            account_id=key.account_id,
        )
        _validate_mutation_result(
            result,
            operation="update",
            object_type="ApiKey",
            object_id=key.credential_id,
        )
        state, observed = _reconcile_registry_objects(
            client,
            state.inputs,
            dependencies,
        )
        if state.key is None:
            raise BootstrapError("management key checkpoint disappeared")
        key = state.key
    authentication = _authenticate_management_key(state, dependencies)
    object_ids = _final_object_ids(
        state.inputs,
        observed,
        state.account,
        key,
    )
    safe_objects = _safe_object_projections(
        state.inputs,
        state.account,
        key,
        object_ids,
    )
    preserved = _preserved_strategy_projection(client)
    executor_proof = validate_executor_observation(
        state.inputs,
        state.account,
        key,
        safe_objects=safe_objects,
        preserved_objects=preserved,
        credentials=observed.api_keys,
        authentication_status=authentication.status,
        authenticated_account_id=authentication.account_id,
        authenticated_username=authentication.username,
        server_version=authentication.server_version,
    )
    payload = build_proof_payload(
        state.inputs,
        state.account,
        key,
        proven_at=_timestamp(dependencies),
        executor_proof=executor_proof,
    )
    _write_new_envelope_0600(
        state.inputs.desired.paths.proof,
        payload,
        root=state.inputs.desired.paths.repository_root,
    )


def _ensure_management_key_and_proof(
    client: object,
    inputs: BootstrapInputs,
    dependencies: BootstrapOrchestratorDependencies,
) -> CheckpointState:
    for _round in range(16):
        state, observed = _reconcile_registry_objects(
            client,
            inputs,
            dependencies,
        )
        if state.proof is not None:
            return state
        if (
            state.account is not None
            and state.key is None
            and state.management_key is None
            and any(
                credential.description
                != state.account.ownership.orphan_key_description
                for credential in observed.api_keys
            )
        ):
            raise BootstrapError(
                "management Account has an unowned credential inventory",
            )
        recovery = plan_crash_recovery(
            state,
            remote_keys=observed.api_keys,
        )
        if recovery.state == "manual-reconciliation-required":
            raise BootstrapError(
                "checkpointed management key needs manual reconciliation",
            )
        if recovery.state == "authenticate-for-future-adoption":
            _publish_adopted_key(
                state,
                observed,
                dependencies,
            )
            continue
        if recovery.state == "resume-exact-account":
            _publish_created_key(client, state, dependencies)
            continue
        if recovery.state == "revoke-orphan-and-replace-once":
            orphan = next(
                (
                    action.object_id
                    for action in recovery.actions
                    if action.kind == "revoke-exact-bootstrap-orphan"
                ),
                None,
            )
            if orphan is None:
                raise BootstrapError("replacement orphan ID is unavailable")
            _publish_replacement_checkpoint(
                state,
                orphan,
                dependencies,
            )
            state = load_checkpoint_state(inputs)
            _revoke_key(client, state, orphan)
            _publish_created_key(client, state, dependencies)
            continue
        if recovery.state == "resume-authorized-replacement":
            for action in recovery.actions:
                if action.kind == "revoke-exact-bootstrap-orphan":
                    if action.object_id is None:
                        raise BootstrapError(
                            "replacement orphan ID is unavailable",
                        )
                    _revoke_key(client, state, action.object_id)
                elif action.kind == "create-one-replacement":
                    _publish_created_key(client, state, dependencies)
                else:
                    raise BootstrapError(
                        "replacement action is not executable",
                    )
            continue
        if recovery.state == "replacement-limit-stop":
            for action in recovery.actions:
                if (
                    action.kind == "revoke-exact-bootstrap-orphan"
                    and action.object_id is not None
                ):
                    _revoke_key(client, state, action.object_id)
            raise BootstrapError(
                "management key replacement limit requires a new invocation",
            )
        if recovery.state == "verify-exact-key":
            _publish_bootstrap_proof(
                client,
                state,
                observed,
                dependencies,
            )
            continue
        raise BootstrapError("bootstrap crash recovery did not converge")
    raise BootstrapError("management API key recovery exceeded its fixed bound")


def _publish_protected_accounts(state: CheckpointState) -> None:
    if state.proof is None:
        raise BootstrapError("protected Account proof is unavailable")
    if state.protected_accounts is not None:
        return
    payload = {
        "account_ids": [state.proof.account_id],
        "schema": PROTECTED_ACCOUNTS_SCHEMA,
    }
    _write_new_canonical_json_0600(
        state.inputs.desired.paths.protected_accounts,
        payload,
        root=state.inputs.desired.paths.repository_root,
    )


def _actor_address(role: str, invocation_id: str) -> str:
    if role not in {"sender", "recipient"}:
        raise BootstrapError("routing actor role is malformed")
    _validate_invocation(invocation_id)
    return f"dashboard-routing-{role}-{invocation_id}@local.test"


def _routing_actor_value(
    *,
    address: str,
    domain_id: str,
    password: bytearray,
) -> dict[str, object]:
    _validate_id(domain_id, "routing Domain ID")
    if (
        type(password) is not bytearray
        or not password
        or len(password) > 1024
        or any(item < 0x21 or item > 0x7E for item in password)
    ):
        raise BootstrapError("routing actor password is malformed")
    try:
        secret = password.decode("utf-8", "strict")
    except UnicodeError:
        raise BootstrapError("routing actor password is malformed") from None
    return {
        **_routing_account_projection(address, domain_id),
        "credentials": {
            "0": {
                "@type": "Password",
                "allowedIps": {},
                "secret": secret,
            },
        },
    }


def _routing_input_payload(
    state: CheckpointState,
    actors: Mapping[str, Mapping[str, str]],
) -> dict[str, object]:
    if (
        state.attempt is None
        or state.account is None
        or state.key is None
        or state.proof is None
    ):
        raise BootstrapError("routing input prerequisites are incomplete")
    copied_actors = json.loads(_json_text(dict(actors)))
    if (
        not isinstance(copied_actors, dict)
        or set(copied_actors) != {"recipient", "sender"}
    ):
        raise BootstrapError("routing input actors are malformed")
    expected: dict[str, dict[str, str]] = {}
    for role in ("recipient", "sender"):
        value = copied_actors.get(role)
        if (
            not isinstance(value, dict)
            or set(value) != {"account_id", "address"}
        ):
            raise BootstrapError("routing input actor is malformed")
        account_id = _validate_id(
            value.get("account_id"),
            "routing actor Account ID",
        )
        address = _actor_address(role, state.attempt.invocation_id)
        if value.get("address") != address:
            raise BootstrapError("routing input actor address is malformed")
        expected[role] = {
            "account_id": account_id,
            "address": address,
        }
    account_ids = {
        state.account.ownership.account_id,
        expected["recipient"]["account_id"],
        expected["sender"]["account_id"],
    }
    if len(account_ids) != 3:
        raise BootstrapError("routing actor Account IDs are not distinct")
    preserved_sha256 = hashlib.sha256(
        _canonical_json_bytes(state.proof.preserved_objects()),
    ).hexdigest()
    return {
        "actors": expected,
        "bootstrap_proof": _file_metadata(state.proof.binding),
        "invocation_id": state.attempt.invocation_id,
        "management_account_id": state.proof.account_id,
        "management_credential_id": state.proof.credential_id,
        "preserved_objects_sha256": preserved_sha256,
        "schema": ROUTING_INPUT_SCHEMA,
        "server_version": SERVER_VERSION,
    }


def _parse_routing_verifier_output(
    result: RoutingCommandResult,
    routing_input: Mapping[str, object],
) -> dict[str, object]:
    if (
        not isinstance(result, RoutingCommandResult)
        or type(result.returncode) is not int
        or type(result.stdout) is not bytes
        or type(result.stderr) is not bytes
    ):
        raise BootstrapError("routing verifier result is malformed")
    if (
        result.returncode != 0
        or result.stderr != b""
        or not result.stdout.endswith(b"\n")
        or result.stdout.count(b"\n") != 1
        or len(result.stdout) > MAXIMUM_JSON_SIZE
    ):
        raise BootstrapError("routing verifier failed safely")
    payload = _strict_json_bytes(
        result.stdout[:-1],
        "routing verifier output",
    )
    expected_keys = {
        "actors",
        "bootstrap_proof",
        "invocation_id",
        "management_account_id",
        "management_credential_id",
        "message_id",
        "preserved_objects_sha256",
        "probes",
        "proven_at",
        "recipient_access_removed",
        "schema",
        "server_version",
    }
    if (
        not isinstance(payload, dict)
        or set(payload) != expected_keys
        or payload.get("schema") != ROUTING_VERIFIER_SCHEMA
        or _canonical_json_bytes(payload) + b"\n" != result.stdout
    ):
        raise BootstrapError("routing verifier output is not canonical")
    for name in (
        "bootstrap_proof",
        "invocation_id",
        "management_account_id",
        "management_credential_id",
        "preserved_objects_sha256",
        "server_version",
    ):
        if payload.get(name) != routing_input.get(name):
            raise BootstrapError("routing verifier output binds different input")
    input_actors = routing_input.get("actors")
    output_actors = payload.get("actors")
    if (
        not isinstance(input_actors, dict)
        or not isinstance(output_actors, dict)
        or set(output_actors) != {"recipient", "sender"}
    ):
        raise BootstrapError("routing verifier actors are malformed")
    for role in ("recipient", "sender"):
        actor = output_actors.get(role)
        original = input_actors.get(role)
        if (
            not isinstance(actor, dict)
            or not isinstance(original, dict)
            or set(actor)
            != {
                "account_id",
                "address",
                "app_password_credential_id",
            }
            or actor.get("account_id") != original.get("account_id")
            or actor.get("address") != original.get("address")
        ):
            raise BootstrapError("routing verifier actor binding is malformed")
        _validate_id(
            actor.get("app_password_credential_id"),
            "routing AppPassword ID",
        )
    _validate_time(payload.get("proven_at"), "routing proof time")
    return payload


def _destroy_and_requery_actor(
    client: object,
    *,
    role: str,
    invocation_id: str,
    account_id: str,
    dependencies: BootstrapOrchestratorDependencies,
) -> None:
    result = client.destroy("Account", account_id)
    _validate_mutation_result(
        result,
        operation="destroy",
        object_type="Account",
        object_id=account_id,
    )
    try:
        client.get_one("Account", account_id)
    except dependencies.registry_not_found_error:
        pass
    else:
        raise BootstrapError("routing Account still exists after destruction")
    local_part = _actor_address(role, invocation_id).partition("@")[0]
    if client.query_named_ids("Account", local_part) != ():
        raise BootstrapError("routing Account address still resolves")


def _best_effort_actor_cleanup(
    client: object,
    actors: Mapping[str, str],
    *,
    invocation_id: str,
    domain_id: str,
) -> None:
    for role in ("sender", "recipient"):
        try:
            local_part = _actor_address(role, invocation_id).partition("@")[0]
            queried = client.query_named_ids("Account", local_part)
            candidates = set(queried)
            known = actors.get(role)
            if known is not None:
                candidates.add(known)
            if len(candidates) != 1:
                continue
            account_id = next(iter(candidates))
            fetched = client.get_one("Account", account_id)
            value = fetched.value()
            if (
                not isinstance(value, dict)
                or value.get("@type") != "User"
                or value.get("name") != local_part
                or value.get("domainId") != domain_id
                or value.get("permissions") != {"@type": "Inherit"}
                or value.get("roles") != {"@type": "User"}
            ):
                continue
            client.destroy("Account", account_id)
        except BaseException:
            pass


def _routing_actor_query_ids(
    client: object,
    *,
    role: str,
    invocation_id: str,
) -> tuple[str, ...]:
    local_part = _actor_address(role, invocation_id).partition("@")[0]
    result = client.query_named_ids("Account", local_part)
    if (
        not isinstance(result, tuple)
        or any(
            type(object_id) is not str
            or SAFE_ID_PATTERN.fullmatch(object_id) is None
            for object_id in result
        )
        or len(set(result)) != len(result)
    ):
        raise BootstrapError("routing Account query result is malformed")
    return result


def _routing_app_password_description(
    role: str,
    invocation_id: str,
) -> str:
    if role not in {"sender", "recipient"}:
        raise BootstrapError("routing actor role is malformed")
    _validate_invocation(invocation_id)
    invocation_uuid = (
        f"{invocation_id[:8]}-{invocation_id[8:12]}-"
        f"{invocation_id[12:16]}-{invocation_id[16:20]}-"
        f"{invocation_id[20:]}"
    )
    generation = 1 if role == "sender" else 2
    return (
        "mail-sandbox/debug-dashboard/"
        f"{invocation_uuid}/{generation}"
    )


def _validate_owned_routing_account(
    client: object,
    *,
    role: str,
    account_id: str,
    intent: RoutingIntent,
) -> str | None:
    fetched = client.get_one("Account", account_id)
    raw = fetched.value()
    if not isinstance(raw, dict):
        raise BootstrapError(
            "owned routing Account projection is malformed",
        )
    value = json.loads(_json_text(raw))
    if not isinstance(value, dict):
        raise BootstrapError(
            "owned routing Account projection is malformed",
        )
    value.pop("id", None)
    credentials = _complete_account_credentials(account_id, value)
    actors = intent.actors()
    actor = actors.get(role)
    if (
        not isinstance(actor, dict)
        or set(actor) != {"address", "projection"}
        or not isinstance(actor.get("projection"), dict)
        or _canonical_json_bytes(value)
        != _canonical_json_bytes(actor["projection"])
    ):
        raise BootstrapError(
            "owned routing Account differs from its durable intent",
        )
    passwords = [
        credential
        for credential in credentials
        if credential.credential_type == "Password"
    ]
    app_passwords = [
        credential
        for credential in credentials
        if credential.credential_type == "AppPassword"
    ]
    if (
        len(passwords) != 1
        or len(app_passwords) > 1
        or len(credentials) != len(passwords) + len(app_passwords)
        or passwords[0].description is not None
        or passwords[0].permissions_dict() is not None
        or passwords[0].allowed_ips_dict() != {}
    ):
        raise BootstrapError(
            "owned routing Account credential inventory is not exact",
        )
    if app_passwords:
        app_password = app_passwords[0]
        expected_permissions = {
            "@type": "Replace",
            "permissions": {
                name: True
                for name in ROUTING_MAIL_PERMISSIONS
            },
        }
        if (
            app_password.description
            != _routing_app_password_description(
                role,
                intent.invocation_id,
            )
            or app_password.permissions_dict() != expected_permissions
            or app_password.allowed_ips_dict() != {}
        ):
            raise BootstrapError(
                "owned routing AppPassword inventory is not exact",
            )
        return app_password.credential_id
    return None


def _query_owned_app_password_ids(
    client: object,
    *,
    account_id: str,
) -> tuple[str, ...]:
    result = client.query_credential_ids(
        "AppPassword",
        account_id,
    )
    if (
        not isinstance(result, tuple)
        or any(
            type(credential_id) is not str
            or SAFE_ID_PATTERN.fullmatch(credential_id) is None
            for credential_id in result
        )
        or len(set(result)) != len(result)
    ):
        raise BootstrapError(
            "routing AppPassword query result is malformed",
        )
    return result


def _destroy_owned_app_password(
    client: object,
    *,
    account_id: str,
    credential_id: str | None,
) -> None:
    if credential_id is None:
        return
    try:
        result = client.destroy(
            "AppPassword",
            credential_id,
            account_id=account_id,
        )
    except Exception:
        if (
            _query_owned_app_password_ids(
                client,
                account_id=account_id,
            )
            == ()
        ):
            return
        raise
    _validate_mutation_result(
        result,
        operation="destroy",
        object_type="AppPassword",
        object_id=credential_id,
    )
    if _query_owned_app_password_ids(
        client,
        account_id=account_id,
    ) != ():
        raise BootstrapError(
            "routing AppPassword still exists after destruction",
        )


def _publish_routing_intent(
    client: object,
    state: CheckpointState,
) -> CheckpointState:
    if state.routing_intent is not None:
        return state
    paths = state.inputs.desired.paths
    if any(
        _path_present(path)
        for path in (
            paths.routing_input,
            paths.routing_sender_password,
            paths.routing_recipient_password,
        )
    ):
        raise BootstrapError(
            "routing handoff exists without a durable ownership intent",
        )
    if state.attempt is None:
        raise BootstrapError("routing ownership attempt is unavailable")
    for role in ("sender", "recipient"):
        if _routing_actor_query_ids(
            client,
            role=role,
            invocation_id=state.attempt.invocation_id,
        ):
            raise BootstrapError(
                "routing actor address exists without a durable ownership intent",
            )
    payload = build_routing_intent_payload(state)
    _write_new_envelope_0600(
        paths.routing_intent,
        payload,
        root=paths.repository_root,
    )
    published = load_checkpoint_state(state.inputs)
    if published.routing_intent is None:
        raise BootstrapError("routing ownership intent was not published")
    return published


def _resume_owned_routing_intent(
    client: object,
    state: CheckpointState,
    dependencies: BootstrapOrchestratorDependencies,
) -> None:
    intent = state.routing_intent
    if (
        intent is None
        or state.attempt is None
        or intent.invocation_id != state.attempt.invocation_id
    ):
        raise BootstrapError("routing ownership intent is unavailable")
    found: list[tuple[str, str, str | None]] = []
    for role in ("sender", "recipient"):
        ids = _routing_actor_query_ids(
            client,
            role=role,
            invocation_id=intent.invocation_id,
        )
        if len(ids) > 1:
            raise BootstrapError(
                "owned routing Account query is ambiguous; "
                "manual reconciliation required",
            )
        if ids:
            app_password_id = _validate_owned_routing_account(
                client,
                role=role,
                account_id=ids[0],
                intent=intent,
            )
            found.append((role, ids[0], app_password_id))
    for _role, account_id, app_password_id in found:
        expected_app_password_ids = (
            ()
            if app_password_id is None
            else (app_password_id,)
        )
        if (
            _query_owned_app_password_ids(
                client,
                account_id=account_id,
            )
            != expected_app_password_ids
        ):
            raise BootstrapError(
                "routing AppPassword inventory differs from "
                "Account projection",
            )
    for role, account_id, app_password_id in found:
        _destroy_owned_app_password(
            client,
            account_id=account_id,
            credential_id=app_password_id,
        )
        _destroy_and_requery_actor(
            client,
            role=role,
            invocation_id=intent.invocation_id,
            account_id=account_id,
            dependencies=dependencies,
        )
    paths = state.inputs.desired.paths
    for handoff in (
        paths.routing_input,
        paths.routing_sender_password,
        paths.routing_recipient_password,
    ):
        if _path_present(handoff):
            _safe_unlink_0600(
                handoff,
                root=paths.repository_root,
            )


def _publish_routing_proof(
    client: object,
    state: CheckpointState,
    dependencies: BootstrapOrchestratorDependencies,
) -> None:
    if state.routing_proof is not None:
        paths = state.inputs.desired.paths
        for handoff in (
            paths.routing_input,
            paths.routing_sender_password,
            paths.routing_recipient_password,
        ):
            if _path_present(handoff):
                _safe_unlink_0600(
                    handoff,
                    root=paths.repository_root,
                )
        return
    if (
        state.attempt is None
        or state.account is None
        or state.proof is None
    ):
        raise BootstrapError("routing proof prerequisites are incomplete")
    paths = state.inputs.desired.paths
    state = _publish_routing_intent(client, state)
    _resume_owned_routing_intent(client, state, dependencies)
    if state.routing_intent is None:
        raise BootstrapError("routing ownership intent is unavailable")
    invocation_id = state.attempt.invocation_id
    domain_id = state.account.ownership.domain_id
    passwords: dict[str, bytearray] = {}
    actor_ids: dict[str, str] = {}
    actors: dict[str, dict[str, str]] = {}
    try:
        for role in ("sender", "recipient"):
            address = _actor_address(role, invocation_id)
            local_part = address.partition("@")[0]
            if client.query_named_ids("Account", local_part):
                raise BootstrapError(
                    "routing actor address already exists without ownership",
                )
            password = dependencies.password_factory()
            if type(password) is not bytearray:
                raise BootstrapError("routing actor password is malformed")
            passwords[role] = password
            result = client.create(
                "Account",
                _routing_actor_value(
                    address=address,
                    domain_id=domain_id,
                    password=password,
                ),
            )
            account_id = _validate_mutation_result(
                result,
                operation="create",
                object_type="Account",
            )
            actor_ids[role] = account_id
            actors[role] = {
                "account_id": account_id,
                "address": address,
            }
        _write_new_mutable_0600(
            paths.routing_sender_password,
            passwords["sender"],
            root=paths.repository_root,
            maximum=1024,
        )
        _write_new_mutable_0600(
            paths.routing_recipient_password,
            passwords["recipient"],
            root=paths.repository_root,
            maximum=1024,
        )
        routing_input = _routing_input_payload(state, actors)
        _write_new_canonical_json_0600(
            paths.routing_input,
            routing_input,
            root=paths.repository_root,
        )
        command = build_routing_verifier_command(
            paths.repository_root,
            invocation_id,
        )
        result = dependencies.routing_runner(
            command,
            stdin=b"",
            cwd=paths.repository_root / "debug-dashboard",
            timeout=300,
        )
        verifier = _parse_routing_verifier_output(result, routing_input)
        for role in ("sender", "recipient"):
            _destroy_and_requery_actor(
                client,
                role=role,
                invocation_id=invocation_id,
                account_id=actor_ids[role],
                dependencies=dependencies,
            )
        cleanup = {
            "account_get_not_found": [
                actor_ids["sender"],
                actor_ids["recipient"],
            ],
            "address_queries": [
                {
                    "address": actors["sender"]["address"],
                    "ids": [],
                },
                {
                    "address": actors["recipient"]["address"],
                    "ids": [],
                },
            ],
            "destroyed_account_ids": [
                actor_ids["sender"],
                actor_ids["recipient"],
            ],
        }
        payload = build_routing_proof_payload(
            state,
            proven_at=verifier["proven_at"],  # type: ignore[arg-type]
            actors=verifier["actors"],  # type: ignore[arg-type]
            message_id=verifier["message_id"],  # type: ignore[arg-type]
            probes=verifier["probes"],  # type: ignore[arg-type]
            recipient_access_removed=verifier[
                "recipient_access_removed"
            ],  # type: ignore[arg-type]
            cleanup=cleanup,
        )
        _write_new_envelope_0600(
            paths.routing_proof,
            payload,
            root=paths.repository_root,
        )
        _safe_unlink_0600(paths.routing_input, root=paths.repository_root)
        _safe_unlink_0600(
            paths.routing_sender_password,
            root=paths.repository_root,
        )
        _safe_unlink_0600(
            paths.routing_recipient_password,
            root=paths.repository_root,
        )
    except Exception:
        _best_effort_actor_cleanup(
            client,
            actor_ids,
            invocation_id=invocation_id,
            domain_id=domain_id,
        )
        raise
    finally:
        for password in passwords.values():
            _wipe_mutable(password)


def _publish_final_receipt(
    inputs: BootstrapInputs,
    state: CheckpointState,
    dependencies: BootstrapOrchestratorDependencies,
) -> None:
    if state.final_receipt is not None:
        return
    payload = build_final_receipt_payload(
        inputs,
        state,
        completed_at=_timestamp(dependencies),
    )
    _write_new_envelope_0600(
        inputs.desired.paths.final_receipt,
        payload,
        root=inputs.desired.paths.repository_root,
    )


def _bootstrap_inside_recovery_runtime(
    runtime: object,
    inputs: BootstrapInputs,
    dependencies: BootstrapOrchestratorDependencies,
) -> None:
    if (
        getattr(runtime, "base_url", None) != "http://127.0.0.1:18080"
        or getattr(runtime, "api_url", None)
        != "http://127.0.0.1:18080/jmap/"
        or getattr(runtime, "server_version", None) != SERVER_VERSION
    ):
        raise BootstrapError("migration bootstrap runtime is not pinned")
    borrowed = runtime.borrow_recovery_credential()
    if not isinstance(borrowed, memoryview):
        raise BootstrapError("recovery credential lease is malformed")
    credential: object | None = None
    try:
        username_text, username, password = _split_recovery_credential(
            borrowed,
        )
        try:
            credential = dependencies.basic_credential_factory(
                username,
                password,
            )
        finally:
            _wipe_mutable(username)
            _wipe_mutable(password)
    finally:
        borrowed.release()
    try:
        client = dependencies.registry_client_factory(
            credential,
            expected_username=username_text,
            expected_account_id=None,
            timeout_seconds=5.0,
        )
    except BaseException:
        close = getattr(credential, "close", None)
        if callable(close):
            close()
        raise
    with client:
        session = client.discover()
        if (
            getattr(session, "username", None) != username_text
            or type(getattr(session, "account_id", None)) is not str
        ):
            raise BootstrapError(
                "recovery Registry authentication is malformed",
            )
        state = load_checkpoint_state(inputs)
        if state.final_receipt is not None:
            return
        _publish_attempt(inputs, dependencies)
        state = _ensure_management_key_and_proof(
            client,
            inputs,
            dependencies,
        )
        _publish_protected_accounts(state)
        state = load_checkpoint_state(inputs)
        _publish_routing_proof(client, state, dependencies)
        state = load_checkpoint_state(inputs)
        _publish_final_receipt(inputs, state, dependencies)
        final_state = load_checkpoint_state(inputs)
        if final_state.final_receipt is None:
            raise BootstrapError("final bootstrap receipt was not published")


def _build_task6_validator(
    migration_paths: object,
    migration_python: Path,
    dependencies: BootstrapOrchestratorDependencies,
    *,
    runtime_phase: str,
) -> object:
    return dependencies.build_task6_validator(
        migration_paths,
        source_receipt_path=migration_paths.source_receipt,
        script_path=migration_paths.migration_script,
        dry_run_receipt_path=migration_paths.dry_run_receipt,
        review_receipt_path=migration_paths.reviewed,
        runner=dependencies.state_runner,
        python_executable=str(migration_python),
        runtime_phase=runtime_phase,
    )


def run_bootstrap(
    repository_root: Path,
    migration_python: Path,
    *,
    dependencies: BootstrapOrchestratorDependencies,
) -> ValidatedFinalBootstrap:
    """Run one exact crash-recoverable bootstrap under the shared live lock."""
    root = _normalized_absolute(repository_root, "repository root")
    migration_interpreter = _normalized_absolute(
        migration_python,
        "migration Python",
    )
    _require_real_root(root)
    _validate_orchestrator_dependencies(dependencies)
    paths = BootstrapPaths.for_repository(root)
    migration_paths = dependencies.migration_paths_factory(root)
    with dependencies.acquire_operation_lock(root) as operation_lock:
        _assert_operation_lock(operation_lock, root)
        _prepare_orchestrator_directories(root, dependencies)
        _assert_operation_lock(operation_lock, root)
        durable_task6_validator = _build_task6_validator(
            migration_paths,
            migration_interpreter,
            dependencies,
            runtime_phase="durable-recovery",
        )
        validated_apply = validate_task6_apply_receipt(
            paths,
            validator=durable_task6_validator,
        )
        _assert_operation_lock(operation_lock, root)

        def bootstrap_operation(runtime: object) -> ValidatedFinalBootstrap:
            _assert_operation_lock(operation_lock, root)
            inputs = load_bootstrap_inputs(
                paths,
                validated_apply=validated_apply,
            )
            _assert_operation_lock(operation_lock, root)
            _bootstrap_inside_recovery_runtime(
                runtime,
                inputs,
                dependencies,
            )
            _assert_operation_lock(operation_lock, root)
            ready_task6_validator = _build_task6_validator(
                migration_paths,
                migration_interpreter,
                dependencies,
                runtime_phase="ready",
            )
            validated_final = validate_final_bootstrap_for_retirement(
                paths,
                task6_validator=ready_task6_validator,
            )
            _assert_operation_lock(operation_lock, root)
            return validated_final

        validated_final = dependencies.run_migration_runtime(
            migration_paths,
            apply_receipt_path=migration_paths.apply_receipt,
            source_receipt_path=migration_paths.source_receipt,
            script_path=migration_paths.migration_script,
            dry_run_receipt_path=migration_paths.dry_run_receipt,
            review_receipt_path=migration_paths.reviewed,
            state_runner=dependencies.state_runner,
            runtime_runner=dependencies.runtime_runner,
            python_executable=str(migration_interpreter),
            operation=bootstrap_operation,
            operation_lock=operation_lock,
        )
        _assert_operation_lock(operation_lock, root)
        return validated_final


def build_routing_verifier_command(
    repository_root: Path,
    invocation_id: str,
) -> list[str]:
    """Return the one fixed Kotlin Toolchain routing-verifier invocation."""
    root = _normalized_absolute(repository_root, "repository root")
    _validate_invocation(invocation_id)
    dashboard_root = root / "debug-dashboard"
    return [
        str(dashboard_root / "kotlin"),
        "--log-level",
        "off",
        "run",
        "-m",
        "dashboard-server",
        "--main-class",
        ROUTING_VERIFIER_MAIN,
        "--",
        "--dashboard-project-root",
        str(dashboard_root),
        "--invocation-id",
        invocation_id,
    ]


def _absolute_cli_path(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute() or Path(os.path.normpath(value)) != path:
        raise argparse.ArgumentTypeError("must be a normalized absolute path")
    return path


def _build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Bootstrap or validate fixed Stalwart v0.16 assets.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate = subparsers.add_parser(
        "validate-assets",
        help="validate the fixed manifest and Sieve policy",
    )
    validate.add_argument(
        "--repository",
        required=True,
        type=_absolute_cli_path,
        help="normalized absolute repository root",
    )
    bootstrap_parser = subparsers.add_parser(
        "bootstrap",
        help="run the exact crash-recoverable Stalwart bootstrap",
    )
    bootstrap_parser.add_argument(
        "--repository",
        required=True,
        type=_absolute_cli_path,
        help="exact normalized repository root",
    )
    bootstrap_parser.add_argument(
        "--migration-python",
        required=True,
        type=_absolute_cli_path,
        help="normalized absolute Task 6 migration Python",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    live_bootstrap_started = False
    if arguments and arguments[0] in {
        "apply",
        "execute",
        "write",
    }:
        print(
            f"error: {arguments[0]} is unavailable in the offline planner",
            file=sys.stderr,
        )
        return 1
    parser = _build_argument_parser()
    try:
        options = parser.parse_args(arguments)
        if options.command == "validate-assets":
            paths = BootstrapPaths.for_repository(options.repository)
            load_desired_state(paths)
            print(paths.manifest)
            return 0
        if options.command != "bootstrap":
            raise BootstrapError("requested action is unavailable")
        if options.repository != REPOSITORY_ROOT:
            raise BootstrapError(
                "bootstrap repository must be the exact repository root",
            )
        live_bootstrap_started = True
        token = run_bootstrap(
            options.repository,
            options.migration_python,
            dependencies=production_orchestrator_dependencies(),
        )
        print(token.final_receipt.path)
        return 0
    except BootstrapError as error:
        if live_bootstrap_started:
            print(
                "error: Stalwart bootstrap failed safely",
                file=sys.stderr,
            )
        else:
            print(f"error: {error}", file=sys.stderr)
        return 1
    except Exception:
        print("error: Stalwart bootstrap failed safely", file=sys.stderr)
        return 1
    except BaseException:
        if not live_bootstrap_started:
            raise
        print("error: Stalwart bootstrap failed safely", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
