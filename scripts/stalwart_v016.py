#!/usr/bin/env python3
"""Fail-closed preparation for the Stalwart v0.16.17 migration."""

from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass, fields, is_dataclass
import errno
import fcntl
import hashlib
import hmac
import http.client
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import signal
import smtplib
import stat
import subprocess
from datetime import datetime, timezone
import sys
from types import ModuleType
from typing import Callable, NamedTuple


STALWART_IMAGE = (
    "stalwartlabs/stalwart:v0.16.17@"
    "sha256:a8108e19bd927e172d4d8c128907b8dfc93fd180ae8ee07dccdd42cb97eb9dfa"
)
STALWART_IMAGE_ID = (
    "sha256:"
    "a8108e19bd927e172d4d8c128907b8dfc93fd180ae8ee07dccdd42cb97eb9dfa"
)
BOOTSTRAP_MANAGEMENT_PERMISSIONS = (
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
BOOTSTRAP_SAFE_ID_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,255}")
BOOTSTRAP_IP_RESTRICTION_DECISION = (
    "disabled-local-only-loopback-network-isolation"
)
STALWART_CLI_IMAGE = (
    "stalwartlabs/cli:1.0.12@"
    "sha256:fe199affac1d120a8c200ef39ae629765a2976270e0453575c1caf906ee15b52"
)
MIGRATION_SCRIPT_SHA256 = (
    "008a490b4c3c60572806958e1960749ecdddf263316683017003797b9c34ca1c"
)
NORMAL_RUNTIME_EVIDENCE_SCHEMA = (
    "mail-sandbox.stalwart-v016-normal-runtime-evidence.v2"
)
MIGRATION_COMPOSE_SHA256 = (
    "77540a67777579e8b4a2be9d386122c3f7f7dba911889cbe8100d49a0e4fac62"
)
CONVERTED_CONFIG_BYTES = (
    b'{\n'
    b'  "@type": "RocksDb",\n'
    b'  "path": "/var/lib/stalwart"\n'
    b"}"
)
CONVERTED_CONFIG_SHA256 = (
    "b7aad53c4d32721e61984b0e5509764fc5d6b7405c68fd11f72c8423f04f2fb6"
)
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
MIGRATION_DATA_VARIABLE = "STALWART_MIGRATION_DATA_DIR"
MIGRATION_CONFIG_VARIABLE = "STALWART_MIGRATION_CONFIG_DIR"
MIGRATION_RECOVERY_ENV_VARIABLE = "STALWART_MIGRATION_RECOVERY_ENV_FILE"
MIGRATION_OWNER_SERVICE = "stalwart-migration-data-owner"
RECOVERY_ENV_PREFIX = b"STALWART_RECOVERY_ADMIN="
MIGRATION_BOOTSTRAP_BASE_URL = "http://127.0.0.1:8443"
MIGRATION_BOOTSTRAP_API_URL = "http://127.0.0.1:8443/jmap/"
COMPOSE_PROJECT_PATTERN = re.compile(r"[a-z0-9][a-z0-9_-]*")
COMPOSE_SERVICE_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")
SAFE_COMMAND_PATH = "/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin"
DOCKER_CLIENT_ENVIRONMENT_NAMES = (
    "HOME",
    "DOCKER_HOST",
    "DOCKER_CONTEXT",
    "DOCKER_CONFIG",
    "DOCKER_TLS_VERIFY",
    "DOCKER_CERT_PATH",
    "DOCKER_API_VERSION",
    "XDG_RUNTIME_DIR",
    "SSH_AUTH_SOCK",
)
DOCKER_CLIENT_PATH_NAMES = {
    "HOME",
    "DOCKER_CONFIG",
    "DOCKER_CERT_PATH",
    "XDG_RUNTIME_DIR",
    "SSH_AUTH_SOCK",
}
MAXIMUM_COMMAND_ENVIRONMENT_VALUE = 4096
MAXIMUM_IDENTITY_COMPONENT = (1 << 64) - 1
SECRET_DISPATCH_MODE = "__stalwart-secret-dispatch"
JMAP_AUTH_PROBE_MODE = "__stalwart-jmap-auth-probe"
JMAP_AUTH_PROBE_HOST = "127.0.0.1"
JMAP_AUTH_PROBE_PORT = 8443
JMAP_AUTH_PROBE_PATH = "/.well-known/jmap"
JMAP_AUTH_PROBE_TIMEOUT_SECONDS = 5
JMAP_AUTH_PROBE_MAXIMUM_BODY = 256 * 1024
JMAP_AUTH_PROBE_MAXIMUM_OUTPUT = 4096
JMAP_CORE_CAPABILITY = "urn:ietf:params:jmap:core"
JMAP_STALWART_CAPABILITY = "urn:stalwart:jmap"
STALWART_OPERATION_LOCK_NAMESPACE_NAME = ".mail-sandbox-stalwart-locks"
STALWART_OPERATION_GLOBAL_GUARD_PATH = Path("/")
MIGRATION_CONTAINER_INSPECT_FORMAT = (
    '{"Id":{{json .Id}}'
    ',"Image":{{json .Config.Image}}'
    ',"ImageID":{{json .Image}}'
    ',"User":{{json .Config.User}}'
    ',"Project":{{json (index .Config.Labels "com.docker.compose.project")}}'
    ',"Service":{{json (index .Config.Labels "com.docker.compose.service")}}'
    ',"WorkingDir":{{json (index .Config.Labels "com.docker.compose.project.working_dir")}}'
    ',"ConfigFiles":{{json (index .Config.Labels "com.docker.compose.project.config_files")}}'
    ',"Oneoff":{{json (index .Config.Labels "com.docker.compose.oneoff")}}'
    ',"Mounts":{{json .Mounts}}'
    ',"Ports":{{json .NetworkSettings.Ports}}'
    ',"Running":{{json .State.Running}}'
    ',"Health":{{json .State.Health.Status}}}'
)
MIGRATION_RECOVERY_CONTAINER_INSPECT_FORMAT = (
    '{"Id":{{json .Id}}'
    ',"Image":{{json .Config.Image}}'
    ',"ImageID":{{json .Image}}'
    ',"User":{{json .Config.User}}'
    ',"Project":{{json (index .Config.Labels "com.docker.compose.project")}}'
    ',"Service":{{json (index .Config.Labels "com.docker.compose.service")}}'
    ',"WorkingDir":{{json (index .Config.Labels "com.docker.compose.project.working_dir")}}'
    ',"ConfigFiles":{{json (index .Config.Labels "com.docker.compose.project.config_files")}}'
    ',"Oneoff":{{json (index .Config.Labels "com.docker.compose.oneoff")}}'
    ',"Mounts":{{json .Mounts}}'
    ',"Ports":{{json .NetworkSettings.Ports}}'
    ',"Running":{{json .State.Running}}'
    ',"Restarting":{{json .State.Restarting}}'
    ',"Health":{{if .State.Health}}{{json .State.Health.Status}}{{else}}""{{end}}'
    ',"Entrypoint":{{json .Config.Entrypoint}}'
    ',"Cmd":{{json .Config.Cmd}}'
    ',"Restart":{{json .HostConfig.RestartPolicy.Name}}}'
)
NORMAL_RUNTIME_TRANSPORT_BASE_URL = "http://127.0.0.1:8443"
NORMAL_RUNTIME_TRANSPORT_API_URL = "http://127.0.0.1:8443/jmap/"
# Receipt metadata continues to describe only the fixed host-side transport;
# the DHCP-sensitive advertised URL is validated live and never serialized.
NORMAL_RUNTIME_BASE_URL = NORMAL_RUNTIME_TRANSPORT_BASE_URL
NORMAL_RUNTIME_API_URL = NORMAL_RUNTIME_TRANSPORT_API_URL
DASHBOARD_MANAGEMENT_USERNAME = "dashboard-management@local.test"
DASHBOARD_MANAGEMENT_PASSWORD = "secret"
NORMAL_RUNTIME_SMTP_HOST = "127.0.0.1"
NORMAL_RUNTIME_SMTP_PORT = 8587
NORMAL_RUNTIME_ENVIRONMENT = frozenset(
    {
        (
            "PATH=/usr/local/sbin:/usr/local/bin:"
            "/usr/sbin:/usr/bin:/sbin:/bin"
        ),
        (
            "STALWART_HEALTHCHECK_URL="
            "https://127.0.0.1:443/healthz/live"
        ),
    },
)
_NETWORK_MODULE_NAME = "_mail_sandbox_stalwart_network_v016"
_NETWORK_MODULE: object | None = None
NORMAL_CONTAINER_INSPECT_FORMAT = (
    '{"Id":{{json .Id}}'
    ',"Image":{{json .Config.Image}}'
    ',"ImageID":{{json .Image}}'
    ',"User":{{json .Config.User}}'
    ',"Project":{{json (index .Config.Labels "com.docker.compose.project")}}'
    ',"Service":{{json (index .Config.Labels "com.docker.compose.service")}}'
    ',"WorkingDir":{{json (index .Config.Labels "com.docker.compose.project.working_dir")}}'
    ',"ConfigFiles":{{json (index .Config.Labels "com.docker.compose.project.config_files")}}'
    ',"Oneoff":{{json (index .Config.Labels "com.docker.compose.oneoff")}}'
    ',"Mounts":{{json .Mounts}}'
    ',"Ports":{{json .NetworkSettings.Ports}}'
    ',"Running":{{json .State.Running}}'
    ',"Health":{{json .State.Health.Status}}'
    ',"Environment":{{json .Config.Env}}}'
)
NORMAL_RECOVERY_CONTAINER_INSPECT_FORMAT = (
    '{"Id":{{json .Id}}'
    ',"Image":{{json .Config.Image}}'
    ',"ImageID":{{json .Image}}'
    ',"User":{{json .Config.User}}'
    ',"Project":{{json (index .Config.Labels "com.docker.compose.project")}}'
    ',"Service":{{json (index .Config.Labels "com.docker.compose.service")}}'
    ',"WorkingDir":{{json (index .Config.Labels "com.docker.compose.project.working_dir")}}'
    ',"ConfigFiles":{{json (index .Config.Labels "com.docker.compose.project.config_files")}}'
    ',"Oneoff":{{json (index .Config.Labels "com.docker.compose.oneoff")}}'
    ',"Mounts":{{json .Mounts}}'
    ',"Ports":{{json .NetworkSettings.Ports}}'
    ',"Running":{{json .State.Running}}'
    ',"Restarting":{{json .State.Restarting}}'
    ',"Health":{{if .State.Health}}{{json .State.Health.Status}}{{else}}""{{end}}'
    ',"Environment":{{json .Config.Env}}'
    ',"Restart":{{json .HostConfig.RestartPolicy.Name}}}'
)


class MigrationError(RuntimeError):
    """A migration safety invariant was not satisfied."""


class CommandError(MigrationError):
    """An external list-form command failed without exposing its arguments."""


class CommandResult(NamedTuple):
    stdout: str
    stderr: str


class RedactedCommandResult(NamedTuple):
    stdout: bytes
    stderr: bytes


class NormalRuntimeInspection(NamedTuple):
    container_id: str
    image_reference: str
    image_id: str
    recovery_environment_names: tuple[str, ...]


@dataclass(frozen=True, repr=False)
class JmapAuthProbe:
    status: int
    account_id: str | None
    username: str | None

    def __repr__(self) -> str:
        return "JmapAuthProbe(<redacted>)"


@dataclass(frozen=True)
class FileSnapshot:
    path: Path
    content: bytes
    sha256: str
    size: int
    identity: tuple[int, int, int, int, int, int]


def run_command(args: list[str]) -> CommandResult:
    if not isinstance(args, list) or not all(isinstance(value, str) for value in args):
        raise MigrationError("external commands require list-form string arguments")
    try:
        completed = subprocess.run(
            args,
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
            umask=0o077,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise CommandError("external command failed safely") from None
    if completed.returncode != 0:
        raise CommandError("external command failed safely")
    if not isinstance(completed.stdout, str) or not isinstance(completed.stderr, str):
        raise CommandError("external command returned malformed output")
    return CommandResult(completed.stdout, completed.stderr)


def run_redacted_command(
    args: list[str],
    *,
    stdin: bytes,
    env: dict[str, str],
    timeout: int | float,
    cwd: Path,
    secret_values: tuple[str, ...] = (),
) -> RedactedCommandResult:
    """Run one binary subprocess without inheriting or reporting its secrets."""
    allowed_stalwart_names = {
        MIGRATION_DATA_VARIABLE,
        MIGRATION_CONFIG_VARIABLE,
        MIGRATION_RECOVERY_ENV_VARIABLE,
        "STALWART_URL",
        "STALWART_USER",
        "STALWART_PASSWORD",
    }
    valid = (
        isinstance(args, list)
        and bool(args)
        and all(type(value) is str and value and "\x00" not in value for value in args)
        and type(stdin) is bytes
        and type(env) is dict
        and all(
            type(name) is str
            and bool(name)
            and "=" not in name
            and "\x00" not in name
            and type(value) is str
            and "\x00" not in value
            for name, value in env.items()
        )
        and not any(
            name.startswith("STALWART_") and name not in allowed_stalwart_names
            for name in env
        )
        and type(timeout) in {int, float}
        and 0 < timeout <= 300
        and isinstance(cwd, Path)
        and type(secret_values) is tuple
        and all(type(value) is str and bool(value) for value in secret_values)
    )
    if not valid:
        raise CommandError("redacted external command is malformed")
    effective_secret_values = (
        *secret_values,
        *(
            value
            for name, value in env.items()
            if name in {"STALWART_USER", "STALWART_PASSWORD"} and value
        ),
    )
    if any(
        secret in argument
        for secret in effective_secret_values
        for argument in args
    ):
        raise CommandError("redacted external command is malformed")
    try:
        normalized_cwd = _plain_absolute(cwd, "external command working directory")
        _require_absolute_no_symlinks(
            normalized_cwd,
            "external command working directory",
        )
        _require_real_directory(
            normalized_cwd,
            "external command working directory",
        )
    except MigrationError:
        raise CommandError("redacted external command is malformed") from None
    failed = False
    completed: subprocess.CompletedProcess[bytes] | None = None
    try:
        completed = subprocess.run(
            args,
            check=False,
            capture_output=True,
            input=stdin,
            text=False,
            timeout=timeout,
            cwd=normalized_cwd,
            env=dict(env),
            umask=0o077,
        )
    except (OSError, subprocess.TimeoutExpired):
        failed = True
    if failed or completed is None or completed.returncode != 0:
        raise CommandError("redacted external command failed safely")
    if type(completed.stdout) is not bytes or type(completed.stderr) is not bytes:
        raise CommandError("redacted external command returned malformed output")
    return RedactedCommandResult(completed.stdout, completed.stderr)


def _write_all_to_descriptor(
    descriptor: int,
    value: bytes | bytearray | memoryview,
) -> None:
    view = value if isinstance(value, memoryview) else memoryview(value)
    owns_view = not isinstance(value, memoryview)
    try:
        offset = 0
        while offset < len(view):
            written = os.write(descriptor, view[offset:])
            if written <= 0:
                raise OSError("pipe write did not progress")
            offset += written
    finally:
        if owns_view:
            view.release()


def _close_secret_dispatch_streams(
    process: subprocess.Popen[bytes],
) -> BaseException | None:
    """Close and detach every child pipe, returning only the first error."""
    cleanup_error: BaseException | None = None
    for name in ("stdin", "stdout", "stderr"):
        stream: object | None = None
        try:
            stream = getattr(process, name, None)
        except BaseException as exc:
            if cleanup_error is None:
                cleanup_error = exc
        if stream is not None:
            try:
                close = getattr(stream, "close", None)
                if not callable(close):
                    raise OSError("secret dispatch pipe is malformed")
                close()
            except BaseException as exc:
                if cleanup_error is None:
                    cleanup_error = exc
        try:
            setattr(process, name, None)
        except BaseException as exc:
            if cleanup_error is None:
                cleanup_error = exc
    return cleanup_error


def _terminate_secret_dispatch(
    process: subprocess.Popen[bytes],
) -> BaseException | None:
    cleanup_error: BaseException | None = None
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except BaseException as exc:
        if not isinstance(exc, OSError):
            cleanup_error = exc
        try:
            process.kill()
        except BaseException as fallback_exc:
            if (
                cleanup_error is None
                and not isinstance(fallback_exc, OSError)
            ):
                cleanup_error = fallback_exc
    stream_error = _close_secret_dispatch_streams(process)
    if cleanup_error is None:
        cleanup_error = stream_error
    try:
        process.wait(timeout=5)
    except BaseException as exc:
        if (
            cleanup_error is None
            and not isinstance(exc, (OSError, subprocess.TimeoutExpired))
        ):
            cleanup_error = exc
    return cleanup_error


def _raise_secret_dispatch_cleanup_error(
    cleanup_error: BaseException | None,
    message: str,
) -> None:
    if cleanup_error is None:
        return
    if not isinstance(cleanup_error, Exception):
        raise cleanup_error
    raise CommandError(message) from None


def run_redacted_secret_command(
    args: list[str],
    *,
    stdin: bytes,
    env: dict[str, str],
    credential: memoryview,
    timeout: int | float,
    cwd: Path,
) -> RedactedCommandResult:
    """Dispatch one credentialed command through a short-lived child helper."""
    valid = (
        isinstance(args, list)
        and bool(args)
        and all(
            type(value) is str and value and "\x00" not in value
            for value in args
        )
        and type(stdin) is bytes
        and type(env) is dict
        and env.get("PATH") == SAFE_COMMAND_PATH
        and set(name for name in env if name.startswith("STALWART_"))
        == {"STALWART_URL"}
        and all(
            type(name) is str
            and bool(name)
            and "=" not in name
            and "\x00" not in name
            and type(value) is str
            and "\x00" not in value
            and "\r" not in value
            and "\n" not in value
            for name, value in env.items()
        )
        and _valid_recovery_credential_view(credential)
        and type(timeout) in {int, float}
        and 0 < timeout <= 300
        and isinstance(cwd, Path)
    )
    if not valid:
        raise CommandError("redacted secret command is malformed")
    try:
        normalized_cwd = _plain_absolute(
            cwd,
            "secret command working directory",
        )
        _require_absolute_no_symlinks(
            normalized_cwd,
            "secret command working directory",
        )
        _require_real_directory(
            normalized_cwd,
            "secret command working directory",
        )
    except MigrationError:
        raise CommandError("redacted secret command is malformed") from None
    metadata = json.dumps(
        {
            "args": args,
            "credential_size": len(credential),
            "cwd": str(normalized_cwd),
            "env": env,
            "stdin_size": len(stdin),
            "timeout": timeout,
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    process: subprocess.Popen[bytes] | None = None
    try:
        process = subprocess.Popen(
            [
                sys.executable,
                str(Path(__file__).resolve()),
                SECRET_DISPATCH_MODE,
                metadata,
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=normalized_cwd,
            env={"PATH": SAFE_COMMAND_PATH},
            text=False,
            umask=0o077,
            start_new_session=True,
        )
        if process.stdin is None:
            raise OSError("secret dispatch stdin is unavailable")
        input_descriptor = process.stdin.fileno()
        _write_all_to_descriptor(input_descriptor, credential)
        _write_all_to_descriptor(input_descriptor, stdin)
        process.stdin.close()
        process.stdin = None
        stdout, stderr = process.communicate(timeout=float(timeout) + 5)
    except (OSError, subprocess.SubprocessError):
        cleanup_error = None
        if process is not None:
            cleanup_error = _terminate_secret_dispatch(process)
        if cleanup_error is not None and not isinstance(
            cleanup_error,
            Exception,
        ):
            raise cleanup_error
        raise CommandError("redacted secret command failed safely") from None
    except BaseException:
        if process is not None:
            _terminate_secret_dispatch(process)
        raise
    cleanup_error = _close_secret_dispatch_streams(process)
    _raise_secret_dispatch_cleanup_error(
        cleanup_error,
        "redacted secret command failed safely",
    )
    if (
        process.returncode != 0
        or type(stdout) is not bytes
        or type(stderr) is not bytes
        or stderr
        or len(stdout) > 32 * 1024 * 1024
    ):
        raise CommandError("redacted secret command failed safely")
    header, separator, payload = stdout.partition(b"\n")
    lengths = header.split(b":")
    if (
        not separator
        or len(lengths) != 2
        or any(re.fullmatch(rb"[0-9]{1,9}", item) is None for item in lengths)
    ):
        raise CommandError("redacted secret command returned malformed output")
    stdout_size, stderr_size = (int(item) for item in lengths)
    if len(payload) != stdout_size + stderr_size:
        raise CommandError("redacted secret command returned malformed output")
    return RedactedCommandResult(
        payload[:stdout_size],
        payload[stdout_size:],
    )


def _plain_absolute(path: Path, label: str) -> Path:
    if not path.is_absolute() or Path(os.path.normpath(str(path))) != path:
        raise MigrationError(f"{label} must be a normalized absolute path")
    return path


def _require_below(root: Path, path: Path, label: str) -> None:
    root = _plain_absolute(root, "trusted root")
    path = _plain_absolute(path, label)
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise MigrationError(f"{label} is outside the trusted root") from exc
    if relative == Path("."):
        raise MigrationError(f"{label} is too broad")


def _require_real_directory(path: Path, label: str) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise MigrationError(f"{label} is unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise MigrationError(f"{label} must not be a symlink")
    if not stat.S_ISDIR(metadata.st_mode):
        raise MigrationError(f"{label} must be a directory")
    return metadata


def _require_no_symlink_components(root: Path, path: Path, label: str) -> None:
    _require_below(root, path, label)
    _require_real_directory(root, "trusted root")
    current = root
    for component in path.relative_to(root).parts:
        current = current / component
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            return
        except OSError as exc:
            raise MigrationError(f"{label} could not be inspected safely") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise MigrationError(f"{label} must not contain symlinks")


def _open_regular_readonly(path: Path, *, root: Path, label: str) -> tuple[int, os.stat_result]:
    _require_no_symlink_components(root, path, label)
    try:
        before = path.lstat()
    except OSError as exc:
        raise MigrationError(f"{label} is unavailable") from exc
    if stat.S_ISLNK(before.st_mode):
        raise MigrationError(f"{label} must not be a symlink")
    if not stat.S_ISREG(before.st_mode):
        raise MigrationError(f"{label} must be a regular file")
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError as exc:
        raise MigrationError(f"{label} changed before it could be opened safely") from exc
    opened = os.fstat(descriptor)
    if (
        not stat.S_ISREG(opened.st_mode)
        or opened.st_dev != before.st_dev
        or opened.st_ino != before.st_ino
    ):
        os.close(descriptor)
        raise MigrationError(f"{label} changed before it could be opened safely")
    return descriptor, opened


def _file_identity(
    metadata: os.stat_result,
) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _open_bound_directory(
    path: Path,
    *,
    root: Path,
    label: str,
) -> tuple[int, tuple[int, int]]:
    """Open one directory and retain its stable filesystem-object identity."""
    _require_no_symlink_components(root, path, label)
    before = _require_real_directory(path, label)
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or opened.st_dev != before.st_dev
            or opened.st_ino != before.st_ino
        ):
            raise MigrationError(f"{label} changed before it could be bound")
        return descriptor, (opened.st_dev, opened.st_ino)
    except OSError as exc:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise MigrationError(f"{label} could not be bound safely") from exc
    except BaseException:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise


def _require_bound_directory(
    descriptor: int,
    identity: tuple[int, int],
    path: Path,
    *,
    root: Path,
    label: str,
) -> None:
    if (
        type(descriptor) is not int
        or descriptor < 0
        or not isinstance(identity, tuple)
        or len(identity) != 2
        or any(type(value) is not int or value < 0 for value in identity)
    ):
        raise MigrationError(f"{label} binding is malformed")
    try:
        opened = os.fstat(descriptor)
    except OSError as exc:
        raise MigrationError(f"{label} binding is unavailable") from exc
    _require_no_symlink_components(root, path, label)
    current = _require_real_directory(path, label)
    if (
        not stat.S_ISDIR(opened.st_mode)
        or (opened.st_dev, opened.st_ino) != identity
        or (current.st_dev, current.st_ino) != identity
    ):
        raise MigrationError(f"{label} directory changed during runtime")


def _read_regular_snapshot(
    path: Path,
    *,
    root: Path,
    label: str,
    maximum: int,
    required_mode: int | None = None,
) -> FileSnapshot:
    descriptor, before = _open_regular_readonly(path, root=root, label=label)
    if required_mode is not None and stat.S_IMODE(before.st_mode) != required_mode:
        os.close(descriptor)
        raise MigrationError(f"{label} must have mode {required_mode:04o}")
    chunks: list[bytes] = []
    digest = hashlib.sha256()
    total = 0
    try:
        while chunk := os.read(descriptor, min(1024 * 1024, maximum + 1 - total)):
            total += len(chunk)
            if total > maximum:
                raise MigrationError(f"{label} is too large")
            chunks.append(chunk)
            digest.update(chunk)
        after = os.fstat(descriptor)
    except OSError as exc:
        raise MigrationError(f"{label} could not be read safely") from exc
    finally:
        os.close(descriptor)
    if _file_identity(after) != _file_identity(before):
        raise MigrationError(f"{label} changed while it was read")
    return FileSnapshot(
        path=path,
        content=b"".join(chunks),
        sha256=digest.hexdigest(),
        size=total,
        identity=_file_identity(after),
    )


def _wipe_bytearray(value: bytearray) -> None:
    for index in range(len(value)):
        value[index] = 0


def _is_ascii_alphanumeric(value: int) -> bool:
    return (
        0x30 <= value <= 0x39
        or 0x41 <= value <= 0x5A
        or 0x61 <= value <= 0x7A
    )


def _valid_recovery_credential_slice(
    value: bytearray,
    *,
    start: int,
    end: int,
) -> bool:
    if (
        type(value) is not bytearray
        or type(start) is not int
        or type(end) is not int
        or start < 0
        or end > len(value)
        or start >= end
    ):
        return False
    separator = value.find(b":", start, end)
    if separator <= start or separator >= end - 1:
        return False
    for index in range(start, separator):
        item = value[index]
        if not _is_ascii_alphanumeric(item) and item not in b"-_.@":
            return False
    for index in range(separator + 1, end):
        item = value[index]
        if not _is_ascii_alphanumeric(item) and item not in b"-_":
            return False
    return True


def _valid_recovery_credential_view(value: object) -> bool:
    if (
        type(value) is not memoryview
        or not value.readonly
        or type(value.obj) is not bytearray
        or value.ndim != 1
        or value.itemsize != 1
        or value.format not in {"B", "b", "c"}
        or not value.c_contiguous
        or len(value) < 3
    ):
        return False
    separator = -1
    for index, item in enumerate(value):
        current = item if type(item) is int else ord(item)
        if current == 0x3A:
            if separator >= 0:
                return False
            separator = index
            continue
        allowed = (
            _is_ascii_alphanumeric(current)
            or current in b"-_"
            or (separator < 0 and current in b".@")
        )
        if not allowed:
            return False
    return 0 < separator < len(value) - 1


def _read_pipe_mutable(descriptor: int, size: int) -> bytearray:
    if type(size) is not int or size < 0 or size > 16 * 1024 * 1024:
        raise MigrationError("secret dispatch input is malformed")
    result = bytearray(size)
    view = memoryview(result)
    try:
        offset = 0
        while offset < size:
            current = view[offset:]
            try:
                read = os.readv(descriptor, [current])
            finally:
                current.release()
            if read <= 0:
                raise MigrationError("secret dispatch input is truncated")
            offset += read
        return result
    except BaseException:
        _wipe_bytearray(result)
        raise
    finally:
        view.release()


def _secret_dispatch_child(metadata_text: str) -> int:
    """Child-only conversion of a mutable credential into an OS environment."""
    credential = bytearray()
    command_input = bytearray()
    credential_view: memoryview | None = None
    try:
        metadata = json.loads(
            metadata_text,
            object_pairs_hook=_strict_json_object,
        )
        if (
            not isinstance(metadata, dict)
            or set(metadata)
            != {
                "args",
                "credential_size",
                "cwd",
                "env",
                "stdin_size",
                "timeout",
            }
        ):
            return 1
        args = metadata.get("args")
        environment = metadata.get("env")
        cwd_value = metadata.get("cwd")
        timeout = metadata.get("timeout")
        if (
            not isinstance(args, list)
            or not args
            or any(type(item) is not str or not item for item in args)
            or not isinstance(environment, dict)
            or set(
                name
                for name in environment
                if isinstance(name, str) and name.startswith("STALWART_")
            )
            != {"STALWART_URL"}
            or any(
                type(name) is not str
                or type(value) is not str
                or "\x00" in name
                or "\x00" in value
                for name, value in environment.items()
            )
            or type(cwd_value) is not str
            or type(timeout) not in {int, float}
            or not 0 < timeout <= 300
        ):
            return 1
        credential = _read_pipe_mutable(
            sys.stdin.fileno(),
            metadata.get("credential_size"),  # type: ignore[arg-type]
        )
        command_input = _read_pipe_mutable(
            sys.stdin.fileno(),
            metadata.get("stdin_size"),  # type: ignore[arg-type]
        )
        trailing = bytearray(1)
        trailing_view = memoryview(trailing)
        try:
            if os.readv(sys.stdin.fileno(), [trailing_view]) != 0:
                return 1
        finally:
            trailing_view.release()
            _wipe_bytearray(trailing)
        credential_view = memoryview(credential).toreadonly()
        if not _valid_recovery_credential_view(credential_view):
            return 1
        separator = credential.find(b":")
        username = credential_view[:separator].tobytes().decode("ascii")
        password = credential_view[separator + 1 :].tobytes().decode("ascii")
        target_environment = {
            **environment,
            "STALWART_USER": username,
            "STALWART_PASSWORD": password,
        }
        completed = subprocess.run(
            args,
            check=False,
            capture_output=True,
            input=command_input,
            text=False,
            timeout=timeout,
            cwd=cwd_value,
            env=target_environment,
            umask=0o077,
        )
        if (
            completed.returncode != 0
            or type(completed.stdout) is not bytes
            or type(completed.stderr) is not bytes
            or len(completed.stdout) + len(completed.stderr)
            > 32 * 1024 * 1024
        ):
            return 1
        header = (
            f"{len(completed.stdout)}:{len(completed.stderr)}\n"
        ).encode("ascii")
        _write_all_to_descriptor(sys.stdout.fileno(), header)
        _write_all_to_descriptor(sys.stdout.fileno(), completed.stdout)
        _write_all_to_descriptor(sys.stdout.fileno(), completed.stderr)
        return 0
    except (Exception, KeyboardInterrupt, SystemExit):
        return 1
    finally:
        if credential_view is not None:
            credential_view.release()
        _wipe_bytearray(credential)
        _wipe_bytearray(command_input)


def _valid_jmap_probe_credential_view(
    value: object,
    *,
    scheme: str,
) -> bool:
    if (
        scheme not in {"bearer", "basic"}
        or type(value) is not memoryview
        or not value.readonly
        or type(value.obj) is not bytearray
        or value.ndim != 1
        or value.itemsize != 1
        or value.format not in {"B", "b", "c"}
        or not value.c_contiguous
        or not 3 <= len(value) <= 4096
    ):
        return False
    if scheme == "basic":
        return _valid_recovery_credential_view(value)
    for item in value:
        current = item if type(item) is int else ord(item)
        if current < 0x21 or current > 0x7E:
            return False
    return True


def _normal_runtime_public_url(repository: Path) -> str:
    """Read the current LAN URL through the strict generated-state loader."""
    global _NETWORK_MODULE
    if _NETWORK_MODULE is None:
        path = Path(__file__).resolve().with_name("stalwart_network.py")
        try:
            specification = importlib.util.spec_from_file_location(
                _NETWORK_MODULE_NAME,
                path,
            )
            if specification is None or specification.loader is None:
                raise ImportError("network loader is unavailable")
            module = importlib.util.module_from_spec(specification)
            sys.modules[_NETWORK_MODULE_NAME] = module
            try:
                specification.loader.exec_module(module)
            except BaseException:
                sys.modules.pop(_NETWORK_MODULE_NAME, None)
                raise
            _NETWORK_MODULE = module
        except (OSError, ImportError):
            raise MigrationError(
                "normal runtime network configuration is unavailable",
            ) from None
    load = getattr(_NETWORK_MODULE, "load_network_configuration", None)
    network_error = getattr(
        _NETWORK_MODULE,
        "NetworkConfigurationError",
        None,
    )
    if not callable(load) or not isinstance(network_error, type):
        raise MigrationError(
            "normal runtime network configuration is unavailable",
        )
    try:
        configuration = load(repository)
    except (network_error, ValueError, OSError):
        raise MigrationError(
            "normal runtime network configuration is invalid",
        ) from None
    public_url = getattr(configuration, "public_url", None)
    environment_path = getattr(configuration, "environment_path", None)
    expected_path = (
        repository
        / "debug-dashboard"
        / ".runtime"
        / "stalwart"
        / "network.env"
    )
    if type(public_url) is not str or environment_path != expected_path:
        raise MigrationError(
            "normal runtime network configuration is invalid",
        )
    return public_url


def _normal_runtime_environment(public_url: str) -> frozenset[str]:
    if (
        type(public_url) is not str
        or re.fullmatch(r"http://[A-Za-z0-9.-]+:8443", public_url) is None
        or public_url.startswith("http://127.")
        or public_url in {
            "http://0.0.0.0:8443",
            "http://localhost:8443",
        }
    ):
        raise MigrationError("normal runtime public URL is malformed")
    return frozenset(
        {
            *NORMAL_RUNTIME_ENVIRONMENT,
            f"STALWART_PUBLIC_URL={public_url}",
        },
    )


def _normal_runtime_expected_api_url(
    plan: RecoveryRetirementPlan,
) -> str:
    source = _normal_runtime_plan_context(plan)
    return f"{_normal_runtime_public_url(source.checkout_root)}/jmap/"


def _fixed_jmap_auth_exchange(
    credential: bytearray,
    *,
    scheme: str,
    expected_api_url: str = NORMAL_RUNTIME_TRANSPORT_API_URL,
    connection_factory: object = http.client.HTTPConnection,
) -> dict[str, object]:
    """Child-only fixed JMAP exchange returning sanitized session metadata."""
    if (
        type(credential) is not bytearray
        or not callable(connection_factory)
        or scheme not in {"bearer", "basic"}
        or type(expected_api_url) is not str
        or re.fullmatch(
            r"http://[A-Za-z0-9.-]+:8443/jmap/",
            expected_api_url,
        )
        is None
    ):
        raise MigrationError("fixed JMAP authentication probe is malformed")
    view = memoryview(credential).toreadonly()
    authorization_buffer = bytearray()
    encoded = bytearray()
    connection: object | None = None
    response: object | None = None
    primary_error = False
    try:
        if not _valid_jmap_probe_credential_view(view, scheme=scheme):
            raise MigrationError(
                "fixed JMAP authentication credential is malformed",
            )
        if scheme == "bearer":
            authorization_buffer.extend(b"Bearer ")
            authorization_buffer.extend(view)
        else:
            encoded.extend(base64.b64encode(view))
            authorization_buffer.extend(b"Basic ")
            authorization_buffer.extend(encoded)
        authorization = authorization_buffer.decode("ascii")
        connection = connection_factory(
            JMAP_AUTH_PROBE_HOST,
            JMAP_AUTH_PROBE_PORT,
            timeout=JMAP_AUTH_PROBE_TIMEOUT_SECONDS,
        )
        request = getattr(connection, "request", None)
        getresponse = getattr(connection, "getresponse", None)
        if not callable(request) or not callable(getresponse):
            raise MigrationError(
                "fixed JMAP authentication transport is malformed",
            )
        request(
            "GET",
            JMAP_AUTH_PROBE_PATH,
            body=None,
            headers={
                "Accept": "application/json",
                "Authorization": authorization,
            },
        )
        response = getresponse()
        status = getattr(response, "status", None)
        getheaders = getattr(response, "getheaders", None)
        read = getattr(response, "read", None)
        if (
            type(status) is not int
            or isinstance(status, bool)
            or not 100 <= status <= 599
            or not callable(getheaders)
            or not callable(read)
        ):
            raise MigrationError(
                "fixed JMAP authentication response is malformed",
            )
        headers = getheaders()
        if (
            type(headers) is not list
            or any(
                type(item) is not tuple
                or len(item) != 2
                or type(item[0]) is not str
                or type(item[1]) is not str
                for item in headers
            )
        ):
            raise MigrationError(
                "fixed JMAP authentication response is malformed",
            )
        content_types = [
            item[1]
            for item in headers
            if item[0].lower() == "content-type"
        ]
        lengths = [
            item[1].strip()
            for item in headers
            if item[0].lower() == "content-length"
        ]
        transfer_encodings = [
            item[1]
            for item in headers
            if item[0].lower() == "transfer-encoding"
        ]
        if (
            len(content_types) > 1
            or len(lengths) > 1
            or bool(transfer_encodings)
            or any(
                not value.isascii() or not value.isdigit()
                for value in lengths
            )
        ):
            raise MigrationError(
                "fixed JMAP authentication response is malformed",
            )
        declared_length = int(lengths[0], 10) if lengths else None
        if (
            declared_length is not None
            and declared_length > JMAP_AUTH_PROBE_MAXIMUM_BODY
        ):
            raise MigrationError(
                "fixed JMAP authentication response is too large",
            )
        if scheme == "basic" and status not in {401, 403}:
            raise MigrationError(
                "fixed JMAP authentication response is malformed",
            )
        raw = read(JMAP_AUTH_PROBE_MAXIMUM_BODY + 1)
        if (
            type(raw) is not bytes
            or len(raw) > JMAP_AUTH_PROBE_MAXIMUM_BODY
            or (
                declared_length is not None
                and len(raw) != declared_length
            )
        ):
            raise MigrationError(
                "fixed JMAP authentication response is malformed",
            )
        if scheme == "basic":
            return {
                "account_id": None,
                "status": status,
                "username": None,
            }
        if status != 200 or len(content_types) != 1 or declared_length is None:
            raise MigrationError(
                "fixed JMAP authentication response is malformed",
            )
        content_type_parts = [
            part.strip().lower()
            for part in content_types[0].split(";")
        ]
        if (
            not content_type_parts
            or content_type_parts[0] != "application/json"
            or len(content_type_parts) > 2
            or any(
                part != "charset=utf-8"
                for part in content_type_parts[1:]
            )
        ):
            raise MigrationError(
                "fixed JMAP authentication response is malformed",
            )
        try:
            payload = json.loads(
                raw.decode("utf-8", "strict"),
                object_pairs_hook=_strict_json_object,
                parse_float=lambda _value: (_ for _ in ()).throw(
                    ValueError("float"),
                ),
                parse_constant=lambda _value: (_ for _ in ()).throw(
                    ValueError("constant"),
                ),
            )
        except (UnicodeError, json.JSONDecodeError, ValueError):
            raise MigrationError(
                "fixed JMAP authentication response is malformed",
            ) from None
        if type(payload) is not dict:
            raise MigrationError(
                "fixed JMAP authentication response is malformed",
            )
        username = payload.get("username")
        api_url = payload.get("apiUrl")
        capabilities = payload.get("capabilities")
        primary_accounts = payload.get("primaryAccounts")
        accounts = payload.get("accounts")
        account_id = (
            primary_accounts.get(JMAP_STALWART_CAPABILITY)
            if type(primary_accounts) is dict
            else None
        )
        account = (
            accounts.get(account_id)
            if type(accounts) is dict and type(account_id) is str
            else None
        )
        account_capabilities = (
            account.get("accountCapabilities")
            if type(account) is dict
            else None
        )
        if (
            type(username) is not str
            or not 1 <= len(username) <= 255
            or any(ord(item) < 0x21 or ord(item) > 0x7E for item in username)
            or api_url != expected_api_url
            or type(capabilities) is not dict
            or type(capabilities.get(JMAP_CORE_CAPABILITY)) is not dict
            or type(capabilities.get(JMAP_STALWART_CAPABILITY)) is not dict
            or type(account_id) is not str
            or BOOTSTRAP_SAFE_ID_PATTERN.fullmatch(account_id) is None
            or type(account) is not dict
            or account.get("name") != username
            or type(account_capabilities) is not dict
            or type(
                account_capabilities.get(JMAP_STALWART_CAPABILITY),
            )
            is not dict
        ):
            raise MigrationError(
                "fixed JMAP authentication response is malformed",
            )
        return {
            "account_id": account_id,
            "status": 200,
            "username": username,
        }
    except BaseException:
        primary_error = True
        raise
    finally:
        view.release()
        _wipe_bytearray(encoded)
        _wipe_bytearray(authorization_buffer)
        cleanup_error: BaseException | None = None
        for resource in (response, connection):
            close = getattr(resource, "close", None)
            if not callable(close):
                continue
            try:
                close()
            except BaseException as exc:
                if cleanup_error is None:
                    cleanup_error = exc
        if not primary_error and cleanup_error is not None:
            if isinstance(cleanup_error, Exception):
                raise MigrationError(
                    "fixed JMAP authentication cleanup failed safely",
                ) from None
            raise cleanup_error


def _validated_jmap_auth_probe_output(
    stdout: bytes,
    *,
    scheme: str,
    authenticated: bool | None = None,
) -> JmapAuthProbe:
    if authenticated is None:
        authenticated = scheme == "bearer"
    if (
        scheme not in {"bearer", "basic"}
        or type(authenticated) is not bool
        or type(stdout) is not bytes
        or not stdout
        or len(stdout) > JMAP_AUTH_PROBE_MAXIMUM_OUTPUT
    ):
        raise MigrationError(
            "fixed JMAP authentication probe output is malformed",
        )
    try:
        value = json.loads(
            stdout.decode("utf-8", "strict"),
            object_pairs_hook=_strict_json_object,
            parse_float=lambda _value: (_ for _ in ()).throw(
                ValueError("float"),
            ),
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("constant"),
            ),
        )
    except (UnicodeError, json.JSONDecodeError, ValueError):
        raise MigrationError(
            "fixed JMAP authentication probe output is malformed",
        ) from None
    if (
        type(value) is not dict
        or set(value) != {"account_id", "status", "username"}
        or type(value.get("status")) is not int
        or isinstance(value.get("status"), bool)
    ):
        raise MigrationError(
            "fixed JMAP authentication probe output is malformed",
        )
    status = value["status"]
    account_id = value["account_id"]
    username = value["username"]
    if authenticated:
        valid = (
            status == 200
            and type(account_id) is str
            and BOOTSTRAP_SAFE_ID_PATTERN.fullmatch(account_id) is not None
            and type(username) is str
            and 1 <= len(username) <= 255
            and all(0x21 <= ord(item) <= 0x7E for item in username)
        )
    else:
        valid = (
            status in {401, 403}
            and account_id is None
            and username is None
        )
    if not valid:
        raise MigrationError(
            "fixed JMAP authentication probe output is malformed",
        )
    return JmapAuthProbe(
        status=status,
        account_id=account_id,
        username=username,
    )


def _fixed_jmap_auth_probe_child(
    scheme: str,
    size_text: str,
    expected_api_url: str,
) -> int:
    credential = bytearray()
    try:
        if (
            scheme not in {"bearer", "basic"}
            or re.fullmatch(r"[1-9][0-9]{0,3}", size_text) is None
        ):
            return 1
        size = int(size_text, 10)
        if size > 4096:
            return 1
        credential = _read_pipe_mutable(sys.stdin.fileno(), size)
        trailing = bytearray(1)
        trailing_view = memoryview(trailing)
        try:
            if os.readv(sys.stdin.fileno(), [trailing_view]) != 0:
                return 1
        finally:
            trailing_view.release()
            _wipe_bytearray(trailing)
        result = _fixed_jmap_auth_exchange(
            credential,
            scheme=scheme,
            expected_api_url=expected_api_url,
        )
        output = json.dumps(
            result,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        if len(output) > JMAP_AUTH_PROBE_MAXIMUM_OUTPUT:
            return 1
        _write_all_to_descriptor(sys.stdout.fileno(), output)
        return 0
    except (Exception, KeyboardInterrupt, SystemExit):
        return 1
    finally:
        _wipe_bytearray(credential)


def _run_fixed_jmap_auth_probe(
    credential: memoryview,
    *,
    scheme: str,
    authenticated: bool,
    expected_api_url: str = NORMAL_RUNTIME_TRANSPORT_API_URL,
) -> JmapAuthProbe:
    """Pipe one mutable credential to the fixed short-lived JMAP child."""
    if (
        not _valid_jmap_probe_credential_view(credential, scheme=scheme)
        or type(expected_api_url) is not str
        or re.fullmatch(
            r"http://[A-Za-z0-9.-]+:8443/jmap/",
            expected_api_url,
        )
        is None
    ):
        raise CommandError("fixed JMAP authentication probe is malformed")
    process: subprocess.Popen[bytes] | None = None
    try:
        process = subprocess.Popen(
            [
                sys.executable,
                str(Path(__file__).resolve()),
                JMAP_AUTH_PROBE_MODE,
                scheme,
                str(len(credential)),
                expected_api_url,
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=Path(__file__).resolve().parents[1],
            env={"PATH": SAFE_COMMAND_PATH},
            text=False,
            umask=0o077,
            start_new_session=True,
        )
        if process.stdin is None:
            raise OSError("fixed JMAP probe stdin is unavailable")
        descriptor = process.stdin.fileno()
        _write_all_to_descriptor(descriptor, credential)
        process.stdin.close()
        process.stdin = None
        stdout, stderr = process.communicate(
            timeout=JMAP_AUTH_PROBE_TIMEOUT_SECONDS + 5,
        )
    except (OSError, subprocess.SubprocessError):
        cleanup_error = None
        if process is not None:
            cleanup_error = _terminate_secret_dispatch(process)
        if cleanup_error is not None and not isinstance(
            cleanup_error,
            Exception,
        ):
            raise cleanup_error
        raise CommandError(
            "fixed JMAP authentication probe failed safely",
        ) from None
    except BaseException:
        if process is not None:
            _terminate_secret_dispatch(process)
        raise
    cleanup_error = _close_secret_dispatch_streams(process)
    _raise_secret_dispatch_cleanup_error(
        cleanup_error,
        "fixed JMAP authentication probe failed safely",
    )
    if (
        process.returncode != 0
        or type(stdout) is not bytes
        or type(stderr) is not bytes
        or stderr
    ):
        raise CommandError(
            "fixed JMAP authentication probe failed safely",
        )
    return _validated_jmap_auth_probe_output(
        stdout,
        scheme=scheme,
        authenticated=authenticated,
    )


def run_fixed_jmap_auth_probe(
    credential: memoryview,
    *,
    scheme: str,
    expected_api_url: str = NORMAL_RUNTIME_TRANSPORT_API_URL,
) -> JmapAuthProbe:
    """Probe the API-key success or retired-recovery rejection contract."""
    # The shared child dispatcher is pinned by JMAP_AUTH_PROBE_MODE.
    return _run_fixed_jmap_auth_probe(
        credential,
        scheme=scheme,
        authenticated=scheme == "bearer",
        expected_api_url=expected_api_url,
    )


def run_fixed_normal_basic_jmap_auth_probe(
    credential: memoryview,
    *,
    expected_api_url: str = NORMAL_RUNTIME_TRANSPORT_API_URL,
) -> JmapAuthProbe:
    """Prove the fixed normal management Password over Basic JMAP."""
    return _run_fixed_jmap_auth_probe(
        credential,
        scheme="basic",
        authenticated=True,
        expected_api_url=expected_api_url,
    )


def run_fixed_normal_smtp_auth_probe(
    credential: memoryview,
    *,
    smtp_factory: object = smtplib.SMTP,
) -> int:
    """Authenticate the fixed normal management account on loopback SMTP."""
    if (
        type(credential) is not memoryview
        or not credential.readonly
        or credential.ndim != 1
        or credential.format != "B"
        or not credential.c_contiguous
        or not callable(smtp_factory)
    ):
        raise CommandError("normal runtime SMTP probe is malformed")
    raw = bytearray(credential)
    username = bytearray()
    password = bytearray()
    try:
        if raw.count(b":") != 1:
            raise CommandError("normal runtime SMTP probe is malformed")
        separator = raw.index(ord(":"))
        username.extend(raw[:separator])
        password.extend(raw[separator + 1 :])
        if (
            not username
            or not password
            or len(raw) > 1024
            or any(item < 0x21 or item > 0x7E for item in raw)
        ):
            raise CommandError("normal runtime SMTP probe is malformed")
        username_text = username.decode("ascii", "strict")
        password_text = password.decode("ascii", "strict")
        with smtp_factory(
            NORMAL_RUNTIME_SMTP_HOST,
            NORMAL_RUNTIME_SMTP_PORT,
            timeout=5.0,
        ) as smtp:
            ehlo_status, _ehlo_message = smtp.ehlo()
            if type(ehlo_status) is not int or ehlo_status != 250:
                raise CommandError(
                    "normal runtime SMTP probe failed safely",
                )
            smtp.login(username_text, password_text)
            status, _message = smtp.noop()
        if type(status) is not int or status != 250:
            raise CommandError("normal runtime SMTP probe failed safely")
        return status
    except (UnicodeError, OSError, smtplib.SMTPException):
        raise CommandError("normal runtime SMTP probe failed safely") from None
    finally:
        _wipe_bytearray(raw)
        _wipe_bytearray(username)
        _wipe_bytearray(password)


def run_fixed_normal_readiness_probe(
    *,
    connection_factory: object = http.client.HTTPConnection,
) -> int:
    """Probe only the loopback normal-runtime liveness endpoint."""
    if not callable(connection_factory):
        raise CommandError("normal runtime readiness probe is malformed")
    connection: object | None = None
    response: object | None = None
    primary_in_flight = False
    try:
        connection = connection_factory(
            JMAP_AUTH_PROBE_HOST,
            JMAP_AUTH_PROBE_PORT,
            timeout=JMAP_AUTH_PROBE_TIMEOUT_SECONDS,
        )
        request = getattr(connection, "request", None)
        getresponse = getattr(connection, "getresponse", None)
        if not callable(request) or not callable(getresponse):
            raise CommandError(
                "normal runtime readiness probe is malformed",
            )
        request(
            "GET",
            "/healthz/live",
            body=None,
            headers={"Accept": "text/plain"},
        )
        response = getresponse()
        status = getattr(response, "status", None)
        read = getattr(response, "read", None)
        if (
            type(status) is not int
            or isinstance(status, bool)
            or status != 200
            or not callable(read)
        ):
            raise CommandError(
                "normal runtime readiness probe failed safely",
            )
        body = read(64 * 1024 + 1)
        if type(body) is not bytes or len(body) > 64 * 1024:
            raise CommandError(
                "normal runtime readiness probe failed safely",
            )
        return 200
    except (CommandError, KeyboardInterrupt, SystemExit):
        primary_in_flight = True
        raise
    except BaseException:
        primary_in_flight = True
        raise CommandError(
            "normal runtime readiness probe failed safely",
        ) from None
    finally:
        cleanup_error: BaseException | None = None
        for resource in (response, connection):
            if resource is None:
                continue
            try:
                close = getattr(resource, "close", None)
                if not callable(close):
                    raise OSError("readiness resource is malformed")
                close()
            except BaseException as exc:
                if cleanup_error is None:
                    cleanup_error = exc
        if not primary_in_flight and cleanup_error is not None:
            if isinstance(cleanup_error, Exception):
                raise CommandError(
                    "normal runtime readiness probe failed safely",
                ) from None
            raise cleanup_error


def _read_regular_mutable(
    path: Path,
    *,
    root: Path,
    label: str,
    maximum: int,
    required_mode: int,
) -> tuple[
    bytearray,
    str,
    int,
    tuple[int, int, int, int, int, int],
]:
    """Read a secret file directly into wipeable storage without byte chunks."""
    descriptor, before = _open_regular_readonly(path, root=root, label=label)
    buffer = bytearray()
    result: tuple[
        bytearray,
        str,
        int,
        tuple[int, int, int, int, int, int],
    ] | None = None
    read_failed = False
    close_failed = False
    try:
        if stat.S_IMODE(before.st_mode) != required_mode:
            raise MigrationError(f"{label} must have mode {required_mode:04o}")
        if before.st_size < 0 or before.st_size > maximum:
            raise MigrationError(f"{label} is too large")
        buffer = bytearray(before.st_size)
        total = 0
        while total < len(buffer):
            view = memoryview(buffer)[total:]
            try:
                read = os.readv(descriptor, [view])
            finally:
                view.release()
            if read <= 0:
                raise MigrationError(f"{label} changed while it was read")
            total += read
        trailing = bytearray(1)
        trailing_view = memoryview(trailing)
        try:
            extra = os.readv(descriptor, [trailing_view])
        finally:
            trailing_view.release()
            _wipe_bytearray(trailing)
        after = os.fstat(descriptor)
        if extra != 0 or total != before.st_size:
            raise MigrationError(f"{label} changed while it was read")
        if _file_identity(after) != _file_identity(before):
            raise MigrationError(f"{label} changed while it was read")
        result = (
            buffer,
            hashlib.sha256(buffer).hexdigest(),
            total,
            _file_identity(after),
        )
    except OSError:
        _wipe_bytearray(buffer)
        read_failed = True
    except BaseException:
        _wipe_bytearray(buffer)
        raise
    finally:
        try:
            os.close(descriptor)
        except OSError:
            _wipe_bytearray(buffer)
            close_failed = True
        except BaseException:
            _wipe_bytearray(buffer)
            raise
    if read_failed or close_failed or result is None:
        raise MigrationError(f"{label} could not be read safely") from None
    return result


def _sha256_regular(path: Path, *, root: Path, label: str) -> str:
    descriptor, before = _open_regular_readonly(path, root=root, label=label)
    digest = hashlib.sha256()
    try:
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        after = os.fstat(descriptor)
    except OSError as exc:
        raise MigrationError(f"{label} could not be read safely") from exc
    finally:
        os.close(descriptor)
    if (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ):
        raise MigrationError(f"{label} changed while it was read")
    return digest.hexdigest()


def require_regular_0600(path: Path, *, root: Path, label: str) -> str:
    descriptor, metadata = _open_regular_readonly(path, root=root, label=label)
    os.close(descriptor)
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise MigrationError(f"{label} must have mode 0600")
    return _sha256_regular(path, root=root, label=label)


def require_regular(path: Path, *, root: Path, label: str) -> None:
    descriptor, _metadata = _open_regular_readonly(path, root=root, label=label)
    os.close(descriptor)


def _require_owner_migration_root(paths: "MigrationPaths") -> None:
    metadata = _require_real_directory(paths.migration_root, "migration root")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        raise MigrationError("migration root must have mode 0700")
    _require_no_symlink_components(
        paths.repository_root,
        paths.migration_root,
        "migration root",
    )


def ensure_owner_directory(
    path: Path,
    *,
    trusted_root: Path,
    owner_root: Path | None = None,
) -> None:
    """Create a symlink-free directory chain with mode 0700."""
    _require_below(trusted_root, path, "owner directory")
    if owner_root is not None:
        _require_below(trusted_root, owner_root, "owner root")
        if owner_root != path and owner_root not in path.parents:
            raise MigrationError("owner root must contain the requested directory")
    _require_real_directory(trusted_root, "trusted root")
    current = trusted_root
    for component in path.relative_to(trusted_root).parts:
        current = current / component
        owner_only = owner_root is None or current == owner_root or owner_root in current.parents
        try:
            if not owner_only:
                _require_real_directory(current, "shared directory prefix")
                continue
            current.mkdir(mode=0o700)
            current.chmod(0o700)
        except FileExistsError:
            metadata = _require_real_directory(current, "owner directory")
            if owner_only and stat.S_IMODE(metadata.st_mode) != 0o700:
                raise MigrationError("owner directory must have mode 0700")
        except OSError as exc:
            raise MigrationError("owner directory could not be created safely") from exc


def _stalwart_operation_anchor_path(repository_root: Path) -> Path:
    repository = _plain_absolute(repository_root, "repository root")
    digest = hashlib.sha256(os.fsencode(str(repository))).hexdigest()
    return (
        repository.parent
        / STALWART_OPERATION_LOCK_NAMESPACE_NAME
        / f"stalwart-operation-{digest}.lock"
    )


class _StalwartOperationAnchorBinding(NamedTuple):
    anchor_path: Path
    anchor_descriptor: int
    anchor_identity: tuple[int, int]
    parent_path: Path
    parent_descriptor: int
    parent_identity: tuple[int, int]
    parent_mode: int
    namespace_path: Path
    namespace_descriptor: int
    namespace_identity: tuple[int, int]


def _acquire_stalwart_global_guard(
) -> tuple[int, tuple[int, int], int, int]:
    """Serialize all cooperating lock namespaces below immutable filesystem root."""
    guard_path = STALWART_OPERATION_GLOBAL_GUARD_PATH
    descriptor = -1
    try:
        before = guard_path.lstat()
        descriptor = os.open(
            guard_path,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        metadata = os.fstat(descriptor)
        current = guard_path.lstat()
        mode = stat.S_IMODE(metadata.st_mode)
        if (
            not stat.S_ISDIR(before.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or not stat.S_ISDIR(current.st_mode)
            or metadata.st_dev != before.st_dev
            or metadata.st_ino != before.st_ino
            or current.st_dev != metadata.st_dev
            or current.st_ino != metadata.st_ino
            or metadata.st_uid != 0
            or mode & 0o022
        ):
            raise MigrationError(
                "Stalwart global operation guard is unsafe",
            )
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno in {errno.EACCES, errno.EAGAIN}:
                raise MigrationError(
                    "another Stalwart operation is active",
                ) from None
            raise MigrationError(
                "Stalwart global operation guard could not be acquired",
            ) from exc
        after = os.fstat(descriptor)
        current_after = guard_path.lstat()
        if (
            (after.st_dev, after.st_ino)
            != (metadata.st_dev, metadata.st_ino)
            or current_after.st_dev != after.st_dev
            or current_after.st_ino != after.st_ino
            or not stat.S_ISDIR(current_after.st_mode)
            or after.st_uid != metadata.st_uid
            or stat.S_IMODE(after.st_mode) != mode
        ):
            raise MigrationError(
                "Stalwart global operation guard changed during acquisition",
            )
        result = (
            descriptor,
            (after.st_dev, after.st_ino),
            after.st_uid,
            mode,
        )
        descriptor = -1
        return result
    except OSError as exc:
        raise MigrationError(
            "Stalwart global operation guard could not be opened safely",
        ) from exc
    finally:
        if descriptor >= 0:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            except OSError:
                pass
            try:
                os.close(descriptor)
            except OSError:
                pass


def _acquire_stalwart_operation_anchor(
    repository_root: Path,
) -> _StalwartOperationAnchorBinding:
    """Acquire one dirfd-bound repository-path leaf outside the repository."""
    repository = _plain_absolute(repository_root, "repository root")
    parent_path = repository.parent
    namespace_path = parent_path / STALWART_OPERATION_LOCK_NAMESPACE_NAME
    anchor_path = _stalwart_operation_anchor_path(repository)
    _require_absolute_no_symlinks(parent_path, "lock anchor parent")
    parent_descriptor = -1
    namespace_descriptor = -1
    anchor_descriptor = -1
    try:
        before_parent = parent_path.lstat()
        parent_mode = stat.S_IMODE(before_parent.st_mode)
        if (
            not stat.S_ISDIR(before_parent.st_mode)
            or before_parent.st_uid != os.getuid()
            or parent_mode & 0o022
        ):
            raise MigrationError("Stalwart lock anchor parent is unsafe")
        parent_descriptor = os.open(
            parent_path,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        opened_parent = os.fstat(parent_descriptor)
        current_parent = parent_path.lstat()
        if (
            not stat.S_ISDIR(opened_parent.st_mode)
            or opened_parent.st_dev != before_parent.st_dev
            or opened_parent.st_ino != before_parent.st_ino
            or current_parent.st_dev != opened_parent.st_dev
            or current_parent.st_ino != opened_parent.st_ino
            or opened_parent.st_uid != os.getuid()
            or stat.S_IMODE(opened_parent.st_mode) != parent_mode
        ):
            raise MigrationError(
                "Stalwart lock anchor parent changed before use",
            )

        namespace_name = STALWART_OPERATION_LOCK_NAMESPACE_NAME
        try:
            os.mkdir(namespace_name, 0o700, dir_fd=parent_descriptor)
            os.chmod(
                namespace_name,
                0o700,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except FileExistsError:
            pass
        before_namespace = os.stat(
            namespace_name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISDIR(before_namespace.st_mode)
            or before_namespace.st_uid != os.getuid()
            or stat.S_IMODE(before_namespace.st_mode) != 0o700
        ):
            raise MigrationError(
                "Stalwart lock anchor namespace is unsafe",
            )
        namespace_descriptor = os.open(
            namespace_name,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent_descriptor,
        )
        opened_namespace = os.fstat(namespace_descriptor)
        current_namespace = os.stat(
            namespace_name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        current_namespace_path = namespace_path.lstat()
        if (
            not stat.S_ISDIR(opened_namespace.st_mode)
            or opened_namespace.st_dev != before_namespace.st_dev
            or opened_namespace.st_ino != before_namespace.st_ino
            or current_namespace.st_dev != opened_namespace.st_dev
            or current_namespace.st_ino != opened_namespace.st_ino
            or current_namespace_path.st_dev != opened_namespace.st_dev
            or current_namespace_path.st_ino != opened_namespace.st_ino
            or not stat.S_ISDIR(current_namespace_path.st_mode)
            or opened_namespace.st_uid != os.getuid()
            or stat.S_IMODE(opened_namespace.st_mode) != 0o700
        ):
            raise MigrationError(
                "Stalwart lock anchor namespace changed before use",
            )

        anchor_name = anchor_path.name
        flags = (
            os.O_RDWR
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        try:
            anchor_descriptor = os.open(
                anchor_name,
                flags | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=namespace_descriptor,
            )
            os.fchmod(anchor_descriptor, 0o600)
        except FileExistsError:
            before_anchor = os.stat(
                anchor_name,
                dir_fd=namespace_descriptor,
                follow_symlinks=False,
            )
            if stat.S_ISLNK(before_anchor.st_mode):
                raise MigrationError(
                    "Stalwart operation lock anchor must not be a symlink",
                )
            anchor_descriptor = os.open(
                anchor_name,
                flags,
                dir_fd=namespace_descriptor,
            )
            opened_anchor = os.fstat(anchor_descriptor)
            if (
                opened_anchor.st_dev != before_anchor.st_dev
                or opened_anchor.st_ino != before_anchor.st_ino
            ):
                raise MigrationError(
                    "Stalwart operation lock anchor changed before use",
                )
        anchor_metadata = os.fstat(anchor_descriptor)
        current_anchor = os.stat(
            anchor_name,
            dir_fd=namespace_descriptor,
            follow_symlinks=False,
        )
        current_anchor_path = anchor_path.lstat()
        if (
            not stat.S_ISREG(anchor_metadata.st_mode)
            or anchor_metadata.st_nlink != 1
            or anchor_metadata.st_uid != os.getuid()
            or anchor_metadata.st_size != 0
            or stat.S_IMODE(anchor_metadata.st_mode) != 0o600
            or stat.S_ISLNK(current_anchor.st_mode)
            or current_anchor.st_dev != anchor_metadata.st_dev
            or current_anchor.st_ino != anchor_metadata.st_ino
            or stat.S_ISLNK(current_anchor_path.st_mode)
            or current_anchor_path.st_dev != anchor_metadata.st_dev
            or current_anchor_path.st_ino != anchor_metadata.st_ino
        ):
            raise MigrationError(
                "Stalwart operation lock anchor is unsafe",
            )
        try:
            fcntl.flock(
                anchor_descriptor,
                fcntl.LOCK_EX | fcntl.LOCK_NB,
            )
        except OSError as exc:
            if exc.errno in {errno.EACCES, errno.EAGAIN}:
                raise MigrationError(
                    "another Stalwart operation is active",
                ) from None
            raise MigrationError(
                "Stalwart operation lock anchor could not be acquired",
            ) from exc
        after_anchor = os.fstat(anchor_descriptor)
        after_parent = parent_path.lstat()
        after_namespace = os.stat(
            namespace_name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        after_namespace_path = namespace_path.lstat()
        after_anchor_relative = os.stat(
            anchor_name,
            dir_fd=namespace_descriptor,
            follow_symlinks=False,
        )
        after_anchor_path = anchor_path.lstat()
        if (
            after_parent.st_dev != opened_parent.st_dev
            or after_parent.st_ino != opened_parent.st_ino
            or not stat.S_ISDIR(after_parent.st_mode)
            or after_namespace.st_dev != opened_namespace.st_dev
            or after_namespace.st_ino != opened_namespace.st_ino
            or after_namespace_path.st_dev != opened_namespace.st_dev
            or after_namespace_path.st_ino != opened_namespace.st_ino
            or not stat.S_ISDIR(after_namespace_path.st_mode)
            or after_anchor_relative.st_dev != after_anchor.st_dev
            or after_anchor_relative.st_ino != after_anchor.st_ino
            or after_anchor_path.st_dev != after_anchor.st_dev
            or after_anchor_path.st_ino != after_anchor.st_ino
            or stat.S_ISLNK(after_anchor_path.st_mode)
            or _file_identity(after_anchor) != _file_identity(anchor_metadata)
        ):
            raise MigrationError(
                "Stalwart lock anchor namespace changed during acquisition",
            )
        result = _StalwartOperationAnchorBinding(
            anchor_path=anchor_path,
            anchor_descriptor=anchor_descriptor,
            anchor_identity=(after_anchor.st_dev, after_anchor.st_ino),
            parent_path=parent_path,
            parent_descriptor=parent_descriptor,
            parent_identity=(
                opened_parent.st_dev,
                opened_parent.st_ino,
            ),
            parent_mode=parent_mode,
            namespace_path=namespace_path,
            namespace_descriptor=namespace_descriptor,
            namespace_identity=(
                opened_namespace.st_dev,
                opened_namespace.st_ino,
            ),
        )
        anchor_descriptor = -1
        parent_descriptor = -1
        namespace_descriptor = -1
        return result
    except OSError as exc:
        raise MigrationError(
            "Stalwart operation lock anchor could not be opened safely",
        ) from exc
    finally:
        if anchor_descriptor >= 0:
            try:
                fcntl.flock(anchor_descriptor, fcntl.LOCK_UN)
            except OSError:
                pass
            try:
                os.close(anchor_descriptor)
            except OSError:
                pass
        if namespace_descriptor >= 0:
            try:
                os.close(namespace_descriptor)
            except OSError:
                pass
        if parent_descriptor >= 0:
            try:
                os.close(parent_descriptor)
            except OSError:
                pass


class StalwartOperationLock:
    """One process-local handle for the persistent bootstrap/retirement lock."""

    __slots__ = (
        "_anchor_descriptor",
        "_anchor_identity",
        "_anchor_namespace_descriptor",
        "_anchor_namespace_identity",
        "_anchor_namespace_path",
        "_anchor_parent_descriptor",
        "_anchor_parent_identity",
        "_anchor_parent_mode",
        "_anchor_parent_path",
        "_anchor_path",
        "_closed",
        "_descriptor",
        "_global_descriptor",
        "_global_identity",
        "_global_mode",
        "_global_path",
        "_global_uid",
        "_lock_directory_identity",
        "_namespace_descriptor",
        "_path",
        "_repository_identity",
        "_repository_path",
    )

    def __init__(
        self,
        path: Path,
        descriptor: int,
        *,
        anchor_descriptor: int,
        anchor_identity: tuple[int, int],
        anchor_path: Path,
        anchor_namespace_descriptor: int,
        anchor_namespace_identity: tuple[int, int],
        anchor_namespace_path: Path,
        anchor_parent_descriptor: int,
        anchor_parent_identity: tuple[int, int],
        anchor_parent_mode: int,
        anchor_parent_path: Path,
        global_descriptor: int,
        global_identity: tuple[int, int],
        global_mode: int,
        global_uid: int,
        namespace_descriptor: int,
        lock_directory_identity: tuple[int, int],
        repository_path: Path,
        repository_identity: tuple[int, int],
    ) -> None:
        descriptors = (
            descriptor,
            anchor_descriptor,
            anchor_namespace_descriptor,
            anchor_parent_descriptor,
            global_descriptor,
            namespace_descriptor,
        )
        identities = (
            anchor_identity,
            anchor_namespace_identity,
            anchor_parent_identity,
            global_identity,
            lock_directory_identity,
            repository_identity,
        )
        if (
            not isinstance(path, Path)
            or any(type(value) is not int or value < 0 for value in descriptors)
            or any(
                not isinstance(identity, tuple)
                or len(identity) != 2
                or any(type(value) is not int or value < 0 for value in identity)
                for identity in identities
            )
            or not isinstance(anchor_path, Path)
            or not isinstance(anchor_namespace_path, Path)
            or not isinstance(anchor_parent_path, Path)
            or type(anchor_parent_mode) is not int
            or anchor_parent_mode < 0
            or anchor_parent_mode > 0o7777
            or type(global_mode) is not int
            or global_mode < 0
            or global_mode > 0o7777
            or type(global_uid) is not int
            or global_uid < 0
            or not isinstance(repository_path, Path)
        ):
            raise MigrationError("Stalwart operation lock is malformed")
        self._anchor_descriptor = anchor_descriptor
        self._anchor_identity = anchor_identity
        self._anchor_namespace_descriptor = anchor_namespace_descriptor
        self._anchor_namespace_identity = anchor_namespace_identity
        self._anchor_namespace_path = anchor_namespace_path
        self._anchor_parent_descriptor = anchor_parent_descriptor
        self._anchor_parent_identity = anchor_parent_identity
        self._anchor_parent_mode = anchor_parent_mode
        self._anchor_parent_path = anchor_parent_path
        self._anchor_path = anchor_path
        self._path = path
        self._descriptor = descriptor
        self._global_descriptor = global_descriptor
        self._global_identity = global_identity
        self._global_mode = global_mode
        self._global_path = STALWART_OPERATION_GLOBAL_GUARD_PATH
        self._global_uid = global_uid
        self._lock_directory_identity = lock_directory_identity
        self._namespace_descriptor = namespace_descriptor
        self._repository_path = repository_path
        self._repository_identity = repository_identity
        self._closed = False

    @property
    def path(self) -> Path:
        if self._closed:
            raise MigrationError("Stalwart operation lock is closed")
        return self._path

    def assert_valid_for(self, repository_root: Path) -> None:
        """Require this exact live lock token for one repository operation."""
        if self._closed:
            raise MigrationError("Stalwart operation lock is closed")
        repository = _plain_absolute(repository_root, "repository root")
        _require_absolute_no_symlinks(repository, "repository root")
        if (
            repository != self._repository_path
            or self._global_path != STALWART_OPERATION_GLOBAL_GUARD_PATH
            or self._anchor_parent_path != repository.parent
            or self._anchor_namespace_path
            != repository.parent / STALWART_OPERATION_LOCK_NAMESPACE_NAME
            or self._anchor_path
            != _stalwart_operation_anchor_path(repository)
            or self._path
            != repository
            / "debug-dashboard"
            / ".runtime"
            / "stalwart"
            / "bootstrap.lock"
        ):
            raise MigrationError(
                "Stalwart operation lock belongs to another repository",
            )
        try:
            global_metadata = os.fstat(self._global_descriptor)
            current_global = self._global_path.lstat()
            anchor_parent_metadata = os.fstat(
                self._anchor_parent_descriptor,
            )
            current_anchor_parent = self._anchor_parent_path.lstat()
            anchor_namespace_metadata = os.fstat(
                self._anchor_namespace_descriptor,
            )
            current_anchor_namespace = os.stat(
                self._anchor_namespace_path.name,
                dir_fd=self._anchor_parent_descriptor,
                follow_symlinks=False,
            )
            current_anchor_namespace_path = (
                self._anchor_namespace_path.lstat()
            )
            anchor_metadata = os.fstat(self._anchor_descriptor)
            current_anchor = os.stat(
                self._anchor_path.name,
                dir_fd=self._anchor_namespace_descriptor,
                follow_symlinks=False,
            )
            current_anchor_path = self._anchor_path.lstat()
            namespace = os.fstat(self._namespace_descriptor)
            current_repository = repository.lstat()
            lock_metadata = os.fstat(self._descriptor)
            current_lock_directory = self._path.parent.lstat()
            current_lock = self._path.lstat()
            fcntl.flock(
                self._global_descriptor,
                fcntl.LOCK_EX | fcntl.LOCK_NB,
            )
            fcntl.flock(
                self._anchor_descriptor,
                fcntl.LOCK_EX | fcntl.LOCK_NB,
            )
            fcntl.flock(
                self._namespace_descriptor,
                fcntl.LOCK_EX | fcntl.LOCK_NB,
            )
            fcntl.flock(
                self._descriptor,
                fcntl.LOCK_EX | fcntl.LOCK_NB,
            )
        except OSError as exc:
            raise MigrationError(
                "Stalwart operation lock namespace changed or is unavailable",
            ) from exc
        if (
            not stat.S_ISDIR(global_metadata.st_mode)
            or (global_metadata.st_dev, global_metadata.st_ino)
            != self._global_identity
            or current_global.st_dev != global_metadata.st_dev
            or current_global.st_ino != global_metadata.st_ino
            or not stat.S_ISDIR(current_global.st_mode)
            or global_metadata.st_uid != self._global_uid
            or self._global_uid != 0
            or stat.S_IMODE(global_metadata.st_mode) != self._global_mode
            or self._global_mode & 0o022
            or not stat.S_ISDIR(anchor_parent_metadata.st_mode)
            or (
                anchor_parent_metadata.st_dev,
                anchor_parent_metadata.st_ino,
            )
            != self._anchor_parent_identity
            or current_anchor_parent.st_dev
            != anchor_parent_metadata.st_dev
            or current_anchor_parent.st_ino
            != anchor_parent_metadata.st_ino
            or not stat.S_ISDIR(current_anchor_parent.st_mode)
            or anchor_parent_metadata.st_uid != os.getuid()
            or stat.S_IMODE(anchor_parent_metadata.st_mode)
            != self._anchor_parent_mode
            or self._anchor_parent_mode & 0o022
            or not stat.S_ISDIR(anchor_namespace_metadata.st_mode)
            or (
                anchor_namespace_metadata.st_dev,
                anchor_namespace_metadata.st_ino,
            )
            != self._anchor_namespace_identity
            or current_anchor_namespace.st_dev
            != anchor_namespace_metadata.st_dev
            or current_anchor_namespace.st_ino
            != anchor_namespace_metadata.st_ino
            or current_anchor_namespace_path.st_dev
            != anchor_namespace_metadata.st_dev
            or current_anchor_namespace_path.st_ino
            != anchor_namespace_metadata.st_ino
            or not stat.S_ISDIR(current_anchor_namespace.st_mode)
            or not stat.S_ISDIR(current_anchor_namespace_path.st_mode)
            or anchor_namespace_metadata.st_uid != os.getuid()
            or stat.S_IMODE(anchor_namespace_metadata.st_mode) != 0o700
            or not stat.S_ISREG(anchor_metadata.st_mode)
            or (anchor_metadata.st_dev, anchor_metadata.st_ino)
            != self._anchor_identity
            or current_anchor.st_dev != anchor_metadata.st_dev
            or current_anchor.st_ino != anchor_metadata.st_ino
            or stat.S_ISLNK(current_anchor.st_mode)
            or current_anchor_path.st_dev != anchor_metadata.st_dev
            or current_anchor_path.st_ino != anchor_metadata.st_ino
            or stat.S_ISLNK(current_anchor_path.st_mode)
            or anchor_metadata.st_nlink != 1
            or anchor_metadata.st_uid != os.getuid()
            or anchor_metadata.st_size != 0
            or stat.S_IMODE(anchor_metadata.st_mode) != 0o600
            or not stat.S_ISDIR(namespace.st_mode)
            or not stat.S_ISDIR(current_repository.st_mode)
            or (namespace.st_dev, namespace.st_ino)
            != self._repository_identity
            or (current_repository.st_dev, current_repository.st_ino)
            != self._repository_identity
            or not stat.S_ISDIR(current_lock_directory.st_mode)
            or (
                current_lock_directory.st_dev,
                current_lock_directory.st_ino,
            )
            != self._lock_directory_identity
            or current_lock_directory.st_uid != os.getuid()
            or stat.S_IMODE(current_lock_directory.st_mode) != 0o700
            or not stat.S_ISREG(lock_metadata.st_mode)
            or lock_metadata.st_nlink != 1
            or lock_metadata.st_uid != os.getuid()
            or lock_metadata.st_size != 0
            or stat.S_IMODE(lock_metadata.st_mode) != 0o600
            or stat.S_ISLNK(current_lock.st_mode)
            or current_lock.st_dev != lock_metadata.st_dev
            or current_lock.st_ino != lock_metadata.st_ino
        ):
            raise MigrationError(
                "Stalwart operation lock namespace changed or is unavailable",
            )

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        descriptor = self._descriptor
        namespace_descriptor = self._namespace_descriptor
        anchor_descriptor = self._anchor_descriptor
        anchor_namespace_descriptor = self._anchor_namespace_descriptor
        anchor_parent_descriptor = self._anchor_parent_descriptor
        global_descriptor = self._global_descriptor
        self._descriptor = -1
        self._namespace_descriptor = -1
        self._anchor_descriptor = -1
        self._anchor_namespace_descriptor = -1
        self._anchor_parent_descriptor = -1
        self._global_descriptor = -1
        locked_descriptors = {
            descriptor,
            namespace_descriptor,
            anchor_descriptor,
            global_descriptor,
        }
        for current_descriptor in (
            descriptor,
            namespace_descriptor,
            anchor_descriptor,
            anchor_namespace_descriptor,
            anchor_parent_descriptor,
            global_descriptor,
        ):
            if current_descriptor in locked_descriptors:
                try:
                    fcntl.flock(current_descriptor, fcntl.LOCK_UN)
                except OSError:
                    pass
            try:
                os.close(current_descriptor)
            except OSError:
                pass

    def __enter__(self) -> "StalwartOperationLock":
        self.assert_valid_for(self._repository_path)
        return self

    def __exit__(
        self,
        _exception_type: object,
        _exception: object,
        _traceback: object,
    ) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except BaseException:
            pass

    def __repr__(self) -> str:
        return "StalwartOperationLock(<redacted>)"


def _prepare_stalwart_operation_lock_directory(repository_root: Path) -> Path:
    repository = _plain_absolute(repository_root, "repository root")
    _require_real_directory(repository, "repository root")
    dashboard_root = repository / "debug-dashboard"
    _require_no_symlink_components(
        repository,
        dashboard_root,
        "dashboard root",
    )
    _require_real_directory(dashboard_root, "dashboard root")
    runtime_root = dashboard_root / ".runtime"
    try:
        runtime_metadata = _require_real_directory(
            runtime_root,
            "dashboard runtime root",
        )
    except MigrationError:
        if _path_present(runtime_root):
            raise
        ensure_owner_directory(
            runtime_root,
            trusted_root=repository,
            owner_root=runtime_root,
        )
        runtime_metadata = _require_real_directory(
            runtime_root,
            "dashboard runtime root",
        )
    if runtime_metadata.st_uid != os.getuid():
        raise MigrationError("dashboard runtime root is not owner-owned")
    if stat.S_IMODE(runtime_metadata.st_mode) != 0o700:
        try:
            os.chmod(runtime_root, 0o700, follow_symlinks=False)
        except OSError as exc:
            raise MigrationError(
                "dashboard runtime root could not be made owner-only",
            ) from exc
        tightened = _require_real_directory(
            runtime_root,
            "dashboard runtime root",
        )
        if (
            tightened.st_dev != runtime_metadata.st_dev
            or tightened.st_ino != runtime_metadata.st_ino
            or tightened.st_uid != os.getuid()
            or stat.S_IMODE(tightened.st_mode) != 0o700
        ):
            raise MigrationError(
                "dashboard runtime root changed while making it owner-only",
            )
    stalwart_root = runtime_root / "stalwart"
    ensure_owner_directory(
        stalwart_root,
        trusted_root=repository,
        owner_root=stalwart_root,
    )
    metadata = _require_real_directory(stalwart_root, "Stalwart runtime root")
    if (
        stat.S_IMODE(metadata.st_mode) != 0o700
        or metadata.st_uid != os.getuid()
    ):
        raise MigrationError(
            "Stalwart runtime root must be owner-owned with mode 0700",
        )
    return stalwart_root


def acquire_stalwart_operation_lock(
    repository_root: Path,
) -> StalwartOperationLock:
    """Acquire the fixed persistent nonblocking bootstrap/retirement lock."""
    (
        global_descriptor,
        global_identity,
        global_uid,
        global_mode,
    ) = _acquire_stalwart_global_guard()
    anchor_descriptor = -1
    anchor_namespace_descriptor = -1
    anchor_parent_descriptor = -1
    namespace_descriptor = -1
    descriptor = -1
    try:
        repository = _plain_absolute(repository_root, "repository root")
        _require_absolute_no_symlinks(repository, "repository root")
        before_repository = _require_real_directory(
            repository,
            "repository root",
        )
        anchor = _acquire_stalwart_operation_anchor(repository)
        anchor_descriptor = anchor.anchor_descriptor
        anchor_namespace_descriptor = anchor.namespace_descriptor
        anchor_parent_descriptor = anchor.parent_descriptor
        namespace_descriptor = os.open(
            repository,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        opened_repository = os.fstat(namespace_descriptor)
        current_repository = repository.lstat()
        if (
            not stat.S_ISDIR(opened_repository.st_mode)
            or opened_repository.st_dev != before_repository.st_dev
            or opened_repository.st_ino != before_repository.st_ino
            or current_repository.st_dev != opened_repository.st_dev
            or current_repository.st_ino != opened_repository.st_ino
        ):
            raise MigrationError(
                "Stalwart operation lock repository namespace changed",
            )
        try:
            fcntl.flock(
                namespace_descriptor,
                fcntl.LOCK_EX | fcntl.LOCK_NB,
            )
        except OSError as exc:
            if exc.errno in {errno.EACCES, errno.EAGAIN}:
                raise MigrationError(
                    "another Stalwart operation is active",
                ) from None
            raise MigrationError(
                "Stalwart operation lock could not be acquired",
            ) from exc

        stalwart_root = _prepare_stalwart_operation_lock_directory(repository)
        stalwart_root_metadata = _require_real_directory(
            stalwart_root,
            "Stalwart runtime root",
        )
        lock_path = stalwart_root / "bootstrap.lock"
        flags = (
            os.O_RDWR
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        try:
            descriptor = os.open(
                lock_path,
                flags | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            os.fchmod(descriptor, 0o600)
        except FileExistsError:
            before = lock_path.lstat()
            if stat.S_ISLNK(before.st_mode):
                raise MigrationError(
                    "Stalwart operation lock must not be a symlink",
                )
            descriptor = os.open(lock_path, flags)
            opened = os.fstat(descriptor)
            if (
                opened.st_dev != before.st_dev
                or opened.st_ino != before.st_ino
            ):
                raise MigrationError(
                    "Stalwart operation lock changed before use",
                )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.getuid()
            or metadata.st_size != 0
        ):
            raise MigrationError(
                "Stalwart operation lock must be one empty owner-owned regular file",
            )
        if stat.S_IMODE(metadata.st_mode) != 0o600:
            raise MigrationError("Stalwart operation lock must have mode 0600")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno in {errno.EACCES, errno.EAGAIN}:
                raise MigrationError(
                    "another Stalwart operation is active",
                ) from None
            raise MigrationError(
                "Stalwart operation lock could not be acquired",
            ) from exc
        after = os.fstat(descriptor)
        current = lock_path.lstat()
        if (
            _file_identity(after) != _file_identity(metadata)
            or current.st_dev != after.st_dev
            or current.st_ino != after.st_ino
            or stat.S_ISLNK(current.st_mode)
        ):
            raise MigrationError("Stalwart operation lock changed during acquisition")
        lock = StalwartOperationLock(
            lock_path,
            descriptor,
            anchor_descriptor=anchor_descriptor,
            anchor_identity=anchor.anchor_identity,
            anchor_path=anchor.anchor_path,
            anchor_namespace_descriptor=anchor_namespace_descriptor,
            anchor_namespace_identity=anchor.namespace_identity,
            anchor_namespace_path=anchor.namespace_path,
            anchor_parent_descriptor=anchor_parent_descriptor,
            anchor_parent_identity=anchor.parent_identity,
            anchor_parent_mode=anchor.parent_mode,
            anchor_parent_path=anchor.parent_path,
            global_descriptor=global_descriptor,
            global_identity=global_identity,
            global_mode=global_mode,
            global_uid=global_uid,
            namespace_descriptor=namespace_descriptor,
            lock_directory_identity=(
                stalwart_root_metadata.st_dev,
                stalwart_root_metadata.st_ino,
            ),
            repository_path=repository,
            repository_identity=(
                opened_repository.st_dev,
                opened_repository.st_ino,
            ),
        )
        descriptor = -1
        namespace_descriptor = -1
        anchor_descriptor = -1
        anchor_namespace_descriptor = -1
        anchor_parent_descriptor = -1
        global_descriptor = -1
        try:
            lock.assert_valid_for(repository)
        except BaseException:
            lock.close()
            raise
        return lock
    except OSError as exc:
        raise MigrationError(
            "Stalwart operation lock could not be opened safely",
        ) from exc
    finally:
        for current_descriptor, locked in (
            (descriptor, True),
            (namespace_descriptor, True),
            (anchor_descriptor, True),
            (anchor_namespace_descriptor, False),
            (anchor_parent_descriptor, False),
            (global_descriptor, True),
        ):
            if current_descriptor < 0:
                continue
            if locked:
                try:
                    fcntl.flock(current_descriptor, fcntl.LOCK_UN)
                except OSError:
                    pass
            try:
                os.close(current_descriptor)
            except OSError:
                pass


def validate_migration_script(
    paths: "MigrationPaths",
    requested_path: Path,
    *,
    expected_sha256: str = MIGRATION_SCRIPT_SHA256,
) -> str:
    if requested_path != paths.migration_script:
        raise MigrationError("migration script is not the fixed repository path")
    _require_owner_migration_root(paths)
    observed = require_regular_0600(
        requested_path,
        root=paths.repository_root,
        label="migration script",
    )
    if observed != expected_sha256:
        raise MigrationError("migration script checksum does not match the pinned source")
    return observed


def verify_source_capture(
    paths: "MigrationPaths",
    receipt_path: Path,
    *,
    runner: object = run_command,
    python_executable: str,
) -> "VerifiedReceipt":
    if receipt_path != paths.source_receipt:
        raise MigrationError("source receipt is not the fixed repository path")
    _require_owner_migration_root(paths)
    before = _read_regular_snapshot(
        receipt_path,
        root=paths.repository_root,
        label="source receipt",
        maximum=4 * 1024 * 1024,
        required_mode=0o600,
    )
    capture_script = paths.repository_root / "scripts" / "capture_stalwart_v015.py"
    require_regular(
        capture_script,
        root=paths.repository_root,
        label="Task 5 capture verifier",
    )
    if not python_executable or not Path(python_executable).is_absolute():
        raise MigrationError("capture verifier interpreter must be an absolute path")
    runner(
        [
            python_executable,
            str(capture_script),
            "verify",
            "--receipt",
            str(receipt_path),
        ],
    )
    after = _read_regular_snapshot(
        receipt_path,
        root=paths.repository_root,
        label="source receipt",
        maximum=4 * 1024 * 1024,
        required_mode=0o600,
    )
    if (
        before.identity != after.identity
        or not secrets.compare_digest(before.sha256, after.sha256)
        or before.content != after.content
    ):
        raise MigrationError("source receipt changed during Task 5 verification")
    return VerifiedReceipt(after)


@dataclass(frozen=True)
class MigrationPaths:
    repository_root: Path
    migration_root: Path
    scratch_store: Path
    source_receipt: Path
    migration_script: Path
    settings: Path
    principals: Path
    converted_config: Path
    export: Path
    unmigrated: Path
    reviewed: Path
    dry_run_receipt: Path
    apply_attempt: Path
    apply_receipt: Path
    bootstrap_receipt: Path
    retire_recovery_attempt: Path
    retire_recovery_proof: Path
    recovery_retired_receipt: Path

    @classmethod
    def for_repository(cls, repository_root: Path) -> "MigrationPaths":
        root = repository_root / "debug-dashboard" / ".runtime" / "stalwart-migration"
        return cls(
            repository_root=repository_root,
            migration_root=root,
            scratch_store=root / "provider-scratch",
            source_receipt=root / "latest-source.json",
            migration_script=root / "migrate_v016.py",
            settings=root / "settings.json",
            principals=root / "principals.json",
            converted_config=root / "config.json",
            export=root / "export.json",
            unmigrated=root / "unmigrated.txt",
            reviewed=root / "reviewed.json",
            dry_run_receipt=root / "dry-run.json",
            apply_attempt=root / "apply-attempt.json",
            apply_receipt=root / "apply.json",
            bootstrap_receipt=(
                repository_root
                / "debug-dashboard"
                / ".runtime"
                / "stalwart"
                / "bootstrap.json"
            ),
            retire_recovery_attempt=root / "retire-recovery-attempt.json",
            retire_recovery_proof=root / "retire-recovery-proof.json",
            recovery_retired_receipt=root / "recovery-retired.json",
        )

    @property
    def dry_run_outputs(self) -> tuple[Path, ...]:
        return (
            self.settings,
            self.principals,
            self.converted_config,
            self.export,
            self.unmigrated,
        )


@dataclass(frozen=True, repr=False)
class VerifiedSource:
    checkout_root: Path
    provider_store: Path
    base_compose: Path
    compose_project: str
    compose_service: str

    def __repr__(self) -> str:
        return "VerifiedSource(<redacted>)"


@dataclass(frozen=True)
class VerifiedReceipt:
    snapshot: FileSnapshot


@dataclass(frozen=True)
class ApplyFile:
    """A fixed apply input represented without any file content."""

    path: Path
    sha256: str
    size: int
    identity: tuple[int, int, int, int, int, int]


@dataclass(frozen=True)
class ApplyOperation:
    """One exact, ordered operation from the reviewed export."""

    op: str
    object_name: str
    count: int = 1


@dataclass(frozen=True, repr=False)
class PostApplyCensusProof:
    """Safe result contract for a future authoritative live census verifier.

    This module only validates an injected proof. It intentionally performs no
    live management request itself.
    """

    operations_sha256: str
    operation_count: int
    server_version: str
    management_status: int

    def __repr__(self) -> str:
        return "PostApplyCensusProof(<redacted>)"


class RecoveryCredentialLease:
    """One closeable mutable in-memory recovery credential."""

    __slots__ = ("_closed", "_credential")

    def __init__(self, credential: bytearray) -> None:
        self._closed = False
        self._credential = credential
        if not _valid_recovery_credential_slice(
            credential,
            start=0,
            end=len(credential) if type(credential) is bytearray else 0,
        ):
            if type(credential) is bytearray:
                for index in range(len(credential)):
                    credential[index] = 0
            self._closed = True
            raise MigrationError("recovery credential lease is malformed")

    @property
    def closed(self) -> bool:
        return self._closed

    def borrow(self) -> memoryview:
        if self._closed:
            raise MigrationError("recovery credential lease is closed")
        return memoryview(self._credential).toreadonly()

    def close(self) -> None:
        if self._closed:
            return
        for index in range(len(self._credential)):
            self._credential[index] = 0
        self._closed = True

    def __enter__(self) -> "RecoveryCredentialLease":
        if self._closed:
            raise MigrationError("recovery credential lease is closed")
        return self

    def __exit__(
        self,
        _exception_type: object,
        _exception: object,
        _traceback: object,
    ) -> None:
        self.close()

    def __repr__(self) -> str:
        return "RecoveryCredentialLease(<redacted>)"


class _MigrationRuntimeCredentialCapability:
    """Cryptographic capability bound to one exact outer credential lease."""

    __slots__ = (
        "_closed",
        "_credential",
        "_credential_identity",
        "_key",
        "_message",
    )

    def __init__(
        self,
        credential: RecoveryCredentialLease,
        *,
        container_id: str,
        operations_sha256: str,
    ) -> None:
        if (
            type(credential) is not RecoveryCredentialLease
            or credential.closed
        ):
            raise MigrationError(
                "migration runtime credential capability is malformed",
            )
        self._credential = credential
        self._credential_identity = id(credential)
        self._key = bytearray(secrets.token_bytes(32))
        self._message = (
            f"{container_id}\0{operations_sha256}\0"
            f"{self._credential_identity}"
        ).encode("ascii")
        self._closed = False

    def tag(self) -> bytes:
        if self._closed:
            raise MigrationError(
                "migration runtime credential capability is closed",
            )
        return hmac.new(
            bytes(self._key),
            self._message,
            hashlib.sha256,
        ).digest()

    def _tag_for(
        self,
        *,
        container_id: object,
        operations_sha256: object,
    ) -> bytes:
        if (
            type(container_id) is not str
            or re.fullmatch(r"[0-9a-f]{64}", container_id) is None
            or type(operations_sha256) is not str
            or re.fullmatch(r"[0-9a-f]{64}", operations_sha256) is None
        ):
            raise MigrationError(
                "migration runtime credential capability binding changed",
            )
        message = (
            f"{container_id}\0{operations_sha256}\0"
            f"{self._credential_identity}"
        ).encode("ascii")
        return hmac.new(
            bytes(self._key),
            message,
            hashlib.sha256,
        ).digest()

    def borrow(
        self,
        tag: bytes,
        *,
        container_id: object,
        operations_sha256: object,
    ) -> memoryview:
        if self._closed:
            raise MigrationError(
                "migration runtime credential capability is closed",
            )
        if (
            type(tag) is not bytes
            or len(tag) != hashlib.sha256().digest_size
            or id(self._credential) != self._credential_identity
            or not hmac.compare_digest(
                self._tag_for(
                    container_id=container_id,
                    operations_sha256=operations_sha256,
                ),
                tag,
            )
        ):
            raise MigrationError(
                "migration runtime credential capability binding changed",
            )
        return self._credential.borrow()

    def assert_bound_to(
        self,
        credential: RecoveryCredentialLease,
        tag: bytes,
        *,
        container_id: object,
        operations_sha256: object,
    ) -> None:
        if (
            self._closed
            or self._credential is not credential
            or id(credential) != self._credential_identity
            or type(tag) is not bytes
            or not hmac.compare_digest(
                self._tag_for(
                    container_id=container_id,
                    operations_sha256=operations_sha256,
                ),
                tag,
            )
        ):
            raise MigrationError(
                "migration runtime credential capability binding changed",
            )

    def close(self) -> None:
        if self._closed:
            return
        _wipe_bytearray(self._key)
        self._closed = True


class MigrationBootstrapRuntime:
    """Bounded live runtime view exposed only while its credential lease is open."""

    __slots__ = (
        "_binding_tag",
        "_capability",
        "_container_id",
        "_operations_sha256",
    )

    def __init__(
        self,
        *,
        container_id: str,
        operations_sha256: str,
        credential: RecoveryCredentialLease,
    ) -> None:
        if (
            type(container_id) is not str
            or re.fullmatch(r"[0-9a-f]{64}", container_id) is None
            or type(operations_sha256) is not str
            or re.fullmatch(r"[0-9a-f]{64}", operations_sha256) is None
            or type(credential) is not RecoveryCredentialLease
            or credential.closed
        ):
            raise MigrationError("migration bootstrap runtime is malformed")
        capability = _MigrationRuntimeCredentialCapability(
            credential,
            container_id=container_id,
            operations_sha256=operations_sha256,
        )
        object.__setattr__(self, "_container_id", container_id)
        object.__setattr__(self, "_operations_sha256", operations_sha256)
        object.__setattr__(self, "_capability", capability)
        object.__setattr__(self, "_binding_tag", capability.tag())

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("migration bootstrap runtime is immutable")

    def __delattr__(self, _name: str) -> None:
        raise AttributeError("migration bootstrap runtime is immutable")

    @property
    def base_url(self) -> str:
        return MIGRATION_BOOTSTRAP_BASE_URL

    @property
    def api_url(self) -> str:
        return MIGRATION_BOOTSTRAP_API_URL

    @property
    def server_version(self) -> str:
        return "0.16.17"

    @property
    def container_id(self) -> str:
        return self._container_id

    @property
    def operations_sha256(self) -> str:
        return self._operations_sha256

    def borrow_recovery_credential(self) -> memoryview:
        return self._capability.borrow(
            self._binding_tag,
            container_id=self._container_id,
            operations_sha256=self._operations_sha256,
        )

    def _assert_bound_to(
        self,
        credential: RecoveryCredentialLease,
        capability: _MigrationRuntimeCredentialCapability,
    ) -> None:
        if self._capability is not capability:
            raise MigrationError(
                "migration runtime credential capability binding changed",
            )
        capability.assert_bound_to(
            credential,
            self._binding_tag,
            container_id=self._container_id,
            operations_sha256=self._operations_sha256,
        )

    def __repr__(self) -> str:
        return "MigrationBootstrapRuntime(<redacted>)"


@dataclass(frozen=True, repr=False)
class BootstrapRetirementBinding:
    """Secret-free commitment to the exact usable dashboard bootstrap."""

    bootstrap_receipt_sha256: str
    apply_receipt_sha256: str
    bootstrap_proof_sha256: str
    server_version: str
    authentication_status: int
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

    def __repr__(self) -> str:
        return "BootstrapRetirementBinding(<redacted>)"


@dataclass(frozen=True, repr=False)
class RecoveryRetirementProof:
    apply_receipt_sha256: str
    bootstrap_receipt_sha256: str
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
    account_projection_sha256: str
    api_key_projection_sha256: str
    retirement_attempt_sha256: str
    operation_plan_sha256: str
    server_version: str
    management_status: int
    readiness_status: int
    old_recovery_auth_status: int
    normal_url: str
    image_reference: str
    image_id: str
    container_id: str
    overlapping_writer_ids: tuple[str, ...]
    migration_container_ids: tuple[str, ...]
    recovery_environment_names: tuple[str, ...]

    def __repr__(self) -> str:
        return "RecoveryRetirementProof(<redacted>)"


@dataclass(frozen=True, repr=False)
class RecoveryArtifactBinding:
    """Content-free identity binding for one recovery-only host artifact."""

    path: Path
    size: int
    identity: tuple[int, int, int, int, int, int]

    def __repr__(self) -> str:
        return "RecoveryArtifactBinding(<redacted>)"


@dataclass(frozen=True, repr=False)
class RecoveryRetirementPlan:
    """Secret-free immutable handoff for one recovery retirement attempt."""

    inputs: tuple[ApplyFile, ...]
    artifacts: tuple[ApplyFile, ...]
    apply_receipt: ApplyFile
    apply_attempt: ApplyFile
    bootstrap_receipt: ApplyFile
    bootstrap: BootstrapRetirementBinding
    retirement_attempt: ApplyFile
    operation_plan_sha256: str
    operation_count: int
    runtime: MigrationRuntimePaths
    source: VerifiedSource
    recovery_config_directory_identity: tuple[int, int, int, int, int, int]
    recovery_config: RecoveryArtifactBinding
    recovery_environment: RecoveryArtifactBinding

    def __repr__(self) -> str:
        return "RecoveryRetirementPlan(<redacted>)"


@dataclass(frozen=True, repr=False)
class MigrationRuntimePaths:
    """Exact host paths for the dormant Stalwart migration Compose service."""

    data_dir: Path
    config_dir: Path
    recovery_env_file: Path
    compose_overlay: Path

    def __repr__(self) -> str:
        return "MigrationRuntimePaths(<redacted>)"

    def compose_environment(self) -> dict[str, str]:
        return {
            MIGRATION_DATA_VARIABLE: str(self.data_dir),
            MIGRATION_CONFIG_VARIABLE: str(self.config_dir),
            MIGRATION_RECOVERY_ENV_VARIABLE: str(self.recovery_env_file),
        }


@dataclass(frozen=True, repr=False)
class ApplyPlan:
    """Immutable, secret-free handoff for the exact reviewed operation plan."""

    inputs: tuple[ApplyFile, ...]
    artifacts: tuple[ApplyFile, ...]
    operations: tuple[ApplyOperation, ...]
    operations_sha256: str
    runtime: MigrationRuntimePaths
    source: VerifiedSource

    def __repr__(self) -> str:
        return "ApplyPlan(<redacted>)"


@dataclass(frozen=True, repr=False)
class _RuntimeArtifactFile:
    path: Path
    content: bytes
    sha256: str
    size: int
    identity: tuple[int, int, int, int, int, int]

    def __repr__(self) -> str:
        return "_RuntimeArtifactFile(<redacted>)"


@dataclass(frozen=True, repr=False)
class _RuntimeEnvironmentFile:
    """Content-free metadata for the wiped mutable recovery-env read."""

    path: Path
    sha256: str
    size: int
    identity: tuple[int, int, int, int, int, int]

    def __repr__(self) -> str:
        return "_RuntimeEnvironmentFile(<redacted>)"


@dataclass(frozen=True, repr=False)
class _RuntimeArtifactSnapshots:
    """Ephemeral recovery handoff state; never serialize this object directly."""

    config_directory_identity: tuple[int, int, int, int, int, int]
    config: _RuntimeArtifactFile
    recovery_environment: _RuntimeEnvironmentFile

    def __repr__(self) -> str:
        return "_RuntimeArtifactSnapshots(<redacted>)"


@dataclass(frozen=True, repr=False)
class _ValidatedApply:
    plan: ApplyPlan
    source: VerifiedSource
    identities: tuple[tuple[Path, tuple[int, int, int, int, int, int]], ...]
    runtime_artifacts: _RuntimeArtifactSnapshots | None

    def __repr__(self) -> str:
        return "_ValidatedApply(<redacted>)"


@dataclass(frozen=True, repr=False)
class RollbackEndpoint:
    base_url: str
    username: str
    password: str
    version: str

    def __repr__(self) -> str:
        return (
            "RollbackEndpoint("
            f"base_url={self.base_url!r}, username={self.username!r}, "
            f"version={self.version!r}, password=<redacted>)"
        )


@dataclass(frozen=True, repr=False)
class RollbackResult:
    value: object
    proof: dict[str, object]

    def __repr__(self) -> str:
        return "RollbackResult(value=<redacted>, proof=<validated>)"


@dataclass(frozen=True, repr=False)
class IsolatedSource:
    url: str
    username: str
    password: str

    def __repr__(self) -> str:
        return (
            "IsolatedSource("
            f"url={self.url!r}, username={self.username!r}, password=<redacted>)"
        )


ROLLBACK_VERSION_PATTERN = re.compile(
    r"^v?0\.15\.[0-9]+(?:[-+][A-Za-z0-9_.-]+)?$",
)


def validate_rollback_endpoint(value: object) -> RollbackEndpoint:
    try:
        base_url = value.base_url
        username = value.username
        password = value.password
        version = value.version
    except (AttributeError, TypeError):
        raise MigrationError("verified rollback endpoint is malformed") from None
    if (
        not isinstance(base_url, str)
        or not isinstance(username, str)
        or not isinstance(password, str)
        or not isinstance(version, str)
    ):
        raise MigrationError("verified rollback endpoint is malformed")
    match = re.fullmatch(r"http://127\.0\.0\.1:([0-9]{1,5})", base_url)
    port = int(match.group(1)) if match is not None else 0
    if (
        match is None
        or port <= 1024
        or port > 65535
        or not username.strip()
        or not password
        or ROLLBACK_VERSION_PATTERN.fullmatch(version) is None
    ):
        raise MigrationError("verified rollback endpoint is incomplete or unsafe")
    return RollbackEndpoint(
        base_url=base_url,
        username=username,
        password=password,
        version=version,
    )


def _validate_rollback_result(value: object) -> RollbackResult:
    try:
        operation_value = value.value
        raw_proof = value.proof
    except (AttributeError, TypeError):
        raise MigrationError("verified rollback result is malformed") from None
    expected_fields = {"management_status", "proved_at", "version"}
    if isinstance(raw_proof, dict):
        if set(raw_proof) != expected_fields:
            raise MigrationError("verified rollback proof is malformed")
        proof = dict(raw_proof)
    elif is_dataclass(raw_proof) and not isinstance(raw_proof, type):
        if {field.name for field in fields(raw_proof)} != expected_fields:
            raise MigrationError("verified rollback proof is malformed")
        try:
            proof = {
                name: getattr(raw_proof, name)
                for name in expected_fields
            }
        except (AttributeError, TypeError):
            raise MigrationError("verified rollback proof is malformed") from None
    else:
        raise MigrationError("verified rollback proof is malformed")
    if (
        type(proof.get("management_status")) is not int
        or proof.get("management_status") != 200
        or not isinstance(proof.get("proved_at"), str)
        or re.fullmatch(r"\d{8}T\d{6}Z", str(proof["proved_at"])) is None
        or not isinstance(proof.get("version"), str)
        or ROLLBACK_VERSION_PATTERN.fullmatch(str(proof["version"])) is None
    ):
        raise MigrationError("verified rollback proof is malformed")
    return RollbackResult(operation_value, dict(proof))


def _load_capture_application() -> object:
    capture_path = REPOSITORY_ROOT / "scripts" / "capture_stalwart_v015.py"
    require_regular(
        capture_path,
        root=REPOSITORY_ROOT,
        label="Task 5 capture runtime",
    )
    module_name = "_mail_sandbox_capture_stalwart_v015"
    spec = importlib.util.spec_from_file_location(module_name, capture_path)
    if spec is None or spec.loader is None:
        raise MigrationError("Task 5 capture runtime could not be loaded safely")
    module = importlib.util.module_from_spec(spec)
    previous = sys.modules.get(module_name)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        raise MigrationError("Task 5 capture runtime could not be loaded safely") from None
    finally:
        if previous is None:
            sys.modules.pop(module_name, None)
        else:
            sys.modules[module_name] = previous
    application_type = getattr(module, "CaptureApplication", None)
    if not callable(application_type):
        raise MigrationError("Task 5 capture runtime is incomplete")
    application = application_type()
    if not callable(getattr(application, "run_verified_rollback", None)):
        raise MigrationError("Task 5 capture runtime lacks the verified rollback executor")
    return application


def default_rollback_executor(
    receipt_path: Path,
    expected_receipt_sha256: str,
    operation: Callable[[object], object],
) -> RollbackResult:
    if (
        not isinstance(receipt_path, Path)
        or not receipt_path.is_absolute()
        or re.fullmatch(r"[0-9a-f]{64}", expected_receipt_sha256) is None
        or not callable(operation)
    ):
        raise MigrationError("verified rollback executor inputs are malformed")
    try:
        application = _load_capture_application()
        result = application.run_verified_rollback(
            receipt_path,
            expected_receipt_sha256=expected_receipt_sha256,
            operation=operation,
        )
    except MigrationError:
        raise
    except Exception:
        raise MigrationError("verified rollback executor failed safely") from None
    return _validate_rollback_result(result)


def default_rollback_activator(
    receipt_path: Path,
    *,
    expected_receipt_sha256: str,
) -> object:
    """Start and verify the frozen v0.15 rollback runtime."""
    if (
        not isinstance(receipt_path, Path)
        or not receipt_path.is_absolute()
        or type(expected_receipt_sha256) is not str
        or re.fullmatch(r"[0-9a-f]{64}", expected_receipt_sha256) is None
    ):
        raise MigrationError("verified rollback activation inputs are malformed")
    try:
        application = _load_capture_application()
        activator = getattr(application, "activate_verified_rollback", None)
        if not callable(activator):
            raise MigrationError(
                "Task 5 capture runtime lacks verified rollback activation",
            )
        return activator(
            receipt_path,
            expected_receipt_sha256=expected_receipt_sha256,
        )
    except MigrationError:
        raise
    except Exception:
        raise MigrationError(
            "verified rollback activation failed safely",
        ) from None


def _validate_migration_python(value: str) -> None:
    if not value or not Path(value).is_absolute():
        raise MigrationError("migration interpreter must be an absolute path")


def build_dump_command(
    migration_python: str,
    paths: MigrationPaths,
    source: IsolatedSource,
) -> list[str]:
    _validate_migration_python(migration_python)
    if (
        not re.fullmatch(r"http://127\.0\.0\.1:[1-9][0-9]{3,4}", source.url)
        or not source.username
        or not source.password
    ):
        raise MigrationError("isolated source handoff is incomplete or unsafe")
    return [
        migration_python,
        str(paths.migration_script),
        "dump",
        "--url",
        source.url,
        "--username",
        source.username,
        "--password",
        source.password,
        "--settings",
        str(paths.settings),
        "--principals",
        str(paths.principals),
    ]


def build_convert_command(
    migration_python: str,
    paths: MigrationPaths,
) -> list[str]:
    _validate_migration_python(migration_python)
    return [
        migration_python,
        str(paths.migration_script),
        "convert",
        "--settings",
        str(paths.settings),
        "--principals",
        str(paths.principals),
        "--config",
        str(paths.converted_config),
        "--output",
        str(paths.export),
        "--patch-paths",
        "/opt/stalwart/data=/var/lib/stalwart",
        "--patch-paths",
        "/opt/stalwart=/var/lib/stalwart",
        "--unmigrated-output",
        str(paths.unmigrated),
    ]


def check_migration_python(
    migration_python: str,
    *,
    runner: object = run_command,
) -> None:
    _validate_migration_python(migration_python)
    try:
        runner([migration_python, "-c", "import requests, urllib3"])
    except MigrationError:
        raise MigrationError(
            "migration interpreter requires requests and urllib3",
        ) from None


def _validate_apply_operation(operation: object) -> ApplyOperation:
    if (
        not isinstance(operation, ApplyOperation)
        or operation.op not in {"create", "update"}
        or not isinstance(operation.object_name, str)
        or not operation.object_name
        or operation.object_name.strip() != operation.object_name
        or len(operation.object_name) > 1024
        or any(ord(character) < 0x20 for character in operation.object_name)
        or type(operation.count) is not int
        or operation.count <= 0
        or (operation.op == "update" and operation.count != 1)
    ):
        raise MigrationError("apply operation contract is malformed")
    return operation


def _operation_plan_value(
    operations: tuple[ApplyOperation, ...],
) -> list[dict[str, object]]:
    return [
        {
            "op": _validate_apply_operation(operation).op,
            "object": operation.object_name,
            "count": operation.count,
        }
        for operation in operations
    ]


def apply_operation_plan_sha256(
    operations: tuple[ApplyOperation, ...],
) -> str:
    """Return the safe digest of an exact ordered export operation plan."""
    if not isinstance(operations, tuple) or not operations:
        raise MigrationError("apply operation plan is empty or malformed")
    return hashlib.sha256(
        _canonical_json_bytes(_operation_plan_value(operations)),
    ).hexdigest()


def _expected_apply_counts(
    operations: tuple[ApplyOperation, ...],
) -> tuple[dict[str, int], dict[str, int]]:
    creates = sum(operation.op == "create" for operation in operations)
    create_objects = sum(
        operation.count
        for operation in operations
        if operation.op == "create"
    )
    updates = sum(operation.op == "update" for operation in operations)
    plan = {
        "destroys": 0,
        "updates": updates,
        "creates": creates,
        "create_objects": create_objects,
        "upserts": 0,
        "upsert_objects": 0,
    }
    done = {
        "destroyed": 0,
        "updated": updates,
        "created": create_objects,
        "failed": 0,
    }
    return plan, done


def validate_apply_ndjson(
    stdout: str,
    *,
    expected_operations: tuple[ApplyOperation, ...],
) -> dict[str, object]:
    """Validate exact ordered executor evidence against the reviewed export."""
    if not isinstance(stdout, str):
        raise MigrationError("apply evidence must be UTF-8 text")
    if not isinstance(expected_operations, tuple) or not expected_operations:
        raise MigrationError("expected apply operation plan is malformed")
    for operation in expected_operations:
        _validate_apply_operation(operation)
    lines = stdout.splitlines()
    if not lines or any(not line.strip() for line in lines):
        raise MigrationError("apply evidence is empty or malformed")
    records: list[dict[str, object]] = []
    for line in lines:
        try:
            record = json.loads(
                line,
                object_pairs_hook=_strict_json_object,
            )
        except (json.JSONDecodeError, ValueError):
            raise MigrationError("apply evidence is malformed NDJSON") from None
        if not isinstance(record, dict):
            raise MigrationError("apply evidence records must be JSON objects")
        records.append(record)
    summaries = [
        (index, record)
        for index, record in enumerate(records)
        if record.get("op") == "summary"
    ]
    if len(summaries) != 1 or summaries[0][0] != len(records) - 1:
        raise MigrationError("apply evidence requires exactly one final summary")
    if len(records) - 1 != len(expected_operations):
        raise MigrationError("apply evidence operation count does not match export")
    for index, (record, expected) in enumerate(
        zip(records[:-1], expected_operations, strict=True),
    ):
        if (
            set(record) != {"op", "object", "index", "count", "status"}
            or record.get("op") != expected.op
            or record.get("object") != expected.object_name
            or type(record.get("index")) is not int
            or record.get("index") != index
            or type(record.get("count")) is not int
            or record.get("count") != expected.count
            or record.get("status") != "ok"
        ):
            raise MigrationError(
                "apply evidence does not match the ordered export plan",
            )
    summary = summaries[0][1]
    plan = summary.get("plan")
    done = summary.get("done")
    expected_plan, expected_done = _expected_apply_counts(expected_operations)
    if (
        set(summary) != {"op", "plan", "done"}
        or not isinstance(plan, dict)
        or set(plan)
        != {
            "destroys",
            "updates",
            "creates",
            "create_objects",
            "upserts",
            "upsert_objects",
        }
        or any(
            type(value) is not int or value < 0
            for value in plan.values()
        )
        or not isinstance(done, dict)
        or set(done) != {"destroyed", "updated", "created", "failed"}
        or any(
            type(value) is not int or value < 0
            for value in done.values()
        )
        or plan != expected_plan
        or done != expected_done
    ):
        raise MigrationError("apply summary does not match the export plan")
    return summary


def prepare_dry_run(
    paths: MigrationPaths,
    *,
    script_path: Path,
    receipt_path: Path,
    runner: object = run_command,
    python_executable: str,
    migration_python: str,
    rollback_executor: object = default_rollback_executor,
    clock: object | None = None,
    expected_script_sha256: str = MIGRATION_SCRIPT_SHA256,
) -> Path:
    """Produce a digest-bound dry-run receipt from an isolated v0.15 source."""
    if script_path != paths.migration_script:
        raise MigrationError("migration script is not the fixed repository path")
    if receipt_path != paths.source_receipt:
        raise MigrationError("source receipt is not the fixed repository path")
    if not callable(rollback_executor):
        raise MigrationError("verified rollback executor is unavailable")
    verified_receipt = verify_source_capture(
        paths,
        receipt_path,
        runner=runner,
        python_executable=python_executable,
    )
    source = load_verified_source(paths, verified_receipt, runner=runner)
    assert_no_running_store_writers(
        paths,
        source_store=source.provider_store,
        runner=runner,
    )
    script_digest = validate_migration_script(
        paths,
        script_path,
        expected_sha256=expected_script_sha256,
    )
    if (
        not isinstance(script_digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", script_digest) is None
    ):
        raise MigrationError("migration script validation returned no stable digest")
    for output in (*paths.dry_run_outputs, paths.dry_run_receipt):
        if output.exists() or output.is_symlink():
            raise MigrationError("dry-run output already exists; refusing to overwrite it")
        if output.parent != paths.migration_root:
            raise MigrationError("dry-run output path escaped the fixed migration root")
    check_migration_python(migration_python, runner=runner)
    callback_count = 0
    dump_completed = False
    used_endpoint_version: str | None = None

    def dump_from_verified_rollback(raw_endpoint: object) -> None:
        nonlocal callback_count, dump_completed, used_endpoint_version
        callback_count += 1
        if callback_count != 1:
            raise MigrationError("verified rollback operation ran more than once")
        endpoint = validate_rollback_endpoint(raw_endpoint)
        used_endpoint_version = endpoint.version.removeprefix("v")
        runner(
            build_dump_command(
                migration_python,
                paths,
                IsolatedSource(
                    url=endpoint.base_url,
                    username=endpoint.username,
                    password=endpoint.password,
                ),
            ),
        )
        dump_completed = True

    try:
        raw_execution = rollback_executor(
            receipt_path,
            verified_receipt.snapshot.sha256,
            dump_from_verified_rollback,
        )
    except MigrationError:
        raise
    except Exception:
        raise MigrationError("verified rollback session failed safely") from None
    execution = _validate_rollback_result(raw_execution)
    if (
        callback_count != 1
        or not dump_completed
        or used_endpoint_version is None
        or execution.value is not None
        or str(execution.proof["version"]).removeprefix("v")
        != used_endpoint_version
    ):
        raise MigrationError("verified rollback execution result does not match the dump")
    for path, label in (
        (paths.settings, "dumped settings"),
        (paths.principals, "dumped principals"),
    ):
        _read_regular_snapshot(
            path,
            root=paths.repository_root,
            label=label,
            maximum=16 * 1024 * 1024,
            required_mode=0o600,
        )
    runner(build_convert_command(migration_python, paths))
    _ensure_unmigrated_report(paths)
    for path in paths.dry_run_outputs:
        _read_regular_snapshot(
            path,
            root=paths.repository_root,
            label=f"dry-run output {path.name}",
            maximum=16 * 1024 * 1024,
            required_mode=0o600,
        )
    validate_converted_outputs(paths)
    receipt = create_dry_run_receipt(
        paths,
        source_receipt_sha256=verified_receipt.snapshot.sha256,
        migration_script_sha256=script_digest,
        rollback_proof=execution.proof,
        clock=clock,
    )
    validate_dry_run_receipt(paths, receipt)
    return receipt


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def validate_digest_envelope(value: object) -> dict[str, object]:
    """Validate the generic digest envelope shared with the Task 5 receipt."""
    if not isinstance(value, dict) or set(value) != {"payload", "payload_sha256"}:
        raise MigrationError("receipt envelope is malformed")
    payload = value.get("payload")
    expected = value.get("payload_sha256")
    if not isinstance(payload, dict) or not isinstance(expected, str):
        raise MigrationError("receipt envelope is malformed")
    observed = hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()
    if not secrets.compare_digest(observed, expected):
        raise MigrationError("receipt payload digest does not match")
    return payload


def _read_regular_bytes(
    path: Path,
    *,
    root: Path,
    label: str,
    maximum: int,
) -> bytes:
    descriptor, before = _open_regular_readonly(path, root=root, label=label)
    chunks: list[bytes] = []
    total = 0
    try:
        while chunk := os.read(descriptor, min(1024 * 1024, maximum + 1 - total)):
            total += len(chunk)
            if total > maximum:
                raise MigrationError(f"{label} is too large")
            chunks.append(chunk)
        after = os.fstat(descriptor)
    except OSError as exc:
        raise MigrationError(f"{label} could not be read safely") from exc
    finally:
        os.close(descriptor)
    if (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ):
        raise MigrationError(f"{label} changed while it was read")
    return b"".join(chunks)


def _require_absolute_no_symlinks(path: Path, label: str) -> None:
    _plain_absolute(path, label)
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current = current / component
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise MigrationError(f"{label} is unavailable") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise MigrationError(f"{label} must not contain symlinks")


def _git_common_directory(
    checkout: Path,
    *,
    runner: object,
) -> Path:
    result = runner(
        [
            "git",
            "-C",
            str(checkout),
            "rev-parse",
            "--path-format=absolute",
            "--git-common-dir",
        ],
    )
    value = _command_stdout(result, "Git common-directory lookup").strip()
    candidate = Path(value)
    if (
        not value
        or not candidate.is_absolute()
        or Path(os.path.normpath(value)) != candidate
    ):
        raise MigrationError("Git common-directory lookup is malformed")
    return candidate


def load_verified_source(
    paths: MigrationPaths,
    verified_receipt: VerifiedReceipt,
    *,
    runner: object = run_command,
) -> VerifiedSource:
    """Load only the source identity from an already Task-5-verified receipt."""
    if (
        not isinstance(verified_receipt, VerifiedReceipt)
        or verified_receipt.snapshot.path != paths.source_receipt
    ):
        raise MigrationError("source receipt was not verified for the fixed path")
    raw = verified_receipt.snapshot.content
    try:
        envelope = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise MigrationError("source receipt is not valid JSON") from None
    payload = validate_digest_envelope(envelope)
    source = payload.get("source")
    if not isinstance(source, dict):
        raise MigrationError("source receipt payload is incomplete")
    checkout_value = source.get("compose_working_directory")
    store_value = source.get("data_path")
    compose_files_value = source.get("compose_config_files")
    compose_project = source.get("compose_project")
    compose_service = source.get("compose_service")
    if (
        not isinstance(checkout_value, str)
        or not isinstance(store_value, str)
        or not isinstance(compose_files_value, list)
        or len(compose_files_value) != 1
        or not isinstance(compose_files_value[0], str)
        or not isinstance(compose_project, str)
        or not isinstance(compose_service, str)
    ):
        raise MigrationError("source receipt store identity is incomplete")
    checkout = _plain_absolute(Path(checkout_value), "source checkout")
    provider_store = _plain_absolute(Path(store_value), "source provider store")
    base_compose = _plain_absolute(
        Path(compose_files_value[0]),
        "source base Compose file",
    )
    if provider_store != checkout / "stalwart-data":
        raise MigrationError("source receipt provider store is not the fixed legacy path")
    if base_compose != checkout / "docker-compose.yml":
        raise MigrationError("source receipt Compose file is not the fixed base path")
    if (
        COMPOSE_PROJECT_PATTERN.fullmatch(compose_project) is None
        or COMPOSE_SERVICE_PATTERN.fullmatch(compose_service) is None
    ):
        raise MigrationError("source receipt Compose identity is malformed")
    _require_absolute_no_symlinks(checkout, "source checkout")
    checkout_metadata = _require_real_directory(checkout, "source checkout")
    if not stat.S_ISDIR(checkout_metadata.st_mode):
        raise MigrationError("source checkout must be a directory")
    _require_absolute_no_symlinks(provider_store, "source provider store")
    _require_real_directory(provider_store, "source provider store")
    _require_absolute_no_symlinks(base_compose, "source base Compose file")
    try:
        base_compose_metadata = base_compose.lstat()
    except OSError as exc:
        raise MigrationError("source base Compose file is unavailable") from exc
    if (
        stat.S_ISLNK(base_compose_metadata.st_mode)
        or not stat.S_ISREG(base_compose_metadata.st_mode)
    ):
        raise MigrationError("source base Compose file must be a regular file")
    git_directory = checkout / ".git"
    _require_absolute_no_symlinks(git_directory, "source Git directory")
    _require_real_directory(git_directory, "source Git directory")
    source_common = _git_common_directory(checkout, runner=runner)
    invocation_common = _git_common_directory(paths.repository_root, runner=runner)
    if source_common != invocation_common or source_common != git_directory:
        raise MigrationError(
            "source receipt does not identify the primary checkout of this repository",
        )
    return VerifiedSource(
        checkout_root=checkout,
        provider_store=provider_store,
        base_compose=base_compose,
        compose_project=compose_project,
        compose_service=compose_service,
    )


def _command_stdout(result: object, label: str) -> str:
    if not isinstance(result, CommandResult):
        raise MigrationError(f"{label} returned malformed output")
    return result.stdout


def _paths_overlap(first: Path, second: Path) -> bool:
    try:
        first.relative_to(second)
        return True
    except ValueError:
        pass
    try:
        second.relative_to(first)
        return True
    except ValueError:
        return False


def assert_no_running_store_writers(
    paths: MigrationPaths,
    *,
    source_store: Path,
    runner: object = run_command,
) -> None:
    """Fail closed if any running bind mount can write either Stalwart store."""
    ps_result = runner(
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
    container_ids = [
        line.strip()
        for line in _command_stdout(ps_result, "running-container census").splitlines()
        if line.strip()
    ]
    if (
        any(re.fullmatch(r"[0-9a-f]{64}", value) is None for value in container_ids)
        or len(container_ids) != len(set(container_ids))
    ):
        raise MigrationError("running-container census is malformed or ambiguous")
    if not container_ids:
        return
    inspect_result = runner(["docker", "inspect", *container_ids])
    try:
        records = json.loads(_command_stdout(inspect_result, "container inspection"))
    except json.JSONDecodeError:
        raise MigrationError("container inspection is malformed or ambiguous") from None
    if not isinstance(records, list) or len(records) != len(container_ids):
        raise MigrationError("container inspection is malformed or ambiguous")
    by_id: dict[str, dict[str, object]] = {}
    for record in records:
        if not isinstance(record, dict):
            raise MigrationError("container inspection is malformed or ambiguous")
        container_id = record.get("Id")
        if (
            not isinstance(container_id, str)
            or container_id not in container_ids
            or container_id in by_id
        ):
            raise MigrationError("container inspection is malformed or ambiguous")
        by_id[container_id] = record
    if set(by_id) != set(container_ids):
        raise MigrationError("container inspection is malformed or ambiguous")
    if (
        not source_store.is_absolute()
        or Path(os.path.normpath(str(source_store))) != source_store
        or source_store.name != "stalwart-data"
    ):
        raise MigrationError("verified source store path is malformed")
    protected_stores = (source_store, paths.scratch_store)
    for container_id in container_ids:
        record = by_id[container_id]
        state = record.get("State")
        mounts = record.get("Mounts")
        if (
            not isinstance(state, dict)
            or state.get("Running") is not True
            or not isinstance(mounts, list)
        ):
            raise MigrationError("container inspection is malformed or ambiguous")
        for mount in mounts:
            if not isinstance(mount, dict) or not isinstance(mount.get("Type"), str):
                raise MigrationError("container inspection is malformed or ambiguous")
            if mount["Type"] != "bind":
                continue
            source_value = mount.get("Source")
            writable = mount.get("RW")
            if not isinstance(source_value, str) or not isinstance(writable, bool):
                raise MigrationError("container bind-mount inspection is malformed")
            source = Path(source_value)
            if (
                not source.is_absolute()
                or Path(os.path.normpath(source_value)) != source
            ):
                raise MigrationError("container bind-mount inspection is malformed")
            if writable and any(
                _paths_overlap(source, store) for store in protected_stores
            ):
                raise MigrationError("a Stalwart store has a running writer")


def validate_export_inventory(
    paths: MigrationPaths,
    candidates: list[Path],
) -> tuple[dict[str, object], ...]:
    """Return content-free metadata for explicitly approved regular files."""
    if not isinstance(candidates, list) or not candidates:
        raise MigrationError("export inventory must contain at least one file")
    if len(candidates) != len(set(candidates)):
        raise MigrationError("export inventory contains duplicate files")
    dashboard_runtime = (
        paths.repository_root / "debug-dashboard" / ".runtime"
    )
    protected_roots = (
        dashboard_runtime / "stalwart",
        dashboard_runtime / "keys",
        dashboard_runtime / "quarantine",
        dashboard_runtime / "stalwart-gate0b",
        paths.repository_root / "stalwart-data",
    )
    inventory: list[dict[str, object]] = []
    for candidate in sorted(candidates):
        _require_below(paths.repository_root, candidate, "export inventory file")
        if any(
            candidate == protected or protected in candidate.parents
            for protected in protected_roots
        ):
            if paths.repository_root / "stalwart-data" in candidate.parents:
                raise MigrationError("export inventory refuses RocksDB provider files")
            raise MigrationError("export inventory path is protected")
        lowered_name = candidate.name.lower()
        if lowered_name == "lock" or lowered_name.endswith(".lock"):
            raise MigrationError("export inventory refuses lock files")
        if (
            re.search(
                r"(^|[._-])"
                r"(secret|secrets|password|credential|credentials|token|private|key|keys)"
                r"([._-]|$)",
                lowered_name,
            )
            is not None
            or lowered_name.endswith(".env")
        ):
            raise MigrationError("export inventory refuses secret-bearing files")
        parent = _require_real_directory(candidate.parent, "export inventory parent")
        if stat.S_IMODE(parent.st_mode) != 0o700:
            raise MigrationError("export inventory parent must have mode 0700")
        snapshot = _read_regular_snapshot(
            candidate,
            root=paths.repository_root,
            label="export inventory file",
            maximum=16 * 1024 * 1024,
            required_mode=0o600,
        )
        content = snapshot.content.lower()
        secret_markers = (
            b"admin_secret=",
            b"password=",
            b'"password"',
            b'"secret"',
            b'"secrets"',
            b'"credentials"',
            b"-----begin private key-----",
            b"authorization: bearer ",
        )
        if any(marker in content for marker in secret_markers):
            raise MigrationError("export inventory refuses secret-bearing files")
        inventory.append(
            {
                "path": candidate.relative_to(paths.repository_root).as_posix(),
                "sha256": snapshot.sha256,
                "size": snapshot.size,
            },
        )
    return tuple(inventory)


def _contains_legacy_path(value: object) -> bool:
    if isinstance(value, str):
        return "/opt/stalwart" in value
    if isinstance(value, dict):
        return any(_contains_legacy_path(nested) for nested in value.values())
    if isinstance(value, list):
        return any(_contains_legacy_path(nested) for nested in value)
    return False


def _require_exact_converted_config_bytes(raw: bytes) -> None:
    if (
        type(raw) is not bytes
        or raw != CONVERTED_CONFIG_BYTES
        or not secrets.compare_digest(
            hashlib.sha256(raw).hexdigest(),
            CONVERTED_CONFIG_SHA256,
        )
    ):
        raise MigrationError(
            "converted config bytes do not match the pinned converter output",
        )


def validate_converted_outputs(paths: MigrationPaths) -> None:
    raw_outputs: dict[Path, bytes] = {}
    for path, label in (
        (paths.converted_config, "converted config"),
        (paths.export, "converted export"),
    ):
        require_regular_0600(
            path,
            root=paths.repository_root,
            label=label,
        )
        raw = _read_regular_bytes(
            path,
            root=paths.repository_root,
            label=label,
            maximum=16 * 1024 * 1024,
        )
        if b"/opt/stalwart" in raw:
            raise MigrationError("converted outputs retain a legacy Stalwart path")
        raw_outputs[path] = raw
    _require_exact_converted_config_bytes(
        raw_outputs[paths.converted_config],
    )
    try:
        store = json.loads(raw_outputs[paths.converted_config].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise MigrationError("converted config is not valid JSON") from None
    if _contains_legacy_path(store):
        raise MigrationError("converted outputs retain a decoded legacy Stalwart path")
    if store != {"@type": "RocksDb", "path": "/var/lib/stalwart"}:
        raise MigrationError(
            "converted config DataStore must be RocksDb at /var/lib/stalwart",
        )
    try:
        lines = raw_outputs[paths.export].decode("utf-8").splitlines()
    except UnicodeDecodeError:
        raise MigrationError("converted export is not valid UTF-8 NDJSON") from None
    if not lines or any(not line.strip() for line in lines):
        raise MigrationError("converted export is empty or malformed NDJSON")
    for line in lines:
        try:
            operation = json.loads(line)
        except json.JSONDecodeError:
            raise MigrationError("converted export is malformed NDJSON") from None
        if _contains_legacy_path(operation):
            raise MigrationError("converted outputs retain a decoded legacy Stalwart path")
        if (
            not isinstance(operation, dict)
            or set(operation) != {"@type", "object", "value"}
            or operation.get("@type") not in {"create", "update"}
            or not isinstance(operation.get("object"), str)
            or not str(operation["object"]).strip()
            or not isinstance(operation.get("value"), dict)
        ):
            raise MigrationError("converted export operation schema is invalid")


REVIEW_SCHEMA = "mail-sandbox.stalwart-v016-review.v1"
DRY_RUN_SCHEMA = "mail-sandbox.stalwart-v016-dry-run.v1"
APPLY_ATTEMPT_SCHEMA = "mail-sandbox.stalwart-v016-apply-attempt.v1"
APPLY_SCHEMA = "mail-sandbox.stalwart-v016-apply.v2"
RETIRE_RECOVERY_ATTEMPT_SCHEMA = (
    "mail-sandbox.stalwart-v016-retire-recovery-attempt.v3"
)
RETIRE_RECOVERY_PROOF_SCHEMA = (
    "mail-sandbox.stalwart-v016-retire-recovery-proof.v3"
)
RECOVERY_RETIRED_SCHEMA = "mail-sandbox.stalwart-v016-recovery-retired.v3"


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _write_new_json_0600(
    target: Path,
    value: object,
    *,
    root: Path,
    preserve_published_on_failure: bool = False,
) -> None:
    _require_below(root, target, "receipt target")
    _require_no_symlink_components(root, target.parent, "receipt parent")
    if target.exists() or target.is_symlink():
        raise MigrationError("receipt target already exists")
    temporary = target.parent / f".{target.name}.{secrets.token_hex(8)}.tmp"
    if temporary.exists() or temporary.is_symlink():
        raise MigrationError("receipt temporary path already exists")
    descriptor: int | None = None
    published_identity: tuple[int, int] | None = None
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
        content = _canonical_json_bytes(value) + b"\n"
        opened = os.fstat(descriptor)
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise MigrationError("receipt write did not progress")
            view = view[written:]
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.link(temporary, target, follow_symlinks=False)
        published_identity = (opened.st_dev, opened.st_ino)
        temporary.unlink()
        parent_descriptor = os.open(
            target.parent,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
    except BaseException as exc:
        if published_identity is not None and not preserve_published_on_failure:
            try:
                published = target.lstat()
                if (
                    not stat.S_ISLNK(published.st_mode)
                    and (published.st_dev, published.st_ino) == published_identity
                ):
                    target.unlink()
                    parent_descriptor = os.open(
                        target.parent,
                        os.O_RDONLY
                        | getattr(os, "O_DIRECTORY", 0)
                        | getattr(os, "O_CLOEXEC", 0),
                    )
                    try:
                        os.fsync(parent_descriptor)
                    finally:
                        os.close(parent_descriptor)
            except BaseException:
                pass
        if isinstance(exc, MigrationError):
            raise
        if isinstance(exc, OSError):
            raise MigrationError("receipt could not be written safely") from None
        raise
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary.exists() and not temporary.is_symlink():
            temporary.unlink()


def _write_new_empty_0600(target: Path, *, root: Path) -> None:
    _require_below(root, target, "empty output target")
    _require_no_symlink_components(root, target.parent, "empty output parent")
    descriptor: int | None = None
    try:
        descriptor = os.open(
            target,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        parent_descriptor = os.open(
            target.parent,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
    except OSError as exc:
        raise MigrationError("empty output could not be created safely") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _ensure_unmigrated_report(paths: MigrationPaths) -> None:
    if not paths.unmigrated.exists() and not paths.unmigrated.is_symlink():
        _write_new_empty_0600(
            paths.unmigrated,
            root=paths.repository_root,
        )
    _read_regular_snapshot(
        paths.unmigrated,
        root=paths.repository_root,
        label="unmigrated report",
        maximum=16 * 1024 * 1024,
        required_mode=0o600,
    )


def _dry_run_timestamp(clock: object | None) -> str:
    if clock is None:
        value = _utc_timestamp()
    elif callable(clock):
        value = clock()
    else:
        raise MigrationError("dry-run receipt clock is unavailable")
    if (
        not isinstance(value, str)
        or re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value) is None
    ):
        raise MigrationError("dry-run receipt timestamp is malformed")
    return value


def _dry_run_output_snapshots(
    paths: MigrationPaths,
) -> tuple[FileSnapshot, ...]:
    return tuple(
        _read_regular_snapshot(
            path,
            root=paths.repository_root,
            label=f"dry-run output {path.name}",
            maximum=16 * 1024 * 1024,
            required_mode=0o600,
        )
        for path in paths.dry_run_outputs
    )


def create_dry_run_receipt(
    paths: MigrationPaths,
    *,
    source_receipt_sha256: str,
    migration_script_sha256: str,
    rollback_proof: dict[str, object],
    clock: object | None = None,
) -> Path:
    _require_owner_migration_root(paths)
    if (
        re.fullmatch(r"[0-9a-f]{64}", source_receipt_sha256) is None
        or re.fullmatch(r"[0-9a-f]{64}", migration_script_sha256) is None
    ):
        raise MigrationError("dry-run receipt input digest is malformed")
    source_snapshot = _read_regular_snapshot(
        paths.source_receipt,
        root=paths.repository_root,
        label="source receipt",
        maximum=4 * 1024 * 1024,
        required_mode=0o600,
    )
    script_snapshot = _read_regular_snapshot(
        paths.migration_script,
        root=paths.repository_root,
        label="migration script",
        maximum=4 * 1024 * 1024,
        required_mode=0o600,
    )
    if (
        not secrets.compare_digest(
            source_snapshot.sha256,
            source_receipt_sha256,
        )
        or not secrets.compare_digest(
            script_snapshot.sha256,
            migration_script_sha256,
        )
    ):
        raise MigrationError("dry-run receipt inputs changed after validation")
    validated_proof = _validate_rollback_result(
        RollbackResult(None, rollback_proof),
    ).proof
    output_snapshots = _dry_run_output_snapshots(paths)
    payload = {
        "schema": DRY_RUN_SCHEMA,
        "created_at": _dry_run_timestamp(clock),
        "source_receipt_sha256": source_receipt_sha256,
        "migration_script_sha256": migration_script_sha256,
        "rollback": validated_proof,
        "outputs": [
            {
                "name": snapshot.path.name,
                "sha256": snapshot.sha256,
                "size": snapshot.size,
            }
            for snapshot in output_snapshots
        ],
    }
    _write_new_json_0600(
        paths.dry_run_receipt,
        payload,
        root=paths.repository_root,
    )
    return paths.dry_run_receipt


def validate_dry_run_receipt(
    paths: MigrationPaths,
    receipt_path: Path,
) -> dict[str, object]:
    if receipt_path != paths.dry_run_receipt:
        raise MigrationError("dry-run receipt is not the fixed repository path")
    _require_owner_migration_root(paths)
    receipt_snapshot = _read_regular_snapshot(
        receipt_path,
        root=paths.repository_root,
        label="dry-run receipt",
        maximum=64 * 1024,
        required_mode=0o600,
    )
    try:
        payload = json.loads(receipt_snapshot.content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise MigrationError("dry-run receipt is not valid JSON") from None
    if not isinstance(payload, dict) or set(payload) != {
        "schema",
        "created_at",
        "source_receipt_sha256",
        "migration_script_sha256",
        "rollback",
        "outputs",
    }:
        raise MigrationError("dry-run receipt is malformed")
    created_at = payload.get("created_at")
    source_digest = payload.get("source_receipt_sha256")
    script_digest = payload.get("migration_script_sha256")
    rollback_proof = payload.get("rollback")
    outputs = payload.get("outputs")
    if (
        payload.get("schema") != DRY_RUN_SCHEMA
        or not isinstance(created_at, str)
        or re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",
            created_at,
        )
        is None
        or not isinstance(source_digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", source_digest) is None
        or not isinstance(script_digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", script_digest) is None
        or not isinstance(outputs, list)
        or len(outputs) != len(paths.dry_run_outputs)
    ):
        raise MigrationError("dry-run receipt is malformed")
    _validate_rollback_result(
        RollbackResult(None, rollback_proof),
    )
    source_snapshot = _read_regular_snapshot(
        paths.source_receipt,
        root=paths.repository_root,
        label="source receipt",
        maximum=4 * 1024 * 1024,
        required_mode=0o600,
    )
    script_snapshot = _read_regular_snapshot(
        paths.migration_script,
        root=paths.repository_root,
        label="migration script",
        maximum=4 * 1024 * 1024,
        required_mode=0o600,
    )
    if (
        not secrets.compare_digest(source_snapshot.sha256, source_digest)
        or not secrets.compare_digest(script_snapshot.sha256, script_digest)
    ):
        raise MigrationError("dry-run receipt input digest does not match")
    snapshots = _dry_run_output_snapshots(paths)
    for entry, snapshot in zip(outputs, snapshots, strict=True):
        if (
            not isinstance(entry, dict)
            or set(entry) != {"name", "sha256", "size"}
            or entry.get("name") != snapshot.path.name
            or not isinstance(entry.get("sha256"), str)
            or not secrets.compare_digest(str(entry["sha256"]), snapshot.sha256)
            or type(entry.get("size")) is not int
            or entry.get("size") != snapshot.size
        ):
            raise MigrationError("dry-run artifact does not match its receipt")
    return payload


def validate_review_receipt(
    paths: MigrationPaths,
    receipt_path: Path,
    report_path: Path,
) -> dict[str, object]:
    if receipt_path != paths.reviewed or report_path != paths.unmigrated:
        raise MigrationError("review artifacts are not the fixed repository paths")
    _require_owner_migration_root(paths)
    report_digest = require_regular_0600(
        report_path,
        root=paths.repository_root,
        label="unmigrated report",
    )
    require_regular_0600(
        receipt_path,
        root=paths.repository_root,
        label="review receipt",
    )
    raw = _read_regular_bytes(
        receipt_path,
        root=paths.repository_root,
        label="review receipt",
        maximum=64 * 1024,
    )
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise MigrationError("review receipt is not valid JSON") from None
    if not isinstance(payload, dict) or set(payload) != {
        "schema",
        "reviewed_at",
        "report",
    }:
        raise MigrationError("review receipt is malformed")
    report = payload.get("report")
    reviewed_at = payload.get("reviewed_at")
    if (
        payload.get("schema") != REVIEW_SCHEMA
        or not isinstance(reviewed_at, str)
        or re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", reviewed_at)
        is None
        or not isinstance(report, dict)
        or set(report) != {"name", "sha256"}
        or report.get("name") != paths.unmigrated.name
        or report.get("sha256") != report_digest
    ):
        raise MigrationError("review receipt does not match the exact report")
    return payload


def mark_reviewed(
    paths: MigrationPaths,
    report_path: Path,
    *,
    clock: object = _utc_timestamp,
) -> Path:
    if report_path != paths.unmigrated:
        raise MigrationError("review report is not the fixed repository path")
    _require_owner_migration_root(paths)
    digest = require_regular_0600(
        report_path,
        root=paths.repository_root,
        label="unmigrated report",
    )
    if paths.reviewed.exists() or paths.reviewed.is_symlink():
        validate_review_receipt(paths, paths.reviewed, report_path)
        return paths.reviewed
    reviewed_at = clock()
    if (
        not isinstance(reviewed_at, str)
        or re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", reviewed_at)
        is None
    ):
        raise MigrationError("review timestamp is malformed")
    payload = {
        "schema": REVIEW_SCHEMA,
        "reviewed_at": reviewed_at,
        "report": {
            "name": paths.unmigrated.name,
            "sha256": digest,
        },
    }
    _write_new_json_0600(paths.reviewed, payload, root=paths.repository_root)
    validate_review_receipt(paths, paths.reviewed, report_path)
    return paths.reviewed


def _require_normalized_non_broad_path(path: object, label: str) -> Path:
    if not isinstance(path, Path):
        raise MigrationError(f"{label} is malformed")
    normalized = _plain_absolute(path, label)
    if normalized == Path(normalized.anchor):
        raise MigrationError(f"{label} is too broad")
    return normalized


def _require_optional_runtime_entry(
    path: Path,
    *,
    root: Path,
    label: str,
    directory: bool,
) -> None:
    _require_no_symlink_components(root, path, label)
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise MigrationError(f"{label} is unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise MigrationError(f"{label} must not be a symlink")
    if directory and not stat.S_ISDIR(metadata.st_mode):
        raise MigrationError(f"{label} must be a directory")
    if not directory and not stat.S_ISREG(metadata.st_mode):
        raise MigrationError(f"{label} must be a regular file")


def validate_migration_runtime_paths(
    paths: MigrationPaths,
    source: VerifiedSource,
    runtime: MigrationRuntimePaths,
) -> dict[str, str]:
    """Validate and return only the exact migration Compose path variables."""
    if (
        not isinstance(paths, MigrationPaths)
        or not isinstance(source, VerifiedSource)
        or not isinstance(runtime, MigrationRuntimePaths)
    ):
        raise MigrationError("migration runtime path contract is malformed")
    repository_root = _require_normalized_non_broad_path(
        paths.repository_root,
        "repository root",
    )
    if paths != MigrationPaths.for_repository(repository_root):
        raise MigrationError("migration runtime paths are not fixed")
    _require_absolute_no_symlinks(repository_root, "repository root")
    _require_owner_migration_root(paths)
    checkout_root = _require_normalized_non_broad_path(
        source.checkout_root,
        "source checkout",
    )
    provider_store = _require_normalized_non_broad_path(
        source.provider_store,
        "source provider store",
    )
    base_compose = _require_normalized_non_broad_path(
        source.base_compose,
        "source base Compose file",
    )
    if (
        provider_store.parent != checkout_root
        or provider_store.name != "stalwart-data"
        or provider_store != checkout_root / "stalwart-data"
    ):
        raise MigrationError(
            "source provider store is not checkout-root stalwart-data",
        )
    if (
        base_compose != checkout_root / "docker-compose.yml"
        or type(source.compose_project) is not str
        or COMPOSE_PROJECT_PATTERN.fullmatch(source.compose_project) is None
        or type(source.compose_service) is not str
        or COMPOSE_SERVICE_PATTERN.fullmatch(source.compose_service) is None
    ):
        raise MigrationError("source Compose identity is malformed")
    values = (
        _require_normalized_non_broad_path(runtime.data_dir, "migration data dir"),
        _require_normalized_non_broad_path(
            runtime.config_dir,
            "migration config dir",
        ),
        _require_normalized_non_broad_path(
            runtime.recovery_env_file,
            "migration recovery environment file",
        ),
        _require_normalized_non_broad_path(
            runtime.compose_overlay,
            "migration Compose overlay",
        ),
    )
    for index, first in enumerate(values):
        for second in values[index + 1 :]:
            if _paths_overlap(first, second):
                raise MigrationError("migration runtime paths overlap")
    expected = MigrationRuntimePaths(
        data_dir=provider_store,
        config_dir=paths.migration_root / "recovery-config",
        recovery_env_file=paths.migration_root / "recovery.env",
        compose_overlay=repository_root
        / "docker-compose.stalwart-migration.yml",
    )
    if runtime != expected:
        raise MigrationError("migration runtime paths are not the exact fixed paths")
    _require_absolute_no_symlinks(checkout_root, "source checkout")
    _require_real_directory(checkout_root, "source checkout")
    _require_absolute_no_symlinks(provider_store, "source provider store")
    _require_real_directory(provider_store, "source provider store")
    _require_absolute_no_symlinks(base_compose, "source base Compose file")
    try:
        base_compose_metadata = base_compose.lstat()
    except OSError as exc:
        raise MigrationError("source base Compose file is unavailable") from exc
    if (
        stat.S_ISLNK(base_compose_metadata.st_mode)
        or not stat.S_ISREG(base_compose_metadata.st_mode)
    ):
        raise MigrationError("source base Compose file must be a regular file")
    _require_optional_runtime_entry(
        runtime.config_dir,
        root=repository_root,
        label="migration config dir",
        directory=True,
    )
    _require_optional_runtime_entry(
        runtime.recovery_env_file,
        root=repository_root,
        label="migration recovery environment file",
        directory=False,
    )
    overlay = _read_regular_snapshot(
        runtime.compose_overlay,
        root=repository_root,
        label="migration Compose overlay",
        maximum=64 * 1024,
        required_mode=0o644,
    )
    if not secrets.compare_digest(overlay.sha256, MIGRATION_COMPOSE_SHA256):
        raise MigrationError("migration Compose overlay digest does not match")
    environment = runtime.compose_environment()
    if set(environment) != {
        MIGRATION_DATA_VARIABLE,
        MIGRATION_CONFIG_VARIABLE,
        MIGRATION_RECOVERY_ENV_VARIABLE,
    }:
        raise MigrationError("migration Compose environment is malformed")
    return environment


def build_migration_runtime_paths(
    paths: MigrationPaths,
    source: VerifiedSource,
) -> MigrationRuntimePaths:
    """Derive the migration runtime contract without accepting path overrides."""
    if not isinstance(paths, MigrationPaths) or not isinstance(source, VerifiedSource):
        raise MigrationError("migration runtime source is malformed")
    runtime = MigrationRuntimePaths(
        data_dir=source.provider_store,
        config_dir=paths.migration_root / "recovery-config",
        recovery_env_file=paths.migration_root / "recovery.env",
        compose_overlay=paths.repository_root
        / "docker-compose.stalwart-migration.yml",
    )
    validate_migration_runtime_paths(paths, source, runtime)
    return runtime


def _runtime_plan_context(
    plan: ApplyPlan,
) -> tuple[MigrationPaths, dict[str, str]]:
    if (
        type(plan) is not ApplyPlan
        or type(plan.source) is not VerifiedSource
        or type(plan.runtime) is not MigrationRuntimePaths
        or type(plan.inputs) is not tuple
        or type(plan.artifacts) is not tuple
        or type(plan.operations) is not tuple
        or type(plan.operations_sha256) is not str
    ):
        raise MigrationError("migration runtime plan is malformed")
    repository_root = _require_normalized_non_broad_path(
        plan.runtime.compose_overlay.parent,
        "migration runtime repository",
    )
    paths = MigrationPaths.for_repository(repository_root)
    environment = validate_migration_runtime_paths(
        paths,
        plan.source,
        plan.runtime,
    )
    expected_inputs = (
        paths.source_receipt,
        paths.migration_script,
        paths.dry_run_receipt,
        paths.reviewed,
        plan.runtime.compose_overlay,
        plan.source.base_compose,
    )
    if any(type(item) is not ApplyFile for item in (*plan.inputs, *plan.artifacts)):
        raise MigrationError("migration runtime plan is malformed")
    if (
        len(plan.inputs) != len(expected_inputs)
        or tuple(item.path for item in plan.inputs) != expected_inputs
        or len(plan.artifacts) != len(paths.dry_run_outputs)
        or tuple(item.path for item in plan.artifacts) != paths.dry_run_outputs
        or any(type(item) is not ApplyOperation for item in plan.operations)
        or re.fullmatch(r"[0-9a-f]{64}", plan.operations_sha256) is None
        or not secrets.compare_digest(
            apply_operation_plan_sha256(plan.operations),
            plan.operations_sha256,
        )
    ):
        raise MigrationError("migration runtime plan is malformed")
    for item in (*plan.inputs, *plan.artifacts):
        if (
            re.fullmatch(r"[0-9a-f]{64}", item.sha256) is None
            or type(item.size) is not int
            or item.size < 0
            or type(item.identity) is not tuple
            or len(item.identity) != 6
            or any(type(value) is not int or value < 0 for value in item.identity)
        ):
            raise MigrationError("migration runtime plan is malformed")
    return paths, environment


def _validate_checkout_config_matches_converted(
    source: VerifiedSource,
    converted: FileSnapshot,
) -> None:
    if type(source) is not VerifiedSource or type(converted) is not FileSnapshot:
        raise MigrationError("normal config validation contract is malformed")
    _require_exact_converted_config_bytes(converted.content)
    normal_config = _read_regular_snapshot(
        source.checkout_root / "stalwart" / "config.json",
        root=source.checkout_root,
        label="normal config",
        maximum=64 * 1024,
        required_mode=0o644,
    )
    if (
        normal_config.size != converted.size
        or not secrets.compare_digest(
            normal_config.sha256,
            converted.sha256,
        )
        or normal_config.content != converted.content
    ):
        raise MigrationError(
            "normal config does not match the pinned converted config",
        )


def _validated_runtime_plan_files(
    plan: ApplyPlan,
) -> tuple[MigrationPaths, dict[str, str], dict[Path, FileSnapshot]]:
    paths, environment = _runtime_plan_context(plan)
    snapshots: dict[Path, FileSnapshot] = {}
    for item in (*plan.inputs, *plan.artifacts):
        if item.path == plan.source.base_compose:
            root = plan.source.checkout_root
            required_mode = 0o644
            maximum = 4 * 1024 * 1024
        elif item.path == plan.runtime.compose_overlay:
            root = paths.repository_root
            required_mode = 0o644
            maximum = 64 * 1024
        else:
            root = paths.repository_root
            required_mode = 0o600
            maximum = 16 * 1024 * 1024
        snapshot = _read_regular_snapshot(
            item.path,
            root=root,
            label="migration runtime plan file",
            maximum=maximum,
            required_mode=required_mode,
        )
        if (
            not secrets.compare_digest(snapshot.sha256, item.sha256)
            or snapshot.size != item.size
            or snapshot.identity != item.identity
        ):
            raise MigrationError("migration runtime plan file changed before use")
        snapshots[item.path] = snapshot
    if len(snapshots) != len(plan.inputs) + len(plan.artifacts):
        raise MigrationError("migration runtime plan contains duplicate files")
    converted = snapshots.get(paths.converted_config)
    if converted is None:
        raise MigrationError("migration converted config is unavailable")
    _validate_checkout_config_matches_converted(plan.source, converted)
    return paths, environment, snapshots


def _write_new_bytes_0644(
    target: Path,
    content: bytes,
    *,
    root: Path,
) -> None:
    if type(content) is not bytes:
        raise MigrationError("runtime artifact content is malformed")
    _require_below(root, target, "runtime artifact target")
    _require_no_symlink_components(root, target.parent, "runtime artifact parent")
    if target.exists() or target.is_symlink():
        raise MigrationError("runtime artifact target already exists")
    descriptor: int | None = None
    try:
        descriptor = os.open(
            target,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            0o644,
        )
        view = memoryview(content)
        try:
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise MigrationError("runtime artifact write did not progress")
                view = view[written:]
        finally:
            view.release()
        os.fchmod(descriptor, 0o644)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        parent_descriptor = os.open(
            target.parent,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
    except MigrationError:
        raise
    except OSError:
        raise MigrationError("runtime artifact could not be written safely") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _write_new_mutable_0600(
    target: Path,
    content: bytearray,
    *,
    root: Path,
) -> None:
    """Publish a mutable buffer without creating an immutable content copy."""
    if type(content) is not bytearray:
        raise MigrationError("runtime artifact content is malformed")
    _require_below(root, target, "runtime artifact target")
    _require_no_symlink_components(root, target.parent, "runtime artifact parent")
    if target.exists() or target.is_symlink():
        raise MigrationError("runtime artifact target already exists")
    descriptor: int | None = None
    view: memoryview | None = None
    try:
        descriptor = os.open(
            target,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        view = memoryview(content)
        offset = 0
        while offset < len(view):
            written = os.write(descriptor, view[offset:])
            if written <= 0:
                raise MigrationError("runtime artifact write did not progress")
            offset += written
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        parent_descriptor = os.open(
            target.parent,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
    except MigrationError:
        raise
    except OSError:
        raise MigrationError("runtime artifact could not be written safely") from None
    finally:
        if view is not None:
            view.release()
        if descriptor is not None:
            os.close(descriptor)


def _make_new_runtime_config_directory(
    paths: MigrationPaths,
    runtime: MigrationRuntimePaths,
) -> None:
    _require_below(
        paths.repository_root,
        runtime.config_dir,
        "migration config dir",
    )
    _require_no_symlink_components(
        paths.repository_root,
        runtime.config_dir.parent,
        "migration config parent",
    )
    try:
        os.mkdir(runtime.config_dir, 0o755)
        os.chmod(runtime.config_dir, 0o755, follow_symlinks=False)
        parent_descriptor = os.open(
            runtime.config_dir.parent,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
    except OSError:
        raise MigrationError(
            "migration config dir could not be created safely",
        ) from None


def _materialize_migration_runtime_artifacts(
    paths: MigrationPaths,
    plan: ApplyPlan,
    snapshots: dict[Path, FileSnapshot],
    credential: bytearray,
) -> None:
    if not _valid_recovery_credential_slice(
        credential,
        start=0,
        end=len(credential) if type(credential) is bytearray else 0,
    ):
        raise MigrationError("migration recovery credential is malformed")
    _require_runtime_artifacts_absent(paths, plan.runtime)
    converted = snapshots.get(paths.converted_config)
    if converted is None:
        raise MigrationError("migration converted config is unavailable")
    _make_new_runtime_config_directory(paths, plan.runtime)
    _write_new_bytes_0644(
        plan.runtime.config_dir / "config.json",
        converted.content,
        root=paths.repository_root,
    )
    environment_buffer = bytearray(RECOVERY_ENV_PREFIX)
    try:
        environment_buffer.extend(credential)
        environment_buffer.extend(b"\n")
        _write_new_mutable_0600(
            plan.runtime.recovery_env_file,
            environment_buffer,
            root=paths.repository_root,
        )
    finally:
        _wipe_bytearray(environment_buffer)


def _runtime_command_environment(
    environment: dict[str, str],
) -> dict[str, str]:
    reserved_names = {"PATH", *DOCKER_CLIENT_ENVIRONMENT_NAMES}
    if (
        type(environment) is not dict
        or any(name in reserved_names for name in environment)
        or any(
            type(name) is not str
            or not name
            or "=" in name
            or "\x00" in name
            or type(value) is not str
            or not value
            or len(value) > MAXIMUM_COMMAND_ENVIRONMENT_VALUE
            or "\x00" in value
            or "\r" in value
            or "\n" in value
            for name, value in environment.items()
        )
    ):
        raise MigrationError("migration command environment is malformed")
    docker_environment: dict[str, str] = {}
    for name in DOCKER_CLIENT_ENVIRONMENT_NAMES:
        if name not in os.environ:
            continue
        value = os.environ[name]
        if (
            type(value) is not str
            or not value
            or len(value) > MAXIMUM_COMMAND_ENVIRONMENT_VALUE
            or "\x00" in value
            or "\r" in value
            or "\n" in value
        ):
            raise MigrationError("Docker client environment is malformed")
        if name in DOCKER_CLIENT_PATH_NAMES:
            candidate = Path(value)
            if (
                not candidate.is_absolute()
                or Path(os.path.normpath(value)) != candidate
            ):
                raise MigrationError("Docker client environment is malformed")
        elif name == "DOCKER_HOST":
            if (
                re.fullmatch(
                    r"(?:unix|tcp|ssh|npipe|fd)://\S+",
                    value,
                )
                is None
            ):
                raise MigrationError("Docker client environment is malformed")
        elif name == "DOCKER_CONTEXT":
            if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+-]{0,255}", value) is None:
                raise MigrationError("Docker client environment is malformed")
        elif name == "DOCKER_TLS_VERIFY":
            if value not in {"0", "1"}:
                raise MigrationError("Docker client environment is malformed")
        elif name == "DOCKER_API_VERSION":
            if re.fullmatch(r"[0-9]{1,3}\.[0-9]{1,3}", value) is None:
                raise MigrationError("Docker client environment is malformed")
        docker_environment[name] = value
    return {
        "PATH": SAFE_COMMAND_PATH,
        **docker_environment,
        **environment,
    }


def _invoke_runtime_runner(
    runner: object,
    args: list[str],
    *,
    stdin: bytes,
    env: dict[str, str],
    timeout: int | float,
    cwd: Path,
    allowed_stalwart_names: set[str],
    secret_values: tuple[str, ...] = (),
) -> RedactedCommandResult:
    if (
        not callable(runner)
        or not isinstance(args, list)
        or not args
        or any(type(argument) is not str or not argument for argument in args)
        or type(stdin) is not bytes
        or type(env) is not dict
        or env.get("PATH") != SAFE_COMMAND_PATH
        or any(
            name.startswith("STALWART_") and name not in allowed_stalwart_names
            for name in env
        )
        or set(name for name in env if name.startswith("STALWART_"))
        != allowed_stalwart_names
        or any(
            type(name) is not str
            or type(value) is not str
            or "\x00" in name
            or "\x00" in value
            for name, value in env.items()
        )
        or type(timeout) not in {int, float}
        or timeout <= 0
        or not isinstance(cwd, Path)
        or type(secret_values) is not tuple
        or any(type(value) is not str or not value for value in secret_values)
        or any(
            secret in argument
            for secret in secret_values
            for argument in args
        )
    ):
        raise CommandError("migration runtime command is malformed")
    failed = False
    result: object = None
    try:
        result = runner(
            args,
            stdin=stdin,
            env=dict(env),
            timeout=timeout,
            cwd=cwd,
        )
    except Exception:
        failed = True
    if failed or type(result) is not RedactedCommandResult:
        raise CommandError("migration runtime command failed safely")
    return result


def _invoke_runtime_secret_runner(
    runner: object,
    args: list[str],
    *,
    stdin: bytes,
    env: dict[str, str],
    credential: bytearray,
    timeout: int | float,
    cwd: Path,
) -> RedactedCommandResult:
    if (
        not callable(runner)
        or not isinstance(args, list)
        or not args
        or any(type(argument) is not str or not argument for argument in args)
        or type(stdin) is not bytes
        or type(env) is not dict
        or env.get("PATH") != SAFE_COMMAND_PATH
        or set(name for name in env if name.startswith("STALWART_"))
        != {"STALWART_URL"}
        or any(
            type(name) is not str
            or type(value) is not str
            or "\x00" in name
            or "\x00" in value
            for name, value in env.items()
        )
        or type(credential) is not bytearray
        or not _valid_recovery_credential_slice(
            credential,
            start=0,
            end=len(credential) if type(credential) is bytearray else 0,
        )
        or type(timeout) not in {int, float}
        or timeout <= 0
        or not isinstance(cwd, Path)
    ):
        raise CommandError("migration secret runtime command is malformed")
    credential_view = memoryview(credential).toreadonly()
    failed = False
    result: object = None
    try:
        try:
            result = runner(
                args,
                stdin=stdin,
                env=dict(env),
                credential=credential_view,
                timeout=timeout,
                cwd=cwd,
            )
        except Exception:
            failed = True
    finally:
        credential_view.release()
    if failed or type(result) is not RedactedCommandResult:
        raise CommandError("migration secret runtime command failed safely")
    return result


def _execute_with_mandatory_stop(
    operation: Callable[[], object],
    stop: Callable[[], None],
    *,
    failure_message: str,
) -> object:
    operation_failed = False
    stop_failed = False
    result: object = None
    try:
        try:
            result = operation()
        except Exception:
            operation_failed = True
    finally:
        try:
            stop()
        except Exception:
            stop_failed = True
    if operation_failed or stop_failed:
        raise MigrationError(failure_message)
    return result


def _migration_compose_prefix(plan: ApplyPlan) -> list[str]:
    _runtime_plan_context(plan)
    return [
        "docker",
        "compose",
        "--project-directory",
        str(plan.source.checkout_root),
        "--project-name",
        plan.source.compose_project,
        "--file",
        str(plan.source.base_compose),
        "--file",
        str(plan.runtime.compose_overlay),
    ]


def build_migration_compose_config_command(plan: ApplyPlan) -> list[str]:
    return [*_migration_compose_prefix(plan), "config", "--quiet"]


def build_migration_compose_start_command(plan: ApplyPlan) -> list[str]:
    return [
        *_migration_compose_prefix(plan),
        "up",
        "--detach",
        "--wait",
        "--force-recreate",
        "--pull",
        "never",
        plan.source.compose_service,
    ]


def build_migration_image_inspect_command() -> list[str]:
    return [
        "docker",
        "image",
        "inspect",
        "--format",
        "{{.Id}}",
        STALWART_IMAGE,
    ]


def _validate_local_migration_image_id(stdout: bytes) -> None:
    if type(stdout) is not bytes or stdout not in {
        STALWART_IMAGE_ID.encode("ascii"),
        (STALWART_IMAGE_ID + "\n").encode("ascii"),
    }:
        raise MigrationError(
            "local Stalwart migration image identity is malformed",
        )


def build_migration_compose_ps_command(plan: ApplyPlan) -> list[str]:
    return [
        *_migration_compose_prefix(plan),
        "ps",
        "--all",
        "--quiet",
        plan.source.compose_service,
    ]


def build_migration_recovery_ps_command(plan: ApplyPlan) -> list[str]:
    """List recovery candidates without loading mutable Compose artifacts."""
    if type(plan) is not ApplyPlan:
        raise MigrationError("migration recovery plan is malformed")
    return [
        "docker",
        "ps",
        "--all",
        "--no-trunc",
        "--quiet",
        "--filter",
        (
            "label=com.docker.compose.project="
            f"{plan.source.compose_project}"
        ),
    ]


def build_migration_compose_stop_command(plan: ApplyPlan) -> list[str]:
    return [
        *_migration_compose_prefix(plan),
        "stop",
        "--timeout",
        "30",
        plan.source.compose_service,
        MIGRATION_OWNER_SERVICE,
    ]


def build_bound_container_stop_command(container_id: str) -> list[str]:
    """Stop only the container whose immutable identity was just validated."""
    if type(container_id) is not str or re.fullmatch(
        r"[0-9a-f]{64}",
        container_id,
    ) is None:
        raise MigrationError("bound container identity is malformed")
    return [
        "docker",
        "container",
        "stop",
        "--timeout",
        "30",
        container_id,
    ]


def _migration_cli_prefix(container_id: str) -> list[str]:
    if type(container_id) is not str or re.fullmatch(
        r"[0-9a-f]{64}",
        container_id,
    ) is None:
        raise MigrationError("migration container identity is malformed")
    return [
        "docker",
        "run",
        "--rm",
        "--pull",
        "never",
        "--network",
        f"container:{container_id}",
        "--env",
        "STALWART_URL",
        "--env",
        "STALWART_USER",
        "--env",
        "STALWART_PASSWORD",
        STALWART_CLI_IMAGE,
    ]


def build_migration_cli_apply_command(container_id: str) -> list[str]:
    return [
        *_migration_cli_prefix(container_id),
        "apply",
        "--stdin",
        "--json",
        "--no-color",
    ]


def build_migration_server_version_command(container_id: str) -> list[str]:
    if type(container_id) is not str or re.fullmatch(
        r"[0-9a-f]{64}",
        container_id,
    ) is None:
        raise MigrationError("migration container identity is malformed")
    return [
        "docker",
        "exec",
        container_id,
        "/usr/local/bin/stalwart",
        "--version",
    ]


def build_migration_cli_account_query_command(container_id: str) -> list[str]:
    return [
        *_migration_cli_prefix(container_id),
        "query",
        "Account",
        "--fields",
        "id",
        "--json",
        "--no-color",
    ]


def build_migration_container_inspect_command(container_id: str) -> list[str]:
    if type(container_id) is not str or re.fullmatch(
        r"[0-9a-f]{64}",
        container_id,
    ) is None:
        raise MigrationError("migration container identity is malformed")
    return [
        "docker",
        "inspect",
        "--type",
        "container",
        "--format",
        MIGRATION_CONTAINER_INSPECT_FORMAT,
        container_id,
    ]


def build_migration_recovery_container_inspect_command(
    container_id: str,
) -> list[str]:
    if type(container_id) is not str or re.fullmatch(
        r"[0-9a-f]{64}",
        container_id,
    ) is None:
        raise MigrationError("migration recovery container identity is malformed")
    return [
        "docker",
        "inspect",
        "--type",
        "container",
        "--format",
        MIGRATION_RECOVERY_CONTAINER_INSPECT_FORMAT,
        container_id,
    ]


def _migration_container_id(stdout: bytes) -> str:
    if type(stdout) is not bytes or len(stdout) > 1024:
        raise MigrationError("migration container identity is malformed")
    try:
        lines = stdout.decode("ascii").splitlines()
    except UnicodeDecodeError:
        raise MigrationError("migration container identity is malformed") from None
    if len(lines) != 1 or re.fullmatch(r"[0-9a-f]{64}", lines[0]) is None:
        raise MigrationError("migration container identity is malformed")
    return lines[0]


def _validate_migration_container_inspection(
    stdout: bytes,
    *,
    plan: ApplyPlan,
    container_id: str,
    require_healthy: bool = True,
    require_running: bool | None = True,
) -> bool:
    if (
        type(stdout) is not bytes
        or len(stdout) > 1024 * 1024
        or type(require_healthy) is not bool
        or (
            require_running is not None
            and type(require_running) is not bool
        )
    ):
        raise MigrationError("migration container inspection is malformed")
    try:
        value = json.loads(
            stdout.decode("utf-8"),
            object_pairs_hook=_strict_json_object,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise MigrationError("migration container inspection is malformed") from None
    expected_keys = {
        "Id",
        "Image",
        "ImageID",
        "User",
        "Project",
        "Service",
        "WorkingDir",
        "ConfigFiles",
        "Oneoff",
        "Mounts",
        "Ports",
        "Running",
        "Health",
    }
    if (
        not isinstance(value, dict)
        or set(value) != expected_keys
        or value.get("Id") != container_id
        or value.get("Image") != STALWART_IMAGE
        or value.get("ImageID") != STALWART_IMAGE_ID
        or value.get("User") != "2000:2000"
        or value.get("Project") != plan.source.compose_project
        or value.get("Service") != plan.source.compose_service
        or value.get("WorkingDir") != str(plan.source.checkout_root)
        or value.get("ConfigFiles")
        != f"{plan.source.base_compose},{plan.runtime.compose_overlay}"
        or value.get("Oneoff") != "False"
        or type(value.get("Running")) is not bool
        or (
            require_running is not None
            and value.get("Running") is not require_running
        )
        or (
            value.get("Health") != "healthy"
            if require_healthy
            else type(value.get("Health")) is not str
        )
        or value.get("Ports")
        != {
            "8080/tcp": [
                {
                    "HostIp": "127.0.0.1",
                    "HostPort": "8443",
                },
            ],
            "587/tcp": [
                {
                    "HostIp": "127.0.0.1",
                    "HostPort": "8587",
                },
            ],
        }
    ):
        raise MigrationError("migration container inspection is malformed")
    mounts = value.get("Mounts")
    if not isinstance(mounts, list) or len(mounts) != 2:
        raise MigrationError("migration container inspection is malformed")
    observed_mounts: dict[str, tuple[str, bool]] = {}
    for mount in mounts:
        if (
            not isinstance(mount, dict)
            or mount.get("Type") != "bind"
            or not isinstance(mount.get("Source"), str)
            or not isinstance(mount.get("Destination"), str)
            or type(mount.get("RW")) is not bool
        ):
            raise MigrationError("migration container inspection is malformed")
        destination = mount["Destination"]
        if destination in observed_mounts:
            raise MigrationError("migration container inspection is malformed")
        observed_mounts[destination] = (mount["Source"], mount["RW"])
    if observed_mounts != {
        "/etc/stalwart": (str(plan.runtime.config_dir), False),
        "/var/lib/stalwart": (str(plan.runtime.data_dir), True),
    }:
        raise MigrationError("migration container inspection is malformed")
    return value["Running"]


def _validate_migration_owner_container_inspection(
    stdout: bytes,
    *,
    plan: ApplyPlan,
    container_id: str,
    require_running: bool | None = None,
) -> bool:
    if (
        type(stdout) is not bytes
        or len(stdout) > 1024 * 1024
        or (
            require_running is not None
            and type(require_running) is not bool
        )
    ):
        raise MigrationError("migration owner inspection is malformed")
    try:
        value = json.loads(
            stdout.decode("utf-8"),
            object_pairs_hook=_strict_json_object,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise MigrationError("migration owner inspection is malformed") from None
    expected_keys = {
        "Id",
        "Image",
        "ImageID",
        "User",
        "Project",
        "Service",
        "WorkingDir",
        "ConfigFiles",
        "Oneoff",
        "Mounts",
        "Ports",
        "Running",
        "Entrypoint",
        "Cmd",
        "Restart",
    }
    ports = value.get("Ports") if isinstance(value, dict) else None
    if (
        not isinstance(value, dict)
        or set(value) != expected_keys
        or value.get("Id") != container_id
        or value.get("Image") != STALWART_IMAGE
        or value.get("ImageID") != STALWART_IMAGE_ID
        or value.get("User") != "0:0"
        or value.get("Project") != plan.source.compose_project
        or value.get("Service") != MIGRATION_OWNER_SERVICE
        or value.get("WorkingDir") != str(plan.source.checkout_root)
        or value.get("ConfigFiles")
        != f"{plan.source.base_compose},{plan.runtime.compose_overlay}"
        or value.get("Oneoff") != "False"
        or type(value.get("Running")) is not bool
        or (
            require_running is not None
            and value.get("Running") is not require_running
        )
        or value.get("Entrypoint") != ["/bin/sh", "-c"]
        or value.get("Cmd")
        != [
            (
                "chown -R 2000:2000 /var/lib/stalwart && "
                "chmod 0700 /var/lib/stalwart"
            ),
        ]
        or value.get("Restart") != "no"
        or (
            ports is not None
            and (
                not isinstance(ports, dict)
                or any(
                    binding is not None
                    for binding in ports.values()
                )
            )
        )
    ):
        raise MigrationError("migration owner inspection is malformed")
    mounts = value.get("Mounts")
    if not isinstance(mounts, list) or len(mounts) != 2:
        raise MigrationError("migration owner inspection is malformed")
    observed_mounts: dict[str, tuple[str, bool]] = {}
    for mount in mounts:
        if (
            not isinstance(mount, dict)
            or mount.get("Type") != "bind"
            or type(mount.get("Source")) is not str
            or type(mount.get("Destination")) is not str
            or type(mount.get("RW")) is not bool
            or mount["Destination"] in observed_mounts
        ):
            raise MigrationError("migration owner inspection is malformed")
        observed_mounts[mount["Destination"]] = (
            mount["Source"],
            mount["RW"],
        )
    if observed_mounts != {
        "/etc/stalwart": (str(plan.runtime.config_dir), False),
        "/var/lib/stalwart": (str(plan.runtime.data_dir), True),
    }:
        raise MigrationError("migration owner inspection is malformed")
    return value["Running"]


def _frozen_normal_runtime_plan_context(
    plan: RecoveryRetirementPlan,
) -> VerifiedSource:
    """Validate only the immutable retirement-plan structure."""
    if (
        type(plan) is not RecoveryRetirementPlan
        or type(plan.source) is not VerifiedSource
        or type(plan.runtime) is not MigrationRuntimePaths
        or plan.runtime.data_dir != plan.source.provider_store
        or plan.source.provider_store
        != plan.source.checkout_root / "stalwart-data"
        or plan.source.base_compose
        != plan.source.checkout_root / "docker-compose.yml"
        or type(plan.source.compose_project) is not str
        or COMPOSE_PROJECT_PATTERN.fullmatch(
            plan.source.compose_project,
        )
        is None
        or plan.source.compose_service != "stalwart"
        or not isinstance(plan.inputs, tuple)
        or not plan.inputs
        or any(type(item) is not ApplyFile for item in plan.inputs)
    ):
        raise MigrationError("normal runtime plan is malformed")
    checkout = _plain_absolute(
        plan.source.checkout_root,
        "normal runtime checkout",
    )
    base_compose = _plain_absolute(
        plan.source.base_compose,
        "normal runtime base Compose file",
    )
    bindings = tuple(
        item for item in plan.inputs if item.path == base_compose
    )
    if len(bindings) != 1 or plan.inputs[-1] != bindings[0]:
        raise MigrationError(
            "normal runtime base Compose binding is malformed",
        )
    return plan.source


def _normal_runtime_plan_context(
    plan: RecoveryRetirementPlan,
) -> VerifiedSource:
    """Revalidate the exact base-Compose binding before each normal command."""
    source = _frozen_normal_runtime_plan_context(plan)
    checkout = source.checkout_root
    base_compose = source.base_compose
    _require_absolute_no_symlinks(checkout, "normal runtime checkout")
    _require_real_directory(checkout, "normal runtime checkout")
    _require_absolute_no_symlinks(
        source.provider_store,
        "normal runtime provider store",
    )
    _require_real_directory(
        source.provider_store,
        "normal runtime provider store",
    )
    snapshot = _read_regular_snapshot(
        base_compose,
        root=checkout,
        label="normal runtime base Compose file",
        maximum=4 * 1024 * 1024,
        required_mode=0o644,
    )
    binding = tuple(
        item for item in plan.inputs if item.path == base_compose
    )[0]
    if (
        not secrets.compare_digest(snapshot.sha256, binding.sha256)
        or snapshot.size != binding.size
        or snapshot.identity != binding.identity
    ):
        raise MigrationError(
            "normal runtime base Compose file changed before use",
        )
    return source


def _normal_compose_prefix(plan: RecoveryRetirementPlan) -> list[str]:
    source = _normal_runtime_plan_context(plan)
    return [
        "docker",
        "compose",
        "--project-directory",
        str(source.checkout_root),
        "--project-name",
        source.compose_project,
        "--file",
        str(source.base_compose),
    ]


def build_normal_compose_config_command(
    plan: RecoveryRetirementPlan,
) -> list[str]:
    return [*_normal_compose_prefix(plan), "config", "--quiet"]


def build_normal_compose_model_command(
    plan: RecoveryRetirementPlan,
) -> list[str]:
    source = _normal_runtime_plan_context(plan)
    return [
        *_normal_compose_prefix(plan),
        "config",
        "--format",
        "json",
        source.compose_service,
    ]


def _validate_normal_compose_model(
    stdout: bytes,
    *,
    plan: RecoveryRetirementPlan,
) -> None:
    """Require the rendered base service to equal the approved normal model."""
    source = _normal_runtime_plan_context(plan)
    public_url = _normal_runtime_public_url(source.checkout_root)
    if type(stdout) is not bytes or not stdout or len(stdout) > 1024 * 1024:
        raise MigrationError("normal runtime Compose model is malformed")
    try:
        value = json.loads(
            stdout.decode("utf-8", "strict"),
            object_pairs_hook=_strict_json_object,
            parse_float=lambda _value: (_ for _ in ()).throw(
                ValueError("float"),
            ),
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("constant"),
            ),
        )
    except (UnicodeError, json.JSONDecodeError, ValueError):
        raise MigrationError(
            "normal runtime Compose model is malformed",
        ) from None
    expected = {
        "name": source.compose_project,
        "networks": {
            "default": {
                "name": f"{source.compose_project}_default",
                "ipam": {},
            },
        },
        "services": {
            source.compose_service: {
                "command": None,
                "container_name": "stalwart-dev",
                "entrypoint": None,
                "environment": {
                    "STALWART_PUBLIC_URL": public_url,
                },
                "healthcheck": {
                    "test": [
                        "CMD",
                        "curl",
                        "-fsS",
                        "http://127.0.0.1:8080/healthz/ready",
                    ],
                    "timeout": "2s",
                    "interval": "2s",
                    "retries": 30,
                    "start_period": "2s",
                },
                "image": STALWART_IMAGE,
                "networks": {"default": None},
                "ports": [
                    {
                        "host_ip": "0.0.0.0",
                        "mode": "ingress",
                        "protocol": "tcp",
                        "published": "8443",
                        "target": 8080,
                    },
                    {
                        "host_ip": "0.0.0.0",
                        "mode": "ingress",
                        "protocol": "tcp",
                        "published": "8587",
                        "target": 587,
                    },
                ],
                "restart": "unless-stopped",
                "user": "2000:2000",
                "volumes": [
                    {
                        "bind": {},
                        "read_only": True,
                        "source": str(
                            source.checkout_root
                            / "stalwart"
                        ),
                        "target": "/etc/stalwart",
                        "type": "bind",
                    },
                    {
                        "bind": {},
                        "source": str(source.provider_store),
                        "target": "/var/lib/stalwart",
                        "type": "bind",
                    },
                ],
            },
        },
    }
    if value != expected:
        raise MigrationError("normal runtime Compose model is malformed")


def _validate_receipt_bound_normal_config(
    plan: RecoveryRetirementPlan,
) -> FileSnapshot:
    """Bind the normal config to the exact converted receipt artifact."""
    source = _normal_runtime_plan_context(plan)
    invocation_root = plan.runtime.compose_overlay.parent
    paths = MigrationPaths.for_repository(invocation_root)
    if (
        len(plan.artifacts) != len(paths.dry_run_outputs)
        or tuple(item.path for item in plan.artifacts)
        != paths.dry_run_outputs
        or type(plan.artifacts[2]) is not ApplyFile
        or plan.artifacts[2].path != paths.converted_config
    ):
        raise MigrationError(
            "normal runtime config receipt binding is malformed",
        )
    converted_binding = plan.artifacts[2]
    converted = _read_regular_snapshot(
        converted_binding.path,
        root=paths.repository_root,
        label="receipt-bound converted config",
        maximum=16 * 1024 * 1024,
        required_mode=0o600,
    )
    if (
        converted.sha256 != converted_binding.sha256
        or converted.size != converted_binding.size
        or converted.identity != converted_binding.identity
    ):
        raise MigrationError(
            "receipt-bound converted config changed before normal use",
        )
    target = source.checkout_root / "stalwart" / "config.json"
    if target != source.checkout_root.joinpath(
        "stalwart",
        "config.json",
    ):
        raise MigrationError("normal runtime config path is malformed")
    normal = _read_regular_snapshot(
        target,
        root=source.checkout_root,
        label="normal runtime config",
        maximum=16 * 1024 * 1024,
        required_mode=0o644,
    )
    try:
        named = target.lstat()
    except OSError:
        raise MigrationError(
            "normal runtime config changed during validation",
        ) from None
    if (
        not stat.S_ISREG(named.st_mode)
        or named.st_nlink != 1
        or named.st_uid != os.getuid()
        or _file_identity(named) != normal.identity
        or normal.size != converted.size
        or not secrets.compare_digest(
            normal.sha256,
            converted.sha256,
        )
        or normal.content != converted.content
    ):
        raise MigrationError(
            "normal runtime config does not match the converted receipt",
        )
    return normal


def build_normal_runtime_image_inspect_command() -> list[str]:
    return [
        "docker",
        "image",
        "inspect",
        "--format",
        "{{.Id}}",
        STALWART_IMAGE,
    ]


def build_normal_compose_start_command(
    plan: RecoveryRetirementPlan,
) -> list[str]:
    source = _normal_runtime_plan_context(plan)
    return [
        *_normal_compose_prefix(plan),
        "up",
        "--detach",
        "--wait",
        "--force-recreate",
        "--pull",
        "never",
        "--no-deps",
        source.compose_service,
    ]


def build_normal_compose_ps_command(
    plan: RecoveryRetirementPlan,
) -> list[str]:
    source = _normal_runtime_plan_context(plan)
    return [
        *_normal_compose_prefix(plan),
        "ps",
        "--all",
        "--quiet",
        source.compose_service,
    ]


def build_normal_recovery_ps_command(
    plan: RecoveryRetirementPlan,
) -> list[str]:
    """List normal-runtime candidates without evaluating Compose files."""
    source = _frozen_normal_runtime_plan_context(plan)
    return [
        "docker",
        "ps",
        "--all",
        "--no-trunc",
        "--quiet",
        "--filter",
        f"label=com.docker.compose.project={source.compose_project}",
        "--filter",
        f"label=com.docker.compose.service={source.compose_service}",
    ]


def build_normal_compose_stop_command(
    plan: RecoveryRetirementPlan,
) -> list[str]:
    source = _normal_runtime_plan_context(plan)
    return [
        *_normal_compose_prefix(plan),
        "stop",
        "--timeout",
        "30",
        source.compose_service,
    ]


def build_normal_compose_restart_command(
    plan: RecoveryRetirementPlan,
) -> list[str]:
    source = _normal_runtime_plan_context(plan)
    return [
        *_normal_compose_prefix(plan),
        "restart",
        "--timeout",
        "30",
        source.compose_service,
    ]


def build_normal_container_inspect_command(
    container_id: str,
) -> list[str]:
    if type(container_id) is not str or re.fullmatch(
        r"[0-9a-f]{64}",
        container_id,
    ) is None:
        raise MigrationError("normal runtime container identity is malformed")
    return [
        "docker",
        "inspect",
        "--type",
        "container",
        "--format",
        NORMAL_CONTAINER_INSPECT_FORMAT,
        container_id,
    ]


def build_normal_recovery_container_inspect_command(
    container_id: str,
) -> list[str]:
    if type(container_id) is not str or re.fullmatch(
        r"[0-9a-f]{64}",
        container_id,
    ) is None:
        raise MigrationError("normal recovery container identity is malformed")
    return [
        "docker",
        "inspect",
        "--type",
        "container",
        "--format",
        NORMAL_RECOVERY_CONTAINER_INSPECT_FORMAT,
        container_id,
    ]


def _validate_normal_container_inspection(
    stdout: bytes,
    *,
    plan: RecoveryRetirementPlan,
    container_id: str,
    require_healthy: bool = True,
    require_running: bool | None = True,
    revalidate_plan: bool = True,
    expected_restart: str | None = None,
) -> NormalRuntimeInspection:
    if (
        type(revalidate_plan) is not bool
        or expected_restart not in (None, "unless-stopped")
    ):
        raise MigrationError("normal runtime container inspection is malformed")
    source = (
        _normal_runtime_plan_context(plan)
        if revalidate_plan
        else _frozen_normal_runtime_plan_context(plan)
    )
    public_url = _normal_runtime_public_url(source.checkout_root)
    if (
        type(container_id) is not str
        or re.fullmatch(r"[0-9a-f]{64}", container_id) is None
        or type(stdout) is not bytes
        or len(stdout) > 1024 * 1024
        or type(require_healthy) is not bool
        or (
            require_running is not None
            and type(require_running) is not bool
        )
    ):
        raise MigrationError("normal runtime container inspection is malformed")
    try:
        value = json.loads(
            stdout.decode("utf-8"),
            object_pairs_hook=_strict_json_object,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise MigrationError(
            "normal runtime container inspection is malformed",
        ) from None
    expected_keys = {
        "Id",
        "Image",
        "ImageID",
        "User",
        "Project",
        "Service",
        "WorkingDir",
        "ConfigFiles",
        "Oneoff",
        "Mounts",
        "Ports",
        "Running",
        "Health",
        "Environment",
    }
    if expected_restart is not None:
        expected_keys.update({"Restarting", "Restart"})
    if (
        not isinstance(value, dict)
        or set(value) != expected_keys
        or value.get("Id") != container_id
        or value.get("Image") != STALWART_IMAGE
        or value.get("ImageID") != STALWART_IMAGE_ID
        or value.get("User") != "2000:2000"
        or value.get("Project") != source.compose_project
        or value.get("Service") != source.compose_service
        or value.get("WorkingDir") != str(source.checkout_root)
        or value.get("ConfigFiles") != str(source.base_compose)
        or value.get("Oneoff") != "False"
        or type(value.get("Running")) is not bool
        or (
            require_running is not None
            and value.get("Running") is not require_running
        )
        or (
            expected_restart is not None
            and (
                value.get("Restarting") is not False
                or value.get("Restart") != expected_restart
            )
        )
        or (
            value.get("Health") != "healthy"
            if require_healthy
            else type(value.get("Health")) is not str
        )
        or value.get("Ports")
        != {
            "8080/tcp": [
                {
                    "HostIp": "0.0.0.0",
                    "HostPort": "8443",
                },
            ],
            "587/tcp": [
                {
                    "HostIp": "0.0.0.0",
                    "HostPort": "8587",
                },
            ],
        }
    ):
        raise MigrationError(
            "normal runtime container inspection is malformed",
        )
    mounts = value.get("Mounts")
    if not isinstance(mounts, list) or len(mounts) != 2:
        raise MigrationError(
            "normal runtime container inspection is malformed",
        )
    observed_mounts: dict[str, tuple[str, bool]] = {}
    for mount in mounts:
        if (
            not isinstance(mount, dict)
            or set(mount) != {"Type", "Source", "Destination", "RW"}
            or mount.get("Type") != "bind"
            or type(mount.get("Source")) is not str
            or type(mount.get("Destination")) is not str
            or type(mount.get("RW")) is not bool
            or mount["Destination"] in observed_mounts
        ):
            raise MigrationError(
                "normal runtime container inspection is malformed",
            )
        observed_mounts[mount["Destination"]] = (
            mount["Source"],
            mount["RW"],
        )
    if observed_mounts != {
        "/etc/stalwart": (
            str(source.checkout_root / "stalwart"),
            False,
        ),
        "/var/lib/stalwart": (str(source.provider_store), True),
    }:
        raise MigrationError(
            "normal runtime container inspection is malformed",
        )
    environment = value.get("Environment")
    if (
        not isinstance(environment, list)
        or any(
            type(item) is not str
            or not item
            or "=" not in item
            or "\x00" in item
            or "\r" in item
            or "\n" in item
            for item in environment
        )
    ):
        raise MigrationError(
            "normal runtime container inspection is malformed",
        )
    environment_names = tuple(item.partition("=")[0] for item in environment)
    recovery_names = tuple(
        sorted(
            name
            for name in environment_names
            if name.startswith("STALWART_RECOVERY_")
        ),
    )
    if (
        len(environment_names) != len(set(environment_names))
        or any(
            re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", name) is None
            for name in environment_names
        )
        or frozenset(environment) != _normal_runtime_environment(public_url)
        or recovery_names
    ):
        raise MigrationError(
            "normal runtime container inspection is malformed",
        )
    return NormalRuntimeInspection(
        container_id=container_id,
        image_reference=STALWART_IMAGE,
        image_id=STALWART_IMAGE_ID,
        recovery_environment_names=recovery_names,
    )


def _normal_management_key_path(paths: MigrationPaths) -> Path:
    return (
        paths.repository_root
        / "debug-dashboard"
        / ".runtime"
        / "secrets"
        / "stalwart-management-api-key"
    )


def _read_bound_management_key(
    paths: MigrationPaths,
    plan: RecoveryRetirementPlan,
) -> bytearray:
    """Read the identity-bound API key without creating a content digest."""
    if (
        not isinstance(paths, MigrationPaths)
        or paths != MigrationPaths.for_repository(paths.repository_root)
        or type(plan) is not RecoveryRetirementPlan
        or plan.bootstrap.management_key_name
        != "stalwart-management-api-key"
        or type(plan.bootstrap.management_key_size) is not int
        or not 3 <= plan.bootstrap.management_key_size <= 4096
        or type(plan.bootstrap.management_key_identity) is not tuple
        or len(plan.bootstrap.management_key_identity) != 8
        or any(
            type(value) is not int
            or value < 0
            or value > MAXIMUM_IDENTITY_COMPONENT
            for value in plan.bootstrap.management_key_identity
        )
    ):
        raise MigrationError("management API key binding is malformed")
    path = _normal_management_key_path(paths)
    descriptor, before = _open_regular_readonly(
        path,
        root=paths.repository_root,
        label="management API key file",
    )
    buffer = bytearray()
    primary_in_flight = False
    try:
        if (
            stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or before.st_size != plan.bootstrap.management_key_size
            or _bootstrap_secret_file_identity(before)
            != plan.bootstrap.management_key_identity
        ):
            raise MigrationError(
                "management API key binding changed before use",
            )
        buffer = bytearray(before.st_size)
        total = 0
        while total < len(buffer):
            view = memoryview(buffer)[total:]
            try:
                read = os.readv(descriptor, [view])
            finally:
                view.release()
            if read <= 0:
                raise MigrationError(
                    "management API key changed while it was read",
                )
            total += read
        trailing = bytearray(1)
        trailing_view = memoryview(trailing)
        try:
            extra = os.readv(descriptor, [trailing_view])
        finally:
            trailing_view.release()
            _wipe_bytearray(trailing)
        after = os.fstat(descriptor)
        named = path.lstat()
        if (
            extra != 0
            or total != before.st_size
            or _bootstrap_secret_file_identity(after)
            != _bootstrap_secret_file_identity(before)
            or _bootstrap_secret_file_identity(named)
            != _bootstrap_secret_file_identity(before)
            or _bootstrap_secret_file_identity(after)
            != plan.bootstrap.management_key_identity
            or any(item < 0x21 or item > 0x7E for item in buffer)
        ):
            raise MigrationError(
                "management API key changed while it was read",
            )
        return buffer
    except (MigrationError, KeyboardInterrupt, SystemExit):
        primary_in_flight = True
        _wipe_bytearray(buffer)
        raise
    except BaseException:
        primary_in_flight = True
        _wipe_bytearray(buffer)
        raise MigrationError(
            "management API key could not be read safely",
        ) from None
    finally:
        try:
            os.close(descriptor)
        except BaseException as exc:
            _wipe_bytearray(buffer)
            if not primary_in_flight:
                if isinstance(exc, Exception):
                    raise MigrationError(
                        "management API key could not be closed safely",
                    ) from None
                raise


def _invoke_normal_runtime_command(
    runner: object,
    args: list[str],
    *,
    plan: RecoveryRetirementPlan,
    timeout: int | float,
) -> RedactedCommandResult:
    environment = _runtime_command_environment({})
    return _invoke_runtime_runner(
        runner,
        args,
        stdin=b"",
        env=environment,
        timeout=timeout,
        cwd=plan.source.checkout_root,
        allowed_stalwart_names=set(),
    )


def _invoke_normal_readiness_probe(probe: object) -> int:
    if not callable(probe):
        raise MigrationError(
            "normal runtime readiness probe is unavailable",
        )
    failed = False
    result: object = None
    try:
        result = probe()
    except Exception:
        failed = True
    if failed or type(result) is not int or result != 200:
        raise MigrationError(
            "normal runtime readiness probe failed safely",
        ) from None
    return result


def _invoke_retirement_jmap_probe(
    probe: object,
    credential: memoryview,
    *,
    scheme: str,
    expected_api_url: str,
) -> JmapAuthProbe:
    if not callable(probe):
        raise MigrationError(
            "normal runtime authentication probe is unavailable",
        )
    failed = False
    result: object = None
    try:
        result = probe(
            credential,
            scheme=scheme,
            expected_api_url=expected_api_url,
        )
    except Exception:
        failed = True
    if failed or type(result) is not JmapAuthProbe:
        raise MigrationError(
            "normal runtime authentication probe failed safely",
        ) from None
    return result


def _invoke_retirement_basic_jmap_probe(
    probe: object,
    credential: memoryview,
    *,
    expected_api_url: str,
) -> JmapAuthProbe:
    if not callable(probe):
        raise MigrationError(
            "normal Basic authentication probe is unavailable",
        )
    failed = False
    result: object = None
    try:
        result = probe(
            credential,
            expected_api_url=expected_api_url,
        )
    except Exception:
        failed = True
    if failed or type(result) is not JmapAuthProbe:
        raise MigrationError(
            "normal Basic authentication probe failed safely",
        ) from None
    return result


def _invoke_retirement_smtp_probe(
    probe: object,
    credential: memoryview,
) -> int:
    if not callable(probe):
        raise MigrationError("normal SMTP probe is unavailable")
    failed = False
    result: object = None
    try:
        result = probe(credential)
    except Exception:
        failed = True
    if failed or type(result) is not int or result != 250:
        raise MigrationError("normal SMTP probe failed safely") from None
    return result


def _prove_normal_management_password(
    plan: RecoveryRetirementPlan,
    *,
    basic_jmap_probe: object,
    smtp_probe: object,
    expected_api_url: str,
) -> None:
    credential = bytearray(
        (
            f"{DASHBOARD_MANAGEMENT_USERNAME}:"
            f"{DASHBOARD_MANAGEMENT_PASSWORD}"
        ).encode("ascii"),
    )
    view: memoryview | None = None
    try:
        view = memoryview(credential).toreadonly()
        basic = _invoke_retirement_basic_jmap_probe(
            basic_jmap_probe,
            view,
            expected_api_url=expected_api_url,
        )
        if (
            basic.status != 200
            or basic.account_id != plan.bootstrap.management_account_id
            or basic.username != DASHBOARD_MANAGEMENT_USERNAME
        ):
            raise MigrationError(
                "normal management Basic authentication differs",
            )
        _invoke_retirement_smtp_probe(smtp_probe, view)
    finally:
        if view is not None:
            view.release()
        _wipe_bytearray(credential)


def _prove_normal_management_key(
    paths: MigrationPaths,
    plan: RecoveryRetirementPlan,
    jmap_probe: object,
    *,
    expected_api_url: str,
) -> None:
    management_key = bytearray()
    management_view: memoryview | None = None
    try:
        management_key = _read_bound_management_key(paths, plan)
        management_view = memoryview(management_key).toreadonly()
        management = _invoke_retirement_jmap_probe(
            jmap_probe,
            management_view,
            scheme="bearer",
            expected_api_url=expected_api_url,
        )
    finally:
        if management_view is not None:
            management_view.release()
        _wipe_bytearray(management_key)
    if (
        management.status != 200
        or management.account_id != plan.bootstrap.management_account_id
        or management.username != DASHBOARD_MANAGEMENT_USERNAME
    ):
        raise MigrationError(
            "normal runtime management authentication differs",
        )


def _prove_recovery_credential_rejected(
    recovery_credential: RecoveryCredentialLease,
    jmap_probe: object,
    *,
    expected_api_url: str,
) -> int:
    recovery_view = recovery_credential.borrow()
    try:
        old_recovery = _invoke_retirement_jmap_probe(
            jmap_probe,
            recovery_view,
            scheme="basic",
            expected_api_url=expected_api_url,
        )
    finally:
        recovery_view.release()
    if (
        old_recovery.status not in {401, 403}
        or old_recovery.account_id is not None
        or old_recovery.username is not None
    ):
        raise MigrationError(
            "normal runtime still accepts the recovery credential",
        )
    return old_recovery.status


def _normal_runtime_writer_census(
    paths: MigrationPaths,
    plan: RecoveryRetirementPlan,
    *,
    expected_container_id: str,
    runner: object,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Return exact writable-store and migration-container identities."""
    source = _normal_runtime_plan_context(plan)
    public_url = _normal_runtime_public_url(source.checkout_root)
    if (
        not callable(runner)
        or type(expected_container_id) is not str
        or re.fullmatch(r"[0-9a-f]{64}", expected_container_id) is None
    ):
        raise MigrationError("normal runtime writer census is malformed")
    try:
        ps_result = runner(
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
    except Exception:
        raise MigrationError(
            "normal runtime writer census failed safely",
        ) from None
    if (
        type(ps_result) is not CommandResult
        or ps_result.stderr
        or len(ps_result.stdout) > 1024 * 1024
    ):
        raise MigrationError("normal runtime writer census is malformed")
    container_ids = tuple(
        line.strip()
        for line in ps_result.stdout.splitlines()
        if line.strip()
    )
    if (
        not container_ids
        or expected_container_id not in container_ids
        or len(container_ids) != len(set(container_ids))
        or any(
            re.fullmatch(r"[0-9a-f]{64}", item) is None
            for item in container_ids
        )
    ):
        raise MigrationError("normal runtime writer census is malformed")
    try:
        inspect_result = runner(
            ["docker", "inspect", *container_ids],
        )
    except Exception:
        raise MigrationError(
            "normal runtime writer census failed safely",
        ) from None
    if (
        type(inspect_result) is not CommandResult
        or inspect_result.stderr
        or len(inspect_result.stdout) > 16 * 1024 * 1024
    ):
        raise MigrationError("normal runtime writer census is malformed")
    try:
        records = json.loads(
            inspect_result.stdout,
            object_pairs_hook=_strict_json_object,
            parse_float=lambda _value: (_ for _ in ()).throw(
                ValueError("float"),
            ),
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("constant"),
            ),
        )
    except (json.JSONDecodeError, ValueError):
        raise MigrationError(
            "normal runtime writer census is malformed",
        ) from None
    if not isinstance(records, list) or len(records) != len(container_ids):
        raise MigrationError("normal runtime writer census is malformed")
    by_id: dict[str, dict[str, object]] = {}
    writer_ids: list[str] = []
    migration_ids: list[str] = []
    protected = (plan.source.provider_store, paths.scratch_store)
    for record in records:
        if not isinstance(record, dict):
            raise MigrationError("normal runtime writer census is malformed")
        container_id = record.get("Id")
        state = record.get("State")
        mounts = record.get("Mounts")
        config = record.get("Config")
        if (
            type(container_id) is not str
            or container_id not in container_ids
            or container_id in by_id
            or not isinstance(state, dict)
            or state.get("Running") is not True
            or not isinstance(mounts, list)
            or not isinstance(config, dict)
        ):
            raise MigrationError("normal runtime writer census is malformed")
        by_id[container_id] = record
        labels = config.get("Labels")
        environment = config.get("Env")
        if labels is None:
            labels = {}
        if environment is None:
            environment = []
        if (
            not isinstance(labels, dict)
            or any(
                type(name) is not str or type(value) is not str
                for name, value in labels.items()
            )
            or not isinstance(environment, list)
            or any(type(item) is not str for item in environment)
        ):
            raise MigrationError("normal runtime writer census is malformed")
        config_files = labels.get(
            "com.docker.compose.project.config_files",
            "",
        )
        if str(plan.runtime.compose_overlay) in config_files.split(","):
            migration_ids.append(container_id)
        if any(
            item.partition("=")[0].startswith("STALWART_RECOVERY_")
            for item in environment
        ):
            migration_ids.append(container_id)
        writes_protected_store = False
        for mount in mounts:
            if (
                not isinstance(mount, dict)
                or type(mount.get("Type")) is not str
            ):
                raise MigrationError(
                    "normal runtime writer census is malformed",
                )
            if mount["Type"] != "bind":
                continue
            source_value = mount.get("Source")
            writable = mount.get("RW")
            if (
                type(source_value) is not str
                or type(writable) is not bool
            ):
                raise MigrationError(
                    "normal runtime writer census is malformed",
                )
            source_path = Path(source_value)
            if (
                not source_path.is_absolute()
                or Path(os.path.normpath(source_value)) != source_path
            ):
                raise MigrationError(
                    "normal runtime writer census is malformed",
                )
            if writable and any(
                _paths_overlap(source_path, store)
                for store in protected
            ):
                writes_protected_store = True
        if writes_protected_store:
            writer_ids.append(container_id)
        if container_id == expected_container_id:
            if (
                labels.get("com.docker.compose.project")
                != plan.source.compose_project
                or labels.get("com.docker.compose.service")
                != plan.source.compose_service
                or labels.get(
                    "com.docker.compose.project.working_dir",
                )
                != str(plan.source.checkout_root)
                or labels.get(
                    "com.docker.compose.project.config_files",
                )
                != str(plan.source.base_compose)
                or labels.get("com.docker.compose.oneoff") != "False"
                or frozenset(environment)
                != _normal_runtime_environment(public_url)
            ):
                raise MigrationError(
                    "normal runtime writer census is malformed",
                )
    if set(by_id) != set(container_ids):
        raise MigrationError("normal runtime writer census is malformed")
    return tuple(sorted(writer_ids)), tuple(sorted(set(migration_ids)))


def _build_recovery_retirement_proof(
    plan: RecoveryRetirementPlan,
    inspection: NormalRuntimeInspection,
    *,
    old_recovery_auth_status: int,
    writer_ids: tuple[str, ...],
    migration_ids: tuple[str, ...],
) -> RecoveryRetirementProof:
    proof = RecoveryRetirementProof(
        apply_receipt_sha256=plan.apply_receipt.sha256,
        bootstrap_receipt_sha256=plan.bootstrap_receipt.sha256,
        bootstrap_proof_sha256=plan.bootstrap.bootstrap_proof_sha256,
        management_account_id=plan.bootstrap.management_account_id,
        management_api_key_id=plan.bootstrap.management_api_key_id,
        ip_restriction_decision=plan.bootstrap.ip_restriction_decision,
        permissions_sha256=plan.bootstrap.permissions_sha256,
        protected_accounts_sha256=(
            plan.bootstrap.protected_accounts_sha256
        ),
        safe_objects_sha256=plan.bootstrap.safe_objects_sha256,
        preserved_objects_sha256=(
            plan.bootstrap.preserved_objects_sha256
        ),
        routing_proof_sha256=plan.bootstrap.routing_proof_sha256,
        listener_id=plan.bootstrap.listener_id,
        account_projection_sha256=(
            plan.bootstrap.account_projection_sha256
        ),
        api_key_projection_sha256=(
            plan.bootstrap.api_key_projection_sha256
        ),
        retirement_attempt_sha256=plan.retirement_attempt.sha256,
        operation_plan_sha256=plan.operation_plan_sha256,
        server_version="0.16.17",
        management_status=200,
        readiness_status=200,
        old_recovery_auth_status=old_recovery_auth_status,
        normal_url=NORMAL_RUNTIME_BASE_URL,
        image_reference=inspection.image_reference,
        image_id=inspection.image_id,
        container_id=inspection.container_id,
        overlapping_writer_ids=writer_ids,
        migration_container_ids=migration_ids,
        recovery_environment_names=(
            inspection.recovery_environment_names
        ),
    )
    _recovery_proof_metadata(proof, plan)
    return proof


def _require_recovery_artifacts_absent(
    paths: MigrationPaths,
    plan: RecoveryRetirementPlan,
) -> None:
    if (
        type(plan) is not RecoveryRetirementPlan
        or plan.runtime.recovery_env_file
        != paths.migration_root / "recovery.env"
        or plan.runtime.config_dir
        != paths.migration_root / "recovery-config"
    ):
        raise MigrationError("retired recovery artifacts are malformed")
    for path in (
        plan.runtime.recovery_env_file,
        plan.runtime.config_dir,
    ):
        try:
            path.lstat()
        except FileNotFoundError:
            continue
        except OSError:
            raise MigrationError(
                "retired recovery artifacts could not be inspected",
            ) from None
        raise MigrationError("retired recovery artifacts remain present")


class RecoveryRetirementExecutor:
    """Start and prove the exact normal runtime before retiring recovery."""

    def __init__(
        self,
        *,
        paths: MigrationPaths,
        runner: object = run_redacted_command,
        state_runner: object = run_command,
        jmap_probe_runner: object = run_fixed_jmap_auth_probe,
        basic_jmap_probe_runner: object = (
            run_fixed_normal_basic_jmap_auth_probe
        ),
        smtp_probe_runner: object = run_fixed_normal_smtp_auth_probe,
        readiness_probe_runner: object = run_fixed_normal_readiness_probe,
    ) -> None:
        if (
            not isinstance(paths, MigrationPaths)
            or paths != MigrationPaths.for_repository(
                paths.repository_root,
            )
            or not callable(runner)
            or not callable(state_runner)
            or not callable(jmap_probe_runner)
            or not callable(basic_jmap_probe_runner)
            or not callable(smtp_probe_runner)
            or not callable(readiness_probe_runner)
        ):
            raise MigrationError(
                "recovery retirement executor dependency is unavailable",
            )
        self._paths = paths
        self._runner = runner
        self._state_runner = state_runner
        self._jmap_probe_runner = jmap_probe_runner
        self._basic_jmap_probe_runner = basic_jmap_probe_runner
        self._smtp_probe_runner = smtp_probe_runner
        self._readiness_probe_runner = readiness_probe_runner

    def __repr__(self) -> str:
        return "RecoveryRetirementExecutor(<redacted>)"

    def __call__(
        self,
        plan: RecoveryRetirementPlan,
        recovery_credential: RecoveryCredentialLease,
        checkpoint: object,
    ) -> RecoveryRetirementProof:
        if (
            type(plan) is not RecoveryRetirementPlan
            or type(recovery_credential) is not RecoveryCredentialLease
            or recovery_credential.closed
            or not callable(checkpoint)
        ):
            raise MigrationError(
                "recovery retirement executor input is malformed",
            )
        normal_may_be_running = False
        checkpointed = False
        stop_command: list[str] | None = None
        try:
            normal_config = _validate_receipt_bound_normal_config(plan)
            model_result = _invoke_normal_runtime_command(
                self._runner,
                build_normal_compose_model_command(plan),
                plan=plan,
                timeout=30,
            )
            _validate_normal_compose_model(
                model_result.stdout,
                plan=plan,
            )
            image_result = _invoke_normal_runtime_command(
                self._runner,
                build_normal_runtime_image_inspect_command(),
                plan=plan,
                timeout=30,
            )
            _validate_local_migration_image_id(image_result.stdout)
            stop_command = build_normal_compose_stop_command(plan)
            if (
                _validate_receipt_bound_normal_config(plan)
                != normal_config
            ):
                raise MigrationError(
                    "normal runtime config changed before start",
                )
            normal_may_be_running = True
            _invoke_normal_runtime_command(
                self._runner,
                build_normal_compose_start_command(plan),
                plan=plan,
                timeout=180,
            )
            ps_result = _invoke_normal_runtime_command(
                self._runner,
                build_normal_compose_ps_command(plan),
                plan=plan,
                timeout=30,
            )
            container_id = _migration_container_id(ps_result.stdout)
            inspect_result = _invoke_normal_runtime_command(
                self._runner,
                build_normal_container_inspect_command(container_id),
                plan=plan,
                timeout=30,
            )
            inspection = _validate_normal_container_inspection(
                inspect_result.stdout,
                plan=plan,
                container_id=container_id,
            )
            version_result = _invoke_normal_runtime_command(
                self._runner,
                build_migration_server_version_command(container_id),
                plan=plan,
                timeout=60,
            )
            _validated_server_version(version_result.stdout)
            _invoke_normal_readiness_probe(
                self._readiness_probe_runner,
            )

            _prove_normal_management_key(
                self._paths,
                plan,
                self._jmap_probe_runner,
                expected_api_url=_normal_runtime_expected_api_url(plan),
            )
            _prove_normal_management_password(
                plan,
                basic_jmap_probe=self._basic_jmap_probe_runner,
                smtp_probe=self._smtp_probe_runner,
                expected_api_url=_normal_runtime_expected_api_url(plan),
            )
            old_recovery_status = _prove_recovery_credential_rejected(
                recovery_credential,
                self._jmap_probe_runner,
                expected_api_url=_normal_runtime_expected_api_url(plan),
            )

            if _validate_receipt_bound_normal_config(plan) != normal_config:
                raise MigrationError(
                    "normal runtime config changed before restart",
                )
            _invoke_normal_runtime_command(
                self._runner,
                build_normal_compose_restart_command(plan),
                plan=plan,
                timeout=60,
            )
            restarted_ps = _invoke_normal_runtime_command(
                self._runner,
                build_normal_compose_ps_command(plan),
                plan=plan,
                timeout=30,
            )
            restarted_container_id = _migration_container_id(
                restarted_ps.stdout,
            )
            if restarted_container_id != container_id:
                raise MigrationError(
                    "normal runtime identity changed during restart",
                )
            restarted_inspect = _invoke_normal_runtime_command(
                self._runner,
                build_normal_container_inspect_command(container_id),
                plan=plan,
                timeout=30,
            )
            restarted_inspection = _validate_normal_container_inspection(
                restarted_inspect.stdout,
                plan=plan,
                container_id=container_id,
            )
            if restarted_inspection != inspection:
                raise MigrationError(
                    "normal runtime inspection changed during restart",
                )
            restarted_version = _invoke_normal_runtime_command(
                self._runner,
                build_migration_server_version_command(container_id),
                plan=plan,
                timeout=60,
            )
            _validated_server_version(restarted_version.stdout)
            _invoke_normal_readiness_probe(self._readiness_probe_runner)
            _prove_normal_management_key(
                self._paths,
                plan,
                self._jmap_probe_runner,
                expected_api_url=_normal_runtime_expected_api_url(plan),
            )
            _prove_normal_management_password(
                plan,
                basic_jmap_probe=self._basic_jmap_probe_runner,
                smtp_probe=self._smtp_probe_runner,
                expected_api_url=_normal_runtime_expected_api_url(plan),
            )
            restarted_recovery_status = (
                _prove_recovery_credential_rejected(
                    recovery_credential,
                    self._jmap_probe_runner,
                    expected_api_url=_normal_runtime_expected_api_url(plan),
                )
            )
            if restarted_recovery_status != old_recovery_status:
                raise MigrationError(
                    "recovery rejection changed during restart",
                )

            writer_ids, migration_ids = _normal_runtime_writer_census(
                self._paths,
                plan,
                expected_container_id=container_id,
                runner=self._state_runner,
            )
            proof = _build_recovery_retirement_proof(
                plan,
                inspection,
                old_recovery_auth_status=old_recovery_status,
                writer_ids=writer_ids,
                migration_ids=migration_ids,
            )
            checkpoint(proof)
            checkpointed = True
            durable = _validate_retirement_proof_snapshot(
                _retirement_proof_snapshot(self._paths),
                plan,
            )
            if durable != proof:
                raise MigrationError(
                    "recovery retirement checkpoint differs",
                )
            _delete_bound_recovery_artifacts(self._paths, plan)
            return proof
        except BaseException as primary:
            if (
                normal_may_be_running
                and not checkpointed
                and stop_command is not None
            ):
                try:
                    _invoke_normal_runtime_command(
                        self._runner,
                        stop_command,
                        plan=plan,
                        timeout=60,
                    )
                except BaseException as stop_error:
                    if not isinstance(primary, Exception):
                        raise primary
                    if not isinstance(stop_error, Exception):
                        raise stop_error
            if not isinstance(primary, Exception):
                raise
            raise MigrationError(
                "recovery retirement execution failed safely",
            ) from None


class RecoveryRetirementPostflightVerifier:
    """Reprove the surviving normal runtime without reading recovery."""

    def __init__(
        self,
        *,
        paths: MigrationPaths,
        runner: object = run_redacted_command,
        state_runner: object = run_command,
        jmap_probe_runner: object = run_fixed_jmap_auth_probe,
        basic_jmap_probe_runner: object = (
            run_fixed_normal_basic_jmap_auth_probe
        ),
        smtp_probe_runner: object = run_fixed_normal_smtp_auth_probe,
        readiness_probe_runner: object = run_fixed_normal_readiness_probe,
    ) -> None:
        if (
            not isinstance(paths, MigrationPaths)
            or paths != MigrationPaths.for_repository(
                paths.repository_root,
            )
            or not callable(runner)
            or not callable(state_runner)
            or not callable(jmap_probe_runner)
            or not callable(basic_jmap_probe_runner)
            or not callable(smtp_probe_runner)
            or not callable(readiness_probe_runner)
        ):
            raise MigrationError(
                "recovery retirement postflight dependency is unavailable",
            )
        self._paths = paths
        self._runner = runner
        self._state_runner = state_runner
        self._jmap_probe_runner = jmap_probe_runner
        self._basic_jmap_probe_runner = basic_jmap_probe_runner
        self._smtp_probe_runner = smtp_probe_runner
        self._readiness_probe_runner = readiness_probe_runner

    def __repr__(self) -> str:
        return "RecoveryRetirementPostflightVerifier(<redacted>)"

    def __call__(
        self,
        plan: RecoveryRetirementPlan,
    ) -> RecoveryRetirementProof:
        if (
            type(plan) is not RecoveryRetirementPlan
        ):
            raise MigrationError(
                "recovery retirement postflight input is malformed",
            )
        try:
            normal_config = _validate_receipt_bound_normal_config(plan)
            model_result = _invoke_normal_runtime_command(
                self._runner,
                build_normal_compose_model_command(plan),
                plan=plan,
                timeout=30,
            )
            _validate_normal_compose_model(
                model_result.stdout,
                plan=plan,
            )
            image_result = _invoke_normal_runtime_command(
                self._runner,
                build_normal_runtime_image_inspect_command(),
                plan=plan,
                timeout=30,
            )
            _validate_local_migration_image_id(image_result.stdout)
            if (
                _validate_receipt_bound_normal_config(plan)
                != normal_config
            ):
                raise MigrationError(
                    "normal runtime config changed during postflight",
                )
            ps_result = _invoke_normal_runtime_command(
                self._runner,
                build_normal_compose_ps_command(plan),
                plan=plan,
                timeout=30,
            )
            container_id = _migration_container_id(ps_result.stdout)
            inspect_result = _invoke_normal_runtime_command(
                self._runner,
                build_normal_container_inspect_command(container_id),
                plan=plan,
                timeout=30,
            )
            inspection = _validate_normal_container_inspection(
                inspect_result.stdout,
                plan=plan,
                container_id=container_id,
            )
            version_result = _invoke_normal_runtime_command(
                self._runner,
                build_migration_server_version_command(container_id),
                plan=plan,
                timeout=60,
            )
            _validated_server_version(version_result.stdout)
            _invoke_normal_readiness_probe(
                self._readiness_probe_runner,
            )

            _prove_normal_management_key(
                self._paths,
                plan,
                self._jmap_probe_runner,
                expected_api_url=_normal_runtime_expected_api_url(plan),
            )
            _prove_normal_management_password(
                plan,
                basic_jmap_probe=self._basic_jmap_probe_runner,
                smtp_probe=self._smtp_probe_runner,
                expected_api_url=_normal_runtime_expected_api_url(plan),
            )
            writer_ids, migration_ids = _normal_runtime_writer_census(
                self._paths,
                plan,
                expected_container_id=container_id,
                runner=self._state_runner,
            )
            _require_recovery_artifacts_absent(self._paths, plan)
            checkpoint = _validate_retirement_proof_snapshot(
                _retirement_proof_snapshot(self._paths),
                plan,
            )
            proof = _build_recovery_retirement_proof(
                plan,
                inspection,
                old_recovery_auth_status=(
                    checkpoint.old_recovery_auth_status
                ),
                writer_ids=writer_ids,
                migration_ids=migration_ids,
            )
            if proof != checkpoint:
                raise MigrationError(
                    "recovery retirement postflight proof differs",
                )
            return proof
        except (MigrationError, KeyboardInterrupt, SystemExit):
            raise
        except BaseException:
            raise MigrationError(
                "recovery retirement postflight failed safely",
            ) from None


class MigrationApplyExecutor:
    """Callable runtime adapter for one already-validated apply plan."""

    def __init__(
        self,
        *,
        credential_factory: object,
        runner: object = run_redacted_command,
        secret_runner: object = run_redacted_secret_command,
        state_runner: object = run_command,
    ) -> None:
        if (
            not callable(credential_factory)
            or not callable(runner)
            or not callable(secret_runner)
            or not callable(state_runner)
        ):
            raise MigrationError("migration apply executor dependency is unavailable")
        self._credential_factory = credential_factory
        self._runner = runner
        self._secret_runner = secret_runner
        self._state_runner = state_runner

    def __repr__(self) -> str:
        return "MigrationApplyExecutor(<redacted>)"

    def __call__(self, plan: ApplyPlan) -> str:
        paths, compose_values, snapshots = _validated_runtime_plan_files(plan)
        compose_environment = _runtime_command_environment(compose_values)
        compose_names = {
            MIGRATION_DATA_VARIABLE,
            MIGRATION_CONFIG_VARIABLE,
            MIGRATION_RECOVERY_ENV_VARIABLE,
        }
        config_command = build_migration_compose_config_command(plan)
        start_command = build_migration_compose_start_command(plan)
        ps_command = build_migration_compose_ps_command(plan)
        stop_command = build_migration_compose_stop_command(plan)
        credential = bytearray()

        def execute() -> object:
            nonlocal credential
            try:
                candidate = self._credential_factory()
                if isinstance(candidate, bytearray):
                    credential = candidate
                if type(candidate) is not bytearray:
                    raise MigrationError(
                        "migration recovery credential is malformed",
                    )
                if not _valid_recovery_credential_slice(
                    credential,
                    start=0,
                    end=len(credential),
                ):
                    raise MigrationError(
                        "migration recovery credential is malformed",
                    )
                _materialize_migration_runtime_artifacts(
                    paths,
                    plan,
                    snapshots,
                    credential,
                )
                _validated_runtime_plan_files(plan)
                _invoke_runtime_runner(
                    self._runner,
                    config_command,
                    stdin=b"",
                    env=compose_environment,
                    timeout=30,
                    cwd=plan.source.checkout_root,
                    allowed_stalwart_names=compose_names,
                )
                image_result = _invoke_runtime_runner(
                    self._runner,
                    build_migration_image_inspect_command(),
                    stdin=b"",
                    env=compose_environment,
                    timeout=30,
                    cwd=plan.source.checkout_root,
                    allowed_stalwart_names=compose_names,
                )
                _validate_local_migration_image_id(image_result.stdout)
                assert_no_running_store_writers(
                    paths,
                    source_store=plan.source.provider_store,
                    runner=self._state_runner,
                )
                _invoke_runtime_runner(
                    self._runner,
                    start_command,
                    stdin=b"",
                    env=compose_environment,
                    timeout=180,
                    cwd=plan.source.checkout_root,
                    allowed_stalwart_names=compose_names,
                )
                ps_result = _invoke_runtime_runner(
                    self._runner,
                    ps_command,
                    stdin=b"",
                    env=compose_environment,
                    timeout=30,
                    cwd=plan.source.checkout_root,
                    allowed_stalwart_names=compose_names,
                )
                container_id = _migration_container_id(ps_result.stdout)
                inspect_result = _invoke_runtime_runner(
                    self._runner,
                    build_migration_container_inspect_command(container_id),
                    stdin=b"",
                    env=compose_environment,
                    timeout=30,
                    cwd=plan.source.checkout_root,
                    allowed_stalwart_names=compose_names,
                )
                _validate_migration_container_inspection(
                    inspect_result.stdout,
                    plan=plan,
                    container_id=container_id,
                )
                export = snapshots.get(paths.export)
                if export is None:
                    raise MigrationError("migration export is unavailable")
                cli_environment = _runtime_command_environment(
                    {
                        "STALWART_URL": "http://127.0.0.1:8080",
                    },
                )
                apply_result = _invoke_runtime_secret_runner(
                    self._secret_runner,
                    build_migration_cli_apply_command(container_id),
                    stdin=export.content,
                    env=cli_environment,
                    credential=credential,
                    timeout=180,
                    cwd=plan.source.checkout_root,
                )
                if len(apply_result.stdout) > 16 * 1024 * 1024:
                    raise MigrationError("migration apply evidence is malformed")
                try:
                    evidence = apply_result.stdout.decode("utf-8")
                except UnicodeDecodeError:
                    raise MigrationError(
                        "migration apply evidence is malformed",
                    ) from None
                validate_apply_ndjson(
                    evidence,
                    expected_operations=plan.operations,
                )
                _validated_runtime_plan_files(plan)
                return evidence
            finally:
                _wipe_bytearray(credential)

        def stop() -> None:
            _invoke_runtime_runner(
                self._runner,
                stop_command,
                stdin=b"",
                env=compose_environment,
                timeout=60,
                cwd=plan.source.checkout_root,
                allowed_stalwart_names=compose_names,
            )

        result = _execute_with_mandatory_stop(
            execute,
            stop,
            failure_message="migration apply execution failed safely",
        )
        if type(result) is not str:
            raise MigrationError("migration apply execution failed safely")
        return result


def _validated_server_version(stdout: bytes) -> str:
    if type(stdout) is not bytes or stdout not in {
        b"0.16.17",
        b"0.16.17\n",
    }:
        raise MigrationError("post-apply version output is malformed")
    return "0.16.17"


def _validated_account_query_ids(stdout: bytes) -> tuple[str, ...]:
    if type(stdout) is not bytes or len(stdout) > 1024 * 1024:
        raise MigrationError("post-apply Account query output is malformed")
    try:
        value = json.loads(
            stdout.decode("utf-8"),
            object_pairs_hook=_strict_json_object,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise MigrationError(
            "post-apply Account query output is malformed",
        ) from None
    if not isinstance(value, list):
        raise MigrationError("post-apply Account query output is malformed")
    observed_ids: list[str] = []
    unique_ids: set[str] = set()
    for item in value:
        if (
            not isinstance(item, dict)
            or set(item) != {"id"}
            or type(item.get("id")) is not str
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:@-]{0,255}", item["id"])
            is None
            or item["id"] in unique_ids
        ):
            raise MigrationError("post-apply Account query output is malformed")
        observed_ids.append(item["id"])
        unique_ids.add(item["id"])
    return tuple(observed_ids)


class MigrationPostApplyVerifier:
    """Independent authenticated runtime census for an applied plan."""

    def __init__(
        self,
        *,
        runner: object = run_redacted_command,
        secret_runner: object = run_redacted_secret_command,
        state_runner: object = run_command,
    ) -> None:
        if (
            not callable(runner)
            or not callable(secret_runner)
            or not callable(state_runner)
        ):
            raise MigrationError("post-apply verifier dependency is unavailable")
        self._runner = runner
        self._secret_runner = secret_runner
        self._state_runner = state_runner

    def __repr__(self) -> str:
        return "MigrationPostApplyVerifier(<redacted>)"

    def __call__(self, plan: ApplyPlan) -> PostApplyCensusProof:
        paths, compose_values, snapshots = _validated_runtime_plan_files(plan)
        compose_environment = _runtime_command_environment(compose_values)
        compose_names = {
            MIGRATION_DATA_VARIABLE,
            MIGRATION_CONFIG_VARIABLE,
            MIGRATION_RECOVERY_ENV_VARIABLE,
        }
        config_command = build_migration_compose_config_command(plan)
        start_command = build_migration_compose_start_command(plan)
        ps_command = build_migration_compose_ps_command(plan)
        stop_command = build_migration_compose_stop_command(plan)
        credential = bytearray()
        lease: RecoveryCredentialLease | None = None

        def execute() -> object:
            nonlocal credential, lease
            try:
                converted = snapshots.get(paths.converted_config)
                if converted is None:
                    raise MigrationError(
                        "migration converted config is unavailable",
                    )
                runtime_artifacts = _validate_runtime_artifacts_ready(
                    paths,
                    plan.runtime,
                    converted_config=converted,
                )
                lease = _load_recovery_credential_lease(
                    paths,
                    plan.runtime,
                    runtime_artifacts.recovery_environment,
                )
                borrowed = lease.borrow()
                try:
                    credential = bytearray(borrowed)
                finally:
                    borrowed.release()
                if not _valid_recovery_credential_slice(
                    credential,
                    start=0,
                    end=len(credential),
                ):
                    raise MigrationError(
                        "migration recovery credential is malformed",
                    )
                cli_environment = _runtime_command_environment(
                    {
                        "STALWART_URL": "http://127.0.0.1:8080",
                    },
                )
                _invoke_runtime_runner(
                    self._runner,
                    config_command,
                    stdin=b"",
                    env=compose_environment,
                    timeout=30,
                    cwd=plan.source.checkout_root,
                    allowed_stalwart_names=compose_names,
                )
                image_result = _invoke_runtime_runner(
                    self._runner,
                    build_migration_image_inspect_command(),
                    stdin=b"",
                    env=compose_environment,
                    timeout=30,
                    cwd=plan.source.checkout_root,
                    allowed_stalwart_names=compose_names,
                )
                _validate_local_migration_image_id(image_result.stdout)
                assert_no_running_store_writers(
                    paths,
                    source_store=plan.source.provider_store,
                    runner=self._state_runner,
                )
                _invoke_runtime_runner(
                    self._runner,
                    start_command,
                    stdin=b"",
                    env=compose_environment,
                    timeout=180,
                    cwd=plan.source.checkout_root,
                    allowed_stalwart_names=compose_names,
                )
                ps_result = _invoke_runtime_runner(
                    self._runner,
                    ps_command,
                    stdin=b"",
                    env=compose_environment,
                    timeout=30,
                    cwd=plan.source.checkout_root,
                    allowed_stalwart_names=compose_names,
                )
                container_id = _migration_container_id(ps_result.stdout)
                inspect_result = _invoke_runtime_runner(
                    self._runner,
                    build_migration_container_inspect_command(container_id),
                    stdin=b"",
                    env=compose_environment,
                    timeout=30,
                    cwd=plan.source.checkout_root,
                    allowed_stalwart_names=compose_names,
                )
                _validate_migration_container_inspection(
                    inspect_result.stdout,
                    plan=plan,
                    container_id=container_id,
                )
                version_result = _invoke_runtime_runner(
                    self._runner,
                    build_migration_server_version_command(container_id),
                    stdin=b"",
                    env=compose_environment,
                    timeout=60,
                    cwd=plan.source.checkout_root,
                    allowed_stalwart_names=compose_names,
                )
                server_version = _validated_server_version(
                    version_result.stdout,
                )
                query_result = _invoke_runtime_secret_runner(
                    self._secret_runner,
                    build_migration_cli_account_query_command(container_id),
                    stdin=b"",
                    env=cli_environment,
                    credential=credential,
                    timeout=60,
                    cwd=plan.source.checkout_root,
                )
                account_ids = _validated_account_query_ids(
                    query_result.stdout,
                )
                expected_account_count = sum(
                    operation.count
                    for operation in plan.operations
                    if operation.op == "create"
                    and operation.object_name == "Account"
                )
                if len(account_ids) != expected_account_count:
                    raise MigrationError(
                        "post-apply Account census does not match the operation plan",
                    )
                proof = PostApplyCensusProof(
                    operations_sha256=plan.operations_sha256,
                    operation_count=len(plan.operations),
                    server_version=server_version,
                    management_status=200,
                )
                _post_apply_proof_metadata(proof, plan)
                _validated_runtime_plan_files(plan)
                return proof
            finally:
                _wipe_bytearray(credential)
                if lease is not None:
                    lease.close()

        def stop() -> None:
            _invoke_runtime_runner(
                self._runner,
                stop_command,
                stdin=b"",
                env=compose_environment,
                timeout=60,
                cwd=plan.source.checkout_root,
                allowed_stalwart_names=compose_names,
            )

        result = _execute_with_mandatory_stop(
            execute,
            stop,
            failure_message="post-apply verification failed safely",
        )
        if type(result) is not PostApplyCensusProof:
            raise MigrationError("post-apply verification failed safely")
        return result


def _run_migration_bootstrap_operation(
    plan: ApplyPlan,
    *,
    state_runner: object,
    runtime_runner: object,
    operation: object,
    credential: RecoveryCredentialLease,
    operation_lock: StalwartOperationLock,
    on_runtime_dispatch: object,
) -> object:
    if not callable(state_runner) or not callable(on_runtime_dispatch):
        raise MigrationError(
            "migration bootstrap runtime dependency is unavailable",
        )
    paths, compose_values, _snapshots = _validated_runtime_plan_files(plan)
    compose_environment = _runtime_command_environment(compose_values)
    compose_names = {
        MIGRATION_DATA_VARIABLE,
        MIGRATION_CONFIG_VARIABLE,
        MIGRATION_RECOVERY_ENV_VARIABLE,
    }
    config_command = build_migration_compose_config_command(plan)
    start_command = build_migration_compose_start_command(plan)
    ps_command = build_migration_compose_ps_command(plan)
    stop_command = build_migration_compose_stop_command(plan)

    def execute() -> object:
        operation_lock.assert_valid_for(plan.source.checkout_root)
        _invoke_runtime_runner(
            runtime_runner,
            config_command,
            stdin=b"",
            env=compose_environment,
            timeout=30,
            cwd=plan.source.checkout_root,
            allowed_stalwart_names=compose_names,
        )
        image_result = _invoke_runtime_runner(
            runtime_runner,
            build_migration_image_inspect_command(),
            stdin=b"",
            env=compose_environment,
            timeout=30,
            cwd=plan.source.checkout_root,
            allowed_stalwart_names=compose_names,
        )
        _validate_local_migration_image_id(image_result.stdout)
        assert_no_running_store_writers(
            paths,
            source_store=plan.source.provider_store,
            runner=state_runner,
        )
        on_runtime_dispatch()
        _invoke_runtime_runner(
            runtime_runner,
            start_command,
            stdin=b"",
            env=compose_environment,
            timeout=180,
            cwd=plan.source.checkout_root,
            allowed_stalwart_names=compose_names,
        )
        ps_result = _invoke_runtime_runner(
            runtime_runner,
            ps_command,
            stdin=b"",
            env=compose_environment,
            timeout=30,
            cwd=plan.source.checkout_root,
            allowed_stalwart_names=compose_names,
        )
        container_id = _migration_container_id(ps_result.stdout)
        inspect_result = _invoke_runtime_runner(
            runtime_runner,
            build_migration_container_inspect_command(container_id),
            stdin=b"",
            env=compose_environment,
            timeout=30,
            cwd=plan.source.checkout_root,
            allowed_stalwart_names=compose_names,
        )
        _validate_migration_container_inspection(
            inspect_result.stdout,
            plan=plan,
            container_id=container_id,
        )
        version_result = _invoke_runtime_runner(
            runtime_runner,
            build_migration_server_version_command(container_id),
            stdin=b"",
            env=compose_environment,
            timeout=60,
            cwd=plan.source.checkout_root,
            allowed_stalwart_names=compose_names,
        )
        _validated_server_version(version_result.stdout)
        operation_lock.assert_valid_for(plan.source.checkout_root)
        session = MigrationBootstrapRuntime(
            container_id=container_id,
            operations_sha256=plan.operations_sha256,
            credential=credential,
        )
        capability = session._capability
        try:
            result = operation(session)
            session._assert_bound_to(credential, capability)
            operation_lock.assert_valid_for(plan.source.checkout_root)
            return result
        finally:
            capability.close()

    def stop() -> None:
        _invoke_runtime_runner(
            runtime_runner,
            stop_command,
            stdin=b"",
            env=compose_environment,
            timeout=60,
            cwd=plan.source.checkout_root,
            allowed_stalwart_names=compose_names,
        )

    return _execute_with_mandatory_stop(
        execute,
        stop,
        failure_message=(
            "migration bootstrap runtime operation failed safely"
        ),
    )


def _recovery_container_ids(
    stdout: bytes,
    *,
    label: str,
) -> tuple[str, ...]:
    if type(stdout) is not bytes or len(stdout) > 128 * 65:
        raise MigrationError(f"{label} container identity is malformed")
    try:
        text = stdout.decode("ascii")
    except UnicodeDecodeError:
        raise MigrationError(f"{label} container identity is malformed") from None
    if not text:
        return ()
    lines = text.splitlines()
    if (
        not lines
        or len(lines) > 128
        or len(lines) != len(set(lines))
        or any(re.fullmatch(r"[0-9a-f]{64}", line) is None for line in lines)
    ):
        raise MigrationError(f"{label} container identity is malformed")
    return tuple(lines)


def _recovery_inspection_payload(
    stdout: bytes,
    *,
    label: str,
) -> dict[str, object]:
    if type(stdout) is not bytes or len(stdout) > 1024 * 1024:
        raise MigrationError(f"{label} inspection is malformed")
    try:
        value = json.loads(
            stdout.decode("utf-8"),
            object_pairs_hook=_strict_json_object,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise MigrationError(f"{label} inspection is malformed") from None
    if not isinstance(value, dict):
        raise MigrationError(f"{label} inspection is malformed")
    return value


def _identify_migration_runtime(
    plan: ApplyPlan,
    *,
    runtime_runner: object,
) -> tuple[tuple[str, bool], ...]:
    """Return exact main/owner containers, tolerating stopped legacy state."""
    if type(plan) is not ApplyPlan:
        raise MigrationError("migration recovery plan is malformed")
    compose_names = {
        MIGRATION_DATA_VARIABLE,
        MIGRATION_CONFIG_VARIABLE,
        MIGRATION_RECOVERY_ENV_VARIABLE,
    }
    environment = _runtime_command_environment(
        plan.runtime.compose_environment(),
    )
    ps_result = _invoke_runtime_runner(
        runtime_runner,
        build_migration_recovery_ps_command(plan),
        stdin=b"",
        env=environment,
        timeout=30,
        cwd=plan.source.checkout_root,
        allowed_stalwart_names=compose_names,
    )
    exact_by_service: dict[str, list[tuple[str, bool]]] = {
        plan.source.compose_service: [],
        MIGRATION_OWNER_SERVICE: [],
    }
    universal_keys = {
        "Id",
        "Image",
        "ImageID",
        "User",
        "Project",
        "Service",
        "WorkingDir",
        "ConfigFiles",
        "Oneoff",
        "Mounts",
        "Ports",
        "Running",
        "Restarting",
        "Health",
        "Entrypoint",
        "Cmd",
        "Restart",
    }
    main_keys = universal_keys - {
        "Entrypoint",
        "Cmd",
        "Restart",
        "Restarting",
    }
    owner_keys = universal_keys - {"Health", "Restarting"}
    for container_id in _recovery_container_ids(
        ps_result.stdout,
        label="migration recovery",
    ):
        inspection = _invoke_runtime_runner(
            runtime_runner,
            build_migration_recovery_container_inspect_command(container_id),
            stdin=b"",
            env=environment,
            timeout=30,
            cwd=plan.source.checkout_root,
            allowed_stalwart_names=compose_names,
        )
        payload = _recovery_inspection_payload(
            inspection.stdout,
            label="migration recovery",
        )
        service = payload.get("Service")
        if service not in exact_by_service:
            continue
        running = payload.get("Running")
        restarting = payload.get("Restarting")
        restart = payload.get("Restart")
        if (
            type(running) is not bool
            or type(restarting) is not bool
            or type(restart) is not str
            or not restart
        ):
            raise MigrationError(
                "migration recovery inspection is malformed",
            )
        if restarting:
            raise MigrationError(
                "migration recovery candidate is restarting",
            )
        try:
            if set(payload) != universal_keys:
                raise MigrationError(
                    "migration recovery inspection is malformed",
                )
            if service == plan.source.compose_service:
                if payload.get("Restart") != "no":
                    raise MigrationError(
                        "migration recovery inspection is malformed",
                    )
                main_payload = {
                    name: payload[name]
                    for name in main_keys
                }
                _validate_migration_container_inspection(
                    json.dumps(main_payload).encode("utf-8"),
                    plan=plan,
                    container_id=container_id,
                    require_healthy=False,
                    require_running=None,
                )
            else:
                owner_payload = {
                    name: payload[name]
                    for name in owner_keys
                }
                _validate_migration_owner_container_inspection(
                    json.dumps(owner_payload).encode("utf-8"),
                    plan=plan,
                    container_id=container_id,
                    require_running=None,
                )
        except MigrationError:
            if running:
                raise MigrationError(
                    "migration recovery running candidate is not exact",
                ) from None
            if restart not in {"no", "unless-stopped"}:
                raise MigrationError(
                    "migration recovery stopped candidate can restart",
                ) from None
            continue
        exact_by_service[service].append((container_id, running))
    for service, candidates in exact_by_service.items():
        if len(candidates) > 1:
            raise MigrationError(
                f"migration recovery {service} identity is ambiguous",
            )
    exact = [
        candidate
        for service in (
            plan.source.compose_service,
            MIGRATION_OWNER_SERVICE,
        )
        for candidate in exact_by_service[service]
    ]
    return tuple(exact)


def _identify_normal_runtime(
    plan: RecoveryRetirementPlan,
    *,
    runtime_runner: object,
) -> tuple[str, bool] | None:
    """Return only the exact receipt-bound normal container and its state."""
    if type(plan) is not RecoveryRetirementPlan:
        raise MigrationError("normal recovery plan is malformed")
    ps_result = _invoke_normal_runtime_command(
        runtime_runner,
        build_normal_recovery_ps_command(plan),
        plan=plan,
        timeout=30,
    )
    exact: list[tuple[str, bool]] = []
    for container_id in _recovery_container_ids(
        ps_result.stdout,
        label="normal recovery",
    ):
        inspection = _invoke_normal_runtime_command(
            runtime_runner,
            build_normal_recovery_container_inspect_command(container_id),
            plan=plan,
            timeout=30,
        )
        payload = _recovery_inspection_payload(
            inspection.stdout,
            label="normal runtime",
        )
        running = payload.get("Running")
        restarting = payload.get("Restarting")
        restart = payload.get("Restart")
        if (
            type(running) is not bool
            or type(restarting) is not bool
            or type(restart) is not str
            or not restart
        ):
            raise MigrationError(
                "normal recovery inspection is malformed",
            )
        if restarting:
            raise MigrationError(
                "normal recovery candidate is restarting",
            )
        try:
            _validate_normal_container_inspection(
                inspection.stdout,
                plan=plan,
                container_id=container_id,
                require_healthy=False,
                require_running=None,
                revalidate_plan=False,
                expected_restart="unless-stopped",
            )
        except MigrationError:
            if running:
                raise MigrationError(
                    "normal recovery running candidate is not exact",
                ) from None
            if restart not in {"no", "unless-stopped"}:
                raise MigrationError(
                    "normal recovery stopped candidate can restart",
                ) from None
            continue
        exact.append((container_id, running))
    if len(exact) > 1:
        raise MigrationError("normal recovery container identity is ambiguous")
    return exact[0] if exact else None


def run_validated_migration_runtime(
    paths: MigrationPaths,
    *,
    apply_receipt_path: Path,
    source_receipt_path: Path,
    script_path: Path,
    dry_run_receipt_path: Path,
    review_receipt_path: Path,
    state_runner: object = run_command,
    runtime_runner: object = run_redacted_command,
    python_executable: str,
    operation: object,
    operation_lock: object = None,
    rollback_activator: object = default_rollback_activator,
    expected_script_sha256: str = MIGRATION_SCRIPT_SHA256,
) -> object:
    """Run one callback inside the exact validated recovery-only runtime."""
    if not isinstance(paths, MigrationPaths):
        raise MigrationError("migration runtime paths are malformed")
    if type(operation_lock) is not StalwartOperationLock:
        raise MigrationError(
            "a live Stalwart operation lock is required",
        )
    operation_lock.assert_valid_for(paths.repository_root)
    if (
        not callable(state_runner)
        or not callable(runtime_runner)
        or not callable(operation)
        or not callable(rollback_activator)
    ):
        raise MigrationError(
            "migration bootstrap runtime dependency is unavailable",
        )
    _require_fixed_apply_paths(
        paths,
        source_receipt_path=source_receipt_path,
        script_path=script_path,
        dry_run_receipt_path=dry_run_receipt_path,
        review_receipt_path=review_receipt_path,
    )
    if apply_receipt_path != paths.apply_receipt:
        raise MigrationError(
            "apply receipt is not the fixed repository path",
        )
    durable_initial = _validated_apply_receipt_for_retirement(
        paths,
        source_receipt_path=source_receipt_path,
        script_path=script_path,
        dry_run_receipt_path=dry_run_receipt_path,
        review_receipt_path=review_receipt_path,
        apply_receipt_path=apply_receipt_path,
        runner=state_runner,
        python_executable=python_executable,
        expected_script_sha256=expected_script_sha256,
        runtime_phase="durable-recovery",
        writer_census=False,
    )
    durable_validated = durable_initial[0]
    operation_lock.assert_valid_for(paths.repository_root)
    plan = durable_validated.plan
    recovery_binding = _rollback_recovery_binding(paths, plan)
    if recovery_binding is None:
        raise MigrationError("rollback recovery binding is unavailable")
    rollback_binding: _RollbackRecoveryBinding | None = recovery_binding

    try:
        assert_no_running_store_writers(
            paths,
            source_store=plan.source.provider_store,
            runner=state_runner,
        )
    except BaseException as census_error:
        operation_lock.assert_valid_for(paths.repository_root)
        try:
            _activate_rollback_after_primary_failure(
                paths,
                recovery_binding,
                primary=census_error,
                operation_lock=operation_lock,
                state_runner=state_runner,
                runtime_runner=runtime_runner,
                rollback_activator=rollback_activator,
            )
        except BaseException:
            if not isinstance(census_error, Exception):
                raise census_error
            raise
        if not isinstance(census_error, Exception):
            raise census_error
        raise MigrationError(
            "migration runtime failure was recovered; "
            "reconciliation is required",
        ) from None

    try:
        initial = _validated_apply_receipt_for_retirement(
            paths,
            source_receipt_path=source_receipt_path,
            script_path=script_path,
            dry_run_receipt_path=dry_run_receipt_path,
            review_receipt_path=review_receipt_path,
            apply_receipt_path=apply_receipt_path,
            runner=state_runner,
            python_executable=python_executable,
            expected_script_sha256=expected_script_sha256,
            runtime_phase="ready",
            writer_census=False,
        )
        validated = initial[0]
        if (
            validated.runtime_artifacts is None
            or validated.plan != plan
            or validated.source != durable_validated.source
            or validated.identities != durable_validated.identities
        ):
            raise MigrationError(
                "migration bootstrap runtime state changed during "
                "recovery validation",
            )
        operation_lock.assert_valid_for(paths.repository_root)
    except BaseException as primary:
        _activate_rollback_after_primary_failure(
            paths,
            recovery_binding,
            primary=primary,
            operation_lock=operation_lock,
            state_runner=state_runner,
            runtime_runner=runtime_runner,
            rollback_activator=rollback_activator,
        )
        raise

    def mark_runtime_dispatched() -> None:
        nonlocal rollback_binding
        operation_lock.assert_valid_for(paths.repository_root)
        candidate = _rollback_recovery_binding(paths, plan)
        if candidate is None:
            raise MigrationError("rollback recovery binding is unavailable")
        if rollback_binding is not None and rollback_binding != candidate:
            raise MigrationError("rollback recovery binding changed")
        rollback_binding = candidate

    provider_descriptor: int | None = None
    try:
        provider_descriptor, provider_identity = _open_bound_directory(
            plan.source.provider_store,
            root=plan.source.checkout_root,
            label="source provider store",
        )
        with _load_recovery_credential_lease(
            paths,
            plan.runtime,
            validated.runtime_artifacts.recovery_environment,
        ) as credential:
            result = _run_migration_bootstrap_operation(
                plan,
                state_runner=state_runner,
                runtime_runner=runtime_runner,
                operation=operation,
                credential=credential,
                operation_lock=operation_lock,
                on_runtime_dispatch=mark_runtime_dispatched,
            )

        operation_lock.assert_valid_for(paths.repository_root)
        _require_bound_directory(
            provider_descriptor,
            provider_identity,
            plan.source.provider_store,
            root=plan.source.checkout_root,
            label="source provider store",
        )

        final = _validated_apply_receipt_for_retirement(
            paths,
            source_receipt_path=source_receipt_path,
            script_path=script_path,
            dry_run_receipt_path=dry_run_receipt_path,
            review_receipt_path=review_receipt_path,
            apply_receipt_path=apply_receipt_path,
            runner=state_runner,
            python_executable=python_executable,
            expected_script_sha256=expected_script_sha256,
            runtime_phase="ready",
            writer_census=True,
        )
        operation_lock.assert_valid_for(paths.repository_root)
        _require_bound_directory(
            provider_descriptor,
            provider_identity,
            plan.source.provider_store,
            root=plan.source.checkout_root,
            label="source provider store",
        )
        if initial != final:
            raise MigrationError(
                "migration bootstrap runtime state changed outside the provider store",
            )
        return result
    except BaseException as primary:
        if rollback_binding is not None:
            _activate_rollback_after_primary_failure(
                paths,
                rollback_binding,
                primary=primary,
                operation_lock=operation_lock,
                state_runner=state_runner,
                runtime_runner=runtime_runner,
                rollback_activator=rollback_activator,
            )
        raise
    finally:
        if provider_descriptor is not None:
            try:
                os.close(provider_descriptor)
            except OSError:
                pass


def _require_fixed_apply_paths(
    paths: MigrationPaths,
    *,
    source_receipt_path: Path,
    script_path: Path,
    dry_run_receipt_path: Path,
    review_receipt_path: Path,
) -> None:
    if not isinstance(paths, MigrationPaths):
        raise MigrationError("apply paths are malformed")
    _plain_absolute(paths.repository_root, "repository root")
    if paths != MigrationPaths.for_repository(paths.repository_root):
        raise MigrationError("apply paths are not the fixed repository paths")
    requested = (
        (source_receipt_path, paths.source_receipt, "source receipt"),
        (script_path, paths.migration_script, "migration script"),
        (dry_run_receipt_path, paths.dry_run_receipt, "dry-run receipt"),
        (review_receipt_path, paths.reviewed, "review receipt"),
    )
    for observed, expected, label in requested:
        if observed != expected:
            raise MigrationError(f"{label} is not the fixed repository path")
    _require_owner_migration_root(paths)
    if (
        paths.apply_attempt.parent != paths.migration_root
        or paths.apply_receipt.parent != paths.migration_root
        or paths.retire_recovery_attempt.parent != paths.migration_root
        or paths.retire_recovery_proof.parent != paths.migration_root
        or paths.recovery_retired_receipt.parent != paths.migration_root
    ):
        raise MigrationError("apply receipt path escaped the fixed migration root")


def _apply_snapshots(
    paths: MigrationPaths,
    source: VerifiedSource,
) -> tuple[tuple[FileSnapshot, ...], tuple[FileSnapshot, ...]]:
    owner_inputs = tuple(
        _read_regular_snapshot(
            path,
            root=paths.repository_root,
            label=label,
            maximum=maximum,
            required_mode=0o600,
        )
        for path, label, maximum in (
            (paths.source_receipt, "source receipt", 4 * 1024 * 1024),
            (paths.migration_script, "migration script", 4 * 1024 * 1024),
            (paths.dry_run_receipt, "dry-run receipt", 64 * 1024),
            (paths.reviewed, "review receipt", 64 * 1024),
        )
    )
    overlay = _read_regular_snapshot(
        paths.repository_root / "docker-compose.stalwart-migration.yml",
        root=paths.repository_root,
        label="migration Compose overlay",
        maximum=64 * 1024,
        required_mode=0o644,
    )
    if not secrets.compare_digest(overlay.sha256, MIGRATION_COMPOSE_SHA256):
        raise MigrationError("migration Compose overlay digest does not match")
    base_compose = _read_regular_snapshot(
        source.base_compose,
        root=source.checkout_root,
        label="source base Compose file",
        maximum=4 * 1024 * 1024,
        required_mode=0o644,
    )
    inputs = (*owner_inputs, overlay, base_compose)
    artifacts = tuple(
        _read_regular_snapshot(
            path,
            root=paths.repository_root,
            label=f"apply artifact {path.name}",
            maximum=16 * 1024 * 1024,
            required_mode=0o600,
        )
        for path in paths.dry_run_outputs
    )
    return inputs, artifacts


def _apply_file(snapshot: FileSnapshot) -> ApplyFile:
    if (
        re.fullmatch(r"[0-9a-f]{64}", snapshot.sha256) is None
        or type(snapshot.size) is not int
        or snapshot.size < 0
    ):
        raise MigrationError("apply file metadata is malformed")
    if (
        not isinstance(snapshot.identity, tuple)
        or len(snapshot.identity) != 6
        or any(type(value) is not int or value < 0 for value in snapshot.identity)
    ):
        raise MigrationError("apply file identity is malformed")
    return ApplyFile(
        snapshot.path,
        snapshot.sha256,
        snapshot.size,
        snapshot.identity,
    )


def _receipt_payload_from_snapshot(
    snapshot: FileSnapshot,
    *,
    label: str,
) -> dict[str, object]:
    try:
        payload = json.loads(snapshot.content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise MigrationError(f"{label} changed after validation") from None
    if not isinstance(payload, dict):
        raise MigrationError(f"{label} changed after validation")
    return payload


def _strict_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON object key")
        value[key] = item
    return value


_NORMAL_RUNTIME_REDACTED_CREDENTIAL_FIELDS = frozenset(
    {
        "otpAuth",
        "secret",
    },
)
_NORMAL_RUNTIME_FORBIDDEN_ACCOUNT_FIELDS = frozenset(
    {
        "access_token",
        "accesstoken",
        "credentials",
        "otpauth",
        "password",
        "privatekey",
        "private_key",
        "secret",
        "secrets",
        "token",
    },
)
_NORMAL_RUNTIME_DOMAIN_CREATION_ID_PATTERN = re.compile(
    r"create-(?:0|[1-9][0-9]*)",
)
_NORMAL_RUNTIME_PINNED_OUTPUT_OPERATIONS = frozenset(
    {
        ("create", "Account"),
        ("create", "Certificate"),
        ("create", "DkimSignature"),
        ("create", "Domain"),
        ("create", "MailingList"),
        ("create", "Tenant"),
        ("update", "BlobStore"),
        ("update", "Enterprise"),
        ("update", "InMemoryStore"),
        ("update", "MetricsStore"),
        ("update", "SearchStore"),
        ("update", "SystemSettings"),
        ("update", "TracingStore"),
    },
)
_NORMAL_RUNTIME_USER_REQUIRED_FIELDS = frozenset(
    {
        "@type",
        "aliases",
        "credentials",
        "domainId",
        "memberGroupIds",
        "name",
        "quotas",
    },
)
_NORMAL_RUNTIME_USER_OPTIONAL_FIELDS = frozenset(
    {
        "description",
    },
)


def _normal_runtime_principal_id(value: object) -> int:
    if type(value) is int:
        principal_id = value
    elif (
        isinstance(value, dict)
        and set(value) == {"integer"}
        and type(value.get("integer")) is int
    ):
        principal_id = value["integer"]  # type: ignore[assignment]
    else:
        raise MigrationError(
            "normal-runtime migration evidence is malformed",
        )
    if principal_id < 0:
        raise MigrationError(
            "normal-runtime migration evidence is malformed",
        )
    return principal_id


def _normal_runtime_contains_forbidden_account_field(
    value: object,
) -> bool:
    if isinstance(value, dict):
        return any(
            type(key) is not str
            or key.casefold() in _NORMAL_RUNTIME_FORBIDDEN_ACCOUNT_FIELDS
            or _normal_runtime_contains_forbidden_account_field(item)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return any(
            _normal_runtime_contains_forbidden_account_field(item)
            for item in value
        )
    return False


def _normal_runtime_redacted_credential(value: object) -> dict[str, object]:
    malformed = "normal-runtime migration evidence is malformed"
    if not isinstance(value, dict):
        raise MigrationError(malformed)
    keys = set(value)
    if (
        keys not in (
            {"@type", "secret"},
            {"@type", "otpAuth", "secret"},
        )
        or value.get("@type") != "Password"
        or any(
            type(value.get(key)) is not str or not value[key]
            for key in _NORMAL_RUNTIME_REDACTED_CREDENTIAL_FIELDS
            if key in value
        )
    ):
        raise MigrationError(malformed)
    return {
        key: (
            "****"
            if key in _NORMAL_RUNTIME_REDACTED_CREDENTIAL_FIELDS
            else item
        )
        for key, item in value.items()
    }


def _normal_runtime_user_projection(value: object) -> dict[str, object]:
    malformed = "normal-runtime migration evidence is malformed"
    if not isinstance(value, dict):
        raise MigrationError(malformed)
    keys = set(value)
    if (
        not _NORMAL_RUNTIME_USER_REQUIRED_FIELDS.issubset(keys)
        or not keys.issubset(
            _NORMAL_RUNTIME_USER_REQUIRED_FIELDS
            | _NORMAL_RUNTIME_USER_OPTIONAL_FIELDS,
        )
        or value.get("@type") != "User"
        or type(value.get("name")) is not str
        or not value["name"]
        or not isinstance(value.get("aliases"), dict)
        or not isinstance(value.get("credentials"), dict)
        or value.get("memberGroupIds") != {}
        or not isinstance(value.get("quotas"), dict)
        or (
            "description" in value
            and (
                type(value.get("description")) is not str
                or not value["description"]
            )
        )
    ):
        raise MigrationError(malformed)
    aliases = value["aliases"]
    if list(aliases) != [str(index) for index in range(len(aliases))]:
        raise MigrationError(malformed)
    for alias in aliases.values():
        if (
            not isinstance(alias, dict)
            or set(alias) != {"domainId", "name"}
            or type(alias.get("name")) is not str
            or not alias["name"]
        ):
            raise MigrationError(malformed)
    credentials = value["credentials"]
    if set(credentials) not in (set(), {"0"}):
        raise MigrationError(malformed)
    quotas = value["quotas"]
    if set(quotas) not in (set(), {"maxDiskQuota"}):
        raise MigrationError(malformed)
    if "maxDiskQuota" in quotas and (
        type(quotas["maxDiskQuota"]) is not int
        or quotas["maxDiskQuota"] <= 0
    ):
        raise MigrationError(malformed)
    account_projection = {
        key: item
        for key, item in value.items()
        if key != "credentials"
    }
    if _normal_runtime_contains_forbidden_account_field(
        account_projection,
    ):
        raise MigrationError(malformed)
    return account_projection


def _normal_runtime_domain_references(
    account_projection: dict[str, object],
    domains: dict[str, str],
) -> list[dict[str, str]]:
    malformed = "normal-runtime migration evidence is malformed"
    references: list[dict[str, str]] = []
    seen: set[str] = set()

    def record(value: object) -> None:
        if (
            type(value) is not str
            or not value.startswith("#")
            or _NORMAL_RUNTIME_DOMAIN_CREATION_ID_PATTERN.fullmatch(value[1:])
            is None
            or value[1:] not in domains
        ):
            raise MigrationError(malformed)
        client_id = value[1:]
        if client_id not in seen:
            seen.add(client_id)
            references.append(
                {
                    "client_id": client_id,
                    "domain_name": domains[client_id],
                },
            )

    def walk(value: object) -> None:
        if isinstance(value, dict):
            for key in sorted(value):
                if key.startswith("#"):
                    raise MigrationError(malformed)
                item = value[key]
                if key == "domainId":
                    record(item)
                else:
                    walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)
        elif type(value) is str and value.startswith("#"):
            raise MigrationError(malformed)

    record(account_projection.get("domainId"))
    walk(account_projection)
    return references


def _normal_runtime_migrated_accounts(
    principals_snapshot: FileSnapshot,
    export_snapshot: FileSnapshot,
) -> list[dict[str, object]]:
    """Project only pinned-converter User Accounts without source secrets."""
    malformed = "normal-runtime migration evidence is malformed"
    try:
        principals = json.loads(
            principals_snapshot.content.decode("utf-8"),
            object_pairs_hook=_strict_json_object,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise MigrationError(malformed) from None
    if not isinstance(principals, list):
        raise MigrationError(malformed)

    principal_types: dict[str, str] = {}
    principal_order: list[str] = []
    for principal in principals:
        if (
            not isinstance(principal, dict)
            or type(principal.get("type")) is not str
        ):
            raise MigrationError(malformed)
        source_type = principal["type"]
        if source_type not in {"domain", "individual"}:
            raise MigrationError(malformed)
        if source_type == "domain":
            continue
        principal_id = _normal_runtime_principal_id(principal.get("id"))
        client_id = f"restore-{principal_id}"
        if client_id in principal_types:
            raise MigrationError(malformed)
        principal_types[client_id] = "User"
        principal_order.append(client_id)

    try:
        export_text = export_snapshot.content.decode("utf-8")
    except UnicodeDecodeError:
        raise MigrationError(malformed) from None
    lines = export_text.splitlines()
    if not lines or any(not line.strip() for line in lines):
        raise MigrationError(malformed)

    migrated: list[dict[str, object]] = []
    account_batch_seen = False
    exported_clients: list[str] = []
    domains: dict[str, str] = {}
    domain_names: set[str] = set()
    domain_batch_seen = False
    seen_clients: set[str] = set()
    for line in lines:
        try:
            operation = json.loads(
                line,
                object_pairs_hook=_strict_json_object,
            )
        except (json.JSONDecodeError, ValueError):
            raise MigrationError(malformed) from None
        if (
            not isinstance(operation, dict)
            or set(operation) != {"@type", "object", "value"}
            or operation.get("@type") not in {"create", "update"}
            or type(operation.get("object")) is not str
            or not operation["object"]
            or not isinstance(operation.get("value"), dict)
            or (operation["@type"] == "create" and not operation["value"])
        ):
            raise MigrationError(malformed)
        if (
            operation["@type"],
            operation["object"],
        ) not in _NORMAL_RUNTIME_PINNED_OUTPUT_OPERATIONS:
            raise MigrationError(malformed)
        if operation["object"] in {"MailingList", "Tenant"}:
            raise MigrationError(malformed)
        if operation["object"] == "Domain":
            if operation["@type"] != "create" or domain_batch_seen:
                raise MigrationError(malformed)
            domain_batch_seen = True
            domain_records = operation["value"]
            if list(domain_records) != [
                f"create-{index}"
                for index in range(len(domain_records))
            ]:
                raise MigrationError(malformed)
            for client_id, projection in operation["value"].items():
                if (
                    type(client_id) is not str
                    or _NORMAL_RUNTIME_DOMAIN_CREATION_ID_PATTERN.fullmatch(
                        client_id,
                    )
                    is None
                    or client_id in domains
                    or not isinstance(projection, dict)
                    or "name" not in projection
                    or not set(projection).issubset(
                        {"description", "logo", "name"},
                    )
                    or type(projection.get("name")) is not str
                    or not projection["name"]
                    or any(
                        type(projection.get(key)) is not str
                        or not projection[key]
                        for key in ("description", "logo")
                        if key in projection
                    )
                    or projection["name"] in domain_names
                    or _normal_runtime_contains_forbidden_account_field(
                        projection,
                    )
                    or any(
                        type(item) is str and item.startswith("#")
                        for item in projection.values()
                    )
                ):
                    raise MigrationError(malformed)
                domains[client_id] = projection["name"]
                domain_names.add(projection["name"])
            if list(domains.values()) != sorted(domains.values()):
                raise MigrationError(malformed)
            continue
        if operation["object"] != "Account":
            continue
        if operation["@type"] != "create":
            raise MigrationError(malformed)

        records = operation["value"]
        if (
            account_batch_seen
            or any(
                not isinstance(record, dict)
                or record.get("@type") != "User"
                for record in records.values()
            )
        ):
            raise MigrationError(malformed)
        account_batch_seen = True

        for client_id, projection in records.items():
            if (
                type(client_id) is not str
                or client_id in seen_clients
                or principal_types.get(client_id) != "User"
            ):
                raise MigrationError(malformed)
            seen_clients.add(client_id)
            exported_clients.append(client_id)

            credentials = projection.get("credentials")
            account_projection = _normal_runtime_user_projection(projection)
            credential_projections: list[dict[str, object]] = []
            for slot, credential in credentials.items():
                if (
                    slot != "0"
                    or not isinstance(credential, dict)
                ):
                    raise MigrationError(malformed)
                credential_projections.append(
                    {
                        "slot": slot,
                        "projection": (
                            _normal_runtime_redacted_credential(
                                credential,
                            )
                        ),
                    },
                )
            migrated.append(
                {
                    "account_projection": account_projection,
                    "credential_projections": credential_projections,
                    "domain_references": (
                        _normal_runtime_domain_references(
                            account_projection,
                            domains,
                        )
                    ),
                },
            )

    if exported_clients != principal_order:
        raise MigrationError(malformed)
    return migrated


def _parse_apply_operations(snapshot: FileSnapshot) -> tuple[ApplyOperation, ...]:
    try:
        text = snapshot.content.decode("utf-8")
    except UnicodeDecodeError:
        raise MigrationError("converted export operation plan is malformed") from None
    lines = text.splitlines()
    if not lines or any(not line.strip() for line in lines):
        raise MigrationError("converted export operation plan is malformed")
    operations: list[ApplyOperation] = []
    for line in lines:
        try:
            record = json.loads(line, object_pairs_hook=_strict_json_object)
        except (json.JSONDecodeError, ValueError):
            raise MigrationError(
                "converted export operation plan is malformed",
            ) from None
        if (
            not isinstance(record, dict)
            or set(record) != {"@type", "object", "value"}
            or not isinstance(record.get("value"), dict)
        ):
            raise MigrationError("converted export operation plan is malformed")
        operation = ApplyOperation(
            op=record.get("@type"),  # type: ignore[arg-type]
            object_name=record.get("object"),  # type: ignore[arg-type]
            count=(
                len(record["value"])
                if record.get("@type") == "create"
                else 1
            ),
        )
        if operation.op == "create" and operation.count == 0:
            raise MigrationError("converted export operation plan is malformed")
        operations.append(_validate_apply_operation(operation))
    return tuple(operations)


def _require_runtime_artifacts_absent(
    paths: MigrationPaths,
    runtime: MigrationRuntimePaths,
) -> None:
    for path, label in (
        (runtime.config_dir, "migration config dir"),
        (runtime.recovery_env_file, "migration recovery environment file"),
    ):
        _require_no_symlink_components(paths.repository_root, path, label)
        try:
            path.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise MigrationError(f"{label} is unavailable") from exc
        raise MigrationError(f"{label} must be absent before executor dispatch")


def _stable_directory_names(
    path: Path,
    *,
    root: Path,
    label: str,
    required_mode: int,
) -> tuple[set[str], tuple[int, int, int, int, int, int]]:
    _require_no_symlink_components(root, path, label)
    try:
        before = path.lstat()
    except OSError as exc:
        raise MigrationError(f"{label} is unavailable") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
        raise MigrationError(f"{label} must be a real directory")
    if stat.S_IMODE(before.st_mode) != required_mode:
        raise MigrationError(f"{label} must have mode {required_mode:04o}")
    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        opened = os.fstat(descriptor)
        names = set(os.listdir(descriptor))
        after = os.fstat(descriptor)
    except OSError as exc:
        raise MigrationError(f"{label} could not be inspected safely") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if (
        _file_identity(before) != _file_identity(opened)
        or _file_identity(opened) != _file_identity(after)
    ):
        raise MigrationError(f"{label} changed while it was inspected")
    return names, _file_identity(after)


def _runtime_artifact_file(snapshot: FileSnapshot) -> _RuntimeArtifactFile:
    return _RuntimeArtifactFile(
        path=snapshot.path,
        content=snapshot.content,
        sha256=snapshot.sha256,
        size=snapshot.size,
        identity=snapshot.identity,
    )


def _validate_recovery_environment_buffer(buffer: bytearray) -> None:
    if type(buffer) is not bytearray:
        raise MigrationError("migration recovery environment file is malformed")
    content_end = len(buffer)
    if content_end and buffer[content_end - 1] == 0x0A:
        content_end -= 1
    if (
        content_end < len(RECOVERY_ENV_PREFIX) + 3
        or not buffer.startswith(RECOVERY_ENV_PREFIX)
        or not _valid_recovery_credential_slice(
            buffer,
            start=len(RECOVERY_ENV_PREFIX),
            end=content_end,
        )
    ):
        raise MigrationError("migration recovery environment file is malformed")
    if content_end != len(buffer) and buffer[content_end] != 0x0A:
        raise MigrationError("migration recovery environment file is malformed")


def _read_runtime_environment_file(
    paths: MigrationPaths,
    runtime: MigrationRuntimePaths,
) -> _RuntimeEnvironmentFile:
    buffer, digest, size, identity = _read_regular_mutable(
        runtime.recovery_env_file,
        root=paths.repository_root,
        label="migration recovery environment file",
        maximum=64 * 1024,
        required_mode=0o600,
    )
    try:
        _validate_recovery_environment_buffer(buffer)
        return _RuntimeEnvironmentFile(
            path=runtime.recovery_env_file,
            sha256=digest,
            size=size,
            identity=identity,
        )
    finally:
        _wipe_bytearray(buffer)


def _validate_runtime_artifacts_ready(
    paths: MigrationPaths,
    runtime: MigrationRuntimePaths,
    *,
    converted_config: FileSnapshot,
) -> _RuntimeArtifactSnapshots:
    config_names, config_directory_identity = _stable_directory_names(
        runtime.config_dir,
        root=paths.repository_root,
        label="migration config dir",
        required_mode=0o755,
    )
    if config_names != {"config.json"}:
        raise MigrationError("migration config dir contents are not exact")
    config = _read_regular_snapshot(
        runtime.config_dir / "config.json",
        root=paths.repository_root,
        label="migration runtime config",
        maximum=16 * 1024 * 1024,
        required_mode=0o644,
    )
    if (
        not secrets.compare_digest(config.sha256, converted_config.sha256)
        or config.size != converted_config.size
        or config.content != converted_config.content
    ):
        raise MigrationError("migration runtime config does not match reviewed config")
    environment = _read_runtime_environment_file(paths, runtime)
    final_config_names, final_config_directory_identity = _stable_directory_names(
        runtime.config_dir,
        root=paths.repository_root,
        label="migration config dir",
        required_mode=0o755,
    )
    if (
        final_config_names != config_names
        or final_config_directory_identity != config_directory_identity
    ):
        raise MigrationError(
            "migration config dir changed while artifacts were validated",
        )
    return _RuntimeArtifactSnapshots(
        config_directory_identity=final_config_directory_identity,
        config=_runtime_artifact_file(config),
        recovery_environment=environment,
    )


def _validate_apply_state(
    paths: MigrationPaths,
    *,
    source_receipt_path: Path,
    script_path: Path,
    dry_run_receipt_path: Path,
    review_receipt_path: Path,
    runner: object,
    python_executable: str,
    expected_script_sha256: str,
    runtime_phase: str,
    writer_census: bool = True,
) -> _ValidatedApply:
    verified_receipt = verify_source_capture(
        paths,
        source_receipt_path,
        runner=runner,
        python_executable=python_executable,
    )
    source = load_verified_source(paths, verified_receipt, runner=runner)
    if writer_census:
        assert_no_running_store_writers(
            paths,
            source_store=source.provider_store,
            runner=runner,
        )
    script_digest = validate_migration_script(
        paths,
        script_path,
        expected_sha256=expected_script_sha256,
    )
    dry_run_payload = validate_dry_run_receipt(paths, dry_run_receipt_path)
    review_payload = validate_review_receipt(
        paths,
        review_receipt_path,
        paths.unmigrated,
    )
    validate_converted_outputs(paths)
    input_snapshots, artifact_snapshots = _apply_snapshots(paths, source)
    _validate_checkout_config_matches_converted(
        source,
        artifact_snapshots[2],
    )
    if input_snapshots[0] != verified_receipt.snapshot:
        raise MigrationError("source receipt changed after Task 5 verification")
    if not secrets.compare_digest(input_snapshots[1].sha256, script_digest):
        raise MigrationError("migration script changed after validation")
    if (
        _receipt_payload_from_snapshot(
            input_snapshots[2],
            label="dry-run receipt",
        )
        != dry_run_payload
        or _receipt_payload_from_snapshot(
            input_snapshots[3],
            label="review receipt",
        )
        != review_payload
    ):
        raise MigrationError("apply receipt input changed after validation")
    expected_outputs = [
        {
            "name": snapshot.path.name,
            "sha256": snapshot.sha256,
            "size": snapshot.size,
        }
        for snapshot in artifact_snapshots
    ]
    if (
        dry_run_payload.get("source_receipt_sha256")
        != input_snapshots[0].sha256
        or dry_run_payload.get("migration_script_sha256")
        != input_snapshots[1].sha256
        or dry_run_payload.get("outputs") != expected_outputs
    ):
        raise MigrationError("dry-run receipt chain changed after validation")
    review_report = review_payload.get("report")
    if (
        not isinstance(review_report, dict)
        or review_report.get("name") != paths.unmigrated.name
        or review_report.get("sha256") != artifact_snapshots[-1].sha256
    ):
        raise MigrationError("review receipt chain changed after validation")
    runtime = build_migration_runtime_paths(paths, source)
    runtime_artifacts: _RuntimeArtifactSnapshots | None = None
    if runtime_phase in {"pre-dispatch", "retired"}:
        _require_runtime_artifacts_absent(paths, runtime)
    elif runtime_phase == "ready":
        runtime_artifacts = _validate_runtime_artifacts_ready(
            paths,
            runtime,
            converted_config=artifact_snapshots[2],
        )
    elif runtime_phase == "durable-recovery":
        # A durable marker can outlive either side of runtime publication.
        # Its exact artifact state is validated only after the marker-bound
        # plan has been reconstructed, so rollback can already be bound.
        pass
    else:
        raise MigrationError("apply runtime phase is malformed")
    operations = _parse_apply_operations(artifact_snapshots[3])
    plan = ApplyPlan(
        inputs=tuple(_apply_file(snapshot) for snapshot in input_snapshots),
        artifacts=tuple(_apply_file(snapshot) for snapshot in artifact_snapshots),
        operations=operations,
        operations_sha256=apply_operation_plan_sha256(operations),
        runtime=runtime,
        source=source,
    )
    identities = tuple(
        (snapshot.path, snapshot.identity)
        for snapshot in (*input_snapshots, *artifact_snapshots)
    )
    return _ValidatedApply(plan, source, identities, runtime_artifacts)


def _load_durable_apply_recovery_state(
    paths: MigrationPaths,
    *,
    source_receipt_path: Path,
    script_path: Path,
    dry_run_receipt_path: Path,
    review_receipt_path: Path,
    runner: object,
    python_executable: str,
    expected_script_sha256: str,
) -> _ValidatedApply | None:
    """Reconstruct an unfinished apply without trusting runtime artifacts."""
    attempt_present = paths.apply_attempt.exists() or paths.apply_attempt.is_symlink()
    receipt_present = paths.apply_receipt.exists() or paths.apply_receipt.is_symlink()
    if not attempt_present or receipt_present:
        return None
    marker_before = _apply_attempt_snapshot(paths)
    validate_digest_envelope(
        _parse_strict_json_snapshot(
            marker_before,
            label="apply attempt marker",
        ),
    )
    validated = _validate_apply_state(
        paths,
        source_receipt_path=source_receipt_path,
        script_path=script_path,
        dry_run_receipt_path=dry_run_receipt_path,
        review_receipt_path=review_receipt_path,
        runner=runner,
        python_executable=python_executable,
        expected_script_sha256=expected_script_sha256,
        runtime_phase="durable-recovery",
        writer_census=False,
    )
    marker_after = _apply_attempt_snapshot(paths)
    if (
        marker_before != marker_after
        or paths.apply_receipt.exists()
        or paths.apply_receipt.is_symlink()
    ):
        raise MigrationError(
            "durable apply recovery state changed during validation",
        )
    _validate_apply_attempt_snapshot(marker_after, validated.plan)
    return validated


def _validate_durable_apply_runtime_state(
    paths: MigrationPaths,
    expected: _ValidatedApply,
    *,
    source_receipt_path: Path,
    script_path: Path,
    dry_run_receipt_path: Path,
    review_receipt_path: Path,
    runner: object,
    python_executable: str,
    expected_script_sha256: str,
) -> None:
    """Accept only a wholly absent or wholly ready marker-bound runtime."""
    runtime = expected.plan.runtime
    state = (
        runtime.recovery_env_file.exists()
        or runtime.recovery_env_file.is_symlink(),
        runtime.config_dir.exists() or runtime.config_dir.is_symlink(),
        (runtime.config_dir / "config.json").exists()
        or (runtime.config_dir / "config.json").is_symlink(),
    )
    if state == (False, False, False):
        runtime_phase = "pre-dispatch"
    elif state == (True, True, True):
        runtime_phase = "ready"
    else:
        raise MigrationError(
            "durable apply runtime artifact state is incomplete",
        )
    current = _validate_apply_state(
        paths,
        source_receipt_path=source_receipt_path,
        script_path=script_path,
        dry_run_receipt_path=dry_run_receipt_path,
        review_receipt_path=review_receipt_path,
        runner=runner,
        python_executable=python_executable,
        expected_script_sha256=expected_script_sha256,
        runtime_phase=runtime_phase,
        writer_census=False,
    )
    marker = _apply_attempt_snapshot(paths)
    _validate_apply_attempt_snapshot(marker, current.plan)
    if not _apply_states_match(
        expected,
        current,
        include_runtime_artifacts=False,
    ):
        raise MigrationError(
            "durable apply recovery binding changed",
        )


def _apply_timestamp(clock: object | None) -> str:
    if clock is None:
        value = _utc_timestamp()
    elif callable(clock):
        value = clock()
    else:
        raise MigrationError("apply receipt clock is unavailable")
    if (
        not isinstance(value, str)
        or re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value) is None
    ):
        raise MigrationError("apply receipt timestamp is malformed")
    return value


def _apply_metadata(files: tuple[ApplyFile, ...]) -> list[dict[str, object]]:
    metadata: list[dict[str, object]] = []
    for item in files:
        if (
            not isinstance(item.path, Path)
            or item.path.name in {"", ".", ".."}
            or "/" in item.path.name
            or "\\" in item.path.name
            or re.fullmatch(r"[0-9a-f]{64}", item.sha256) is None
            or type(item.size) is not int
            or item.size < 0
            or not isinstance(item.identity, tuple)
            or len(item.identity) != 6
            or any(
                type(value) is not int or value < 0
                for value in item.identity
            )
        ):
            raise MigrationError("apply plan contains unsafe file metadata")
        metadata.append(
            {
                "name": item.path.name,
                "sha256": item.sha256,
                "size": item.size,
                "identity": list(item.identity),
            },
        )
    return metadata


def _apply_summary_counts(
    summary: dict[str, object],
    operations: tuple[ApplyOperation, ...],
) -> dict[str, int]:
    _, expected_done = _expected_apply_counts(operations)
    if summary.get("done") != expected_done:
        raise MigrationError("apply summary does not match the export plan")
    return expected_done


def _apply_attempt_payload(
    plan: ApplyPlan,
    *,
    started_at: str,
) -> dict[str, object]:
    expected_plan, _expected_done = _expected_apply_counts(plan.operations)
    return {
        "schema": APPLY_ATTEMPT_SCHEMA,
        "started_at": started_at,
        "inputs": _apply_metadata(plan.inputs),
        "artifacts": _apply_metadata(plan.artifacts),
        "operation_plan": {
            "sha256": plan.operations_sha256,
            "count": len(plan.operations),
            **expected_plan,
        },
    }


def _digest_envelope(payload: dict[str, object]) -> dict[str, object]:
    return {
        "payload": payload,
        "payload_sha256": hashlib.sha256(
            _canonical_json_bytes(payload),
        ).hexdigest(),
    }


def _apply_attempt_snapshot(
    paths: MigrationPaths,
) -> FileSnapshot:
    return _read_regular_snapshot(
        paths.apply_attempt,
        root=paths.repository_root,
        label="apply attempt marker",
        maximum=64 * 1024,
        required_mode=0o600,
    )


def _validate_apply_attempt_snapshot(
    snapshot: FileSnapshot,
    plan: ApplyPlan,
) -> dict[str, object]:
    if snapshot.path != plan.inputs[0].path.parent / "apply-attempt.json":
        raise MigrationError("apply attempt marker path is malformed")
    try:
        value = json.loads(
            snapshot.content.decode("utf-8"),
            object_pairs_hook=_strict_json_object,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise MigrationError("apply attempt marker is malformed") from None
    payload = validate_digest_envelope(value)
    started_at = payload.get("started_at")
    if (
        not isinstance(started_at, str)
        or re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",
            started_at,
        )
        is None
        or _canonical_json_bytes(payload)
        != _canonical_json_bytes(
            _apply_attempt_payload(plan, started_at=started_at),
        )
    ):
        raise MigrationError("apply attempt marker does not match fixed inputs")
    return payload


def _post_apply_proof_metadata(
    proof: object,
    plan: ApplyPlan,
) -> dict[str, object]:
    if (
        type(proof) is not PostApplyCensusProof
        or type(proof.operations_sha256) is not str
        or re.fullmatch(r"[0-9a-f]{64}", proof.operations_sha256) is None
        or not secrets.compare_digest(
            proof.operations_sha256,
            plan.operations_sha256,
        )
        or type(proof.operation_count) is not int
        or proof.operation_count != len(plan.operations)
        or type(proof.server_version) is not str
        or proof.server_version != "0.16.17"
        or type(proof.management_status) is not int
        or proof.management_status != 200
    ):
        raise MigrationError(
            "post-apply census proof does not match the export plan",
        )
    return {
        "operations_sha256": proof.operations_sha256,
        "operation_count": proof.operation_count,
        "server_version": proof.server_version,
        "management_status": proof.management_status,
    }


def _apply_file_metadata(file: ApplyFile) -> dict[str, object]:
    return _apply_metadata((file,))[0]


def _runtime_identity_metadata(
    identity: object,
    *,
    label: str,
) -> list[int]:
    if (
        not isinstance(identity, tuple)
        or len(identity) != 6
        or any(type(value) is not int or value < 0 for value in identity)
    ):
        raise MigrationError(f"{label} identity is malformed")
    return list(identity)


def _runtime_artifact_receipt_metadata(
    artifacts: object,
) -> dict[str, object]:
    if type(artifacts) is not _RuntimeArtifactSnapshots:
        raise MigrationError("runtime artifact snapshots are unavailable")
    config = artifacts.config
    environment = artifacts.recovery_environment
    if (
        type(config) is not _RuntimeArtifactFile
        or type(environment) is not _RuntimeEnvironmentFile
        or config.path.name != "config.json"
        or environment.path.name != "recovery.env"
        or type(config.content) is not bytes
        or type(config.sha256) is not str
        or re.fullmatch(r"[0-9a-f]{64}", config.sha256) is None
        or not secrets.compare_digest(
            hashlib.sha256(config.content).hexdigest(),
            config.sha256,
        )
        or type(environment.sha256) is not str
        or re.fullmatch(r"[0-9a-f]{64}", environment.sha256) is None
        or type(config.size) is not int
        or config.size != len(config.content)
        or type(environment.size) is not int
        or environment.size < len(RECOVERY_ENV_PREFIX) + 3
    ):
        raise MigrationError("runtime artifact snapshots are malformed")
    config_directory_identity = _runtime_identity_metadata(
        artifacts.config_directory_identity,
        label="runtime config directory",
    )
    return {
        "config_directory_identity": config_directory_identity,
        "config": {
            "name": "config.json",
            "sha256": config.sha256,
            "size": config.size,
            "identity": _runtime_identity_metadata(
                config.identity,
                label="runtime config",
            ),
        },
        "recovery_environment": {
            "name": "recovery.env",
            "size": environment.size,
            "identity": _runtime_identity_metadata(
                environment.identity,
                label="runtime recovery environment",
            ),
        },
    }


def _validate_runtime_artifact_commitment(
    value: object,
) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != {
        "config_directory_identity",
        "config",
        "recovery_environment",
    }:
        raise MigrationError("apply runtime artifact commitment is malformed")
    directory_identity = value.get("config_directory_identity")
    config = value.get("config")
    environment = value.get("recovery_environment")
    if (
        not isinstance(directory_identity, list)
        or len(directory_identity) != 6
        or any(type(item) is not int or item < 0 for item in directory_identity)
        or not isinstance(config, dict)
        or set(config) != {"name", "sha256", "size", "identity"}
        or config.get("name") != "config.json"
        or type(config.get("sha256")) is not str
        or re.fullmatch(r"[0-9a-f]{64}", config["sha256"]) is None
        or type(config.get("size")) is not int
        or config["size"] < 0
        or not isinstance(config.get("identity"), list)
        or len(config["identity"]) != 6
        or any(
            type(item) is not int or item < 0
            for item in config["identity"]
        )
        or not isinstance(environment, dict)
        or set(environment) != {"name", "size", "identity"}
        or environment.get("name") != "recovery.env"
        or type(environment.get("size")) is not int
        or environment["size"] < len(RECOVERY_ENV_PREFIX) + 3
        or not isinstance(environment.get("identity"), list)
        or len(environment["identity"]) != 6
        or any(
            type(item) is not int or item < 0
            for item in environment["identity"]
        )
    ):
        raise MigrationError("apply runtime artifact commitment is malformed")
    return value


def _apply_states_match(
    before: _ValidatedApply,
    after: _ValidatedApply,
    *,
    include_runtime_artifacts: bool = True,
) -> bool:
    return (
        before.plan == after.plan
        and before.source == after.source
        and before.identities == after.identities
        and (
            not include_runtime_artifacts
            or before.runtime_artifacts == after.runtime_artifacts
        )
    )


def _validate_apply_receipt_payload(
    payload: object,
    plan: ApplyPlan,
    *,
    attempt: FileSnapshot,
    runtime_artifacts: _RuntimeArtifactSnapshots,
) -> dict[str, object]:
    return _validate_apply_receipt_payload_with_runtime_metadata(
        payload,
        plan,
        attempt=attempt,
        runtime_metadata=_runtime_artifact_receipt_metadata(runtime_artifacts),
    )


def _validate_apply_receipt_payload_with_runtime_metadata(
    payload: object,
    plan: ApplyPlan,
    *,
    attempt: FileSnapshot,
    runtime_metadata: object,
) -> dict[str, object]:
    if not isinstance(payload, dict) or set(payload) != {
        "schema",
        "applied_at",
        "inputs",
        "artifacts",
        "attempt",
        "post_apply_proof",
        "runtime_artifacts",
        "summary",
    }:
        raise MigrationError("apply receipt is malformed")
    validated_runtime_metadata = _validate_runtime_artifact_commitment(
        runtime_metadata,
    )
    applied_at = payload.get("applied_at")
    _, expected_summary = _expected_apply_counts(plan.operations)
    expected_proof = {
        "operations_sha256": plan.operations_sha256,
        "operation_count": len(plan.operations),
        "server_version": "0.16.17",
        "management_status": 200,
    }
    expected_payload = {
        "schema": APPLY_SCHEMA,
        "applied_at": applied_at,
        "inputs": _apply_metadata(plan.inputs),
        "artifacts": _apply_metadata(plan.artifacts),
        "attempt": _apply_file_metadata(_apply_file(attempt)),
        "post_apply_proof": expected_proof,
        "runtime_artifacts": validated_runtime_metadata,
        "summary": expected_summary,
    }
    if (
        payload.get("schema") != APPLY_SCHEMA
        or not isinstance(applied_at, str)
        or re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",
            applied_at,
        )
        is None
        or _canonical_json_bytes(payload)
        != _canonical_json_bytes(expected_payload)
    ):
        raise MigrationError("apply receipt does not match the fixed inputs")
    return payload


def prepare_apply(
    paths: MigrationPaths,
    *,
    source_receipt_path: Path,
    script_path: Path,
    dry_run_receipt_path: Path,
    review_receipt_path: Path,
    runner: object = run_command,
    python_executable: str,
    executor: object,
    post_apply_verifier: object,
    clock: object | None = None,
    expected_script_sha256: str = MIGRATION_SCRIPT_SHA256,
) -> Path:
    """Prepare one apply using injected executor and authoritative census seam.

    The caller-supplied verifier is the offline contract boundary for a future
    live v0.16.17 management census. This module makes no live request itself.
    """
    _require_fixed_apply_paths(
        paths,
        source_receipt_path=source_receipt_path,
        script_path=script_path,
        dry_run_receipt_path=dry_run_receipt_path,
        review_receipt_path=review_receipt_path,
    )
    if paths.apply_attempt.exists() or paths.apply_attempt.is_symlink():
        raise MigrationError(
            "apply attempt marker exists; reconciliation is required",
        )
    if paths.apply_receipt.exists() or paths.apply_receipt.is_symlink():
        raise MigrationError("apply receipt already exists; refusing to re-execute")
    if not callable(executor):
        raise MigrationError("apply executor is unavailable")
    if not callable(post_apply_verifier):
        raise MigrationError("post-apply census verifier is unavailable")
    applied_at = _apply_timestamp(clock)
    before = _validate_apply_state(
        paths,
        source_receipt_path=source_receipt_path,
        script_path=script_path,
        dry_run_receipt_path=dry_run_receipt_path,
        review_receipt_path=review_receipt_path,
        runner=runner,
        python_executable=python_executable,
        expected_script_sha256=expected_script_sha256,
        runtime_phase="pre-dispatch",
    )
    marker_payload = _apply_attempt_payload(before.plan, started_at=applied_at)
    _write_new_json_0600(
        paths.apply_attempt,
        _digest_envelope(marker_payload),
        root=paths.repository_root,
        preserve_published_on_failure=True,
    )
    marker_before = _apply_attempt_snapshot(paths)
    _validate_apply_attempt_snapshot(marker_before, before.plan)
    evidence: object = None
    execution_error: BaseException | None = None
    execution_traceback = None
    try:
        evidence = executor(before.plan)
    except BaseException as exc:
        execution_error = exc
        execution_traceback = exc.__traceback__
    postflight_failed = False
    after: _ValidatedApply | None = None
    marker_after_executor: FileSnapshot | None = None
    try:
        assert_no_running_store_writers(
            paths,
            source_store=before.source.provider_store,
            runner=runner,
        )
        after = _validate_apply_state(
            paths,
            source_receipt_path=source_receipt_path,
            script_path=script_path,
            dry_run_receipt_path=dry_run_receipt_path,
            review_receipt_path=review_receipt_path,
            runner=runner,
            python_executable=python_executable,
            expected_script_sha256=expected_script_sha256,
            runtime_phase="ready",
        )
        marker_after_executor = _apply_attempt_snapshot(paths)
        _validate_apply_attempt_snapshot(marker_after_executor, after.plan)
    except BaseException:
        postflight_failed = True
    if postflight_failed:
        raise MigrationError(
            "apply postflight failed; reconciliation is required",
        ) from None
    assert after is not None
    assert marker_after_executor is not None
    if (
        not _apply_states_match(
            before,
            after,
            include_runtime_artifacts=False,
        )
        or marker_before != marker_after_executor
    ):
        raise MigrationError(
            "apply postflight changed; reconciliation is required",
        )
    if execution_error is not None:
        raise execution_error.with_traceback(execution_traceback)
    summary = validate_apply_ndjson(
        evidence,  # type: ignore[arg-type]
        expected_operations=after.plan.operations,
    )
    verifier_error: BaseException | None = None
    proof: object = None
    try:
        proof = post_apply_verifier(after.plan)
    except BaseException as exc:
        verifier_error = exc
    verification_postflight_failed = False
    final: _ValidatedApply | None = None
    marker_final: FileSnapshot | None = None
    try:
        assert_no_running_store_writers(
            paths,
            source_store=after.source.provider_store,
            runner=runner,
        )
        final = _validate_apply_state(
            paths,
            source_receipt_path=source_receipt_path,
            script_path=script_path,
            dry_run_receipt_path=dry_run_receipt_path,
            review_receipt_path=review_receipt_path,
            runner=runner,
            python_executable=python_executable,
            expected_script_sha256=expected_script_sha256,
            runtime_phase="ready",
        )
        marker_final = _apply_attempt_snapshot(paths)
        _validate_apply_attempt_snapshot(marker_final, final.plan)
    except BaseException:
        verification_postflight_failed = True
    if verification_postflight_failed:
        raise MigrationError(
            "post-apply verification cleanup failed; reconciliation is required",
        ) from None
    assert final is not None
    assert marker_final is not None
    if (
        not _apply_states_match(after, final)
        or marker_after_executor != marker_final
    ):
        raise MigrationError(
            "post-apply verification changed fixed state; reconciliation is required",
        )
    if verifier_error is not None:
        raise MigrationError(
            "post-apply census verifier failed; reconciliation is required",
        ) from None
    if final.runtime_artifacts is None:
        raise MigrationError(
            "runtime artifact snapshots are unavailable; reconciliation is required",
        )
    proof_metadata = _post_apply_proof_metadata(proof, final.plan)
    payload = {
        "schema": APPLY_SCHEMA,
        "applied_at": applied_at,
        "inputs": _apply_metadata(final.plan.inputs),
        "artifacts": _apply_metadata(final.plan.artifacts),
        "attempt": _apply_file_metadata(_apply_file(marker_final)),
        "post_apply_proof": proof_metadata,
        "runtime_artifacts": _runtime_artifact_receipt_metadata(
            final.runtime_artifacts,
        ),
        "summary": _apply_summary_counts(summary, final.plan.operations),
    }
    _validate_apply_receipt_payload(
        payload,
        final.plan,
        attempt=marker_final,
        runtime_artifacts=final.runtime_artifacts,
    )
    if paths.apply_receipt.exists() or paths.apply_receipt.is_symlink():
        raise MigrationError("apply receipt already exists; refusing to overwrite")
    _write_new_json_0600(
        paths.apply_receipt,
        payload,
        root=paths.repository_root,
    )
    return paths.apply_receipt


def _generate_production_recovery_credential() -> bytearray:
    """Generate one high-entropy, CLI-safe mutable recovery credential."""
    hexadecimal = b"0123456789abcdef"
    urlsafe = (
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        b"abcdefghijklmnopqrstuvwxyz"
        b"0123456789-_"
    )
    credential = bytearray(b"migration-")
    completed = False
    try:
        for _index in range(32):
            selected = secrets.randbelow(len(hexadecimal))
            if type(selected) is not int or not 0 <= selected < len(hexadecimal):
                raise MigrationError(
                    "production recovery credential generation failed safely",
                )
            credential.append(hexadecimal[selected])
        credential.extend(b":")
        for _index in range(64):
            selected = secrets.randbelow(len(urlsafe))
            if type(selected) is not int or not 0 <= selected < len(urlsafe):
                raise MigrationError(
                    "production recovery credential generation failed safely",
                )
            credential.append(urlsafe[selected])
        if not _valid_recovery_credential_slice(
            credential,
            start=0,
            end=len(credential),
        ):
            raise MigrationError(
                "production recovery credential generation failed safely",
            )
        completed = True
        return credential
    except Exception:
        raise MigrationError(
            "production recovery credential generation failed safely",
        ) from None
    finally:
        if not completed:
            _wipe_bytearray(credential)


class _ProductionRecoveryCredentialFactory:
    """One-shot source/copy owner that wipes every mutable credential buffer."""

    __slots__ = (
        "_called",
        "_closed",
        "_issued",
        "_source",
        "_source_factory",
    )

    def __init__(self, source_factory: object) -> None:
        if not callable(source_factory):
            raise MigrationError(
                "production recovery credential source is unavailable",
            )
        self._source_factory = source_factory
        self._source: bytearray | None = None
        self._issued: bytearray | None = None
        self._called = False
        self._closed = False

    def __call__(self) -> bytearray:
        if self._closed or self._called:
            raise MigrationError(
                "production recovery credential source is unavailable",
            )
        self._called = True
        candidate: object = None
        try:
            candidate = self._source_factory()
            if isinstance(candidate, bytearray):
                self._source = candidate
            if type(candidate) is not bytearray:
                raise MigrationError(
                    "production recovery credential is malformed",
                )
            if not _valid_recovery_credential_slice(
                candidate,
                start=0,
                end=len(candidate),
            ):
                raise MigrationError(
                    "production recovery credential is malformed",
                )
            self._issued = bytearray(candidate)
            return self._issued
        except Exception:
            self.close()
            raise MigrationError(
                "production recovery credential generation failed safely",
            ) from None
        finally:
            if isinstance(candidate, bytearray):
                _wipe_bytearray(candidate)

    def close(self) -> None:
        if self._source is not None:
            _wipe_bytearray(self._source)
        if self._issued is not None:
            _wipe_bytearray(self._issued)
        self._closed = True

    def __del__(self) -> None:
        try:
            self.close()
        except BaseException:
            pass

    def __repr__(self) -> str:
        return "_ProductionRecoveryCredentialFactory(<redacted>)"


@dataclass(frozen=True, repr=False)
class _RollbackRecoveryBinding:
    """Content-free identity needed to activate rollback after mutation."""

    plan: object
    source: VerifiedSource
    runtime_kind: str
    source_receipt: ApplyFile
    apply_attempt: ApplyFile
    retirement_attempt: ApplyFile | None
    backup_root: Path
    base_url: str
    project: str
    image_digest: str
    image_id: str
    version: str

    def __repr__(self) -> str:
        return "_RollbackRecoveryBinding(<redacted>)"


def _rollback_source_identity(
    paths: MigrationPaths,
    *,
    source: VerifiedSource,
    source_receipt: ApplyFile,
) -> tuple[Path, str, str, str, str, str]:
    source_snapshot = _read_regular_snapshot(
        paths.source_receipt,
        root=paths.repository_root,
        label="source receipt",
        maximum=4 * 1024 * 1024,
        required_mode=0o600,
    )
    if _apply_file(source_snapshot) != source_receipt:
        raise MigrationError("rollback recovery binding is malformed")
    payload = validate_digest_envelope(
        _receipt_payload_from_snapshot(
            source_snapshot,
            label="source receipt",
        ),
    )
    source_payload = payload.get("source")
    backup_payload = payload.get("backup")
    rollback_payload = payload.get("rollback")
    if (
        not isinstance(source_payload, dict)
        or not isinstance(backup_payload, dict)
        or not isinstance(rollback_payload, dict)
    ):
        raise MigrationError("rollback recovery binding is malformed")
    backup_root_value = backup_payload.get("root")
    rollback_port = rollback_payload.get("port")
    project = rollback_payload.get("project")
    image_digest = source_payload.get("image_digest")
    image_id = source_payload.get("image_id")
    version = source_payload.get("version")
    backup_root = (
        Path(backup_root_value)
        if type(backup_root_value) is str
        else Path()
    )
    expected_backups = (
        source.checkout_root
        / "captures"
        / "debug-dashboard"
        / "stalwart-v015"
        / "backups"
    )
    if (
        type(backup_root_value) is not str
        or not backup_root.is_absolute()
        or backup_root.parent != expected_backups
        or re.fullmatch(
            r"stalwart-v015-[0-9]{8}T[0-9]{6}Z-[a-z0-9]{8}",
            backup_root.name,
        )
        is None
        or type(rollback_port) is not int
        or rollback_port <= 1024
        or rollback_port > 65535
        or type(project) is not str
        or COMPOSE_PROJECT_PATTERN.fullmatch(project) is None
        or type(image_digest) is not str
        or re.fullmatch(
            r"stalwartlabs/stalwart@sha256:[0-9a-f]{64}",
            image_digest,
        )
        is None
        or type(image_id) is not str
        or re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) is None
        or type(version) is not str
        or ROLLBACK_VERSION_PATTERN.fullmatch(version) is None
    ):
        raise MigrationError("rollback recovery binding is malformed")
    return (
        backup_root,
        f"http://127.0.0.1:{rollback_port}",
        project,
        image_digest,
        image_id,
        version.removeprefix("v"),
    )


def _rollback_recovery_binding(
    paths: MigrationPaths,
    plan: object,
) -> _RollbackRecoveryBinding | None:
    """Bind recovery only after a real apply plan reached its dispatch seam."""
    if type(plan) is not ApplyPlan:
        return None
    if (
        type(plan.source) is not VerifiedSource
        or not plan.inputs
        or type(plan.inputs[0]) is not ApplyFile
        or plan.inputs[0].path != paths.source_receipt
        or plan.source.checkout_root != paths.repository_root
    ):
        raise MigrationError("rollback recovery binding is malformed")
    (
        backup_root,
        base_url,
        project,
        image_digest,
        image_id,
        version,
    ) = _rollback_source_identity(
        paths,
        source=plan.source,
        source_receipt=plan.inputs[0],
    )
    attempt = _apply_attempt_snapshot(paths)
    _validate_apply_attempt_snapshot(attempt, plan)
    return _RollbackRecoveryBinding(
        plan=plan,
        source=plan.source,
        runtime_kind="migration",
        source_receipt=plan.inputs[0],
        apply_attempt=_apply_file(attempt),
        retirement_attempt=None,
        backup_root=backup_root,
        base_url=base_url,
        project=project,
        image_digest=image_digest,
        image_id=image_id,
        version=version,
    )


def _rollback_retirement_recovery_binding(
    paths: MigrationPaths,
    plan: object,
) -> _RollbackRecoveryBinding | None:
    if type(plan) is not RecoveryRetirementPlan:
        return None
    if (
        type(plan.source) is not VerifiedSource
        or not plan.inputs
        or type(plan.inputs[0]) is not ApplyFile
        or type(plan.apply_attempt) is not ApplyFile
        or plan.inputs[0].path != paths.source_receipt
        or plan.apply_attempt.path != paths.apply_attempt
        or plan.source.checkout_root != paths.repository_root
    ):
        raise MigrationError("rollback recovery binding is malformed")
    (
        backup_root,
        base_url,
        project,
        image_digest,
        image_id,
        version,
    ) = _rollback_source_identity(
        paths,
        source=plan.source,
        source_receipt=plan.inputs[0],
    )
    attempt = _apply_attempt_snapshot(paths)
    if _apply_file(attempt) != plan.apply_attempt:
        raise MigrationError("rollback recovery binding is malformed")
    return _RollbackRecoveryBinding(
        plan=plan,
        source=plan.source,
        runtime_kind="normal",
        source_receipt=plan.inputs[0],
        apply_attempt=plan.apply_attempt,
        retirement_attempt=plan.retirement_attempt,
        backup_root=backup_root,
        base_url=base_url,
        project=project,
        image_digest=image_digest,
        image_id=image_id,
        version=version,
    )


def _revalidate_rollback_recovery_binding(
    paths: MigrationPaths,
    binding: _RollbackRecoveryBinding,
) -> None:
    source = _read_regular_snapshot(
        paths.source_receipt,
        root=paths.repository_root,
        label="source receipt",
        maximum=4 * 1024 * 1024,
        required_mode=0o600,
    )
    attempt = _apply_attempt_snapshot(paths)
    if binding.runtime_kind == "migration":
        if type(binding.plan) is not ApplyPlan:
            raise MigrationError("rollback recovery binding is malformed")
        _validate_apply_attempt_snapshot(attempt, binding.plan)
    elif (
        binding.runtime_kind != "normal"
        or type(binding.plan) is not RecoveryRetirementPlan
        or type(binding.retirement_attempt) is not ApplyFile
        or _apply_file(_retirement_attempt_snapshot(paths))
        != binding.retirement_attempt
    ):
        raise MigrationError("rollback recovery binding is malformed")
    if (
        _apply_file(source) != binding.source_receipt
        or _apply_file(attempt) != binding.apply_attempt
    ):
        raise MigrationError("rollback recovery binding changed")


def _stop_failed_migration_runtime(
    binding: _RollbackRecoveryBinding,
    *,
    runner: object,
) -> None:
    if binding.runtime_kind == "normal":
        if type(binding.plan) is not RecoveryRetirementPlan:
            raise MigrationError("rollback recovery binding is malformed")
        identified_normal = _identify_normal_runtime(
            binding.plan,
            runtime_runner=runner,
        )
        if identified_normal is not None and identified_normal[1]:
            _invoke_normal_runtime_command(
                runner,
                build_bound_container_stop_command(identified_normal[0]),
                plan=binding.plan,
                timeout=60,
            )
        return
    if binding.runtime_kind != "migration" or type(binding.plan) is not ApplyPlan:
        raise MigrationError("rollback recovery binding is malformed")
    identified_migration = _identify_migration_runtime(
        binding.plan,
        runtime_runner=runner,
    )
    running_container_ids = tuple(
        container_id
        for container_id, running in identified_migration
        if running
    )
    if running_container_ids:
        compose_names = {
            MIGRATION_DATA_VARIABLE,
            MIGRATION_CONFIG_VARIABLE,
            MIGRATION_RECOVERY_ENV_VARIABLE,
        }
        environment = _runtime_command_environment(
            binding.plan.runtime.compose_environment(),
        )
        for container_id in running_container_ids:
            _invoke_runtime_runner(
                runner,
                build_bound_container_stop_command(container_id),
                stdin=b"",
                env=environment,
                timeout=60,
                cwd=binding.plan.source.checkout_root,
                allowed_stalwart_names=compose_names,
            )


def _activation_dataclass_values(
    value: object,
    *,
    expected_fields: set[str],
    label: str,
) -> dict[str, object]:
    if (
        not is_dataclass(value)
        or isinstance(value, type)
        or {field.name for field in fields(value)} != expected_fields
        or getattr(type(value), "__dataclass_params__", None) is None
        or not type(value).__dataclass_params__.frozen
    ):
        raise MigrationError(f"{label} is malformed")
    try:
        return {name: getattr(value, name) for name in expected_fields}
    except (AttributeError, TypeError):
        raise MigrationError(f"{label} is malformed") from None


def _validate_verified_rollback_activation(
    activation: object,
    *,
    binding: _RollbackRecoveryBinding,
    expected_receipt_sha256: str,
) -> None:
    values = _activation_dataclass_values(
        activation,
        expected_fields={"proof_path", "base_url", "proof"},
        label="verified rollback activation",
    )
    proof_values = _activation_dataclass_values(
        values["proof"],
        expected_fields={"management_status", "proved_at", "version"},
        label="verified rollback activation proof",
    )
    proof_path = values["proof_path"]
    base_url = values["base_url"]
    proved_at = proof_values["proved_at"]
    version = proof_values["version"]
    base_url_match = (
        re.fullmatch(r"http://127\.0\.0\.1:([0-9]{1,5})", base_url)
        if type(base_url) is str
        else None
    )
    port = int(base_url_match.group(1)) if base_url_match is not None else 0
    if (
        not isinstance(proof_path, Path)
        or not proof_path.is_absolute()
        or base_url_match is None
        or port <= 1024
        or port > 65535
        or proof_values["management_status"] != 200
        or type(proved_at) is not str
        or re.fullmatch(r"\d{8}T\d{6}Z", proved_at) is None
        or type(version) is not str
        or ROLLBACK_VERSION_PATTERN.fullmatch(version) is None
    ):
        raise MigrationError("verified rollback activation is malformed")
    backup_root = proof_path.parent
    if (
        proof_path.name != "rollback-activation.json"
        or backup_root != binding.backup_root
        or base_url != binding.base_url
        or version != binding.version
    ):
        raise MigrationError("verified rollback activation path is malformed")
    proof_snapshot = _read_regular_snapshot(
        proof_path,
        root=binding.source.checkout_root,
        label="verified rollback activation proof",
        maximum=1024 * 1024,
        required_mode=0o600,
    )
    try:
        envelope = json.loads(
            proof_snapshot.content.decode("utf-8"),
            object_pairs_hook=_strict_json_object,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise MigrationError(
            "verified rollback activation proof is malformed",
        ) from None
    payload = validate_digest_envelope(envelope)
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
    if (
        set(payload) != expected_fields
        or payload.get("activated_at") != proved_at
        or payload.get("backup_root") != str(backup_root)
        or payload.get("base_url") != base_url
        or payload.get("management_status") != 200
        or payload.get("schema")
        != "mail-sandbox.stalwart-v015-rollback-activation.v1"
        or payload.get("service") != "stalwart-rollback"
        or payload.get("source_receipt_sha256")
        != expected_receipt_sha256
        or payload.get("version") != version
        or payload.get("project") != binding.project
        or payload.get("image_digest") != binding.image_digest
        or payload.get("image_id") != binding.image_id
        or type(payload.get("container_id")) is not str
        or re.fullmatch(r"[0-9a-f]{64}", payload["container_id"]) is None
        or type(payload.get("network_id")) is not str
        or re.fullmatch(r"[0-9a-f]{64}", payload["network_id"]) is None
    ):
        raise MigrationError("verified rollback activation proof is malformed")


def _activate_rollback_after_failed_mutation(
    paths: MigrationPaths,
    binding: _RollbackRecoveryBinding,
    *,
    operation_lock: object,
    state_runner: object,
    runtime_runner: object,
    rollback_activator: object,
) -> None:
    safe_to_activate = True
    cancellation: BaseException | None = None
    for operation in (
        lambda: _assert_production_apply_lock(
            operation_lock,
            paths.repository_root,
        ),
        lambda: _stop_failed_migration_runtime(
            binding,
            runner=runtime_runner,
        ),
        lambda: _assert_production_apply_lock(
            operation_lock,
            paths.repository_root,
        ),
        lambda: assert_no_running_store_writers(
            paths,
            source_store=binding.source.provider_store,
            runner=state_runner,
        ),
        lambda: _assert_production_apply_lock(
            operation_lock,
            paths.repository_root,
        ),
        lambda: _revalidate_rollback_recovery_binding(paths, binding),
        lambda: _assert_production_apply_lock(
            operation_lock,
            paths.repository_root,
        ),
    ):
        try:
            operation()
        except BaseException as error:
            safe_to_activate = False
            if not isinstance(error, Exception) and cancellation is None:
                cancellation = error
    if not safe_to_activate:
        if cancellation is not None:
            raise cancellation
        raise MigrationError(
            "failed mutation rollback activation failed safely",
        ) from None
    try:
        activation = rollback_activator(
            paths.source_receipt,
            expected_receipt_sha256=binding.source_receipt.sha256,
        )
        _validate_verified_rollback_activation(
            activation,
            binding=binding,
            expected_receipt_sha256=binding.source_receipt.sha256,
        )
        _assert_production_apply_lock(
            operation_lock,
            paths.repository_root,
        )
    except Exception:
        raise MigrationError(
            "failed mutation rollback activation failed safely",
        ) from None


def _activate_rollback_after_primary_failure(
    paths: MigrationPaths,
    binding: _RollbackRecoveryBinding,
    *,
    primary: BaseException,
    operation_lock: object,
    state_runner: object,
    runtime_runner: object,
    rollback_activator: object,
) -> None:
    """Keep cancellation identity even when secondary recovery also fails."""
    if not isinstance(primary, BaseException):
        raise MigrationError("failed mutation primary error is malformed")
    try:
        _activate_rollback_after_failed_mutation(
            paths,
            binding,
            operation_lock=operation_lock,
            state_runner=state_runner,
            runtime_runner=runtime_runner,
            rollback_activator=rollback_activator,
        )
    except BaseException:
        if not isinstance(primary, Exception):
            raise primary
        raise


@dataclass(frozen=True, repr=False)
class ProductionApplyDependencies:
    """Offline-testable production adapters for the fixed APPLY workflow."""

    acquire_operation_lock: object
    prepare: object
    apply_executor_factory: object
    post_apply_verifier_factory: object
    state_runner: object
    runtime_runner: object
    secret_runtime_runner: object
    recovery_credential_source: object
    rollback_activator: object = default_rollback_activator

    def __post_init__(self) -> None:
        if any(
            not callable(value)
            for value in (
                self.acquire_operation_lock,
                self.prepare,
                self.apply_executor_factory,
                self.post_apply_verifier_factory,
                self.state_runner,
                self.runtime_runner,
                self.secret_runtime_runner,
                self.recovery_credential_source,
                self.rollback_activator,
            )
        ):
            raise MigrationError("production apply dependency is unavailable")

    def __repr__(self) -> str:
        return "ProductionApplyDependencies(<redacted>)"


def production_apply_dependencies() -> ProductionApplyDependencies:
    """Return the exact production dependency set without capturing patch state."""
    return ProductionApplyDependencies(
        acquire_operation_lock=acquire_stalwart_operation_lock,
        prepare=prepare_apply,
        apply_executor_factory=MigrationApplyExecutor,
        post_apply_verifier_factory=MigrationPostApplyVerifier,
        state_runner=run_command,
        runtime_runner=run_redacted_command,
        secret_runtime_runner=run_redacted_secret_command,
        recovery_credential_source=_generate_production_recovery_credential,
        rollback_activator=default_rollback_activator,
    )


def _assert_production_apply_lock(
    operation_lock: object,
    repository_root: Path,
) -> None:
    validator = getattr(operation_lock, "assert_valid_for", None)
    if not callable(validator):
        raise MigrationError("Stalwart operation lock token is malformed")
    validator(repository_root)


def run_production_apply(
    paths: MigrationPaths,
    *,
    script_path: Path,
    review_receipt_path: Path,
    dependencies: ProductionApplyDependencies | None = None,
    expected_script_sha256: str = MIGRATION_SCRIPT_SHA256,
) -> Path:
    """Execute fixed Task 6 APPLY while holding the shared operation lock."""
    if not isinstance(paths, MigrationPaths):
        raise MigrationError("production apply paths are malformed")
    if not isinstance(script_path, Path) or not isinstance(
        review_receipt_path,
        Path,
    ):
        raise MigrationError("production apply arguments are malformed")
    if (
        type(expected_script_sha256) is not str
        or re.fullmatch(r"[0-9a-f]{64}", expected_script_sha256) is None
    ):
        raise MigrationError("production apply script digest is malformed")
    selected = (
        production_apply_dependencies()
        if dependencies is None
        else dependencies
    )
    if type(selected) is not ProductionApplyDependencies:
        raise MigrationError("production apply dependencies are malformed")

    lock_context = selected.acquire_operation_lock(paths.repository_root)
    try:
        enter = getattr(lock_context, "__enter__", None)
        exit_context = getattr(lock_context, "__exit__", None)
        if not callable(enter) or not callable(exit_context):
            raise MigrationError("Stalwart operation lock token is malformed")
        with lock_context as operation_lock:
            _assert_production_apply_lock(
                operation_lock,
                paths.repository_root,
            )
            rollback_binding: _RollbackRecoveryBinding | None = None

            def bind_durable_apply_recovery() -> bool:
                nonlocal rollback_binding
                recovered = _load_durable_apply_recovery_state(
                    paths,
                    source_receipt_path=paths.source_receipt,
                    script_path=script_path,
                    dry_run_receipt_path=paths.dry_run_receipt,
                    review_receipt_path=review_receipt_path,
                    runner=selected.state_runner,
                    python_executable=sys.executable,
                    expected_script_sha256=expected_script_sha256,
                )
                if recovered is None:
                    return False
                _assert_production_apply_lock(
                    operation_lock,
                    paths.repository_root,
                )
                candidate = _rollback_recovery_binding(
                    paths,
                    recovered.plan,
                )
                if candidate is None:
                    raise MigrationError(
                        "durable apply rollback binding is unavailable",
                    )
                if (
                    rollback_binding is not None
                    and rollback_binding != candidate
                ):
                    raise MigrationError(
                        "rollback recovery binding changed",
                    )
                rollback_binding = candidate
                _validate_durable_apply_runtime_state(
                    paths,
                    recovered,
                    source_receipt_path=paths.source_receipt,
                    script_path=script_path,
                    dry_run_receipt_path=paths.dry_run_receipt,
                    review_receipt_path=review_receipt_path,
                    runner=selected.state_runner,
                    python_executable=sys.executable,
                    expected_script_sha256=expected_script_sha256,
                )
                _assert_production_apply_lock(
                    operation_lock,
                    paths.repository_root,
                )
                return True

            try:
                if bind_durable_apply_recovery():
                    raise MigrationError(
                        "apply attempt marker exists; reconciliation is required",
                    )
                credential_factory = _ProductionRecoveryCredentialFactory(
                    selected.recovery_credential_source,
                )
                try:
                    executor = selected.apply_executor_factory(
                        credential_factory=credential_factory,
                        runner=selected.runtime_runner,
                        secret_runner=selected.secret_runtime_runner,
                        state_runner=selected.state_runner,
                    )
                    verifier = selected.post_apply_verifier_factory(
                        runner=selected.runtime_runner,
                        secret_runner=selected.secret_runtime_runner,
                        state_runner=selected.state_runner,
                    )
                    if not callable(executor) or not callable(verifier):
                        raise MigrationError(
                            "production apply runtime adapter is unavailable",
                        )

                    def locked_executor(plan: ApplyPlan) -> str:
                        nonlocal rollback_binding
                        _assert_production_apply_lock(
                            operation_lock,
                            paths.repository_root,
                        )
                        candidate = _rollback_recovery_binding(paths, plan)
                        if candidate is not None:
                            if (
                                rollback_binding is not None
                                and rollback_binding != candidate
                            ):
                                raise MigrationError(
                                    "rollback recovery binding changed",
                                )
                            rollback_binding = candidate
                        try:
                            return executor(plan)
                        finally:
                            _assert_production_apply_lock(
                                operation_lock,
                                paths.repository_root,
                            )

                    def locked_verifier(plan: ApplyPlan) -> PostApplyCensusProof:
                        _assert_production_apply_lock(
                            operation_lock,
                            paths.repository_root,
                        )
                        try:
                            return verifier(plan)
                        finally:
                            _assert_production_apply_lock(
                                operation_lock,
                                paths.repository_root,
                            )

                    receipt = selected.prepare(
                        paths,
                        source_receipt_path=paths.source_receipt,
                        script_path=script_path,
                        dry_run_receipt_path=paths.dry_run_receipt,
                        review_receipt_path=review_receipt_path,
                        runner=selected.state_runner,
                        python_executable=sys.executable,
                        executor=locked_executor,
                        post_apply_verifier=locked_verifier,
                        expected_script_sha256=expected_script_sha256,
                    )
                finally:
                    credential_factory.close()
                    _assert_production_apply_lock(
                        operation_lock,
                        paths.repository_root,
                    )
                if receipt != paths.apply_receipt:
                    raise MigrationError(
                        "production apply returned a non-fixed receipt path",
                    )
                require_regular_0600(
                    receipt,
                    root=paths.repository_root,
                    label="apply receipt",
                )
                _assert_production_apply_lock(
                    operation_lock,
                    paths.repository_root,
                )
                return receipt
            except BaseException as primary:
                recovery_error: BaseException | None = None
                if rollback_binding is None:
                    try:
                        bind_durable_apply_recovery()
                    except BaseException as error:
                        recovery_error = error
                if rollback_binding is not None:
                    _activate_rollback_after_primary_failure(
                        paths,
                        rollback_binding,
                        primary=primary,
                        operation_lock=operation_lock,
                        state_runner=selected.state_runner,
                        runtime_runner=selected.runtime_runner,
                        rollback_activator=selected.rollback_activator,
                    )
                if recovery_error is not None:
                    if not isinstance(primary, Exception):
                        raise primary
                    if not isinstance(recovery_error, Exception):
                        raise recovery_error
                    raise MigrationError(
                        "apply attempt marker exists; "
                        "reconciliation is required",
                    ) from None
                raise
    except (MigrationError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise MigrationError("production apply failed safely") from None


PRODUCTION_BOOTSTRAP_MODULE_NAME_PREFIX = (
    "_mail_sandbox_bootstrap_stalwart_v016_"
)
_PRODUCTION_BOOTSTRAP_MODULE_MARKER = object()
_PRODUCTION_BOOTSTRAP_MODULE_MARKER_ATTRIBUTE = (
    "_mail_sandbox_production_bootstrap_module_marker"
)
_PRODUCTION_BOOTSTRAP_MODULES: dict[
    str,
    tuple[ModuleType, object],
] = {}


def _assert_trusted_production_bootstrap_module(
    module: object,
    bootstrap_path: Path,
) -> ModuleType:
    """Require one loader-issued module to remain under its unique alias."""
    if type(module) is not ModuleType:
        raise MigrationError(
            "production bootstrap module identity is malformed",
        )
    module_name = getattr(module, "__name__", None)
    specification = getattr(module, "__spec__", None)
    loader = getattr(module, "__loader__", None)
    registered = (
        _PRODUCTION_BOOTSTRAP_MODULES.get(module_name)
        if type(module_name) is str
        else None
    )
    if (
        type(module_name) is not str
        or re.fullmatch(
            re.escape(PRODUCTION_BOOTSTRAP_MODULE_NAME_PREFIX)
            + r"[0-9a-f]{32}",
            module_name,
        )
        is None
        or type(specification) is not importlib.machinery.ModuleSpec
        or type(loader) is not importlib.machinery.SourceFileLoader
        or specification.name != module_name
        or specification.origin != str(bootstrap_path)
        or specification.loader is not loader
        or loader.name != module_name
        or loader.path != str(bootstrap_path)
        or getattr(module, "__file__", None) != str(bootstrap_path)
        or getattr(
            module,
            _PRODUCTION_BOOTSTRAP_MODULE_MARKER_ATTRIBUTE,
            None,
        )
        is not _PRODUCTION_BOOTSTRAP_MODULE_MARKER
        or registered is None
        or registered[0] is not module
        or registered[1] is not loader
        or sys.modules.get(module_name) is not module
    ):
        raise MigrationError(
            "production bootstrap module identity is malformed",
        )
    token_type = getattr(module, "ValidatedFinalBootstrap", None)
    if (
        type(token_type) is not type
        or token_type.__module__ != module_name
        or getattr(
            module,
            "_FINAL_BOOTSTRAP_VALIDATION_MARKER",
            None,
        )
        is None
    ):
        raise MigrationError(
            "production bootstrap module identity is malformed",
        )
    return module


def _release_production_bootstrap_module(module: object) -> None:
    """Forget only the exact loader-issued module, never a replacement."""
    if type(module) is not ModuleType:
        return
    module_name = getattr(module, "__name__", None)
    if type(module_name) is not str:
        return
    registered = _PRODUCTION_BOOTSTRAP_MODULES.get(module_name)
    if registered is None or registered[0] is not module:
        return
    if sys.modules.get(module_name) is module:
        del sys.modules[module_name]
    del _PRODUCTION_BOOTSTRAP_MODULES[module_name]


def _load_production_bootstrap_module(
    repository_root: Path,
) -> object:
    """Load the fixed sibling bootstrap module under a fresh private name."""
    root = _plain_absolute(
        repository_root,
        "production bootstrap repository",
    )
    script_path = Path(__file__).resolve()
    expected_root = script_path.parents[1]
    if root != expected_root:
        raise MigrationError(
            "production bootstrap repository is not the current checkout",
        )
    bootstrap_path = script_path.with_name("bootstrap_stalwart_v016.py")
    try:
        nonce = secrets.token_hex(16)
        if (
            type(nonce) is not str
            or re.fullmatch(r"[0-9a-f]{32}", nonce) is None
        ):
            raise MigrationError(
                "production bootstrap module identity is malformed",
            )
        module_name = PRODUCTION_BOOTSTRAP_MODULE_NAME_PREFIX + nonce
        if (
            module_name in sys.modules
            or module_name in _PRODUCTION_BOOTSTRAP_MODULES
        ):
            raise MigrationError(
                "production bootstrap module identity is malformed",
            )
        specification = importlib.util.spec_from_file_location(
            module_name,
            bootstrap_path,
        )
        if (
            type(specification) is not importlib.machinery.ModuleSpec
            or type(specification.loader)
            is not importlib.machinery.SourceFileLoader
        ):
            raise MigrationError(
                "production bootstrap module is unavailable",
            )
        module = importlib.util.module_from_spec(specification)
        setattr(
            module,
            _PRODUCTION_BOOTSTRAP_MODULE_MARKER_ATTRIBUTE,
            _PRODUCTION_BOOTSTRAP_MODULE_MARKER,
        )
        sys.modules[module_name] = module
        try:
            specification.loader.exec_module(module)
        except BaseException:
            if sys.modules.get(module_name) is module:
                del sys.modules[module_name]
            raise
        _PRODUCTION_BOOTSTRAP_MODULES[module_name] = (
            module,
            specification.loader,
        )
        try:
            return _assert_trusted_production_bootstrap_module(
                module,
                bootstrap_path,
            )
        except BaseException:
            _release_production_bootstrap_module(module)
            raise
    except (MigrationError, KeyboardInterrupt, SystemExit):
        raise
    except BaseException:
        raise MigrationError(
            "production bootstrap module failed safely",
        ) from None


def _load_existing_retirement_recovery_plan(
    paths: MigrationPaths,
    *,
    bootstrap_receipt_validator: object,
    state_runner: object,
    python_executable: str,
    expected_script_sha256: str,
) -> RecoveryRetirementPlan | None:
    attempt_exists, _proof_exists, _receipt_exists = (
        _retirement_file_state(paths)
    )
    if not attempt_exists:
        return None
    state = _validated_retirement_state(
        paths,
        source_receipt_path=paths.source_receipt,
        script_path=paths.migration_script,
        dry_run_receipt_path=paths.dry_run_receipt,
        review_receipt_path=paths.reviewed,
        apply_receipt_path=paths.apply_receipt,
        runner=state_runner,
        python_executable=python_executable,
        expected_script_sha256=expected_script_sha256,
        runtime_phase="durable-recovery",
        writer_census=False,
        bootstrap_receipt_validator=bootstrap_receipt_validator,
    )
    retirement_attempt = _retirement_attempt_snapshot(paths)
    plan = _recovery_retirement_plan(
        state.validated,
        apply_receipt=state.apply_receipt,
        apply_attempt=state.apply_attempt,
        bootstrap_receipt=state.bootstrap_receipt,
        bootstrap=state.bootstrap,
        retirement_attempt=retirement_attempt,
        runtime_metadata=state.runtime_metadata,
    )
    _validate_retirement_attempt_snapshot(
        retirement_attempt,
        plan,
        runtime_metadata=state.runtime_metadata,
    )
    return plan


@dataclass(frozen=True, repr=False)
class ProductionRecoveryRetirementDependencies:
    """Offline-testable adapters for fixed production recovery retirement."""

    acquire_operation_lock: object
    prepare: object
    bootstrap_module_loader: object
    bootstrap_apply_validator_factory: object
    retirement_executor_factory: object
    postflight_verifier_factory: object
    state_runner: object
    runtime_runner: object
    jmap_probe_runner: object
    basic_jmap_probe_runner: object = run_fixed_normal_basic_jmap_auth_probe
    smtp_probe_runner: object = run_fixed_normal_smtp_auth_probe
    rollback_activator: object = default_rollback_activator
    existing_retirement_plan_loader: object = (
        _load_existing_retirement_recovery_plan
    )

    def __post_init__(self) -> None:
        if any(
            not callable(value)
            for value in (
                self.acquire_operation_lock,
                self.prepare,
                self.bootstrap_module_loader,
                self.bootstrap_apply_validator_factory,
                self.retirement_executor_factory,
                self.postflight_verifier_factory,
                self.state_runner,
                self.runtime_runner,
                self.jmap_probe_runner,
                self.basic_jmap_probe_runner,
                self.smtp_probe_runner,
                self.rollback_activator,
                self.existing_retirement_plan_loader,
            )
        ):
            raise MigrationError(
                "production recovery retirement dependency is unavailable",
            )

    def __repr__(self) -> str:
        return "ProductionRecoveryRetirementDependencies(<redacted>)"


def production_recovery_retirement_dependencies(
) -> ProductionRecoveryRetirementDependencies:
    """Return the fixed production dependency set without loading modules."""
    return ProductionRecoveryRetirementDependencies(
        acquire_operation_lock=acquire_stalwart_operation_lock,
        prepare=prepare_recovery_retirement,
        bootstrap_module_loader=_load_production_bootstrap_module,
        bootstrap_apply_validator_factory=(
            build_bootstrap_apply_receipt_validator
        ),
        retirement_executor_factory=RecoveryRetirementExecutor,
        postflight_verifier_factory=RecoveryRetirementPostflightVerifier,
        state_runner=run_command,
        runtime_runner=run_redacted_command,
        jmap_probe_runner=run_fixed_jmap_auth_probe,
        basic_jmap_probe_runner=run_fixed_normal_basic_jmap_auth_probe,
        smtp_probe_runner=run_fixed_normal_smtp_auth_probe,
        rollback_activator=default_rollback_activator,
        existing_retirement_plan_loader=(
            _load_existing_retirement_recovery_plan
        ),
    )


def _assert_production_retirement_lock(
    operation_lock: object,
    repository_root: Path,
) -> None:
    validator = getattr(operation_lock, "assert_valid_for", None)
    if not callable(validator):
        raise MigrationError("Stalwart operation lock token is malformed")
    validator(repository_root)


def run_production_recovery_retirement(
    paths: MigrationPaths,
    *,
    dependencies: ProductionRecoveryRetirementDependencies | None = None,
    expected_script_sha256: str = MIGRATION_SCRIPT_SHA256,
) -> Path:
    """Retire recovery using exactly one shared operation lock."""
    if not isinstance(paths, MigrationPaths):
        raise MigrationError("production recovery retirement paths are malformed")
    if (
        type(expected_script_sha256) is not str
        or re.fullmatch(r"[0-9a-f]{64}", expected_script_sha256) is None
    ):
        raise MigrationError(
            "production recovery retirement script digest is malformed",
        )
    selected = (
        production_recovery_retirement_dependencies()
        if dependencies is None
        else dependencies
    )
    if type(selected) is not ProductionRecoveryRetirementDependencies:
        raise MigrationError(
            "production recovery retirement dependencies are malformed",
        )

    lock_context = selected.acquire_operation_lock(paths.repository_root)
    bootstrap_module: object | None = None
    try:
        enter = getattr(lock_context, "__enter__", None)
        exit_context = getattr(lock_context, "__exit__", None)
        if not callable(enter) or not callable(exit_context):
            raise MigrationError("Stalwart operation lock token is malformed")
        with lock_context as operation_lock:
            _assert_production_retirement_lock(
                operation_lock,
                paths.repository_root,
            )
            bootstrap_module = selected.bootstrap_module_loader(
                paths.repository_root,
            )
            trusted_bootstrap_module: ModuleType | None = None
            if (
                type(bootstrap_module) is ModuleType
                and getattr(
                    bootstrap_module,
                    _PRODUCTION_BOOTSTRAP_MODULE_MARKER_ATTRIBUTE,
                    None,
                )
                is _PRODUCTION_BOOTSTRAP_MODULE_MARKER
            ):
                trusted_bootstrap_module = (
                    _assert_trusted_production_bootstrap_module(
                        bootstrap_module,
                        Path(__file__).resolve().with_name(
                            "bootstrap_stalwart_v016.py",
                        ),
                    )
                )
            _assert_production_retirement_lock(
                operation_lock,
                paths.repository_root,
            )
            current_finalizer = getattr(
                bootstrap_module,
                "finalize_migrated_current_runtime",
                None,
            )
            if not callable(current_finalizer):
                raise MigrationError(
                    "current runtime finalizer is unavailable",
                )
            expected_current = (
                paths.repository_root
                / "debug-dashboard"
                / ".runtime"
                / "stalwart"
                / "current.json"
            )

            def finalize_current_runtime() -> Path:
                if trusted_bootstrap_module is not None:
                    _assert_trusted_production_bootstrap_module(
                        trusted_bootstrap_module,
                        Path(__file__).resolve().with_name(
                            "bootstrap_stalwart_v016.py",
                        ),
                    )
                try:
                    current_receipt = current_finalizer(
                        paths.repository_root,
                    )
                except (KeyboardInterrupt, SystemExit):
                    raise
                except Exception:
                    raise MigrationError(
                        "current runtime finalization failed safely",
                    ) from None
                if current_receipt != expected_current:
                    raise MigrationError(
                        "current runtime finalizer returned a non-fixed receipt",
                    )
                require_regular_0600(
                    current_receipt,
                    root=paths.repository_root,
                    label="current runtime receipt",
                )
                _assert_production_retirement_lock(
                    operation_lock,
                    paths.repository_root,
                )
                return current_receipt

            if _path_present(expected_current):
                finalize_current_runtime()
            bootstrap_paths_type = getattr(
                bootstrap_module,
                "BootstrapPaths",
                None,
            )
            bootstrap_validator = getattr(
                bootstrap_module,
                "validate_final_bootstrap_for_retirement",
                None,
            )
            bootstrap_paths_factory = getattr(
                bootstrap_paths_type,
                "for_repository",
                None,
            )
            if not callable(bootstrap_paths_factory) or not callable(
                bootstrap_validator,
            ):
                raise MigrationError(
                    "production bootstrap validator is unavailable",
                )
            bootstrap_paths = bootstrap_paths_factory(
                paths.repository_root,
            )

            def authoritative_bootstrap_validator(
                runtime_phase: str,
            ) -> object:
                if runtime_phase not in {
                    "ready",
                    "retired",
                    "durable-recovery",
                }:
                    raise MigrationError(
                        "retirement runtime phase is malformed",
                    )
                _assert_production_retirement_lock(
                    operation_lock,
                    paths.repository_root,
                )
                if trusted_bootstrap_module is not None:
                    _assert_trusted_production_bootstrap_module(
                        trusted_bootstrap_module,
                        Path(__file__).resolve().with_name(
                            "bootstrap_stalwart_v016.py",
                        ),
                    )
                try:
                    task6_validator = (
                        selected.bootstrap_apply_validator_factory(
                            paths,
                            source_receipt_path=paths.source_receipt,
                            script_path=paths.migration_script,
                            dry_run_receipt_path=paths.dry_run_receipt,
                            review_receipt_path=paths.reviewed,
                            runner=selected.state_runner,
                            python_executable=sys.executable,
                            expected_script_sha256=(
                                expected_script_sha256
                            ),
                            runtime_phase=runtime_phase,
                        )
                    )
                    if not callable(task6_validator):
                        raise MigrationError(
                            "bootstrap apply validator is unavailable",
                        )
                    token = bootstrap_validator(
                        bootstrap_paths,
                        task6_validator=task6_validator,
                    )
                    if trusted_bootstrap_module is not None:
                        _assert_trusted_production_bootstrap_module(
                            trusted_bootstrap_module,
                            Path(__file__).resolve().with_name(
                                "bootstrap_stalwart_v016.py",
                            ),
                        )
                    return token
                finally:
                    _assert_production_retirement_lock(
                        operation_lock,
                        paths.repository_root,
                    )

            if trusted_bootstrap_module is not None:
                setattr(
                    authoritative_bootstrap_validator,
                    "_trusted_bootstrap_module",
                    trusted_bootstrap_module,
                )
            _assert_production_retirement_lock(
                operation_lock,
                paths.repository_root,
            )
            rollback_binding: _RollbackRecoveryBinding | None = None
            existing_attempt = _path_present(
                paths.retire_recovery_attempt,
            )
            try:
                existing_plan = (
                    selected.existing_retirement_plan_loader(
                        paths,
                        bootstrap_receipt_validator=(
                            authoritative_bootstrap_validator
                        ),
                        state_runner=selected.state_runner,
                        python_executable=sys.executable,
                        expected_script_sha256=expected_script_sha256,
                    )
                )
            except BaseException as error:
                if not isinstance(error, Exception):
                    raise
                if existing_attempt:
                    raise MigrationError(
                        "existing retirement recovery plan failed safely",
                    ) from None
                raise
            if existing_attempt and existing_plan is None:
                raise MigrationError(
                    "existing retirement recovery plan failed safely",
                )
            if existing_plan is not None:
                rollback_binding = (
                    _rollback_retirement_recovery_binding(
                        paths,
                        existing_plan,
                    )
                )
                if rollback_binding is None:
                    raise MigrationError(
                        "existing retirement recovery plan is malformed",
                    )
            try:
                _assert_production_retirement_lock(
                    operation_lock,
                    paths.repository_root,
                )
                executor = selected.retirement_executor_factory(
                    paths=paths,
                    runner=selected.runtime_runner,
                    state_runner=selected.state_runner,
                    jmap_probe_runner=selected.jmap_probe_runner,
                    basic_jmap_probe_runner=(
                        selected.basic_jmap_probe_runner
                    ),
                    smtp_probe_runner=selected.smtp_probe_runner,
                )
                _assert_production_retirement_lock(
                    operation_lock,
                    paths.repository_root,
                )
                verifier = selected.postflight_verifier_factory(
                    paths=paths,
                    runner=selected.runtime_runner,
                    state_runner=selected.state_runner,
                    jmap_probe_runner=selected.jmap_probe_runner,
                    basic_jmap_probe_runner=(
                        selected.basic_jmap_probe_runner
                    ),
                    smtp_probe_runner=selected.smtp_probe_runner,
                )
                if not callable(executor) or not callable(verifier):
                    raise MigrationError(
                        "production recovery retirement adapter is unavailable",
                    )
            except BaseException as primary:
                if rollback_binding is not None:
                    _activate_rollback_after_primary_failure(
                        paths,
                        rollback_binding,
                        primary=primary,
                        operation_lock=operation_lock,
                        state_runner=selected.state_runner,
                        runtime_runner=selected.runtime_runner,
                        rollback_activator=selected.rollback_activator,
                    )
                raise

            def locked_executor(
                plan: RecoveryRetirementPlan,
                credential: RecoveryCredentialLease,
                checkpoint: object,
            ) -> RecoveryRetirementProof:
                nonlocal rollback_binding
                _assert_production_retirement_lock(
                    operation_lock,
                    paths.repository_root,
                )
                candidate = _rollback_retirement_recovery_binding(
                    paths,
                    plan,
                )
                if candidate is not None:
                    if (
                        rollback_binding is not None
                        and rollback_binding != candidate
                    ):
                        raise MigrationError(
                            "rollback recovery binding changed",
                        )
                    rollback_binding = candidate
                try:
                    return executor(plan, credential, checkpoint)
                finally:
                    _assert_production_retirement_lock(
                        operation_lock,
                        paths.repository_root,
                    )

            def locked_verifier(
                plan: RecoveryRetirementPlan,
            ) -> RecoveryRetirementProof:
                nonlocal rollback_binding
                _assert_production_retirement_lock(
                    operation_lock,
                    paths.repository_root,
                )
                candidate = _rollback_retirement_recovery_binding(
                    paths,
                    plan,
                )
                if candidate is not None:
                    if (
                        rollback_binding is not None
                        and rollback_binding != candidate
                    ):
                        raise MigrationError(
                            "rollback recovery binding changed",
                        )
                    rollback_binding = candidate
                try:
                    return verifier(plan)
                finally:
                    _assert_production_retirement_lock(
                        operation_lock,
                        paths.repository_root,
                    )

            try:
                receipt = selected.prepare(
                    paths,
                    source_receipt_path=paths.source_receipt,
                    script_path=paths.migration_script,
                    dry_run_receipt_path=paths.dry_run_receipt,
                    review_receipt_path=paths.reviewed,
                    apply_receipt_path=paths.apply_receipt,
                    runner=selected.state_runner,
                    python_executable=sys.executable,
                    executor=locked_executor,
                    postflight_verifier=locked_verifier,
                    bootstrap_receipt_validator=(
                        authoritative_bootstrap_validator
                    ),
                    expected_script_sha256=expected_script_sha256,
                )
                if receipt != paths.recovery_retired_receipt:
                    raise MigrationError(
                        "production recovery retirement returned a non-fixed receipt path",
                    )
                require_regular_0600(
                    receipt,
                    root=paths.repository_root,
                    label="recovery-retired receipt",
                )
                _assert_production_retirement_lock(
                    operation_lock,
                    paths.repository_root,
                )
                retirement_receipt = receipt
            except BaseException as primary:
                recovery_error: BaseException | None = None
                if (
                    rollback_binding is None
                    and _path_present(paths.retire_recovery_attempt)
                ):
                    try:
                        recovered_plan = (
                            selected.existing_retirement_plan_loader(
                                paths,
                                bootstrap_receipt_validator=(
                                    authoritative_bootstrap_validator
                                ),
                                state_runner=selected.state_runner,
                                python_executable=sys.executable,
                                expected_script_sha256=(
                                    expected_script_sha256
                                ),
                            )
                        )
                        candidate = (
                            _rollback_retirement_recovery_binding(
                                paths,
                                recovered_plan,
                            )
                            if recovered_plan is not None
                            else None
                        )
                        if candidate is None:
                            raise MigrationError(
                                "retirement recovery binding is unavailable",
                            )
                        rollback_binding = candidate
                    except BaseException as error:
                        recovery_error = error
                if rollback_binding is not None:
                    _activate_rollback_after_primary_failure(
                        paths,
                        rollback_binding,
                        primary=primary,
                        operation_lock=operation_lock,
                        state_runner=selected.state_runner,
                        runtime_runner=selected.runtime_runner,
                        rollback_activator=selected.rollback_activator,
                    )
                if recovery_error is not None:
                    if not isinstance(primary, Exception):
                        raise primary
                    if not isinstance(recovery_error, Exception):
                        raise recovery_error
                    raise MigrationError(
                        "retirement attempt marker exists; "
                        "reconciliation is required",
                    ) from None
                raise

            _assert_production_retirement_lock(
                operation_lock,
                paths.repository_root,
            )
            finalize_current_runtime()
            return retirement_receipt
    except (MigrationError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise MigrationError(
            "production recovery retirement failed safely",
        ) from None
    finally:
        _release_production_bootstrap_module(bootstrap_module)


def _validate_apply_receipt_chain(
    paths: MigrationPaths,
    receipt_path: Path,
    *,
    source_receipt_path: Path,
    script_path: Path,
    dry_run_receipt_path: Path,
    review_receipt_path: Path,
    runner: object = run_command,
    python_executable: str,
    expected_script_sha256: str = MIGRATION_SCRIPT_SHA256,
    writer_census: bool,
) -> dict[str, object]:
    _require_fixed_apply_paths(
        paths,
        source_receipt_path=source_receipt_path,
        script_path=script_path,
        dry_run_receipt_path=dry_run_receipt_path,
        review_receipt_path=review_receipt_path,
    )
    if receipt_path != paths.apply_receipt:
        raise MigrationError("apply receipt is not the fixed repository path")
    before = _read_regular_snapshot(
        receipt_path,
        root=paths.repository_root,
        label="apply receipt",
        maximum=64 * 1024,
        required_mode=0o600,
    )
    marker_before = _apply_attempt_snapshot(paths)
    validated = _validate_apply_state(
        paths,
        source_receipt_path=source_receipt_path,
        script_path=script_path,
        dry_run_receipt_path=dry_run_receipt_path,
        review_receipt_path=review_receipt_path,
        runner=runner,
        python_executable=python_executable,
        expected_script_sha256=expected_script_sha256,
        runtime_phase="ready",
        writer_census=writer_census,
    )
    after = _read_regular_snapshot(
        receipt_path,
        root=paths.repository_root,
        label="apply receipt",
        maximum=64 * 1024,
        required_mode=0o600,
    )
    marker_after = _apply_attempt_snapshot(paths)
    if before != after or marker_before != marker_after:
        raise MigrationError("apply receipt changed while inputs were revalidated")
    try:
        payload = json.loads(
            after.content.decode("utf-8"),
            object_pairs_hook=_strict_json_object,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise MigrationError("apply receipt is not valid JSON") from None
    _validate_apply_attempt_snapshot(marker_after, validated.plan)
    if validated.runtime_artifacts is None:
        raise MigrationError("runtime artifact snapshots are unavailable")
    return _validate_apply_receipt_payload(
        payload,
        validated.plan,
        attempt=marker_after,
        runtime_artifacts=validated.runtime_artifacts,
    )


def validate_apply_receipt(
    paths: MigrationPaths,
    receipt_path: Path,
    *,
    source_receipt_path: Path,
    script_path: Path,
    dry_run_receipt_path: Path,
    review_receipt_path: Path,
    runner: object = run_command,
    python_executable: str,
    expected_script_sha256: str = MIGRATION_SCRIPT_SHA256,
) -> dict[str, object]:
    """Revalidate an apply receipt against every fixed current input."""
    return _validate_apply_receipt_chain(
        paths,
        receipt_path,
        source_receipt_path=source_receipt_path,
        script_path=script_path,
        dry_run_receipt_path=dry_run_receipt_path,
        review_receipt_path=review_receipt_path,
        runner=runner,
        python_executable=python_executable,
        expected_script_sha256=expected_script_sha256,
        writer_census=True,
    )


def validate_apply_receipt_for_bootstrap(
    paths: MigrationPaths,
    receipt_path: Path,
    *,
    source_receipt_path: Path,
    script_path: Path,
    dry_run_receipt_path: Path,
    review_receipt_path: Path,
    runner: object = run_command,
    python_executable: str,
    expected_script_sha256: str = MIGRATION_SCRIPT_SHA256,
    runtime_phase: str = "ready",
) -> dict[str, object]:
    """Validate Task 6 for bootstrap in one explicit runtime phase."""
    if runtime_phase not in {"ready", "retired", "durable-recovery"}:
        raise MigrationError("bootstrap apply runtime phase is malformed")
    _require_fixed_apply_paths(
        paths,
        source_receipt_path=source_receipt_path,
        script_path=script_path,
        dry_run_receipt_path=dry_run_receipt_path,
        review_receipt_path=review_receipt_path,
    )
    if receipt_path != paths.apply_receipt:
        raise MigrationError("apply receipt is not the fixed repository path")
    return _validated_apply_receipt_for_retirement(
        paths,
        source_receipt_path=source_receipt_path,
        script_path=script_path,
        dry_run_receipt_path=dry_run_receipt_path,
        review_receipt_path=review_receipt_path,
        apply_receipt_path=receipt_path,
        runner=runner,
        python_executable=python_executable,
        expected_script_sha256=expected_script_sha256,
        runtime_phase=runtime_phase,
        writer_census=False,
    )[3]


def build_bootstrap_apply_receipt_validator(
    paths: MigrationPaths,
    *,
    source_receipt_path: Path,
    script_path: Path,
    dry_run_receipt_path: Path,
    review_receipt_path: Path,
    runner: object = run_command,
    python_executable: str,
    expected_script_sha256: str = MIGRATION_SCRIPT_SHA256,
    runtime_phase: str = "ready",
) -> Callable[[Path], dict[str, object]]:
    """Build the exact Task 6 closure consumed by the bootstrap planner."""
    if runtime_phase not in {"ready", "retired", "durable-recovery"}:
        raise MigrationError("bootstrap apply runtime phase is malformed")

    def validator(receipt_path: Path) -> dict[str, object]:
        return validate_apply_receipt_for_bootstrap(
            paths,
            receipt_path,
            source_receipt_path=source_receipt_path,
            script_path=script_path,
            dry_run_receipt_path=dry_run_receipt_path,
            review_receipt_path=review_receipt_path,
            runner=runner,
            python_executable=python_executable,
            expected_script_sha256=expected_script_sha256,
            runtime_phase=runtime_phase,
        )

    return validator


def _require_fixed_retirement_paths(
    paths: MigrationPaths,
    *,
    source_receipt_path: Path,
    script_path: Path,
    dry_run_receipt_path: Path,
    review_receipt_path: Path,
    apply_receipt_path: Path,
) -> None:
    _require_fixed_apply_paths(
        paths,
        source_receipt_path=source_receipt_path,
        script_path=script_path,
        dry_run_receipt_path=dry_run_receipt_path,
        review_receipt_path=review_receipt_path,
    )
    if apply_receipt_path != paths.apply_receipt:
        raise MigrationError("apply receipt is not the fixed repository path")
    expected_bootstrap_receipt = (
        paths.repository_root
        / "debug-dashboard"
        / ".runtime"
        / "stalwart"
        / "bootstrap.json"
    )
    if paths.bootstrap_receipt != expected_bootstrap_receipt:
        raise MigrationError("bootstrap receipt is not the fixed repository path")
    for path, label in (
        (paths.retire_recovery_attempt, "retirement attempt"),
        (paths.retire_recovery_proof, "retirement proof"),
        (paths.recovery_retired_receipt, "recovery-retired receipt"),
    ):
        if path.parent != paths.migration_root:
            raise MigrationError(f"{label} path escaped the fixed migration root")


def _path_present(path: Path) -> bool:
    return path.exists() or path.is_symlink()


def _retirement_file_state(paths: MigrationPaths) -> tuple[bool, bool, bool]:
    return (
        _path_present(paths.retire_recovery_attempt),
        _path_present(paths.retire_recovery_proof),
        _path_present(paths.recovery_retired_receipt),
    )


def _parse_strict_json_snapshot(
    snapshot: FileSnapshot,
    *,
    label: str,
) -> dict[str, object]:
    try:
        value = json.loads(
            snapshot.content.decode("utf-8"),
            object_pairs_hook=_strict_json_object,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise MigrationError(f"{label} is malformed") from None
    if not isinstance(value, dict):
        raise MigrationError(f"{label} is malformed")
    return value


def _bootstrap_permissions_sha256() -> str:
    return hashlib.sha256(
        _canonical_json_bytes(list(BOOTSTRAP_MANAGEMENT_PERMISSIONS)),
    ).hexdigest()


def _bootstrap_file_identity(
    metadata: os.stat_result,
) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
    )


def _bootstrap_secret_file_identity(
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


def _validate_bootstrap_secret_metadata(
    paths: MigrationPaths,
    value: object,
) -> tuple[
    int,
    tuple[int, int, int, int, int, int, int, int],
]:
    path = (
        paths.repository_root
        / "debug-dashboard"
        / ".runtime"
        / "secrets"
        / "stalwart-management-api-key"
    )
    descriptor, before = _open_regular_readonly(
        path,
        root=paths.repository_root,
        label="management API key file",
    )
    try:
        after = os.fstat(descriptor)
    except OSError as exc:
        raise MigrationError(
            "management API key file could not be inspected safely",
        ) from exc
    finally:
        try:
            os.close(descriptor)
        except OSError as exc:
            raise MigrationError(
                "management API key file could not be closed safely",
            ) from exc
    try:
        named = path.lstat()
    except OSError as exc:
        raise MigrationError(
            "management API key file changed during validation",
        ) from exc
    identity = _bootstrap_secret_file_identity(after)
    expected = {
        "identity": list(identity),
        "name": path.name,
        "size": after.st_size,
    }
    if (
        _bootstrap_secret_file_identity(before) != identity
        or _bootstrap_secret_file_identity(named) != identity
        or stat.S_IMODE(after.st_mode) != 0o600
        or after.st_nlink != 1
        or not 1 <= after.st_size <= 4096
        or value != expected
    ):
        raise MigrationError("management API key commitment is stale or malformed")
    return after.st_size, identity


def _validate_bootstrap_token_file(
    paths: MigrationPaths,
    value: object,
    *,
    path: Path,
    label: str,
) -> FileSnapshot:
    snapshot = _read_regular_snapshot(
        path,
        root=paths.repository_root,
        label=label,
        maximum=4 * 1024 * 1024,
        required_mode=0o600,
    )
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise MigrationError(f"{label} changed during validation") from exc
    if (
        _file_identity(metadata) != snapshot.identity
        or getattr(value, "path", None) != path
        or getattr(value, "sha256", None) != snapshot.sha256
        or getattr(value, "size", None) != snapshot.size
        or getattr(value, "identity", None)
        != _bootstrap_file_identity(metadata)
    ):
        raise MigrationError(f"{label} token binding is stale or malformed")
    return snapshot


def _validated_authoritative_bootstrap_token(
    paths: MigrationPaths,
    *,
    apply_receipt: FileSnapshot,
    validator: object,
    runtime_phase: str,
) -> tuple[FileSnapshot, BootstrapRetirementBinding]:
    if not callable(validator):
        raise MigrationError(
            "authoritative bootstrap receipt validator is unavailable",
        )
    receipt_before = _read_regular_snapshot(
        paths.bootstrap_receipt,
        root=paths.repository_root,
        label="bootstrap receipt",
        maximum=4 * 1024 * 1024,
        required_mode=0o600,
    )
    try:
        token = validator(runtime_phase)
    except Exception:
        raise MigrationError(
            "authoritative bootstrap receipt validation failed",
        ) from None
    token_type = type(token)
    token_module = sys.modules.get(token_type.__module__)
    trusted_module = getattr(
        validator,
        "_trusted_bootstrap_module",
        None,
    )
    expected_module_path = Path(__file__).resolve().with_name(
        "bootstrap_stalwart_v016.py",
    )
    try:
        token_module_path = Path(token_module.__file__).resolve()
    except (AttributeError, OSError, TypeError, ValueError):
        raise MigrationError(
            "authoritative bootstrap validator returned an untrusted token",
        ) from None
    if (
        (
            trusted_module is not None
            and (
                type(trusted_module) is not ModuleType
                or getattr(trusted_module, "__name__", None)
                != token_type.__module__
                or sys.modules.get(token_type.__module__)
                is not trusted_module
                or token_module is not trusted_module
            )
        )
        or
        token_module_path != expected_module_path
        or token_type
        is not getattr(token_module, "ValidatedFinalBootstrap", None)
        or getattr(token, "_marker", None)
        is not getattr(
            token_module,
            "_FINAL_BOOTSTRAP_VALIDATION_MARKER",
            None,
        )
        or not is_dataclass(token)
        or not token_type.__dataclass_params__.frozen
        or repr(token) != "ValidatedFinalBootstrap(<redacted>)"
    ):
        raise MigrationError(
            "authoritative bootstrap validator returned an untrusted token",
        )
    _validate_bootstrap_token_file(
        paths,
        getattr(token, "final_receipt", None),
        path=paths.bootstrap_receipt,
        label="bootstrap receipt",
    )
    _validate_bootstrap_token_file(
        paths,
        getattr(token, "apply_receipt", None),
        path=paths.apply_receipt,
        label="bootstrap-bound apply receipt",
    )
    proof_snapshot = _validate_bootstrap_token_file(
        paths,
        getattr(token, "bootstrap_proof", None),
        path=paths.bootstrap_receipt.parent / "bootstrap-proof.json",
        label="bootstrap proof checkpoint",
    )
    routing_snapshot = _validate_bootstrap_token_file(
        paths,
        getattr(token, "routing_proof", None),
        path=(
            paths.bootstrap_receipt.parent
            / "bootstrap-routing-proof.json"
        ),
        label="bootstrap routing proof",
    )
    protected_snapshot = _validate_bootstrap_token_file(
        paths,
        getattr(token, "protected_accounts", None),
        path=paths.bootstrap_receipt.parent / "protected-accounts.json",
        label="protected Account IDs",
    )
    if (
        getattr(token, "bootstrap_receipt_sha256", None)
        != receipt_before.sha256
        or getattr(token, "apply_receipt_sha256", None)
        != apply_receipt.sha256
        or getattr(token, "bootstrap_proof_sha256", None)
        != proof_snapshot.sha256
        or getattr(token, "protected_accounts_sha256", None)
        != protected_snapshot.sha256
        or getattr(token, "routing_proof_sha256", None)
        != routing_snapshot.sha256
    ):
        raise MigrationError(
            "authoritative bootstrap token file digests are stale",
        )
    try:
        apply_metadata = paths.apply_receipt.lstat()
    except OSError as exc:
        raise MigrationError(
            "bootstrap-bound apply receipt changed during validation",
        ) from exc
    if (
        _file_identity(apply_metadata) != apply_receipt.identity
        or getattr(token, "apply_receipt", None).identity
        != _bootstrap_file_identity(apply_metadata)
    ):
        raise MigrationError(
            "authoritative bootstrap token binds a different apply receipt",
        )

    account_id = getattr(token, "management_account_id", None)
    credential_id = getattr(token, "management_api_key_id", None)
    digest_names = (
        "permissions_sha256",
        "protected_accounts_sha256",
        "safe_objects_sha256",
        "preserved_objects_sha256",
        "routing_proof_sha256",
        "account_projection_sha256",
        "api_key_projection_sha256",
    )
    if (
        type(account_id) is not str
        or BOOTSTRAP_SAFE_ID_PATTERN.fullmatch(account_id) is None
        or type(credential_id) is not str
        or BOOTSTRAP_SAFE_ID_PATTERN.fullmatch(credential_id) is None
        or any(
            type(getattr(token, name, None)) is not str
            or re.fullmatch(
                r"[0-9a-f]{64}",
                getattr(token, name),
            )
            is None
            for name in digest_names
        )
        or getattr(token, "permissions_sha256", None)
        != _bootstrap_permissions_sha256()
        or type(getattr(token, "ip_restriction_decision", None)) is not str
        or getattr(token, "ip_restriction_decision", None)
        != BOOTSTRAP_IP_RESTRICTION_DECISION
        or getattr(token, "listener_name", None) != "http"
        or getattr(token, "listener_bind", None) != ("[::]:8080",)
        or getattr(token, "listener_protocol", None) != "http"
        or getattr(token, "listener_use_tls", None) is not False
        or getattr(token, "listener_tls_implicit", None) is not False
        or type(getattr(token, "listener_id", None)) is not str
        or BOOTSTRAP_SAFE_ID_PATTERN.fullmatch(token.listener_id) is None
    ):
        raise MigrationError(
            "authoritative bootstrap token semantics are malformed",
        )
    key_metadata = {
        "identity": list(
            getattr(token, "management_key_identity", ()),
        ),
        "name": getattr(token, "management_key_name", None),
        "size": getattr(token, "management_key_size", None),
    }
    key_size, key_identity = _validate_bootstrap_secret_metadata(
        paths,
        key_metadata,
    )
    proof_after = _validate_bootstrap_token_file(
        paths,
        token.bootstrap_proof,
        path=paths.bootstrap_receipt.parent / "bootstrap-proof.json",
        label="bootstrap proof checkpoint",
    )
    routing_after = _validate_bootstrap_token_file(
        paths,
        token.routing_proof,
        path=(
            paths.bootstrap_receipt.parent
            / "bootstrap-routing-proof.json"
        ),
        label="bootstrap routing proof",
    )
    protected_after = _validate_bootstrap_token_file(
        paths,
        token.protected_accounts,
        path=paths.bootstrap_receipt.parent / "protected-accounts.json",
        label="protected Account IDs",
    )
    key_size_after, key_identity_after = (
        _validate_bootstrap_secret_metadata(
            paths,
            key_metadata,
        )
    )
    if (
        proof_snapshot != proof_after
        or routing_snapshot != routing_after
        or protected_snapshot != protected_after
        or key_size != key_size_after
        or key_identity != key_identity_after
    ):
        raise MigrationError(
            "authoritative bootstrap files changed during validation",
        )
    receipt_after = _read_regular_snapshot(
        paths.bootstrap_receipt,
        root=paths.repository_root,
        label="bootstrap receipt",
        maximum=4 * 1024 * 1024,
        required_mode=0o600,
    )
    if receipt_before != receipt_after:
        raise MigrationError(
            "bootstrap receipt changed during authoritative validation",
        )
    return receipt_after, BootstrapRetirementBinding(
        bootstrap_receipt_sha256=receipt_after.sha256,
        apply_receipt_sha256=apply_receipt.sha256,
        bootstrap_proof_sha256=proof_snapshot.sha256,
        server_version="0.16.17",
        authentication_status=200,
        management_account_id=account_id,
        management_api_key_id=credential_id,
        ip_restriction_decision=token.ip_restriction_decision,
        permissions_sha256=token.permissions_sha256,
        protected_accounts_sha256=protected_snapshot.sha256,
        safe_objects_sha256=token.safe_objects_sha256,
        preserved_objects_sha256=token.preserved_objects_sha256,
        routing_proof_sha256=routing_snapshot.sha256,
        listener_id=token.listener_id,
        listener_name=token.listener_name,
        listener_bind=token.listener_bind,
        listener_protocol=token.listener_protocol,
        listener_use_tls=token.listener_use_tls,
        listener_tls_implicit=token.listener_tls_implicit,
        account_projection_sha256=token.account_projection_sha256,
        api_key_projection_sha256=token.api_key_projection_sha256,
        management_key_name=token.management_key_name,
        management_key_size=key_size,
        management_key_identity=key_identity,
    )


def _validate_bootstrap_receipt_for_retirement(
    paths: MigrationPaths,
    *,
    apply_receipt: FileSnapshot,
    validator: object,
    runtime_phase: str,
) -> tuple[FileSnapshot, BootstrapRetirementBinding]:
    return _validated_authoritative_bootstrap_token(
        paths,
        apply_receipt=apply_receipt,
        validator=validator,
        runtime_phase=runtime_phase,
    )


def _validated_apply_receipt_for_retirement(
    paths: MigrationPaths,
    *,
    source_receipt_path: Path,
    script_path: Path,
    dry_run_receipt_path: Path,
    review_receipt_path: Path,
    apply_receipt_path: Path,
    runner: object,
    python_executable: str,
    expected_script_sha256: str,
    runtime_phase: str,
    writer_census: bool,
) -> tuple[
    _ValidatedApply,
    FileSnapshot,
    FileSnapshot,
    dict[str, object],
    dict[str, object],
]:
    apply_receipt_before = _read_regular_snapshot(
        apply_receipt_path,
        root=paths.repository_root,
        label="apply receipt",
        maximum=64 * 1024,
        required_mode=0o600,
    )
    apply_attempt_before = _apply_attempt_snapshot(paths)
    validated = _validate_apply_state(
        paths,
        source_receipt_path=source_receipt_path,
        script_path=script_path,
        dry_run_receipt_path=dry_run_receipt_path,
        review_receipt_path=review_receipt_path,
        runner=runner,
        python_executable=python_executable,
        expected_script_sha256=expected_script_sha256,
        runtime_phase=runtime_phase,
        writer_census=writer_census,
    )
    apply_receipt_after = _read_regular_snapshot(
        apply_receipt_path,
        root=paths.repository_root,
        label="apply receipt",
        maximum=64 * 1024,
        required_mode=0o600,
    )
    apply_attempt_after = _apply_attempt_snapshot(paths)
    if (
        apply_receipt_before != apply_receipt_after
        or apply_attempt_before != apply_attempt_after
    ):
        raise MigrationError(
            "apply receipt state changed during retirement validation",
        )
    _validate_apply_attempt_snapshot(apply_attempt_after, validated.plan)
    payload = _parse_strict_json_snapshot(
        apply_receipt_after,
        label="apply receipt",
    )
    if runtime_phase == "ready":
        if validated.runtime_artifacts is None:
            raise MigrationError("active recovery artifacts are unavailable")
        runtime_metadata = _runtime_artifact_receipt_metadata(
            validated.runtime_artifacts,
        )
    elif runtime_phase in {"retired", "durable-recovery"}:
        runtime_metadata = _validate_runtime_artifact_commitment(
            payload.get("runtime_artifacts"),
        )
    else:
        raise MigrationError("retirement runtime phase is malformed")
    _validate_apply_receipt_payload_with_runtime_metadata(
        payload,
        validated.plan,
        attempt=apply_attempt_after,
        runtime_metadata=runtime_metadata,
    )
    return (
        validated,
        apply_receipt_after,
        apply_attempt_after,
        payload,
        runtime_metadata,
    )


class _ValidatedRetirementState(NamedTuple):
    validated: _ValidatedApply
    apply_receipt: FileSnapshot
    apply_attempt: FileSnapshot
    apply_payload: dict[str, object]
    runtime_metadata: dict[str, object]
    bootstrap_receipt: FileSnapshot
    bootstrap: BootstrapRetirementBinding


def _validated_retirement_state(
    paths: MigrationPaths,
    *,
    source_receipt_path: Path,
    script_path: Path,
    dry_run_receipt_path: Path,
    review_receipt_path: Path,
    apply_receipt_path: Path,
    runner: object,
    python_executable: str,
    expected_script_sha256: str,
    runtime_phase: str,
    writer_census: bool,
    bootstrap_receipt_validator: object,
) -> _ValidatedRetirementState:
    initial_apply_receipt = _read_regular_snapshot(
        apply_receipt_path,
        root=paths.repository_root,
        label="apply receipt",
        maximum=64 * 1024,
        required_mode=0o600,
    )
    (
        initial_bootstrap_receipt,
        initial_bootstrap,
    ) = _validate_bootstrap_receipt_for_retirement(
        paths,
        apply_receipt=initial_apply_receipt,
        validator=bootstrap_receipt_validator,
        runtime_phase=runtime_phase,
    )
    (
        validated,
        apply_receipt,
        apply_attempt,
        apply_payload,
        runtime_metadata,
    ) = _validated_apply_receipt_for_retirement(
        paths,
        source_receipt_path=source_receipt_path,
        script_path=script_path,
        dry_run_receipt_path=dry_run_receipt_path,
        review_receipt_path=review_receipt_path,
        apply_receipt_path=apply_receipt_path,
        runner=runner,
        python_executable=python_executable,
        expected_script_sha256=expected_script_sha256,
        runtime_phase=runtime_phase,
        writer_census=writer_census,
    )
    bootstrap_receipt, bootstrap = _validate_bootstrap_receipt_for_retirement(
        paths,
        apply_receipt=apply_receipt,
        validator=bootstrap_receipt_validator,
        runtime_phase=runtime_phase,
    )
    if (
        initial_apply_receipt != apply_receipt
        or initial_bootstrap_receipt != bootstrap_receipt
        or initial_bootstrap != bootstrap
    ):
        raise MigrationError(
            "bootstrap-bound state changed during retirement preflight",
        )
    apply_receipt_after = _read_regular_snapshot(
        apply_receipt_path,
        root=paths.repository_root,
        label="apply receipt",
        maximum=64 * 1024,
        required_mode=0o600,
    )
    apply_attempt_after = _apply_attempt_snapshot(paths)
    if (
        apply_receipt_after != apply_receipt
        or apply_attempt_after != apply_attempt
    ):
        raise MigrationError(
            "apply receipt state changed during bootstrap validation",
        )
    return _ValidatedRetirementState(
        validated,
        apply_receipt,
        apply_attempt,
        apply_payload,
        runtime_metadata,
        bootstrap_receipt,
        bootstrap,
    )


def _retirement_timestamp(clock: object | None) -> str:
    value = _apply_timestamp(clock)
    return value


def _retirement_runtime_commitment(
    runtime: MigrationRuntimePaths,
    runtime_metadata: dict[str, object],
) -> dict[str, object]:
    if (
        runtime.data_dir.name != "stalwart-data"
        or runtime.config_dir.name != "recovery-config"
        or runtime.recovery_env_file.name != "recovery.env"
        or runtime.compose_overlay.name
        != "docker-compose.stalwart-migration.yml"
    ):
        raise MigrationError("retirement runtime paths are malformed")
    return {
        "data_directory": "stalwart-data",
        "config_directory": "recovery-config",
        "recovery_environment": "recovery.env",
        "compose_overlay": "docker-compose.stalwart-migration.yml",
        "artifacts": _validate_runtime_artifact_commitment(runtime_metadata),
    }


def _bootstrap_retirement_metadata(
    receipt: ApplyFile,
    binding: BootstrapRetirementBinding,
) -> dict[str, object]:
    if (
        type(binding) is not BootstrapRetirementBinding
        or not secrets.compare_digest(
            receipt.sha256,
            binding.bootstrap_receipt_sha256,
        )
        or binding.server_version != "0.16.17"
        or type(binding.authentication_status) is not int
        or binding.authentication_status != 200
        or type(binding.ip_restriction_decision) is not str
        or binding.ip_restriction_decision
        != BOOTSTRAP_IP_RESTRICTION_DECISION
        or re.fullmatch(r"[0-9a-f]{64}", binding.apply_receipt_sha256) is None
        or re.fullmatch(r"[0-9a-f]{64}", binding.bootstrap_proof_sha256) is None
        or re.fullmatch(r"[0-9a-f]{64}", binding.permissions_sha256) is None
        or re.fullmatch(
            r"[0-9a-f]{64}",
            binding.protected_accounts_sha256,
        )
        is None
        or re.fullmatch(
            r"[0-9a-f]{64}",
            binding.preserved_objects_sha256,
        )
        is None
        or re.fullmatch(
            r"[0-9a-f]{64}",
            binding.safe_objects_sha256,
        )
        is None
        or re.fullmatch(
            r"[0-9a-f]{64}",
            binding.routing_proof_sha256,
        )
        is None
        or re.fullmatch(
            r"[0-9a-f]{64}",
            binding.account_projection_sha256,
        )
        is None
        or re.fullmatch(
            r"[0-9a-f]{64}",
            binding.api_key_projection_sha256,
        )
        is None
        or any(
            BOOTSTRAP_SAFE_ID_PATTERN.fullmatch(value) is None
            for value in (
                binding.management_account_id,
                binding.management_api_key_id,
                binding.listener_id,
            )
        )
        or binding.listener_name != "http"
        or binding.listener_bind != ("[::]:8080",)
        or binding.listener_protocol != "http"
        or binding.listener_use_tls is not False
        or binding.listener_tls_implicit is not False
        or binding.management_key_name != "stalwart-management-api-key"
        or type(binding.management_key_size) is not int
        or not 1 <= binding.management_key_size <= 4096
        or type(binding.management_key_identity) is not tuple
        or len(binding.management_key_identity) != 8
        or any(
            type(value) is not int
            or value < 0
            or value > MAXIMUM_IDENTITY_COMPONENT
            for value in binding.management_key_identity
        )
    ):
        raise MigrationError("bootstrap retirement binding is malformed")
    return {
        "receipt": _apply_file_metadata(receipt),
        "apply_receipt_sha256": binding.apply_receipt_sha256,
        "bootstrap_proof_sha256": binding.bootstrap_proof_sha256,
        "server_version": binding.server_version,
        "authentication_status": binding.authentication_status,
        "ip_restriction_decision": binding.ip_restriction_decision,
        "management": {
            "account_id": binding.management_account_id,
            "api_key_id": binding.management_api_key_id,
            "key_file": {
                "identity": list(binding.management_key_identity),
                "name": binding.management_key_name,
                "size": binding.management_key_size,
            },
        },
        "permissions_sha256": binding.permissions_sha256,
        "protected_accounts_sha256": binding.protected_accounts_sha256,
        "safe_objects_sha256": binding.safe_objects_sha256,
        "preserved_objects_sha256": binding.preserved_objects_sha256,
        "routing_proof_sha256": binding.routing_proof_sha256,
        "listener": {
            "id": binding.listener_id,
            "name": binding.listener_name,
            "bind": list(binding.listener_bind),
            "protocol": binding.listener_protocol,
            "use_tls": binding.listener_use_tls,
            "tls_implicit": binding.listener_tls_implicit,
        },
        "projections": {
            "account_sha256": binding.account_projection_sha256,
            "api_key_sha256": binding.api_key_projection_sha256,
        },
    }


def _retirement_attempt_payload(
    apply_plan: ApplyPlan,
    *,
    apply_receipt: FileSnapshot,
    apply_attempt: FileSnapshot,
    bootstrap_receipt: FileSnapshot,
    bootstrap: BootstrapRetirementBinding,
    runtime_metadata: dict[str, object],
    started_at: str,
) -> dict[str, object]:
    return {
        "schema": RETIRE_RECOVERY_ATTEMPT_SCHEMA,
        "started_at": started_at,
        "inputs": _apply_metadata(apply_plan.inputs),
        "artifacts": _apply_metadata(apply_plan.artifacts),
        "apply_attempt": _apply_file_metadata(_apply_file(apply_attempt)),
        "apply_receipt": _apply_file_metadata(_apply_file(apply_receipt)),
        "bootstrap": _bootstrap_retirement_metadata(
            _apply_file(bootstrap_receipt),
            bootstrap,
        ),
        "operation_plan": {
            "sha256": apply_plan.operations_sha256,
            "count": len(apply_plan.operations),
        },
        "runtime": _retirement_runtime_commitment(
            apply_plan.runtime,
            runtime_metadata,
        ),
    }


def _retirement_attempt_snapshot(paths: MigrationPaths) -> FileSnapshot:
    return _read_regular_snapshot(
        paths.retire_recovery_attempt,
        root=paths.repository_root,
        label="retirement attempt marker",
        maximum=64 * 1024,
        required_mode=0o600,
    )


def _validate_retirement_attempt_snapshot(
    snapshot: FileSnapshot,
    plan: RecoveryRetirementPlan,
    *,
    runtime_metadata: dict[str, object],
) -> dict[str, object]:
    if snapshot.path != plan.runtime.config_dir.parent / "retire-recovery-attempt.json":
        raise MigrationError("retirement attempt marker path is malformed")
    envelope = _parse_strict_json_snapshot(
        snapshot,
        label="retirement attempt marker",
    )
    payload = validate_digest_envelope(envelope)
    started_at = payload.get("started_at")
    expected = {
        "schema": RETIRE_RECOVERY_ATTEMPT_SCHEMA,
        "started_at": started_at,
        "inputs": _apply_metadata(plan.inputs),
        "artifacts": _apply_metadata(plan.artifacts),
        "apply_attempt": _apply_file_metadata(plan.apply_attempt),
        "apply_receipt": _apply_file_metadata(plan.apply_receipt),
        "bootstrap": _bootstrap_retirement_metadata(
            plan.bootstrap_receipt,
            plan.bootstrap,
        ),
        "operation_plan": {
            "sha256": plan.operation_plan_sha256,
            "count": plan.operation_count,
        },
        "runtime": _retirement_runtime_commitment(
            plan.runtime,
            runtime_metadata,
        ),
    }
    if (
        not isinstance(started_at, str)
        or re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",
            started_at,
        )
        is None
        or _canonical_json_bytes(payload) != _canonical_json_bytes(expected)
    ):
        raise MigrationError(
            "retirement attempt marker does not match fixed inputs",
        )
    return payload


def _recovery_retirement_plan(
    validated: _ValidatedApply,
    *,
    apply_receipt: FileSnapshot,
    apply_attempt: FileSnapshot,
    bootstrap_receipt: FileSnapshot,
    bootstrap: BootstrapRetirementBinding,
    retirement_attempt: FileSnapshot,
    runtime_metadata: dict[str, object],
) -> RecoveryRetirementPlan:
    committed = _validate_runtime_artifact_commitment(runtime_metadata)
    directory_identity = tuple(committed["config_directory_identity"])
    config = committed["config"]
    environment = committed["recovery_environment"]
    if not isinstance(config, dict) or not isinstance(environment, dict):
        raise MigrationError("retirement recovery artifact binding is malformed")
    config_binding = RecoveryArtifactBinding(
        path=validated.plan.runtime.config_dir / "config.json",
        size=config["size"],  # type: ignore[arg-type]
        identity=tuple(config["identity"]),  # type: ignore[arg-type]
    )
    environment_binding = RecoveryArtifactBinding(
        path=validated.plan.runtime.recovery_env_file,
        size=environment["size"],  # type: ignore[arg-type]
        identity=tuple(environment["identity"]),  # type: ignore[arg-type]
    )
    return RecoveryRetirementPlan(
        inputs=validated.plan.inputs,
        artifacts=validated.plan.artifacts,
        apply_receipt=_apply_file(apply_receipt),
        apply_attempt=_apply_file(apply_attempt),
        bootstrap_receipt=_apply_file(bootstrap_receipt),
        bootstrap=bootstrap,
        retirement_attempt=_apply_file(retirement_attempt),
        operation_plan_sha256=validated.plan.operations_sha256,
        operation_count=len(validated.plan.operations),
        runtime=validated.plan.runtime,
        source=validated.source,
        recovery_config_directory_identity=directory_identity,
        recovery_config=config_binding,
        recovery_environment=environment_binding,
    )


def _recovery_proof_metadata(
    proof: object,
    plan: RecoveryRetirementPlan,
) -> dict[str, object]:
    if (
        type(proof) is not RecoveryRetirementProof
        or type(proof.apply_receipt_sha256) is not str
        or re.fullmatch(r"[0-9a-f]{64}", proof.apply_receipt_sha256) is None
        or not secrets.compare_digest(
            proof.apply_receipt_sha256,
            plan.apply_receipt.sha256,
        )
        or type(proof.bootstrap_receipt_sha256) is not str
        or not secrets.compare_digest(
            proof.bootstrap_receipt_sha256,
            plan.bootstrap_receipt.sha256,
        )
        or type(proof.bootstrap_proof_sha256) is not str
        or not secrets.compare_digest(
            proof.bootstrap_proof_sha256,
            plan.bootstrap.bootstrap_proof_sha256,
        )
        or proof.management_account_id
        != plan.bootstrap.management_account_id
        or proof.management_api_key_id
        != plan.bootstrap.management_api_key_id
        or type(proof.ip_restriction_decision) is not str
        or proof.ip_restriction_decision
        != plan.bootstrap.ip_restriction_decision
        or proof.ip_restriction_decision
        != BOOTSTRAP_IP_RESTRICTION_DECISION
        or type(proof.permissions_sha256) is not str
        or not secrets.compare_digest(
            proof.permissions_sha256,
            plan.bootstrap.permissions_sha256,
        )
        or type(proof.protected_accounts_sha256) is not str
        or not secrets.compare_digest(
            proof.protected_accounts_sha256,
            plan.bootstrap.protected_accounts_sha256,
        )
        or type(proof.preserved_objects_sha256) is not str
        or not secrets.compare_digest(
            proof.preserved_objects_sha256,
            plan.bootstrap.preserved_objects_sha256,
        )
        or type(proof.safe_objects_sha256) is not str
        or not secrets.compare_digest(
            proof.safe_objects_sha256,
            plan.bootstrap.safe_objects_sha256,
        )
        or type(proof.routing_proof_sha256) is not str
        or not secrets.compare_digest(
            proof.routing_proof_sha256,
            plan.bootstrap.routing_proof_sha256,
        )
        or proof.listener_id != plan.bootstrap.listener_id
        or type(proof.account_projection_sha256) is not str
        or not secrets.compare_digest(
            proof.account_projection_sha256,
            plan.bootstrap.account_projection_sha256,
        )
        or type(proof.api_key_projection_sha256) is not str
        or not secrets.compare_digest(
            proof.api_key_projection_sha256,
            plan.bootstrap.api_key_projection_sha256,
        )
        or type(proof.retirement_attempt_sha256) is not str
        or re.fullmatch(
            r"[0-9a-f]{64}",
            proof.retirement_attempt_sha256,
        )
        is None
        or not secrets.compare_digest(
            proof.retirement_attempt_sha256,
            plan.retirement_attempt.sha256,
        )
        or type(proof.operation_plan_sha256) is not str
        or re.fullmatch(r"[0-9a-f]{64}", proof.operation_plan_sha256) is None
        or not secrets.compare_digest(
            proof.operation_plan_sha256,
            plan.operation_plan_sha256,
        )
        or proof.server_version != "0.16.17"
        or type(proof.management_status) is not int
        or proof.management_status != 200
        or type(proof.readiness_status) is not int
        or proof.readiness_status != 200
        or type(proof.old_recovery_auth_status) is not int
        or proof.old_recovery_auth_status not in {401, 403}
        or proof.normal_url != "http://127.0.0.1:8443"
        or proof.image_reference != STALWART_IMAGE
        or proof.image_id != STALWART_IMAGE_ID
        or type(proof.container_id) is not str
        or re.fullmatch(r"[0-9a-f]{64}", proof.container_id) is None
        or type(proof.overlapping_writer_ids) is not tuple
        or proof.overlapping_writer_ids != (proof.container_id,)
        or type(proof.migration_container_ids) is not tuple
        or proof.migration_container_ids
        or type(proof.recovery_environment_names) is not tuple
        or proof.recovery_environment_names
    ):
        raise MigrationError(
            "recovery retirement proof does not match the fixed runtime",
        )
    return {
        "apply_receipt_sha256": proof.apply_receipt_sha256,
        "bootstrap_receipt_sha256": proof.bootstrap_receipt_sha256,
        "bootstrap_proof_sha256": proof.bootstrap_proof_sha256,
        "management_account_id": proof.management_account_id,
        "management_api_key_id": proof.management_api_key_id,
        "ip_restriction_decision": proof.ip_restriction_decision,
        "permissions_sha256": proof.permissions_sha256,
        "protected_accounts_sha256": proof.protected_accounts_sha256,
        "safe_objects_sha256": proof.safe_objects_sha256,
        "preserved_objects_sha256": proof.preserved_objects_sha256,
        "routing_proof_sha256": proof.routing_proof_sha256,
        "listener_id": proof.listener_id,
        "account_projection_sha256": proof.account_projection_sha256,
        "api_key_projection_sha256": proof.api_key_projection_sha256,
        "retirement_attempt_sha256": proof.retirement_attempt_sha256,
        "operation_plan_sha256": proof.operation_plan_sha256,
        "server_version": proof.server_version,
        "management_status": proof.management_status,
        "readiness_status": proof.readiness_status,
        "old_recovery_auth_status": proof.old_recovery_auth_status,
        "normal_url": proof.normal_url,
        "image_reference": proof.image_reference,
        "image_id": proof.image_id,
        "container_id": proof.container_id,
        "overlapping_writer_ids": list(proof.overlapping_writer_ids),
        "migration_container_ids": list(proof.migration_container_ids),
        "recovery_environment_names": list(
            proof.recovery_environment_names,
        ),
    }


def _proof_from_metadata(value: object) -> RecoveryRetirementProof:
    if not isinstance(value, dict):
        raise MigrationError("recovery retirement proof is malformed")
    expected = {
        "apply_receipt_sha256",
        "bootstrap_receipt_sha256",
        "bootstrap_proof_sha256",
        "management_account_id",
        "management_api_key_id",
        "ip_restriction_decision",
        "permissions_sha256",
        "protected_accounts_sha256",
        "safe_objects_sha256",
        "preserved_objects_sha256",
        "routing_proof_sha256",
        "listener_id",
        "account_projection_sha256",
        "api_key_projection_sha256",
        "retirement_attempt_sha256",
        "operation_plan_sha256",
        "server_version",
        "management_status",
        "readiness_status",
        "old_recovery_auth_status",
        "normal_url",
        "image_reference",
        "image_id",
        "container_id",
        "overlapping_writer_ids",
        "migration_container_ids",
        "recovery_environment_names",
    }
    if set(value) != expected:
        raise MigrationError("recovery retirement proof is malformed")
    for name in (
        "overlapping_writer_ids",
        "migration_container_ids",
        "recovery_environment_names",
    ):
        items = value.get(name)
        if not isinstance(items, list) or any(
            not isinstance(item, str) for item in items
        ):
            raise MigrationError("recovery retirement proof is malformed")
    return RecoveryRetirementProof(
        apply_receipt_sha256=value.get("apply_receipt_sha256"),  # type: ignore[arg-type]
        bootstrap_receipt_sha256=value.get("bootstrap_receipt_sha256"),  # type: ignore[arg-type]
        bootstrap_proof_sha256=value.get("bootstrap_proof_sha256"),  # type: ignore[arg-type]
        management_account_id=value.get("management_account_id"),  # type: ignore[arg-type]
        management_api_key_id=value.get("management_api_key_id"),  # type: ignore[arg-type]
        ip_restriction_decision=value.get("ip_restriction_decision"),  # type: ignore[arg-type]
        permissions_sha256=value.get("permissions_sha256"),  # type: ignore[arg-type]
        protected_accounts_sha256=value.get("protected_accounts_sha256"),  # type: ignore[arg-type]
        safe_objects_sha256=value.get("safe_objects_sha256"),  # type: ignore[arg-type]
        preserved_objects_sha256=value.get("preserved_objects_sha256"),  # type: ignore[arg-type]
        routing_proof_sha256=value.get("routing_proof_sha256"),  # type: ignore[arg-type]
        listener_id=value.get("listener_id"),  # type: ignore[arg-type]
        account_projection_sha256=value.get("account_projection_sha256"),  # type: ignore[arg-type]
        api_key_projection_sha256=value.get("api_key_projection_sha256"),  # type: ignore[arg-type]
        retirement_attempt_sha256=value.get("retirement_attempt_sha256"),  # type: ignore[arg-type]
        operation_plan_sha256=value.get("operation_plan_sha256"),  # type: ignore[arg-type]
        server_version=value.get("server_version"),  # type: ignore[arg-type]
        management_status=value.get("management_status"),  # type: ignore[arg-type]
        readiness_status=value.get("readiness_status"),  # type: ignore[arg-type]
        old_recovery_auth_status=value.get("old_recovery_auth_status"),  # type: ignore[arg-type]
        normal_url=value.get("normal_url"),  # type: ignore[arg-type]
        image_reference=value.get("image_reference"),  # type: ignore[arg-type]
        image_id=value.get("image_id"),  # type: ignore[arg-type]
        container_id=value.get("container_id"),  # type: ignore[arg-type]
        overlapping_writer_ids=tuple(value["overlapping_writer_ids"]),
        migration_container_ids=tuple(value["migration_container_ids"]),
        recovery_environment_names=tuple(
            value["recovery_environment_names"],
        ),
    )


def _retirement_proof_snapshot(paths: MigrationPaths) -> FileSnapshot:
    return _read_regular_snapshot(
        paths.retire_recovery_proof,
        root=paths.repository_root,
        label="retirement proof checkpoint",
        maximum=64 * 1024,
        required_mode=0o600,
    )


def _validate_retirement_proof_snapshot(
    snapshot: FileSnapshot,
    plan: RecoveryRetirementPlan,
) -> RecoveryRetirementProof:
    if snapshot.path != plan.runtime.config_dir.parent / "retire-recovery-proof.json":
        raise MigrationError("retirement proof checkpoint path is malformed")
    payload = _parse_strict_json_snapshot(
        snapshot,
        label="retirement proof checkpoint",
    )
    if set(payload) != {"bootstrap", "schema", "proof"} or payload.get(
        "schema",
    ) != RETIRE_RECOVERY_PROOF_SCHEMA:
        raise MigrationError("retirement proof checkpoint is malformed")
    if payload.get("bootstrap") != _bootstrap_retirement_metadata(
        plan.bootstrap_receipt,
        plan.bootstrap,
    ):
        raise MigrationError("retirement proof bootstrap binding is malformed")
    proof = _proof_from_metadata(payload.get("proof"))
    _recovery_proof_metadata(proof, plan)
    return proof


def _load_recovery_credential_lease(
    paths: MigrationPaths,
    runtime: MigrationRuntimePaths,
    expected: _RuntimeEnvironmentFile,
) -> RecoveryCredentialLease:
    if (
        type(expected) is not _RuntimeEnvironmentFile
        or expected.path != runtime.recovery_env_file
    ):
        raise MigrationError("recovery environment snapshot is malformed")
    buffer, digest, size, identity = _read_regular_mutable(
        runtime.recovery_env_file,
        root=paths.repository_root,
        label="migration recovery environment file",
        maximum=64 * 1024,
        required_mode=0o600,
    )
    credential = bytearray()
    try:
        _validate_recovery_environment_buffer(buffer)
        if (
            not secrets.compare_digest(digest, expected.sha256)
            or size != expected.size
            or identity != expected.identity
        ):
            raise MigrationError(
                "migration recovery environment file changed before dispatch",
            )
        content_end = len(buffer)
        if content_end and buffer[content_end - 1] == 0x0A:
            content_end -= 1
        credential = bytearray(content_end - len(RECOVERY_ENV_PREFIX))
        source_view = memoryview(buffer)[len(RECOVERY_ENV_PREFIX) : content_end]
        target_view = memoryview(credential)
        try:
            target_view[:] = source_view
        finally:
            target_view.release()
            source_view.release()
        return RecoveryCredentialLease(credential)
    except BaseException:
        _wipe_bytearray(credential)
        raise
    finally:
        _wipe_bytearray(buffer)


def _validate_recovery_artifact_binding(
    value: object,
    *,
    path: Path,
    label: str,
) -> RecoveryArtifactBinding:
    if (
        type(value) is not RecoveryArtifactBinding
        or value.path != path
        or type(value.size) is not int
        or value.size < 0
        or type(value.identity) is not tuple
        or len(value.identity) != 6
        or any(type(item) is not int or item < 0 for item in value.identity)
    ):
        raise MigrationError(f"{label} identity binding is malformed")
    return value


def _resume_checkpointed_recovery_artifact_deletion(
    paths: MigrationPaths,
    plan: RecoveryRetirementPlan,
    config: RecoveryArtifactBinding,
    *,
    state: tuple[bool, bool, bool],
) -> None:
    """Resume only the exact durable suffix of environment/config deletion."""
    if state not in {
        (False, True, True),
        (False, True, False),
        (False, False, False),
    }:
        raise MigrationError(
            "checkpointed recovery artifact state is malformed",
        )
    root_before = _require_real_directory(
        paths.migration_root,
        "migration root",
    )
    root_descriptor = -1
    config_directory_descriptor = -1
    config_descriptor = -1
    primary_in_flight = False

    def optional_stat(name: str, *, directory: int) -> os.stat_result | None:
        try:
            return os.stat(
                name,
                dir_fd=directory,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return None

    try:
        try:
            root_descriptor = os.open(
                paths.migration_root,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
            )
            root_opened = os.fstat(root_descriptor)
            if (
                not stat.S_ISDIR(root_opened.st_mode)
                or root_opened.st_dev != root_before.st_dev
                or root_opened.st_ino != root_before.st_ino
            ):
                raise MigrationError(
                    "migration root identity changed before recovery deletion",
                )
            if optional_stat(
                plan.runtime.recovery_env_file.name,
                directory=root_descriptor,
            ) is not None:
                raise MigrationError(
                    "deleted recovery environment was substituted",
                )
            config_directory_named = optional_stat(
                plan.runtime.config_dir.name,
                directory=root_descriptor,
            )
            if state == (False, False, False):
                if config_directory_named is not None:
                    raise MigrationError(
                        "deleted recovery config directory was substituted",
                    )
                return
            if (
                config_directory_named is None
                or not stat.S_ISDIR(config_directory_named.st_mode)
                or (
                    _file_identity(config_directory_named)
                    != plan.recovery_config_directory_identity
                    if state == (False, True, True)
                    else _file_identity(config_directory_named)[:3]
                    != plan.recovery_config_directory_identity[:3]
                )
            ):
                raise MigrationError(
                    "recovery config directory identity changed before deletion",
                )
            config_directory_descriptor = os.open(
                plan.runtime.config_dir.name,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=root_descriptor,
            )
            config_directory_opened = os.fstat(
                config_directory_descriptor,
            )
            expected_names = (
                {config.path.name}
                if state == (False, True, True)
                else set()
            )
            if (
                (
                    _file_identity(config_directory_opened)
                    != plan.recovery_config_directory_identity
                    if state == (False, True, True)
                    else _file_identity(config_directory_opened)[:3]
                    != plan.recovery_config_directory_identity[:3]
                )
                or set(os.listdir(config_directory_descriptor))
                != expected_names
            ):
                raise MigrationError(
                    "recovery config directory changed during deletion",
                )
            if state == (False, True, True):
                config_descriptor = os.open(
                    config.path.name,
                    os.O_RDONLY
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0),
                    dir_fd=config_directory_descriptor,
                )
                config_opened = os.fstat(config_descriptor)
                config_named = os.stat(
                    config.path.name,
                    dir_fd=config_directory_descriptor,
                    follow_symlinks=False,
                )
                if (
                    not stat.S_ISREG(config_opened.st_mode)
                    or config_opened.st_nlink != 1
                    or config_opened.st_size != config.size
                    or _file_identity(config_opened) != config.identity
                    or _file_identity(config_named) != config.identity
                ):
                    raise MigrationError(
                        "recovery config identity changed before deletion",
                    )
                if optional_stat(
                    plan.runtime.recovery_env_file.name,
                    directory=root_descriptor,
                ) is not None:
                    raise MigrationError(
                        "deleted recovery environment was substituted",
                    )
                os.unlink(
                    config.path.name,
                    dir_fd=config_directory_descriptor,
                )
                os.fsync(config_directory_descriptor)
            if os.listdir(config_directory_descriptor):
                raise MigrationError(
                    "recovery config directory is not empty after deletion",
                )
            config_directory_after = os.stat(
                plan.runtime.config_dir.name,
                dir_fd=root_descriptor,
                follow_symlinks=False,
            )
            if (
                _file_identity(config_directory_after)[:3]
                != plan.recovery_config_directory_identity[:3]
                or _file_identity(os.fstat(config_directory_descriptor))[:3]
                != plan.recovery_config_directory_identity[:3]
            ):
                raise MigrationError(
                    "recovery config directory changed during deletion",
                )
            os.rmdir(
                plan.runtime.config_dir.name,
                dir_fd=root_descriptor,
            )
            os.fsync(root_descriptor)
            if (
                optional_stat(
                    plan.runtime.recovery_env_file.name,
                    directory=root_descriptor,
                )
                is not None
                or optional_stat(
                    plan.runtime.config_dir.name,
                    directory=root_descriptor,
                )
                is not None
            ):
                raise MigrationError(
                    "recovery artifacts remain after resumed deletion",
                )
        except BaseException:
            primary_in_flight = True
            raise
    except (MigrationError, KeyboardInterrupt, SystemExit):
        raise
    except OSError:
        raise MigrationError(
            "recovery artifact deletion failed safely",
        ) from None
    finally:
        cleanup_error: BaseException | None = None
        for descriptor in (
            config_descriptor,
            config_directory_descriptor,
            root_descriptor,
        ):
            if descriptor < 0:
                continue
            try:
                os.close(descriptor)
            except BaseException as exc:
                if cleanup_error is None:
                    cleanup_error = exc
        if not primary_in_flight and cleanup_error is not None:
            if isinstance(cleanup_error, Exception):
                raise MigrationError(
                    "recovery artifact descriptor cleanup failed safely",
                ) from None
            raise cleanup_error


def _delete_bound_recovery_artifacts(
    paths: MigrationPaths,
    plan: RecoveryRetirementPlan,
) -> None:
    """Delete only checkpoint-bound recovery artifacts with durable ordering."""
    if (
        not isinstance(paths, MigrationPaths)
        or paths != MigrationPaths.for_repository(paths.repository_root)
        or type(plan) is not RecoveryRetirementPlan
        or plan.runtime.config_dir
        != paths.migration_root / "recovery-config"
        or plan.runtime.recovery_env_file
        != paths.migration_root / "recovery.env"
    ):
        raise MigrationError("recovery artifact deletion plan is malformed")
    environment = _validate_recovery_artifact_binding(
        plan.recovery_environment,
        path=plan.runtime.recovery_env_file,
        label="recovery environment",
    )
    config = _validate_recovery_artifact_binding(
        plan.recovery_config,
        path=plan.runtime.config_dir / "config.json",
        label="recovery config",
    )
    if (
        type(plan.recovery_config_directory_identity) is not tuple
        or len(plan.recovery_config_directory_identity) != 6
        or any(
            type(item) is not int or item < 0
            for item in plan.recovery_config_directory_identity
        )
    ):
        raise MigrationError(
            "recovery config directory identity binding is malformed",
        )
    try:
        proof_snapshot = _retirement_proof_snapshot(paths)
        _validate_retirement_proof_snapshot(proof_snapshot, plan)
    except MigrationError:
        raise MigrationError(
            "valid recovery retirement proof checkpoint is required before deletion",
        ) from None

    _require_owner_migration_root(paths)
    root_before = _require_real_directory(
        paths.migration_root,
        "migration root",
    )
    artifact_state = (
        _path_present(plan.runtime.recovery_env_file),
        _path_present(plan.runtime.config_dir),
        _path_present(config.path),
    )
    if artifact_state != (True, True, True):
        _resume_checkpointed_recovery_artifact_deletion(
            paths,
            plan,
            config,
            state=artifact_state,
        )
        return
    root_descriptor = -1
    environment_descriptor = -1
    config_directory_descriptor = -1
    config_descriptor = -1
    primary_in_flight = False
    try:
        try:
            root_descriptor = os.open(
                paths.migration_root,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
            )
            root_opened = os.fstat(root_descriptor)
            if (
                not stat.S_ISDIR(root_opened.st_mode)
                or root_opened.st_dev != root_before.st_dev
                or root_opened.st_ino != root_before.st_ino
            ):
                raise MigrationError(
                    "migration root identity changed before recovery deletion",
                )

            environment_descriptor = os.open(
                environment.path.name,
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=root_descriptor,
            )
            environment_opened = os.fstat(environment_descriptor)
            environment_named = os.stat(
                environment.path.name,
                dir_fd=root_descriptor,
                follow_symlinks=False,
            )
            if (
                not stat.S_ISREG(environment_opened.st_mode)
                or environment_opened.st_nlink != 1
                or environment_opened.st_size != environment.size
                or _file_identity(environment_opened)
                != environment.identity
                or _file_identity(environment_named)
                != environment.identity
            ):
                raise MigrationError(
                    "recovery environment identity changed before deletion",
                )
            config_directory_named = os.stat(
                plan.runtime.config_dir.name,
                dir_fd=root_descriptor,
                follow_symlinks=False,
            )
            if (
                not stat.S_ISDIR(config_directory_named.st_mode)
                or _file_identity(config_directory_named)
                != plan.recovery_config_directory_identity
            ):
                raise MigrationError(
                    "recovery config directory identity changed before deletion",
                )
            config_directory_descriptor = os.open(
                plan.runtime.config_dir.name,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=root_descriptor,
            )
            config_directory_opened = os.fstat(
                config_directory_descriptor,
            )
            if (
                _file_identity(config_directory_opened)
                != plan.recovery_config_directory_identity
                or set(os.listdir(config_directory_descriptor))
                != {config.path.name}
            ):
                raise MigrationError(
                    "recovery config directory identity changed before deletion",
                )
            config_descriptor = os.open(
                config.path.name,
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=config_directory_descriptor,
            )
            config_opened = os.fstat(config_descriptor)
            config_named = os.stat(
                config.path.name,
                dir_fd=config_directory_descriptor,
                follow_symlinks=False,
            )
            if (
                not stat.S_ISREG(config_opened.st_mode)
                or config_opened.st_nlink != 1
                or config_opened.st_size != config.size
                or _file_identity(config_opened) != config.identity
                or _file_identity(config_named) != config.identity
            ):
                raise MigrationError(
                    "recovery config identity changed before deletion",
                )
            environment_named_before_unlink = os.stat(
                environment.path.name,
                dir_fd=root_descriptor,
                follow_symlinks=False,
            )
            config_named_before_unlink = os.stat(
                config.path.name,
                dir_fd=config_directory_descriptor,
                follow_symlinks=False,
            )
            if (
                _file_identity(environment_named_before_unlink)
                != environment.identity
                or _file_identity(config_named_before_unlink)
                != config.identity
            ):
                raise MigrationError(
                    "recovery artifact identity changed before deletion",
                )
            os.unlink(
                environment.path.name,
                dir_fd=root_descriptor,
            )
            os.fsync(root_descriptor)
            config_directory_opened_after_environment = os.fstat(
                config_directory_descriptor,
            )
            config_directory_named_after_environment = os.stat(
                plan.runtime.config_dir.name,
                dir_fd=root_descriptor,
                follow_symlinks=False,
            )
            config_opened_after_environment = os.fstat(
                config_descriptor,
            )
            config_named_after_environment = os.stat(
                config.path.name,
                dir_fd=config_directory_descriptor,
                follow_symlinks=False,
            )
            if (
                _file_identity(config_directory_opened_after_environment)
                != plan.recovery_config_directory_identity
                or _file_identity(config_directory_named_after_environment)
                != plan.recovery_config_directory_identity
                or set(os.listdir(config_directory_descriptor))
                != {config.path.name}
                or not stat.S_ISREG(
                    config_opened_after_environment.st_mode,
                )
                or config_opened_after_environment.st_nlink != 1
                or config_opened_after_environment.st_size != config.size
                or _file_identity(config_opened_after_environment)
                != config.identity
                or _file_identity(config_named_after_environment)
                != config.identity
            ):
                raise MigrationError(
                    "recovery config identity changed after environment deletion",
                )
            os.unlink(
                config.path.name,
                dir_fd=config_directory_descriptor,
            )
            os.fsync(config_directory_descriptor)
            if os.listdir(config_directory_descriptor):
                raise MigrationError(
                    "recovery config directory is not empty after deletion",
                )
            config_directory_after = os.stat(
                plan.runtime.config_dir.name,
                dir_fd=root_descriptor,
                follow_symlinks=False,
            )
            if (
                config_directory_after.st_dev
                != config_directory_opened.st_dev
                or config_directory_after.st_ino
                != config_directory_opened.st_ino
            ):
                raise MigrationError(
                    "recovery config directory changed during deletion",
                )
            os.rmdir(
                plan.runtime.config_dir.name,
                dir_fd=root_descriptor,
            )
            os.fsync(root_descriptor)
        except BaseException:
            primary_in_flight = True
            raise
    except (MigrationError, KeyboardInterrupt, SystemExit):
        raise
    except OSError:
        raise MigrationError(
            "recovery artifact deletion failed safely",
        ) from None
    finally:
        cleanup_error: BaseException | None = None
        for descriptor in (
            config_descriptor,
            config_directory_descriptor,
            environment_descriptor,
            root_descriptor,
        ):
            if descriptor < 0:
                continue
            try:
                os.close(descriptor)
            except BaseException as exc:
                if cleanup_error is None:
                    cleanup_error = exc
        if not primary_in_flight and cleanup_error is not None:
            if isinstance(cleanup_error, Exception):
                raise MigrationError(
                    "recovery artifact descriptor cleanup failed safely",
                ) from None
            raise cleanup_error


def _retired_receipt_payload(
    plan: RecoveryRetirementPlan,
    *,
    proof_snapshot: FileSnapshot,
    proof: RecoveryRetirementProof,
    retired_at: str,
) -> dict[str, object]:
    return {
        "schema": RECOVERY_RETIRED_SCHEMA,
        "retired_at": retired_at,
        "apply_attempt": _apply_file_metadata(plan.apply_attempt),
        "apply_receipt": _apply_file_metadata(plan.apply_receipt),
        "bootstrap": _bootstrap_retirement_metadata(
            plan.bootstrap_receipt,
            plan.bootstrap,
        ),
        "retirement_attempt": _apply_file_metadata(
            plan.retirement_attempt,
        ),
        "retirement_proof": _apply_file_metadata(
            _apply_file(proof_snapshot),
        ),
        "operation_plan": {
            "sha256": plan.operation_plan_sha256,
            "count": plan.operation_count,
        },
        "proof": _recovery_proof_metadata(proof, plan),
    }


def _validate_retired_receipt_payload(
    value: object,
    plan: RecoveryRetirementPlan,
    *,
    proof_snapshot: FileSnapshot,
    proof: RecoveryRetirementProof,
) -> dict[str, object]:
    if not isinstance(value, dict):
        raise MigrationError("recovery-retired receipt is malformed")
    retired_at = value.get("retired_at")
    expected = _retired_receipt_payload(
        plan,
        proof_snapshot=proof_snapshot,
        proof=proof,
        retired_at=retired_at,  # type: ignore[arg-type]
    )
    if (
        not isinstance(retired_at, str)
        or re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",
            retired_at,
        )
        is None
        or _canonical_json_bytes(value) != _canonical_json_bytes(expected)
    ):
        raise MigrationError(
            "recovery-retired receipt does not match fixed state",
        )
    return value


def _finalize_recovery_retirement(
    paths: MigrationPaths,
    *,
    source_receipt_path: Path,
    script_path: Path,
    dry_run_receipt_path: Path,
    review_receipt_path: Path,
    apply_receipt_path: Path,
    runner: object,
    python_executable: str,
    postflight_verifier: object,
    bootstrap_receipt_validator: object,
    clock: object | None,
    expected_script_sha256: str,
    expected_executor_proof: RecoveryRetirementProof | None = None,
) -> Path:
    if not callable(postflight_verifier):
        raise MigrationError("recovery retirement postflight verifier is unavailable")
    before = _validated_retirement_state(
        paths,
        source_receipt_path=source_receipt_path,
        script_path=script_path,
        dry_run_receipt_path=dry_run_receipt_path,
        review_receipt_path=review_receipt_path,
        apply_receipt_path=apply_receipt_path,
        runner=runner,
        python_executable=python_executable,
        expected_script_sha256=expected_script_sha256,
        runtime_phase="retired",
        writer_census=False,
        bootstrap_receipt_validator=bootstrap_receipt_validator,
    )
    (
        validated_before,
        apply_receipt_before,
        apply_attempt_before,
        _apply_payload_before,
        runtime_metadata_before,
        bootstrap_receipt_before,
        bootstrap_before,
    ) = before
    retirement_attempt_before = _retirement_attempt_snapshot(paths)
    plan_before = _recovery_retirement_plan(
        validated_before,
        apply_receipt=apply_receipt_before,
        apply_attempt=apply_attempt_before,
        bootstrap_receipt=bootstrap_receipt_before,
        bootstrap=bootstrap_before,
        retirement_attempt=retirement_attempt_before,
        runtime_metadata=runtime_metadata_before,
    )
    _validate_retirement_attempt_snapshot(
        retirement_attempt_before,
        plan_before,
        runtime_metadata=runtime_metadata_before,
    )
    proof_snapshot_before = _retirement_proof_snapshot(paths)
    checkpoint_proof = _validate_retirement_proof_snapshot(
        proof_snapshot_before,
        plan_before,
    )
    if expected_executor_proof is not None:
        _recovery_proof_metadata(expected_executor_proof, plan_before)
        if expected_executor_proof != checkpoint_proof:
            raise MigrationError(
                "executor proof does not match the durable checkpoint",
            )

    verifier_failed = False
    verifier_proof: object = None
    try:
        verifier_proof = postflight_verifier(plan_before)
    except Exception:
        verifier_failed = True
    if verifier_failed:
        raise MigrationError(
            "recovery retirement postflight verifier failed; "
            "reconciliation is required",
        ) from None
    _recovery_proof_metadata(verifier_proof, plan_before)
    if verifier_proof != checkpoint_proof:
        raise MigrationError(
            "postflight proof does not match the durable checkpoint",
        )

    retired_at = _retirement_timestamp(clock)
    after = _validated_retirement_state(
        paths,
        source_receipt_path=source_receipt_path,
        script_path=script_path,
        dry_run_receipt_path=dry_run_receipt_path,
        review_receipt_path=review_receipt_path,
        apply_receipt_path=apply_receipt_path,
        runner=runner,
        python_executable=python_executable,
        expected_script_sha256=expected_script_sha256,
        runtime_phase="retired",
        writer_census=False,
        bootstrap_receipt_validator=bootstrap_receipt_validator,
    )
    (
        validated_after,
        apply_receipt_after,
        apply_attempt_after,
        _apply_payload_after,
        runtime_metadata_after,
        bootstrap_receipt_after,
        bootstrap_after,
    ) = after
    retirement_attempt_after = _retirement_attempt_snapshot(paths)
    proof_snapshot_after = _retirement_proof_snapshot(paths)
    plan_after = _recovery_retirement_plan(
        validated_after,
        apply_receipt=apply_receipt_after,
        apply_attempt=apply_attempt_after,
        bootstrap_receipt=bootstrap_receipt_after,
        bootstrap=bootstrap_after,
        retirement_attempt=retirement_attempt_after,
        runtime_metadata=runtime_metadata_after,
    )
    _validate_retirement_attempt_snapshot(
        retirement_attempt_after,
        plan_after,
        runtime_metadata=runtime_metadata_after,
    )
    checkpoint_proof_after = _validate_retirement_proof_snapshot(
        proof_snapshot_after,
        plan_after,
    )
    if (
        plan_before != plan_after
        or runtime_metadata_before != runtime_metadata_after
        or retirement_attempt_before != retirement_attempt_after
        or proof_snapshot_before != proof_snapshot_after
        or checkpoint_proof != checkpoint_proof_after
    ):
        raise MigrationError(
            "recovery retirement state changed during postflight verification",
        )
    if _path_present(paths.recovery_retired_receipt):
        raise MigrationError(
            "recovery-retired receipt already exists; refusing to overwrite",
        )
    payload = _retired_receipt_payload(
        plan_after,
        proof_snapshot=proof_snapshot_after,
        proof=checkpoint_proof_after,
        retired_at=retired_at,
    )
    _validate_retired_receipt_payload(
        payload,
        plan_after,
        proof_snapshot=proof_snapshot_after,
        proof=checkpoint_proof_after,
    )
    _write_new_json_0600(
        paths.recovery_retired_receipt,
        payload,
        root=paths.repository_root,
    )
    return paths.recovery_retired_receipt


def prepare_recovery_retirement(
    paths: MigrationPaths,
    *,
    source_receipt_path: Path,
    script_path: Path,
    dry_run_receipt_path: Path,
    review_receipt_path: Path,
    apply_receipt_path: Path,
    runner: object = run_command,
    python_executable: str,
    executor: object,
    postflight_verifier: object,
    bootstrap_receipt_validator: object,
    clock: object | None = None,
    expected_script_sha256: str = MIGRATION_SCRIPT_SHA256,
) -> Path:
    """Retire the one-use recovery handoff through a durable proof checkpoint.

    A durable attempt without a proof is intentionally not replayable. A
    durable proof without the final receipt resumes only the secret-free
    postflight path; it never invokes the executor or reads the credential.
    """
    _require_fixed_retirement_paths(
        paths,
        source_receipt_path=source_receipt_path,
        script_path=script_path,
        dry_run_receipt_path=dry_run_receipt_path,
        review_receipt_path=review_receipt_path,
        apply_receipt_path=apply_receipt_path,
    )
    attempt_exists, proof_exists, receipt_exists = _retirement_file_state(paths)
    if receipt_exists:
        if not attempt_exists or not proof_exists:
            raise MigrationError(
                "recovery retirement receipt is incomplete; reconciliation is required",
            )
        validate_recovery_retired_receipt(
            paths,
            paths.recovery_retired_receipt,
            source_receipt_path=source_receipt_path,
            script_path=script_path,
            dry_run_receipt_path=dry_run_receipt_path,
            review_receipt_path=review_receipt_path,
            apply_receipt_path=apply_receipt_path,
            runner=runner,
            bootstrap_receipt_validator=bootstrap_receipt_validator,
            python_executable=python_executable,
            expected_script_sha256=expected_script_sha256,
        )
        return paths.recovery_retired_receipt
    if proof_exists and not attempt_exists:
        raise MigrationError(
            "retirement proof exists without its attempt; reconciliation is required",
        )
    if attempt_exists and not proof_exists:
        raise MigrationError(
            "retirement attempt has no proof; manual reconciliation is required",
        )
    if attempt_exists:
        plan = _load_existing_retirement_recovery_plan(
            paths,
            bootstrap_receipt_validator=bootstrap_receipt_validator,
            state_runner=runner,
            python_executable=python_executable,
            expected_script_sha256=expected_script_sha256,
        )
        if plan is None:
            raise MigrationError(
                "durable retirement recovery plan is unavailable",
            )
        checkpoint_proof = _validate_retirement_proof_snapshot(
            _retirement_proof_snapshot(paths),
            plan,
        )
        _delete_bound_recovery_artifacts(paths, plan)
        return _finalize_recovery_retirement(
            paths,
            source_receipt_path=source_receipt_path,
            script_path=script_path,
            dry_run_receipt_path=dry_run_receipt_path,
            review_receipt_path=review_receipt_path,
            apply_receipt_path=apply_receipt_path,
            runner=runner,
            python_executable=python_executable,
            postflight_verifier=postflight_verifier,
            bootstrap_receipt_validator=bootstrap_receipt_validator,
            clock=clock,
            expected_script_sha256=expected_script_sha256,
            expected_executor_proof=checkpoint_proof,
        )
    if not callable(executor):
        raise MigrationError("recovery retirement executor is unavailable")
    if not callable(postflight_verifier):
        raise MigrationError("recovery retirement postflight verifier is unavailable")

    started_at = _retirement_timestamp(clock)
    preflight = _validated_retirement_state(
        paths,
        source_receipt_path=source_receipt_path,
        script_path=script_path,
        dry_run_receipt_path=dry_run_receipt_path,
        review_receipt_path=review_receipt_path,
        apply_receipt_path=apply_receipt_path,
        runner=runner,
        python_executable=python_executable,
        expected_script_sha256=expected_script_sha256,
        runtime_phase="ready",
        writer_census=True,
        bootstrap_receipt_validator=bootstrap_receipt_validator,
    )
    (
        validated,
        apply_receipt,
        apply_attempt,
        _apply_payload,
        runtime_metadata,
        bootstrap_receipt,
        bootstrap,
    ) = preflight
    if validated.runtime_artifacts is None:
        raise MigrationError("active recovery artifacts are unavailable")

    def dispatch(lease: RecoveryCredentialLease) -> object:
        attempt_payload = _retirement_attempt_payload(
            validated.plan,
            apply_receipt=apply_receipt,
            apply_attempt=apply_attempt,
            bootstrap_receipt=bootstrap_receipt,
            bootstrap=bootstrap,
            runtime_metadata=runtime_metadata,
            started_at=started_at,
        )
        _write_new_json_0600(
            paths.retire_recovery_attempt,
            _digest_envelope(attempt_payload),
            root=paths.repository_root,
            preserve_published_on_failure=True,
        )
        retirement_attempt = _retirement_attempt_snapshot(paths)
        plan = _recovery_retirement_plan(
            validated,
            apply_receipt=apply_receipt,
            apply_attempt=apply_attempt,
            bootstrap_receipt=bootstrap_receipt,
            bootstrap=bootstrap,
            retirement_attempt=retirement_attempt,
            runtime_metadata=runtime_metadata,
        )
        _validate_retirement_attempt_snapshot(
            retirement_attempt,
            plan,
            runtime_metadata=runtime_metadata,
        )
        checkpoint_value: RecoveryRetirementProof | None = None

        def checkpoint(candidate: object) -> None:
            nonlocal checkpoint_value
            if checkpoint_value is not None or _path_present(
                paths.retire_recovery_proof,
            ):
                raise MigrationError(
                    "recovery retirement proof checkpoint already exists",
                )
            current = _validated_retirement_state(
                paths,
                source_receipt_path=source_receipt_path,
                script_path=script_path,
                dry_run_receipt_path=dry_run_receipt_path,
                review_receipt_path=review_receipt_path,
                apply_receipt_path=apply_receipt_path,
                runner=runner,
                python_executable=python_executable,
                expected_script_sha256=expected_script_sha256,
                runtime_phase="ready",
                writer_census=False,
                bootstrap_receipt_validator=bootstrap_receipt_validator,
            )
            (
                validated_current,
                apply_receipt_current,
                apply_attempt_current,
                _apply_payload_current,
                runtime_metadata_current,
                bootstrap_receipt_current,
                bootstrap_current,
            ) = current
            retirement_attempt_current = _retirement_attempt_snapshot(paths)
            current_plan = _recovery_retirement_plan(
                validated_current,
                apply_receipt=apply_receipt_current,
                apply_attempt=apply_attempt_current,
                bootstrap_receipt=bootstrap_receipt_current,
                bootstrap=bootstrap_current,
                retirement_attempt=retirement_attempt_current,
                runtime_metadata=runtime_metadata_current,
            )
            _validate_retirement_attempt_snapshot(
                retirement_attempt_current,
                current_plan,
                runtime_metadata=runtime_metadata_current,
            )
            if (
                current_plan != plan
                or runtime_metadata_current != runtime_metadata
                or retirement_attempt_current != retirement_attempt
            ):
                raise MigrationError(
                    "recovery retirement state changed before checkpoint",
                )
            metadata = _recovery_proof_metadata(candidate, current_plan)
            _write_new_json_0600(
                paths.retire_recovery_proof,
                {
                    "bootstrap": _bootstrap_retirement_metadata(
                        current_plan.bootstrap_receipt,
                        current_plan.bootstrap,
                    ),
                    "schema": RETIRE_RECOVERY_PROOF_SCHEMA,
                    "proof": metadata,
                },
                root=paths.repository_root,
                preserve_published_on_failure=True,
            )
            checkpoint_snapshot = _retirement_proof_snapshot(paths)
            checkpoint_value = _validate_retirement_proof_snapshot(
                checkpoint_snapshot,
                current_plan,
            )

        executor_failed = False
        executor_proof: object = None
        try:
            executor_proof = executor(plan, lease, checkpoint)
        except Exception:
            executor_failed = True
        if executor_failed:
            raise MigrationError(
                "recovery retirement executor failed; "
                "reconciliation is required",
            ) from None
        if checkpoint_value is None:
            raise MigrationError(
                "executor returned without a durable recovery proof checkpoint",
            )
        _recovery_proof_metadata(executor_proof, plan)
        if executor_proof != checkpoint_value:
            raise MigrationError(
                "executor proof does not match its durable checkpoint",
            )
        return executor_proof

    with _load_recovery_credential_lease(
        paths,
        validated.plan.runtime,
        validated.runtime_artifacts.recovery_environment,
    ) as lease:
        executor_proof = dispatch(lease)
    return _finalize_recovery_retirement(
        paths,
        source_receipt_path=source_receipt_path,
        script_path=script_path,
        dry_run_receipt_path=dry_run_receipt_path,
        review_receipt_path=review_receipt_path,
        apply_receipt_path=apply_receipt_path,
        runner=runner,
        python_executable=python_executable,
        postflight_verifier=postflight_verifier,
        bootstrap_receipt_validator=bootstrap_receipt_validator,
        clock=clock,
        expected_script_sha256=expected_script_sha256,
        expected_executor_proof=executor_proof,
    )


def validate_recovery_retired_receipt(
    paths: MigrationPaths,
    receipt_path: Path,
    *,
    source_receipt_path: Path,
    script_path: Path,
    dry_run_receipt_path: Path,
    review_receipt_path: Path,
    apply_receipt_path: Path,
    runner: object = run_command,
    bootstrap_receipt_validator: object,
    python_executable: str,
    expected_script_sha256: str = MIGRATION_SCRIPT_SHA256,
) -> dict[str, object]:
    """Validate the final secret-free retirement receipt without live auth."""
    _require_fixed_retirement_paths(
        paths,
        source_receipt_path=source_receipt_path,
        script_path=script_path,
        dry_run_receipt_path=dry_run_receipt_path,
        review_receipt_path=review_receipt_path,
        apply_receipt_path=apply_receipt_path,
    )
    if receipt_path != paths.recovery_retired_receipt:
        raise MigrationError(
            "recovery-retired receipt is not the fixed repository path",
        )
    attempt_exists, proof_exists, receipt_exists = _retirement_file_state(paths)
    if not attempt_exists or not proof_exists or not receipt_exists:
        raise MigrationError(
            "recovery retirement receipt chain is incomplete",
        )
    receipt_before = _read_regular_snapshot(
        receipt_path,
        root=paths.repository_root,
        label="recovery-retired receipt",
        maximum=64 * 1024,
        required_mode=0o600,
    )
    state_before = _validated_retirement_state(
        paths,
        source_receipt_path=source_receipt_path,
        script_path=script_path,
        dry_run_receipt_path=dry_run_receipt_path,
        review_receipt_path=review_receipt_path,
        apply_receipt_path=apply_receipt_path,
        runner=runner,
        python_executable=python_executable,
        expected_script_sha256=expected_script_sha256,
        runtime_phase="retired",
        writer_census=False,
        bootstrap_receipt_validator=bootstrap_receipt_validator,
    )
    (
        validated_before,
        apply_receipt_before,
        apply_attempt_before,
        _apply_payload_before,
        runtime_metadata_before,
        bootstrap_receipt_before,
        bootstrap_before,
    ) = state_before
    retirement_attempt_before = _retirement_attempt_snapshot(paths)
    proof_snapshot_before = _retirement_proof_snapshot(paths)
    plan_before = _recovery_retirement_plan(
        validated_before,
        apply_receipt=apply_receipt_before,
        apply_attempt=apply_attempt_before,
        bootstrap_receipt=bootstrap_receipt_before,
        bootstrap=bootstrap_before,
        retirement_attempt=retirement_attempt_before,
        runtime_metadata=runtime_metadata_before,
    )
    _validate_retirement_attempt_snapshot(
        retirement_attempt_before,
        plan_before,
        runtime_metadata=runtime_metadata_before,
    )
    proof_before = _validate_retirement_proof_snapshot(
        proof_snapshot_before,
        plan_before,
    )
    payload = _parse_strict_json_snapshot(
        receipt_before,
        label="recovery-retired receipt",
    )
    _validate_retired_receipt_payload(
        payload,
        plan_before,
        proof_snapshot=proof_snapshot_before,
        proof=proof_before,
    )

    receipt_after = _read_regular_snapshot(
        receipt_path,
        root=paths.repository_root,
        label="recovery-retired receipt",
        maximum=64 * 1024,
        required_mode=0o600,
    )
    state_after = _validated_retirement_state(
        paths,
        source_receipt_path=source_receipt_path,
        script_path=script_path,
        dry_run_receipt_path=dry_run_receipt_path,
        review_receipt_path=review_receipt_path,
        apply_receipt_path=apply_receipt_path,
        runner=runner,
        python_executable=python_executable,
        expected_script_sha256=expected_script_sha256,
        runtime_phase="retired",
        writer_census=False,
        bootstrap_receipt_validator=bootstrap_receipt_validator,
    )
    retirement_attempt_after = _retirement_attempt_snapshot(paths)
    proof_snapshot_after = _retirement_proof_snapshot(paths)
    if (
        receipt_before != receipt_after
        or state_before != state_after
        or retirement_attempt_before != retirement_attempt_after
        or proof_snapshot_before != proof_snapshot_after
    ):
        raise MigrationError(
            "recovery retirement receipt chain changed during validation",
        )
    return payload


@dataclass(frozen=True, repr=False)
class NormalRuntimeEvidenceDependencies:
    """Read-only adapters for the fixed normal-runtime evidence command."""

    repository_root: Path
    bootstrap_module_loader: object
    bootstrap_module_releaser: object
    state_runner: object
    python_executable: str

    def __post_init__(self) -> None:
        if not isinstance(self.repository_root, Path):
            raise MigrationError(
                "normal-runtime evidence dependency is unavailable",
            )
        _plain_absolute(
            self.repository_root,
            "normal-runtime evidence repository",
        )
        if (
            any(
                not callable(value)
                for value in (
                    self.bootstrap_module_loader,
                    self.bootstrap_module_releaser,
                    self.state_runner,
                )
            )
            or type(self.python_executable) is not str
            or not self.python_executable
            or not Path(self.python_executable).is_absolute()
            or Path(os.path.normpath(self.python_executable))
            != Path(self.python_executable)
        ):
            raise MigrationError(
                "normal-runtime evidence dependency is unavailable",
            )

    def __repr__(self) -> str:
        return "NormalRuntimeEvidenceDependencies(<redacted>)"


def normal_runtime_evidence_dependencies(
) -> NormalRuntimeEvidenceDependencies:
    """Return the fixed primary-checkout read-only evidence adapters."""
    return NormalRuntimeEvidenceDependencies(
        repository_root=REPOSITORY_ROOT,
        bootstrap_module_loader=_load_production_bootstrap_module,
        bootstrap_module_releaser=_release_production_bootstrap_module,
        state_runner=run_command,
        python_executable=sys.executable,
    )


def _normal_runtime_outer_snapshots(
    paths: MigrationPaths,
) -> tuple[FileSnapshot, ...]:
    protected_accounts = (
        paths.bootstrap_receipt.parent / "protected-accounts.json"
    )
    return tuple(
        _read_regular_snapshot(
            path,
            root=paths.repository_root,
            label=label,
            maximum=maximum,
            required_mode=0o600,
        )
        for path, label, maximum in (
            (paths.apply_receipt, "apply receipt", 64 * 1024),
            (
                paths.bootstrap_receipt,
                "bootstrap receipt",
                4 * 1024 * 1024,
            ),
            (
                paths.principals,
                "dumped principals",
                16 * 1024 * 1024,
            ),
            (
                paths.export,
                "converted export",
                16 * 1024 * 1024,
            ),
            (
                paths.retire_recovery_proof,
                "retirement proof",
                64 * 1024,
            ),
            (
                paths.recovery_retired_receipt,
                "recovery-retired receipt",
                64 * 1024,
            ),
            (
                protected_accounts,
                "protected Account IDs",
                64 * 1024,
            ),
        )
    )


def _normal_runtime_bootstrap_management(
    bootstrap_snapshot: FileSnapshot,
    protected_snapshot: FileSnapshot,
    token: object,
) -> tuple[dict[str, object], list[str]]:
    malformed = "normal-runtime bootstrap evidence is malformed"
    envelope = _parse_strict_json_snapshot(
        bootstrap_snapshot,
        label="bootstrap receipt",
    )
    try:
        payload = validate_digest_envelope(envelope)
    except MigrationError:
        raise MigrationError(malformed) from None
    if (
        _canonical_json_bytes(envelope) + b"\n"
        != bootstrap_snapshot.content
    ):
        raise MigrationError(malformed)

    account_id = getattr(token, "management_account_id", None)
    api_key_id = getattr(token, "management_api_key_id", None)
    safe_objects = payload.get("safe_objects")
    inventory = payload.get("credential_inventory")
    management = payload.get("management")
    inventory_keys = {
        "account_id",
        "allowed_ips",
        "credential_id",
        "credential_type",
        "description",
        "permissions",
    }
    if (
        type(account_id) is not str
        or BOOTSTRAP_SAFE_ID_PATTERN.fullmatch(account_id) is None
        or type(api_key_id) is not str
        or BOOTSTRAP_SAFE_ID_PATTERN.fullmatch(api_key_id) is None
        or not isinstance(safe_objects, list)
        or not isinstance(inventory, list)
        or len(inventory) != 1
        or not isinstance(inventory[0], dict)
        or set(inventory[0]) != inventory_keys
        or inventory[0].get("account_id") != account_id
        or inventory[0].get("credential_id") != api_key_id
        or inventory[0].get("credential_type") != "ApiKey"
        or type(inventory[0].get("description")) is not str
        or not isinstance(inventory[0].get("allowed_ips"), dict)
        or not isinstance(inventory[0].get("permissions"), dict)
        or not isinstance(management, dict)
        or management.get("account_id") != account_id
        or management.get("credential_id") != api_key_id
        or hashlib.sha256(
            _canonical_json_bytes(safe_objects),
        ).hexdigest()
        != getattr(token, "safe_objects_sha256", None)
        or _normal_runtime_contains_forbidden_account_field(inventory)
    ):
        raise MigrationError(malformed)

    selected: dict[str, dict[str, object]] = {}
    for projection in safe_objects:
        if not isinstance(projection, dict):
            raise MigrationError(malformed)
        object_type = projection.get("object_type")
        expected_id = {
            "Account": account_id,
            "ApiKey": api_key_id,
        }.get(object_type)
        if expected_id is None:
            continue
        if projection.get("id") != expected_id:
            raise MigrationError(malformed)
        if (
            set(projection) != {"id", "object_type", "value"}
            or not isinstance(projection.get("value"), dict)
            or object_type in selected
            or _normal_runtime_contains_forbidden_account_field(
                projection,
            )
        ):
            raise MigrationError(malformed)
        selected[object_type] = projection
    if set(selected) != {"Account", "ApiKey"}:
        raise MigrationError(malformed)
    if (
        hashlib.sha256(
            _canonical_json_bytes(selected["Account"]),
        ).hexdigest()
        != getattr(token, "account_projection_sha256", None)
        or hashlib.sha256(
            _canonical_json_bytes(selected["ApiKey"]),
        ).hexdigest()
        != getattr(token, "api_key_projection_sha256", None)
    ):
        raise MigrationError(malformed)

    protected = _parse_strict_json_snapshot(
        protected_snapshot,
        label="protected Account IDs",
    )
    protected_ids = protected.get("account_ids")
    if (
        set(protected) != {"account_ids", "schema"}
        or protected.get("schema")
        != "mail-sandbox.stalwart-v016-protected-accounts.v1"
        or not isinstance(protected_ids, list)
        or protected_ids != [account_id]
        or any(type(value) is not str for value in protected_ids)
        or protected_snapshot.sha256
        != getattr(token, "protected_accounts_sha256", None)
    ):
        raise MigrationError(malformed)
    return (
        {
            "account_id": account_id,
            "api_key_id": api_key_id,
            "account_projection": selected["Account"],
            "api_key_projection": selected["ApiKey"],
            "credential_inventory": inventory,
        },
        protected_ids,
    )


def _normal_runtime_old_recovery_status(
    retired_payload: dict[str, object],
) -> int:
    proof = retired_payload.get("proof")
    if not isinstance(proof, dict):
        raise MigrationError(
            "normal-runtime retirement evidence is malformed",
        )
    status = proof.get("old_recovery_auth_status")
    if type(status) is not int or status not in {401, 403}:
        raise MigrationError(
            "normal-runtime retirement evidence is malformed",
        )
    return status


def _build_normal_runtime_evidence(
    paths: MigrationPaths,
    *,
    dependencies: NormalRuntimeEvidenceDependencies,
    expected_script_sha256: str,
) -> bytes:
    if (
        not isinstance(paths, MigrationPaths)
        or type(dependencies) is not NormalRuntimeEvidenceDependencies
        or paths.repository_root != dependencies.repository_root
        or paths
        != MigrationPaths.for_repository(dependencies.repository_root)
        or type(expected_script_sha256) is not str
        or re.fullmatch(r"[0-9a-f]{64}", expected_script_sha256) is None
    ):
        raise MigrationError(
            "normal-runtime evidence inputs are malformed",
        )
    before = _normal_runtime_outer_snapshots(paths)
    (
        _apply_snapshot,
        bootstrap_snapshot,
        principals_snapshot,
        export_snapshot,
        _proof_snapshot,
        _retired_snapshot,
        protected_snapshot,
    ) = before

    previous_bytecode_mode = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        bootstrap_module = dependencies.bootstrap_module_loader(
            dependencies.repository_root,
        )
    finally:
        sys.dont_write_bytecode = previous_bytecode_mode
    primary: BaseException | None = None
    try:
        trusted_bootstrap_module: ModuleType | None = None
        if (
            type(bootstrap_module) is ModuleType
            and getattr(
                bootstrap_module,
                _PRODUCTION_BOOTSTRAP_MODULE_MARKER_ATTRIBUTE,
                None,
            )
            is _PRODUCTION_BOOTSTRAP_MODULE_MARKER
        ):
            trusted_bootstrap_module = (
                _assert_trusted_production_bootstrap_module(
                    bootstrap_module,
                    Path(__file__).resolve().with_name(
                        "bootstrap_stalwart_v016.py",
                    ),
                )
            )
        bootstrap_paths_type = getattr(
            bootstrap_module,
            "BootstrapPaths",
            None,
        )
        bootstrap_paths_factory = getattr(
            bootstrap_paths_type,
            "for_repository",
            None,
        )
        bootstrap_validator = getattr(
            bootstrap_module,
            "validate_final_bootstrap_for_retirement",
            None,
        )
        if not callable(bootstrap_paths_factory) or not callable(
            bootstrap_validator,
        ):
            raise MigrationError(
                "normal-runtime bootstrap validator is unavailable",
            )
        bootstrap_paths = bootstrap_paths_factory(
            dependencies.repository_root,
        )
        task6_validator = build_bootstrap_apply_receipt_validator(
            paths,
            source_receipt_path=paths.source_receipt,
            script_path=paths.migration_script,
            dry_run_receipt_path=paths.dry_run_receipt,
            review_receipt_path=paths.reviewed,
            runner=dependencies.state_runner,
            python_executable=dependencies.python_executable,
            expected_script_sha256=expected_script_sha256,
            runtime_phase="retired",
        )
        bootstrap_validation_tokens: list[object] = []
        authoritative_tokens: list[object] = []

        def authoritative_bootstrap_validator(
            runtime_phase: str,
        ) -> object:
            if runtime_phase != "retired":
                raise MigrationError(
                    "normal-runtime bootstrap phase is malformed",
                )
            if trusted_bootstrap_module is not None:
                _assert_trusted_production_bootstrap_module(
                    trusted_bootstrap_module,
                    Path(__file__).resolve().with_name(
                        "bootstrap_stalwart_v016.py",
                    ),
                )
            token = bootstrap_validator(
                bootstrap_paths,
                task6_validator=task6_validator,
            )
            if trusted_bootstrap_module is not None:
                _assert_trusted_production_bootstrap_module(
                    trusted_bootstrap_module,
                    Path(__file__).resolve().with_name(
                        "bootstrap_stalwart_v016.py",
                    ),
                )
            bootstrap_validation_tokens.append(token)
            return token

        if trusted_bootstrap_module is not None:
            setattr(
                authoritative_bootstrap_validator,
                "_trusted_bootstrap_module",
                trusted_bootstrap_module,
            )

        def validate_retired() -> dict[str, object]:
            token_offset = len(bootstrap_validation_tokens)
            payload = validate_recovery_retired_receipt(
                paths,
                paths.recovery_retired_receipt,
                source_receipt_path=paths.source_receipt,
                script_path=paths.migration_script,
                dry_run_receipt_path=paths.dry_run_receipt,
                review_receipt_path=paths.reviewed,
                apply_receipt_path=paths.apply_receipt,
                runner=dependencies.state_runner,
                bootstrap_receipt_validator=(
                    authoritative_bootstrap_validator
                ),
                python_executable=dependencies.python_executable,
                expected_script_sha256=expected_script_sha256,
            )
            observed_tokens = bootstrap_validation_tokens[token_offset:]
            if (
                not observed_tokens
                or any(
                    token != observed_tokens[0]
                    for token in observed_tokens[1:]
                )
            ):
                raise MigrationError(
                    "normal-runtime bootstrap evidence changed",
                )
            authoritative_tokens.append(observed_tokens[0])
            return payload

        retired_payload = validate_retired()
        if len(authoritative_tokens) != 1:
            raise MigrationError(
                "normal-runtime bootstrap evidence is unavailable",
            )
        first_token = authoritative_tokens[0]
        management, protected_ids = (
            _normal_runtime_bootstrap_management(
                bootstrap_snapshot,
                protected_snapshot,
                first_token,
            )
        )
        migrated_accounts = _normal_runtime_migrated_accounts(
            principals_snapshot,
            export_snapshot,
        )
        final_retired_payload = validate_retired()
        if (
            len(authoritative_tokens) != 2
            or final_retired_payload != retired_payload
            or authoritative_tokens[1] != first_token
        ):
            raise MigrationError(
                "normal-runtime authoritative evidence changed",
            )
        final_management, final_protected_ids = (
            _normal_runtime_bootstrap_management(
                bootstrap_snapshot,
                protected_snapshot,
                authoritative_tokens[1],
            )
        )
        if (
            final_management != management
            or final_protected_ids != protected_ids
        ):
            raise MigrationError(
                "normal-runtime authoritative bindings changed",
            )
        payload = {
            "schema": NORMAL_RUNTIME_EVIDENCE_SCHEMA,
            "management": management,
            "protected_account_ids": protected_ids,
            "old_recovery_auth_status": (
                _normal_runtime_old_recovery_status(
                    retired_payload,
                )
            ),
            "migrated_accounts": migrated_accounts,
        }
        line = _canonical_json_bytes(_digest_envelope(payload)) + b"\n"
    except BaseException as exc:
        primary = exc
        raise
    finally:
        try:
            dependencies.bootstrap_module_releaser(
                bootstrap_module,
            )
        except BaseException:
            if primary is None:
                raise

    after = _normal_runtime_outer_snapshots(paths)
    if before != after:
        raise MigrationError(
            "normal-runtime evidence files changed during validation",
        )
    return line


def build_normal_runtime_evidence(
    paths: MigrationPaths,
    *,
    dependencies: NormalRuntimeEvidenceDependencies | None = None,
    expected_script_sha256: str = MIGRATION_SCRIPT_SHA256,
) -> bytes:
    """Return one canonical, secret-free line from one fixed outer snapshot."""
    selected = (
        normal_runtime_evidence_dependencies()
        if dependencies is None
        else dependencies
    )
    try:
        return _build_normal_runtime_evidence(
            paths,
            dependencies=selected,
            expected_script_sha256=expected_script_sha256,
        )
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise MigrationError(
            "normal-runtime evidence validation failed safely",
        ) from None


def _absolute_cli_path(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute() or Path(os.path.normpath(value)) != path:
        raise argparse.ArgumentTypeError("must be a normalized absolute path")
    return path


def _build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Prepare, execute, and retire the fail-closed Stalwart v0.16.17 "
            "migration."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    dry_run = subparsers.add_parser(
        "dry-run",
        help="dump from verified v0.15, convert, and emit a digest-bound receipt",
    )
    dry_run.add_argument("--script", required=True, type=Path)
    dry_run.add_argument("--source-receipt", required=True, type=Path)
    dry_run.add_argument(
        "--migration-python",
        required=True,
        type=_absolute_cli_path,
        help="absolute Python interpreter with requests and urllib3 installed",
    )
    reviewed = subparsers.add_parser(
        "mark-reviewed",
        help="bind the fixed unmigrated.txt report to an owner-only review receipt",
    )
    reviewed.add_argument("--report", required=True, type=Path)
    apply = subparsers.add_parser(
        "apply",
        help="execute the reviewed fixed migration plan under the shared lock",
    )
    apply.add_argument("--script", required=True, type=Path)
    apply.add_argument("--review-receipt", required=True, type=Path)
    subparsers.add_parser(
        "retire-recovery",
        help="retire the one-use recovery credential on the fixed runtime",
    )
    subparsers.add_parser(
        "normal-runtime-evidence",
        help="emit one read-only digest-bound normal-runtime evidence line",
    )
    return parser


def _from_cwd(path: Path) -> Path:
    return path if path.is_absolute() else Path.cwd() / path


def main(argv: list[str] | None = None) -> int:
    arguments = _build_argument_parser().parse_args(argv)
    paths = MigrationPaths.for_repository(REPOSITORY_ROOT)
    try:
        if arguments.command == "normal-runtime-evidence":
            try:
                line = build_normal_runtime_evidence(paths)
                if (
                    type(line) is not bytes
                    or not line.endswith(b"\n")
                    or line.count(b"\n") != 1
                ):
                    raise MigrationError(
                        "normal-runtime evidence output is malformed",
                    )
                text = line.decode("utf-8")
            except BaseException:
                print(
                    (
                        "error: Stalwart normal-runtime evidence "
                        "validation failed safely"
                    ),
                    file=sys.stderr,
                )
                return 1
            sys.stdout.write(text)
            return 0
        if arguments.command == "apply":
            try:
                receipt = run_production_apply(
                    paths,
                    script_path=_from_cwd(arguments.script),
                    review_receipt_path=_from_cwd(
                        arguments.review_receipt,
                    ),
                )
            except BaseException:
                print(
                    "error: Stalwart v0.16 apply failed safely",
                    file=sys.stderr,
                )
                return 1
            print(receipt)
            return 0
        if arguments.command == "retire-recovery":
            try:
                receipt = run_production_recovery_retirement(paths)
            except BaseException:
                print(
                    "error: Stalwart recovery retirement failed safely",
                    file=sys.stderr,
                )
                return 1
            print(receipt)
            return 0
        if arguments.command == "mark-reviewed":
            receipt = mark_reviewed(paths, _from_cwd(arguments.report))
            print(f"review receipt: {receipt}")
            return 0
        if arguments.command == "dry-run":
            receipt = prepare_dry_run(
                paths,
                script_path=_from_cwd(arguments.script),
                receipt_path=_from_cwd(arguments.source_receipt),
                runner=run_command,
                python_executable=sys.executable,
                migration_python=str(arguments.migration_python),
            )
            print(receipt)
            return 0
        raise MigrationError(
            f"{arguments.command} is intentionally unavailable in the preparation tool",
        )
    except MigrationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == JMAP_AUTH_PROBE_MODE:
        jmap_probe_exit = (
            _fixed_jmap_auth_probe_child(
                sys.argv[2],
                sys.argv[3],
                sys.argv[4],
            )
            if len(sys.argv) == 5
            else 1
        )
        raise SystemExit(jmap_probe_exit)
    if len(sys.argv) >= 2 and sys.argv[1] == SECRET_DISPATCH_MODE:
        secret_dispatch_exit = (
            _secret_dispatch_child(sys.argv[2])
            if len(sys.argv) == 3
            else 1
        )
        raise SystemExit(secret_dispatch_exit)
    raise SystemExit(main())
