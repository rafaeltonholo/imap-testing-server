#!/usr/bin/env python3
"""Prepare and read the LAN URL used by the local Stalwart runtime.

The generated file is deliberately runtime state rather than configuration in
Git: a DHCP address change must not invalidate a captured-store receipt.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
import ipaddress
import os
from pathlib import Path
import platform
import re
import socket
import stat
import subprocess
import sys
import tempfile


HOST_OVERRIDE = "MAIL_SANDBOX_LAN_HOST"
PUBLIC_URL_VARIABLE = "STALWART_PUBLIC_URL"
PUBLIC_PORT = 8443
NETWORK_ENV_RELATIVE = (
    Path("debug-dashboard") / ".runtime" / "stalwart" / "network.env"
)
_OVERRIDE_GUIDANCE = (
    "Set MAIL_SANDBOX_LAN_HOST to one local non-loopback IPv4 address "
    "or hostname."
)
_HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_ENVIRONMENT_LINE = re.compile(
    rb"STALWART_PUBLIC_URL=http://([^:/@\s]+):8443\n"
)


class NetworkConfigurationError(RuntimeError):
    """The LAN endpoint cannot be selected or trusted."""


@dataclass(frozen=True)
class NetworkConfiguration:
    repository: Path
    host: str
    public_url: str
    environment_path: Path


CommandRunner = Callable[[Sequence[str]], str]
HostResolver = Callable[[str], Iterable[str]]
AddressProvider = Callable[[], Iterable[str]]


def _repository_path(value: Path) -> Path:
    candidate = Path(value)
    if not candidate.is_absolute():
        raise ValueError("repository must be a normalized absolute path")
    try:
        resolved = candidate.resolve(strict=True)
        metadata = os.lstat(candidate)
    except (FileNotFoundError, OSError) as exc:
        raise ValueError("repository must be an existing directory") from exc
    if candidate != resolved or stat.S_ISLNK(metadata.st_mode):
        raise ValueError("repository must be a normalized absolute path")
    if not stat.S_ISDIR(metadata.st_mode):
        raise ValueError("repository must be an existing directory")
    return resolved


def _eligible_ipv4(value: str) -> ipaddress.IPv4Address | None:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if not isinstance(address, ipaddress.IPv4Address):
        return None
    if (
        address.is_unspecified
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
    ):
        return None
    return address


def _default_hostname_resolver(host: str) -> tuple[str, ...]:
    try:
        answers = socket.getaddrinfo(
            host,
            None,
            family=socket.AF_INET,
            type=socket.SOCK_STREAM,
        )
    except OSError as exc:
        raise NetworkConfigurationError(
            f"hostname resolution failed. {_OVERRIDE_GUIDANCE}"
        ) from exc
    return tuple(answer[4][0] for answer in answers)


def _run_command(command: Sequence[str]) -> str:
    completed = subprocess.run(
        list(command),
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout


def _route_error(detail: str) -> NetworkConfigurationError:
    return NetworkConfigurationError(f"{detail}. {_OVERRIDE_GUIDANCE}")


def _darwin_default_interface(route_output: str) -> str:
    interfaces: list[str] = []
    for line in route_output.splitlines():
        fields = line.split()
        if len(fields) >= 4 and fields[0] == "default":
            interfaces.append(fields[3])
    if len(interfaces) != 1:
        raise _route_error("expected exactly one default-route interface")
    return interfaces[0]


def _linux_default_interface(route_output: str) -> str:
    candidates: list[tuple[int, str]] = []
    for line in route_output.splitlines():
        fields = line.split()
        if not fields or fields[0] != "default" or "dev" not in fields:
            continue
        device_index = fields.index("dev")
        if device_index + 1 >= len(fields):
            raise _route_error("default route has no interface")
        metric = 0
        if "metric" in fields:
            metric_index = fields.index("metric")
            if metric_index + 1 >= len(fields):
                raise _route_error("default route has no usable metric")
            try:
                metric = int(fields[metric_index + 1])
            except ValueError as exc:
                raise _route_error("default route has no usable metric") from exc
        candidates.append((metric, fields[device_index + 1]))

    if not candidates:
        raise _route_error("no default-route interface was found")
    best_metric = min(metric for metric, _interface in candidates)
    interfaces = [
        interface for metric, interface in candidates if metric == best_metric
    ]
    if len(interfaces) != 1:
        raise _route_error("expected exactly one default-route interface")
    return interfaces[0]


def _addresses_from_output(output: str) -> tuple[str, ...]:
    addresses = {
        str(address)
        for match in re.finditer(r"(?:^|\s)inet\s+([0-9.]+)(?:/\d+)?", output)
        if (address := _eligible_ipv4(match.group(1))) is not None
    }
    return tuple(sorted(addresses))


def detect_default_route_ipv4(
    *,
    runner: CommandRunner = _run_command,
    platform_name: str | None = None,
) -> str:
    """Return the sole eligible IPv4 on the sole best default-route interface."""

    operating_system = platform_name or platform.system()
    try:
        if operating_system == "Darwin":
            routes = runner(("netstat", "-rn", "-f", "inet"))
            interface = _darwin_default_interface(routes)
            address_output = runner(("ifconfig", interface))
        elif operating_system == "Linux":
            routes = runner(("ip", "-4", "route", "show", "default"))
            interface = _linux_default_interface(routes)
            address_output = runner(
                (
                    "ip",
                    "-o",
                    "-4",
                    "addr",
                    "show",
                    "dev",
                    interface,
                    "scope",
                    "global",
                )
            )
        else:
            raise _route_error(f"unsupported operating system {operating_system!r}")
    except NetworkConfigurationError:
        raise
    except (OSError, subprocess.SubprocessError) as exc:
        raise _route_error("default-route inspection failed") from exc

    addresses = _addresses_from_output(address_output)
    if len(addresses) != 1:
        raise _route_error(
            "default-route interface must have exactly one eligible IPv4 address"
        )
    return addresses[0]


def _default_local_ipv4_provider() -> tuple[str, ...]:
    operating_system = platform.system()
    try:
        if operating_system == "Darwin":
            output = _run_command(("ifconfig",))
        elif operating_system == "Linux":
            output = _run_command(
                ("ip", "-o", "-4", "addr", "show", "scope", "global")
            )
        else:
            raise _route_error(f"unsupported operating system {operating_system!r}")
    except NetworkConfigurationError:
        raise
    except (OSError, subprocess.SubprocessError) as exc:
        raise _route_error("local interface inspection failed") from exc
    return _addresses_from_output(output)


def _normalize_host_shape(value: str) -> tuple[str, bool]:
    if not isinstance(value, str) or not value:
        raise NetworkConfigurationError(f"invalid {HOST_OVERRIDE}. {_OVERRIDE_GUIDANCE}")
    if value != value.strip() or any(character.isspace() for character in value):
        raise NetworkConfigurationError(f"invalid {HOST_OVERRIDE}. {_OVERRIDE_GUIDANCE}")
    if any(token in value for token in ("://", "/", "@", ":", "[", "]")):
        raise NetworkConfigurationError(f"invalid {HOST_OVERRIDE}. {_OVERRIDE_GUIDANCE}")

    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        parsed = None
    if parsed is not None:
        eligible = _eligible_ipv4(value)
        if eligible is None:
            raise NetworkConfigurationError(
                f"invalid {HOST_OVERRIDE}; expected non-loopback unicast IPv4. "
                f"{_OVERRIDE_GUIDANCE}"
            )
        return str(eligible), True

    if all(character.isdigit() or character == "." for character in value):
        raise NetworkConfigurationError(f"invalid {HOST_OVERRIDE}. {_OVERRIDE_GUIDANCE}")

    hostname = value.lower()
    if len(hostname) > 253 or hostname.endswith("."):
        raise NetworkConfigurationError(f"invalid {HOST_OVERRIDE}. {_OVERRIDE_GUIDANCE}")
    labels = hostname.split(".")
    if not labels or any(_HOST_LABEL.fullmatch(label) is None for label in labels):
        raise NetworkConfigurationError(f"invalid {HOST_OVERRIDE}. {_OVERRIDE_GUIDANCE}")
    return hostname, False


def _normalize_host(
    value: str,
    *,
    hostname_resolver: HostResolver,
    local_ipv4_provider: AddressProvider,
) -> str:
    hostname, is_ipv4 = _normalize_host_shape(value)
    if is_ipv4:
        return hostname

    try:
        resolved_values = tuple(hostname_resolver(hostname))
    except NetworkConfigurationError:
        raise
    except Exception as exc:
        raise NetworkConfigurationError(
            f"hostname resolution failed. {_OVERRIDE_GUIDANCE}"
        ) from exc
    resolved = {
        str(address)
        for raw in resolved_values
        if (address := _eligible_ipv4(raw)) is not None
    }
    if len(resolved) != 1 or len(set(resolved_values)) != 1:
        raise NetworkConfigurationError(
            f"hostname must resolve to exactly one eligible IPv4 address. "
            f"{_OVERRIDE_GUIDANCE}"
        )

    try:
        local = {
            str(address)
            for raw in local_ipv4_provider()
            if (address := _eligible_ipv4(raw)) is not None
        }
    except NetworkConfigurationError:
        raise
    except Exception as exc:
        raise NetworkConfigurationError(
            f"local interface inspection failed. {_OVERRIDE_GUIDANCE}"
        ) from exc
    if next(iter(resolved)) not in local:
        raise NetworkConfigurationError(
            f"hostname must resolve to one local non-loopback IPv4 address. "
            f"{_OVERRIDE_GUIDANCE}"
        )
    return hostname


def resolve_network_configuration(
    repository: Path,
    *,
    environment: Mapping[str, str] | None = None,
    detector: Callable[[], str] = detect_default_route_ipv4,
    hostname_resolver: HostResolver = _default_hostname_resolver,
    local_ipv4_provider: AddressProvider = _default_local_ipv4_provider,
) -> NetworkConfiguration:
    """Resolve one validated public URL without mutating the repository."""

    root = _repository_path(repository)
    source = os.environ if environment is None else environment
    if HOST_OVERRIDE in source:
        raw_host = source[HOST_OVERRIDE]
    else:
        try:
            raw_host = detector()
        except NetworkConfigurationError:
            raise
        except Exception as exc:
            raise _route_error("default-route inspection failed") from exc
    host = _normalize_host(
        raw_host,
        hostname_resolver=hostname_resolver,
        local_ipv4_provider=local_ipv4_provider,
    )
    public_url = f"http://{host}:{PUBLIC_PORT}"
    return NetworkConfiguration(
        repository=root,
        host=host,
        public_url=public_url,
        environment_path=root / NETWORK_ENV_RELATIVE,
    )


def _ensure_directory(path: Path, *, mode: int, enforce_mode: bool = True) -> None:
    if path.exists() or path.is_symlink():
        metadata = os.lstat(path)
        if stat.S_ISLNK(metadata.st_mode):
            raise NetworkConfigurationError(
                f"refusing symbolic link in runtime path: {path}"
            )
        if not stat.S_ISDIR(metadata.st_mode):
            raise NetworkConfigurationError(f"runtime path is not a directory: {path}")
    else:
        path.mkdir(mode=mode)
    if enforce_mode:
        path.chmod(mode)


def _ensure_runtime_directory(repository: Path) -> Path:
    dashboard = repository / "debug-dashboard"
    _ensure_directory(dashboard, mode=0o755, enforce_mode=False)
    runtime = dashboard / ".runtime"
    _ensure_directory(runtime, mode=0o700)
    stalwart = runtime / "stalwart"
    _ensure_directory(stalwart, mode=0o700)
    return stalwart


def _fsync_directory(directory: Path) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    descriptor = os.open(directory, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _validate_configuration(configuration: NetworkConfiguration) -> None:
    repository = _repository_path(configuration.repository)
    expected_path = repository / NETWORK_ENV_RELATIVE
    expected_url = f"http://{configuration.host}:{PUBLIC_PORT}"
    if configuration.environment_path != expected_path:
        raise NetworkConfigurationError("network environment path escaped repository")
    normalized_host, _is_ipv4 = _normalize_host_shape(configuration.host)
    if normalized_host != configuration.host:
        raise NetworkConfigurationError("network host is not normalized")
    if configuration.public_url != expected_url:
        raise NetworkConfigurationError("network public URL is inconsistent")


def write_network_environment(configuration: NetworkConfiguration) -> Path:
    """Atomically publish the exact owner-only Compose environment file."""

    _validate_configuration(configuration)
    directory = _ensure_runtime_directory(configuration.repository)
    target = directory / "network.env"
    if target.exists() and target.is_dir() and not target.is_symlink():
        raise NetworkConfigurationError("network environment target is a directory")
    payload = f"{PUBLIC_URL_VARIABLE}={configuration.public_url}\n".encode("ascii")

    descriptor = -1
    temporary: Path | None = None
    try:
        descriptor, name = tempfile.mkstemp(prefix="network.env.tmp-", dir=directory)
        temporary = Path(name)
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            descriptor = -1
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
        temporary = None
        _fsync_directory(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary is not None:
            temporary.unlink(missing_ok=True)

    metadata = os.lstat(target)
    if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600:
        raise NetworkConfigurationError("network environment must be a 0600 regular file")
    return target


def _require_directory(path: Path, *, required_mode: int | None = None) -> None:
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise NetworkConfigurationError(f"missing runtime directory: {path}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise NetworkConfigurationError(f"runtime path must be a regular directory: {path}")
    if required_mode is not None and stat.S_IMODE(metadata.st_mode) != required_mode:
        raise NetworkConfigurationError(
            f"runtime directory must have mode {required_mode:04o}: {path}"
        )


def load_network_configuration(
    repository: Path,
    *,
    hostname_resolver: HostResolver = _default_hostname_resolver,
    local_ipv4_provider: AddressProvider = _default_local_ipv4_provider,
) -> NetworkConfiguration:
    """Read a strictly formed current network file without modifying it."""

    root = _repository_path(repository)
    dashboard = root / "debug-dashboard"
    runtime = dashboard / ".runtime"
    directory = runtime / "stalwart"
    _require_directory(dashboard)
    _require_directory(runtime, required_mode=0o700)
    _require_directory(directory, required_mode=0o700)
    target = root / NETWORK_ENV_RELATIVE
    try:
        metadata = os.lstat(target)
    except OSError as exc:
        raise NetworkConfigurationError(
            f"missing network environment; run stalwart_network.py prepare. "
            f"{_OVERRIDE_GUIDANCE}"
        ) from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise NetworkConfigurationError("network environment must be a regular file")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise NetworkConfigurationError("network environment must have mode 0600")
    if metadata.st_size > 512:
        raise NetworkConfigurationError("network environment is too large")
    payload = target.read_bytes()
    match = _ENVIRONMENT_LINE.fullmatch(payload)
    if match is None:
        raise NetworkConfigurationError("network environment has invalid content")
    try:
        stored_host = match.group(1).decode("ascii")
    except UnicodeDecodeError as exc:
        raise NetworkConfigurationError("network environment host is not ASCII") from exc
    host = _normalize_host(
        stored_host,
        hostname_resolver=hostname_resolver,
        local_ipv4_provider=local_ipv4_provider,
    )
    if host != stored_host:
        raise NetworkConfigurationError("network environment host is not normalized")
    public_url = f"http://{host}:{PUBLIC_PORT}"
    return NetworkConfiguration(root, host, public_url, target)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Prepare or display the LAN URL for the local Stalwart runtime.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("prepare", "show"):
        command = commands.add_parser(name)
        command.add_argument("--repository", required=True, type=Path)
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    environment: Mapping[str, str] | None = None,
) -> int:
    options = _parser().parse_args(argv)
    if options.command == "prepare":
        configuration = resolve_network_configuration(
            options.repository,
            environment=environment,
        )
        write_network_environment(configuration)
    else:
        configuration = load_network_configuration(options.repository)
    print(configuration.public_url)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (NetworkConfigurationError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(2) from error
