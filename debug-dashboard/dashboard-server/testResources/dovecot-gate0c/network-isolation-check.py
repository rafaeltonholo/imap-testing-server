"""Fixed Task 6 network-isolation proof helper."""

import errno
import ipaddress
import signal
import socket
import sys


MAX_INPUT_BYTES = 1024
MAX_HOSTS = 32
SOCKET_TIMEOUT_SECONDS = 0.5

_ORDINARY_DOVECOT = ("dovecot", 31993)
_OPERATOR_DNS_NAME = "dovecot-operator"
_OPERATOR_IMAPS_PORT = 31993
_OPERATOR_HOST_PORT = 2993
_FIXED_HOST_GATEWAYS = (
    (
        "host.docker.internal",
        "HOST_DOCKER_INTERNAL_REACHABLE",
        "HOST_DOCKER_INTERNAL_UNRESOLVED",
    ),
    (
        "gateway.docker.internal",
        "GATEWAY_DOCKER_INTERNAL_REACHABLE",
        "GATEWAY_DOCKER_INTERNAL_UNRESOLVED",
    ),
    (
        "task6-host-gateway",
        "TASK6_HOST_GATEWAY_REACHABLE",
        "TASK6_HOST_GATEWAY_UNRESOLVED",
    ),
)
MAX_CONNECT_ATTEMPTS = 2 + len(_FIXED_HOST_GATEWAYS) + MAX_HOSTS
MAX_CONNECT_SECONDS = MAX_CONNECT_ATTEMPTS * SOCKET_TIMEOUT_SECONDS
MAX_WALL_SECONDS = 20.0
_ABSENT_RESOLUTION_ERRORS = frozenset(
    value
    for value in (
        getattr(socket, "EAI_NONAME", None),
        getattr(socket, "EAI_NODATA", None),
    )
    if value is not None
)
_EXPECTED_NEGATIVE_CONNECT_ERRORS = frozenset(
    value
    for value in (
        errno.EACCES,
        errno.ECONNREFUSED,
        errno.ECONNRESET,
        errno.EHOSTUNREACH,
        errno.ENETUNREACH,
        errno.EPERM,
        errno.ETIMEDOUT,
        getattr(errno, "EHOSTDOWN", None),
    )
    if value is not None
)


class InputError(Exception):
    """The bounded public network-target input is invalid."""


class DeadlineExpired(BaseException):
    """The fixed process-local wall deadline expired."""


def parse_input(data):
    if (
        not isinstance(data, bytes)
        or not data
        or len(data) > MAX_INPUT_BYTES
        or not data.endswith(b"\n")
        or b"\r" in data
    ):
        raise InputError
    try:
        lines = data.decode("ascii").removesuffix("\n").split("\n")
    except UnicodeDecodeError as failure:
        raise InputError from failure
    if not 2 <= len(lines) <= MAX_HOSTS + 1:
        raise InputError

    operator_kind, operator_value = _parse_line(lines[0])
    if operator_kind != "operator":
        raise InputError
    operator_ip = _canonical_ipv4(operator_value)

    host_ips = []
    observed = {operator_ip}
    for line in lines[1:]:
        kind, value = _parse_line(line)
        if kind != "host":
            raise InputError
        host_ip = _canonical_ipv4(value)
        if host_ip in observed:
            raise InputError
        observed.add(host_ip)
        host_ips.append(host_ip)
    return operator_ip, tuple(host_ips)


def _parse_line(line):
    fields = line.split(" ")
    if len(fields) != 2 or not fields[0] or not fields[1]:
        raise InputError
    return fields[0], fields[1]


def _canonical_ipv4(value):
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as failure:
        raise InputError from failure
    if (
        str(address) != value
        or address.is_unspecified
        or address.is_loopback
        or address.is_multicast
        or address.is_reserved
    ):
        raise InputError
    return str(address)


def network_diagnostic(operator_ip, host_ips):
    unresolved_gateway, gateway_targets = _resolve_fixed_gateways()
    if unresolved_gateway is not None:
        return unresolved_gateway
    ordinary_address = _resolve_single_ipv4(*_ORDINARY_DOVECOT)
    if ordinary_address is None or not _connects(
        ordinary_address,
        _ORDINARY_DOVECOT[1],
    ):
        return "DOVECOT_UNREACHABLE"
    if _operator_dns_resolves():
        return "OPERATOR_DNS_RESOLVED"
    if _connects(operator_ip, _OPERATOR_IMAPS_PORT):
        return "OPERATOR_IP_REACHABLE"
    for address, diagnostic in gateway_targets:
        if _connects(address, _OPERATOR_HOST_PORT):
            return diagnostic
    for host_ip in host_ips:
        if _connects(host_ip, _OPERATOR_HOST_PORT):
            return "HOST_IP_REACHABLE"
    return None


def _resolve_fixed_gateways():
    first_unresolved = None
    targets = []
    for hostname, _, unresolved_diagnostic in _FIXED_HOST_GATEWAYS:
        addresses = _resolve_ipv4(hostname, _OPERATOR_HOST_PORT)
        if not addresses:
            if first_unresolved is None:
                first_unresolved = unresolved_diagnostic
            continue
        if len(addresses) != 1:
            raise RuntimeError("fixed gateway resolution is ambiguous")
        targets.append((addresses[0], _gateway_diagnostic(hostname)))
    return first_unresolved, tuple(targets)


def _gateway_diagnostic(hostname):
    for fixed_hostname, diagnostic, _ in _FIXED_HOST_GATEWAYS:
        if hostname == fixed_hostname:
            return diagnostic
    raise RuntimeError("fixed gateway identity is invalid")


def _resolve_single_ipv4(hostname, port):
    addresses = _resolve_ipv4(hostname, port)
    if not addresses:
        return None
    if len(addresses) != 1:
        raise RuntimeError("fixed service resolution is ambiguous")
    return addresses[0]


def _resolve_ipv4(hostname, port):
    try:
        results = socket.getaddrinfo(
            hostname,
            port,
            family=socket.AF_INET,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as failure:
        if failure.errno in _ABSENT_RESOLUTION_ERRORS:
            return ()
        raise
    addresses = {
        result[4][0]
        for result in results
        if (
            len(result) >= 5
            and result[0] == socket.AF_INET
            and isinstance(result[4], tuple)
            and len(result[4]) >= 2
        )
    }
    if len(addresses) != len(results):
        raise RuntimeError("fixed IPv4 resolution was invalid")
    return tuple(sorted(addresses))


def _connects(host, port):
    try:
        with socket.create_connection(
            (host, port),
            timeout=SOCKET_TIMEOUT_SECONDS,
        ):
            return True
    except TimeoutError:
        return False
    except OSError as failure:
        if failure.errno in _EXPECTED_NEGATIVE_CONNECT_ERRORS:
            return False
        raise


def _operator_dns_resolves():
    try:
        addresses = socket.getaddrinfo(
            _OPERATOR_DNS_NAME,
            _OPERATOR_IMAPS_PORT,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as failure:
        if failure.errno in _ABSENT_RESOLUTION_ERRORS:
            return False
        raise
    return bool(addresses)


def _deadline_expired(_signal_number, _frame):
    raise DeadlineExpired


def _evaluate_without_deadline(data, arguments):
    if arguments:
        return 2, "INVALID_INVOCATION"
    try:
        operator_ip, host_ips = parse_input(data)
        diagnostic = network_diagnostic(operator_ip, host_ips)
    except InputError:
        return 2, "INVALID_INPUT"
    except BaseException:
        return 1, "CHECK_ERROR"
    if diagnostic is not None:
        return 1, diagnostic
    return 0, "OK"


def _arm_deadline():
    previous_handler = signal.signal(signal.SIGALRM, _deadline_expired)
    previous_timer = signal.setitimer(
        signal.ITIMER_REAL,
        MAX_WALL_SECONDS,
    )
    return previous_handler, previous_timer


def _restore_deadline(previous_handler, previous_timer):
    signal.setitimer(signal.ITIMER_REAL, 0)
    signal.signal(signal.SIGALRM, previous_handler)
    if previous_timer[0] > 0:
        signal.setitimer(
            signal.ITIMER_REAL,
            previous_timer[0],
            previous_timer[1],
        )


def evaluate(data, arguments):
    previous_handler, previous_timer = _arm_deadline()
    try:
        return _evaluate_without_deadline(data, arguments)
    finally:
        _restore_deadline(previous_handler, previous_timer)


def main():
    previous_handler, previous_timer = _arm_deadline()
    try:
        arguments = tuple(sys.argv[1:])
        if arguments:
            status, output = 2, "INVALID_INVOCATION"
        else:
            data = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
            status, output = _evaluate_without_deadline(data, arguments)
    except BaseException:
        status, output = 1, "CHECK_ERROR"
    finally:
        _restore_deadline(previous_handler, previous_timer)
    sys.stdout.write(output + "\n")
    sys.stdout.flush()
    return status


if __name__ == "__main__":
    raise SystemExit(main())
