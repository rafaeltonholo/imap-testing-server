"""Fixed Task 6 network-isolation proof helper."""

import ipaddress
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
    ("host.docker.internal", "HOST_DOCKER_INTERNAL_REACHABLE"),
    ("gateway.docker.internal", "GATEWAY_DOCKER_INTERNAL_REACHABLE"),
    ("task6-host-gateway", "TASK6_HOST_GATEWAY_REACHABLE"),
)


class InputError(Exception):
    """The bounded public network-target input is invalid."""


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
    if not _connects(*_ORDINARY_DOVECOT):
        return "DOVECOT_UNREACHABLE"
    if _operator_dns_resolves():
        return "OPERATOR_DNS_RESOLVED"
    if _connects(operator_ip, _OPERATOR_IMAPS_PORT):
        return "OPERATOR_IP_REACHABLE"
    for hostname, diagnostic in _FIXED_HOST_GATEWAYS:
        if _connects(hostname, _OPERATOR_HOST_PORT):
            return diagnostic
    for host_ip in host_ips:
        if _connects(host_ip, _OPERATOR_HOST_PORT):
            return "HOST_IP_REACHABLE"
    return None


def _connects(host, port):
    try:
        with socket.create_connection(
            (host, port),
            timeout=SOCKET_TIMEOUT_SECONDS,
        ):
            return True
    except OSError:
        return False


def _operator_dns_resolves():
    try:
        socket.getaddrinfo(
            _OPERATOR_DNS_NAME,
            _OPERATOR_IMAPS_PORT,
            type=socket.SOCK_STREAM,
        )
        return True
    except socket.gaierror:
        return False


def evaluate(data, arguments):
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


def main():
    data = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    status, output = evaluate(data, tuple(sys.argv[1:]))
    sys.stdout.write(output + "\n")
    sys.stdout.flush()
    return status


if __name__ == "__main__":
    raise SystemExit(main())
