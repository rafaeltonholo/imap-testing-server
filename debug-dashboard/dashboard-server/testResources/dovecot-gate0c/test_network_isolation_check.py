import errno
import importlib.util
import pathlib
import socket
import subprocess
import sys
import time
import unittest
from unittest import mock


sys.dont_write_bytecode = True

HELPER = pathlib.Path(__file__).with_name("network-isolation-check.py")


def load_helper():
    spec = importlib.util.spec_from_file_location(
        "task6_network_isolation_check",
        HELPER,
    )
    if spec is None or spec.loader is None:
        raise AssertionError("could not load fixed network-isolation helper")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class NetworkIsolationCheckPresenceTest(unittest.TestCase):
    def test_fixed_helper_exists_as_a_regular_file(self):
        self.assertTrue(HELPER.is_file())
        self.assertFalse(HELPER.is_symlink())

    def test_helper_defines_the_fixed_testable_contract(self):
        module = load_helper()

        for name in (
            "MAX_INPUT_BYTES",
            "MAX_HOSTS",
            "MAX_CONNECT_ATTEMPTS",
            "MAX_CONNECT_SECONDS",
            "MAX_WALL_SECONDS",
            "SOCKET_TIMEOUT_SECONDS",
            "DeadlineExpired",
            "InputError",
            "parse_input",
            "network_diagnostic",
            "evaluate",
        ):
            self.assertTrue(hasattr(module, name), name)
        self.assertEqual(1024, module.MAX_INPUT_BYTES)
        self.assertEqual(32, module.MAX_HOSTS)
        self.assertEqual(37, module.MAX_CONNECT_ATTEMPTS)
        self.assertEqual(18.5, module.MAX_CONNECT_SECONDS)
        self.assertEqual(20.0, module.MAX_WALL_SECONDS)
        self.assertEqual(0.5, module.SOCKET_TIMEOUT_SECONDS)
        self.assertTrue(issubclass(module.InputError, Exception))
        self.assertTrue(callable(module.parse_input))
        self.assertTrue(callable(module.network_diagnostic))
        self.assertTrue(callable(module.evaluate))

    def test_helper_has_no_environment_command_or_dependency_knobs(self):
        source = HELPER.read_text(encoding="utf-8")

        for forbidden in (
            "os.environ",
            "os.getenv",
            "argparse",
            "subprocess",
            "requests",
            "urllib",
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn('if __name__ == "__main__":', source)


class NetworkIsolationInputTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.helper = load_helper()

    def test_accepts_one_operator_then_unique_canonical_host_ipv4_lines(self):
        operator, hosts = self.helper.parse_input(
            b"operator 172.31.0.5\n"
            b"host 192.168.64.1\n"
            b"host 10.0.0.8\n",
        )

        self.assertEqual("172.31.0.5", operator)
        self.assertEqual(("192.168.64.1", "10.0.0.8"), hosts)

    def test_accepts_at_most_thirty_two_host_lines(self):
        data = b"operator 172.31.0.5\n" + b"".join(
            f"host 10.0.0.{index}\n".encode("ascii")
            for index in range(1, 33)
        )

        _, hosts = self.helper.parse_input(data)

        self.assertEqual(32, len(hosts))

    def test_accepts_link_local_host_ipv4(self):
        operator, hosts = self.helper.parse_input(
            b"operator 172.31.0.5\n"
            b"host 169.254.23.9\n",
        )

        self.assertEqual("172.31.0.5", operator)
        self.assertEqual(("169.254.23.9",), hosts)

    def test_rejects_every_noncanonical_or_unbounded_input_shape(self):
        too_many_hosts = b"operator 172.31.0.5\n" + b"".join(
            f"host 10.0.0.{index}\n".encode("ascii")
            for index in range(1, 34)
        )
        invalid_inputs = (
            b"",
            b"operator 172.31.0.5",
            b"operator 172.31.0.5\n",
            b"host 192.168.64.1\noperator 172.31.0.5\n",
            b"operator 172.31.0.5\noperator 172.31.0.6\n"
            b"host 192.168.64.1\n",
            b"operator 172.31.0.5\npeer 192.168.64.1\n",
            b"operator 172.31.0.5\nhost 192.168.64.1\n"
            b"host 192.168.64.1\n",
            b"operator 172.31.0.5\nhost 172.31.0.5\n",
            b"operator 172.31.000.005\nhost 192.168.64.1\n",
            b"operator 172.31.0.5\nhost 192.168.064.001\n",
            b"operator 172.31.0.5\nhost ::1\n",
            b"operator 172.31.0.5\r\nhost 192.168.64.1\r\n",
            b"operator 172.31.0.5\nhost 192.168.64.1 \n",
            b"operator  172.31.0.5\nhost 192.168.64.1\n",
            b"operator\t172.31.0.5\nhost 192.168.64.1\n",
            b"operator 127.0.0.1\nhost 192.168.64.1\n",
            b"operator 172.31.0.5\nhost 0.0.0.0\n",
            b"operator 172.31.0.5\nhost 224.0.0.1\n",
            "operator 172.31.0.5\nhost 192.168.64.é\n".encode("utf-8"),
            too_many_hosts,
            b"x" * 1025,
        )

        for data in invalid_inputs:
            with self.subTest(data=data[:80]):
                with self.assertRaises(self.helper.InputError):
                    self.helper.parse_input(data)


class FakeConnection:
    def __enter__(self):
        return self

    def __exit__(self, _type, _value, _traceback):
        return False


class NetworkIsolationChecksTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.helper = load_helper()
        cls.operator = "172.31.0.5"
        cls.hosts = ("192.168.64.1", "10.0.0.8")
        cls.resolved_ips = {
            "host.docker.internal": "192.0.2.10",
            "gateway.docker.internal": "192.0.2.11",
            "task6-host-gateway": "192.0.2.12",
            "dovecot": "172.31.0.2",
        }

    def fixed_resolution(self, host, port, **_kwargs):
        if host == "dovecot-operator":
            raise socket.gaierror(socket.EAI_NONAME, "not found")
        address = self.resolved_ips[host]
        return [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                6,
                "",
                (address, port),
            ),
        ]

    def test_runs_only_the_fixed_checks_in_order(self):
        calls = []

        def connect(address, timeout):
            calls.append((address, timeout))
            if address == ("172.31.0.2", 31993):
                return FakeConnection()
            raise ConnectionRefusedError(errno.ECONNREFUSED, "refused")

        with mock.patch.object(
            self.helper.socket,
            "create_connection",
            side_effect=connect,
        ), mock.patch.object(
            self.helper.socket,
            "getaddrinfo",
            side_effect=self.fixed_resolution,
        ) as resolve:
            diagnostic = self.helper.network_diagnostic(
                self.operator,
                self.hosts,
            )

        self.assertIsNone(diagnostic)
        self.assertEqual(
            [
                mock.call(
                    "host.docker.internal",
                    2993,
                    family=socket.AF_INET,
                    type=socket.SOCK_STREAM,
                ),
                mock.call(
                    "gateway.docker.internal",
                    2993,
                    family=socket.AF_INET,
                    type=socket.SOCK_STREAM,
                ),
                mock.call(
                    "task6-host-gateway",
                    2993,
                    family=socket.AF_INET,
                    type=socket.SOCK_STREAM,
                ),
                mock.call(
                    "dovecot",
                    31993,
                    family=socket.AF_INET,
                    type=socket.SOCK_STREAM,
                ),
                mock.call(
                    "dovecot-operator",
                    31993,
                    type=socket.SOCK_STREAM,
                ),
            ],
            resolve.call_args_list,
        )
        self.assertEqual(
            [
                (("172.31.0.2", 31993), 0.5),
                ((self.operator, 31993), 0.5),
                (("192.0.2.10", 2993), 0.5),
                (("192.0.2.11", 2993), 0.5),
                (("192.0.2.12", 2993), 0.5),
                ((self.hosts[0], 2993), 0.5),
                ((self.hosts[1], 2993), 0.5),
            ],
            calls,
        )

    def test_reports_a_fixed_label_when_dovecot_is_unreachable(self):
        with mock.patch.object(
            self.helper.socket,
            "create_connection",
            side_effect=ConnectionRefusedError(
                errno.ECONNREFUSED,
                "secret transport detail",
            ),
        ), mock.patch.object(
            self.helper.socket,
            "getaddrinfo",
            side_effect=self.fixed_resolution,
        ) as resolve:
            diagnostic = self.helper.network_diagnostic(
                self.operator,
                self.hosts,
            )

        self.assertEqual("DOVECOT_UNREACHABLE", diagnostic)
        self.assertEqual(
            [
                mock.call(
                    "host.docker.internal",
                    2993,
                    family=socket.AF_INET,
                    type=socket.SOCK_STREAM,
                ),
                mock.call(
                    "gateway.docker.internal",
                    2993,
                    family=socket.AF_INET,
                    type=socket.SOCK_STREAM,
                ),
                mock.call(
                    "task6-host-gateway",
                    2993,
                    family=socket.AF_INET,
                    type=socket.SOCK_STREAM,
                ),
                mock.call(
                    "dovecot",
                    31993,
                    family=socket.AF_INET,
                    type=socket.SOCK_STREAM,
                ),
            ],
            resolve.call_args_list,
        )

    def test_reports_a_fixed_label_when_operator_dns_resolves(self):
        with mock.patch.object(
            self.helper.socket,
            "create_connection",
            return_value=FakeConnection(),
        ), mock.patch.object(
            self.helper.socket,
            "getaddrinfo",
            side_effect=lambda host, port, **_kwargs: [
                (
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    6,
                    "",
                    (
                        self.resolved_ips.get(host, "172.31.0.99"),
                        port,
                    ),
                ),
            ],
        ):
            diagnostic = self.helper.network_diagnostic(
                self.operator,
                self.hosts,
            )

        self.assertEqual("OPERATOR_DNS_RESOLVED", diagnostic)

    def test_requires_every_fixed_gateway_to_resolve_before_connecting(self):
        cases = (
            (
                "host.docker.internal",
                "HOST_DOCKER_INTERNAL_UNRESOLVED",
            ),
            (
                "gateway.docker.internal",
                "GATEWAY_DOCKER_INTERNAL_UNRESOLVED",
            ),
            (
                "task6-host-gateway",
                "TASK6_HOST_GATEWAY_UNRESOLVED",
            ),
        )

        for unresolved, expected in cases:
            resolutions = []

            def resolve(host, port, **kwargs):
                resolutions.append((host, port, kwargs))
                if host == unresolved:
                    raise socket.gaierror(
                        socket.EAI_NONAME,
                        "not found",
                    )
                return self.fixed_resolution(host, port, **kwargs)

            with self.subTest(expected=expected), mock.patch.object(
                self.helper.socket,
                "getaddrinfo",
                side_effect=resolve,
            ), mock.patch.object(
                self.helper.socket,
                "create_connection",
            ) as connect:
                diagnostic = self.helper.network_diagnostic(
                    self.operator,
                    self.hosts,
                )

            self.assertEqual(expected, diagnostic)
            self.assertEqual(
                [
                    (
                        "host.docker.internal",
                        2993,
                        {
                            "family": socket.AF_INET,
                            "type": socket.SOCK_STREAM,
                        },
                    ),
                    (
                        "gateway.docker.internal",
                        2993,
                        {
                            "family": socket.AF_INET,
                            "type": socket.SOCK_STREAM,
                        },
                    ),
                    (
                        "task6-host-gateway",
                        2993,
                        {
                            "family": socket.AF_INET,
                            "type": socket.SOCK_STREAM,
                        },
                    ),
                ],
                resolutions,
            )
            connect.assert_not_called()

    def test_worst_case_host_inventory_has_an_explicit_duration_contract(self):
        hosts = tuple(f"10.0.0.{index}" for index in range(1, 33))
        calls = []

        def connect(address, timeout):
            calls.append((address, timeout))
            if address == ("172.31.0.2", 31993):
                return FakeConnection()
            raise ConnectionRefusedError(errno.ECONNREFUSED, "refused")

        with mock.patch.object(
            self.helper.socket,
            "create_connection",
            side_effect=connect,
        ), mock.patch.object(
            self.helper.socket,
            "getaddrinfo",
            side_effect=self.fixed_resolution,
        ):
            diagnostic = self.helper.network_diagnostic(
                self.operator,
                hosts,
            )

        self.assertIsNone(diagnostic)
        self.assertEqual(37, len(calls))
        self.assertTrue(
            all(timeout == self.helper.SOCKET_TIMEOUT_SECONDS for _, timeout in calls),
        )
        self.assertEqual(37, self.helper.MAX_CONNECT_ATTEMPTS)
        self.assertEqual(18.5, self.helper.MAX_CONNECT_SECONDS)

    def test_reports_only_fixed_labels_for_every_reachable_negative_path(self):
        cases = (
            (self.operator, 31993, "OPERATOR_IP_REACHABLE"),
            ("host.docker.internal", 2993, "HOST_DOCKER_INTERNAL_REACHABLE"),
            (
                "gateway.docker.internal",
                2993,
                "GATEWAY_DOCKER_INTERNAL_REACHABLE",
            ),
            ("task6-host-gateway", 2993, "TASK6_HOST_GATEWAY_REACHABLE"),
            (self.hosts[0], 2993, "HOST_IP_REACHABLE"),
        )

        for reachable_host, reachable_port, expected in cases:
            reachable_address = self.resolved_ips.get(
                reachable_host,
                reachable_host,
            )

            def connect(address, timeout):
                self.assertEqual(0.5, timeout)
                if address == ("172.31.0.2", 31993):
                    return FakeConnection()
                if address == (reachable_address, reachable_port):
                    return FakeConnection()
                raise ConnectionRefusedError(
                    errno.ECONNREFUSED,
                    "refused",
                )

            with self.subTest(expected=expected), mock.patch.object(
                self.helper.socket,
                "create_connection",
                side_effect=connect,
            ), mock.patch.object(
                self.helper.socket,
                "getaddrinfo",
                side_effect=self.fixed_resolution,
            ):
                diagnostic = self.helper.network_diagnostic(
                    self.operator,
                    self.hosts,
                )

            self.assertEqual(expected, diagnostic)

    def test_gateway_connections_use_the_resolved_numeric_ipv4_once(self):
        gateway_ips = {
            "host.docker.internal": "192.0.2.10",
            "gateway.docker.internal": "192.0.2.11",
            "task6-host-gateway": "192.0.2.12",
            "dovecot": "172.31.0.2",
        }
        calls = []

        def resolve(host, port, **_kwargs):
            if host == "dovecot-operator":
                raise socket.gaierror(socket.EAI_NONAME, "not found")
            address = gateway_ips[host]
            return [
                (
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    6,
                    "",
                    (address, port),
                ),
            ]

        def connect(address, timeout):
            calls.append((address, timeout))
            if address in {
                ("dovecot", 31993),
                ("172.31.0.2", 31993),
            }:
                return FakeConnection()
            raise ConnectionRefusedError(errno.ECONNREFUSED, "refused")

        with mock.patch.object(
            self.helper.socket,
            "getaddrinfo",
            side_effect=resolve,
        ), mock.patch.object(
            self.helper.socket,
            "create_connection",
            side_effect=connect,
        ):
            diagnostic = self.helper.network_diagnostic(
                self.operator,
                self.hosts,
            )

        self.assertIsNone(diagnostic)
        for hostname, address in gateway_ips.items():
            if hostname == "dovecot":
                continue
            self.assertIn(((address, 2993), 0.5), calls)
            self.assertNotIn(((hostname, 2993), 0.5), calls)

    def test_transient_resolution_and_resource_exhaustion_fail_closed(self):
        valid_input = (
            b"operator 172.31.0.5\n"
            b"host 192.168.64.1\n"
        )

        with mock.patch.object(
            self.helper.socket,
            "getaddrinfo",
            side_effect=socket.gaierror(
                socket.EAI_AGAIN,
                "temporary resolver failure",
            ),
        ):
            self.assertEqual(
                (1, "CHECK_ERROR"),
                self.helper.evaluate(valid_input, ()),
            )

        def ambiguous_resolution(host, port, **kwargs):
            resolved = self.fixed_resolution(host, port, **kwargs)
            if host == "gateway.docker.internal":
                return resolved + [
                    (
                        socket.AF_INET,
                        socket.SOCK_STREAM,
                        6,
                        "",
                        ("192.0.2.99", port),
                    ),
                ]
            return resolved

        with mock.patch.object(
            self.helper.socket,
            "getaddrinfo",
            side_effect=ambiguous_resolution,
        ), mock.patch.object(
            self.helper.socket,
            "create_connection",
        ) as connect:
            self.assertEqual(
                (1, "CHECK_ERROR"),
                self.helper.evaluate(valid_input, ()),
            )
        connect.assert_not_called()

        def resolve(host, port, **_kwargs):
            address = {
                "host.docker.internal": "192.0.2.10",
                "gateway.docker.internal": "192.0.2.11",
                "task6-host-gateway": "192.0.2.12",
                "dovecot": "172.31.0.2",
            }.get(host)
            if address is None:
                raise socket.gaierror(socket.EAI_NONAME, "not found")
            return [
                (
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    6,
                    "",
                    (address, port),
                ),
            ]

        with mock.patch.object(
            self.helper.socket,
            "getaddrinfo",
            side_effect=resolve,
        ), mock.patch.object(
            self.helper.socket,
            "create_connection",
            side_effect=OSError(errno.EMFILE, "descriptor exhaustion"),
        ):
            self.assertEqual(
                (1, "CHECK_ERROR"),
                self.helper.evaluate(valid_input, ()),
            )

    def test_blocking_resolution_has_a_process_local_wall_deadline(self):
        valid_input = (
            b"operator 172.31.0.5\n"
            b"host 192.168.64.1\n"
        )

        def blocking_resolution(*_args, **_kwargs):
            time.sleep(0.2)
            raise socket.gaierror(socket.EAI_NONAME, "not found")

        started = time.monotonic()
        with mock.patch.object(
            self.helper,
            "MAX_WALL_SECONDS",
            0.02,
            create=True,
        ), mock.patch.object(
            self.helper.socket,
            "getaddrinfo",
            side_effect=blocking_resolution,
        ):
            result = self.helper.evaluate(valid_input, ())
        elapsed = time.monotonic() - started

        self.assertEqual((1, "CHECK_ERROR"), result)
        self.assertLess(elapsed, 0.15)


class NetworkIsolationEvaluationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.helper = load_helper()
        cls.valid_input = (
            b"operator 172.31.0.5\n"
            b"host 192.168.64.1\n"
        )

    def test_returns_ok_only_after_all_fixed_checks_pass(self):
        with mock.patch.object(
            self.helper,
            "network_diagnostic",
            return_value=None,
        ) as checks:
            status, output = self.helper.evaluate(self.valid_input, ())

        self.assertEqual((0, "OK"), (status, output))
        checks.assert_called_once_with("172.31.0.5", ("192.168.64.1",))

    def test_rejects_arguments_and_input_without_running_checks(self):
        cases = (
            ((b"secret input", ("secret-argument",)), "INVALID_INVOCATION"),
            ((b"secret input", ()), "INVALID_INPUT"),
        )
        for arguments, expected in cases:
            with self.subTest(expected=expected), mock.patch.object(
                self.helper,
                "network_diagnostic",
            ) as checks:
                status, output = self.helper.evaluate(*arguments)

            self.assertEqual(2, status)
            self.assertEqual(expected, output)
            checks.assert_not_called()
            self.assertNotIn("secret", output)

    def test_converts_check_and_unexpected_failures_to_fixed_output(self):
        with mock.patch.object(
            self.helper,
            "network_diagnostic",
            return_value="HOST_IP_REACHABLE",
        ):
            self.assertEqual(
                (1, "HOST_IP_REACHABLE"),
                self.helper.evaluate(self.valid_input, ()),
            )
        with mock.patch.object(
            self.helper,
            "network_diagnostic",
            side_effect=RuntimeError("secret unexpected detail"),
        ):
            self.assertEqual(
                (1, "CHECK_ERROR"),
                self.helper.evaluate(self.valid_input, ()),
            )

    def test_isolated_cli_emits_only_one_fixed_line(self):
        cases = (
            (
                [sys.executable, "-I", str(HELPER), "secret-argument"],
                b"",
                2,
                "INVALID_INVOCATION\n",
            ),
            (
                [sys.executable, "-I", str(HELPER)],
                b"secret malformed input\n",
                2,
                "INVALID_INPUT\n",
            ),
        )
        for command, stdin, expected_status, expected_stdout in cases:
            with self.subTest(expected_stdout=expected_stdout):
                result = subprocess.run(
                    command,
                    input=stdin,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                    timeout=2,
                )

            self.assertEqual(expected_status, result.returncode)
            self.assertEqual(expected_stdout, result.stdout.decode("ascii"))
            self.assertEqual(b"", result.stderr)
            self.assertNotIn(b"secret", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
