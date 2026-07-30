import importlib.util
import pathlib
import socket
import subprocess
import sys
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
            "SOCKET_TIMEOUT_SECONDS",
            "InputError",
            "parse_input",
            "network_diagnostic",
            "evaluate",
        ):
            self.assertTrue(hasattr(module, name), name)
        self.assertEqual(1024, module.MAX_INPUT_BYTES)
        self.assertEqual(32, module.MAX_HOSTS)
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

    def test_runs_only_the_fixed_checks_in_order(self):
        calls = []

        def connect(address, timeout):
            calls.append((address, timeout))
            if address == ("dovecot", 31993):
                return FakeConnection()
            raise OSError("fixed negative check")

        with mock.patch.object(
            self.helper.socket,
            "create_connection",
            side_effect=connect,
        ), mock.patch.object(
            self.helper.socket,
            "getaddrinfo",
            side_effect=socket.gaierror("not found"),
        ) as resolve:
            diagnostic = self.helper.network_diagnostic(
                self.operator,
                self.hosts,
            )

        self.assertIsNone(diagnostic)
        resolve.assert_called_once_with(
            "dovecot-operator",
            31993,
            type=socket.SOCK_STREAM,
        )
        self.assertEqual(
            [
                (("dovecot", 31993), 0.5),
                ((self.operator, 31993), 0.5),
                (("host.docker.internal", 2993), 0.5),
                (("gateway.docker.internal", 2993), 0.5),
                (("task6-host-gateway", 2993), 0.5),
                ((self.hosts[0], 2993), 0.5),
                ((self.hosts[1], 2993), 0.5),
            ],
            calls,
        )

    def test_reports_a_fixed_label_when_dovecot_is_unreachable(self):
        with mock.patch.object(
            self.helper.socket,
            "create_connection",
            side_effect=OSError("secret transport detail"),
        ), mock.patch.object(
            self.helper.socket,
            "getaddrinfo",
        ) as resolve:
            diagnostic = self.helper.network_diagnostic(
                self.operator,
                self.hosts,
            )

        self.assertEqual("DOVECOT_UNREACHABLE", diagnostic)
        resolve.assert_not_called()

    def test_reports_a_fixed_label_when_operator_dns_resolves(self):
        with mock.patch.object(
            self.helper.socket,
            "create_connection",
            return_value=FakeConnection(),
        ), mock.patch.object(
            self.helper.socket,
            "getaddrinfo",
            return_value=[object()],
        ):
            diagnostic = self.helper.network_diagnostic(
                self.operator,
                self.hosts,
            )

        self.assertEqual("OPERATOR_DNS_RESOLVED", diagnostic)

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
            def connect(address, timeout):
                self.assertEqual(0.5, timeout)
                if address == ("dovecot", 31993):
                    return FakeConnection()
                if address == (reachable_host, reachable_port):
                    return FakeConnection()
                raise OSError("fixed negative check")

            with self.subTest(expected=expected), mock.patch.object(
                self.helper.socket,
                "create_connection",
                side_effect=connect,
            ), mock.patch.object(
                self.helper.socket,
                "getaddrinfo",
                side_effect=socket.gaierror("not found"),
            ):
                diagnostic = self.helper.network_diagnostic(
                    self.operator,
                    self.hosts,
                )

            self.assertEqual(expected, diagnostic)


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
