from __future__ import annotations

import importlib.util
import io
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPOSITORY_ROOT / "scripts" / "stalwart_network.py"


network = None
IMPORT_ERROR: Exception | None = None
if SCRIPT_PATH.exists():
    try:
        spec = importlib.util.spec_from_file_location("stalwart_network", SCRIPT_PATH)
        assert spec is not None
        assert spec.loader is not None
        network = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = network
        spec.loader.exec_module(network)
    except Exception as exc:  # pragma: no cover - reported by existence test
        IMPORT_ERROR = exc


class ScriptPresenceTests(unittest.TestCase):
    def test_script_exists_and_imports(self) -> None:
        self.assertTrue(SCRIPT_PATH.is_file())
        self.assertIsNone(IMPORT_ERROR)


@unittest.skipIf(network is None, "stalwart_network.py is not implemented")
class NetworkResolutionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.repository = Path(self.temporary_directory.name).resolve()

    def test_explicit_ipv4_override_wins_without_detection(self) -> None:
        configuration = network.resolve_network_configuration(
            self.repository,
            environment={"MAIL_SANDBOX_LAN_HOST": "192.168.86.36"},
            detector=mock.Mock(side_effect=AssertionError("detector must not run")),
        )

        self.assertEqual(configuration.host, "192.168.86.36")
        self.assertEqual(configuration.public_url, "http://192.168.86.36:8443")
        self.assertEqual(
            configuration.environment_path,
            self.repository
            / "debug-dashboard"
            / ".runtime"
            / "stalwart"
            / "network.env",
        )

    def test_default_route_address_is_used_without_override(self) -> None:
        detector = mock.Mock(return_value="192.168.86.99")

        configuration = network.resolve_network_configuration(
            self.repository,
            environment={},
            detector=detector,
        )

        self.assertEqual(configuration.public_url, "http://192.168.86.99:8443")
        detector.assert_called_once_with()

    def test_safe_hostname_resolving_to_one_local_address_is_accepted(self) -> None:
        configuration = network.resolve_network_configuration(
            self.repository,
            environment={"MAIL_SANDBOX_LAN_HOST": "Mail-Box.local"},
            detector=mock.Mock(side_effect=AssertionError("detector must not run")),
            hostname_resolver=lambda _host: ("192.168.86.36",),
            local_ipv4_provider=lambda: {"192.168.86.36", "10.0.0.4"},
        )

        self.assertEqual(configuration.host, "mail-box.local")
        self.assertEqual(configuration.public_url, "http://mail-box.local:8443")

    def test_invalid_override_values_are_rejected(self) -> None:
        invalid_values = (
            "",
            " 192.168.86.36",
            "192.168.86.36 ",
            "192.168.86.36\nexample.test",
            "http://192.168.86.36",
            "https://mail.local",
            "192.168.86.36:8443",
            "mail.local/path",
            "user@mail.local",
            "0.0.0.0",
            "127.0.0.1",
            "169.254.10.1",
            "224.0.0.1",
            "255.255.255.255",
            "192.168.086.036",
            "::1",
            "[::1]",
            "*.local",
            "bad_name.local",
            "-mail.local",
            "mail-.local",
            "mail..local",
        )

        for value in invalid_values:
            with self.subTest(value=value):
                with self.assertRaisesRegex(
                    network.NetworkConfigurationError,
                    "MAIL_SANDBOX_LAN_HOST",
                ):
                    network.resolve_network_configuration(
                        self.repository,
                        environment={"MAIL_SANDBOX_LAN_HOST": value},
                        detector=lambda: "192.168.86.99",
                        hostname_resolver=lambda _host: ("192.168.86.36",),
                        local_ipv4_provider=lambda: {"192.168.86.36"},
                    )

    def test_hostname_must_resolve_to_exactly_one_ipv4(self) -> None:
        resolutions = ((), ("192.168.86.36", "192.168.86.37"))

        for resolved in resolutions:
            with self.subTest(resolved=resolved):
                with self.assertRaisesRegex(
                    network.NetworkConfigurationError,
                    "exactly one",
                ):
                    network.resolve_network_configuration(
                        self.repository,
                        environment={"MAIL_SANDBOX_LAN_HOST": "mail.local"},
                        detector=lambda: "192.168.86.99",
                        hostname_resolver=lambda _host, values=resolved: values,
                        local_ipv4_provider=lambda: {"192.168.86.36"},
                    )

    def test_hostname_resolution_must_be_eligible_and_local(self) -> None:
        cases = (
            (("127.0.0.1",), {"127.0.0.1"}),
            (("224.0.0.1",), {"224.0.0.1"}),
            (("192.168.86.37",), {"192.168.86.36"}),
        )

        for resolved, local_addresses in cases:
            with self.subTest(resolved=resolved, local_addresses=local_addresses):
                with self.assertRaisesRegex(
                    network.NetworkConfigurationError,
                    "local non-loopback IPv4",
                ):
                    network.resolve_network_configuration(
                        self.repository,
                        environment={"MAIL_SANDBOX_LAN_HOST": "mail.local"},
                        detector=lambda: "192.168.86.99",
                        hostname_resolver=lambda _host, values=resolved: values,
                        local_ipv4_provider=lambda values=local_addresses: values,
                    )

    def test_repository_must_be_an_existing_normalized_absolute_directory(self) -> None:
        invalid = (
            Path("relative"),
            self.repository / "missing",
            self.repository / "child" / "..",
        )

        for repository in invalid:
            with self.subTest(repository=repository):
                with self.assertRaisesRegex(ValueError, "repository"):
                    network.resolve_network_configuration(
                        repository,
                        environment={"MAIL_SANDBOX_LAN_HOST": "192.168.86.36"},
                    )


@unittest.skipIf(network is None, "stalwart_network.py is not implemented")
class DefaultRouteDetectionTests(unittest.TestCase):
    def test_darwin_uses_one_default_route_interface_and_one_ipv4(self) -> None:
        outputs = {
            ("netstat", "-rn", "-f", "inet"): """
Routing tables
Internet:
Destination        Gateway            Flags       Netif Expire
default            192.168.86.1       UGScg         en0
192.168.86/24      link#12            UCS           en0
""",
            ("ifconfig", "en0"): """
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST>
    inet 192.168.86.36 netmask 0xffffff00 broadcast 192.168.86.255
""",
        }

        detected = network.detect_default_route_ipv4(
            runner=lambda command: outputs[tuple(command)],
            platform_name="Darwin",
        )

        self.assertEqual(detected, "192.168.86.36")

    def test_linux_uses_unique_lowest_metric_default_route(self) -> None:
        outputs = {
            ("ip", "-4", "route", "show", "default"): (
                "default via 10.0.0.1 dev eth1 metric 200\n"
                "default via 192.168.86.1 dev eth0 metric 100\n"
            ),
            ("ip", "-o", "-4", "addr", "show", "dev", "eth0", "scope", "global"): (
                "2: eth0    inet 192.168.86.36/24 brd 192.168.86.255 scope global eth0\n"
            ),
        }

        detected = network.detect_default_route_ipv4(
            runner=lambda command: outputs[tuple(command)],
            platform_name="Linux",
        )

        self.assertEqual(detected, "192.168.86.36")

    def test_ambiguous_default_routes_fail_with_override_guidance(self) -> None:
        route_outputs = {
            "Darwin": """
default            192.168.86.1       UGScg         en0
default            10.0.0.1           UGScg         en1
""",
            "Linux": (
                "default via 192.168.86.1 dev eth0 metric 100\n"
                "default via 10.0.0.1 dev eth1 metric 100\n"
            ),
        }

        for platform_name, route_output in route_outputs.items():
            with self.subTest(platform_name=platform_name):
                runner = mock.Mock(return_value=route_output)
                with self.assertRaisesRegex(
                    network.NetworkConfigurationError,
                    "MAIL_SANDBOX_LAN_HOST",
                ):
                    network.detect_default_route_ipv4(
                        runner=runner,
                        platform_name=platform_name,
                    )

    def test_equal_metric_routes_on_same_interface_are_ambiguous(self) -> None:
        outputs = {
            ("ip", "-4", "route", "show", "default"): (
                "default via 192.168.86.1 dev eth0 metric 100\n"
                "default via 192.168.86.254 dev eth0 metric 100\n"
            ),
            ("ip", "-o", "-4", "addr", "show", "dev", "eth0", "scope", "global"): (
                "2: eth0 inet 192.168.86.36/24 scope global eth0\n"
            ),
        }

        with self.assertRaisesRegex(
            network.NetworkConfigurationError,
            "default-route interface",
        ):
            network.detect_default_route_ipv4(
                runner=lambda command: outputs[tuple(command)],
                platform_name="Linux",
            )

    def test_missing_or_multiple_interface_addresses_fail(self) -> None:
        address_outputs = (
            "",
            (
                "2: eth0 inet 192.168.86.36/24 scope global eth0\n"
                "2: eth0 inet 192.168.86.37/24 scope global secondary eth0\n"
            ),
        )

        for address_output in address_outputs:
            with self.subTest(address_output=address_output):
                outputs = {
                    ("ip", "-4", "route", "show", "default"): (
                        "default via 192.168.86.1 dev eth0 metric 100\n"
                    ),
                    (
                        "ip",
                        "-o",
                        "-4",
                        "addr",
                        "show",
                        "dev",
                        "eth0",
                        "scope",
                        "global",
                    ): address_output,
                }
                with self.assertRaisesRegex(
                    network.NetworkConfigurationError,
                    "MAIL_SANDBOX_LAN_HOST",
                ):
                    network.detect_default_route_ipv4(
                        runner=lambda command: outputs[tuple(command)],
                        platform_name="Linux",
                    )

    def test_unsupported_platform_and_command_failure_are_actionable(self) -> None:
        with self.assertRaisesRegex(
            network.NetworkConfigurationError,
            "MAIL_SANDBOX_LAN_HOST",
        ):
            network.detect_default_route_ipv4(
                runner=lambda _command: "",
                platform_name="Windows",
            )

        def fail(_command: list[str]) -> str:
            raise OSError("command unavailable")

        with self.assertRaisesRegex(
            network.NetworkConfigurationError,
            "MAIL_SANDBOX_LAN_HOST",
        ):
            network.detect_default_route_ipv4(runner=fail, platform_name="Linux")


@unittest.skipIf(network is None, "stalwart_network.py is not implemented")
class NetworkEnvironmentFileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.repository = Path(self.temporary_directory.name).resolve()
        self.configuration = network.resolve_network_configuration(
            self.repository,
            environment={"MAIL_SANDBOX_LAN_HOST": "192.168.86.36"},
        )

    def test_write_is_exact_atomic_and_owner_only(self) -> None:
        target = network.write_network_environment(self.configuration)

        self.assertEqual(
            target.read_bytes(),
            b"STALWART_PUBLIC_URL=http://192.168.86.36:8443\n",
        )
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(target.parent.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(target.parent.parent.stat().st_mode), 0o700)
        self.assertEqual(list(target.parent.glob("network.env.tmp-*")), [])

    def test_write_replaces_existing_content_and_modes_idempotently(self) -> None:
        target = self.configuration.environment_path
        target.parent.mkdir(parents=True, mode=0o755)
        target.parent.parent.chmod(0o755)
        target.write_text("STALWART_PUBLIC_URL=http://old.local:8443\n", encoding="utf-8")
        target.chmod(0o644)

        first = network.write_network_environment(self.configuration)
        second = network.write_network_environment(self.configuration)

        self.assertEqual(first, second)
        self.assertEqual(
            second.read_bytes(),
            b"STALWART_PUBLIC_URL=http://192.168.86.36:8443\n",
        )
        self.assertEqual(stat.S_IMODE(second.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(second.parent.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(second.parent.parent.stat().st_mode), 0o700)
        self.assertEqual(list(second.parent.iterdir()), [second])

    def test_symlinked_runtime_ancestor_is_rejected(self) -> None:
        dashboard = self.repository / "debug-dashboard"
        dashboard.mkdir()
        outside = self.repository / "outside"
        outside.mkdir()
        (dashboard / ".runtime").symlink_to(outside, target_is_directory=True)

        with self.assertRaisesRegex(
            network.NetworkConfigurationError,
            "symbolic link",
        ):
            network.write_network_environment(self.configuration)

        self.assertEqual(list(outside.iterdir()), [])

    def test_existing_dashboard_directory_mode_is_preserved(self) -> None:
        dashboard = self.repository / "debug-dashboard"
        dashboard.mkdir(mode=0o700)

        network.write_network_environment(self.configuration)

        self.assertEqual(stat.S_IMODE(dashboard.stat().st_mode), 0o700)

    def test_forged_configuration_cannot_write_multiple_environment_lines(self) -> None:
        forged = network.NetworkConfiguration(
            repository=self.repository,
            host="192.168.86.36\nINJECTED=true",
            public_url="http://192.168.86.36\nINJECTED=true:8443",
            environment_path=self.configuration.environment_path,
        )

        with self.assertRaises(network.NetworkConfigurationError):
            network.write_network_environment(forged)

        self.assertFalse(forged.environment_path.exists())

    def test_failed_atomic_replace_preserves_old_file_and_cleans_temporary(self) -> None:
        target = network.write_network_environment(self.configuration)
        original = target.read_bytes()
        replacement = network.resolve_network_configuration(
            self.repository,
            environment={"MAIL_SANDBOX_LAN_HOST": "192.168.86.37"},
        )

        with mock.patch.object(network.os, "replace", side_effect=OSError("boom")):
            with self.assertRaisesRegex(OSError, "boom"):
                network.write_network_environment(replacement)

        self.assertEqual(target.read_bytes(), original)
        self.assertEqual(list(target.parent.glob("network.env.tmp-*")), [])

    def test_loader_requires_exact_content_regular_file_and_owner_modes(self) -> None:
        target = network.write_network_environment(self.configuration)
        loaded = network.load_network_configuration(self.repository)
        self.assertEqual(loaded, self.configuration)

        invalid_payloads = (
            b"STALWART_PUBLIC_URL=http://192.168.86.36:8443",
            b"STALWART_PUBLIC_URL=http://192.168.86.36:8443\nEXTRA=true\n",
            b"OTHER=http://192.168.86.36:8443\n",
            b"STALWART_PUBLIC_URL=http://127.0.0.1:8443\n",
        )
        for payload in invalid_payloads:
            with self.subTest(payload=payload):
                target.write_bytes(payload)
                target.chmod(0o600)
                with self.assertRaises(network.NetworkConfigurationError):
                    network.load_network_configuration(self.repository)

        target.write_bytes(
            b"STALWART_PUBLIC_URL=http://192.168.86.36:8443\n",
        )
        target.chmod(0o644)
        with self.assertRaisesRegex(network.NetworkConfigurationError, "0600"):
            network.load_network_configuration(self.repository)

    def test_loader_rejects_symlinked_file(self) -> None:
        target = self.configuration.environment_path
        target.parent.mkdir(parents=True, mode=0o700)
        target.parent.parent.chmod(0o700)
        outside = self.repository / "outside.env"
        outside.write_bytes(
            b"STALWART_PUBLIC_URL=http://192.168.86.36:8443\n",
        )
        outside.chmod(0o600)
        target.symlink_to(outside)

        with self.assertRaisesRegex(
            network.NetworkConfigurationError,
            "regular file",
        ):
            network.load_network_configuration(self.repository)

    def test_loader_rejects_symlinked_dashboard_ancestor(self) -> None:
        outside = self.repository / "outside"
        outside.mkdir()
        runtime = outside / ".runtime"
        runtime.mkdir(mode=0o700)
        directory = runtime / "stalwart"
        directory.mkdir(mode=0o700)
        target = directory / "network.env"
        target.write_bytes(
            b"STALWART_PUBLIC_URL=http://192.168.86.36:8443\n",
        )
        target.chmod(0o600)
        (self.repository / "debug-dashboard").symlink_to(
            outside,
            target_is_directory=True,
        )

        with self.assertRaisesRegex(
            network.NetworkConfigurationError,
            "debug-dashboard",
        ):
            network.load_network_configuration(self.repository)

    def test_cli_prepare_and_show_print_only_public_url(self) -> None:
        prepare_output = io.StringIO()
        with redirect_stdout(prepare_output):
            exit_code = network.main(
                ["prepare", "--repository", str(self.repository)],
                environment={"MAIL_SANDBOX_LAN_HOST": "192.168.86.36"},
            )
        self.assertEqual(exit_code, 0)
        self.assertEqual(prepare_output.getvalue(), "http://192.168.86.36:8443\n")

        show_output = io.StringIO()
        with redirect_stdout(show_output):
            exit_code = network.main(
                ["show", "--repository", str(self.repository)],
                environment={},
            )
        self.assertEqual(exit_code, 0)
        self.assertEqual(show_output.getvalue(), "http://192.168.86.36:8443\n")


if __name__ == "__main__":
    unittest.main()
