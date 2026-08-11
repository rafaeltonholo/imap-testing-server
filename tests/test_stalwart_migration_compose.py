from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
BASE_COMPOSE = REPOSITORY_ROOT / "docker-compose.yml"
MIGRATION_COMPOSE = REPOSITORY_ROOT / "docker-compose.stalwart-migration.yml"

RECOVERY_ENV_VARIABLE = "STALWART_MIGRATION_RECOVERY_ENV_FILE"
CONFIG_DIR_VARIABLE = "STALWART_MIGRATION_CONFIG_DIR"
DATA_DIR_VARIABLE = "STALWART_MIGRATION_DATA_DIR"
REQUIRED_PATH_VARIABLES = (
    RECOVERY_ENV_VARIABLE,
    CONFIG_DIR_VARIABLE,
    DATA_DIR_VARIABLE,
)
CONFIG_COMMAND = [
    "docker",
    "compose",
    "-f",
    str(BASE_COMPOSE),
    "-f",
    str(MIGRATION_COMPOSE),
    "config",
    "--no-env-resolution",
    "--format",
    "json",
]
EXPECTED_ENVIRONMENT = {
    "STALWART_PUBLIC_URL": "http://127.0.0.1:8443",
    "STALWART_RECOVERY_ADMIN": "review-placeholder:review-placeholder",
    "STALWART_RECOVERY_MODE": "1",
    "STALWART_RECOVERY_MODE_PORT": "8080",
}
EXPECTED_RECOVERY_ENV_FILE = (
    "STALWART_RECOVERY_ADMIN="
    "review-placeholder:review-placeholder\n"
)
EXPECTED_SERVICE_KEYS = {
    "command",
    "container_name",
    "depends_on",
    "entrypoint",
    "environment",
    "healthcheck",
    "image",
    "networks",
    "ports",
    "profiles",
    "restart",
    "user",
    "volumes",
}
OWNER_SERVICE = "stalwart-migration-data-owner"
EXPECTED_OWNER_SERVICE_KEYS = {
    "command",
    "entrypoint",
    "image",
    "networks",
    "profiles",
    "restart",
    "user",
    "volumes",
}
EXPECTED_OWNER_COMMAND = [
    "chown -R 2000:2000 /var/lib/stalwart && "
    "chmod 0700 /var/lib/stalwart",
]
EXPECTED_STALWART_IMAGE = (
    "stalwartlabs/stalwart:v0.16.17@"
    "sha256:a8108e19bd927e172d4d8c128907b8dfc93fd180ae8ee07dccdd42cb97eb9dfa"
)


def render_compose(environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        CONFIG_COMMAND,
        cwd=REPOSITORY_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )


def parse_stalwart_service(
    completed: subprocess.CompletedProcess[str],
) -> dict[str, object]:
    if completed.returncode != 0:
        raise AssertionError("Compose model did not resolve")
    model = json.loads(completed.stdout)
    services = model.get("services")
    if not isinstance(services, dict):
        raise AssertionError("Compose services are malformed")
    service = services.get("stalwart")
    if not isinstance(service, dict):
        raise AssertionError("resolved Stalwart service is malformed")
    return service


def require_exact_environment(service: dict[str, object]) -> None:
    if service.get("environment") != EXPECTED_ENVIRONMENT:
        raise AssertionError("resolved migration environment is not exact")


def require_exact_owner_service(
    service: dict[str, object],
    *,
    config_dir: Path,
    data_dir: Path,
) -> None:
    expected = {
        "command": EXPECTED_OWNER_COMMAND,
        "entrypoint": ["/bin/sh", "-c"],
        "image": EXPECTED_STALWART_IMAGE,
        "networks": {"default": None},
        "profiles": ["stalwart-migration"],
        "restart": "no",
        "user": "0:0",
        "volumes": [
            {
                "type": "bind",
                "source": str(config_dir),
                "target": "/etc/stalwart",
                "read_only": True,
                "bind": {},
            },
            {
                "type": "bind",
                "source": str(data_dir),
                "target": "/var/lib/stalwart",
                "bind": {},
            },
        ],
    }
    if service != expected or set(service) != EXPECTED_OWNER_SERVICE_KEYS:
        raise AssertionError("resolved migration data owner is not exact")


def require_exact_owner_dependency(service: dict[str, object]) -> None:
    if service.get("depends_on") != {
        OWNER_SERVICE: {
            "condition": "service_completed_successfully",
            "required": True,
        },
    }:
        raise AssertionError("resolved migration owner dependency is not exact")


class StalwartMigrationComposeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary_directory = tempfile.TemporaryDirectory()
        cls.placeholder_root = Path(cls.temporary_directory.name).resolve()
        cls.recovery_env = cls.placeholder_root / "recovery.env"
        cls.config_dir = cls.placeholder_root / "config"
        cls.data_dir = cls.placeholder_root / "data"
        cls.recovery_env.write_text(
            EXPECTED_RECOVERY_ENV_FILE,
            encoding="utf-8",
        )
        cls.recovery_env.chmod(0o600)
        cls.config_dir.mkdir()
        cls.data_dir.mkdir()

        cls.required_environment = os.environ.copy()
        cls.required_environment.update(
            {
                RECOVERY_ENV_VARIABLE: str(cls.recovery_env),
                CONFIG_DIR_VARIABLE: str(cls.config_dir),
                DATA_DIR_VARIABLE: str(cls.data_dir),
            },
        )
        active_environment = cls.required_environment.copy()
        active_environment["COMPOSE_PROFILES"] = "stalwart-migration"
        cls.completed = render_compose(active_environment)
        cls.model = (
            json.loads(cls.completed.stdout)
            if cls.completed.returncode == 0
            else {}
        )
        inactive_environment = cls.required_environment.copy()
        inactive_environment.pop("COMPOSE_PROFILES", None)
        cls.inactive_completed = render_compose(inactive_environment)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary_directory.cleanup()

    def migration_service(self) -> dict[str, object]:
        self.assertEqual(
            self.completed.returncode,
            0,
            "migration overlay must resolve with installed Docker Compose:\n"
            f"{self.completed.stderr}",
        )
        services = self.model.get("services")
        self.assertIsInstance(services, dict)
        self.assertIn("stalwart", services)
        service = services["stalwart"]
        self.assertIsInstance(service, dict)
        return service

    def owner_service(self) -> dict[str, object]:
        self.assertEqual(
            self.completed.returncode,
            0,
            "migration overlay must resolve with installed Docker Compose:\n"
            f"{self.completed.stderr}",
        )
        services = self.model.get("services")
        self.assertIsInstance(services, dict)
        self.assertIn(OWNER_SERVICE, services)
        service = services[OWNER_SERVICE]
        self.assertIsInstance(service, dict)
        return service

    def test_resolved_service_has_dormant_pinned_migration_identity(self) -> None:
        service = self.migration_service()

        self.assertEqual(service.get("image"), EXPECTED_STALWART_IMAGE)
        self.assertEqual(
            service.get("container_name"),
            "mail-sandbox-stalwart-migration",
        )
        self.assertEqual(service.get("user"), "2000:2000")
        self.assertEqual(service.get("restart"), "no")
        self.assertEqual(service.get("profiles"), ["stalwart-migration"])
        self.assertIsNone(service.get("command"))
        self.assertIsNone(service.get("entrypoint"))
        self.assertEqual(service.get("networks"), {"default": None})
        require_exact_owner_dependency(service)
        self.assertEqual(set(service), EXPECTED_SERVICE_KEYS)

    def test_resolved_owner_is_exact_pinned_root_one_shot_with_only_fixed_binds(
        self,
    ) -> None:
        require_exact_owner_service(
            self.owner_service(),
            config_dir=self.config_dir,
            data_dir=self.data_dir,
        )

    def test_owner_audit_rejects_broad_mounts_commands_images_and_identity(
        self,
    ) -> None:
        service = self.owner_service()
        mutations = {
            "broad-mount": {
                **service,
                "volumes": [
                    {
                        "type": "bind",
                        "source": str(self.placeholder_root),
                        "target": "/var/lib/stalwart",
                        "bind": {},
                    },
                ],
            },
            "broad-command": {
                **service,
                "command": ["chown -R 2000:2000 /"],
            },
            "unpinned-image": {
                **service,
                "image": "stalwartlabs/stalwart:latest",
            },
            "non-root": {
                **service,
                "user": "2000:2000",
            },
            "unscoped": {
                **service,
                "profiles": [],
            },
        }
        for label, candidate in mutations.items():
            with self.subTest(label=label), self.assertRaisesRegex(
                AssertionError,
                "owner",
            ):
                require_exact_owner_service(
                    candidate,
                    config_dir=self.config_dir,
                    data_dir=self.data_dir,
                )

    def test_stalwart_dependency_audit_rejects_missing_or_weakened_owner_gate(
        self,
    ) -> None:
        service = self.migration_service()
        for label, dependency in {
            "missing": {},
            "started-only": {
                OWNER_SERVICE: {
                    "condition": "service_started",
                    "required": True,
                },
            },
            "optional": {
                OWNER_SERVICE: {
                    "condition": "service_completed_successfully",
                    "required": False,
                },
            },
        }.items():
            with self.subTest(label=label), self.assertRaisesRegex(
                AssertionError,
                "dependency",
            ):
                require_exact_owner_dependency(
                    {**service, "depends_on": dependency},
                )

    def test_profile_keeps_migration_service_dormant_by_default(self) -> None:
        self.assertEqual(
            self.inactive_completed.returncode,
            0,
            "inactive migration overlay must still resolve:\n"
            f"{self.inactive_completed.stderr}",
        )
        model = json.loads(self.inactive_completed.stdout)
        self.assertNotIn("stalwart", model.get("services", {}))
        self.assertNotIn(OWNER_SERVICE, model.get("services", {}))

    def test_each_missing_required_path_fails_closed_without_secret_output(
        self,
    ) -> None:
        for removed_variable in REQUIRED_PATH_VARIABLES:
            with self.subTest(removed_variable=removed_variable):
                environment = self.required_environment.copy()
                environment["COMPOSE_PROFILES"] = "stalwart-migration"
                environment.pop(removed_variable)

                completed = render_compose(environment)

                self.assertNotEqual(completed.returncode, 0)
                self.assertEqual(completed.stdout, "")
                self.assertIn("required", completed.stderr)
                self.assertIn(removed_variable, completed.stderr)
                self.assertLess(len(completed.stderr), 1024)
                for retained_variable in (
                    set(REQUIRED_PATH_VARIABLES) - {removed_variable}
                ):
                    self.assertNotIn(retained_variable, completed.stderr)
                self.assertNotIn("ADMIN_SECRET", completed.stderr)
                self.assertNotIn("review-placeholder", completed.stderr)

    def test_resolved_service_replaces_all_inherited_runtime_inputs(self) -> None:
        service = self.migration_service()

        require_exact_environment(service)
        self.assertEqual(
            service.get("ports"),
            [
                {
                    "mode": "ingress",
                    "target": 8080,
                    "published": "8443",
                    "protocol": "tcp",
                    "host_ip": "127.0.0.1",
                },
                {
                    "mode": "ingress",
                    "target": 587,
                    "published": "8587",
                    "protocol": "tcp",
                    "host_ip": "127.0.0.1",
                },
            ],
        )
        self.assertEqual(
            service.get("volumes"),
            [
                {
                    "type": "bind",
                    "source": str(self.config_dir),
                    "target": "/etc/stalwart",
                    "read_only": True,
                    "bind": {},
                },
                {
                    "type": "bind",
                    "source": str(self.data_dir),
                    "target": "/var/lib/stalwart",
                    "bind": {},
                },
            ],
        )

    def test_recovery_env_fixture_is_exact_and_owner_only(self) -> None:
        self.assertEqual(
            stat.S_IMODE(self.recovery_env.stat().st_mode),
            0o600,
        )
        if self.recovery_env.read_text(encoding="utf-8") != EXPECTED_RECOVERY_ENV_FILE:
            self.fail("recovery environment fixture is not exact")

    def test_overlay_uses_required_recovery_file_and_noncreating_binds(self) -> None:
        overlay = MIGRATION_COMPOSE.read_text(encoding="utf-8")
        self.assertIn("  stalwart: !override\n", overlay)
        self.assertEqual(overlay.count("!override"), 1)
        self.assertNotIn("!reset", overlay)
        self.assertEqual(overlay.count("    command:"), 1)
        self.assertEqual(overlay.count("    entrypoint:"), 1)
        migration_service = overlay[overlay.index("  stalwart: !override\n") :]
        self.assertNotIn("    command:", migration_service)
        self.assertNotIn("    entrypoint:", migration_service)
        env_file_start = overlay.index("    env_file:\n")
        environment_start = overlay.index("    environment:\n")

        self.assertEqual(
            overlay[env_file_start:environment_start],
            "    env_file:\n"
            "      - path: ${STALWART_MIGRATION_RECOVERY_ENV_FILE:?required}\n"
            "        required: true\n",
        )
        self.assertEqual(
            overlay.count(
                "${STALWART_MIGRATION_RECOVERY_ENV_FILE:?required}",
            ),
            1,
        )
        self.assertEqual(overlay.count("create_host_path: false"), 4)
        self.assertEqual(overlay.count("read_only: true"), 2)
        self.assertEqual(overlay.count("read_only: false"), 2)

    def test_environment_audit_rejects_legacy_and_extra_env_file_keys(self) -> None:
        for filename, unreviewed_line in (
            ("legacy.env", "ADMIN_SECRET=legacy-placeholder\n"),
            ("extra.env", "STALWART_UNREVIEWED=extra-placeholder\n"),
        ):
            with self.subTest(filename=filename):
                env_file = self.placeholder_root / filename
                env_file.write_text(
                    EXPECTED_RECOVERY_ENV_FILE + unreviewed_line,
                    encoding="utf-8",
                )
                env_file.chmod(0o600)
                environment = self.required_environment.copy()
                environment["COMPOSE_PROFILES"] = "stalwart-migration"
                environment[RECOVERY_ENV_VARIABLE] = str(env_file)

                completed = render_compose(environment)
                self.assertEqual(
                    completed.returncode,
                    0,
                    "mutated audit fixture must resolve before rejection",
                )
                service = parse_stalwart_service(completed)
                with self.assertRaisesRegex(
                    AssertionError,
                    "resolved migration environment is not exact",
                ):
                    require_exact_environment(service)

    def test_resolved_service_has_only_the_readiness_healthcheck(self) -> None:
        service = self.migration_service()

        self.assertEqual(
            service.get("healthcheck"),
            {
                "test": [
                    "CMD",
                    "curl",
                    "-fsS",
                    "http://127.0.0.1:8080/healthz/ready",
                ],
                "interval": "2s",
                "timeout": "2s",
                "retries": 30,
                "start_period": "2s",
            },
        )

    def test_resolved_service_contains_only_reviewed_jmap_and_submission_surface(self) -> None:
        service = self.migration_service()
        self.assertNotEqual(
            service.get("image"),
            "stalwartlabs/stalwart:latest",
        )

        environment = service.get("environment")
        self.assertIsInstance(environment, dict)
        self.assertNotIn("ADMIN_SECRET", environment)

        ports = service.get("ports")
        self.assertIsInstance(ports, list)
        exposed_ports = {
            int(port[field])
            for port in ports
            for field in ("target", "published")
        }
        self.assertEqual(exposed_ports, {587, 8080, 8443, 8587})

        volumes = service.get("volumes")
        self.assertIsInstance(volumes, list)
        for volume in volumes:
            with self.subTest(volume=volume):
                self.assertNotIn("/opt/stalwart", str(volume.get("target")))


if __name__ == "__main__":
    unittest.main()
