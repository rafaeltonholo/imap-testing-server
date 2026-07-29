from __future__ import annotations

from contextlib import contextmanager
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPOSITORY_ROOT / "scripts" / "capture_stalwart_v015.py"

capture = None
IMPORT_ERROR: Exception | None = None
if SCRIPT_PATH.exists():
    try:
        spec = importlib.util.spec_from_file_location("capture_stalwart_v015", SCRIPT_PATH)
        assert spec is not None
        assert spec.loader is not None
        capture = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = capture
        spec.loader.exec_module(capture)
    except Exception as exc:  # pragma: no cover - reported by the existence test
        IMPORT_ERROR = exc


class ScriptExistenceTest(unittest.TestCase):
    def test_capture_module_exists_and_imports(self) -> None:
        self.assertIsNotNone(
            capture,
            f"{SCRIPT_PATH.relative_to(REPOSITORY_ROOT)} must import cleanly: {IMPORT_ERROR}",
        )


@unittest.skipIf(capture is None, "capture script has not been implemented yet")
class ManifestTests(unittest.TestCase):
    def test_manifest_records_every_directory_and_regular_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "empty").mkdir()
            (root / "nested").mkdir()
            (root / "nested" / "alpha").write_bytes(b"alpha")
            (root / "zeta").write_bytes(b"z")

            manifest = capture.manifest_tree(root)

            self.assertEqual(manifest["file_count"], 2)
            self.assertEqual(manifest["directory_count"], 2)
            self.assertEqual(manifest["total_bytes"], 6)
            self.assertEqual(
                [(entry["path"], entry["type"]) for entry in manifest["entries"]],
                [
                    ("empty", "directory"),
                    ("nested", "directory"),
                    ("nested/alpha", "file"),
                    ("zeta", "file"),
                ],
            )
            file_entry = manifest["entries"][2]
            self.assertEqual(file_entry["size"], 5)
            self.assertEqual(
                file_entry["sha256"],
                "8ed3f6ad685b959ead7022518e1af76cd816f8e8ec7ccdda1ed4018e8f2223f8",
            )

    def test_manifest_refuses_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "target").write_text("data", encoding="utf-8")
            (root / "link").symlink_to("target")

            with self.assertRaisesRegex(capture.CaptureError, "symlink"):
                capture.manifest_tree(root)

    def test_manifest_refuses_non_regular_entries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            fifo = root / "pipe"
            os.mkfifo(fifo)

            with self.assertRaisesRegex(capture.CaptureError, "non-regular"):
                capture.manifest_tree(root)

    def test_manifest_refuses_final_component_swap_during_hash(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            entry = root / "CURRENT"
            entry.write_bytes(b"expected")
            outside = root.parent / f"{root.name}-outside"
            outside.write_bytes(b"must-not-hash")
            self.addCleanup(lambda: outside.unlink(missing_ok=True))
            original_open = capture.os.open
            swapped = False

            def swapping_open(path: object, flags: int, *args: object, **kwargs: object) -> int:
                nonlocal swapped
                if Path(path) == entry and not swapped:
                    swapped = True
                    entry.unlink()
                    entry.symlink_to(outside)
                return original_open(path, flags, *args, **kwargs)

            with mock.patch.object(capture.os, "open", side_effect=swapping_open):
                with self.assertRaisesRegex(capture.CaptureError, "symlink|changed"):
                    capture.manifest_tree(root)


@unittest.skipIf(capture is None, "capture script has not been implemented yet")
class ReceiptPrimitiveTests(unittest.TestCase):
    def test_receipt_envelope_detects_payload_tampering(self) -> None:
        envelope = capture.make_receipt_envelope({"schema": "test", "value": 1})
        envelope["payload"]["value"] = 2

        with self.assertRaisesRegex(capture.CaptureError, "digest"):
            capture.validate_receipt_envelope(envelope)

    def test_atomic_json_write_is_owner_only_and_not_a_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            target = root / "receipt.json"
            capture.write_json_0600_atomic(target, {"ok": True})

            target_stat = target.lstat()
            self.assertTrue(stat.S_ISREG(target_stat.st_mode))
            self.assertEqual(stat.S_IMODE(target_stat.st_mode), 0o600)
            self.assertEqual(json.loads(target.read_text(encoding="utf-8")), {"ok": True})

            target.unlink()
            target.symlink_to(root / "elsewhere")
            with self.assertRaisesRegex(capture.CaptureError, "symlink"):
                capture.write_json_0600_atomic(target, {"ok": False})

    def test_pinned_image_requires_a_repository_sha256_digest(self) -> None:
        self.assertTrue(
            capture.is_pinned_image(
                "stalwartlabs/stalwart@sha256:" + ("a" * 64),
            ),
        )
        for unsafe in (
            "stalwartlabs/stalwart:latest",
            "stalwartlabs/stalwart:v0.15.5",
            "sha256:" + ("a" * 64),
            "stalwartlabs/stalwart@sha256:not-a-digest",
        ):
            with self.subTest(unsafe=unsafe):
                self.assertFalse(capture.is_pinned_image(unsafe))

    def test_owner_directory_and_cleanup_refuse_symlinked_ancestors(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            outside = root / "outside"
            outside.mkdir()
            (outside / "victim").mkdir()
            linked_parent = root / "linked"
            linked_parent.symlink_to(outside, target_is_directory=True)

            with self.assertRaisesRegex(capture.CaptureError, "symlink"):
                capture.ensure_owner_directory(linked_parent / "new-owner-directory")
            self.assertFalse((outside / "new-owner-directory").exists())

            with self.assertRaisesRegex(capture.CaptureError, "symlink"):
                capture._safe_remove_generated_tree(
                    linked_parent / "victim",
                    linked_parent,
                )
            self.assertTrue((outside / "victim").is_dir())

    def test_management_probe_disables_proxies_redirects_and_external_hosts(self) -> None:
        handlers: list[object] = []

        class Response:
            status = 200

            def __enter__(self) -> "Response":
                return self

            def __exit__(self, *args: object) -> None:
                return None

            def read(self, size: int) -> bytes:
                return b'{"data":[]}'

        class Opener:
            def open(self, request: object, timeout: int) -> Response:
                self.request = request
                self.timeout = timeout
                return Response()

        def build_opener(*values: object) -> Opener:
            handlers.extend(values)
            return Opener()

        with mock.patch.object(
            capture.urllib.request,
            "build_opener",
            side_effect=build_opener,
        ), mock.patch.object(
            capture.urllib.request,
            "urlopen",
            side_effect=AssertionError("global urlopen must not be used"),
        ):
            status = capture._default_management_probe(
                "http://127.0.0.1:29443/api/principal?type=individual",
                "admin",
                "unit-only-value",
            )
            external = capture._default_management_probe(
                "http://example.test/api/principal",
                "admin",
                "unit-only-value",
            )

        self.assertEqual(status, 200)
        self.assertEqual(external, 0)
        self.assertTrue(
            any(
                isinstance(handler, capture.urllib.request.ProxyHandler)
                and handler.proxies == {}
                for handler in handlers
            ),
        )
        self.assertTrue(
            any(type(handler).__name__ == "_NoRedirectHandler" for handler in handlers),
        )

    def test_atomic_json_write_fsyncs_its_parent_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            synced: list[Path] = []
            with mock.patch.object(
                capture,
                "fsync_directory",
                side_effect=lambda path: synced.append(path),
            ):
                capture.write_json_0600_atomic(root / "receipt.json", {"ok": True})

            self.assertIn(root, synced)

    def test_owner_directory_fsyncs_each_new_parent_entry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            synced: list[Path] = []
            with mock.patch.object(
                capture,
                "fsync_directory",
                side_effect=lambda path: synced.append(path),
            ):
                capture.ensure_owner_directory(root / "one" / "two")

            self.assertIn(root, synced)
            self.assertIn(root / "one", synced)

    def test_sha256_file_refuses_a_final_component_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            target = root / "outside"
            target.write_bytes(b"must-not-be-hashed")
            link = root / "config.toml"
            link.symlink_to(target)

            with self.assertRaisesRegex(capture.CaptureError, "symlink|regular"):
                capture.sha256_file(link)

    def test_config_copy_refuses_final_component_swap_without_chmodding_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / "config.toml"
            source.write_bytes(b"expected")
            outside = root / "outside"
            outside.write_bytes(b"must-not-copy")
            outside.chmod(0o644)
            destination = root / "backup.toml"
            original_open = capture.os.open
            swapped = False

            def swapping_open(path: object, flags: int, *args: object, **kwargs: object) -> int:
                nonlocal swapped
                if Path(path) == source and not swapped:
                    swapped = True
                    source.unlink()
                    source.symlink_to(outside)
                return original_open(path, flags, *args, **kwargs)

            with mock.patch.object(capture.os, "open", side_effect=swapping_open):
                with self.assertRaisesRegex(capture.CaptureError, "symlink|changed|regular"):
                    capture.copy_regular_file_0600(source, destination)

            self.assertEqual(stat.S_IMODE(outside.stat().st_mode), 0o644)
            self.assertFalse(destination.exists())

    def test_run_command_uses_a_bounded_timeout_and_redacts_timeout_output(self) -> None:
        expired = subprocess.TimeoutExpired(
            ["docker", "exec", "abc"],
            15,
            output="unit-only-secret",
            stderr="unit-only-secret",
        )
        with mock.patch.object(
            capture.subprocess,
            "run",
            side_effect=expired,
        ) as run:
            with self.assertRaises(capture.CommandError) as raised:
                capture.run_command(["docker", "exec", "abc"])

        self.assertNotIn("unit-only-secret", str(raised.exception))
        timeout = run.call_args.kwargs.get("timeout")
        self.assertIsInstance(timeout, int)
        self.assertGreater(timeout, 0)
        self.assertLessEqual(timeout, 120)
        self.assertNotIn("shell", run.call_args.kwargs)


@unittest.skipIf(capture is None, "capture script has not been implemented yet")
class FakeRuntime:
    SOURCE_ID = "1" * 64
    ROLLBACK_ID = "2" * 64
    REPLACEMENT_ID = "6" * 64
    NETWORK_ID = "7" * 64
    FOREIGN_ROLLBACK_ID = "8" * 64
    V016_IMAGE_ID = "sha256:" + ("a" * 64)
    IMAGE_ID = "sha256:" + ("3" * 64)
    IMAGE_DIGEST = "stalwartlabs/stalwart@sha256:" + ("4" * 64)

    def __init__(self, repository_root: Path, source_root: Path | None = None) -> None:
        self.repository_root = repository_root
        self.source_root = source_root or repository_root
        self.source_root.mkdir(parents=True, exist_ok=True)
        self.common_git_dir = self.source_root / ".git"
        self.common_git_dir.mkdir(mode=0o700)
        self.config_path = self.source_root / "stalwart" / "config.toml"
        self.config_path.parent.mkdir()
        self.config_path.write_text(
            """
[server.listener.http]
bind = ["[::]:8443"]
protocol = "http"

[authentication.fallback-admin]
user = "admin"
secret = "%{env:ADMIN_SECRET}%"
""".strip()
            + "\n",
            encoding="utf-8",
        )
        self.data_path = self.source_root / "stalwart-data"
        (self.data_path / "nested").mkdir(parents=True)
        (self.data_path / "CURRENT").write_bytes(b"MANIFEST-000001\n")
        (self.data_path / "nested" / "000001.sst").write_bytes(b"rocks-data")
        self.compose_path = self.source_root / "docker-compose.yml"
        self.compose_path.write_text("services: {}\n", encoding="utf-8")
        self.source_running = True
        self.replacement_source_running = False
        self.replacement_source_mode = "legacy"
        self.source_container_exists = True
        self.rollback_running = False
        self.rollback_compose_id_override: str | None = None
        self.rollback_image_id = self.IMAGE_ID
        self.rollback_environment = ["ADMIN_SECRET=unit-only-value"]
        self.rollback_version = "0.15.5"
        self.source_version = "0.15.5"
        self.repo_digests = [self.IMAGE_DIGEST]
        self.extra_source_inspects: list[dict[str, object]] = []
        self.calls: list[list[str]] = []
        self.management_status = 200
        self.management_calls: list[tuple[str, str, str]] = []
        self.fail_copy = False
        self.running_copy = False
        self.foreign_rollback_running = False
        self.foreign_rollback_after_up = False
        self.rollback_network_internal = False
        self.canonical_root_ignored = True
        self.timeout_on_rollback_up = False
        self.fail_rollback_down = False
        self.rollback_down_leaves_stopped_container = False
        self.events: list[str] = []
        self.copy_destinations: list[Path] = []
        self.v016_config_mount_style = "directory"
        self.v016_extra_parent_volume = False
        self.v016_project_label = "source-project"
        self.v016_config_files_label = str(self.compose_path)
        self.v016_data_source = self.data_path

    def source_inspect(self, container_id: str | None = None) -> dict[str, object]:
        return {
            "Id": container_id or self.SOURCE_ID,
            "Name": "/source-stalwart",
            "Config": {
                "Image": "stalwartlabs/stalwart:latest",
                "Labels": {
                    "com.docker.compose.project": "source-project",
                    "com.docker.compose.service": "stalwart",
                    "com.docker.compose.project.working_dir": str(self.source_root),
                    "com.docker.compose.project.config_files": str(self.compose_path),
                },
                "Env": ["ADMIN_SECRET=unit-only-value"],
            },
            "Image": self.IMAGE_ID,
            "State": {"Running": self.source_running},
            "Mounts": [
                {
                    "Type": "volume",
                    "Name": "source-image-declared-volume",
                    "Source": "/var/lib/docker/volumes/source-image-declared-volume/_data",
                    "Destination": "/opt/stalwart",
                    "RW": True,
                    "Mode": "z",
                },
                {
                    "Type": "bind",
                    "Source": str(self.config_path),
                    "Destination": "/opt/stalwart/etc/config.toml",
                    "RW": False,
                    "Mode": "ro",
                },
                {
                    "Type": "bind",
                    "Source": str(self.data_path),
                    "Destination": "/opt/stalwart/data",
                    "RW": True,
                    "Mode": "rw",
                },
            ],
        }

    def rollback_inspect(self) -> dict[str, object]:
        backup = self.current_backup()
        definition = json.loads((backup / "rollback.compose.json").read_text(encoding="utf-8"))
        port = definition["services"]["stalwart-rollback"]["ports"][0]["published"]
        tmpfs = definition["services"]["stalwart-rollback"].get("tmpfs")
        return {
            "Id": self.ROLLBACK_ID,
            "Config": {
                "Image": self.IMAGE_DIGEST,
                "Labels": {
                    "com.docker.compose.project": self.rollback_project(),
                    "com.docker.compose.service": "stalwart-rollback",
                    "mail.sandbox.stalwart.rollback": "v015",
                },
                "Env": list(self.rollback_environment),
            },
            "Image": self.rollback_image_id,
            "State": {"Running": self.rollback_running},
            "HostConfig": {
                "Tmpfs": (
                    {
                        "/opt/stalwart": "rw,noexec,nosuid,nodev,mode=0700",
                    }
                    if tmpfs
                    else {}
                ),
            },
            "Mounts": [
                {
                    "Type": "bind",
                    "Source": str(backup / "config.toml"),
                    "Destination": "/opt/stalwart/etc/config.toml",
                    "RW": False,
                },
                {
                    "Type": "bind",
                    "Source": str(backup / "rollback-data"),
                    "Destination": "/opt/stalwart/data",
                    "RW": True,
                },
            ],
            "NetworkSettings": {
                "Networks": {
                    f"{self.rollback_project()}_default": {
                        "NetworkID": self.NETWORK_ID,
                    },
                },
                "Ports": {
                    "8443/tcp": [
                        {
                            "HostIp": "127.0.0.1",
                            "HostPort": str(port),
                        },
                    ],
                },
            },
        }

    def replacement_inspect(self) -> dict[str, object]:
        legacy = self.replacement_source_mode == "legacy"
        v016_config_source = (
            self.config_path.parent
            if self.v016_config_mount_style == "directory"
            else self.config_path.parent / "config.json"
        )
        v016_config_target = (
            "/etc/stalwart"
            if self.v016_config_mount_style == "directory"
            else "/etc/stalwart/config.json"
        )
        v016_mounts = [
            {
                "Type": "bind",
                "Source": str(v016_config_source),
                "Destination": v016_config_target,
                "RW": False,
            },
            {
                "Type": "bind",
                "Source": str(self.v016_data_source),
                "Destination": "/var/lib/stalwart",
                "RW": True,
            },
        ]
        if self.v016_extra_parent_volume:
            v016_mounts.append(
                {
                    "Type": "volume",
                    "Source": "/var/lib/docker/volumes/v016-config/_data",
                    "Destination": "/etc/stalwart",
                    "RW": True,
                },
            )
        return {
            "Id": self.REPLACEMENT_ID,
            "Config": {
                "Image": (
                    "stalwartlabs/stalwart:latest"
                    if legacy
                    else "stalwartlabs/stalwart:v0.16.14"
                ),
                "Labels": {
                    "com.docker.compose.project": (
                        "source-project" if legacy else self.v016_project_label
                    ),
                    "com.docker.compose.service": "stalwart",
                    "com.docker.compose.project.working_dir": str(self.source_root),
                    "com.docker.compose.project.config_files": (
                        str(self.compose_path)
                        if legacy
                        else self.v016_config_files_label
                    ),
                },
                "Env": [],
            },
            "Image": self.IMAGE_ID if legacy else self.V016_IMAGE_ID,
            "State": {"Running": self.replacement_source_running},
            "Mounts": (
                [
                    {
                        "Type": "volume",
                        "Source": "/var/lib/docker/volumes/recreated/_data",
                        "Destination": "/opt/stalwart",
                        "RW": True,
                    },
                    {
                        "Type": "bind",
                        "Source": str(self.config_path),
                        "Destination": "/opt/stalwart/etc/config.toml",
                        "RW": False,
                    },
                    {
                        "Type": "bind",
                        "Source": str(self.data_path),
                        "Destination": "/opt/stalwart/data",
                        "RW": True,
                    },
                ]
                if legacy
                else v016_mounts
            ),
        }

    def current_backup(self) -> Path:
        partials = sorted(
            (
                self.source_root
                / "captures"
                / "debug-dashboard"
                / "stalwart-v015"
                / "backups"
            ).glob(".partial-*"),
        )
        finals = sorted(
            path
            for path in (
                self.source_root
                / "captures"
                / "debug-dashboard"
                / "stalwart-v015"
                / "backups"
            ).glob("stalwart-v015-*")
            if path.is_dir()
        )
        candidates = partials or finals
        if not candidates:
            raise AssertionError("no backup exists")
        return candidates[-1]

    def rollback_project(self) -> str:
        definition = json.loads(
            (self.current_backup() / "rollback.compose.json").read_text(encoding="utf-8"),
        )
        return definition["x-mail-sandbox"]["project"]

    def normalized_compose(self) -> dict[str, object]:
        backup = self.current_backup()
        definition = json.loads((backup / "rollback.compose.json").read_text(encoding="utf-8"))
        service = definition["services"]["stalwart-rollback"]
        resolved_service = {
            "image": service["image"],
            "ports": service["ports"],
            "volumes": [
                {
                    "type": "bind",
                    "source": str(backup / "config.toml"),
                    "target": "/opt/stalwart/etc/config.toml",
                    "read_only": True,
                },
                {
                    "type": "bind",
                    "source": str(backup / "rollback-data"),
                    "target": "/opt/stalwart/data",
                    "read_only": False,
                },
            ],
            "env_file": [str(backup / "rollback.env")],
        }
        if "tmpfs" in service:
            resolved_service["tmpfs"] = service["tmpfs"]
        return {
            "services": {
                "stalwart-rollback": resolved_service,
            },
        }

    def __call__(self, args: list[str]) -> "capture.CommandResult":
        self.assert_list_form(args)
        self.calls.append(list(args))
        if args[:2] == ["docker", "ps"]:
            id_filters = [
                item.split("=", 1)[1]
                for item in args
                if item.startswith("id=")
            ]
            if id_filters:
                output = self.SOURCE_ID + "\n" if self.source_container_exists else ""
                return capture.CommandResult(output, "")
            if "label=com.docker.compose.project=source-project" in args:
                ids = []
                if self.source_running:
                    ids.append(self.SOURCE_ID)
                if self.replacement_source_running:
                    ids.append(self.REPLACEMENT_ID)
                return capture.CommandResult(
                    "\n".join(ids) + ("\n" if ids else ""),
                    "",
                )
            if "label=mail.sandbox.stalwart.rollback=v015" in args:
                ids = []
                if self.rollback_running:
                    ids.append(self.ROLLBACK_ID)
                if self.foreign_rollback_running:
                    ids.append(self.FOREIGN_ROLLBACK_ID)
                return capture.CommandResult(
                    "\n".join(ids) + ("\n" if ids else ""),
                    "",
                )
            ids = []
            if self.source_running:
                ids.append(self.SOURCE_ID)
            if self.replacement_source_running:
                ids.append(self.REPLACEMENT_ID)
            ids.extend(str(item["Id"]) for item in self.extra_source_inspects)
            return capture.CommandResult("\n".join(ids) + ("\n" if ids else ""), "")
        if args[:2] == ["docker", "inspect"]:
            ids = args[2:]
            records: list[dict[str, object]] = []
            for container_id in ids:
                if container_id == self.SOURCE_ID:
                    if self.source_container_exists:
                        records.append(self.source_inspect())
                elif container_id == self.ROLLBACK_ID:
                    self.events.append("inspect")
                    records.append(self.rollback_inspect())
                elif container_id == self.REPLACEMENT_ID:
                    records.append(self.replacement_inspect())
                else:
                    records.extend(
                        item
                        for item in self.extra_source_inspects
                        if item["Id"] == container_id
                    )
            if not records:
                raise capture.CommandError(args, 1)
            return capture.CommandResult(json.dumps(records), "")
        if args[:2] == ["docker", "exec"]:
            container_id = args[2]
            if container_id == self.SOURCE_ID:
                return capture.CommandResult(self.source_version + "\n", "")
            if container_id == self.ROLLBACK_ID and self.rollback_running:
                self.events.append("version")
                return capture.CommandResult(self.rollback_version + "\n", "")
            raise capture.CommandError(args, 1)
        if args[:3] == ["docker", "image", "inspect"]:
            return capture.CommandResult(
                json.dumps(
                    [
                        {
                            "Id": self.IMAGE_ID,
                            "RepoDigests": self.repo_digests,
                        },
                    ],
                ),
                "",
            )
        if args[:3] == ["docker", "network", "inspect"]:
            self.events.append("network")
            return capture.CommandResult(
                json.dumps(
                    [
                        {
                            "Id": self.NETWORK_ID,
                            "Internal": self.rollback_network_internal,
                            "Labels": {
                                "com.docker.compose.network": "default",
                                "com.docker.compose.project": self.rollback_project(),
                            },
                        },
                    ],
                ),
                "",
            )
        if args[:2] == ["git", "-C"] and "check-ignore" in args:
            if not self.canonical_root_ignored:
                raise capture.CommandError(args, 1)
            return capture.CommandResult("", "")
        if args[:2] == ["git", "-C"]:
            return capture.CommandResult(str(self.common_git_dir) + "\n", "")
        if args[:2] == ["docker", "compose"]:
            if "stop" in args and "stalwart" == args[-1]:
                self.source_running = False
                self.replacement_source_running = False
                return capture.CommandResult("", "")
            if "config" in args:
                return capture.CommandResult(json.dumps(self.normalized_compose()), "")
            if "ps" in args and "--status" in args:
                output = self.ROLLBACK_ID + "\n" if self.running_copy else ""
                return capture.CommandResult(output, "")
            if "up" in args:
                if self.timeout_on_rollback_up:
                    raise capture.CommandError(args, 124)
                self.events.append("up")
                self.rollback_running = True
                if self.foreign_rollback_after_up:
                    self.foreign_rollback_running = True
                rollback_data = self.current_backup() / "rollback-data" / "CURRENT"
                rollback_data.write_bytes(rollback_data.read_bytes() + b"proof-write")
                return capture.CommandResult("", "")
            if "ps" in args:
                if self.rollback_compose_id_override is not None:
                    if "--all" in args or self.rollback_running:
                        return capture.CommandResult(
                            self.rollback_compose_id_override + "\n",
                            "",
                        )
                    return capture.CommandResult("", "")
                return capture.CommandResult(
                    (
                        self.ROLLBACK_ID + "\n"
                        if self.rollback_running or self.running_copy
                        else ""
                    ),
                    "",
                )
            if "down" in args:
                self.events.append("down")
                if self.fail_rollback_down:
                    raise capture.CommandError(args, 1)
                self.rollback_running = False
                if self.rollback_down_leaves_stopped_container:
                    self.rollback_compose_id_override = self.ROLLBACK_ID
                else:
                    self.rollback_compose_id_override = None
                return capture.CommandResult("", "")
        raise AssertionError(f"unexpected command: {args!r}")

    def copy_tree(self, source: Path, destination: Path) -> None:
        self.copy_destinations.append(destination)
        if self.fail_copy:
            destination.mkdir(mode=0o700)
            first_file = next(path for path in source.rglob("*") if path.is_file())
            (destination / first_file.name).write_bytes(first_file.read_bytes())
            raise OSError("injected partial copy")
        capture.copy_tree(source, destination)

    def probe(self, url: str, username: str, secret: str) -> int:
        self.events.append("management")
        self.management_calls.append((url, username, secret))
        return self.management_status

    @staticmethod
    def assert_list_form(args: list[str]) -> None:
        if not isinstance(args, list) or not all(isinstance(arg, str) for arg in args):
            raise AssertionError("commands must use list-form strings")


@unittest.skipIf(capture is None, "capture script has not been implemented yet")
class CaptureWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.repository_root = Path(self.temporary_directory.name).resolve()
        self.runtime = FakeRuntime(self.repository_root)
        self.application = capture.CaptureApplication(
            repository_root=self.repository_root,
            runner=self.runtime,
            management_probe=self.runtime.probe,
            port_allocator=lambda excluded: 29443,
            port_checker=lambda port: port == 29443,
            clock=lambda: "20260728T120000Z",
            nonce=lambda: "abc12345",
            tree_copier=self.runtime.copy_tree,
        )

    @property
    def latest_receipt(self) -> Path:
        return (
            self.repository_root
            / "debug-dashboard"
            / ".runtime"
            / "stalwart-migration"
            / "latest-source.json"
        )

    def capture_successfully(self) -> dict[str, object]:
        receipt = self.application.capture("stalwart")
        self.assertEqual(receipt, self.latest_receipt)
        return self.application.verify(receipt)

    def rewrite_receipt(self, payload: dict[str, object]) -> None:
        envelope = capture.make_receipt_envelope(payload)
        backup_receipt = Path(payload["backup"]["root"]) / "source-receipt.json"
        capture.write_json_0600_atomic(backup_receipt, envelope)
        capture.write_json_0600_atomic(
            Path(payload["backup"]["canonical_latest_receipt"]),
            envelope,
        )
        capture.write_json_0600_atomic(self.latest_receipt, envelope)

    def append_unrelated_running_writer(
        self,
        mount_source: str,
        *,
        writable: bool = True,
    ) -> str:
        writer_id = "9" * 64
        writer = self.runtime.source_inspect(writer_id)
        writer["Config"]["Image"] = "example.test/unrelated:unit"
        writer["Image"] = "sha256:" + ("e" * 64)
        writer["State"]["Running"] = True
        writer["Mounts"] = [
            {
                "Type": "bind",
                "Source": mount_source,
                "Destination": "/unrelated",
                "RW": writable,
            },
        ]
        self.runtime.extra_source_inspects.append(writer)
        return writer_id

    def receipt_sha256(self) -> str:
        return capture.sha256_file(self.latest_receipt)

    def write_activation_intent(
        self,
        payload: dict[str, object],
        expected_receipt_sha256: str,
    ) -> Path:
        backup = Path(payload["backup"]["root"])
        intent_path = backup / "rollback-activation-intent.json"
        capture.write_json_0600_atomic(
            intent_path,
            capture.make_receipt_envelope(
                self.application._build_activation_intent(
                    payload=payload,
                    expected_receipt_sha256=expected_receipt_sha256,
                ),
            ),
        )
        return intent_path

    def prepare_running_activation_intent(
        self,
    ) -> tuple[dict[str, object], str, Path]:
        payload = self.capture_successfully()
        expected_receipt_sha256 = self.receipt_sha256()
        intent_path = self.write_activation_intent(
            payload,
            expected_receipt_sha256,
        )
        backup = Path(payload["backup"]["root"])
        current = backup / "rollback-data" / "CURRENT"
        current.write_bytes(current.read_bytes() + b"activation-crash-state")
        self.runtime.rollback_running = True
        self.runtime.calls.clear()
        self.runtime.events.clear()
        self.runtime.copy_destinations.clear()
        return payload, expected_receipt_sha256, intent_path

    def assert_running_intent_health_status_reconciles_inactive(
        self,
        status: int,
    ) -> None:
        payload, expected_receipt_sha256, intent_path = (
            self.prepare_running_activation_intent()
        )
        backup = Path(payload["backup"]["root"])
        self.runtime.management_status = status

        result = self.application.reconcile_verified_rollback(
            self.latest_receipt,
            expected_receipt_sha256=expected_receipt_sha256,
        )

        self.assertIsNone(result)
        self.assertFalse(self.runtime.rollback_running)
        self.assertFalse(intent_path.exists())
        self.assertFalse((backup / "rollback-activation.json").exists())
        self.assertEqual(
            capture.manifest_tree(backup / "rollback-data"),
            payload["data_manifest"],
        )
        down_calls = [call for call in self.runtime.calls if "down" in call]
        self.assertEqual(len(down_calls), 1)
        self.assertNotIn("-v", down_calls[0])
        self.assertNotIn("--volumes", down_calls[0])
        down_index = self.runtime.calls.index(down_calls[0])
        self.assertTrue(
            any(
                index > down_index
                and call[:2] == ["docker", "ps"]
                and (
                    "label=mail.sandbox.stalwart.rollback=v015"
                    in call
                )
                for index, call in enumerate(self.runtime.calls)
            ),
        )
        self.assertTrue(
            any(
                index > down_index
                and call[:2] == ["docker", "compose"]
                and "ps" in call
                and "--all" in call
                for index, call in enumerate(self.runtime.calls)
            ),
        )

    def test_capture_proves_backup_publishes_receipt_and_leaves_source_stopped(self) -> None:
        payload = self.capture_successfully()

        self.assertFalse(self.runtime.source_running)
        self.assertEqual(stat.S_IMODE(self.latest_receipt.stat().st_mode), 0o600)
        runtime_root = self.repository_root / "debug-dashboard" / ".runtime"
        self.assertEqual(stat.S_IMODE(runtime_root.stat().st_mode), 0o700)
        backup = Path(payload["backup"]["root"])
        self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o700)
        self.assertEqual(capture.manifest_tree(backup / "source-data"), payload["data_manifest"])
        self.assertEqual(capture.manifest_tree(backup / "rollback-data"), payload["data_manifest"])
        self.assertEqual(payload["source"]["version"], "0.15.5")
        self.assertEqual(payload["source"]["image_reference"], "stalwartlabs/stalwart:latest")
        self.assertEqual(payload["source"]["image_id"], self.runtime.IMAGE_ID)
        self.assertEqual(payload["source"]["image_digest"], self.runtime.IMAGE_DIGEST)
        self.assertEqual(payload["rollback"]["host_ip"], "127.0.0.1")
        self.assertEqual(payload["rollback"]["port"], 29443)
        self.assertEqual(payload["rollback"]["proof"]["management_status"], 200)
        self.assertTrue(self.runtime.management_calls)
        all_arguments = "\n".join(argument for call in self.runtime.calls for argument in call)
        self.assertNotIn("unit-only-value", all_arguments)
        self.assertNotIn(
            "unit-only-value",
            self.latest_receipt.read_text(encoding="utf-8"),
        )
        down_calls = [call for call in self.runtime.calls if "down" in call]
        self.assertTrue(down_calls)
        self.assertTrue(all("-v" not in call and "--volumes" not in call for call in down_calls))
        self.assertTrue(all("mail-sandbox-stalwart-gate" not in call for call in self.runtime.calls))
        config_calls = [call for call in self.runtime.calls if "config" in call]
        self.assertTrue(config_calls)
        self.assertTrue(all("--quiet" in call for call in config_calls))
        self.assertTrue(all("--format" not in call for call in config_calls))

    def test_prove_rollback_reverifies_and_restores_clean_working_copy(self) -> None:
        payload = self.capture_successfully()
        before = len(self.runtime.management_calls)

        proof = self.application.prove_rollback(self.latest_receipt)

        self.assertEqual(proof["version"], "0.15.5")
        self.assertEqual(proof["management_status"], 200)
        self.assertEqual(len(self.runtime.management_calls), before + 2)
        backup = Path(payload["backup"]["root"])
        self.assertEqual(capture.manifest_tree(backup / "rollback-data"), payload["data_manifest"])
        self.assertFalse(self.runtime.rollback_running)
        self.assertFalse(self.runtime.source_running)

    def test_activate_verified_rollback_persists_safe_proof_and_leaves_it_running(
        self,
    ) -> None:
        payload = self.capture_successfully()
        backup = Path(payload["backup"]["root"])
        expected_receipt_sha256 = self.receipt_sha256()
        self.runtime.calls.clear()
        self.runtime.events.clear()

        activation = self.application.activate_verified_rollback(
            self.latest_receipt,
            expected_receipt_sha256=expected_receipt_sha256,
        )

        proof_path = backup / "rollback-activation.json"
        self.assertIsInstance(activation, capture.VerifiedRollbackActivation)
        self.assertEqual(activation.proof_path, proof_path)
        self.assertEqual(activation.base_url, "http://127.0.0.1:29443")
        self.assertEqual(activation.proof.version, "0.15.5")
        self.assertEqual(activation.proof.management_status, 200)
        self.assertTrue(self.runtime.rollback_running)
        self.assertTrue(proof_path.is_file())
        self.assertEqual(stat.S_IMODE(proof_path.stat().st_mode), 0o600)

        envelope = json.loads(proof_path.read_text(encoding="utf-8"))
        activation_payload = capture.validate_receipt_envelope(envelope)
        self.assertEqual(
            set(activation_payload),
            {
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
            },
        )
        self.assertEqual(
            activation_payload["schema"],
            "mail-sandbox.stalwart-v015-rollback-activation.v1",
        )
        self.assertEqual(
            activation_payload["source_receipt_sha256"],
            expected_receipt_sha256,
        )
        self.assertEqual(activation_payload["container_id"], self.runtime.ROLLBACK_ID)
        self.assertEqual(activation_payload["network_id"], self.runtime.NETWORK_ID)
        self.assertNotIn(
            "unit-only-value",
            proof_path.read_text(encoding="utf-8"),
        )
        up_calls = [call for call in self.runtime.calls if "up" in call]
        self.assertEqual(len(up_calls), 1)
        self.assertIn("--pull", up_calls[0])
        self.assertIn("never", up_calls[0])
        self.assertIn("--no-build", up_calls[0])
        self.assertIn("--force-recreate", up_calls[0])
        up_index = self.runtime.calls.index(up_calls[0])
        pre_up_compose_census = [
            index
            for index, call in enumerate(self.runtime.calls)
            if call[:2] == ["docker", "compose"]
            and "ps" in call
            and "--all" in call
            and index < up_index
        ]
        self.assertTrue(pre_up_compose_census)
        self.assertFalse(any("down" in call for call in self.runtime.calls))
        self.assertNotEqual(
            capture.manifest_tree(backup / "rollback-data"),
            payload["data_manifest"],
        )

    def test_activation_persists_intent_before_up_and_reconciles_exact_crash_runtime(
        self,
    ) -> None:
        payload = self.capture_successfully()
        backup = Path(payload["backup"]["root"])
        expected_receipt_sha256 = self.receipt_sha256()
        intent_path = backup / "rollback-activation-intent.json"
        observed_intents: list[dict[str, object]] = []
        original_runner = self.application.runner

        class SimulatedProcessDeath(BaseException):
            pass

        def crash_after_up(args: list[str]) -> "capture.CommandResult":
            result = original_runner(args)
            if "up" in args:
                self.assertTrue(intent_path.is_file())
                self.assertEqual(stat.S_IMODE(intent_path.stat().st_mode), 0o600)
                observed_intents.append(
                    capture.validate_receipt_envelope(
                        json.loads(intent_path.read_text(encoding="utf-8")),
                    ),
                )
                raise SimulatedProcessDeath()
            return result

        self.application.runner = crash_after_up
        self.runtime.fail_rollback_down = True

        with self.assertRaisesRegex(capture.CaptureError, "activation cleanup"):
            self.application.activate_verified_rollback(
                self.latest_receipt,
                expected_receipt_sha256=expected_receipt_sha256,
            )

        self.assertEqual(len(observed_intents), 1)
        self.assertEqual(
            observed_intents[0]["source_receipt_sha256"],
            expected_receipt_sha256,
        )
        self.assertEqual(
            set(observed_intents[0]),
            {
                "attempted_at",
                "backup_root",
                "base_url",
                "config_sha256",
                "environment_sha256",
                "image_digest",
                "image_id",
                "project",
                "rollback_compose_sha256",
                "schema",
                "service",
                "source_manifest_sha256",
                "source_receipt_sha256",
            },
        )
        self.assertEqual(
            observed_intents[0]["schema"],
            "mail-sandbox.stalwart-v015-rollback-activation-intent.v1",
        )
        self.assertNotIn(
            "unit-only-value",
            intent_path.read_text(encoding="utf-8"),
        )
        self.assertTrue(self.runtime.rollback_running)
        self.assertTrue(intent_path.is_file())
        self.assertFalse((backup / "rollback-activation.json").exists())

        self.runtime.fail_rollback_down = False
        restarted = capture.CaptureApplication(
            repository_root=self.repository_root,
            runner=self.runtime,
            management_probe=self.runtime.probe,
            port_allocator=lambda excluded: 29443,
            port_checker=lambda port: port == 29443,
            clock=lambda: "20260728T120001Z",
            nonce=lambda: "def67890",
            tree_copier=self.runtime.copy_tree,
        )
        activation = restarted.reconcile_verified_rollback(
            self.latest_receipt,
            expected_receipt_sha256=expected_receipt_sha256,
        )

        self.assertIsInstance(activation, capture.VerifiedRollbackActivation)
        self.assertTrue(self.runtime.rollback_running)
        self.assertTrue((backup / "rollback-activation.json").is_file())
        self.assertFalse(intent_path.exists())

    def test_reconciliation_deactivates_owned_intent_after_version_failure(
        self,
    ) -> None:
        payload, expected_receipt_sha256, intent_path = (
            self.prepare_running_activation_intent()
        )
        backup = Path(payload["backup"]["root"])
        self.runtime.rollback_version = "0.16.0"

        with (
            mock.patch.object(
                capture.time,
                "monotonic",
                side_effect=[0.0, 0.0, 61.0],
            ),
            mock.patch.object(capture.time, "sleep"),
        ):
            result = self.application.reconcile_verified_rollback(
                self.latest_receipt,
                expected_receipt_sha256=expected_receipt_sha256,
            )

        self.assertIsNone(result)
        self.assertFalse(self.runtime.rollback_running)
        self.assertFalse(intent_path.exists())
        self.assertFalse((backup / "rollback-activation.json").exists())
        self.assertEqual(
            capture.manifest_tree(backup / "rollback-data"),
            payload["data_manifest"],
        )
        self.assertLess(
            self.runtime.events.index("inspect"),
            self.runtime.events.index("version"),
        )
        self.assertEqual(
            len([call for call in self.runtime.calls if "down" in call]),
            1,
        )

    def test_reconciliation_deactivates_owned_intent_after_http_401(self) -> None:
        self.assert_running_intent_health_status_reconciles_inactive(401)

    def test_reconciliation_deactivates_owned_intent_after_http_403(self) -> None:
        self.assert_running_intent_health_status_reconciles_inactive(403)

    def test_reconciliation_deactivates_owned_intent_when_management_is_unavailable(
        self,
    ) -> None:
        payload, expected_receipt_sha256, intent_path = (
            self.prepare_running_activation_intent()
        )
        backup = Path(payload["backup"]["root"])
        self.runtime.management_status = 0

        with (
            mock.patch.object(
                capture.time,
                "monotonic",
                side_effect=[0.0, 0.0, 61.0],
            ),
            mock.patch.object(capture.time, "sleep"),
        ):
            result = self.application.reconcile_verified_rollback(
                self.latest_receipt,
                expected_receipt_sha256=expected_receipt_sha256,
            )

        self.assertIsNone(result)
        self.assertFalse(self.runtime.rollback_running)
        self.assertFalse(intent_path.exists())
        self.assertFalse((backup / "rollback-activation.json").exists())
        self.assertEqual(
            capture.manifest_tree(backup / "rollback-data"),
            payload["data_manifest"],
        )

    def test_reconciliation_never_downs_structurally_unbound_intent_runtime(
        self,
    ) -> None:
        _payload, expected_receipt_sha256, intent_path = (
            self.prepare_running_activation_intent()
        )
        self.runtime.rollback_compose_id_override = (
            self.runtime.FOREIGN_ROLLBACK_ID
        )

        with self.assertRaisesRegex(capture.CaptureError, "identity"):
            self.application.reconcile_verified_rollback(
                self.latest_receipt,
                expected_receipt_sha256=expected_receipt_sha256,
            )

        self.assertTrue(self.runtime.rollback_running)
        self.assertTrue(intent_path.exists())
        self.assertFalse(any("down" in call for call in self.runtime.calls))
        self.runtime.rollback_compose_id_override = None
        base_record = self.runtime.rollback_inspect()

        for failure in (
            "compose-label",
            "image",
            "mount",
            "environment",
            "network",
            "port",
        ):
            with self.subTest(failure=failure):
                record = json.loads(json.dumps(base_record))
                if failure == "compose-label":
                    record["Config"]["Labels"][
                        "com.docker.compose.project"
                    ] = "foreign-project"
                elif failure == "image":
                    record["Image"] = "sha256:" + ("9" * 64)
                elif failure == "mount":
                    record["Mounts"][1]["Source"] = "/tmp/foreign-data"
                elif failure == "environment":
                    record["Config"]["Env"] = [
                        "ADMIN_SECRET=foreign-secret",
                    ]
                elif failure == "network":
                    network = next(
                        iter(record["NetworkSettings"]["Networks"].values()),
                    )
                    network["NetworkID"] = "9" * 64
                else:
                    record["NetworkSettings"]["Ports"]["8443/tcp"][0][
                        "HostIp"
                    ] = "0.0.0.0"
                self.runtime.calls.clear()
                with mock.patch.object(
                    self.runtime,
                    "rollback_inspect",
                    return_value=record,
                ):
                    with self.assertRaises(capture.CaptureError):
                        self.application.reconcile_verified_rollback(
                            self.latest_receipt,
                            expected_receipt_sha256=expected_receipt_sha256,
                        )
                self.assertTrue(self.runtime.rollback_running)
                self.assertTrue(intent_path.exists())
                self.assertFalse(
                    any("down" in call for call in self.runtime.calls),
                )

    def test_reconciliation_structural_interruption_preserves_intent_without_down(
        self,
    ) -> None:
        _payload, expected_receipt_sha256, intent_path = (
            self.prepare_running_activation_intent()
        )

        class InjectedFatal(BaseException):
            pass

        failure = InjectedFatal("injected structural interruption")
        with mock.patch.object(
            self.application,
            "_validate_actual_rollback_container",
            side_effect=failure,
        ):
            with self.assertRaises(InjectedFatal) as raised:
                self.application.reconcile_verified_rollback(
                    self.latest_receipt,
                    expected_receipt_sha256=expected_receipt_sha256,
                )

        self.assertIs(raised.exception, failure)
        self.assertTrue(self.runtime.rollback_running)
        self.assertTrue(intent_path.exists())
        self.assertFalse(any("down" in call for call in self.runtime.calls))

    def test_reconciliation_health_interruption_cleans_then_preserves_identity(
        self,
    ) -> None:
        payload, expected_receipt_sha256, intent_path = (
            self.prepare_running_activation_intent()
        )
        backup = Path(payload["backup"]["root"])

        class InjectedFatal(BaseException):
            pass

        failure = InjectedFatal("injected health interruption")
        with mock.patch.object(
            self.application,
            "_rollback_version",
            side_effect=failure,
        ):
            with self.assertRaises(InjectedFatal) as raised:
                self.application.reconcile_verified_rollback(
                    self.latest_receipt,
                    expected_receipt_sha256=expected_receipt_sha256,
                )

        self.assertIs(raised.exception, failure)
        self.assertFalse(self.runtime.rollback_running)
        self.assertFalse(intent_path.exists())
        self.assertFalse((backup / "rollback-activation.json").exists())
        self.assertEqual(
            capture.manifest_tree(backup / "rollback-data"),
            payload["data_manifest"],
        )

    def test_reconciliation_preserves_intent_unlink_fsync_baseexception_identity(
        self,
    ) -> None:
        payload, expected_receipt_sha256, intent_path = (
            self.prepare_running_activation_intent()
        )
        backup = Path(payload["backup"]["root"])
        proof_path = backup / "rollback-activation.json"
        original_directory_sync = self.application.directory_sync
        interruptions = 0

        class InjectedFatal(BaseException):
            pass

        failure = InjectedFatal("injected intent directory fsync interruption")

        def interrupt_after_intent_unlink(path: Path) -> None:
            nonlocal interruptions
            if (
                interruptions == 0
                and not intent_path.exists()
                and proof_path.exists()
                and self.runtime.rollback_running
            ):
                interruptions += 1
                raise failure
            original_directory_sync(path)

        self.application.directory_sync = interrupt_after_intent_unlink

        with self.assertRaises(InjectedFatal) as raised:
            self.application.reconcile_verified_rollback(
                self.latest_receipt,
                expected_receipt_sha256=expected_receipt_sha256,
            )

        self.assertIs(raised.exception, failure)
        self.assertEqual(interruptions, 1)
        self.assertFalse(self.runtime.rollback_running)
        self.assertFalse(intent_path.exists())
        self.assertFalse(proof_path.exists())
        self.assertEqual(
            capture.manifest_tree(backup / "rollback-data"),
            payload["data_manifest"],
        )

    def test_reconciliation_rejects_intent_absence_before_owned_removal(
        self,
    ) -> None:
        payload, expected_receipt_sha256, intent_path = (
            self.prepare_running_activation_intent()
        )
        backup = Path(payload["backup"]["root"])

        def remove_foreign_intent(
            _url: str,
            _username: str,
            _secret: str,
        ) -> int:
            intent_path.unlink()
            return 401

        self.application.management_probe = remove_foreign_intent

        with self.assertRaisesRegex(
            capture.CaptureError,
            "reconciliation cleanup",
        ):
            self.application.reconcile_verified_rollback(
                self.latest_receipt,
                expected_receipt_sha256=expected_receipt_sha256,
            )

        self.assertFalse(self.runtime.rollback_running)
        self.assertFalse(intent_path.exists())
        self.assertFalse((backup / "rollback-activation.json").exists())
        self.assertEqual(
            capture.manifest_tree(backup / "rollback-data"),
            payload["data_manifest"],
        )

    def test_reconciliation_health_cleanup_failure_preserves_intent_claim(
        self,
    ) -> None:
        payload, expected_receipt_sha256, intent_path = (
            self.prepare_running_activation_intent()
        )
        backup = Path(payload["backup"]["root"])
        dirty_manifest = capture.manifest_tree(backup / "rollback-data")
        self.runtime.management_status = 401
        self.runtime.fail_rollback_down = True

        with self.assertRaisesRegex(capture.CaptureError, "reconciliation cleanup"):
            self.application.reconcile_verified_rollback(
                self.latest_receipt,
                expected_receipt_sha256=expected_receipt_sha256,
            )

        self.assertTrue(self.runtime.rollback_running)
        self.assertTrue(intent_path.exists())
        self.assertFalse((backup / "rollback-activation.json").exists())
        self.assertEqual(
            capture.manifest_tree(backup / "rollback-data"),
            dirty_manifest,
        )

    def test_reconciliation_receipt_drift_after_refresh_preserves_intent_last(
        self,
    ) -> None:
        payload, expected_receipt_sha256, intent_path = (
            self.prepare_running_activation_intent()
        )
        backup = Path(payload["backup"]["root"])
        self.runtime.management_status = 401
        original_refresh = self.application._refresh_rollback_data

        def refresh_then_tamper(
            refresh_root: Path,
            expected_manifest: dict[str, object],
        ) -> None:
            original_refresh(refresh_root, expected_manifest)
            self.latest_receipt.write_bytes(
                self.latest_receipt.read_bytes() + b" ",
            )

        with mock.patch.object(
            self.application,
            "_refresh_rollback_data",
            side_effect=refresh_then_tamper,
        ):
            with self.assertRaisesRegex(
                capture.CaptureError,
                "reconciliation cleanup",
            ):
                self.application.reconcile_verified_rollback(
                    self.latest_receipt,
                    expected_receipt_sha256=expected_receipt_sha256,
                )

        self.assertFalse(self.runtime.rollback_running)
        self.assertTrue(intent_path.exists())
        self.assertFalse((backup / "rollback-activation.json").exists())
        self.assertEqual(
            capture.manifest_tree(backup / "rollback-data"),
            payload["data_manifest"],
        )

    def test_reconciliation_deactivates_bound_preexisting_proof_when_unhealthy(
        self,
    ) -> None:
        payload = self.capture_successfully()
        backup = Path(payload["backup"]["root"])
        expected_receipt_sha256 = self.receipt_sha256()
        activation = self.application.activate_verified_rollback(
            self.latest_receipt,
            expected_receipt_sha256=expected_receipt_sha256,
        )
        intent_path = self.write_activation_intent(
            payload,
            expected_receipt_sha256,
        )
        self.runtime.management_status = 401
        self.runtime.calls.clear()

        result = self.application.reconcile_verified_rollback(
            self.latest_receipt,
            expected_receipt_sha256=expected_receipt_sha256,
        )

        self.assertIsNone(result)
        self.assertFalse(self.runtime.rollback_running)
        self.assertFalse(intent_path.exists())
        self.assertFalse(activation.proof_path.exists())
        self.assertEqual(
            capture.manifest_tree(backup / "rollback-data"),
            payload["data_manifest"],
        )

    def test_reconciliation_writer_failure_cleans_without_wedging_intent(
        self,
    ) -> None:
        payload, expected_receipt_sha256, intent_path = (
            self.prepare_running_activation_intent()
        )
        backup = Path(payload["backup"]["root"])
        failure = OSError("injected transient proof writer failure")

        def fail_proof_write(target: Path, value: object) -> None:
            if target.name == "rollback-activation.json":
                raise failure
            capture.write_json_0600_atomic(target, value)

        self.application.receipt_writer = fail_proof_write

        with self.assertRaises(OSError) as raised:
            self.application.reconcile_verified_rollback(
                self.latest_receipt,
                expected_receipt_sha256=expected_receipt_sha256,
            )

        self.assertIs(raised.exception, failure)
        self.assertFalse(self.runtime.rollback_running)
        self.assertFalse(intent_path.exists())
        self.assertFalse((backup / "rollback-activation.json").exists())
        self.assertEqual(
            capture.manifest_tree(backup / "rollback-data"),
            payload["data_manifest"],
        )
        self.assertIsNone(
            self.application.reconcile_verified_rollback(
                self.latest_receipt,
                expected_receipt_sha256=expected_receipt_sha256,
            ),
        )

    def test_reconciliation_discards_proof_published_before_writer_failure(
        self,
    ) -> None:
        payload, expected_receipt_sha256, intent_path = (
            self.prepare_running_activation_intent()
        )
        backup = Path(payload["backup"]["root"])
        proof_path = backup / "rollback-activation.json"
        failure = OSError("injected post-publication writer failure")

        def publish_then_fail(target: Path, value: object) -> None:
            capture.write_json_0600_atomic(target, value)
            if target == proof_path:
                raise failure

        self.application.receipt_writer = publish_then_fail

        with self.assertRaises(OSError) as raised:
            self.application.reconcile_verified_rollback(
                self.latest_receipt,
                expected_receipt_sha256=expected_receipt_sha256,
            )

        self.assertIs(raised.exception, failure)
        self.assertFalse(self.runtime.rollback_running)
        self.assertFalse(intent_path.exists())
        self.assertFalse(proof_path.exists())
        self.assertEqual(
            capture.manifest_tree(backup / "rollback-data"),
            payload["data_manifest"],
        )

    def test_reconciliation_discards_partial_proof_created_by_current_attempt(
        self,
    ) -> None:
        payload, expected_receipt_sha256, intent_path = (
            self.prepare_running_activation_intent()
        )
        backup = Path(payload["backup"]["root"])
        proof_path = backup / "rollback-activation.json"

        def write_partial_proof(target: Path, value: object) -> None:
            if target == proof_path:
                target.write_text('{"partial":', encoding="utf-8")
                target.chmod(0o600)
                return
            capture.write_json_0600_atomic(target, value)

        self.application.receipt_writer = write_partial_proof

        with self.assertRaisesRegex(capture.CaptureError, "not valid JSON"):
            self.application.reconcile_verified_rollback(
                self.latest_receipt,
                expected_receipt_sha256=expected_receipt_sha256,
            )

        self.assertFalse(self.runtime.rollback_running)
        self.assertFalse(intent_path.exists())
        self.assertFalse(proof_path.exists())
        self.assertEqual(
            capture.manifest_tree(backup / "rollback-data"),
            payload["data_manifest"],
        )
        self.assertIsNone(
            self.application.reconcile_verified_rollback(
                self.latest_receipt,
                expected_receipt_sha256=expected_receipt_sha256,
            ),
        )

    def test_reconciliation_retries_transient_partial_proof_discard_after_down(
        self,
    ) -> None:
        payload, expected_receipt_sha256, intent_path = (
            self.prepare_running_activation_intent()
        )
        backup = Path(payload["backup"]["root"])
        proof_path = backup / "rollback-activation.json"
        original_discard = self.application._discard_failed_activation_proof
        discard_attempts = 0
        observed_running: list[bool] = []
        observed_manifests: list[dict[str, object]] = []

        def write_partial_proof(target: Path, value: object) -> None:
            if target == proof_path:
                target.write_text('{"partial":', encoding="utf-8")
                target.chmod(0o600)
                return
            capture.write_json_0600_atomic(target, value)

        def transient_discard_failure(target: Path) -> None:
            nonlocal discard_attempts
            discard_attempts += 1
            observed_running.append(self.runtime.rollback_running)
            observed_manifests.append(
                capture.manifest_tree(backup / "rollback-data"),
            )
            if discard_attempts == 1:
                raise OSError("injected transient unlink failure")
            original_discard(target)

        self.application.receipt_writer = write_partial_proof

        with mock.patch.object(
            self.application,
            "_discard_failed_activation_proof",
            side_effect=transient_discard_failure,
        ):
            with self.assertRaisesRegex(capture.CaptureError, "not valid JSON"):
                self.application.reconcile_verified_rollback(
                    self.latest_receipt,
                    expected_receipt_sha256=expected_receipt_sha256,
                )

        self.assertEqual(discard_attempts, 2)
        self.assertEqual(observed_running, [False, False])
        self.assertTrue(
            all(
                manifest == payload["data_manifest"]
                for manifest in observed_manifests
            ),
        )
        self.assertFalse(intent_path.exists())
        self.assertFalse(proof_path.exists())
        self.assertIsNone(
            self.application.reconcile_verified_rollback(
                self.latest_receipt,
                expected_receipt_sha256=expected_receipt_sha256,
            ),
        )

    def test_reconciliation_persistent_proof_discard_failure_preserves_claims(
        self,
    ) -> None:
        _payload, expected_receipt_sha256, intent_path = (
            self.prepare_running_activation_intent()
        )
        proof_path = intent_path.parent / "rollback-activation.json"

        def write_partial_proof(target: Path, value: object) -> None:
            if target == proof_path:
                target.write_text('{"partial":', encoding="utf-8")
                target.chmod(0o600)
                return
            capture.write_json_0600_atomic(target, value)

        self.application.receipt_writer = write_partial_proof

        with mock.patch.object(
            self.application,
            "_discard_failed_activation_proof",
            side_effect=OSError("injected persistent unlink failure"),
        ) as discard:
            with self.assertRaisesRegex(
                capture.CaptureError,
                "reconciliation cleanup",
            ):
                self.application.reconcile_verified_rollback(
                    self.latest_receipt,
                    expected_receipt_sha256=expected_receipt_sha256,
                )

        self.assertEqual(discard.call_count, 2)
        self.assertFalse(self.runtime.rollback_running)
        self.assertTrue(intent_path.exists())
        self.assertTrue(proof_path.exists())

    def test_reconciliation_discards_tampered_proof_created_by_current_attempt(
        self,
    ) -> None:
        payload, expected_receipt_sha256, intent_path = (
            self.prepare_running_activation_intent()
        )
        backup = Path(payload["backup"]["root"])
        proof_path = backup / "rollback-activation.json"

        def write_tampered_proof(target: Path, value: object) -> None:
            if target == proof_path:
                envelope = json.loads(json.dumps(value))
                proof = capture.validate_receipt_envelope(envelope)
                proof["container_id"] = self.runtime.FOREIGN_ROLLBACK_ID
                value = capture.make_receipt_envelope(proof)
            capture.write_json_0600_atomic(target, value)

        self.application.receipt_writer = write_tampered_proof

        with self.assertRaisesRegex(capture.CaptureError, "identity"):
            self.application.reconcile_verified_rollback(
                self.latest_receipt,
                expected_receipt_sha256=expected_receipt_sha256,
            )

        self.assertFalse(self.runtime.rollback_running)
        self.assertFalse(intent_path.exists())
        self.assertFalse(proof_path.exists())
        self.assertEqual(
            capture.manifest_tree(backup / "rollback-data"),
            payload["data_manifest"],
        )

    def test_reconciliation_does_not_discard_unbound_preexisting_proof(
        self,
    ) -> None:
        payload = self.capture_successfully()
        expected_receipt_sha256 = self.receipt_sha256()
        activation = self.application.activate_verified_rollback(
            self.latest_receipt,
            expected_receipt_sha256=expected_receipt_sha256,
        )
        intent_path = self.write_activation_intent(
            payload,
            expected_receipt_sha256,
        )
        activation.proof_path.write_text('{"tampered":true}\n', encoding="utf-8")
        activation.proof_path.chmod(0o600)
        self.runtime.calls.clear()

        with self.assertRaises(capture.CaptureError):
            self.application.reconcile_verified_rollback(
                self.latest_receipt,
                expected_receipt_sha256=expected_receipt_sha256,
            )

        self.assertTrue(self.runtime.rollback_running)
        self.assertTrue(intent_path.exists())
        self.assertTrue(activation.proof_path.exists())
        self.assertFalse(any("down" in call for call in self.runtime.calls))

    def test_reconciliation_cli_reports_health_failure_as_safely_inactive(
        self,
    ) -> None:
        _payload, expected_receipt_sha256, _intent_path = (
            self.prepare_running_activation_intent()
        )
        self.runtime.management_status = 401

        with (
            mock.patch.object(
                capture,
                "CaptureApplication",
                return_value=self.application,
            ),
            mock.patch("builtins.print") as output,
        ):
            result = capture.main(
                [
                    "reconcile-rollback",
                    "--receipt",
                    str(self.latest_receipt),
                    "--expected-receipt-sha256",
                    expected_receipt_sha256,
                ],
            )

        rendered = "\n".join(
            str(argument)
            for call in output.call_args_list
            for argument in call.args
        )
        self.assertEqual(result, 0)
        self.assertIn("reconciliation complete: inactive", rendered)
        self.assertNotIn("error:", rendered)
        self.assertFalse(self.runtime.rollback_running)

    def test_reconciliation_refuses_tampered_intent_without_down(self) -> None:
        payload = self.capture_successfully()
        expected_receipt_sha256 = self.receipt_sha256()
        intent_path = self.write_activation_intent(
            payload,
            expected_receipt_sha256,
        )
        envelope = json.loads(intent_path.read_text(encoding="utf-8"))
        intent = capture.validate_receipt_envelope(envelope)
        intent["project"] = "mail-sandbox-stalwart-rollback-foreign"
        capture.write_json_0600_atomic(
            intent_path,
            capture.make_receipt_envelope(intent),
        )
        self.runtime.calls.clear()

        with self.assertRaisesRegex(capture.CaptureError, "intent identity"):
            self.application.reconcile_verified_rollback(
                self.latest_receipt,
                expected_receipt_sha256=expected_receipt_sha256,
            )

        self.assertTrue(intent_path.exists())
        self.assertFalse(any("down" in call for call in self.runtime.calls))

    def test_reconciliation_refuses_unclaimed_stopped_compose_container(
        self,
    ) -> None:
        self.capture_successfully()
        self.runtime.rollback_compose_id_override = self.runtime.FOREIGN_ROLLBACK_ID
        self.runtime.calls.clear()

        with self.assertRaisesRegex(capture.CaptureError, "unclaimed"):
            self.application.reconcile_verified_rollback(
                self.latest_receipt,
                expected_receipt_sha256=self.receipt_sha256(),
            )

        self.assertEqual(
            self.runtime.rollback_compose_id_override,
            self.runtime.FOREIGN_ROLLBACK_ID,
        )
        self.assertFalse(any("down" in call for call in self.runtime.calls))

    def test_reconciliation_cleans_exact_stopped_intent_runtime(self) -> None:
        payload = self.capture_successfully()
        expected_receipt_sha256 = self.receipt_sha256()
        intent_path = self.write_activation_intent(
            payload,
            expected_receipt_sha256,
        )
        self.runtime.rollback_compose_id_override = self.runtime.ROLLBACK_ID
        self.runtime.rollback_running = False
        current = Path(payload["backup"]["root"]) / "rollback-data" / "CURRENT"
        current.write_bytes(current.read_bytes() + b"stopped-crash-state")
        self.runtime.calls.clear()

        result = self.application.reconcile_verified_rollback(
            self.latest_receipt,
            expected_receipt_sha256=expected_receipt_sha256,
        )

        self.assertIsNone(result)
        self.assertFalse(intent_path.exists())
        self.assertIsNone(self.runtime.rollback_compose_id_override)
        self.assertEqual(
            capture.manifest_tree(Path(payload["backup"]["root"]) / "rollback-data"),
            payload["data_manifest"],
        )
        down_calls = [call for call in self.runtime.calls if "down" in call]
        self.assertEqual(len(down_calls), 1)
        self.assertNotIn("-v", down_calls[0])
        self.assertNotIn("--volumes", down_calls[0])

    def test_reconciliation_finishes_published_proof_transition_without_restart(
        self,
    ) -> None:
        payload = self.capture_successfully()
        expected_receipt_sha256 = self.receipt_sha256()
        activation = self.application.activate_verified_rollback(
            self.latest_receipt,
            expected_receipt_sha256=expected_receipt_sha256,
        )
        intent_path = self.write_activation_intent(
            payload,
            expected_receipt_sha256,
        )
        self.runtime.calls.clear()

        reconciled = self.application.reconcile_verified_rollback(
            self.latest_receipt,
            expected_receipt_sha256=expected_receipt_sha256,
        )

        self.assertIsInstance(reconciled, capture.VerifiedRollbackActivation)
        self.assertEqual(reconciled.proof_path, activation.proof_path)
        self.assertTrue(self.runtime.rollback_running)
        self.assertTrue(activation.proof_path.exists())
        self.assertFalse(intent_path.exists())
        self.assertFalse(any("up" in call for call in self.runtime.calls))
        self.assertFalse(any("down" in call for call in self.runtime.calls))

    def test_reconciliation_refuses_active_source_tamper_without_down(self) -> None:
        payload = self.capture_successfully()
        expected_receipt_sha256 = self.receipt_sha256()
        activation = self.application.activate_verified_rollback(
            self.latest_receipt,
            expected_receipt_sha256=expected_receipt_sha256,
        )
        backup = Path(payload["backup"]["root"])
        (backup / "config.toml").write_bytes(
            (backup / "config.toml").read_bytes() + b"# tampered\n",
        )
        self.runtime.calls.clear()

        with self.assertRaisesRegex(capture.CaptureError, "digest"):
            self.application.reconcile_verified_rollback(
                self.latest_receipt,
                expected_receipt_sha256=expected_receipt_sha256,
            )

        self.assertTrue(self.runtime.rollback_running)
        self.assertTrue(activation.proof_path.exists())
        self.assertFalse(any("down" in call for call in self.runtime.calls))

    def test_activation_cleanup_preserves_proof_until_intent_removal_succeeds(
        self,
    ) -> None:
        payload = self.capture_successfully()
        backup = Path(payload["backup"]["root"])
        expected_receipt_sha256 = self.receipt_sha256()

        with mock.patch.object(
            self.application,
            "_remove_activation_intent",
            side_effect=capture.CaptureError("injected intent removal failure"),
        ):
            with self.assertRaisesRegex(capture.CaptureError, "activation cleanup"):
                self.application.activate_verified_rollback(
                    self.latest_receipt,
                    expected_receipt_sha256=expected_receipt_sha256,
                )

        self.assertFalse(self.runtime.rollback_running)
        self.assertTrue((backup / "rollback-activation-intent.json").is_file())
        self.assertTrue((backup / "rollback-activation.json").is_file())
        self.assertEqual(
            capture.manifest_tree(backup / "rollback-data"),
            payload["data_manifest"],
        )

        result = self.application.reconcile_verified_rollback(
            self.latest_receipt,
            expected_receipt_sha256=expected_receipt_sha256,
        )

        self.assertIsNone(result)
        self.assertFalse((backup / "rollback-activation-intent.json").exists())
        self.assertFalse((backup / "rollback-activation.json").exists())

    def test_activation_cleanup_retries_partial_proof_discard_before_intent(
        self,
    ) -> None:
        payload = self.capture_successfully()
        backup = Path(payload["backup"]["root"])
        proof_path = backup / "rollback-activation.json"
        intent_path = backup / "rollback-activation-intent.json"
        expected_receipt_sha256 = self.receipt_sha256()
        original_discard = self.application._discard_failed_activation_proof
        discard_attempts = 0

        class InjectedFatal(BaseException):
            pass

        failure = InjectedFatal("injected partial proof publication interruption")

        def publish_partial_then_interrupt(target: Path, value: object) -> None:
            if target == proof_path:
                target.write_text('{"partial":', encoding="utf-8")
                target.chmod(0o600)
                raise failure
            capture.write_json_0600_atomic(target, value)

        def transient_discard_failure(target: Path) -> None:
            nonlocal discard_attempts
            discard_attempts += 1
            self.assertFalse(self.runtime.rollback_running)
            self.assertTrue(intent_path.exists())
            if discard_attempts == 1:
                raise OSError("injected transient proof unlink failure")
            original_discard(target)

        self.application.receipt_writer = publish_partial_then_interrupt

        with mock.patch.object(
            self.application,
            "_discard_failed_activation_proof",
            side_effect=transient_discard_failure,
        ):
            with self.assertRaises(InjectedFatal) as raised:
                self.application.activate_verified_rollback(
                    self.latest_receipt,
                    expected_receipt_sha256=expected_receipt_sha256,
                )

        self.assertIs(raised.exception, failure)
        self.assertEqual(discard_attempts, 2)
        self.assertFalse(self.runtime.rollback_running)
        self.assertFalse(intent_path.exists())
        self.assertFalse(proof_path.exists())
        self.assertEqual(
            capture.manifest_tree(backup / "rollback-data"),
            payload["data_manifest"],
        )

    def test_activation_cleanup_persistent_partial_discard_preserves_claims(
        self,
    ) -> None:
        payload = self.capture_successfully()
        backup = Path(payload["backup"]["root"])
        proof_path = backup / "rollback-activation.json"
        intent_path = backup / "rollback-activation-intent.json"

        def publish_partial_proof(target: Path, value: object) -> None:
            if target == proof_path:
                target.write_text('{"partial":', encoding="utf-8")
                target.chmod(0o600)
                return
            capture.write_json_0600_atomic(target, value)

        self.application.receipt_writer = publish_partial_proof

        with mock.patch.object(
            self.application,
            "_discard_failed_activation_proof",
            side_effect=OSError("injected persistent proof unlink failure"),
        ) as discard:
            with self.assertRaisesRegex(
                capture.CaptureError,
                "activation cleanup",
            ):
                self.application.activate_verified_rollback(
                    self.latest_receipt,
                    expected_receipt_sha256=self.receipt_sha256(),
                )

        self.assertEqual(discard.call_count, 2)
        self.assertFalse(self.runtime.rollback_running)
        self.assertTrue(intent_path.exists())
        self.assertTrue(proof_path.exists())
        self.assertEqual(
            capture.manifest_tree(backup / "rollback-data"),
            payload["data_manifest"],
        )

    def test_activation_preserves_primary_baseexception_identity_after_cleanup(
        self,
    ) -> None:
        payload = self.capture_successfully()
        backup = Path(payload["backup"]["root"])
        expected_receipt_sha256 = self.receipt_sha256()

        class InjectedFatal(BaseException):
            pass

        failure = InjectedFatal("injected proof publication interruption")

        def interrupt_proof(target: Path, value: object) -> None:
            if target.name == "rollback-activation.json":
                raise failure
            capture.write_json_0600_atomic(target, value)

        self.application.receipt_writer = interrupt_proof

        with self.assertRaises(InjectedFatal) as raised:
            self.application.activate_verified_rollback(
                self.latest_receipt,
                expected_receipt_sha256=expected_receipt_sha256,
            )

        self.assertIs(raised.exception, failure)
        self.assertFalse(self.runtime.rollback_running)
        self.assertFalse((backup / "rollback-activation-intent.json").exists())
        self.assertFalse((backup / "rollback-activation.json").exists())
        self.assertEqual(
            capture.manifest_tree(backup / "rollback-data"),
            payload["data_manifest"],
        )

    def test_deactivate_verified_rollback_rebinds_refreshes_and_removes_proof(
        self,
    ) -> None:
        payload = self.capture_successfully()
        backup = Path(payload["backup"]["root"])
        expected_receipt_sha256 = self.receipt_sha256()
        activation = self.application.activate_verified_rollback(
            self.latest_receipt,
            expected_receipt_sha256=expected_receipt_sha256,
        )
        current = backup / "rollback-data" / "CURRENT"
        current.write_bytes(current.read_bytes() + b"recovery-runtime-write")
        self.runtime.calls.clear()

        self.application.deactivate_verified_rollback(
            self.latest_receipt,
            expected_receipt_sha256=expected_receipt_sha256,
        )

        self.assertFalse(self.runtime.rollback_running)
        self.assertFalse(activation.proof_path.exists())
        self.assertEqual(
            capture.manifest_tree(backup / "rollback-data"),
            payload["data_manifest"],
        )
        down_calls = [call for call in self.runtime.calls if "down" in call]
        self.assertEqual(len(down_calls), 1)
        self.assertNotIn("-v", down_calls[0])
        self.assertNotIn("--volumes", down_calls[0])
        self.assertEqual(
            down_calls[0][:8],
            [
                "docker",
                "compose",
                "--project-directory",
                str(backup),
                "-p",
                str(payload["rollback"]["project"]),
                "-f",
                str(backup / "rollback.compose.json"),
            ],
        )
        self.assertEqual(down_calls[0][-1], "down")
        self.assertFalse(any("up" in call for call in self.runtime.calls))
        self.application.verify(self.latest_receipt)

    def test_deactivation_finishes_published_proof_transition_intent(self) -> None:
        payload = self.capture_successfully()
        expected_receipt_sha256 = self.receipt_sha256()
        activation = self.application.activate_verified_rollback(
            self.latest_receipt,
            expected_receipt_sha256=expected_receipt_sha256,
        )
        intent_path = self.write_activation_intent(
            payload,
            expected_receipt_sha256,
        )

        self.application.deactivate_verified_rollback(
            self.latest_receipt,
            expected_receipt_sha256=expected_receipt_sha256,
        )

        self.assertFalse(self.runtime.rollback_running)
        self.assertFalse(intent_path.exists())
        self.assertFalse(activation.proof_path.exists())

    def test_deactivation_uses_structural_ownership_when_runtime_is_unhealthy(
        self,
    ) -> None:
        self.capture_successfully()
        expected_receipt_sha256 = self.receipt_sha256()
        activation = self.application.activate_verified_rollback(
            self.latest_receipt,
            expected_receipt_sha256=expected_receipt_sha256,
        )
        self.runtime.calls.clear()

        with mock.patch.object(
            self.application,
            "_rollback_version",
            side_effect=AssertionError("deactivation must not require health"),
        ), mock.patch.object(
            self.application,
            "management_probe",
            side_effect=AssertionError("deactivation must not require health"),
        ):
            self.application.deactivate_verified_rollback(
                self.latest_receipt,
                expected_receipt_sha256=expected_receipt_sha256,
            )

        self.assertFalse(self.runtime.rollback_running)
        self.assertFalse(activation.proof_path.exists())
        self.assertEqual(
            len([call for call in self.runtime.calls if "down" in call]),
            1,
        )

    def test_deactivate_verified_rollback_refuses_tampered_activation_identity(
        self,
    ) -> None:
        payload = self.capture_successfully()
        expected_receipt_sha256 = self.receipt_sha256()
        activation = self.application.activate_verified_rollback(
            self.latest_receipt,
            expected_receipt_sha256=expected_receipt_sha256,
        )
        envelope = json.loads(activation.proof_path.read_text(encoding="utf-8"))
        activation_payload = capture.validate_receipt_envelope(envelope)
        activation_payload["container_id"] = self.runtime.FOREIGN_ROLLBACK_ID
        capture.write_json_0600_atomic(
            activation.proof_path,
            capture.make_receipt_envelope(activation_payload),
        )
        down_calls_before = len(
            [call for call in self.runtime.calls if "down" in call],
        )

        with self.assertRaisesRegex(capture.CaptureError, "identity"):
            self.application.deactivate_verified_rollback(
                self.latest_receipt,
                expected_receipt_sha256=expected_receipt_sha256,
            )

        self.assertTrue(self.runtime.rollback_running)
        self.assertTrue(activation.proof_path.exists())
        self.assertEqual(
            len([call for call in self.runtime.calls if "down" in call]),
            down_calls_before,
        )
        self.assertNotEqual(
            capture.manifest_tree(Path(payload["backup"]["root"]) / "rollback-data"),
            payload["data_manifest"],
        )

    def test_activation_proof_write_failure_downs_and_refreshes_runtime(self) -> None:
        payload = self.capture_successfully()
        backup = Path(payload["backup"]["root"])
        expected_receipt_sha256 = self.receipt_sha256()

        def fail_activation_proof(target: Path, value: object) -> None:
            if target.name == "rollback-activation.json":
                raise OSError("injected activation proof publication failure")
            capture.write_json_0600_atomic(target, value)

        self.application.receipt_writer = fail_activation_proof
        self.runtime.calls.clear()

        with self.assertRaises(OSError):
            self.application.activate_verified_rollback(
                self.latest_receipt,
                expected_receipt_sha256=expected_receipt_sha256,
            )

        self.assertFalse(self.runtime.rollback_running)
        self.assertFalse((backup / "rollback-activation.json").exists())
        self.assertFalse((backup / "rollback-activation-intent.json").exists())
        self.assertEqual(
            capture.manifest_tree(backup / "rollback-data"),
            payload["data_manifest"],
        )
        self.assertEqual(
            len([call for call in self.runtime.calls if "up" in call]),
            1,
        )
        self.assertEqual(
            len([call for call in self.runtime.calls if "down" in call]),
            1,
        )

    def test_activation_cleanup_keeps_intent_if_immutable_source_changes(
        self,
    ) -> None:
        payload = self.capture_successfully()
        backup = Path(payload["backup"]["root"])

        def tamper_before_proof(target: Path, value: object) -> None:
            if target.name == "rollback-activation.json":
                (backup / "config.toml").write_bytes(
                    (backup / "config.toml").read_bytes() + b"# tampered\n",
                )
                raise OSError("injected proof publication failure")
            capture.write_json_0600_atomic(target, value)

        self.application.receipt_writer = tamper_before_proof

        with self.assertRaisesRegex(capture.CaptureError, "activation cleanup"):
            self.application.activate_verified_rollback(
                self.latest_receipt,
                expected_receipt_sha256=self.receipt_sha256(),
            )

        self.assertFalse(self.runtime.rollback_running)
        self.assertTrue((backup / "rollback-activation-intent.json").is_file())
        self.assertFalse((backup / "rollback-activation.json").exists())

    def test_activation_cleanup_rejects_stopped_compose_container_left_by_down(
        self,
    ) -> None:
        payload = self.capture_successfully()
        backup = Path(payload["backup"]["root"])
        self.runtime.rollback_down_leaves_stopped_container = True

        def fail_activation_proof(target: Path, value: object) -> None:
            if target.name == "rollback-activation.json":
                raise OSError("injected activation proof publication failure")
            capture.write_json_0600_atomic(target, value)

        self.application.receipt_writer = fail_activation_proof

        with self.assertRaisesRegex(capture.CaptureError, "activation cleanup"):
            self.application.activate_verified_rollback(
                self.latest_receipt,
                expected_receipt_sha256=self.receipt_sha256(),
            )

        self.assertFalse(self.runtime.rollback_running)
        self.assertEqual(
            self.runtime.rollback_compose_id_override,
            self.runtime.ROLLBACK_ID,
        )
        self.assertFalse((backup / "rollback-activation.json").exists())
        self.assertEqual(
            capture.manifest_tree(backup / "rollback-data"),
            payload["data_manifest"],
        )
        compose_ps_calls = [
            call
            for call in self.runtime.calls
            if call[:2] == ["docker", "compose"]
            and "ps" in call
            and "--status" not in call
        ]
        self.assertTrue(compose_ps_calls)
        self.assertTrue(all("--all" in call for call in compose_ps_calls))

    def test_activation_cleanup_preserves_published_proof_when_down_fails(
        self,
    ) -> None:
        payload = self.capture_successfully()
        backup = Path(payload["backup"]["root"])
        expected_receipt_sha256 = self.receipt_sha256()
        self.runtime.fail_rollback_down = True

        with mock.patch.object(
            self.application,
            "_read_activation_proof",
            side_effect=capture.CaptureError(
                "injected post-publication validation failure",
            ),
        ):
            with self.assertRaisesRegex(capture.CaptureError, "activation cleanup"):
                self.application.activate_verified_rollback(
                    self.latest_receipt,
                    expected_receipt_sha256=expected_receipt_sha256,
                )

        proof_path = backup / "rollback-activation.json"
        self.assertTrue(self.runtime.rollback_running)
        self.assertTrue(proof_path.is_file())
        self.assertEqual(stat.S_IMODE(proof_path.stat().st_mode), 0o600)
        activation_payload = capture.validate_receipt_envelope(
            json.loads(proof_path.read_text(encoding="utf-8")),
        )
        self.assertEqual(
            activation_payload["source_receipt_sha256"],
            expected_receipt_sha256,
        )
        self.assertNotEqual(
            capture.manifest_tree(backup / "rollback-data"),
            payload["data_manifest"],
        )

    def test_activation_rejects_runtime_with_wrong_admin_environment(self) -> None:
        payload = self.capture_successfully()
        backup = Path(payload["backup"]["root"])
        self.runtime.rollback_environment = [
            "ADMIN_SECRET=different-value",
        ]

        with self.assertRaisesRegex(capture.CaptureError, "environment|secret"):
            self.application.activate_verified_rollback(
                self.latest_receipt,
                expected_receipt_sha256=self.receipt_sha256(),
            )

        self.assertFalse(self.runtime.rollback_running)
        self.assertFalse((backup / "rollback-activation.json").exists())
        self.assertEqual(
            capture.manifest_tree(backup / "rollback-data"),
            payload["data_manifest"],
        )

    def test_activation_foreign_race_stops_only_own_copy_and_refreshes_data(
        self,
    ) -> None:
        payload = self.capture_successfully()
        backup = Path(payload["backup"]["root"])
        self.runtime.foreign_rollback_after_up = True

        with self.assertRaisesRegex(capture.CaptureError, "activation|rollback"):
            self.application.activate_verified_rollback(
                self.latest_receipt,
                expected_receipt_sha256=self.receipt_sha256(),
            )

        self.assertFalse(self.runtime.rollback_running)
        self.assertTrue(self.runtime.foreign_rollback_running)
        self.assertFalse((backup / "rollback-activation.json").exists())
        self.assertEqual(
            capture.manifest_tree(backup / "rollback-data"),
            payload["data_manifest"],
        )

    def test_activation_replay_never_adopts_or_restarts_active_runtime(self) -> None:
        self.capture_successfully()
        expected_receipt_sha256 = self.receipt_sha256()
        activation = self.application.activate_verified_rollback(
            self.latest_receipt,
            expected_receipt_sha256=expected_receipt_sha256,
        )
        self.runtime.calls.clear()

        with self.assertRaises(capture.CaptureError):
            self.application.activate_verified_rollback(
                self.latest_receipt,
                expected_receipt_sha256=expected_receipt_sha256,
            )

        self.assertTrue(self.runtime.rollback_running)
        self.assertTrue(activation.proof_path.exists())
        self.assertFalse(any("up" in call for call in self.runtime.calls))
        self.assertFalse(any("down" in call for call in self.runtime.calls))

    def test_activation_refuses_running_orphan_without_claiming_or_stopping_it(
        self,
    ) -> None:
        payload = self.capture_successfully()
        backup = Path(payload["backup"]["root"])
        self.runtime.rollback_running = True
        self.runtime.calls.clear()

        with self.assertRaisesRegex(capture.CaptureError, "rollback copy.*running"):
            self.application.activate_verified_rollback(
                self.latest_receipt,
                expected_receipt_sha256=self.receipt_sha256(),
            )

        self.assertTrue(self.runtime.rollback_running)
        self.assertFalse((backup / "rollback-activation.json").exists())
        self.assertFalse(any("up" in call for call in self.runtime.calls))
        self.assertFalse(any("down" in call for call in self.runtime.calls))

    def test_activation_refuses_stopped_compose_container_without_adopting_it(
        self,
    ) -> None:
        payload = self.capture_successfully()
        backup = Path(payload["backup"]["root"])
        self.runtime.rollback_compose_id_override = self.runtime.FOREIGN_ROLLBACK_ID
        self.runtime.calls.clear()

        with self.assertRaisesRegex(capture.CaptureError, "Compose container"):
            self.application.activate_verified_rollback(
                self.latest_receipt,
                expected_receipt_sha256=self.receipt_sha256(),
            )

        self.assertEqual(
            self.runtime.rollback_compose_id_override,
            self.runtime.FOREIGN_ROLLBACK_ID,
        )
        self.assertFalse(self.runtime.rollback_running)
        self.assertFalse((backup / "rollback-activation.json").exists())
        self.assertFalse(
            (backup / "rollback-activation-intent.json").exists(),
        )
        self.assertFalse(any("up" in call for call in self.runtime.calls))
        self.assertFalse(any("down" in call for call in self.runtime.calls))

    def test_deactivation_down_failure_preserves_active_proof_and_working_data(
        self,
    ) -> None:
        payload = self.capture_successfully()
        backup = Path(payload["backup"]["root"])
        expected_receipt_sha256 = self.receipt_sha256()
        activation = self.application.activate_verified_rollback(
            self.latest_receipt,
            expected_receipt_sha256=expected_receipt_sha256,
        )
        dirty_manifest = capture.manifest_tree(backup / "rollback-data")
        self.runtime.fail_rollback_down = True
        copies_before = len(self.runtime.copy_destinations)

        with self.assertRaisesRegex(capture.CaptureError, "deactivation"):
            self.application.deactivate_verified_rollback(
                self.latest_receipt,
                expected_receipt_sha256=expected_receipt_sha256,
            )

        self.assertTrue(self.runtime.rollback_running)
        self.assertTrue(activation.proof_path.exists())
        self.assertEqual(
            capture.manifest_tree(backup / "rollback-data"),
            dirty_manifest,
        )
        self.assertEqual(len(self.runtime.copy_destinations), copies_before)

    def test_deactivation_requires_compose_container_census_empty_after_down(
        self,
    ) -> None:
        self.capture_successfully()
        expected_receipt_sha256 = self.receipt_sha256()
        activation = self.application.activate_verified_rollback(
            self.latest_receipt,
            expected_receipt_sha256=expected_receipt_sha256,
        )
        self.runtime.rollback_down_leaves_stopped_container = True

        with self.assertRaisesRegex(capture.CaptureError, "deactivation"):
            self.application.deactivate_verified_rollback(
                self.latest_receipt,
                expected_receipt_sha256=expected_receipt_sha256,
            )

        self.assertFalse(self.runtime.rollback_running)
        self.assertTrue(activation.proof_path.exists())

    def test_deactivation_can_resume_refresh_after_runtime_is_already_down(self) -> None:
        payload = self.capture_successfully()
        backup = Path(payload["backup"]["root"])
        expected_receipt_sha256 = self.receipt_sha256()
        activation = self.application.activate_verified_rollback(
            self.latest_receipt,
            expected_receipt_sha256=expected_receipt_sha256,
        )
        self.runtime.fail_copy = True

        with self.assertRaisesRegex(capture.CaptureError, "deactivation"):
            self.application.deactivate_verified_rollback(
                self.latest_receipt,
                expected_receipt_sha256=expected_receipt_sha256,
            )

        self.assertFalse(self.runtime.rollback_running)
        self.assertTrue(activation.proof_path.exists())
        self.runtime.fail_copy = False
        self.application.deactivate_verified_rollback(
            self.latest_receipt,
            expected_receipt_sha256=expected_receipt_sha256,
        )

        self.assertFalse(activation.proof_path.exists())
        self.assertEqual(
            capture.manifest_tree(backup / "rollback-data"),
            payload["data_manifest"],
        )

    def test_deactivation_refuses_foreign_stopped_compose_container(self) -> None:
        self.capture_successfully()
        expected_receipt_sha256 = self.receipt_sha256()
        activation = self.application.activate_verified_rollback(
            self.latest_receipt,
            expected_receipt_sha256=expected_receipt_sha256,
        )
        self.runtime.rollback_running = False
        self.runtime.rollback_compose_id_override = self.runtime.FOREIGN_ROLLBACK_ID
        self.runtime.calls.clear()

        with self.assertRaisesRegex(capture.CaptureError, "identity"):
            self.application.deactivate_verified_rollback(
                self.latest_receipt,
                expected_receipt_sha256=expected_receipt_sha256,
            )

        self.assertTrue(activation.proof_path.exists())
        self.assertFalse(any("down" in call for call in self.runtime.calls))

    def test_deactivation_refuses_foreign_running_census_without_down(self) -> None:
        self.capture_successfully()
        expected_receipt_sha256 = self.receipt_sha256()
        activation = self.application.activate_verified_rollback(
            self.latest_receipt,
            expected_receipt_sha256=expected_receipt_sha256,
        )
        self.runtime.foreign_rollback_running = True
        self.runtime.calls.clear()

        with self.assertRaisesRegex(capture.CaptureError, "identity"):
            self.application.deactivate_verified_rollback(
                self.latest_receipt,
                expected_receipt_sha256=expected_receipt_sha256,
            )

        self.assertTrue(self.runtime.rollback_running)
        self.assertTrue(self.runtime.foreign_rollback_running)
        self.assertTrue(activation.proof_path.exists())
        self.assertFalse(any("down" in call for call in self.runtime.calls))

    def test_deactivation_refuses_missing_proof_without_down(self) -> None:
        self.capture_successfully()
        expected_receipt_sha256 = self.receipt_sha256()
        activation = self.application.activate_verified_rollback(
            self.latest_receipt,
            expected_receipt_sha256=expected_receipt_sha256,
        )
        activation.proof_path.unlink()
        self.runtime.calls.clear()

        with self.assertRaisesRegex(capture.CaptureError, "activation proof"):
            self.application.deactivate_verified_rollback(
                self.latest_receipt,
                expected_receipt_sha256=expected_receipt_sha256,
            )

        self.assertTrue(self.runtime.rollback_running)
        self.assertFalse(any("down" in call for call in self.runtime.calls))

    def test_verified_rollback_callback_receives_exact_redacted_endpoint_once_in_order(
        self,
    ) -> None:
        payload = self.capture_successfully()
        backup = Path(payload["backup"]["root"])
        self.runtime.events.clear()
        callback_calls = 0
        endpoint_repr = ""
        lock_events: list[str] = []
        original_backup_lock = self.application._rollback_proof_lock
        original_global_lock = self.application._global_rollback_proof_lock

        @contextmanager
        def backup_lock(path: Path) -> object:
            lock_events.append("backup-enter")
            with original_backup_lock(path):
                yield
            lock_events.append("backup-exit")

        @contextmanager
        def global_lock(path: Path) -> object:
            self.assertTrue((backup / ".rollback-proof.lock").exists())
            lock_events.append("global-enter")
            with original_global_lock(path):
                yield
            lock_events.append("global-exit")

        def operation(endpoint: object) -> dict[str, str]:
            nonlocal callback_calls, endpoint_repr
            callback_calls += 1
            lock_events.append("callback")
            self.runtime.events.append("callback")
            self.assertIsInstance(endpoint, capture.VerifiedRollbackEndpoint)
            self.assertTrue(endpoint.__dataclass_params__.frozen)
            self.assertEqual(endpoint.base_url, "http://127.0.0.1:29443")
            self.assertEqual(endpoint.username, "admin")
            self.assertEqual(endpoint.password, "unit-only-value")
            self.assertEqual(endpoint.version, "0.15.5")
            self.assertTrue(self.runtime.rollback_running)
            endpoint_repr = repr(endpoint)
            current = backup / "rollback-data" / "CURRENT"
            current.write_bytes(current.read_bytes() + b"callback-write")
            return {"secret": endpoint.password}

        with (
            mock.patch.object(
                self.application,
                "_rollback_proof_lock",
                backup_lock,
            ),
            mock.patch.object(
                self.application,
                "_global_rollback_proof_lock",
                global_lock,
            ),
        ):
            result = self.application.run_verified_rollback(
                self.latest_receipt,
                expected_receipt_sha256=self.receipt_sha256(),
                operation=operation,
            )

        self.assertEqual(callback_calls, 1)
        self.assertEqual(
            lock_events,
            [
                "backup-enter",
                "global-enter",
                "callback",
                "global-exit",
                "backup-exit",
            ],
        )
        self.assertEqual(result.value, {"secret": "unit-only-value"})
        self.assertEqual(result.proof.version, "0.15.5")
        self.assertEqual(result.proof.management_status, 200)
        self.assertNotIn("unit-only-value", endpoint_repr)
        self.assertNotIn("unit-only-value", repr(result))
        self.assertLess(
            self.runtime.events.index("management"),
            self.runtime.events.index("callback"),
        )
        self.assertLess(
            self.runtime.events.index("callback"),
            len(self.runtime.events)
            - 1
            - self.runtime.events[::-1].index("management"),
        )
        self.assertLess(
            len(self.runtime.events) - 1 - self.runtime.events[::-1].index("management"),
            self.runtime.events.index("down"),
        )
        self.assertFalse(self.runtime.rollback_running)
        self.assertEqual(
            capture.manifest_tree(backup / "rollback-data"),
            payload["data_manifest"],
        )

    def test_verified_rollback_rejects_expected_digest_mismatch_before_callback(
        self,
    ) -> None:
        self.capture_successfully()
        callback_calls = 0
        up_calls = len([call for call in self.runtime.calls if "up" in call])

        def operation(endpoint: object) -> None:
            nonlocal callback_calls
            callback_calls += 1

        with self.assertRaisesRegex(capture.CaptureError, "digest"):
            self.application.run_verified_rollback(
                self.latest_receipt,
                expected_receipt_sha256="0" * 64,
                operation=operation,
            )

        self.assertEqual(callback_calls, 0)
        self.assertEqual(
            len([call for call in self.runtime.calls if "up" in call]),
            up_calls,
        )

    def test_verified_rollback_rejects_receipt_replacement_under_both_locks(
        self,
    ) -> None:
        self.capture_successfully()
        expected_digest = self.receipt_sha256()
        callback_calls = 0
        original_global_lock = self.application._global_rollback_proof_lock

        @contextmanager
        def replacing_global_lock(path: Path) -> object:
            with original_global_lock(path):
                capture.write_bytes_0600_atomic(
                    self.latest_receipt,
                    self.latest_receipt.read_bytes() + b" ",
                )
                yield

        def operation(endpoint: object) -> None:
            nonlocal callback_calls
            callback_calls += 1

        with mock.patch.object(
            self.application,
            "_global_rollback_proof_lock",
            replacing_global_lock,
        ):
            with self.assertRaisesRegex(capture.CaptureError, "digest|changed"):
                self.application.run_verified_rollback(
                    self.latest_receipt,
                    expected_receipt_sha256=expected_digest,
                    operation=operation,
                )

        self.assertEqual(callback_calls, 0)

    def test_verified_rollback_preserves_original_callback_baseexceptions(self) -> None:
        payload = self.capture_successfully()
        backup = Path(payload["backup"]["root"])
        for expected in (
            RuntimeError("callback runtime failure"),
            KeyboardInterrupt(),
            SystemExit(23),
        ):
            with self.subTest(exception=type(expected).__name__):
                callback_calls = 0

                def operation(endpoint: object) -> None:
                    nonlocal callback_calls
                    callback_calls += 1
                    raise expected

                with self.assertRaises(type(expected)) as raised:
                    self.application.run_verified_rollback(
                        self.latest_receipt,
                        expected_receipt_sha256=self.receipt_sha256(),
                        operation=operation,
                    )

                self.assertIs(raised.exception, expected)
                self.assertEqual(callback_calls, 1)
                self.assertFalse(self.runtime.rollback_running)
                self.assertEqual(
                    capture.manifest_tree(backup / "rollback-data"),
                    payload["data_manifest"],
                )

    def test_verified_rollback_readiness_failure_never_calls_operation(self) -> None:
        payload = self.capture_successfully()
        backup = Path(payload["backup"]["root"])
        self.runtime.management_status = 401
        callback_calls = 0

        def operation(endpoint: object) -> None:
            nonlocal callback_calls
            callback_calls += 1

        with self.assertRaisesRegex(capture.CaptureError, "management"):
            self.application.run_verified_rollback(
                self.latest_receipt,
                expected_receipt_sha256=self.receipt_sha256(),
                operation=operation,
            )

        self.assertEqual(callback_calls, 0)
        self.assertFalse(self.runtime.rollback_running)
        self.assertEqual(
            capture.manifest_tree(backup / "rollback-data"),
            payload["data_manifest"],
        )

    def test_verified_rollback_detects_runtime_tamper_after_callback(self) -> None:
        self.capture_successfully()
        callback_calls = 0

        def operation(endpoint: object) -> None:
            nonlocal callback_calls
            callback_calls += 1
            self.runtime.rollback_image_id = "sha256:" + ("9" * 64)

        with self.assertRaisesRegex(capture.CaptureError, "image ID"):
            self.application.run_verified_rollback(
                self.latest_receipt,
                expected_receipt_sha256=self.receipt_sha256(),
                operation=operation,
            )

        self.assertEqual(callback_calls, 1)
        self.assertFalse(self.runtime.rollback_running)

    def test_verified_rollback_cleanup_failure_overrides_and_skips_uncertain_refresh(
        self,
    ) -> None:
        payload = self.capture_successfully()
        backup = Path(payload["backup"]["root"])
        self.runtime.copy_destinations.clear()
        self.runtime.fail_rollback_down = True
        callback_error = RuntimeError("callback failure must be overridden")

        def operation(endpoint: object) -> None:
            current = backup / "rollback-data" / "CURRENT"
            current.write_bytes(current.read_bytes() + b"callback-write")
            raise callback_error

        with self.assertRaisesRegex(capture.CaptureError, "cleanup") as raised:
            self.application.run_verified_rollback(
                self.latest_receipt,
                expected_receipt_sha256=self.receipt_sha256(),
                operation=operation,
            )

        self.assertIsNot(raised.exception, callback_error)
        self.assertTrue(self.runtime.rollback_running)
        self.assertEqual(len(self.runtime.copy_destinations), 1)
        self.assertIn(
            b"callback-write",
            (backup / "rollback-data" / "CURRENT").read_bytes(),
        )

    def test_verified_rollback_rechecks_bound_receipt_after_cleanup(self) -> None:
        payload = self.capture_successfully()
        backup = Path(payload["backup"]["root"])
        expected_digest = self.receipt_sha256()
        callback_calls = 0

        def operation(endpoint: object) -> str:
            nonlocal callback_calls
            callback_calls += 1
            capture.write_bytes_0600_atomic(
                self.latest_receipt,
                self.latest_receipt.read_bytes() + b" ",
            )
            return "must-not-return"

        with self.assertRaisesRegex(capture.CaptureError, "digest|changed"):
            self.application.run_verified_rollback(
                self.latest_receipt,
                expected_receipt_sha256=expected_digest,
                operation=operation,
            )

        self.assertEqual(callback_calls, 1)
        self.assertFalse(self.runtime.rollback_running)
        self.assertEqual(
            capture.manifest_tree(backup / "rollback-data"),
            payload["data_manifest"],
        )

    def test_refresh_preserves_old_working_tree_when_atomic_publication_fails(
        self,
    ) -> None:
        payload = self.capture_successfully()
        backup = Path(payload["backup"]["root"])
        rollback_data = backup / "rollback-data"
        old_current = b"old-generated-working-state"
        (rollback_data / "CURRENT").write_bytes(old_current)
        original_replace = capture.os.replace
        destinations: list[Path] = []

        def copy_tree(source: Path, destination: Path) -> None:
            destinations.append(destination)
            capture.copy_tree(source, destination)

        def fail_new_publication(source: object, destination: object) -> None:
            source_path = Path(source)
            destination_path = Path(destination)
            if (
                source_path == backup / ".rollback-data.next"
                and destination_path == rollback_data
            ):
                raise OSError("injected publication failure")
            original_replace(source_path, destination_path)

        self.application.tree_copier = copy_tree
        with mock.patch.object(
            capture.os,
            "replace",
            side_effect=fail_new_publication,
        ):
            with self.assertRaisesRegex(capture.CaptureError, "refresh|publication"):
                self.application._refresh_rollback_data(
                    backup,
                    payload["data_manifest"],
                )

        self.assertEqual(destinations, [backup / ".rollback-data.next"])
        self.assertEqual((rollback_data / "CURRENT").read_bytes(), old_current)
        self.assertFalse((backup / ".rollback-data.next").exists())
        self.assertFalse((backup / ".rollback-data.previous").exists())

    def test_refresh_reconciles_every_persisted_publication_crash_matrix(
        self,
    ) -> None:
        payload = self.capture_successfully()
        backup = Path(payload["backup"]["root"])
        source_data = backup / "source-data"
        rollback_data = backup / "rollback-data"
        next_data = backup / ".rollback-data.next"
        previous_data = backup / ".rollback-data.previous"

        for state in (
            "rollback-next",
            "previous-next",
            "rollback-previous",
            "missing-rollback",
        ):
            with self.subTest(state=state):
                for path in (rollback_data, next_data, previous_data):
                    if path.exists():
                        shutil.rmtree(path)
                if state in {"rollback-next", "rollback-previous"}:
                    shutil.copytree(source_data, rollback_data)
                    rollback_data.chmod(0o700)
                    (rollback_data / "CURRENT").write_bytes(b"dirty-runtime-data")
                if state in {"rollback-next", "previous-next"}:
                    shutil.copytree(source_data, next_data)
                    next_data.chmod(0o700)
                if state in {"previous-next", "rollback-previous"}:
                    shutil.copytree(source_data, previous_data)
                    previous_data.chmod(0o700)
                    (previous_data / "CURRENT").write_bytes(b"older-runtime-data")

                self.application._refresh_rollback_data(
                    backup,
                    payload["data_manifest"],
                )

                self.assertEqual(
                    capture.manifest_tree(rollback_data),
                    payload["data_manifest"],
                )
                self.assertFalse(next_data.exists())
                self.assertFalse(previous_data.exists())

    def test_standalone_prove_fsyncs_each_refreshed_rollback_working_copy(self) -> None:
        payload = self.capture_successfully()
        backup = Path(payload["backup"]["root"])
        events: list[tuple[str, Path]] = []
        self.application.tree_sync = lambda path: events.append(("tree", path))
        self.application.directory_sync = lambda path: events.append(("directory", path))

        self.application.prove_rollback(self.latest_receipt)

        staging_tree = ("tree", backup / ".rollback-data.next")
        tree_event_indexes = [
            index for index, event in enumerate(events) if event == staging_tree
        ]
        self.assertEqual(len(tree_event_indexes), 2)
        for tree_event_index in tree_event_indexes:
            self.assertIn(
                ("directory", backup),
                events[tree_event_index + 1 :],
            )

    def test_rollback_replaces_image_volume_with_ephemeral_parent_tmpfs(self) -> None:
        payload = self.capture_successfully()
        backup = Path(payload["backup"]["root"])
        definition = json.loads(
            (backup / "rollback.compose.json").read_text(encoding="utf-8"),
        )
        service = definition["services"]["stalwart-rollback"]

        self.assertEqual(
            service["tmpfs"],
            ["/opt/stalwart:rw,noexec,nosuid,nodev,mode=0700"],
        )
        mounts = self.runtime.rollback_inspect()["Mounts"]
        self.assertEqual(
            [
                (mount["Type"], mount["Destination"])
                for mount in mounts
            ],
            [
                ("bind", "/opt/stalwart/etc/config.toml"),
                ("bind", "/opt/stalwart/data"),
            ],
        )
        self.assertNotIn("volume", {mount["Type"] for mount in mounts})
        self.assertEqual(
            self.runtime.rollback_inspect()["HostConfig"]["Tmpfs"],
            {
                "/opt/stalwart": "rw,noexec,nosuid,nodev,mode=0700",
            },
        )
        self.assertNotIn("networks", definition)
        self.assertNotIn("networks", service)
        self.assertEqual(
            service["labels"],
            {
                "mail.sandbox.stalwart.rollback": "v015",
            },
        )

    def test_wrong_source_version_refuses_before_stopping(self) -> None:
        self.runtime.source_version = "0.16.14"

        with self.assertRaisesRegex(capture.CaptureError, "v0.15"):
            self.application.capture("stalwart")

        self.assertTrue(self.runtime.source_running)
        self.assertFalse(self.latest_receipt.exists())

    def test_missing_and_ambiguous_legacy_service_are_refused(self) -> None:
        original = self.runtime.__call__

        def missing(args: list[str]) -> "capture.CommandResult":
            if args[:2] == ["docker", "ps"]:
                return capture.CommandResult("", "")
            return original(args)

        self.application.runner = missing
        with self.assertRaisesRegex(capture.CaptureError, "exactly one"):
            self.application.capture("stalwart")
        self.assertTrue(self.runtime.source_running)

        self.application.runner = self.runtime
        duplicate = self.runtime.source_inspect("5" * 64)
        self.runtime.extra_source_inspects.append(duplicate)
        with self.assertRaisesRegex(capture.CaptureError, "ambiguous"):
            self.application.capture("stalwart")
        self.assertTrue(self.runtime.source_running)

    def test_unsafe_labels_and_mounts_are_refused(self) -> None:
        other_compose = self.repository_root / "other-compose.yml"
        other_compose.write_text("services: {}\n", encoding="utf-8")

        def update_mount(
            record: dict[str, object],
            target: str,
            values: dict[str, object],
        ) -> None:
            mount = next(
                item
                for item in record["Mounts"]
                if item["Destination"] == target
            )
            mount.update(values)

        unsafe_cases = {
            "project label": lambda record: record["Config"]["Labels"].update(
                {"com.docker.compose.project": "../../unsafe"},
            ),
            "mount source": lambda record: update_mount(
                record,
                "/opt/stalwart/data",
                {"Source": str(self.repository_root)},
            ),
            "read-only data": lambda record: update_mount(
                record,
                "/opt/stalwart/data",
                {"RW": False},
            ),
            "config-files label": lambda record: record["Config"]["Labels"].update(
                {
                    "com.docker.compose.project.config_files": str(other_compose),
                },
            ),
        }
        for expected, mutate in unsafe_cases.items():
            with self.subTest(expected=expected):
                record = self.runtime.source_inspect()
                mutate(record)
                original = self.runtime.source_inspect
                self.runtime.source_inspect = lambda container_id=None, record=record: record
                try:
                    with self.assertRaisesRegex(capture.CaptureError, expected):
                        self.application.capture("stalwart")
                finally:
                    self.runtime.source_inspect = original
                self.assertTrue(self.runtime.source_running)
                self.assertFalse(self.latest_receipt.exists())

    def test_symlink_or_non_regular_source_entry_stops_source_without_publishing(self) -> None:
        for kind in ("symlink", "fifo"):
            with self.subTest(kind=kind):
                path = self.runtime.data_path / f"unsafe-{kind}"
                if kind == "symlink":
                    path.symlink_to("CURRENT")
                else:
                    os.mkfifo(path)
                with self.assertRaisesRegex(capture.CaptureError, "symlink|non-regular"):
                    self.application.capture("stalwart")
                self.assertFalse(self.runtime.source_running)
                self.assertFalse(self.latest_receipt.exists())
                path.unlink()
                self.runtime.source_running = True

    def test_existing_capture_lock_refuses_without_stopping_source(self) -> None:
        migration = (
            self.repository_root
            / "captures"
            / "debug-dashboard"
            / "stalwart-v015"
            / "migration"
        )
        migration.mkdir(parents=True, mode=0o700)
        lock = migration / ".capture.lock"
        lock.write_text("busy", encoding="utf-8")
        lock.chmod(0o600)

        with lock.open("r+", encoding="utf-8") as stream:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            try:
                with self.assertRaisesRegex(capture.CaptureError, "capture.*running"):
                    self.application.capture("stalwart")
            finally:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)

        self.assertTrue(self.runtime.source_running)
        self.assertFalse(self.latest_receipt.exists())

    def test_unpinned_image_refuses_before_stopping(self) -> None:
        self.runtime.repo_digests = []

        with self.assertRaisesRegex(capture.CaptureError, "immutable"):
            self.application.capture("stalwart")

        self.assertTrue(self.runtime.source_running)
        self.assertFalse(self.latest_receipt.exists())

    def test_partial_copy_never_publishes_a_receipt_and_source_stays_stopped(self) -> None:
        self.runtime.fail_copy = True

        with self.assertRaisesRegex(capture.CaptureError, "copy"):
            self.application.capture("stalwart")

        self.assertFalse(self.runtime.source_running)
        self.assertFalse(self.latest_receipt.exists())
        backup_root = (
            self.repository_root / "debug-dashboard" / ".runtime" / "stalwart-backups"
        )
        self.assertEqual(list(backup_root.glob("stalwart-v015-*")), [])

    def test_replacement_source_writer_during_copy_blocks_publication_and_is_stopped(self) -> None:
        def start_replacement(source: Path, destination: Path) -> None:
            capture.copy_tree(source, destination)
            if destination.name == "source-data":
                self.runtime.replacement_source_running = True

        application = capture.CaptureApplication(
            repository_root=self.repository_root,
            runner=self.runtime,
            management_probe=self.runtime.probe,
            port_allocator=lambda excluded: 29443,
            port_checker=lambda port: port == 29443,
            clock=lambda: "20260728T120000Z",
            nonce=lambda: "abc12345",
            tree_copier=start_replacement,
        )

        with self.assertRaisesRegex(capture.CaptureError, "source.*running"):
            application.capture("stalwart")

        self.assertFalse(self.runtime.source_running)
        self.assertFalse(self.runtime.replacement_source_running)
        self.assertFalse(self.latest_receipt.exists())

    def test_cleanup_failure_still_reasserts_stopped_source_invariant(self) -> None:
        outside = self.repository_root / "outside-partial"
        outside.mkdir()

        def sabotage_copy(source: Path, destination: Path) -> None:
            if destination.name == "source-data":
                self.runtime.source_running = True
                partial = destination.parent
                shutil.rmtree(partial)
                partial.symlink_to(outside, target_is_directory=True)
                raise OSError("injected cleanup sabotage")
            capture.copy_tree(source, destination)

        application = capture.CaptureApplication(
            repository_root=self.repository_root,
            runner=self.runtime,
            management_probe=self.runtime.probe,
            port_allocator=lambda excluded: 29443,
            port_checker=lambda port: port == 29443,
            clock=lambda: "20260728T120000Z",
            nonce=lambda: "abc12345",
            tree_copier=sabotage_copy,
        )

        with self.assertRaises(capture.CaptureError):
            application.capture("stalwart")

        self.assertFalse(self.runtime.source_running)
        self.assertFalse(self.latest_receipt.exists())

    def test_failed_management_proof_does_not_publish_or_disclose_secret(self) -> None:
        self.runtime.management_status = 401

        with self.assertRaises(capture.CaptureError) as raised:
            self.application.capture("stalwart")

        self.assertNotIn("unit-only-value", str(raised.exception))
        self.assertFalse(self.latest_receipt.exists())
        self.assertFalse(self.runtime.source_running)
        self.assertFalse(self.runtime.rollback_running)

    def test_rollback_up_timeout_runs_cleanup_and_keeps_source_stopped(self) -> None:
        self.runtime.timeout_on_rollback_up = True

        with self.assertRaises(capture.CaptureError) as raised:
            self.application.capture("stalwart")

        self.assertNotIn("unit-only-value", str(raised.exception))
        self.assertTrue(any("down" in call for call in self.runtime.calls))
        self.assertFalse(self.runtime.rollback_running)
        self.assertFalse(self.runtime.source_running)
        self.assertFalse(self.latest_receipt.exists())

    def test_failed_final_publication_never_leaves_latest_receipt(self) -> None:
        writes = 0

        def fail_latest(target: Path, value: object) -> None:
            nonlocal writes
            writes += 1
            if target.name == "latest-source.json":
                raise capture.CaptureError("injected final publication failure")
            capture.write_json_0600_atomic(target, value)

        application = capture.CaptureApplication(
            repository_root=self.repository_root,
            runner=self.runtime,
            management_probe=self.runtime.probe,
            port_allocator=lambda excluded: 29443,
            port_checker=lambda port: port == 29443,
            clock=lambda: "20260728T120000Z",
            nonce=lambda: "abc12345",
            tree_copier=self.runtime.copy_tree,
            receipt_writer=fail_latest,
        )

        with self.assertRaisesRegex(capture.CaptureError, "publication"):
            application.capture("stalwart")

        self.assertGreaterEqual(writes, 2)
        self.assertFalse(self.latest_receipt.exists())
        self.assertFalse(self.runtime.source_running)

    def test_capture_fsyncs_backup_tree_and_parent_before_latest_publication(self) -> None:
        events: list[str] = []

        def writer(target: Path, value: object) -> None:
            events.append("latest" if target.name == "latest-source.json" else "backup-receipt")
            capture.write_json_0600_atomic(target, value)

        application = capture.CaptureApplication(
            repository_root=self.repository_root,
            runner=self.runtime,
            management_probe=self.runtime.probe,
            port_allocator=lambda excluded: 29443,
            port_checker=lambda port: port == 29443,
            clock=lambda: "20260728T120000Z",
            nonce=lambda: "abc12345",
            tree_copier=self.runtime.copy_tree,
            receipt_writer=writer,
            tree_sync=lambda path: events.append(
                "archive-tree-sync"
                if path.name.startswith(".partial-")
                else "working-tree-sync",
            ),
            directory_sync=lambda path: events.append("backup-parent-sync"),
        )

        application.capture("stalwart")

        self.assertLess(events.index("backup-receipt"), events.index("archive-tree-sync"))
        tree_index = events.index("archive-tree-sync")
        latest_index = events.index("latest")
        self.assertTrue(
            any(
                event == "backup-parent-sync"
                for event in events[tree_index + 1 : latest_index]
            ),
        )

    def test_cross_worktree_capture_uses_durable_source_root_and_survives_tool_removal(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            tool_root = base / "tool-worktree"
            source_root = base / "primary-source"
            tool_root.mkdir()
            runtime = FakeRuntime(tool_root, source_root)
            observed_locks: list[tuple[bool, bool]] = []
            canonical_migration = (
                source_root
                / "captures"
                / "debug-dashboard"
                / "stalwart-v015"
                / "migration"
            )

            def probe(url: str, username: str, secret: str) -> int:
                observed_locks.append(
                    (
                        (canonical_migration / ".capture.lock").exists(),
                        (canonical_migration / ".rollback-global.lock").exists(),
                    ),
                )
                return runtime.probe(url, username, secret)

            application = capture.CaptureApplication(
                repository_root=tool_root,
                runner=runtime,
                management_probe=probe,
                port_allocator=lambda excluded: 29443,
                port_checker=lambda port: port == 29443,
                clock=lambda: "20260728T120000Z",
                nonce=lambda: "abc12345",
                tree_copier=runtime.copy_tree,
            )
            local_receipt = application.capture("stalwart")
            canonical_receipt = canonical_migration / "latest-source.json"
            local_envelope = json.loads(local_receipt.read_text(encoding="utf-8"))
            canonical_envelope = json.loads(canonical_receipt.read_text(encoding="utf-8"))

            self.assertEqual(
                local_receipt,
                tool_root
                / "debug-dashboard"
                / ".runtime"
                / "stalwart-migration"
                / "latest-source.json",
            )
            self.assertEqual(local_envelope, canonical_envelope)
            backup_root = Path(canonical_envelope["payload"]["backup"]["root"])
            self.assertTrue(
                backup_root.is_relative_to(
                    source_root / "captures" / "debug-dashboard" / "stalwart-v015",
                ),
            )
            self.assertEqual(
                canonical_envelope["payload"]["backup"]["canonical_latest_receipt"],
                str(canonical_receipt),
            )
            self.assertTrue(observed_locks)
            self.assertTrue(all(capture_lock and global_lock for capture_lock, global_lock in observed_locks))

            shutil.rmtree(tool_root)
            durable_application = capture.CaptureApplication(
                repository_root=source_root,
                runner=runtime,
                management_probe=runtime.probe,
                port_allocator=lambda excluded: 29443,
                port_checker=lambda port: port == 29443,
                clock=lambda: "20260728T120001Z",
                nonce=lambda: "def67890",
                tree_copier=runtime.copy_tree,
            )
            payload = durable_application.verify(canonical_receipt)
            proof = durable_application.prove_rollback(canonical_receipt)

            self.assertEqual(payload["source"]["version"], "0.15.5")
            self.assertEqual(proof["management_status"], 200)

    def test_cross_worktree_capture_refuses_unproved_ignored_canonical_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            tool_root = base / "tool-worktree"
            source_root = base / "primary-source"
            tool_root.mkdir()
            runtime = FakeRuntime(tool_root, source_root)
            runtime.canonical_root_ignored = False
            application = capture.CaptureApplication(
                repository_root=tool_root,
                runner=runtime,
                management_probe=runtime.probe,
                port_allocator=lambda excluded: 29443,
                port_checker=lambda port: port == 29443,
                clock=lambda: "20260728T120000Z",
                nonce=lambda: "abc12345",
                tree_copier=runtime.copy_tree,
            )

            with self.assertRaisesRegex(capture.CaptureError, "ignored.*canonical|canonical.*ignored"):
                application.capture("stalwart")

            self.assertTrue(runtime.source_running)
            self.assertFalse((source_root / "captures").exists())

    def test_verify_detects_data_digest_tamper_and_receipt_mode(self) -> None:
        payload = self.capture_successfully()
        backup = Path(payload["backup"]["root"])
        (backup / "source-data" / "CURRENT").write_bytes(b"tampered")

        with self.assertRaisesRegex(capture.CaptureError, "manifest"):
            self.application.verify(self.latest_receipt)

        (backup / "source-data" / "CURRENT").write_bytes(b"MANIFEST-000001\n")
        self.latest_receipt.chmod(0o644)
        with self.assertRaisesRegex(capture.CaptureError, "0600"):
            self.application.verify(self.latest_receipt)

    def test_verify_detects_receipt_digest_tamper(self) -> None:
        self.capture_successfully()
        envelope = json.loads(self.latest_receipt.read_text(encoding="utf-8"))
        envelope["payload"]["source"]["version"] = "0.15.4"
        self.latest_receipt.write_text(json.dumps(envelope), encoding="utf-8")
        self.latest_receipt.chmod(0o600)

        with self.assertRaisesRegex(capture.CaptureError, "digest"):
            self.application.verify(self.latest_receipt)

    def test_verify_rejects_option_shaped_image_id_before_running_command(self) -> None:
        payload = self.capture_successfully()
        payload["source"]["image_id"] = "--format"
        self.rewrite_receipt(payload)
        calls_before = len(self.runtime.calls)

        with self.assertRaisesRegex(capture.CaptureError, "image ID"):
            self.application.verify(self.latest_receipt)

        later_arguments = [
            argument
            for call in self.runtime.calls[calls_before:]
            for argument in call
        ]
        self.assertNotIn("--format", later_arguments)

    def test_verify_rejects_option_shaped_container_id_before_running_command(self) -> None:
        payload = self.capture_successfully()
        payload["source"]["container_id"] = "--format"
        self.rewrite_receipt(payload)
        calls_before = len(self.runtime.calls)

        with self.assertRaisesRegex(capture.CaptureError, "container identity"):
            self.application.verify(self.latest_receipt)

        later_arguments = [
            argument
            for call in self.runtime.calls[calls_before:]
            for argument in call
        ]
        self.assertNotIn("--format", later_arguments)

    def test_verify_and_prove_refuse_if_source_is_running(self) -> None:
        self.capture_successfully()
        self.runtime.source_running = True
        up_calls_before = len([call for call in self.runtime.calls if "up" in call])

        with self.assertRaisesRegex(capture.CaptureError, "source.*stopped"):
            self.application.verify(self.latest_receipt)
        with self.assertRaisesRegex(capture.CaptureError, "source.*stopped"):
            self.application.prove_rollback(self.latest_receipt)

        up_calls_after = len([call for call in self.runtime.calls if "up" in call])
        self.assertEqual(up_calls_after, up_calls_before)

    def test_verify_and_prove_remain_durable_after_legacy_source_is_replaced(self) -> None:
        self.capture_successfully()
        self.runtime.source_container_exists = False
        self.runtime.config_path.write_text("replaced by v0.16\n", encoding="utf-8")
        (self.runtime.data_path / "CURRENT").write_bytes(b"migrated-v0.16")

        payload = self.application.verify(self.latest_receipt)
        proof = self.application.prove_rollback(self.latest_receipt)

        self.assertEqual(payload["source"]["version"], "0.15.5")
        self.assertEqual(proof["version"], "0.15.5")
        self.assertEqual(proof["management_status"], 200)

    def test_verify_rejects_recreated_legacy_writer_on_recorded_store(self) -> None:
        self.capture_successfully()
        self.runtime.source_container_exists = False
        self.runtime.replacement_source_mode = "legacy"
        self.runtime.replacement_source_running = True

        with self.assertRaisesRegex(capture.CaptureError, "legacy.*writer"):
            self.application.verify(self.latest_receipt)

    def test_verify_rejects_differently_labeled_writer_on_recorded_store(self) -> None:
        self.capture_successfully()
        writer_id = "9" * 64
        writer = self.runtime.source_inspect(writer_id)
        writer["State"]["Running"] = True
        writer["Config"]["Labels"]["com.docker.compose.service"] = "unrelated"
        self.runtime.extra_source_inspects.append(writer)

        def label_aware_runner(args: list[str]) -> "capture.CommandResult":
            result = self.runtime(args)
            if (
                args[:2] == ["docker", "ps"]
                and "--no-trunc" in args
                and "label=com.docker.compose.service=stalwart" in args
            ):
                visible_ids = [
                    container_id
                    for container_id in result.stdout.splitlines()
                    if container_id != writer_id
                ]
                return capture.CommandResult(
                    "\n".join(visible_ids) + ("\n" if visible_ids else ""),
                    "",
                )
            return result

        self.application.runner = label_aware_runner
        self.runtime.calls.clear()

        with self.assertRaisesRegex(capture.CaptureError, "legacy.*writer"):
            self.application.verify(self.latest_receipt)

        self.assertIn(["docker", "inspect", writer_id], self.runtime.calls)

    def test_verify_rejects_unrelated_writer_mounted_at_protected_store(self) -> None:
        self.capture_successfully()
        self.append_unrelated_running_writer(str(self.runtime.data_path))

        with self.assertRaisesRegex(capture.CaptureError, "legacy.*writer"):
            self.application.verify(self.latest_receipt)

    def test_verify_rejects_unrelated_writer_mounted_above_protected_store(self) -> None:
        self.capture_successfully()
        self.append_unrelated_running_writer(str(self.runtime.source_root))

        with self.assertRaisesRegex(capture.CaptureError, "legacy.*writer"):
            self.application.verify(self.latest_receipt)

    def test_verify_rejects_unrelated_writer_mounted_below_protected_store(self) -> None:
        self.capture_successfully()
        self.append_unrelated_running_writer(str(self.runtime.data_path / "nested"))

        with self.assertRaisesRegex(capture.CaptureError, "legacy.*writer"):
            self.application.verify(self.latest_receipt)

    def test_verify_rejects_normalized_alias_of_protected_store(self) -> None:
        self.capture_successfully()
        aliased_source = (
            f"{self.runtime.data_path.parent}/stalwart/../"
            f"{self.runtime.data_path.name}/nested"
        )
        self.append_unrelated_running_writer(aliased_source)

        with self.assertRaisesRegex(capture.CaptureError, "legacy.*writer"):
            self.application.verify(self.latest_receipt)

    def test_verify_rejects_non_absolute_writable_mount_source(self) -> None:
        self.capture_successfully()
        unsafe_source = "stalwart-data/nested"
        self.append_unrelated_running_writer(unsafe_source)

        with self.assertRaisesRegex(capture.CaptureError, "absolute path") as raised:
            self.application.verify(self.latest_receipt)

        self.assertNotIn(unsafe_source, str(raised.exception))

    def test_verify_allows_unrelated_writer_on_sibling_prefix_path(self) -> None:
        self.capture_successfully()
        sibling = self.runtime.data_path.with_name(self.runtime.data_path.name + "-copy")
        self.append_unrelated_running_writer(str(sibling))

        try:
            payload = self.application.verify(self.latest_receipt)
        except capture.CaptureError as exc:
            self.fail(f"sibling prefix path must not overlap the protected store: {exc}")

        self.assertEqual(payload["source"]["version"], "0.15.5")

    def test_verify_allows_exact_v016_replacement_runtime(self) -> None:
        self.capture_successfully()
        self.runtime.source_container_exists = False
        self.runtime.replacement_source_mode = "v016"
        self.runtime.replacement_source_running = True

        try:
            payload = self.application.verify(self.latest_receipt)
        except capture.CaptureError as exc:
            self.fail(f"exact v0.16 replacement should be accepted: {exc}")

        self.assertEqual(payload["source"]["version"], "0.15.5")

    def test_verify_rejects_v016_child_config_bind_on_recorded_store(self) -> None:
        self.capture_successfully()
        self.runtime.source_container_exists = False
        self.runtime.replacement_source_mode = "v016"
        self.runtime.replacement_source_running = True
        self.runtime.v016_config_mount_style = "child"

        with self.assertRaisesRegex(capture.CaptureError, "legacy.*writer"):
            self.application.verify(self.latest_receipt)

    def test_verify_rejects_v016_config_parent_with_wrong_data_source(self) -> None:
        self.capture_successfully()
        self.runtime.source_container_exists = False
        self.runtime.replacement_source_mode = "v016"
        self.runtime.replacement_source_running = True
        self.runtime.v016_data_source = self.runtime.source_root / "foreign-data"

        with self.assertRaisesRegex(capture.CaptureError, "legacy.*writer"):
            self.application.verify(self.latest_receipt)

    def test_verify_rejects_v016_extra_anonymous_config_parent_volume(self) -> None:
        self.capture_successfully()
        self.runtime.source_container_exists = False
        self.runtime.replacement_source_mode = "v016"
        self.runtime.replacement_source_running = True
        self.runtime.v016_config_mount_style = "child"
        self.runtime.v016_extra_parent_volume = True

        with self.assertRaisesRegex(capture.CaptureError, "legacy.*writer"):
            self.application.verify(self.latest_receipt)

    def test_verify_rejects_v016_wrong_project_label(self) -> None:
        self.capture_successfully()
        self.runtime.source_container_exists = False
        self.runtime.replacement_source_mode = "v016"
        self.runtime.replacement_source_running = True
        self.runtime.v016_project_label = "other-project"

        with self.assertRaisesRegex(capture.CaptureError, "legacy.*writer"):
            self.application.verify(self.latest_receipt)

    def test_verify_rejects_v016_wrong_config_file_label(self) -> None:
        self.capture_successfully()
        self.runtime.source_container_exists = False
        self.runtime.replacement_source_mode = "v016"
        self.runtime.replacement_source_running = True
        self.runtime.v016_config_files_label = str(
            self.runtime.source_root / "other-compose.yml",
        )

        with self.assertRaisesRegex(capture.CaptureError, "legacy.*writer"):
            self.application.verify(self.latest_receipt)

    def test_verify_and_prove_use_archive_when_stopped_legacy_container_still_exists(self) -> None:
        self.capture_successfully()
        self.runtime.config_path.unlink()
        shutil.rmtree(self.runtime.data_path)
        self.runtime.compose_path.write_text("services: replaced\n", encoding="utf-8")

        payload = self.application.verify(self.latest_receipt)
        proof = self.application.prove_rollback(self.latest_receipt)

        self.assertFalse(self.runtime.source_running)
        self.assertEqual(payload["source"]["version"], "0.15.5")
        self.assertEqual(proof["management_status"], 200)

    def test_prove_requires_rollback_container_to_use_captured_image_id(self) -> None:
        self.capture_successfully()
        self.runtime.rollback_image_id = "sha256:" + ("9" * 64)

        with self.assertRaisesRegex(capture.CaptureError, "image ID"):
            self.application.prove_rollback(self.latest_receipt)

    def test_prove_refuses_stopped_compose_container_without_adopting_it(
        self,
    ) -> None:
        payload = self.capture_successfully()
        backup = Path(payload["backup"]["root"])
        self.runtime.rollback_compose_id_override = self.runtime.FOREIGN_ROLLBACK_ID
        self.runtime.calls.clear()

        with self.assertRaisesRegex(capture.CaptureError, "Compose container"):
            self.application.prove_rollback(self.latest_receipt)

        self.assertEqual(
            self.runtime.rollback_compose_id_override,
            self.runtime.FOREIGN_ROLLBACK_ID,
        )
        self.assertFalse(self.runtime.rollback_running)
        self.assertFalse(any("up" in call for call in self.runtime.calls))
        self.assertFalse(any("down" in call for call in self.runtime.calls))
        self.assertEqual(
            capture.manifest_tree(backup / "rollback-data"),
            payload["data_manifest"],
        )

    def test_prove_cleanup_rejects_stopped_compose_leftover_before_refresh(
        self,
    ) -> None:
        payload = self.capture_successfully()
        backup = Path(payload["backup"]["root"])
        self.runtime.copy_destinations.clear()
        self.runtime.rollback_down_leaves_stopped_container = True

        with self.assertRaisesRegex(capture.CaptureError, "cleanup"):
            self.application.prove_rollback(self.latest_receipt)

        self.assertFalse(self.runtime.rollback_running)
        self.assertEqual(
            self.runtime.rollback_compose_id_override,
            self.runtime.ROLLBACK_ID,
        )
        self.assertEqual(
            self.runtime.copy_destinations,
            [backup / ".rollback-data.next"],
        )
        self.assertNotEqual(
            capture.manifest_tree(backup / "rollback-data"),
            payload["data_manifest"],
        )

    def test_prove_uses_all_state_census_and_force_recreation(self) -> None:
        self.capture_successfully()
        self.runtime.calls.clear()

        self.application.prove_rollback(self.latest_receipt)

        up_calls = [call for call in self.runtime.calls if "up" in call]
        self.assertEqual(len(up_calls), 1)
        self.assertIn("--force-recreate", up_calls[0])
        up_index = self.runtime.calls.index(up_calls[0])
        all_state_census = [
            index
            for index, call in enumerate(self.runtime.calls)
            if call[:2] == ["docker", "compose"]
            and "ps" in call
            and "--all" in call
        ]
        self.assertTrue(any(index < up_index for index in all_state_census))
        down_index = next(
            index
            for index, call in enumerate(self.runtime.calls)
            if "down" in call
        )
        self.assertTrue(any(index > down_index for index in all_state_census))

    def test_prove_refuses_an_already_running_rollback_copy(self) -> None:
        self.capture_successfully()
        self.runtime.running_copy = True
        self.runtime.calls.clear()

        with self.assertRaisesRegex(capture.CaptureError, "Compose container"):
            self.application.prove_rollback(self.latest_receipt)

        self.assertFalse(any("up" in call for call in self.runtime.calls))
        self.assertFalse(any("down" in call for call in self.runtime.calls))

    def test_prove_refuses_a_concurrent_proof_lock(self) -> None:
        payload = self.capture_successfully()
        lock = Path(payload["backup"]["root"]) / ".rollback-proof.lock"
        lock.write_text("busy\n", encoding="utf-8")
        lock.chmod(0o600)
        up_calls_before = len([call for call in self.runtime.calls if "up" in call])

        with lock.open("r+", encoding="utf-8") as stream:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            try:
                with self.assertRaisesRegex(capture.CaptureError, "proof.*running"):
                    self.application.prove_rollback(self.latest_receipt)
            finally:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)

        up_calls_after = len([call for call in self.runtime.calls if "up" in call])
        self.assertEqual(up_calls_after, up_calls_before)

    def test_abandoned_proof_lock_is_reusable_but_live_advisory_lock_refuses(
        self,
    ) -> None:
        payload = self.capture_successfully()
        lock = Path(payload["backup"]["root"]) / ".rollback-proof.lock"
        lock.write_text("abandoned-pid\n", encoding="utf-8")
        lock.chmod(0o600)

        proof = self.application.prove_rollback(self.latest_receipt)

        self.assertEqual(proof["version"], "0.15.5")
        with lock.open("r+", encoding="utf-8") as stream:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            try:
                with self.assertRaisesRegex(
                    capture.CaptureError,
                    "another rollback proof operation is already running",
                ):
                    self.application.prove_rollback(self.latest_receipt)
            finally:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)

    def test_prove_refuses_globally_labeled_foreign_rollback_copy(self) -> None:
        self.capture_successfully()
        self.runtime.foreign_rollback_running = True
        down_calls_before = len([call for call in self.runtime.calls if "down" in call])

        with self.assertRaisesRegex(capture.CaptureError, "rollback copy.*running"):
            self.application.prove_rollback(self.latest_receipt)

        down_calls_after = len([call for call in self.runtime.calls if "down" in call])
        self.assertEqual(down_calls_after, down_calls_before)
        self.assertTrue(self.runtime.foreign_rollback_running)

    def test_prove_rejects_foreign_rollback_race_without_stopping_foreign_project(self) -> None:
        self.capture_successfully()
        self.runtime.foreign_rollback_after_up = True
        management_calls_before = len(self.runtime.management_calls)

        with self.assertRaisesRegex(capture.CaptureError, "rollback"):
            self.application.prove_rollback(self.latest_receipt)

        self.assertEqual(len(self.runtime.management_calls), management_calls_before)
        self.assertFalse(self.runtime.rollback_running)
        self.assertTrue(self.runtime.foreign_rollback_running)

    def test_capture_uses_unique_non_internal_bridge_with_loopback_publication(self) -> None:
        self.runtime.rollback_network_internal = False

        payload = self.capture_successfully()

        self.assertEqual(payload["rollback"]["host_ip"], "127.0.0.1")
        self.assertFalse(self.runtime.rollback_network_internal)
        self.assertFalse(self.runtime.source_running)

    def test_missing_receipt_hard_stops_without_booting_anything(self) -> None:
        missing = self.repository_root / "missing.json"

        with self.assertRaisesRegex(capture.CaptureError, "receipt"):
            self.application.verify(missing)
        with self.assertRaisesRegex(capture.CaptureError, "receipt"):
            self.application.prove_rollback(missing)

        self.assertFalse(any("up" in call for call in self.runtime.calls))


@unittest.skipIf(capture is None, "capture script has not been implemented yet")
class RollbackDefinitionTests(unittest.TestCase):
    def test_definition_refuses_unpinned_image_broad_mount_and_non_loopback_port(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            backup = Path(directory)
            (backup / "config.toml").write_text("config", encoding="utf-8")
            (backup / "rollback-data").mkdir()
            (backup / "rollback.env").write_text("ADMIN_SECRET=value\n", encoding="utf-8")
            base = capture.build_rollback_definition(
                image_digest="stalwartlabs/stalwart@sha256:" + ("a" * 64),
                port=29443,
                project="mail-sandbox-stalwart-rollback-abc12345",
            )
            capture.validate_rollback_definition(base, backup)

            mutations = (
                lambda value: value["services"]["stalwart-rollback"].update(
                    {"image": "stalwartlabs/stalwart:latest"},
                ),
                lambda value: value["services"]["stalwart-rollback"]["volumes"][1].update(
                    {"source": "/"},
                ),
                lambda value: value["services"]["stalwart-rollback"]["ports"][0].update(
                    {"host_ip": "0.0.0.0"},
                ),
                lambda value: value["services"]["stalwart-rollback"].update(
                    {"command": ["/bin/false"]},
                ),
            )
            for mutate in mutations:
                with self.subTest(mutate=mutate):
                    candidate = json.loads(json.dumps(base))
                    mutate(candidate)
                    with self.assertRaises(capture.CaptureError):
                        capture.validate_rollback_definition(candidate, backup)


@unittest.skipIf(capture is None, "capture script has not been implemented yet")
class RollbackLifecycleCliTests(unittest.TestCase):
    def test_lifecycle_subcommands_require_receipt_digest_binding(self) -> None:
        parser = capture._build_argument_parser()
        for command in (
            "activate-rollback",
            "deactivate-rollback",
            "reconcile-rollback",
        ):
            with self.subTest(command=command):
                arguments = parser.parse_args(
                    [
                        command,
                        "--receipt",
                        "/tmp/source-receipt.json",
                        "--expected-receipt-sha256",
                        "a" * 64,
                    ],
                )
                self.assertEqual(arguments.command, command)
                self.assertEqual(
                    arguments.expected_receipt_sha256,
                    "a" * 64,
                )

    def test_lifecycle_main_dispatches_without_printing_credentials(self) -> None:
        application = mock.Mock()
        application.activate_verified_rollback.return_value = (
            capture.VerifiedRollbackActivation(
                proof_path=Path("/tmp/rollback-activation.json"),
                base_url="http://127.0.0.1:29443",
                proof=capture.VerifiedRollbackProof(
                    management_status=200,
                    proved_at="20260729T010000Z",
                    version="0.15.5",
                ),
            )
        )
        application.reconcile_verified_rollback.return_value = (
            application.activate_verified_rollback.return_value
        )
        digest = "a" * 64
        with (
            mock.patch.object(
                capture,
                "CaptureApplication",
                return_value=application,
            ),
            mock.patch("builtins.print") as output,
        ):
            self.assertEqual(
                capture.main(
                    [
                        "activate-rollback",
                        "--receipt",
                        "/tmp/source-receipt.json",
                        "--expected-receipt-sha256",
                        digest,
                    ],
                ),
                0,
            )
            self.assertEqual(
                capture.main(
                    [
                        "reconcile-rollback",
                        "--receipt",
                        "/tmp/source-receipt.json",
                        "--expected-receipt-sha256",
                        digest,
                    ],
                ),
                0,
            )
            self.assertEqual(
                capture.main(
                    [
                        "deactivate-rollback",
                        "--receipt",
                        "/tmp/source-receipt.json",
                        "--expected-receipt-sha256",
                        digest,
                    ],
                ),
                0,
            )

        application.activate_verified_rollback.assert_called_once_with(
            Path("/tmp/source-receipt.json"),
            expected_receipt_sha256=digest,
        )
        application.deactivate_verified_rollback.assert_called_once_with(
            Path("/tmp/source-receipt.json"),
            expected_receipt_sha256=digest,
        )
        application.reconcile_verified_rollback.assert_called_once_with(
            Path("/tmp/source-receipt.json"),
            expected_receipt_sha256=digest,
        )
        rendered = "\n".join(
            str(argument)
            for call in output.call_args_list
            for argument in call.args
        )
        self.assertIn("http://127.0.0.1:29443", rendered)
        self.assertNotIn("password", rendered.lower())
        self.assertNotIn("secret", rendered.lower())


if __name__ == "__main__":
    unittest.main()
