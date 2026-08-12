from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPOSITORY_ROOT / "scripts" / "stalwart_runtime_state.py"
CONFIG_PATH = REPOSITORY_ROOT / "stalwart" / "config.json"

CURRENT_IMAGE = (
    "stalwartlabs/stalwart:v0.16.17@"
    "sha256:a8108e19bd927e172d4d8c128907b8dfc93fd180ae8ee07dccdd42cb97eb9dfa"
)
LEGACY_IMAGE = (
    "stalwartlabs/stalwart:v0.15@"
    "sha256:dcf575db2d53d9ef86d6ced8abe4ba491984659a0f8862cc6079ee7b41c3c568"
)
CONFIG_BYTES = b'{\n  "@type": "RocksDb",\n  "path": "/var/lib/stalwart"\n}'


runtime_state = None
IMPORT_ERROR: Exception | None = None
if SCRIPT_PATH.exists():
    try:
        spec = importlib.util.spec_from_file_location(
            "stalwart_runtime_state",
            SCRIPT_PATH,
        )
        assert spec is not None
        assert spec.loader is not None
        runtime_state = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = runtime_state
        spec.loader.exec_module(runtime_state)
    except Exception as exc:  # pragma: no cover - reported by existence test
        IMPORT_ERROR = exc


def current_compose_text() -> str:
    return f"""services:
  stalwart:
    image: {CURRENT_IMAGE}
    container_name: stalwart-dev
    user: "2000:2000"
    restart: unless-stopped
    ports:
      - target: 8080
        published: "8443"
        host_ip: 0.0.0.0
        protocol: tcp
      - target: 587
        published: "8587"
        host_ip: 0.0.0.0
        protocol: tcp
    env_file:
      - ./debug-dashboard/.runtime/stalwart/network.env
    volumes:
      - type: bind
        source: ./stalwart
        target: /etc/stalwart
        read_only: true
        bind:
          create_host_path: false
      - type: bind
        source: ./stalwart-data
        target: /var/lib/stalwart
        read_only: false
        bind:
          create_host_path: false
    healthcheck:
      test:
        - CMD
        - curl
        - -fsS
        - http://127.0.0.1:8080/healthz/ready
      interval: 2s
      timeout: 2s
      retries: 30
      start_period: 2s
"""


def write_network_environment(
    root: Path,
    public_url: str = "http://192.168.86.36:8443",
) -> Path:
    runtime = root / "debug-dashboard" / ".runtime"
    directory = runtime / "stalwart"
    directory.mkdir(parents=True, exist_ok=True)
    runtime.chmod(0o700)
    directory.chmod(0o700)
    target = directory / "network.env"
    target.write_bytes(f"STALWART_PUBLIC_URL={public_url}\n".encode("ascii"))
    target.chmod(0o600)
    return target


def legacy_compose_text() -> str:
    return f"""services:
  stalwart:
    image: {LEGACY_IMAGE}
    restart: unless-stopped
    ports:
      - "8443:8443"   # JMAP HTTP
    volumes:
      - ./stalwart/config.toml:/opt/stalwart/etc/config.toml:ro
      - ./stalwart-data:/opt/stalwart/data
    environment:
      - ADMIN_SECRET=secret
    healthcheck:
      test: ["CMD", "bash", "-c", "echo > /dev/tcp/localhost/8443"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 15s
"""


def under_shadow_parent(compose: str) -> str:
    return (
        compose.replace("services:\n", "x-shadow:\n", 1)
        + "\nservices:\n"
        + "  placeholder:\n"
        + "    image: example.invalid/placeholder:fixed\n"
    )


def prepare_current_repository(root: Path) -> Path:
    (root / "stalwart").mkdir()
    (root / "debug-dashboard" / ".runtime" / "stalwart").mkdir(
        parents=True,
    )
    write_network_environment(root)
    (root / "stalwart" / "config.json").write_bytes(CONFIG_BYTES)
    (root / "docker-compose.yml").write_text(
        current_compose_text(),
        encoding="utf-8",
    )
    store = root / "stalwart-data"
    store.mkdir()
    (store / "CURRENT").write_bytes(b"fixture")
    return store


def bind_receipt_to_compose(receipt: Path, compose: str) -> None:
    envelope = json.loads(receipt.read_text(encoding="utf-8"))
    payload = envelope["payload"]
    payload["compose_sha256"] = hashlib.sha256(compose.encode()).hexdigest()
    canonical_payload = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    envelope["payload_sha256"] = hashlib.sha256(canonical_payload).hexdigest()
    receipt.write_bytes(
        json.dumps(
            envelope,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        + b"\n",
    )


def snapshot_tree(root: Path) -> tuple[tuple[str, int, int, bytes | None], ...]:
    result: list[tuple[str, int, int, bytes | None]] = []
    for path in sorted((root, *root.rglob("*"))):
        metadata = path.lstat()
        content = path.read_bytes() if stat.S_ISREG(metadata.st_mode) else None
        result.append(
            (
                "." if path == root else str(path.relative_to(root)),
                metadata.st_mode,
                metadata.st_ino,
                content,
            ),
        )
    return tuple(result)


class ScriptExistenceTest(unittest.TestCase):
    def test_runtime_state_module_exists_and_imports(self) -> None:
        self.assertIsNotNone(
            runtime_state,
            f"{SCRIPT_PATH.relative_to(REPOSITORY_ROOT)} must import cleanly: "
            f"{IMPORT_ERROR}",
        )

    def test_tracked_current_config_is_the_reviewed_v016_storage_locator(self) -> None:
        self.assertTrue(CONFIG_PATH.is_file())
        self.assertEqual(CONFIG_PATH.read_bytes(), CONFIG_BYTES)
        self.assertEqual(stat.S_IMODE(CONFIG_PATH.stat().st_mode), 0o644)


@unittest.skipIf(runtime_state is None, "runtime-state script is absent")
class RuntimeStateClassificationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name).resolve()
        (self.root / "stalwart").mkdir()
        (self.root / "debug-dashboard" / ".runtime" / "stalwart").mkdir(
            parents=True,
        )
        write_network_environment(self.root)
        (self.root / "stalwart" / "config.json").write_bytes(CONFIG_BYTES)

    def test_root_failure_intent_is_ignored_by_git(self) -> None:
        gitignore = (REPOSITORY_ROOT / ".gitignore").read_text(encoding="utf-8")

        self.assertIn(
            "/.mail-sandbox-fresh-initialization-intent\n",
            gitignore,
        )

    def write_compose(self, image: str) -> None:
        if image == CURRENT_IMAGE:
            content = current_compose_text()
        elif image == LEGACY_IMAGE:
            content = legacy_compose_text()
        else:
            self.fail(f"unsupported fixture image: {image}")
        (self.root / "docker-compose.yml").write_text(
            content,
            encoding="utf-8",
        )

    def write_compose_content(self, content: str) -> None:
        (self.root / "docker-compose.yml").write_text(
            content,
            encoding="utf-8",
        )

    def make_nonempty_store(self) -> Path:
        store = self.root / "stalwart-data"
        store.mkdir(exist_ok=True)
        (store / "CURRENT").write_bytes(b"fixture")
        return store

    def test_enum_values_are_the_approved_startup_contract(self) -> None:
        self.assertEqual(
            [state.value for state in runtime_state.RuntimeState],
            ["fresh", "current", "migration-required", "invalid"],
        )

    def test_absent_or_empty_store_is_fresh(self) -> None:
        self.write_compose(LEGACY_IMAGE)
        self.assertEqual(
            runtime_state.classify_repository(self.root),
            runtime_state.RuntimeState.FRESH,
        )

        (self.root / "stalwart-data").mkdir()
        self.assertEqual(
            runtime_state.classify_repository(self.root),
            runtime_state.RuntimeState.FRESH,
        )

    def test_known_nonempty_v015_hold_requires_migration(self) -> None:
        self.write_compose(LEGACY_IMAGE)
        self.make_nonempty_store()

        self.assertEqual(
            runtime_state.classify_repository(self.root),
            runtime_state.RuntimeState.MIGRATION_REQUIRED,
        )

    def test_real_root_remains_the_exact_legacy_hold_before_authorization(self) -> None:
        self.assertEqual(
            runtime_state._compose_kind(REPOSITORY_ROOT)[0],
            "legacy",
        )
        self.assertEqual(
            runtime_state.classify_repository(REPOSITORY_ROOT),
            runtime_state.RuntimeState.MIGRATION_REQUIRED,
        )

    def test_legacy_model_under_an_extension_is_invalid(self) -> None:
        self.write_compose_content(
            under_shadow_parent(legacy_compose_text()),
        )
        self.make_nonempty_store()

        self.assertEqual(
            runtime_state.classify_repository(self.root),
            runtime_state.RuntimeState.INVALID,
        )

    def test_legacy_service_stops_before_following_top_level_section(self) -> None:
        self.write_compose_content(
            legacy_compose_text()
            + "\nnetworks:\n"
            + "  operator-ingress:\n"
            + "    driver: bridge\n",
        )
        self.make_nonempty_store()

        self.assertEqual(
            runtime_state.classify_repository(self.root),
            runtime_state.RuntimeState.MIGRATION_REQUIRED,
        )

    def test_current_service_stops_before_following_top_level_section(self) -> None:
        self.write_compose_content(
            current_compose_text()
            + "\nnetworks:\n"
            + "  operator-ingress:\n"
            + "    driver: bridge\n",
        )
        self.make_nonempty_store()

        self.assertIsNotNone(runtime_state._compose_kind(self.root))
        receipt = runtime_state.publish_current_receipt(self.root)

        envelope = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertNotIn(
            "http://192.168.86.36:8443",
            json.dumps(envelope["payload"], sort_keys=True),
        )

        self.assertEqual(
            runtime_state.classify_repository(self.root),
            runtime_state.RuntimeState.CURRENT,
        )

    def test_legacy_requires_the_exact_frozen_service_model(self) -> None:
        self.make_nonempty_store()
        canonical = legacy_compose_text()
        contradictions = {
            "current-style-port": canonical.replace(
                '      - "8443:8443"   # JMAP HTTP',
                '      - "127.0.0.1:8443:8080"',
            ),
            "extra-port": canonical.replace(
                "    volumes:\n",
                '      - "127.0.0.1:8587:587"\n    volumes:\n',
            ),
            "wrong-config-mount": canonical.replace(
                "/opt/stalwart/etc/config.toml:ro",
                "/etc/stalwart/config.toml:ro",
            ),
            "extra-environment": canonical.replace(
                "      - ADMIN_SECRET=secret\n",
                "      - ADMIN_SECRET=secret\n      - EXTRA=value\n",
            ),
            "network-mode": canonical.replace(
                "    restart: unless-stopped\n",
                "    restart: unless-stopped\n    network_mode: host\n",
            ),
        }

        for label, content in contradictions.items():
            with self.subTest(label=label):
                self.write_compose_content(content)
                self.assertEqual(
                    runtime_state.classify_repository(self.root),
                    runtime_state.RuntimeState.INVALID,
                )

    def test_current_model_rejects_extra_or_contradictory_service_fields(
        self,
    ) -> None:
        canonical = current_compose_text()
        contradictions = {
            "loopback-port": canonical.replace(
                "        host_ip: 0.0.0.0\n",
                "        host_ip: 127.0.0.1\n",
                1,
            ),
            "extra-port": canonical.replace(
                "    env_file:\n",
                "      - target: 25\n"
                "        published: \"8025\"\n"
                "        host_ip: 127.0.0.1\n"
                "        protocol: tcp\n"
                "    env_file:\n",
            ),
            "extra-mount": canonical.replace(
                "    healthcheck:\n",
                "      - type: bind\n"
                "        source: ./extra\n"
                "        target: /extra\n"
                "        read_only: true\n"
                "        bind:\n"
                "          create_host_path: false\n"
                "    healthcheck:\n",
            ),
            "replaced-env-file": canonical.replace(
                "      - ./debug-dashboard/.runtime/stalwart/network.env\n",
                "      - ./debug-dashboard/.runtime/stalwart/replaced.env\n",
            ),
            "network-mode": canonical.replace(
                "    restart: unless-stopped\n",
                "    restart: unless-stopped\n    network_mode: host\n",
            ),
        }

        for label, content in contradictions.items():
            with self.subTest(label=label):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory).resolve()
                    prepare_current_repository(root)
                    receipt = runtime_state.publish_current_receipt(root)
                    (root / "docker-compose.yml").write_text(
                        content,
                        encoding="utf-8",
                    )
                    bind_receipt_to_compose(receipt, content)
                    self.assertEqual(
                        runtime_state.classify_repository(root),
                        runtime_state.RuntimeState.INVALID,
                    )
                    receipt.unlink()
                    with self.assertRaises(ValueError):
                        runtime_state.publish_current_receipt(root)

    def test_current_requires_the_strict_current_network_environment(self) -> None:
        cases = {
            "missing": None,
            "invalid": b"STALWART_PUBLIC_URL=http://127.0.0.1:8443\n",
            "extra": (
                b"STALWART_PUBLIC_URL=http://192.168.86.36:8443\n"
                b"EXTRA=value\n"
            ),
        }
        for label, content in cases.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                prepare_current_repository(root)
                network_file = (
                    root / "debug-dashboard" / ".runtime" / "stalwart" / "network.env"
                )
                if content is None:
                    network_file.unlink()
                else:
                    network_file.write_bytes(content)
                    network_file.chmod(0o600)

                self.assertEqual(
                    runtime_state.classify_repository(root),
                    runtime_state.RuntimeState.INVALID,
                )
                with self.assertRaises(ValueError):
                    runtime_state.publish_current_receipt(root)

    def test_current_model_must_be_a_direct_child_of_services(self) -> None:
        self.write_compose(CURRENT_IMAGE)
        self.make_nonempty_store()
        receipt = runtime_state.publish_current_receipt(self.root)
        shadowed = under_shadow_parent(current_compose_text())
        self.write_compose_content(shadowed)
        bind_receipt_to_compose(receipt, shadowed)

        self.assertEqual(
            runtime_state.classify_repository(self.root),
            runtime_state.RuntimeState.INVALID,
        )

        receipt.unlink()
        with self.assertRaises(ValueError):
            runtime_state.publish_current_receipt(self.root)

    def test_duplicate_or_malformed_services_keys_are_invalid(self) -> None:
        canonical = current_compose_text()
        invalid_documents = {
            "duplicate": canonical
            + "\nservices:\n"
            + "  placeholder:\n"
            + "    image: example.invalid/placeholder:fixed\n",
            "inline-value": canonical.replace(
                "services:\n",
                "services: {}\nx-shadow:\n",
                1,
            ),
            "quoted": canonical.replace("services:\n", '"services":\n', 1),
            "tagged-services": canonical
            + "\n!!str services:\n"
            + "  placeholder:\n"
            + "    image: example.invalid/placeholder:fixed\n",
            "tagged-stalwart": canonical.rstrip()
            + "\n  !!str stalwart:\n"
            + "    image: example.invalid/shadow:fixed\n",
        }

        for label, content in invalid_documents.items():
            with self.subTest(label=label):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory).resolve()
                    prepare_current_repository(root)
                    receipt = runtime_state.publish_current_receipt(root)
                    (root / "docker-compose.yml").write_text(
                        content,
                        encoding="utf-8",
                    )
                    bind_receipt_to_compose(receipt, content)

                    self.assertEqual(
                        runtime_state.classify_repository(root),
                        runtime_state.RuntimeState.INVALID,
                    )

                    receipt.unlink()
                    with self.assertRaises(ValueError):
                        runtime_state.publish_current_receipt(root)

    def test_failure_marker_overrides_a_real_current_receipt(self) -> None:
        self.write_compose(CURRENT_IMAGE)
        self.make_nonempty_store()
        runtime_state.publish_current_receipt(self.root)
        self.assertEqual(
            runtime_state.classify_repository(self.root),
            runtime_state.RuntimeState.CURRENT,
        )
        self.assertTrue(
            hasattr(runtime_state, "publish_failure_marker"),
            "runtime state must own the shared failure-marker publisher",
        )

        marker = runtime_state.publish_failure_marker(self.root)

        self.assertEqual(
            marker,
            self.root
            / "stalwart-data"
            / ".mail-sandbox-fresh-initialization-failed",
        )
        self.assertEqual(marker.read_bytes(), b"invalid\n")
        self.assertEqual(stat.S_IMODE(marker.stat().st_mode), 0o600)
        self.assertEqual(runtime_state.publish_failure_marker(self.root), marker)
        self.assertEqual(
            runtime_state.classify_repository(self.root),
            runtime_state.RuntimeState.INVALID,
        )

    def test_marked_fresh_runtime_finalizes_receipt_before_becoming_current(
        self,
    ) -> None:
        self.write_compose(CURRENT_IMAGE)
        self.make_nonempty_store()
        marker = runtime_state.publish_failure_marker(self.root)
        self.assertEqual(
            runtime_state.classify_repository(self.root),
            runtime_state.RuntimeState.INVALID,
        )
        self.assertTrue(
            hasattr(runtime_state, "finalize_marked_current_receipt"),
        )

        receipt = runtime_state.finalize_marked_current_receipt(self.root)

        self.assertTrue(receipt.is_file())
        self.assertFalse(marker.exists())
        self.assertEqual(
            runtime_state.classify_repository(self.root),
            runtime_state.RuntimeState.CURRENT,
        )

    def test_failure_marker_syncs_new_store_and_idempotent_existing_marker(
        self,
    ) -> None:
        self.write_compose(CURRENT_IMAGE)
        with mock.patch.object(
            runtime_state.os,
            "fsync",
            wraps=runtime_state.os.fsync,
        ) as synced:
            marker = runtime_state.publish_failure_marker(self.root)
            first_syncs = synced.call_count
            self.assertGreaterEqual(first_syncs, 3)

            self.assertEqual(
                runtime_state.publish_failure_marker(self.root),
                marker,
            )
            self.assertGreaterEqual(synced.call_count - first_syncs, 2)

    def test_any_failure_marker_type_is_invalid(self) -> None:
        self.write_compose(CURRENT_IMAGE)
        store = self.make_nonempty_store()
        runtime_state.publish_current_receipt(self.root)
        marker = store / ".mail-sandbox-fresh-initialization-failed"
        outside = self.root / "outside-marker"

        for kind in ("file", "directory", "symlink"):
            with self.subTest(kind=kind):
                try:
                    if kind == "file":
                        marker.write_bytes(b"anything")
                    elif kind == "directory":
                        marker.mkdir()
                    else:
                        outside.write_bytes(b"outside")
                        marker.symlink_to(outside)
                    self.assertEqual(
                        runtime_state.classify_repository(self.root),
                        runtime_state.RuntimeState.INVALID,
                    )
                finally:
                    if marker.is_symlink() or marker.is_file():
                        marker.unlink()
                    elif marker.exists():
                        marker.rmdir()
                    if outside.exists():
                        outside.unlink()

    def test_receipt_publication_refuses_any_failure_marker_presence(self) -> None:
        self.write_compose(CURRENT_IMAGE)
        store = self.make_nonempty_store()
        marker = store / ".mail-sandbox-fresh-initialization-failed"
        outside = self.root / "outside-marker"

        for kind in ("file", "directory", "symlink"):
            with self.subTest(kind=kind):
                try:
                    if kind == "file":
                        marker.write_bytes(b"anything")
                    elif kind == "directory":
                        marker.mkdir()
                    else:
                        outside.write_bytes(b"outside")
                        marker.symlink_to(outside)
                    with self.assertRaises(ValueError):
                        runtime_state.publish_current_receipt(self.root)
                finally:
                    if marker.is_symlink() or marker.is_file():
                        marker.unlink()
                    elif marker.exists():
                        marker.rmdir()
                    if outside.exists():
                        outside.unlink()

    def test_current_requires_valid_receipt_bound_to_image_config_and_store(self) -> None:
        self.write_compose(CURRENT_IMAGE)
        self.make_nonempty_store()
        self.assertEqual(
            runtime_state.classify_repository(self.root),
            runtime_state.RuntimeState.INVALID,
        )

        runtime_state.publish_current_receipt(self.root)

        self.assertEqual(
            runtime_state.classify_repository(self.root),
            runtime_state.RuntimeState.CURRENT,
        )

    def test_started_fresh_store_without_receipt_can_never_be_current(self) -> None:
        self.write_compose(CURRENT_IMAGE)
        self.assertEqual(
            runtime_state.classify_repository(self.root),
            runtime_state.RuntimeState.FRESH,
        )

        self.make_nonempty_store()

        self.assertEqual(
            runtime_state.classify_repository(self.root),
            runtime_state.RuntimeState.INVALID,
        )

    def test_tampered_or_contradictory_receipt_is_invalid(self) -> None:
        self.write_compose(CURRENT_IMAGE)
        self.make_nonempty_store()
        receipt = runtime_state.publish_current_receipt(self.root)
        envelope = json.loads(receipt.read_text(encoding="utf-8"))
        envelope["payload"]["config_sha256"] = "0" * 64
        receipt.write_text(json.dumps(envelope), encoding="utf-8")

        self.assertEqual(
            runtime_state.classify_repository(self.root),
            runtime_state.RuntimeState.INVALID,
        )

    def test_symlinked_store_config_or_receipt_is_invalid(self) -> None:
        self.write_compose(CURRENT_IMAGE)
        store = self.make_nonempty_store()
        receipt = runtime_state.publish_current_receipt(self.root)

        cases = (
            (store, self.root / "outside-store"),
            (self.root / "stalwart" / "config.json", self.root / "outside-config"),
            (receipt, self.root / "outside-receipt"),
        )
        for path, outside in cases:
            with self.subTest(path=path.relative_to(self.root)):
                if path.is_dir():
                    path.rename(outside)
                else:
                    outside.write_bytes(path.read_bytes())
                    path.unlink()
                path.symlink_to(outside, target_is_directory=outside.is_dir())
                self.assertEqual(
                    runtime_state.classify_repository(self.root),
                    runtime_state.RuntimeState.INVALID,
                )
                path.unlink()
                if outside.is_dir():
                    outside.rename(path)
                else:
                    path.write_bytes(outside.read_bytes())
                    outside.unlink()

    def test_symlinked_config_or_receipt_ancestor_is_invalid_and_unpublishable(
        self,
    ) -> None:
        ancestor_relatives = (
            Path("stalwart"),
            Path("debug-dashboard"),
            Path("debug-dashboard/.runtime"),
            Path("debug-dashboard/.runtime/stalwart"),
        )
        for relative in ancestor_relatives:
            with self.subTest(ancestor=relative):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory).resolve()
                    prepare_current_repository(root)
                    receipt = runtime_state.publish_current_receipt(root)
                    target = root / relative
                    outside = target.with_name(f"{target.name}-outside")
                    target.rename(outside)
                    target.symlink_to(outside, target_is_directory=True)

                    self.assertEqual(
                        runtime_state.classify_repository(root),
                        runtime_state.RuntimeState.INVALID,
                    )
                    receipt.unlink()
                    with self.assertRaises(ValueError):
                        runtime_state.publish_current_receipt(root)

    def test_classification_performs_no_filesystem_mutation(self) -> None:
        self.write_compose(CURRENT_IMAGE)
        self.make_nonempty_store()
        runtime_state.publish_current_receipt(self.root)
        before = snapshot_tree(self.root)

        self.assertEqual(
            runtime_state.classify_repository(self.root),
            runtime_state.RuntimeState.CURRENT,
        )

        self.assertEqual(snapshot_tree(self.root), before)

    def test_cli_prints_only_the_stable_state_value(self) -> None:
        self.write_compose(LEGACY_IMAGE)
        output = io.StringIO()

        with redirect_stdout(output):
            result = runtime_state.main(
                ["classify", "--repository", str(self.root)],
            )

        self.assertEqual(result, 0)
        self.assertEqual(output.getvalue(), "fresh\n")
