from __future__ import annotations

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
CONFIG_BYTES = b'{\n  "@type": "RocksDb",\n  "path": "/var/lib/stalwart/"\n}'


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


def compose_text(image: str) -> str:
    return f"""services:
  stalwart:
    image: {image}
    restart: unless-stopped
    user: "2000:2000"
    ports:
      - "127.0.0.1:8443:8080"
      - "127.0.0.1:8587:587"
    environment:
      STALWART_PUBLIC_URL: http://127.0.0.1:8443
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
        bind:
          create_host_path: false
"""


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
        (self.root / "stalwart" / "config.json").write_bytes(CONFIG_BYTES)

    def write_compose(self, image: str) -> None:
        (self.root / "docker-compose.yml").write_text(
            compose_text(image),
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
