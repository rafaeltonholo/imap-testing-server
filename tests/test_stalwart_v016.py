from __future__ import annotations

import ast
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from dataclasses import dataclass, replace
import gc
import hashlib
import importlib.util
import inspect
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import textwrap
from types import ModuleType, SimpleNamespace
import unittest
from unittest import mock


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPOSITORY_ROOT / "scripts" / "stalwart_v016.py"
BOOTSTRAP_SCRIPT_PATH = (
    REPOSITORY_ROOT / "scripts" / "bootstrap_stalwart_v016.py"
)
MIGRATION_OVERLAY_PATH = (
    REPOSITORY_ROOT / "docker-compose.stalwart-migration.yml"
)
MIGRATION_RUNBOOK_PATH = (
    REPOSITORY_ROOT / "docs" / "stalwart-v016-migration.md"
)
CANONICAL_MIGRATION_OVERLAY = MIGRATION_OVERLAY_PATH.read_bytes()
CANONICAL_MIGRATION_OVERLAY_SHA256 = hashlib.sha256(
    CANONICAL_MIGRATION_OVERLAY,
).hexdigest()
AUDITED_CONVERTED_CONFIG_BYTES = (
    b'{\n'
    b'  "@type": "RocksDb",\n'
    b'  "path": "/var/lib/stalwart"\n'
    b"}"
)
AUDITED_CONVERTED_CONFIG_SHA256 = (
    "b7aad53c4d32721e61984b0e5509764fc5d6b7405c68fd11f72c8423f04f2fb6"
)

stalwart_v016 = None
bootstrap_stalwart_v016 = None
IMPORT_ERROR: Exception | None = None
if SCRIPT_PATH.exists():
    try:
        spec = importlib.util.spec_from_file_location("stalwart_v016", SCRIPT_PATH)
        assert spec is not None
        assert spec.loader is not None
        stalwart_v016 = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = stalwart_v016
        spec.loader.exec_module(stalwart_v016)
    except Exception as exc:  # pragma: no cover - reported by the existence test
        IMPORT_ERROR = exc
if BOOTSTRAP_SCRIPT_PATH.exists():
    try:
        bootstrap_spec = importlib.util.spec_from_file_location(
            "bootstrap_stalwart_v016_for_retirement_tests",
            BOOTSTRAP_SCRIPT_PATH,
        )
        assert bootstrap_spec is not None
        assert bootstrap_spec.loader is not None
        bootstrap_stalwart_v016 = importlib.util.module_from_spec(
            bootstrap_spec,
        )
        sys.modules[bootstrap_spec.name] = bootstrap_stalwart_v016
        bootstrap_spec.loader.exec_module(bootstrap_stalwart_v016)
    except Exception as exc:  # pragma: no cover - reported by fixture failures
        IMPORT_ERROR = exc


def receipt_envelope(payload: dict[str, object]) -> dict[str, object]:
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return {
        "payload": payload,
        "payload_sha256": hashlib.sha256(canonical).hexdigest(),
    }


def write_network_environment(
    repository: Path,
    public_url: str = "http://192.168.86.36:8443",
) -> Path:
    runtime = repository / "debug-dashboard" / ".runtime"
    directory = runtime / "stalwart"
    directory.mkdir(parents=True, exist_ok=True)
    (repository / "debug-dashboard").chmod(0o700)
    runtime.chmod(0o700)
    directory.chmod(0o700)
    target = directory / "network.env"
    target.write_bytes(f"STALWART_PUBLIC_URL={public_url}\n".encode("ascii"))
    target.chmod(0o600)
    return target


def normal_compose_text() -> str:
    return textwrap.dedent(
        """\
        services:
          stalwart:
            image: stalwartlabs/stalwart:v0.16.17@sha256:a8108e19bd927e172d4d8c128907b8dfc93fd180ae8ee07dccdd42cb97eb9dfa
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
        """,
    )


def verified_source_fixture(
    checkout: Path,
    provider_store: Path,
) -> object:
    return stalwart_v016.VerifiedSource(
        checkout_root=checkout,
        provider_store=provider_store,
        base_compose=checkout / "docker-compose.yml",
        compose_project="mail-sandbox",
        compose_service="stalwart",
    )


@dataclass(frozen=True)
class _UnitRollbackProof:
    management_status: int
    proved_at: str
    version: str


@dataclass(frozen=True)
class _UnitRollbackActivation:
    proof_path: Path
    base_url: str
    proof: _UnitRollbackProof


class ScriptExistenceTest(unittest.TestCase):
    def test_migration_module_exists_and_imports(self) -> None:
        self.assertIsNotNone(
            stalwart_v016,
            f"{SCRIPT_PATH.relative_to(REPOSITORY_ROOT)} must import cleanly: {IMPORT_ERROR}",
        )

    @unittest.skipIf(stalwart_v016 is None, "migration script is not implemented")
    def test_cli_exposes_approved_apply_contract_and_only_retirement_is_unavailable(
        self,
    ) -> None:
        builder = getattr(stalwart_v016, "_build_argument_parser", None)
        self.assertIsNotNone(builder)
        help_text = builder().format_help()
        for command in (
            "dry-run",
            "mark-reviewed",
            "apply",
            "retire-recovery",
            "normal-runtime-evidence",
        ):
            self.assertIn(command, help_text)
        dry_run_help = builder()._subparsers._group_actions[0].choices[
            "dry-run"
        ].format_help()
        self.assertIn("--migration-python", dry_run_help)
        apply_help = builder()._subparsers._group_actions[0].choices[
            "apply"
        ].format_help()
        self.assertIn("--script", apply_help)
        self.assertIn("--review-receipt", apply_help)
        self.assertNotIn("unavailable", apply_help.lower())
        self.assertNotIn("live apply", help_text.lower())

        with mock.patch.object(
            stalwart_v016,
            "prepare_dry_run",
            side_effect=stalwart_v016.MigrationError("expected stop"),
        ) as prepare:
            with redirect_stderr(io.StringIO()):
                result = stalwart_v016.main(
                    [
                        "dry-run",
                        "--script",
                        "/repo/migrate_v016.py",
                        "--source-receipt",
                        "/repo/latest-source.json",
                        "--migration-python",
                        "/venv/bin/python3",
                    ],
                )
        self.assertEqual(result, 1)
        self.assertEqual(
            prepare.call_args.kwargs["migration_python"],
            "/venv/bin/python3",
        )

    def test_cli_dry_run_prints_only_the_receipt_path_on_success(self) -> None:
        paths = stalwart_v016.MigrationPaths.for_repository(REPOSITORY_ROOT)
        with mock.patch.object(
            stalwart_v016,
            "prepare_dry_run",
            return_value=paths.migration_root / "dry-run.json",
        ):
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                result = stalwart_v016.main(
                    [
                        "dry-run",
                        "--script",
                        str(paths.migration_script),
                        "--source-receipt",
                        str(paths.source_receipt),
                        "--migration-python",
                        "/venv/bin/python3",
                    ],
                )

        self.assertEqual(result, 0)
        self.assertEqual(stdout.getvalue(), f"{paths.migration_root / 'dry-run.json'}\n")

    def test_cli_apply_resolves_relative_paths_and_prints_only_fixed_receipt(
        self,
    ) -> None:
        paths = stalwart_v016.MigrationPaths.for_repository(REPOSITORY_ROOT)
        script = paths.migration_script.relative_to(REPOSITORY_ROOT)
        reviewed = paths.reviewed.relative_to(REPOSITORY_ROOT)
        with (
            mock.patch("pathlib.Path.cwd", return_value=REPOSITORY_ROOT),
            mock.patch.object(
                stalwart_v016,
                "run_production_apply",
                return_value=paths.apply_receipt,
                create=True,
            ) as apply,
            redirect_stdout(stdout := io.StringIO()),
            redirect_stderr(stderr := io.StringIO()),
        ):
            result = stalwart_v016.main(
                [
                    "apply",
                    "--script",
                    str(script),
                    "--review-receipt",
                    str(reviewed),
                ],
            )

        self.assertEqual(result, 0)
        self.assertEqual(stdout.getvalue(), f"{paths.apply_receipt}\n")
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(
            apply.call_args.args,
            (paths,),
        )
        self.assertEqual(
            apply.call_args.kwargs,
            {
                "script_path": paths.migration_script,
                "review_receipt_path": paths.reviewed,
            },
        )

    def test_cli_apply_reports_only_generic_safe_error_for_every_live_failure(
        self,
    ) -> None:
        paths = stalwart_v016.MigrationPaths.for_repository(REPOSITORY_ROOT)
        for failure in (
            RuntimeError("unit-user:unit-secret"),
            KeyboardInterrupt("unit-password"),
        ):
            with self.subTest(failure=type(failure).__name__):
                with (
                    mock.patch.object(
                        stalwart_v016,
                        "run_production_apply",
                        side_effect=failure,
                        create=True,
                    ),
                    redirect_stdout(stdout := io.StringIO()),
                    redirect_stderr(stderr := io.StringIO()),
                ):
                    result = stalwart_v016.main(
                        [
                            "apply",
                            "--script",
                            str(paths.migration_script),
                            "--review-receipt",
                            str(paths.reviewed),
                        ],
                    )

                self.assertEqual(result, 1)
                self.assertEqual(stdout.getvalue(), "")
                self.assertEqual(
                    stderr.getvalue(),
                    "error: Stalwart v0.16 apply failed safely\n",
                )
                self.assertNotIn("unit", stderr.getvalue())
                self.assertIsNone(failure.__context__)

    def test_cli_retirement_prints_only_the_fixed_receipt_on_success(self) -> None:
        paths = stalwart_v016.MigrationPaths.for_repository(REPOSITORY_ROOT)
        with (
            mock.patch.object(
                stalwart_v016,
                "run_production_recovery_retirement",
                return_value=paths.recovery_retired_receipt,
                create=True,
            ) as retirement,
            redirect_stdout(stdout := io.StringIO()),
            redirect_stderr(stderr := io.StringIO()),
        ):
            result = stalwart_v016.main(["retire-recovery"])

        self.assertEqual(result, 0)
        self.assertEqual(stdout.getvalue(), f"{paths.recovery_retired_receipt}\n")
        self.assertEqual(stderr.getvalue(), "")
        retirement.assert_called_once_with(paths)

    def test_cli_retirement_reports_only_generic_safe_error_for_every_failure(
        self,
    ) -> None:
        for failure in (
            RuntimeError("unit-user:unit-secret"),
            KeyboardInterrupt("unit-password"),
        ):
            with self.subTest(failure=type(failure).__name__):
                with (
                    mock.patch.object(
                        stalwart_v016,
                        "run_production_recovery_retirement",
                        side_effect=failure,
                        create=True,
                    ),
                    redirect_stdout(stdout := io.StringIO()),
                    redirect_stderr(stderr := io.StringIO()),
                ):
                    result = stalwart_v016.main(["retire-recovery"])

                self.assertEqual(result, 1)
                self.assertEqual(stdout.getvalue(), "")
                self.assertEqual(
                    stderr.getvalue(),
                    "error: Stalwart recovery retirement failed safely\n",
                )
                self.assertNotIn("unit", stderr.getvalue())

    def test_cli_normal_runtime_evidence_prints_only_one_canonical_line(
        self,
    ) -> None:
        paths = stalwart_v016.MigrationPaths.for_repository(REPOSITORY_ROOT)
        line = (
            b'{"payload":{"schema":"unit.v1"},'
            b'"payload_sha256":"'
            + hashlib.sha256(b'{"schema":"unit.v1"}').hexdigest().encode()
            + b'"}\n'
        )
        with (
            mock.patch.object(
                stalwart_v016,
                "build_normal_runtime_evidence",
                return_value=line,
            ) as build,
            redirect_stdout(stdout := io.StringIO()),
            redirect_stderr(stderr := io.StringIO()),
        ):
            result = stalwart_v016.main(["normal-runtime-evidence"])

        self.assertEqual(result, 0)
        self.assertEqual(stdout.getvalue(), line.decode("utf-8"))
        self.assertEqual(stderr.getvalue(), "")
        build.assert_called_once_with(paths)

    def test_cli_normal_runtime_evidence_has_no_partial_or_secret_error_output(
        self,
    ) -> None:
        for failure in (
            RuntimeError("unit-user:unit-secret"),
            stalwart_v016.MigrationError("secret=unit-secret"),
            KeyboardInterrupt("unit-password"),
        ):
            with self.subTest(failure=type(failure).__name__):
                with (
                    mock.patch.object(
                        stalwart_v016,
                        "build_normal_runtime_evidence",
                        side_effect=failure,
                    ),
                    redirect_stdout(stdout := io.StringIO()),
                    redirect_stderr(stderr := io.StringIO()),
                ):
                    result = stalwart_v016.main(
                        ["normal-runtime-evidence"],
                    )

                self.assertEqual(result, 1)
                self.assertEqual(stdout.getvalue(), "")
                self.assertEqual(
                    stderr.getvalue(),
                    (
                        "error: Stalwart normal-runtime evidence "
                        "validation failed safely\n"
                    ),
                )
                self.assertNotIn("unit", stderr.getvalue())


@unittest.skipIf(stalwart_v016 is None, "migration script is not implemented")
class SharedOperationLockTest(unittest.TestCase):
    _ANCHOR_NAMESPACE_NAME = ".mail-sandbox-stalwart-locks"

    def _repository(self, temporary: str) -> Path:
        repository = Path(temporary).resolve() / "mail-sandbox"
        (repository / "debug-dashboard").mkdir(parents=True)
        return repository

    def _probe_lock_from_another_process(
        self,
        repository: Path,
    ) -> subprocess.CompletedProcess[str]:
        probe = textwrap.dedent(
            """
            import importlib.util
            from pathlib import Path
            import sys

            script = Path(sys.argv[1])
            repository = Path(sys.argv[2])
            specification = importlib.util.spec_from_file_location(
                "stalwart_v016_lock_probe",
                script,
            )
            assert specification is not None
            assert specification.loader is not None
            module = importlib.util.module_from_spec(specification)
            sys.modules[specification.name] = module
            specification.loader.exec_module(module)
            try:
                lock = module.acquire_stalwart_operation_lock(repository)
            except module.MigrationError as error:
                print(str(error))
                raise SystemExit(23)
            else:
                lock.close()
                print("unexpectedly acquired")
                raise SystemExit(0)
            """,
        )
        return subprocess.run(
            [
                sys.executable,
                "-c",
                probe,
                str(SCRIPT_PATH),
                str(repository),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )

    def test_lock_is_owner_only_persistent_and_reusable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self._repository(temporary)
            expected = (
                repository
                / "debug-dashboard"
                / ".runtime"
                / "stalwart"
                / "bootstrap.lock"
            )

            with stalwart_v016.acquire_stalwart_operation_lock(
                repository,
            ) as acquired:
                self.assertEqual(acquired.path, expected)
                self.assertEqual(
                    repr(acquired),
                    "StalwartOperationLock(<redacted>)",
                )
                self.assertTrue(expected.is_file())
                self.assertEqual(expected.read_bytes(), b"")
                self.assertEqual(
                    stat.S_IMODE(expected.stat().st_mode),
                    0o600,
                )
                self.assertEqual(
                    stat.S_IMODE(expected.parent.stat().st_mode),
                    0o700,
                )
                self.assertEqual(
                    stat.S_IMODE(expected.parent.parent.stat().st_mode),
                    0o700,
                )

            self.assertTrue(expected.exists())
            with stalwart_v016.acquire_stalwart_operation_lock(repository):
                pass
            self.assertTrue(expected.exists())

    def test_lock_refuses_concurrent_holder_without_unlinking(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self._repository(temporary)
            lock_path = (
                repository
                / "debug-dashboard"
                / ".runtime"
                / "stalwart"
                / "bootstrap.lock"
            )

            with stalwart_v016.acquire_stalwart_operation_lock(repository):
                with self.assertRaisesRegex(
                    stalwart_v016.MigrationError,
                    "another Stalwart operation is active",
                ):
                    stalwart_v016.acquire_stalwart_operation_lock(repository)
                self.assertTrue(lock_path.exists())

            self.assertTrue(lock_path.exists())

    def test_lock_refuses_split_holder_after_runtime_namespace_replacement(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self._repository(temporary)
            stalwart_root = (
                repository
                / "debug-dashboard"
                / ".runtime"
                / "stalwart"
            )
            moved_root = (
                repository
                / "debug-dashboard"
                / ".runtime"
                / "moved-stalwart"
            )
            first = stalwart_v016.acquire_stalwart_operation_lock(repository)
            try:
                stalwart_root.rename(moved_root)
                stalwart_root.mkdir(mode=0o700)

                with self.assertRaisesRegex(
                    stalwart_v016.MigrationError,
                    "another Stalwart operation is active",
                ):
                    stalwart_v016.acquire_stalwart_operation_lock(repository)
                with self.assertRaisesRegex(
                    stalwart_v016.MigrationError,
                    "namespace changed",
                ):
                    first.assert_valid_for(repository)
            finally:
                first.close()

    def test_external_lock_anchor_blocks_repository_rename_and_recreation_split(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self._repository(temporary)
            moved_repository = Path(temporary).resolve() / "held-repository"
            first = stalwart_v016.acquire_stalwart_operation_lock(repository)
            try:
                repository.rename(moved_repository)
                (repository / "debug-dashboard").mkdir(parents=True)

                with self.assertRaisesRegex(
                    stalwart_v016.MigrationError,
                    "another Stalwart operation is active",
                ):
                    stalwart_v016.acquire_stalwart_operation_lock(repository)
            finally:
                first.close()

    def test_global_guard_blocks_multiprocess_repo_and_anchor_parent_split(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            outer = Path(temporary).resolve()
            anchor_parent = outer / "operation-parent"
            anchor_parent.mkdir(mode=0o700)
            repository = anchor_parent / "mail-sandbox"
            (repository / "debug-dashboard").mkdir(parents=True)
            moved_anchor_parent = outer / "held-operation-parent"
            anchor_namespace = (
                anchor_parent / self._ANCHOR_NAMESPACE_NAME
            )
            first = stalwart_v016.acquire_stalwart_operation_lock(repository)
            try:
                self.assertEqual(first._anchor_path.parent, anchor_namespace)
                anchor_parent.rename(moved_anchor_parent)
                anchor_parent.mkdir(mode=0o700)
                (repository / "debug-dashboard").mkdir(parents=True)

                probe = self._probe_lock_from_another_process(repository)

                self.assertEqual(probe.returncode, 23, probe.stdout + probe.stderr)
                self.assertIn(
                    "another Stalwart operation is active",
                    probe.stdout,
                )
                self.assertNotIn("unexpectedly acquired", probe.stdout)
                with self.assertRaisesRegex(
                    stalwart_v016.MigrationError,
                    "namespace changed",
                ):
                    first.assert_valid_for(repository)
            finally:
                first.close()

    def test_external_anchor_refuses_group_or_other_writable_parent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            repository = self._repository(temporary)
            root.chmod(0o777)
            try:
                with self.assertRaisesRegex(
                    stalwart_v016.MigrationError,
                    "anchor parent.*unsafe",
                ):
                    stalwart_v016.acquire_stalwart_operation_lock(repository)
                self.assertFalse(
                    (root / self._ANCHOR_NAMESPACE_NAME).exists(),
                )
            finally:
                root.chmod(0o700)

    def test_external_anchor_revalidates_parent_mode_while_held(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            repository = self._repository(temporary)
            first = stalwart_v016.acquire_stalwart_operation_lock(repository)
            try:
                root.chmod(0o777)
                with self.assertRaisesRegex(
                    stalwart_v016.MigrationError,
                    "namespace changed",
                ):
                    first.assert_valid_for(repository)
                with self.assertRaisesRegex(
                    stalwart_v016.MigrationError,
                    "another Stalwart operation is active",
                ):
                    stalwart_v016.acquire_stalwart_operation_lock(repository)
            finally:
                root.chmod(0o700)
                first.close()

    def test_external_anchor_dirfd_detects_namespace_to_symlink_swap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            repository = self._repository(temporary)
            anchor_namespace = root / self._ANCHOR_NAMESPACE_NAME
            anchor_namespace.mkdir(mode=0o700)
            moved_namespace = root / "moved-anchor-namespace"
            outside = root / "outside-anchor-target"
            outside.mkdir(mode=0o700)
            anchor_name = stalwart_v016._stalwart_operation_anchor_path(
                repository,
            ).name
            real_open = stalwart_v016.os.open
            swapped = False
            leaf_open: list[tuple[int, int]] = []

            def racing_open(
                path: object,
                flags: int,
                mode: int = 0o777,
                *,
                dir_fd: int | None = None,
            ) -> int:
                nonlocal swapped
                if (
                    not swapped
                    and path == anchor_name
                    and dir_fd is not None
                ):
                    leaf_open.append((flags, dir_fd))
                    anchor_namespace.rename(moved_namespace)
                    anchor_namespace.symlink_to(
                        outside,
                        target_is_directory=True,
                    )
                    swapped = True
                if dir_fd is None:
                    return real_open(path, flags, mode)
                return real_open(path, flags, mode, dir_fd=dir_fd)

            with (
                mock.patch.object(
                    stalwart_v016.os,
                    "open",
                    side_effect=racing_open,
                ),
                self.assertRaisesRegex(
                    stalwart_v016.MigrationError,
                    "anchor .*safely|anchor namespace.*changed",
                ),
            ):
                stalwart_v016.acquire_stalwart_operation_lock(repository)

            self.assertTrue(swapped)
            self.assertEqual(len(leaf_open), 1)
            self.assertTrue(
                leaf_open[0][0]
                & getattr(stalwart_v016.os, "O_NOFOLLOW", 0),
            )
            self.assertTrue(
                leaf_open[0][0]
                & getattr(stalwart_v016.os, "O_CLOEXEC", 0),
            )
            self.assertEqual(tuple(outside.iterdir()), ())

    def test_external_lock_anchor_refuses_symlink_and_wrong_mode(self) -> None:
        for case in ("symlink", "wrong-mode"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                repository = self._repository(temporary)
                anchor = stalwart_v016._stalwart_operation_anchor_path(
                    repository,
                )
                anchor.parent.mkdir(mode=0o700)
                if case == "symlink":
                    target = anchor.with_name("unsafe-anchor-target")
                    target.write_bytes(b"")
                    target.chmod(0o600)
                    anchor.symlink_to(target)
                else:
                    anchor.write_bytes(b"")
                    anchor.chmod(0o644)

                with self.assertRaisesRegex(
                    stalwart_v016.MigrationError,
                    "anchor",
                ):
                    stalwart_v016.acquire_stalwart_operation_lock(repository)

    def test_dropped_lock_handle_closes_descriptors_and_releases_lock(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self._repository(temporary)
            held = stalwart_v016.acquire_stalwart_operation_lock(repository)
            descriptor = held._descriptor
            namespace_descriptor = held._namespace_descriptor
            anchor_descriptor = held._anchor_descriptor
            anchor_namespace_descriptor = held._anchor_namespace_descriptor
            anchor_parent_descriptor = held._anchor_parent_descriptor
            global_descriptor = held._global_descriptor
            try:
                del held
                gc.collect()

                for closed_descriptor in (
                    descriptor,
                    namespace_descriptor,
                    anchor_descriptor,
                    anchor_namespace_descriptor,
                    anchor_parent_descriptor,
                    global_descriptor,
                ):
                    with self.assertRaises(OSError):
                        os.fstat(closed_descriptor)
                with stalwart_v016.acquire_stalwart_operation_lock(repository):
                    pass
            finally:
                for leaked_descriptor in (
                    descriptor,
                    namespace_descriptor,
                    anchor_descriptor,
                    anchor_namespace_descriptor,
                    anchor_parent_descriptor,
                    global_descriptor,
                ):
                    try:
                        os.close(leaked_descriptor)
                    except OSError:
                        pass

    def test_lock_refuses_symlink_and_wrong_mode_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self._repository(temporary)
            lock_parent = (
                repository
                / "debug-dashboard"
                / ".runtime"
                / "stalwart"
            )
            lock_parent.mkdir(parents=True)
            os.chmod(lock_parent.parent, 0o700)
            os.chmod(lock_parent, 0o700)
            target = repository / "outside"
            target.write_bytes(b"")
            lock_path = lock_parent / "bootstrap.lock"
            lock_path.symlink_to(target)

            with self.assertRaises(stalwart_v016.MigrationError):
                stalwart_v016.acquire_stalwart_operation_lock(repository)
            self.assertTrue(lock_path.is_symlink())
            self.assertEqual(target.read_bytes(), b"")

        with tempfile.TemporaryDirectory() as temporary:
            repository = self._repository(temporary)
            lock_parent = (
                repository
                / "debug-dashboard"
                / ".runtime"
                / "stalwart"
            )
            lock_parent.mkdir(parents=True)
            os.chmod(lock_parent.parent, 0o700)
            os.chmod(lock_parent, 0o700)
            lock_path = lock_parent / "bootstrap.lock"
            lock_path.write_bytes(b"")
            os.chmod(lock_path, 0o644)

            with self.assertRaisesRegex(
                stalwart_v016.MigrationError,
                "mode 0600",
            ):
                stalwart_v016.acquire_stalwart_operation_lock(repository)
            self.assertEqual(stat.S_IMODE(lock_path.stat().st_mode), 0o644)

    def test_lock_refuses_runtime_symlink_component(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self._repository(temporary)
            outside = Path(temporary) / "outside"
            outside.mkdir()
            (
                repository / "debug-dashboard" / ".runtime"
            ).symlink_to(outside, target_is_directory=True)

            with self.assertRaises(stalwart_v016.MigrationError):
                stalwart_v016.acquire_stalwart_operation_lock(repository)
            self.assertEqual(tuple(outside.iterdir()), ())

    def test_lock_refuses_symlinked_repository_ancestor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            real_parent = root / "real-parent"
            repository = real_parent / "mail-sandbox"
            (repository / "debug-dashboard").mkdir(parents=True)
            alias = root / "alias"
            alias.symlink_to(real_parent, target_is_directory=True)
            aliased_repository = alias / "mail-sandbox"

            with self.assertRaisesRegex(
                stalwart_v016.MigrationError,
                "repository root.*symlink",
            ):
                with stalwart_v016.acquire_stalwart_operation_lock(
                    aliased_repository,
                ):
                    pass

            self.assertFalse(
                (
                    repository
                    / "debug-dashboard"
                    / ".runtime"
                ).exists(),
            )

    def test_lock_tightens_an_existing_owned_runtime_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self._repository(temporary)
            runtime = repository / "debug-dashboard" / ".runtime"
            runtime.mkdir(mode=0o755)
            runtime.chmod(0o755)

            with stalwart_v016.acquire_stalwart_operation_lock(repository):
                self.assertEqual(
                    stat.S_IMODE(runtime.stat().st_mode),
                    0o700,
                )

            self.assertEqual(
                stat.S_IMODE(runtime.stat().st_mode),
                0o700,
            )


@unittest.skipIf(stalwart_v016 is None, "migration script is not implemented")
class FixedContractTest(unittest.TestCase):
    def test_pins_the_exact_stalwart_image_and_migration_script_digest(self) -> None:
        self.assertEqual(
            getattr(stalwart_v016, "STALWART_IMAGE", None),
            "stalwartlabs/stalwart:v0.16.17@"
            "sha256:a8108e19bd927e172d4d8c128907b8dfc93fd180ae8ee07dccdd42cb97eb9dfa",
        )
        self.assertEqual(
            getattr(stalwart_v016, "STALWART_IMAGE_ID", None),
            "sha256:"
            "a8108e19bd927e172d4d8c128907b8dfc93fd180ae8ee07dccdd42cb97eb9dfa",
        )
        self.assertEqual(
            getattr(stalwart_v016, "MIGRATION_SCRIPT_SHA256", None),
            "008a490b4c3c60572806958e1960749ecdddf263316683017003797b9c34ca1c",
        )
        self.assertEqual(
            getattr(stalwart_v016, "STALWART_CLI_IMAGE", None),
            "stalwartlabs/cli:1.0.12@sha256:"
            "fe199affac1d120a8c200ef39ae629765a2976270e0453575c1caf906ee15b52",
        )
        self.assertEqual(
            CANONICAL_MIGRATION_OVERLAY_SHA256,
            "77540a67777579e8b4a2be9d386122c3f7f7dba911889cbe8100d49a0e4fac62",
        )
        self.assertEqual(
            getattr(stalwart_v016, "MIGRATION_COMPOSE_SHA256", None),
            CANONICAL_MIGRATION_OVERLAY_SHA256,
        )
        self.assertEqual(
            stat.S_IMODE(MIGRATION_OVERLAY_PATH.stat().st_mode),
            0o644,
        )

    def test_runbook_downloads_the_exact_tagged_migration_script(self) -> None:
        text = MIGRATION_RUNBOOK_PATH.read_text(encoding="utf-8")

        self.assertIn(
            "https://raw.githubusercontent.com/stalwartlabs/stalwart/"
            "v0.16.17/resources/scripts/migrate_v016.py",
            text,
        )
        self.assertNotIn(
            "https://raw.githubusercontent.com/stalwartlabs/stalwart/"
            "v0.16.14/resources/scripts/migrate_v016.py",
            text,
        )

    def test_derives_every_dry_run_artifact_from_the_fixed_migration_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory).resolve()

            paths_type = getattr(stalwart_v016, "MigrationPaths", None)
            self.assertIsNotNone(paths_type)
            paths = paths_type.for_repository(repository)

            root = repository / "debug-dashboard" / ".runtime" / "stalwart-migration"
            self.assertEqual(paths.migration_root, root)
            self.assertEqual(paths.scratch_store, root / "provider-scratch")
            self.assertEqual(paths.source_receipt, root / "latest-source.json")
            self.assertEqual(paths.migration_script, root / "migrate_v016.py")
            self.assertEqual(paths.settings, root / "settings.json")
            self.assertEqual(paths.principals, root / "principals.json")
            self.assertEqual(paths.converted_config, root / "config.json")
            self.assertEqual(paths.export, root / "export.json")
            self.assertEqual(paths.unmigrated, root / "unmigrated.txt")
            self.assertEqual(paths.reviewed, root / "reviewed.json")
            self.assertEqual(paths.dry_run_receipt, root / "dry-run.json")
            self.assertEqual(paths.apply_attempt, root / "apply-attempt.json")
            self.assertEqual(paths.apply_receipt, root / "apply.json")
            self.assertEqual(
                paths.bootstrap_receipt,
                repository
                / "debug-dashboard"
                / ".runtime"
                / "stalwart"
                / "bootstrap.json",
            )
            self.assertEqual(
                paths.retire_recovery_attempt,
                root / "retire-recovery-attempt.json",
            )
            self.assertEqual(
                paths.retire_recovery_proof,
                root / "retire-recovery-proof.json",
            )
            self.assertEqual(
                paths.recovery_retired_receipt,
                root / "recovery-retired.json",
            )
            for output in paths.dry_run_outputs:
                self.assertEqual(output.parent, root)


@unittest.skipIf(stalwart_v016 is None, "migration script is not implemented")
class RecoveryRetirementContractTest(unittest.TestCase):
    def test_every_non_normal_stalwart_publication_remains_loopback_only(
        self,
    ) -> None:
        gate_definitions = sorted(
            (
                REPOSITORY_ROOT
                / "debug-dashboard"
                / "dashboard-server"
                / "testResources"
                / "stalwart-gate0b"
            ).glob("compose*.yml"),
        )
        definitions = [
            REPOSITORY_ROOT / "docker-compose.stalwart-migration.yml",
            *gate_definitions,
        ]
        for name in (
            "docker-compose.stalwart-gate.yml",
            "docker-compose.stalwart-recovery.yml",
            "docker-compose.stalwart-rollback.yml",
            "docker-compose.stalwart-rehearsal.yml",
        ):
            candidate = REPOSITORY_ROOT / name
            if candidate.exists():
                definitions.append(candidate)

        self.assertEqual(
            [path.name for path in gate_definitions],
            ["compose.recovery.yml", "compose.yml"],
        )

        for path in definitions:
            with self.subTest(path=path.relative_to(REPOSITORY_ROOT)):
                self.assertTrue(path.is_file())
                content = path.read_text(encoding="utf-8")
                self.assertNotIn("0.0.0.0", content)
                for match in re.finditer(
                    r"[\"']?host_ip[\"']?\s*:\s*[\"']?([^\s#\"']+)",
                    content,
                ):
                    self.assertEqual(match.group(1), "127.0.0.1")
                for match in re.finditer(
                    r'^\s*-\s*["\']?([^\s#"\']+)["\']?\s*(?:#.*)?$',
                    content,
                    re.MULTILINE,
                ):
                    publication = match.group(1)
                    port = re.fullmatch(
                        r"(?:(?P<host>[^:]+):)?\d+:\d+",
                        publication,
                    )
                    if port is not None:
                        self.assertEqual(
                            port.group("host"),
                            "127.0.0.1",
                            publication,
                        )

        capture_source = (
            REPOSITORY_ROOT / "scripts" / "capture_stalwart_v015.py"
        ).read_text(encoding="utf-8")
        rollback_host_ips = re.findall(
            r'"(?:host_ip|HostIp)"\s*:\s*"([^"]+)"',
            capture_source,
        )
        self.assertGreaterEqual(len(rollback_host_ips), 2)
        self.assertEqual(set(rollback_host_ips), {"127.0.0.1"})

    def test_fixed_jmap_probe_result_contract_is_strict_and_redacted(
        self,
    ) -> None:
        bearer = stalwart_v016._validated_jmap_auth_probe_output(
            (
                b'{"account_id":"unit-account","status":200,'
                b'"username":"dashboard-management@local.test"}'
            ),
            scheme="bearer",
        )
        rejected = stalwart_v016._validated_jmap_auth_probe_output(
            b'{"account_id":null,"status":401,"username":null}',
            scheme="basic",
        )
        basic = stalwart_v016._validated_jmap_auth_probe_output(
            b'{"account_id":"unit-account","status":200,'
            b'"username":"dashboard-management@local.test"}',
            scheme="basic",
            authenticated=True,
        )

        self.assertEqual(
            bearer,
            stalwart_v016.JmapAuthProbe(
                status=200,
                account_id="unit-account",
                username="dashboard-management@local.test",
            ),
        )
        self.assertEqual(rejected.status, 401)
        self.assertIsNone(rejected.account_id)
        self.assertIsNone(rejected.username)
        self.assertEqual(basic, bearer)
        self.assertEqual(repr(bearer), "JmapAuthProbe(<redacted>)")

        invalid = (
            (b"", "bearer"),
            (b"{" + b"x" * (4096 + 1), "bearer"),
            (
                b'{"account_id":"unit-account","status":302,'
                b'"username":"dashboard-management@local.test"}',
                "bearer",
            ),
            (
                b'{"account_id":null,"status":401,"username":null}',
                "bearer",
            ),
            (
                b'{"account_id":"unit-account","status":200,'
                b'"username":"dashboard-management@local.test"}',
                "basic",
            ),
            (
                b'{"account_id":null,"status":302,"username":null}',
                "basic",
            ),
            (
                b'{"account_id":null,"status":500,"username":null}',
                "basic",
            ),
            (
                b'{"account_id":null,"extra":1,"status":401,'
                b'"username":null}',
                "basic",
            ),
            (
                b'{"account_id":null,"status":true,"username":null}',
                "basic",
            ),
        )
        for raw, scheme in invalid:
            with self.subTest(raw=raw[:40], scheme=scheme):
                with self.assertRaises(stalwart_v016.MigrationError):
                    stalwart_v016._validated_jmap_auth_probe_output(
                        raw,
                        scheme=scheme,
                    )

        parent_source = inspect.getsource(
            stalwart_v016.run_fixed_jmap_auth_probe,
        )
        for forbidden in (
            "bytes(",
            ".tobytes(",
            ".decode(",
            "Authorization",
            "Basic ",
            "Bearer ",
        ):
            self.assertNotIn(forbidden, parent_source)
        self.assertIn(
            "JMAP_AUTH_PROBE_MODE",
            parent_source,
        )

    def test_fixed_normal_smtp_probe_uses_loopback_8587_and_management_login(
        self,
    ) -> None:
        events: list[object] = []

        class Smtp:
            def __init__(
                self,
                host: str,
                port: int,
                *,
                timeout: float,
            ) -> None:
                events.append(("connect", host, port, timeout))

            def __enter__(self) -> "Smtp":
                return self

            def __exit__(self, *_args: object) -> None:
                events.append(("close",))

            def ehlo(self) -> tuple[int, bytes]:
                events.append(("ehlo",))
                return 250, b"ok"

            def login(self, username: str, password: str) -> None:
                events.append(("login", username, password))

            def noop(self) -> tuple[int, bytes]:
                events.append(("noop",))
                return 250, b"ok"

        credential = bytearray(
            b"dashboard-management@local.test:secret",
        )

        view = memoryview(credential).toreadonly()
        try:
            status = stalwart_v016.run_fixed_normal_smtp_auth_probe(
                view,
                smtp_factory=Smtp,
            )
        finally:
            view.release()

        self.assertEqual(status, 250)
        self.assertEqual(
            events,
            [
                ("connect", "127.0.0.1", 8587, 5.0),
                ("ehlo",),
                (
                    "login",
                    "dashboard-management@local.test",
                    "secret",
                ),
                ("noop",),
                ("close",),
            ],
        )

    def test_normal_runtime_public_url_is_loaded_strictly_at_proof_time(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory).resolve()
            write_network_environment(repository)

            self.assertEqual(
                stalwart_v016._normal_runtime_public_url(repository),
                "http://192.168.86.36:8443",
            )

            target = (
                repository
                / "debug-dashboard"
                / ".runtime"
                / "stalwart"
                / "network.env"
            )
            target.write_bytes(
                b"STALWART_PUBLIC_URL=http://127.0.0.1:8443\n",
            )
            target.chmod(0o600)
            with self.assertRaises(stalwart_v016.MigrationError):
                stalwart_v016._normal_runtime_public_url(repository)

    def test_fixed_jmap_probe_child_uses_only_fixed_endpoint_and_sanitized_output(
        self,
    ) -> None:
        session = {
            "accounts": {
                "unit-account": {
                    "accountCapabilities": {
                        "urn:stalwart:jmap": {},
                    },
                    "name": "dashboard-management@local.test",
                },
            },
            "apiUrl": "http://192.168.86.36:8443/jmap/",
            "capabilities": {
                "urn:ietf:params:jmap:core": {},
                "urn:stalwart:jmap": {},
            },
            "primaryAccounts": {
                "urn:stalwart:jmap": "unit-account",
            },
            "username": "dashboard-management@local.test",
        }
        body = json.dumps(
            session,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        calls: list[object] = []

        class Response:
            status = 200

            def getheaders(self) -> list[tuple[str, str]]:
                return [
                    ("Content-Type", "application/json"),
                    ("Content-Length", str(len(body))),
                ]

            def read(self, maximum: int) -> bytes:
                self.maximum = maximum
                return body

            def close(self) -> None:
                calls.append("response-close")

        class Connection:
            def __init__(
                self,
                host: str,
                port: int,
                *,
                timeout: int | float,
            ) -> None:
                calls.append(("connect", host, port, timeout))

            def request(
                self,
                method: str,
                path: str,
                *,
                body: object,
                headers: dict[str, str],
            ) -> None:
                calls.append(
                    (
                        "request",
                        method,
                        path,
                        body,
                        dict(headers),
                    ),
                )

            def getresponse(self) -> Response:
                return Response()

            def close(self) -> None:
                calls.append("connection-close")

        secret = bytearray(b"API_unit-management-key")
        result = stalwart_v016._fixed_jmap_auth_exchange(
            secret,
            scheme="bearer",
            expected_api_url="http://192.168.86.36:8443/jmap/",
            connection_factory=Connection,
        )

        self.assertEqual(
            calls[0],
            ("connect", "127.0.0.1", 8443, 5),
        )
        request = calls[1]
        self.assertEqual(request[1:4], ("GET", "/.well-known/jmap", None))
        self.assertEqual(
            request[4]["Accept"],
            "application/json",
        )
        self.assertTrue(request[4]["Authorization"].startswith("Bearer "))
        self.assertEqual(
            result,
            {
                "account_id": "unit-account",
                "status": 200,
                "username": "dashboard-management@local.test",
            },
        )
        serialized = json.dumps(result, sort_keys=True)
        self.assertNotIn("API_unit-management-key", serialized)
        self.assertEqual(
            calls[-2:],
            ["response-close", "connection-close"],
        )

        def assert_rejected(
            *,
            response_body: bytes = body,
            headers: list[tuple[str, str]] | None = None,
            status: int = 200,
            scheme: str = "bearer",
        ) -> None:
            cleanup: list[str] = []
            selected_headers = (
                [
                    ("Content-Type", "application/json"),
                    ("Content-Length", str(len(response_body))),
                ]
                if headers is None
                else headers
            )

            class RejectedResponse:
                def __init__(self) -> None:
                    self.status = status

                def getheaders(self) -> list[tuple[str, str]]:
                    return selected_headers

                def read(self, _maximum: int) -> bytes:
                    return response_body

                def close(self) -> None:
                    cleanup.append("response")

            class RejectedConnection:
                def __init__(self, *_args: object, **_kwargs: object) -> None:
                    pass

                def request(self, *_args: object, **_kwargs: object) -> None:
                    pass

                def getresponse(self) -> RejectedResponse:
                    return RejectedResponse()

                def close(self) -> None:
                    cleanup.append("connection")

            rejected_credential = (
                bytearray(b"unit-user:unit-secret")
                if scheme == "basic"
                else bytearray(b"API_unit-management-key")
            )
            with self.assertRaises(stalwart_v016.MigrationError):
                stalwart_v016._fixed_jmap_auth_exchange(
                    rejected_credential,
                    scheme=scheme,
                    expected_api_url="http://192.168.86.36:8443/jmap/",
                    connection_factory=RejectedConnection,
                )
            self.assertEqual(cleanup, ["response", "connection"])

        malformed_responses = {
            "missing-content-type": {
                "headers": [("Content-Length", str(len(body)))],
            },
            "duplicate-content-type": {
                "headers": [
                    ("Content-Type", "application/json"),
                    ("Content-Type", "application/json"),
                    ("Content-Length", str(len(body))),
                ],
            },
            "non-json-content-type": {
                "headers": [
                    ("Content-Type", "text/plain"),
                    ("Content-Length", str(len(body))),
                ],
            },
            "missing-content-length": {
                "headers": [("Content-Type", "application/json")],
            },
            "duplicate-content-length": {
                "headers": [
                    ("Content-Type", "application/json"),
                    ("Content-Length", str(len(body))),
                    ("Content-Length", str(len(body))),
                ],
            },
            "chunked": {
                "headers": [
                    ("Content-Type", "application/json"),
                    ("Content-Length", str(len(body))),
                    ("Transfer-Encoding", "chunked"),
                ],
            },
            "length-mismatch": {
                "headers": [
                    ("Content-Type", "application/json"),
                    ("Content-Length", str(len(body) - 1)),
                ],
            },
            "length-overflow": {
                "headers": [
                    ("Content-Type", "application/json"),
                    (
                        "Content-Length",
                        str(
                            stalwart_v016.JMAP_AUTH_PROBE_MAXIMUM_BODY
                            + 1
                        ),
                    ),
                ],
            },
            "redirect": {"status": 302},
            "duplicate-json-member": {
                "response_body": (
                    b'{"username":"first","username":"second"}'
                ),
            },
        }
        for label, changes in malformed_responses.items():
            with self.subTest(label=label):
                assert_rejected(**changes)

        basic_responses = (
            (401, [], b""),
            (
                403,
                [
                    ("Content-Type", "text/plain"),
                    ("Content-Length", "9"),
                ],
                b"forbidden",
            ),
        )
        for status, selected_headers, response_body in basic_responses:
            with self.subTest(basic_status=status):
                cleanup: list[str] = []

                class BasicResponse:
                    def __init__(self) -> None:
                        self.status = status

                    def getheaders(self) -> list[tuple[str, str]]:
                        return selected_headers

                    def read(self, _maximum: int) -> bytes:
                        return response_body

                    def close(self) -> None:
                        cleanup.append("response")

                class BasicConnection:
                    def __init__(
                        self,
                        *_args: object,
                        **_kwargs: object,
                    ) -> None:
                        pass

                    def request(
                        self,
                        *_args: object,
                        **_kwargs: object,
                    ) -> None:
                        pass

                    def getresponse(self) -> BasicResponse:
                        return BasicResponse()

                    def close(self) -> None:
                        cleanup.append("connection")

                basic_result = stalwart_v016._fixed_jmap_auth_exchange(
                    bytearray(b"unit-user:unit-secret"),
                    scheme="basic",
                    expected_api_url="http://192.168.86.36:8443/jmap/",
                    connection_factory=BasicConnection,
                )
                self.assertEqual(
                    basic_result,
                    {
                        "account_id": None,
                        "status": status,
                        "username": None,
                    },
                )
                self.assertEqual(cleanup, ["response", "connection"])

    def test_fixed_jmap_probe_parent_cancellation_is_exact_and_secret_free(
        self,
    ) -> None:
        interruption = KeyboardInterrupt("unit-cancellation")
        read_descriptor, write_descriptor = os.pipe()
        captured: list[tuple[object, dict[str, object]]] = []

        class Process:
            pid = 4242
            returncode = None

            def __init__(self) -> None:
                self.stdin = os.fdopen(
                    write_descriptor,
                    "wb",
                    buffering=0,
                )

            def communicate(self, *, timeout: int | float) -> object:
                self.timeout = timeout
                raise interruption

        process = Process()

        def process_factory(
            args: object,
            **kwargs: object,
        ) -> Process:
            captured.append((args, kwargs))
            return process

        credential = bytearray(b"unit-user:unit-secret")
        lease = stalwart_v016.RecoveryCredentialLease(credential)
        view = lease.borrow()
        try:
            with (
                mock.patch.object(
                    stalwart_v016.subprocess,
                    "Popen",
                    side_effect=process_factory,
                ),
                mock.patch.object(
                    stalwart_v016,
                    "_terminate_secret_dispatch",
                ) as terminate,
            ):
                with self.assertRaises(KeyboardInterrupt) as raised:
                    stalwart_v016.run_fixed_jmap_auth_probe(
                        view,
                        scheme="basic",
                    )
        finally:
            view.release()
            lease.close()
            os.close(read_descriptor)

        self.assertIs(raised.exception, interruption)
        terminate.assert_called_once_with(process)
        invocation = repr(captured)
        self.assertNotIn("unit-user", invocation)
        self.assertNotIn("unit-secret", invocation)
        self.assertEqual(
            credential,
            bytearray(b"\x00" * len(b"unit-user:unit-secret")),
        )

    def test_fixed_jmap_probe_write_cancellation_closes_every_pipe(
        self,
    ) -> None:
        interruption = KeyboardInterrupt("unit-write-cancellation")
        stdin_read, stdin_write = os.pipe()
        stdout_read, stdout_write = os.pipe()
        stderr_read, stderr_write = os.pipe()
        streams = (
            os.fdopen(stdin_write, "wb", buffering=0),
            os.fdopen(stdout_read, "rb", buffering=0),
            os.fdopen(stderr_read, "rb", buffering=0),
        )

        class Process:
            pid = 4242
            returncode = None

            def __init__(self) -> None:
                self.stdin, self.stdout, self.stderr = streams
                self.killed = 0
                self.waited: list[int | float] = []

            def kill(self) -> None:
                self.killed += 1

            def wait(self, *, timeout: int | float) -> int:
                self.waited.append(timeout)
                return -9

            def communicate(self, *, timeout: int | float) -> object:
                self.fail(f"unexpected communicate: {timeout}")

        process = Process()
        credential = bytearray(b"unit-user:unit-secret")
        view = memoryview(credential).toreadonly()
        try:
            with (
                mock.patch.object(
                    stalwart_v016.subprocess,
                    "Popen",
                    return_value=process,
                ),
                mock.patch.object(
                    stalwart_v016,
                    "_write_all_to_descriptor",
                    side_effect=interruption,
                ),
                mock.patch.object(
                    stalwart_v016.os,
                    "killpg",
                    side_effect=OSError("unit-no-process-group"),
                ),
                self.assertRaises(KeyboardInterrupt) as raised,
            ):
                stalwart_v016.run_fixed_jmap_auth_probe(
                    view,
                    scheme="basic",
                )
        finally:
            view.release()
            os.close(stdin_read)
            os.close(stdout_write)
            os.close(stderr_write)

        self.assertIs(raised.exception, interruption)
        self.assertEqual(process.killed, 1)
        self.assertEqual(process.waited, [5])
        self.assertTrue(all(stream.closed for stream in streams))
        self.assertIsNone(process.stdin)
        self.assertIsNone(process.stdout)
        self.assertIsNone(process.stderr)

    def test_fixed_jmap_probe_communicate_cancellation_closes_every_pipe(
        self,
    ) -> None:
        interruption = KeyboardInterrupt("unit-communicate-cancellation")
        stdin_read, stdin_write = os.pipe()
        stdout_read, stdout_write = os.pipe()
        stderr_read, stderr_write = os.pipe()
        streams = (
            os.fdopen(stdin_write, "wb", buffering=0),
            os.fdopen(stdout_read, "rb", buffering=0),
            os.fdopen(stderr_read, "rb", buffering=0),
        )

        class Process:
            pid = 4343
            returncode = None

            def __init__(self) -> None:
                self.stdin, self.stdout, self.stderr = streams
                self.killed = 0
                self.waited: list[int | float] = []

            def kill(self) -> None:
                self.killed += 1

            def wait(self, *, timeout: int | float) -> int:
                self.waited.append(timeout)
                return -9

            def communicate(self, *, timeout: int | float) -> object:
                self.timeout = timeout
                raise interruption

        process = Process()
        credential = bytearray(b"unit-user:unit-secret")
        view = memoryview(credential).toreadonly()
        try:
            with (
                mock.patch.object(
                    stalwart_v016.subprocess,
                    "Popen",
                    return_value=process,
                ),
                mock.patch.object(
                    stalwart_v016.os,
                    "killpg",
                    side_effect=OSError("unit-no-process-group"),
                ),
                self.assertRaises(KeyboardInterrupt) as raised,
            ):
                stalwart_v016.run_fixed_jmap_auth_probe(
                    view,
                    scheme="basic",
                )
        finally:
            view.release()
            os.close(stdin_read)
            os.close(stdout_write)
            os.close(stderr_write)

        self.assertIs(raised.exception, interruption)
        self.assertEqual(process.killed, 1)
        self.assertEqual(process.waited, [5])
        self.assertEqual(
            process.timeout,
            stalwart_v016.JMAP_AUTH_PROBE_TIMEOUT_SECONDS + 5,
        )
        self.assertTrue(all(stream.closed for stream in streams))
        self.assertIsNone(process.stdin)
        self.assertIsNone(process.stdout)
        self.assertIsNone(process.stderr)

    def test_mutable_credential_lease_is_redacted_closeable_and_wipes_in_place(
        self,
    ) -> None:
        credential = bytearray(b"unit-user:unit-secret")
        lease_type = getattr(
            stalwart_v016,
            "RecoveryCredentialLease",
            None,
        )
        self.assertIsNotNone(lease_type)

        lease = lease_type(credential)
        borrowed = lease.borrow()

        self.assertTrue(borrowed.readonly)
        self.assertEqual(bytes(borrowed), b"unit-user:unit-secret")
        self.assertNotIn("unit-user", repr(lease))
        self.assertNotIn("unit-secret", repr(lease))
        self.assertFalse(lease.closed)

        lease.close()

        self.assertTrue(lease.closed)
        self.assertEqual(bytes(borrowed), b"\x00" * len(credential))
        self.assertEqual(credential, bytearray(b"\x00" * len(credential)))
        lease.close()
        with self.assertRaises(stalwart_v016.MigrationError):
            lease.borrow()

        colon_password = bytearray(b"unit-user:unit-secret:")
        with self.assertRaises(stalwart_v016.MigrationError):
            lease_type(colon_password)
        self.assertEqual(
            colon_password,
            bytearray(b"\x00" * len(colon_password)),
        )

    def test_retirement_proof_is_frozen_typed_and_repr_redacted(self) -> None:
        proof_type = getattr(
            stalwart_v016,
            "RecoveryRetirementProof",
            None,
        )
        self.assertIsNotNone(proof_type)
        proof = proof_type(
            apply_receipt_sha256="a" * 64,
            bootstrap_receipt_sha256="b" * 64,
            bootstrap_proof_sha256="c" * 64,
            management_account_id="unit-account",
            management_api_key_id="unit-key",
            ip_restriction_decision=(
                "disabled-local-only-loopback-network-isolation"
            ),
            permissions_sha256="d" * 64,
            protected_accounts_sha256="e" * 64,
            safe_objects_sha256="3" * 64,
            preserved_objects_sha256="1" * 64,
            routing_proof_sha256="2" * 64,
            listener_id="unit-listener",
            account_projection_sha256="f" * 64,
            api_key_projection_sha256="0" * 64,
            retirement_attempt_sha256="b" * 64,
            operation_plan_sha256="c" * 64,
            server_version="0.16.17",
            management_status=200,
            readiness_status=200,
            old_recovery_auth_status=401,
            normal_url="http://127.0.0.1:8443",
            image_reference="stalwartlabs/stalwart:v0.16.17@sha256:a8108e19bd927e172d4d8c128907b8dfc93fd180ae8ee07dccdd42cb97eb9dfa",
            image_id="sha256:" + "d" * 64,
            container_id="e" * 64,
            overlapping_writer_ids=("e" * 64,),
            migration_container_ids=(),
            recovery_environment_names=(),
        )

        self.assertTrue(proof.__dataclass_params__.frozen)
        self.assertEqual(repr(proof), "RecoveryRetirementProof(<redacted>)")
        with self.assertRaises((AttributeError, TypeError)):
            proof.management_status = 500

    def test_bootstrap_retirement_binding_is_frozen_and_redacted(self) -> None:
        binding_type = getattr(
            stalwart_v016,
            "BootstrapRetirementBinding",
            None,
        )
        self.assertIsNotNone(binding_type)
        binding = binding_type(
            bootstrap_receipt_sha256="0" * 64,
            apply_receipt_sha256="1" * 64,
            bootstrap_proof_sha256="2" * 64,
            server_version="0.16.17",
            authentication_status=200,
            management_account_id="unit-account",
            management_api_key_id="unit-key",
            ip_restriction_decision=(
                "disabled-local-only-loopback-network-isolation"
            ),
            permissions_sha256="3" * 64,
            protected_accounts_sha256="4" * 64,
            safe_objects_sha256="5" * 64,
            preserved_objects_sha256="6" * 64,
            routing_proof_sha256="7" * 64,
            listener_id="unit-listener",
            listener_name="http",
            listener_bind=("[::]:8080",),
            listener_protocol="http",
            listener_use_tls=False,
            listener_tls_implicit=False,
            account_projection_sha256="8" * 64,
            api_key_projection_sha256="9" * 64,
            management_key_name="stalwart-management-api-key",
            management_key_size=32,
            management_key_identity=(1, 2, 3, 4, 5, 6, 7, 8),
        )

        self.assertTrue(binding.__dataclass_params__.frozen)
        self.assertEqual(
            repr(binding),
            "BootstrapRetirementBinding(<redacted>)",
        )
        with self.assertRaises(stalwart_v016.MigrationError):
            stalwart_v016._bootstrap_retirement_metadata(
                stalwart_v016.ApplyFile(
                    path=Path("/unit/bootstrap.json"),
                    sha256="0" * 64,
                    size=1,
                    identity=(1, 2, 3, 4, 5, 6),
                ),
                replace(
                    binding,
                    management_key_identity=(
                        1,
                        2,
                        3,
                        4,
                        5,
                        6,
                        7,
                        1 << 64,
                    ),
                ),
            )
        with self.assertRaises((AttributeError, TypeError)):
            binding.authentication_status = 500


@unittest.skipIf(stalwart_v016 is None, "migration script is not implemented")
class FilesystemContractTest(unittest.TestCase):
    def test_owner_directory_creation_uses_0700_for_every_new_component(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory).resolve()
            destination = repository / "one" / "two"
            helper = getattr(stalwart_v016, "ensure_owner_directory", None)
            self.assertIsNotNone(helper)

            helper(destination, trusted_root=repository)

            self.assertEqual(stat.S_IMODE((repository / "one").stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o700)

    def test_migration_root_allows_existing_0755_shared_prefixes_without_chmod(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory).resolve()
            dashboard = repository / "debug-dashboard"
            runtime = dashboard / ".runtime"
            dashboard.mkdir(mode=0o755)
            runtime.mkdir(mode=0o755)
            paths = stalwart_v016.MigrationPaths.for_repository(repository)

            stalwart_v016.ensure_owner_directory(
                paths.migration_root,
                trusted_root=repository,
                owner_root=paths.migration_root,
            )

            self.assertEqual(stat.S_IMODE(dashboard.stat().st_mode), 0o755)
            self.assertEqual(stat.S_IMODE(runtime.stat().st_mode), 0o755)
            self.assertEqual(stat.S_IMODE(paths.migration_root.stat().st_mode), 0o700)

    def test_owner_directory_refuses_symlinked_or_non_owner_components(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory).resolve()
            outside = repository / "outside"
            outside.mkdir(mode=0o700)
            linked = repository / "linked"
            linked.symlink_to(outside, target_is_directory=True)

            with self.assertRaisesRegex(stalwart_v016.MigrationError, "symlink"):
                stalwart_v016.ensure_owner_directory(
                    linked / "escaped",
                    trusted_root=repository,
                )
            self.assertFalse((outside / "escaped").exists())

            loose = repository / "loose"
            loose.mkdir(mode=0o755)
            with self.assertRaisesRegex(stalwart_v016.MigrationError, "0700"):
                stalwart_v016.ensure_owner_directory(
                    loose / "child",
                    trusted_root=repository,
                )

    def test_migration_script_must_be_the_fixed_0600_regular_file_with_exact_digest(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory).resolve()
            paths = stalwart_v016.MigrationPaths.for_repository(repository)
            stalwart_v016.ensure_owner_directory(
                paths.migration_root,
                trusted_root=repository,
            )
            content = b"pinned migration script fixture\n"
            paths.migration_script.write_bytes(content)
            paths.migration_script.chmod(0o600)
            digest = hashlib.sha256(content).hexdigest()
            validator = getattr(stalwart_v016, "validate_migration_script", None)
            self.assertIsNotNone(validator)

            validator(paths, paths.migration_script, expected_sha256=digest)

            with self.assertRaisesRegex(stalwart_v016.MigrationError, "checksum"):
                validator(paths, paths.migration_script, expected_sha256="0" * 64)
            with self.assertRaisesRegex(stalwart_v016.MigrationError, "fixed"):
                validator(
                    paths,
                    paths.migration_root / "other.py",
                    expected_sha256=digest,
                )
            paths.migration_script.chmod(0o644)
            with self.assertRaisesRegex(stalwart_v016.MigrationError, "0600"):
                validator(paths, paths.migration_script, expected_sha256=digest)
            paths.migration_script.unlink()
            outside = repository / "outside.py"
            outside.write_bytes(content)
            paths.migration_script.symlink_to(outside)
            with self.assertRaisesRegex(stalwart_v016.MigrationError, "symlink"):
                validator(paths, paths.migration_script, expected_sha256=digest)


@unittest.skipIf(stalwart_v016 is None, "migration script is not implemented")
class CommandRunnerTest(unittest.TestCase):
    def test_runner_is_list_form_owner_umask_and_redacts_failed_output(self) -> None:
        secret = "unit-only-password"
        completed = subprocess.CompletedProcess(
            ["tool", "--password", secret],
            7,
            stdout=secret,
            stderr=secret,
        )
        runner = getattr(stalwart_v016, "run_command", None)
        self.assertIsNotNone(runner)

        with mock.patch.object(
            stalwart_v016.subprocess,
            "run",
            return_value=completed,
        ) as invoked:
            with self.assertRaises(stalwart_v016.CommandError) as raised:
                runner(["tool", "--password", secret])

        self.assertNotIn(secret, str(raised.exception))
        args, kwargs = invoked.call_args
        self.assertEqual(args, (["tool", "--password", secret],))
        self.assertEqual(kwargs["umask"], 0o077)
        self.assertNotIn("shell", kwargs)
        self.assertTrue(kwargs["capture_output"])
        self.assertTrue(kwargs["text"])
        self.assertGreater(kwargs["timeout"], 0)

    def test_redacted_runner_preserves_binary_stdin_sanitized_env_timeout_and_cwd(
        self,
    ) -> None:
        runner = getattr(stalwart_v016, "run_redacted_command", None)
        self.assertIsNotNone(runner)
        environment = {
            "STALWART_URL": "http://127.0.0.1:8080",
            "STALWART_USER": "unit-user",
            "STALWART_PASSWORD": "unit-secret",
        }
        completed = subprocess.CompletedProcess(
            ["tool"],
            0,
            stdout=b'{"status":"ok"}\n',
            stderr=b"",
        )
        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.object(
                stalwart_v016.subprocess,
                "run",
                return_value=completed,
            ) as invoked,
        ):
            cwd = Path(directory).resolve()
            result = runner(
                ["tool", "apply"],
                stdin=b"exact\x00bytes\n",
                env=environment,
                timeout=17,
                cwd=cwd,
                secret_values=("unit-user", "unit-secret"),
            )

        self.assertEqual(
            result,
            stalwart_v016.RedactedCommandResult(
                b'{"status":"ok"}\n',
                b"",
            ),
        )
        args, kwargs = invoked.call_args
        self.assertEqual(args, (["tool", "apply"],))
        self.assertEqual(kwargs["input"], b"exact\x00bytes\n")
        self.assertEqual(kwargs["env"], environment)
        self.assertEqual(kwargs["timeout"], 17)
        self.assertEqual(kwargs["cwd"], cwd)
        self.assertEqual(kwargs["umask"], 0o077)
        self.assertFalse(kwargs["text"])
        self.assertTrue(kwargs["capture_output"])
        self.assertNotIn("shell", kwargs)

    def test_redacted_runner_rejects_secret_argv_and_unexpected_stalwart_env(
        self,
    ) -> None:
        runner = getattr(stalwart_v016, "run_redacted_command", None)
        self.assertIsNotNone(runner)
        with tempfile.TemporaryDirectory() as directory:
            cwd = Path(directory).resolve()
            cases = (
                (
                    ["tool", "--password=unit-secret"],
                    {"STALWART_PASSWORD": "unit-secret"},
                    (),
                ),
                (
                    ["tool"],
                    {"STALWART_TOKEN": "unit-secret"},
                    (),
                ),
            )
            for args, environment, secret_values in cases:
                with self.subTest(args=args, environment=environment):
                    with (
                        mock.patch.object(
                            stalwart_v016.subprocess,
                            "run",
                        ) as invoked,
                        self.assertRaises(stalwart_v016.CommandError) as raised,
                    ):
                        runner(
                            args,
                            stdin=b"",
                            env=environment,
                            timeout=3,
                            cwd=cwd,
                            secret_values=secret_values,
                        )
                    invoked.assert_not_called()
                    self.assertNotIn("unit-secret", str(raised.exception))
                    self.assertIsNone(raised.exception.__cause__)
                    self.assertIsNone(raised.exception.__context__)

    def test_redacted_runner_hides_failed_stdout_stderr_and_nested_exception(
        self,
    ) -> None:
        completed = subprocess.CompletedProcess(
            ["tool"],
            7,
            stdout=b"unit-secret stdout",
            stderr=b"unit-secret stderr",
        )
        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.object(
                stalwart_v016.subprocess,
                "run",
                return_value=completed,
            ),
            self.assertRaises(stalwart_v016.CommandError) as raised,
        ):
            stalwart_v016.run_redacted_command(
                ["tool"],
                stdin=b"unit-secret stdin",
                env={
                    "STALWART_URL": "http://127.0.0.1:8080",
                    "STALWART_USER": "unit-user",
                    "STALWART_PASSWORD": "unit-secret",
                },
                timeout=3,
                cwd=Path(directory).resolve(),
                secret_values=("unit-user", "unit-secret"),
            )

        self.assertEqual(
            str(raised.exception),
            "redacted external command failed safely",
        )
        self.assertNotIn("unit-secret", str(raised.exception))
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)

    def test_secret_runner_converts_environment_only_in_short_lived_helper(
        self,
    ) -> None:
        credential = bytearray(b"unit-user:unit-secret")
        borrowed = memoryview(credential).toreadonly()
        try:
            result = stalwart_v016.run_redacted_secret_command(
                [
                    sys.executable,
                    "-c",
                    (
                        "import os,sys;"
                        "assert os.environ['STALWART_USER'];"
                        "assert os.environ['STALWART_PASSWORD'];"
                        "sys.stdout.buffer.write(sys.stdin.buffer.read())"
                    ),
                ],
                stdin=b"unit-non-secret-input",
                env={
                    "PATH": stalwart_v016.SAFE_COMMAND_PATH,
                    "STALWART_URL": "http://127.0.0.1:8080",
                },
                credential=borrowed,
                timeout=10,
                cwd=REPOSITORY_ROOT,
            )
        finally:
            borrowed.release()
            stalwart_v016._wipe_bytearray(credential)

        self.assertEqual(
            result,
            stalwart_v016.RedactedCommandResult(
                b"unit-non-secret-input",
                b"",
            ),
        )
        self.assertTrue(all(value == 0 for value in credential))

    def test_task5_receipt_is_verified_by_the_exact_list_form_cli(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory).resolve()
            paths = stalwart_v016.MigrationPaths.for_repository(repository)
            stalwart_v016.ensure_owner_directory(
                paths.migration_root,
                trusted_root=repository,
            )
            paths.source_receipt.write_text("{}\n", encoding="utf-8")
            paths.source_receipt.chmod(0o600)
            capture_script = repository / "scripts" / "capture_stalwart_v015.py"
            capture_script.parent.mkdir(mode=0o700)
            capture_script.write_text("# fixture\n", encoding="utf-8")
            calls: list[list[str]] = []

            def runner(args: list[str]) -> object:
                calls.append(list(args))
                return stalwart_v016.CommandResult("", "")

            verifier = getattr(stalwart_v016, "verify_source_capture", None)
            self.assertIsNotNone(verifier)
            verifier(
                paths,
                paths.source_receipt,
                runner=runner,
                python_executable="/unit/python3",
            )

            self.assertEqual(
                calls,
                [
                    [
                        "/unit/python3",
                        str(capture_script),
                        "verify",
                        "--receipt",
                        str(paths.source_receipt),
                    ],
                ],
            )

    def test_task5_verification_rejects_receipt_replacement_during_verifier(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory).resolve()
            paths = stalwart_v016.MigrationPaths.for_repository(repository)
            stalwart_v016.ensure_owner_directory(
                paths.migration_root,
                trusted_root=repository,
            )
            receipt_bytes = b'{"fixture":"same-content"}\n'
            paths.source_receipt.write_bytes(receipt_bytes)
            paths.source_receipt.chmod(0o600)
            capture_script = repository / "scripts" / "capture_stalwart_v015.py"
            capture_script.parent.mkdir(mode=0o700)
            capture_script.write_text("# fixture\n", encoding="utf-8")

            def replacing_runner(args: list[str]) -> object:
                replacement = paths.migration_root / "replacement.json"
                replacement.write_bytes(receipt_bytes)
                replacement.chmod(0o600)
                os.replace(replacement, paths.source_receipt)
                return stalwart_v016.CommandResult("", "")

            with self.assertRaisesRegex(stalwart_v016.MigrationError, "changed"):
                stalwart_v016.verify_source_capture(
                    paths,
                    paths.source_receipt,
                    runner=replacing_runner,
                    python_executable="/unit/python3",
                )

    def test_dump_and_convert_builders_use_fixed_outputs_and_ordered_path_patches(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            paths = stalwart_v016.MigrationPaths.for_repository(
                Path(directory).resolve(),
            )
            source_type = getattr(stalwart_v016, "IsolatedSource", None)
            dump_builder = getattr(stalwart_v016, "build_dump_command", None)
            convert_builder = getattr(stalwart_v016, "build_convert_command", None)
            self.assertIsNotNone(source_type)
            self.assertIsNotNone(dump_builder)
            self.assertIsNotNone(convert_builder)
            secret = "unit-only-admin-secret"
            source = source_type(
                url="http://127.0.0.1:19443",
                username="admin",
                password=secret,
            )

            dump = dump_builder("/venv/bin/python3", paths, source)
            convert = convert_builder("/venv/bin/python3", paths)

            self.assertEqual(
                dump,
                [
                    "/venv/bin/python3",
                    str(paths.migration_script),
                    "dump",
                    "--url",
                    "http://127.0.0.1:19443",
                    "--username",
                    "admin",
                    "--password",
                    secret,
                    "--settings",
                    str(paths.settings),
                    "--principals",
                    str(paths.principals),
                ],
            )
            self.assertEqual(
                convert,
                [
                    "/venv/bin/python3",
                    str(paths.migration_script),
                    "convert",
                    "--settings",
                    str(paths.settings),
                    "--principals",
                    str(paths.principals),
                    "--config",
                    str(paths.converted_config),
                    "--output",
                    str(paths.export),
                    "--patch-paths",
                    "/opt/stalwart/data=/var/lib/stalwart",
                    "--patch-paths",
                    "/opt/stalwart=/var/lib/stalwart",
                    "--unmigrated-output",
                    str(paths.unmigrated),
                ],
            )
            self.assertNotIn(secret, repr(source))

    def test_dependency_probe_fails_before_any_upstream_script_invocation(self) -> None:
        calls: list[list[str]] = []

        def runner(args: list[str]) -> object:
            calls.append(list(args))
            raise stalwart_v016.CommandError("missing dependencies")

        probe = getattr(stalwart_v016, "check_migration_python", None)
        self.assertIsNotNone(probe)
        with self.assertRaisesRegex(
            stalwart_v016.MigrationError,
            "requests.*urllib3",
        ):
            probe("/venv/bin/python3", runner=runner)

        self.assertEqual(
            calls,
            [["/venv/bin/python3", "-c", "import requests, urllib3"]],
        )
        self.assertTrue(all("migrate_v016.py" not in call for call in calls))

    def test_rollback_endpoint_requires_a_local_v015_runtime_and_redacts_secret(
        self,
    ) -> None:
        endpoint_type = getattr(stalwart_v016, "RollbackEndpoint", None)
        validator = getattr(stalwart_v016, "validate_rollback_endpoint", None)
        self.assertIsNotNone(endpoint_type)
        self.assertIsNotNone(validator)
        secret = "unit-only-rollback-secret"
        endpoint = endpoint_type(
            base_url="http://127.0.0.1:19443",
            username="admin",
            password=secret,
            version="0.15.5",
        )

        self.assertEqual(validator(endpoint), endpoint)
        self.assertNotIn(secret, repr(endpoint))
        invalid = [
            endpoint_type(
                base_url="https://127.0.0.1:19443",
                username="admin",
                password=secret,
                version="0.15.5",
            ),
            endpoint_type(
                base_url="http://127.0.0.1:1024",
                username="admin",
                password=secret,
                version="0.15.5",
            ),
            endpoint_type(
                base_url="http://127.0.0.1:65536",
                username="admin",
                password=secret,
                version="0.15.5",
            ),
            endpoint_type(
                base_url="http://127.0.0.1:19443",
                username="",
                password=secret,
                version="0.15.5",
            ),
            endpoint_type(
                base_url="http://127.0.0.1:19443",
                username="admin",
                password="",
                version="0.15.5",
            ),
            endpoint_type(
                base_url="http://127.0.0.1:19443",
                username="admin",
                password=secret,
                version="0.16.17",
            ),
        ]
        for candidate in invalid:
            with self.subTest(candidate=repr(candidate)):
                with self.assertRaises(stalwart_v016.MigrationError):
                    validator(candidate)

    def test_default_executor_is_lazy_and_rejects_malformed_proof(self) -> None:
        executor = getattr(stalwart_v016, "default_rollback_executor", None)
        loader = getattr(stalwart_v016, "_load_capture_application", None)
        self.assertIsNotNone(executor)
        self.assertIsNotNone(loader)
        receipt = Path("/repo/latest-source.json")
        digest = "a" * 64
        endpoint = SimpleNamespace(
            base_url="http://127.0.0.1:19443",
            username="admin",
            password="unit-only-secret",
            version="0.15.5",
        )

        class FakeApplication:
            def __init__(self, result: object) -> None:
                self.result = result
                self.calls: list[tuple[object, ...]] = []

            def run_verified_rollback(
                self,
                receipt_path: Path,
                *,
                expected_receipt_sha256: str,
                operation: object,
            ) -> object:
                self.calls.append(
                    (receipt_path, expected_receipt_sha256, operation),
                )
                value = operation(endpoint)
                if self.result == "valid":
                    return SimpleNamespace(
                        value=value,
                        proof={
                            "management_status": 200,
                            "proved_at": "20260728T120000Z",
                            "version": "0.15.5",
                        },
                    )
                return self.result

        valid_application = FakeApplication("valid")
        operation_calls: list[object] = []
        with mock.patch.object(
            stalwart_v016,
            "_load_capture_application",
            return_value=valid_application,
        ) as imported:
            self.assertEqual(operation_calls, [])
            result = executor(
                receipt,
                digest,
                lambda value: operation_calls.append(value),
            )
        imported.assert_called_once_with()
        self.assertEqual(operation_calls, [endpoint])
        self.assertEqual(result.proof["management_status"], 200)
        result_with_secret = stalwart_v016.RollbackResult(
            "unit-only-callback-secret",
            {"unexpected": "unit-only-proof-secret"},
        )
        self.assertNotIn("unit-only-callback-secret", repr(result_with_secret))
        self.assertNotIn("unit-only-proof-secret", repr(result_with_secret))
        self.assertEqual(
            valid_application.calls[0][:2],
            (receipt, digest),
        )

        @dataclass(frozen=True)
        class TypedProof:
            management_status: int
            proved_at: str
            version: str

        typed_application = FakeApplication(
            SimpleNamespace(
                value=None,
                proof=TypedProof(
                    management_status=200,
                    proved_at="20260728T120000Z",
                    version="0.15.5",
                ),
            ),
        )
        with mock.patch.object(
            stalwart_v016,
            "_load_capture_application",
            return_value=typed_application,
        ):
            typed_result = executor(receipt, digest, lambda _value: None)
        self.assertEqual(
            typed_result.proof,
            {
                "management_status": 200,
                "proved_at": "20260728T120000Z",
                "version": "0.15.5",
            },
        )

        @dataclass(frozen=True)
        class ExtraTypedProof:
            management_status: int
            proved_at: str
            version: str
            unexpected: str

        malformed_proofs = [
            {"management_status": 500},
            {
                "management_status": 200,
                "proved_at": "2026-07-28T12:00:00Z",
                "version": "0.15.5",
            },
            ExtraTypedProof(
                management_status=200,
                proved_at="20260728T120000Z",
                version="0.15.5",
                unexpected="unit-only-proof-secret",
            ),
        ]
        for proof in malformed_proofs:
            with self.subTest(proof=proof):
                malformed_application = FakeApplication(
                    SimpleNamespace(value=None, proof=proof),
                )
                with mock.patch.object(
                    stalwart_v016,
                    "_load_capture_application",
                    return_value=malformed_application,
                ):
                    with self.assertRaisesRegex(
                        stalwart_v016.MigrationError,
                        "result|proof",
                    ):
                        executor(receipt, digest, lambda _value: None)

    def test_real_capture_loader_types_are_adapter_compatible_without_docker(
        self,
    ) -> None:
        loader = getattr(stalwart_v016, "_load_capture_application", None)
        executor = getattr(stalwart_v016, "default_rollback_executor", None)
        self.assertIsNotNone(loader)
        self.assertIsNotNone(executor)

        external_process = mock.Mock(
            side_effect=AssertionError("integration test invoked an external process"),
        )
        with mock.patch.object(subprocess, "run", external_process):
            application = loader()
        method_globals = type(application).run_verified_rollback.__globals__
        endpoint_type = method_globals["VerifiedRollbackEndpoint"]
        proof_type = method_globals["VerifiedRollbackProof"]
        result_type = method_globals["VerifiedRollbackResult"]
        capture_path = REPOSITORY_ROOT / "scripts" / "capture_stalwart_v015.py"
        self.assertEqual(
            Path(method_globals["__file__"]).resolve(),
            capture_path.resolve(),
        )
        for loaded_type in (endpoint_type, proof_type, result_type):
            self.assertEqual(
                loaded_type.__module__,
                "_mail_sandbox_capture_stalwart_v015",
            )

        endpoint_secret = "unit-only-real-loader-endpoint-secret"
        callback_secret = "unit-only-real-loader-callback-secret"
        endpoint = endpoint_type(
            base_url="http://127.0.0.1:19443",
            username="admin",
            password=endpoint_secret,
            version="0.15.5",
        )
        proof = proof_type(
            management_status=200,
            proved_at="20260728T120000Z",
            version="0.15.5",
        )
        receipt = Path("/repo/latest-source.json")
        digest = "b" * 64
        calls: list[tuple[Path, str, object]] = []
        task5_results: list[object] = []

        def verified_rollback_without_docker(
            receipt_path: Path,
            *,
            expected_receipt_sha256: str,
            operation: object,
        ) -> object:
            calls.append((receipt_path, expected_receipt_sha256, operation))
            value = operation(endpoint)
            result = result_type(value=value, proof=proof)
            task5_results.append(result)
            return result

        observed_endpoints: list[object] = []

        def operation(value: object) -> str:
            observed_endpoints.append(
                stalwart_v016.validate_rollback_endpoint(value),
            )
            return callback_secret

        with (
            mock.patch.object(
                application,
                "run_verified_rollback",
                side_effect=verified_rollback_without_docker,
            ) as rollback,
            mock.patch.object(
                stalwart_v016,
                "_load_capture_application",
                return_value=application,
            ) as loaded,
            mock.patch.object(subprocess, "run", external_process),
        ):
            result = executor(receipt, digest, operation)

        loaded.assert_called_once_with()
        rollback.assert_called_once()
        external_process.assert_not_called()
        self.assertEqual(calls, [(receipt, digest, operation)])
        self.assertEqual(len(observed_endpoints), 1)
        self.assertIsInstance(observed_endpoints[0], stalwart_v016.RollbackEndpoint)
        self.assertEqual(result.value, callback_secret)
        self.assertEqual(
            result.proof,
            {
                "management_status": 200,
                "proved_at": "20260728T120000Z",
                "version": "0.15.5",
            },
        )
        self.assertNotIn(endpoint_secret, repr(endpoint))
        self.assertNotIn(callback_secret, repr(task5_results[0]))
        self.assertNotIn(callback_secret, repr(result))

    def test_apply_ndjson_requires_ok_operations_and_one_zero_failure_summary(
        self,
    ) -> None:
        parser = getattr(stalwart_v016, "validate_apply_ndjson", None)
        self.assertIsNotNone(parser)
        expected = (
            stalwart_v016.ApplyOperation("create", "principal/one", 2),
            stalwart_v016.ApplyOperation("update", "domain/one.example"),
        )
        valid_records = [
            {
                "op": "create",
                "object": "principal/one",
                "index": 0,
                "count": 2,
                "status": "ok",
            },
            {
                "op": "update",
                "object": "domain/one.example",
                "index": 1,
                "count": 1,
                "status": "ok",
            },
            {
                "op": "summary",
                "plan": {
                    "destroys": 0,
                    "updates": 1,
                    "creates": 1,
                    "create_objects": 2,
                    "upserts": 0,
                    "upsert_objects": 0,
                },
                "done": {
                    "destroyed": 0,
                    "updated": 1,
                    "created": 2,
                    "failed": 0,
                },
            },
        ]

        def encode(records: list[dict[str, object]]) -> str:
            return "\n".join(json.dumps(record) for record in records)

        def clone() -> list[dict[str, object]]:
            return json.loads(json.dumps(valid_records))

        valid = encode(valid_records)
        summary = parser(valid, expected_operations=expected)
        self.assertEqual(summary["done"]["failed"], 0)

        mutations: tuple[tuple[str, object], ...] = (
            ("wrong-status", lambda value: value[0].__setitem__("status", "failed")),
            ("wrong-op", lambda value: value[0].__setitem__("op", "update")),
            ("wrong-object", lambda value: value[0].__setitem__("object", "other")),
            ("wrong-index", lambda value: value[0].__setitem__("index", 1)),
            ("bool-index", lambda value: value[0].__setitem__("index", False)),
            ("negative-index", lambda value: value[0].__setitem__("index", -1)),
            ("wrong-count", lambda value: value[0].__setitem__("count", 1)),
            ("bool-count", lambda value: value[1].__setitem__("count", True)),
            ("negative-count", lambda value: value[1].__setitem__("count", -1)),
            (
                "extra-operation-key",
                lambda value: value[0].__setitem__("provider_id", "extra"),
            ),
            ("missing-operation-key", lambda value: value[0].pop("status")),
            (
                "wrong-plan",
                lambda value: value[2]["plan"].__setitem__("create_objects", 1),
            ),
            (
                "bool-plan",
                lambda value: value[2]["plan"].__setitem__("updates", True),
            ),
            (
                "negative-plan",
                lambda value: value[2]["plan"].__setitem__("destroys", -1),
            ),
            (
                "extra-plan-key",
                lambda value: value[2]["plan"].__setitem__("extra", 0),
            ),
            ("missing-plan-key", lambda value: value[2]["plan"].pop("upserts")),
            (
                "wrong-done",
                lambda value: value[2]["done"].__setitem__("created", 1),
            ),
            (
                "bool-done",
                lambda value: value[2]["done"].__setitem__("updated", True),
            ),
            (
                "negative-done",
                lambda value: value[2]["done"].__setitem__("destroyed", -1),
            ),
            (
                "failed",
                lambda value: value[2]["done"].__setitem__("failed", 1),
            ),
            ("extra-summary-key", lambda value: value[2].__setitem__("extra", 0)),
            ("missing-summary-key", lambda value: value[2].pop("done")),
            ("wrong-order", lambda value: value.__setitem__(slice(0, 2), value[1::-1])),
            ("missing-summary", lambda value: value.pop()),
            ("duplicate-summary", lambda value: value.append(dict(value[2]))),
        )
        for label, mutation in mutations:
            candidate = clone()
            mutation(candidate)
            with self.subTest(label=label):
                with self.assertRaises(stalwart_v016.MigrationError):
                    parser(encode(candidate), expected_operations=expected)

        with self.assertRaises(stalwart_v016.MigrationError):
            parser(valid + "\n\n", expected_operations=expected)

    def test_apply_plan_counts_create_objects_rejects_empty_maps_and_binds_digest(
        self,
    ) -> None:
        parser = getattr(stalwart_v016, "_parse_apply_operations", None)
        self.assertIsNotNone(parser)

        def snapshot(records: list[dict[str, object]]) -> object:
            content = (
                "\n".join(json.dumps(record) for record in records) + "\n"
            ).encode("utf-8")
            return stalwart_v016.FileSnapshot(
                path=Path("/unit/export.json"),
                content=content,
                sha256=hashlib.sha256(content).hexdigest(),
                size=len(content),
                identity=(1, 2, stat.S_IFREG | 0o600, len(content), 3, 4),
            )

        records = [
            {
                "@type": "create",
                "object": "principal",
                "value": {
                    "alice": {"name": "alice"},
                    "bob": {"name": "bob"},
                },
            },
            {
                "@type": "update",
                "object": "settings",
                "value": {"storage": "rocksdb"},
            },
        ]
        operations = parser(snapshot(records))

        self.assertTrue(all(hasattr(operation, "count") for operation in operations))
        self.assertEqual(
            operations,
            (
                stalwart_v016.ApplyOperation("create", "principal", 2),
                stalwart_v016.ApplyOperation("update", "settings", 1),
            ),
        )
        self.assertNotEqual(
            stalwart_v016.apply_operation_plan_sha256(operations),
            stalwart_v016.apply_operation_plan_sha256(
                (
                    stalwart_v016.ApplyOperation("create", "principal", 1),
                    stalwart_v016.ApplyOperation("update", "settings", 1),
                ),
            ),
        )

        empty_create = [
            {
                "@type": "create",
                "object": "principal",
                "value": {},
            },
        ]
        with self.assertRaises(stalwart_v016.MigrationError):
            parser(snapshot(empty_create))
        for invalid_count in (True, 0, -1, 1.0):
            with self.subTest(invalid_count=invalid_count):
                with self.assertRaises(stalwart_v016.MigrationError):
                    stalwart_v016.apply_operation_plan_sha256(
                        (
                            stalwart_v016.ApplyOperation(
                                "create",
                                "principal",
                                invalid_count,
                            ),
                        ),
                    )

    def test_update_operation_rejects_multi_object_count_in_digest_and_evidence(
        self,
    ) -> None:
        invalid_update = stalwart_v016.ApplyOperation("update", "settings", 2)
        evidence = "\n".join(
            (
                json.dumps(
                    {
                        "op": "update",
                        "object": "settings",
                        "index": 0,
                        "count": 2,
                        "status": "ok",
                    },
                ),
                json.dumps(
                    {
                        "op": "summary",
                        "plan": {
                            "destroys": 0,
                            "updates": 1,
                            "creates": 0,
                            "create_objects": 0,
                            "upserts": 0,
                            "upsert_objects": 0,
                        },
                        "done": {
                            "destroyed": 0,
                            "updated": 1,
                            "created": 0,
                            "failed": 0,
                        },
                    },
                ),
            ),
        )

        with self.subTest(contract="digest"):
            with self.assertRaises(stalwart_v016.MigrationError):
                stalwart_v016.apply_operation_plan_sha256((invalid_update,))
        with self.subTest(contract="evidence"):
            with self.assertRaises(stalwart_v016.MigrationError):
                stalwart_v016.validate_apply_ndjson(
                    evidence,
                    expected_operations=(invalid_update,),
                )

    def test_stale_task5_receipt_hard_stops_before_migration_invocation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory).resolve()
            paths = stalwart_v016.MigrationPaths.for_repository(repository)
            stalwart_v016.ensure_owner_directory(
                paths.migration_root,
                trusted_root=repository,
            )
            paths.source_receipt.write_text("{}\n", encoding="utf-8")
            paths.source_receipt.chmod(0o600)
            script_content = b"migration fixture\n"
            paths.migration_script.write_bytes(script_content)
            paths.migration_script.chmod(0o600)
            capture_script = repository / "scripts" / "capture_stalwart_v015.py"
            capture_script.parent.mkdir(mode=0o700)
            capture_script.write_text("# fixture\n", encoding="utf-8")
            calls: list[list[str]] = []

            def runner(args: list[str]) -> object:
                calls.append(list(args))
                raise stalwart_v016.CommandError("stale receipt")

            prepare = getattr(stalwart_v016, "prepare_dry_run", None)
            self.assertIsNotNone(prepare)
            with self.assertRaises(stalwart_v016.CommandError):
                prepare(
                    paths,
                    script_path=paths.migration_script,
                    receipt_path=paths.source_receipt,
                    runner=runner,
                    python_executable="/unit/python3",
                    migration_python="/venv/bin/python3",
                    expected_script_sha256=hashlib.sha256(script_content).hexdigest(),
                )

            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0][2:4], ["verify", "--receipt"])
            self.assertTrue(all("migrate_v016.py" not in call for call in calls))


@unittest.skipIf(stalwart_v016 is None, "migration script is not implemented")
class DryRunExecutionTest(unittest.TestCase):
    def _verified_receipt(
        self,
        paths: object,
    ) -> tuple[object, str]:
        content = paths.source_receipt.read_bytes()
        digest = hashlib.sha256(content).hexdigest()
        snapshot = stalwart_v016.FileSnapshot(
            path=paths.source_receipt,
            content=content,
            sha256=digest,
            size=len(content),
            identity=(1, 2, stat.S_IFREG | 0o600, len(content), 3, 4),
        )
        return stalwart_v016.VerifiedReceipt(snapshot), digest

    def _call_prepare(
        self,
        paths: object,
        *,
        runner: object,
        rollback_executor: object,
        timestamp: str = "2026-07-28T12:00:00Z",
    ) -> Path:
        verified_receipt, _receipt_digest = self._verified_receipt(paths)
        source = verified_source_fixture(
            paths.repository_root,
            paths.repository_root / "stalwart-data",
        )
        script_digest = hashlib.sha256(b"migration script\n").hexdigest()
        with (
            mock.patch.object(
                stalwart_v016,
                "verify_source_capture",
                return_value=verified_receipt,
            ),
            mock.patch.object(
                stalwart_v016,
                "load_verified_source",
                return_value=source,
            ),
            mock.patch.object(
                stalwart_v016,
                "assert_no_running_store_writers",
            ),
            mock.patch.object(
                stalwart_v016,
                "validate_migration_script",
                return_value=script_digest,
            ),
            mock.patch.object(
                stalwart_v016,
                "check_migration_python",
            ),
        ):
            return stalwart_v016.prepare_dry_run(
                paths,
                script_path=paths.migration_script,
                receipt_path=paths.source_receipt,
                runner=runner,
                python_executable="/unit/python3",
                migration_python="/venv/bin/python3",
                rollback_executor=rollback_executor,
                clock=lambda: timestamp,
            )

    @staticmethod
    def _write_dump_outputs(paths: object) -> None:
        paths.settings.write_text(
            json.dumps({"unit-secret": "must-not-enter-receipt"}),
            encoding="utf-8",
        )
        paths.principals.write_text("[]\n", encoding="utf-8")
        paths.settings.chmod(0o600)
        paths.principals.chmod(0o600)

    @staticmethod
    def _write_convert_outputs(paths: object, *, unmigrated: bool = False) -> None:
        paths.converted_config.write_bytes(AUDITED_CONVERTED_CONFIG_BYTES)
        paths.export.write_text(
            json.dumps(
                {
                    "@type": "update",
                    "object": "SystemSettings",
                    "value": {"hostname": "localhost"},
                },
            )
            + "\n",
            encoding="utf-8",
        )
        paths.converted_config.chmod(0o600)
        paths.export.chmod(0o600)
        if unmigrated:
            paths.unmigrated.write_text("review me\n", encoding="utf-8")
            paths.unmigrated.chmod(0o600)

    @staticmethod
    def _valid_execution(value: object = None) -> object:
        return SimpleNamespace(
            value=value,
            proof={
                "management_status": 200,
                "proved_at": "20260728T120000Z",
                "version": "0.15.5",
            },
        )

    def test_dump_runs_inside_executor_and_convert_waits_for_cleanup_return(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory).resolve()
            paths = stalwart_v016.MigrationPaths.for_repository(repository)
            stalwart_v016.ensure_owner_directory(
                paths.migration_root,
                trusted_root=repository,
            )
            paths.source_receipt.write_text("{}\n", encoding="utf-8")
            paths.source_receipt.chmod(0o600)
            paths.migration_script.write_text("migration script\n", encoding="utf-8")
            paths.migration_script.chmod(0o600)
            events: list[str] = []
            forwarded: list[tuple[Path, str]] = []

            def runner(args: list[str]) -> object:
                if "dump" in args:
                    events.append("dump")
                    self._write_dump_outputs(paths)
                elif "convert" in args:
                    events.append("convert")
                    self._write_convert_outputs(paths)
                else:
                    self.fail(f"unexpected command: {args!r}")
                return stalwart_v016.CommandResult("", "")

            def executor(
                receipt_path: Path,
                expected_digest: str,
                operation: object,
            ) -> object:
                forwarded.append((receipt_path, expected_digest))
                events.append("executor-enter")
                value = operation(
                    SimpleNamespace(
                        base_url="http://127.0.0.1:19443",
                        username="admin",
                        password="unit-only-admin-secret",
                        version="0.15.5",
                    ),
                )
                events.append("executor-cleanup-return")
                return self._valid_execution(value)

            receipt = self._call_prepare(
                paths,
                runner=runner,
                rollback_executor=executor,
            )
            _verified, receipt_digest = self._verified_receipt(paths)

            self.assertEqual(
                events,
                ["executor-enter", "dump", "executor-cleanup-return", "convert"],
            )
            self.assertEqual(
                forwarded,
                [(paths.source_receipt, receipt_digest)],
            )
            self.assertEqual(receipt, paths.dry_run_receipt)

    def test_missing_unmigrated_is_created_0600_and_receipt_detects_mutation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory).resolve()
            paths = stalwart_v016.MigrationPaths.for_repository(repository)
            stalwart_v016.ensure_owner_directory(
                paths.migration_root,
                trusted_root=repository,
            )
            paths.source_receipt.write_text("{}\n", encoding="utf-8")
            paths.source_receipt.chmod(0o600)
            paths.migration_script.write_text("migration script\n", encoding="utf-8")
            paths.migration_script.chmod(0o600)

            def runner(args: list[str]) -> object:
                if "dump" in args:
                    self._write_dump_outputs(paths)
                elif "convert" in args:
                    self._write_convert_outputs(paths)
                else:
                    self.fail(f"unexpected command: {args!r}")
                return stalwart_v016.CommandResult("", "")

            def executor(
                _receipt_path: Path,
                _expected_digest: str,
                operation: object,
            ) -> object:
                value = operation(
                    SimpleNamespace(
                        base_url="http://127.0.0.1:19443",
                        username="admin",
                        password="unit-only-admin-secret",
                        version="v0.15.5",
                    ),
                )
                return self._valid_execution(value)

            receipt_path = self._call_prepare(
                paths,
                runner=runner,
                rollback_executor=executor,
            )

            self.assertEqual(paths.unmigrated.read_bytes(), b"")
            self.assertEqual(stat.S_IMODE(paths.unmigrated.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(receipt_path.stat().st_mode), 0o600)
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            self.assertEqual(
                set(receipt),
                {
                    "schema",
                    "created_at",
                    "source_receipt_sha256",
                    "migration_script_sha256",
                    "rollback",
                    "outputs",
                },
            )
            self.assertEqual(
                receipt["schema"],
                "mail-sandbox.stalwart-v016-dry-run.v1",
            )
            self.assertEqual(receipt["created_at"], "2026-07-28T12:00:00Z")
            self.assertEqual(
                receipt["rollback"],
                {
                    "management_status": 200,
                    "proved_at": "20260728T120000Z",
                    "version": "0.15.5",
                },
            )
            self.assertEqual(
                [entry["name"] for entry in receipt["outputs"]],
                [
                    "settings.json",
                    "principals.json",
                    "config.json",
                    "export.json",
                    "unmigrated.txt",
                ],
            )
            self.assertEqual(
                set(receipt["outputs"][0]),
                {"name", "sha256", "size"},
            )
            self.assertNotIn(
                "must-not-enter-receipt",
                json.dumps(receipt),
            )
            stalwart_v016.validate_dry_run_receipt(paths, receipt_path)

            invalid_proof = dict(receipt)
            invalid_proof["rollback"] = dict(receipt["rollback"])
            invalid_proof["rollback"]["proved_at"] = "not-task5-utc"
            receipt_path.write_text(
                json.dumps(invalid_proof) + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                stalwart_v016.MigrationError,
                "rollback|proof|malformed",
            ):
                stalwart_v016.validate_dry_run_receipt(paths, receipt_path)
            receipt_path.write_text(json.dumps(receipt) + "\n", encoding="utf-8")

            paths.settings.write_text('{"changed":true}\n', encoding="utf-8")
            with self.assertRaisesRegex(
                stalwart_v016.MigrationError,
                "match|digest",
            ):
                stalwart_v016.validate_dry_run_receipt(paths, receipt_path)

    def test_dump_or_executor_cleanup_failure_prevents_convert(self) -> None:
        for failure in ("dump", "executor", "cleanup"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                repository = Path(directory).resolve()
                paths = stalwart_v016.MigrationPaths.for_repository(repository)
                stalwart_v016.ensure_owner_directory(
                    paths.migration_root,
                    trusted_root=repository,
                )
                paths.source_receipt.write_text("{}\n", encoding="utf-8")
                paths.source_receipt.chmod(0o600)
                paths.migration_script.write_text(
                    "migration script\n",
                    encoding="utf-8",
                )
                paths.migration_script.chmod(0o600)
                calls: list[str] = []

                def runner(args: list[str]) -> object:
                    if "dump" in args:
                        calls.append("dump")
                        if failure == "dump":
                            raise stalwart_v016.CommandError("dump failed safely")
                        self._write_dump_outputs(paths)
                    elif "convert" in args:
                        calls.append("convert")
                        self._write_convert_outputs(paths)
                    return stalwart_v016.CommandResult("", "")

                def executor(
                    _receipt_path: Path,
                    _expected_digest: str,
                    operation: object,
                ) -> object:
                    if failure == "executor":
                        raise RuntimeError("executor failure")
                    value = operation(
                        SimpleNamespace(
                            base_url="http://127.0.0.1:19443",
                            username="admin",
                            password="unit-only-admin-secret",
                            version="0.15.5",
                        ),
                    )
                    if failure == "cleanup":
                        raise RuntimeError("cleanup failure")
                    return self._valid_execution(value)

                with self.assertRaises(stalwart_v016.MigrationError):
                    self._call_prepare(
                        paths,
                        runner=runner,
                        rollback_executor=executor,
                    )
                self.assertNotIn("convert", calls)
                self.assertFalse(
                    (paths.migration_root / "dry-run.json").exists(),
                )

    def test_convert_failure_prevents_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory).resolve()
            paths = stalwart_v016.MigrationPaths.for_repository(repository)
            stalwart_v016.ensure_owner_directory(
                paths.migration_root,
                trusted_root=repository,
            )
            paths.source_receipt.write_text("{}\n", encoding="utf-8")
            paths.source_receipt.chmod(0o600)
            paths.migration_script.write_text("migration script\n", encoding="utf-8")
            paths.migration_script.chmod(0o600)
            calls: list[str] = []

            def runner(args: list[str]) -> object:
                if "dump" in args:
                    calls.append("dump")
                    self._write_dump_outputs(paths)
                elif "convert" in args:
                    calls.append("convert")
                    raise stalwart_v016.CommandError("convert failed safely")
                return stalwart_v016.CommandResult("", "")

            def executor(
                _receipt_path: Path,
                _expected_digest: str,
                operation: object,
            ) -> object:
                value = operation(
                    SimpleNamespace(
                        base_url="http://127.0.0.1:19443",
                        username="admin",
                        password="unit-only-admin-secret",
                        version="0.15.5",
                    ),
                )
                return self._valid_execution(value)

            with self.assertRaises(stalwart_v016.CommandError):
                self._call_prepare(
                    paths,
                    runner=runner,
                    rollback_executor=executor,
                )
            self.assertEqual(calls, ["dump", "convert"])
            self.assertFalse(paths.dry_run_receipt.exists())

    def test_dump_artifacts_must_be_regular_0600_before_convert(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory).resolve()
            paths = stalwart_v016.MigrationPaths.for_repository(repository)
            stalwart_v016.ensure_owner_directory(
                paths.migration_root,
                trusted_root=repository,
            )
            paths.source_receipt.write_text("{}\n", encoding="utf-8")
            paths.source_receipt.chmod(0o600)
            paths.migration_script.write_text("migration script\n", encoding="utf-8")
            paths.migration_script.chmod(0o600)
            calls: list[str] = []

            def runner(args: list[str]) -> object:
                if "dump" in args:
                    calls.append("dump")
                    self._write_dump_outputs(paths)
                    paths.settings.chmod(0o644)
                elif "convert" in args:
                    calls.append("convert")
                    self._write_convert_outputs(paths)
                return stalwart_v016.CommandResult("", "")

            def executor(
                _receipt_path: Path,
                _expected_digest: str,
                operation: object,
            ) -> object:
                value = operation(
                    SimpleNamespace(
                        base_url="http://127.0.0.1:19443",
                        username="admin",
                        password="unit-only-admin-secret",
                        version="0.15.5",
                    ),
                )
                return self._valid_execution(value)

            with self.assertRaisesRegex(stalwart_v016.MigrationError, "0600"):
                self._call_prepare(
                    paths,
                    runner=runner,
                    rollback_executor=executor,
                )
            self.assertEqual(calls, ["dump"])

    def test_missing_unmigrated_refuses_a_symlink_without_overwriting(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory).resolve()
            paths = stalwart_v016.MigrationPaths.for_repository(repository)
            stalwart_v016.ensure_owner_directory(
                paths.migration_root,
                trusted_root=repository,
            )
            paths.source_receipt.write_text("{}\n", encoding="utf-8")
            paths.source_receipt.chmod(0o600)
            paths.migration_script.write_text("migration script\n", encoding="utf-8")
            paths.migration_script.chmod(0o600)
            outside = repository / "outside.txt"
            outside.write_text("preserve me\n", encoding="utf-8")
            outside.chmod(0o600)

            def runner(args: list[str]) -> object:
                if "dump" in args:
                    self._write_dump_outputs(paths)
                elif "convert" in args:
                    self._write_convert_outputs(paths)
                    paths.unmigrated.symlink_to(outside)
                return stalwart_v016.CommandResult("", "")

            def executor(
                _receipt_path: Path,
                _expected_digest: str,
                operation: object,
            ) -> object:
                value = operation(
                    SimpleNamespace(
                        base_url="http://127.0.0.1:19443",
                        username="admin",
                        password="unit-only-admin-secret",
                        version="0.15.5",
                    ),
                )
                return self._valid_execution(value)

            with self.assertRaisesRegex(stalwart_v016.MigrationError, "symlink"):
                self._call_prepare(
                    paths,
                    runner=runner,
                    rollback_executor=executor,
                )
            self.assertEqual(outside.read_text(encoding="utf-8"), "preserve me\n")
            self.assertFalse(paths.dry_run_receipt.exists())


@unittest.skipIf(stalwart_v016 is None, "migration script is not implemented")
class StoreWriterCensusTest(unittest.TestCase):
    def test_receipt_envelope_rejects_payload_tampering(self) -> None:
        envelope = receipt_envelope({"schema": "fixture", "value": 1})
        envelope["payload"]["value"] = 2

        with self.assertRaisesRegex(stalwart_v016.MigrationError, "digest"):
            stalwart_v016.validate_digest_envelope(envelope)

    def test_verified_receipt_resolves_the_primary_checkout_provider_store(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory).resolve()
            primary = workspace / "primary"
            worktree = primary / ".worktrees" / "feature"
            primary.mkdir(mode=0o700)
            (primary / ".git").mkdir(mode=0o700)
            base_compose = primary / "docker-compose.yml"
            base_compose.write_text("services: {}\n", encoding="utf-8")
            worktree.mkdir(mode=0o700, parents=True)
            (worktree / ".git").write_text("gitdir: fixture\n", encoding="utf-8")
            source_store = primary / "stalwart-data"
            source_store.mkdir(mode=0o700)
            paths = stalwart_v016.MigrationPaths.for_repository(worktree)
            stalwart_v016.ensure_owner_directory(
                paths.migration_root,
                trusted_root=worktree,
            )
            payload = {
                "source": {
                    "compose_config_files": [str(base_compose)],
                    "compose_project": "mail-sandbox",
                    "compose_service": "stalwart",
                    "compose_working_directory": str(primary),
                    "data_path": str(source_store),
                },
            }
            paths.source_receipt.write_text(
                json.dumps(receipt_envelope(payload)) + "\n",
                encoding="utf-8",
            )
            paths.source_receipt.chmod(0o600)
            capture_script = worktree / "scripts" / "capture_stalwart_v015.py"
            capture_script.parent.mkdir(mode=0o700)
            capture_script.write_text("# fixture\n", encoding="utf-8")
            calls: list[list[str]] = []

            def runner(args: list[str]) -> object:
                calls.append(list(args))
                if args[0] == "/unit/python3":
                    return stalwart_v016.CommandResult("", "")
                if args[:2] == ["git", "-C"]:
                    return stalwart_v016.CommandResult(str(primary / ".git") + "\n", "")
                self.fail(f"unexpected command: {args!r}")

            loader = getattr(stalwart_v016, "load_verified_source", None)
            self.assertIsNotNone(loader)
            verified_receipt = stalwart_v016.verify_source_capture(
                paths,
                paths.source_receipt,
                runner=runner,
                python_executable="/unit/python3",
            )
            source = loader(paths, verified_receipt, runner=runner)

            self.assertEqual(source.checkout_root, primary)
            self.assertEqual(source.provider_store, source_store)
            self.assertEqual(source.base_compose, base_compose)
            self.assertEqual(source.compose_project, "mail-sandbox")
            self.assertEqual(source.compose_service, "stalwart")
            self.assertEqual(repr(source), "VerifiedSource(<redacted>)")
            self.assertEqual(
                calls,
                [
                    [
                        "/unit/python3",
                        str(capture_script),
                        "verify",
                        "--receipt",
                        str(paths.source_receipt),
                    ],
                    [
                        "git",
                        "-C",
                        str(primary),
                        "rev-parse",
                        "--path-format=absolute",
                        "--git-common-dir",
                    ],
                    [
                        "git",
                        "-C",
                        str(worktree),
                        "rev-parse",
                        "--path-format=absolute",
                        "--git-common-dir",
                    ],
                ],
            )

    def test_verified_receipt_rejects_missing_or_unsafe_compose_identity(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory).resolve()
            (repository / ".git").mkdir(mode=0o700)
            store = repository / "stalwart-data"
            store.mkdir(mode=0o700)
            base_compose = repository / "docker-compose.yml"
            base_compose.write_text("services: {}\n", encoding="utf-8")
            paths = stalwart_v016.MigrationPaths.for_repository(repository)
            base_source: dict[str, object] = {
                "compose_config_files": [str(base_compose)],
                "compose_project": "mail-sandbox",
                "compose_service": "stalwart",
                "compose_working_directory": str(repository),
                "data_path": str(store),
            }

            def verified(source: dict[str, object]) -> object:
                content = (
                    json.dumps(receipt_envelope({"source": source})) + "\n"
                ).encode("utf-8")
                return stalwart_v016.VerifiedReceipt(
                    stalwart_v016.FileSnapshot(
                        path=paths.source_receipt,
                        content=content,
                        sha256=hashlib.sha256(content).hexdigest(),
                        size=len(content),
                        identity=(
                            1,
                            2,
                            stat.S_IFREG | 0o600,
                            len(content),
                            3,
                            4,
                        ),
                    ),
                )

            def runner(_args: list[str]) -> object:
                return stalwart_v016.CommandResult(
                    str(repository / ".git") + "\n",
                    "",
                )

            cases: dict[str, dict[str, object]] = {}
            for name in (
                "compose_config_files",
                "compose_project",
                "compose_service",
            ):
                candidate = dict(base_source)
                candidate.pop(name)
                cases[f"missing-{name}"] = candidate
            cases["unsafe-project"] = {
                **base_source,
                "compose_project": "../mail",
            }
            cases["unsafe-service"] = {
                **base_source,
                "compose_service": "mail/service",
            }
            cases["wrong-base-compose"] = {
                **base_source,
                "compose_config_files": [str(repository / "compose.yml")],
            }
            cases["multiple-compose-files"] = {
                **base_source,
                "compose_config_files": [
                    str(base_compose),
                    str(repository / "other.yml"),
                ],
            }
            for case, source in cases.items():
                with self.subTest(case=case):
                    with self.assertRaisesRegex(
                        stalwart_v016.MigrationError,
                        "incomplete|Compose",
                    ):
                        stalwart_v016.load_verified_source(
                            paths,
                            verified(source),
                            runner=runner,
                        )

    def test_worktree_census_protects_the_primary_receipt_store(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory).resolve()
            primary = workspace / "primary"
            worktree = primary / ".worktrees" / "feature"
            worktree.mkdir(mode=0o700, parents=True)
            source_store = primary / "stalwart-data"
            source_store.mkdir(mode=0o700)
            paths = stalwart_v016.MigrationPaths.for_repository(worktree)
            container_id = "d" * 64

            def runner(args: list[str]) -> object:
                if args[:2] == ["docker", "ps"]:
                    return stalwart_v016.CommandResult(container_id + "\n", "")
                return stalwart_v016.CommandResult(
                    json.dumps(
                        [
                            {
                                "Id": container_id,
                                "State": {"Running": True},
                                "Mounts": [
                                    {
                                        "Type": "bind",
                                        "Source": str(source_store),
                                        "RW": True,
                                    },
                                ],
                            },
                        ],
                    ),
                    "",
                )

            census = stalwart_v016.assert_no_running_store_writers
            self.assertIn("source_store", inspect.signature(census).parameters)
            with self.assertRaisesRegex(
                stalwart_v016.MigrationError,
                "running writer",
            ):
                census(paths, source_store=source_store, runner=runner)

    def test_safe_census_uses_list_form_ps_and_inspects_every_running_container(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            paths = stalwart_v016.MigrationPaths.for_repository(
                Path(directory).resolve(),
            )
            first = "a" * 64
            second = "b" * 64
            calls: list[list[str]] = []

            def runner(args: list[str]) -> object:
                calls.append(list(args))
                if args[:2] == ["docker", "ps"]:
                    return stalwart_v016.CommandResult(f"{first}\n{second}\n", "")
                if args[:2] == ["docker", "inspect"]:
                    return stalwart_v016.CommandResult(
                        json.dumps(
                            [
                                {"Id": first, "State": {"Running": True}, "Mounts": []},
                                {"Id": second, "State": {"Running": True}, "Mounts": []},
                            ],
                        ),
                        "",
                    )
                self.fail(f"unexpected command: {args!r}")

            census = getattr(
                stalwart_v016,
                "assert_no_running_store_writers",
                None,
            )
            self.assertIsNotNone(census)
            source_store = paths.repository_root / "stalwart-data"
            census(paths, source_store=source_store, runner=runner)

            self.assertEqual(
                calls,
                [
                    [
                        "docker",
                        "ps",
                        "--no-trunc",
                        "--filter",
                        "status=running",
                        "--format",
                        "{{.ID}}",
                    ],
                    ["docker", "inspect", first, second],
                ],
            )

    def test_census_refuses_a_running_writer_on_either_fixed_store(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            paths = stalwart_v016.MigrationPaths.for_repository(
                Path(directory).resolve(),
            )
            source_store = paths.repository_root / "stalwart-data"
            container_id = "c" * 64
            for store in (source_store, paths.scratch_store):
                with self.subTest(store=store):
                    def runner(args: list[str]) -> object:
                        if args[:2] == ["docker", "ps"]:
                            return stalwart_v016.CommandResult(container_id + "\n", "")
                        return stalwart_v016.CommandResult(
                            json.dumps(
                                [
                                    {
                                        "Id": container_id,
                                        "State": {"Running": True},
                                        "Mounts": [
                                            {
                                                "Type": "bind",
                                                "Source": str(store),
                                                "RW": True,
                                            },
                                        ],
                                    },
                                ],
                            ),
                            "",
                        )

                    with self.assertRaisesRegex(
                        stalwart_v016.MigrationError,
                        "running writer",
                    ):
                        stalwart_v016.assert_no_running_store_writers(
                            paths,
                            source_store=source_store,
                            runner=runner,
                        )

    def test_census_fails_closed_on_malformed_or_ambiguous_docker_results(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            paths = stalwart_v016.MigrationPaths.for_repository(
                Path(directory).resolve(),
            )
            source_store = paths.repository_root / "stalwart-data"
            container_id = "e" * 64
            scenarios = [
                (container_id + "\n" + container_id + "\n", "[]"),
                (container_id + "\n", "not-json"),
                (
                    container_id + "\n",
                    json.dumps([{"Id": container_id, "Mounts": []}]),
                ),
                (
                    container_id + "\n",
                    json.dumps(
                        [
                            {
                                "Id": container_id,
                                "State": {"Running": True},
                                "Mounts": [
                                    {
                                        "Type": "bind",
                                        "Source": str(source_store),
                                    },
                                ],
                            },
                        ],
                    ),
                ),
            ]
            for ps_stdout, inspect_stdout in scenarios:
                with self.subTest(inspect=inspect_stdout):
                    def runner(args: list[str]) -> object:
                        output = (
                            ps_stdout
                            if args[:2] == ["docker", "ps"]
                            else inspect_stdout
                        )
                        return stalwart_v016.CommandResult(output, "")

                    with self.assertRaisesRegex(
                        stalwart_v016.MigrationError,
                        "malformed|ambiguous",
                    ):
                        stalwart_v016.assert_no_running_store_writers(
                            paths,
                            source_store=source_store,
                            runner=runner,
                        )


@unittest.skipIf(stalwart_v016 is None, "migration script is not implemented")
class ExportInventoryTest(unittest.TestCase):
    def test_safe_inventory_contains_only_repository_relative_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory).resolve()
            paths = stalwart_v016.MigrationPaths.for_repository(repository)
            evidence = repository / "evidence" / "summary.txt"
            evidence.parent.mkdir(mode=0o700)
            evidence.write_bytes(b"safe\n")
            evidence.chmod(0o600)
            validator = getattr(stalwart_v016, "validate_export_inventory", None)
            self.assertIsNotNone(validator)

            inventory = validator(paths, [evidence])

            self.assertEqual(
                inventory,
                (
                    {
                        "path": "evidence/summary.txt",
                        "sha256": hashlib.sha256(b"safe\n").hexdigest(),
                        "size": 5,
                    },
                ),
            )
            self.assertNotIn("safe", json.dumps(inventory))

    def test_inventory_metadata_and_scan_use_one_validated_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory).resolve()
            paths = stalwart_v016.MigrationPaths.for_repository(repository)
            evidence = repository / "evidence" / "summary.txt"
            evidence.parent.mkdir(mode=0o700)
            original = b"safe snapshot\n"
            evidence.write_bytes(original)
            evidence.chmod(0o600)
            replacement = evidence.with_name("replacement.tmp")
            replacement.write_bytes(b"ADMIN_SECRET=concurrent-replacement\n")
            replacement.chmod(0o600)
            read_snapshot = stalwart_v016._read_regular_snapshot

            def snapshot_then_replace(*args: object, **kwargs: object) -> object:
                snapshot = read_snapshot(*args, **kwargs)
                replacement.replace(evidence)
                return snapshot

            with mock.patch.object(
                stalwart_v016,
                "_read_regular_snapshot",
                side_effect=snapshot_then_replace,
            ) as snapshot_reader:
                inventory = stalwart_v016.validate_export_inventory(
                    paths,
                    [evidence],
                )

            snapshot_reader.assert_called_once_with(
                evidence,
                root=repository,
                label="export inventory file",
                maximum=16 * 1024 * 1024,
                required_mode=0o600,
            )
            self.assertEqual(
                inventory,
                (
                    {
                        "path": "evidence/summary.txt",
                        "sha256": hashlib.sha256(original).hexdigest(),
                        "size": len(original),
                    },
                ),
            )

    def test_inventory_refuses_runtime_stores_keys_quarantine_gate_and_rocksdb(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory).resolve()
            paths = stalwart_v016.MigrationPaths.for_repository(repository)
            runtime = repository / "debug-dashboard" / ".runtime"
            candidates = [
                runtime / "stalwart" / "data.json",
                runtime / "keys" / "key.json",
                runtime / "quarantine" / "item.json",
                runtime / "stalwart-gate0b" / "fixture-secrets",
                runtime / "stalwart-gate0b" / "credential-store" / "store.json",
                repository / "stalwart-data" / "CURRENT",
            ]
            for candidate in candidates:
                with self.subTest(candidate=candidate):
                    candidate.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    for parent in candidate.parents:
                        if parent == repository:
                            break
                        parent.chmod(0o700)
                    candidate.write_text("safe fixture\n", encoding="utf-8")
                    candidate.chmod(0o600)

                    with self.assertRaisesRegex(
                        stalwart_v016.MigrationError,
                        "protected|RocksDB",
                    ):
                        stalwart_v016.validate_export_inventory(paths, [candidate])

    def test_inventory_refuses_locks_and_secret_bearing_names_or_content(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory).resolve()
            paths = stalwart_v016.MigrationPaths.for_repository(repository)
            evidence = repository / "evidence"
            evidence.mkdir(mode=0o700)
            secret = "unit-only-secret-value"
            cases = {
                "migration.lock": b"safe fixture\n",
                "admin-secret.txt": b"safe fixture\n",
                "private.pem": b"-----BEGIN PRIVATE KEY-----\nfixture\n",
                "plain.txt": f"ADMIN_SECRET={secret}\n".encode("utf-8"),
            }
            for name, content in cases.items():
                with self.subTest(name=name):
                    candidate = evidence / name
                    candidate.write_bytes(content)
                    candidate.chmod(0o600)
                    with self.assertRaisesRegex(
                        stalwart_v016.MigrationError,
                        "lock|secret",
                    ) as raised:
                        stalwart_v016.validate_export_inventory(paths, [candidate])
                    self.assertNotIn(secret, str(raised.exception))

    def test_converted_outputs_require_exact_rocksdb_path_and_no_legacy_paths(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory).resolve()
            paths = stalwart_v016.MigrationPaths.for_repository(repository)
            stalwart_v016.ensure_owner_directory(
                paths.migration_root,
                trusted_root=repository,
            )
            paths.converted_config.write_bytes(AUDITED_CONVERTED_CONFIG_BYTES)
            paths.export.write_text(
                "\n".join(
                    [
                        json.dumps(
                            {
                                "@type": "create",
                                "object": "principal/alice",
                                "value": {"name": "alice"},
                            },
                        ),
                        json.dumps(
                            {
                                "@type": "update",
                                "object": "settings",
                                "value": {"storage": "rocksdb"},
                            },
                        ),
                    ],
                )
                + "\n",
                encoding="utf-8",
            )
            paths.converted_config.chmod(0o600)
            paths.export.chmod(0o600)
            validator = getattr(stalwart_v016, "validate_converted_outputs", None)
            self.assertIsNotNone(validator)

            validator(paths)
            self.assertEqual(
                hashlib.sha256(AUDITED_CONVERTED_CONFIG_BYTES).hexdigest(),
                AUDITED_CONVERTED_CONFIG_SHA256,
            )

            for label, content in {
                "compact": b'{"@type":"RocksDb","path":"/var/lib/stalwart"}',
                "trailing-newline": AUDITED_CONVERTED_CONFIG_BYTES + b"\n",
                "different-indentation": (
                    b'{\n'
                    b'    "@type": "RocksDb",\n'
                    b'    "path": "/var/lib/stalwart"\n'
                    b"}"
                ),
            }.items():
                with self.subTest(exact_bytes=label):
                    paths.converted_config.write_bytes(content)
                    paths.converted_config.chmod(0o600)
                    with self.assertRaisesRegex(
                        stalwart_v016.MigrationError,
                        "exact|bytes",
                    ):
                        validator(paths)

            paths.converted_config.write_text(
                json.dumps(
                    {
                        "@type": "RocksDb",
                        "path": "/var/lib/stalwart/data",
                    },
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                stalwart_v016.MigrationError,
                "bytes|DataStore",
            ):
                validator(paths)
            paths.converted_config.write_text(
                json.dumps(
                    {
                        "@type": "RocksDb",
                        "path": "/var/lib/stalwart/",
                    },
                ),
                encoding="utf-8",
            )
            paths.export.write_text(
                json.dumps(
                    {
                        "@type": "create",
                        "object": "principal/alice",
                        "value": {},
                    },
                )
                + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                stalwart_v016.MigrationError,
                "bytes|DataStore",
            ):
                validator(paths)
            paths.converted_config.write_bytes(AUDITED_CONVERTED_CONFIG_BYTES)
            paths.export.write_text(
                json.dumps(
                    {
                        "@type": "update",
                        "object": "settings",
                        "value": {"legacy": "/opt/stalwart/data"},
                    },
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(stalwart_v016.MigrationError, "legacy"):
                validator(paths)

    def test_converted_export_rejects_arbitrary_ops_and_escaped_legacy_paths(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory).resolve()
            paths = stalwart_v016.MigrationPaths.for_repository(repository)
            stalwart_v016.ensure_owner_directory(
                paths.migration_root,
                trusted_root=repository,
            )
            paths.converted_config.write_bytes(AUDITED_CONVERTED_CONFIG_BYTES)
            paths.converted_config.chmod(0o600)
            cases = [
                (
                    '{"op":"create"}\n',
                    "schema",
                ),
                (
                    '{"@type":"create","object":"settings",'
                    '"value":{"path":"\\/opt\\/stalwart\\/data"}}\n',
                    "legacy",
                ),
            ]
            for content, error in cases:
                with self.subTest(error=error):
                    paths.export.write_text(content, encoding="utf-8")
                    paths.export.chmod(0o600)
                    with self.assertRaisesRegex(
                        stalwart_v016.MigrationError,
                        error,
                    ):
                        stalwart_v016.validate_converted_outputs(paths)


@unittest.skipIf(stalwart_v016 is None, "migration script is not implemented")
class ReviewReceiptTest(unittest.TestCase):
    def test_mark_reviewed_writes_and_revalidates_a_digest_bound_0600_receipt(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory).resolve()
            paths = stalwart_v016.MigrationPaths.for_repository(repository)
            stalwart_v016.ensure_owner_directory(
                paths.migration_root,
                trusted_root=repository,
            )
            report = b"unmapped.setting\n"
            paths.unmigrated.write_bytes(report)
            paths.unmigrated.chmod(0o600)
            marker = getattr(stalwart_v016, "mark_reviewed", None)
            validator = getattr(stalwart_v016, "validate_review_receipt", None)
            self.assertIsNotNone(marker)
            self.assertIsNotNone(validator)

            receipt_path = marker(
                paths,
                paths.unmigrated,
                clock=lambda: "2026-07-28T12:00:00Z",
            )
            payload = validator(paths, receipt_path, paths.unmigrated)

            self.assertEqual(receipt_path, paths.reviewed)
            self.assertEqual(stat.S_IMODE(receipt_path.stat().st_mode), 0o600)
            self.assertEqual(
                payload,
                {
                    "schema": "mail-sandbox.stalwart-v016-review.v1",
                    "reviewed_at": "2026-07-28T12:00:00Z",
                    "report": {
                        "name": "unmigrated.txt",
                        "sha256": hashlib.sha256(report).hexdigest(),
                    },
                },
            )
            self.assertNotIn("unmapped.setting", receipt_path.read_text(encoding="utf-8"))

            self.assertEqual(
                marker(
                    paths,
                    paths.unmigrated,
                    clock=lambda: "different-time-must-not-rewrite",
                ),
                receipt_path,
            )

            paths.unmigrated.write_bytes(b"changed after review\n")
            with self.assertRaisesRegex(stalwart_v016.MigrationError, "match"):
                validator(paths, receipt_path, paths.unmigrated)
            with self.assertRaisesRegex(stalwart_v016.MigrationError, "match"):
                marker(paths, paths.unmigrated)

    def test_mark_reviewed_refuses_broad_and_symlinked_reports(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory).resolve()
            paths = stalwart_v016.MigrationPaths.for_repository(repository)
            stalwart_v016.ensure_owner_directory(
                paths.migration_root,
                trusted_root=repository,
            )
            outside = repository / "outside.txt"
            outside.write_text("outside\n", encoding="utf-8")
            outside.chmod(0o600)
            paths.unmigrated.symlink_to(outside)

            with self.assertRaisesRegex(stalwart_v016.MigrationError, "symlink"):
                stalwart_v016.mark_reviewed(paths, paths.unmigrated)
            with self.assertRaisesRegex(stalwart_v016.MigrationError, "fixed"):
                stalwart_v016.mark_reviewed(paths, paths.migration_root)


@unittest.skipIf(stalwart_v016 is None, "migration script is not implemented")
class ApplyPreparationTest(unittest.TestCase):
    @staticmethod
    def _write_0600(path: Path, content: bytes) -> None:
        path.write_bytes(content)
        path.chmod(0o600)

    @staticmethod
    def _write_0644(path: Path, content: bytes) -> None:
        path.write_bytes(content)
        path.chmod(0o644)

    def _fixture(
        self,
        directory: str,
        *,
        compose_project: str = "mail-sandbox",
        base_compose_content: str | None = None,
        operations: tuple[tuple[str, str], ...] = (
            ("create", "principal/unit-fixture"),
            ("update", "domain/unit.example"),
        ),
    ) -> SimpleNamespace:
        repository = Path(directory).resolve()
        public_url = "http://192.168.86.36:8443"
        network_environment = write_network_environment(repository, public_url)
        (repository / ".git").mkdir(mode=0o700)
        source_store = repository / "stalwart-data"
        source_store.mkdir(mode=0o700)
        base_compose = repository / "docker-compose.yml"
        base_compose.write_text(
            (
                normal_compose_text()
                if base_compose_content is None
                else base_compose_content
            ),
            encoding="utf-8",
        )
        capture_script = repository / "scripts" / "capture_stalwart_v015.py"
        capture_script.parent.mkdir(mode=0o700)
        capture_script.write_text("# unit-only verifier fixture\n", encoding="utf-8")
        capture_script.chmod(0o600)
        compose_overlay = repository / "docker-compose.stalwart-migration.yml"
        compose_overlay.write_bytes(CANONICAL_MIGRATION_OVERLAY)
        compose_overlay.chmod(0o644)
        paths = stalwart_v016.MigrationPaths.for_repository(repository)
        stalwart_v016.ensure_owner_directory(
            paths.migration_root,
            trusted_root=repository,
        )

        source_payload = {
            "backup": {
                "root": str(
                    repository
                    / "captures"
                    / "debug-dashboard"
                    / "stalwart-v015"
                    / "backups"
                    / "stalwart-v015-20260728T120000Z-unitabcd"
                ),
            },
            "rollback": {
                "port": 18081,
                "project": "mail-sandbox-stalwart-v015-rollback",
            },
            "source": {
                "compose_config_files": [str(base_compose)],
                "compose_project": compose_project,
                "compose_service": "stalwart",
                "compose_working_directory": str(repository),
                "data_path": str(source_store),
                "image_digest": (
                    "stalwartlabs/stalwart@sha256:" + "b" * 64
                ),
                "image_id": "sha256:" + "c" * 64,
                "version": "0.15.5",
            },
        }
        self._write_0600(
            paths.source_receipt,
            (json.dumps(receipt_envelope(source_payload)) + "\n").encode("utf-8"),
        )
        script_content = b"unit-only pinned migration script\n"
        self._write_0600(paths.migration_script, script_content)
        self._write_0600(paths.settings, b'{"settings":"safe fixture"}\n')
        self._write_0600(paths.principals, b"[]\n")
        self._write_0600(
            paths.converted_config,
            AUDITED_CONVERTED_CONFIG_BYTES,
        )
        normal_config = repository / "stalwart" / "config.json"
        normal_config.parent.mkdir(mode=0o700)
        normal_config.write_bytes(paths.converted_config.read_bytes())
        normal_config.chmod(0o644)
        export_records = (
            {
                "@type": operation,
                "object": object_name,
                "value": {"name": object_name.rsplit("/", 1)[-1]},
            }
            for operation, object_name in operations
        )
        self._write_0600(
            paths.export,
            (
                "\n".join(json.dumps(record) for record in export_records)
                + "\n"
            ).encode("utf-8"),
        )
        self._write_0600(paths.unmigrated, b"reviewed.unit.fixture\n")
        source_digest = hashlib.sha256(paths.source_receipt.read_bytes()).hexdigest()
        script_digest = hashlib.sha256(script_content).hexdigest()
        stalwart_v016.create_dry_run_receipt(
            paths,
            source_receipt_sha256=source_digest,
            migration_script_sha256=script_digest,
            rollback_proof={
                "management_status": 200,
                "proved_at": "20260728T120000Z",
                "version": "0.15.5",
            },
            clock=lambda: "2026-07-28T12:00:00Z",
        )
        stalwart_v016.mark_reviewed(
            paths,
            paths.unmigrated,
            clock=lambda: "2026-07-28T12:01:00Z",
        )

        state = {
            "stale_source": False,
            "writer": False,
        }
        events: list[str] = []
        container_id = "f" * 64

        def runner(args: list[str]) -> object:
            if args and args[0] == "/unit/python3":
                events.append("verify")
                if state["stale_source"]:
                    raise stalwart_v016.CommandError("stale source receipt")
                return stalwart_v016.CommandResult("", "")
            if args[:2] == ["git", "-C"]:
                events.append("git")
                return stalwart_v016.CommandResult(
                    str(repository / ".git") + "\n",
                    "",
                )
            if args[:2] == ["docker", "ps"]:
                events.append("census")
                stdout = container_id + "\n" if state["writer"] else ""
                return stalwart_v016.CommandResult(stdout, "")
            if args[:2] == ["docker", "inspect"]:
                events.append("inspect")
                return stalwart_v016.CommandResult(
                    json.dumps(
                        [
                            {
                                "Id": container_id,
                                "State": {"Running": True},
                                "Mounts": [
                                    {
                                        "Type": "bind",
                                        "Source": str(source_store),
                                        "RW": True,
                                    },
                                ],
                            },
                        ],
                    ),
                    "",
                )
            self.fail(f"unexpected injected command: {args!r}")

        return SimpleNamespace(
            repository=repository,
            paths=paths,
            source_store=source_store,
            compose_project=compose_project,
            public_url=public_url,
            network_environment=network_environment,
            normal_config=normal_config,
            script_digest=script_digest,
            state=state,
            events=events,
            operations=operations,
            runner=runner,
        )

    @staticmethod
    def _valid_evidence(
        *,
        operations: tuple[tuple[str, str], ...] = (
            ("create", "principal/unit-fixture"),
            ("update", "domain/unit.example"),
        ),
    ) -> str:
        creates = sum(operation == "create" for operation, _ in operations)
        updates = sum(operation == "update" for operation, _ in operations)
        create_objects = creates
        records = [
            {
                "op": operation,
                "object": object_name,
                "index": index,
                "count": 1,
                "status": "ok",
            }
            for index, (operation, object_name) in enumerate(operations)
        ]
        records.append(
            {
                "op": "summary",
                "plan": {
                    "destroys": 0,
                    "updates": updates,
                    "creates": creates,
                    "create_objects": create_objects,
                    "upserts": 0,
                    "upsert_objects": 0,
                },
                "done": {
                    "destroyed": 0,
                    "updated": updates,
                    "created": create_objects,
                    "failed": 0,
                },
            },
        )
        return "\n".join(json.dumps(record) for record in records)

    def _materialize_runtime(
        self,
        fixture: SimpleNamespace,
        *,
        environment: bytes = (
            b"STALWART_RECOVERY_ADMIN=unit-user:unit-secret\n"
        ),
    ) -> None:
        config_dir = fixture.paths.migration_root / "recovery-config"
        config_dir.mkdir(mode=0o755)
        config_dir.chmod(0o755)
        self._write_0644(
            config_dir / "config.json",
            fixture.paths.converted_config.read_bytes(),
        )
        self._write_0600(
            fixture.paths.migration_root / "recovery.env",
            environment,
        )

    @staticmethod
    def _operation_digest(
        operations: tuple[tuple[str, str], ...],
    ) -> str:
        value = [
            {
                "op": operation,
                "object": object_name,
                "count": 1,
            }
            for operation, object_name in operations
        ]
        return hashlib.sha256(
            json.dumps(
                value,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8"),
        ).hexdigest()

    def _valid_post_apply_proof(self, plan: object) -> object:
        operations = tuple(
            (operation.op, operation.object_name)
            for operation in plan.operations
        )
        return stalwart_v016.PostApplyCensusProof(
            operations_sha256=self._operation_digest(operations),
            operation_count=len(operations),
            server_version="0.16.17",
            management_status=200,
        )

    def _valid_rollback_activation(
        self,
        fixture: SimpleNamespace,
        *,
        expected_receipt_sha256: str,
    ) -> _UnitRollbackActivation:
        backup_root = (
            fixture.repository
            / "captures"
            / "debug-dashboard"
            / "stalwart-v015"
            / "backups"
            / "stalwart-v015-20260728T120000Z-unitabcd"
        )
        backup_root.mkdir(parents=True, mode=0o700)
        for parent in (
            fixture.repository / "captures",
            fixture.repository / "captures" / "debug-dashboard",
            fixture.repository
            / "captures"
            / "debug-dashboard"
            / "stalwart-v015",
            fixture.repository
            / "captures"
            / "debug-dashboard"
            / "stalwart-v015"
            / "backups",
            backup_root,
        ):
            parent.chmod(0o700)
        proof_path = backup_root / "rollback-activation.json"
        base_url = "http://127.0.0.1:18081"
        proved_at = "20260728T120000Z"
        payload = {
            "activated_at": proved_at,
            "backup_root": str(backup_root),
            "base_url": base_url,
            "container_id": "a" * 64,
            "image_digest": (
                "stalwartlabs/stalwart@sha256:" + "b" * 64
            ),
            "image_id": "sha256:" + "c" * 64,
            "management_status": 200,
            "network_id": "d" * 64,
            "project": "mail-sandbox-stalwart-v015-rollback",
            "schema": (
                "mail-sandbox.stalwart-v015-rollback-activation.v1"
            ),
            "service": "stalwart-rollback",
            "source_receipt_sha256": expected_receipt_sha256,
            "version": "0.15.5",
        }
        self._write_0600(
            proof_path,
            (
                json.dumps(receipt_envelope(payload), sort_keys=True)
                + "\n"
            ).encode("utf-8"),
        )
        return _UnitRollbackActivation(
            proof_path=proof_path,
            base_url=base_url,
            proof=_UnitRollbackProof(
                management_status=200,
                proved_at=proved_at,
                version="0.15.5",
            ),
        )

    def _publish_apply_attempt(
        self,
        fixture: SimpleNamespace,
        plan: object,
    ) -> None:
        payload = stalwart_v016._apply_attempt_payload(
            plan,
            started_at="2026-07-28T12:02:00Z",
        )
        stalwart_v016._write_new_json_0600(
            fixture.paths.apply_attempt,
            stalwart_v016._digest_envelope(payload),
            root=fixture.repository,
        )

    @staticmethod
    def _pre_dispatch_plan(fixture: SimpleNamespace) -> object:
        return stalwart_v016._validate_apply_state(
            fixture.paths,
            source_receipt_path=fixture.paths.source_receipt,
            script_path=fixture.paths.migration_script,
            dry_run_receipt_path=fixture.paths.dry_run_receipt,
            review_receipt_path=fixture.paths.reviewed,
            runner=fixture.runner,
            python_executable="/unit/python3",
            expected_script_sha256=fixture.script_digest,
            runtime_phase="pre-dispatch",
        ).plan

    @staticmethod
    def _valid_runtime_inspection(
        fixture: SimpleNamespace,
        plan: object,
        container_id: str,
    ) -> dict[str, object]:
        return {
            "Id": container_id,
            "Image": "stalwartlabs/stalwart:v0.16.17@sha256:a8108e19bd927e172d4d8c128907b8dfc93fd180ae8ee07dccdd42cb97eb9dfa",
            "ImageID": stalwart_v016.STALWART_IMAGE_ID,
            "User": "2000:2000",
            "Project": plan.source.compose_project,
            "Service": "stalwart",
            "WorkingDir": str(fixture.repository),
            "ConfigFiles": ",".join(
                (
                    str(fixture.repository / "docker-compose.yml"),
                    str(
                        fixture.repository
                        / "docker-compose.stalwart-migration.yml",
                    ),
                ),
            ),
            "Oneoff": "False",
            "Mounts": [
                {
                    "Type": "bind",
                    "Source": str(plan.runtime.config_dir),
                    "Destination": "/etc/stalwart",
                    "RW": False,
                },
                {
                    "Type": "bind",
                    "Source": str(plan.runtime.data_dir),
                    "Destination": "/var/lib/stalwart",
                    "RW": True,
                },
            ],
            "Ports": {
                "8080/tcp": [
                    {
                        "HostIp": "127.0.0.1",
                        "HostPort": "8443",
                    },
                ],
                "587/tcp": [
                    {
                        "HostIp": "127.0.0.1",
                        "HostPort": "8587",
                    },
                ],
            },
            "Running": True,
            "Health": "healthy",
        }

    def _valid_recovery_runtime_inspection(
        self,
        fixture: SimpleNamespace,
        plan: object,
        container_id: str,
        *,
        running: bool = True,
        restarting: bool = False,
        health: str = "healthy",
    ) -> dict[str, object]:
        value = self._valid_runtime_inspection(
            fixture,
            plan,
            container_id,
        )
        value.update(
            {
                "Running": running,
                "Restarting": restarting,
                "Health": health,
                "Entrypoint": None,
                "Cmd": None,
                "Restart": "no",
            },
        )
        return value

    @staticmethod
    def _valid_owner_recovery_inspection(
        fixture: SimpleNamespace,
        plan: object,
        container_id: str,
        *,
        running: bool = True,
        restarting: bool = False,
    ) -> dict[str, object]:
        return {
            "Id": container_id,
            "Image": stalwart_v016.STALWART_IMAGE,
            "ImageID": stalwart_v016.STALWART_IMAGE_ID,
            "User": "0:0",
            "Project": plan.source.compose_project,
            "Service": stalwart_v016.MIGRATION_OWNER_SERVICE,
            "WorkingDir": str(fixture.repository),
            "ConfigFiles": (
                f"{plan.source.base_compose},"
                f"{plan.runtime.compose_overlay}"
            ),
            "Oneoff": "False",
            "Mounts": [
                {
                    "Type": "bind",
                    "Source": str(plan.runtime.config_dir),
                    "Destination": "/etc/stalwart",
                    "RW": False,
                },
                {
                    "Type": "bind",
                    "Source": str(plan.runtime.data_dir),
                    "Destination": "/var/lib/stalwart",
                    "RW": True,
                },
            ],
            "Ports": {},
            "Running": running,
            "Restarting": restarting,
            "Health": "",
            "Entrypoint": ["/bin/sh", "-c"],
            "Cmd": [
                (
                    "chown -R 2000:2000 /var/lib/stalwart && "
                    "chmod 0700 /var/lib/stalwart"
                ),
            ],
            "Restart": "no",
        }

    @staticmethod
    def _docker_client_environment() -> dict[str, str]:
        return {
            "HOME": "/unit/home",
            "DOCKER_HOST": "unix:///run/user/501/docker.sock",
            "DOCKER_CONTEXT": "rootless-unit",
            "DOCKER_CONFIG": "/unit/home/.docker",
            "DOCKER_TLS_VERIFY": "1",
            "DOCKER_CERT_PATH": "/unit/home/.docker/certs",
            "DOCKER_API_VERSION": "1.45",
            "XDG_RUNTIME_DIR": "/run/user/501",
            "SSH_AUTH_SOCK": "/run/user/501/ssh-agent.socket",
        }

    def _prepare(
        self,
        fixture: SimpleNamespace,
        executor: object,
        *,
        source_receipt_path: Path | None = None,
        post_apply_verifier: object | None = None,
        materialize_runtime: bool = True,
        clock: object | None = None,
    ) -> Path:
        paths = fixture.paths

        def wrapped_executor(plan: object) -> object:
            result = executor(plan)
            if materialize_runtime:
                self._materialize_runtime(fixture)
            return result

        verifier = (
            self._valid_post_apply_proof
            if post_apply_verifier is None
            else post_apply_verifier
        )
        return stalwart_v016.prepare_apply(
            paths,
            source_receipt_path=(
                paths.source_receipt
                if source_receipt_path is None
                else source_receipt_path
            ),
            script_path=paths.migration_script,
            dry_run_receipt_path=paths.dry_run_receipt,
            review_receipt_path=paths.reviewed,
            runner=fixture.runner,
            python_executable="/unit/python3",
            executor=wrapped_executor,
            post_apply_verifier=verifier,
            clock=(
                (lambda: "2026-07-28T12:02:00Z")
                if clock is None
                else clock
            ),
            expected_script_sha256=fixture.script_digest,
        )

    def test_production_recovery_credential_is_strong_valid_and_mutable(
        self,
    ) -> None:
        with mock.patch.object(
            stalwart_v016.secrets,
            "randbelow",
            return_value=0,
        ) as randbelow:
            credential = (
                stalwart_v016._generate_production_recovery_credential()
            )

        self.assertIs(type(credential), bytearray)
        self.assertEqual(
            credential,
            bytearray(
                b"migration-"
                + b"0" * 32
                + b":"
                + b"A" * 64,
            ),
        )
        self.assertTrue(
            stalwart_v016._valid_recovery_credential_slice(
                credential,
                start=0,
                end=len(credential),
            ),
        )
        self.assertEqual(
            randbelow.call_args_list,
            [mock.call(16)] * 32 + [mock.call(64)] * 64,
        )
        stalwart_v016._wipe_bytearray(credential)

    def test_production_recovery_generator_wipes_partial_buffer_on_cancellation(
        self,
    ) -> None:
        original_wipe = stalwart_v016._wipe_bytearray
        for interruption in (
            KeyboardInterrupt("unit-generator-cancellation"),
            SystemExit(73),
        ):
            with self.subTest(cancellation=type(interruption).__name__):
                wiped: list[bytearray] = []

                def recording_wipe(value: bytearray) -> None:
                    original_wipe(value)
                    wiped.append(value)

                raised: BaseException | None = None
                with (
                    mock.patch.object(
                        stalwart_v016.secrets,
                        "randbelow",
                        side_effect=(0, interruption),
                    ),
                    mock.patch.object(
                        stalwart_v016,
                        "_wipe_bytearray",
                        side_effect=recording_wipe,
                    ),
                ):
                    try:
                        stalwart_v016._generate_production_recovery_credential()
                    except BaseException as error:
                        raised = error

                self.assertIs(raised, interruption)
                self.assertEqual(len(wiped), 1)
                self.assertTrue(all(value == 0 for value in wiped[0]))

    def test_production_apply_defaults_to_exact_runtime_adapters_and_wipes_copies(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            source = bytearray(b"unit-user:unit-secret")
            issued: list[bytearray] = []
            observed: dict[str, object] = {}

            def prepare(paths: object, **kwargs: object) -> Path:
                self.assertEqual(paths, fixture.paths)
                executor = observed["runtime_executor"]
                verifier = observed["runtime_verifier"]
                self.assertIs(type(executor), stalwart_v016.MigrationApplyExecutor)
                self.assertIs(
                    type(verifier),
                    stalwart_v016.MigrationPostApplyVerifier,
                )
                self.assertIs(
                    executor._runner,
                    stalwart_v016.run_redacted_command,
                )
                self.assertIs(
                    verifier._runner,
                    stalwart_v016.run_redacted_command,
                )
                self.assertIs(
                    executor._secret_runner,
                    stalwart_v016.run_redacted_secret_command,
                )
                self.assertIs(
                    verifier._secret_runner,
                    stalwart_v016.run_redacted_secret_command,
                )
                self.assertIs(executor._state_runner, fixture.runner)
                self.assertIs(verifier._state_runner, fixture.runner)
                credential = executor._credential_factory()
                self.assertIs(type(credential), bytearray)
                issued.append(credential)
                observed.update(kwargs)
                self._write_0600(
                    fixture.paths.apply_receipt,
                    b'{"unit":"published-under-lock"}\n',
                )
                return fixture.paths.apply_receipt

            def executor_factory(**kwargs: object) -> object:
                executor = stalwart_v016.MigrationApplyExecutor(**kwargs)
                observed["runtime_executor"] = executor
                return executor

            def verifier_factory(**kwargs: object) -> object:
                verifier = stalwart_v016.MigrationPostApplyVerifier(**kwargs)
                observed["runtime_verifier"] = verifier
                return verifier

            dependencies = replace(
                stalwart_v016.production_apply_dependencies(),
                prepare=prepare,
                apply_executor_factory=executor_factory,
                post_apply_verifier_factory=verifier_factory,
                state_runner=fixture.runner,
                recovery_credential_source=lambda: source,
            )
            self.assertEqual(
                repr(dependencies),
                "ProductionApplyDependencies(<redacted>)",
            )

            result = stalwart_v016.run_production_apply(
                fixture.paths,
                script_path=fixture.paths.migration_script,
                review_receipt_path=fixture.paths.reviewed,
                dependencies=dependencies,
                expected_script_sha256=fixture.script_digest,
            )

            self.assertEqual(result, fixture.paths.apply_receipt)
            self.assertEqual(observed["source_receipt_path"], fixture.paths.source_receipt)
            self.assertEqual(observed["script_path"], fixture.paths.migration_script)
            self.assertEqual(
                observed["dry_run_receipt_path"],
                fixture.paths.dry_run_receipt,
            )
            self.assertEqual(observed["review_receipt_path"], fixture.paths.reviewed)
            self.assertIs(observed["runner"], fixture.runner)
            self.assertEqual(observed["python_executable"], sys.executable)
            self.assertEqual(
                observed["expected_script_sha256"],
                fixture.script_digest,
            )
            self.assertEqual(len(issued), 1)
            self.assertTrue(all(value == 0 for value in source))
            self.assertTrue(all(value == 0 for value in issued[0]))

    def test_production_apply_holds_and_validates_one_lock_across_every_phase(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            events: list[str] = []
            acquired_roots: list[Path] = []
            source = bytearray(b"unit-user:unit-secret")
            issued: list[bytearray] = []
            runtime_runner = mock.Mock(name="redacted-runtime-runner")
            secret_runtime_runner = mock.Mock(
                name="redacted-secret-runtime-runner",
            )
            state_runner = mock.Mock(name="state-runner")
            plan = object()

            class RecordingLock:
                active = False

                def __enter__(self) -> object:
                    self.active = True
                    events.append("lock-enter")
                    return self

                def assert_valid_for(self, repository_root: Path) -> None:
                    self.assert_active()
                    self.assertEqual(repository_root, fixture.repository)
                    events.append("lock-valid")

                def assert_active(self) -> None:
                    if not self.active:
                        raise AssertionError("operation lock is not active")

                def assertEqual(self, left: object, right: object) -> None:
                    if left != right:
                        raise AssertionError(f"{left!r} != {right!r}")

                def __exit__(
                    self,
                    _kind: object,
                    _error: object,
                    _traceback: object,
                ) -> None:
                    self.assert_active()
                    events.append("lock-exit")
                    self.active = False

            lock = RecordingLock()

            def acquire(repository_root: Path) -> object:
                acquired_roots.append(repository_root)
                events.append("lock-acquire")
                return lock

            def executor_factory(
                *,
                credential_factory: object,
                runner: object,
                secret_runner: object,
                state_runner: object,
            ) -> object:
                lock.assert_active()
                self.assertIs(runner, runtime_runner)
                self.assertIs(secret_runner, secret_runtime_runner)
                self.assertIs(state_runner, dependencies.state_runner)
                events.append("executor-build")

                def executor(observed_plan: object) -> str:
                    lock.assert_active()
                    self.assertIs(observed_plan, plan)
                    events.append("executor")
                    credential = credential_factory()
                    issued.append(credential)
                    return "unit-evidence"

                return executor

            def verifier_factory(
                *,
                runner: object,
                secret_runner: object,
                state_runner: object,
            ) -> object:
                lock.assert_active()
                self.assertIs(runner, runtime_runner)
                self.assertIs(secret_runner, secret_runtime_runner)
                self.assertIs(state_runner, dependencies.state_runner)
                events.append("verifier-build")

                def verifier(observed_plan: object) -> str:
                    lock.assert_active()
                    self.assertIs(observed_plan, plan)
                    events.append("verifier")
                    return "unit-proof"

                return verifier

            def prepare(paths: object, **kwargs: object) -> Path:
                lock.assert_active()
                self.assertEqual(paths, fixture.paths)
                self.assertIs(kwargs["runner"], state_runner)
                events.append("preflight")
                self.assertEqual(kwargs["executor"](plan), "unit-evidence")
                self.assertEqual(
                    kwargs["post_apply_verifier"](plan),
                    "unit-proof",
                )
                lock.assert_active()
                events.append("receipt-publication")
                self._write_0600(
                    fixture.paths.apply_receipt,
                    b'{"unit":"receipt"}\n',
                )
                return fixture.paths.apply_receipt

            dependencies = stalwart_v016.ProductionApplyDependencies(
                acquire_operation_lock=acquire,
                prepare=prepare,
                apply_executor_factory=executor_factory,
                post_apply_verifier_factory=verifier_factory,
                state_runner=state_runner,
                runtime_runner=runtime_runner,
                secret_runtime_runner=secret_runtime_runner,
                recovery_credential_source=lambda: source,
            )
            with (
                redirect_stdout(stdout := io.StringIO()),
                redirect_stderr(stderr := io.StringIO()),
            ):
                result = stalwart_v016.run_production_apply(
                    fixture.paths,
                    script_path=fixture.paths.migration_script,
                    review_receipt_path=fixture.paths.reviewed,
                    dependencies=dependencies,
                    expected_script_sha256=fixture.script_digest,
                )

            self.assertEqual(result, fixture.paths.apply_receipt)
            self.assertEqual(acquired_roots, [fixture.repository])
            self.assertEqual(events[0:2], ["lock-acquire", "lock-enter"])
            self.assertEqual(events[-1], "lock-exit")
            self.assertLess(events.index("lock-enter"), events.index("preflight"))
            self.assertLess(events.index("preflight"), events.index("executor"))
            self.assertLess(events.index("executor"), events.index("verifier"))
            self.assertLess(
                events.index("verifier"),
                events.index("receipt-publication"),
            )
            self.assertLess(
                events.index("receipt-publication"),
                events.index("lock-exit"),
            )
            self.assertGreaterEqual(events.count("lock-valid"), 6)
            self.assertEqual(stdout.getvalue(), "")
            self.assertEqual(stderr.getvalue(), "")
            self.assertTrue(all(value == 0 for value in source))
            self.assertEqual(len(issued), 1)
            self.assertTrue(all(value == 0 for value in issued[0]))

    def test_production_apply_wipes_credential_copies_on_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            source = bytearray(b"unit-user:unit-secret")
            issued: list[bytearray] = []
            lock_active = False

            class Lock:
                def __enter__(self) -> object:
                    nonlocal lock_active
                    lock_active = True
                    return self

                def assert_valid_for(self, _repository_root: Path) -> None:
                    if not lock_active:
                        raise AssertionError("lock was released early")

                def __exit__(
                    self,
                    _kind: object,
                    _error: object,
                    _traceback: object,
                ) -> None:
                    nonlocal lock_active
                    lock_active = False

            def executor_factory(
                *,
                credential_factory: object,
                runner: object,
                secret_runner: object,
                state_runner: object,
            ) -> object:
                del runner, secret_runner, state_runner

                def executor(_plan: object) -> str:
                    credential = credential_factory()
                    issued.append(credential)
                    raise RuntimeError("unit-user:unit-secret")

                return executor

            def prepare(_paths: object, **kwargs: object) -> Path:
                kwargs["executor"](object())
                raise AssertionError("executor failure was not propagated")

            dependencies = stalwart_v016.ProductionApplyDependencies(
                acquire_operation_lock=lambda _root: Lock(),
                prepare=prepare,
                apply_executor_factory=executor_factory,
                post_apply_verifier_factory=lambda **_kwargs: mock.Mock(),
                state_runner=mock.Mock(),
                runtime_runner=mock.Mock(),
                secret_runtime_runner=mock.Mock(),
                recovery_credential_source=lambda: source,
            )
            with self.assertRaisesRegex(
                stalwart_v016.MigrationError,
                "failed safely",
            ) as raised:
                stalwart_v016.run_production_apply(
                    fixture.paths,
                    script_path=fixture.paths.migration_script,
                    review_receipt_path=fixture.paths.reviewed,
                    dependencies=dependencies,
                    expected_script_sha256=fixture.script_digest,
                )

            self.assertTrue(raised.exception.__suppress_context__)
            self.assertNotIn("unit-secret", str(raised.exception))
            self.assertFalse(lock_active)
            self.assertTrue(all(value == 0 for value in source))
            self.assertEqual(len(issued), 1)
            self.assertTrue(all(value == 0 for value in issued[0]))

    def test_production_apply_runtime_failure_activates_verified_rollback_once(
        self,
    ) -> None:
        self.assertIn(
            "rollback_activator",
            stalwart_v016.ProductionApplyDependencies.__dataclass_fields__,
        )
        for failure_stage in ("executor", "post-verifier"):
            with (
                self.subTest(failure_stage=failure_stage),
                tempfile.TemporaryDirectory() as directory,
            ):
                fixture = self._fixture(directory)
                events: list[str] = []
                captured_plan: list[object] = []
                failed_state: dict[str, object] = {}
                recovery_started = False
                lock_active = False
                activations = 0

                class Lock:
                    def __enter__(self) -> object:
                        nonlocal lock_active
                        lock_active = True
                        return self

                    def assert_valid_for(self, repository_root: Path) -> None:
                        if (
                            not lock_active
                            or repository_root != fixture.repository
                        ):
                            raise AssertionError("operation lock is not active")

                    def __exit__(
                        self,
                        _kind: object,
                        _error: object,
                        _traceback: object,
                    ) -> None:
                        nonlocal lock_active
                        lock_active = False

                def capture_failed_state() -> None:
                    failed_state.update(
                        {
                            "store_entries": tuple(
                                fixture.source_store.rglob("*"),
                            ),
                            "config": (
                                fixture.paths.migration_root
                                / "recovery-config"
                                / "config.json"
                            ).read_bytes(),
                            "environment": (
                                fixture.paths.migration_root / "recovery.env"
                            ).read_bytes(),
                            "export": fixture.paths.export.read_bytes(),
                            "attempt": fixture.paths.apply_attempt.read_bytes(),
                        },
                    )

                def executor_factory(**_kwargs: object) -> object:
                    def executor(plan: object) -> str:
                        captured_plan.append(plan)
                        self._materialize_runtime(fixture)
                        if failure_stage == "executor":
                            capture_failed_state()
                            raise RuntimeError(
                                "unit-secret executor endpoint failure",
                            )
                        return self._valid_evidence()

                    return executor

                def verifier_factory(**_kwargs: object) -> object:
                    def verifier(_plan: object) -> object:
                        if failure_stage == "post-verifier":
                            capture_failed_state()
                            raise RuntimeError(
                                "unit-secret verifier endpoint failure",
                            )
                        return self._valid_post_apply_proof(captured_plan[0])

                    return verifier

                def runtime_runner(
                    args: list[str],
                    **_kwargs: object,
                ) -> object:
                    nonlocal recovery_started
                    self.assertTrue(lock_active)
                    container_id = "a" * 64
                    plan = captured_plan[0]
                    if args == (
                        stalwart_v016
                        .build_migration_recovery_ps_command(plan)
                    ):
                        return stalwart_v016.RedactedCommandResult(
                            (container_id + "\n").encode("ascii"),
                            b"",
                        )
                    if args == (
                        stalwart_v016
                        .build_migration_recovery_container_inspect_command(
                            container_id,
                        )
                    ):
                        return stalwart_v016.RedactedCommandResult(
                            json.dumps(
                                self._valid_recovery_runtime_inspection(
                                    fixture,
                                    plan,
                                    container_id,
                                ),
                            ).encode("utf-8"),
                            b"",
                        )
                    self.assertEqual(
                        args,
                        stalwart_v016.build_bound_container_stop_command(
                            container_id,
                        ),
                    )
                    recovery_started = True
                    events.append("stop")
                    return stalwart_v016.RedactedCommandResult(b"", b"")

                def state_runner(args: list[str]) -> object:
                    if recovery_started and args[:2] == ["docker", "ps"]:
                        self.assertTrue(lock_active)
                        events.append("census")
                    translated = list(args)
                    if translated and translated[0] == sys.executable:
                        translated[0] = "/unit/python3"
                    return fixture.runner(translated)

                def activate(
                    receipt_path: Path,
                    *,
                    expected_receipt_sha256: str,
                ) -> object:
                    nonlocal activations
                    self.assertTrue(lock_active)
                    self.assertEqual(
                        receipt_path,
                        fixture.paths.source_receipt,
                    )
                    self.assertEqual(
                        expected_receipt_sha256,
                        hashlib.sha256(
                            fixture.paths.source_receipt.read_bytes(),
                        ).hexdigest(),
                    )
                    activations += 1
                    events.append("activate")
                    return self._valid_rollback_activation(
                        fixture,
                        expected_receipt_sha256=expected_receipt_sha256,
                    )

                dependencies = replace(
                    stalwart_v016.production_apply_dependencies(),
                    acquire_operation_lock=lambda _root: Lock(),
                    prepare=stalwart_v016.prepare_apply,
                    apply_executor_factory=executor_factory,
                    post_apply_verifier_factory=verifier_factory,
                    state_runner=state_runner,
                    runtime_runner=runtime_runner,
                    recovery_credential_source=lambda: bytearray(
                        b"unit-user:unit-secret",
                    ),
                    rollback_activator=activate,
                )
                with self.assertRaisesRegex(
                    stalwart_v016.MigrationError,
                    r"(?:failed safely|reconciliation is required)",
                ) as raised:
                    stalwart_v016.run_production_apply(
                        fixture.paths,
                        script_path=fixture.paths.migration_script,
                        review_receipt_path=fixture.paths.reviewed,
                        dependencies=dependencies,
                        expected_script_sha256=fixture.script_digest,
                    )

                self.assertTrue(raised.exception.__suppress_context__)
                self.assertNotIn("unit-secret", str(raised.exception))
                self.assertFalse(lock_active)
                self.assertEqual(activations, 1)
                self.assertEqual(events[-3:], ["stop", "census", "activate"])
                self.assertFalse(fixture.paths.apply_receipt.exists())
                self.assertEqual(
                    tuple(fixture.source_store.rglob("*")),
                    failed_state["store_entries"],
                )
                self.assertEqual(
                    (
                        fixture.paths.migration_root
                        / "recovery-config"
                        / "config.json"
                    ).read_bytes(),
                    failed_state["config"],
                )
                self.assertEqual(
                    (
                        fixture.paths.migration_root / "recovery.env"
                    ).read_bytes(),
                    failed_state["environment"],
                )
                self.assertEqual(
                    fixture.paths.export.read_bytes(),
                    failed_state["export"],
                )
                self.assertEqual(
                    fixture.paths.apply_attempt.read_bytes(),
                    failed_state["attempt"],
                )

    def test_production_apply_rollback_activation_fails_closed_on_faults(
        self,
    ) -> None:
        for fault in (
            "stop",
            "census",
            "binding",
            "activator",
            "activation-result",
        ):
            with (
                self.subTest(fault=fault),
                tempfile.TemporaryDirectory() as directory,
            ):
                fixture = self._fixture(directory)
                events: list[str] = []
                captured_plan: list[object] = []
                lock_active = False
                recovery_started = False
                activations = 0

                class Lock:
                    def __enter__(self) -> object:
                        nonlocal lock_active
                        lock_active = True
                        return self

                    def assert_valid_for(self, root: Path) -> None:
                        if not lock_active or root != fixture.repository:
                            raise AssertionError("operation lock is not active")

                    def __exit__(
                        self,
                        _kind: object,
                        _error: object,
                        _traceback: object,
                    ) -> None:
                        nonlocal lock_active
                        lock_active = False

                def prepare(_paths: object, **kwargs: object) -> Path:
                    plan = self._pre_dispatch_plan(fixture)
                    self._publish_apply_attempt(fixture, plan)
                    kwargs["executor"](plan)
                    raise AssertionError("executor failure was not propagated")

                def executor_factory(**_kwargs: object) -> object:
                    def executor(plan: object) -> object:
                        captured_plan.append(plan)
                        self._materialize_runtime(fixture)
                        if fault == "binding":
                            fixture.paths.source_receipt.write_bytes(
                                b'{"tampered":"source receipt"}\n',
                            )
                            fixture.paths.source_receipt.chmod(0o600)
                        raise RuntimeError(
                            "unit-secret runtime endpoint failure",
                        )

                    return executor

                def runtime_runner(
                    args: list[str],
                    **_kwargs: object,
                ) -> object:
                    nonlocal recovery_started
                    self.assertTrue(lock_active)
                    container_id = "a" * 64
                    plan = captured_plan[0]
                    if args == (
                        stalwart_v016
                        .build_migration_recovery_ps_command(plan)
                    ):
                        return stalwart_v016.RedactedCommandResult(
                            (container_id + "\n").encode("ascii"),
                            b"",
                        )
                    if args == (
                        stalwart_v016
                        .build_migration_recovery_container_inspect_command(
                            container_id,
                        )
                    ):
                        return stalwart_v016.RedactedCommandResult(
                            json.dumps(
                                self._valid_recovery_runtime_inspection(
                                    fixture,
                                    plan,
                                    container_id,
                                ),
                            ).encode("utf-8"),
                            b"",
                        )
                    self.assertEqual(
                        args,
                        stalwart_v016.build_bound_container_stop_command(
                            container_id,
                        ),
                    )
                    recovery_started = True
                    events.append("stop")
                    if fault == "stop":
                        raise RuntimeError(
                            "unit-secret stop endpoint failure",
                        )
                    return stalwart_v016.RedactedCommandResult(b"", b"")

                def state_runner(args: list[str]) -> object:
                    if recovery_started and args[:2] == ["docker", "ps"]:
                        self.assertTrue(lock_active)
                        events.append("census")
                        if fault == "census":
                            raise RuntimeError(
                                "unit-secret census endpoint failure",
                            )
                    return fixture.runner(args)

                def activate(
                    _receipt_path: Path,
                    *,
                    expected_receipt_sha256: str,
                ) -> object:
                    nonlocal activations
                    self.assertTrue(lock_active)
                    activations += 1
                    events.append("activate")
                    if fault == "activator":
                        raise RuntimeError(
                            "unit-secret rollback endpoint failure",
                        )
                    if fault == "activation-result":
                        return SimpleNamespace(
                            base_url="http://unit-secret.invalid:18443",
                        )
                    return self._valid_rollback_activation(
                        fixture,
                        expected_receipt_sha256=expected_receipt_sha256,
                    )

                dependencies = replace(
                    stalwart_v016.production_apply_dependencies(),
                    acquire_operation_lock=lambda _root: Lock(),
                    prepare=prepare,
                    apply_executor_factory=executor_factory,
                    post_apply_verifier_factory=lambda **_kwargs: mock.Mock(),
                    state_runner=state_runner,
                    runtime_runner=runtime_runner,
                    recovery_credential_source=lambda: bytearray(
                        b"unit-user:unit-secret",
                    ),
                    rollback_activator=activate,
                )
                with self.assertRaisesRegex(
                    stalwart_v016.MigrationError,
                    "failed safely",
                ) as raised:
                    stalwart_v016.run_production_apply(
                        fixture.paths,
                        script_path=fixture.paths.migration_script,
                        review_receipt_path=fixture.paths.reviewed,
                        dependencies=dependencies,
                        expected_script_sha256=fixture.script_digest,
                    )

                self.assertTrue(raised.exception.__suppress_context__)
                self.assertNotIn("unit-secret", str(raised.exception))
                self.assertNotIn("activated", str(raised.exception))
                self.assertFalse(lock_active)
                self.assertIn("stop", events)
                self.assertIn("census", events)
                if fault in {"stop", "census", "binding"}:
                    self.assertEqual(activations, 0)
                    self.assertNotIn("activate", events)
                else:
                    self.assertEqual(activations, 1)

    def test_production_apply_preserves_cancellation_after_rollback_activation(
        self,
    ) -> None:
        for interruption in (
            KeyboardInterrupt("unit-secret cancellation"),
            SystemExit(73),
        ):
            with (
                self.subTest(interruption=type(interruption).__name__),
                tempfile.TemporaryDirectory() as directory,
            ):
                fixture = self._fixture(directory)
                captured_plan: list[object] = []
                lock_active = False
                activations = 0

                class Lock:
                    def __enter__(self) -> object:
                        nonlocal lock_active
                        lock_active = True
                        return self

                    def assert_valid_for(self, root: Path) -> None:
                        if not lock_active or root != fixture.repository:
                            raise AssertionError("operation lock is not active")

                    def __exit__(
                        self,
                        _kind: object,
                        _error: object,
                        _traceback: object,
                    ) -> None:
                        nonlocal lock_active
                        lock_active = False

                def prepare(_paths: object, **kwargs: object) -> Path:
                    plan = self._pre_dispatch_plan(fixture)
                    self._publish_apply_attempt(fixture, plan)
                    kwargs["executor"](plan)
                    raise AssertionError("cancellation was not propagated")

                def executor_factory(**_kwargs: object) -> object:
                    def executor(plan: object) -> object:
                        captured_plan.append(plan)
                        self._materialize_runtime(fixture)
                        raise interruption

                    return executor

                def runtime_runner(
                    args: list[str],
                    **_kwargs: object,
                ) -> object:
                    container_id = "a" * 64
                    plan = captured_plan[0]
                    if args == (
                        stalwart_v016
                        .build_migration_recovery_ps_command(plan)
                    ):
                        return stalwart_v016.RedactedCommandResult(
                            (container_id + "\n").encode("ascii"),
                            b"",
                        )
                    if args == (
                        stalwart_v016
                        .build_migration_recovery_container_inspect_command(
                            container_id,
                        )
                    ):
                        return stalwart_v016.RedactedCommandResult(
                            json.dumps(
                                self._valid_recovery_runtime_inspection(
                                    fixture,
                                    plan,
                                    container_id,
                                ),
                            ).encode("utf-8"),
                            b"",
                        )
                    self.assertEqual(
                        args,
                        stalwart_v016.build_bound_container_stop_command(
                            container_id,
                        ),
                    )
                    return stalwart_v016.RedactedCommandResult(b"", b"")

                def activate(
                    _receipt_path: Path,
                    *,
                    expected_receipt_sha256: str,
                ) -> object:
                    nonlocal activations
                    self.assertTrue(lock_active)
                    activations += 1
                    return self._valid_rollback_activation(
                        fixture,
                        expected_receipt_sha256=expected_receipt_sha256,
                    )

                dependencies = replace(
                    stalwart_v016.production_apply_dependencies(),
                    acquire_operation_lock=lambda _root: Lock(),
                    prepare=prepare,
                    apply_executor_factory=executor_factory,
                    post_apply_verifier_factory=lambda **_kwargs: mock.Mock(),
                    state_runner=fixture.runner,
                    runtime_runner=runtime_runner,
                    recovery_credential_source=lambda: bytearray(
                        b"unit-user:unit-secret",
                    ),
                    rollback_activator=activate,
                )
                raised: BaseException | None = None
                try:
                    stalwart_v016.run_production_apply(
                        fixture.paths,
                        script_path=fixture.paths.migration_script,
                        review_receipt_path=fixture.paths.reviewed,
                        dependencies=dependencies,
                        expected_script_sha256=fixture.script_digest,
                    )
                except BaseException as error:
                    raised = error

                self.assertIs(raised, interruption)
                self.assertEqual(activations, 1)
                self.assertFalse(lock_active)

    def test_production_apply_predispatch_failure_never_activates_rollback(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            activator = mock.Mock()
            runtime_runner = mock.Mock()
            dependencies = replace(
                stalwart_v016.production_apply_dependencies(),
                prepare=mock.Mock(
                    side_effect=RuntimeError(
                        "unit-secret predispatch failure",
                    ),
                ),
                runtime_runner=runtime_runner,
                rollback_activator=activator,
            )

            with self.assertRaisesRegex(
                stalwart_v016.MigrationError,
                "failed safely",
            ):
                stalwart_v016.run_production_apply(
                    fixture.paths,
                    script_path=fixture.paths.migration_script,
                    review_receipt_path=fixture.paths.reviewed,
                    dependencies=dependencies,
                    expected_script_sha256=fixture.script_digest,
                )

            activator.assert_not_called()
            runtime_runner.assert_not_called()
            self.assertFalse(fixture.paths.apply_attempt.exists())

    def test_frozen_capture_runtime_exposes_verified_rollback_activation_api(
        self,
    ) -> None:
        application = stalwart_v016._load_capture_application()
        activator = application.activate_verified_rollback
        signature = inspect.signature(activator)

        self.assertTrue(callable(activator))
        self.assertEqual(
            tuple(signature.parameters),
            ("receipt_path", "expected_receipt_sha256"),
        )
        self.assertEqual(
            signature.parameters[
                "expected_receipt_sha256"
            ].kind,
            inspect.Parameter.KEYWORD_ONLY,
        )

    def test_production_apply_preserves_cancellation_from_secret_source_and_dispatch(
        self,
    ) -> None:
        for stage, interruption in (
            ("source", KeyboardInterrupt("unit-source-cancellation")),
            ("source", SystemExit(73)),
            ("dispatch", KeyboardInterrupt("unit-dispatch-cancellation")),
            ("dispatch", SystemExit(73)),
        ):
            with (
                self.subTest(
                    stage=stage,
                    cancellation=type(interruption).__name__,
                ),
                tempfile.TemporaryDirectory() as directory,
            ):
                fixture = self._fixture(directory)
                source = bytearray(b"unit-user:unit-secret")
                issued: list[bytearray] = []
                lock_active = False

                class Lock:
                    def __enter__(self) -> object:
                        nonlocal lock_active
                        lock_active = True
                        return self

                    def assert_valid_for(self, _root: Path) -> None:
                        if not lock_active:
                            raise AssertionError("lock was released early")

                    def __exit__(
                        self,
                        _kind: object,
                        _error: object,
                        _traceback: object,
                    ) -> None:
                        nonlocal lock_active
                        lock_active = False

                def source_factory() -> bytearray:
                    if stage == "source":
                        raise interruption
                    return source

                def executor_factory(
                    *,
                    credential_factory: object,
                    runner: object,
                    secret_runner: object,
                    state_runner: object,
                ) -> object:
                    del runner, secret_runner, state_runner

                    def executor(_plan: object) -> object:
                        credential = credential_factory()
                        issued.append(credential)
                        raise interruption

                    return executor

                def prepare(_paths: object, **kwargs: object) -> Path:
                    kwargs["executor"](object())
                    raise AssertionError("cancellation was not propagated")

                dependencies = stalwart_v016.ProductionApplyDependencies(
                    acquire_operation_lock=lambda _root: Lock(),
                    prepare=prepare,
                    apply_executor_factory=executor_factory,
                    post_apply_verifier_factory=lambda **_kwargs: mock.Mock(),
                    state_runner=mock.Mock(),
                    runtime_runner=mock.Mock(),
                    secret_runtime_runner=mock.Mock(),
                    recovery_credential_source=source_factory,
                )
                raised: BaseException | None = None
                try:
                    stalwart_v016.run_production_apply(
                        fixture.paths,
                        script_path=fixture.paths.migration_script,
                        review_receipt_path=fixture.paths.reviewed,
                        dependencies=dependencies,
                        expected_script_sha256=fixture.script_digest,
                    )
                except BaseException as error:
                    raised = error

                self.assertIs(raised, interruption)
                self.assertFalse(lock_active)
                if stage == "dispatch":
                    self.assertTrue(all(value == 0 for value in source))
                    self.assertEqual(len(issued), 1)
                    self.assertTrue(
                        all(value == 0 for value in issued[0]),
                    )

    def test_production_apply_contention_stops_before_any_command_or_secret(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            acquire = mock.Mock(
                side_effect=stalwart_v016.MigrationError(
                    "another Stalwart operation is active",
                ),
            )
            prepare = mock.Mock()
            executor_factory = mock.Mock()
            verifier_factory = mock.Mock()
            state_runner = mock.Mock()
            runtime_runner = mock.Mock()
            secret_runtime_runner = mock.Mock()
            credential_source = mock.Mock()
            dependencies = stalwart_v016.ProductionApplyDependencies(
                acquire_operation_lock=acquire,
                prepare=prepare,
                apply_executor_factory=executor_factory,
                post_apply_verifier_factory=verifier_factory,
                state_runner=state_runner,
                runtime_runner=runtime_runner,
                secret_runtime_runner=secret_runtime_runner,
                recovery_credential_source=credential_source,
            )

            with self.assertRaisesRegex(
                stalwart_v016.MigrationError,
                "another Stalwart operation",
            ):
                stalwart_v016.run_production_apply(
                    fixture.paths,
                    script_path=fixture.paths.migration_script,
                    review_receipt_path=fixture.paths.reviewed,
                    dependencies=dependencies,
                    expected_script_sha256=fixture.script_digest,
                )

            acquire.assert_called_once_with(fixture.repository)
            prepare.assert_not_called()
            executor_factory.assert_not_called()
            verifier_factory.assert_not_called()
            state_runner.assert_not_called()
            runtime_runner.assert_not_called()
            secret_runtime_runner.assert_not_called()
            credential_source.assert_not_called()

    def test_production_apply_fixed_validators_reject_path_substitutions_before_commands(
        self,
    ) -> None:
        substitutions = (
            ("script", lambda fixture: fixture.repository / "other.py"),
            (
                "non-normalized-script",
                lambda fixture: (
                    fixture.paths.migration_root
                    / "child"
                    / ".."
                    / fixture.paths.migration_script.name
                ),
            ),
            ("review", lambda fixture: fixture.repository / "other-review.json"),
        )
        for label, substitute in substitutions:
            with (
                self.subTest(label=label),
                tempfile.TemporaryDirectory() as directory,
            ):
                fixture = self._fixture(directory)
                state_runner = mock.Mock()
                runtime_runner = mock.Mock()
                credential_source = mock.Mock()
                dependencies = replace(
                    stalwart_v016.production_apply_dependencies(),
                    state_runner=state_runner,
                    runtime_runner=runtime_runner,
                    recovery_credential_source=credential_source,
                )
                script = fixture.paths.migration_script
                reviewed = fixture.paths.reviewed
                if label == "review":
                    reviewed = substitute(fixture)
                else:
                    script = substitute(fixture)

                with self.assertRaisesRegex(
                    stalwart_v016.MigrationError,
                    "fixed repository path",
                ):
                    stalwart_v016.run_production_apply(
                        fixture.paths,
                        script_path=script,
                        review_receipt_path=reviewed,
                        dependencies=dependencies,
                        expected_script_sha256=fixture.script_digest,
                    )

                state_runner.assert_not_called()
                runtime_runner.assert_not_called()
                credential_source.assert_not_called()

    def test_production_apply_preserves_receipt_and_attempt_refusal_semantics(
        self,
    ) -> None:
        cases = (
            ("receipt", "already exists"),
            ("attempt", "reconciliation"),
        )
        for case, message in cases:
            with (
                self.subTest(case=case),
                tempfile.TemporaryDirectory() as directory,
            ):
                fixture = self._fixture(directory)
                target = (
                    fixture.paths.apply_receipt
                    if case == "receipt"
                    else fixture.paths.apply_attempt
                )
                original = b'{"preexisting":"preserve"}\n'
                self._write_0600(target, original)
                state_runner = mock.Mock()
                runtime_runner = mock.Mock()
                credential_source = mock.Mock()
                dependencies = replace(
                    stalwart_v016.production_apply_dependencies(),
                    state_runner=state_runner,
                    runtime_runner=runtime_runner,
                    recovery_credential_source=credential_source,
                )

                with self.assertRaisesRegex(
                    stalwart_v016.MigrationError,
                    message,
                ):
                    stalwart_v016.run_production_apply(
                        fixture.paths,
                        script_path=fixture.paths.migration_script,
                        review_receipt_path=fixture.paths.reviewed,
                        dependencies=dependencies,
                        expected_script_sha256=fixture.script_digest,
                    )

                self.assertEqual(target.read_bytes(), original)
                state_runner.assert_not_called()
                runtime_runner.assert_not_called()
                credential_source.assert_not_called()

    def _validate_receipt(self, fixture: SimpleNamespace) -> dict[str, object]:
        paths = fixture.paths
        return stalwart_v016.validate_apply_receipt(
            paths,
            paths.apply_receipt,
            source_receipt_path=paths.source_receipt,
            script_path=paths.migration_script,
            dry_run_receipt_path=paths.dry_run_receipt,
            review_receipt_path=paths.reviewed,
            runner=fixture.runner,
            python_executable="/unit/python3",
            expected_script_sha256=fixture.script_digest,
        )

    def _applied_fixture(
        self,
        directory: str,
        *,
        compose_project: str = "mail-sandbox",
        base_compose_content: str | None = None,
        operations: tuple[tuple[str, str], ...] = (
            ("create", "principal/unit-fixture"),
            ("update", "domain/unit.example"),
        ),
    ) -> SimpleNamespace:
        fixture = self._fixture(
            directory,
            compose_project=compose_project,
            base_compose_content=base_compose_content,
            operations=operations,
        )
        self._prepare(
            fixture,
            lambda _plan: self._valid_evidence(
                operations=fixture.operations,
            ),
        )
        self._materialize_bootstrap_receipt(fixture)
        fixture.events.clear()
        return fixture

    def test_dynamic_public_url_is_absent_from_migration_receipt_payloads(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._applied_fixture(directory)

            for receipt in (
                fixture.paths.source_receipt,
                fixture.paths.dry_run_receipt,
                fixture.paths.reviewed,
                fixture.paths.apply_attempt,
                fixture.paths.apply_receipt,
                fixture.paths.bootstrap_receipt,
            ):
                with self.subTest(receipt=receipt.name):
                    document = json.loads(receipt.read_text(encoding="utf-8"))
                    payload = document.get("payload", document)
                    self.assertNotIn(
                        fixture.public_url,
                        json.dumps(payload, sort_keys=True),
                    )

    @staticmethod
    def _bootstrap_identity(path: Path) -> list[int]:
        metadata = path.lstat()
        return [
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mode,
            metadata.st_nlink,
            metadata.st_uid,
            metadata.st_gid,
        ]

    @staticmethod
    def _bootstrap_secret_identity(path: Path) -> list[int]:
        metadata = path.lstat()
        return [
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mode,
            metadata.st_nlink,
            metadata.st_uid,
            metadata.st_gid,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        ]

    def _bootstrap_file_metadata(
        self,
        path: Path,
        *,
        include_digest: bool = True,
    ) -> dict[str, object]:
        content = path.read_bytes()
        value: dict[str, object] = {
            "identity": (
                self._bootstrap_identity(path)
                if include_digest
                else self._bootstrap_secret_identity(path)
            ),
            "name": path.name,
            "size": len(content),
        }
        if include_digest:
            value["sha256"] = hashlib.sha256(content).hexdigest()
        return value

    @staticmethod
    def _bootstrap_permissions() -> dict[str, bool]:
        return {
            name: True
            for name in (
                "authenticate",
                "sysAccountGet",
                "sysAccountQuery",
                "sysAccountCreate",
                "sysAccountUpdate",
                "sysAccountDestroy",
                "sysDomainGet",
                "sysDomainQuery",
                "sysDomainCreate",
                "sysTaskGet",
                "sysTaskQuery",
            )
        }

    @staticmethod
    def _bootstrap_permissions_sha256() -> str:
        permissions = (
            "authenticate",
            "sysAccountGet",
            "sysAccountQuery",
            "sysAccountCreate",
            "sysAccountUpdate",
            "sysAccountDestroy",
            "sysDomainGet",
            "sysDomainQuery",
            "sysDomainCreate",
            "sysTaskGet",
            "sysTaskQuery",
        )
        return hashlib.sha256(
            json.dumps(
                list(permissions),
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8"),
        ).hexdigest()

    def _write_bootstrap_receipt(
        self,
        fixture: SimpleNamespace,
        payload: dict[str, object],
    ) -> None:
        self._write_0600(
            fixture.paths.bootstrap_receipt,
            (
                json.dumps(
                    receipt_envelope(payload),
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                )
                + "\n"
            ).encode("utf-8"),
        )

    def _mutate_bootstrap_receipt(
        self,
        fixture: SimpleNamespace,
        mutate: object,
    ) -> None:
        payload = json.loads(
            json.dumps(fixture.bootstrap_payload),
        )
        mutate(payload)
        self._write_bootstrap_receipt(fixture, payload)

    def _materialize_bootstrap_receipt(
        self,
        fixture: SimpleNamespace,
    ) -> None:
        repository = fixture.repository
        bootstrap_dir = fixture.paths.bootstrap_receipt.parent
        secrets_dir = repository / "debug-dashboard" / ".runtime" / "secrets"
        assets_dir = repository / "stalwart"
        for directory in (bootstrap_dir, secrets_dir, assets_dir):
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            directory.chmod(0o700)

        manifest = assets_dir / "bootstrap-v016.ndjson"
        sieve = assets_dir / "protected-recipients.sieve"
        manifest.write_bytes(b'{"unit":"bootstrap manifest"}\n')
        manifest.chmod(0o644)
        sieve.write_bytes(b'unit-only protected recipient policy\n')
        sieve.chmod(0o644)

        checkpoints: dict[str, Path] = {}
        for name in ("account", "attempt", "key", "proof"):
            path = bootstrap_dir / f"bootstrap-{name}.json"
            self._write_0600(
                path,
                (json.dumps({"checkpoint": name}) + "\n").encode("utf-8"),
            )
            checkpoints[name] = path

        account_id = "unit-management-account"
        credential_id = "unit-management-key"
        domain_id = "unit-local-domain"
        management_key = secrets_dir / "stalwart-management-api-key"
        management_key_bytes = b"unit-management-api-key-secret"
        self._write_0600(management_key, management_key_bytes)
        protected = bootstrap_dir / "protected-accounts.json"
        protected_payload = {
            "account_ids": [account_id],
            "schema": "mail-sandbox.stalwart-v016-protected-accounts.v1",
        }
        self._write_0600(
            protected,
            (
                json.dumps(
                    protected_payload,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                )
                + "\n"
            ).encode("utf-8"),
        )
        permissions = self._bootstrap_permissions()
        permission_replace = {
            "@type": "Replace",
            "disabledPermissions": {},
            "enabledPermissions": permissions,
        }
        key_permission_replace = {
            "@type": "Replace",
            "permissions": permissions,
        }
        safe_objects = [
            {
                "id": "unit-http-listener",
                "object_type": "NetworkListener",
                "value": {
                    "bind": {"[::]:8080": True},
                    "name": "http",
                    "protocol": "http",
                    "tlsImplicit": False,
                    "useTls": False,
                },
            },
            {
                "id": domain_id,
                "object_type": "Domain",
                "value": {
                    "aliases": {},
                    "allowRelaying": False,
                    "catchAllAddress": None,
                    "certificateManagement": {"@type": "Manual"},
                    "directoryId": None,
                    "dkimManagement": {"@type": "Manual"},
                    "dnsManagement": {"@type": "Manual"},
                    "isEnabled": True,
                    "name": "local.test",
                    "subAddressing": {"@type": "Enabled"},
                },
            },
            {
                "id": "singleton",
                "object_type": "SystemSettings",
                "value": {
                    "defaultDomainId": domain_id,
                    "defaultHostname": "stalwart.local.test",
                },
            },
            {
                "id": "unit-local-route",
                "object_type": "MtaRoute",
                "value": {
                    "@type": "Local",
                    "description": "mail-sandbox local-only delivery",
                    "name": "local",
                },
            },
            {
                "id": "unit-protected-script",
                "object_type": "SieveSystemScript",
                "value": {
                    "contents": (
                        'require ["envelope", "reject"];\n\n'
                        'if envelope :is "to" '
                        '"dashboard-management@local.test" {\n'
                        '    reject "550 5.7.1 Recipient is reserved for '
                        'dashboard management.";\n}\n\n'
                        'if envelope :matches "to" '
                        '"dashboard-management+*@local.test" {\n'
                        '    reject "550 5.7.1 Recipient is reserved for '
                        'dashboard management.";\n}\n'
                    ),
                    "description": (
                        "Reject delivery to the protected dashboard "
                        "management recipient."
                    ),
                    "isActive": True,
                    "name": "mail-sandbox-protected-recipients",
                },
            },
            {
                "id": "singleton",
                "object_type": "MtaStageRcpt",
                "value": {
                    "allowRelaying": {"else": "false", "match": {}},
                    "script": {
                        "else": "'mail-sandbox-protected-recipients'",
                        "match": {},
                    },
                },
            },
            {
                "id": account_id,
                "object_type": "Account",
                "value": {
                    "@type": "User",
                    "aliases": {},
                    "description": (
                        "mail-sandbox/debug-dashboard/management"
                    ),
                    "domainId": domain_id,
                    "name": "dashboard-management",
                    "permissions": permission_replace,
                    "roles": {"@type": "User"},
                },
            },
            {
                "id": credential_id,
                "object_type": "ApiKey",
                "value": {
                    "accountId": account_id,
                    "allowedIps": {},
                    "credentialType": "ApiKey",
                    "description": (
                        "mail-sandbox/debug-dashboard/management"
                    ),
                    "permissions": key_permission_replace,
                },
            },
        ]
        preserved_objects = [
            {
                "id": "singleton",
                "object_type": "MtaOutboundStrategy",
                "value": {
                    "connection": {
                        "else": "'default'",
                        "match": {},
                    },
                    "route": {
                        "else": "'mx'",
                        "match": {
                            "0": {
                                "if": "is_local_domain(rcpt_domain)",
                                "then": "'local'",
                            },
                        },
                    },
                    "schedule": {
                        "else": "'remote'",
                        "match": {
                            "0": {
                                "if": "is_local_domain(rcpt_domain)",
                                "then": "'local'",
                            },
                            "1": {
                                "if": "source == 'dsn'",
                                "then": "'dsn'",
                            },
                            "2": {
                                "if": "source == 'report'",
                                "then": "'report'",
                            },
                        },
                    },
                    "tls": {
                        "else": "'default'",
                        "match": {
                            "0": {
                                "if": (
                                    "retry_num > 0 && "
                                    "last_error == 'tls'"
                                ),
                                "then": "'invalid-tls'",
                            },
                        },
                    },
                },
            },
        ]
        preserved_objects_sha256 = hashlib.sha256(
            json.dumps(
                preserved_objects,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8"),
        ).hexdigest()
        routing_proof_path = (
            bootstrap_dir / "bootstrap-routing-proof.json"
        )
        routing_invocation = "1" * 32
        routing_sender_id = "unit-routing-sender"
        routing_recipient_id = "unit-routing-recipient"
        routing_sender_credential = "unit-routing-sender-app-password"
        routing_recipient_credential = (
            "unit-routing-recipient-app-password"
        )
        routing_sender = (
            f"dashboard-routing-sender-{routing_invocation}@local.test"
        )
        routing_recipient = (
            f"dashboard-routing-recipient-{routing_invocation}@local.test"
        )
        routing_message_id = (
            f"<mail-sandbox-routing-{routing_invocation}@local.test>"
        )

        def rejection_probe(
            recipient: str,
            *,
            enhanced_status: str,
        ) -> dict[str, object]:
            return {
                "delivery_status": "permanentFailure",
                "enhanced_status": enhanced_status,
                "queue_accepted": False,
                "recipient": recipient,
                "smtp_code": 550,
                "submission_created": True,
                "submission_id": "unit-rejected-submission",
                "undo_status": "pending",
            }

        routing_payload = {
            "actors": {
                "recipient": {
                    "account_id": routing_recipient_id,
                    "address": routing_recipient,
                    "app_password_credential_id": (
                        routing_recipient_credential
                    ),
                },
                "sender": {
                    "account_id": routing_sender_id,
                    "address": routing_sender,
                    "app_password_credential_id": (
                        routing_sender_credential
                    ),
                },
            },
            "bootstrap_proof": self._bootstrap_file_metadata(
                checkpoints["proof"],
            ),
            "cleanup": {
                "account_get_not_found": sorted(
                    (routing_sender_id, routing_recipient_id),
                ),
                "address_queries": {
                    routing_recipient: [],
                    routing_sender: [],
                },
                "destroyed_account_ids": sorted(
                    (routing_sender_id, routing_recipient_id),
                ),
            },
            "invocation_id": routing_invocation,
            "management_account_id": account_id,
            "management_credential_id": credential_id,
            "message_id": routing_message_id,
            "preserved_objects_sha256": preserved_objects_sha256,
            "probes": {
                "external": rejection_probe(
                    (
                        "dashboard-routing-external-"
                        f"{routing_invocation}@example.invalid"
                    ),
                    enhanced_status="5.1.2",
                ),
                "registered_local": {
                    "arrival": {
                        "account_id": routing_recipient_id,
                        "matching_email_ids": ["unit-probe-email"],
                        "message_id": routing_message_id,
                    },
                    "delivery_status": "delivered",
                    "enhanced_status": "2.0.0",
                    "queue_accepted": True,
                    "recipient": routing_recipient,
                    "smtp_code": 250,
                    "submission_created": True,
                    "submission_id": "unit-normal-submission",
                    "undo_status": "final",
                },
                "protected_exact": rejection_probe(
                    "dashboard-management@local.test",
                    enhanced_status="5.7.1",
                ),
                "protected_subaddress": rejection_probe(
                    (
                        "dashboard-management+routing-"
                        f"{routing_invocation}@local.test"
                    ),
                    enhanced_status="5.7.1",
                ),
                "unregistered_local": rejection_probe(
                    (
                        "dashboard-routing-unregistered-"
                        f"{routing_invocation}@local.test"
                    ),
                    enhanced_status="5.1.1",
                ),
            },
            "proven_at": "2026-07-28T12:02:29Z",
            "recipient_access_removed": {
                "authentication_status": 401,
                "credential_id": routing_recipient_credential,
                "projected_state": "absent",
                "readiness_preflight": {
                    "blob_upload_calls": 0,
                    "email_submission_calls": 0,
                    "outcome": "blocked-before-network",
                },
            },
            "schema": (
                "mail-sandbox.stalwart-v016-bootstrap-routing-proof.v1"
            ),
            "server_version": "0.16.17",
        }
        self._write_0600(
            routing_proof_path,
            (
                json.dumps(
                    receipt_envelope(routing_payload),
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                )
                + "\n"
            ).encode("utf-8"),
        )
        payload = {
            "apply_receipt": self._bootstrap_file_metadata(
                fixture.paths.apply_receipt,
            ),
            "authentication": {
                "account_id": account_id,
                "server_version": "0.16.17",
                "status": 200,
                "username": "dashboard-management@local.test",
            },
            "checkpoints": {
                name: self._bootstrap_file_metadata(path)
                for name, path in checkpoints.items()
            },
            "completed_at": "2026-07-28T12:02:30Z",
            "credential_inventory": [
                {
                    "account_id": account_id,
                    "allowed_ips": {},
                    "credential_id": credential_id,
                    "credential_type": "ApiKey",
                    "description": (
                        "mail-sandbox/debug-dashboard/management"
                    ),
                    "permissions": key_permission_replace,
                },
            ],
            "inputs": {
                "manifest": self._bootstrap_file_metadata(manifest),
                "sieve": self._bootstrap_file_metadata(sieve),
            },
            "ip_restriction_decision": (
                "disabled-local-only-loopback-network-isolation"
            ),
            "management": {
                "account_id": account_id,
                "address": "dashboard-management@local.test",
                "credential_id": credential_id,
                "key_file": self._bootstrap_file_metadata(
                    management_key,
                    include_digest=False,
                ),
            },
            "permissions_sha256": self._bootstrap_permissions_sha256(),
            "preserved_objects": preserved_objects,
            "protected_accounts": self._bootstrap_file_metadata(protected),
            "routing_proof": self._bootstrap_file_metadata(
                routing_proof_path,
            ),
            "safe_objects": safe_objects,
            "schema": (
                "mail-sandbox.stalwart-v016-bootstrap-receipt.v2"
            ),
            "server_version": "0.16.17",
        }
        self._write_bootstrap_receipt(fixture, payload)
        fixture.bootstrap_payload = payload
        fixture.management_key = management_key
        fixture.management_key_bytes = management_key_bytes
        fixture.routing_payload = routing_payload
        fixture.bootstrap_validation_calls = 0
        fixture.bootstrap_validation_phases = []

        def token_binding(path: Path) -> object:
            metadata = self._bootstrap_file_metadata(path)
            return bootstrap_stalwart_v016.FileBinding(
                path=path,
                sha256=metadata["sha256"],
                size=metadata["size"],
                identity=tuple(metadata["identity"]),
            )

        bootstrap_token = bootstrap_stalwart_v016.ValidatedFinalBootstrap(
            final_receipt=token_binding(fixture.paths.bootstrap_receipt),
            apply_receipt=token_binding(fixture.paths.apply_receipt),
            bootstrap_proof=token_binding(checkpoints["proof"]),
            routing_proof=token_binding(routing_proof_path),
            protected_accounts=token_binding(protected),
            bootstrap_receipt_sha256=hashlib.sha256(
                fixture.paths.bootstrap_receipt.read_bytes(),
            ).hexdigest(),
            apply_receipt_sha256=hashlib.sha256(
                fixture.paths.apply_receipt.read_bytes(),
            ).hexdigest(),
            bootstrap_proof_sha256=hashlib.sha256(
                checkpoints["proof"].read_bytes(),
            ).hexdigest(),
            management_account_id=account_id,
            management_api_key_id=credential_id,
            ip_restriction_decision=(
                "disabled-local-only-loopback-network-isolation"
            ),
            permissions_sha256=self._bootstrap_permissions_sha256(),
            protected_accounts_sha256=hashlib.sha256(
                protected.read_bytes(),
            ).hexdigest(),
            safe_objects_sha256=hashlib.sha256(
                json.dumps(
                    safe_objects,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("utf-8"),
            ).hexdigest(),
            preserved_objects_sha256=preserved_objects_sha256,
            routing_proof_sha256=hashlib.sha256(
                routing_proof_path.read_bytes(),
            ).hexdigest(),
            listener_id="unit-http-listener",
            listener_name="http",
            listener_bind=("[::]:8080",),
            listener_protocol="http",
            listener_use_tls=False,
            listener_tls_implicit=False,
            account_projection_sha256=hashlib.sha256(
                json.dumps(
                    safe_objects[6],
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("utf-8"),
            ).hexdigest(),
            api_key_projection_sha256=hashlib.sha256(
                json.dumps(
                    safe_objects[7],
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("utf-8"),
            ).hexdigest(),
            management_key_name=management_key.name,
            management_key_size=len(management_key_bytes),
            management_key_identity=tuple(
                self._bootstrap_secret_identity(management_key),
            ),
            _marker=(
                bootstrap_stalwart_v016
                ._FINAL_BOOTSTRAP_VALIDATION_MARKER
            ),
        )
        fixture.bootstrap_token = bootstrap_token

        def bootstrap_validator(runtime_phase: str) -> object:
            fixture.bootstrap_validation_calls += 1
            fixture.bootstrap_validation_phases.append(runtime_phase)
            if runtime_phase not in {
                "ready",
                "retired",
                "durable-recovery",
            }:
                raise stalwart_v016.MigrationError(
                    "bootstrap runtime phase differs",
                )
            try:
                envelope = json.loads(
                    fixture.paths.bootstrap_receipt.read_text(
                        encoding="utf-8",
                    ),
                )
                observed_payload = envelope["payload"]
                routing_envelope = json.loads(
                    routing_proof_path.read_text(encoding="utf-8"),
                )
            except (OSError, KeyError, TypeError, json.JSONDecodeError):
                raise stalwart_v016.MigrationError(
                    "bootstrap proof is malformed",
                ) from None
            if (
                observed_payload != fixture.bootstrap_payload
                or routing_envelope.get("payload")
                != fixture.routing_payload
            ):
                raise stalwart_v016.MigrationError(
                    "bootstrap proof differs from authoritative state",
                )
            return bootstrap_token

        fixture.bootstrap_validator = bootstrap_validator

    @staticmethod
    def _valid_retirement_proof(
        plan: object,
        **changes: object,
    ) -> object:
        values: dict[str, object] = {
            "apply_receipt_sha256": plan.apply_receipt.sha256,
            "bootstrap_receipt_sha256": plan.bootstrap_receipt.sha256,
            "bootstrap_proof_sha256": plan.bootstrap.bootstrap_proof_sha256,
            "management_account_id": plan.bootstrap.management_account_id,
            "management_api_key_id": plan.bootstrap.management_api_key_id,
            "ip_restriction_decision": (
                plan.bootstrap.ip_restriction_decision
            ),
            "permissions_sha256": plan.bootstrap.permissions_sha256,
            "protected_accounts_sha256": (
                plan.bootstrap.protected_accounts_sha256
            ),
            "safe_objects_sha256": plan.bootstrap.safe_objects_sha256,
            "preserved_objects_sha256": (
                plan.bootstrap.preserved_objects_sha256
            ),
            "routing_proof_sha256": (
                plan.bootstrap.routing_proof_sha256
            ),
            "listener_id": plan.bootstrap.listener_id,
            "account_projection_sha256": (
                plan.bootstrap.account_projection_sha256
            ),
            "api_key_projection_sha256": (
                plan.bootstrap.api_key_projection_sha256
            ),
            "retirement_attempt_sha256": plan.retirement_attempt.sha256,
            "operation_plan_sha256": plan.operation_plan_sha256,
            "server_version": "0.16.17",
            "management_status": 200,
            "readiness_status": 200,
            "old_recovery_auth_status": 401,
            "normal_url": "http://127.0.0.1:8443",
            "image_reference": "stalwartlabs/stalwart:v0.16.17@sha256:a8108e19bd927e172d4d8c128907b8dfc93fd180ae8ee07dccdd42cb97eb9dfa",
            "image_id": stalwart_v016.STALWART_IMAGE_ID,
            "container_id": "b" * 64,
            "overlapping_writer_ids": ("b" * 64,),
            "migration_container_ids": (),
            "recovery_environment_names": (),
        }
        values.update(changes)
        return stalwart_v016.RecoveryRetirementProof(**values)

    @staticmethod
    def _valid_normal_compose_model(
        fixture: SimpleNamespace,
    ) -> dict[str, object]:
        return {
            "name": fixture.compose_project,
            "networks": {
                "default": {
                    "name": f"{fixture.compose_project}_default",
                    "ipam": {},
                },
            },
            "services": {
                "stalwart": {
                    "command": None,
                    "container_name": "stalwart-dev",
                    "entrypoint": None,
                    "environment": {
                        "STALWART_PUBLIC_URL": (
                            fixture.public_url
                        ),
                    },
                    "healthcheck": {
                        "test": [
                            "CMD",
                            "curl",
                            "-fsS",
                            (
                                "http://127.0.0.1:8080/"
                                "healthz/ready"
                            ),
                        ],
                        "timeout": "2s",
                        "interval": "2s",
                        "retries": 30,
                        "start_period": "2s",
                    },
                    "image": stalwart_v016.STALWART_IMAGE,
                    "networks": {"default": None},
                    "ports": [
                        {
                            "host_ip": "0.0.0.0",
                            "mode": "ingress",
                            "protocol": "tcp",
                            "published": "8443",
                            "target": 8080,
                        },
                        {
                            "host_ip": "0.0.0.0",
                            "mode": "ingress",
                            "protocol": "tcp",
                            "published": "8587",
                            "target": 587,
                        },
                    ],
                    "restart": "unless-stopped",
                    "user": "2000:2000",
                    "volumes": [
                        {
                            "bind": {},
                            "read_only": True,
                            "source": str(
                                fixture.repository
                                / "stalwart"
                            ),
                            "target": "/etc/stalwart",
                            "type": "bind",
                        },
                        {
                            "bind": {},
                            "source": str(fixture.source_store),
                            "target": "/var/lib/stalwart",
                            "type": "bind",
                        },
                    ],
                },
            },
        }

    @staticmethod
    def _valid_normal_inspection(
        fixture: SimpleNamespace,
        container_id: str,
    ) -> dict[str, object]:
        return {
            "Id": container_id,
            "Image": stalwart_v016.STALWART_IMAGE,
            "ImageID": stalwart_v016.STALWART_IMAGE_ID,
            "User": "2000:2000",
            "Project": fixture.compose_project,
            "Service": "stalwart",
            "WorkingDir": str(fixture.repository),
            "ConfigFiles": str(
                fixture.repository / "docker-compose.yml",
            ),
            "Oneoff": "False",
            "Mounts": [
                {
                    "Type": "bind",
                    "Source": str(
                        fixture.repository
                        / "stalwart"
                    ),
                    "Destination": "/etc/stalwart",
                    "RW": False,
                },
                {
                    "Type": "bind",
                    "Source": str(fixture.source_store),
                    "Destination": "/var/lib/stalwart",
                    "RW": True,
                },
            ],
            "Ports": {
                "8080/tcp": [
                    {
                        "HostIp": "0.0.0.0",
                        "HostPort": "8443",
                    },
                ],
                "587/tcp": [
                    {
                        "HostIp": "0.0.0.0",
                        "HostPort": "8587",
                    },
                ],
            },
            "Running": True,
            "Health": "healthy",
            "Environment": sorted(
                stalwart_v016._normal_runtime_environment(
                    fixture.public_url,
                ),
            ),
        }

    def _valid_normal_recovery_inspection(
        self,
        fixture: SimpleNamespace,
        container_id: str,
        *,
        running: bool = True,
        restarting: bool = False,
        health: str = "healthy",
        restart: str = "unless-stopped",
    ) -> dict[str, object]:
        value = self._valid_normal_inspection(
            fixture,
            container_id,
        )
        value.update(
            {
                "Running": running,
                "Restarting": restarting,
                "Health": health,
                "Restart": restart,
            },
        )
        return value

    @staticmethod
    def _valid_normal_census_record(
        fixture: SimpleNamespace,
        container_id: str,
    ) -> dict[str, object]:
        return {
            "Id": container_id,
            "State": {"Running": True},
            "Config": {
                "Env": sorted(
                    stalwart_v016._normal_runtime_environment(
                        fixture.public_url,
                    ),
                ),
                "Labels": {
                    "com.docker.compose.oneoff": "False",
                    "com.docker.compose.project": (
                        fixture.compose_project
                    ),
                    "com.docker.compose.project.config_files": str(
                        fixture.repository / "docker-compose.yml",
                    ),
                    "com.docker.compose.project.working_dir": str(
                        fixture.repository,
                    ),
                    "com.docker.compose.service": "stalwart",
                },
            },
            "Mounts": [
                {
                    "Type": "bind",
                    "Source": str(fixture.source_store),
                    "RW": True,
                },
            ],
        }

    @staticmethod
    def _delete_recovery_artifacts(fixture: SimpleNamespace) -> None:
        paths = fixture.paths
        (paths.migration_root / "recovery.env").unlink()
        config_dir = paths.migration_root / "recovery-config"
        (config_dir / "config.json").unlink()
        config_dir.rmdir()

    def _retire(
        self,
        fixture: SimpleNamespace,
        executor: object,
        *,
        postflight_verifier: object,
        clock: object | None = None,
    ) -> Path:
        paths = fixture.paths
        return stalwart_v016.prepare_recovery_retirement(
            paths,
            source_receipt_path=paths.source_receipt,
            script_path=paths.migration_script,
            dry_run_receipt_path=paths.dry_run_receipt,
            review_receipt_path=paths.reviewed,
            apply_receipt_path=paths.apply_receipt,
            runner=fixture.runner,
            python_executable="/unit/python3",
            executor=executor,
            postflight_verifier=postflight_verifier,
            bootstrap_receipt_validator=fixture.bootstrap_validator,
            clock=(
                (lambda: "2026-07-28T12:03:00Z")
                if clock is None
                else clock
            ),
            expected_script_sha256=fixture.script_digest,
        )

    def _validate_retired_receipt(
        self,
        fixture: SimpleNamespace,
    ) -> dict[str, object]:
        paths = fixture.paths
        return stalwart_v016.validate_recovery_retired_receipt(
            paths,
            paths.recovery_retired_receipt,
            source_receipt_path=paths.source_receipt,
            script_path=paths.migration_script,
            dry_run_receipt_path=paths.dry_run_receipt,
            review_receipt_path=paths.reviewed,
            apply_receipt_path=paths.apply_receipt,
            runner=fixture.runner,
            bootstrap_receipt_validator=fixture.bootstrap_validator,
            python_executable="/unit/python3",
            expected_script_sha256=fixture.script_digest,
        )

    def _retired_fixture(self, directory: str) -> SimpleNamespace:
        fixture = self._applied_fixture(
            directory,
            operations=(("update", "SystemSettings"),),
        )
        proofs: list[object] = []

        def executor(
            plan: object,
            _lease: object,
            checkpoint: object,
        ) -> object:
            proof = self._valid_retirement_proof(plan)
            proofs.append(proof)
            checkpoint(proof)
            self._delete_recovery_artifacts(fixture)
            return proof

        self._retire(
            fixture,
            executor,
            postflight_verifier=lambda _plan: proofs[0],
        )
        fixture.events.clear()
        return fixture

    def _normal_runtime_evidence_dependencies(
        self,
        fixture: SimpleNamespace,
        *,
        validate: object | None = None,
        release: object | None = None,
    ) -> tuple[object, object, list[object], list[Path], list[str]]:
        validation_phases: list[str] = []
        loaded_roots: list[Path] = []
        released_modules: list[object] = []

        class BootstrapPaths:
            @staticmethod
            def for_repository(repository: Path) -> Path:
                self.assertEqual(repository, fixture.repository)
                return repository

        def validate_final(
            bootstrap_paths: Path,
            *,
            task6_validator: object,
        ) -> object:
            self.assertEqual(bootstrap_paths, fixture.repository)
            validation_phases.append("retired")
            if validate is not None:
                return validate(task6_validator)
            task6_validator(fixture.paths.apply_receipt)
            return fixture.bootstrap_token

        module = SimpleNamespace(
            BootstrapPaths=BootstrapPaths,
            validate_final_bootstrap_for_retirement=validate_final,
        )

        def loader(repository: Path) -> object:
            loaded_roots.append(repository)
            return module

        def releaser(selected: object) -> None:
            released_modules.append(selected)
            if release is not None:
                release()

        dependencies = stalwart_v016.NormalRuntimeEvidenceDependencies(
            repository_root=fixture.repository,
            bootstrap_module_loader=loader,
            bootstrap_module_releaser=releaser,
            state_runner=fixture.runner,
            python_executable="/unit/python3",
        )
        return (
            dependencies,
            module,
            released_modules,
            loaded_roots,
            validation_phases,
        )

    @staticmethod
    def _normal_runtime_snapshot(
        name: str,
        content: bytes,
    ) -> object:
        return stalwart_v016.FileSnapshot(
            path=Path("/unit") / name,
            content=content,
            sha256=hashlib.sha256(content).hexdigest(),
            size=len(content),
            identity=(1, 2, 3, 4, 5, 6),
        )

    @staticmethod
    def _normal_runtime_tree_state(
        repository: Path,
    ) -> tuple[tuple[object, ...], ...]:
        state: list[tuple[object, ...]] = []
        for path in sorted(repository.rglob("*")):
            metadata = path.lstat()
            relative = path.relative_to(repository).as_posix()
            digest = (
                hashlib.sha256(path.read_bytes()).hexdigest()
                if stat.S_ISREG(metadata.st_mode)
                else None
            )
            state.append(
                (
                    relative,
                    metadata.st_dev,
                    metadata.st_ino,
                    metadata.st_mode,
                    metadata.st_nlink,
                    metadata.st_size,
                    metadata.st_mtime_ns,
                    digest,
                ),
            )
        return tuple(state)

    def test_normal_runtime_evidence_is_one_exact_canonical_safe_envelope(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._retired_fixture(directory)
            (
                dependencies,
                module,
                released,
                loaded,
                validation_phases,
            ) = self._normal_runtime_evidence_dependencies(fixture)
            observed_bytecode_modes: list[bool] = []
            original_loader = dependencies.bootstrap_module_loader

            def bytecode_observing_loader(repository: Path) -> object:
                observed_bytecode_modes.append(sys.dont_write_bytecode)
                return original_loader(repository)

            dependencies = replace(
                dependencies,
                bootstrap_module_loader=bytecode_observing_loader,
            )
            original_bytecode_mode = sys.dont_write_bytecode
            before_tree = self._normal_runtime_tree_state(
                fixture.repository,
            )
            forbidden_names = (
                "acquire_stalwart_operation_lock",
                "assert_no_running_store_writers",
                "default_rollback_activator",
                "MigrationApplyExecutor",
                "MigrationPostApplyVerifier",
                "prepare_apply",
                "prepare_recovery_retirement",
                "RecoveryRetirementExecutor",
                "RecoveryRetirementPostflightVerifier",
                "run_production_apply",
                "run_production_recovery_retirement",
                "run_fixed_jmap_auth_probe",
                "run_redacted_command",
                "run_redacted_secret_command",
            )
            with ExitStack() as stack:
                task6_factory = stack.enter_context(
                    mock.patch.object(
                        stalwart_v016,
                        "build_bootstrap_apply_receipt_validator",
                        wraps=(
                            stalwart_v016
                            .build_bootstrap_apply_receipt_validator
                        ),
                    ),
                )
                retired_validator = stack.enter_context(
                    mock.patch.object(
                        stalwart_v016,
                        "validate_recovery_retired_receipt",
                        wraps=(
                            stalwart_v016
                            .validate_recovery_retired_receipt
                        ),
                    ),
                )
                forbidden = [
                    stack.enter_context(
                        mock.patch.object(
                            stalwart_v016,
                            name,
                            side_effect=AssertionError(
                                f"forbidden evidence dependency: {name}",
                            ),
                        ),
                    )
                    for name in forbidden_names
                ]
                line = stalwart_v016.build_normal_runtime_evidence(
                    fixture.paths,
                    dependencies=dependencies,
                    expected_script_sha256=fixture.script_digest,
                )
            after_tree = self._normal_runtime_tree_state(
                fixture.repository,
            )

            expected_payload = {
                "schema": (
                    "mail-sandbox.stalwart-v016-normal-runtime-evidence.v2"
                ),
                "management": {
                    "account_id": "unit-management-account",
                    "api_key_id": "unit-management-key",
                    "account_projection": (
                        fixture.bootstrap_payload["safe_objects"][6]
                    ),
                    "api_key_projection": (
                        fixture.bootstrap_payload["safe_objects"][7]
                    ),
                    "credential_inventory": (
                        fixture.bootstrap_payload["credential_inventory"]
                    ),
                },
                "protected_account_ids": ["unit-management-account"],
                "old_recovery_auth_status": 401,
                "migrated_accounts": [],
            }
            expected_line = (
                json.dumps(
                    receipt_envelope(expected_payload),
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                )
                + "\n"
            ).encode("utf-8")
            self.assertEqual(line, expected_line)
            self.assertEqual(loaded, [fixture.repository])
            self.assertEqual(released, [module])
            self.assertGreaterEqual(len(validation_phases), 2)
            self.assertEqual(set(validation_phases), {"retired"})
            self.assertIn("verify", fixture.events)
            self.assertIn("git", fixture.events)
            self.assertNotIn("census", fixture.events)
            self.assertNotIn(fixture.management_key_bytes, line)
            self.assertNotIn(
                hashlib.sha256(fixture.management_key_bytes).hexdigest().encode(),
                line,
            )
            self.assertEqual(before_tree, after_tree)
            self.assertEqual(observed_bytecode_modes, [True])
            self.assertIs(
                sys.dont_write_bytecode,
                original_bytecode_mode,
            )
            for forbidden_call in forbidden:
                forbidden_call.assert_not_called()
            task6_factory.assert_called_once()
            self.assertEqual(
                task6_factory.call_args.kwargs["runtime_phase"],
                "retired",
            )
            self.assertEqual(retired_validator.call_count, 2)
            self.assertEqual(
                set(expected_payload["management"]["account_projection"]),
                {"id", "object_type", "value"},
            )
            self.assertEqual(
                set(expected_payload["management"]["api_key_projection"]),
                {"id", "object_type", "value"},
            )

    def test_normal_runtime_evidence_dependencies_and_paths_are_exact(
        self,
    ) -> None:
        invalid_dependencies = (
            {
                "repository_root": "/unit/repository",
                "bootstrap_module_loader": lambda _root: None,
                "bootstrap_module_releaser": lambda _module: None,
                "state_runner": lambda _args: None,
                "python_executable": "/unit/python3",
            },
            {
                "repository_root": Path("/unit/repository"),
                "bootstrap_module_loader": None,
                "bootstrap_module_releaser": lambda _module: None,
                "state_runner": lambda _args: None,
                "python_executable": "/unit/python3",
            },
            {
                "repository_root": Path("/unit/repository"),
                "bootstrap_module_loader": lambda _root: None,
                "bootstrap_module_releaser": lambda _module: None,
                "state_runner": lambda _args: None,
                "python_executable": "relative/python3",
            },
        )
        for values in invalid_dependencies:
            with self.subTest(values=values):
                with self.assertRaises(stalwart_v016.MigrationError):
                    stalwart_v016.NormalRuntimeEvidenceDependencies(
                        **values,
                    )

        with tempfile.TemporaryDirectory() as directory:
            fixture = self._retired_fixture(directory)
            (
                dependencies,
                _module,
                released,
                loaded,
                _phases,
            ) = self._normal_runtime_evidence_dependencies(fixture)
            escaped = replace(
                fixture.paths,
                export=fixture.repository / "other-export.json",
            )
            with self.assertRaises(stalwart_v016.MigrationError):
                stalwart_v016.build_normal_runtime_evidence(
                    escaped,
                    dependencies=dependencies,
                    expected_script_sha256=fixture.script_digest,
                )
            self.assertEqual(loaded, [])
            self.assertEqual(released, [])
            self.assertEqual(
                repr(dependencies),
                "NormalRuntimeEvidenceDependencies(<redacted>)",
            )

    def test_normal_runtime_evidence_rejects_every_outer_snapshot_replacement(
        self,
    ) -> None:
        target_names = (
            "apply_receipt",
            "bootstrap_receipt",
            "principals",
            "export",
            "retire_recovery_proof",
            "recovery_retired_receipt",
            "protected_accounts",
        )
        for target_name in target_names:
            with self.subTest(target=target_name):
                with tempfile.TemporaryDirectory() as directory:
                    fixture = self._retired_fixture(directory)
                    target = (
                        fixture.paths.bootstrap_receipt.parent
                        / "protected-accounts.json"
                        if target_name == "protected_accounts"
                        else getattr(fixture.paths, target_name)
                    )
                    original = target.read_bytes()

                    def replace_after_validation() -> None:
                        replacement = target.with_name(
                            f".{target.name}.unit-replacement",
                        )
                        self._write_0600(replacement, original)
                        os.replace(replacement, target)

                    (
                        dependencies,
                        _module,
                        released,
                        _loaded,
                        _phases,
                    ) = self._normal_runtime_evidence_dependencies(
                        fixture,
                        release=replace_after_validation,
                    )

                    with self.assertRaises(stalwart_v016.MigrationError):
                        stalwart_v016.build_normal_runtime_evidence(
                            fixture.paths,
                            dependencies=dependencies,
                            expected_script_sha256=fixture.script_digest,
                        )
                    self.assertEqual(len(released), 1)

    def test_normal_runtime_evidence_rejects_outer_content_mutation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._retired_fixture(directory)
            original = fixture.paths.principals.read_bytes()

            def mutate_after_validation() -> None:
                self._write_0600(
                    fixture.paths.principals,
                    original + b" ",
                )

            (
                dependencies,
                _module,
                released,
                _loaded,
                _phases,
            ) = self._normal_runtime_evidence_dependencies(
                fixture,
                release=mutate_after_validation,
            )
            with self.assertRaises(stalwart_v016.MigrationError):
                stalwart_v016.build_normal_runtime_evidence(
                    fixture.paths,
                    dependencies=dependencies,
                    expected_script_sha256=fixture.script_digest,
                )
            self.assertEqual(len(released), 1)

    def test_normal_runtime_evidence_rejects_changed_final_authority(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._retired_fixture(directory)
            (
                dependencies,
                module,
                released,
                _loaded,
                _phases,
            ) = self._normal_runtime_evidence_dependencies(fixture)
            original = stalwart_v016.validate_recovery_retired_receipt
            validations = 0

            def changing_authority(*args: object, **kwargs: object) -> object:
                nonlocal validations
                payload = original(*args, **kwargs)
                validations += 1
                if validations != 2:
                    return payload
                changed = json.loads(json.dumps(payload))
                changed["proof"]["old_recovery_auth_status"] = 403
                return changed

            with (
                mock.patch.object(
                    stalwart_v016,
                    "validate_recovery_retired_receipt",
                    side_effect=changing_authority,
                ),
                self.assertRaises(stalwart_v016.MigrationError),
            ):
                stalwart_v016.build_normal_runtime_evidence(
                    fixture.paths,
                    dependencies=dependencies,
                    expected_script_sha256=fixture.script_digest,
                )

            self.assertEqual(validations, 2)
            self.assertEqual(released, [module])

    def test_normal_runtime_evidence_rejects_changed_final_bootstrap_binding(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._retired_fixture(directory)
            token_validations = 0
            retired_validations = 0

            def changing_token(task6_validator: object) -> object:
                nonlocal token_validations
                task6_validator(fixture.paths.apply_receipt)
                token_validations += 1
                if retired_validations == 1:
                    return fixture.bootstrap_token
                return replace(
                    fixture.bootstrap_token,
                    routing_proof_sha256="f" * 64,
                )

            (
                dependencies,
                module,
                released,
                _loaded,
                _phases,
            ) = self._normal_runtime_evidence_dependencies(
                fixture,
                validate=changing_token,
            )
            original = stalwart_v016.validate_recovery_retired_receipt
            authoritative_payload: object | None = None

            def changed_binding(*args: object, **kwargs: object) -> object:
                nonlocal retired_validations, authoritative_payload
                retired_validations += 1
                if retired_validations == 1:
                    authoritative_payload = original(*args, **kwargs)
                    return authoritative_payload
                kwargs["bootstrap_receipt_validator"]("retired")
                return authoritative_payload

            with (
                mock.patch.object(
                    stalwart_v016,
                    "validate_recovery_retired_receipt",
                    side_effect=changed_binding,
                ),
                self.assertRaises(stalwart_v016.MigrationError),
            ):
                stalwart_v016.build_normal_runtime_evidence(
                    fixture.paths,
                    dependencies=dependencies,
                    expected_script_sha256=fixture.script_digest,
                )

            self.assertEqual(retired_validations, 2)
            self.assertGreaterEqual(token_validations, 2)
            self.assertEqual(released, [module])

    def test_normal_runtime_evidence_releases_loader_on_failure_and_cancellation(
        self,
    ) -> None:
        class UnitCancellation(BaseException):
            pass

        for failure in (
            RuntimeError("unit-secret-validation-failure"),
            UnitCancellation("unit-secret-cancellation"),
        ):
            with self.subTest(failure=type(failure).__name__):
                with tempfile.TemporaryDirectory() as directory:
                    fixture = self._retired_fixture(directory)

                    def fail_after_task6(task6_validator: object) -> object:
                        task6_validator(fixture.paths.apply_receipt)
                        raise failure

                    (
                        dependencies,
                        module,
                        released,
                        _loaded,
                        _phases,
                    ) = self._normal_runtime_evidence_dependencies(
                        fixture,
                        validate=fail_after_task6,
                    )
                    raised: BaseException | None = None
                    try:
                        stalwart_v016.build_normal_runtime_evidence(
                            fixture.paths,
                            dependencies=dependencies,
                            expected_script_sha256=fixture.script_digest,
                        )
                    except BaseException as exc:
                        raised = exc

                    self.assertIsNotNone(raised)
                    self.assertEqual(released, [module])
                    if isinstance(failure, UnitCancellation):
                        self.assertIs(raised, failure)
                    else:
                        self.assertIsInstance(
                            raised,
                            stalwart_v016.MigrationError,
                        )
                        self.assertNotIn(
                            "unit-secret",
                            str(raised),
                        )

    def test_normal_runtime_safe_projection_seam_rejects_missing_extra_and_secret_data(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._applied_fixture(directory)
            protected_bytes = (
                fixture.paths.bootstrap_receipt.parent
                / "protected-accounts.json"
            ).read_bytes()
            protected = self._normal_runtime_snapshot(
                "protected-accounts.json",
                protected_bytes,
            )

            def bootstrap_snapshot(payload: dict[str, object]) -> object:
                content = (
                    json.dumps(
                        receipt_envelope(payload),
                        ensure_ascii=False,
                        separators=(",", ":"),
                        sort_keys=True,
                    )
                    + "\n"
                ).encode("utf-8")
                return self._normal_runtime_snapshot(
                    "bootstrap.json",
                    content,
                )

            def rebound_token(payload: dict[str, object]) -> object:
                safe_objects = payload["safe_objects"]
                account = next(
                    (
                        value
                        for value in safe_objects
                        if value.get("object_type") == "Account"
                    ),
                    {},
                )
                api_key = next(
                    (
                        value
                        for value in safe_objects
                        if value.get("object_type") == "ApiKey"
                    ),
                    {},
                )
                canonical = lambda value: json.dumps(
                    value,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("utf-8")
                return replace(
                    fixture.bootstrap_token,
                    safe_objects_sha256=hashlib.sha256(
                        canonical(safe_objects),
                    ).hexdigest(),
                    account_projection_sha256=hashlib.sha256(
                        canonical(account),
                    ).hexdigest(),
                    api_key_projection_sha256=hashlib.sha256(
                        canonical(api_key),
                    ).hexdigest(),
                )

            cases: dict[str, dict[str, object]] = {}
            missing_account = json.loads(
                json.dumps(fixture.bootstrap_payload),
            )
            missing_account["safe_objects"] = [
                value
                for value in missing_account["safe_objects"]
                if value["object_type"] != "Account"
            ]
            cases["missing-account-wrapper"] = missing_account

            extra_wrapper = json.loads(
                json.dumps(fixture.bootstrap_payload),
            )
            extra_wrapper["safe_objects"][6]["extra"] = True
            cases["extra-account-wrapper-key"] = extra_wrapper

            extra_account = json.loads(
                json.dumps(fixture.bootstrap_payload),
            )
            unexpected_account = json.loads(
                json.dumps(extra_account["safe_objects"][6]),
            )
            unexpected_account["id"] = "unexpected-account"
            extra_account["safe_objects"].append(unexpected_account)
            cases["extra-account-projection"] = extra_account

            missing_inventory = json.loads(
                json.dumps(fixture.bootstrap_payload),
            )
            missing_inventory["credential_inventory"] = []
            cases["missing-inventory"] = missing_inventory

            extra_inventory = json.loads(
                json.dumps(fixture.bootstrap_payload),
            )
            extra_inventory["credential_inventory"][0]["extra"] = True
            cases["extra-inventory-key"] = extra_inventory

            secret_inventory = json.loads(
                json.dumps(fixture.bootstrap_payload),
            )
            secret_inventory["credential_inventory"][0]["secret"] = (
                "unit-secret-must-not-escape"
            )
            cases["secret-inventory"] = secret_inventory

            secret_projection = json.loads(
                json.dumps(fixture.bootstrap_payload),
            )
            secret_projection["safe_objects"][7]["value"]["otpAuth"] = (
                "unit-secret-must-not-escape"
            )
            cases["secret-api-key-projection"] = secret_projection

            for case, payload in cases.items():
                with self.subTest(case=case):
                    with self.assertRaises(
                        stalwart_v016.MigrationError,
                    ) as raised:
                        stalwart_v016._normal_runtime_bootstrap_management(
                            bootstrap_snapshot(payload),
                            protected,
                            rebound_token(payload),
                        )
                    self.assertNotIn(
                        "unit-secret",
                        str(raised.exception),
                    )

            protected_cases = {
                "missing-key": {
                    "schema": (
                        "mail-sandbox.stalwart-v016-protected-accounts.v1"
                    ),
                },
                "extra-key": {
                    "account_ids": ["unit-management-account"],
                    "extra": True,
                    "schema": (
                        "mail-sandbox.stalwart-v016-protected-accounts.v1"
                    ),
                },
                "different-id": {
                    "account_ids": ["other-account"],
                    "schema": (
                        "mail-sandbox.stalwart-v016-protected-accounts.v1"
                    ),
                },
            }
            valid_bootstrap = bootstrap_snapshot(
                fixture.bootstrap_payload,
            )
            for case, value in protected_cases.items():
                with self.subTest(protected=case):
                    content = (
                        json.dumps(
                            value,
                            ensure_ascii=False,
                            separators=(",", ":"),
                            sort_keys=True,
                        )
                        + "\n"
                    ).encode("utf-8")
                    changed_protected = self._normal_runtime_snapshot(
                        "protected-accounts.json",
                        content,
                    )
                    token = replace(
                        fixture.bootstrap_token,
                        protected_accounts_sha256=hashlib.sha256(
                            content,
                        ).hexdigest(),
                    )
                    with self.assertRaises(stalwart_v016.MigrationError):
                        stalwart_v016._normal_runtime_bootstrap_management(
                            valid_bootstrap,
                            changed_protected,
                            token,
                        )

    def test_normal_runtime_retired_status_seam_rejects_missing_extra_and_malformed(
        self,
    ) -> None:
        invalid = (
            {},
            {"proof": []},
            {"proof": {}},
            {"proof": {"old_recovery_auth_status": True}},
            {"proof": {"old_recovery_auth_status": 200}},
            {"proof": {"old_recovery_auth_status": "401"}},
        )
        for value in invalid:
            with self.subTest(value=value):
                with self.assertRaises(stalwart_v016.MigrationError):
                    stalwart_v016._normal_runtime_old_recovery_status(
                        value,
                    )
        for status in (401, 403):
            self.assertEqual(
                stalwart_v016._normal_runtime_old_recovery_status(
                    {
                        "proof": {
                            "old_recovery_auth_status": status,
                            "validated-extra-proof-field": "allowed",
                        },
                    },
                ),
                status,
            )

    def test_normal_runtime_migrated_accounts_bind_domains_canonically(
        self,
    ) -> None:
        principals = [
            {
                "id": 10,
                "name": "local.test",
                "type": "domain",
            },
            {
                "id": 11,
                "name": "alice@local.test",
                "type": "individual",
            },
            {
                "id": 12,
                "name": "alice@other.test",
                "type": "individual",
            },
        ]
        operations = [
            {
                "@type": "create",
                "object": "Domain",
                "value": {
                    "create-0": {
                        "description": "Local test Domain",
                        "logo": "local-test.svg",
                        "name": "local.test",
                    },
                    "create-1": {"name": "other.test"},
                },
            },
            {
                "@type": "create",
                "object": "Account",
                "value": {
                    "restore-11": {
                        "@type": "User",
                        "aliases": {
                            "0": {
                                "domainId": "#create-1",
                                "name": "alice",
                            },
                            "1": {
                                "domainId": "#create-0",
                                "name": "a",
                            },
                        },
                        "credentials": {
                            "0": {
                                "@type": "Password",
                                "secret": "password-secret",
                            },
                        },
                        "domainId": "#create-0",
                        "memberGroupIds": {},
                        "name": "alice",
                        "quotas": {"maxDiskQuota": 123},
                    },
                    "restore-12": {
                        "@type": "User",
                        "aliases": {},
                        "credentials": {},
                        "domainId": "#create-1",
                        "memberGroupIds": {},
                        "name": "alice",
                        "quotas": {},
                    },
                },
            },
        ]
        principals_bytes = (
            json.dumps(principals, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        export_bytes = (
            "\n".join(
                json.dumps(operation, separators=(",", ":"))
                for operation in operations
            )
            + "\n"
        ).encode("utf-8")

        try:
            migrated = stalwart_v016._normal_runtime_migrated_accounts(
                self._normal_runtime_snapshot(
                    "principals.json",
                    principals_bytes,
                ),
                self._normal_runtime_snapshot("export.json", export_bytes),
            )
        except stalwart_v016.MigrationError as exc:
            self.fail(f"pinned Domain projection was rejected: {exc}")

        self.assertEqual(
            migrated,
            [
                {
                    "account_projection": {
                        "@type": "User",
                        "aliases": {
                            "0": {
                                "domainId": "#create-1",
                                "name": "alice",
                            },
                            "1": {
                                "domainId": "#create-0",
                                "name": "a",
                            },
                        },
                        "domainId": "#create-0",
                        "memberGroupIds": {},
                        "name": "alice",
                        "quotas": {"maxDiskQuota": 123},
                    },
                    "credential_projections": [
                        {
                            "slot": "0",
                            "projection": {
                                "@type": "Password",
                                "secret": "****",
                            },
                        },
                    ],
                    "domain_references": [
                        {
                            "client_id": "create-0",
                            "domain_name": "local.test",
                        },
                        {
                            "client_id": "create-1",
                            "domain_name": "other.test",
                        },
                    ],
                },
                {
                    "account_projection": {
                        "@type": "User",
                        "aliases": {},
                        "domainId": "#create-1",
                        "memberGroupIds": {},
                        "name": "alice",
                        "quotas": {},
                    },
                    "credential_projections": [],
                    "domain_references": [
                        {
                            "client_id": "create-1",
                            "domain_name": "other.test",
                        },
                    ],
                },
            ],
        )

    def test_normal_runtime_migrated_accounts_reject_unsupported_principals(
        self,
    ) -> None:
        valid_user = {
            "@type": "User",
            "aliases": {},
            "credentials": {},
            "domainId": "#create-0",
            "memberGroupIds": {},
            "name": "alice",
            "quotas": {},
        }
        domain_operation = {
            "@type": "create",
            "object": "Domain",
            "value": {"create-0": {"name": "local.test"}},
        }
        user_operation = {
            "@type": "create",
            "object": "Account",
            "value": {"restore-7": valid_user},
        }
        cases = {
            "missing-output-individual": (
                [
                    {
                        "id": 7,
                        "name": "alice@local.test",
                        "type": "individual",
                    },
                ],
                [domain_operation],
            ),
            "missing-one-output-individual": (
                [
                    {
                        "id": 7,
                        "name": "alice@local.test",
                        "type": "individual",
                    },
                    {
                        "id": 8,
                        "name": "bob@local.test",
                        "type": "individual",
                    },
                ],
                [domain_operation, user_operation],
            ),
            "source-group": (
                [
                    {
                        "id": 9,
                        "name": "team@local.test",
                        "type": "group",
                    },
                ],
                [domain_operation],
            ),
            "source-tenant": (
                [
                    {
                        "id": 9,
                        "name": "tenant",
                        "type": "tenant",
                    },
                ],
                [domain_operation],
            ),
            "source-list": (
                [
                    {
                        "id": 9,
                        "name": "list@local.test",
                        "type": "list",
                    },
                ],
                [domain_operation],
            ),
            "source-unknown": (
                [
                    {
                        "id": 9,
                        "name": "mystery",
                        "type": "future-principal",
                    },
                ],
                [domain_operation],
            ),
            "output-group": (
                [
                    {
                        "id": 9,
                        "name": "alice@local.test",
                        "type": "individual",
                    },
                ],
                [
                    domain_operation,
                    {
                        "@type": "create",
                        "object": "Account",
                        "value": {
                            "restore-9": {
                                "@type": "Group",
                                "name": "team",
                                "quotas": {},
                            },
                        },
                    },
                ],
            ),
            "output-tenant": (
                [],
                [
                    {
                        "@type": "create",
                        "object": "Tenant",
                        "value": {
                            "create-0": {
                                "name": "tenant",
                                "quotas": {},
                            },
                        },
                    },
                ],
            ),
            "output-mailing-list": (
                [],
                [
                    {
                        "@type": "create",
                        "object": "MailingList",
                        "value": {
                            "create-0": {
                                "aliases": {},
                                "domainId": "#create-1",
                                "name": "list",
                            },
                        },
                    },
                ],
            ),
        }
        for case, (principals, operations) in cases.items():
            with self.subTest(case=case):
                principals_bytes = (
                    json.dumps(principals, separators=(",", ":")) + "\n"
                ).encode("utf-8")
                export_bytes = (
                    "\n".join(
                        json.dumps(operation, separators=(",", ":"))
                        for operation in operations
                    )
                    + "\n"
                ).encode("utf-8")
                with self.assertRaises(stalwart_v016.MigrationError):
                    stalwart_v016._normal_runtime_migrated_accounts(
                        self._normal_runtime_snapshot(
                            "principals.json",
                            principals_bytes,
                        ),
                        self._normal_runtime_snapshot(
                            "export.json",
                            export_bytes,
                        ),
                    )

    def test_normal_runtime_migrated_accounts_reject_unknown_output_object(
        self,
    ) -> None:
        principals_bytes = b"[]\n"
        export_bytes = (
            b'{"@type":"update","object":"FutureObject",'
            b'"value":{"safe":true}}\n'
        )

        with self.assertRaises(stalwart_v016.MigrationError):
            stalwart_v016._normal_runtime_migrated_accounts(
                self._normal_runtime_snapshot(
                    "principals.json",
                    principals_bytes,
                ),
                self._normal_runtime_snapshot("export.json", export_bytes),
            )

    def test_normal_runtime_migrated_accounts_enforce_pinned_shapes(
        self,
    ) -> None:
        principals = [
            {
                "id": 7,
                "name": "alice@local.test",
                "type": "individual",
            },
        ]
        valid_operations = [
            {
                "@type": "create",
                "object": "Domain",
                "value": {"create-0": {"name": "local.test"}},
            },
            {
                "@type": "create",
                "object": "Account",
                "value": {
                    "restore-7": {
                        "@type": "User",
                        "aliases": {
                            "0": {
                                "domainId": "#create-0",
                                "name": "a",
                            },
                        },
                        "credentials": {
                            "0": {
                                "@type": "Password",
                                "secret": "unit-secret",
                            },
                        },
                        "domainId": "#create-0",
                        "memberGroupIds": {},
                        "name": "alice",
                        "quotas": {"maxDiskQuota": 123},
                    },
                },
            },
        ]

        def changed() -> list[dict[str, object]]:
            return json.loads(json.dumps(valid_operations))

        cases: dict[str, list[dict[str, object]]] = {}
        missing_aliases = changed()
        del missing_aliases[1]["value"]["restore-7"]["aliases"]
        cases["missing-required-user-key"] = missing_aliases
        extra_user = changed()
        extra_user[1]["value"]["restore-7"]["displayName"] = "Alice"
        cases["extra-user-key"] = extra_user
        empty_user_description = changed()
        empty_user_description[1]["value"]["restore-7"]["description"] = ""
        cases["empty-user-description"] = empty_user_description
        malformed_alias = changed()
        del malformed_alias[1]["value"]["restore-7"]["aliases"]["0"][
            "domainId"
        ]
        cases["malformed-alias"] = malformed_alias
        alias_gap = changed()
        alias_gap[1]["value"]["restore-7"]["aliases"]["1"] = (
            alias_gap[1]["value"]["restore-7"]["aliases"].pop("0")
        )
        cases["non-contiguous-alias-slot"] = alias_gap
        reversed_aliases = changed()
        aliases = reversed_aliases[1]["value"]["restore-7"]["aliases"]
        aliases["1"] = {
            "domainId": "#create-0",
            "name": "second",
        }
        aliases["0"] = aliases.pop("0")
        cases["out-of-order-alias-slots"] = reversed_aliases
        populated_groups = changed()
        populated_groups[1]["value"]["restore-7"]["memberGroupIds"] = {
            "#restore-9": True,
        }
        cases["unsupported-group-reference"] = populated_groups
        invalid_quota = changed()
        invalid_quota[1]["value"]["restore-7"]["quotas"] = {
            "maxDiskQuota": 0,
        }
        cases["invalid-quota"] = invalid_quota
        wrong_slot = changed()
        wrong_slot[1]["value"]["restore-7"]["credentials"]["1"] = (
            wrong_slot[1]["value"]["restore-7"]["credentials"].pop("0")
        )
        cases["unsupported-credential-slot"] = wrong_slot
        extra_credential = changed()
        extra_credential[1]["value"]["restore-7"]["credentials"]["0"][
            "label"
        ] = "unsafe"
        cases["extra-credential-key"] = extra_credential
        typed_secret = changed()
        typed_secret[1]["value"]["restore-7"]["credentials"]["0"][
            "secret"
        ] = {"value": "unit-secret"}
        cases["non-string-secret"] = typed_secret
        casefold_secret = changed()
        casefold_secret[1]["value"]["restore-7"]["Secret"] = "unit-secret"
        cases["case-insensitive-secret-field"] = casefold_secret
        unknown_primary_domain = changed()
        unknown_primary_domain[1]["value"]["restore-7"][
            "domainId"
        ] = "#create-9"
        cases["unknown-primary-domain-reference"] = unknown_primary_domain
        unknown_alias_domain = changed()
        unknown_alias_domain[1]["value"]["restore-7"]["aliases"]["0"][
            "domainId"
        ] = "#create-9"
        cases["unknown-alias-domain-reference"] = unknown_alias_domain
        forbidden_hash_value = changed()
        forbidden_hash_value[1]["value"]["restore-7"][
            "description"
        ] = "#create-0"
        cases["hash-reference-outside-domain-id"] = forbidden_hash_value
        prefixed_domain_client = changed()
        domain_projection = prefixed_domain_client[0]["value"].pop(
            "create-0",
        )
        prefixed_domain_client[0]["value"][
            "#create-0"
        ] = domain_projection
        cases["prefixed-domain-creation-client"] = prefixed_domain_client
        non_pinned_domain_client = changed()
        domain_projection = non_pinned_domain_client[0]["value"].pop(
            "create-0",
        )
        non_pinned_domain_client[0]["value"][
            "domain-local"
        ] = domain_projection
        non_pinned_domain_client[1]["value"]["restore-7"][
            "domainId"
        ] = "#domain-local"
        non_pinned_domain_client[1]["value"]["restore-7"]["aliases"]["0"][
            "domainId"
        ] = "#domain-local"
        cases["non-pinned-domain-creation-client"] = non_pinned_domain_client
        non_canonical_domain_client = changed()
        domain_projection = non_canonical_domain_client[0]["value"].pop(
            "create-0",
        )
        non_canonical_domain_client[0]["value"][
            "create-00"
        ] = domain_projection
        non_canonical_domain_client[1]["value"]["restore-7"][
            "domainId"
        ] = "#create-00"
        non_canonical_domain_client[1]["value"]["restore-7"]["aliases"]["0"][
            "domainId"
        ] = "#create-00"
        cases["non-canonical-domain-creation-client"] = (
            non_canonical_domain_client
        )
        non_contiguous_domain_client = changed()
        domain_projection = non_contiguous_domain_client[0]["value"].pop(
            "create-0",
        )
        non_contiguous_domain_client[0]["value"][
            "create-1"
        ] = domain_projection
        non_contiguous_domain_client[1]["value"]["restore-7"][
            "domainId"
        ] = "#create-1"
        non_contiguous_domain_client[1]["value"]["restore-7"]["aliases"]["0"][
            "domainId"
        ] = "#create-1"
        cases["non-contiguous-domain-creation-client"] = (
            non_contiguous_domain_client
        )
        reversed_domain_clients = changed()
        reversed_domain_clients[0]["value"] = {
            "create-1": {"name": "other.test"},
            "create-0": {"name": "local.test"},
        }
        cases["out-of-order-domain-creation-clients"] = (
            reversed_domain_clients
        )
        empty_domain_description = changed()
        empty_domain_description[0]["value"]["create-0"][
            "description"
        ] = ""
        cases["empty-domain-description"] = empty_domain_description
        empty_domain_logo = changed()
        empty_domain_logo[0]["value"]["create-0"]["logo"] = ""
        cases["empty-domain-logo"] = empty_domain_logo
        duplicate_domain_name = changed()
        duplicate_domain_name[0]["value"]["create-1"] = {
            "name": "local.test",
        }
        cases["duplicate-domain-name"] = duplicate_domain_name
        out_of_order_domains = changed()
        out_of_order_domains[0]["value"] = {
            "create-0": {"name": "z.test"},
            "create-1": {"name": "a.test"},
        }
        out_of_order_domains[1]["value"]["restore-7"][
            "domainId"
        ] = "#create-0"
        out_of_order_domains[1]["value"]["restore-7"]["aliases"]["0"][
            "domainId"
        ] = "#create-0"
        cases["out-of-order-domain-names"] = out_of_order_domains
        second_domain_batch = changed()
        second_domain_batch.insert(
            1,
            {
                "@type": "create",
                "object": "Domain",
                "value": {"create-1": {"name": "other.test"}},
            },
        )
        cases["second-domain-create"] = second_domain_batch
        tenant_domain = changed()
        tenant_domain[0]["value"]["create-0"][
            "memberTenantId"
        ] = "#tenant"
        cases["unsupported-domain-tenant"] = tenant_domain

        principals_bytes = (
            json.dumps(principals, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        for case, operations in cases.items():
            with self.subTest(case=case):
                export_bytes = (
                    "\n".join(
                        json.dumps(operation, separators=(",", ":"))
                        for operation in operations
                    )
                    + "\n"
                ).encode("utf-8")
                with self.assertRaises(stalwart_v016.MigrationError) as raised:
                    stalwart_v016._normal_runtime_migrated_accounts(
                        self._normal_runtime_snapshot(
                            "principals.json",
                            principals_bytes,
                        ),
                        self._normal_runtime_snapshot(
                            "export.json",
                            export_bytes,
                        ),
                    )
                self.assertNotIn("unit-secret", str(raised.exception))

    def test_normal_runtime_migrated_accounts_preserve_exact_safe_projections(
        self,
    ) -> None:
        principals_secret = "principal-secret-must-not-escape"
        password_secret = "password-secret-must-not-escape"
        otp_secret = "otp-secret-must-not-escape"
        principals = [
            {
                "id": {"integer": 11},
                "name": {"string": "alice@local.test"},
                "secrets": [
                    principals_secret,
                    "$app$source-app-password-must-not-escape",
                ],
                "type": "individual",
            },
            {
                "id": 12,
                "name": ["alice@other.test"],
                "type": "individual",
            },
        ]
        operations = [
            {
                "@type": "create",
                "object": "Domain",
                "value": {
                    "create-0": {
                        "description": " ",
                        "name": "local.test",
                    },
                    "create-1": {
                        "logo": "\t",
                        "name": "other.test",
                    },
                },
            },
            {
                "@type": "create",
                "object": "Account",
                "value": {
                    "restore-11": {
                        "@type": "User",
                        "aliases": {
                            "0": {
                                "domainId": "#create-1",
                                "name": "a",
                            },
                        },
                        "credentials": {
                            "0": {
                                "@type": "Password",
                                "otpAuth": otp_secret,
                                "secret": password_secret,
                            },
                        },
                        "description": "Migrated Alice",
                        "domainId": "#create-0",
                        "memberGroupIds": {},
                        "name": "alice",
                        "quotas": {},
                    },
                    "restore-12": {
                        "@type": "User",
                        "aliases": {},
                        "credentials": {},
                        "description": " ",
                        "domainId": "#create-1",
                        "memberGroupIds": {},
                        "name": "alice",
                        "quotas": {"maxDiskQuota": 123},
                    },
                },
            },
            {
                "@type": "update",
                "object": "SystemSettings",
                "value": {"defaultHostname": "stalwart.local.test"},
            },
            {
                "@type": "create",
                "object": "DkimSignature",
                "value": {
                    "create-2": {
                        "algorithm": "Ed25519",
                        "domainId": "#create-0",
                        "selector": "default",
                    },
                },
            },
            {
                "@type": "create",
                "object": "Certificate",
                "value": {
                    "create-3": {
                        "certificate": "safe-test-certificate",
                    },
                },
            },
        ]
        principals_bytes = (
            json.dumps(principals, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        export_bytes = (
            "\n".join(
                json.dumps(operation, separators=(",", ":"))
                for operation in operations
            )
            + "\n"
        ).encode("utf-8")

        migrated = stalwart_v016._normal_runtime_migrated_accounts(
            self._normal_runtime_snapshot("principals.json", principals_bytes),
            self._normal_runtime_snapshot("export.json", export_bytes),
        )

        self.assertEqual(
            migrated,
            [
                {
                    "account_projection": {
                        "@type": "User",
                        "aliases": {
                            "0": {
                                "domainId": "#create-1",
                                "name": "a",
                            },
                        },
                        "description": "Migrated Alice",
                        "domainId": "#create-0",
                        "memberGroupIds": {},
                        "name": "alice",
                        "quotas": {},
                    },
                    "credential_projections": [
                        {
                            "slot": "0",
                            "projection": {
                                "@type": "Password",
                                "otpAuth": "****",
                                "secret": "****",
                            },
                        },
                    ],
                    "domain_references": [
                        {
                            "client_id": "create-0",
                            "domain_name": "local.test",
                        },
                        {
                            "client_id": "create-1",
                            "domain_name": "other.test",
                        },
                    ],
                },
                {
                    "account_projection": {
                        "@type": "User",
                        "aliases": {},
                        "description": " ",
                        "domainId": "#create-1",
                        "memberGroupIds": {},
                        "name": "alice",
                        "quotas": {"maxDiskQuota": 123},
                    },
                    "credential_projections": [],
                    "domain_references": [
                        {
                            "client_id": "create-1",
                            "domain_name": "other.test",
                        },
                    ],
                },
            ],
        )
        serialized = json.dumps(
            receipt_envelope({"migrated_accounts": migrated}),
            separators=(",", ":"),
            sort_keys=True,
        )
        for secret_value in (
            principals_secret,
            "$app$source-app-password-must-not-escape",
            password_secret,
            otp_secret,
            hashlib.sha256(principals_secret.encode()).hexdigest(),
            hashlib.sha256(
                b"$app$source-app-password-must-not-escape",
            ).hexdigest(),
            hashlib.sha256(password_secret.encode()).hexdigest(),
            hashlib.sha256(otp_secret.encode()).hexdigest(),
        ):
            self.assertNotIn(secret_value, serialized)

    def test_normal_runtime_migrated_accounts_reject_ambiguous_shapes(
        self,
    ) -> None:
        valid_principals = (
            b'[{"id":7,"name":"alice@local.test","type":"individual"}]\n'
        )
        valid_export = (
            b'{"@type":"create","object":"Domain","value":'
            b'{"create-0":{"name":"local.test"}}}\n'
            b'{"@type":"create","object":"Account","value":'
            b'{"restore-7":{"@type":"User","aliases":{},'
            b'"credentials":{},"domainId":"#create-0",'
            b'"memberGroupIds":{},"name":"alice","quotas":{}}}}\n'
        )
        cases = {
            "missing-principal": (
                valid_principals,
                valid_export.replace(b"restore-7", b"restore-8"),
            ),
            "extra-operation-key": (
                valid_principals,
                valid_export.replace(
                    b'"value":',
                    b'"extra":true,"value":',
                ),
            ),
            "missing-credentials": (
                valid_principals,
                valid_export.replace(b'"credentials":{},', b""),
            ),
            "non-object-credentials": (
                valid_principals,
                valid_export.replace(b'"credentials":{}', b'"credentials":[]'),
            ),
            "bool-principal-id": (
                valid_principals.replace(b'"id":7', b'"id":true'),
                valid_export,
            ),
            "wrapped-id-extra": (
                valid_principals.replace(
                    b'"id":7',
                    b'"id":{"integer":7,"extra":true}',
                ),
                valid_export,
            ),
            "duplicate-json-key": (
                valid_principals,
                valid_export.replace(
                    b'"name":"alice"',
                    b'"name":"alice","name":"mallory"',
                ),
            ),
            "unsafe-account-field": (
                valid_principals,
                valid_export.replace(
                    b'"name":"alice"',
                    b'"name":"alice","secret":"must-not-escape"',
                ),
            ),
            "unsafe-credential-token": (
                valid_principals,
                valid_export.replace(
                    b'"credentials":{}',
                    (
                        b'"credentials":{"0":{"@type":"Password",'
                        b'"token":"must-not-escape"}}'
                    ),
                ),
            ),
            "unsupported-app-password": (
                valid_principals,
                valid_export.replace(
                    b'"credentials":{}',
                    (
                        b'"credentials":{"0":{"@type":"AppPassword",'
                        b'"description":"unrelated"}}'
                    ),
                ),
            ),
        }
        for case, (principals_bytes, export_bytes) in cases.items():
            with self.subTest(case=case):
                with self.assertRaises(stalwart_v016.MigrationError) as raised:
                    stalwart_v016._normal_runtime_migrated_accounts(
                        self._normal_runtime_snapshot(
                            "principals.json",
                            principals_bytes,
                        ),
                        self._normal_runtime_snapshot(
                            "export.json",
                            export_bytes,
                        ),
                    )
                self.assertNotIn("must-not-escape", str(raised.exception))

    def test_bootstrap_apply_verifier_revalidates_full_chain_without_writer_census(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._applied_fixture(directory)
            paths = fixture.paths

            validator = stalwart_v016.build_bootstrap_apply_receipt_validator(
                paths,
                source_receipt_path=paths.source_receipt,
                script_path=paths.migration_script,
                dry_run_receipt_path=paths.dry_run_receipt,
                review_receipt_path=paths.reviewed,
                runner=fixture.runner,
                python_executable="/unit/python3",
                expected_script_sha256=fixture.script_digest,
            )
            payload = validator(paths.apply_receipt)

            self.assertEqual(
                payload,
                json.loads(paths.apply_receipt.read_text(encoding="utf-8")),
            )
            self.assertIn("verify", fixture.events)
            self.assertIn("git", fixture.events)
            self.assertNotIn("census", fixture.events)

            fixture.state["stale_source"] = True
            with self.assertRaises(stalwart_v016.MigrationError):
                validator(paths.apply_receipt)

    def test_bootstrap_apply_verifier_requires_explicit_matching_runtime_phase(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._applied_fixture(directory)
            paths = fixture.paths
            common = {
                "source_receipt_path": paths.source_receipt,
                "script_path": paths.migration_script,
                "dry_run_receipt_path": paths.dry_run_receipt,
                "review_receipt_path": paths.reviewed,
                "runner": fixture.runner,
                "python_executable": "/unit/python3",
                "expected_script_sha256": fixture.script_digest,
            }
            ready = stalwart_v016.build_bootstrap_apply_receipt_validator(
                paths,
                runtime_phase="ready",
                **common,
            )
            retired_too_soon = (
                stalwart_v016.build_bootstrap_apply_receipt_validator(
                    paths,
                    runtime_phase="retired",
                    **common,
                )
            )

            self.assertEqual(
                ready(paths.apply_receipt),
                json.loads(
                    paths.apply_receipt.read_text(encoding="utf-8"),
                ),
            )
            with self.assertRaises(stalwart_v016.MigrationError):
                retired_too_soon(paths.apply_receipt)
            with self.assertRaises(stalwart_v016.MigrationError):
                stalwart_v016.build_bootstrap_apply_receipt_validator(
                    paths,
                    runtime_phase="unknown",
                    **common,
                )

            proofs: list[object] = []

            def executor(
                plan: object,
                _lease: object,
                checkpoint: object,
            ) -> object:
                proof = self._valid_retirement_proof(plan)
                proofs.append(proof)
                checkpoint(proof)
                self._delete_recovery_artifacts(fixture)
                return proof

            self._retire(
                fixture,
                executor,
                postflight_verifier=lambda _plan: proofs[0],
            )
            fixture.events.clear()
            resumed_retired = (
                stalwart_v016.build_bootstrap_apply_receipt_validator(
                    paths,
                    runtime_phase="retired",
                    **common,
                )
            )

            with self.assertRaises(stalwart_v016.MigrationError):
                ready(paths.apply_receipt)
            self.assertEqual(
                resumed_retired(paths.apply_receipt),
                json.loads(
                    paths.apply_receipt.read_text(encoding="utf-8"),
                ),
            )
            self.assertNotIn("census", fixture.events)

    def test_retirement_requires_fixed_safe_bootstrap_receipt_before_executor(
        self,
    ) -> None:
        cases = ("missing", "mode", "symlink", "wrong-path")
        for case in cases:
            with (
                self.subTest(case=case),
                tempfile.TemporaryDirectory() as directory,
            ):
                fixture = self._applied_fixture(directory)
                original = fixture.paths.bootstrap_receipt
                if case == "missing":
                    original.unlink()
                elif case == "mode":
                    original.chmod(0o644)
                elif case == "symlink":
                    target = original.with_name("bootstrap-target.json")
                    original.rename(target)
                    original.symlink_to(target)
                else:
                    alternate = original.with_name("bootstrap-other.json")
                    original.rename(alternate)
                    fixture.paths = replace(
                        fixture.paths,
                        bootstrap_receipt=alternate,
                    )
                executor = mock.Mock()
                verifier = mock.Mock()

                with self.assertRaises(stalwart_v016.MigrationError):
                    self._retire(
                        fixture,
                        executor,
                        postflight_verifier=verifier,
                    )

                executor.assert_not_called()
                verifier.assert_not_called()
                self.assertFalse(
                    fixture.paths.retire_recovery_attempt.exists(),
                )

    def test_retirement_rejects_bootstrap_schema_and_semantic_mutations(
        self,
    ) -> None:
        def set_nested(*keys_and_value: object) -> object:
            *keys, value = keys_and_value

            def mutate(payload: dict[str, object]) -> None:
                target: object = payload
                for key in keys[:-1]:
                    target = target[key]  # type: ignore[index]
                target[keys[-1]] = value  # type: ignore[index]

            return mutate

        cases = {
            "schema": set_nested(
                "schema",
                "mail-sandbox.stalwart-v016-bootstrap-receipt.v0",
            ),
            "apply": set_nested(
                "apply_receipt",
                "sha256",
                "a" * 64,
            ),
            "version": set_nested("server_version", "0.16.13"),
            "authentication": set_nested(
                "authentication",
                "status",
                201,
            ),
            "account-id": set_nested(
                "management",
                "account_id",
                "other-account",
            ),
            "api-key-id": set_nested(
                "management",
                "credential_id",
                "other-key",
            ),
            "permissions": set_nested(
                "permissions_sha256",
                "b" * 64,
            ),
            "protected": set_nested(
                "protected_accounts",
                "sha256",
                "c" * 64,
            ),
            "preserved-routing": set_nested(
                "preserved_objects",
                0,
                "value",
                "route",
                "else",
                "'direct'",
            ),
            "routing-proof": set_nested(
                "routing_proof",
                "sha256",
                "d" * 64,
            ),
            "listener": set_nested(
                "safe_objects",
                0,
                "value",
                "useTls",
                True,
            ),
            "account": set_nested(
                "safe_objects",
                6,
                "value",
                "name",
                "other-management",
            ),
            "api-key": set_nested(
                "safe_objects",
                7,
                "value",
                "credentialType",
                "Password",
            ),
            "key-name": set_nested(
                "management",
                "key_file",
                "name",
                "other-key-file",
            ),
            "key-size": set_nested(
                "management",
                "key_file",
                "size",
                1,
            ),
            "key-identity": set_nested(
                "management",
                "key_file",
                "identity",
                [0, 0, 0, 0, 0, 0],
            ),
        }
        for case, mutate in cases.items():
            with (
                self.subTest(case=case),
                tempfile.TemporaryDirectory() as directory,
            ):
                fixture = self._applied_fixture(directory)
                self._mutate_bootstrap_receipt(fixture, mutate)
                executor = mock.Mock()

                with self.assertRaises(stalwart_v016.MigrationError):
                    self._retire(
                        fixture,
                        executor,
                        postflight_verifier=mock.Mock(),
                    )

                executor.assert_not_called()
                self.assertFalse(
                    fixture.paths.retire_recovery_attempt.exists(),
                )

    def test_retirement_requires_authoritative_bootstrap_validation_result(
        self,
    ) -> None:
        for case in ("missing", "mismatched", "wrong-marker"):
            with (
                self.subTest(case=case),
                tempfile.TemporaryDirectory() as directory,
            ):
                fixture = self._applied_fixture(directory)
                if case == "missing":
                    fixture.bootstrap_validator = None
                elif case == "mismatched":
                    fixture.bootstrap_validator = lambda _phase: {
                        "schema": "untrusted-structural-result",
                    }
                else:
                    fixture.bootstrap_validator = lambda _phase: replace(
                        fixture.bootstrap_token,
                        _marker=object(),
                    )
                executor = mock.Mock()

                with self.assertRaises(stalwart_v016.MigrationError):
                    self._retire(
                        fixture,
                        executor,
                        postflight_verifier=mock.Mock(),
                    )

                executor.assert_not_called()
                self.assertFalse(
                    fixture.paths.retire_recovery_attempt.exists(),
                )

    def test_authoritative_bootstrap_token_rejects_duplicate_registered_module(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._applied_fixture(directory)
            trusted = bootstrap_stalwart_v016
            setattr(
                fixture.bootstrap_validator,
                "_trusted_bootstrap_module",
                trusted,
            )
            duplicate = ModuleType(trusted.__name__)
            duplicate.__file__ = trusted.__file__
            duplicate.ValidatedFinalBootstrap = (
                trusted.ValidatedFinalBootstrap
            )
            duplicate._FINAL_BOOTSTRAP_VALIDATION_MARKER = (
                trusted._FINAL_BOOTSTRAP_VALIDATION_MARKER
            )
            executor = mock.Mock()

            with (
                mock.patch.dict(
                    sys.modules,
                    {trusted.__name__: duplicate},
                ),
                self.assertRaises(stalwart_v016.MigrationError),
            ):
                self._retire(
                    fixture,
                    executor,
                    postflight_verifier=mock.Mock(),
                )

            executor.assert_not_called()
            self.assertFalse(
                fixture.paths.retire_recovery_attempt.exists(),
            )

    def test_retirement_rejects_pending_authoritative_ip_decision_before_executor(
        self,
    ) -> None:
        class EqualitySpoof(str):
            def __eq__(self, _other: object) -> bool:
                return True

            def __ne__(self, _other: object) -> bool:
                return False

        for decision in (
            "disabled-local-only-pending-live-network-proof",
            EqualitySpoof(
                "disabled-local-only-pending-live-network-proof",
            ),
        ):
            with (
                self.subTest(decision_type=type(decision).__name__),
                tempfile.TemporaryDirectory() as directory,
            ):
                fixture = self._applied_fixture(directory)
                pending = replace(
                    fixture.bootstrap_token,
                    ip_restriction_decision=decision,
                )
                fixture.bootstrap_validator = lambda _phase: pending
                executor = mock.Mock()
                verifier = mock.Mock()

                with self.assertRaisesRegex(
                    stalwart_v016.MigrationError,
                    "bootstrap token semantics",
                ):
                    self._retire(
                        fixture,
                        executor,
                        postflight_verifier=verifier,
                    )

                executor.assert_not_called()
                verifier.assert_not_called()
                self.assertFalse(
                    fixture.paths.retire_recovery_attempt.exists(),
                )

    def test_bootstrap_atomic_replacement_during_validation_fails_closed(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._applied_fixture(directory)
            original_reader = stalwart_v016._read_regular_snapshot
            bootstrap_reads = 0

            def replacing_reader(path: Path, **kwargs: object) -> object:
                nonlocal bootstrap_reads
                result = original_reader(path, **kwargs)
                if path == fixture.paths.bootstrap_receipt:
                    bootstrap_reads += 1
                    if bootstrap_reads == 1:
                        content = path.read_bytes()
                        path.unlink()
                        self._write_0600(path, content)
                return result

            executor = mock.Mock()
            with (
                mock.patch.object(
                    stalwart_v016,
                    "_read_regular_snapshot",
                    side_effect=replacing_reader,
                ),
                self.assertRaises(stalwart_v016.MigrationError),
            ):
                self._retire(
                    fixture,
                    executor,
                    postflight_verifier=mock.Mock(),
                )

            self.assertGreaterEqual(bootstrap_reads, 2)
            executor.assert_not_called()

    def test_bootstrap_binding_is_checked_at_checkpoint_finalize_and_validation(
        self,
    ) -> None:
        for phase in ("checkpoint", "finalize", "postflight", "validation"):
            with (
                self.subTest(phase=phase),
                tempfile.TemporaryDirectory() as directory,
            ):
                fixture = self._applied_fixture(directory)
                proofs: list[object] = []

                def mutate_receipt() -> None:
                    self._mutate_bootstrap_receipt(
                        fixture,
                        lambda payload: payload.__setitem__(
                            "server_version",
                            "0.16.13",
                        ),
                    )

                def executor(
                    plan: object,
                    _lease: object,
                    checkpoint: object,
                ) -> object:
                    proof = self._valid_retirement_proof(plan)
                    proofs.append(proof)
                    if phase == "checkpoint":
                        mutate_receipt()
                    checkpoint(proof)
                    if phase == "finalize":
                        mutate_receipt()
                    self._delete_recovery_artifacts(fixture)
                    return proof

                def verifier(_plan: object) -> object:
                    if phase == "postflight":
                        mutate_receipt()
                    return proofs[0]

                if phase == "validation":
                    self._retire(
                        fixture,
                        executor,
                        postflight_verifier=verifier,
                    )
                    mutate_receipt()
                    with self.assertRaises(stalwart_v016.MigrationError):
                        self._validate_retired_receipt(fixture)
                else:
                    with self.assertRaises(stalwart_v016.MigrationError):
                        self._retire(
                            fixture,
                            executor,
                            postflight_verifier=verifier,
                        )

    def test_retirement_receipts_bind_bootstrap_without_management_key_material(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._applied_fixture(directory)
            proofs: list[object] = []

            def executor(
                plan: object,
                _lease: object,
                checkpoint: object,
            ) -> object:
                proof = self._valid_retirement_proof(plan)
                proofs.append(proof)
                checkpoint(proof)
                self._delete_recovery_artifacts(fixture)
                return proof

            self._retire(
                fixture,
                executor,
                postflight_verifier=lambda _plan: proofs[0],
            )
            payload = self._validate_retired_receipt(fixture)
            self.assertGreaterEqual(fixture.bootstrap_validation_calls, 6)
            self.assertIn(
                "ready",
                fixture.bootstrap_validation_phases,
            )
            self.assertIn(
                "retired",
                fixture.bootstrap_validation_phases,
            )

            self.assertEqual(
                payload["schema"],
                "mail-sandbox.stalwart-v016-recovery-retired.v3",
            )
            artifacts = (
                fixture.paths.retire_recovery_attempt,
                fixture.paths.retire_recovery_proof,
                fixture.paths.recovery_retired_receipt,
            )
            for artifact in artifacts:
                value = json.loads(artifact.read_text(encoding="utf-8"))
                inner = value.get("payload", value)
                self.assertIn("bootstrap", inner)
                self.assertEqual(
                    inner["bootstrap"]["ip_restriction_decision"],
                    "disabled-local-only-loopback-network-isolation",
                )
                if "proof" in inner:
                    self.assertEqual(
                        inner["proof"]["ip_restriction_decision"],
                        "disabled-local-only-loopback-network-isolation",
                    )
            serialized = b"\n".join(
                artifact.read_bytes() for artifact in artifacts
            )
            self.assertNotIn(b"pending", serialized)
            self.assertNotIn(fixture.management_key_bytes, serialized)
            self.assertNotIn(
                hashlib.sha256(
                    fixture.management_key_bytes,
                ).hexdigest().encode("ascii"),
                serialized,
            )

            payload["schema"] = (
                "mail-sandbox.stalwart-v016-recovery-retired.v1"
            )
            self._write_0600(
                fixture.paths.recovery_retired_receipt,
                (
                    json.dumps(
                        payload,
                        ensure_ascii=False,
                        separators=(",", ":"),
                        sort_keys=True,
                    )
                    + "\n"
                ).encode("utf-8"),
            )
            with self.assertRaises(stalwart_v016.MigrationError):
                self._validate_retired_receipt(fixture)

    def test_retirement_v3_chain_rejects_every_legacy_schema(self) -> None:
        cases = {
            "attempt-v1": (
                "mail-sandbox.stalwart-v016-retire-recovery-attempt.v1"
            ),
            "attempt-v2": (
                "mail-sandbox.stalwart-v016-retire-recovery-attempt.v2"
            ),
            "proof-v1": (
                "mail-sandbox.stalwart-v016-retire-recovery-proof.v1"
            ),
            "proof-v2": (
                "mail-sandbox.stalwart-v016-retire-recovery-proof.v2"
            ),
            "final-v1": "mail-sandbox.stalwart-v016-recovery-retired.v1",
            "final-v2": "mail-sandbox.stalwart-v016-recovery-retired.v2",
        }
        for artifact, legacy_schema in cases.items():
            with (
                self.subTest(artifact=artifact),
                tempfile.TemporaryDirectory() as directory,
            ):
                fixture = self._applied_fixture(directory)
                proofs: list[object] = []

                def executor(
                    plan: object,
                    _lease: object,
                    checkpoint: object,
                ) -> object:
                    proof = self._valid_retirement_proof(plan)
                    proofs.append(proof)
                    checkpoint(proof)
                    self._delete_recovery_artifacts(fixture)
                    return proof

                self._retire(
                    fixture,
                    executor,
                    postflight_verifier=lambda _plan: proofs[0],
                )
                path = {
                    "attempt": fixture.paths.retire_recovery_attempt,
                    "proof": fixture.paths.retire_recovery_proof,
                    "final": fixture.paths.recovery_retired_receipt,
                }[artifact.split("-", 1)[0]]
                value = json.loads(path.read_text(encoding="utf-8"))
                if artifact.startswith("attempt"):
                    value["payload"]["schema"] = legacy_schema
                    value = receipt_envelope(value["payload"])
                else:
                    value["schema"] = legacy_schema
                self._write_0600(
                    path,
                    (
                        json.dumps(
                            value,
                            ensure_ascii=False,
                            separators=(",", ":"),
                            sort_keys=True,
                        )
                        + "\n"
                    ).encode("utf-8"),
                )

                with self.assertRaises(stalwart_v016.MigrationError):
                    self._validate_retired_receipt(fixture)

    def test_runtime_builder_derives_exact_paths_and_only_three_environment_values(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            source = verified_source_fixture(
                fixture.repository,
                fixture.source_store,
            )
            builder = getattr(
                stalwart_v016,
                "build_migration_runtime_paths",
                None,
            )
            validator = getattr(
                stalwart_v016,
                "validate_migration_runtime_paths",
                None,
            )
            self.assertIsNotNone(builder)
            self.assertIsNotNone(validator)
            self.assertEqual(set(inspect.signature(builder).parameters), {"paths", "source"})

            runtime = builder(fixture.paths, source)
            environment = validator(fixture.paths, source, runtime)

            self.assertIsInstance(runtime, stalwart_v016.MigrationRuntimePaths)
            self.assertTrue(runtime.__dataclass_params__.frozen)
            self.assertEqual(repr(runtime), "MigrationRuntimePaths(<redacted>)")
            self.assertEqual(
                set(runtime.__dataclass_fields__),
                {
                    "data_dir",
                    "config_dir",
                    "recovery_env_file",
                    "compose_overlay",
                },
            )
            self.assertEqual(runtime.data_dir, fixture.source_store)
            self.assertEqual(
                runtime.config_dir,
                fixture.paths.migration_root / "recovery-config",
            )
            self.assertEqual(
                runtime.recovery_env_file,
                fixture.paths.migration_root / "recovery.env",
            )
            self.assertEqual(
                runtime.compose_overlay,
                fixture.repository / "docker-compose.stalwart-migration.yml",
            )
            self.assertFalse(runtime.config_dir.exists())
            self.assertFalse(runtime.recovery_env_file.exists())
            self.assertEqual(
                environment,
                {
                    "STALWART_MIGRATION_DATA_DIR": str(fixture.source_store),
                    "STALWART_MIGRATION_CONFIG_DIR": str(runtime.config_dir),
                    "STALWART_MIGRATION_RECOVERY_ENV_FILE": str(
                        runtime.recovery_env_file,
                    ),
                },
            )
            self.assertEqual(runtime.compose_environment(), environment)

    def test_runtime_command_builders_are_exact_and_secret_free(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(
                directory,
                compose_project="dovecot-docker",
            )
            plan = self._pre_dispatch_plan(fixture)
            container_id = "a" * 64
            prefix = [
                "docker",
                "compose",
                "--project-directory",
                str(fixture.repository),
                "--project-name",
                "dovecot-docker",
                "--file",
                str(fixture.repository / "docker-compose.yml"),
                "--file",
                str(
                    fixture.repository
                    / "docker-compose.stalwart-migration.yml",
                ),
            ]

            self.assertEqual(
                stalwart_v016.build_migration_compose_config_command(plan),
                [*prefix, "config", "--quiet"],
            )
            self.assertEqual(
                stalwart_v016.build_migration_compose_start_command(plan),
                [
                    *prefix,
                    "up",
                    "--detach",
                    "--wait",
                    "--force-recreate",
                    "--pull",
                    "never",
                    "stalwart",
                ],
            )
            self.assertEqual(
                stalwart_v016.build_migration_image_inspect_command(),
                [
                    "docker",
                    "image",
                    "inspect",
                    "--format",
                    "{{.Id}}",
                    "stalwartlabs/stalwart:v0.16.17@sha256:a8108e19bd927e172d4d8c128907b8dfc93fd180ae8ee07dccdd42cb97eb9dfa",
                ],
            )
            self.assertEqual(
                stalwart_v016.build_migration_compose_ps_command(plan),
                [*prefix, "ps", "--all", "--quiet", "stalwart"],
            )
            self.assertEqual(
                stalwart_v016.build_migration_compose_stop_command(plan),
                [
                    *prefix,
                    "stop",
                    "--timeout",
                    "30",
                    "stalwart",
                    "stalwart-migration-data-owner",
                ],
            )
            self.assertEqual(
                stalwart_v016.build_migration_recovery_ps_command(plan),
                [
                    "docker",
                    "ps",
                    "--all",
                    "--no-trunc",
                    "--quiet",
                    "--filter",
                    "label=com.docker.compose.project=dovecot-docker",
                ],
            )
            self.assertEqual(
                stalwart_v016.build_bound_container_stop_command(
                    container_id,
                ),
                [
                    "docker",
                    "container",
                    "stop",
                    "--timeout",
                    "30",
                    container_id,
                ],
            )
            self.assertEqual(
                stalwart_v016.build_migration_cli_apply_command(container_id),
                [
                    "docker",
                    "run",
                    "--rm",
                    "--pull",
                    "never",
                    "--network",
                    f"container:{container_id}",
                    "--env",
                    "STALWART_URL",
                    "--env",
                    "STALWART_USER",
                    "--env",
                    "STALWART_PASSWORD",
                    stalwart_v016.STALWART_CLI_IMAGE,
                    "apply",
                    "--stdin",
                    "--json",
                    "--no-color",
                ],
            )
            cli_prefix = [
                "docker",
                "run",
                "--rm",
                "--pull",
                "never",
                "--network",
                f"container:{container_id}",
                "--env",
                "STALWART_URL",
                "--env",
                "STALWART_USER",
                "--env",
                "STALWART_PASSWORD",
                stalwart_v016.STALWART_CLI_IMAGE,
            ]
            self.assertEqual(
                stalwart_v016.build_migration_server_version_command(
                    container_id,
                ),
                [
                    "docker",
                    "exec",
                    container_id,
                    "/usr/local/bin/stalwart",
                    "--version",
                ],
            )
            self.assertEqual(
                stalwart_v016.build_migration_cli_account_query_command(
                    container_id,
                ),
                [
                    *cli_prefix,
                    "query",
                    "Account",
                    "--fields",
                    "id",
                    "--json",
                    "--no-color",
                ],
            )
            inspection = self._valid_runtime_inspection(
                fixture,
                plan,
                container_id,
            )
            stalwart_v016._validate_migration_container_inspection(
                json.dumps(inspection).encode("utf-8"),
                plan=plan,
                container_id=container_id,
            )
            inspection["Project"] = "mail-sandbox"
            with self.assertRaises(stalwart_v016.MigrationError):
                stalwart_v016._validate_migration_container_inspection(
                    json.dumps(inspection).encode("utf-8"),
                    plan=plan,
                    container_id=container_id,
                )

    def test_parent_secret_paths_have_no_immutable_credential_conversions(
        self,
    ) -> None:
        targets = (
            stalwart_v016._generate_production_recovery_credential,
            stalwart_v016._materialize_migration_runtime_artifacts,
            stalwart_v016.MigrationApplyExecutor.__call__,
            stalwart_v016.MigrationPostApplyVerifier.__call__,
        )
        prohibited_secret_calls = {
            "token_hex",
            "token_urlsafe",
            "token_bytes",
        }
        for target in targets:
            with self.subTest(target=target.__qualname__):
                source = textwrap.dedent(inspect.getsource(target))
                tree = ast.parse(source)
                for node in ast.walk(tree):
                    if not isinstance(node, ast.Call):
                        continue
                    if (
                        isinstance(node.func, ast.Name)
                        and node.func.id == "bytes"
                    ):
                        self.fail(
                            f"{target.__qualname__} materializes immutable bytes",
                        )
                    if (
                        isinstance(node.func, ast.Attribute)
                        and isinstance(node.func.value, ast.Name)
                        and node.func.value.id == "secrets"
                        and node.func.attr in prohibited_secret_calls
                    ):
                        self.fail(
                            f"{target.__qualname__} uses immutable secrets output",
                        )

    def test_apply_secret_dispatch_gets_only_a_mutable_view_and_parent_wipes_it(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            plan = self._pre_dispatch_plan(fixture)
            credential = bytearray(b"unit-user:unit-secret")
            container_id = "a" * 64
            inspection = self._valid_runtime_inspection(
                fixture,
                plan,
                container_id,
            )
            captured_views: list[memoryview] = []
            captured_buffers: list[bytearray] = []

            def runner(
                args: list[str],
                **_kwargs: object,
            ) -> object:
                if args == stalwart_v016.build_migration_image_inspect_command():
                    return stalwart_v016.RedactedCommandResult(
                        (stalwart_v016.STALWART_IMAGE_ID + "\n").encode("ascii"),
                        b"",
                    )
                if args == stalwart_v016.build_migration_compose_ps_command(plan):
                    return stalwart_v016.RedactedCommandResult(
                        (container_id + "\n").encode("ascii"),
                        b"",
                    )
                if args[:3] == ["docker", "inspect", "--type"]:
                    return stalwart_v016.RedactedCommandResult(
                        json.dumps(inspection).encode("utf-8"),
                        b"",
                    )
                return stalwart_v016.RedactedCommandResult(b"", b"")

            def secret_runner(
                args: list[str],
                *,
                stdin: bytes,
                env: dict[str, str],
                credential: memoryview,
                timeout: int | float,
                cwd: Path,
            ) -> object:
                del stdin, timeout, cwd
                self.assertEqual(
                    args,
                    stalwart_v016.build_migration_cli_apply_command(
                        container_id,
                    ),
                )
                self.assertEqual(
                    env,
                    {
                        "PATH": stalwart_v016.SAFE_COMMAND_PATH,
                        **self._docker_client_environment(),
                        "STALWART_URL": "http://127.0.0.1:8080",
                    },
                )
                self.assertIs(type(credential), memoryview)
                self.assertTrue(credential.readonly)
                self.assertIs(type(credential.obj), bytearray)
                self.assertNotIn("unit-user", repr(env))
                self.assertNotIn("unit-secret", repr(env))
                captured_views.append(credential)
                captured_buffers.append(credential.obj)
                return stalwart_v016.RedactedCommandResult(
                    self._valid_evidence().encode("utf-8"),
                    b"",
                )

            executor = stalwart_v016.MigrationApplyExecutor(
                runner=runner,
                secret_runner=secret_runner,
                state_runner=fixture.runner,
                credential_factory=lambda: credential,
            )
            with mock.patch.dict(
                os.environ,
                self._docker_client_environment(),
                clear=True,
            ):
                self.assertEqual(executor(plan), self._valid_evidence())

            self.assertEqual(len(captured_views), 1)
            with self.assertRaises(ValueError):
                captured_views[0].tobytes()
            self.assertEqual(captured_buffers, [credential])
            self.assertTrue(all(value == 0 for value in credential))

    def test_wrong_local_stalwart_image_id_blocks_compose_up_in_exact_order(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            plan = self._pre_dispatch_plan(fixture)
            credential = bytearray(b"unit-user:unit-secret")
            calls: list[list[str]] = []

            def runner(
                args: list[str],
                **_kwargs: object,
            ) -> object:
                calls.append(list(args))
                if args == stalwart_v016.build_migration_image_inspect_command():
                    return stalwart_v016.RedactedCommandResult(
                        b"sha256:" + b"0" * 64 + b"\n",
                        b"",
                    )
                return stalwart_v016.RedactedCommandResult(b"", b"")

            executor = stalwart_v016.MigrationApplyExecutor(
                runner=runner,
                state_runner=fixture.runner,
                credential_factory=lambda: credential,
            )
            with self.assertRaisesRegex(
                stalwart_v016.MigrationError,
                "failed safely",
            ):
                executor(plan)

            self.assertEqual(
                calls,
                [
                    stalwart_v016.build_migration_compose_config_command(plan),
                    stalwart_v016.build_migration_image_inspect_command(),
                    stalwart_v016.build_migration_compose_stop_command(plan),
                ],
            )
            self.assertNotIn(
                stalwart_v016.build_migration_compose_start_command(plan),
                calls,
            )
            self.assertTrue(all(value == 0 for value in credential))

    def test_runtime_owner_dispatch_has_an_immediate_clean_writer_census(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            plan = self._pre_dispatch_plan(fixture)
            credential = bytearray(b"unit-user:unit-secret")
            events: list[str] = []

            def state_runner(args: list[str]) -> object:
                events.append("writer-census")
                return fixture.runner(args)

            def runtime_runner(
                args: list[str],
                **_kwargs: object,
            ) -> object:
                if args == stalwart_v016.build_migration_compose_config_command(
                    plan,
                ):
                    events.append("config")
                elif args == stalwart_v016.build_migration_image_inspect_command():
                    events.append("image")
                    return stalwart_v016.RedactedCommandResult(
                        (stalwart_v016.STALWART_IMAGE_ID + "\n").encode("ascii"),
                        b"",
                    )
                elif args == stalwart_v016.build_migration_compose_start_command(
                    plan,
                ):
                    events.append("owner-and-stalwart-start")
                    raise RuntimeError("unit-only start failure")
                elif args == stalwart_v016.build_migration_compose_stop_command(
                    plan,
                ):
                    events.append("stop-both")
                else:
                    self.fail(f"unexpected runtime command: {args!r}")
                return stalwart_v016.RedactedCommandResult(b"", b"")

            self.assertIn(
                "state_runner",
                inspect.signature(
                    stalwart_v016.MigrationApplyExecutor,
                ).parameters,
            )
            executor = stalwart_v016.MigrationApplyExecutor(
                runner=runtime_runner,
                state_runner=state_runner,
                credential_factory=lambda: credential,
            )

            with self.assertRaisesRegex(
                stalwart_v016.MigrationError,
                "failed safely",
            ):
                executor(plan)

            self.assertEqual(
                events,
                [
                    "config",
                    "image",
                    "writer-census",
                    "owner-and-stalwart-start",
                    "stop-both",
                ],
            )
            self.assertTrue(all(value == 0 for value in credential))

    def test_failed_immediate_writer_census_prevents_owner_and_stalwart_start(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            plan = self._pre_dispatch_plan(fixture)
            credential = bytearray(b"unit-user:unit-secret")
            runtime_calls: list[list[str]] = []

            def state_runner(_args: list[str]) -> object:
                raise stalwart_v016.MigrationError(
                    "running writer still targets the source store",
                )

            def runtime_runner(
                args: list[str],
                **_kwargs: object,
            ) -> object:
                runtime_calls.append(list(args))
                if args == stalwart_v016.build_migration_image_inspect_command():
                    return stalwart_v016.RedactedCommandResult(
                        (stalwart_v016.STALWART_IMAGE_ID + "\n").encode("ascii"),
                        b"",
                    )
                return stalwart_v016.RedactedCommandResult(b"", b"")

            self.assertIn(
                "state_runner",
                inspect.signature(
                    stalwart_v016.MigrationApplyExecutor,
                ).parameters,
            )
            executor = stalwart_v016.MigrationApplyExecutor(
                runner=runtime_runner,
                state_runner=state_runner,
                credential_factory=lambda: credential,
            )

            with self.assertRaisesRegex(
                stalwart_v016.MigrationError,
                "failed safely",
            ):
                executor(plan)

            self.assertEqual(
                runtime_calls,
                [
                    stalwart_v016.build_migration_compose_config_command(plan),
                    stalwart_v016.build_migration_image_inspect_command(),
                    stalwart_v016.build_migration_compose_stop_command(plan),
                ],
            )
            self.assertNotIn(
                stalwart_v016.build_migration_compose_start_command(plan),
                runtime_calls,
            )
            self.assertTrue(all(value == 0 for value in credential))

    def test_runtime_apply_executor_orders_exact_commands_stdin_env_and_stop(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            plan = self._pre_dispatch_plan(fixture)
            credential = bytearray(b"unit-user:unit-secret")
            container_id = "a" * 64
            calls: list[dict[str, object]] = []
            running = False
            inspection = self._valid_runtime_inspection(
                fixture,
                plan,
                container_id,
            )

            def runner(
                args: list[str],
                *,
                stdin: bytes,
                env: dict[str, str],
                timeout: int | float,
                cwd: Path,
                credential: memoryview | None = None,
            ) -> object:
                nonlocal running
                calls.append(
                    {
                        "args": list(args),
                        "stdin": stdin,
                        "env": dict(env),
                        "timeout": timeout,
                        "cwd": cwd,
                        "has_credential": credential is not None,
                    },
                )
                if args == stalwart_v016.build_migration_image_inspect_command():
                    return stalwart_v016.RedactedCommandResult(
                        (stalwart_v016.STALWART_IMAGE_ID + "\n").encode("ascii"),
                        b"",
                    )
                if args == stalwart_v016.build_migration_compose_start_command(plan):
                    running = True
                    return stalwart_v016.RedactedCommandResult(b"", b"")
                if args == stalwart_v016.build_migration_compose_ps_command(plan):
                    return stalwart_v016.RedactedCommandResult(
                        (container_id + "\n").encode("ascii"),
                        b"",
                    )
                if args[:3] == ["docker", "inspect", "--type"]:
                    return stalwart_v016.RedactedCommandResult(
                        json.dumps(inspection).encode("utf-8") + b"\n",
                        b"",
                    )
                if args == stalwart_v016.build_migration_cli_apply_command(
                    container_id,
                ):
                    self.assertTrue(running)
                    return stalwart_v016.RedactedCommandResult(
                        self._valid_evidence().encode("utf-8"),
                        b"",
                    )
                if args == stalwart_v016.build_migration_compose_stop_command(plan):
                    running = False
                    return stalwart_v016.RedactedCommandResult(b"", b"")
                return stalwart_v016.RedactedCommandResult(b"", b"")

            executor = stalwart_v016.MigrationApplyExecutor(
                runner=runner,
                secret_runner=runner,
                state_runner=fixture.runner,
                credential_factory=lambda: credential,
            )
            docker_environment = self._docker_client_environment()
            with mock.patch.dict(
                os.environ,
                {
                    **docker_environment,
                    "STALWART_TOKEN": "ambient-secret",
                    "STALWART_PASSWORD": "ambient-password",
                    "UNRELATED_SECRET": "must-not-propagate",
                },
                clear=True,
            ):
                evidence = executor(plan)

            self.assertEqual(evidence, self._valid_evidence())
            self.assertFalse(running)
            self.assertTrue(all(value == 0 for value in credential))
            self.assertEqual(
                plan.runtime.config_dir.stat().st_mode & 0o777,
                0o755,
            )
            config_file = plan.runtime.config_dir / "config.json"
            self.assertEqual(config_file.stat().st_mode & 0o777, 0o644)
            self.assertEqual(
                config_file.read_bytes(),
                fixture.paths.converted_config.read_bytes(),
            )
            self.assertEqual(
                plan.runtime.recovery_env_file.stat().st_mode & 0o777,
                0o600,
            )
            self.assertEqual(
                plan.runtime.recovery_env_file.read_bytes(),
                b"STALWART_RECOVERY_ADMIN=unit-user:unit-secret\n",
            )
            secret_bearing_runtime_files = [
                path
                for path in plan.runtime.config_dir.parent.rglob("*")
                if path.is_file()
                and b"unit-secret" in path.read_bytes()
            ]
            self.assertEqual(
                secret_bearing_runtime_files,
                [plan.runtime.recovery_env_file],
            )
            self.assertTrue(
                all(
                    stat.S_IMODE(path.stat().st_mode) == 0o600
                    for path in secret_bearing_runtime_files
                ),
            )
            self.assertEqual(
                [call["args"] for call in calls],
                [
                    stalwart_v016.build_migration_compose_config_command(plan),
                    stalwart_v016.build_migration_image_inspect_command(),
                    stalwart_v016.build_migration_compose_start_command(plan),
                    stalwart_v016.build_migration_compose_ps_command(plan),
                    stalwart_v016.build_migration_container_inspect_command(
                        container_id,
                    ),
                    stalwart_v016.build_migration_cli_apply_command(
                        container_id,
                    ),
                    stalwart_v016.build_migration_compose_stop_command(plan),
                ],
            )
            compose_environment = {
                "PATH": stalwart_v016.SAFE_COMMAND_PATH,
                **docker_environment,
                **plan.runtime.compose_environment(),
            }
            for call in (*calls[:5], calls[-1]):
                self.assertEqual(call["stdin"], b"")
                self.assertEqual(call["env"], compose_environment)
                self.assertEqual(call["cwd"], fixture.repository)
                self.assertFalse(call["has_credential"])
                self.assertNotIn("STALWART_TOKEN", call["env"])
                self.assertNotIn("UNRELATED_SECRET", call["env"])
            cli_call = calls[5]
            self.assertEqual(
                cli_call["stdin"],
                fixture.paths.export.read_bytes(),
            )
            self.assertEqual(
                cli_call["env"],
                {
                    "PATH": stalwart_v016.SAFE_COMMAND_PATH,
                    **docker_environment,
                    "STALWART_URL": "http://127.0.0.1:8080",
                },
            )
            self.assertTrue(cli_call["has_credential"])
            self.assertNotIn("STALWART_TOKEN", cli_call["env"])
            self.assertNotIn("UNRELATED_SECRET", cli_call["env"])
            self.assertEqual(cli_call["cwd"], fixture.repository)

    def test_runtime_environment_rejects_malformed_docker_client_values_before_runner(
        self,
    ) -> None:
        malformed_environments: dict[str, dict[str, object]] = {
            "relative-home": {"HOME": "relative/home"},
            "context": {"DOCKER_CONTEXT": "bad/context"},
            "tls": {"DOCKER_TLS_VERIFY": "yes"},
            "api": {"DOCKER_API_VERSION": "latest"},
            "newline": {"DOCKER_HOST": "tcp://127.0.0.1:2376\n"},
            "relative-socket": {"SSH_AUTH_SOCK": "agent.socket"},
            "non-string": {"DOCKER_CONFIG": 7},
            "overlong": {"DOCKER_HOST": "x" * 4097},
        }
        for case, environment in malformed_environments.items():
            with self.subTest(case=case):
                with tempfile.TemporaryDirectory() as directory:
                    fixture = self._fixture(directory)
                    plan = self._pre_dispatch_plan(fixture)
                    runner = mock.Mock()
                    credential_factory = mock.Mock(
                        return_value=bytearray(b"unit-user:unit-secret"),
                    )
                    executor = stalwart_v016.MigrationApplyExecutor(
                        runner=runner,
                        state_runner=fixture.runner,
                        credential_factory=credential_factory,
                    )
                    with (
                        mock.patch.object(
                            stalwart_v016.os,
                            "environ",
                            environment,
                        ),
                        self.assertRaises(stalwart_v016.MigrationError),
                    ):
                        executor(plan)

                    runner.assert_not_called()
                    credential_factory.assert_not_called()
                    self.assertFalse(plan.runtime.config_dir.exists())
                    self.assertFalse(plan.runtime.recovery_env_file.exists())

    def test_runtime_environment_refuses_operation_overrides_of_client_or_path(
        self,
    ) -> None:
        docker_environment = self._docker_client_environment()
        with mock.patch.object(
            stalwart_v016.os,
            "environ",
            docker_environment,
        ):
            for name in ("PATH", "HOME", "DOCKER_HOST", "SSH_AUTH_SOCK"):
                with self.subTest(name=name):
                    with self.assertRaises(stalwart_v016.MigrationError):
                        stalwart_v016._runtime_command_environment(
                            {name: "unit-override"},
                        )

    def test_runtime_apply_executor_stops_and_redacts_every_failure_stage(
        self,
    ) -> None:
        for failure_stage in (
            "credential",
            "config",
            "image",
            "start",
            "ps",
            "inspect",
            "apply",
            "apply-mutation",
            "stop",
        ):
            with self.subTest(failure_stage=failure_stage):
                with tempfile.TemporaryDirectory() as directory:
                    fixture = self._fixture(directory)
                    plan = self._pre_dispatch_plan(fixture)
                    credential = (
                        bytearray(b"malformed-unit-secret")
                        if failure_stage == "credential"
                        else bytearray(b"unit-user:unit-secret")
                    )
                    container_id = "a" * 64
                    inspection = self._valid_runtime_inspection(
                        fixture,
                        plan,
                        container_id,
                    )
                    calls: list[list[str]] = []

                    def runner(
                        args: list[str],
                        *,
                        stdin: bytes,
                        env: dict[str, str],
                        timeout: int | float,
                        cwd: Path,
                        credential: memoryview | None = None,
                    ) -> object:
                        del stdin, env, timeout, cwd, credential
                        calls.append(list(args))
                        if (
                            args
                            == stalwart_v016.build_migration_compose_config_command(
                                plan,
                            )
                            and failure_stage == "config"
                        ):
                            raise RuntimeError("unit-secret config stderr")
                        if (
                            args
                            == stalwart_v016.build_migration_image_inspect_command()
                        ):
                            if failure_stage == "image":
                                return stalwart_v016.RedactedCommandResult(
                                    b"sha256:" + b"0" * 64 + b"\n",
                                    b"",
                                )
                            return stalwart_v016.RedactedCommandResult(
                                (
                                    stalwart_v016.STALWART_IMAGE_ID + "\n"
                                ).encode("ascii"),
                                b"",
                            )
                        if (
                            args
                            == stalwart_v016.build_migration_compose_start_command(
                                plan,
                            )
                            and failure_stage == "start"
                        ):
                            raise RuntimeError("unit-secret start stderr")
                        if args == stalwart_v016.build_migration_compose_ps_command(
                            plan,
                        ):
                            stdout = (
                                b"not-a-container\n"
                                if failure_stage == "ps"
                                else (container_id + "\n").encode("ascii")
                            )
                            return stalwart_v016.RedactedCommandResult(stdout, b"")
                        if args[:3] == ["docker", "inspect", "--type"]:
                            stdout = (
                                b'{"unit-secret":"bad"}\n'
                                if failure_stage == "inspect"
                                else json.dumps(inspection).encode("utf-8") + b"\n"
                            )
                            return stalwart_v016.RedactedCommandResult(stdout, b"")
                        if args == stalwart_v016.build_migration_cli_apply_command(
                            container_id,
                        ):
                            if failure_stage == "apply-mutation":
                                self._write_0600(
                                    fixture.paths.export,
                                    fixture.paths.export.read_bytes() + b" ",
                                )
                            stdout = (
                                b"unit-secret invalid evidence"
                                if failure_stage == "apply"
                                else self._valid_evidence().encode("utf-8")
                            )
                            return stalwart_v016.RedactedCommandResult(stdout, b"")
                        if args == stalwart_v016.build_migration_compose_stop_command(
                            plan,
                        ) and failure_stage == "stop":
                            raise RuntimeError("unit-secret stop stderr")
                        return stalwart_v016.RedactedCommandResult(b"", b"")

                    executor = stalwart_v016.MigrationApplyExecutor(
                        runner=runner,
                        secret_runner=runner,
                        state_runner=fixture.runner,
                        credential_factory=lambda: credential,
                    )
                    with self.assertRaises(
                        stalwart_v016.MigrationError,
                    ) as raised:
                        executor(plan)

                    self.assertEqual(
                        str(raised.exception),
                        "migration apply execution failed safely",
                    )
                    self.assertNotIn("unit-secret", str(raised.exception))
                    self.assertIsNone(raised.exception.__cause__)
                    self.assertIsNone(raised.exception.__context__)
                    self.assertTrue(all(value == 0 for value in credential))
                    self.assertEqual(
                        calls[-1],
                        stalwart_v016.build_migration_compose_stop_command(plan),
                    )

    def test_runtime_apply_executor_preserves_cancellation_identity_and_stops(
        self,
    ) -> None:
        for cancellation_kind in ("keyboard-interrupt", "system-exit"):
            for cancellation_stage in (
                "config",
                "image",
                "start",
                "ps",
                "inspect",
                "apply",
                "stop",
            ):
                with self.subTest(
                    cancellation_kind=cancellation_kind,
                    cancellation_stage=cancellation_stage,
                ):
                    with tempfile.TemporaryDirectory() as directory:
                        fixture = self._fixture(directory)
                        plan = self._pre_dispatch_plan(fixture)
                        credential = bytearray(b"unit-user:unit-secret")
                        container_id = "a" * 64
                        inspection = self._valid_runtime_inspection(
                            fixture,
                            plan,
                            container_id,
                        )
                        commands = {
                            "config": (
                                stalwart_v016.build_migration_compose_config_command(
                                    plan,
                                )
                            ),
                            "image": (
                                stalwart_v016.build_migration_image_inspect_command()
                            ),
                            "start": (
                                stalwart_v016.build_migration_compose_start_command(
                                    plan,
                                )
                            ),
                            "ps": stalwart_v016.build_migration_compose_ps_command(
                                plan,
                            ),
                            "inspect": (
                                stalwart_v016.build_migration_container_inspect_command(
                                    container_id,
                                )
                            ),
                            "apply": (
                                stalwart_v016.build_migration_cli_apply_command(
                                    container_id,
                                )
                            ),
                            "stop": (
                                stalwart_v016.build_migration_compose_stop_command(
                                    plan,
                                )
                            ),
                        }
                        cancellation: BaseException = (
                            KeyboardInterrupt()
                            if cancellation_kind == "keyboard-interrupt"
                            else SystemExit(73)
                        )
                        calls: list[list[str]] = []

                        def runner(
                            args: list[str],
                            *,
                            stdin: bytes,
                            env: dict[str, str],
                            timeout: int | float,
                            cwd: Path,
                            credential: memoryview | None = None,
                        ) -> object:
                            del stdin, env, timeout, cwd, credential
                            calls.append(list(args))
                            if args == commands[cancellation_stage]:
                                raise cancellation
                            if args == commands["image"]:
                                return stalwart_v016.RedactedCommandResult(
                                    (
                                        stalwart_v016.STALWART_IMAGE_ID + "\n"
                                    ).encode("ascii"),
                                    b"",
                                )
                            if args == commands["ps"]:
                                return stalwart_v016.RedactedCommandResult(
                                    (container_id + "\n").encode("ascii"),
                                    b"",
                                )
                            if args == commands["inspect"]:
                                return stalwart_v016.RedactedCommandResult(
                                    json.dumps(inspection).encode("utf-8"),
                                    b"",
                                )
                            if args == commands["apply"]:
                                return stalwart_v016.RedactedCommandResult(
                                    self._valid_evidence().encode("utf-8"),
                                    b"",
                                )
                            return stalwart_v016.RedactedCommandResult(b"", b"")

                        executor = stalwart_v016.MigrationApplyExecutor(
                            runner=runner,
                            secret_runner=runner,
                            state_runner=fixture.runner,
                            credential_factory=lambda: credential,
                        )
                        raised: BaseException | None = None
                        with mock.patch.dict(os.environ, {}, clear=True):
                            try:
                                executor(plan)
                            except BaseException as exc:
                                raised = exc

                        self.assertIs(raised, cancellation)
                        self.assertEqual(calls[-1], commands["stop"])
                        self.assertTrue(all(value == 0 for value in credential))
                        self.assertFalse(fixture.paths.apply_receipt.exists())
                        self.assertNotIn(
                            "unit-secret",
                            str(raised),
                        )

    def test_runtime_apply_executor_rejects_bound_file_mutation_before_commands(
        self,
    ) -> None:
        for path_name in (
            "config",
            "export",
            "export-identity",
            "base-compose",
        ):
            with self.subTest(path_name=path_name):
                with tempfile.TemporaryDirectory() as directory:
                    fixture = self._fixture(directory)
                    plan = self._pre_dispatch_plan(fixture)
                    target = {
                        "config": fixture.paths.converted_config,
                        "export": fixture.paths.export,
                        "export-identity": fixture.paths.export,
                        "base-compose": fixture.repository
                        / "docker-compose.yml",
                    }[path_name]
                    original = target.read_bytes()
                    if path_name == "export-identity":
                        replacement = target.with_name("replacement-export.json")
                        replacement.write_bytes(original)
                        replacement.chmod(0o600)
                        os.replace(replacement, target)
                    else:
                        target.write_bytes(original + b" ")
                        target.chmod(
                            0o644 if path_name == "base-compose" else 0o600,
                        )
                    credential = bytearray(b"unit-user:unit-secret")
                    runner = mock.Mock()
                    executor = stalwart_v016.MigrationApplyExecutor(
                        runner=runner,
                        state_runner=fixture.runner,
                        credential_factory=lambda: credential,
                    )

                    with self.assertRaisesRegex(
                        stalwart_v016.MigrationError,
                        "changed",
                    ):
                        executor(plan)

                    runner.assert_not_called()
                    self.assertEqual(
                        credential,
                        bytearray(b"unit-user:unit-secret"),
                    )
                    self.assertFalse(plan.runtime.config_dir.exists())
                    self.assertFalse(plan.runtime.recovery_env_file.exists())

    def test_runtime_apply_executor_is_new_only_and_refuses_runtime_symlinks(
        self,
    ) -> None:
        for case in (
            "existing-config",
            "existing-environment",
            "config-symlink",
            "environment-symlink",
        ):
            with self.subTest(case=case):
                with tempfile.TemporaryDirectory() as directory:
                    fixture = self._fixture(directory)
                    plan = self._pre_dispatch_plan(fixture)
                    outside = fixture.repository / "outside-runtime"
                    outside.mkdir(mode=0o700)
                    outside_file = outside / "preserve.env"
                    outside_file.write_bytes(b"PRESERVE=1\n")
                    outside_file.chmod(0o600)
                    if case == "existing-config":
                        plan.runtime.config_dir.mkdir(mode=0o755)
                        sentinel = plan.runtime.config_dir / "preserve.txt"
                        sentinel.write_text("preserve\n", encoding="utf-8")
                    elif case == "existing-environment":
                        plan.runtime.recovery_env_file.write_bytes(
                            b"PRESERVE=1\n",
                        )
                        plan.runtime.recovery_env_file.chmod(0o600)
                    elif case == "config-symlink":
                        plan.runtime.config_dir.symlink_to(
                            outside,
                            target_is_directory=True,
                        )
                    else:
                        plan.runtime.recovery_env_file.symlink_to(outside_file)
                    credential = bytearray(b"unit-user:unit-secret")
                    runner = mock.Mock(
                        return_value=stalwart_v016.RedactedCommandResult(b"", b""),
                    )
                    executor = stalwart_v016.MigrationApplyExecutor(
                        runner=runner,
                        state_runner=fixture.runner,
                        credential_factory=lambda: credential,
                    )

                    with self.assertRaises(stalwart_v016.MigrationError):
                        executor(plan)

                    self.assertEqual(outside_file.read_bytes(), b"PRESERVE=1\n")
                    if case == "existing-config":
                        self.assertEqual(
                            sentinel.read_text(encoding="utf-8"),
                            "preserve\n",
                        )
                        self.assertTrue(all(value == 0 for value in credential))
                    elif case == "existing-environment":
                        self.assertEqual(
                            plan.runtime.recovery_env_file.read_bytes(),
                            b"PRESERVE=1\n",
                        )
                        self.assertTrue(all(value == 0 for value in credential))
                    else:
                        self.assertEqual(
                            credential,
                            bytearray(b"unit-user:unit-secret"),
                        )
                        runner.assert_not_called()

    def test_post_apply_verifier_runs_fresh_authenticated_cycle_and_stops(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            plan = self._pre_dispatch_plan(fixture)
            self._materialize_runtime(fixture)
            fixture.events.clear()
            container_id = "a" * 64
            inspection = self._valid_runtime_inspection(
                fixture,
                plan,
                container_id,
            )
            calls: list[dict[str, object]] = []
            running = False
            captured_leases: list[object] = []
            original_loader = stalwart_v016._load_recovery_credential_lease

            def recording_loader(*args: object, **kwargs: object) -> object:
                lease = original_loader(*args, **kwargs)
                captured_leases.append(lease)
                return lease

            def runner(
                args: list[str],
                *,
                stdin: bytes,
                env: dict[str, str],
                timeout: int | float,
                cwd: Path,
                credential: memoryview | None = None,
            ) -> object:
                nonlocal running
                calls.append(
                    {
                        "args": list(args),
                        "stdin": stdin,
                        "env": dict(env),
                        "timeout": timeout,
                        "cwd": cwd,
                        "has_credential": credential is not None,
                    },
                )
                if args == stalwart_v016.build_migration_image_inspect_command():
                    return stalwart_v016.RedactedCommandResult(
                        (stalwart_v016.STALWART_IMAGE_ID + "\n").encode("ascii"),
                        b"",
                    )
                if args == stalwart_v016.build_migration_compose_start_command(plan):
                    running = True
                if args == stalwart_v016.build_migration_compose_ps_command(plan):
                    return stalwart_v016.RedactedCommandResult(
                        (container_id + "\n").encode("ascii"),
                        b"",
                    )
                if args[:3] == ["docker", "inspect", "--type"]:
                    return stalwart_v016.RedactedCommandResult(
                        json.dumps(inspection).encode("utf-8") + b"\n",
                        b"",
                    )
                if args == stalwart_v016.build_migration_server_version_command(
                    container_id,
                ):
                    self.assertTrue(running)
                    return stalwart_v016.RedactedCommandResult(
                        b"0.16.17\n",
                        b"",
                    )
                if (
                    args
                    == stalwart_v016.build_migration_cli_account_query_command(
                        container_id,
                    )
                ):
                    self.assertTrue(running)
                    return stalwart_v016.RedactedCommandResult(
                        b"[]\n",
                        b"",
                    )
                if args == stalwart_v016.build_migration_compose_stop_command(plan):
                    running = False
                return stalwart_v016.RedactedCommandResult(b"", b"")

            self.assertIn(
                "state_runner",
                inspect.signature(
                    stalwart_v016.MigrationPostApplyVerifier,
                ).parameters,
            )
            verifier = stalwart_v016.MigrationPostApplyVerifier(
                runner=runner,
                secret_runner=runner,
                state_runner=fixture.runner,
            )
            docker_environment = self._docker_client_environment()
            with (
                mock.patch.object(
                    stalwart_v016,
                    "_load_recovery_credential_lease",
                    side_effect=recording_loader,
                ),
                mock.patch.dict(
                    os.environ,
                    {
                        **docker_environment,
                        "STALWART_TOKEN": "ambient-secret",
                        "STALWART_PASSWORD": "ambient-password",
                        "UNRELATED_SECRET": "must-not-propagate",
                    },
                    clear=True,
                ),
            ):
                proof = verifier(plan)

            self.assertEqual(
                proof,
                stalwart_v016.PostApplyCensusProof(
                    operations_sha256=plan.operations_sha256,
                    operation_count=len(plan.operations),
                    server_version="0.16.17",
                    management_status=200,
                ),
            )
            self.assertFalse(running)
            self.assertEqual(fixture.events, ["census"])
            self.assertEqual(len(captured_leases), 1)
            self.assertTrue(captured_leases[0].closed)
            self.assertEqual(
                [call["args"] for call in calls],
                [
                    stalwart_v016.build_migration_compose_config_command(plan),
                    stalwart_v016.build_migration_image_inspect_command(),
                    stalwart_v016.build_migration_compose_start_command(plan),
                    stalwart_v016.build_migration_compose_ps_command(plan),
                    stalwart_v016.build_migration_container_inspect_command(
                        container_id,
                    ),
                    stalwart_v016.build_migration_server_version_command(
                        container_id,
                    ),
                    stalwart_v016.build_migration_cli_account_query_command(
                        container_id,
                    ),
                    stalwart_v016.build_migration_compose_stop_command(plan),
                ],
            )
            compose_environment = {
                "PATH": stalwart_v016.SAFE_COMMAND_PATH,
                **docker_environment,
                **plan.runtime.compose_environment(),
            }
            for call in (*calls[:6], calls[-1]):
                self.assertEqual(call["stdin"], b"")
                self.assertEqual(call["env"], compose_environment)
                self.assertEqual(call["cwd"], fixture.repository)
                self.assertFalse(call["has_credential"])
            for call in calls[6:7]:
                self.assertEqual(call["stdin"], b"")
                self.assertEqual(
                    call["env"],
                    {
                        "PATH": stalwart_v016.SAFE_COMMAND_PATH,
                        **docker_environment,
                        "STALWART_URL": "http://127.0.0.1:8080",
                    },
                )
                self.assertTrue(call["has_credential"])
                self.assertNotIn("STALWART_TOKEN", call["env"])
                self.assertNotIn("UNRELATED_SECRET", call["env"])

    def test_bootstrap_runtime_session_is_validated_bounded_and_wiped(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            self._prepare(
                fixture,
                lambda _plan: self._valid_evidence(),
            )
            validated = stalwart_v016._validate_apply_state(
                fixture.paths,
                source_receipt_path=fixture.paths.source_receipt,
                script_path=fixture.paths.migration_script,
                dry_run_receipt_path=fixture.paths.dry_run_receipt,
                review_receipt_path=fixture.paths.reviewed,
                runner=fixture.runner,
                python_executable="/unit/python3",
                expected_script_sha256=fixture.script_digest,
                runtime_phase="ready",
            )
            plan = validated.plan
            container_id = "a" * 64
            inspection = self._valid_runtime_inspection(
                fixture,
                plan,
                container_id,
            )
            calls: list[list[str]] = []
            running = False
            captured: list[object] = []

            def runtime_runner(
                args: list[str],
                *,
                stdin: bytes,
                env: dict[str, str],
                timeout: int | float,
                cwd: Path,
            ) -> object:
                del stdin, env, timeout, cwd
                nonlocal running
                calls.append(list(args))
                if args == stalwart_v016.build_migration_image_inspect_command():
                    return stalwart_v016.RedactedCommandResult(
                        (stalwart_v016.STALWART_IMAGE_ID + "\n").encode("ascii"),
                        b"",
                    )
                if args == stalwart_v016.build_migration_compose_start_command(
                    plan,
                ):
                    running = True
                if args == stalwart_v016.build_migration_compose_ps_command(
                    plan,
                ):
                    return stalwart_v016.RedactedCommandResult(
                        (container_id + "\n").encode("ascii"),
                        b"",
                    )
                if args[:3] == ["docker", "inspect", "--type"]:
                    return stalwart_v016.RedactedCommandResult(
                        json.dumps(inspection).encode("utf-8"),
                        b"",
                    )
                if args == stalwart_v016.build_migration_server_version_command(
                    container_id,
                ):
                    self.assertTrue(running)
                    return stalwart_v016.RedactedCommandResult(
                        b"0.16.17\n",
                        b"",
                    )
                if args == stalwart_v016.build_migration_compose_stop_command(
                    plan,
                ):
                    running = False
                return stalwart_v016.RedactedCommandResult(b"", b"")

            def operation(session: object) -> object:
                captured.append(session)
                self.assertEqual(
                    repr(session),
                    "MigrationBootstrapRuntime(<redacted>)",
                )
                self.assertEqual(session.base_url, "http://127.0.0.1:8443")
                self.assertEqual(session.api_url, "http://127.0.0.1:8443/jmap/")
                self.assertEqual(session.server_version, "0.16.17")
                self.assertEqual(session.container_id, container_id)
                self.assertEqual(
                    session.operations_sha256,
                    plan.operations_sha256,
                )
                borrowed = session.borrow_recovery_credential()
                try:
                    self.assertEqual(
                        bytes(borrowed),
                        b"unit-user:unit-secret",
                    )
                finally:
                    borrowed.release()
                return {"result": "unit-ok"}

            fixture.events.clear()
            with (
                stalwart_v016.acquire_stalwart_operation_lock(
                    fixture.repository,
                ) as operation_lock,
                mock.patch.dict(
                    os.environ,
                    self._docker_client_environment(),
                    clear=True,
                ),
            ):
                result = stalwart_v016.run_validated_migration_runtime(
                    fixture.paths,
                    apply_receipt_path=fixture.paths.apply_receipt,
                    source_receipt_path=fixture.paths.source_receipt,
                    script_path=fixture.paths.migration_script,
                    dry_run_receipt_path=fixture.paths.dry_run_receipt,
                    review_receipt_path=fixture.paths.reviewed,
                    state_runner=fixture.runner,
                    runtime_runner=runtime_runner,
                    python_executable="/unit/python3",
                    operation=operation,
                    operation_lock=operation_lock,
                    expected_script_sha256=fixture.script_digest,
                )

            self.assertEqual(result, {"result": "unit-ok"})
            self.assertEqual(fixture.events.count("census"), 3)
            self.assertFalse(running)
            self.assertEqual(len(captured), 1)
            with self.assertRaisesRegex(
                stalwart_v016.MigrationError,
                "closed",
            ):
                captured[0].borrow_recovery_credential()
            self.assertEqual(
                calls,
                [
                    stalwart_v016.build_migration_compose_config_command(plan),
                    stalwart_v016.build_migration_image_inspect_command(),
                    stalwart_v016.build_migration_compose_start_command(plan),
                    stalwart_v016.build_migration_compose_ps_command(plan),
                    stalwart_v016.build_migration_container_inspect_command(
                        container_id,
                    ),
                    stalwart_v016.build_migration_server_version_command(
                        container_id,
                    ),
                    stalwart_v016.build_migration_compose_stop_command(plan),
                ],
            )

    def test_bootstrap_runtime_rejects_provider_store_directory_replacement(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            self._prepare(
                fixture,
                lambda _plan: self._valid_evidence(),
            )
            validated = stalwart_v016._validate_apply_state(
                fixture.paths,
                source_receipt_path=fixture.paths.source_receipt,
                script_path=fixture.paths.migration_script,
                dry_run_receipt_path=fixture.paths.dry_run_receipt,
                review_receipt_path=fixture.paths.reviewed,
                runner=fixture.runner,
                python_executable="/unit/python3",
                expected_script_sha256=fixture.script_digest,
                runtime_phase="ready",
            )
            plan = validated.plan
            container_id = "a" * 64
            inspection = self._valid_runtime_inspection(
                fixture,
                plan,
                container_id,
            )
            running = False
            activations = 0

            def runtime_runner(
                args: list[str],
                **_kwargs: object,
            ) -> object:
                nonlocal running
                if args == stalwart_v016.build_migration_image_inspect_command():
                    return stalwart_v016.RedactedCommandResult(
                        (stalwart_v016.STALWART_IMAGE_ID + "\n").encode("ascii"),
                        b"",
                    )
                if args == stalwart_v016.build_migration_compose_start_command(
                    plan,
                ):
                    running = True
                if args == stalwart_v016.build_migration_compose_ps_command(
                    plan,
                ):
                    return stalwart_v016.RedactedCommandResult(
                        (container_id + "\n").encode("ascii"),
                        b"",
                    )
                if args[:3] == ["docker", "inspect", "--type"]:
                    return stalwart_v016.RedactedCommandResult(
                        json.dumps(inspection).encode("utf-8"),
                        b"",
                    )
                if args == stalwart_v016.build_migration_server_version_command(
                    container_id,
                ):
                    return stalwart_v016.RedactedCommandResult(
                        b"0.16.17\n",
                        b"",
                    )
                if args == stalwart_v016.build_migration_compose_stop_command(
                    plan,
                ):
                    running = False
                return stalwart_v016.RedactedCommandResult(b"", b"")

            moved_store = fixture.repository / "moved-stalwart-data"

            def replace_provider_store(_session: object) -> str:
                fixture.source_store.rename(moved_store)
                fixture.source_store.mkdir(mode=0o700)
                return "must-not-be-accepted"

            def activate(
                _receipt_path: Path,
                *,
                expected_receipt_sha256: str,
            ) -> object:
                nonlocal activations
                operation_lock.assert_valid_for(fixture.repository)
                activations += 1
                return self._valid_rollback_activation(
                    fixture,
                    expected_receipt_sha256=expected_receipt_sha256,
                )

            with (
                stalwart_v016.acquire_stalwart_operation_lock(
                    fixture.repository,
                ) as operation_lock,
                mock.patch.dict(
                    os.environ,
                    self._docker_client_environment(),
                    clear=True,
                ),
                self.assertRaisesRegex(
                    stalwart_v016.MigrationError,
                    "provider store.*changed",
                ),
            ):
                stalwart_v016.run_validated_migration_runtime(
                    fixture.paths,
                    apply_receipt_path=fixture.paths.apply_receipt,
                    source_receipt_path=fixture.paths.source_receipt,
                    script_path=fixture.paths.migration_script,
                    dry_run_receipt_path=fixture.paths.dry_run_receipt,
                    review_receipt_path=fixture.paths.reviewed,
                    state_runner=fixture.runner,
                    runtime_runner=runtime_runner,
                    python_executable="/unit/python3",
                    operation=replace_provider_store,
                    operation_lock=operation_lock,
                    rollback_activator=activate,
                    expected_script_sha256=fixture.script_digest,
                )

            self.assertFalse(running)
            self.assertTrue(moved_store.is_dir())
            self.assertEqual(activations, 1)

    def test_bootstrap_runtime_rejects_credential_capability_replacement(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            self._prepare(
                fixture,
                lambda _plan: self._valid_evidence(),
            )
            validated = stalwart_v016._validate_apply_state(
                fixture.paths,
                source_receipt_path=fixture.paths.source_receipt,
                script_path=fixture.paths.migration_script,
                dry_run_receipt_path=fixture.paths.dry_run_receipt,
                review_receipt_path=fixture.paths.reviewed,
                runner=fixture.runner,
                python_executable="/unit/python3",
                expected_script_sha256=fixture.script_digest,
                runtime_phase="ready",
            )
            plan = validated.plan
            container_id = "a" * 64
            inspection = self._valid_runtime_inspection(
                fixture,
                plan,
                container_id,
            )
            captured_leases: list[object] = []
            original_loader = stalwart_v016._load_recovery_credential_lease

            def recording_loader(*args: object, **kwargs: object) -> object:
                lease = original_loader(*args, **kwargs)
                captured_leases.append(lease)
                return lease

            def runtime_runner(
                args: list[str],
                **_kwargs: object,
            ) -> object:
                if args == stalwart_v016.build_migration_image_inspect_command():
                    return stalwart_v016.RedactedCommandResult(
                        (stalwart_v016.STALWART_IMAGE_ID + "\n").encode("ascii"),
                        b"",
                    )
                if args == stalwart_v016.build_migration_compose_ps_command(
                    plan,
                ):
                    return stalwart_v016.RedactedCommandResult(
                        (container_id + "\n").encode("ascii"),
                        b"",
                    )
                if args[:3] == ["docker", "inspect", "--type"]:
                    return stalwart_v016.RedactedCommandResult(
                        json.dumps(inspection).encode("utf-8"),
                        b"",
                    )
                if args == stalwart_v016.build_migration_server_version_command(
                    container_id,
                ):
                    return stalwart_v016.RedactedCommandResult(
                        b"0.16.17\n",
                        b"",
                    )
                return stalwart_v016.RedactedCommandResult(b"", b"")

            def operation(session: object) -> str:
                replacement = stalwart_v016.RecoveryCredentialLease(
                    bytearray(b"other-user:other-secret"),
                )
                forged_capability = (
                    stalwart_v016._MigrationRuntimeCredentialCapability(
                        replacement,
                        container_id=session.container_id,
                        operations_sha256=session.operations_sha256,
                    )
                )
                try:
                    original_capability = session._capability
                    original_container_id = session.container_id
                    object.__setattr__(
                        session,
                        "_container_id",
                        "b" * 64,
                    )
                    with self.assertRaisesRegex(
                        stalwart_v016.MigrationError,
                        "binding changed",
                    ):
                        session.borrow_recovery_credential()
                    object.__setattr__(
                        session,
                        "_container_id",
                        original_container_id,
                    )
                    object.__setattr__(
                        session,
                        "_capability",
                        forged_capability,
                    )
                    with self.assertRaisesRegex(
                        stalwart_v016.MigrationError,
                        "binding changed",
                    ):
                        session.borrow_recovery_credential()
                    object.__setattr__(
                        session,
                        "_capability",
                        original_capability,
                    )
                    with self.assertRaises((AttributeError, TypeError)):
                        del session._capability
                    with self.assertRaises((AttributeError, TypeError)):
                        session._credential = replacement
                    self.assertEqual(len(captured_leases), 1)
                    captured_leases[0].close()
                    with self.assertRaisesRegex(
                        stalwart_v016.MigrationError,
                        "closed",
                    ):
                        session.borrow_recovery_credential()
                    return "replacement-rejected"
                finally:
                    forged_capability.close()
                    replacement.close()

            with (
                stalwart_v016.acquire_stalwart_operation_lock(
                    fixture.repository,
                ) as operation_lock,
                mock.patch.object(
                    stalwart_v016,
                    "_load_recovery_credential_lease",
                    side_effect=recording_loader,
                ),
                mock.patch.dict(
                    os.environ,
                    self._docker_client_environment(),
                    clear=True,
                ),
            ):
                result = stalwart_v016.run_validated_migration_runtime(
                    fixture.paths,
                    apply_receipt_path=fixture.paths.apply_receipt,
                    source_receipt_path=fixture.paths.source_receipt,
                    script_path=fixture.paths.migration_script,
                    dry_run_receipt_path=fixture.paths.dry_run_receipt,
                    review_receipt_path=fixture.paths.reviewed,
                    state_runner=fixture.runner,
                    runtime_runner=runtime_runner,
                    python_executable="/unit/python3",
                    operation=operation,
                    operation_lock=operation_lock,
                    expected_script_sha256=fixture.script_digest,
                )

            self.assertEqual(result, "replacement-rejected")
            self.assertTrue(captured_leases[0].closed)

    def test_bootstrap_runtime_failure_stops_wipes_and_redacts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            self._prepare(
                fixture,
                lambda _plan: self._valid_evidence(),
            )
            validated = stalwart_v016._validate_apply_state(
                fixture.paths,
                source_receipt_path=fixture.paths.source_receipt,
                script_path=fixture.paths.migration_script,
                dry_run_receipt_path=fixture.paths.dry_run_receipt,
                review_receipt_path=fixture.paths.reviewed,
                runner=fixture.runner,
                python_executable="/unit/python3",
                expected_script_sha256=fixture.script_digest,
                runtime_phase="ready",
            )
            plan = validated.plan
            container_id = "a" * 64
            inspection = self._valid_runtime_inspection(
                fixture,
                plan,
                container_id,
            )
            calls: list[list[str]] = []
            captured: list[object] = []
            activations = 0

            def runtime_runner(
                args: list[str],
                **_kwargs: object,
            ) -> object:
                calls.append(list(args))
                if args == stalwart_v016.build_migration_image_inspect_command():
                    return stalwart_v016.RedactedCommandResult(
                        (stalwart_v016.STALWART_IMAGE_ID + "\n").encode("ascii"),
                        b"",
                    )
                if args == stalwart_v016.build_migration_compose_ps_command(
                    plan,
                ):
                    return stalwart_v016.RedactedCommandResult(
                        (container_id + "\n").encode("ascii"),
                        b"",
                    )
                if args[:3] == ["docker", "inspect", "--type"]:
                    return stalwart_v016.RedactedCommandResult(
                        json.dumps(inspection).encode("utf-8"),
                        b"",
                    )
                if args == stalwart_v016.build_migration_server_version_command(
                    container_id,
                ):
                    return stalwart_v016.RedactedCommandResult(
                        b"0.16.17\n",
                        b"",
                    )
                return stalwart_v016.RedactedCommandResult(b"", b"")

            def operation(session: object) -> object:
                captured.append(session)
                raise RuntimeError("unit-secret must be redacted")

            def activate(
                receipt_path: Path,
                *,
                expected_receipt_sha256: str,
            ) -> object:
                nonlocal activations
                operation_lock.assert_valid_for(fixture.repository)
                self.assertEqual(
                    receipt_path,
                    fixture.paths.source_receipt,
                )
                activations += 1
                return self._valid_rollback_activation(
                    fixture,
                    expected_receipt_sha256=expected_receipt_sha256,
                )

            with (
                stalwart_v016.acquire_stalwart_operation_lock(
                    fixture.repository,
                ) as operation_lock,
                mock.patch.dict(
                    os.environ,
                    self._docker_client_environment(),
                    clear=True,
                ),
                self.assertRaises(
                    stalwart_v016.MigrationError,
                ) as raised,
            ):
                stalwart_v016.run_validated_migration_runtime(
                    fixture.paths,
                    apply_receipt_path=fixture.paths.apply_receipt,
                    source_receipt_path=fixture.paths.source_receipt,
                    script_path=fixture.paths.migration_script,
                    dry_run_receipt_path=fixture.paths.dry_run_receipt,
                    review_receipt_path=fixture.paths.reviewed,
                    state_runner=fixture.runner,
                    runtime_runner=runtime_runner,
                    python_executable="/unit/python3",
                    operation=operation,
                    operation_lock=operation_lock,
                    rollback_activator=activate,
                    expected_script_sha256=fixture.script_digest,
                )

            self.assertEqual(
                str(raised.exception),
                "migration bootstrap runtime operation failed safely",
            )
            self.assertNotIn("unit-secret", str(raised.exception))
            self.assertIsNone(raised.exception.__cause__)
            self.assertEqual(
                calls[-1],
                stalwart_v016.build_migration_recovery_ps_command(plan),
            )
            self.assertEqual(
                calls.count(
                    stalwart_v016.build_migration_compose_stop_command(plan),
                ),
                1,
            )
            self.assertEqual(activations, 1)
            with self.assertRaisesRegex(
                stalwart_v016.MigrationError,
                "closed",
            ):
                captured[0].borrow_recovery_credential()

    def test_bootstrap_runtime_rollback_activation_stage_matrix(
        self,
    ) -> None:
        recovery_bound = {"config", "image", "census"}
        runtime_dispatched = {
            "start",
            "ps",
            "inspect",
            "operation",
            "mandatory-stop",
            "final-validation",
        }
        for failure_stage in (
            *sorted(recovery_bound),
            *sorted(runtime_dispatched),
        ):
            with (
                self.subTest(failure_stage=failure_stage),
                tempfile.TemporaryDirectory() as directory,
            ):
                fixture = self._fixture(directory)
                self._prepare(
                    fixture,
                    lambda _plan: self._valid_evidence(),
                )
                validated = stalwart_v016._validate_apply_state(
                    fixture.paths,
                    source_receipt_path=fixture.paths.source_receipt,
                    script_path=fixture.paths.migration_script,
                    dry_run_receipt_path=fixture.paths.dry_run_receipt,
                    review_receipt_path=fixture.paths.reviewed,
                    runner=fixture.runner,
                    python_executable="/unit/python3",
                    expected_script_sha256=fixture.script_digest,
                    runtime_phase="ready",
                )
                plan = validated.plan
                container_id = "a" * 64
                inspection = self._valid_runtime_inspection(
                    fixture,
                    plan,
                    container_id,
                )
                census_calls = 0
                stop_calls = 0
                activations = 0

                def state_runner(args: list[str]) -> object:
                    nonlocal census_calls
                    if args[:2] == ["docker", "ps"]:
                        census_calls += 1
                        if (
                            failure_stage == "census"
                            and census_calls == 2
                        ):
                            raise RuntimeError(
                                "unit-secret census endpoint failure",
                            )
                    return fixture.runner(args)

                def runtime_runner(
                    args: list[str],
                    **_kwargs: object,
                ) -> object:
                    nonlocal stop_calls
                    if args == (
                        stalwart_v016
                        .build_migration_compose_config_command(plan)
                    ):
                        if failure_stage == "config":
                            raise RuntimeError(
                                "unit-secret config endpoint failure",
                            )
                    elif args == (
                        stalwart_v016
                        .build_migration_image_inspect_command()
                    ):
                        if failure_stage == "image":
                            raise RuntimeError(
                                "unit-secret image endpoint failure",
                            )
                        return stalwart_v016.RedactedCommandResult(
                            (
                                stalwart_v016.STALWART_IMAGE_ID + "\n"
                            ).encode("ascii"),
                            b"",
                        )
                    elif args == (
                        stalwart_v016
                        .build_migration_compose_start_command(plan)
                    ):
                        if failure_stage == "start":
                            raise RuntimeError(
                                "unit-secret start endpoint failure",
                            )
                    elif args == (
                        stalwart_v016
                        .build_migration_compose_ps_command(plan)
                    ):
                        if failure_stage == "ps":
                            raise RuntimeError(
                                "unit-secret ps endpoint failure",
                            )
                        return stalwart_v016.RedactedCommandResult(
                            (container_id + "\n").encode("ascii"),
                            b"",
                        )
                    elif args[:3] == ["docker", "inspect", "--type"]:
                        if failure_stage == "inspect":
                            raise RuntimeError(
                                "unit-secret inspect endpoint failure",
                            )
                        return stalwart_v016.RedactedCommandResult(
                            json.dumps(inspection).encode("utf-8"),
                            b"",
                        )
                    elif args == (
                        stalwart_v016
                        .build_migration_server_version_command(
                            container_id,
                        )
                    ):
                        return stalwart_v016.RedactedCommandResult(
                            b"0.16.17\n",
                            b"",
                        )
                    elif args == (
                        stalwart_v016
                        .build_migration_compose_stop_command(plan)
                    ):
                        stop_calls += 1
                        if (
                            failure_stage == "mandatory-stop"
                            and stop_calls == 1
                        ):
                            raise RuntimeError(
                                "unit-secret first stop failure",
                            )
                    return stalwart_v016.RedactedCommandResult(b"", b"")

                def operation(_session: object) -> str:
                    if failure_stage == "operation":
                        raise RuntimeError(
                            "unit-secret operation endpoint failure",
                        )
                    if failure_stage == "final-validation":
                        fixture.paths.export.write_bytes(
                            b'{"changed":"after runtime"}\n',
                        )
                        fixture.paths.export.chmod(0o600)
                    return "unit-result"

                def activate(
                    _receipt_path: Path,
                    *,
                    expected_receipt_sha256: str,
                ) -> object:
                    nonlocal activations
                    operation_lock.assert_valid_for(fixture.repository)
                    activations += 1
                    return self._valid_rollback_activation(
                        fixture,
                        expected_receipt_sha256=expected_receipt_sha256,
                    )

                with (
                    stalwart_v016.acquire_stalwart_operation_lock(
                        fixture.repository,
                    ) as operation_lock,
                    mock.patch.dict(
                        os.environ,
                        self._docker_client_environment(),
                        clear=True,
                    ),
                    self.assertRaises(stalwart_v016.MigrationError),
                ):
                    stalwart_v016.run_validated_migration_runtime(
                        fixture.paths,
                        apply_receipt_path=fixture.paths.apply_receipt,
                        source_receipt_path=fixture.paths.source_receipt,
                        script_path=fixture.paths.migration_script,
                        dry_run_receipt_path=fixture.paths.dry_run_receipt,
                        review_receipt_path=fixture.paths.reviewed,
                        state_runner=state_runner,
                        runtime_runner=runtime_runner,
                        python_executable="/unit/python3",
                        operation=operation,
                        operation_lock=operation_lock,
                        rollback_activator=activate,
                        expected_script_sha256=fixture.script_digest,
                    )

                self.assertEqual(
                    activations,
                    1,
                )
                if failure_stage in runtime_dispatched:
                    self.assertGreaterEqual(stop_calls, 1)

    def test_bootstrap_runtime_preserves_cancellation_after_activation(
        self,
    ) -> None:
        for interruption in (
            KeyboardInterrupt("unit-secret cancellation"),
            SystemExit(73),
        ):
            with (
                self.subTest(interruption=type(interruption).__name__),
                tempfile.TemporaryDirectory() as directory,
            ):
                fixture = self._fixture(directory)
                self._prepare(
                    fixture,
                    lambda _plan: self._valid_evidence(),
                )
                validated = stalwart_v016._validate_apply_state(
                    fixture.paths,
                    source_receipt_path=fixture.paths.source_receipt,
                    script_path=fixture.paths.migration_script,
                    dry_run_receipt_path=fixture.paths.dry_run_receipt,
                    review_receipt_path=fixture.paths.reviewed,
                    runner=fixture.runner,
                    python_executable="/unit/python3",
                    expected_script_sha256=fixture.script_digest,
                    runtime_phase="ready",
                )
                plan = validated.plan
                container_id = "a" * 64
                inspection = self._valid_runtime_inspection(
                    fixture,
                    plan,
                    container_id,
                )
                activations = 0

                def runtime_runner(
                    args: list[str],
                    **_kwargs: object,
                ) -> object:
                    if args == (
                        stalwart_v016
                        .build_migration_image_inspect_command()
                    ):
                        return stalwart_v016.RedactedCommandResult(
                            (
                                stalwart_v016.STALWART_IMAGE_ID + "\n"
                            ).encode("ascii"),
                            b"",
                        )
                    if args == (
                        stalwart_v016
                        .build_migration_compose_ps_command(plan)
                    ):
                        return stalwart_v016.RedactedCommandResult(
                            (container_id + "\n").encode("ascii"),
                            b"",
                        )
                    if args[:3] == ["docker", "inspect", "--type"]:
                        return stalwart_v016.RedactedCommandResult(
                            json.dumps(inspection).encode("utf-8"),
                            b"",
                        )
                    if args == (
                        stalwart_v016
                        .build_migration_server_version_command(
                            container_id,
                        )
                    ):
                        return stalwart_v016.RedactedCommandResult(
                            b"0.16.17\n",
                            b"",
                        )
                    return stalwart_v016.RedactedCommandResult(b"", b"")

                def operation(_session: object) -> object:
                    raise interruption

                def activate(
                    _receipt_path: Path,
                    *,
                    expected_receipt_sha256: str,
                ) -> object:
                    nonlocal activations
                    operation_lock.assert_valid_for(fixture.repository)
                    activations += 1
                    return self._valid_rollback_activation(
                        fixture,
                        expected_receipt_sha256=expected_receipt_sha256,
                    )

                raised: BaseException | None = None
                with (
                    stalwart_v016.acquire_stalwart_operation_lock(
                        fixture.repository,
                    ) as operation_lock,
                    mock.patch.dict(
                        os.environ,
                        self._docker_client_environment(),
                        clear=True,
                    ),
                ):
                    try:
                        stalwart_v016.run_validated_migration_runtime(
                            fixture.paths,
                            apply_receipt_path=fixture.paths.apply_receipt,
                            source_receipt_path=fixture.paths.source_receipt,
                            script_path=fixture.paths.migration_script,
                            dry_run_receipt_path=fixture.paths.dry_run_receipt,
                            review_receipt_path=fixture.paths.reviewed,
                            state_runner=fixture.runner,
                            runtime_runner=runtime_runner,
                            python_executable="/unit/python3",
                            operation=operation,
                            operation_lock=operation_lock,
                            rollback_activator=activate,
                            expected_script_sha256=fixture.script_digest,
                        )
                    except BaseException as error:
                        raised = error

                self.assertIs(raised, interruption)
                self.assertEqual(activations, 1)

    def test_bootstrap_runtime_refuses_nonfixed_receipt_before_dispatch(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            self._prepare(
                fixture,
                lambda _plan: self._valid_evidence(),
            )
            alternate = fixture.paths.migration_root / "alternate-apply.json"
            alternate.write_bytes(fixture.paths.apply_receipt.read_bytes())
            alternate.chmod(0o600)
            runtime_runner = mock.Mock()
            operation = mock.Mock()
            rollback_activator = mock.Mock()

            with (
                stalwart_v016.acquire_stalwart_operation_lock(
                    fixture.repository,
                ) as operation_lock,
                self.assertRaisesRegex(
                    stalwart_v016.MigrationError,
                    "fixed repository path",
                ),
            ):
                stalwart_v016.run_validated_migration_runtime(
                    fixture.paths,
                    apply_receipt_path=alternate,
                    source_receipt_path=fixture.paths.source_receipt,
                    script_path=fixture.paths.migration_script,
                    dry_run_receipt_path=fixture.paths.dry_run_receipt,
                    review_receipt_path=fixture.paths.reviewed,
                    state_runner=fixture.runner,
                    runtime_runner=runtime_runner,
                    python_executable="/unit/python3",
                    operation=operation,
                    operation_lock=operation_lock,
                    rollback_activator=rollback_activator,
                    expected_script_sha256=fixture.script_digest,
                )

            runtime_runner.assert_not_called()
            operation.assert_not_called()
            rollback_activator.assert_not_called()

    def test_bootstrap_runtime_requires_a_live_shared_lock_before_dispatch(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            self._prepare(
                fixture,
                lambda _plan: self._valid_evidence(),
            )
            runtime_runner = mock.Mock()
            operation = mock.Mock()

            with self.assertRaisesRegex(
                stalwart_v016.MigrationError,
                "operation lock",
            ):
                stalwart_v016.run_validated_migration_runtime(
                    fixture.paths,
                    apply_receipt_path=fixture.paths.apply_receipt,
                    source_receipt_path=fixture.paths.source_receipt,
                    script_path=fixture.paths.migration_script,
                    dry_run_receipt_path=fixture.paths.dry_run_receipt,
                    review_receipt_path=fixture.paths.reviewed,
                    state_runner=fixture.runner,
                    runtime_runner=runtime_runner,
                    python_executable="/unit/python3",
                    operation=operation,
                    expected_script_sha256=fixture.script_digest,
                )

            runtime_runner.assert_not_called()
            operation.assert_not_called()

    def test_bootstrap_runtime_rejects_closed_and_wrong_repository_locks(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            self._prepare(
                fixture,
                lambda _plan: self._valid_evidence(),
            )
            runtime_runner = mock.Mock()
            operation = mock.Mock()

            def invoke(operation_lock: object) -> None:
                stalwart_v016.run_validated_migration_runtime(
                    fixture.paths,
                    apply_receipt_path=fixture.paths.apply_receipt,
                    source_receipt_path=fixture.paths.source_receipt,
                    script_path=fixture.paths.migration_script,
                    dry_run_receipt_path=fixture.paths.dry_run_receipt,
                    review_receipt_path=fixture.paths.reviewed,
                    state_runner=fixture.runner,
                    runtime_runner=runtime_runner,
                    python_executable="/unit/python3",
                    operation=operation,
                    operation_lock=operation_lock,
                    expected_script_sha256=fixture.script_digest,
                )

            closed = stalwart_v016.acquire_stalwart_operation_lock(
                fixture.repository,
            )
            closed.close()
            with self.assertRaisesRegex(
                stalwart_v016.MigrationError,
                "closed",
            ):
                invoke(closed)

            other_repository = fixture.repository / "other-repository"
            (other_repository / "debug-dashboard").mkdir(parents=True)
            with (
                stalwart_v016.acquire_stalwart_operation_lock(
                    other_repository,
                ) as wrong_lock,
                self.assertRaisesRegex(
                    stalwart_v016.MigrationError,
                    "another repository",
                ),
            ):
                invoke(wrong_lock)

            runtime_runner.assert_not_called()
            operation.assert_not_called()

    def test_post_apply_verifier_rejects_version_and_account_json_and_stops(
        self,
    ) -> None:
        for failure_stage in (
            "config",
            "image",
            "start",
            "ps",
            "inspect",
            "version-format",
            "version-value",
            "query-json",
            "query-extra",
            "query-id",
            "query-duplicate-key",
            "query-count",
            "stop",
        ):
            with self.subTest(failure_stage=failure_stage):
                with tempfile.TemporaryDirectory() as directory:
                    fixture = self._fixture(directory)
                    plan = self._pre_dispatch_plan(fixture)
                    self._materialize_runtime(fixture)
                    container_id = "a" * 64
                    inspection = self._valid_runtime_inspection(
                        fixture,
                        plan,
                        container_id,
                    )
                    calls: list[list[str]] = []

                    def runner(
                        args: list[str],
                        *,
                        stdin: bytes,
                        env: dict[str, str],
                        timeout: int | float,
                        cwd: Path,
                        credential: memoryview | None = None,
                    ) -> object:
                        del stdin, env, timeout, cwd, credential
                        calls.append(list(args))
                        if (
                            args
                            == stalwart_v016.build_migration_compose_config_command(
                                plan,
                            )
                            and failure_stage == "config"
                        ):
                            raise RuntimeError("unit-secret config failure")
                        if (
                            args
                            == stalwart_v016.build_migration_image_inspect_command()
                        ):
                            if failure_stage == "image":
                                return stalwart_v016.RedactedCommandResult(
                                    b"sha256:" + b"0" * 64 + b"\n",
                                    b"",
                                )
                            return stalwart_v016.RedactedCommandResult(
                                (
                                    stalwart_v016.STALWART_IMAGE_ID + "\n"
                                ).encode("ascii"),
                                b"",
                            )
                        if (
                            args
                            == stalwart_v016.build_migration_compose_start_command(
                                plan,
                            )
                            and failure_stage == "start"
                        ):
                            raise RuntimeError("unit-secret start failure")
                        if args == stalwart_v016.build_migration_compose_ps_command(
                            plan,
                        ):
                            if failure_stage == "ps":
                                return stalwart_v016.RedactedCommandResult(
                                    b"malformed-container\n",
                                    b"",
                                )
                            return stalwart_v016.RedactedCommandResult(
                                (container_id + "\n").encode("ascii"),
                                b"",
                            )
                        if args[:3] == ["docker", "inspect", "--type"]:
                            if failure_stage == "inspect":
                                return stalwart_v016.RedactedCommandResult(
                                    b'{"Health":"starting"}',
                                    b"",
                                )
                            return stalwart_v016.RedactedCommandResult(
                                json.dumps(inspection).encode("utf-8") + b"\n",
                                b"",
                            )
                        if (
                            args
                            == stalwart_v016.build_migration_server_version_command(
                                container_id,
                            )
                        ):
                            stdout = {
                                "version-format": b"0.16.17\r\n",
                                "version-value": b"0.16.15\n",
                            }.get(
                                failure_stage,
                                b"0.16.17\n",
                            )
                            return stalwart_v016.RedactedCommandResult(stdout, b"")
                        if (
                            args
                            == stalwart_v016.build_migration_cli_account_query_command(
                                container_id,
                            )
                        ):
                            stdout = {
                                "query-json": b"unit-secret not-json",
                                "query-extra": (
                                    b'[{"id":"account-1","name":"unsafe"}]'
                                ),
                                "query-id": (
                                    b'[{"id":true}]'
                                ),
                                "query-duplicate-key": (
                                    b'[{"id":"one","id":"two"}]'
                                ),
                                "query-count": (
                                    b'[{"id":"unexpected-account"}]'
                                ),
                            }.get(
                                failure_stage,
                                b"[]",
                            )
                            return stalwart_v016.RedactedCommandResult(stdout, b"")
                        if (
                            args
                            == stalwart_v016.build_migration_compose_stop_command(
                                plan,
                            )
                            and failure_stage == "stop"
                        ):
                            raise RuntimeError("unit-secret stop failure")
                        return stalwart_v016.RedactedCommandResult(b"", b"")

                    verifier = stalwart_v016.MigrationPostApplyVerifier(
                        runner=runner,
                        secret_runner=runner,
                        state_runner=fixture.runner,
                    )
                    with self.assertRaises(
                        stalwart_v016.MigrationError,
                    ) as raised:
                        verifier(plan)

                    self.assertEqual(
                        str(raised.exception),
                        "post-apply verification failed safely",
                    )
                    self.assertNotIn("unit-secret", str(raised.exception))
                    self.assertIsNone(raised.exception.__cause__)
                    self.assertIsNone(raised.exception.__context__)
                    self.assertEqual(
                        calls[-1],
                        stalwart_v016.build_migration_compose_stop_command(plan),
                    )

    def test_post_apply_verifier_preserves_cancellation_identity_and_stops(
        self,
    ) -> None:
        for cancellation_kind in ("keyboard-interrupt", "system-exit"):
            for cancellation_stage in (
                "config",
                "image",
                "start",
                "ps",
                "inspect",
                "version",
                "query",
                "stop",
            ):
                with self.subTest(
                    cancellation_kind=cancellation_kind,
                    cancellation_stage=cancellation_stage,
                ):
                    with tempfile.TemporaryDirectory() as directory:
                        fixture = self._fixture(directory)
                        plan = self._pre_dispatch_plan(fixture)
                        self._materialize_runtime(fixture)
                        container_id = "a" * 64
                        inspection = self._valid_runtime_inspection(
                            fixture,
                            plan,
                            container_id,
                        )
                        commands = {
                            "config": (
                                stalwart_v016.build_migration_compose_config_command(
                                    plan,
                                )
                            ),
                            "image": (
                                stalwart_v016.build_migration_image_inspect_command()
                            ),
                            "start": (
                                stalwart_v016.build_migration_compose_start_command(
                                    plan,
                                )
                            ),
                            "ps": stalwart_v016.build_migration_compose_ps_command(
                                plan,
                            ),
                            "inspect": (
                                stalwart_v016.build_migration_container_inspect_command(
                                    container_id,
                                )
                            ),
                            "version": (
                                stalwart_v016.build_migration_server_version_command(
                                    container_id,
                                )
                            ),
                            "query": (
                                stalwart_v016.build_migration_cli_account_query_command(
                                    container_id,
                                )
                            ),
                            "stop": (
                                stalwart_v016.build_migration_compose_stop_command(
                                    plan,
                                )
                            ),
                        }
                        cancellation: BaseException = (
                            KeyboardInterrupt()
                            if cancellation_kind == "keyboard-interrupt"
                            else SystemExit(73)
                        )
                        calls: list[list[str]] = []
                        captured_leases: list[object] = []
                        original_loader = (
                            stalwart_v016._load_recovery_credential_lease
                        )

                        def recording_loader(
                            *args: object,
                            **kwargs: object,
                        ) -> object:
                            lease = original_loader(*args, **kwargs)
                            captured_leases.append(lease)
                            return lease

                        def runner(
                            args: list[str],
                            *,
                            stdin: bytes,
                            env: dict[str, str],
                            timeout: int | float,
                            cwd: Path,
                            credential: memoryview | None = None,
                        ) -> object:
                            del stdin, env, timeout, cwd, credential
                            calls.append(list(args))
                            if args == commands[cancellation_stage]:
                                raise cancellation
                            if args == commands["image"]:
                                return stalwart_v016.RedactedCommandResult(
                                    (
                                        stalwart_v016.STALWART_IMAGE_ID + "\n"
                                    ).encode("ascii"),
                                    b"",
                                )
                            if args == commands["ps"]:
                                return stalwart_v016.RedactedCommandResult(
                                    (container_id + "\n").encode("ascii"),
                                    b"",
                                )
                            if args == commands["inspect"]:
                                return stalwart_v016.RedactedCommandResult(
                                    json.dumps(inspection).encode("utf-8"),
                                    b"",
                                )
                            if args == commands["version"]:
                                return stalwart_v016.RedactedCommandResult(
                                    b"0.16.17\n",
                                    b"",
                                )
                            if args == commands["query"]:
                                return stalwart_v016.RedactedCommandResult(
                                    b"[]\n",
                                    b"",
                                )
                            return stalwart_v016.RedactedCommandResult(b"", b"")

                        verifier = stalwart_v016.MigrationPostApplyVerifier(
                            runner=runner,
                            secret_runner=runner,
                            state_runner=fixture.runner,
                        )
                        raised: BaseException | None = None
                        with (
                            mock.patch.object(
                                stalwart_v016,
                                "_load_recovery_credential_lease",
                                side_effect=recording_loader,
                            ),
                            mock.patch.dict(os.environ, {}, clear=True),
                        ):
                            try:
                                verifier(plan)
                            except BaseException as exc:
                                raised = exc

                        self.assertIs(raised, cancellation)
                        self.assertEqual(calls[-1], commands["stop"])
                        self.assertEqual(len(captured_leases), 1)
                        self.assertTrue(captured_leases[0].closed)
                        self.assertFalse(fixture.paths.apply_receipt.exists())
                        self.assertNotIn("unit-secret", str(raised))

    def test_post_apply_account_census_matches_split_account_create_counts(
        self,
    ) -> None:
        cases = {
            "exact": b'[{"id":"group-1"},{"id":"group-2"},{"id":"user-1"}]',
            "too-few": b'[{"id":"group-1"},{"id":"user-1"}]',
            "too-many": (
                b'[{"id":"group-1"},{"id":"group-2"},'
                b'{"id":"user-1"},{"id":"user-2"}]'
            ),
            "duplicate": (
                b'[{"id":"group-1"},{"id":"group-1"},{"id":"user-1"}]'
            ),
        }
        for case, query_output in cases.items():
            with self.subTest(case=case):
                with tempfile.TemporaryDirectory() as directory:
                    fixture = self._fixture(directory)
                    base_plan = self._pre_dispatch_plan(fixture)
                    operations = (
                        stalwart_v016.ApplyOperation("create", "Account", 2),
                        stalwart_v016.ApplyOperation("create", "Account", 1),
                        stalwart_v016.ApplyOperation("create", "Group", 4),
                        stalwart_v016.ApplyOperation("create", "User", 5),
                    )
                    plan = replace(
                        base_plan,
                        operations=operations,
                        operations_sha256=(
                            stalwart_v016.apply_operation_plan_sha256(
                                operations,
                            )
                        ),
                    )
                    self._materialize_runtime(fixture)
                    container_id = "a" * 64
                    inspection = self._valid_runtime_inspection(
                        fixture,
                        plan,
                        container_id,
                    )
                    calls: list[list[str]] = []

                    def runner(
                        args: list[str],
                        *,
                        stdin: bytes,
                        env: dict[str, str],
                        timeout: int | float,
                        cwd: Path,
                        credential: memoryview | None = None,
                    ) -> object:
                        del stdin, env, timeout, cwd, credential
                        calls.append(list(args))
                        if (
                            args
                            == stalwart_v016.build_migration_image_inspect_command()
                        ):
                            return stalwart_v016.RedactedCommandResult(
                                (
                                    stalwart_v016.STALWART_IMAGE_ID + "\n"
                                ).encode("ascii"),
                                b"",
                            )
                        if args == stalwart_v016.build_migration_compose_ps_command(
                            plan,
                        ):
                            return stalwart_v016.RedactedCommandResult(
                                (container_id + "\n").encode("ascii"),
                                b"",
                            )
                        if args[:3] == ["docker", "inspect", "--type"]:
                            return stalwart_v016.RedactedCommandResult(
                                json.dumps(inspection).encode("utf-8"),
                                b"",
                            )
                        if (
                            args
                            == stalwart_v016.build_migration_server_version_command(
                                container_id,
                            )
                        ):
                            return stalwart_v016.RedactedCommandResult(
                                b"0.16.17\n",
                                b"",
                            )
                        if (
                            args
                            == stalwart_v016.build_migration_cli_account_query_command(
                                container_id,
                            )
                        ):
                            return stalwart_v016.RedactedCommandResult(
                                query_output,
                                b"",
                            )
                        return stalwart_v016.RedactedCommandResult(b"", b"")

                    verifier = stalwart_v016.MigrationPostApplyVerifier(
                        runner=runner,
                        secret_runner=runner,
                        state_runner=fixture.runner,
                    )
                    if case == "exact":
                        proof = verifier(plan)
                        self.assertEqual(proof.operation_count, 4)
                        self.assertEqual(proof.management_status, 200)
                    else:
                        with self.assertRaisesRegex(
                            stalwart_v016.MigrationError,
                            "failed safely",
                        ):
                            verifier(plan)
                    self.assertEqual(
                        calls[-1],
                        stalwart_v016.build_migration_compose_stop_command(plan),
                    )

    def test_runtime_inspection_rejects_another_well_formed_image_id(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            plan = self._pre_dispatch_plan(fixture)
            container_id = "a" * 64
            inspection = self._valid_runtime_inspection(
                fixture,
                plan,
                container_id,
            )
            inspection["ImageID"] = "sha256:" + "c" * 64

            with self.assertRaisesRegex(
                stalwart_v016.MigrationError,
                "inspection",
            ):
                stalwart_v016._validate_migration_container_inspection(
                    json.dumps(inspection).encode("utf-8"),
                    plan=plan,
                    container_id=container_id,
                )

    def test_runtime_validator_rejects_broad_overlapping_custom_and_wrong_sources(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            source = verified_source_fixture(
                fixture.repository,
                fixture.source_store,
            )
            runtime = stalwart_v016.build_migration_runtime_paths(
                fixture.paths,
                source,
            )
            runtime_type = stalwart_v016.MigrationRuntimePaths
            invalid_runtimes = {
                "root": runtime_type(
                    data_dir=Path("/"),
                    config_dir=runtime.config_dir,
                    recovery_env_file=runtime.recovery_env_file,
                    compose_overlay=runtime.compose_overlay,
                ),
                "same": runtime_type(
                    data_dir=runtime.data_dir,
                    config_dir=runtime.data_dir,
                    recovery_env_file=runtime.recovery_env_file,
                    compose_overlay=runtime.compose_overlay,
                ),
                "overlap": runtime_type(
                    data_dir=runtime.data_dir,
                    config_dir=runtime.data_dir / "nested",
                    recovery_env_file=runtime.recovery_env_file,
                    compose_overlay=runtime.compose_overlay,
                ),
                "custom": runtime_type(
                    data_dir=runtime.data_dir,
                    config_dir=runtime.config_dir,
                    recovery_env_file=fixture.paths.migration_root / "custom.env",
                    compose_overlay=runtime.compose_overlay,
                ),
                "wrong-overlay-name": runtime_type(
                    data_dir=runtime.data_dir,
                    config_dir=runtime.config_dir,
                    recovery_env_file=runtime.recovery_env_file,
                    compose_overlay=fixture.repository / "compose.yml",
                ),
            }
            for case, candidate in invalid_runtimes.items():
                with self.subTest(case=case):
                    with self.assertRaisesRegex(
                        stalwart_v016.MigrationError,
                        "broad|overlap|exact|fixed",
                    ):
                        stalwart_v016.validate_migration_runtime_paths(
                            fixture.paths,
                            source,
                            candidate,
                        )

            wrong_checkout = fixture.repository / "wrong-checkout"
            wrong_checkout.mkdir(mode=0o700)
            wrong_name = fixture.repository / "wrong-provider-data"
            wrong_name.mkdir(mode=0o700)
            for case, invalid_source in {
                "checkout": verified_source_fixture(
                    wrong_checkout,
                    fixture.source_store,
                ),
                "name": verified_source_fixture(
                    fixture.repository,
                    wrong_name,
                ),
            }.items():
                with self.subTest(case=case):
                    with self.assertRaisesRegex(
                        stalwart_v016.MigrationError,
                        "checkout|stalwart-data|source",
                    ):
                        stalwart_v016.build_migration_runtime_paths(
                            fixture.paths,
                            invalid_source,
                        )

    def test_runtime_builder_rejects_symlink_in_repository_ancestor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory).resolve()
            actual = workspace / "actual"
            actual.mkdir(mode=0o700)
            linked = workspace / "linked"
            linked.symlink_to(actual, target_is_directory=True)
            repository = linked / "repository"
            repository.mkdir(mode=0o700)
            paths = stalwart_v016.MigrationPaths.for_repository(repository)
            paths.migration_root.mkdir(mode=0o700, parents=True)
            paths.migration_root.chmod(0o700)
            overlay = repository / "docker-compose.stalwart-migration.yml"
            overlay.write_bytes(CANONICAL_MIGRATION_OVERLAY)
            overlay.chmod(0o644)
            checkout = workspace / "source"
            checkout.mkdir(mode=0o700)
            store = checkout / "stalwart-data"
            store.mkdir(mode=0o700)
            source = verified_source_fixture(checkout, store)

            with self.assertRaisesRegex(
                stalwart_v016.MigrationError,
                "symlink",
            ):
                stalwart_v016.build_migration_runtime_paths(paths, source)

    def test_fixed_runtime_symlinks_block_executor_without_creating_receipt(
        self,
    ) -> None:
        for case in ("config", "environment", "overlay"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                fixture = self._fixture(directory)
                outside = fixture.repository / "outside"
                outside.mkdir(mode=0o700)
                if case == "config":
                    (
                        fixture.paths.migration_root / "recovery-config"
                    ).symlink_to(outside, target_is_directory=True)
                elif case == "environment":
                    outside_file = outside / "recovery.env"
                    self._write_0600(outside_file, b"UNIT_ONLY=1\n")
                    (
                        fixture.paths.migration_root / "recovery.env"
                    ).symlink_to(outside_file)
                else:
                    overlay = (
                        fixture.repository
                        / "docker-compose.stalwart-migration.yml"
                    )
                    overlay.unlink()
                    outside_overlay = outside / "migration.yml"
                    outside_overlay.write_bytes(CANONICAL_MIGRATION_OVERLAY)
                    outside_overlay.chmod(0o644)
                    overlay.symlink_to(outside_overlay)
                executor = mock.Mock(return_value=self._valid_evidence())

                with self.assertRaisesRegex(
                    stalwart_v016.MigrationError,
                    "symlink",
                ):
                    self._prepare(fixture, executor)

                executor.assert_not_called()
                self.assertFalse(fixture.paths.apply_receipt.exists())

    def test_executor_receives_one_frozen_redacted_fixed_content_free_plan(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            observed: list[object] = []

            def executor(plan: object) -> str:
                observed.append(plan)
                return self._valid_evidence()

            self._prepare(fixture, executor)

            self.assertEqual(len(observed), 1)
            plan = observed[0]
            self.assertIsInstance(plan, stalwart_v016.ApplyPlan)
            self.assertTrue(plan.__dataclass_params__.frozen)
            self.assertEqual(repr(plan), "ApplyPlan(<redacted>)")
            self.assertNotIn(str(fixture.repository), repr(plan))
            self.assertFalse(hasattr(plan, "bootstrap_receipt"))
            self.assertFalse(hasattr(plan, "bootstrap"))
            self.assertIsInstance(
                plan.runtime,
                stalwart_v016.MigrationRuntimePaths,
            )
            self.assertEqual(repr(plan.runtime), "MigrationRuntimePaths(<redacted>)")
            self.assertEqual(plan.runtime.data_dir, fixture.source_store)
            self.assertEqual(plan.source.checkout_root, fixture.repository)
            self.assertEqual(
                plan.source.base_compose,
                fixture.repository / "docker-compose.yml",
            )
            self.assertEqual(plan.source.compose_project, "mail-sandbox")
            self.assertEqual(plan.source.compose_service, "stalwart")
            self.assertEqual(repr(plan.source), "VerifiedSource(<redacted>)")
            self.assertEqual(
                plan.runtime.compose_overlay,
                fixture.repository / "docker-compose.stalwart-migration.yml",
            )
            with self.assertRaises((AttributeError, TypeError)):
                plan.inputs = ()
            self.assertEqual(
                tuple(item.path for item in plan.inputs),
                (
                    fixture.paths.source_receipt,
                    fixture.paths.migration_script,
                    fixture.paths.dry_run_receipt,
                    fixture.paths.reviewed,
                    fixture.repository
                    / "docker-compose.stalwart-migration.yml",
                    fixture.repository / "docker-compose.yml",
                ),
            )
            self.assertEqual(
                tuple(item.path for item in plan.artifacts),
                fixture.paths.dry_run_outputs,
            )
            for item in (*plan.inputs, *plan.artifacts):
                self.assertEqual(
                    set(item.__dataclass_fields__),
                    {"path", "sha256", "size", "identity"},
                )
                self.assertRegex(item.sha256, r"^[0-9a-f]{64}$")
                self.assertGreaterEqual(item.size, 0)
                self.assertEqual(len(item.identity), 6)
                self.assertTrue(
                    all(type(value) is int for value in item.identity),
                )
            self.assertEqual(
                tuple(
                    (operation.op, operation.object_name)
                    for operation in plan.operations
                ),
                fixture.operations,
            )
            self.assertEqual(
                self._operation_digest(fixture.operations),
                plan.operations_sha256,
            )

    def test_all_preflight_validation_precedes_one_executor_and_postflight_precedes_receipt(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            validations = {"script": 0, "dry": 0, "review": 0}
            events = fixture.events
            original_script = stalwart_v016.validate_migration_script
            original_dry = stalwart_v016.validate_dry_run_receipt
            original_review = stalwart_v016.validate_review_receipt
            original_write = stalwart_v016._write_new_json_0600

            def script_validator(*args: object, **kwargs: object) -> object:
                result = original_script(*args, **kwargs)
                validations["script"] += 1
                events.append("script")
                return result

            def dry_validator(*args: object, **kwargs: object) -> object:
                result = original_dry(*args, **kwargs)
                validations["dry"] += 1
                events.append("dry")
                return result

            def review_validator(*args: object, **kwargs: object) -> object:
                result = original_review(*args, **kwargs)
                validations["review"] += 1
                events.append("review")
                return result

            def receipt_writer(*args: object, **kwargs: object) -> object:
                target = args[0]
                events.append(
                    "publish-attempt"
                    if target == fixture.paths.apply_attempt
                    else "publish-receipt",
                )
                return original_write(*args, **kwargs)

            def executor(_plan: object) -> str:
                self.assertEqual(validations, {"script": 1, "dry": 1, "review": 1})
                events.append("executor-enter")
                events.append("executor-cleanup-return")
                return self._valid_evidence()

            def post_apply_verifier(plan: object) -> object:
                events.append("post-apply-verifier")
                return self._valid_post_apply_proof(plan)

            with (
                mock.patch.object(
                    stalwart_v016,
                    "validate_migration_script",
                    side_effect=script_validator,
                ),
                mock.patch.object(
                    stalwart_v016,
                    "validate_dry_run_receipt",
                    side_effect=dry_validator,
                ),
                mock.patch.object(
                    stalwart_v016,
                    "validate_review_receipt",
                    side_effect=review_validator,
                ),
                mock.patch.object(
                    stalwart_v016,
                    "_write_new_json_0600",
                    side_effect=receipt_writer,
                ),
            ):
                receipt = self._prepare(
                    fixture,
                    executor,
                    post_apply_verifier=post_apply_verifier,
                )

            self.assertEqual(receipt, fixture.paths.apply_receipt)
            self.assertEqual(validations, {"script": 3, "dry": 3, "review": 3})
            self.assertEqual(events.count("executor-enter"), 1)
            executor_index = events.index("executor-enter")
            cleanup_index = events.index("executor-cleanup-return")
            attempt_index = events.index("publish-attempt")
            publish_index = events.index("publish-receipt")
            verifier_index = events.index("post-apply-verifier")
            self.assertLess(events.index("review"), executor_index)
            self.assertLess(attempt_index, executor_index)
            self.assertLess(cleanup_index, events.index("verify", cleanup_index))
            self.assertLess(events.index("review", cleanup_index), verifier_index)
            self.assertLess(verifier_index, publish_index)

    def test_stale_invalid_or_mutated_preflight_input_blocks_executor(self) -> None:
        cases = (
            "stale-source",
            "script",
            "artifact",
            "review",
            "overlay-content",
            "overlay-mode",
            "runtime-config",
            "runtime-environment",
        )
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                fixture = self._fixture(directory)
                if case == "stale-source":
                    fixture.state["stale_source"] = True
                elif case == "script":
                    self._write_0600(
                        fixture.paths.migration_script,
                        b"mutated script\n",
                    )
                elif case == "artifact":
                    self._write_0600(
                        fixture.paths.export,
                        b'{"changed":"before apply"}\n',
                    )
                elif case == "review":
                    self._write_0600(fixture.paths.reviewed, b"{}\n")
                elif case == "overlay-content":
                    overlay = (
                        fixture.repository
                        / "docker-compose.stalwart-migration.yml"
                    )
                    overlay.write_bytes(CANONICAL_MIGRATION_OVERLAY + b" ")
                    overlay.chmod(0o644)
                elif case == "overlay-mode":
                    (
                        fixture.repository
                        / "docker-compose.stalwart-migration.yml"
                    ).chmod(0o600)
                elif case == "runtime-config":
                    (
                        fixture.paths.migration_root / "recovery-config"
                    ).mkdir(mode=0o755)
                else:
                    self._write_0600(
                        fixture.paths.migration_root / "recovery.env",
                        b"STALWART_RECOVERY_ADMIN=stale:secret\n",
                    )
                executor = mock.Mock(return_value=self._valid_evidence())

                with self.assertRaises(stalwart_v016.MigrationError):
                    self._prepare(fixture, executor)

                executor.assert_not_called()
                self.assertFalse(fixture.paths.apply_attempt.exists())
                self.assertFalse(fixture.paths.apply_receipt.exists())

    def test_apply_preflight_requires_exact_regular_0644_checkout_config(
        self,
    ) -> None:
        cases: dict[str, bytes | None] = {
            "compact": b'{"@type":"RocksDb","path":"/var/lib/stalwart/"}',
            "trailing-newline": AUDITED_CONVERTED_CONFIG_BYTES + b"\n",
            "wrong-mode": AUDITED_CONVERTED_CONFIG_BYTES,
            "directory": None,
        }
        for case, content in cases.items():
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                fixture = self._fixture(directory)
                if case == "directory":
                    fixture.normal_config.unlink()
                    fixture.normal_config.mkdir(mode=0o755)
                else:
                    assert content is not None
                    fixture.normal_config.write_bytes(content)
                    fixture.normal_config.chmod(
                        0o600 if case == "wrong-mode" else 0o644,
                    )
                executor = mock.Mock(return_value=self._valid_evidence())

                with self.assertRaisesRegex(
                    stalwart_v016.MigrationError,
                    "normal config|converted config|regular file|0644",
                ):
                    self._prepare(fixture, executor)

                executor.assert_not_called()
                self.assertFalse(fixture.paths.apply_attempt.exists())
                self.assertFalse(fixture.paths.apply_receipt.exists())
                self.assertFalse(
                    (fixture.paths.migration_root / "recovery-config").exists(),
                )
                if content is not None:
                    self.assertEqual(fixture.normal_config.read_bytes(), content)

    def test_runtime_plan_revalidates_checkout_config_before_any_writer(
        self,
    ) -> None:
        for content in (
            b'{"@type":"RocksDb","path":"/var/lib/stalwart/"}',
            AUDITED_CONVERTED_CONFIG_BYTES + b"\n",
        ):
            with self.subTest(content=content), tempfile.TemporaryDirectory() as directory:
                fixture = self._fixture(directory)
                plan = self._pre_dispatch_plan(fixture)
                fixture.normal_config.write_bytes(content)
                fixture.normal_config.chmod(0o644)

                with self.assertRaisesRegex(
                    stalwart_v016.MigrationError,
                    "normal config|converted config|match",
                ):
                    stalwart_v016._validated_runtime_plan_files(plan)

                self.assertFalse(plan.runtime.config_dir.exists())
                self.assertFalse(plan.runtime.recovery_env_file.exists())
                self.assertEqual(fixture.normal_config.read_bytes(), content)

    def test_wrong_fixed_path_and_preflight_writer_block_executor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            executor = mock.Mock(return_value=self._valid_evidence())
            with self.assertRaisesRegex(stalwart_v016.MigrationError, "fixed"):
                self._prepare(
                    fixture,
                    executor,
                    source_receipt_path=fixture.repository / "other.json",
                )
            executor.assert_not_called()
            self.assertEqual(fixture.events, [])
            self.assertFalse(fixture.paths.apply_attempt.exists())

        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            fixture.state["writer"] = True
            executor = mock.Mock(return_value=self._valid_evidence())
            with self.assertRaisesRegex(
                stalwart_v016.MigrationError,
                "running writer",
            ):
                self._prepare(fixture, executor)
            executor.assert_not_called()
            self.assertFalse(fixture.paths.apply_attempt.exists())
            self.assertFalse(fixture.paths.apply_receipt.exists())

    def test_post_executor_mutation_or_lingering_writer_blocks_receipt(self) -> None:
        for case in (
            "source-receipt",
            "script",
            "dry-run-receipt",
            "review-receipt",
            "artifact",
            "overlay",
            "writer",
        ):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                fixture = self._fixture(directory)

                def executor(_plan: object) -> str:
                    if case == "source-receipt":
                        self._write_0600(
                            fixture.paths.source_receipt,
                            fixture.paths.source_receipt.read_bytes() + b" ",
                        )
                    elif case == "script":
                        self._write_0600(
                            fixture.paths.migration_script,
                            b"changed after executor\n",
                        )
                    elif case == "dry-run-receipt":
                        self._write_0600(
                            fixture.paths.dry_run_receipt,
                            fixture.paths.dry_run_receipt.read_bytes() + b" ",
                        )
                    elif case == "review-receipt":
                        self._write_0600(
                            fixture.paths.reviewed,
                            fixture.paths.reviewed.read_bytes() + b" ",
                        )
                    elif case == "artifact":
                        self._write_0600(
                            fixture.paths.export,
                            b'{"changed":"after executor"}\n',
                        )
                    elif case == "overlay":
                        overlay = (
                            fixture.repository
                            / "docker-compose.stalwart-migration.yml"
                        )
                        overlay.write_bytes(
                            CANONICAL_MIGRATION_OVERLAY + b" ",
                        )
                        overlay.chmod(0o644)
                    else:
                        fixture.state["writer"] = True
                    return self._valid_evidence()

                with self.assertRaisesRegex(
                    stalwart_v016.MigrationError,
                    "reconciliation",
                ):
                    self._prepare(fixture, executor)

                self.assertTrue(fixture.paths.apply_attempt.exists())
                self.assertFalse(fixture.paths.apply_receipt.exists())
                self.assertGreaterEqual(fixture.events.count("census"), 2)

    def test_executor_failure_or_invalid_evidence_never_writes_receipt(self) -> None:
        scenarios = {
            "executor": RuntimeError("unit-only executor failure"),
            "malformed": "not-json",
            "failed-operation": "\n".join(
                [
                    json.dumps(
                        {
                            "op": "create",
                            "object": "principal/unit-fixture",
                            "status": "failed",
                        },
                    ),
                    json.dumps(
                        {
                            "op": "summary",
                            "plan": {
                                "destroyed": 0,
                                "updated": 0,
                                "created": 0,
                            },
                            "done": {
                                "destroyed": 0,
                                "updated": 0,
                                "created": 0,
                                "failed": 0,
                            },
                        },
                    ),
                ],
            ),
            "failed-summary": self._valid_evidence().replace(
                '"failed": 0',
                '"failed": 1',
            ),
        }
        for case, outcome in scenarios.items():
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                fixture = self._fixture(directory)

                def executor(_plan: object) -> str:
                    if isinstance(outcome, Exception):
                        raise outcome
                    return outcome

                with self.assertRaises(stalwart_v016.MigrationError):
                    self._prepare(fixture, executor)

                self.assertTrue(fixture.paths.apply_attempt.exists())
                self.assertFalse(fixture.paths.apply_receipt.exists())
                if case == "executor":
                    self.assertGreaterEqual(
                        fixture.events.count("census"),
                        2,
                    )

    def test_full_postflight_preserves_clean_baseexception_and_reconciles_dirty_failure(
        self,
    ) -> None:
        for error in (
            RuntimeError("unit-runtime-secret"),
            KeyboardInterrupt("unit-keyboard-secret"),
            SystemExit("unit-system-exit-secret"),
        ):
            with (
                self.subTest(error=type(error).__name__),
                tempfile.TemporaryDirectory() as directory,
            ):
                fixture = self._fixture(directory)
                verifier = mock.Mock()

                def executor(_plan: object) -> str:
                    self._materialize_runtime(fixture)
                    raise error

                with self.assertRaises(BaseException) as raised:
                    self._prepare(
                        fixture,
                        executor,
                        post_apply_verifier=verifier,
                        materialize_runtime=False,
                    )

                self.assertIs(raised.exception, error)
                verifier.assert_not_called()
                self.assertGreaterEqual(fixture.events.count("census"), 2)
                self.assertTrue(fixture.paths.apply_attempt.exists())
                self.assertFalse(fixture.paths.apply_receipt.exists())

        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            secret = "unit-dirty-executor-secret"

            def dirty_executor(_plan: object) -> str:
                self._materialize_runtime(fixture)
                fixture.state["writer"] = True
                raise RuntimeError(secret)

            with self.assertRaisesRegex(
                stalwart_v016.MigrationError,
                "reconciliation",
            ) as raised:
                self._prepare(
                    fixture,
                    dirty_executor,
                    materialize_runtime=False,
                )

            self.assertNotIn(secret, str(raised.exception))
            self.assertGreaterEqual(fixture.events.count("census"), 2)
            self.assertTrue(fixture.paths.apply_attempt.exists())
            self.assertFalse(fixture.paths.apply_receipt.exists())
    class _LockToken:
        def __init__(self, repository: Path, events: list[str]) -> None:
            self.repository = repository
            self.events = events

        def assert_valid_for(self, repository: Path) -> None:
            if repository != self.repository:
                raise AssertionError("wrong repository")
            self.events.append("lock-valid")

    class _LockContext:
        def __init__(self, repository: Path, events: list[str]) -> None:
            self.token = ApplyPreparationTest._LockToken(
                repository,
                events,
            )
            self.events = events

        def __enter__(self) -> object:
            self.events.append("lock-enter")
            return self.token

        def __exit__(
            self,
            _error_type: object,
            _error: object,
            _traceback: object,
        ) -> None:
            self.events.append("lock-exit")

    @staticmethod
    def _paths(directory: str) -> object:
        repository = Path(directory).resolve() / "mail-sandbox"
        (repository / "debug-dashboard").mkdir(parents=True)
        return stalwart_v016.MigrationPaths.for_repository(repository)

    @staticmethod
    def _unexpected_current_finalizer(_repository: Path) -> Path:
        raise AssertionError("current finalizer unexpectedly reached")

    def test_production_retirement_holds_one_lock_across_both_bootstrap_phases(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            paths = self._paths(directory)
            paths.migration_root.mkdir(parents=True)
            events: list[str] = []
            task6_phases: list[str] = []

            class BootstrapPaths:
                @staticmethod
                def for_repository(repository: Path) -> tuple[str, Path]:
                    events.append("bootstrap-paths")
                    return ("bootstrap-paths", repository)

            class BootstrapModule:
                @staticmethod
                def validate_final_bootstrap_for_retirement(
                    bootstrap_paths: object,
                    *,
                    task6_validator: object,
                ) -> str:
                    phase = task6_validator(paths.apply_receipt)
                    events.append(f"bootstrap-{phase}")
                    self.assertEqual(
                        bootstrap_paths,
                        ("bootstrap-paths", paths.repository_root),
                    )
                    return f"validated-{phase}"

                @staticmethod
                def finalize_migrated_current_runtime(
                    repository: Path,
                ) -> Path:
                    events.append("finalize-current")
                    self.assertEqual(repository, paths.repository_root)
                    current = (
                        repository
                        / "debug-dashboard"
                        / ".runtime"
                        / "stalwart"
                        / "current.json"
                    )
                    current.parent.mkdir(parents=True, exist_ok=True)
                    current.write_text("{}\n", encoding="utf-8")
                    current.chmod(0o600)
                    return current

            BootstrapModule.BootstrapPaths = BootstrapPaths

            acquire = mock.Mock(
                side_effect=lambda repository: (
                    events.append("acquire")
                    or self._LockContext(repository, events)
                ),
            )
            loader = mock.Mock(
                side_effect=lambda repository: (
                    events.append("load-bootstrap") or BootstrapModule
                ),
            )

            def task6_factory(
                selected_paths: object,
                **kwargs: object,
            ) -> object:
                self.assertIs(selected_paths, paths)
                phase = kwargs["runtime_phase"]
                task6_phases.append(phase)
                events.append(f"task6-{phase}")
                return lambda receipt: (
                    phase
                    if receipt == paths.apply_receipt
                    else self.fail("non-fixed apply receipt")
                )

            executor = mock.Mock(return_value="executor-proof")
            verifier = mock.Mock(return_value="verifier-proof")
            executor_factory = mock.Mock(
                side_effect=lambda **_kwargs: (
                    events.append("executor-factory") or executor
                ),
            )
            verifier_factory = mock.Mock(
                side_effect=lambda **_kwargs: (
                    events.append("verifier-factory") or verifier
                ),
            )

            def prepare(selected_paths: object, **kwargs: object) -> Path:
                events.append("prepare")
                self.assertIs(selected_paths, paths)
                validator = kwargs["bootstrap_receipt_validator"]
                self.assertEqual(validator("ready"), "validated-ready")
                kwargs["executor"]("plan", "lease", "checkpoint")
                kwargs["postflight_verifier"]("plan")
                self.assertEqual(validator("retired"), "validated-retired")
                paths.recovery_retired_receipt.write_text(
                    "{}\n",
                    encoding="utf-8",
                )
                paths.recovery_retired_receipt.chmod(0o600)
                return paths.recovery_retired_receipt

            dependencies = (
                stalwart_v016.ProductionRecoveryRetirementDependencies(
                    acquire_operation_lock=acquire,
                    prepare=prepare,
                    bootstrap_module_loader=loader,
                    bootstrap_apply_validator_factory=task6_factory,
                    retirement_executor_factory=executor_factory,
                    postflight_verifier_factory=verifier_factory,
                    state_runner=mock.Mock(),
                    runtime_runner=mock.Mock(),
                    jmap_probe_runner=mock.Mock(),
                )
            )

            result = stalwart_v016.run_production_recovery_retirement(
                paths,
                dependencies=dependencies,
                expected_script_sha256="a" * 64,
            )

            self.assertEqual(result, paths.recovery_retired_receipt)
            acquire.assert_called_once_with(paths.repository_root)
            loader.assert_called_once_with(paths.repository_root)
            self.assertEqual(task6_phases, ["ready", "retired"])
            executor.assert_called_once_with("plan", "lease", "checkpoint")
            verifier.assert_called_once_with("plan")
            self.assertLess(events.index("lock-enter"), events.index("load-bootstrap"))
            self.assertLess(events.index("load-bootstrap"), events.index("prepare"))
            self.assertLess(events.index("bootstrap-retired"), events.index("lock-exit"))
            self.assertLess(events.index("finalize-current"), events.index("lock-exit"))
            self.assertGreaterEqual(events.count("lock-valid"), 9)

    def test_current_receipt_publication_failure_never_rolls_back_and_resumes(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            paths = self._paths(directory)
            paths.migration_root.mkdir(parents=True)
            events: list[str] = []
            finalizer_calls = 0
            rollback = mock.Mock()

            class BootstrapModule:
                class BootstrapPaths:
                    @staticmethod
                    def for_repository(repository: Path) -> Path:
                        return repository

                @staticmethod
                def validate_final_bootstrap_for_retirement(
                    _paths: object,
                    *,
                    task6_validator: object,
                ) -> object:
                    return task6_validator(paths.apply_receipt)

                @staticmethod
                def finalize_migrated_current_runtime(
                    repository: Path,
                ) -> Path:
                    nonlocal finalizer_calls
                    finalizer_calls += 1
                    events.append("finalize-current")
                    if finalizer_calls == 1:
                        raise RuntimeError("injected publication failure")
                    current = (
                        repository
                        / "debug-dashboard"
                        / ".runtime"
                        / "stalwart"
                        / "current.json"
                    )
                    current.parent.mkdir(parents=True, exist_ok=True)
                    current.write_text("{}\n", encoding="utf-8")
                    current.chmod(0o600)
                    return current

            def prepare(_paths: object, **_kwargs: object) -> Path:
                events.append("prepare")
                paths.recovery_retired_receipt.write_text(
                    "{}\n",
                    encoding="utf-8",
                )
                paths.recovery_retired_receipt.chmod(0o600)
                return paths.recovery_retired_receipt

            dependencies = (
                stalwart_v016.ProductionRecoveryRetirementDependencies(
                    acquire_operation_lock=lambda repository: self._LockContext(
                        repository,
                        events,
                    ),
                    prepare=prepare,
                    bootstrap_module_loader=lambda _root: BootstrapModule,
                    bootstrap_apply_validator_factory=(
                        lambda *_args, **_kwargs: mock.Mock()
                    ),
                    retirement_executor_factory=lambda **_kwargs: mock.Mock(),
                    postflight_verifier_factory=lambda **_kwargs: mock.Mock(),
                    state_runner=mock.Mock(),
                    runtime_runner=mock.Mock(),
                    jmap_probe_runner=mock.Mock(),
                    rollback_activator=rollback,
                    existing_retirement_plan_loader=(
                        lambda *_args, **_kwargs: None
                    ),
                )
            )

            with self.assertRaisesRegex(
                stalwart_v016.MigrationError,
                "current runtime finalization failed safely",
            ):
                stalwart_v016.run_production_recovery_retirement(
                    paths,
                    dependencies=dependencies,
                    expected_script_sha256="a" * 64,
                )

            current = (
                paths.repository_root
                / "debug-dashboard"
                / ".runtime"
                / "stalwart"
                / "current.json"
            )
            self.assertTrue(paths.recovery_retired_receipt.is_file())
            self.assertFalse(current.exists())
            rollback.assert_not_called()

            receipt = stalwart_v016.run_production_recovery_retirement(
                paths,
                dependencies=dependencies,
                expected_script_sha256="a" * 64,
            )

            self.assertEqual(receipt, paths.recovery_retired_receipt)
            self.assertTrue(current.is_file())
            self.assertEqual(finalizer_calls, 2)
            self.assertEqual(events.count("prepare"), 2)
            rollback.assert_not_called()

    def test_malformed_current_receipt_stops_before_retirement_prepare(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            paths = self._paths(directory)
            paths.migration_root.mkdir(parents=True)
            current = (
                paths.repository_root
                / "debug-dashboard"
                / ".runtime"
                / "stalwart"
                / "current.json"
            )
            current.parent.mkdir(parents=True)
            current.write_text('{"malformed":true}\n', encoding="utf-8")
            current.chmod(0o600)

            class BootstrapModule:
                class BootstrapPaths:
                    @staticmethod
                    def for_repository(repository: Path) -> Path:
                        return repository

                @staticmethod
                def validate_final_bootstrap_for_retirement(
                    _paths: object,
                    *,
                    task6_validator: object,
                ) -> object:
                    return task6_validator(paths.apply_receipt)

                finalize_migrated_current_runtime = staticmethod(
                    bootstrap_stalwart_v016.finalize_migrated_current_runtime
                )

            prepare = mock.Mock()
            executor = mock.Mock()
            executor_factory = mock.Mock(return_value=executor)
            verifier_factory = mock.Mock()
            rollback = mock.Mock()
            existing_plan_loader = mock.Mock(return_value=None)
            dependencies = (
                stalwart_v016.ProductionRecoveryRetirementDependencies(
                    acquire_operation_lock=lambda repository: self._LockContext(
                        repository,
                        [],
                    ),
                    prepare=prepare,
                    bootstrap_module_loader=lambda _root: BootstrapModule,
                    bootstrap_apply_validator_factory=mock.Mock(),
                    retirement_executor_factory=executor_factory,
                    postflight_verifier_factory=verifier_factory,
                    state_runner=mock.Mock(),
                    runtime_runner=mock.Mock(),
                    jmap_probe_runner=mock.Mock(),
                    rollback_activator=rollback,
                    existing_retirement_plan_loader=existing_plan_loader,
                )
            )

            with self.assertRaisesRegex(
                stalwart_v016.MigrationError,
                "current runtime finalization failed safely",
            ):
                stalwart_v016.run_production_recovery_retirement(
                    paths,
                    dependencies=dependencies,
                    expected_script_sha256="a" * 64,
                )

            self.assertEqual(
                current.read_text(encoding="utf-8"),
                '{"malformed":true}\n',
            )
            prepare.assert_not_called()
            executor_factory.assert_not_called()
            executor.assert_not_called()
            verifier_factory.assert_not_called()
            rollback.assert_not_called()
            existing_plan_loader.assert_not_called()

    def test_production_retirement_failure_activates_rollback_before_or_after_deletion(
        self,
    ) -> None:
        self.assertIn(
            "rollback_activator",
            (
                stalwart_v016
                .ProductionRecoveryRetirementDependencies
                .__dataclass_fields__
            ),
        )
        for deletion_stage in ("before", "after"):
            with (
                self.subTest(deletion_stage=deletion_stage),
                tempfile.TemporaryDirectory() as directory,
            ):
                fixture = self._applied_fixture(directory)
                captured_plans: list[object] = []

                def capture_plan(
                    plan: object,
                    _lease: object,
                    _checkpoint: object,
                ) -> object:
                    captured_plans.append(plan)
                    raise RuntimeError("unit-only plan capture")

                with self.assertRaisesRegex(
                    stalwart_v016.MigrationError,
                    "reconciliation",
                ):
                    self._retire(
                        fixture,
                        capture_plan,
                        postflight_verifier=mock.Mock(),
                    )
                plan = captured_plans[0]
                config_path = (
                    fixture.paths.migration_root
                    / "recovery-config"
                    / "config.json"
                )
                environment_path = (
                    fixture.paths.migration_root / "recovery.env"
                )
                preserved = {
                    "store": tuple(fixture.source_store.rglob("*")),
                    "export": fixture.paths.export.read_bytes(),
                    "config": config_path.read_bytes(),
                    "environment": environment_path.read_bytes(),
                }
                events: list[str] = []
                recovery_started = False
                activations = 0

                class BootstrapModule:
                    class BootstrapPaths:
                        @staticmethod
                        def for_repository(repository: Path) -> Path:
                            return repository

                    @staticmethod
                    def validate_final_bootstrap_for_retirement(
                        _paths: object,
                        *,
                        task6_validator: object,
                    ) -> object:
                        return task6_validator(
                            fixture.paths.apply_receipt,
                        )

                    finalize_migrated_current_runtime = staticmethod(
                        ApplyPreparationTest._unexpected_current_finalizer
                    )

                def prepare(_paths: object, **kwargs: object) -> Path:
                    kwargs["executor"](plan, object(), object())
                    raise AssertionError(
                        "retirement failure was not propagated",
                    )

                def retirement_executor(
                    _plan: object,
                    _lease: object,
                    _checkpoint: object,
                ) -> object:
                    if deletion_stage == "after":
                        self._delete_recovery_artifacts(fixture)
                    raise RuntimeError(
                        "unit-secret retirement endpoint failure",
                    )

                def runtime_runner(
                    args: list[str],
                    **_kwargs: object,
                ) -> object:
                    nonlocal recovery_started
                    container_id = "f" * 64
                    if args == (
                        stalwart_v016.build_normal_recovery_ps_command(
                            plan,
                        )
                    ):
                        return stalwart_v016.RedactedCommandResult(
                            (container_id + "\n").encode("ascii"),
                            b"",
                        )
                    if args == (
                        stalwart_v016
                        .build_normal_recovery_container_inspect_command(
                            container_id,
                        )
                    ):
                        return stalwart_v016.RedactedCommandResult(
                            json.dumps(
                                self._valid_normal_recovery_inspection(
                                    fixture,
                                    container_id,
                                ),
                            ).encode("utf-8"),
                            b"",
                        )
                    self.assertEqual(
                        args,
                        stalwart_v016.build_bound_container_stop_command(
                            container_id,
                        ),
                    )
                    recovery_started = True
                    events.append("stop")
                    return stalwart_v016.RedactedCommandResult(b"", b"")

                def state_runner(args: list[str]) -> object:
                    if recovery_started and args[:2] == ["docker", "ps"]:
                        events.append("census")
                    return fixture.runner(args)

                def activate(
                    _receipt_path: Path,
                    *,
                    expected_receipt_sha256: str,
                ) -> object:
                    nonlocal activations
                    activations += 1
                    events.append("activate")
                    return self._valid_rollback_activation(
                        fixture,
                        expected_receipt_sha256=expected_receipt_sha256,
                    )

                dependencies = replace(
                    (
                        stalwart_v016
                        .production_recovery_retirement_dependencies()
                    ),
                    bootstrap_module_loader=lambda _root: BootstrapModule,
                    bootstrap_apply_validator_factory=(
                        lambda *_args, **_kwargs: mock.Mock()
                    ),
                    prepare=prepare,
                    retirement_executor_factory=(
                        lambda **_kwargs: retirement_executor
                    ),
                    postflight_verifier_factory=(
                        lambda **_kwargs: mock.Mock()
                    ),
                    state_runner=state_runner,
                    runtime_runner=runtime_runner,
                    jmap_probe_runner=mock.Mock(),
                    rollback_activator=activate,
                    existing_retirement_plan_loader=(
                        lambda *_args, **_kwargs: plan
                    ),
                )
                with self.assertRaisesRegex(
                    stalwart_v016.MigrationError,
                    "failed safely",
                ) as raised:
                    stalwart_v016.run_production_recovery_retirement(
                        fixture.paths,
                        dependencies=dependencies,
                        expected_script_sha256=fixture.script_digest,
                    )

                self.assertTrue(raised.exception.__suppress_context__)
                self.assertNotIn("unit-secret", str(raised.exception))
                self.assertEqual(activations, 1)
                self.assertEqual(events[-3:], ["stop", "census", "activate"])
                self.assertEqual(
                    tuple(fixture.source_store.rglob("*")),
                    preserved["store"],
                )
                self.assertEqual(
                    fixture.paths.export.read_bytes(),
                    preserved["export"],
                )
                if deletion_stage == "before":
                    self.assertEqual(
                        config_path.read_bytes(),
                        preserved["config"],
                    )
                    self.assertEqual(
                        environment_path.read_bytes(),
                        preserved["environment"],
                    )
                else:
                    self.assertFalse(config_path.exists())
                    self.assertFalse(environment_path.exists())

    def test_production_retirement_restart_failure_uses_durable_attempt_binding(
        self,
    ) -> None:
        for restart_state in ("attempt-only", "checkpoint"):
            with (
                self.subTest(restart_state=restart_state),
                tempfile.TemporaryDirectory() as directory,
            ):
                fixture = self._applied_fixture(directory)
                captured_plans: list[object] = []

                if restart_state == "attempt-only":
                    def initial_executor(
                        plan: object,
                        _lease: object,
                        _checkpoint: object,
                    ) -> object:
                        captured_plans.append(plan)
                        raise RuntimeError("unit-only interrupted executor")
                else:
                    def initial_executor(
                        plan: object,
                        _lease: object,
                        checkpoint: object,
                    ) -> object:
                        captured_plans.append(plan)
                        proof = self._valid_retirement_proof(plan)
                        checkpoint(proof)
                        self._delete_recovery_artifacts(fixture)
                        return proof

                with self.assertRaisesRegex(
                    stalwart_v016.MigrationError,
                    "reconciliation",
                ):
                    self._retire(
                        fixture,
                        initial_executor,
                        postflight_verifier=mock.Mock(
                            side_effect=RuntimeError(
                                "unit-only restart boundary",
                            ),
                        ),
                    )
                plan = captured_plans[0]
                events: list[str] = []
                recovery_started = False
                activations = 0
                executor = mock.Mock()
                verifier = mock.Mock(
                    side_effect=RuntimeError(
                        "unit-secret resumed verifier endpoint",
                    ),
                )

                class BootstrapModule:
                    class BootstrapPaths:
                        @staticmethod
                        def for_repository(repository: Path) -> Path:
                            return repository

                    @staticmethod
                    def validate_final_bootstrap_for_retirement(
                        _paths: object,
                        *,
                        task6_validator: object,
                    ) -> object:
                        return task6_validator(
                            fixture.paths.apply_receipt,
                        )

                    finalize_migrated_current_runtime = staticmethod(
                        ApplyPreparationTest._unexpected_current_finalizer
                    )

                def prepare(_paths: object, **kwargs: object) -> Path:
                    if restart_state == "attempt-only":
                        raise stalwart_v016.MigrationError(
                            "retirement attempt has no proof; "
                            "manual reconciliation is required",
                        )
                    kwargs["postflight_verifier"](plan)
                    raise AssertionError(
                        "postflight failure was not propagated",
                    )

                def runtime_runner(
                    args: list[str],
                    **_kwargs: object,
                ) -> object:
                    nonlocal recovery_started
                    container_id = "f" * 64
                    if args == (
                        stalwart_v016.build_normal_recovery_ps_command(
                            plan,
                        )
                    ):
                        return stalwart_v016.RedactedCommandResult(
                            (container_id + "\n").encode("ascii"),
                            b"",
                        )
                    if args == (
                        stalwart_v016
                        .build_normal_recovery_container_inspect_command(
                            container_id,
                        )
                    ):
                        return stalwart_v016.RedactedCommandResult(
                            json.dumps(
                                self._valid_normal_recovery_inspection(
                                    fixture,
                                    container_id,
                                ),
                            ).encode("utf-8"),
                            b"",
                        )
                    self.assertEqual(
                        args,
                        stalwart_v016.build_bound_container_stop_command(
                            container_id,
                        ),
                    )
                    recovery_started = True
                    events.append("stop")
                    return stalwart_v016.RedactedCommandResult(b"", b"")

                def state_runner(args: list[str]) -> object:
                    if recovery_started and args[:2] == ["docker", "ps"]:
                        events.append("census")
                    return fixture.runner(args)

                def activate(
                    _receipt_path: Path,
                    *,
                    expected_receipt_sha256: str,
                ) -> object:
                    nonlocal activations
                    activations += 1
                    events.append("activate")
                    return self._valid_rollback_activation(
                        fixture,
                        expected_receipt_sha256=expected_receipt_sha256,
                    )

                dependencies = replace(
                    (
                        stalwart_v016
                        .production_recovery_retirement_dependencies()
                    ),
                    bootstrap_module_loader=lambda _root: BootstrapModule,
                    bootstrap_apply_validator_factory=(
                        lambda *_args, **_kwargs: mock.Mock()
                    ),
                    prepare=prepare,
                    retirement_executor_factory=(
                        lambda **_kwargs: executor
                    ),
                    postflight_verifier_factory=(
                        lambda **_kwargs: verifier
                    ),
                    state_runner=state_runner,
                    runtime_runner=runtime_runner,
                    jmap_probe_runner=mock.Mock(),
                    rollback_activator=activate,
                    existing_retirement_plan_loader=(
                        lambda *_args, **_kwargs: plan
                    ),
                )
                with self.assertRaises(
                    stalwart_v016.MigrationError,
                ) as raised:
                    stalwart_v016.run_production_recovery_retirement(
                        fixture.paths,
                        dependencies=dependencies,
                        expected_script_sha256=fixture.script_digest,
                    )

                self.assertNotIn("unit-secret", str(raised.exception))
                self.assertEqual(activations, 1)
                self.assertEqual(events[-3:], ["stop", "census", "activate"])
                executor.assert_not_called()
                if restart_state == "attempt-only":
                    verifier.assert_not_called()
                else:
                    verifier.assert_called_once_with(plan)

    def test_existing_retirement_plan_loader_accepts_attempt_only_after_deletion(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._applied_fixture(directory)
            captured_plans: list[object] = []

            def capture_plan(
                plan: object,
                _lease: object,
                _checkpoint: object,
            ) -> object:
                captured_plans.append(plan)
                raise RuntimeError("unit-only interrupted executor")

            with self.assertRaisesRegex(
                stalwart_v016.MigrationError,
                "reconciliation",
            ):
                self._retire(
                    fixture,
                    capture_plan,
                    postflight_verifier=mock.Mock(),
                )
            self._delete_recovery_artifacts(fixture)

            loaded = (
                stalwart_v016._load_existing_retirement_recovery_plan(
                    fixture.paths,
                    bootstrap_receipt_validator=(
                        fixture.bootstrap_validator
                    ),
                    state_runner=fixture.runner,
                    python_executable="/unit/python3",
                    expected_script_sha256=fixture.script_digest,
                )
            )

            self.assertEqual(loaded, captured_plans[0])

    def test_production_retirement_rollback_faults_fail_closed(
        self,
    ) -> None:
        for fault in (
            "stop",
            "census",
            "retirement-binding",
            "activator",
        ):
            with (
                self.subTest(fault=fault),
                tempfile.TemporaryDirectory() as directory,
            ):
                fixture = self._applied_fixture(directory)
                captured_plans: list[object] = []

                def capture_plan(
                    plan: object,
                    _lease: object,
                    _checkpoint: object,
                ) -> object:
                    captured_plans.append(plan)
                    raise RuntimeError("unit-only interrupted executor")

                with self.assertRaisesRegex(
                    stalwart_v016.MigrationError,
                    "reconciliation",
                ):
                    self._retire(
                        fixture,
                        capture_plan,
                        postflight_verifier=mock.Mock(),
                    )
                plan = captured_plans[0]
                events: list[str] = []
                recovery_started = False
                activations = 0

                class BootstrapModule:
                    class BootstrapPaths:
                        @staticmethod
                        def for_repository(repository: Path) -> Path:
                            return repository

                    @staticmethod
                    def validate_final_bootstrap_for_retirement(
                        _paths: object,
                        *,
                        task6_validator: object,
                    ) -> object:
                        return task6_validator(
                            fixture.paths.apply_receipt,
                        )

                    finalize_migrated_current_runtime = staticmethod(
                        ApplyPreparationTest._unexpected_current_finalizer
                    )

                def runtime_runner(
                    args: list[str],
                    **_kwargs: object,
                ) -> object:
                    nonlocal recovery_started
                    container_id = "f" * 64
                    if args == (
                        stalwart_v016.build_normal_recovery_ps_command(
                            plan,
                        )
                    ):
                        return stalwart_v016.RedactedCommandResult(
                            (container_id + "\n").encode("ascii"),
                            b"",
                        )
                    if args == (
                        stalwart_v016
                        .build_normal_recovery_container_inspect_command(
                            container_id,
                        )
                    ):
                        return stalwart_v016.RedactedCommandResult(
                            json.dumps(
                                self._valid_normal_recovery_inspection(
                                    fixture,
                                    container_id,
                                ),
                            ).encode("utf-8"),
                            b"",
                        )
                    self.assertEqual(
                        args,
                        stalwart_v016.build_bound_container_stop_command(
                            container_id,
                        ),
                    )
                    recovery_started = True
                    events.append("stop")
                    if fault == "stop":
                        raise RuntimeError(
                            "unit-secret stop endpoint failure",
                        )
                    return stalwart_v016.RedactedCommandResult(b"", b"")

                def state_runner(args: list[str]) -> object:
                    if recovery_started and args[:2] == ["docker", "ps"]:
                        events.append("census")
                        if fault == "census":
                            raise RuntimeError(
                                "unit-secret census endpoint failure",
                            )
                    return fixture.runner(args)

                def activate(
                    _receipt_path: Path,
                    *,
                    expected_receipt_sha256: str,
                ) -> object:
                    nonlocal activations
                    activations += 1
                    events.append("activate")
                    if fault == "activator":
                        raise RuntimeError(
                            "unit-secret rollback endpoint failure",
                        )
                    return self._valid_rollback_activation(
                        fixture,
                        expected_receipt_sha256=expected_receipt_sha256,
                    )

                def prepare(_paths: object, **_kwargs: object) -> Path:
                    if fault == "retirement-binding":
                        fixture.paths.retire_recovery_attempt.write_bytes(
                            b'{"tampered":"retirement attempt"}\n',
                        )
                        fixture.paths.retire_recovery_attempt.chmod(0o600)
                    raise stalwart_v016.MigrationError(
                        "manual reconciliation is required",
                    )

                dependencies = replace(
                    (
                        stalwart_v016
                        .production_recovery_retirement_dependencies()
                    ),
                    bootstrap_module_loader=lambda _root: BootstrapModule,
                    bootstrap_apply_validator_factory=(
                        lambda *_args, **_kwargs: mock.Mock()
                    ),
                    prepare=prepare,
                    retirement_executor_factory=(
                        lambda **_kwargs: mock.Mock()
                    ),
                    postflight_verifier_factory=(
                        lambda **_kwargs: mock.Mock()
                    ),
                    state_runner=state_runner,
                    runtime_runner=runtime_runner,
                    jmap_probe_runner=mock.Mock(),
                    rollback_activator=activate,
                    existing_retirement_plan_loader=(
                        lambda *_args, **_kwargs: plan
                    ),
                )
                with self.assertRaisesRegex(
                    stalwart_v016.MigrationError,
                    "failed safely",
                ) as raised:
                    stalwart_v016.run_production_recovery_retirement(
                        fixture.paths,
                        dependencies=dependencies,
                        expected_script_sha256=fixture.script_digest,
                    )

                self.assertTrue(raised.exception.__suppress_context__)
                self.assertNotIn("unit-secret", str(raised.exception))
                self.assertIn("stop", events)
                self.assertIn("census", events)
                if fault in {
                    "stop",
                    "census",
                    "retirement-binding",
                }:
                    self.assertEqual(activations, 0)
                else:
                    self.assertEqual(activations, 1)

    def test_production_retirement_preserves_cancellation_after_activation(
        self,
    ) -> None:
        for interruption in (
            KeyboardInterrupt("unit-secret cancellation"),
            SystemExit(73),
        ):
            with (
                self.subTest(interruption=type(interruption).__name__),
                tempfile.TemporaryDirectory() as directory,
            ):
                fixture = self._applied_fixture(directory)
                captured_plans: list[object] = []

                def capture_plan(
                    plan: object,
                    _lease: object,
                    _checkpoint: object,
                ) -> object:
                    captured_plans.append(plan)
                    raise RuntimeError("unit-only interrupted executor")

                with self.assertRaisesRegex(
                    stalwart_v016.MigrationError,
                    "reconciliation",
                ):
                    self._retire(
                        fixture,
                        capture_plan,
                        postflight_verifier=mock.Mock(),
                    )
                plan = captured_plans[0]
                activations = 0

                class BootstrapModule:
                    class BootstrapPaths:
                        @staticmethod
                        def for_repository(repository: Path) -> Path:
                            return repository

                    @staticmethod
                    def validate_final_bootstrap_for_retirement(
                        _paths: object,
                        *,
                        task6_validator: object,
                    ) -> object:
                        return task6_validator(
                            fixture.paths.apply_receipt,
                        )

                    finalize_migrated_current_runtime = staticmethod(
                        ApplyPreparationTest._unexpected_current_finalizer
                    )

                def runtime_runner(
                    args: list[str],
                    **_kwargs: object,
                ) -> object:
                    container_id = "f" * 64
                    if args == (
                        stalwart_v016.build_normal_recovery_ps_command(
                            plan,
                        )
                    ):
                        return stalwart_v016.RedactedCommandResult(
                            (container_id + "\n").encode("ascii"),
                            b"",
                        )
                    if args == (
                        stalwart_v016
                        .build_normal_recovery_container_inspect_command(
                            container_id,
                        )
                    ):
                        return stalwart_v016.RedactedCommandResult(
                            json.dumps(
                                self._valid_normal_recovery_inspection(
                                    fixture,
                                    container_id,
                                ),
                            ).encode("utf-8"),
                            b"",
                        )
                    self.assertEqual(
                        args,
                        stalwart_v016.build_bound_container_stop_command(
                            container_id,
                        ),
                    )
                    return stalwart_v016.RedactedCommandResult(b"", b"")

                def activate(
                    _receipt_path: Path,
                    *,
                    expected_receipt_sha256: str,
                ) -> object:
                    nonlocal activations
                    activations += 1
                    return self._valid_rollback_activation(
                        fixture,
                        expected_receipt_sha256=expected_receipt_sha256,
                    )

                dependencies = replace(
                    (
                        stalwart_v016
                        .production_recovery_retirement_dependencies()
                    ),
                    bootstrap_module_loader=lambda _root: BootstrapModule,
                    bootstrap_apply_validator_factory=(
                        lambda *_args, **_kwargs: mock.Mock()
                    ),
                    prepare=mock.Mock(side_effect=interruption),
                    retirement_executor_factory=(
                        lambda **_kwargs: mock.Mock()
                    ),
                    postflight_verifier_factory=(
                        lambda **_kwargs: mock.Mock()
                    ),
                    state_runner=fixture.runner,
                    runtime_runner=runtime_runner,
                    jmap_probe_runner=mock.Mock(),
                    rollback_activator=activate,
                    existing_retirement_plan_loader=(
                        lambda *_args, **_kwargs: plan
                    ),
                )
                raised: BaseException | None = None
                try:
                    stalwart_v016.run_production_recovery_retirement(
                        fixture.paths,
                        dependencies=dependencies,
                        expected_script_sha256=fixture.script_digest,
                    )
                except BaseException as error:
                    raised = error

                self.assertIs(raised, interruption)
                self.assertEqual(activations, 1)

    def test_production_bootstrap_loader_rejects_prepopulated_cache_entries(
        self,
    ) -> None:
        nonce = "0" * 32
        alias = (
            stalwart_v016.PRODUCTION_BOOTSTRAP_MODULE_NAME_PREFIX
            + nonce
        )
        bootstrap_path = (
            Path(stalwart_v016.__file__)
            .resolve()
            .with_name("bootstrap_stalwart_v016.py")
        )
        forged_module = ModuleType(alias)
        forged_specification = importlib.util.spec_from_file_location(
            alias,
            bootstrap_path,
        )
        self.assertIsNotNone(forged_specification)
        forged_module.__file__ = str(bootstrap_path)
        forged_module.__spec__ = forged_specification
        forged_module.__loader__ = forged_specification.loader
        setattr(
            forged_module,
            stalwart_v016._PRODUCTION_BOOTSTRAP_MODULE_MARKER_ATTRIBUTE,
            stalwart_v016._PRODUCTION_BOOTSTRAP_MODULE_MARKER,
        )
        poisons = (
            SimpleNamespace(__file__=str(bootstrap_path)),
            forged_module,
        )
        for poison in poisons:
            with (
                self.subTest(poison_type=type(poison).__name__),
                mock.patch.object(
                    stalwart_v016.secrets,
                    "token_hex",
                    return_value=nonce,
                ),
                mock.patch.dict(
                    stalwart_v016._PRODUCTION_BOOTSTRAP_MODULES,
                    {},
                    clear=True,
                ),
                mock.patch.dict(sys.modules, {alias: poison}),
                self.assertRaises(stalwart_v016.MigrationError),
            ):
                stalwart_v016._load_production_bootstrap_module(
                    stalwart_v016.REPOSITORY_ROOT,
                )

    def test_production_retirement_rejects_post_load_module_swap_before_task6(
        self,
    ) -> None:
        paths = stalwart_v016.MigrationPaths.for_repository(
            stalwart_v016.REPOSITORY_ROOT,
        )
        modules: list[object] = []
        state_runner = mock.Mock()
        runtime_runner = mock.Mock()
        jmap_probe_runner = mock.Mock()
        task6_factory = mock.Mock()
        executor = mock.Mock()

        def loader(repository: Path) -> object:
            module = stalwart_v016._load_production_bootstrap_module(
                repository,
            )
            modules.append(module)
            return module

        def prepare(_paths: object, **kwargs: object) -> object:
            module = modules[0]
            replacement = ModuleType(module.__name__)
            replacement.__file__ = module.__file__
            sys.modules[module.__name__] = replacement
            kwargs["bootstrap_receipt_validator"]("ready")
            self.fail("swapped bootstrap module was accepted")

        dependencies = (
            stalwart_v016.ProductionRecoveryRetirementDependencies(
                acquire_operation_lock=lambda repository: self._LockContext(
                    repository,
                    [],
                ),
                prepare=prepare,
                bootstrap_module_loader=loader,
                bootstrap_apply_validator_factory=task6_factory,
                retirement_executor_factory=lambda **_kwargs: executor,
                postflight_verifier_factory=lambda **_kwargs: mock.Mock(),
                state_runner=state_runner,
                runtime_runner=runtime_runner,
                jmap_probe_runner=jmap_probe_runner,
            )
        )

        with (
            mock.patch.dict(sys.modules, {}, clear=False),
            self.assertRaises(stalwart_v016.MigrationError),
        ):
            stalwart_v016.run_production_recovery_retirement(
                paths,
                dependencies=dependencies,
                expected_script_sha256="a" * 64,
            )

        task6_factory.assert_not_called()
        executor.assert_not_called()
        state_runner.assert_not_called()
        runtime_runner.assert_not_called()
        jmap_probe_runner.assert_not_called()
        self.assertEqual(
            stalwart_v016._PRODUCTION_BOOTSTRAP_MODULES,
            {},
        )

    def test_production_retirement_contention_calls_no_dependency_after_lock(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            paths = self._paths(directory)
            acquire = mock.Mock(
                side_effect=stalwart_v016.MigrationError(
                    "another Stalwart operation is active",
                ),
            )
            dependencies = (
                stalwart_v016.ProductionRecoveryRetirementDependencies(
                    acquire_operation_lock=acquire,
                    prepare=mock.Mock(),
                    bootstrap_module_loader=mock.Mock(),
                    bootstrap_apply_validator_factory=mock.Mock(),
                    retirement_executor_factory=mock.Mock(),
                    postflight_verifier_factory=mock.Mock(),
                    state_runner=mock.Mock(),
                    runtime_runner=mock.Mock(),
                    jmap_probe_runner=mock.Mock(),
                )
            )

            with self.assertRaisesRegex(
                stalwart_v016.MigrationError,
                "another Stalwart operation",
            ):
                stalwart_v016.run_production_recovery_retirement(
                    paths,
                    dependencies=dependencies,
                    expected_script_sha256="a" * 64,
                )

            acquire.assert_called_once_with(paths.repository_root)
            for dependency in (
                dependencies.prepare,
                dependencies.bootstrap_module_loader,
                dependencies.bootstrap_apply_validator_factory,
                dependencies.retirement_executor_factory,
                dependencies.postflight_verifier_factory,
                dependencies.state_runner,
                dependencies.runtime_runner,
                dependencies.jmap_probe_runner,
            ):
                dependency.assert_not_called()

    def test_production_retirement_preserves_cancellation_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            paths = self._paths(directory)
            interruption = KeyboardInterrupt("unit-secret")

            class BootstrapModule:
                class BootstrapPaths:
                    @staticmethod
                    def for_repository(repository: Path) -> Path:
                        return repository

                @staticmethod
                def validate_final_bootstrap_for_retirement(
                    _paths: object,
                    *,
                    task6_validator: object,
                ) -> object:
                    return task6_validator(paths.apply_receipt)

                finalize_migrated_current_runtime = staticmethod(
                    ApplyPreparationTest._unexpected_current_finalizer
                )

            dependencies = (
                stalwart_v016.ProductionRecoveryRetirementDependencies(
                    acquire_operation_lock=lambda repository: self._LockContext(
                        repository,
                        [],
                    ),
                    prepare=mock.Mock(side_effect=interruption),
                    bootstrap_module_loader=lambda _repository: BootstrapModule,
                    bootstrap_apply_validator_factory=lambda *_args, **_kwargs: (
                        lambda _receipt: object()
                    ),
                    retirement_executor_factory=lambda **_kwargs: mock.Mock(),
                    postflight_verifier_factory=lambda **_kwargs: mock.Mock(),
                    state_runner=mock.Mock(),
                    runtime_runner=mock.Mock(),
                    jmap_probe_runner=mock.Mock(),
                )
            )

            with self.assertRaises(KeyboardInterrupt) as raised:
                stalwart_v016.run_production_recovery_retirement(
                    paths,
                    dependencies=dependencies,
                    expected_script_sha256="a" * 64,
                )

            self.assertIs(raised.exception, interruption)

    def test_reconciliation_error_has_no_secret_bearing_exception_context(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            original_runner = fixture.runner
            secret = "unit-postflight-runner-secret"
            census_calls = 0

            def runner(args: list[str]) -> object:
                nonlocal census_calls
                if args[:2] == ["docker", "ps"]:
                    census_calls += 1
                    if census_calls == 2:
                        raise RuntimeError(secret)
                return original_runner(args)

            fixture.runner = runner
            with self.assertRaisesRegex(
                stalwart_v016.MigrationError,
                "reconciliation",
            ) as raised:
                self._prepare(
                    fixture,
                    lambda _plan: self._valid_evidence(),
                )

            self.assertIsNone(raised.exception.__context__)
            self.assertNotIn(secret, str(raised.exception))
            self.assertGreaterEqual(census_calls, 2)
            self.assertTrue(fixture.paths.apply_attempt.exists())
            self.assertFalse(fixture.paths.apply_receipt.exists())

    def test_postflight_requires_exact_runtime_artifacts(self) -> None:
        cases = (
            "missing",
            "config-dir-owner-only",
            "config-dir-group-writable",
            "config-owner-only",
            "config-group-writable",
            "config-content",
            "extra-config-file",
            "environment-mode",
            "environment-extra-line",
            "environment-malformed",
            "environment-tab",
            "environment-nul",
            "environment-del",
            "environment-non-ascii",
            "environment-dollar",
            "environment-hash",
            "environment-quote",
            "environment-backslash",
            "environment-space",
        )
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                fixture = self._fixture(directory)

                def executor(_plan: object) -> str:
                    if case != "missing":
                        self._materialize_runtime(fixture)
                    config_dir = (
                        fixture.paths.migration_root / "recovery-config"
                    )
                    config_file = config_dir / "config.json"
                    environment_file = (
                        fixture.paths.migration_root / "recovery.env"
                    )
                    if case == "config-dir-owner-only":
                        config_dir.chmod(0o700)
                    elif case == "config-dir-group-writable":
                        config_dir.chmod(0o775)
                    elif case == "config-owner-only":
                        config_file.chmod(0o600)
                    elif case == "config-group-writable":
                        config_file.chmod(0o664)
                    elif case == "config-content":
                        self._write_0644(config_file, b'{"wrong":true}\n')
                    elif case == "extra-config-file":
                        self._write_0644(config_dir / "extra.json", b"{}\n")
                    elif case == "environment-mode":
                        environment_file.chmod(0o644)
                    elif case == "environment-extra-line":
                        self._write_0600(
                            environment_file,
                            b"STALWART_RECOVERY_ADMIN=user:secret\nEXTRA=1\n",
                        )
                    elif case == "environment-malformed":
                        self._write_0600(
                            environment_file,
                            b"STALWART_RECOVERY_ADMIN=missing-secret\n",
                        )
                    elif case == "environment-tab":
                        self._write_0600(
                            environment_file,
                            b"STALWART_RECOVERY_ADMIN=unit\tuser:secret\n",
                        )
                    elif case == "environment-nul":
                        self._write_0600(
                            environment_file,
                            b"STALWART_RECOVERY_ADMIN=unit\x00user:secret\n",
                        )
                    elif case == "environment-del":
                        self._write_0600(
                            environment_file,
                            b"STALWART_RECOVERY_ADMIN=unit\x7fuser:secret\n",
                        )
                    elif case == "environment-non-ascii":
                        self._write_0600(
                            environment_file,
                            b"STALWART_RECOVERY_ADMIN=unit\x80user:secret\n",
                        )
                    elif case == "environment-dollar":
                        self._write_0600(
                            environment_file,
                            b"STALWART_RECOVERY_ADMIN=unit-user:sec$ret\n",
                        )
                    elif case == "environment-hash":
                        self._write_0600(
                            environment_file,
                            b"STALWART_RECOVERY_ADMIN=unit-user:sec#ret\n",
                        )
                    elif case == "environment-quote":
                        self._write_0600(
                            environment_file,
                            b'STALWART_RECOVERY_ADMIN=unit-user:sec"ret\n',
                        )
                    elif case == "environment-backslash":
                        self._write_0600(
                            environment_file,
                            b"STALWART_RECOVERY_ADMIN=unit-user:sec\\ret\n",
                        )
                    elif case == "environment-space":
                        self._write_0600(
                            environment_file,
                            b"STALWART_RECOVERY_ADMIN=unit-user:sec ret\n",
                        )
                    return self._valid_evidence()

                with self.assertRaisesRegex(
                    stalwart_v016.MigrationError,
                    "reconciliation",
                ):
                    self._prepare(
                        fixture,
                        executor,
                        materialize_runtime=False,
                    )

                self.assertTrue(fixture.paths.apply_attempt.exists())
                self.assertFalse(fixture.paths.apply_receipt.exists())

    def test_runtime_artifact_modes_match_the_secret_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            self._materialize_runtime(fixture)
            source = verified_source_fixture(
                fixture.repository,
                fixture.source_store,
            )
            runtime = stalwart_v016.build_migration_runtime_paths(
                fixture.paths,
                source,
            )
            converted = stalwart_v016._read_regular_snapshot(
                fixture.paths.converted_config,
                root=fixture.repository,
                label="unit converted config",
                maximum=1024 * 1024,
                required_mode=0o600,
            )

            try:
                stalwart_v016._validate_runtime_artifacts_ready(
                    fixture.paths,
                    runtime,
                    converted_config=converted,
                )
            except stalwart_v016.MigrationError as error:
                self.fail(
                    "container-readable runtime config modes must validate: "
                    f"{error}",
                )

        cases = (
            ("config-directory-owner-only", "directory", 0o700, "0755"),
            ("config-directory-group-writable", "directory", 0o775, "0755"),
            ("config-owner-only", "config", 0o600, "0644"),
            ("config-group-writable", "config", 0o664, "0644"),
            ("environment-world-readable", "environment", 0o644, "0600"),
        )
        for case, target_name, wrong_mode, expected_mode in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                fixture = self._fixture(directory)
                self._materialize_runtime(fixture)
                source = verified_source_fixture(
                    fixture.repository,
                    fixture.source_store,
                )
                runtime = stalwart_v016.build_migration_runtime_paths(
                    fixture.paths,
                    source,
                )
                target = {
                    "directory": runtime.config_dir,
                    "config": runtime.config_dir / "config.json",
                    "environment": runtime.recovery_env_file,
                }[target_name]
                target.chmod(wrong_mode)
                converted = stalwart_v016._read_regular_snapshot(
                    fixture.paths.converted_config,
                    root=fixture.repository,
                    label="unit converted config",
                    maximum=1024 * 1024,
                    required_mode=0o600,
                )

                with self.assertRaisesRegex(
                    stalwart_v016.MigrationError,
                    expected_mode,
                ):
                    stalwart_v016._validate_runtime_artifacts_ready(
                        fixture.paths,
                        runtime,
                        converted_config=converted,
                    )

    def test_runtime_validation_rechecks_config_directory_after_child_reads(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            self._materialize_runtime(fixture)
            source = verified_source_fixture(
                fixture.repository,
                fixture.source_store,
            )
            runtime = stalwart_v016.build_migration_runtime_paths(
                fixture.paths,
                source,
            )
            converted = stalwart_v016._read_regular_snapshot(
                fixture.paths.converted_config,
                root=fixture.repository,
                label="unit converted config",
                maximum=1024 * 1024,
                required_mode=0o600,
            )
            original_config_dir = runtime.config_dir
            saved_config_dir = (
                fixture.paths.migration_root / "saved-recovery-config"
            )
            replacement_config_dir = (
                fixture.paths.migration_root / "replacement-recovery-config"
            )
            replacement_config_dir.mkdir(mode=0o755)
            os.link(
                original_config_dir / "config.json",
                replacement_config_dir / "config.json",
            )
            self._write_0644(
                replacement_config_dir / "extra.json",
                b"{}\n",
            )
            original_reader = stalwart_v016._read_regular_snapshot
            swapped = False

            def swapping_reader(path: Path, **kwargs: object) -> object:
                nonlocal swapped
                if path == original_config_dir / "config.json" and not swapped:
                    original_config_dir.rename(saved_config_dir)
                    replacement_config_dir.rename(original_config_dir)
                    swapped = True
                return original_reader(path, **kwargs)

            with (
                mock.patch.object(
                    stalwart_v016,
                    "_read_regular_snapshot",
                    side_effect=swapping_reader,
                ),
                self.assertRaises(stalwart_v016.MigrationError),
            ):
                stalwart_v016._validate_runtime_artifacts_ready(
                    fixture.paths,
                    runtime,
                    converted_config=converted,
                )

            self.assertTrue(swapped)
            self.assertEqual(
                {path.name for path in original_config_dir.iterdir()},
                {"config.json", "extra.json"},
            )

    def test_ephemeral_runtime_snapshots_redact_environment_state_from_repr(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            self._materialize_runtime(fixture)
            source = verified_source_fixture(
                fixture.repository,
                fixture.source_store,
            )
            runtime = stalwart_v016.build_migration_runtime_paths(
                fixture.paths,
                source,
            )
            converted = stalwart_v016._read_regular_snapshot(
                fixture.paths.converted_config,
                root=fixture.repository,
                label="unit converted config",
                maximum=1024 * 1024,
                required_mode=0o600,
            )

            snapshots = stalwart_v016._validate_runtime_artifacts_ready(
                fixture.paths,
                runtime,
                converted_config=converted,
            )

            environment = snapshots.recovery_environment
            environment_digest = environment.sha256
            self.assertFalse(hasattr(environment, "content"))
            for rendered in (repr(snapshots), repr(environment)):
                self.assertNotIn("unit-user", rendered)
                self.assertNotIn("unit-secret", rendered)
                self.assertNotIn("recovery.env", rendered)
                self.assertNotIn(str(fixture.repository), rendered)
                self.assertNotIn(environment_digest, rendered)

    def test_recovery_environment_validation_wipes_its_mutable_read_buffer(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            self._materialize_runtime(fixture)
            source = verified_source_fixture(
                fixture.repository,
                fixture.source_store,
            )
            runtime = stalwart_v016.build_migration_runtime_paths(
                fixture.paths,
                source,
            )
            converted = stalwart_v016._read_regular_snapshot(
                fixture.paths.converted_config,
                root=fixture.repository,
                label="unit converted config",
                maximum=1024 * 1024,
                required_mode=0o600,
            )
            original_readv = os.readv
            captured: list[bytearray] = []

            def recording_readv(
                descriptor: int,
                buffers: list[memoryview],
            ) -> int:
                for buffer in buffers:
                    candidate = buffer.obj
                    if isinstance(candidate, bytearray) and len(candidate) > 1:
                        captured.append(candidate)
                return original_readv(descriptor, buffers)

            with mock.patch.object(
                stalwart_v016.os,
                "readv",
                side_effect=recording_readv,
            ):
                snapshots = stalwart_v016._validate_runtime_artifacts_ready(
                    fixture.paths,
                    runtime,
                    converted_config=converted,
                )

            self.assertEqual(
                snapshots.recovery_environment.size,
                len(b"STALWART_RECOVERY_ADMIN=unit-user:unit-secret\n"),
            )
            self.assertEqual(len(captured), 1)
            self.assertTrue(all(value == 0 for value in captured[0]))

    def test_invalid_recovery_environment_wipes_its_mutable_read_buffer(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            self._materialize_runtime(
                fixture,
                environment=b"STALWART_RECOVERY_ADMIN=unit\x00user:secret\n",
            )
            source = verified_source_fixture(
                fixture.repository,
                fixture.source_store,
            )
            runtime = stalwart_v016.build_migration_runtime_paths(
                fixture.paths,
                source,
            )
            converted = stalwart_v016._read_regular_snapshot(
                fixture.paths.converted_config,
                root=fixture.repository,
                label="unit converted config",
                maximum=1024 * 1024,
                required_mode=0o600,
            )
            original_readv = os.readv
            captured: list[bytearray] = []

            def recording_readv(
                descriptor: int,
                buffers: list[memoryview],
            ) -> int:
                for buffer in buffers:
                    candidate = buffer.obj
                    if isinstance(candidate, bytearray) and len(candidate) > 1:
                        captured.append(candidate)
                return original_readv(descriptor, buffers)

            with (
                mock.patch.object(
                    stalwart_v016.os,
                    "readv",
                    side_effect=recording_readv,
                ),
                self.assertRaises(stalwart_v016.MigrationError),
            ):
                stalwart_v016._validate_runtime_artifacts_ready(
                    fixture.paths,
                    runtime,
                    converted_config=converted,
                )

            self.assertEqual(len(captured), 1)
            self.assertTrue(all(value == 0 for value in captured[0]))

    def test_recovery_environment_close_failure_wipes_and_redacts(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            environment = root / "recovery.env"
            self._write_0600(
                environment,
                b"STALWART_RECOVERY_ADMIN=unit-user:unit-secret\n",
            )
            original_readv = os.readv
            original_close = os.close
            captured: list[bytearray] = []

            def recording_readv(
                descriptor: int,
                buffers: list[memoryview],
            ) -> int:
                for buffer in buffers:
                    candidate = buffer.obj
                    if isinstance(candidate, bytearray) and len(candidate) > 1:
                        captured.append(candidate)
                return original_readv(descriptor, buffers)

            def failing_close(descriptor: int) -> None:
                original_close(descriptor)
                raise OSError("unit-close-secret")

            with (
                mock.patch.object(
                    stalwart_v016.os,
                    "readv",
                    side_effect=recording_readv,
                ),
                mock.patch.object(
                    stalwart_v016.os,
                    "close",
                    side_effect=failing_close,
                ),
                self.assertRaises(stalwart_v016.MigrationError) as raised,
            ):
                stalwart_v016._read_regular_mutable(
                    environment,
                    root=root,
                    label="unit recovery environment",
                    maximum=64 * 1024,
                    required_mode=0o600,
                )

            self.assertIsNone(raised.exception.__context__)
            self.assertNotIn("unit-close-secret", str(raised.exception))
            self.assertEqual(len(captured), 1)
            self.assertTrue(all(value == 0 for value in captured[0]))

    def test_recovery_environment_close_cancellation_wipes_and_propagates(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            environment = root / "recovery.env"
            self._write_0600(
                environment,
                b"STALWART_RECOVERY_ADMIN=unit-user:unit-secret\n",
            )
            original_readv = os.readv
            original_close = os.close
            captured: list[bytearray] = []
            cancellation = KeyboardInterrupt("unit-only close cancellation")

            def recording_readv(
                descriptor: int,
                buffers: list[memoryview],
            ) -> int:
                for buffer in buffers:
                    candidate = buffer.obj
                    if isinstance(candidate, bytearray) and len(candidate) > 1:
                        captured.append(candidate)
                return original_readv(descriptor, buffers)

            def cancelling_close(descriptor: int) -> None:
                original_close(descriptor)
                raise cancellation

            with (
                mock.patch.object(
                    stalwart_v016.os,
                    "readv",
                    side_effect=recording_readv,
                ),
                mock.patch.object(
                    stalwart_v016.os,
                    "close",
                    side_effect=cancelling_close,
                ),
                self.assertRaises(KeyboardInterrupt) as raised,
            ):
                stalwart_v016._read_regular_mutable(
                    environment,
                    root=root,
                    label="unit recovery environment",
                    maximum=64 * 1024,
                    required_mode=0o600,
                )

            self.assertIs(raised.exception, cancellation)
            self.assertEqual(len(captured), 1)
            self.assertTrue(all(value == 0 for value in captured[0]))

    def test_recovery_environment_without_newline_and_urlsafe_password_is_valid(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            self._materialize_runtime(
                fixture,
                environment=(
                    b"STALWART_RECOVERY_ADMIN="
                    b"unit-user:unit-secret"
                ),
            )
            source = verified_source_fixture(
                fixture.repository,
                fixture.source_store,
            )
            runtime = stalwart_v016.build_migration_runtime_paths(
                fixture.paths,
                source,
            )
            converted = stalwart_v016._read_regular_snapshot(
                fixture.paths.converted_config,
                root=fixture.repository,
                label="unit converted config",
                maximum=1024 * 1024,
                required_mode=0o600,
            )
            snapshots = stalwart_v016._validate_runtime_artifacts_ready(
                fixture.paths,
                runtime,
                converted_config=converted,
            )

            lease = stalwart_v016._load_recovery_credential_lease(
                fixture.paths,
                runtime,
                snapshots.recovery_environment,
            )
            borrowed = lease.borrow()
            self.assertEqual(bytes(borrowed), b"unit-user:unit-secret")
            lease.close()
            self.assertEqual(bytes(borrowed), b"\x00" * 21)

    def test_apply_timestamp_callback_precedes_runtime_preflight(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            executor = mock.Mock(return_value=self._valid_evidence())

            def mutating_clock() -> str:
                self._write_0600(
                    fixture.paths.migration_root / "recovery.env",
                    b"STALWART_RECOVERY_ADMIN=clock:mutation\n",
                )
                return "2026-07-28T12:02:00Z"

            with self.assertRaises(stalwart_v016.MigrationError):
                self._prepare(
                    fixture,
                    executor,
                    clock=mutating_clock,
                )

            executor.assert_not_called()
            self.assertFalse(fixture.paths.apply_attempt.exists())
            self.assertFalse(fixture.paths.apply_receipt.exists())

    def test_invalid_or_missing_offline_post_apply_proof_blocks_receipt(self) -> None:
        invalid_proofs = {
            "wrong-type": {
                "operations_sha256": "0" * 64,
            },
            "digest": stalwart_v016.PostApplyCensusProof(
                operations_sha256="0" * 64,
                operation_count=2,
                server_version="0.16.17",
                management_status=200,
            ),
            "count": stalwart_v016.PostApplyCensusProof(
                operations_sha256=self._operation_digest(
                    (
                        ("create", "principal/unit-fixture"),
                        ("update", "domain/unit.example"),
                    ),
                ),
                operation_count=1,
                server_version="0.16.17",
                management_status=200,
            ),
            "version": stalwart_v016.PostApplyCensusProof(
                operations_sha256=self._operation_digest(
                    (
                        ("create", "principal/unit-fixture"),
                        ("update", "domain/unit.example"),
                    ),
                ),
                operation_count=2,
                server_version="0.16.15",
                management_status=200,
            ),
            "status": stalwart_v016.PostApplyCensusProof(
                operations_sha256=self._operation_digest(
                    (
                        ("create", "principal/unit-fixture"),
                        ("update", "domain/unit.example"),
                    ),
                ),
                operation_count=2,
                server_version="0.16.17",
                management_status=500,
            ),
        }
        for case, proof in invalid_proofs.items():
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                fixture = self._fixture(directory)
                verifier = mock.Mock(return_value=proof)

                with self.assertRaises(stalwart_v016.MigrationError):
                    self._prepare(
                        fixture,
                        lambda _plan: self._valid_evidence(),
                        post_apply_verifier=verifier,
                    )

                verifier.assert_called_once()
                self.assertTrue(fixture.paths.apply_attempt.exists())
                self.assertFalse(fixture.paths.apply_receipt.exists())

        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            executor = mock.Mock(return_value=self._valid_evidence())
            with self.assertRaisesRegex(
                stalwart_v016.MigrationError,
                "verifier",
            ):
                self._prepare(
                    fixture,
                    executor,
                    post_apply_verifier=False,
                )
            executor.assert_not_called()
            self.assertFalse(fixture.paths.apply_attempt.exists())

        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            secret = "unit-verifier-secret"

            def failed_verifier(_plan: object) -> object:
                raise RuntimeError(secret)

            with self.assertRaisesRegex(
                stalwart_v016.MigrationError,
                "reconciliation",
            ) as raised:
                self._prepare(
                    fixture,
                    lambda _plan: self._valid_evidence(),
                    post_apply_verifier=failed_verifier,
                )
            self.assertNotIn(secret, str(raised.exception))
            self.assertTrue(fixture.paths.apply_attempt.exists())
            self.assertFalse(fixture.paths.apply_receipt.exists())

    def test_verifier_cannot_mutate_overlay_or_attempt_marker_before_receipt(
        self,
    ) -> None:
        for case in ("overlay", "attempt-marker"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                fixture = self._fixture(directory)

                def verifier(plan: object) -> object:
                    if case == "overlay":
                        overlay = (
                            fixture.repository
                            / "docker-compose.stalwart-migration.yml"
                        )
                        overlay.write_bytes(
                            CANONICAL_MIGRATION_OVERLAY + b" ",
                        )
                        overlay.chmod(0o644)
                    else:
                        self._write_0600(
                            fixture.paths.apply_attempt,
                            b'{"mutated":"during verifier"}\n',
                        )
                    return self._valid_post_apply_proof(plan)

                with self.assertRaisesRegex(
                    stalwart_v016.MigrationError,
                    "reconciliation",
                ):
                    self._prepare(
                        fixture,
                        lambda _plan: self._valid_evidence(),
                        post_apply_verifier=verifier,
                    )

                self.assertFalse(fixture.paths.apply_receipt.exists())

    def test_verifier_runtime_artifact_replacement_requires_redacted_reconciliation(
        self,
    ) -> None:
        for case in ("same-bytes-config", "valid-new-credential"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                fixture = self._fixture(directory)
                replacement_secret = "unit-replacement-recovery-secret"

                def verifier(plan: object) -> object:
                    if case == "same-bytes-config":
                        config = (
                            fixture.paths.migration_root
                            / "recovery-config"
                            / "config.json"
                        )
                        content = config.read_bytes()
                        config.unlink()
                        self._write_0644(config, content)
                    else:
                        environment = (
                            fixture.paths.migration_root / "recovery.env"
                        )
                        environment.unlink()
                        self._write_0600(
                            environment,
                            (
                                "STALWART_RECOVERY_ADMIN="
                                f"replacement-user:{replacement_secret}\n"
                            ).encode("utf-8"),
                        )
                    return self._valid_post_apply_proof(plan)

                with self.assertRaisesRegex(
                    stalwart_v016.MigrationError,
                    "reconciliation",
                ) as raised:
                    self._prepare(
                        fixture,
                        lambda _plan: self._valid_evidence(),
                        post_apply_verifier=verifier,
                    )

                self.assertIsNone(raised.exception.__context__)
                self.assertNotIn(
                    replacement_secret,
                    str(raised.exception),
                )
                self.assertTrue(fixture.paths.apply_attempt.exists())
                self.assertFalse(fixture.paths.apply_receipt.exists())
                self.assertNotIn(
                    replacement_secret,
                    fixture.paths.apply_attempt.read_text(encoding="utf-8"),
                )

    def test_receipt_is_0600_content_free_and_bound_to_all_current_inputs(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            secret = "unit-only-executor-secret-must-not-persist"

            def executor(_plan: object) -> str:
                return self._valid_evidence()

            receipt_path = self._prepare(fixture, executor)
            payload = self._validate_receipt(fixture)
            serialized = receipt_path.read_text(encoding="utf-8")
            attempt = fixture.paths.apply_attempt
            attempt_serialized = attempt.read_text(encoding="utf-8")
            config_dir = fixture.paths.migration_root / "recovery-config"
            config_file = config_dir / "config.json"
            environment_file = fixture.paths.migration_root / "recovery.env"

            self.assertEqual(stat.S_IMODE(receipt_path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(attempt.stat().st_mode), 0o600)
            self.assertEqual(
                set(payload),
                {
                    "schema",
                    "applied_at",
                    "inputs",
                    "artifacts",
                    "attempt",
                    "post_apply_proof",
                    "runtime_artifacts",
                    "summary",
                },
            )
            self.assertEqual(
                payload["schema"],
                "mail-sandbox.stalwart-v016-apply.v2",
            )
            self.assertEqual(payload["applied_at"], "2026-07-28T12:02:00Z")
            self.assertEqual(
                [entry["name"] for entry in payload["inputs"]],
                [
                    "latest-source.json",
                    "migrate_v016.py",
                    "dry-run.json",
                    "reviewed.json",
                    "docker-compose.stalwart-migration.yml",
                    "docker-compose.yml",
                ],
            )
            self.assertEqual(
                [entry["name"] for entry in payload["artifacts"]],
                [
                    "settings.json",
                    "principals.json",
                    "config.json",
                    "export.json",
                    "unmigrated.txt",
                ],
            )
            for entry in (*payload["inputs"], *payload["artifacts"]):
                self.assertEqual(
                    set(entry),
                    {"name", "sha256", "size", "identity"},
                )
                self.assertNotIn("/", entry["name"])
                self.assertEqual(len(entry["identity"]), 6)
            self.assertEqual(
                payload["summary"],
                {
                    "destroyed": 0,
                    "updated": 1,
                    "created": 1,
                    "failed": 0,
                },
            )
            self.assertEqual(
                payload["attempt"],
                {
                    "name": "apply-attempt.json",
                    "sha256": hashlib.sha256(
                        attempt.read_bytes(),
                    ).hexdigest(),
                    "size": len(attempt.read_bytes()),
                    "identity": list(
                        stalwart_v016._file_identity(attempt.stat()),
                    ),
                },
            )
            self.assertEqual(
                payload["post_apply_proof"],
                {
                    "management_status": 200,
                    "operation_count": 2,
                    "operations_sha256": self._operation_digest(
                        fixture.operations,
                    ),
                    "server_version": "0.16.17",
                },
            )
            self.assertEqual(
                payload["runtime_artifacts"],
                {
                    "config_directory_identity": list(
                        stalwart_v016._file_identity(config_dir.stat()),
                    ),
                    "config": {
                        "name": "config.json",
                        "sha256": hashlib.sha256(
                            config_file.read_bytes(),
                        ).hexdigest(),
                        "size": len(config_file.read_bytes()),
                        "identity": list(
                            stalwart_v016._file_identity(
                                config_file.stat(),
                            ),
                        ),
                    },
                    "recovery_environment": {
                        "name": "recovery.env",
                        "size": len(environment_file.read_bytes()),
                        "identity": list(
                            stalwart_v016._file_identity(
                                environment_file.stat(),
                            ),
                        ),
                    },
                },
            )
            self.assertNotIn(
                "sha256",
                payload["runtime_artifacts"]["recovery_environment"],
            )
            environment_sha256 = hashlib.sha256(
                environment_file.read_bytes(),
            ).hexdigest()
            self.assertNotIn(environment_sha256, serialized)
            self.assertNotIn(environment_sha256, attempt_serialized)
            self.assertNotIn(secret, serialized)
            self.assertNotIn(str(fixture.repository), serialized)
            self.assertNotIn("STALWART_MIGRATION_", serialized)
            self.assertNotIn("recovery-config", serialized)
            self.assertNotIn("unit-user", serialized)
            self.assertNotIn("unit-secret", serialized)
            self.assertNotIn("unit-user", attempt_serialized)
            self.assertNotIn("unit-secret", attempt_serialized)

            self.assertEqual(stat.S_IMODE(config_dir.stat().st_mode), 0o755)
            self.assertEqual(
                {entry.name for entry in config_dir.iterdir()},
                {"config.json"},
            )
            self.assertEqual(stat.S_IMODE(config_file.stat().st_mode), 0o644)
            self.assertEqual(
                config_file.read_bytes(),
                fixture.paths.converted_config.read_bytes(),
            )
            self.assertEqual(
                stat.S_IMODE(environment_file.stat().st_mode),
                0o600,
            )
            self.assertEqual(
                environment_file.read_bytes(),
                b"STALWART_RECOVERY_ADMIN=unit-user:unit-secret\n",
            )
            runtime_metadata = payload["runtime_artifacts"]
            self.assertEqual(
                stat.S_IMODE(runtime_metadata["config_directory_identity"][2]),
                0o755,
            )
            self.assertEqual(
                stat.S_IMODE(runtime_metadata["config"]["identity"][2]),
                0o644,
            )
            self.assertEqual(
                stat.S_IMODE(
                    runtime_metadata["recovery_environment"]["identity"][2],
                ),
                0o600,
            )

            tampered = dict(payload)
            tampered["command_output"] = secret
            self._write_0600(
                receipt_path,
                (json.dumps(tampered) + "\n").encode("utf-8"),
            )
            with self.assertRaisesRegex(stalwart_v016.MigrationError, "malformed"):
                self._validate_receipt(fixture)
            self._write_0600(receipt_path, serialized.encode("utf-8"))
            self._validate_receipt(fixture)

            original_export = fixture.paths.export.read_bytes()
            self._write_0600(
                fixture.paths.export,
                b'{"changed":"after receipt"}\n',
            )
            with self.assertRaises(stalwart_v016.MigrationError):
                self._validate_receipt(fixture)
            self._write_0600(fixture.paths.export, original_export)
            with self.assertRaises(stalwart_v016.MigrationError):
                self._validate_receipt(fixture)

            self._write_0600(
                attempt,
                attempt.read_bytes() + b" ",
            )
            with self.assertRaises(stalwart_v016.MigrationError):
                self._validate_receipt(fixture)

    def test_overlay_mutation_after_receipt_invalidates_receipt(self) -> None:
        for mutation in ("content", "same-bytes-replacement"):
            with (
                self.subTest(mutation=mutation),
                tempfile.TemporaryDirectory() as directory,
            ):
                fixture = self._fixture(directory)
                self._prepare(
                    fixture,
                    lambda _plan: self._valid_evidence(),
                )
                overlay = (
                    fixture.repository
                    / "docker-compose.stalwart-migration.yml"
                )
                if mutation == "content":
                    overlay.write_bytes(CANONICAL_MIGRATION_OVERLAY + b" ")
                else:
                    overlay.unlink()
                    overlay.write_bytes(CANONICAL_MIGRATION_OVERLAY)
                overlay.chmod(0o644)

                with self.assertRaises(stalwart_v016.MigrationError):
                    self._validate_receipt(fixture)

    def test_runtime_artifact_replacement_after_receipt_invalidates_active_handoff(
        self,
    ) -> None:
        for case in ("same-bytes-config", "valid-new-credential"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                fixture = self._fixture(directory)
                receipt = self._prepare(
                    fixture,
                    lambda _plan: self._valid_evidence(),
                )
                replacement_secret = "unit-post-receipt-secret"
                if case == "same-bytes-config":
                    config = (
                        fixture.paths.migration_root
                        / "recovery-config"
                        / "config.json"
                    )
                    content = config.read_bytes()
                    config.unlink()
                    self._write_0644(config, content)
                else:
                    environment = (
                        fixture.paths.migration_root / "recovery.env"
                    )
                    environment.unlink()
                    self._write_0600(
                        environment,
                        (
                            "STALWART_RECOVERY_ADMIN="
                            f"replacement-user:{replacement_secret}\n"
                        ).encode("utf-8"),
                    )

                with self.assertRaises(stalwart_v016.MigrationError) as raised:
                    self._validate_receipt(fixture)

                self.assertIsNone(raised.exception.__context__)
                self.assertNotIn(
                    replacement_secret,
                    str(raised.exception),
                )
                self.assertNotIn(
                    replacement_secret,
                    receipt.read_text(encoding="utf-8"),
                )

    def test_config_directory_hard_link_swap_after_receipt_invalidates_handoff(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            config_dir = fixture.paths.migration_root / "recovery-config"
            replacement_dir = (
                fixture.paths.migration_root / "replacement-recovery-config"
            )

            def executor(_plan: object) -> str:
                self._materialize_runtime(fixture)
                replacement_dir.mkdir(mode=0o755)
                os.link(
                    config_dir / "config.json",
                    replacement_dir / "config.json",
                )
                return self._valid_evidence()

            self._prepare(
                fixture,
                executor,
                materialize_runtime=False,
            )
            config_identity_before = stalwart_v016._file_identity(
                (config_dir / "config.json").stat(),
            )
            original_dir = (
                fixture.paths.migration_root / "original-recovery-config"
            )
            config_dir.rename(original_dir)
            replacement_dir.rename(config_dir)
            self.assertEqual(
                stalwart_v016._file_identity(
                    (config_dir / "config.json").stat(),
                ),
                config_identity_before,
            )

            with self.assertRaises(stalwart_v016.MigrationError) as raised:
                self._validate_receipt(fixture)

            self.assertIsNone(raised.exception.__context__)

    def test_recovery_retirement_orders_checkpoint_before_delete_and_wipes_lease(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._applied_fixture(directory)
            paths = fixture.paths
            events: list[str] = []
            borrowed: list[memoryview] = []
            proofs: list[object] = []

            def executor(
                plan: object,
                lease: object,
                checkpoint: object,
            ) -> object:
                events.append("executor")
                self.assertEqual(
                    plan.source,
                    verified_source_fixture(
                        fixture.repository,
                        fixture.source_store,
                    ),
                )
                self.assertEqual(
                    set(plan.recovery_config.__dataclass_fields__),
                    {"path", "size", "identity"},
                )
                self.assertEqual(
                    set(plan.recovery_environment.__dataclass_fields__),
                    {"path", "size", "identity"},
                )
                self.assertEqual(
                    plan.recovery_config.path,
                    paths.migration_root / "recovery-config" / "config.json",
                )
                self.assertEqual(
                    plan.recovery_environment.path,
                    paths.migration_root / "recovery.env",
                )
                self.assertEqual(
                    plan.recovery_config_directory_identity,
                    stalwart_v016._file_identity(
                        (paths.migration_root / "recovery-config").stat(),
                    ),
                )
                self.assertNotIn(
                    "unit-secret",
                    repr(plan.recovery_environment),
                )
                self.assertEqual(
                    repr(plan.recovery_environment),
                    "RecoveryArtifactBinding(<redacted>)",
                )
                view = lease.borrow()
                borrowed.append(view)
                self.assertEqual(
                    bytes(view),
                    b"unit-user:unit-secret",
                )
                self.assertTrue(paths.retire_recovery_attempt.exists())
                proof = self._valid_retirement_proof(plan)
                proofs.append(proof)
                checkpoint(proof)
                events.append("checkpoint")
                self.assertTrue(paths.retire_recovery_proof.exists())
                self.assertTrue(
                    (paths.migration_root / "recovery.env").exists(),
                )
                self.assertTrue(
                    (
                        paths.migration_root
                        / "recovery-config"
                        / "config.json"
                    ).exists(),
                )
                self._delete_recovery_artifacts(fixture)
                events.append("delete")
                return proof

            def verifier(plan: object) -> object:
                events.append("verifier")
                self.assertFalse(
                    (paths.migration_root / "recovery.env").exists(),
                )
                self.assertFalse(
                    (paths.migration_root / "recovery-config").exists(),
                )
                return proofs[0]

            receipt = self._retire(
                fixture,
                executor,
                postflight_verifier=verifier,
            )
            payload = self._validate_retired_receipt(fixture)

            self.assertEqual(receipt, paths.recovery_retired_receipt)
            self.assertEqual(events, ["executor", "checkpoint", "delete", "verifier"])
            self.assertEqual(len(borrowed), 1)
            self.assertEqual(
                bytes(borrowed[0]),
                b"\x00" * len(b"unit-user:unit-secret"),
            )
            for artifact in (
                paths.retire_recovery_attempt,
                paths.retire_recovery_proof,
                paths.recovery_retired_receipt,
            ):
                self.assertEqual(stat.S_IMODE(artifact.stat().st_mode), 0o600)
            self.assertEqual(
                payload["schema"],
                "mail-sandbox.stalwart-v016-recovery-retired.v3",
            )
            serialized = "\n".join(
                artifact.read_text(encoding="utf-8")
                for artifact in (
                    paths.retire_recovery_attempt,
                    paths.retire_recovery_proof,
                    paths.recovery_retired_receipt,
                )
            )
            for forbidden in (
                "unit-user",
                "unit-secret",
                "STALWART_RECOVERY_ADMIN",
                str(paths.migration_root / "recovery.env"),
                fixture.public_url,
            ):
                self.assertNotIn(forbidden, serialized)

    def test_normal_runtime_builders_and_inspection_are_exact_base_only(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._applied_fixture(
                directory,
                compose_project="dovecot-docker",
            )
            paths = fixture.paths
            container_id = "c" * 64
            proofs: list[object] = []

            def executor(
                plan: object,
                _lease: object,
                checkpoint: object,
            ) -> object:
                prefix = [
                    "docker",
                    "compose",
                    "--project-directory",
                    str(fixture.repository),
                    "--project-name",
                    "dovecot-docker",
                    "--file",
                    str(fixture.repository / "docker-compose.yml"),
                ]
                self.assertEqual(
                    stalwart_v016.build_normal_compose_config_command(plan),
                    [*prefix, "config", "--quiet"],
                )
                self.assertEqual(
                    stalwart_v016.build_normal_compose_model_command(plan),
                    [
                        *prefix,
                        "config",
                        "--format",
                        "json",
                        "stalwart",
                    ],
                )
                self.assertEqual(
                    stalwart_v016.build_normal_runtime_image_inspect_command(),
                    [
                        "docker",
                        "image",
                        "inspect",
                        "--format",
                        "{{.Id}}",
                        stalwart_v016.STALWART_IMAGE,
                    ],
                )
                self.assertEqual(
                    stalwart_v016.build_normal_compose_start_command(plan),
                    [
                        *prefix,
                        "up",
                        "--detach",
                        "--wait",
                        "--force-recreate",
                        "--pull",
                        "never",
                        "--no-deps",
                        "stalwart",
                    ],
                )
                self.assertEqual(
                    stalwart_v016.build_normal_compose_ps_command(plan),
                    [*prefix, "ps", "--all", "--quiet", "stalwart"],
                )
                self.assertEqual(
                    stalwart_v016.build_normal_compose_stop_command(plan),
                    [*prefix, "stop", "--timeout", "30", "stalwart"],
                )
                self.assertEqual(
                    stalwart_v016.build_normal_compose_restart_command(plan),
                    [*prefix, "restart", "--timeout", "30", "stalwart"],
                )
                inspect_command = (
                    stalwart_v016.build_normal_container_inspect_command(
                        container_id,
                    )
                )
                self.assertEqual(
                    inspect_command[:5],
                    [
                        "docker",
                        "inspect",
                        "--type",
                        "container",
                        "--format",
                    ],
                )
                self.assertIn("Environment", inspect_command[5])
                self.assertEqual(inspect_command[6], container_id)
                for command in (
                    stalwart_v016.build_normal_compose_config_command(plan),
                    stalwart_v016.build_normal_compose_model_command(plan),
                    stalwart_v016.build_normal_compose_start_command(plan),
                    stalwart_v016.build_normal_compose_ps_command(plan),
                    stalwart_v016.build_normal_compose_stop_command(plan),
                    stalwart_v016.build_normal_compose_restart_command(plan),
                ):
                    self.assertNotIn(
                        "docker-compose.stalwart-migration.yml",
                        command,
                    )

                compose_model = {
                    "name": "dovecot-docker",
                    "networks": {
                        "default": {
                            "name": "dovecot-docker_default",
                            "ipam": {},
                        },
                    },
                    "services": {
                        "stalwart": {
                            "command": None,
                            "container_name": "stalwart-dev",
                            "entrypoint": None,
                            "environment": {
                                "STALWART_PUBLIC_URL": (
                                    fixture.public_url
                                ),
                            },
                            "healthcheck": {
                                "test": [
                                    "CMD",
                                    "curl",
                                    "-fsS",
                                    (
                                        "http://127.0.0.1:8080/"
                                        "healthz/ready"
                                    ),
                                ],
                                "timeout": "2s",
                                "interval": "2s",
                                "retries": 30,
                                "start_period": "2s",
                            },
                            "image": stalwart_v016.STALWART_IMAGE,
                            "networks": {"default": None},
                            "ports": [
                                {
                                    "host_ip": "0.0.0.0",
                                    "mode": "ingress",
                                    "protocol": "tcp",
                                    "published": "8443",
                                    "target": 8080,
                                },
                                {
                                    "host_ip": "0.0.0.0",
                                    "mode": "ingress",
                                    "protocol": "tcp",
                                    "published": "8587",
                                    "target": 587,
                                },
                            ],
                            "restart": "unless-stopped",
                            "user": "2000:2000",
                            "volumes": [
                                {
                                    "bind": {},
                                    "read_only": True,
                                    "source": str(
                                        fixture.repository
                                        / "stalwart"
                                    ),
                                    "target": "/etc/stalwart",
                                    "type": "bind",
                                },
                                {
                                    "bind": {},
                                    "source": str(fixture.source_store),
                                    "target": "/var/lib/stalwart",
                                    "type": "bind",
                                },
                            ],
                        },
                    },
                }
                stalwart_v016._validate_normal_compose_model(
                    json.dumps(compose_model).encode("utf-8"),
                    plan=plan,
                )
                model_substitutions = {
                    "latest-image": lambda value: value["services"][
                        "stalwart"
                    ].update(
                        {"image": "stalwartlabs/stalwart:latest"},
                    ),
                    "root-user": lambda value: value["services"][
                        "stalwart"
                    ].update({"user": "0:0"}),
                    "loopback-port": lambda value: value["services"][
                        "stalwart"
                    ]["ports"][0].update({"host_ip": "127.0.0.1"}),
                    "extra-mount": lambda value: value["services"][
                        "stalwart"
                    ]["volumes"].append(
                        {
                            "bind": {"create_host_path": True},
                            "read_only": False,
                            "source": "/unit/extra",
                            "target": "/unit/extra",
                            "type": "bind",
                        },
                    ),
                    "recovery-environment": lambda value: value[
                        "services"
                    ]["stalwart"]["environment"].update(
                        {"STALWART_RECOVERY_MODE": "1"},
                    ),
                    "stale-public-url": lambda value: value[
                        "services"
                    ]["stalwart"]["environment"].update(
                        {
                            "STALWART_PUBLIC_URL": (
                                "http://192.168.86.99:8443"
                            ),
                        },
                    ),
                    "extra-service": lambda value: value[
                        "services"
                    ].update({"migration": {}}),
                    "child-config-source": lambda value: value[
                        "services"
                    ]["stalwart"]["volumes"][0].update(
                        {
                            "source": str(
                                fixture.repository
                                / "stalwart"
                                / "config.json"
                            ),
                        },
                    ),
                    "child-config-target": lambda value: value[
                        "services"
                    ]["stalwart"]["volumes"][0].update(
                        {"target": "/etc/stalwart/config.json"},
                    ),
                    "wrong-data-target": lambda value: value[
                        "services"
                    ]["stalwart"]["volumes"][1].update(
                        {"target": "/unit/data"},
                    ),
                    "privileged-override": lambda value: value[
                        "services"
                    ]["stalwart"].update({"privileged": True}),
                    "missing-healthcheck": lambda value: value[
                        "services"
                    ]["stalwart"].pop("healthcheck"),
                    "wrong-readiness-healthcheck": lambda value: value[
                        "services"
                    ]["stalwart"]["healthcheck"]["test"].__setitem__(
                        3,
                        "http://127.0.0.1:8080/healthz/live",
                    ),
                }
                for label, mutate in model_substitutions.items():
                    with self.subTest(model_substitution=label):
                        changed = json.loads(json.dumps(compose_model))
                        mutate(changed)
                        with self.assertRaises(
                            stalwart_v016.MigrationError,
                        ):
                            stalwart_v016._validate_normal_compose_model(
                                json.dumps(changed).encode("utf-8"),
                                plan=plan,
                            )

                inspection = {
                    "Id": container_id,
                    "Image": stalwart_v016.STALWART_IMAGE,
                    "ImageID": stalwart_v016.STALWART_IMAGE_ID,
                    "User": "2000:2000",
                    "Project": "dovecot-docker",
                    "Service": "stalwart",
                    "WorkingDir": str(fixture.repository),
                    "ConfigFiles": str(
                        fixture.repository / "docker-compose.yml",
                    ),
                    "Oneoff": "False",
                    "Mounts": [
                        {
                            "Type": "bind",
                            "Source": str(
                                fixture.repository
                                / "stalwart"
                            ),
                            "Destination": "/etc/stalwart",
                            "RW": False,
                        },
                        {
                            "Type": "bind",
                            "Source": str(fixture.source_store),
                            "Destination": "/var/lib/stalwart",
                            "RW": True,
                        },
                    ],
                    "Ports": {
                        "8080/tcp": [
                            {
                                "HostIp": "0.0.0.0",
                                "HostPort": "8443",
                            },
                        ],
                        "587/tcp": [
                            {
                                "HostIp": "0.0.0.0",
                                "HostPort": "8587",
                            },
                        ],
                    },
                    "Running": True,
                    "Health": "healthy",
                    "Environment": [
                        (
                            "PATH=/usr/local/sbin:/usr/local/bin:"
                            "/usr/sbin:/usr/bin:/sbin:/bin"
                        ),
                        (
                            "STALWART_HEALTHCHECK_URL="
                            "https://127.0.0.1:443/healthz/live"
                        ),
                        (
                            "STALWART_PUBLIC_URL="
                            f"{fixture.public_url}"
                        ),
                    ],
                }
                observed = (
                    stalwart_v016._validate_normal_container_inspection(
                        json.dumps(inspection).encode("utf-8"),
                        plan=plan,
                        container_id=container_id,
                    )
                )
                self.assertEqual(observed.container_id, container_id)
                self.assertEqual(observed.recovery_environment_names, ())

                substitutions = {
                    "recovery-environment": (
                        "Environment",
                        [
                            *inspection["Environment"],
                            "STALWART_RECOVERY_MODE=1",
                        ],
                    ),
                    "unknown-environment": (
                        "Environment",
                        [
                            *inspection["Environment"],
                            "UNREVIEWED_DEFAULT=1",
                        ],
                    ),
                    "missing-environment": (
                        "Environment",
                        inspection["Environment"][:-1],
                    ),
                    "stale-public-url": (
                        "Environment",
                        [
                            *inspection["Environment"][:-1],
                            (
                                "STALWART_PUBLIC_URL="
                                "http://192.168.86.99:8443"
                            ),
                        ],
                    ),
                    "migration-overlay": (
                        "ConfigFiles",
                        (
                            f"{fixture.repository / 'docker-compose.yml'},"
                            f"{fixture.repository / 'docker-compose.stalwart-migration.yml'}"
                        ),
                    ),
                    "loopback-port": (
                        "Ports",
                        {
                            "8080/tcp": [
                                {
                                    "HostIp": "127.0.0.1",
                                    "HostPort": "8443",
                                },
                            ],
                        },
                    ),
                    "extra-port": (
                        "Ports",
                        {
                            **inspection["Ports"],
                            "25/tcp": [
                                {
                                    "HostIp": "127.0.0.1",
                                    "HostPort": "25",
                                },
                            ],
                        },
                    ),
                    "extra-mount": (
                        "Mounts",
                        [
                            *inspection["Mounts"],
                            {
                                "Type": "bind",
                                "Source": "/unit/extra",
                                "Destination": "/unit/extra",
                                "RW": False,
                            },
                        ],
                    ),
                    "anonymous-config-parent-volume": (
                        "Mounts",
                        [
                            *inspection["Mounts"],
                            {
                                "Type": "volume",
                                "Source": (
                                    "anonymous-stalwart-config"
                                ),
                                "Destination": "/etc/stalwart",
                                "RW": True,
                            },
                        ],
                    ),
                    "child-config-bind": (
                        "Mounts",
                        [
                            {
                                **inspection["Mounts"][0],
                                "Source": str(
                                    fixture.repository
                                    / "stalwart"
                                    / "config.json"
                                ),
                                "Destination": (
                                    "/etc/stalwart/config.json"
                                ),
                            },
                            inspection["Mounts"][1],
                        ],
                    ),
                    "extra-mount-member": (
                        "Mounts",
                        [
                            {
                                **inspection["Mounts"][0],
                                "Mode": "ro",
                            },
                            inspection["Mounts"][1],
                        ],
                    ),
                    "wrong-image": (
                        "Image",
                        "stalwartlabs/stalwart:latest",
                    ),
                    "wrong-image-id": (
                        "ImageID",
                        "sha256:" + "f" * 64,
                    ),
                    "mismatched-project-label": (
                        "Project",
                        "mail-sandbox",
                    ),
                    "wrong-service-label": ("Service", "other-service"),
                    "wrong-working-directory": (
                        "WorkingDir",
                        str(fixture.repository / "other"),
                    ),
                    "oneoff-container": ("Oneoff", "True"),
                    "root-user": ("User", "0:0"),
                    "stopped": ("Running", False),
                    "unhealthy": ("Health", "unhealthy"),
                }
                for label, (field, replacement) in substitutions.items():
                    with self.subTest(label=label):
                        changed = json.loads(json.dumps(inspection))
                        changed[field] = replacement
                        with self.assertRaises(stalwart_v016.MigrationError):
                            stalwart_v016._validate_normal_container_inspection(
                                json.dumps(changed).encode("utf-8"),
                                plan=plan,
                                container_id=container_id,
                            )
                with self.assertRaises(stalwart_v016.MigrationError):
                    stalwart_v016._validate_normal_container_inspection(
                        json.dumps(inspection).encode("utf-8"),
                        plan=plan,
                        container_id="not-a-container-id",
                    )

                def census_runner(args: list[str]) -> object:
                    if args[:2] == ["docker", "ps"]:
                        return stalwart_v016.CommandResult(
                            container_id + "\n",
                            "",
                        )
                    if args[:2] == ["docker", "inspect"]:
                        return stalwart_v016.CommandResult(
                            json.dumps(
                                [
                                    self._valid_normal_census_record(
                                        fixture,
                                        container_id,
                                    ),
                                ],
                            ),
                            "",
                        )
                    self.fail(f"unexpected census command: {args!r}")

                self.assertEqual(
                    stalwart_v016._normal_runtime_writer_census(
                        paths,
                        plan,
                        expected_container_id=container_id,
                        runner=census_runner,
                    ),
                    ((container_id,), ()),
                )

                mismatched_census = self._valid_normal_census_record(
                    fixture,
                    container_id,
                )
                mismatched_census["Config"]["Labels"][
                    "com.docker.compose.project"
                ] = "mail-sandbox"

                def mismatched_census_runner(
                    args: list[str],
                ) -> object:
                    if args[:2] == ["docker", "ps"]:
                        return stalwart_v016.CommandResult(
                            container_id + "\n",
                            "",
                        )
                    return stalwart_v016.CommandResult(
                        json.dumps([mismatched_census]),
                        "",
                    )

                with self.assertRaises(stalwart_v016.MigrationError):
                    stalwart_v016._normal_runtime_writer_census(
                        paths,
                        plan,
                        expected_container_id=container_id,
                        runner=mismatched_census_runner,
                    )

                malformed_plan = replace(
                    plan,
                    source=replace(
                        plan.source,
                        compose_project="../malformed",
                    ),
                )
                for builder in (
                    stalwart_v016.build_normal_compose_config_command,
                    stalwart_v016.build_normal_compose_model_command,
                    stalwart_v016.build_normal_compose_start_command,
                    stalwart_v016.build_normal_compose_ps_command,
                    stalwart_v016.build_normal_compose_stop_command,
                    stalwart_v016.build_normal_compose_restart_command,
                ):
                    with self.subTest(
                        malformed_source_builder=builder.__name__,
                    ):
                        with self.assertRaises(
                            stalwart_v016.MigrationError,
                        ):
                            builder(malformed_plan)

                proof = self._valid_retirement_proof(
                    plan,
                    container_id=container_id,
                    overlapping_writer_ids=(container_id,),
                )
                proofs.append(proof)
                checkpoint(proof)
                self._delete_recovery_artifacts(fixture)
                return proof

            self._retire(
                fixture,
                executor,
                postflight_verifier=lambda _plan: proofs[0],
            )

    def test_normal_compose_model_requires_exact_audited_readiness_render(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._applied_fixture(
                directory,
                compose_project="dovecot-docker",
            )
            captured: dict[str, object] = {}

            def capture(
                plan: object,
                _lease: object,
                _checkpoint: object,
            ) -> object:
                captured["plan"] = plan
                raise stalwart_v016.MigrationError(
                    "unit-only plan capture",
                )

            with self.assertRaises(stalwart_v016.MigrationError):
                self._retire(
                    fixture,
                    capture,
                    postflight_verifier=mock.Mock(),
                )
            plan = captured["plan"]
            model = self._valid_normal_compose_model(fixture)
            stalwart_v016._validate_normal_compose_model(
                json.dumps(model).encode("utf-8"),
                plan=plan,
            )

            mutations = {
                "missing-healthcheck": lambda value: value[
                    "services"
                ]["stalwart"].pop("healthcheck"),
                "wrong-readiness-path": lambda value: value[
                    "services"
                ]["stalwart"]["healthcheck"]["test"].__setitem__(
                    3,
                    "http://127.0.0.1:8080/healthz/live",
                ),
                "missing-network-ipam": lambda value: value[
                    "networks"
                ]["default"].pop("ipam"),
                "missing-null-command": lambda value: value[
                    "services"
                ]["stalwart"].pop("command"),
                "missing-null-entrypoint": lambda value: value[
                    "services"
                ]["stalwart"].pop("entrypoint"),
                "explicit-rw-read-only": lambda value: value[
                    "services"
                ]["stalwart"]["volumes"][1].update(
                    {"read_only": False},
                ),
            }
            for label, mutate in mutations.items():
                with self.subTest(label=label):
                    changed = json.loads(json.dumps(model))
                    mutate(changed)
                    with self.assertRaises(stalwart_v016.MigrationError):
                        stalwart_v016._validate_normal_compose_model(
                            json.dumps(changed).encode("utf-8"),
                            plan=plan,
                        )

            fixture.network_environment.write_bytes(
                b"STALWART_PUBLIC_URL=http://192.168.86.37:8443\n",
            )
            fixture.network_environment.chmod(0o600)
            with self.assertRaises(stalwart_v016.MigrationError):
                stalwart_v016._validate_normal_compose_model(
                    json.dumps(model).encode("utf-8"),
                    plan=plan,
                )

    def test_normal_compose_model_rejects_noncanonical_environment_source(
        self,
    ) -> None:
        canonical = normal_compose_text()
        substitutions = {
            "direct-environment": canonical.replace(
                "    env_file:\n"
                "      - ./debug-dashboard/.runtime/stalwart/network.env\n",
                "    environment:\n"
                "      STALWART_PUBLIC_URL: http://192.168.86.36:8443\n",
            ),
            "replacement-env-file": canonical.replace(
                "./debug-dashboard/.runtime/stalwart/network.env",
                "./debug-dashboard/.runtime/stalwart/replaced.env",
            ),
        }
        for label, compose in substitutions.items():
            with (
                self.subTest(label=label),
                tempfile.TemporaryDirectory() as directory,
            ):
                fixture = self._applied_fixture(
                    directory,
                    compose_project="dovecot-docker",
                    base_compose_content=compose,
                )
                calls: list[list[str]] = []

                def runtime_runner(
                    args: list[str],
                    **_kwargs: object,
                ) -> object:
                    calls.append(args)
                    return stalwart_v016.RedactedCommandResult(
                        json.dumps(
                            self._valid_normal_compose_model(fixture),
                        ).encode("utf-8"),
                        b"",
                    )

                executor = stalwart_v016.RecoveryRetirementExecutor(
                    paths=fixture.paths,
                    runner=runtime_runner,
                    state_runner=mock.Mock(),
                    jmap_probe_runner=mock.Mock(),
                    readiness_probe_runner=mock.Mock(),
                )
                with self.assertRaises(stalwart_v016.MigrationError):
                    self._retire(
                        fixture,
                        executor,
                        postflight_verifier=mock.Mock(),
                    )
                self.assertEqual(len(calls), 1)
                self.assertEqual(
                    calls[0][-4:],
                    ["config", "--format", "json", "stalwart"],
                )
                self.assertNotIn("up", calls[0])

    def test_normal_compose_validator_accepts_installed_compose_render(
        self,
    ) -> None:
        compose_content = textwrap.dedent(
            """\
            services:
              stalwart:
                image: stalwartlabs/stalwart:v0.16.17@sha256:a8108e19bd927e172d4d8c128907b8dfc93fd180ae8ee07dccdd42cb97eb9dfa
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
            """,
        )
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._applied_fixture(
                directory,
                compose_project="dovecot-docker",
                base_compose_content=compose_content,
            )
            captured: dict[str, object] = {}

            def capture(
                plan: object,
                _lease: object,
                _checkpoint: object,
            ) -> object:
                captured["plan"] = plan
                raise stalwart_v016.MigrationError(
                    "unit-only plan capture",
                )

            with self.assertRaises(stalwart_v016.MigrationError):
                self._retire(
                    fixture,
                    capture,
                    postflight_verifier=mock.Mock(),
                )
            plan = captured["plan"]
            environment = os.environ.copy()
            for name in (
                "COMPOSE_FILE",
                "COMPOSE_PROFILES",
                "COMPOSE_PROJECT_NAME",
            ):
                environment.pop(name, None)
            completed = subprocess.run(
                stalwart_v016.build_normal_compose_model_command(plan),
                cwd=fixture.repository,
                env=environment,
                check=False,
                capture_output=True,
                timeout=30,
            )
            self.assertEqual(
                completed.returncode,
                0,
                completed.stderr.decode("utf-8", "replace")[:2048],
            )

            stalwart_v016._validate_normal_compose_model(
                completed.stdout,
                plan=plan,
            )
            self.assertEqual(
                json.loads(completed.stdout),
                self._valid_normal_compose_model(fixture),
            )

    def test_production_retirement_executor_rejects_unpinned_model_before_start(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._applied_fixture(directory)
            calls: list[list[str]] = []
            delete = mock.Mock()
            state_runner = mock.Mock()
            auth_probe = mock.Mock()
            readiness = mock.Mock()

            def runtime_runner(
                args: list[str],
                **_kwargs: object,
            ) -> object:
                calls.append(args)
                model = self._valid_normal_compose_model(fixture)
                model["services"]["stalwart"]["image"] = (
                    "stalwartlabs/stalwart:latest"
                )
                return stalwart_v016.RedactedCommandResult(
                    json.dumps(model).encode("utf-8"),
                    b"",
                )

            executor = stalwart_v016.RecoveryRetirementExecutor(
                paths=fixture.paths,
                runner=runtime_runner,
                state_runner=state_runner,
                jmap_probe_runner=auth_probe,
                readiness_probe_runner=readiness,
            )
            with (
                mock.patch.object(
                    stalwart_v016,
                    "_delete_bound_recovery_artifacts",
                    delete,
                ),
                self.assertRaises(stalwart_v016.MigrationError),
            ):
                self._retire(
                    fixture,
                    executor,
                    postflight_verifier=mock.Mock(),
                )

            self.assertEqual(len(calls), 1)
            self.assertEqual(
                calls[0][-4:],
                ["config", "--format", "json", "stalwart"],
            )
            self.assertNotIn("up", calls[0])
            state_runner.assert_not_called()
            auth_probe.assert_not_called()
            readiness.assert_not_called()
            delete.assert_not_called()
            self.assertFalse(
                fixture.paths.retire_recovery_proof.exists(),
            )

    def test_retirement_rejects_equal_length_same_inode_management_key_overwrite_before_executor(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._applied_fixture(directory)
            before = fixture.management_key.stat()
            with fixture.management_key.open(
                "r+b",
                buffering=0,
            ) as stream:
                stream.write(b"Q" * before.st_size)
                stream.flush()
                os.fsync(stream.fileno())
            os.utime(
                fixture.management_key,
                ns=(
                    before.st_atime_ns,
                    before.st_mtime_ns + 1_000_000,
                ),
            )
            executor = mock.Mock()
            verifier = mock.Mock()

            with self.assertRaises(stalwart_v016.MigrationError):
                self._retire(
                    fixture,
                    executor,
                    postflight_verifier=verifier,
                )

            executor.assert_not_called()
            verifier.assert_not_called()
            self.assertFalse(
                fixture.paths.retire_recovery_attempt.exists(),
            )
            self.assertFalse(
                fixture.paths.retire_recovery_proof.exists(),
            )

    def test_production_retirement_executor_requires_receipt_bound_normal_config_before_commands(
        self,
    ) -> None:
        cases = ("missing", "same-size-altered", "symlink", "directory")
        for case in cases:
            with (
                self.subTest(case=case),
                tempfile.TemporaryDirectory() as directory,
            ):
                fixture = self._applied_fixture(directory)
                captured: dict[str, object] = {}

                def capture_plan(
                    plan: object,
                    _lease: object,
                    _checkpoint: object,
                ) -> object:
                    captured["plan"] = plan
                    raise stalwart_v016.MigrationError(
                        "unit-only plan capture",
                    )

                with self.assertRaises(stalwart_v016.MigrationError):
                    self._retire(
                        fixture,
                        capture_plan,
                        postflight_verifier=mock.Mock(),
                    )

                original = fixture.normal_config.read_bytes()
                if case == "missing":
                    fixture.normal_config.unlink()
                elif case == "same-size-altered":
                    fixture.normal_config.write_bytes(
                        b"x" * len(original),
                    )
                    fixture.normal_config.chmod(0o644)
                elif case == "symlink":
                    fixture.normal_config.unlink()
                    fixture.normal_config.symlink_to(
                        fixture.paths.converted_config,
                    )
                else:
                    fixture.normal_config.unlink()
                    fixture.normal_config.mkdir(mode=0o700)

                runtime_runner = mock.Mock()
                state_runner = mock.Mock()
                auth_probe = mock.Mock()
                readiness = mock.Mock()
                checkpoint = mock.Mock()
                executor = stalwart_v016.RecoveryRetirementExecutor(
                    paths=fixture.paths,
                    runner=runtime_runner,
                    state_runner=state_runner,
                    jmap_probe_runner=auth_probe,
                    readiness_probe_runner=readiness,
                )
                lease = stalwart_v016.RecoveryCredentialLease(
                    bytearray(b"unit-user:unit-secret"),
                )
                try:
                    with self.assertRaises(
                        stalwart_v016.MigrationError,
                    ):
                        executor(
                            captured["plan"],
                            lease,
                            checkpoint,
                        )
                finally:
                    lease.close()

                runtime_runner.assert_not_called()
                state_runner.assert_not_called()
                auth_probe.assert_not_called()
                readiness.assert_not_called()
                checkpoint.assert_not_called()

    def test_production_retirement_executor_revalidates_normal_config_immediately_before_up(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._applied_fixture(directory)
            captured: dict[str, object] = {}

            def capture_plan(
                plan: object,
                _lease: object,
                _checkpoint: object,
            ) -> object:
                captured["plan"] = plan
                raise stalwart_v016.MigrationError("unit-only plan capture")

            with self.assertRaises(stalwart_v016.MigrationError):
                self._retire(
                    fixture,
                    capture_plan,
                    postflight_verifier=mock.Mock(),
                )

            calls: list[list[str]] = []
            original = fixture.normal_config.read_bytes()

            def runtime_runner(
                args: list[str],
                **_kwargs: object,
            ) -> object:
                calls.append(args)
                if args[-4:] == [
                    "config",
                    "--format",
                    "json",
                    "stalwart",
                ]:
                    return stalwart_v016.RedactedCommandResult(
                        json.dumps(
                            self._valid_normal_compose_model(fixture),
                        ).encode("utf-8"),
                        b"",
                    )
                if args[:3] == ["docker", "image", "inspect"]:
                    fixture.normal_config.write_bytes(
                        b"y" * len(original),
                    )
                    fixture.normal_config.chmod(0o644)
                    return stalwart_v016.RedactedCommandResult(
                        stalwart_v016.STALWART_IMAGE_ID.encode("ascii"),
                        b"",
                    )
                return stalwart_v016.RedactedCommandResult(b"", b"")

            executor = stalwart_v016.RecoveryRetirementExecutor(
                paths=fixture.paths,
                runner=runtime_runner,
                state_runner=mock.Mock(),
                jmap_probe_runner=mock.Mock(),
                readiness_probe_runner=mock.Mock(),
            )
            lease = stalwart_v016.RecoveryCredentialLease(
                bytearray(b"unit-user:unit-secret"),
            )
            try:
                with self.assertRaises(stalwart_v016.MigrationError):
                    executor(
                        captured["plan"],
                        lease,
                        mock.Mock(),
                    )
            finally:
                lease.close()

            self.assertEqual(len(calls), 2)
            self.assertEqual(
                calls[0][-4:],
                ["config", "--format", "json", "stalwart"],
            )
            self.assertEqual(
                calls[1][:3],
                ["docker", "image", "inspect"],
            )
            self.assertFalse(any("up" in command for command in calls))

    def test_production_retirement_executor_runs_exact_order_and_postflight(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._applied_fixture(directory)
            container_id = "d" * 64
            events: list[str] = []
            running = False
            observed_buffers: list[bytearray] = []
            original_write = stalwart_v016._write_new_json_0600
            original_delete = (
                stalwart_v016._delete_bound_recovery_artifacts
            )

            def runtime_runner(
                args: list[str],
                **kwargs: object,
            ) -> object:
                nonlocal running
                self.assertEqual(kwargs["cwd"], fixture.repository)
                environment = kwargs["env"]
                self.assertEqual(
                    {
                        name
                        for name in environment
                        if name.startswith("STALWART_")
                    },
                    set(),
                )
                if args[-4:] == [
                    "config",
                    "--format",
                    "json",
                    "stalwart",
                ]:
                    events.append("model")
                    return stalwart_v016.RedactedCommandResult(
                        json.dumps(
                            self._valid_normal_compose_model(fixture),
                        ).encode("utf-8"),
                        b"",
                    )
                if args[:3] == ["docker", "image", "inspect"]:
                    events.append("image")
                    return stalwart_v016.RedactedCommandResult(
                        (
                            stalwart_v016.STALWART_IMAGE_ID + "\n"
                        ).encode("ascii"),
                        b"",
                    )
                if "up" in args:
                    events.append("start")
                    running = True
                    return stalwart_v016.RedactedCommandResult(b"", b"")
                if "restart" in args:
                    events.append("restart")
                    return stalwart_v016.RedactedCommandResult(b"", b"")
                if args[-4:] == [
                    "ps",
                    "--all",
                    "--quiet",
                    "stalwart",
                ]:
                    events.append("ps")
                    return stalwart_v016.RedactedCommandResult(
                        (container_id + "\n").encode("ascii"),
                        b"",
                    )
                if args[:3] == ["docker", "inspect", "--type"]:
                    events.append("inspect")
                    return stalwart_v016.RedactedCommandResult(
                        json.dumps(
                            self._valid_normal_inspection(
                                fixture,
                                container_id,
                            ),
                        ).encode("utf-8"),
                        b"",
                    )
                if args[:2] == ["docker", "exec"]:
                    events.append("version")
                    return stalwart_v016.RedactedCommandResult(
                        b"0.16.17\n",
                        b"",
                    )
                if "stop" in args:
                    events.append("stop")
                    running = False
                    return stalwart_v016.RedactedCommandResult(b"", b"")
                self.fail(f"unexpected runtime command: {args!r}")

            def state_runner(args: list[str]) -> object:
                if running and args[:2] == ["docker", "ps"]:
                    events.append("census-ps")
                    return stalwart_v016.CommandResult(
                        container_id + "\n",
                        "",
                    )
                if running and args[:2] == ["docker", "inspect"]:
                    events.append("census-inspect")
                    return stalwart_v016.CommandResult(
                        json.dumps(
                            [
                                self._valid_normal_census_record(
                                    fixture,
                                    container_id,
                                ),
                            ],
                        ),
                        "",
                    )
                return fixture.runner(args)

            def readiness() -> int:
                events.append("readiness")
                return 200

            def auth_probe(
                credential: memoryview,
                *,
                scheme: str,
                expected_api_url: str,
            ) -> object:
                self.assertEqual(
                    expected_api_url,
                    f"{fixture.public_url}/jmap/",
                )
                observed_buffers.append(credential.obj)
                if scheme == "bearer":
                    events.append("bearer")
                    return stalwart_v016.JmapAuthProbe(
                        status=200,
                        account_id=(
                            fixture.bootstrap_token.management_account_id
                        ),
                        username=(
                            "dashboard-management@local.test"
                        ),
                    )
                if bytes(credential) == (
                    b"dashboard-management@local.test:secret"
                ):
                    events.append("management-basic")
                    return stalwart_v016.JmapAuthProbe(
                        status=200,
                        account_id=(
                            fixture.bootstrap_token.management_account_id
                        ),
                        username="dashboard-management@local.test",
                    )
                events.append("recovery-basic")
                return stalwart_v016.JmapAuthProbe(
                    status=401,
                    account_id=None,
                    username=None,
                )

            def smtp_probe(credential: memoryview) -> int:
                observed_buffers.append(credential.obj)
                self.assertEqual(
                    bytes(credential),
                    b"dashboard-management@local.test:secret",
                )
                events.append("smtp")
                return 250

            def basic_jmap_probe(
                credential: memoryview,
                *,
                expected_api_url: str,
            ) -> object:
                return auth_probe(
                    credential,
                    scheme="basic",
                    expected_api_url=expected_api_url,
                )

            def recording_write(
                target: Path,
                value: object,
                **kwargs: object,
            ) -> None:
                original_write(target, value, **kwargs)
                if target == fixture.paths.retire_recovery_proof:
                    events.append("checkpoint")

            def recording_delete(
                paths: object,
                plan: object,
            ) -> None:
                original_delete(paths, plan)
                events.append("delete")

            executor = stalwart_v016.RecoveryRetirementExecutor(
                paths=fixture.paths,
                runner=runtime_runner,
                state_runner=state_runner,
                jmap_probe_runner=auth_probe,
                basic_jmap_probe_runner=basic_jmap_probe,
                smtp_probe_runner=smtp_probe,
                readiness_probe_runner=readiness,
            )
            verifier = (
                stalwart_v016.RecoveryRetirementPostflightVerifier(
                    paths=fixture.paths,
                    runner=runtime_runner,
                    state_runner=state_runner,
                    jmap_probe_runner=auth_probe,
                    basic_jmap_probe_runner=basic_jmap_probe,
                    smtp_probe_runner=smtp_probe,
                    readiness_probe_runner=readiness,
                )
            )
            with (
                mock.patch.object(
                    stalwart_v016,
                    "_write_new_json_0600",
                    side_effect=recording_write,
                ),
                mock.patch.object(
                    stalwart_v016,
                    "_delete_bound_recovery_artifacts",
                    side_effect=recording_delete,
                ),
            ):
                result = self._retire(
                    fixture,
                    executor,
                    postflight_verifier=verifier,
                )

            self.assertEqual(
                result,
                fixture.paths.recovery_retired_receipt,
            )
            self.assertEqual(
                events,
                [
                    "model",
                    "image",
                    "start",
                    "ps",
                    "inspect",
                    "version",
                    "readiness",
                    "bearer",
                    "management-basic",
                    "smtp",
                    "recovery-basic",
                    "restart",
                    "ps",
                    "inspect",
                    "version",
                    "readiness",
                    "bearer",
                    "management-basic",
                    "smtp",
                    "recovery-basic",
                    "census-ps",
                    "census-inspect",
                    "checkpoint",
                    "delete",
                    "model",
                    "image",
                    "ps",
                    "inspect",
                    "version",
                    "readiness",
                    "bearer",
                    "management-basic",
                    "smtp",
                    "census-ps",
                    "census-inspect",
                ],
            )
            self.assertTrue(running)
            self.assertTrue(observed_buffers)
            self.assertTrue(
                all(
                    all(item == 0 for item in buffer)
                    for buffer in observed_buffers
                ),
            )

    def test_production_retirement_executor_auth_failure_stops_without_checkpoint_or_delete(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._applied_fixture(directory)
            container_id = "e" * 64
            events: list[str] = []
            observed_management: list[bytearray] = []
            deletion = mock.Mock()

            def runtime_runner(
                args: list[str],
                **_kwargs: object,
            ) -> object:
                if args[-4:] == [
                    "config",
                    "--format",
                    "json",
                    "stalwart",
                ]:
                    events.append("model")
                    return stalwart_v016.RedactedCommandResult(
                        json.dumps(
                            self._valid_normal_compose_model(fixture),
                        ).encode("utf-8"),
                        b"",
                    )
                if args[:3] == ["docker", "image", "inspect"]:
                    events.append("image")
                    return stalwart_v016.RedactedCommandResult(
                        stalwart_v016.STALWART_IMAGE_ID.encode("ascii"),
                        b"",
                    )
                if "up" in args:
                    events.append("start")
                    return stalwart_v016.RedactedCommandResult(b"", b"")
                if args[-4:] == [
                    "ps",
                    "--all",
                    "--quiet",
                    "stalwart",
                ]:
                    events.append("ps")
                    return stalwart_v016.RedactedCommandResult(
                        container_id.encode("ascii"),
                        b"",
                    )
                if args[:3] == ["docker", "inspect", "--type"]:
                    events.append("inspect")
                    return stalwart_v016.RedactedCommandResult(
                        json.dumps(
                            self._valid_normal_inspection(
                                fixture,
                                container_id,
                            ),
                        ).encode("utf-8"),
                        b"",
                    )
                if args[:2] == ["docker", "exec"]:
                    events.append("version")
                    return stalwart_v016.RedactedCommandResult(
                        b"0.16.17",
                        b"",
                    )
                if "stop" in args:
                    events.append("stop")
                    return stalwart_v016.RedactedCommandResult(b"", b"")
                self.fail(f"unexpected runtime command: {args!r}")

            def readiness() -> int:
                events.append("readiness")
                return 200

            def failed_auth(
                credential: memoryview,
                *,
                scheme: str,
                expected_api_url: str,
            ) -> object:
                self.assertEqual(scheme, "bearer")
                self.assertEqual(expected_api_url, f"{fixture.public_url}/jmap/")
                events.append("bearer")
                observed_management.append(credential.obj)
                return stalwart_v016.JmapAuthProbe(
                    status=200,
                    account_id="wrong-account",
                    username="dashboard-management@local.test",
                )

            executor = stalwart_v016.RecoveryRetirementExecutor(
                paths=fixture.paths,
                runner=runtime_runner,
                state_runner=mock.Mock(),
                jmap_probe_runner=failed_auth,
                readiness_probe_runner=readiness,
            )
            with (
                mock.patch.object(
                    stalwart_v016,
                    "_delete_bound_recovery_artifacts",
                    deletion,
                ),
                self.assertRaises(stalwart_v016.MigrationError),
            ):
                self._retire(
                    fixture,
                    executor,
                    postflight_verifier=mock.Mock(),
                )

            self.assertEqual(
                events,
                [
                    "model",
                    "image",
                    "start",
                    "ps",
                    "inspect",
                    "version",
                    "readiness",
                    "bearer",
                    "stop",
                ],
            )
            deletion.assert_not_called()
            self.assertFalse(
                fixture.paths.retire_recovery_proof.exists(),
            )
            self.assertTrue(
                fixture.paths.migration_root.joinpath(
                    "recovery.env",
                ).exists(),
            )
            self.assertTrue(
                fixture.paths.migration_root.joinpath(
                    "recovery-config",
                    "config.json",
                ).exists(),
            )
            self.assertEqual(len(observed_management), 1)
            self.assertTrue(
                all(item == 0 for item in observed_management[0]),
            )

    def test_production_retirement_executor_cancellation_stops_and_is_exact(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._applied_fixture(directory)
            captured: dict[str, object] = {}

            def capture_plan(
                plan: object,
                _lease: object,
                _checkpoint: object,
            ) -> object:
                captured["plan"] = plan
                raise stalwart_v016.MigrationError("unit-only plan capture")

            with self.assertRaises(stalwart_v016.MigrationError):
                self._retire(
                    fixture,
                    capture_plan,
                    postflight_verifier=mock.Mock(),
                )

            plan = captured["plan"]
            container_id = "a" * 64
            commands: list[list[str]] = []
            interruption = KeyboardInterrupt(
                "unit-retirement-cancellation",
            )
            observed_key: list[bytearray] = []

            def runtime_runner(
                args: list[str],
                **_kwargs: object,
            ) -> object:
                commands.append(args)
                if args[-4:] == [
                    "config",
                    "--format",
                    "json",
                    "stalwart",
                ]:
                    return stalwart_v016.RedactedCommandResult(b"{}", b"")
                if args[:3] == ["docker", "image", "inspect"]:
                    return stalwart_v016.RedactedCommandResult(
                        stalwart_v016.STALWART_IMAGE_ID.encode("ascii"),
                        b"",
                    )
                if args[-4:] == [
                    "ps",
                    "--all",
                    "--quiet",
                    "stalwart",
                ]:
                    return stalwart_v016.RedactedCommandResult(
                        container_id.encode("ascii"),
                        b"",
                    )
                if args[:3] == ["docker", "inspect", "--type"]:
                    return stalwart_v016.RedactedCommandResult(b"{}", b"")
                if args[:2] == ["docker", "exec"]:
                    return stalwart_v016.RedactedCommandResult(
                        b"0.16.17",
                        b"",
                    )
                return stalwart_v016.RedactedCommandResult(b"", b"")

            def cancelling_probe(
                credential: memoryview,
                *,
                scheme: str,
                expected_api_url: str,
            ) -> object:
                self.assertEqual(scheme, "bearer")
                self.assertEqual(expected_api_url, f"{fixture.public_url}/jmap/")
                observed_key.append(credential.obj)
                raise interruption

            inspection = stalwart_v016.NormalRuntimeInspection(
                container_id=container_id,
                image_reference=stalwart_v016.STALWART_IMAGE,
                image_id=stalwart_v016.STALWART_IMAGE_ID,
                recovery_environment_names=(),
            )
            executor = stalwart_v016.RecoveryRetirementExecutor(
                paths=fixture.paths,
                runner=runtime_runner,
                state_runner=mock.Mock(),
                jmap_probe_runner=cancelling_probe,
                readiness_probe_runner=lambda: 200,
            )
            recovery = bytearray(b"unit-user:unit-secret")
            lease = stalwart_v016.RecoveryCredentialLease(recovery)
            try:
                with (
                    mock.patch.object(
                        stalwart_v016,
                        "_validate_normal_compose_model",
                    ),
                    mock.patch.object(
                        stalwart_v016,
                        "_validate_normal_container_inspection",
                        return_value=inspection,
                    ),
                    self.assertRaises(KeyboardInterrupt) as raised,
                ):
                    executor(plan, lease, mock.Mock())
            finally:
                lease.close()

            self.assertIs(raised.exception, interruption)
            self.assertTrue(commands)
            self.assertIn("stop", commands[-1])
            self.assertEqual(len(observed_key), 1)
            self.assertTrue(
                all(item == 0 for item in observed_key[0]),
            )
            self.assertFalse(
                fixture.paths.retire_recovery_proof.exists(),
            )

    def test_production_retirement_executor_never_stops_after_checkpoint_callback_returns(
        self,
    ) -> None:
        failures: tuple[BaseException, ...] = (
            RuntimeError("unit-post-checkpoint-error"),
            KeyboardInterrupt("unit-post-checkpoint-interrupt"),
            SystemExit("unit-post-checkpoint-exit"),
        )
        for failure in failures:
            with (
                self.subTest(failure=type(failure).__name__),
                tempfile.TemporaryDirectory() as directory,
            ):
                fixture = self._applied_fixture(directory)
                captured: dict[str, object] = {}

                def capture(
                    plan: object,
                    _lease: object,
                    checkpoint: object,
                ) -> object:
                    captured["plan"] = plan
                    captured["checkpoint"] = checkpoint
                    raise stalwart_v016.MigrationError(
                        "unit-only plan capture",
                    )

                with self.assertRaises(stalwart_v016.MigrationError):
                    self._retire(
                        fixture,
                        capture,
                        postflight_verifier=mock.Mock(),
                    )

                plan = captured["plan"]
                checkpoint = captured["checkpoint"]
                container_id = "b" * 64
                running = False
                commands: list[list[str]] = []

                def runtime_runner(
                    args: list[str],
                    **_kwargs: object,
                ) -> object:
                    nonlocal running
                    commands.append(args)
                    if args[-4:] == [
                        "config",
                        "--format",
                        "json",
                        "stalwart",
                    ]:
                        return stalwart_v016.RedactedCommandResult(
                            b"{}",
                            b"",
                        )
                    if args[:3] == ["docker", "image", "inspect"]:
                        return stalwart_v016.RedactedCommandResult(
                            stalwart_v016.STALWART_IMAGE_ID.encode("ascii"),
                            b"",
                        )
                    if "up" in args:
                        running = True
                        return stalwart_v016.RedactedCommandResult(b"", b"")
                    if "restart" in args:
                        return stalwart_v016.RedactedCommandResult(b"", b"")
                    if "stop" in args:
                        running = False
                        return stalwart_v016.RedactedCommandResult(b"", b"")
                    if args[-4:] == [
                        "ps",
                        "--all",
                        "--quiet",
                        "stalwart",
                    ]:
                        return stalwart_v016.RedactedCommandResult(
                            container_id.encode("ascii"),
                            b"",
                        )
                    if args[:3] == ["docker", "inspect", "--type"]:
                        return stalwart_v016.RedactedCommandResult(b"{}", b"")
                    if args[:2] == ["docker", "exec"]:
                        return stalwart_v016.RedactedCommandResult(
                            b"0.16.17",
                            b"",
                        )
                    self.fail(f"unexpected runtime command: {args!r}")

                def auth_probe(
                    _credential: memoryview,
                    *,
                    scheme: str,
                    expected_api_url: str,
                ) -> object:
                    self.assertEqual(
                        expected_api_url,
                        f"{fixture.public_url}/jmap/",
                    )
                    if scheme == "bearer":
                        return stalwart_v016.JmapAuthProbe(
                            status=200,
                            account_id=(
                                fixture
                                .bootstrap_token
                                .management_account_id
                            ),
                            username=(
                                "dashboard-management@local.test"
                            ),
                        )
                    return stalwart_v016.JmapAuthProbe(
                        status=401,
                        account_id=None,
                        username=None,
                    )

                inspection = stalwart_v016.NormalRuntimeInspection(
                    container_id=container_id,
                    image_reference=stalwart_v016.STALWART_IMAGE,
                    image_id=stalwart_v016.STALWART_IMAGE_ID,
                    recovery_environment_names=(),
                )
                executor = stalwart_v016.RecoveryRetirementExecutor(
                    paths=fixture.paths,
                    runner=runtime_runner,
                    state_runner=mock.Mock(),
                    jmap_probe_runner=auth_probe,
                    basic_jmap_probe_runner=lambda _credential, *, expected_api_url: (
                        stalwart_v016.JmapAuthProbe(
                            status=200,
                            account_id=(
                                fixture
                                .bootstrap_token
                                .management_account_id
                            ),
                            username=(
                                "dashboard-management@local.test"
                            ),
                        )
                    ),
                    smtp_probe_runner=lambda _credential: 250,
                    readiness_probe_runner=lambda: 200,
                )
                original_snapshot = (
                    stalwart_v016._retirement_proof_snapshot
                )
                snapshot_calls = 0

                def fail_redundant_snapshot(
                    paths: object,
                ) -> object:
                    nonlocal snapshot_calls
                    snapshot_calls += 1
                    if snapshot_calls == 2:
                        raise failure
                    return original_snapshot(paths)

                lease = stalwart_v016.RecoveryCredentialLease(
                    bytearray(b"unit-user:unit-secret"),
                )
                deletion = mock.Mock()
                try:
                    with (
                        mock.patch.object(
                            stalwart_v016,
                            "_validate_normal_compose_model",
                        ),
                        mock.patch.object(
                            stalwart_v016,
                            "_validate_normal_container_inspection",
                            return_value=inspection,
                        ),
                        mock.patch.object(
                            stalwart_v016,
                            "_normal_runtime_writer_census",
                            return_value=((container_id,), ()),
                        ),
                        mock.patch.object(
                            stalwart_v016,
                            "_delete_bound_recovery_artifacts",
                            deletion,
                        ),
                        mock.patch.object(
                            stalwart_v016,
                            "_retirement_proof_snapshot",
                            side_effect=fail_redundant_snapshot,
                        ),
                    ):
                        if isinstance(failure, Exception):
                            with self.assertRaises(
                                stalwart_v016.MigrationError,
                            ):
                                executor(plan, lease, checkpoint)
                        else:
                            with self.assertRaises(
                                type(failure),
                            ) as raised:
                                executor(plan, lease, checkpoint)
                            self.assertIs(raised.exception, failure)
                finally:
                    lease.close()

                self.assertEqual(snapshot_calls, 2)
                self.assertTrue(running)
                self.assertFalse(
                    any("stop" in command for command in commands),
                )
                deletion.assert_not_called()
                self.assertTrue(
                    fixture.paths.retire_recovery_attempt.exists(),
                )
                self.assertTrue(
                    fixture.paths.retire_recovery_proof.exists(),
                )
                self.assertTrue(
                    fixture.paths.migration_root.joinpath(
                        "recovery.env",
                    ).exists(),
                )
                self.assertTrue(
                    fixture.paths.migration_root.joinpath(
                        "recovery-config",
                        "config.json",
                    ).exists(),
                )

    def test_production_retirement_executor_keeps_source_and_invocation_roots_distinct(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._applied_fixture(directory)
            captured: dict[str, object] = {}

            def capture_plan(
                plan: object,
                _lease: object,
                _checkpoint: object,
            ) -> object:
                captured["plan"] = plan
                raise stalwart_v016.MigrationError("unit-only plan capture")

            with self.assertRaises(stalwart_v016.MigrationError):
                self._retire(
                    fixture,
                    capture_plan,
                    postflight_verifier=mock.Mock(),
                )

            original_plan = captured["plan"]
            source_root = (
                Path(directory).resolve() / "approved-primary-checkout"
            )
            source_root.mkdir(mode=0o700)
            source_public_url = "http://192.168.86.37:8443"
            write_network_environment(source_root, source_public_url)
            source_store = source_root / "stalwart-data"
            source_store.mkdir(mode=0o700)
            source_base = source_root / "docker-compose.yml"
            source_base.write_bytes(
                fixture.repository.joinpath(
                    "docker-compose.yml",
                ).read_bytes(),
            )
            source_base.chmod(0o644)
            source_config = source_root / "stalwart" / "config.json"
            source_config.parent.mkdir(mode=0o700)
            source_config.write_bytes(
                fixture.paths.converted_config.read_bytes(),
            )
            source_config.chmod(0o644)
            source_metadata = source_base.stat()
            source_binding = stalwart_v016.ApplyFile(
                path=source_base,
                sha256=hashlib.sha256(
                    source_base.read_bytes(),
                ).hexdigest(),
                size=source_metadata.st_size,
                identity=stalwart_v016._file_identity(
                    source_metadata,
                ),
            )
            source = stalwart_v016.VerifiedSource(
                checkout_root=source_root,
                provider_store=source_store,
                base_compose=source_base,
                compose_project="mail-sandbox",
                compose_service="stalwart",
            )
            plan = replace(
                original_plan,
                inputs=(
                    *original_plan.inputs[:-1],
                    source_binding,
                ),
                runtime=replace(
                    original_plan.runtime,
                    data_dir=source_store,
                ),
                source=source,
            )
            source_fixture = SimpleNamespace(
                repository=source_root,
                source_store=source_store,
                compose_project=plan.source.compose_project,
                public_url=source_public_url,
            )
            container_id = "f" * 64
            events: list[str] = []
            observed_key: list[bytes] = []

            def runtime_runner(
                args: list[str],
                **kwargs: object,
            ) -> object:
                self.assertEqual(kwargs["cwd"], source_root)
                if args[:2] == ["docker", "compose"]:
                    project_index = args.index("--project-directory")
                    file_index = args.index("--file")
                    self.assertEqual(
                        args[project_index + 1],
                        str(source_root),
                    )
                    self.assertEqual(
                        args[file_index + 1],
                        str(source_base),
                    )
                    self.assertNotIn(
                        str(fixture.repository / "docker-compose.yml"),
                        args,
                    )
                if args[-4:] == [
                    "config",
                    "--format",
                    "json",
                    "stalwart",
                ]:
                    events.append("model")
                    return stalwart_v016.RedactedCommandResult(
                        json.dumps(
                            self._valid_normal_compose_model(
                                source_fixture,
                            ),
                        ).encode("utf-8"),
                        b"",
                    )
                if args[:3] == ["docker", "image", "inspect"]:
                    events.append("image")
                    return stalwart_v016.RedactedCommandResult(
                        stalwart_v016.STALWART_IMAGE_ID.encode("ascii"),
                        b"",
                    )
                if "up" in args:
                    events.append("start")
                    return stalwart_v016.RedactedCommandResult(b"", b"")
                if args[-4:] == [
                    "ps",
                    "--all",
                    "--quiet",
                    "stalwart",
                ]:
                    events.append("ps")
                    return stalwart_v016.RedactedCommandResult(
                        container_id.encode("ascii"),
                        b"",
                    )
                if args[:3] == ["docker", "inspect", "--type"]:
                    events.append("inspect")
                    return stalwart_v016.RedactedCommandResult(
                        json.dumps(
                            self._valid_normal_inspection(
                                source_fixture,
                                container_id,
                            ),
                        ).encode("utf-8"),
                        b"",
                    )
                if args[:2] == ["docker", "exec"]:
                    events.append("version")
                    return stalwart_v016.RedactedCommandResult(
                        b"0.16.17",
                        b"",
                    )
                if "stop" in args:
                    events.append("stop")
                    return stalwart_v016.RedactedCommandResult(b"", b"")
                self.fail(f"unexpected runtime command: {args!r}")

            def wrong_auth(
                credential: memoryview,
                *,
                scheme: str,
                expected_api_url: str,
            ) -> object:
                self.assertEqual(scheme, "bearer")
                self.assertEqual(
                    expected_api_url,
                    f"{source_fixture.public_url}/jmap/",
                )
                observed_key.append(bytes(credential))
                return stalwart_v016.JmapAuthProbe(
                    status=200,
                    account_id="wrong-account",
                    username="dashboard-management@local.test",
                )

            executor = stalwart_v016.RecoveryRetirementExecutor(
                paths=fixture.paths,
                runner=runtime_runner,
                state_runner=mock.Mock(),
                jmap_probe_runner=wrong_auth,
                readiness_probe_runner=lambda: 200,
            )
            recovery = bytearray(b"unit-user:unit-secret")
            lease = stalwart_v016.RecoveryCredentialLease(recovery)
            try:
                with self.assertRaises(stalwart_v016.MigrationError):
                    executor(plan, lease, mock.Mock())
            finally:
                lease.close()

            self.assertNotEqual(
                fixture.paths.repository_root,
                plan.source.checkout_root,
            )
            self.assertEqual(
                observed_key,
                [fixture.management_key_bytes],
            )
            self.assertEqual(
                events,
                [
                    "model",
                    "image",
                    "start",
                    "ps",
                    "inspect",
                    "version",
                    "stop",
                ],
            )

    def test_recovery_artifact_deletion_requires_checkpoint_and_fsyncs_in_order(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._applied_fixture(directory)
            paths = fixture.paths
            proofs: list[object] = []
            events: list[str] = []

            def executor(
                plan: object,
                _lease: object,
                checkpoint: object,
            ) -> object:
                with self.assertRaisesRegex(
                    stalwart_v016.MigrationError,
                    "proof checkpoint",
                ):
                    stalwart_v016._delete_bound_recovery_artifacts(
                        paths,
                        plan,
                    )
                self.assertTrue(plan.recovery_environment.path.exists())
                self.assertTrue(plan.recovery_config.path.exists())

                proof = self._valid_retirement_proof(plan)
                proofs.append(proof)
                checkpoint(proof)
                migration_root = paths.migration_root.stat()
                config_directory = plan.runtime.config_dir.stat()
                original_unlink = stalwart_v016.os.unlink
                original_rmdir = stalwart_v016.os.rmdir
                original_fsync = stalwart_v016.os.fsync

                def unlink(
                    target: object,
                    *,
                    dir_fd: int | None = None,
                ) -> None:
                    events.append(f"unlink:{target}")
                    original_unlink(target, dir_fd=dir_fd)

                def rmdir(
                    target: object,
                    *,
                    dir_fd: int | None = None,
                ) -> None:
                    events.append(f"rmdir:{target}")
                    original_rmdir(target, dir_fd=dir_fd)

                def fsync(descriptor: int) -> None:
                    metadata = os.fstat(descriptor)
                    if (
                        metadata.st_dev,
                        metadata.st_ino,
                    ) == (
                        config_directory.st_dev,
                        config_directory.st_ino,
                    ):
                        events.append("fsync:config-directory")
                    elif (
                        metadata.st_dev,
                        metadata.st_ino,
                    ) == (
                        migration_root.st_dev,
                        migration_root.st_ino,
                    ):
                        events.append("fsync:migration-root")
                    else:
                        events.append("fsync:unexpected")
                    original_fsync(descriptor)

                with (
                    mock.patch.object(
                        stalwart_v016.os,
                        "unlink",
                        side_effect=unlink,
                    ),
                    mock.patch.object(
                        stalwart_v016.os,
                        "rmdir",
                        side_effect=rmdir,
                    ),
                    mock.patch.object(
                        stalwart_v016.os,
                        "fsync",
                        side_effect=fsync,
                    ),
                ):
                    stalwart_v016._delete_bound_recovery_artifacts(
                        paths,
                        plan,
                    )
                return proof

            self._retire(
                fixture,
                executor,
                postflight_verifier=lambda _plan: proofs[0],
            )

            self.assertEqual(
                events,
                [
                    "unlink:recovery.env",
                    "fsync:migration-root",
                    "unlink:config.json",
                    "fsync:config-directory",
                    "rmdir:recovery-config",
                    "fsync:migration-root",
                ],
            )

    def test_recovery_artifact_deletion_refuses_identity_substitution(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._applied_fixture(directory)
            paths = fixture.paths
            replacement = b"STALWART_RECOVERY_ADMIN=new-user:new-secret\n"

            def executor(
                plan: object,
                _lease: object,
                checkpoint: object,
            ) -> object:
                proof = self._valid_retirement_proof(plan)
                checkpoint(proof)
                plan.recovery_environment.path.unlink()
                self._write_0600(
                    plan.recovery_environment.path,
                    replacement,
                )
                with self.assertRaisesRegex(
                    stalwart_v016.MigrationError,
                    "identity",
                ):
                    stalwart_v016._delete_bound_recovery_artifacts(
                        paths,
                        plan,
                    )
                return proof

            with self.assertRaises(stalwart_v016.MigrationError):
                self._retire(
                    fixture,
                    executor,
                    postflight_verifier=mock.Mock(),
                )

            self.assertEqual(
                paths.migration_root.joinpath("recovery.env").read_bytes(),
                replacement,
            )
            self.assertTrue(
                paths.migration_root.joinpath(
                    "recovery-config",
                    "config.json",
                ).exists(),
            )

    def test_recovery_artifact_deletion_prevalidates_all_targets_before_first_unlink(
        self,
    ) -> None:
        cases = ("config-replacement", "config-directory-swap", "extra-entry")
        for case in cases:
            with (
                self.subTest(case=case),
                tempfile.TemporaryDirectory() as directory,
            ):
                fixture = self._applied_fixture(directory)
                paths = fixture.paths
                environment_before = paths.migration_root.joinpath(
                    "recovery.env",
                ).read_bytes()

                def executor(
                    plan: object,
                    _lease: object,
                    checkpoint: object,
                ) -> object:
                    proof = self._valid_retirement_proof(plan)
                    checkpoint(proof)
                    config_directory = plan.runtime.config_dir
                    config_path = config_directory / "config.json"
                    config_content = config_path.read_bytes()
                    if case == "config-replacement":
                        config_path.unlink()
                        self._write_0644(config_path, config_content)
                    elif case == "config-directory-swap":
                        displaced = config_directory.with_name(
                            "recovery-config-displaced",
                        )
                        config_directory.rename(displaced)
                        config_directory.mkdir(mode=0o755)
                        self._write_0644(
                            config_directory / "config.json",
                            config_content,
                        )
                    else:
                        self._write_0600(
                            config_directory / "unexpected",
                            b"unexpected\n",
                        )

                    with (
                        mock.patch.object(
                            stalwart_v016.os,
                            "unlink",
                        ) as unlink,
                        mock.patch.object(
                            stalwart_v016.os,
                            "fsync",
                        ) as fsync,
                        mock.patch.object(
                            stalwart_v016.os,
                            "rmdir",
                        ) as rmdir,
                        self.assertRaises(stalwart_v016.MigrationError),
                    ):
                        stalwart_v016._delete_bound_recovery_artifacts(
                            paths,
                            plan,
                        )

                    unlink.assert_not_called()
                    fsync.assert_not_called()
                    rmdir.assert_not_called()
                    self.assertEqual(
                        plan.recovery_environment.path.read_bytes(),
                        environment_before,
                    )
                    raise stalwart_v016.MigrationError(
                        "unit-only retirement abort",
                    )

                with self.assertRaises(stalwart_v016.MigrationError):
                    self._retire(
                        fixture,
                        executor,
                        postflight_verifier=mock.Mock(),
                    )

    def test_recovery_artifact_deletion_revalidates_config_after_environment_fsync(
        self,
    ) -> None:
        for case in ("config-replacement", "config-directory-swap"):
            with (
                self.subTest(case=case),
                tempfile.TemporaryDirectory() as directory,
            ):
                fixture = self._applied_fixture(directory)
                paths = fixture.paths
                observed: dict[str, object] = {}

                def executor(
                    plan: object,
                    _lease: object,
                    checkpoint: object,
                ) -> object:
                    proof = self._valid_retirement_proof(plan)
                    checkpoint(proof)
                    config_directory = plan.runtime.config_dir
                    config_path = config_directory / "config.json"
                    config_content = config_path.read_bytes()
                    migration_root = paths.migration_root.stat()
                    original_fsync = stalwart_v016.os.fsync
                    mutated = False
                    displaced = config_directory.with_name(
                        "recovery-config-displaced",
                    )

                    def fsync(descriptor: int) -> None:
                        nonlocal mutated
                        original_fsync(descriptor)
                        metadata = os.fstat(descriptor)
                        if (
                            not mutated
                            and (
                                metadata.st_dev,
                                metadata.st_ino,
                            )
                            == (
                                migration_root.st_dev,
                                migration_root.st_ino,
                            )
                        ):
                            mutated = True
                            if case == "config-replacement":
                                config_path.unlink()
                                self._write_0644(
                                    config_path,
                                    config_content,
                                )
                            else:
                                config_directory.rename(displaced)
                                config_directory.mkdir(mode=0o755)
                                self._write_0644(
                                    config_directory / "config.json",
                                    config_content,
                                )

                    try:
                        with mock.patch.object(
                            stalwart_v016.os,
                            "fsync",
                            side_effect=fsync,
                        ):
                            stalwart_v016._delete_bound_recovery_artifacts(
                                paths,
                                plan,
                            )
                    except BaseException as error:
                        observed["error"] = error
                    observed["mutated"] = mutated
                    observed["environment_exists"] = (
                        plan.recovery_environment.path.exists()
                    )
                    observed["config_exists"] = config_path.exists()
                    observed["displaced_config_exists"] = (
                        displaced.joinpath("config.json").exists()
                    )
                    raise stalwart_v016.MigrationError(
                        "unit-only deletion race abort",
                    )

                with self.assertRaises(stalwart_v016.MigrationError):
                    self._retire(
                        fixture,
                        executor,
                        postflight_verifier=mock.Mock(),
                    )
                self.assertIsInstance(
                    observed.get("error"),
                    stalwart_v016.MigrationError,
                )
                self.assertIs(observed.get("mutated"), True)
                self.assertIs(
                    observed.get("environment_exists"),
                    False,
                )
                self.assertIs(observed.get("config_exists"), True)
                if case == "config-directory-swap":
                    self.assertIs(
                        observed.get("displaced_config_exists"),
                        True,
                    )

    def test_retirement_attempt_without_checkpoint_never_replays_auth_or_executor(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._applied_fixture(directory)
            borrowed: list[memoryview] = []

            def interrupted_executor(
                _plan: object,
                lease: object,
                _checkpoint: object,
            ) -> object:
                borrowed.append(lease.borrow())
                raise KeyboardInterrupt("unit-only interruption")

            with self.assertRaises(KeyboardInterrupt):
                self._retire(
                    fixture,
                    interrupted_executor,
                    postflight_verifier=mock.Mock(),
                )

            self.assertTrue(fixture.paths.retire_recovery_attempt.exists())
            self.assertFalse(fixture.paths.retire_recovery_proof.exists())
            self.assertFalse(fixture.paths.recovery_retired_receipt.exists())
            self.assertEqual(
                bytes(borrowed[0]),
                b"\x00" * len(b"unit-user:unit-secret"),
            )
            fixture.events.clear()
            replay_executor = mock.Mock()
            verifier = mock.Mock()

            with self.assertRaisesRegex(
                stalwart_v016.MigrationError,
                "manual reconciliation",
            ):
                self._retire(
                    fixture,
                    replay_executor,
                    postflight_verifier=verifier,
                )

            replay_executor.assert_not_called()
            verifier.assert_not_called()
            self.assertEqual(fixture.events, [])

    def test_retirement_executor_failure_is_redacted_and_wipes_borrowed_bytes(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._applied_fixture(directory)
            borrowed: list[memoryview] = []

            def failing_executor(
                _plan: object,
                lease: object,
                _checkpoint: object,
            ) -> object:
                borrowed.append(lease.borrow())
                raise RuntimeError("unit-user:unit-secret")

            with self.assertRaises(
                stalwart_v016.MigrationError,
            ) as raised:
                self._retire(
                    fixture,
                    failing_executor,
                    postflight_verifier=mock.Mock(),
                )

            self.assertIsNone(raised.exception.__context__)
            self.assertNotIn("unit-user", str(raised.exception))
            self.assertNotIn("unit-secret", str(raised.exception))
            self.assertEqual(
                bytes(borrowed[0]),
                b"\x00" * len(b"unit-user:unit-secret"),
            )
            self.assertTrue(fixture.paths.retire_recovery_attempt.exists())
            self.assertFalse(fixture.paths.retire_recovery_proof.exists())

    def test_checkpoint_resume_is_finalize_only_and_final_receipt_is_validation_only(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._applied_fixture(directory)
            proofs: list[object] = []
            borrowed: list[memoryview] = []

            def interrupted_after_delete(
                plan: object,
                lease: object,
                checkpoint: object,
            ) -> object:
                borrowed.append(lease.borrow())
                proof = self._valid_retirement_proof(plan)
                proofs.append(proof)
                checkpoint(proof)
                self._delete_recovery_artifacts(fixture)
                raise SystemExit("unit-only interruption after delete")

            with self.assertRaises(SystemExit):
                self._retire(
                    fixture,
                    interrupted_after_delete,
                    postflight_verifier=mock.Mock(),
                )

            self.assertTrue(fixture.paths.retire_recovery_attempt.exists())
            self.assertTrue(fixture.paths.retire_recovery_proof.exists())
            self.assertFalse(fixture.paths.recovery_retired_receipt.exists())
            self.assertEqual(
                bytes(borrowed[0]),
                b"\x00" * len(b"unit-user:unit-secret"),
            )

            resumed_executor = mock.Mock()
            resumed_verifier = mock.Mock(return_value=proofs[0])
            receipt = self._retire(
                fixture,
                resumed_executor,
                postflight_verifier=resumed_verifier,
            )
            self.assertEqual(receipt, fixture.paths.recovery_retired_receipt)
            resumed_executor.assert_not_called()
            resumed_verifier.assert_called_once()

            fixture.state["writer"] = True
            fixture.events.clear()
            validation_executor = mock.Mock()
            validation_verifier = mock.Mock()
            self.assertEqual(
                self._retire(
                    fixture,
                    validation_executor,
                    postflight_verifier=validation_verifier,
                ),
                receipt,
            )
            validation_executor.assert_not_called()
            validation_verifier.assert_not_called()
            self.assertNotIn("census", fixture.events)

    def test_checkpoint_without_artifact_deletion_resumes_without_executor(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._applied_fixture(directory)
            proofs: list[object] = []

            def interrupted_before_delete(
                plan: object,
                _lease: object,
                checkpoint: object,
            ) -> object:
                proof = self._valid_retirement_proof(plan)
                proofs.append(proof)
                checkpoint(proof)
                raise KeyboardInterrupt("unit-only interruption before delete")

            with self.assertRaises(KeyboardInterrupt):
                self._retire(
                    fixture,
                    interrupted_before_delete,
                    postflight_verifier=mock.Mock(),
                )

            retry_executor = mock.Mock()
            retry_verifier = mock.Mock(return_value=proofs[0])
            receipt = self._retire(
                fixture,
                retry_executor,
                postflight_verifier=retry_verifier,
            )
            retry_executor.assert_not_called()
            retry_verifier.assert_called_once()
            self.assertEqual(
                receipt,
                fixture.paths.recovery_retired_receipt,
            )
            self.assertFalse(
                (fixture.paths.migration_root / "recovery.env").exists(),
            )

    def test_checkpoint_must_precede_deletion_and_invalid_runtime_proofs_never_publish(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._applied_fixture(directory)

            def deletes_first(
                plan: object,
                _lease: object,
                checkpoint: object,
            ) -> object:
                proof = self._valid_retirement_proof(plan)
                self._delete_recovery_artifacts(fixture)
                checkpoint(proof)
                return proof

            with self.assertRaises(stalwart_v016.MigrationError):
                self._retire(
                    fixture,
                    deletes_first,
                    postflight_verifier=mock.Mock(),
                )
            self.assertFalse(fixture.paths.retire_recovery_proof.exists())
            self.assertFalse(fixture.paths.recovery_retired_receipt.exists())

        invalid_cases = (
            {
                "ip_restriction_decision": (
                    "disabled-local-only-pending-live-network-proof"
                ),
            },
            {"old_recovery_auth_status": 200},
            {"overlapping_writer_ids": ()},
            {"migration_container_ids": ("c" * 64,)},
            {
                "recovery_environment_names": (
                    "STALWART_RECOVERY_ADMIN",
                ),
            },
            {"image_reference": "stalwartlabs/stalwart:latest"},
            {"image_id": "sha256:" + "c" * 64},
        )
        for changes in invalid_cases:
            with (
                self.subTest(changes=changes),
                tempfile.TemporaryDirectory() as directory,
            ):
                fixture = self._applied_fixture(directory)

                def invalid_executor(
                    plan: object,
                    _lease: object,
                    checkpoint: object,
                ) -> object:
                    proof = self._valid_retirement_proof(plan, **changes)
                    checkpoint(proof)
                    return proof

                with self.assertRaisesRegex(
                    stalwart_v016.MigrationError,
                    "executor|reconciliation",
                ):
                    self._retire(
                        fixture,
                        invalid_executor,
                        postflight_verifier=mock.Mock(),
                    )
                self.assertFalse(
                    fixture.paths.retire_recovery_proof.exists(),
                )
                self.assertFalse(
                    fixture.paths.recovery_retired_receipt.exists(),
                )

    def test_postflight_mismatch_preserves_checkpoint_for_safe_finalize_retry(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._applied_fixture(directory)
            proofs: list[object] = []

            def executor(
                plan: object,
                _lease: object,
                checkpoint: object,
            ) -> object:
                proof = self._valid_retirement_proof(plan)
                proofs.append(proof)
                checkpoint(proof)
                self._delete_recovery_artifacts(fixture)
                return proof

            def mismatched_verifier(plan: object) -> object:
                return self._valid_retirement_proof(
                    plan,
                    old_recovery_auth_status=403,
                )

            with self.assertRaisesRegex(
                stalwart_v016.MigrationError,
                "does not match",
            ):
                self._retire(
                    fixture,
                    executor,
                    postflight_verifier=mismatched_verifier,
                )

            self.assertTrue(fixture.paths.retire_recovery_proof.exists())
            self.assertFalse(fixture.paths.recovery_retired_receipt.exists())
            replay_executor = mock.Mock()
            self.assertEqual(
                self._retire(
                    fixture,
                    replay_executor,
                    postflight_verifier=lambda _plan: proofs[0],
                ),
                fixture.paths.recovery_retired_receipt,
            )
            replay_executor.assert_not_called()

    def test_final_timestamp_callback_precedes_last_artifact_absence_check(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._applied_fixture(directory)
            proofs: list[object] = []
            clock_calls = 0

            def executor(
                plan: object,
                _lease: object,
                checkpoint: object,
            ) -> object:
                proof = self._valid_retirement_proof(plan)
                proofs.append(proof)
                checkpoint(proof)
                self._delete_recovery_artifacts(fixture)
                return proof

            def mutating_clock() -> str:
                nonlocal clock_calls
                clock_calls += 1
                if clock_calls == 2:
                    self._materialize_runtime(fixture)
                return "2026-07-28T12:03:00Z"

            with self.assertRaises(stalwart_v016.MigrationError):
                self._retire(
                    fixture,
                    executor,
                    postflight_verifier=lambda _plan: proofs[0],
                    clock=mutating_clock,
                )

            self.assertEqual(clock_calls, 2)
            self.assertFalse(fixture.paths.recovery_retired_receipt.exists())
            self.assertTrue(
                (fixture.paths.migration_root / "recovery.env").exists(),
            )
            self.assertTrue(
                (fixture.paths.migration_root / "recovery-config").exists(),
            )

    def test_retirement_timestamp_callback_precedes_active_preflight(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._applied_fixture(directory)
            executor = mock.Mock()

            def mutating_clock() -> str:
                self._write_0600(
                    fixture.paths.migration_root / "recovery.env",
                    b"STALWART_RECOVERY_ADMIN=clock:mutation\n",
                )
                return "2026-07-28T12:03:00Z"

            with self.assertRaises(stalwart_v016.MigrationError):
                self._retire(
                    fixture,
                    executor,
                    postflight_verifier=mock.Mock(),
                    clock=mutating_clock,
                )

            executor.assert_not_called()
            self.assertFalse(
                fixture.paths.retire_recovery_attempt.exists(),
            )
            self.assertFalse(
                fixture.paths.retire_recovery_proof.exists(),
            )

    def test_retirement_lease_metadata_mismatch_wipes_before_attempt(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._applied_fixture(directory)
            original_reader = stalwart_v016._read_regular_mutable
            reads = 0
            captured: list[bytearray] = []

            def mutating_reader(
                path: Path,
                **kwargs: object,
            ) -> object:
                nonlocal reads
                if path == fixture.paths.migration_root / "recovery.env":
                    reads += 1
                    if reads == 2:
                        path.unlink()
                        self._write_0600(
                            path,
                            b"STALWART_RECOVERY_ADMIN=changed:credential\n",
                        )
                result = original_reader(path, **kwargs)
                if path == fixture.paths.migration_root / "recovery.env":
                    captured.append(result[0])
                return result

            executor = mock.Mock()
            with (
                mock.patch.object(
                    stalwart_v016,
                    "_read_regular_mutable",
                    side_effect=mutating_reader,
                ),
                self.assertRaises(stalwart_v016.MigrationError),
            ):
                self._retire(
                    fixture,
                    executor,
                    postflight_verifier=mock.Mock(),
                )

            self.assertEqual(reads, 2)
            self.assertEqual(len(captured), 2)
            self.assertTrue(
                all(
                    all(value == 0 for value in buffer)
                    for buffer in captured
                ),
            )
            executor.assert_not_called()
            self.assertFalse(
                fixture.paths.retire_recovery_attempt.exists(),
            )

    def test_retirement_attempt_publication_failure_wipes_loaded_lease(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._applied_fixture(directory)
            original_loader = stalwart_v016._load_recovery_credential_lease
            original_writer = stalwart_v016._write_new_json_0600
            leases: list[object] = []
            borrowed: list[memoryview] = []

            def capturing_loader(*args: object, **kwargs: object) -> object:
                lease = original_loader(*args, **kwargs)
                leases.append(lease)
                borrowed.append(lease.borrow())
                return lease

            def interrupting_writer(
                path: Path,
                *args: object,
                **kwargs: object,
            ) -> object:
                if path == fixture.paths.retire_recovery_attempt:
                    raise KeyboardInterrupt(
                        "unit-only attempt publication interruption",
                    )
                return original_writer(path, *args, **kwargs)

            with (
                mock.patch.object(
                    stalwart_v016,
                    "_load_recovery_credential_lease",
                    side_effect=capturing_loader,
                ),
                mock.patch.object(
                    stalwart_v016,
                    "_write_new_json_0600",
                    side_effect=interrupting_writer,
                ),
                self.assertRaises(KeyboardInterrupt),
            ):
                self._retire(
                    fixture,
                    mock.Mock(),
                    postflight_verifier=mock.Mock(),
                )

            self.assertEqual(len(leases), 1)
            self.assertTrue(leases[0].closed)
            self.assertEqual(
                bytes(borrowed[0]),
                b"\x00" * len(b"unit-user:unit-secret"),
            )
            self.assertFalse(
                fixture.paths.retire_recovery_attempt.exists(),
            )

    def test_orphan_proof_and_tampered_final_receipt_fail_closed(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._applied_fixture(directory)
            self._write_0600(
                fixture.paths.retire_recovery_proof,
                b'{"orphan":"preserve"}\n',
            )
            fixture.events.clear()
            executor = mock.Mock()
            verifier = mock.Mock()
            with self.assertRaisesRegex(
                stalwart_v016.MigrationError,
                "without its attempt",
            ):
                self._retire(
                    fixture,
                    executor,
                    postflight_verifier=verifier,
                )
            executor.assert_not_called()
            verifier.assert_not_called()
            self.assertEqual(fixture.events, [])

        with tempfile.TemporaryDirectory() as directory:
            fixture = self._applied_fixture(directory)
            proofs: list[object] = []

            def executor(
                plan: object,
                _lease: object,
                checkpoint: object,
            ) -> object:
                proof = self._valid_retirement_proof(plan)
                proofs.append(proof)
                checkpoint(proof)
                self._delete_recovery_artifacts(fixture)
                return proof

            self._retire(
                fixture,
                executor,
                postflight_verifier=lambda _plan: proofs[0],
            )
            payload = json.loads(
                fixture.paths.recovery_retired_receipt.read_text(
                    encoding="utf-8",
                ),
            )
            payload["proof"]["management_status"] = 201
            self._write_0600(
                fixture.paths.recovery_retired_receipt,
                (json.dumps(payload) + "\n").encode("utf-8"),
            )

            with self.assertRaises(stalwart_v016.MigrationError):
                self._validate_retired_receipt(fixture)

    def test_existing_receipt_fails_before_runner_or_executor_without_overwrite(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            original = b'{"preexisting":"preserve"}\n'
            self._write_0600(fixture.paths.apply_receipt, original)
            fixture.events.clear()
            executor = mock.Mock(return_value=self._valid_evidence())

            with self.assertRaisesRegex(stalwart_v016.MigrationError, "already exists"):
                self._prepare(fixture, executor)

            executor.assert_not_called()
            self.assertEqual(fixture.events, [])
            self.assertEqual(fixture.paths.apply_receipt.read_bytes(), original)

    def test_attempt_marker_blocks_every_replay_before_runner_or_executor(
        self,
    ) -> None:
        for initial_outcome in ("success", "invalid-evidence"):
            with (
                self.subTest(initial_outcome=initial_outcome),
                tempfile.TemporaryDirectory() as directory,
            ):
                fixture = self._fixture(directory)
                first_executor = mock.Mock(
                    return_value=(
                        self._valid_evidence()
                        if initial_outcome == "success"
                        else "not-json"
                    ),
                )
                if initial_outcome == "success":
                    self._prepare(fixture, first_executor)
                else:
                    with self.assertRaises(stalwart_v016.MigrationError):
                        self._prepare(fixture, first_executor)
                marker = fixture.paths.apply_attempt
                original_marker = marker.read_bytes()
                fixture.events.clear()
                second_executor = mock.Mock(return_value=self._valid_evidence())

                with self.assertRaisesRegex(
                    stalwart_v016.MigrationError,
                    "attempt|reconciliation",
                ):
                    self._prepare(fixture, second_executor)

                second_executor.assert_not_called()
                self.assertEqual(fixture.events, [])
                self.assertEqual(marker.read_bytes(), original_marker)

        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            original = b'{"preexisting":"preserve"}\n'
            self._write_0600(fixture.paths.apply_attempt, original)
            fixture.events.clear()
            executor = mock.Mock(return_value=self._valid_evidence())

            with self.assertRaisesRegex(
                stalwart_v016.MigrationError,
                "attempt|reconciliation",
            ):
                self._prepare(fixture, executor)

            executor.assert_not_called()
            self.assertEqual(fixture.events, [])
            self.assertEqual(fixture.paths.apply_attempt.read_bytes(), original)

    def test_marker_publication_failure_prevents_dispatch_and_final_publication_failure_keeps_marker(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            executor = mock.Mock(return_value=self._valid_evidence())
            with mock.patch.object(
                stalwart_v016.os,
                "link",
                side_effect=OSError("unit-only marker link failure"),
            ):
                with self.assertRaisesRegex(
                    stalwart_v016.MigrationError,
                    "written safely",
                ):
                    self._prepare(fixture, executor)
            executor.assert_not_called()
            self.assertFalse(fixture.paths.apply_attempt.exists())
            self.assertFalse(fixture.paths.apply_receipt.exists())
            self.assertEqual(
                list(
                    fixture.paths.migration_root.glob(
                        ".apply-attempt.json.*.tmp",
                    ),
                ),
                [],
            )

        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            executor = mock.Mock(return_value=self._valid_evidence())
            original_fsync = stalwart_v016.os.fsync
            fsync_calls = 0

            def failing_marker_parent_fsync(descriptor: int) -> None:
                nonlocal fsync_calls
                fsync_calls += 1
                if fsync_calls == 2:
                    raise OSError("unit-only marker parent fsync failure")
                original_fsync(descriptor)

            with mock.patch.object(
                stalwart_v016.os,
                "fsync",
                side_effect=failing_marker_parent_fsync,
            ):
                with self.assertRaisesRegex(
                    stalwart_v016.MigrationError,
                    "written safely",
                ):
                    self._prepare(fixture, executor)

            executor.assert_not_called()
            self.assertTrue(fixture.paths.apply_attempt.exists())
            self.assertFalse(fixture.paths.apply_receipt.exists())

    def test_baseexception_after_final_receipt_publication_removes_only_final_receipt(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            original_fsync = stalwart_v016.os.fsync
            fsync_calls = 0
            interruption = KeyboardInterrupt(
                "unit-final-publication-secret",
            )

            def interrupted_final_parent_fsync(descriptor: int) -> None:
                nonlocal fsync_calls
                fsync_calls += 1
                if fsync_calls == 4:
                    raise interruption
                original_fsync(descriptor)

            with mock.patch.object(
                stalwart_v016.os,
                "fsync",
                side_effect=interrupted_final_parent_fsync,
            ):
                with self.assertRaises(KeyboardInterrupt) as raised:
                    self._prepare(
                        fixture,
                        lambda _plan: self._valid_evidence(),
                    )

            self.assertIs(raised.exception, interruption)
            self.assertTrue(fixture.paths.apply_attempt.exists())
            self.assertFalse(fixture.paths.apply_receipt.exists())
            self.assertEqual(
                list(
                    fixture.paths.migration_root.glob(
                        ".apply.json.*.tmp",
                    ),
                ),
                [],
            )

        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            original_writer = stalwart_v016._write_new_json_0600

            def failing_final_writer(
                target: Path,
                value: object,
                *,
                root: Path,
                preserve_published_on_failure: bool = False,
            ) -> None:
                if target == fixture.paths.apply_receipt:
                    raise stalwart_v016.MigrationError(
                        "unit-only final publication failure",
                    )
                original_writer(
                    target,
                    value,
                    root=root,
                    preserve_published_on_failure=(
                        preserve_published_on_failure
                    ),
                )

            with mock.patch.object(
                stalwart_v016,
                "_write_new_json_0600",
                side_effect=failing_final_writer,
            ):
                with self.assertRaises(stalwart_v016.MigrationError):
                    self._prepare(
                        fixture,
                        lambda _plan: self._valid_evidence(),
                    )

            self.assertTrue(fixture.paths.apply_attempt.exists())
            self.assertFalse(fixture.paths.apply_receipt.exists())

    def test_rollback_activation_preserves_capture_cancellation_identity(
        self,
    ) -> None:
        class UnitCancellation(BaseException):
            pass

        for interruption in (
            KeyboardInterrupt("unit-keyboard-secret"),
            SystemExit(73),
            UnitCancellation("unit-custom-secret"),
        ):
            with (
                self.subTest(
                    adapter="default",
                    cancellation=type(interruption).__name__,
                ),
                tempfile.TemporaryDirectory() as directory,
            ):
                receipt = Path(directory).resolve() / "source.json"

                class Application:
                    @staticmethod
                    def activate_verified_rollback(
                        _receipt_path: Path,
                        *,
                        expected_receipt_sha256: str,
                    ) -> object:
                        self.assertEqual(
                            expected_receipt_sha256,
                            "a" * 64,
                        )
                        raise interruption

                raised: BaseException | None = None
                with mock.patch.object(
                    stalwart_v016,
                    "_load_capture_application",
                    return_value=Application(),
                ):
                    try:
                        stalwart_v016.default_rollback_activator(
                            receipt,
                            expected_receipt_sha256="a" * 64,
                        )
                    except BaseException as error:
                        raised = error

                self.assertIs(raised, interruption)

            with (
                self.subTest(
                    adapter="failed-mutation",
                    cancellation=type(interruption).__name__,
                ),
                tempfile.TemporaryDirectory() as directory,
            ):
                fixture = self._fixture(directory)
                plan = self._pre_dispatch_plan(fixture)
                self._publish_apply_attempt(fixture, plan)
                binding = stalwart_v016._rollback_recovery_binding(
                    fixture.paths,
                    plan,
                )
                self.assertIsNotNone(binding)

                def runtime_runner(
                    args: list[str],
                    **_kwargs: object,
                ) -> object:
                    if args == (
                        stalwart_v016
                        .build_migration_recovery_ps_command(plan)
                    ):
                        return stalwart_v016.RedactedCommandResult(
                            b"",
                            b"",
                        )
                    self.fail(f"unexpected recovery command: {args!r}")

                def activate(
                    _receipt_path: Path,
                    *,
                    expected_receipt_sha256: str,
                ) -> object:
                    self.assertEqual(
                        expected_receipt_sha256,
                        plan.inputs[0].sha256,
                    )
                    raise interruption

                raised = None
                with stalwart_v016.acquire_stalwart_operation_lock(
                    fixture.repository,
                ) as operation_lock:
                    try:
                        stalwart_v016._activate_rollback_after_failed_mutation(
                            fixture.paths,
                            binding,
                            operation_lock=operation_lock,
                            state_runner=fixture.runner,
                            runtime_runner=runtime_runner,
                            rollback_activator=activate,
                        )
                    except BaseException as error:
                        raised = error

                self.assertIs(raised, interruption)

        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.object(
                stalwart_v016,
                "_load_capture_application",
                return_value=SimpleNamespace(
                    activate_verified_rollback=mock.Mock(
                        side_effect=RuntimeError(
                            "unit-ordinary-secret",
                        ),
                    ),
                ),
            ),
            self.assertRaisesRegex(
                stalwart_v016.MigrationError,
                "failed safely",
            ) as raised,
        ):
            stalwart_v016.default_rollback_activator(
                Path(directory).resolve() / "source.json",
                expected_receipt_sha256="a" * 64,
            )
        self.assertNotIn("unit-ordinary-secret", str(raised.exception))

    def test_production_apply_recovers_durable_predispatch_attempt(
        self,
    ) -> None:
        for runtime_state in ("absent", "ready"):
            with (
                self.subTest(runtime_state=runtime_state),
                tempfile.TemporaryDirectory() as directory,
            ):
                fixture = self._fixture(directory)
                plan = self._pre_dispatch_plan(fixture)
                self._publish_apply_attempt(fixture, plan)
                if runtime_state == "ready":
                    self._materialize_runtime(fixture)
                stops = 0
                activations = 0
                prepare = mock.Mock(
                    side_effect=AssertionError(
                        "durable recovery must precede ordinary prepare",
                    ),
                )

                def runtime_runner(
                    args: list[str],
                    **_kwargs: object,
                ) -> object:
                    nonlocal stops
                    if args == (
                        stalwart_v016
                        .build_migration_recovery_ps_command(plan)
                    ):
                        return stalwart_v016.RedactedCommandResult(
                            b"",
                            b"",
                        )
                    self.fail(f"unexpected recovery command: {args!r}")

                def activate(
                    _receipt_path: Path,
                    *,
                    expected_receipt_sha256: str,
                ) -> object:
                    nonlocal activations
                    activations += 1
                    return self._valid_rollback_activation(
                        fixture,
                        expected_receipt_sha256=expected_receipt_sha256,
                    )

                dependencies = replace(
                    stalwart_v016.production_apply_dependencies(),
                    prepare=prepare,
                    state_runner=fixture.runner,
                    runtime_runner=runtime_runner,
                    recovery_credential_source=mock.Mock(),
                    rollback_activator=activate,
                )
                with (
                    mock.patch.object(
                        stalwart_v016.sys,
                        "executable",
                        "/unit/python3",
                    ),
                    self.assertRaisesRegex(
                        stalwart_v016.MigrationError,
                        "reconciliation|failed safely",
                    ),
                ):
                    stalwart_v016.run_production_apply(
                        fixture.paths,
                        script_path=fixture.paths.migration_script,
                        review_receipt_path=fixture.paths.reviewed,
                        dependencies=dependencies,
                        expected_script_sha256=fixture.script_digest,
                    )

                prepare.assert_not_called()
                self.assertEqual(stops, 0)
                self.assertEqual(activations, 1)
                self.assertFalse(fixture.paths.apply_receipt.exists())

    def test_production_apply_recovers_published_marker_before_dispatch(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            plan = self._pre_dispatch_plan(fixture)
            original_writer = stalwart_v016._write_new_json_0600
            interruption = KeyboardInterrupt(
                "unit-marker-publication-cancellation",
            )
            activations = 0
            stops = 0

            def interrupted_writer(
                target: Path,
                value: object,
                *,
                root: Path,
                preserve_published_on_failure: bool = False,
            ) -> None:
                original_writer(
                    target,
                    value,
                    root=root,
                    preserve_published_on_failure=(
                        preserve_published_on_failure
                    ),
                )
                if target == fixture.paths.apply_attempt:
                    raise interruption

            def runtime_runner(
                args: list[str],
                **_kwargs: object,
            ) -> object:
                nonlocal stops
                if args == (
                    stalwart_v016
                    .build_migration_recovery_ps_command(
                        plan,
                    )
                ):
                    return stalwart_v016.RedactedCommandResult(b"", b"")
                stops += 1
                return stalwart_v016.RedactedCommandResult(b"", b"")

            def activate(
                _receipt_path: Path,
                *,
                expected_receipt_sha256: str,
            ) -> object:
                nonlocal activations
                activations += 1
                return self._valid_rollback_activation(
                    fixture,
                    expected_receipt_sha256=expected_receipt_sha256,
                )

            dependencies = replace(
                stalwart_v016.production_apply_dependencies(),
                state_runner=fixture.runner,
                runtime_runner=runtime_runner,
                rollback_activator=activate,
            )
            raised: BaseException | None = None
            with (
                mock.patch.object(
                    stalwart_v016.sys,
                    "executable",
                    "/unit/python3",
                ),
                mock.patch.object(
                    stalwart_v016,
                    "_write_new_json_0600",
                    side_effect=interrupted_writer,
                ),
            ):
                try:
                    stalwart_v016.run_production_apply(
                        fixture.paths,
                        script_path=fixture.paths.migration_script,
                        review_receipt_path=fixture.paths.reviewed,
                        dependencies=dependencies,
                        expected_script_sha256=fixture.script_digest,
                    )
                except BaseException as error:
                    raised = error

            self.assertIs(raised, interruption)
            self.assertTrue(fixture.paths.apply_attempt.exists())
            self.assertFalse(fixture.paths.apply_receipt.exists())
            self.assertEqual(stops, 0)
            self.assertEqual(activations, 1)

    def test_bound_bootstrap_primary_cancellation_wins_over_activation_failure(
        self,
    ) -> None:
        class UnitCancellation(BaseException):
            pass

        for failure_stage in ("ready-validation", "operation"):
            with (
                self.subTest(failure_stage=failure_stage),
                tempfile.TemporaryDirectory() as directory,
            ):
                fixture = self._fixture(directory)
                self._prepare(
                    fixture,
                    lambda _plan: self._valid_evidence(),
                )
                interruption = UnitCancellation(
                    f"unit-{failure_stage}-primary",
                )
                original_validator = (
                    stalwart_v016
                    ._validated_apply_receipt_for_retirement
                )
                validation_calls = 0

                def validator(
                    *args: object,
                    **kwargs: object,
                ) -> object:
                    nonlocal validation_calls
                    validation_calls += 1
                    if (
                        failure_stage == "ready-validation"
                        and validation_calls == 2
                    ):
                        raise interruption
                    return original_validator(*args, **kwargs)

                runtime_operation = (
                    mock.Mock(side_effect=interruption)
                    if failure_stage == "operation"
                    else mock.Mock()
                )
                raised: BaseException | None = None
                with (
                    stalwart_v016.acquire_stalwart_operation_lock(
                        fixture.repository,
                    ) as operation_lock,
                    mock.patch.object(
                        stalwart_v016,
                        "_validated_apply_receipt_for_retirement",
                        side_effect=validator,
                    ),
                    mock.patch.object(
                        stalwart_v016,
                        "_run_migration_bootstrap_operation",
                        runtime_operation,
                    ),
                    mock.patch.object(
                        stalwart_v016,
                        "_activate_rollback_after_failed_mutation",
                        side_effect=RuntimeError(
                            "unit-secondary-activation-failure",
                        ),
                    ),
                ):
                    try:
                        stalwart_v016.run_validated_migration_runtime(
                            fixture.paths,
                            apply_receipt_path=fixture.paths.apply_receipt,
                            source_receipt_path=fixture.paths.source_receipt,
                            script_path=fixture.paths.migration_script,
                            dry_run_receipt_path=fixture.paths.dry_run_receipt,
                            review_receipt_path=fixture.paths.reviewed,
                            state_runner=fixture.runner,
                            runtime_runner=mock.Mock(),
                            python_executable="/unit/python3",
                            operation=mock.Mock(),
                            operation_lock=operation_lock,
                            expected_script_sha256=fixture.script_digest,
                        )
                    except BaseException as error:
                        raised = error

                self.assertIs(raised, interruption)

    def test_bootstrap_entry_recovers_exact_detached_runtime(
        self,
    ) -> None:
        for bootstrap_state in (
            "absent",
            "attempt",
            "checkpoint",
            "starting-before-attempt",
        ):
            with (
                self.subTest(bootstrap_state=bootstrap_state),
                tempfile.TemporaryDirectory() as directory,
            ):
                fixture = self._fixture(directory)
                self._prepare(
                    fixture,
                    lambda _plan: self._valid_evidence(),
                )
                validated = (
                    stalwart_v016
                    ._validated_apply_receipt_for_retirement(
                        fixture.paths,
                        source_receipt_path=(
                            fixture.paths.source_receipt
                        ),
                        script_path=fixture.paths.migration_script,
                        dry_run_receipt_path=(
                            fixture.paths.dry_run_receipt
                        ),
                        review_receipt_path=fixture.paths.reviewed,
                        apply_receipt_path=fixture.paths.apply_receipt,
                        runner=fixture.runner,
                        python_executable="/unit/python3",
                        expected_script_sha256=fixture.script_digest,
                        runtime_phase="ready",
                        writer_census=False,
                    )
                )
                plan = validated[0].plan
                bootstrap_root = fixture.paths.bootstrap_receipt.parent
                bootstrap_root.mkdir(
                    mode=0o700,
                    parents=True,
                    exist_ok=True,
                )
                bootstrap_root.chmod(0o700)
                if bootstrap_state in {"attempt", "checkpoint"}:
                    self._write_0600(
                        bootstrap_root / "bootstrap-attempt.json",
                        b'{"unit":"attempt"}\n',
                    )
                if bootstrap_state == "checkpoint":
                    self._write_0600(
                        bootstrap_root / "bootstrap-proof.json",
                        b'{"unit":"proof"}\n',
                    )

                container_id = "a" * 64
                running = True
                stops = 0
                activations = 0
                operation = mock.Mock()

                def state_runner(args: list[str]) -> object:
                    if args[:2] == ["docker", "ps"]:
                        return stalwart_v016.CommandResult(
                            container_id + "\n" if running else "",
                            "",
                        )
                    if args[:2] == ["docker", "inspect"]:
                        return stalwart_v016.CommandResult(
                            json.dumps(
                                [
                                    {
                                        "Id": container_id,
                                        "State": {"Running": True},
                                        "Mounts": [
                                            {
                                                "Type": "bind",
                                                "Source": str(
                                                    fixture.source_store
                                                ),
                                                "RW": True,
                                            },
                                        ],
                                    },
                                ],
                            ),
                            "",
                        )
                    return fixture.runner(args)

                def runtime_runner(
                    args: list[str],
                    **_kwargs: object,
                ) -> object:
                    nonlocal running, stops
                    if args == (
                        stalwart_v016
                        .build_migration_recovery_ps_command(plan)
                    ):
                        return stalwart_v016.RedactedCommandResult(
                            (container_id + "\n").encode("ascii"),
                            b"",
                        )
                    if args == (
                        stalwart_v016
                        .build_migration_recovery_container_inspect_command(
                            container_id,
                        )
                    ):
                        inspection = (
                            self._valid_recovery_runtime_inspection(
                                fixture,
                                plan,
                                container_id,
                            )
                        )
                        if bootstrap_state == "starting-before-attempt":
                            inspection["Health"] = "starting"
                        return stalwart_v016.RedactedCommandResult(
                            json.dumps(inspection).encode("utf-8"),
                            b"",
                        )
                    if args == (
                        stalwart_v016
                        .build_bound_container_stop_command(container_id)
                    ):
                        stops += 1
                        running = False
                        return stalwart_v016.RedactedCommandResult(
                            b"",
                            b"",
                        )
                    self.fail(
                        f"unexpected recovery runtime command: {args!r}",
                    )

                def activate(
                    _receipt_path: Path,
                    *,
                    expected_receipt_sha256: str,
                ) -> object:
                    nonlocal activations
                    activations += 1
                    return self._valid_rollback_activation(
                        fixture,
                        expected_receipt_sha256=expected_receipt_sha256,
                    )

                with (
                    stalwart_v016.acquire_stalwart_operation_lock(
                        fixture.repository,
                    ) as operation_lock,
                    mock.patch.dict(
                        os.environ,
                        self._docker_client_environment(),
                        clear=True,
                    ),
                    self.assertRaisesRegex(
                        stalwart_v016.MigrationError,
                        "reconciliation|failed safely",
                    ),
                ):
                    stalwart_v016.run_validated_migration_runtime(
                        fixture.paths,
                        apply_receipt_path=fixture.paths.apply_receipt,
                        source_receipt_path=fixture.paths.source_receipt,
                        script_path=fixture.paths.migration_script,
                        dry_run_receipt_path=(
                            fixture.paths.dry_run_receipt
                        ),
                        review_receipt_path=fixture.paths.reviewed,
                        state_runner=state_runner,
                        runtime_runner=runtime_runner,
                        python_executable="/unit/python3",
                        operation=operation,
                        operation_lock=operation_lock,
                        rollback_activator=activate,
                        expected_script_sha256=fixture.script_digest,
                    )

                operation.assert_not_called()
                self.assertEqual(stops, 1)
                self.assertEqual(activations, 1)

    def test_bootstrap_entry_never_stops_a_foreign_writer(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            self._prepare(
                fixture,
                lambda _plan: self._valid_evidence(),
            )
            plan = (
                stalwart_v016
                ._validated_apply_receipt_for_retirement(
                    fixture.paths,
                    source_receipt_path=fixture.paths.source_receipt,
                    script_path=fixture.paths.migration_script,
                    dry_run_receipt_path=fixture.paths.dry_run_receipt,
                    review_receipt_path=fixture.paths.reviewed,
                    apply_receipt_path=fixture.paths.apply_receipt,
                    runner=fixture.runner,
                    python_executable="/unit/python3",
                    expected_script_sha256=fixture.script_digest,
                    runtime_phase="ready",
                    writer_census=False,
                )[0]
                .plan
            )
            container_id = "e" * 64
            runtime_calls: list[list[str]] = []
            activator = mock.Mock()

            def state_runner(args: list[str]) -> object:
                if args[:2] == ["docker", "ps"]:
                    return stalwart_v016.CommandResult(
                        container_id + "\n",
                        "",
                    )
                if args[:2] == ["docker", "inspect"]:
                    return stalwart_v016.CommandResult(
                        json.dumps(
                            [
                                {
                                    "Id": container_id,
                                    "State": {"Running": True},
                                    "Mounts": [
                                        {
                                            "Type": "bind",
                                            "Source": str(
                                                fixture.source_store
                                            ),
                                            "RW": True,
                                        },
                                    ],
                                },
                            ],
                        ),
                        "",
                    )
                return fixture.runner(args)

            def runtime_runner(
                args: list[str],
                **_kwargs: object,
            ) -> object:
                runtime_calls.append(args)
                if args == (
                    stalwart_v016
                    .build_migration_recovery_ps_command(plan)
                ):
                    return stalwart_v016.RedactedCommandResult(
                        (container_id + "\n").encode("ascii"),
                        b"",
                    )
                inspection = self._valid_recovery_runtime_inspection(
                    fixture,
                    plan,
                    container_id,
                )
                inspection["ImageID"] = "sha256:" + "f" * 64
                return stalwart_v016.RedactedCommandResult(
                    json.dumps(inspection).encode("utf-8"),
                    b"",
                )

            with (
                stalwart_v016.acquire_stalwart_operation_lock(
                    fixture.repository,
                ) as operation_lock,
                mock.patch.dict(
                    os.environ,
                    self._docker_client_environment(),
                    clear=True,
                ),
                self.assertRaises(stalwart_v016.MigrationError),
            ):
                stalwart_v016.run_validated_migration_runtime(
                    fixture.paths,
                    apply_receipt_path=fixture.paths.apply_receipt,
                    source_receipt_path=fixture.paths.source_receipt,
                    script_path=fixture.paths.migration_script,
                    dry_run_receipt_path=fixture.paths.dry_run_receipt,
                    review_receipt_path=fixture.paths.reviewed,
                    state_runner=state_runner,
                    runtime_runner=runtime_runner,
                    python_executable="/unit/python3",
                    operation=mock.Mock(),
                    operation_lock=operation_lock,
                    rollback_activator=activator,
                    expected_script_sha256=fixture.script_digest,
                )

            self.assertIn(
                stalwart_v016.build_migration_recovery_ps_command(plan),
                runtime_calls,
            )
            self.assertNotIn(
                stalwart_v016.build_bound_container_stop_command(
                    container_id,
                ),
                runtime_calls,
            )
            activator.assert_not_called()

    def test_production_retirement_rebinds_published_marker_before_executor(
        self,
    ) -> None:
        class UnitCancellation(BaseException):
            pass

        for case, interruption, activation_fails in (
            (
                "cancellation",
                UnitCancellation(
                    "unit-retirement-marker-cancellation",
                ),
                False,
            ),
            (
                "cancellation-and-activation-failure",
                UnitCancellation(
                    "unit-retirement-marker-cancellation-secondary",
                ),
                True,
            ),
            (
                "ordinary-failure",
                RuntimeError("unit-retirement-marker-failure"),
                False,
            ),
        ):
            with (
                self.subTest(case=case),
                tempfile.TemporaryDirectory() as directory,
            ):
                fixture = self._applied_fixture(directory)
                original_writer = stalwart_v016._write_new_json_0600
                activations = 0
                executor = mock.Mock()

                class BootstrapModule:
                    class BootstrapPaths:
                        @staticmethod
                        def for_repository(repository: Path) -> Path:
                            return repository

                    @staticmethod
                    def validate_final_bootstrap_for_retirement(
                        _paths: object,
                        *,
                        task6_validator: object,
                    ) -> object:
                        task6_validator(fixture.paths.apply_receipt)
                        return fixture.bootstrap_token

                    @staticmethod
                    def finalize_migrated_current_runtime(
                        repository: Path,
                    ) -> Path:
                        current = (
                            repository
                            / "debug-dashboard"
                            / ".runtime"
                            / "stalwart"
                            / "current.json"
                        )
                        current.parent.mkdir(parents=True, exist_ok=True)
                        current.write_text("{}\n", encoding="utf-8")
                        current.chmod(0o600)
                        return current

                def interrupted_writer(
                    target: Path,
                    value: object,
                    *,
                    root: Path,
                    preserve_published_on_failure: bool = False,
                ) -> None:
                    original_writer(
                        target,
                        value,
                        root=root,
                        preserve_published_on_failure=(
                            preserve_published_on_failure
                        ),
                    )
                    if target == fixture.paths.retire_recovery_attempt:
                        raise interruption

                def runtime_runner(
                    args: list[str],
                    **_kwargs: object,
                ) -> object:
                    if (
                        args[:4]
                        == ["docker", "ps", "--all", "--no-trunc"]
                    ):
                        return stalwart_v016.RedactedCommandResult(
                            b"",
                            b"",
                        )
                    self.fail(
                        f"unexpected retirement recovery command: {args!r}",
                    )

                def activate(
                    _receipt_path: Path,
                    *,
                    expected_receipt_sha256: str,
                ) -> object:
                    nonlocal activations
                    activations += 1
                    if activation_fails:
                        raise RuntimeError(
                            "unit-secondary-activation-failure",
                        )
                    return self._valid_rollback_activation(
                        fixture,
                        expected_receipt_sha256=expected_receipt_sha256,
                    )

                dependencies = replace(
                    (
                        stalwart_v016
                        .production_recovery_retirement_dependencies()
                    ),
                    bootstrap_module_loader=(
                        lambda _root: BootstrapModule
                    ),
                    retirement_executor_factory=(
                        lambda **_kwargs: executor
                    ),
                    postflight_verifier_factory=(
                        lambda **_kwargs: mock.Mock()
                    ),
                    state_runner=fixture.runner,
                    runtime_runner=runtime_runner,
                    jmap_probe_runner=mock.Mock(),
                    rollback_activator=activate,
                )
                raised: BaseException | None = None
                with (
                    mock.patch.object(
                        stalwart_v016.sys,
                        "executable",
                        "/unit/python3",
                    ),
                    mock.patch.object(
                        stalwart_v016,
                        "_write_new_json_0600",
                        side_effect=interrupted_writer,
                    ),
                ):
                    try:
                        (
                            stalwart_v016
                            .run_production_recovery_retirement(
                                fixture.paths,
                                dependencies=dependencies,
                                expected_script_sha256=(
                                    fixture.script_digest
                                ),
                            )
                        )
                    except BaseException as error:
                        raised = error

                if isinstance(interruption, Exception):
                    self.assertIsInstance(
                        raised,
                        stalwart_v016.MigrationError,
                    )
                    self.assertNotIn(
                        "unit-retirement-marker-failure",
                        str(raised),
                    )
                else:
                    self.assertIs(raised, interruption)
                self.assertTrue(
                    fixture.paths.retire_recovery_attempt.exists(),
                )
                executor.assert_not_called()
                self.assertEqual(activations, 1)

    def test_existing_retirement_loader_preserves_custom_cancellation(
        self,
    ) -> None:
        class UnitCancellation(BaseException):
            pass

        with tempfile.TemporaryDirectory() as directory:
            fixture = self._applied_fixture(directory)

            def interrupt_after_attempt(
                _plan: object,
                _lease: object,
                _checkpoint: object,
            ) -> object:
                raise RuntimeError("unit-create-retirement-attempt")

            with self.assertRaises(stalwart_v016.MigrationError):
                self._retire(
                    fixture,
                    interrupt_after_attempt,
                    postflight_verifier=mock.Mock(),
                )
            interruption = UnitCancellation(
                "unit-existing-loader-cancellation",
            )
            factories = mock.Mock()
            activator = mock.Mock()

            class BootstrapModule:
                class BootstrapPaths:
                    @staticmethod
                    def for_repository(repository: Path) -> Path:
                        return repository

                @staticmethod
                def validate_final_bootstrap_for_retirement(
                    _paths: object,
                    *,
                    task6_validator: object,
                ) -> object:
                    task6_validator(fixture.paths.apply_receipt)
                    return fixture.bootstrap_token

                finalize_migrated_current_runtime = staticmethod(
                    ApplyPreparationTest._unexpected_current_finalizer
                )

            dependencies = replace(
                (
                    stalwart_v016
                    .production_recovery_retirement_dependencies()
                ),
                bootstrap_module_loader=lambda _root: BootstrapModule,
                retirement_executor_factory=factories,
                postflight_verifier_factory=factories,
                existing_retirement_plan_loader=mock.Mock(
                    side_effect=interruption,
                ),
                rollback_activator=activator,
            )
            raised: BaseException | None = None
            try:
                stalwart_v016.run_production_recovery_retirement(
                    fixture.paths,
                    dependencies=dependencies,
                    expected_script_sha256=fixture.script_digest,
                )
            except BaseException as error:
                raised = error

            self.assertIs(raised, interruption)
            factories.assert_not_called()
            activator.assert_not_called()

    def test_bootstrap_cancellation_wins_over_recovery_failure(
        self,
    ) -> None:
        class UnitCancellation(BaseException):
            pass

        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            self._prepare(
                fixture,
                lambda _plan: self._valid_evidence(),
            )
            interruption = UnitCancellation(
                "unit-primary-bootstrap-cancellation",
            )
            census_calls = 0

            def state_runner(args: list[str]) -> object:
                nonlocal census_calls
                if args[:2] == ["docker", "ps"]:
                    census_calls += 1
                    if census_calls == 1:
                        raise interruption
                return fixture.runner(args)

            def failed_recovery_runner(
                _args: list[str],
                **_kwargs: object,
            ) -> object:
                raise RuntimeError("unit-recovery-scan-failure")

            raised: BaseException | None = None
            with stalwart_v016.acquire_stalwart_operation_lock(
                fixture.repository,
            ) as operation_lock:
                try:
                    stalwart_v016.run_validated_migration_runtime(
                        fixture.paths,
                        apply_receipt_path=fixture.paths.apply_receipt,
                        source_receipt_path=fixture.paths.source_receipt,
                        script_path=fixture.paths.migration_script,
                        dry_run_receipt_path=fixture.paths.dry_run_receipt,
                        review_receipt_path=fixture.paths.reviewed,
                        state_runner=state_runner,
                        runtime_runner=failed_recovery_runner,
                        python_executable="/unit/python3",
                        operation=mock.Mock(),
                        operation_lock=operation_lock,
                        rollback_activator=mock.Mock(),
                        expected_script_sha256=fixture.script_digest,
                    )
                except BaseException as error:
                    raised = error

            self.assertIs(raised, interruption)

    def test_checkpoint_resume_deletes_every_durable_partial_state(
        self,
    ) -> None:
        for crash_state in (
            "all-present",
            "environment-absent",
            "empty-config-directory",
        ):
            with (
                self.subTest(crash_state=crash_state),
                tempfile.TemporaryDirectory() as directory,
            ):
                fixture = self._applied_fixture(directory)
                proofs: list[object] = []

                def checkpoint_then_interrupt(
                    plan: object,
                    _lease: object,
                    checkpoint: object,
                ) -> object:
                    proof = self._valid_retirement_proof(plan)
                    proofs.append(proof)
                    checkpoint(proof)
                    raise KeyboardInterrupt(
                        "unit-retirement-deletion-crash",
                    )

                with self.assertRaises(KeyboardInterrupt):
                    self._retire(
                        fixture,
                        checkpoint_then_interrupt,
                        postflight_verifier=mock.Mock(),
                    )

                config_dir = (
                    fixture.paths.migration_root / "recovery-config"
                )
                config_path = config_dir / "config.json"
                environment_path = (
                    fixture.paths.migration_root / "recovery.env"
                )
                if crash_state in {
                    "environment-absent",
                    "empty-config-directory",
                }:
                    environment_path.unlink()
                if crash_state == "empty-config-directory":
                    config_path.unlink()

                resumed_executor = mock.Mock()
                receipt = self._retire(
                    fixture,
                    resumed_executor,
                    postflight_verifier=lambda _plan: proofs[0],
                )

                self.assertEqual(
                    receipt,
                    fixture.paths.recovery_retired_receipt,
                )
                resumed_executor.assert_not_called()
                self.assertFalse(environment_path.exists())
                self.assertFalse(config_path.exists())
                self.assertFalse(config_dir.exists())

    def test_production_apply_recovery_rejects_runtime_substitutions_after_binding(
        self,
    ) -> None:
        for runtime_state in ("partial", "tampered-ready"):
            with (
                self.subTest(runtime_state=runtime_state),
                tempfile.TemporaryDirectory() as directory,
            ):
                fixture = self._fixture(directory)
                plan = self._pre_dispatch_plan(fixture)
                self._publish_apply_attempt(fixture, plan)
                self._materialize_runtime(fixture)
                if runtime_state == "partial":
                    (
                        fixture.paths.migration_root / "recovery.env"
                    ).unlink()
                else:
                    self._write_0644(
                        fixture.paths.migration_root
                        / "recovery-config"
                        / "config.json",
                        b'{"tampered":"runtime config"}\n',
                    )
                stops = 0
                activations = 0

                def runtime_runner(
                    args: list[str],
                    **_kwargs: object,
                ) -> object:
                    nonlocal stops
                    if args == (
                        stalwart_v016
                        .build_migration_recovery_ps_command(plan)
                    ):
                        return stalwart_v016.RedactedCommandResult(
                            b"",
                            b"",
                        )
                    self.fail(f"unexpected recovery command: {args!r}")

                def activate(
                    _receipt_path: Path,
                    *,
                    expected_receipt_sha256: str,
                ) -> object:
                    nonlocal activations
                    activations += 1
                    return self._valid_rollback_activation(
                        fixture,
                        expected_receipt_sha256=expected_receipt_sha256,
                    )

                dependencies = replace(
                    stalwart_v016.production_apply_dependencies(),
                    prepare=mock.Mock(),
                    state_runner=fixture.runner,
                    runtime_runner=runtime_runner,
                    recovery_credential_source=mock.Mock(),
                    rollback_activator=activate,
                )
                with (
                    mock.patch.object(
                        stalwart_v016.sys,
                        "executable",
                        "/unit/python3",
                    ),
                    self.assertRaises(stalwart_v016.MigrationError),
                ):
                    stalwart_v016.run_production_apply(
                        fixture.paths,
                        script_path=fixture.paths.migration_script,
                        review_receipt_path=fixture.paths.reviewed,
                        dependencies=dependencies,
                        expected_script_sha256=fixture.script_digest,
                    )

                self.assertEqual(stops, 0)
                self.assertEqual(activations, 1)
                dependencies.prepare.assert_not_called()

    def test_production_apply_recovery_never_stops_a_foreign_runtime(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            plan = self._pre_dispatch_plan(fixture)
            self._publish_apply_attempt(fixture, plan)
            self._materialize_runtime(fixture)
            container_id = "e" * 64
            runtime_calls: list[list[str]] = []
            activator = mock.Mock()

            def runtime_runner(
                args: list[str],
                **_kwargs: object,
            ) -> object:
                runtime_calls.append(args)
                if args == (
                    stalwart_v016
                    .build_migration_recovery_ps_command(plan)
                ):
                    return stalwart_v016.RedactedCommandResult(
                        (container_id + "\n").encode("ascii"),
                        b"",
                    )
                inspection = self._valid_recovery_runtime_inspection(
                    fixture,
                    plan,
                    container_id,
                )
                inspection["Mounts"][1]["Source"] = str(
                    fixture.repository / "foreign-stalwart-data",
                )
                return stalwart_v016.RedactedCommandResult(
                    json.dumps(inspection).encode("utf-8"),
                    b"",
                )

            dependencies = replace(
                stalwart_v016.production_apply_dependencies(),
                prepare=mock.Mock(),
                state_runner=fixture.runner,
                runtime_runner=runtime_runner,
                recovery_credential_source=mock.Mock(),
                rollback_activator=activator,
            )
            with (
                mock.patch.object(
                    stalwart_v016.sys,
                    "executable",
                    "/unit/python3",
                ),
                mock.patch.dict(
                    os.environ,
                    self._docker_client_environment(),
                    clear=True,
                ),
                self.assertRaises(stalwart_v016.MigrationError),
            ):
                stalwart_v016.run_production_apply(
                    fixture.paths,
                    script_path=fixture.paths.migration_script,
                    review_receipt_path=fixture.paths.reviewed,
                    dependencies=dependencies,
                    expected_script_sha256=fixture.script_digest,
                )

            self.assertIn(
                stalwart_v016.build_migration_recovery_ps_command(plan),
                runtime_calls,
            )
            self.assertNotIn(
                stalwart_v016.build_bound_container_stop_command(
                    container_id,
                ),
                runtime_calls,
            )
            activator.assert_not_called()

    def test_production_retirement_resumes_every_checkpointed_deletion_state(
        self,
    ) -> None:
        for crash_state in (
            "all-present",
            "environment-absent",
            "empty-config-directory",
            "all-absent",
        ):
            with (
                self.subTest(crash_state=crash_state),
                tempfile.TemporaryDirectory() as directory,
            ):
                fixture = self._applied_fixture(directory)
                plans: list[object] = []
                proofs: list[object] = []

                def checkpoint_then_interrupt(
                    plan: object,
                    _lease: object,
                    checkpoint: object,
                ) -> object:
                    plans.append(plan)
                    proof = self._valid_retirement_proof(plan)
                    proofs.append(proof)
                    checkpoint(proof)
                    raise KeyboardInterrupt(
                        "unit-production-retirement-crash",
                    )

                with self.assertRaises(KeyboardInterrupt):
                    self._retire(
                        fixture,
                        checkpoint_then_interrupt,
                        postflight_verifier=mock.Mock(),
                    )

                config_dir = (
                    fixture.paths.migration_root / "recovery-config"
                )
                config_path = config_dir / "config.json"
                environment_path = (
                    fixture.paths.migration_root / "recovery.env"
                )
                if crash_state in {
                    "environment-absent",
                    "empty-config-directory",
                    "all-absent",
                }:
                    environment_path.unlink()
                if crash_state in {
                    "empty-config-directory",
                    "all-absent",
                }:
                    config_path.unlink()
                if crash_state == "all-absent":
                    config_dir.rmdir()

                class BootstrapModule:
                    class BootstrapPaths:
                        @staticmethod
                        def for_repository(repository: Path) -> Path:
                            return repository

                    @staticmethod
                    def validate_final_bootstrap_for_retirement(
                        _paths: object,
                        *,
                        task6_validator: object,
                    ) -> object:
                        task6_validator(fixture.paths.apply_receipt)
                        return fixture.bootstrap_token

                    @staticmethod
                    def finalize_migrated_current_runtime(
                        repository: Path,
                    ) -> Path:
                        current = (
                            repository
                            / "debug-dashboard"
                            / ".runtime"
                            / "stalwart"
                            / "current.json"
                        )
                        current.parent.mkdir(parents=True, exist_ok=True)
                        current.write_text("{}\n", encoding="utf-8")
                        current.chmod(0o600)
                        return current

                executor = mock.Mock()
                verifier = mock.Mock(return_value=proofs[0])
                activator = mock.Mock()
                dependencies = replace(
                    (
                        stalwart_v016
                        .production_recovery_retirement_dependencies()
                    ),
                    bootstrap_module_loader=(
                        lambda _root: BootstrapModule
                    ),
                    retirement_executor_factory=(
                        lambda **_kwargs: executor
                    ),
                    postflight_verifier_factory=(
                        lambda **_kwargs: verifier
                    ),
                    state_runner=fixture.runner,
                    runtime_runner=mock.Mock(),
                    jmap_probe_runner=mock.Mock(),
                    rollback_activator=activator,
                )
                with mock.patch.object(
                    stalwart_v016.sys,
                    "executable",
                    "/unit/python3",
                ):
                    receipt = (
                        stalwart_v016
                        .run_production_recovery_retirement(
                            fixture.paths,
                            dependencies=dependencies,
                            expected_script_sha256=(
                                fixture.script_digest
                            ),
                        )
                    )

                self.assertEqual(
                    receipt,
                    fixture.paths.recovery_retired_receipt,
                )
                executor.assert_not_called()
                verifier.assert_called_once()
                activator.assert_not_called()
                self.assertFalse(environment_path.exists())
                self.assertFalse(config_dir.exists())

    def test_production_retirement_activates_after_partial_substitution_failure(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._applied_fixture(directory)
            plans: list[object] = []

            def checkpoint_then_interrupt(
                plan: object,
                _lease: object,
                checkpoint: object,
            ) -> object:
                plans.append(plan)
                proof = self._valid_retirement_proof(plan)
                checkpoint(proof)
                raise KeyboardInterrupt(
                    "unit-production-retirement-crash",
                )

            with self.assertRaises(KeyboardInterrupt):
                self._retire(
                    fixture,
                    checkpoint_then_interrupt,
                    postflight_verifier=mock.Mock(),
                )
            plan = plans[0]
            environment_path = (
                fixture.paths.migration_root / "recovery.env"
            )
            config_path = (
                fixture.paths.migration_root
                / "recovery-config"
                / "config.json"
            )
            original_config = config_path.read_bytes()
            environment_path.unlink()
            config_path.unlink()
            self._write_0644(config_path, original_config)
            stops = 0
            activations = 0

            class BootstrapModule:
                class BootstrapPaths:
                    @staticmethod
                    def for_repository(repository: Path) -> Path:
                        return repository

                @staticmethod
                def validate_final_bootstrap_for_retirement(
                    _paths: object,
                    *,
                    task6_validator: object,
                ) -> object:
                    task6_validator(fixture.paths.apply_receipt)
                    return fixture.bootstrap_token

                finalize_migrated_current_runtime = staticmethod(
                    ApplyPreparationTest._unexpected_current_finalizer
                )

            def runtime_runner(
                args: list[str],
                **_kwargs: object,
            ) -> object:
                nonlocal stops
                container_id = "f" * 64
                if args == (
                    stalwart_v016.build_normal_recovery_ps_command(
                        plan,
                    )
                ):
                    return stalwart_v016.RedactedCommandResult(
                        (container_id + "\n").encode("ascii"),
                        b"",
                    )
                if args == (
                    stalwart_v016
                    .build_normal_recovery_container_inspect_command(
                        container_id,
                    )
                ):
                    return stalwart_v016.RedactedCommandResult(
                        json.dumps(
                            self._valid_normal_recovery_inspection(
                                fixture,
                                container_id,
                            ),
                        ).encode("utf-8"),
                        b"",
                    )
                self.assertEqual(
                    args,
                    stalwart_v016.build_bound_container_stop_command(
                        container_id,
                    ),
                )
                stops += 1
                return stalwart_v016.RedactedCommandResult(b"", b"")

            def activate(
                _receipt_path: Path,
                *,
                expected_receipt_sha256: str,
            ) -> object:
                nonlocal activations
                activations += 1
                return self._valid_rollback_activation(
                    fixture,
                    expected_receipt_sha256=expected_receipt_sha256,
                )

            dependencies = replace(
                (
                    stalwart_v016
                    .production_recovery_retirement_dependencies()
                ),
                bootstrap_module_loader=lambda _root: BootstrapModule,
                retirement_executor_factory=(
                    lambda **_kwargs: mock.Mock()
                ),
                postflight_verifier_factory=(
                    lambda **_kwargs: mock.Mock()
                ),
                state_runner=fixture.runner,
                runtime_runner=runtime_runner,
                jmap_probe_runner=mock.Mock(),
                rollback_activator=activate,
            )
            with (
                mock.patch.object(
                    stalwart_v016.sys,
                    "executable",
                    "/unit/python3",
                ),
                self.assertRaises(stalwart_v016.MigrationError),
            ):
                stalwart_v016.run_production_recovery_retirement(
                    fixture.paths,
                    dependencies=dependencies,
                    expected_script_sha256=fixture.script_digest,
                )

            self.assertEqual(stops, 1)
            self.assertEqual(activations, 1)

    def test_bootstrap_recovery_stops_exact_writer_before_artifact_validation(
        self,
    ) -> None:
        for artifact_state in ("missing-environment", "tampered-config"):
            with (
                self.subTest(artifact_state=artifact_state),
                tempfile.TemporaryDirectory() as directory,
            ):
                fixture = self._fixture(directory)
                self._prepare(
                    fixture,
                    lambda _plan: self._valid_evidence(),
                )
                plan = (
                    stalwart_v016
                    ._validated_apply_receipt_for_retirement(
                        fixture.paths,
                        source_receipt_path=fixture.paths.source_receipt,
                        script_path=fixture.paths.migration_script,
                        dry_run_receipt_path=fixture.paths.dry_run_receipt,
                        review_receipt_path=fixture.paths.reviewed,
                        apply_receipt_path=fixture.paths.apply_receipt,
                        runner=fixture.runner,
                        python_executable="/unit/python3",
                        expected_script_sha256=fixture.script_digest,
                        runtime_phase="ready",
                        writer_census=False,
                    )[0]
                    .plan
                )
                if artifact_state == "missing-environment":
                    plan.runtime.recovery_env_file.unlink()
                else:
                    self._write_0644(
                        plan.runtime.config_dir / "config.json",
                        b'{"unit":"tampered"}\n',
                    )
                container_id = "a" * 64
                running = True
                stops = 0
                activations = 0
                operation = mock.Mock()

                def state_runner(args: list[str]) -> object:
                    if args[:2] == ["docker", "ps"]:
                        return stalwart_v016.CommandResult(
                            container_id + "\n" if running else "",
                            "",
                        )
                    if args[:2] == ["docker", "inspect"]:
                        return stalwart_v016.CommandResult(
                            json.dumps(
                                [
                                    {
                                        "Id": container_id,
                                        "State": {"Running": True},
                                        "Mounts": [
                                            {
                                                "Type": "bind",
                                                "Source": str(
                                                    fixture.source_store
                                                ),
                                                "RW": True,
                                            },
                                        ],
                                    },
                                ],
                            ),
                            "",
                        )
                    return fixture.runner(args)

                def runtime_runner(
                    args: list[str],
                    **_kwargs: object,
                ) -> object:
                    nonlocal running, stops
                    self.assertNotIn("compose", args)
                    if args == (
                        stalwart_v016
                        .build_migration_recovery_ps_command(plan)
                    ):
                        return stalwart_v016.RedactedCommandResult(
                            (container_id + "\n").encode("ascii"),
                            b"",
                        )
                    if args == (
                        stalwart_v016
                        .build_migration_recovery_container_inspect_command(
                            container_id,
                        )
                    ):
                        return stalwart_v016.RedactedCommandResult(
                            json.dumps(
                                self._valid_recovery_runtime_inspection(
                                    fixture,
                                    plan,
                                    container_id,
                                ),
                            ).encode("utf-8"),
                            b"",
                        )
                    self.assertEqual(
                        args,
                        stalwart_v016.build_bound_container_stop_command(
                            container_id,
                        ),
                    )
                    stops += 1
                    running = False
                    return stalwart_v016.RedactedCommandResult(b"", b"")

                def activate(
                    _receipt_path: Path,
                    *,
                    expected_receipt_sha256: str,
                ) -> object:
                    nonlocal activations
                    activations += 1
                    return self._valid_rollback_activation(
                        fixture,
                        expected_receipt_sha256=expected_receipt_sha256,
                    )

                credential_loader = mock.Mock(
                    side_effect=AssertionError(
                        "credential must not be read before recovery",
                    ),
                )
                with (
                    stalwart_v016.acquire_stalwart_operation_lock(
                        fixture.repository,
                    ) as operation_lock,
                    mock.patch.dict(
                        os.environ,
                        self._docker_client_environment(),
                        clear=True,
                    ),
                    mock.patch.object(
                        stalwart_v016,
                        "_load_recovery_credential_lease",
                        credential_loader,
                    ),
                    self.assertRaisesRegex(
                        stalwart_v016.MigrationError,
                        "reconciliation|failed safely",
                    ),
                ):
                    stalwart_v016.run_validated_migration_runtime(
                        fixture.paths,
                        apply_receipt_path=fixture.paths.apply_receipt,
                        source_receipt_path=fixture.paths.source_receipt,
                        script_path=fixture.paths.migration_script,
                        dry_run_receipt_path=fixture.paths.dry_run_receipt,
                        review_receipt_path=fixture.paths.reviewed,
                        state_runner=state_runner,
                        runtime_runner=runtime_runner,
                        python_executable="/unit/python3",
                        operation=operation,
                        operation_lock=operation_lock,
                        rollback_activator=activate,
                        expected_script_sha256=fixture.script_digest,
                    )

                operation.assert_not_called()
                credential_loader.assert_not_called()
                self.assertEqual(stops, 1)
                self.assertEqual(activations, 1)

    def test_bootstrap_recovery_handles_only_exact_migration_owner(
        self,
    ) -> None:
        for owner_state in ("exact", "substituted"):
            with (
                self.subTest(owner_state=owner_state),
                tempfile.TemporaryDirectory() as directory,
            ):
                fixture = self._fixture(directory)
                self._prepare(
                    fixture,
                    lambda _plan: self._valid_evidence(),
                )
                plan = (
                    stalwart_v016
                    ._validated_apply_receipt_for_retirement(
                        fixture.paths,
                        source_receipt_path=fixture.paths.source_receipt,
                        script_path=fixture.paths.migration_script,
                        dry_run_receipt_path=fixture.paths.dry_run_receipt,
                        review_receipt_path=fixture.paths.reviewed,
                        apply_receipt_path=fixture.paths.apply_receipt,
                        runner=fixture.runner,
                        python_executable="/unit/python3",
                        expected_script_sha256=fixture.script_digest,
                        runtime_phase="ready",
                        writer_census=False,
                    )[0]
                    .plan
                )
                owner_id = "b" * 64
                running = True
                stops = 0
                activations = 0

                def state_runner(args: list[str]) -> object:
                    if args[:2] == ["docker", "ps"]:
                        return stalwart_v016.CommandResult(
                            owner_id + "\n" if running else "",
                            "",
                        )
                    if args[:2] == ["docker", "inspect"]:
                        return stalwart_v016.CommandResult(
                            json.dumps(
                                [
                                    {
                                        "Id": owner_id,
                                        "State": {"Running": True},
                                        "Mounts": [
                                            {
                                                "Type": "bind",
                                                "Source": str(
                                                    fixture.source_store
                                                ),
                                                "RW": True,
                                            },
                                        ],
                                    },
                                ],
                            ),
                            "",
                        )
                    return fixture.runner(args)

                def runtime_runner(
                    args: list[str],
                    **_kwargs: object,
                ) -> object:
                    nonlocal running, stops
                    if args == (
                        stalwart_v016
                        .build_migration_recovery_ps_command(plan)
                    ):
                        return stalwart_v016.RedactedCommandResult(
                            (owner_id + "\n").encode("ascii"),
                            b"",
                        )
                    if args == (
                        stalwart_v016
                        .build_migration_recovery_container_inspect_command(
                            owner_id,
                        )
                    ):
                        inspection = (
                            self._valid_owner_recovery_inspection(
                                fixture,
                                plan,
                                owner_id,
                            )
                        )
                        if owner_state == "substituted":
                            inspection["User"] = "2000:2000"
                        return stalwart_v016.RedactedCommandResult(
                            json.dumps(inspection).encode("utf-8"),
                            b"",
                        )
                    self.assertEqual(
                        args,
                        stalwart_v016.build_bound_container_stop_command(
                            owner_id,
                        ),
                    )
                    stops += 1
                    running = False
                    return stalwart_v016.RedactedCommandResult(b"", b"")

                def activate(
                    _receipt_path: Path,
                    *,
                    expected_receipt_sha256: str,
                ) -> object:
                    nonlocal activations
                    activations += 1
                    return self._valid_rollback_activation(
                        fixture,
                        expected_receipt_sha256=expected_receipt_sha256,
                    )

                with (
                    stalwart_v016.acquire_stalwart_operation_lock(
                        fixture.repository,
                    ) as operation_lock,
                    mock.patch.dict(
                        os.environ,
                        self._docker_client_environment(),
                        clear=True,
                    ),
                    self.assertRaises(stalwart_v016.MigrationError),
                ):
                    stalwart_v016.run_validated_migration_runtime(
                        fixture.paths,
                        apply_receipt_path=fixture.paths.apply_receipt,
                        source_receipt_path=fixture.paths.source_receipt,
                        script_path=fixture.paths.migration_script,
                        dry_run_receipt_path=fixture.paths.dry_run_receipt,
                        review_receipt_path=fixture.paths.reviewed,
                        state_runner=state_runner,
                        runtime_runner=runtime_runner,
                        python_executable="/unit/python3",
                        operation=mock.Mock(),
                        operation_lock=operation_lock,
                        rollback_activator=activate,
                        expected_script_sha256=fixture.script_digest,
                    )

                self.assertEqual(stops, 1 if owner_state == "exact" else 0)
                self.assertEqual(
                    activations,
                    1 if owner_state == "exact" else 0,
                )

    def test_migration_recovery_rejects_stopped_latent_candidates(
        self,
    ) -> None:
        scenarios = tuple(
            (service, restart, False)
            for service in ("main", "owner")
            for restart in ("always", "on-failure")
        ) + (
            ("main", "no", True),
            ("owner", "no", True),
        )
        for service, restart, restarting in scenarios:
            with (
                self.subTest(
                    service=service,
                    restart=restart,
                    restarting=restarting,
                ),
                tempfile.TemporaryDirectory() as directory,
            ):
                fixture = self._fixture(directory)
                plan = self._pre_dispatch_plan(fixture)
                self._publish_apply_attempt(fixture, plan)
                binding = stalwart_v016._rollback_recovery_binding(
                    fixture.paths,
                    plan,
                )
                self.assertIsNotNone(binding)
                candidate_id = "b" * 64
                runtime_calls: list[list[str]] = []
                activator = mock.Mock()

                def runtime_runner(
                    args: list[str],
                    **_kwargs: object,
                ) -> object:
                    runtime_calls.append(args)
                    if args == (
                        stalwart_v016
                        .build_migration_recovery_ps_command(plan)
                    ):
                        return stalwart_v016.RedactedCommandResult(
                            (candidate_id + "\n").encode("ascii"),
                            b"",
                        )
                    self.assertEqual(
                        args,
                        stalwart_v016
                        .build_migration_recovery_container_inspect_command(
                            candidate_id,
                        ),
                    )
                    if service == "main":
                        inspection = (
                            self._valid_recovery_runtime_inspection(
                                fixture,
                                plan,
                                candidate_id,
                                running=False,
                                restarting=restarting,
                                health="",
                            )
                        )
                    else:
                        inspection = (
                            self._valid_owner_recovery_inspection(
                                fixture,
                                plan,
                                candidate_id,
                                running=False,
                                restarting=restarting,
                            )
                        )
                    inspection["Restart"] = restart
                    return stalwart_v016.RedactedCommandResult(
                        json.dumps(inspection).encode("utf-8"),
                        b"",
                    )

                with (
                    stalwart_v016.acquire_stalwart_operation_lock(
                        fixture.repository,
                    ) as operation_lock,
                    self.assertRaises(stalwart_v016.MigrationError),
                ):
                    stalwart_v016._activate_rollback_after_failed_mutation(
                        fixture.paths,
                        binding,
                        operation_lock=operation_lock,
                        state_runner=fixture.runner,
                        runtime_runner=runtime_runner,
                        rollback_activator=activator,
                    )

                self.assertNotIn(
                    stalwart_v016.build_bound_container_stop_command(
                        candidate_id,
                    ),
                    runtime_calls,
                )
                activator.assert_not_called()

    def test_recovery_scan_tolerates_stopped_legacy_and_exact_runtime(
        self,
    ) -> None:
        for exact_running in (False, True):
            with (
                self.subTest(exact_running=exact_running),
                tempfile.TemporaryDirectory() as directory,
            ):
                fixture = self._fixture(directory)
                plan = self._pre_dispatch_plan(fixture)
                self._publish_apply_attempt(fixture, plan)
                binding = stalwart_v016._rollback_recovery_binding(
                    fixture.paths,
                    plan,
                )
                self.assertIsNotNone(binding)
                legacy_id = "c" * 64
                exact_id = "d" * 64
                stops: list[str] = []
                activations = 0

                def runtime_runner(
                    args: list[str],
                    **_kwargs: object,
                ) -> object:
                    if args == (
                        stalwart_v016
                        .build_migration_recovery_ps_command(plan)
                    ):
                        return stalwart_v016.RedactedCommandResult(
                            (
                                f"{legacy_id}\n{exact_id}\n"
                            ).encode("ascii"),
                            b"",
                        )
                    if args == (
                        stalwart_v016
                        .build_migration_recovery_container_inspect_command(
                            legacy_id,
                        )
                    ):
                        legacy = (
                            self._valid_recovery_runtime_inspection(
                                fixture,
                                plan,
                                legacy_id,
                                running=False,
                                health="",
                            )
                        )
                        legacy["Image"] = (
                            "stalwartlabs/mail-server:v0.15.5"
                        )
                        legacy["ImageID"] = "sha256:" + "e" * 64
                        legacy["Restart"] = "unless-stopped"
                        return stalwart_v016.RedactedCommandResult(
                            json.dumps(legacy).encode("utf-8"),
                            b"",
                        )
                    if args == (
                        stalwart_v016
                        .build_migration_recovery_container_inspect_command(
                            exact_id,
                        )
                    ):
                        exact = (
                            self._valid_recovery_runtime_inspection(
                                fixture,
                                plan,
                                exact_id,
                                running=exact_running,
                                health=(
                                    "starting"
                                    if exact_running
                                    else ""
                                ),
                            )
                        )
                        return stalwart_v016.RedactedCommandResult(
                            json.dumps(exact).encode("utf-8"),
                            b"",
                        )
                    self.assertEqual(
                        args,
                        stalwart_v016.build_bound_container_stop_command(
                            exact_id,
                        ),
                    )
                    stops.append(exact_id)
                    return stalwart_v016.RedactedCommandResult(b"", b"")

                def activate(
                    _receipt_path: Path,
                    *,
                    expected_receipt_sha256: str,
                ) -> object:
                    nonlocal activations
                    activations += 1
                    return self._valid_rollback_activation(
                        fixture,
                        expected_receipt_sha256=expected_receipt_sha256,
                    )

                with stalwart_v016.acquire_stalwart_operation_lock(
                    fixture.repository,
                ) as operation_lock:
                    stalwart_v016._activate_rollback_after_failed_mutation(
                        fixture.paths,
                        binding,
                        operation_lock=operation_lock,
                        state_runner=fixture.runner,
                        runtime_runner=runtime_runner,
                        rollback_activator=activate,
                    )

                self.assertEqual(
                    stops,
                    [exact_id] if exact_running else [],
                )
                self.assertNotIn(legacy_id, stops)
                self.assertEqual(activations, 1)

    def test_bootstrap_recovery_preserves_initial_census_cancellation(
        self,
    ) -> None:
        class UnitCancellation(BaseException):
            pass

        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            self._prepare(
                fixture,
                lambda _plan: self._valid_evidence(),
            )
            plan = (
                stalwart_v016
                ._validated_apply_receipt_for_retirement(
                    fixture.paths,
                    source_receipt_path=fixture.paths.source_receipt,
                    script_path=fixture.paths.migration_script,
                    dry_run_receipt_path=fixture.paths.dry_run_receipt,
                    review_receipt_path=fixture.paths.reviewed,
                    apply_receipt_path=fixture.paths.apply_receipt,
                    runner=fixture.runner,
                    python_executable="/unit/python3",
                    expected_script_sha256=fixture.script_digest,
                    runtime_phase="ready",
                    writer_census=False,
                )[0]
                .plan
            )
            interruption = UnitCancellation("unit-census-secret")
            census_calls = 0
            activations = 0

            def state_runner(args: list[str]) -> object:
                nonlocal census_calls
                if args[:2] == ["docker", "ps"]:
                    census_calls += 1
                    if census_calls == 1:
                        raise interruption
                return fixture.runner(args)

            def runtime_runner(
                args: list[str],
                **_kwargs: object,
            ) -> object:
                self.assertEqual(
                    args,
                    stalwart_v016.build_migration_recovery_ps_command(
                        plan,
                    ),
                )
                return stalwart_v016.RedactedCommandResult(b"", b"")

            def activate(
                _receipt_path: Path,
                *,
                expected_receipt_sha256: str,
            ) -> object:
                nonlocal activations
                activations += 1
                return self._valid_rollback_activation(
                    fixture,
                    expected_receipt_sha256=expected_receipt_sha256,
                )

            raised: BaseException | None = None
            with stalwart_v016.acquire_stalwart_operation_lock(
                fixture.repository,
            ) as operation_lock:
                try:
                    stalwart_v016.run_validated_migration_runtime(
                        fixture.paths,
                        apply_receipt_path=fixture.paths.apply_receipt,
                        source_receipt_path=fixture.paths.source_receipt,
                        script_path=fixture.paths.migration_script,
                        dry_run_receipt_path=fixture.paths.dry_run_receipt,
                        review_receipt_path=fixture.paths.reviewed,
                        state_runner=state_runner,
                        runtime_runner=runtime_runner,
                        python_executable="/unit/python3",
                        operation=mock.Mock(),
                        operation_lock=operation_lock,
                        rollback_activator=activate,
                        expected_script_sha256=fixture.script_digest,
                    )
                except BaseException as error:
                    raised = error

            self.assertIs(raised, interruption)
            self.assertEqual(census_calls, 2)
            self.assertEqual(activations, 1)

    def test_normal_recovery_rejects_untrusted_runtime_candidates(
        self,
    ) -> None:
        scenarios = (
            ("running-foreign-mount", True, False, "unless-stopped"),
            ("running-restart-always", True, False, "always"),
            ("stopped-restart-always", False, False, "always"),
            ("stopped-restart-on-failure", False, False, "on-failure"),
            ("restarting-exact", False, True, "unless-stopped"),
        )
        for scenario, running, restarting, restart in scenarios:
            with (
                self.subTest(scenario=scenario),
                tempfile.TemporaryDirectory() as directory,
            ):
                fixture = self._applied_fixture(directory)
                plans: list[object] = []

                def capture_plan(
                    plan: object,
                    _lease: object,
                    _checkpoint: object,
                ) -> object:
                    plans.append(plan)
                    raise RuntimeError("unit-capture-retirement-plan")

                with self.assertRaises(stalwart_v016.MigrationError):
                    self._retire(
                        fixture,
                        capture_plan,
                        postflight_verifier=mock.Mock(),
                    )
                plan = plans[0]
                binding = (
                    stalwart_v016._rollback_retirement_recovery_binding(
                        fixture.paths,
                        plan,
                    )
                )
                self.assertIsNotNone(binding)
                candidate_id = "f" * 64
                runtime_calls: list[list[str]] = []
                activator = mock.Mock()

                def runtime_runner(
                    args: list[str],
                    **_kwargs: object,
                ) -> object:
                    runtime_calls.append(args)
                    if args == (
                        stalwart_v016.build_normal_recovery_ps_command(
                            plan,
                        )
                    ):
                        return stalwart_v016.RedactedCommandResult(
                            (candidate_id + "\n").encode("ascii"),
                            b"",
                        )
                    self.assertEqual(
                        args,
                        stalwart_v016
                        .build_normal_recovery_container_inspect_command(
                            candidate_id,
                        ),
                    )
                    inspection = (
                        self._valid_normal_recovery_inspection(
                            fixture,
                            candidate_id,
                            running=running,
                            restarting=restarting,
                            health="healthy" if running else "",
                            restart=restart,
                        )
                    )
                    if scenario == "running-foreign-mount":
                        inspection["Mounts"][1]["Source"] = str(
                            fixture.repository / "foreign-store",
                        )
                    return stalwart_v016.RedactedCommandResult(
                        json.dumps(inspection).encode("utf-8"),
                        b"",
                    )

                with (
                    stalwart_v016.acquire_stalwart_operation_lock(
                        fixture.repository,
                    ) as operation_lock,
                    self.assertRaises(stalwart_v016.MigrationError),
                ):
                    stalwart_v016._activate_rollback_after_failed_mutation(
                        fixture.paths,
                        binding,
                        operation_lock=operation_lock,
                        state_runner=fixture.runner,
                        runtime_runner=runtime_runner,
                        rollback_activator=activator,
                    )

                self.assertNotIn(
                    stalwart_v016.build_bound_container_stop_command(
                        candidate_id,
                    ),
                    runtime_calls,
                )
                activator.assert_not_called()
