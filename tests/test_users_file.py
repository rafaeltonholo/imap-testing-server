from __future__ import annotations

import fcntl
import hashlib
import importlib
import inspect
import io
import multiprocessing
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPOSITORY_ROOT / "scripts"
SCRIPT_PATH = SCRIPTS_DIR / "users_file.py"
DEFAULTS_PATH = REPOSITORY_ROOT / "config" / "users.defaults"
RESET_SCRIPT = REPOSITORY_ROOT / "scripts" / "reset.py"
DASHBOARD_RESET = REPOSITORY_ROOT / "debug-dashboard" / "reset-local-accounts.sh"
ACTIVE_AUTHORITY_DOCS = [
    REPOSITORY_ROOT / ".ai" / "guidelines.md",
    REPOSITORY_ROOT / "CLAUDE.md",
    REPOSITORY_ROOT / ".ai" / "architecture.md",
    REPOSITORY_ROOT / ".ai" / "skills" / "python-scripts" / "references" / "script-inventory.md",
    REPOSITORY_ROOT / ".ai" / "skills" / "stalwart" / "references" / "admin-api.md",
    REPOSITORY_ROOT / ".ai" / "skills" / "stalwart" / "SKILL.md",
    REPOSITORY_ROOT / "README.md",
]

sys.path.insert(0, str(SCRIPTS_DIR))

users_file = None
IMPORT_ERROR: Exception | None = None
if SCRIPT_PATH.exists():
    try:
        users_file = importlib.import_module("users_file")
    except Exception as exc:  # pragma: no cover - reported by existence test
        IMPORT_ERROR = exc


DEFAULT_ADDRESSES = [
    "dev@local.test",
    "dev1@local.test",
    "dev2@local.test",
    "dev3@local.test",
    "dev4@local.test",
    "dev5@local.test",
    "a_very_long-email_for_testing@local.test",
    "inline_img@local.test",
    "inline_msg@local.test",
]
DEFAULT_TEXT = "".join(f"{address}:{{PLAIN}}secret::::::\n" for address in DEFAULT_ADDRESSES)
JOURNAL_PREFIX = "users-mutation-journal-v1"


def _journal(before: bytes | None, after: bytes) -> str:
    before_field = "absent" if before is None else f"sha256:{hashlib.sha256(before).hexdigest()}"
    after_field = f"sha256:{hashlib.sha256(after).hexdigest()}"
    return f"{JOURNAL_PREFIX} before={before_field} after={after_field}\n"


def _write_journal(users_path: Path, state: str) -> Path:
    lock_path = users_path.with_name("users.lock")
    lock_path.write_text(state, encoding="ascii")
    lock_path.chmod(0o600)
    return lock_path


def _hold_record_lock(lock_path: str, ready: multiprocessing.synchronize.Event,
                      release: multiprocessing.synchronize.Event) -> None:
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.lockf(descriptor, fcntl.LOCK_EX)
        ready.set()
        release.wait(10)
    finally:
        os.close(descriptor)


class UsersFileExistenceTests(unittest.TestCase):
    def test_users_file_module_exists_and_imports(self) -> None:
        self.assertIsNotNone(
            users_file,
            f"{SCRIPT_PATH.relative_to(REPOSITORY_ROOT)} must import cleanly: {IMPORT_ERROR}",
        )

    def test_defaults_file_has_exact_canonical_records(self) -> None:
        self.assertTrue(DEFAULTS_PATH.is_file(), "config/users.defaults must exist")
        self.assertEqual(DEFAULT_TEXT, DEFAULTS_PATH.read_text(encoding="utf-8"))

    def test_package_qualified_import_succeeds_without_scripts_path_injection(self) -> None:
        result = subprocess.run(
            [sys.executable, "-c", "import scripts.users_file"],
            cwd=REPOSITORY_ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(0, result.returncode, result.stderr)

    def test_module_and_direct_script_help_modes_both_succeed(self) -> None:
        commands = (
            [sys.executable, "-m", "scripts.users_file", "--help"],
            [sys.executable, str(SCRIPT_PATH), "--help"],
        )
        for command in commands:
            with self.subTest(command=command):
                result = subprocess.run(
                    command,
                    cwd=REPOSITORY_ROOT,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertIn("bootstrap-defaults", result.stdout)


@unittest.skipIf(users_file is None, "users_file.py has not been implemented yet")
class ParserTests(unittest.TestCase):
    def test_parser_round_trips_canonical_eight_field_records(self) -> None:
        records = users_file.parse_records(DEFAULT_TEXT)
        self.assertEqual(DEFAULT_ADDRESSES, [record.address for record in records])
        self.assertEqual(DEFAULT_TEXT, users_file.serialize_records(records))
        self.assertTrue(all(record.password_field == "{PLAIN}secret" for record in records))

    def test_parser_rejects_malformed_or_noncanonical_addresses(self) -> None:
        for address in (
            "missing-at",
            "two@@local.test",
            "Dev@local.test",
            "dev@LOCAL.test",
            " dev@local.test",
            "dev@local.test ",
            "dev@localhost",
        ):
            with self.subTest(address=address):
                with self.assertRaises(users_file.UsersFileError):
                    users_file.parse_records(f"{address}:{{PLAIN}}secret::::::\n")

    def test_parser_rejects_duplicates_non_eight_fields_and_password_schemes(self) -> None:
        invalid_documents = (
            "dev@local.test:{PLAIN}secret::::::\ndev@local.test:{PLAIN}other::::::\n",
            "dev@local.test:{PLAIN}secret\n",
            "dev@local.test:{PLAIN}secret:::::\n",
            "dev@local.test:{ARGON2ID}hash::::::\n",
            "dev@local.test:secret::::::\n",
        )
        for document in invalid_documents:
            with self.subTest(document=document):
                with self.assertRaises(users_file.UsersFileError):
                    users_file.parse_records(document)

    def test_serializer_rejects_nul_newline_or_delimiter_in_plain_password(self) -> None:
        for password in ("{PLAIN}nul\0value", "{PLAIN}line\nvalue", "{PLAIN}colon:value"):
            with self.subTest(password=password):
                record = users_file.UserRecord("dev@local.test", password)
                with self.assertRaises(users_file.UsersFileError):
                    users_file.serialize_records([record])


@unittest.skipIf(users_file is None, "users_file.py has not been implemented yet")
class MutationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.users = self.root / "users"
        self.defaults = self.root / "users.defaults"
        self.defaults.write_text(DEFAULT_TEXT, encoding="utf-8")
        self.defaults.chmod(0o600)

    def runner(self, command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if command == ["doveadm", "user", "*"]:
            stdout = "\n".join(DEFAULT_ADDRESSES) + "\n"
            return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    def write_users(self, text: str = DEFAULT_TEXT) -> None:
        self.users.write_text(text, encoding="utf-8")
        self.users.chmod(0o600)

    def test_bootstrap_creates_only_when_missing_and_preserves_existing_bytes(self) -> None:
        calls: list[list[str]] = []

        def runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            calls.append(command)
            stdout = "\n".join(DEFAULT_ADDRESSES) + "\n" if command[-1:] == ["*"] else ""
            return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

        users_file.bootstrap_defaults(self.users, self.defaults, runner=runner)
        self.assertEqual(DEFAULT_TEXT.encode(), self.users.read_bytes())
        self.assertEqual(0o600, stat.S_IMODE(self.users.stat().st_mode))
        self.assertEqual(
            [
                ["doveadm", "reload"],
                *[["doveadm", "user", address] for address in DEFAULT_ADDRESSES],
                ["doveadm", "user", "*"],
            ],
            calls,
        )

        for existing in (b"", b"dev@local.test:{PLAIN}modified::::::\n"):
            self.users.write_bytes(existing)
            self.users.chmod(0o600)
            with mock.patch.object(users_file, "reload_and_verify") as verify:
                changed = users_file.bootstrap_defaults(
                    self.users,
                    self.defaults,
                    runner=self.runner,
                )
            self.assertFalse(changed)
            self.assertEqual(existing, self.users.read_bytes())
            verify.assert_not_called()

    def test_existing_bootstrap_never_reads_missing_or_invalid_defaults(self) -> None:
        invalid_defaults = self.root / "invalid.defaults"
        invalid_defaults.write_text("not a passwd file\n", encoding="utf-8")
        missing_defaults = self.root / "missing.defaults"

        for existing in (b"", b"dev@local.test:{PLAIN}modified::::::\n"):
            for defaults_path in (missing_defaults, invalid_defaults):
                with self.subTest(existing=existing, defaults_path=defaults_path.name):
                    self.users.write_bytes(existing)
                    self.users.chmod(0o600)

                    try:
                        changed = users_file.bootstrap_defaults(
                            self.users,
                            defaults_path,
                            runner=self.runner,
                        )
                    except users_file.UsersFileError as exc:
                        self.fail(f"existing destination read defaults unexpectedly: {exc}")

                    self.assertFalse(changed)
                    self.assertEqual(existing, self.users.read_bytes())

    def test_existing_bootstrap_checks_destination_safety_before_defaults(self) -> None:
        missing_defaults = self.root / "missing.defaults"
        outside = self.root / "outside"
        outside.write_bytes(b"preserve")
        self.users.symlink_to(outside)
        with self.assertRaisesRegex(users_file.UsersFileError, "symlink"):
            users_file.bootstrap_defaults(self.users, missing_defaults, runner=self.runner)
        self.assertEqual(b"preserve", outside.read_bytes())

        self.users.unlink()
        self.users.write_bytes(b"")
        self.users.chmod(0o644)
        with self.assertRaisesRegex(users_file.UsersFileError, "0600"):
            users_file.bootstrap_defaults(self.users, missing_defaults, runner=self.runner)

    def test_upsert_preserves_unrelated_records_and_writes_eight_fields(self) -> None:
        self.write_users(
            "unrelated@local.test:{PLAIN}keep-me::::::\n"
            "dev@local.test:{PLAIN}old::::::\n"
        )

        changed = users_file.upsert_user(
            "dev@local.test",
            "new-secret",
            self.users,
            runner=self.runner,
        )

        self.assertTrue(changed)
        self.assertEqual(
            "unrelated@local.test:{PLAIN}keep-me::::::\n"
            "dev@local.test:{PLAIN}new-secret::::::\n",
            self.users.read_text(encoding="utf-8"),
        )
        self.assertTrue(all(len(line.split(":")) == 8 for line in self.users.read_text().splitlines()))

    def test_delete_removes_only_auth_record_and_verifies_absence(self) -> None:
        self.write_users(
            "dev@local.test:{PLAIN}secret::::::\n"
            "other@local.test:{PLAIN}secret::::::\n"
        )
        mailbox = self.root / "vmail" / "dev@local.test" / "Maildir"
        mailbox.mkdir(parents=True)
        sentinel = mailbox / "message"
        sentinel.write_bytes(b"preserve")
        calls: list[list[str]] = []

        def runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            calls.append(command)
            if command == ["doveadm", "user", "*"]:
                return subprocess.CompletedProcess(
                    command,
                    0,
                    stdout="other@local.test\n",
                    stderr="",
                )
            returncode = 1 if command == ["doveadm", "user", "dev@local.test"] else 0
            return subprocess.CompletedProcess(command, returncode, stdout="", stderr="unknown user")

        users_file.delete_user("dev@local.test", self.users, runner=runner)

        self.assertEqual("other@local.test:{PLAIN}secret::::::\n", self.users.read_text())
        self.assertEqual(b"preserve", sentinel.read_bytes())
        self.assertIn(["doveadm", "reload"], calls)
        self.assertIn(["doveadm", "user", "dev@local.test"], calls)

    def test_writers_block_on_shared_users_lock(self) -> None:
        self.write_users("dev@local.test:{PLAIN}secret::::::\n")
        context = multiprocessing.get_context("fork")
        ready = context.Event()
        release = context.Event()
        process = context.Process(
            target=_hold_record_lock,
            args=(str(self.root / "users.lock"), ready, release),
        )
        process.start()
        self.addCleanup(lambda: process.is_alive() and process.terminate())
        self.assertTrue(ready.wait(5))
        completed = threading.Event()

        def mutate() -> None:
            users_file.upsert_user(
                "dev@local.test", "changed", self.users, runner=self.runner
            )
            completed.set()

        thread = threading.Thread(target=mutate, daemon=True)
        thread.start()
        time.sleep(0.15)
        self.assertFalse(completed.is_set(), "writer must wait for users.lock")
        release.set()
        thread.join(5)
        process.join(5)
        self.assertTrue(completed.is_set())
        self.assertEqual(0, process.exitcode)

    def test_mutation_atomically_replaces_with_0600_and_leaves_no_temp_debris(self) -> None:
        self.write_users("dev@local.test:{PLAIN}old::::::\n")
        original_replace = users_file.os.replace
        observations: list[tuple[Path, Path, bytes]] = []

        def observing_replace(source: object, destination: object) -> None:
            source_path = Path(source)
            destination_path = Path(destination)
            observations.append((source_path, destination_path, destination_path.read_bytes()))
            original_replace(source, destination)

        with mock.patch.object(users_file.os, "replace", side_effect=observing_replace):
            users_file.upsert_user("dev@local.test", "new", self.users, runner=self.runner)

        self.assertEqual(1, len(observations))
        source, destination, prior = observations[0]
        self.assertEqual(self.root, source.parent)
        self.assertEqual(self.users, destination)
        self.assertEqual(b"dev@local.test:{PLAIN}old::::::\n", prior)
        self.assertEqual(0o600, stat.S_IMODE(self.users.stat().st_mode))
        self.assertEqual([], list(self.root.glob("users.tmp-*")))

    def test_atomic_replace_fsyncs_users_directory(self) -> None:
        self.write_users("dev@local.test:{PLAIN}old::::::\n")
        synced: list[Path] = []

        with mock.patch.object(
            users_file,
            "_fsync_directory",
            side_effect=lambda path: synced.append(path),
        ):
            users_file.upsert_user("dev@local.test", "new", self.users, runner=self.runner)

        self.assertEqual([self.root], synced)

    def test_symlinks_and_wrong_final_modes_fail_closed(self) -> None:
        outside = self.root / "outside"
        outside.write_text("dev@local.test:{PLAIN}outside::::::\n")
        self.users.symlink_to(outside)
        with self.assertRaises(users_file.UsersFileError):
            users_file.upsert_user("dev@local.test", "new", self.users, runner=self.runner)
        self.assertIn("outside", outside.read_text())

        self.users.unlink()
        self.write_users("dev@local.test:{PLAIN}secret::::::\n")
        self.users.chmod(0o644)
        with self.assertRaises(users_file.UsersFileError):
            users_file.delete_user("dev@local.test", self.users, runner=self.runner)

    def test_projection_failure_does_not_fake_rollback_of_durable_mutation(self) -> None:
        self.write_users("dev@local.test:{PLAIN}old::::::\n")

        def failing_runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(command, 1, stdout="", stderr="provider unavailable")

        with self.assertRaisesRegex(users_file.UsersFileError, "durable|provider unavailable"):
            users_file.upsert_user("dev@local.test", "new", self.users, runner=failing_runner)
        self.assertIn("{PLAIN}new", self.users.read_text())

    def test_replace_failure_preserves_existing_authority_and_clears_journal(self) -> None:
        original = b"dev@local.test:{PLAIN}old::::::\n"
        self.users.write_bytes(original)
        self.users.chmod(0o600)
        with mock.patch.object(users_file.os, "replace", side_effect=OSError("replace failed")):
            try:
                users_file.upsert_user("dev@local.test", "new", self.users, runner=self.runner)
            except Exception as exc:
                self.assertIsInstance(exc, users_file.UsersFileError)
                self.assertRegex(str(exc), "not applied|retry")
            else:
                self.fail("replace failure unexpectedly succeeded")

        self.assertEqual(original, self.users.read_bytes())
        self.assertFalse(users_file.verification_pending(self.users))
        self.assertTrue(
            users_file.upsert_user("dev@local.test", "new", self.users, runner=self.runner)
        )

    def test_pre_replace_failure_with_missing_authority_clears_journal(self) -> None:
        with mock.patch.object(users_file.os, "replace", side_effect=OSError("replace failed")):
            try:
                users_file.upsert_user("new@local.test", "secret", self.users, runner=self.runner)
            except Exception as exc:
                self.assertIsInstance(exc, users_file.UsersFileError)
                self.assertRegex(str(exc), "not applied|retry")
            else:
                self.fail("replace failure unexpectedly succeeded")

        self.assertFalse(self.users.exists())
        self.assertFalse(users_file.verification_pending(self.users))
        self.assertTrue(
            users_file.upsert_user("new@local.test", "secret", self.users, runner=self.runner)
        )

    def test_post_replace_failure_retains_recoverable_pending_journal(self) -> None:
        original = b"dev@local.test:{PLAIN}old::::::\n"
        updated = b"dev@local.test:{PLAIN}new::::::\n"
        self.users.write_bytes(original)
        self.users.chmod(0o600)
        with mock.patch.object(
            users_file,
            "_fsync_directory",
            side_effect=OSError("directory fsync failed"),
        ):
            try:
                users_file.upsert_user("dev@local.test", "new", self.users, runner=self.runner)
            except Exception as exc:
                self.assertIsInstance(exc, users_file.UsersFileError)
                self.assertRegex(str(exc), "durable|pending")
            else:
                self.fail("post-replace failure unexpectedly succeeded")

        self.assertEqual(updated, self.users.read_bytes())
        self.assertTrue(users_file.verification_pending(self.users))

        def runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            stdout = "dev@local.test\n" if command[-1:] == ["*"] else ""
            return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

        users_file.verify_users(self.users, runner=runner)
        self.assertFalse(users_file.verification_pending(self.users))

    def test_atomic_write_failure_with_third_state_fails_closed(self) -> None:
        original = b"dev@local.test:{PLAIN}old::::::\n"
        third = b"third@local.test:{PLAIN}third::::::\n"
        self.users.write_bytes(original)
        self.users.chmod(0o600)
        runner = mock.Mock(side_effect=AssertionError("provider must not be called"))

        def leave_third_state(path: Path, content: bytes) -> None:
            del content
            path.write_bytes(third)
            path.chmod(0o600)
            raise OSError("write outcome is indeterminate")

        with mock.patch.object(users_file, "_atomic_write", side_effect=leave_third_state):
            try:
                users_file.upsert_user("dev@local.test", "new", self.users, runner=runner)
            except Exception as exc:
                self.assertIsInstance(exc, users_file.UsersFileError)
                self.assertRegex(str(exc), "indeterminate")
            else:
                self.fail("indeterminate write failure unexpectedly succeeded")

        runner.assert_not_called()
        self.assertEqual(third, self.users.read_bytes())
        self.assertTrue(users_file.verification_pending(self.users))

    def test_all_public_mutations_delegate_to_one_locked_primitive(self) -> None:
        for mutation in (
            users_file.bootstrap_defaults,
            users_file.reset_defaults,
            users_file.upsert_user,
            users_file.delete_user,
        ):
            with self.subTest(mutation=mutation.__name__):
                source = inspect.getsource(mutation)
                self.assertIn("return _mutate_users(", source)
                self.assertNotIn("_atomic_write(", source)
                self.assertNotIn("with _locked(", source)


@unittest.skipIf(users_file is None, "users_file.py has not been implemented yet")
class ProjectionAndDeferTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.users = self.root / "users"
        self.defaults = self.root / "users.defaults"
        self.defaults.write_text(DEFAULT_TEXT, encoding="utf-8")
        self.defaults.chmod(0o600)

    def test_reset_defaults_reloads_checks_every_user_and_compares_wildcard(self) -> None:
        self.users.write_text("old@local.test:{PLAIN}old::::::\n", encoding="utf-8")
        self.users.chmod(0o600)
        calls: list[tuple[list[str], dict[str, object]]] = []

        def runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            calls.append((command, kwargs))
            stdout = "\n".join(DEFAULT_ADDRESSES) + "\n" if command[-1:] == ["*"] else ""
            return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

        users_file.reset_defaults(self.users, self.defaults, runner=runner)

        self.assertEqual(
            [
                (["doveadm", "reload"], {}),
                *[
                    (["doveadm", "user", address], {"capture": True})
                    for address in DEFAULT_ADDRESSES
                ],
                (["doveadm", "user", "*"], {"capture": True}),
            ],
            calls,
        )
        self.assertEqual(DEFAULT_TEXT, self.users.read_text())

    def test_unchanged_reset_still_runs_full_projection_verification(self) -> None:
        self.users.write_text(DEFAULT_TEXT, encoding="utf-8")
        self.users.chmod(0o600)
        calls: list[list[str]] = []

        def runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            calls.append(command)
            stdout = "\n".join(DEFAULT_ADDRESSES) + "\n" if command[-1:] == ["*"] else ""
            return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

        changed = users_file.reset_defaults(self.users, self.defaults, runner=runner)

        self.assertFalse(changed)
        self.assertEqual(
            [
                ["doveadm", "reload"],
                *[["doveadm", "user", address] for address in DEFAULT_ADDRESSES],
                ["doveadm", "user", "*"],
            ],
            calls,
        )

    def test_deleted_user_requires_nonzero_doveadm_user_result(self) -> None:
        self.users.write_text("dev@local.test:{PLAIN}secret::::::\n", encoding="utf-8")
        self.users.chmod(0o600)

        def falsely_present(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            stdout = "" if command[-1:] == ["*"] else "dev@local.test\n"
            return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

        with self.assertRaisesRegex(users_file.UsersFileError, "still projects"):
            users_file.delete_user("dev@local.test", self.users, runner=falsely_present)
        self.assertEqual("", self.users.read_text())

    def test_delete_requires_exact_remaining_projection_before_negative_lookup(self) -> None:
        self.users.write_text(
            "dev@local.test:{PLAIN}secret::::::\n"
            "other@local.test:{PLAIN}secret::::::\n",
            encoding="utf-8",
        )
        self.users.chmod(0o600)
        calls: list[list[str]] = []

        def runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            calls.append(command)
            if command == ["doveadm", "user", "*"]:
                return subprocess.CompletedProcess(command, 0, stdout="other@local.test\n", stderr="")
            if command == ["doveadm", "user", "dev@local.test"]:
                return subprocess.CompletedProcess(command, 1, stdout="", stderr="unknown user")
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

        users_file.delete_user("dev@local.test", self.users, runner=runner)

        wildcard = ["doveadm", "user", "*"]
        deleted_lookup = ["doveadm", "user", "dev@local.test"]
        self.assertIn(wildcard, calls)
        self.assertIn(deleted_lookup, calls)
        if wildcard in calls and deleted_lookup in calls:
            self.assertLess(calls.index(wildcard), calls.index(deleted_lookup))
        self.assertFalse(users_file.verification_pending(self.users))

    def test_delete_of_final_user_requires_empty_wildcard_and_negative_lookup(self) -> None:
        self.users.write_text("dev@local.test:{PLAIN}secret::::::\n", encoding="utf-8")
        self.users.chmod(0o600)
        calls: list[list[str]] = []

        def runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            calls.append(command)
            if command == ["doveadm", "user", "*"]:
                return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
            if command == ["doveadm", "user", "dev@local.test"]:
                return subprocess.CompletedProcess(command, 1, stdout="", stderr="unknown user")
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

        users_file.delete_user("dev@local.test", self.users, runner=runner)

        self.assertEqual(b"", self.users.read_bytes())
        self.assertIn(["doveadm", "user", "*"], calls)
        self.assertIn(["doveadm", "user", "dev@local.test"], calls)

    def test_delete_wildcard_failure_keeps_pending_even_if_lookup_would_be_nonzero(self) -> None:
        self.users.write_text("dev@local.test:{PLAIN}secret::::::\n", encoding="utf-8")
        self.users.chmod(0o600)
        calls: list[list[str]] = []

        def failing_runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            calls.append(command)
            if command == ["doveadm", "user", "*"]:
                return subprocess.CompletedProcess(command, 75, stdout="", stderr="provider failure")
            if command == ["doveadm", "user", "dev@local.test"]:
                return subprocess.CompletedProcess(command, 1, stdout="", stderr="unknown user")
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

        with self.assertRaisesRegex(users_file.UsersFileError, "durable|provider failure"):
            users_file.delete_user("dev@local.test", self.users, runner=failing_runner)

        self.assertEqual(b"", self.users.read_bytes())
        self.assertTrue(users_file.verification_pending(self.users))
        self.assertNotIn(["doveadm", "user", "dev@local.test"], calls)

    def test_verify_recovers_before_and_after_journal_states(self) -> None:
        old = b"old@local.test:{PLAIN}old::::::\n"
        new = b"new@local.test:{PLAIN}new::::::\n"

        self.users.write_bytes(old)
        self.users.chmod(0o600)
        lock_path = _write_journal(self.users, _journal(old, new))
        old_calls: list[list[str]] = []

        def old_runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            old_calls.append(command)
            stdout = "old@local.test\n" if command[-1:] == ["*"] else ""
            return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

        with self.assertRaisesRegex(users_file.UsersFileError, "not applied|retry"):
            users_file.verify_users(self.users, runner=old_runner)
        self.assertEqual("", lock_path.read_text(encoding="ascii"))
        self.assertIn(["doveadm", "user", "old@local.test"], old_calls)

        self.users.write_bytes(new)
        self.users.chmod(0o600)
        lock_path.write_text(_journal(old, new), encoding="ascii")
        lock_path.chmod(0o600)

        def new_runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            stdout = "new@local.test\n" if command[-1:] == ["*"] else ""
            return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

        try:
            users_file.verify_users(self.users, runner=new_runner)
        except users_file.UsersFileError as exc:
            self.fail(f"after-state journal did not recover: {exc}")
        self.assertEqual("", lock_path.read_text(encoding="ascii"))

    def test_after_state_recovery_fsyncs_directory_before_provider_verification(self) -> None:
        old = b"old@local.test:{PLAIN}old::::::\n"
        new = b"new@local.test:{PLAIN}new::::::\n"
        self.users.write_bytes(new)
        self.users.chmod(0o600)
        lock_path = _write_journal(self.users, _journal(old, new))
        events: list[tuple[str, object]] = []

        def fsync_directory(path: Path) -> None:
            events.append(("fsync", path))

        def runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            events.append(("provider", command))
            stdout = "new@local.test\n" if command[-1:] == ["*"] else ""
            return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

        with mock.patch.object(
            users_file,
            "_fsync_directory",
            side_effect=fsync_directory,
        ):
            users_file.verify_users(self.users, runner=runner)

        self.assertEqual(("fsync", self.root), events[0])
        self.assertEqual("", lock_path.read_text(encoding="ascii"))

    def test_after_state_recovery_fsync_failure_stays_pending_and_retry_clears(self) -> None:
        old = b"old@local.test:{PLAIN}old::::::\n"
        new = b"new@local.test:{PLAIN}new::::::\n"
        self.users.write_bytes(new)
        self.users.chmod(0o600)
        pending = _journal(old, new)
        lock_path = _write_journal(self.users, pending)
        calls: list[list[str]] = []

        def runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            calls.append(command)
            stdout = "new@local.test\n" if command[-1:] == ["*"] else ""
            return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

        with mock.patch.object(
            users_file,
            "_fsync_directory",
            side_effect=OSError("directory fsync failed"),
        ):
            try:
                users_file.verify_users(self.users, runner=runner)
            except Exception as exc:
                self.assertIsInstance(exc, users_file.UsersFileError)
                self.assertRegex(str(exc), "durability|pending")
            else:
                self.fail("recovery unexpectedly ignored directory fsync failure")

        self.assertEqual([], calls)
        self.assertEqual(pending.encode("ascii"), lock_path.read_bytes())
        self.assertTrue(users_file.verification_pending(self.users))

        with mock.patch.object(users_file, "_fsync_directory") as fsync_directory:
            users_file.verify_users(self.users, runner=runner)

        fsync_directory.assert_called_once_with(self.root)
        self.assertNotEqual([], calls)
        self.assertFalse(users_file.verification_pending(self.users))

    def test_verify_clears_absent_before_state_for_retry_without_provider_calls(self) -> None:
        intended = b"new@local.test:{PLAIN}new::::::\n"
        lock_path = _write_journal(self.users, _journal(None, intended))
        runner = mock.Mock(side_effect=AssertionError("provider must not be called"))

        with self.assertRaisesRegex(users_file.UsersFileError, "not applied|retry"):
            users_file.verify_users(self.users, runner=runner)

        runner.assert_not_called()
        self.assertEqual("", lock_path.read_text(encoding="ascii"))

    def test_verify_leaves_indeterminate_third_digest_pending(self) -> None:
        old = b"old@local.test:{PLAIN}old::::::\n"
        new = b"new@local.test:{PLAIN}new::::::\n"
        third = b"third@local.test:{PLAIN}third::::::\n"
        self.users.write_bytes(third)
        self.users.chmod(0o600)
        lock_path = _write_journal(self.users, _journal(old, new))
        runner = mock.Mock(side_effect=AssertionError("provider must not be called"))

        with self.assertRaisesRegex(users_file.UsersFileError, "indeterminate"):
            users_file.verify_users(self.users, runner=runner)

        runner.assert_not_called()
        self.assertEqual(_journal(old, new), lock_path.read_text(encoding="ascii"))

    def test_pending_journal_parser_rejects_every_noncanonical_encoding(self) -> None:
        digest = "a" * 64
        invalid_states = (
            f"pending-verification sha256={digest}\n",
            f"{JOURNAL_PREFIX} before=sha256:{digest[:-1]} after=sha256:{digest}\n",
            f"{JOURNAL_PREFIX} before=sha256:{digest.upper()} after=sha256:{digest}\n",
            f"{JOURNAL_PREFIX} before=sha256:{digest} after=sha256:{digest}\n",
            f"{JOURNAL_PREFIX} before=absent after=absent\n",
            f"{JOURNAL_PREFIX} before=absent after=sha256:{digest}\ntrailing",
            f" {JOURNAL_PREFIX} before=absent after=sha256:{digest}\n",
        )
        for state in invalid_states:
            with self.subTest(state=state):
                _write_journal(self.users, state)
                with self.assertRaisesRegex(users_file.UsersFileError, "invalid.*journal"):
                    users_file.verification_pending(self.users)

    def test_bootstrap_defer_is_start_local_only_and_requires_later_verify(self) -> None:
        calls: list[list[str]] = []

        def runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            calls.append(command)
            stdout = "\n".join(DEFAULT_ADDRESSES) + "\n" if command[-1:] == ["*"] else ""
            return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

        try:
            with self.assertRaises(users_file.UsersFileError):
                users_file.bootstrap_defaults(
                    self.users,
                    self.defaults,
                    defer_provider_verification=True,
                    lifecycle="anything-else",
                    runner=runner,
                )
        except TypeError as exc:
            self.fail(f"exact internal defer-provider field is missing: {exc}")
        self.assertFalse(self.users.exists())

        try:
            users_file.bootstrap_defaults(
                self.users,
                self.defaults,
                defer_provider_verification=True,
                lifecycle="dashboard-start-local",
                runner=runner,
            )
        except TypeError as exc:
            self.fail(f"exact internal defer-provider field is missing: {exc}")
        self.assertEqual([], calls)
        self.assertTrue(users_file.verification_pending(self.users))
        with self.assertRaisesRegex(users_file.UsersFileError, "pending"):
            users_file.upsert_user("new@local.test", "secret", self.users, runner=runner)

        users_file.verify_users(self.users, runner=runner)
        self.assertFalse(users_file.verification_pending(self.users))
        self.assertEqual(
            [
                ["doveadm", "reload"],
                *[["doveadm", "user", address] for address in DEFAULT_ADDRESSES],
                ["doveadm", "user", "*"],
            ],
            calls,
        )

    def test_cli_accepts_only_exact_defer_provider_verification_name(self) -> None:
        with mock.patch("sys.stderr", new=io.StringIO()):
            try:
                args = users_file.build_parser().parse_args(
                    [
                        "bootstrap-defaults",
                        "--defer-provider-verification",
                        "--lifecycle",
                        "dashboard-start-local",
                    ]
                )
            except SystemExit as exc:
                self.fail(f"exact defer-provider flag was rejected with exit {exc.code}")
        self.assertTrue(args.defer_provider_verification)
        for rejected_flag in ("--defer-verification", "--defer-provider"):
            with self.subTest(rejected_flag=rejected_flag), mock.patch(
                "sys.stderr", new=io.StringIO()
            ):
                with self.assertRaises(SystemExit):
                    users_file.build_parser().parse_args(
                        [
                            "bootstrap-defaults",
                            rejected_flag,
                            "--lifecycle",
                            "dashboard-start-local",
                        ]
                    )


class ResetScopeTests(unittest.TestCase):
    def test_bulk_stalwart_sync_script_is_retired(self) -> None:
        self.assertFalse((SCRIPTS_DIR / "sync_stalwart_users.py").exists())
        self.assertNotIn("sync_stalwart_users.py", RESET_SCRIPT.read_text(encoding="utf-8"))

    def test_active_docs_do_not_prescribe_retired_sync_or_unsafe_bare_reset(self) -> None:
        for path in ACTIVE_AUTHORITY_DOCS:
            with self.subTest(path=path.relative_to(REPOSITORY_ROOT)):
                source = path.read_text(encoding="utf-8")
                self.assertNotIn("sync_stalwart_users.py", source)
        for path in (
            REPOSITORY_ROOT / ".ai" / "guidelines.md",
            REPOSITORY_ROOT / "CLAUDE.md",
            REPOSITORY_ROOT / "README.md",
        ):
            with self.subTest(path=path.relative_to(REPOSITORY_ROOT)):
                source = path.read_text(encoding="utf-8")
                self.assertIn(
                    "python3 scripts/reset.py --destroy-all-provider-data",
                    source,
                )
                self.assertNotIn("python3 scripts/reset.py   #", source)
                self.assertIn("destroy vmail/, stalwart-data/, config/users", source)

        readme = (REPOSITORY_ROOT / "README.md").read_text(encoding="utf-8")
        self.assertNotIn("Add or edit users in [`config/users`]", readme)
        for supported_command in (
            "scripts/create_and_feed_account.py --email",
            "scripts/users_file.py upsert",
            "scripts/users_file.py delete",
            "scripts/users_file.py reset-defaults",
            "scripts/users_file.py verify",
        ):
            self.assertIn(supported_command, readme)
        self.assertIn("Do not edit `config/users` directly", readme)

    def test_dashboard_reset_is_narrow_and_never_names_provider_data(self) -> None:
        self.assertTrue(DASHBOARD_RESET.is_file())
        source = DASHBOARD_RESET.read_text(encoding="utf-8")
        self.assertIn("--dovecot-defaults", source)
        self.assertIn("--yes", source)
        self.assertIn("reset-defaults", source)
        self.assertNotIn("vmail", source)
        self.assertNotIn("stalwart-data", source)
        self.assertNotIn("docker-compose.local-providers.yml", source)
        self.assertNotIn("-p ", source)

    def test_whole_reset_requires_exact_flag_and_confirmation_scope(self) -> None:
        source = RESET_SCRIPT.read_text(encoding="utf-8")
        self.assertIn("--destroy-all-provider-data", source)
        for name in ("vmail/", "stalwart-data/", "config/users"):
            self.assertIn(name, source)
        self.assertNotIn("git checkout", source)

    def test_whole_reset_rejects_abbreviated_destructive_flag(self) -> None:
        reset = importlib.import_module("reset")
        with mock.patch("sys.stderr", new=io.StringIO()):
            with self.assertRaises(SystemExit):
                reset.build_parser().parse_args(["--destroy-all"])

    def test_whole_reset_does_nothing_without_both_authorizations(self) -> None:
        reset = importlib.import_module("reset")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vmail = root / "vmail"
            stalwart = root / "stalwart-data"
            vmail.mkdir()
            stalwart.mkdir()
            (vmail / "mail").write_bytes(b"mail")
            (stalwart / "store").write_bytes(b"store")
            with mock.patch.object(reset, "VMAIL_DIR", vmail), mock.patch.object(
                reset, "STALWART_DATA_DIR", stalwart
            ), mock.patch.object(reset, "_clear_runtime_directory") as clear, mock.patch.object(
                reset.subprocess, "run"
            ) as run, mock.patch.object(reset, "reset_defaults") as restore:
                with mock.patch("sys.stdout", new=io.StringIO()), mock.patch(
                    "sys.stderr", new=io.StringIO()
                ):
                    self.assertEqual(2, reset.main([]))
                    with mock.patch("builtins.input", return_value="y"):
                        self.assertEqual(1, reset.main(["--destroy-all-provider-data"]))

            clear.assert_not_called()
            run.assert_not_called()
            restore.assert_not_called()
            self.assertEqual(b"mail", (vmail / "mail").read_bytes())
            self.assertEqual(b"store", (stalwart / "store").read_bytes())

    def test_authorized_whole_reset_cleans_exact_roots_then_starts_and_resets(self) -> None:
        reset = importlib.import_module("reset")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vmail = root / "vmail"
            stalwart = root / "stalwart-data"
            vmail.mkdir()
            stalwart.mkdir()
            (vmail / ".gitkeep").touch()
            (stalwart / ".gitkeep").touch()
            (vmail / "account").mkdir()
            (vmail / "account" / "mail").write_bytes(b"mail")
            (stalwart / "store").write_bytes(b"store")
            with mock.patch.object(reset, "VMAIL_DIR", vmail), mock.patch.object(
                reset, "STALWART_DATA_DIR", stalwart
            ), mock.patch(
                "builtins.input", return_value=reset.CONFIRMATION
            ), mock.patch.object(reset.subprocess, "run") as run, mock.patch.object(
                reset, "reset_defaults"
            ) as restore:
                with mock.patch("sys.stdout", new=io.StringIO()):
                    self.assertEqual(0, reset.main(["--destroy-all-provider-data"]))

            self.assertEqual([vmail / ".gitkeep"], list(vmail.iterdir()))
            self.assertEqual([stalwart / ".gitkeep"], list(stalwart.iterdir()))
            run.assert_called_once_with(
                [
                    "docker",
                    "compose",
                    "-f",
                    str(REPOSITORY_ROOT / "docker-compose.yml"),
                    "up",
                    "-d",
                    "oauth2-mock",
                    "dovecot",
                ],
                check=True,
            )
            restore.assert_called_once_with()


class WriterMigrationTests(unittest.TestCase):
    def test_account_writer_uses_users_file_api_without_direct_file_mutation(self) -> None:
        source = (SCRIPTS_DIR / "create_and_feed_account.py").read_text(encoding="utf-8")
        self.assertIn("upsert_user", source)
        self.assertNotIn("USERS_FILE.read_text", source)
        self.assertNotIn("USERS_FILE.write_text", source)
        self.assertNotIn("USERS_FILE.open", source)


if __name__ == "__main__":
    unittest.main()
