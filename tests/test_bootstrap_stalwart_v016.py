from __future__ import annotations

from contextlib import (
    contextmanager,
    nullcontext,
    redirect_stderr,
    redirect_stdout,
)
from dataclasses import replace
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import stat
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPOSITORY_ROOT / "scripts" / "bootstrap_stalwart_v016.py"
MANIFEST_PATH = REPOSITORY_ROOT / "stalwart" / "bootstrap-v016.ndjson"
SIEVE_PATH = REPOSITORY_ROOT / "stalwart" / "protected-recipients.sieve"

MANAGEMENT_PERMISSIONS = (
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
PERMISSION_MAP = {permission: True for permission in MANAGEMENT_PERMISSIONS}
ACCOUNT_PERMISSIONS = {
    "@type": "Replace",
    "disabledPermissions": {},
    "enabledPermissions": PERMISSION_MAP,
}
KEY_PERMISSIONS = {
    "@type": "Replace",
    "permissions": PERMISSION_MAP,
}
ROUTING_MAIL_PERMISSIONS = (
    "authenticate",
    "jmapMailboxGet",
    "jmapMailboxCreate",
    "jmapMailboxUpdate",
    "jmapMailboxDestroy",
    "jmapEmailGet",
    "jmapEmailQuery",
    "jmapEmailUpdate",
    "jmapEmailDestroy",
    "jmapEmailImport",
    "jmapIdentityGet",
    "jmapEmailSubmissionGet",
    "jmapEmailSubmissionCreate",
    "jmapBlobGet",
    "jmapBlobUpload",
)
PRESERVED_OBJECTS = [
    {
        "id": "singleton",
        "object_type": "MtaOutboundStrategy",
        "value": {
            "connection": {"else": "'default'", "match": {}},
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
                    "1": {"if": "source == 'dsn'", "then": "'dsn'"},
                    "2": {"if": "source == 'report'", "then": "'report'"},
                },
            },
            "tls": {
                "else": "'default'",
                "match": {
                    "0": {
                        "if": "retry_num > 0 && last_error == 'tls'",
                        "then": "'invalid-tls'",
                    },
                },
            },
        },
    },
]
SIEVE_TEXT = (
    'require ["envelope", "reject"];\n'
    "\n"
    'if envelope :is "to" "dashboard-management@local.test" {\n'
    '    reject "550 5.7.1 Recipient is reserved for dashboard management.";\n'
    "}\n"
    "\n"
    'if envelope :matches "to" "dashboard-management+*@local.test" {\n'
    '    reject "550 5.7.1 Recipient is reserved for dashboard management.";\n'
    "}\n"
)
SIEVE_BYTES = SIEVE_TEXT.encode("ascii")
MANIFEST_RECORDS = (
    {
        "deferred_capabilities": ["directory", "tracer"],
        "kind": "metadata",
        "policy_input": "stalwart/protected-recipients.sieve",
        "schema": "mail-sandbox.stalwart-v016-bootstrap-manifest.v1",
    },
    {
        "desired": {
            "bind": {"[::]:8080": True},
            "name": "http",
            "protocol": "http",
            "tlsImplicit": False,
            "useTls": False,
        },
        "kind": "object",
        "lookup": {"name": "http"},
        "object_type": "NetworkListener",
    },
    {
        "desired": {
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
        "kind": "object",
        "lookup": {"name": "local.test"},
        "object_type": "Domain",
    },
    {
        "desired": {
            "defaultDomainId": {"$ref": "Domain:local.test:id"},
            "defaultHostname": "stalwart.local.test",
        },
        "kind": "object",
        "lookup": {"id": "singleton"},
        "object_type": "SystemSettings",
    },
    {
        "desired": {
            "@type": "Local",
            "description": "mail-sandbox local-only delivery",
            "name": "local",
        },
        "kind": "object",
        "lookup": {"name": "local"},
        "object_type": "MtaRoute",
    },
    {
        "desired": {
            "contents": {
                "$asset": "stalwart/protected-recipients.sieve",
            },
            "description": (
                "Reject delivery to the protected dashboard management recipient."
            ),
            "isActive": True,
            "name": "mail-sandbox-protected-recipients",
        },
        "kind": "object",
        "lookup": {"name": "mail-sandbox-protected-recipients"},
        "object_type": "SieveSystemScript",
    },
    {
        "desired": {
            "allowRelaying": {
                "else": "false",
                "match": {},
            },
            "script": {
                "else": "'mail-sandbox-protected-recipients'",
                "match": {},
            },
        },
        "kind": "object",
        "lookup": {"id": "singleton"},
        "object_type": "MtaStageRcpt",
    },
    {
        "desired": {
            "@type": "User",
            "aliases": {},
            "description": "mail-sandbox/debug-dashboard/management",
            "domainId": {"$ref": "Domain:local.test:id"},
            "name": "dashboard-management",
            "permissions": ACCOUNT_PERMISSIONS,
            "roles": {"@type": "User"},
        },
        "kind": "object",
        "lookup": {"address": "dashboard-management@local.test"},
        "object_type": "Account",
    },
    {
        "desired": {
            "bind": {"[::]:587": True},
            "name": "submission",
            "protocol": "smtp",
            "tlsImplicit": False,
            "useTls": False,
        },
        "kind": "normal_runtime_object",
        "lookup": {"name": "submission"},
        "object_type": "NetworkListener",
    },
    {
        "desired": {
            "directoryId": None,
            "passwordMinLength": 1,
            "passwordMinStrength": "zero",
        },
        "kind": "normal_runtime_object",
        "lookup": {"id": "singleton"},
        "object_type": "Authentication",
    },
    {
        "desired": {
            "maxFailures": {"else": "3", "match": {}},
            "mustMatchSender": {"else": "true", "match": {}},
            "require": {"else": "true", "match": {}},
            "saslMechanisms": {
                "else": "[plain, login, oauthbearer, xoauth2]",
                "match": {},
            },
            "waitOnFail": {"else": "0ms", "match": {}},
        },
        "kind": "normal_runtime_object",
        "lookup": {"id": "singleton"},
        "object_type": "MtaStageAuth",
    },
    {
        "desired": {
            "@type": "Stdout",
            "ansi": False,
            "buffered": False,
            "enable": True,
            "events": {},
            "eventsPolicy": "exclude",
            "level": "debug",
            "lossy": False,
            "multiline": False,
        },
        "kind": "normal_runtime_object",
        "lookup": {"description": "mail-sandbox debug stdout"},
        "object_type": "Tracer",
    },
    {
        "account": "dashboard-management@local.test",
        "kind": "normal_runtime_password_intent",
        "password": "secret",
    },
    {
        "account": "dashboard-management@local.test",
        "allowed_ips": {},
        "description": "mail-sandbox/debug-dashboard/management",
        "ip_restriction_decision": (
            "disabled-local-only-loopback-network-isolation"
        ),
        "kind": "api_key_intent",
        "permissions": KEY_PERMISSIONS,
    },
)


def canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


MANIFEST_BYTES = b"".join(canonical_json(record) + b"\n" for record in MANIFEST_RECORDS)


def task6_file(name: str, marker: int) -> dict[str, object]:
    return {
        "identity": [1, marker, 33152, 1, 501, 20],
        "name": name,
        "sha256": f"{marker:064x}",
        "size": marker,
    }


TASK6_APPLY_PAYLOAD = {
    "applied_at": "2026-07-28T11:00:00Z",
    "artifacts": [
        task6_file(name, index)
        for index, name in enumerate(
            (
                "settings.json",
                "principals.json",
                "config.json",
                "export.json",
                "unmigrated.txt",
            ),
            start=11,
        )
    ],
    "attempt": task6_file("apply-attempt.json", 21),
    "inputs": [
        task6_file(name, index)
        for index, name in enumerate(
            (
                "latest-source.json",
                "migrate_v016.py",
                "dry-run.json",
                "reviewed.json",
                "docker-compose.stalwart-migration.yml",
                "docker-compose.yml",
            ),
            start=1,
        )
    ],
    "post_apply_proof": {
        "management_status": 200,
        "operation_count": 5,
        "operations_sha256": "f" * 64,
        "server_version": "0.16.17",
    },
    "runtime_artifacts": {
        "config": task6_file("config.json", 31),
        "config_directory_identity": [1, 30, 16832, 1, 501, 20],
        "recovery_environment": {
            "identity": [1, 32, 33152, 1, 501, 20],
            "name": "recovery.env",
            "size": 64,
        },
    },
    "schema": "mail-sandbox.stalwart-v016-apply.v2",
    "summary": {
        "created": 3,
        "destroyed": 0,
        "failed": 0,
        "updated": 2,
    },
}

bootstrap = None
IMPORT_ERROR: Exception | None = None
if SCRIPT_PATH.exists():
    try:
        spec = importlib.util.spec_from_file_location(
            "bootstrap_stalwart_v016",
            SCRIPT_PATH,
        )
        assert spec is not None
        assert spec.loader is not None
        bootstrap = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = bootstrap
        spec.loader.exec_module(bootstrap)
    except Exception as exc:  # pragma: no cover - reported by existence test
        IMPORT_ERROR = exc


def write_file(path: Path, content: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    path.chmod(mode)


def write_envelope(path: Path, payload: dict[str, object]) -> None:
    encoded = canonical_json(payload)
    envelope = {
        "payload": payload,
        "payload_sha256": hashlib.sha256(encoded).hexdigest(),
    }
    write_file(path, canonical_json(envelope) + b"\n", 0o600)


def file_metadata(path: Path, *, digest: bool = True) -> dict[str, object]:
    metadata = path.stat()
    identity = [
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
    ]
    if not digest:
        identity.extend(
            [
                metadata.st_mtime_ns,
                metadata.st_ctime_ns,
            ],
        )
    result: dict[str, object] = {
        "name": path.name,
        "size": metadata.st_size,
        "identity": identity,
    }
    if digest:
        result["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


class TemporaryRepository:
    def __init__(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.root = Path(self._temporary.name).resolve()
        write_file(
            self.root / "stalwart" / "bootstrap-v016.ndjson",
            MANIFEST_BYTES,
            0o644,
        )
        write_file(
            self.root / "stalwart" / "protected-recipients.sieve",
            SIEVE_BYTES,
            0o644,
        )
        write_file(
            self.root
            / "debug-dashboard"
            / ".runtime"
            / "stalwart-migration"
            / "apply.json",
            canonical_json(TASK6_APPLY_PAYLOAD) + b"\n",
            0o600,
        )
        (
            self.root / "debug-dashboard" / ".runtime" / "stalwart"
        ).mkdir(parents=True, exist_ok=True)
        (
            self.root / "debug-dashboard" / ".runtime" / "secrets"
        ).mkdir(parents=True, exist_ok=True)
        runtime = self.root / "debug-dashboard" / ".runtime"
        for directory in (
            runtime,
            runtime / "stalwart",
            runtime / "secrets",
            runtime / "stalwart-migration",
        ):
            directory.chmod(0o700)
        write_file(
            runtime / "stalwart" / "network.env",
            b"STALWART_PUBLIC_URL=http://192.168.86.36:8443\n",
            0o600,
        )

    def close(self) -> None:
        self._temporary.cleanup()

    def __enter__(self) -> "TemporaryRepository":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


class ScriptExistenceTest(unittest.TestCase):
    def test_module_and_tracked_assets_exist(self) -> None:
        self.assertIsNotNone(
            bootstrap,
            f"{SCRIPT_PATH.relative_to(REPOSITORY_ROOT)} must import: {IMPORT_ERROR}",
        )
        self.assertTrue(MANIFEST_PATH.is_file())
        self.assertTrue(SIEVE_PATH.is_file())


@unittest.skipIf(bootstrap is None, "bootstrap planner is not implemented")
class CanonicalAssetTest(unittest.TestCase):
    def test_tracked_assets_are_the_reviewed_canonical_inputs(self) -> None:
        self.assertEqual(MANIFEST_PATH.read_bytes(), MANIFEST_BYTES)
        self.assertEqual(SIEVE_PATH.read_bytes(), SIEVE_BYTES)
        self.assertEqual(stat.S_IMODE(MANIFEST_PATH.stat().st_mode), 0o644)
        self.assertEqual(stat.S_IMODE(SIEVE_PATH.stat().st_mode), 0o644)

    def test_loads_fixed_assets_and_resolves_only_the_sieve_contents(self) -> None:
        with TemporaryRepository() as repository:
            paths = bootstrap.BootstrapPaths.for_repository(repository.root)
            desired = bootstrap.load_desired_state(paths)

        self.assertEqual(
            tuple(item.object_type for item in desired.objects),
            (
                "NetworkListener",
                "Domain",
                "SystemSettings",
                "MtaRoute",
                "SieveSystemScript",
                "MtaStageRcpt",
                "Account",
            ),
        )
        self.assertEqual(desired.deferred_capabilities, ("directory", "tracer"))
        self.assertEqual(
            desired.object("SieveSystemScript").desired_dict()["contents"],
            SIEVE_TEXT,
        )
        self.assertEqual(
            desired.api_key_intent.ip_restriction_decision,
            "disabled-local-only-loopback-network-isolation",
        )
        self.assertNotIn(
            "pending",
            desired.api_key_intent.ip_restriction_decision,
        )

    def test_manifest_contains_exact_permissions_and_no_ordinary_users(self) -> None:
        with TemporaryRepository() as repository:
            desired = bootstrap.load_desired_state(
                bootstrap.BootstrapPaths.for_repository(repository.root),
            )

        account = desired.object("Account").desired_dict()
        self.assertEqual(
            tuple(account["permissions"]["enabledPermissions"]),
            MANAGEMENT_PERMISSIONS,
        )
        self.assertEqual(account["permissions"], ACCOUNT_PERMISSIONS)
        self.assertEqual(
            desired.api_key_intent.permissions_dict(),
            KEY_PERMISSIONS,
        )
        serialized = canonical_json(
            [item.desired_dict() for item in desired.objects],
        ).decode("utf-8")
        for ordinary in ("gate-one", "gate-two", "dev@local.test"):
            self.assertNotIn(ordinary, serialized)
        self.assertEqual(
            [
                item
                for item in desired.objects
                if item.object_type == "Account"
            ][0].lookup_dict(),
            {"address": "dashboard-management@local.test"},
        )

    def test_manifest_has_exact_local_password_intent_and_no_invented_directory(self) -> None:
        lowered = MANIFEST_BYTES.decode("utf-8").lower()
        self.assertEqual(lowered.count('"password":"secret"'), 1)
        self.assertEqual(lowered.count('"kind":"normal_runtime_password_intent"'), 1)
        self.assertNotIn('"object_type":"directory"', lowered)
        self.assertIn('"object_type":"mtaroute"', lowered)
        self.assertIn('"object_type":"sievesystemscript"', lowered)
        self.assertIn('"isactive":true', lowered)

    def test_loads_normal_runtime_contract_for_password_smtp_and_debug_stdout(self) -> None:
        with TemporaryRepository() as repository:
            contract = bootstrap.load_normal_runtime_contract(
                bootstrap.BootstrapPaths.for_repository(repository.root),
            )

        self.assertEqual(contract.management_address, "dashboard-management@local.test")
        self.assertEqual(contract.management_password, "secret")
        self.assertEqual(
            tuple(item.object_type for item in contract.objects),
            ("NetworkListener", "Authentication", "MtaStageAuth", "Tracer"),
        )
        submission = contract.objects[0].desired_dict()
        self.assertEqual(submission["bind"], {"[::]:587": True})
        self.assertEqual(submission["protocol"], "smtp")
        authentication = contract.objects[1].desired_dict()
        self.assertIsNone(authentication["directoryId"])
        self.assertEqual(authentication["passwordMinLength"], 1)
        self.assertEqual(authentication["passwordMinStrength"], "zero")
        tracer = contract.objects[3].desired_dict()
        self.assertEqual(tracer["@type"], "Stdout")
        self.assertEqual(tracer["level"], "debug")
        self.assertFalse(tracer["buffered"])

    def test_rejects_duplicate_extra_malformed_and_noncanonical_records(self) -> None:
        mutations = (
            MANIFEST_BYTES.replace(
                b'"kind":"metadata"',
                b'"kind":"metadata","kind":"metadata"',
                1,
            ),
            MANIFEST_BYTES + canonical_json(MANIFEST_RECORDS[1]) + b"\n",
            MANIFEST_BYTES.replace(b'"kind":"metadata"', b'"kind":', 1),
            MANIFEST_BYTES.replace(b'{"deferred_capabilities"', b'{ "deferred_capabilities"', 1),
        )
        for content in mutations:
            with self.subTest(content=content[:80]):
                with TemporaryRepository() as repository:
                    paths = bootstrap.BootstrapPaths.for_repository(repository.root)
                    write_file(paths.manifest, content, 0o644)
                    with self.assertRaises(bootstrap.BootstrapError):
                        bootstrap.load_desired_state(paths)

    def test_rejects_wrong_json_types_including_bool_as_integer(self) -> None:
        records = json.loads(json.dumps(MANIFEST_RECORDS))
        records[1]["desired"]["useTls"] = 0
        records[4]["desired"]["@type"] = True
        content = b"".join(canonical_json(record) + b"\n" for record in records)
        with TemporaryRepository() as repository:
            paths = bootstrap.BootstrapPaths.for_repository(repository.root)
            write_file(paths.manifest, content, 0o644)
            with self.assertRaises(bootstrap.BootstrapError):
                bootstrap.load_desired_state(paths)

    def test_rejects_sieve_mutation_crlf_and_malformed_policy(self) -> None:
        mutations = (
            SIEVE_BYTES.replace(b"dashboard-management", b"another-account"),
            SIEVE_BYTES.replace(b"\n", b"\r\n"),
            SIEVE_BYTES.replace(b'require ["envelope", "reject"];', b""),
            SIEVE_BYTES + b"# extra\n",
        )
        for content in mutations:
            with self.subTest(content=content):
                with TemporaryRepository() as repository:
                    paths = bootstrap.BootstrapPaths.for_repository(repository.root)
                    write_file(paths.sieve, content, 0o644)
                    with self.assertRaises(bootstrap.BootstrapError):
                        bootstrap.load_desired_state(paths)

    def test_rejects_asset_symlinks_modes_and_nonfixed_paths(self) -> None:
        with TemporaryRepository() as repository:
            paths = bootstrap.BootstrapPaths.for_repository(repository.root)
            paths.manifest.chmod(0o600)
            with self.assertRaises(bootstrap.BootstrapError):
                bootstrap.load_desired_state(paths)

        with TemporaryRepository() as repository:
            paths = bootstrap.BootstrapPaths.for_repository(repository.root)
            target = repository.root / "manifest-target"
            write_file(target, MANIFEST_BYTES, 0o644)
            paths.manifest.unlink()
            paths.manifest.symlink_to(target)
            with self.assertRaises(bootstrap.BootstrapError):
                bootstrap.load_desired_state(paths)

        with TemporaryRepository() as repository:
            paths = bootstrap.BootstrapPaths.for_repository(repository.root)
            altered = replace(paths, manifest=repository.root / "other.ndjson")
            write_file(altered.manifest, MANIFEST_BYTES, 0o644)
            with self.assertRaises(bootstrap.BootstrapError):
                bootstrap.load_desired_state(altered)

    def test_models_are_frozen_and_repr_is_redacted(self) -> None:
        with TemporaryRepository() as repository:
            desired = bootstrap.load_desired_state(
                bootstrap.BootstrapPaths.for_repository(repository.root),
            )
        with self.assertRaises(Exception):
            desired.deferred_capabilities = ()  # type: ignore[misc]
        self.assertIn("redacted", repr(desired).lower())
        self.assertNotIn("dashboard-management", repr(desired))


@unittest.skipIf(bootstrap is None, "bootstrap planner is not implemented")
class ReconciliationPlannerTest(unittest.TestCase):
    def load_desired(self) -> object:
        repository = TemporaryRepository()
        self.addCleanup(repository.close)
        return bootstrap.load_desired_state(
            bootstrap.BootstrapPaths.for_repository(repository.root),
        )

    def observed(
        self,
        desired: object,
        *,
        exact: bool,
        include_ordinary: bool = False,
    ) -> object:
        objects = []
        domain_id = "domain-id"
        for item in desired.objects:
            if not exact:
                continue
            value = item.desired_dict()
            if item.object_type in {"SystemSettings", "Account"}:
                value["defaultDomainId" if item.object_type == "SystemSettings" else "domainId"] = (
                    domain_id
                )
            object_id = {
                "NetworkListener": "listener-id",
                "Domain": domain_id,
                "SystemSettings": "singleton",
                "MtaRoute": "route-id",
                "SieveSystemScript": "sieve-id",
                "MtaStageRcpt": "singleton",
                "Account": "management-id",
            }[item.object_type]
            objects.append(
                bootstrap.ObservedObject.from_mapping(
                    item.object_type,
                    object_id,
                    value,
                ),
            )
        if include_ordinary:
            objects.append(
                bootstrap.ObservedObject.from_mapping(
                    "Account",
                    "ordinary-id",
                    {
                        "@type": "User",
                        "domainId": domain_id,
                        "name": "ordinary-user",
                        "unrelated": "preserve",
                    },
                ),
            )
        return bootstrap.ObservedState(
            queried_types=bootstrap.REQUIRED_QUERY_TYPES,
            objects=tuple(objects),
            api_keys=(),
        )

    def ownership(self) -> object:
        return bootstrap.AccountOwnership(
            invocation_id="a" * 32,
            account_id="management-id",
            domain_id="domain-id",
            temporary_account_description=(
                "mail-sandbox/debug-dashboard/account/bootstrap-" + "a" * 32
            ),
            orphan_key_description=(
                "mail-sandbox/debug-dashboard/management/bootstrap-" + "a" * 32
            ),
        )

    def attempt(self) -> object:
        return bootstrap.AttemptCheckpoint(
            binding=bootstrap.FileBinding(
                path=Path("/private/tmp/bootstrap-attempt.json"),
                sha256="0" * 64,
                size=1,
                identity=(1, 1, 33152, 1, 501, 20),
            ),
            started_at="2026-07-28T12:00:00Z",
            invocation_id="a" * 32,
            account_ownership_description=(
                "mail-sandbox/debug-dashboard/account/bootstrap-" + "a" * 32
            ),
        )

    def test_exact_state_is_noop_and_ordinary_accounts_are_untouched(self) -> None:
        desired = self.load_desired()
        observed = self.observed(desired, exact=True, include_ordinary=True)

        plan = bootstrap.plan_reconciliation(
            desired,
            observed,
            ownership=self.ownership(),
        )

        self.assertEqual({action.kind for action in plan.actions}, {"noop"})
        self.assertNotIn("ordinary-id", repr(plan.actions))
        self.assertEqual(plan.state, "reconciled")

    def test_absent_domain_uses_two_phase_create_and_requery_without_pseudo_ids(
        self,
    ) -> None:
        desired = self.load_desired()
        observed = self.observed(desired, exact=False)

        plan = bootstrap.plan_reconciliation(desired, observed, ownership=None)

        self.assertEqual(plan.state, "domain-create-requery-required")
        self.assertEqual(
            {
                action.object_type
                for action in plan.actions
                if action.kind == "create"
            },
            {
                "NetworkListener",
                "Domain",
                "MtaRoute",
                "SieveSystemScript",
                "MtaStageRcpt",
            },
        )
        self.assertEqual(
            {
                action.object_type
                for action in plan.actions
                if action.kind == "requery-after-domain-create"
            },
            {"SystemSettings", "Account"},
        )
        serialized = canonical_json(
            [action.changes_dict() for action in plan.actions],
        ).decode("utf-8")
        self.assertNotIn("$created", serialized)
        self.assertNotIn("password", serialized)
        self.assertNotIn("secret", serialized)

    def test_patch_contains_only_changed_fields_and_preserves_unrelated_fields(self) -> None:
        desired = self.load_desired()
        observed = self.observed(desired, exact=True)
        listener = next(
            item for item in observed.objects if item.object_type == "NetworkListener"
        )
        changed = listener.value_dict()
        changed["protocol"] = "https"
        changed["migratedUnrelatedField"] = {"keep": True}
        replacement = bootstrap.ObservedObject.from_mapping(
            listener.object_type,
            listener.object_id,
            changed,
        )
        observed = replace(
            observed,
            objects=tuple(
                replacement if item is listener else item
                for item in observed.objects
            ),
        )

        plan = bootstrap.plan_reconciliation(
            desired,
            observed,
            ownership=self.ownership(),
        )

        patch = next(
            action
            for action in plan.actions
            if action.object_type == "NetworkListener"
        )
        self.assertEqual(patch.kind, "patch")
        self.assertEqual(patch.changes_dict(), {"protocol": "http"})
        self.assertNotIn("migratedUnrelatedField", patch.changes_dict())

    def test_compatible_nested_fields_preserve_unrelated_migrated_members(self) -> None:
        desired = self.load_desired()
        observed = self.observed(desired, exact=True)
        domain = next(
            item for item in observed.objects if item.object_type == "Domain"
        )
        changed = domain.value_dict()
        changed["certificateManagement"]["migratedHint"] = "keep"
        replacement = bootstrap.ObservedObject.from_mapping(
            "Domain",
            domain.object_id,
            changed,
        )
        observed = replace(
            observed,
            objects=tuple(
                replacement if item is domain else item
                for item in observed.objects
            ),
        )

        plan = bootstrap.plan_reconciliation(
            desired,
            observed,
            ownership=self.ownership(),
        )

        domain_action = next(
            action for action in plan.actions if action.object_type == "Domain"
        )
        self.assertEqual(domain_action.kind, "noop")
        self.assertEqual(domain_action.changes_dict(), {})

    def test_requires_all_query_results_before_planning(self) -> None:
        desired = self.load_desired()
        observed = self.observed(desired, exact=False)
        observed = replace(
            observed,
            queried_types=bootstrap.REQUIRED_QUERY_TYPES[:-1],
        )
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.plan_reconciliation(desired, observed, ownership=None)

    def test_rejects_duplicate_ambiguous_and_conflicting_objects(self) -> None:
        desired = self.load_desired()
        observed = self.observed(desired, exact=True)
        domain = next(item for item in observed.objects if item.object_type == "Domain")
        duplicate = bootstrap.ObservedObject.from_mapping(
            "Domain",
            "second-domain-id",
            domain.value_dict(),
        )
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.plan_reconciliation(
                desired,
                replace(observed, objects=observed.objects + (duplicate,)),
                ownership=self.ownership(),
            )

        conflicting = bootstrap.ObservedObject.from_mapping(
            "NetworkListener",
            "listener-id",
            {
                "bind": {"[::]:8080": True},
                "name": "http",
                "protocol": 7,
                "tlsImplicit": False,
                "useTls": False,
            },
        )
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.plan_reconciliation(
                desired,
                replace(
                    observed,
                    objects=tuple(
                        conflicting if item.object_type == "NetworkListener" else item
                        for item in observed.objects
                    ),
                ),
                ownership=self.ownership(),
            )

    def test_management_account_preexistence_requires_matching_durable_ownership(self) -> None:
        desired = self.load_desired()
        observed = self.observed(desired, exact=True)
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.plan_reconciliation(desired, observed, ownership=None)
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.plan_reconciliation(
                desired,
                observed,
                ownership=replace(self.ownership(), account_id="another-id"),
            )

    def test_management_account_create_uses_durable_temporary_ownership_marker(
        self,
    ) -> None:
        desired = self.load_desired()
        exact = self.observed(desired, exact=True)
        without_account = replace(
            exact,
            objects=tuple(
                item for item in exact.objects if item.object_type != "Account"
            ),
        )
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.plan_reconciliation(
                desired,
                without_account,
                ownership=None,
            )

        create_plan = bootstrap.plan_reconciliation(
            desired,
            without_account,
            ownership=None,
            attempt=self.attempt(),
        )
        create = next(
            action
            for action in create_plan.actions
            if action.object_type == "Account"
        )
        self.assertEqual(create.kind, "create-with-ownership-marker")
        self.assertEqual(
            create.changes_dict()["description"],
            self.attempt().account_ownership_description,
        )
        self.assertNotEqual(
            create.changes_dict()["description"],
            "mail-sandbox/debug-dashboard/management",
        )

        remote_value = desired.object("Account").desired_dict()
        remote_value["domainId"] = "domain-id"
        remote_value["description"] = self.attempt().account_ownership_description
        remote = bootstrap.ObservedObject.from_mapping(
            "Account",
            "management-id",
            remote_value,
        )
        recovered = bootstrap.plan_reconciliation(
            desired,
            replace(
                without_account,
                objects=without_account.objects + (remote,),
            ),
            ownership=None,
            attempt=self.attempt(),
        )
        recovery = next(
            action
            for action in recovered.actions
            if action.object_type == "Account"
        )
        self.assertEqual(recovery.kind, "checkpoint-account-before-finalize")
        self.assertEqual(recovery.object_id, "management-id")

        finalized = bootstrap.plan_reconciliation(
            desired,
            replace(
                without_account,
                objects=without_account.objects + (remote,),
            ),
            ownership=self.ownership(),
            attempt=self.attempt(),
        )
        final_patch = next(
            action
            for action in finalized.actions
            if action.object_type == "Account"
        )
        self.assertEqual(final_patch.kind, "patch")
        self.assertEqual(
            final_patch.changes_dict()["description"],
            "mail-sandbox/debug-dashboard/management",
        )

    def test_observation_rejects_secret_bearing_values(self) -> None:
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.ObservedObject.from_mapping(
                "Account",
                "account-id",
                {"name": "dashboard-management", "secret": "API_do-not-keep"},
            )


@unittest.skipIf(bootstrap is None, "bootstrap planner is not implemented")
class CheckpointAndReceiptTest(unittest.TestCase):
    STARTED = "2026-07-28T12:00:00Z"
    INVOCATION = "b" * 32

    def setup_repository(self) -> tuple[TemporaryRepository, object, object]:
        repository = TemporaryRepository()
        self.addCleanup(repository.close)
        paths = bootstrap.BootstrapPaths.for_repository(repository.root)
        validated_apply = bootstrap.validate_task6_apply_receipt(
            paths,
            validator=lambda receipt: json.loads(
                receipt.read_text("utf-8"),
            ),
        )
        inputs = bootstrap.load_bootstrap_inputs(
            paths,
            validated_apply=validated_apply,
        )
        return repository, paths, inputs

    def write_attempt(
        self,
        paths: object,
        inputs: object,
    ) -> object:
        payload = bootstrap.build_attempt_payload(
            inputs,
            started_at=self.STARTED,
            invocation_id=self.INVOCATION,
        )
        write_envelope(paths.attempt, payload)
        return bootstrap.load_checkpoint_state(inputs).attempt

    def write_account(
        self,
        paths: object,
        inputs: object,
        attempt: object,
    ) -> object:
        payload = bootstrap.build_account_checkpoint_payload(
            attempt,
            created_at=self.STARTED,
            account_id="management-id",
            domain_id="domain-id",
            observed_description=attempt.account_ownership_description,
        )
        write_envelope(paths.account, payload)
        return bootstrap.load_checkpoint_state(inputs).account

    def write_key(
        self,
        paths: object,
        inputs: object,
        account: object,
    ) -> object:
        write_file(paths.management_key, b"API_local-only-key", 0o600)
        state = bootstrap.load_checkpoint_state(inputs)
        payload = bootstrap.build_key_checkpoint_payload(
            account,
            state.management_key,
            created_at=self.STARTED,
            credential_id="credential-id",
            origin="created",
            adoption_proof=None,
        )
        write_envelope(paths.key, payload)
        return bootstrap.load_checkpoint_state(inputs).key

    def write_replacement(
        self,
        paths: object,
        inputs: object,
        account: object,
        *,
        orphan_credential_id: str,
    ) -> object:
        payload = bootstrap.build_replacement_checkpoint_payload(
            account,
            created_at=self.STARTED,
            orphan_credential_id=orphan_credential_id,
        )
        write_envelope(paths.replacement, payload)
        return bootstrap.load_checkpoint_state(inputs).replacement

    def safe_ids(self) -> dict[str, str]:
        return {
            "NetworkListener": "listener-id",
            "Domain": "domain-id",
            "SystemSettings": "singleton",
            "MtaRoute": "route-id",
            "SieveSystemScript": "sieve-id",
            "MtaStageRcpt": "singleton",
            "Account": "management-id",
            "ApiKey": "credential-id",
        }

    def safe_objects(
        self,
        inputs: object,
        key: object,
        *,
        object_ids: dict[str, str] | None = None,
    ) -> list[dict[str, object]]:
        ids = self.safe_ids() if object_ids is None else object_ids

        def resolve(value: object) -> object:
            if isinstance(value, dict):
                if value == {"$ref": "Domain:local.test:id"}:
                    return ids["Domain"]
                return {name: resolve(item) for name, item in value.items()}
            if isinstance(value, list):
                return [resolve(item) for item in value]
            return value

        values = [
            {
                "id": ids[item.object_type],
                "object_type": item.object_type,
                "value": resolve(item.desired_dict()),
            }
            for item in inputs.desired.objects
        ]
        values.append(
            {
                "id": ids["ApiKey"],
                "object_type": "ApiKey",
                "value": {
                    "accountId": key.account_id,
                    "allowedIps": {},
                    "credentialType": "ApiKey",
                    "description": "mail-sandbox/debug-dashboard/management",
                    "permissions": KEY_PERMISSIONS,
                },
            },
        )
        return values

    def credential(
        self,
        *,
        account_id: str = "management-id",
        credential_id: str = "credential-id",
        credential_type: str = "ApiKey",
        description: str | None = "mail-sandbox/debug-dashboard/management",
        permissions: dict[str, object] | None = KEY_PERMISSIONS,
        allowed_ips: dict[str, object] | None = None,
    ) -> object:
        return bootstrap.CredentialProjection.from_mapping(
            account_id=account_id,
            credential_id=credential_id,
            credential_type=credential_type,
            description=description,
            permissions=permissions,
            allowed_ips={} if allowed_ips is None else allowed_ips,
        )

    def preserved_objects(self) -> list[dict[str, object]]:
        return json.loads(json.dumps(PRESERVED_OBJECTS))

    def executor_proof(
        self,
        inputs: object,
        account: object,
        key: object,
    ) -> object:
        return bootstrap.validate_executor_observation(
            inputs,
            account,
            key,
            safe_objects=self.safe_objects(inputs, key),
            preserved_objects=self.preserved_objects(),
            credentials=(self.credential(),),
            authentication_status=200,
            authenticated_account_id="management-id",
            authenticated_username="dashboard-management@local.test",
            server_version="0.16.17",
        )

    def write_proof(
        self,
        paths: object,
        inputs: object,
        key: object,
    ) -> object:
        state = bootstrap.load_checkpoint_state(inputs)
        account = state.account
        assert account is not None
        payload = bootstrap.build_proof_payload(
            inputs,
            account,
            key,
            proven_at=self.STARTED,
            executor_proof=self.executor_proof(inputs, account, key),
        )
        write_envelope(paths.proof, payload)
        return bootstrap.load_checkpoint_state(inputs).proof

    def write_protected(self, paths: object) -> None:
        payload = {
            "account_ids": ["management-id"],
            "schema": "mail-sandbox.stalwart-v016-protected-accounts.v1",
        }
        write_file(paths.protected_accounts, canonical_json(payload) + b"\n", 0o600)

    def routing_arguments(self) -> dict[str, object]:
        invocation = self.INVOCATION
        sender_address = f"dashboard-routing-sender-{invocation}@local.test"
        recipient_address = (
            f"dashboard-routing-recipient-{invocation}@local.test"
        )
        message_id = f"<mail-sandbox-routing-{invocation}@local.test>"
        actors = {
            "sender": {
                "account_id": "routing-sender-account",
                "address": sender_address,
                "app_password_credential_id": "routing-sender-app-password",
            },
            "recipient": {
                "account_id": "routing-recipient-account",
                "address": recipient_address,
                "app_password_credential_id": "routing-recipient-app-password",
            },
        }
        probes = {
            "registered_local": {
                "recipient": recipient_address,
                "submission_id": "registered-submission",
                "submission_created": True,
                "delivery_status": "unknown",
                "smtp_code": 250,
                "enhanced_status": "2.1.5",
                "queue_accepted": True,
                "undo_status": "final",
                "arrival": {
                    "account_id": "routing-recipient-account",
                    "message_id": message_id,
                    "matching_email_ids": ["recipient-email-id"],
                },
            },
            "protected_exact": {
                "recipient": "dashboard-management@local.test",
                "submission_id": "protected-exact-submission",
                "submission_created": True,
                "delivery_status": "no",
                "smtp_code": 550,
                "enhanced_status": "5.7.1",
                "queue_accepted": False,
                "undo_status": "pending",
            },
            "protected_subaddress": {
                "recipient": (
                    f"dashboard-management+routing-{invocation}@local.test"
                ),
                "submission_id": "protected-subaddress-submission",
                "submission_created": True,
                "delivery_status": "no",
                "smtp_code": 550,
                "enhanced_status": "5.7.1",
                "queue_accepted": False,
                "undo_status": "pending",
            },
            "unregistered_local": {
                "recipient": (
                    f"dashboard-routing-missing-{invocation}@local.test"
                ),
                "submission_id": "unregistered-submission",
                "submission_created": True,
                "delivery_status": "no",
                "smtp_code": 550,
                "enhanced_status": "5.1.2",
                "queue_accepted": False,
                "undo_status": "pending",
            },
            "external": {
                "recipient": f"dashboard-routing-{invocation}@example.invalid",
                "submission_id": "external-submission",
                "submission_created": True,
                "delivery_status": "no",
                "smtp_code": 550,
                "enhanced_status": "5.1.2",
                "queue_accepted": False,
                "undo_status": "pending",
            },
        }
        recipient_access_removed = {
            "credential_id": "routing-recipient-app-password",
            "authentication_status": 401,
            "projected_state": "enrollmentRequired",
            "readiness_preflight": {
                "upload_calls": 0,
                "submission_calls": 0,
            },
        }
        cleanup = {
            "destroyed_account_ids": [
                "routing-sender-account",
                "routing-recipient-account",
            ],
            "account_get_not_found": [
                "routing-sender-account",
                "routing-recipient-account",
            ],
            "address_queries": [
                {"address": sender_address, "ids": []},
                {"address": recipient_address, "ids": []},
            ],
        }
        return {
            "actors": actors,
            "message_id": message_id,
            "probes": probes,
            "recipient_access_removed": recipient_access_removed,
            "cleanup": cleanup,
        }

    def write_routing(
        self,
        paths: object,
        inputs: object,
    ) -> object:
        state = bootstrap.load_checkpoint_state(inputs)
        if state.routing_intent is None:
            payload = bootstrap.build_routing_intent_payload(state)
            write_envelope(paths.routing_intent, payload)
            state = bootstrap.load_checkpoint_state(inputs)
        payload = bootstrap.build_routing_proof_payload(
            state,
            proven_at=self.STARTED,
            **self.routing_arguments(),
        )
        write_envelope(paths.routing_proof, payload)
        return bootstrap.load_checkpoint_state(inputs).routing_proof

    def write_final(
        self,
        paths: object,
        inputs: object,
        proof: object,
    ) -> None:
        self.write_protected(paths)
        self.write_routing(paths, inputs)
        state = bootstrap.load_checkpoint_state(inputs)
        payload = bootstrap.build_final_receipt_payload(
            inputs,
            state,
            completed_at=self.STARTED,
        )
        write_envelope(paths.final_receipt, payload)

    def test_fixed_runtime_paths_are_exact(self) -> None:
        repository, paths, _inputs = self.setup_repository()
        runtime = repository.root / "debug-dashboard" / ".runtime"
        self.assertEqual(
            paths.apply_receipt,
            runtime / "stalwart-migration" / "apply.json",
        )
        self.assertEqual(paths.attempt, runtime / "stalwart" / "bootstrap-attempt.json")
        self.assertEqual(paths.account, runtime / "stalwart" / "bootstrap-account.json")
        self.assertEqual(
            paths.replacement,
            runtime / "stalwart" / "bootstrap-replacement.json",
        )
        self.assertEqual(paths.key, runtime / "stalwart" / "bootstrap-key.json")
        self.assertEqual(paths.proof, runtime / "stalwart" / "bootstrap-proof.json")
        self.assertEqual(
            paths.routing_proof,
            runtime / "stalwart" / "bootstrap-routing-proof.json",
        )
        self.assertEqual(
            paths.routing_intent,
            runtime / "stalwart" / "bootstrap-routing-intent.json",
        )
        self.assertEqual(paths.final_receipt, runtime / "stalwart" / "bootstrap.json")
        self.assertEqual(
            paths.management_key,
            runtime / "secrets" / "stalwart-management-api-key",
        )
        self.assertEqual(
            paths.protected_accounts,
            runtime / "stalwart" / "protected-accounts.json",
        )
        self.assertEqual(
            paths.routing_input,
            runtime / "stalwart" / "bootstrap-routing-input.json",
        )
        self.assertEqual(
            paths.routing_sender_password,
            runtime / "secrets" / "stalwart-routing-sender-password",
        )
        self.assertEqual(
            paths.routing_recipient_password,
            runtime / "secrets" / "stalwart-routing-recipient-password",
        )

    def test_routing_intent_is_secret_free_new_only_and_bound_to_final(
        self,
    ) -> None:
        _repository, paths, inputs = self.setup_repository()
        attempt = self.write_attempt(paths, inputs)
        account = self.write_account(paths, inputs, attempt)
        key = self.write_key(paths, inputs, account)
        self.write_proof(paths, inputs, key)
        state = bootstrap.load_checkpoint_state(inputs)

        payload = bootstrap.build_routing_intent_payload(state)
        write_envelope(paths.routing_intent, payload)
        original = paths.routing_intent.read_bytes()

        self.assertEqual(
            set(payload),
            {
                "account_checkpoint",
                "actors",
                "attempt_checkpoint",
                "bootstrap_proof",
                "domain_id",
                "invocation_id",
                "schema",
            },
        )
        self.assertEqual(
            payload["schema"],
            "mail-sandbox.stalwart-v016-routing-intent.v1",
        )
        self.assertNotIn(b"password", canonical_json(payload).lower())
        self.assertNotIn(b"secret", canonical_json(payload).lower())
        self.assertEqual(
            stat.S_IMODE(paths.routing_intent.stat().st_mode),
            0o600,
        )
        loaded = bootstrap.load_checkpoint_state(inputs)
        self.assertEqual(
            loaded.routing_intent.invocation_id,
            self.INVOCATION,
        )
        self.assertEqual(loaded.routing_intent.domain_id, "domain-id")
        with self.assertRaisesRegex(
            bootstrap.BootstrapError,
            "already exists",
        ):
            bootstrap._write_new_envelope_0600(
                paths.routing_intent,
                payload,
                root=paths.repository_root,
            )
        self.assertEqual(paths.routing_intent.read_bytes(), original)

        self.write_final(paths, inputs, key)
        routing = json.loads(paths.routing_proof.read_text("utf-8"))[
            "payload"
        ]
        final = json.loads(paths.final_receipt.read_text("utf-8"))[
            "payload"
        ]
        expected = file_metadata(paths.routing_intent)
        self.assertEqual(routing["routing_intent"], expected)
        self.assertEqual(final["checkpoints"]["routing_intent"], expected)

    def test_routing_intent_rejects_mode_symlink_and_semantic_tampering(
        self,
    ) -> None:
        for case in ("mode", "symlink", "tamper"):
            with self.subTest(case=case):
                _repository, paths, inputs = self.setup_repository()
                attempt = self.write_attempt(paths, inputs)
                account = self.write_account(paths, inputs, attempt)
                key = self.write_key(paths, inputs, account)
                self.write_proof(paths, inputs, key)
                state = bootstrap.load_checkpoint_state(inputs)
                payload = bootstrap.build_routing_intent_payload(state)

                if case == "symlink":
                    paths.routing_intent.symlink_to(paths.proof)
                else:
                    if case == "tamper":
                        payload["actors"]["sender"]["projection"]["name"] = (
                            "different-routing-actor"
                        )
                    write_envelope(paths.routing_intent, payload)
                    if case == "mode":
                        paths.routing_intent.chmod(0o644)

                with self.assertRaises(bootstrap.BootstrapError):
                    bootstrap.load_checkpoint_state(inputs)

    def test_requires_authoritative_task6_apply_validation_and_semantic_success(self) -> None:
        repository = TemporaryRepository()
        self.addCleanup(repository.close)
        paths = bootstrap.BootstrapPaths.for_repository(repository.root)

        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.load_bootstrap_inputs(paths)

        invalid = dict(TASK6_APPLY_PAYLOAD)
        invalid["post_apply_proof"] = dict(TASK6_APPLY_PAYLOAD["post_apply_proof"])
        invalid["post_apply_proof"]["management_status"] = 500
        write_file(
            paths.apply_receipt,
            canonical_json(invalid) + b"\n",
            0o600,
        )
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.validate_task6_apply_receipt(
                paths,
                validator=lambda receipt: json.loads(
                    receipt.read_text("utf-8"),
                ),
            )

        write_file(
            paths.apply_receipt,
            canonical_json(TASK6_APPLY_PAYLOAD) + b"\n",
            0o600,
        )
        different = dict(TASK6_APPLY_PAYLOAD)
        different["applied_at"] = "2026-07-28T11:00:01Z"
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.validate_task6_apply_receipt(
                paths,
                validator=lambda _receipt: different,
            )

        def leaking_validator(_receipt: Path) -> object:
            raise RuntimeError("API_must-not-escape")

        with self.assertRaises(bootstrap.BootstrapError) as raised:
            bootstrap.validate_task6_apply_receipt(
                paths,
                validator=leaking_validator,
            )
        self.assertNotIn("API_must-not-escape", str(raised.exception))

    def test_runtime_directories_must_match_owner_only_loader_contract(self) -> None:
        repository = TemporaryRepository()
        self.addCleanup(repository.close)
        paths = bootstrap.BootstrapPaths.for_repository(repository.root)
        (repository.root / "debug-dashboard" / ".runtime" / "secrets").chmod(
            0o755,
        )
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.validate_task6_apply_receipt(
                paths,
                validator=lambda receipt: json.loads(
                    receipt.read_text("utf-8"),
                ),
            )

    def test_checkpoint_state_matrix_and_valid_final_receipt(self) -> None:
        _repository, paths, inputs = self.setup_repository()
        state = bootstrap.load_checkpoint_state(inputs)
        self.assertEqual(bootstrap.plan_crash_recovery(state, remote_keys=()).state, "start")

        attempt = self.write_attempt(paths, inputs)
        state = bootstrap.load_checkpoint_state(inputs)
        self.assertEqual(
            bootstrap.plan_crash_recovery(state, remote_keys=()).state,
            "reconcile-read-only",
        )

        account = self.write_account(paths, inputs, attempt)
        state = bootstrap.load_checkpoint_state(inputs)
        self.assertEqual(
            bootstrap.plan_crash_recovery(state, remote_keys=()).state,
            "resume-exact-account",
        )

        key = self.write_key(paths, inputs, account)
        state = bootstrap.load_checkpoint_state(inputs)
        plan = bootstrap.plan_crash_recovery(
            state,
            remote_keys=(
                self.credential(),
            ),
        )
        self.assertEqual(plan.state, "verify-exact-key")
        self.assertEqual([action.kind for action in plan.actions], ["authenticate-exact-key"])

        proof = self.write_proof(paths, inputs, key)
        state = bootstrap.load_checkpoint_state(inputs)
        self.assertEqual(
            bootstrap.plan_crash_recovery(state, remote_keys=()).state,
            "routing-proof-required",
        )

        self.write_final(paths, inputs, proof)
        final_state = bootstrap.load_checkpoint_state(inputs)
        self.assertEqual(
            bootstrap.plan_crash_recovery(final_state, remote_keys=()).state,
            "validated-final",
        )
        self.assertEqual(final_state.final_receipt.server_version, "0.16.17")
        self.assertIn("redacted", repr(final_state.final_receipt).lower())

    def test_remote_orphan_is_exactly_revoked_then_replaced_once(self) -> None:
        _repository, paths, inputs = self.setup_repository()
        attempt = self.write_attempt(paths, inputs)
        account = self.write_account(paths, inputs, attempt)
        state = bootstrap.load_checkpoint_state(inputs)
        orphan = self.credential(
            credential_id="orphan-id",
            description=account.ownership.orphan_key_description,
        )

        plan = bootstrap.plan_crash_recovery(state, remote_keys=(orphan,))

        self.assertEqual(plan.state, "revoke-orphan-and-replace-once")
        self.assertEqual(
            [action.kind for action in plan.actions],
            [
                "write-replacement-checkpoint",
                "revoke-exact-bootstrap-orphan",
                "create-one-replacement",
            ],
        )
        self.assertEqual(plan.actions[1].object_id, "orphan-id")

        _repository, paths, inputs = self.setup_repository()
        attempt = self.write_attempt(paths, inputs)
        account = self.write_account(paths, inputs, attempt)
        self.write_replacement(
            paths,
            inputs,
            account,
            orphan_credential_id="orphan-id",
        )
        state = bootstrap.load_checkpoint_state(inputs)
        orphan = replace(
            orphan,
            description=account.ownership.orphan_key_description,
        )
        resumed = bootstrap.plan_crash_recovery(state, remote_keys=(orphan,))
        self.assertEqual(resumed.state, "resume-authorized-replacement")
        self.assertEqual(
            [action.kind for action in resumed.actions],
            ["revoke-exact-bootstrap-orphan", "create-one-replacement"],
        )

        replacement_orphan = replace(orphan, credential_id="replacement-id")
        limited = bootstrap.plan_crash_recovery(
            state,
            remote_keys=(replacement_orphan,),
        )
        self.assertEqual(limited.state, "replacement-limit-stop")
        self.assertEqual(
            [action.kind for action in limited.actions],
            ["revoke-exact-bootstrap-orphan", "require-new-invocation"],
        )

    def test_replacement_key_checkpoint_cannot_reuse_orphan_id(self) -> None:
        _repository, paths, inputs = self.setup_repository()
        attempt = self.write_attempt(paths, inputs)
        account = self.write_account(paths, inputs, attempt)
        self.write_replacement(
            paths,
            inputs,
            account,
            orphan_credential_id="credential-id",
        )
        write_file(paths.management_key, b"API_replacement-key", 0o600)
        state = bootstrap.load_checkpoint_state(inputs)
        payload = bootstrap.build_key_checkpoint_payload(
            account,
            state.management_key,
            created_at=self.STARTED,
            credential_id="credential-id",
            origin="created",
            adoption_proof=None,
        )
        write_envelope(paths.key, payload)

        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.load_checkpoint_state(inputs)

    def test_recovery_planner_rejects_reused_replacement_id(self) -> None:
        _repository, paths, inputs = self.setup_repository()
        attempt = self.write_attempt(paths, inputs)
        account = self.write_account(paths, inputs, attempt)
        self.write_key(paths, inputs, account)
        state = bootstrap.load_checkpoint_state(inputs)
        replacement = bootstrap.ReplacementCheckpoint(
            binding=state.account.binding,
            created_at=self.STARTED,
            account_id=state.key.account_id,
            orphan_credential_id=state.key.credential_id,
        )
        invalid_state = replace(state, replacement=replacement)

        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.plan_crash_recovery(invalid_state, remote_keys=())

    def test_unowned_or_ambiguous_remote_keys_are_never_revoked(self) -> None:
        _repository, paths, inputs = self.setup_repository()
        attempt = self.write_attempt(paths, inputs)
        account = self.write_account(paths, inputs, attempt)
        state = bootstrap.load_checkpoint_state(inputs)
        unrelated = self.credential(
            credential_id="unrelated-id",
            description="manual-key",
        )
        plan = bootstrap.plan_crash_recovery(state, remote_keys=(unrelated,))
        self.assertNotIn("revoke", repr(plan.actions))

        orphan_one = replace(
            unrelated,
            credential_id="orphan-one",
            description=account.ownership.orphan_key_description,
        )
        orphan_two = replace(orphan_one, credential_id="orphan-two")
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.plan_crash_recovery(
                state,
                remote_keys=(orphan_one, orphan_two),
            )

        unowned_final = replace(
            unrelated,
            credential_id="unowned-final",
            description="mail-sandbox/debug-dashboard/management",
        )
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.plan_crash_recovery(
                state,
                remote_keys=(unowned_final,),
            )

    def test_local_secret_without_key_checkpoint_is_authenticate_adopt_only(self) -> None:
        _repository, paths, inputs = self.setup_repository()
        attempt = self.write_attempt(paths, inputs)
        self.write_account(paths, inputs, attempt)
        write_file(paths.management_key, b"API_unbound-local-key", 0o600)
        state = bootstrap.load_checkpoint_state(inputs)

        plan = bootstrap.plan_crash_recovery(state, remote_keys=())

        self.assertEqual(plan.state, "authenticate-for-future-adoption")
        self.assertEqual(
            [action.kind for action in plan.actions],
            ["authenticate-local-secret-for-future-adoption"],
        )
        serialized = repr(plan.actions).lower()
        self.assertNotIn("overwrite", serialized)
        self.assertNotIn("create", serialized)

    def test_durable_key_checkpoint_with_missing_secret_stops_for_manual_reconciliation(
        self,
    ) -> None:
        _repository, paths, inputs = self.setup_repository()
        attempt = self.write_attempt(paths, inputs)
        account = self.write_account(paths, inputs, attempt)
        self.write_key(paths, inputs, account)
        paths.management_key.unlink()
        state = bootstrap.load_checkpoint_state(inputs)

        plan = bootstrap.plan_crash_recovery(
            state,
            remote_keys=(self.credential(),),
        )

        self.assertEqual(plan.state, "manual-reconciliation-required")
        self.assertEqual(
            [action.kind for action in plan.actions],
            ["stop-missing-checkpointed-secret"],
        )
        self.assertNotIn("revoke", repr(plan.actions))
        self.assertNotIn("create", repr(plan.actions))

        _repository, paths, inputs = self.setup_repository()
        attempt = self.write_attempt(paths, inputs)
        account = self.write_account(paths, inputs, attempt)
        key = self.write_key(paths, inputs, account)
        self.write_proof(paths, inputs, key)
        paths.management_key.unlink()
        state = bootstrap.load_checkpoint_state(inputs)
        plan = bootstrap.plan_crash_recovery(state, remote_keys=())
        self.assertEqual(plan.state, "manual-reconciliation-required")
        self.assertEqual(
            [action.kind for action in plan.actions],
            ["stop-missing-checkpointed-secret"],
        )

    def test_secret_binding_has_no_digest_and_raw_secret_is_never_in_models(self) -> None:
        _repository, paths, inputs = self.setup_repository()
        attempt = self.write_attempt(paths, inputs)
        account = self.write_account(paths, inputs, attempt)
        raw = b"API_unique-never-serialized"
        write_file(paths.management_key, raw, 0o600)
        state = bootstrap.load_checkpoint_state(inputs)
        payload = bootstrap.build_key_checkpoint_payload(
            account,
            state.management_key,
            created_at=self.STARTED,
            credential_id="credential-id",
            origin="created",
            adoption_proof=None,
        )
        encoded = canonical_json(payload)
        self.assertEqual(
            payload["account_checkpoint"],
            file_metadata(paths.account),
        )
        self.assertNotIn(raw, encoded)
        self.assertNotIn(hashlib.sha256(raw).hexdigest().encode("ascii"), encoded)
        self.assertNotIn("sha256", payload["key_file"])
        self.assertEqual(
            payload["schema"],
            "mail-sandbox.stalwart-v016-bootstrap-key.v2",
        )
        self.assertEqual(len(payload["key_file"]["identity"]), 8)
        self.assertNotIn(raw.decode("ascii"), repr(state))

        legacy_payload = dict(payload)
        legacy_payload["schema"] = (
            "mail-sandbox.stalwart-v016-bootstrap-key.v1"
        )
        legacy_payload["key_file"] = dict(payload["key_file"])
        legacy_payload["key_file"]["identity"] = payload["key_file"][
            "identity"
        ][:6]
        write_envelope(paths.key, legacy_payload)
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.load_checkpoint_state(inputs)

        weak_payload = dict(payload)
        weak_payload["key_file"] = dict(payload["key_file"])
        weak_payload["key_file"]["identity"] = payload["key_file"][
            "identity"
        ][:6]
        write_envelope(paths.key, weak_payload)
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.load_checkpoint_state(inputs)

        unbounded_payload = dict(payload)
        unbounded_payload["key_file"] = dict(payload["key_file"])
        unbounded_payload["key_file"]["identity"] = list(
            payload["key_file"]["identity"],
        )
        unbounded_payload["key_file"]["identity"][-1] = 1 << 64
        write_envelope(paths.key, unbounded_payload)
        paths.management_key.unlink()
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.load_checkpoint_state(inputs)

    def test_local_secret_adoption_requires_exact_authentication_proof(self) -> None:
        _repository, paths, inputs = self.setup_repository()
        attempt = self.write_attempt(paths, inputs)
        account = self.write_account(paths, inputs, attempt)
        write_file(paths.management_key, b"API_adopt-only-after-auth", 0o600)
        state = bootstrap.load_checkpoint_state(inputs)

        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.build_key_checkpoint_payload(
                account,
                state.management_key,
                created_at=self.STARTED,
                credential_id="credential-id",
                origin="adopted",
                adoption_proof=None,
            )

        try:
            with self.assertRaises(bootstrap.BootstrapError):
                bootstrap.validate_key_adoption(
                    inputs,
                    account,
                    credentials=(
                        self.credential(),
                        self.credential(
                            credential_id="password-id",
                            credential_type="Password",
                            description=None,
                            permissions=None,
                        ),
                    ),
                    authentication_status=200,
                    authenticated_account_id="management-id",
                    authenticated_username=(
                        "dashboard-management@local.test"
                    ),
                    server_version="0.16.17",
                )
        except TypeError:
            self.fail("key adoption lacks a complete-inventory API")

        adoption = bootstrap.validate_key_adoption(
            inputs,
            account,
            credentials=(self.credential(),),
            authentication_status=200,
            authenticated_account_id="management-id",
            authenticated_username="dashboard-management@local.test",
            server_version="0.16.17",
        )
        payload = bootstrap.build_key_checkpoint_payload(
            account,
            state.management_key,
            created_at=self.STARTED,
            credential_id="credential-id",
            origin="adopted",
            adoption_proof=adoption,
        )
        self.assertEqual(payload["origin"], "adopted")
        self.assertEqual(
            payload["adoption_evidence"],
            {
                "authentication": {
                    "account_id": "management-id",
                    "server_version": "0.16.17",
                    "status": 200,
                    "username": "dashboard-management@local.test",
                },
                "credential_inventory": [
                    {
                        "account_id": "management-id",
                        "allowed_ips": {},
                        "credential_id": "credential-id",
                        "credential_type": "ApiKey",
                        "description": (
                            "mail-sandbox/debug-dashboard/management"
                        ),
                        "permissions": KEY_PERMISSIONS,
                    },
                ],
            },
        )
        write_envelope(paths.key, payload)
        self.assertEqual(
            bootstrap.load_checkpoint_state(inputs).key.origin,
            "adopted",
        )
        payload["adoption_evidence"]["credential_inventory"].append(
            {
                "account_id": "management-id",
                "allowed_ips": {},
                "credential_id": "password-id",
                "credential_type": "Password",
                "description": None,
                "permissions": None,
            },
        )
        write_envelope(paths.key, payload)
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.load_checkpoint_state(inputs)

    def test_rejects_stale_or_mutated_inputs_and_secret_identity(self) -> None:
        _repository, paths, inputs = self.setup_repository()
        attempt = self.write_attempt(paths, inputs)
        self.write_account(paths, inputs, attempt)
        paths.manifest.write_bytes(MANIFEST_BYTES + b"\n")
        paths.manifest.chmod(0o644)
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.load_checkpoint_state(inputs)

    def test_end_of_load_revalidation_rejects_atomic_checkpoint_replacement(
        self,
    ) -> None:
        repository, paths, inputs = self.setup_repository()
        attempt = self.write_attempt(paths, inputs)
        self.write_account(paths, inputs, attempt)
        original = bootstrap._read_envelope
        replaced = False

        def replacing_reader(
            path: Path,
            *,
            root: Path,
            label: str,
        ) -> object:
            nonlocal replaced
            result = original(path, root=root, label=label)
            if path == paths.attempt and not replaced:
                replacement = repository.root / "replacement-attempt"
                write_file(replacement, path.read_bytes(), 0o600)
                os.replace(replacement, path)
                replaced = True
            return result

        with mock.patch.object(
            bootstrap,
            "_read_envelope",
            side_effect=replacing_reader,
        ):
            with self.assertRaises(bootstrap.BootstrapError):
                bootstrap.load_checkpoint_state(inputs)

    def test_end_of_load_revalidation_rejects_atomic_secret_replacement(
        self,
    ) -> None:
        repository, paths, inputs = self.setup_repository()
        attempt = self.write_attempt(paths, inputs)
        account = self.write_account(paths, inputs, attempt)
        self.write_key(paths, inputs, account)
        original = bootstrap._snapshot_secret
        replaced = False

        def replacing_secret(path: Path, *, root: Path) -> object:
            nonlocal replaced
            result = original(path, root=root)
            if not replaced:
                replacement = repository.root / "replacement-key"
                write_file(replacement, path.read_bytes(), 0o600)
                os.replace(replacement, path)
                replaced = True
            return result

        with mock.patch.object(
            bootstrap,
            "_snapshot_secret",
            side_effect=replacing_secret,
        ):
            with self.assertRaises(bootstrap.BootstrapError):
                bootstrap.load_checkpoint_state(inputs)

        _repository, paths, inputs = self.setup_repository()
        attempt = self.write_attempt(paths, inputs)
        account = self.write_account(paths, inputs, attempt)
        self.write_key(paths, inputs, account)
        replacement_path = paths.management_key.with_name("replacement")
        write_file(replacement_path, b"API_other-key-value", 0o600)
        os.replace(replacement_path, paths.management_key)
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.load_checkpoint_state(inputs)

    def test_secret_commitment_rejects_equal_length_same_inode_overwrite(
        self,
    ) -> None:
        _repository, paths, inputs = self.setup_repository()
        attempt = self.write_attempt(paths, inputs)
        account = self.write_account(paths, inputs, attempt)
        self.write_key(paths, inputs, account)
        before = paths.management_key.stat()
        replacement = b"Z" * before.st_size

        with paths.management_key.open("r+b", buffering=0) as stream:
            stream.write(replacement)
            stream.flush()
            os.fsync(stream.fileno())
        os.utime(
            paths.management_key,
            ns=(
                before.st_atime_ns,
                before.st_mtime_ns + 1_000_000,
            ),
        )

        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.load_checkpoint_state(inputs)

    def test_rejects_checkpoint_holes_symlinks_modes_and_tampering(self) -> None:
        _repository, paths, inputs = self.setup_repository()
        write_envelope(
            paths.account,
            {
                "schema": bootstrap.ACCOUNT_CHECKPOINT_SCHEMA,
                "created_at": self.STARTED,
                "invocation_id": self.INVOCATION,
                "account_id": "management-id",
                "domain_id": "domain-id",
                "orphan_key_description": "invalid",
            },
        )
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.load_checkpoint_state(inputs)

        _repository, paths, inputs = self.setup_repository()
        payload = bootstrap.build_attempt_payload(
            inputs,
            started_at=self.STARTED,
            invocation_id=self.INVOCATION,
        )
        payload["extra"] = "reject"
        write_envelope(paths.attempt, payload)
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.load_checkpoint_state(inputs)

        _repository, paths, inputs = self.setup_repository()
        attempt = self.write_attempt(paths, inputs)
        paths.attempt.chmod(0o644)
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.load_checkpoint_state(inputs)

        repository, paths, inputs = self.setup_repository()
        target = repository.root / "attempt-target"
        write_file(target, paths.attempt.read_bytes() if paths.attempt.exists() else b"{}", 0o600)
        if paths.attempt.exists():
            paths.attempt.unlink()
        paths.attempt.symlink_to(target)
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.load_checkpoint_state(inputs)

    def test_rejects_duplicate_json_keys_bool_counts_and_invalid_types(self) -> None:
        _repository, paths, inputs = self.setup_repository()
        payload = bootstrap.build_attempt_payload(
            inputs,
            started_at=self.STARTED,
            invocation_id=self.INVOCATION,
        )
        encoded = canonical_json(payload)
        duplicate = (
            b'{"payload":'
            + encoded
            + b',"payload":'
            + encoded
            + b',"payload_sha256":"'
            + hashlib.sha256(encoded).hexdigest().encode("ascii")
            + b'"}\n'
        )
        write_file(paths.attempt, duplicate, 0o600)
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.load_checkpoint_state(inputs)

        payload["replacement_count"] = False
        write_envelope(paths.attempt, payload)
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.load_checkpoint_state(inputs)

    def test_rejects_proof_and_final_receipt_tampering(self) -> None:
        _repository, paths, inputs = self.setup_repository()
        attempt = self.write_attempt(paths, inputs)
        account = self.write_account(paths, inputs, attempt)
        key = self.write_key(paths, inputs, account)
        proof_payload = bootstrap.build_proof_payload(
            inputs,
            account,
            key,
            proven_at=self.STARTED,
            executor_proof=self.executor_proof(inputs, account, key),
        )
        proof_payload["server_version"] = "0.16.15"
        write_envelope(paths.proof, proof_payload)
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.load_checkpoint_state(inputs)

        paths.proof.unlink()
        proof = self.write_proof(paths, inputs, key)
        self.write_final(paths, inputs, proof)
        envelope = json.loads(paths.final_receipt.read_text("utf-8"))
        envelope["payload"]["management"]["credential_id"] = "other-key"
        write_envelope(paths.final_receipt, envelope["payload"])
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.load_checkpoint_state(inputs)

    def test_final_retirement_validation_rejects_a_pending_network_decision(
        self,
    ) -> None:
        _repository, paths, inputs = self.setup_repository()
        attempt = self.write_attempt(paths, inputs)
        account = self.write_account(paths, inputs, attempt)
        key = self.write_key(paths, inputs, account)
        proof = self.write_proof(paths, inputs, key)
        self.write_final(paths, inputs, proof)
        envelope = json.loads(paths.final_receipt.read_text("utf-8"))
        envelope["payload"]["ip_restriction_decision"] = (
            "disabled-local-only-pending-live-network-proof"
        )
        write_envelope(paths.final_receipt, envelope["payload"])

        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.validate_final_bootstrap_for_retirement(
                paths,
                task6_validator=lambda receipt: json.loads(
                    receipt.read_text("utf-8"),
                ),
            )

    def test_routing_proof_requires_all_probes_cleanup_and_zero_call_preflight(
        self,
    ) -> None:
        repository, paths, inputs = self.setup_repository()
        attempt = self.write_attempt(paths, inputs)
        account = self.write_account(paths, inputs, attempt)
        key = self.write_key(paths, inputs, account)
        proof = self.write_proof(paths, inputs, key)
        state = bootstrap.load_checkpoint_state(inputs)
        write_envelope(
            paths.routing_intent,
            bootstrap.build_routing_intent_payload(state),
        )
        state = bootstrap.load_checkpoint_state(inputs)
        arguments = self.routing_arguments()

        payload = bootstrap.build_routing_proof_payload(
            state,
            proven_at=self.STARTED,
            **arguments,
        )

        self.assertEqual(
            set(payload),
            {
                "actors",
                "bootstrap_proof",
                "cleanup",
                "invocation_id",
                "management_account_id",
                "management_credential_id",
                "message_id",
                "preserved_objects_sha256",
                "probes",
                "proven_at",
                "recipient_access_removed",
                "routing_intent",
                "schema",
                "server_version",
            },
        )
        self.assertEqual(payload["bootstrap_proof"], file_metadata(paths.proof))
        self.assertEqual(
            payload["routing_intent"],
            file_metadata(paths.routing_intent),
        )
        self.assertEqual(
            payload["preserved_objects_sha256"],
            hashlib.sha256(canonical_json(PRESERVED_OBJECTS)).hexdigest(),
        )

        invalid_arguments = json.loads(json.dumps(arguments))
        invalid_arguments["probes"]["external"]["smtp_code"] = 451
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.build_routing_proof_payload(
                state,
                proven_at=self.STARTED,
                **invalid_arguments,
            )

        invalid_arguments = json.loads(json.dumps(arguments))
        invalid_arguments["recipient_access_removed"][
            "readiness_preflight"
        ]["submission_calls"] = 1
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.build_routing_proof_payload(
                state,
                proven_at=self.STARTED,
                **invalid_arguments,
            )

        invalid_arguments = json.loads(json.dumps(arguments))
        invalid_arguments["actors"]["sender"]["account_id"] = "management-id"
        invalid_arguments["cleanup"]["destroyed_account_ids"][0] = (
            "management-id"
        )
        invalid_arguments["cleanup"]["account_get_not_found"][0] = (
            "management-id"
        )
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.build_routing_proof_payload(
                state,
                proven_at=self.STARTED,
                **invalid_arguments,
            )

        write_envelope(paths.routing_proof, payload)
        loaded = bootstrap.load_checkpoint_state(inputs)
        self.assertEqual(loaded.routing_proof.invocation_id, self.INVOCATION)
        paths.routing_proof.chmod(0o644)
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.load_checkpoint_state(inputs)
        paths.routing_proof.chmod(0o600)

        original = bootstrap._read_envelope
        replaced = False

        def replacing_routing_reader(
            path: Path,
            *,
            root: Path,
            label: str,
        ) -> object:
            nonlocal replaced
            result = original(path, root=root, label=label)
            if path == paths.routing_proof and not replaced:
                replacement = repository.root / "replacement-routing-proof"
                write_file(replacement, path.read_bytes(), 0o600)
                os.replace(replacement, path)
                replaced = True
            return result

        with mock.patch.object(
            bootstrap,
            "_read_envelope",
            side_effect=replacing_routing_reader,
        ):
            with self.assertRaises(bootstrap.BootstrapError):
                bootstrap.load_checkpoint_state(inputs)

    def test_executor_proof_requires_full_state_and_exact_api_key_only_inventory(
        self,
    ) -> None:
        _repository, paths, inputs = self.setup_repository()
        attempt = self.write_attempt(paths, inputs)
        account = self.write_account(paths, inputs, attempt)
        key = self.write_key(paths, inputs, account)
        safe_objects = self.safe_objects(inputs, key)

        invalid_credentials = (
            (),
            (
                self.credential(
                    credential_type="Password",
                    description=None,
                    permissions=None,
                ),
            ),
            (
                self.credential(
                    permissions={
                        "@type": "Replace",
                        "permissions": {"authenticate": True},
                    },
                ),
            ),
            (
                self.credential(),
                self.credential(
                    credential_id="password-id",
                    credential_type="Password",
                    description=None,
                    permissions=None,
                ),
            ),
        )
        for credentials in invalid_credentials:
            with self.subTest(credentials=credentials):
                with self.assertRaises(bootstrap.BootstrapError):
                    bootstrap.validate_executor_observation(
                        inputs,
                        account,
                        key,
                        safe_objects=safe_objects,
                        preserved_objects=self.preserved_objects(),
                        credentials=credentials,
                        authentication_status=200,
                        authenticated_account_id="management-id",
                        authenticated_username=(
                            "dashboard-management@local.test"
                        ),
                        server_version="0.16.17",
                    )

        incomplete = safe_objects[:-1]
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.validate_executor_observation(
                inputs,
                account,
                key,
                safe_objects=incomplete,
                preserved_objects=self.preserved_objects(),
                credentials=(self.credential(),),
                authentication_status=200,
                authenticated_account_id="management-id",
                authenticated_username="dashboard-management@local.test",
                server_version="0.16.17",
            )

        incompatible_preserved = self.preserved_objects()
        incompatible_preserved[0]["value"]["route"]["else"] = "'remote'"
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.validate_executor_observation(
                inputs,
                account,
                key,
                safe_objects=safe_objects,
                preserved_objects=incompatible_preserved,
                credentials=(self.credential(),),
                authentication_status=200,
                authenticated_account_id="management-id",
                authenticated_username="dashboard-management@local.test",
                server_version="0.16.17",
            )

    def test_executor_proof_binds_durable_account_domain_id(self) -> None:
        _repository, paths, inputs = self.setup_repository()
        attempt = self.write_attempt(paths, inputs)
        account = self.write_account(paths, inputs, attempt)
        key = self.write_key(paths, inputs, account)
        mismatched_ids = self.safe_ids()
        mismatched_ids["Domain"] = "other-domain-id"

        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.validate_executor_observation(
                inputs,
                account,
                key,
                safe_objects=self.safe_objects(
                    inputs,
                    key,
                    object_ids=mismatched_ids,
                ),
                preserved_objects=self.preserved_objects(),
                credentials=(self.credential(),),
                authentication_status=200,
                authenticated_account_id="management-id",
                authenticated_username="dashboard-management@local.test",
                server_version="0.16.17",
            )

        forged_account = replace(
            account,
            ownership=replace(
                account.ownership,
                domain_id="other-domain-id",
            ),
        )
        forged_executor_proof = bootstrap.validate_executor_observation(
            inputs,
            forged_account,
            key,
            safe_objects=self.safe_objects(
                inputs,
                key,
                object_ids=mismatched_ids,
            ),
            preserved_objects=self.preserved_objects(),
            credentials=(self.credential(),),
            authentication_status=200,
            authenticated_account_id="management-id",
            authenticated_username="dashboard-management@local.test",
            server_version="0.16.17",
        )
        forged_payload = bootstrap.build_proof_payload(
            inputs,
            forged_account,
            key,
            proven_at=self.STARTED,
            executor_proof=forged_executor_proof,
        )
        write_envelope(paths.proof, forged_payload)
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.load_checkpoint_state(inputs)

    def test_final_receipt_binds_exact_safe_evidence_without_key_hash(self) -> None:
        _repository, paths, inputs = self.setup_repository()
        attempt = self.write_attempt(paths, inputs)
        account = self.write_account(paths, inputs, attempt)
        key = self.write_key(paths, inputs, account)
        proof = self.write_proof(paths, inputs, key)
        self.write_final(paths, inputs, proof)
        envelope = json.loads(paths.final_receipt.read_text("utf-8"))
        payload = envelope["payload"]

        self.assertEqual(
            set(payload),
            {
                "apply_receipt",
                "authentication",
                "checkpoints",
                "completed_at",
                "credential_inventory",
                "inputs",
                "ip_restriction_decision",
                "management",
                "permissions_sha256",
                "protected_accounts",
                "preserved_objects",
                "routing_proof",
                "safe_objects",
                "schema",
                "server_version",
            },
        )
        self.assertEqual(payload["server_version"], "0.16.17")
        self.assertEqual(
            payload["schema"],
            "mail-sandbox.stalwart-v016-bootstrap-receipt.v2",
        )
        self.assertEqual(
            payload["ip_restriction_decision"],
            "disabled-local-only-loopback-network-isolation",
        )
        self.assertNotIn("pending", payload["ip_restriction_decision"])
        self.assertEqual(payload["preserved_objects"], PRESERVED_OBJECTS)
        self.assertEqual(
            payload["authentication"],
            {
                "account_id": "management-id",
                "server_version": "0.16.17",
                "status": 200,
                "username": "dashboard-management@local.test",
            },
        )
        self.assertEqual(
            payload["management"]["account_id"],
            payload["authentication"]["account_id"],
        )
        self.assertEqual(
            payload["management"]["credential_id"],
            payload["credential_inventory"][0]["credential_id"],
        )
        self.assertNotIn("sha256", payload["management"]["key_file"])
        self.assertEqual(
            len(payload["management"]["key_file"]["identity"]),
            8,
        )
        self.assertIn("sha256", payload["apply_receipt"])
        self.assertIn("sha256", payload["protected_accounts"])
        serialized = canonical_json(payload)
        self.assertNotIn(b"API_local-only-key", serialized)

        legacy_payload = dict(payload)
        legacy_payload["schema"] = (
            "mail-sandbox.stalwart-v016-bootstrap-receipt.v1"
        )
        legacy_payload["management"] = dict(payload["management"])
        legacy_payload["management"]["key_file"] = dict(
            payload["management"]["key_file"],
        )
        legacy_payload["management"]["key_file"]["identity"] = payload[
            "management"
        ]["key_file"]["identity"][:6]
        write_envelope(paths.final_receipt, legacy_payload)
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.load_checkpoint_state(inputs)

        weak_payload = dict(payload)
        weak_payload["management"] = dict(payload["management"])
        weak_payload["management"]["key_file"] = dict(
            payload["management"]["key_file"],
        )
        weak_payload["management"]["key_file"]["identity"] = payload[
            "management"
        ]["key_file"]["identity"][:6]
        write_envelope(paths.final_receipt, weak_payload)
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.load_checkpoint_state(inputs)

    def test_final_retirement_token_revalidates_the_full_bootstrap_chain(
        self,
    ) -> None:
        _repository, paths, inputs = self.setup_repository()
        attempt = self.write_attempt(paths, inputs)
        account = self.write_account(paths, inputs, attempt)
        key = self.write_key(paths, inputs, account)
        proof = self.write_proof(paths, inputs, key)
        self.write_final(paths, inputs, proof)

        token = bootstrap.validate_final_bootstrap_for_retirement(
            paths,
            task6_validator=lambda receipt: json.loads(
                receipt.read_text("utf-8"),
            ),
        )

        self.assertEqual(token.final_receipt.path, paths.final_receipt)
        self.assertEqual(token.bootstrap_proof.path, paths.proof)
        self.assertEqual(token.routing_proof.path, paths.routing_proof)
        self.assertEqual(
            token.routing_proof_sha256,
            file_metadata(paths.routing_proof)["sha256"],
        )
        self.assertEqual(token.management_account_id, "management-id")
        self.assertEqual(token.management_api_key_id, "credential-id")
        self.assertEqual(
            token.ip_restriction_decision,
            "disabled-local-only-loopback-network-isolation",
        )
        self.assertEqual(
            token.preserved_objects_sha256,
            hashlib.sha256(canonical_json(PRESERVED_OBJECTS)).hexdigest(),
        )
        self.assertEqual(token.listener_id, "listener-id")
        self.assertEqual(token.listener_bind, ("[::]:8080",))
        self.assertEqual(token.management_key_name, paths.management_key.name)
        self.assertNotIn("API_local-only-key", repr(token))
        self.assertNotIn(token.ip_restriction_decision, repr(token))

    def test_protected_ids_are_strict_unique_and_owner_only(self) -> None:
        _repository, paths, inputs = self.setup_repository()
        attempt = self.write_attempt(paths, inputs)
        account = self.write_account(paths, inputs, attempt)
        key = self.write_key(paths, inputs, account)
        self.write_proof(paths, inputs, key)
        invalid_values = (
            {"account_ids": [], "schema": bootstrap.PROTECTED_ACCOUNTS_SCHEMA},
            {
                "account_ids": ["management-id", "management-id"],
                "schema": bootstrap.PROTECTED_ACCOUNTS_SCHEMA,
            },
            {
                "account_ids": ["management-id", "other-id"],
                "schema": bootstrap.PROTECTED_ACCOUNTS_SCHEMA,
            },
            {
                "account_ids": [True],
                "schema": bootstrap.PROTECTED_ACCOUNTS_SCHEMA,
            },
            {
                "account_ids": ["bad.id"],
                "schema": bootstrap.PROTECTED_ACCOUNTS_SCHEMA,
            },
        )
        for value in invalid_values:
            with self.subTest(value=value):
                write_file(
                    paths.protected_accounts,
                    canonical_json(value) + b"\n",
                    0o600,
                )
                with self.assertRaises(bootstrap.BootstrapError):
                    bootstrap.load_checkpoint_state(inputs)
        self.write_protected(paths)
        paths.protected_accounts.chmod(0o644)
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.load_checkpoint_state(inputs)


class FakeRegistryNotFound(RuntimeError):
    pass


class FakeRegistryAuthenticationError(RuntimeError):
    status = 401


class FakeCredential:
    def __init__(self, kind: str, *values: object) -> None:
        self.kind = kind
        self.buffers = [bytearray(value) for value in values]
        self.closed = False

    def close(self) -> None:
        for buffer in self.buffers:
            for index in range(len(buffer)):
                buffer[index] = 0
        self.closed = True


class FakeApiKeySecret:
    def __init__(self, value: bytes) -> None:
        self.buffer = bytearray(value)
        self.closed = False

    def copy_bytes(self) -> bytearray:
        return bytearray(self.buffer)

    def close(self) -> None:
        for index in range(len(self.buffer)):
            self.buffer[index] = 0
        self.closed = True


class FakeApiKeyCreation:
    def __init__(self, account_id: str, credential_id: str) -> None:
        self.account_id = account_id
        self.credential_id = credential_id
        self.secret = FakeApiKeySecret(
            b"API_0123456789abcdefghijklmnopqrstuvwxyz_AB",
        )

    def close(self) -> None:
        self.secret.close()

    def __enter__(self) -> "FakeApiKeyCreation":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


class FakeRegistryObject:
    def __init__(
        self,
        object_type: str,
        object_id: str,
        account_id: str,
        value: dict[str, object],
    ) -> None:
        self.object_type = object_type
        self.object_id = object_id
        self.account_id = account_id
        self._value = json.loads(json.dumps(value))

    def value(self) -> dict[str, object]:
        return json.loads(json.dumps(self._value))


class FakeRegistryServer:
    def __init__(self) -> None:
        self.next_id = 1
        self.objects: dict[str, dict[str, dict[str, object]]] = {
            object_type: {}
            for object_type in (
                "NetworkListener",
                "Domain",
                "SystemSettings",
                "MtaRoute",
                "SieveSystemScript",
                "MtaStageRcpt",
                "Authentication",
                "MtaStageAuth",
                "Tracer",
                "Account",
                "MtaOutboundStrategy",
            )
        }
        self.credentials: dict[str, dict[str, dict[str, object]]] = {}
        self.password_secrets: dict[str, dict[str, str]] = {}
        self.objects["MtaOutboundStrategy"]["singleton"] = json.loads(
            json.dumps(PRESERVED_OBJECTS[0]["value"]),
        )
        self.calls: list[tuple[object, ...]] = []
        self.clients: list[object] = []
        self.fail_after_api_key_create_once = False
        self.fail_after_account_create_name_once: str | None = None
        self.hard_exit_after_account_create_name_once: str | None = None
        self.fail_after_app_password_destroy_once: BaseException | None = None
        self.fail_credential_query_number: int | None = None
        self.credential_query_attempts = 0
        self.credential_query_overrides: dict[
            tuple[str, str],
            tuple[str, ...],
        ] = {}
        self.add_password_to_management_account = False
        self.fail_before_mutation_number: int | None = None
        self.fail_after_mutation_number: int | None = None
        self.mutation_attempts = 0

    def _id(self, prefix: str) -> str:
        value = f"{prefix}-{self.next_id}"
        self.next_id += 1
        return value

    def account_credentials(self, account_id: str) -> dict[str, object]:
        return json.loads(
            json.dumps(self.credentials.get(account_id, {})),
        )

    def before_mutation(self) -> int:
        self.mutation_attempts += 1
        if self.fail_before_mutation_number == self.mutation_attempts:
            self.fail_before_mutation_number = None
            raise RuntimeError("injected pre-dispatch failure")
        return self.mutation_attempts

    def after_mutation(self, mutation_number: int) -> None:
        if self.fail_after_mutation_number == mutation_number:
            self.fail_after_mutation_number = None
            raise RuntimeError("injected ambiguous dispatch failure")


class FakeRegistryClient:
    def __init__(
        self,
        server: FakeRegistryServer,
        credential: FakeCredential,
        *,
        expected_username: str,
        expected_account_id: str | None = None,
        timeout_seconds: float = 5.0,
    ) -> None:
        del timeout_seconds
        self.server = server
        self.credential = credential
        self.expected_username = expected_username
        self.expected_account_id = expected_account_id
        self.closed = False
        self.session = None
        server.clients.append(self)

    def __enter__(self) -> "FakeRegistryClient":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def close(self) -> None:
        self.credential.close()
        self.closed = True

    def discover(self) -> object:
        if (
            self.credential.kind == "basic"
            and self.expected_username != "recovery-admin"
        ):
            supplied_username = bytes(self.credential.buffers[0]).decode()
            supplied_password = bytes(self.credential.buffers[1]).decode()
            local_part = supplied_username.partition("@")[0]
            matches = [
                object_id
                for object_id, value in self.server.objects["Account"].items()
                if value.get("name") == local_part
            ]
            if (
                supplied_username != self.expected_username
                or len(matches) != 1
                or supplied_password
                not in self.server.password_secrets.get(matches[0], {}).values()
            ):
                raise FakeRegistryAuthenticationError(
                    "fixed authentication rejection",
                )
            account_id = matches[0]
        else:
            account_id = (
                "recovery-account"
                if self.credential.kind == "basic"
                else self.expected_account_id
            )
        if account_id is None:
            raise AssertionError("Bearer client omitted expected Account")
        if (
            self.expected_account_id is not None
            and account_id != self.expected_account_id
        ):
            raise FakeRegistryAuthenticationError(
                "fixed authentication rejection",
            )
        self.session = SimpleNamespace(
            username=self.expected_username,
            account_id=account_id,
            api_path="/jmap/",
        )
        self.server.calls.append(
            ("discover", self.credential.kind, self.expected_username, account_id),
        )
        return self.session

    def query_named_ids(
        self,
        object_type: str,
        name: str,
        *,
        page_limit: int = 100,
    ) -> tuple[str, ...]:
        self.server.calls.append(
            ("query", object_type, name, page_limit),
        )
        return tuple(
            object_id
            for object_id, value in self.server.objects[object_type].items()
            if value.get("name") == name
        )

    def query_described_ids(
        self,
        object_type: str,
        description: str,
        *,
        page_limit: int = 100,
    ) -> tuple[str, ...]:
        self.server.calls.append(
            ("query-description", object_type, description, page_limit),
        )
        return tuple(
            object_id
            for object_id, value in self.server.objects[object_type].items()
            if value.get("description") == description
        )

    def get_one(
        self,
        object_type: str,
        object_id: str,
        *,
        properties: object = None,
        account_id: str | None = None,
    ) -> FakeRegistryObject:
        del properties
        self.server.calls.append(("get", object_type, object_id, account_id))
        values = self.server.objects[object_type]
        if object_id not in values:
            raise FakeRegistryNotFound(f"{object_type}:{object_id}")
        value = json.loads(json.dumps(values[object_id]))
        if object_type == "Account":
            value["credentials"] = self.server.account_credentials(object_id)
        return FakeRegistryObject(
            object_type,
            object_id,
            (
                "recovery-account"
                if account_id is None
                else account_id
            ),
            value,
        )

    def get_singleton(
        self,
        object_type: str,
        *,
        properties: object = None,
    ) -> FakeRegistryObject:
        return self.get_one(
            object_type,
            "singleton",
            properties=properties,
        )

    def query_credential_ids(
        self,
        credential_type: str,
        owner_account_id: str,
        *,
        page_limit: int = 100,
    ) -> tuple[str, ...]:
        self.server.credential_query_attempts += 1
        self.server.calls.append(
            (
                "query-credentials",
                credential_type,
                owner_account_id,
                page_limit,
            ),
        )
        if (
            self.server.fail_credential_query_number
            == self.server.credential_query_attempts
        ):
            self.server.fail_credential_query_number = None
            raise RuntimeError(
                "injected credential inventory query failure",
            )
        override = self.server.credential_query_overrides.get(
            (credential_type, owner_account_id),
        )
        if override is not None:
            return override
        return tuple(
            credential_id
            for credential_id, value in self.server.credentials.get(
                owner_account_id,
                {},
            ).items()
            if value.get("@type") == credential_type
        )

    def create(
        self,
        object_type: str,
        value: dict[str, object],
        *,
        account_id: str | None = None,
    ) -> object:
        mutation_number = self.server.before_mutation()
        self.server.calls.append(
            ("create", object_type, json.loads(json.dumps(value)), account_id),
        )
        object_id = (
            "singleton"
            if object_type
            in {
                "Authentication",
                "MtaStageAuth",
                "MtaStageRcpt",
                "SystemSettings",
            }
            else self.server._id(object_type.lower())
        )
        copied = json.loads(json.dumps(value))
        credentials = copied.pop("credentials", None)
        self.server.objects[object_type][object_id] = copied
        if object_type == "Account":
            self.server.credentials[object_id] = {}
            self.server.password_secrets[object_id] = {}
            if isinstance(credentials, dict):
                for map_key, credential in credentials.items():
                    item = json.loads(json.dumps(credential))
                    secret = item.get("secret")
                    if item.get("@type") == "Password" and isinstance(
                        secret,
                        str,
                    ):
                        self.server.password_secrets[object_id][map_key] = (
                            secret
                        )
                    item["credentialId"] = self.server._id("password")
                    item["secret"] = "****"
                    self.server.credentials[object_id][map_key] = item
            if (
                self.server.add_password_to_management_account
                and copied.get("name") == "dashboard-management"
            ):
                self.server.credentials[object_id]["unexpected-password"] = {
                    "@type": "Password",
                    "allowedIps": {},
                    "credentialId": self.server._id("password"),
                    "secret": "****",
                }
            if (
                self.server.hard_exit_after_account_create_name_once
                == copied.get("name")
            ):
                self.server.hard_exit_after_account_create_name_once = None
                raise SystemExit("injected hard routing Account crash")
            if (
                self.server.fail_after_account_create_name_once
                == copied.get("name")
            ):
                self.server.fail_after_account_create_name_once = None
                raise RuntimeError(
                    "injected ambiguous Account create failure",
                )
        self.server.after_mutation(mutation_number)
        return SimpleNamespace(
            operation="create",
            object_type=object_type,
            object_id=object_id,
            account_id="recovery-account",
        )

    def create_api_key(
        self,
        owner_account_id: str,
        value: dict[str, object],
    ) -> FakeApiKeyCreation:
        mutation_number = self.server.before_mutation()
        self.server.calls.append(
            (
                "create-api-key",
                owner_account_id,
                json.loads(json.dumps(value)),
            ),
        )
        credential_id = self.server._id("api-key")
        self.server.credentials[owner_account_id][credential_id] = {
            "@type": "ApiKey",
            "allowedIps": json.loads(json.dumps(value["allowedIps"])),
            "credentialId": credential_id,
            "description": value["description"],
            "permissions": json.loads(json.dumps(value["permissions"])),
            "secret": "****",
        }
        if self.server.fail_after_api_key_create_once:
            self.server.fail_after_api_key_create_once = False
            raise RuntimeError("injected ambiguous API-key create failure")
        self.server.after_mutation(mutation_number)
        return FakeApiKeyCreation(owner_account_id, credential_id)

    def update(
        self,
        object_type: str,
        object_id: str,
        patch: dict[str, object],
        *,
        account_id: str | None = None,
    ) -> object:
        mutation_number = self.server.before_mutation()
        self.server.calls.append(
            (
                "update",
                object_type,
                object_id,
                json.loads(json.dumps(patch)),
                account_id,
            ),
        )
        if object_type == "ApiKey":
            target = self.server.credentials[account_id][object_id]  # type: ignore[index]
        else:
            target = self.server.objects[object_type][object_id]
        for path, value in patch.items():
            if object_type == "Account" and path.startswith("credentials/"):
                credential_path = path.removeprefix("credentials/").split("/")
                map_key = credential_path[0]
                if not map_key or len(credential_path) > 2:
                    raise AssertionError("test credential patch is malformed")
                if len(credential_path) == 2:
                    if credential_path[1] != "secret" or not isinstance(
                        value,
                        str,
                    ):
                        raise AssertionError(
                            "test credential secret patch is malformed",
                        )
                    existing = self.server.credentials[object_id][map_key]
                    if existing.get("@type") != "Password":
                        raise AssertionError(
                            "test credential secret target is malformed",
                        )
                    self.server.password_secrets[object_id][map_key] = value
                    continue
                if value is None:
                    self.server.credentials[object_id].pop(map_key, None)
                    self.server.password_secrets[object_id].pop(map_key, None)
                    continue
                if not isinstance(value, dict):
                    raise AssertionError("test credential value is malformed")
                item = json.loads(json.dumps(value))
                secret = item.get("secret")
                if item.get("@type") == "Password" and isinstance(
                    secret,
                    str,
                ):
                    self.server.password_secrets[object_id][map_key] = secret
                item["credentialId"] = self.server._id("password")
                if "secret" in item:
                    item["secret"] = "****"
                self.server.credentials[object_id][map_key] = item
                continue
            parts = path.split("/")
            nested = target
            for part in parts[:-1]:
                child = nested.setdefault(part, {})
                if not isinstance(child, dict):
                    raise AssertionError("test patch path conflicts")
                nested = child
            nested[parts[-1]] = json.loads(json.dumps(value))
        self.server.after_mutation(mutation_number)
        return SimpleNamespace(
            operation="update",
            object_type=object_type,
            object_id=object_id,
            account_id=account_id or "recovery-account",
        )

    def destroy(
        self,
        object_type: str,
        object_id: str,
        *,
        account_id: str | None = None,
    ) -> object:
        mutation_number = self.server.before_mutation()
        self.server.calls.append(
            ("destroy", object_type, object_id, account_id),
        )
        if object_type in {"ApiKey", "AppPassword"}:
            del self.server.credentials[account_id][object_id]  # type: ignore[index]
            if (
                object_type == "AppPassword"
                and self.server.fail_after_app_password_destroy_once
                is not None
            ):
                failure = (
                    self.server.fail_after_app_password_destroy_once
                )
                self.server.fail_after_app_password_destroy_once = None
                raise failure
        else:
            del self.server.objects[object_type][object_id]
            if object_type == "Account":
                residual_app_passwords = {
                    credential_id: value
                    for credential_id, value in self.server.credentials.get(
                        object_id,
                        {},
                    ).items()
                    if value.get("@type") == "AppPassword"
                }
                if residual_app_passwords:
                    self.server.credentials[object_id] = (
                        residual_app_passwords
                    )
                else:
                    self.server.credentials.pop(object_id, None)
                    self.server.password_secrets.pop(object_id, None)
        self.server.after_mutation(mutation_number)
        return SimpleNamespace(
            operation="destroy",
            object_type=object_type,
            object_id=object_id,
            account_id=account_id or "recovery-account",
        )


class FakeMigrationPaths:
    def __init__(self, repository_root: Path) -> None:
        root = repository_root / "debug-dashboard" / ".runtime" / "stalwart-migration"
        self.repository_root = repository_root
        self.source_receipt = root / "latest-source.json"
        self.migration_script = root / "migrate_v016.py"
        self.dry_run_receipt = root / "dry-run.json"
        self.reviewed = root / "reviewed.json"
        self.apply_receipt = root / "apply.json"


class ProductionRoutingRunnerTest(unittest.TestCase):
    DESCENDANT_CODE = (
        "import os\n"
        "from pathlib import Path\n"
        "import signal\n"
        "import sys\n"
        "import time\n"
        "pid_path = Path(sys.argv[1])\n"
        "termination_path = Path(sys.argv[2])\n"
        "def record_termination(_signal_number, _frame):\n"
        "    termination_path.write_text('term', encoding='ascii')\n"
        "signal.signal(signal.SIGTERM, record_termination)\n"
        "pid_path.write_text(str(os.getpid()), encoding='ascii')\n"
        "time.sleep(10)\n"
    )
    DIRECT_CHILD_CODE = (
        "from pathlib import Path\n"
        "import subprocess\n"
        "import sys\n"
        "import time\n"
        "pid_path = Path(sys.argv[2])\n"
        "subprocess.Popen(\n"
        "    [\n"
        "        sys.executable,\n"
        "        '-c',\n"
        "        sys.argv[1],\n"
        "        str(pid_path),\n"
        "        sys.argv[3],\n"
        "    ],\n"
        "    stdin=subprocess.DEVNULL,\n"
        "    stdout=subprocess.DEVNULL,\n"
        "    stderr=subprocess.DEVNULL,\n"
        "    close_fds=True,\n"
        ")\n"
        "deadline = time.monotonic() + 5\n"
        "while not pid_path.is_file():\n"
        "    if time.monotonic() >= deadline:\n"
        "        raise RuntimeError('descendant did not start')\n"
        "    time.sleep(0.01)\n"
        "time.sleep(10)\n"
    )
    EXITING_DIRECT_CHILD_CODE = (
        "from pathlib import Path\n"
        "import os\n"
        "import subprocess\n"
        "import sys\n"
        "import time\n"
        "pid_path = Path(sys.argv[2])\n"
        "group_path = Path(sys.argv[3])\n"
        "stream_mode = sys.argv[4]\n"
        "stream = subprocess.DEVNULL if stream_mode == 'closed' else None\n"
        "subprocess.Popen(\n"
        "    [\n"
        "        sys.executable,\n"
        "        '-c',\n"
        "        sys.argv[1],\n"
        "        str(pid_path),\n"
        "        sys.argv[5],\n"
        "    ],\n"
        "    stdin=subprocess.DEVNULL,\n"
        "    stdout=stream,\n"
        "    stderr=stream,\n"
        "    close_fds=True,\n"
        ")\n"
        "group_path.write_text(str(os.getpgrp()), encoding='ascii')\n"
        "deadline = time.monotonic() + 5\n"
        "while not pid_path.is_file():\n"
        "    if time.monotonic() >= deadline:\n"
        "        raise RuntimeError('descendant did not start')\n"
        "    time.sleep(0.01)\n"
    )

    def process_tree_command(
        self,
        pid_path: Path,
        termination_path: Path,
    ) -> list[str]:
        return [
            sys.executable,
            "-c",
            self.DIRECT_CHILD_CODE,
            self.DESCENDANT_CODE,
            str(pid_path),
            str(termination_path),
        ]

    def exiting_parent_command(
        self,
        pid_path: Path,
        group_path: Path,
        termination_path: Path,
        *,
        stream_mode: str,
    ) -> list[str]:
        return [
            sys.executable,
            "-c",
            self.EXITING_DIRECT_CHILD_CODE,
            self.DESCENDANT_CODE,
            str(pid_path),
            str(group_path),
            stream_mode,
            str(termination_path),
        ]

    def process_is_alive(self, pid: int | None) -> bool:
        if pid is None:
            return False
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        return True

    def wait_for_process_exit(
        self,
        pid: int,
        *,
        timeout: float = 2,
    ) -> bool:
        deadline = time.monotonic() + timeout
        while self.process_is_alive(pid) and time.monotonic() < deadline:
            time.sleep(0.01)
        return not self.process_is_alive(pid)

    def kill_process(self, pid: int | None) -> None:
        if not self.process_is_alive(pid):
            return
        assert pid is not None
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            return
        self.wait_for_process_exit(pid)

    def process_group_is_alive(
        self,
        process_group: int | None,
    ) -> bool | None:
        if process_group is None:
            return False
        try:
            os.killpg(process_group, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return None
        return True

    def kill_process_group(self, process_group: int | None) -> None:
        if self.process_group_is_alive(process_group) is False:
            return
        assert process_group is not None
        try:
            os.killpg(process_group, signal.SIGKILL)
        except (PermissionError, ProcessLookupError):
            return

    def test_exited_parent_closed_stdio_descendant_is_reaped_before_failure(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            pid_path = directory / "descendant.pid"
            group_path = directory / "process-group.pid"
            termination_path = directory / "descendant.term"
            descendant_pid: int | None = None
            process_group: int | None = None

            try:
                with self.assertRaisesRegex(
                    bootstrap.BootstrapError,
                    "^routing verifier failed safely$",
                ):
                    bootstrap._production_routing_runner(
                        self.exiting_parent_command(
                            pid_path,
                            group_path,
                            termination_path,
                            stream_mode="closed",
                        ),
                        stdin=b"",
                        cwd=directory,
                        timeout=5,
                    )
                descendant_pid = int(
                    pid_path.read_text(encoding="ascii"),
                    10,
                )
                process_group = int(
                    group_path.read_text(encoding="ascii"),
                    10,
                )
                group_alive = self.process_group_is_alive(process_group)
                if group_alive is not None:
                    self.assertFalse(
                        group_alive,
                        "routing verifier process group survived runner failure",
                    )
                self.assertFalse(
                    self.process_is_alive(descendant_pid),
                    "routing verifier descendant was not reaped",
                )
                self.assertEqual(
                    termination_path.read_text(encoding="ascii"),
                    "term",
                )
            finally:
                if process_group is None and group_path.is_file():
                    process_group = int(
                        group_path.read_text(encoding="ascii"),
                        10,
                    )
                if descendant_pid is None and pid_path.is_file():
                    descendant_pid = int(
                        pid_path.read_text(encoding="ascii"),
                        10,
                    )
                self.kill_process_group(process_group)
                self.kill_process(descendant_pid)

    def test_exited_parent_inherited_stdio_descendant_is_reaped_before_failure(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            pid_path = directory / "descendant.pid"
            group_path = directory / "process-group.pid"
            termination_path = directory / "descendant.term"
            descendant_pid: int | None = None
            process_group: int | None = None

            try:
                with self.assertRaisesRegex(
                    bootstrap.BootstrapError,
                    "^routing verifier failed safely$",
                ):
                    bootstrap._production_routing_runner(
                        self.exiting_parent_command(
                            pid_path,
                            group_path,
                            termination_path,
                            stream_mode="inherited",
                        ),
                        stdin=b"",
                        cwd=directory,
                        timeout=1,
                    )
                descendant_pid = int(
                    pid_path.read_text(encoding="ascii"),
                    10,
                )
                process_group = int(
                    group_path.read_text(encoding="ascii"),
                    10,
                )
                group_alive = self.process_group_is_alive(process_group)
                if group_alive is not None:
                    self.assertFalse(
                        group_alive,
                        "routing verifier process group survived runner failure",
                    )
                self.assertFalse(
                    self.process_is_alive(descendant_pid),
                    "routing verifier descendant was not reaped",
                )
                self.assertEqual(
                    termination_path.read_text(encoding="ascii"),
                    "term",
                )
            finally:
                if process_group is None and group_path.is_file():
                    process_group = int(
                        group_path.read_text(encoding="ascii"),
                        10,
                    )
                if descendant_pid is None and pid_path.is_file():
                    descendant_pid = int(
                        pid_path.read_text(encoding="ascii"),
                        10,
                    )
                self.kill_process_group(process_group)
                self.kill_process(descendant_pid)

    def test_timeout_terminates_spawned_descendant(self) -> None:

        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            pid_path = directory / "descendant.pid"
            termination_path = directory / "descendant.term"
            descendant_pid: int | None = None

            try:
                with self.assertRaisesRegex(
                    bootstrap.BootstrapError,
                    "^routing verifier failed safely$",
                ):
                    bootstrap._production_routing_runner(
                        self.process_tree_command(
                            pid_path,
                            termination_path,
                        ),
                        stdin=b"",
                        cwd=directory,
                        timeout=1,
                    )
                descendant_pid = int(
                    pid_path.read_text(encoding="ascii"),
                    10,
                )
                self.assertTrue(
                    self.wait_for_process_exit(descendant_pid),
                    "routing verifier descendant survived timeout",
                )
                self.assertEqual(
                    termination_path.read_text(encoding="ascii"),
                    "term",
                )
            finally:
                self.kill_process(descendant_pid)

    @unittest.skipUnless(
        hasattr(signal, "setitimer"),
        "requires POSIX interval timers",
    )
    def test_keyboard_interrupt_terminates_spawned_descendant(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            pid_path = directory / "descendant.pid"
            termination_path = directory / "descendant.term"
            descendant_pid: int | None = None
            original_handler = signal.getsignal(signal.SIGALRM)

            def interrupt_runner(
                _signal_number: int,
                _frame: object,
            ) -> None:
                raise KeyboardInterrupt("routing cancellation canary")

            try:
                signal.signal(signal.SIGALRM, interrupt_runner)
                signal.setitimer(signal.ITIMER_REAL, 1)
                with self.assertRaises(KeyboardInterrupt) as raised:
                    bootstrap._production_routing_runner(
                        self.process_tree_command(
                            pid_path,
                            termination_path,
                        ),
                        stdin=b"",
                        cwd=directory,
                        timeout=5,
                    )
                signal.setitimer(signal.ITIMER_REAL, 0)
                self.assertEqual(
                    str(raised.exception),
                    "routing cancellation canary",
                )
                descendant_pid = int(
                    pid_path.read_text(encoding="ascii"),
                    10,
                )
                self.assertTrue(
                    self.wait_for_process_exit(descendant_pid),
                    "routing verifier descendant survived cancellation",
                )
                self.assertEqual(
                    termination_path.read_text(encoding="ascii"),
                    "term",
                )
            finally:
                signal.setitimer(signal.ITIMER_REAL, 0)
                signal.signal(signal.SIGALRM, original_handler)
                if descendant_pid is None and pid_path.is_file():
                    descendant_pid = int(
                        pid_path.read_text(encoding="ascii"),
                        10,
                    )
                self.kill_process(descendant_pid)

    def test_success_preserves_process_invocation_semantics(self) -> None:
        environment_name = "MAIL_SANDBOX_ROUTING_RUNNER_TEST"
        environment_value = "inherited-environment-value"
        code = (
            "import os\n"
            "from pathlib import Path\n"
            "import sys\n"
            "payload = sys.stdin.buffer.read()\n"
            "cwd = str(Path.cwd()).encode('utf-8')\n"
            f"environment = os.environ[{environment_name!r}].encode('ascii')\n"
            "sys.stdout.buffer.write(payload + b'|' + cwd + b'|' + environment)\n"
            "sys.stderr.buffer.write(b'bounded-stderr')\n"
            "raise SystemExit(7)\n"
        )
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory) / "routing cwd with spaces"
            directory.mkdir()
            with mock.patch.dict(
                os.environ,
                {environment_name: environment_value},
            ):
                result = bootstrap._production_routing_runner(
                    [sys.executable, "-c", code],
                    stdin=b"binary-stdin",
                    cwd=directory,
                    timeout=5,
                )

        self.assertEqual(result.returncode, 7)
        self.assertEqual(
            result.stdout,
            (
                b"binary-stdin|"
                + str(directory.resolve()).encode("utf-8")
                + b"|"
                + environment_value.encode("ascii")
            ),
        )
        self.assertEqual(result.stderr, b"bounded-stderr")

    def test_cleanup_reports_an_unreaped_direct_process(self) -> None:
        class Process:
            pid = 424242
            returncode = None

            def __init__(self) -> None:
                self.waits: list[float] = []

            def terminate(self) -> None:
                pass

            def kill(self) -> None:
                pass

            def wait(self, *, timeout: float) -> int:
                self.waits.append(timeout)
                raise bootstrap.subprocess.TimeoutExpired(
                    ["redacted-command-canary"],
                    timeout,
                )

        process = Process()
        with (
            mock.patch.object(bootstrap.os, "killpg"),
            mock.patch.object(
                bootstrap,
                "_bounded_routing_cleanup_pause",
            ),
            self.assertRaises(bootstrap._RoutingProcessFailure),
        ):
            bootstrap._terminate_routing_process_group(
                process,
                (None, None, None),
            )
        self.assertEqual(
            process.waits,
            [bootstrap.ROUTING_PROCESS_REAP_TIMEOUT_SECONDS] * 2,
        )

    def test_cleanup_preserves_stream_close_interrupt_after_reaping(
        self,
    ) -> None:
        interruption = KeyboardInterrupt("routing-close-canary")
        close_order: list[str] = []

        class Stream:
            def __init__(self, name: str, *, interrupt: bool = False) -> None:
                self.name = name
                self.interrupt = interrupt

            def close(self) -> None:
                close_order.append(self.name)
                if self.interrupt:
                    raise interruption

        class Process:
            pid = 454545
            returncode = None

            def __init__(self) -> None:
                self.waits: list[float] = []

            def wait(self, *, timeout: float) -> int:
                self.waits.append(timeout)
                self.returncode = 0
                return 0

            def poll(self) -> int:
                return 0

        process = Process()
        signals: list[int] = []
        with (
            mock.patch.object(
                bootstrap,
                "_signal_routing_process_group",
                side_effect=lambda _process, group_signal: signals.append(
                    group_signal,
                ),
            ),
            mock.patch.object(
                bootstrap,
                "_bounded_routing_cleanup_pause",
            ),
            self.assertRaises(KeyboardInterrupt) as raised,
        ):
            bootstrap._terminate_routing_process_group(
                process,
                (
                    Stream("stdin", interrupt=True),
                    Stream("stdout"),
                    Stream("stderr"),
                ),
            )

        self.assertIs(raised.exception, interruption)
        self.assertEqual(close_order, ["stdin", "stdout", "stderr"])
        self.assertEqual(signals, [signal.SIGTERM, signal.SIGKILL])
        self.assertEqual(
            process.waits,
            [bootstrap.ROUTING_PROCESS_REAP_TIMEOUT_SECONDS],
        )

    def test_cleanup_preserves_signal_interrupt_after_reaping(
        self,
    ) -> None:
        interruption = KeyboardInterrupt("routing-cleanup-canary")
        close_order: list[str] = []
        signal_attempts: list[int] = []

        class Stream:
            def __init__(self, name: str) -> None:
                self.name = name

            def close(self) -> None:
                close_order.append(self.name)

        class Process:
            pid = 464646
            returncode = None

            def __init__(self) -> None:
                self.waits: list[float] = []

            def wait(self, *, timeout: float) -> int:
                self.waits.append(timeout)
                self.returncode = 0
                return 0

            def poll(self) -> int:
                return 0

        def signal_process_group(
            _process: object,
            group_signal: int,
        ) -> None:
            signal_attempts.append(group_signal)
            if group_signal == signal.SIGTERM:
                raise interruption

        process = Process()
        with (
            mock.patch.object(
                bootstrap,
                "_signal_routing_process_group",
                side_effect=signal_process_group,
            ),
            mock.patch.object(
                bootstrap,
                "_bounded_routing_cleanup_pause",
            ),
            self.assertRaises(KeyboardInterrupt) as raised,
        ):
            bootstrap._terminate_routing_process_group(
                process,
                (
                    Stream("stdin"),
                    Stream("stdout"),
                    Stream("stderr"),
                ),
            )

        self.assertIs(raised.exception, interruption)
        self.assertEqual(close_order, ["stdin", "stdout", "stderr"])
        self.assertEqual(
            signal_attempts,
            [signal.SIGTERM, signal.SIGKILL],
        )
        self.assertEqual(
            process.waits,
            [bootstrap.ROUTING_PROCESS_REAP_TIMEOUT_SECONDS],
        )

    def test_cleanup_failure_does_not_replace_keyboard_interrupt(
        self,
    ) -> None:
        interruption = KeyboardInterrupt("routing cancellation canary")
        process = SimpleNamespace(
            pid=434343,
            returncode=None,
            stdin=io.BytesIO(),
            stdout=io.BytesIO(),
            stderr=io.BytesIO(),
        )
        with tempfile.TemporaryDirectory() as raw_directory:
            with (
                mock.patch.object(
                    bootstrap.subprocess,
                    "Popen",
                    return_value=process,
                ),
                mock.patch.object(
                    bootstrap,
                    "_communicate_with_routing_process",
                    side_effect=interruption,
                ),
                mock.patch.object(
                    bootstrap,
                    "_terminate_routing_process_group",
                    side_effect=bootstrap._RoutingProcessFailure,
                ),
                self.assertRaises(KeyboardInterrupt) as raised,
            ):
                bootstrap._production_routing_runner(
                    ["/unit/routing-verifier"],
                    stdin=b"",
                    cwd=Path(raw_directory),
                    timeout=5,
                )
        self.assertIs(raised.exception, interruption)

    def test_cleanup_failure_keeps_regular_errors_redacted(self) -> None:
        cleanup_canary = "routing-cleanup-secret-canary"
        process = SimpleNamespace(
            pid=444444,
            returncode=None,
            stdin=io.BytesIO(),
            stdout=io.BytesIO(),
            stderr=io.BytesIO(),
        )
        with tempfile.TemporaryDirectory() as raw_directory:
            with (
                mock.patch.object(
                    bootstrap.subprocess,
                    "Popen",
                    return_value=process,
                ),
                mock.patch.object(
                    bootstrap,
                    "_communicate_with_routing_process",
                    side_effect=bootstrap._RoutingProcessFailure,
                ),
                mock.patch.object(
                    bootstrap,
                    "_terminate_routing_process_group",
                    side_effect=RuntimeError(cleanup_canary),
                ),
                self.assertRaisesRegex(
                    bootstrap.BootstrapError,
                    "^routing verifier failed safely$",
                ) as raised,
            ):
                bootstrap._production_routing_runner(
                    ["/unit/routing-verifier"],
                    stdin=b"",
                    cwd=Path(raw_directory),
                    timeout=5,
                )
        self.assertNotIn(cleanup_canary, str(raised.exception))

    def test_stdout_and_stderr_are_hard_capped(self) -> None:
        canary = "routing-output-limit-secret-canary"
        code = (
            "import os\n"
            "import sys\n"
            "descriptor = int(sys.argv[1])\n"
            "size = int(sys.argv[2])\n"
            "canary = sys.argv[3].encode('ascii')\n"
            "payload = canary * (size // len(canary) + 1)\n"
            "payload = payload[:size + 1]\n"
            "offset = 0\n"
            "while offset < len(payload):\n"
            "    offset += os.write(descriptor, payload[offset:])\n"
        )
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            for descriptor in (1, 2):
                with self.subTest(descriptor=descriptor):
                    with self.assertRaisesRegex(
                        bootstrap.BootstrapError,
                        "^routing verifier failed safely$",
                    ) as raised:
                        bootstrap._production_routing_runner(
                            [
                                sys.executable,
                                "-c",
                                code,
                                str(descriptor),
                                str(bootstrap.MAXIMUM_JSON_SIZE),
                                canary,
                            ],
                            stdin=b"",
                            cwd=directory,
                            timeout=5,
                        )
                    self.assertNotIn(canary, str(raised.exception))


class FreshInitializationTest(unittest.TestCase):
    CURRENT_IMAGE = (
        "stalwartlabs/stalwart:v0.16.17@"
        "sha256:a8108e19bd927e172d4d8c128907b8dfc93fd180ae8ee07dccdd42cb97eb9dfa"
    )
    CURRENT_CONFIG_BYTES = (
        b'{\n'
        b'  "@type": "RocksDb",\n'
        b'  "path": "/var/lib/stalwart"\n'
        b'}'
    )

    def test_migrated_current_finalizer_is_idempotent_and_rejects_bad_receipt(
        self,
    ) -> None:
        current_state = object()
        invalid_state = object()
        runtime_state = SimpleNamespace(
            RuntimeState=SimpleNamespace(
                CURRENT=current_state,
                INVALID=invalid_state,
            ),
            RECEIPT_RELATIVE=(
                Path("debug-dashboard")
                / ".runtime"
                / "stalwart"
                / "current.json"
            ),
            classify_repository=mock.Mock(return_value=current_state),
            publish_current_receipt=mock.Mock(),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            receipt = root / runtime_state.RECEIPT_RELATIVE
            receipt.parent.mkdir(parents=True)
            write_file(receipt, b"valid\n", 0o600)
            with mock.patch.object(
                bootstrap,
                "_load_sibling_module",
                return_value=runtime_state,
            ):
                self.assertEqual(
                    bootstrap.finalize_migrated_current_runtime(root),
                    receipt,
                )
            runtime_state.publish_current_receipt.assert_not_called()

            receipt.unlink()
            runtime_state.classify_repository.side_effect = [
                invalid_state,
                current_state,
            ]
            runtime_state.publish_current_receipt.return_value = receipt
            with mock.patch.object(
                bootstrap,
                "_load_sibling_module",
                return_value=runtime_state,
            ):
                self.assertEqual(
                    bootstrap.finalize_migrated_current_runtime(root),
                    receipt,
                )
            runtime_state.publish_current_receipt.assert_called_once_with(root)

            runtime_state.publish_current_receipt.reset_mock()
            runtime_state.classify_repository.side_effect = None
            runtime_state.classify_repository.return_value = invalid_state
            write_file(receipt, b"malformed\n", 0o600)
            with (
                mock.patch.object(
                    bootstrap,
                    "_load_sibling_module",
                    return_value=runtime_state,
                ),
                self.assertRaises(bootstrap.BootstrapError),
            ):
                bootstrap.finalize_migrated_current_runtime(root)
            runtime_state.publish_current_receipt.assert_not_called()

    def dependencies(
        self,
        events: list[object],
        states: list[str],
        *,
        fail_at: str | None = None,
    ) -> object:
        def step(name: str, result: object = None):
            def run(*args: object) -> object:
                events.append((name, *args))
                if fail_at == name:
                    raise RuntimeError("secret failure detail")
                return result

            return run

        def classify(repository: Path) -> str:
            events.append(("classify", repository))
            return states.pop(0)

        class OperationLock:
            def __enter__(self) -> "OperationLock":
                events.append(("enter-lock",))
                return self

            def __exit__(self, *_args: object) -> None:
                events.append(("release-lock",))

            def assert_valid_for(self, repository: Path) -> None:
                events.append(("assert-lock", repository))

        def acquire_lock(repository: Path) -> OperationLock:
            events.append(("acquire-lock", repository))
            if fail_at == "acquire-lock":
                raise bootstrap.BootstrapError("operation lock is held")
            return OperationLock()

        arguments = dict(
            classify=classify,
            validate_definition=step("validate-definition"),
            prepare=step("prepare"),
            start_recovery=step("start-recovery"),
            apply_contract=step("apply-contract"),
            prove=step("prove"),
            stop_recovery=step("stop-recovery"),
            start_normal=step("start-normal"),
            restart_normal=step("restart-normal"),
            stop_normal=step("stop-normal"),
            publish_receipt=step(
                "publish-receipt",
                Path("/unit/current.json"),
            ),
            mark_invalid=step("mark-invalid"),
        )
        if (
            "acquire_operation_lock"
            in bootstrap.FreshInitializationDependencies.__dataclass_fields__
        ):
            arguments["acquire_operation_lock"] = acquire_lock
        return bootstrap.FreshInitializationDependencies(**arguments)

    def test_initialize_fresh_orders_proofs_restart_and_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            events: list[object] = []
            dependencies = self.dependencies(
                events,
                ["fresh", "current"],
            )

            receipt = bootstrap.initialize_fresh(
                root,
                dependencies=dependencies,
            )

            self.assertEqual(receipt, Path("/unit/current.json"))
            self.assertEqual(
                [
                    event[0]
                    for event in events
                    if event[0]
                    not in {
                        "acquire-lock",
                        "enter-lock",
                        "assert-lock",
                        "release-lock",
                    }
                ],
                [
                    "classify",
                    "validate-definition",
                    "mark-invalid",
                    "prepare",
                    "start-recovery",
                    "apply-contract",
                    "prove",
                    "stop-recovery",
                    "start-normal",
                    "prove",
                    "restart-normal",
                    "prove",
                    "publish-receipt",
                    "classify",
                ],
            )
            self.assertEqual(
                [event[2] for event in events if event[0] == "prove"],
                ["recovery", "normal", "restarted"],
            )

    def test_legacy_hold_refuses_before_any_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            events: list[object] = []
            dependencies = self.dependencies(events, ["fresh"])
            dependencies.validate_definition = (
                lambda repository: (
                    events.append(("validate-definition", repository)),
                    (_ for _ in ()).throw(
                        bootstrap.BootstrapError(
                            "root Compose is not the current runtime",
                        ),
                    ),
                )[-1]
            )

            with self.assertRaisesRegex(
                bootstrap.BootstrapError,
                "root Compose is not the current runtime",
            ):
                bootstrap.initialize_fresh(
                    root,
                    dependencies=dependencies,
                )

            self.assertEqual(
                [
                    event[0]
                    for event in events
                    if event[0]
                    not in {
                        "acquire-lock",
                        "enter-lock",
                        "assert-lock",
                        "release-lock",
                    }
                ],
                ["classify", "validate-definition"],
            )

    def test_failure_after_prepare_stops_and_marks_store_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            events: list[object] = []
            dependencies = self.dependencies(
                events,
                ["fresh", "invalid"],
                fail_at="apply-contract",
            )

            with self.assertRaisesRegex(
                bootstrap.BootstrapError,
                "fresh Stalwart initialization failed safely",
            ) as raised:
                bootstrap.initialize_fresh(
                    root,
                    dependencies=dependencies,
                )

            self.assertNotIn("secret failure detail", str(raised.exception))
            self.assertEqual(
                [
                    event[0]
                    for event in events
                    if event[0]
                    not in {
                        "acquire-lock",
                        "enter-lock",
                        "assert-lock",
                        "release-lock",
                    }
                ],
                [
                    "classify",
                    "validate-definition",
                    "mark-invalid",
                    "prepare",
                    "start-recovery",
                    "apply-contract",
                    "stop-normal",
                    "stop-recovery",
                    "mark-invalid",
                    "classify",
                ],
            )

    def test_failure_publishing_initial_invalid_marker_does_not_stop_services(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            events: list[object] = []
            dependencies = self.dependencies(
                events,
                ["fresh"],
                fail_at="mark-invalid",
            )

            with self.assertRaisesRegex(
                bootstrap.BootstrapError,
                "fresh Stalwart initialization failed safely",
            ):
                bootstrap.initialize_fresh(
                    root,
                    dependencies=dependencies,
                )

            self.assertEqual(
                [
                    event[0]
                    for event in events
                    if event[0]
                    not in {
                        "acquire-lock",
                        "enter-lock",
                        "assert-lock",
                        "release-lock",
                    }
                ],
                [
                    "classify",
                    "validate-definition",
                    "mark-invalid",
                ],
            )

    def test_initialize_fresh_holds_operation_lock_across_full_transition(
        self,
    ) -> None:
        self.assertIn(
            "acquire_operation_lock",
            bootstrap.FreshInitializationDependencies.__dataclass_fields__,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            events: list[object] = []

            bootstrap.initialize_fresh(
                root,
                dependencies=self.dependencies(
                    events,
                    ["fresh", "current"],
                ),
            )

            names = [event[0] for event in events]
            self.assertEqual(names[0:3], [
                "acquire-lock",
                "enter-lock",
                "assert-lock",
            ])
            self.assertLess(names.index("classify"), names.index("mark-invalid"))
            self.assertLess(names.index("mark-invalid"), names.index("prepare"))
            self.assertLess(names.index("publish-receipt"), names.index("release-lock"))
            self.assertEqual(names[-1], "release-lock")

    def test_initialize_fresh_lock_contention_prevents_classification_or_mutation(
        self,
    ) -> None:
        self.assertIn(
            "acquire_operation_lock",
            bootstrap.FreshInitializationDependencies.__dataclass_fields__,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            events: list[object] = []

            with self.assertRaisesRegex(
                bootstrap.BootstrapError,
                "operation lock is held",
            ):
                bootstrap.initialize_fresh(
                    root,
                    dependencies=self.dependencies(
                        events,
                        [],
                        fail_at="acquire-lock",
                    ),
                )

            self.assertEqual(
                [event[0] for event in events],
                ["acquire-lock"],
            )

    def test_production_failure_marker_uses_runtime_state_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            publish = mock.Mock(
                return_value=(
                    root
                    / "stalwart-data"
                    / ".mail-sandbox-fresh-initialization-failed"
                ),
            )
            runtime = bootstrap._ProductionFreshRuntime(
                migration=object(),
                registry=object(),
                runtime_state=SimpleNamespace(
                    publish_failure_marker=publish,
                ),
            )

            runtime.mark_invalid(root)

            publish.assert_called_once_with(root)

    def test_definition_rejects_unsafe_or_noncanonical_config_before_compose(
        self,
    ) -> None:
        cases = ("missing", "wrong-bytes", "wrong-mode", "symlink")
        for case in cases:
            with self.subTest(case=case), TemporaryRepository() as repository:
                config = repository.root / "stalwart" / "config.json"
                if case == "wrong-bytes":
                    write_file(config, b"{}", 0o644)
                elif case == "wrong-mode":
                    write_file(config, self.CURRENT_CONFIG_BYTES, 0o600)
                elif case == "symlink":
                    target = repository.root / "outside-config.json"
                    write_file(target, self.CURRENT_CONFIG_BYTES, 0o644)
                    config.symlink_to(target)
                runtime = bootstrap._ProductionFreshRuntime(
                    migration=object(),
                    registry=object(),
                    runtime_state=SimpleNamespace(
                        CURRENT_IMAGE=self.CURRENT_IMAGE,
                        CURRENT_CONFIG_BYTES=self.CURRENT_CONFIG_BYTES,
                    ),
                )
                with (
                    mock.patch.object(
                        bootstrap,
                        "_run_fresh_command",
                        return_value=b"{}",
                    ) as run,
                    self.assertRaises(bootstrap.BootstrapError),
                ):
                    runtime.validate_definition(repository.root)
                run.assert_not_called()

    def test_definition_accepts_exact_plain_config_before_render_validation(
        self,
    ) -> None:
        with TemporaryRepository() as repository:
            config = repository.root / "stalwart" / "config.json"
            write_file(config, self.CURRENT_CONFIG_BYTES, 0o644)
            runtime = bootstrap._ProductionFreshRuntime(
                migration=object(),
                registry=object(),
                runtime_state=SimpleNamespace(
                    CURRENT_IMAGE=self.CURRENT_IMAGE,
                    CURRENT_CONFIG_BYTES=self.CURRENT_CONFIG_BYTES,
                ),
            )
            with (
                mock.patch.object(
                    bootstrap,
                    "_run_fresh_command",
                    return_value=b"rendered",
                ) as run,
                mock.patch.object(
                    bootstrap,
                    "_validate_fresh_compose_model",
                ) as validate,
            ):
                runtime.validate_definition(repository.root)

            run.assert_called_once()
            validate.assert_called_once_with(
                b"rendered",
                repository=repository.root,
                current_image=self.CURRENT_IMAGE,
            )

    def test_prepare_accepts_only_the_authoritative_fresh_failure_marker(
        self,
    ) -> None:
        marker_name = ".mail-sandbox-fresh-initialization-failed"
        with TemporaryRepository() as repository:
            store = repository.root / "stalwart-data"
            store.mkdir(mode=0o700)
            marker = store / marker_name
            write_file(marker, b"invalid\n", 0o600)
            runtime = bootstrap._ProductionFreshRuntime(
                migration=SimpleNamespace(
                    ensure_owner_directory=lambda *_args, **_kwargs: None,
                ),
                registry=object(),
                runtime_state=object(),
            )

            runtime.prepare(repository.root)

            self.assertEqual(marker.read_bytes(), b"invalid\n")
            self.assertEqual(stat.S_IMODE(marker.stat().st_mode), 0o600)
            self.assertTrue(
                (
                    repository.root
                    / bootstrap.FRESH_RECOVERY_ENV_RELATIVE
                ).is_file(),
            )

        with TemporaryRepository() as repository:
            store = repository.root / "stalwart-data"
            store.mkdir(mode=0o700)
            write_file(store / marker_name, b"invalid\n", 0o600)
            write_file(store / "unexpected", b"data", 0o600)
            runtime = bootstrap._ProductionFreshRuntime(
                migration=SimpleNamespace(
                    ensure_owner_directory=lambda *_args, **_kwargs: None,
                ),
                registry=object(),
                runtime_state=object(),
            )
            with self.assertRaises(bootstrap.BootstrapError):
                runtime.prepare(repository.root)

    def test_rendered_root_definition_is_exact_image_ports_and_mounts(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            runtime = root / "debug-dashboard" / ".runtime"
            network_directory = runtime / "stalwart"
            network_directory.mkdir(parents=True)
            runtime.chmod(0o700)
            network_directory.chmod(0o700)
            write_file(
                network_directory / "network.env",
                b"STALWART_PUBLIC_URL=http://192.168.86.36:8443\n",
                0o600,
            )
            service = {
                "command": None,
                "container_name": "stalwart-dev",
                "entrypoint": None,
                "environment": {
                    "STALWART_PUBLIC_URL": "http://192.168.86.36:8443",
                },
                "healthcheck": {
                    "test": [
                        "CMD",
                        "curl",
                        "-fsS",
                        "http://127.0.0.1:8080/healthz/ready",
                    ],
                    "timeout": "2s",
                    "interval": "2s",
                    "retries": 30,
                    "start_period": "2s",
                },
                "image": self.CURRENT_IMAGE,
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
                        "source": str(root / "stalwart"),
                        "target": "/etc/stalwart",
                        "type": "bind",
                    },
                    {
                        "bind": {},
                        "source": str(root / "stalwart-data"),
                        "target": "/var/lib/stalwart",
                        "type": "bind",
                    },
                ],
            }

            bootstrap._validate_fresh_compose_model(
                json.dumps(
                    {
                        "name": "fresh-project",
                        "networks": {
                            "default": {
                                "name": "fresh-project_default",
                                "ipam": {},
                            },
                        },
                        "services": {"stalwart": service},
                    },
                ).encode(),
                repository=root,
                current_image=self.CURRENT_IMAGE,
            )

            mutations = {
                "floating-image": lambda value: value.update(
                    {"image": "stalwartlabs/stalwart:latest"},
                ),
                "missing-smtp": lambda value: value["ports"].pop(),
                "loopback-jmap": lambda value: value["ports"][0].update(
                    {"host_ip": "127.0.0.1"},
                ),
                "wrong-store": lambda value: value["volumes"][1].update(
                    {"source": str(root / "copy")},
                ),
                "recovery-env": lambda value: value["environment"].update(
                    {"STALWART_RECOVERY_MODE": "1"},
                ),
                "privileged": lambda value: value.update(
                    {"privileged": True},
                ),
                "host-network": lambda value: value.update(
                    {"network_mode": "host"},
                ),
                "command": lambda value: value.update(
                    {"command": ["sh", "-c", "sleep infinity"]},
                ),
            }
            for label, mutate in mutations.items():
                with self.subTest(label=label):
                    changed = json.loads(json.dumps(service))
                    mutate(changed)
                    with self.assertRaises(bootstrap.BootstrapError):
                        bootstrap._validate_fresh_compose_model(
                            json.dumps(
                                {
                                    "name": "fresh-project",
                                    "networks": {
                                        "default": {
                                            "name": "fresh-project_default",
                                            "ipam": {},
                                        },
                                    },
                                    "services": {"stalwart": changed},
                                },
                            ).encode(),
                            repository=root,
                            current_image=self.CURRENT_IMAGE,
                        )

            extra_service = {
                "name": "fresh-project",
                "networks": {
                    "default": {
                        "name": "fresh-project_default",
                        "ipam": {},
                    },
                },
                "services": {
                    "stalwart": service,
                    "shadow": {"image": "example.invalid/shadow:fixed"},
                },
            }
            with self.assertRaises(bootstrap.BootstrapError):
                bootstrap._validate_fresh_compose_model(
                    json.dumps(extra_service).encode(),
                    repository=root,
                    current_image=self.CURRENT_IMAGE,
                )

            (network_directory / "network.env").write_bytes(
                b"STALWART_PUBLIC_URL=http://192.168.86.37:8443\n",
            )
            (network_directory / "network.env").chmod(0o600)
            with self.assertRaises(bootstrap.BootstrapError):
                bootstrap._validate_fresh_compose_model(
                    json.dumps(
                        {
                            "name": "fresh-project",
                            "networks": {
                                "default": {
                                    "name": "fresh-project_default",
                                    "ipam": {},
                                },
                            },
                            "services": {"stalwart": service},
                        },
                    ).encode(),
                    repository=root,
                    current_image=self.CURRENT_IMAGE,
                )

    def test_normal_proof_uses_loopback_transport_and_current_lan_api_url(
        self,
    ) -> None:
        events: list[object] = []

        def jmap_probe(
            credential: memoryview,
            *,
            expected_api_url: str,
        ) -> object:
            events.append(
                (
                    "jmap",
                    bytes(credential),
                    expected_api_url,
                ),
            )
            return SimpleNamespace(
                status=200,
                account_id="management-account",
                username=bootstrap.MANAGEMENT_ADDRESS,
            )

        class Smtp:
            def __init__(self, host: str, port: int, *, timeout: float) -> None:
                events.append(("smtp-connect", host, port, timeout))

            def __enter__(self) -> "Smtp":
                return self

            def __exit__(self, *_args: object) -> None:
                events.append(("smtp-close",))

            def ehlo(self) -> None:
                events.append(("ehlo",))

            def login(self, username: str, password: str) -> None:
                events.append(("login", username, password))

            def noop(self) -> tuple[int, bytes]:
                return 250, b"ok"

        with TemporaryRepository() as repository:
            runtime = bootstrap._ProductionFreshRuntime(
                migration=SimpleNamespace(
                    run_fixed_normal_basic_jmap_auth_probe=jmap_probe,
                ),
                registry=object(),
                runtime_state=object(),
            )
            with (
                mock.patch.object(
                    runtime,
                    "_protected_account_id",
                    return_value="management-account",
                ),
                mock.patch.object(bootstrap.smtplib, "SMTP", Smtp),
                mock.patch.object(bootstrap.time, "sleep"),
            ):
                runtime.prove(repository.root, "normal")

        self.assertEqual(
            events,
            [
                (
                    "jmap",
                    b"dashboard-management@local.test:secret",
                    "http://192.168.86.36:8443/jmap/",
                ),
                ("smtp-connect", "127.0.0.1", 8587, 5.0),
                ("ehlo",),
                (
                    "login",
                    "dashboard-management@local.test",
                    "secret",
                ),
                ("smtp-close",),
            ],
        )

class ProductionOrchestratorTest(unittest.TestCase):
    STARTED = "2026-07-28T12:00:00Z"
    INVOCATION = "0123456789abcdef0123456789abcdef"

    def test_account_inventory_accepts_only_the_pinned_four_star_mask(
        self,
    ) -> None:
        def account(secret: object) -> dict[str, object]:
            return {
                "credentials": {
                    "management-key": {
                        "@type": "ApiKey",
                        "allowedIps": {},
                        "credentialId": "management-key",
                        "secret": secret,
                    },
                },
            }

        credentials = bootstrap._complete_account_credentials(
            "management-account",
            account("****"),
        )
        self.assertEqual(len(credentials), 1)
        self.assertEqual(credentials[0].credential_id, "management-key")

        for invalid in ("********", "plaintext-secret", "", 4):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(
                bootstrap.BootstrapError,
                "exposed a secret",
            ):
                bootstrap._complete_account_credentials(
                    "management-account",
                    account(invalid),
                )

    def test_account_inventory_redacts_non_scalar_mask_failures(
        self,
    ) -> None:
        for invalid in (
            ["mask-shape-canary"],
            {"unexpected": "mask-shape-canary"},
        ):
            with self.subTest(kind=type(invalid).__name__):
                account = {
                    "credentials": {
                        "management-key": {
                            "@type": "ApiKey",
                            "allowedIps": {},
                            "credentialId": "management-key",
                            "secret": invalid,
                        },
                    },
                }
                with self.assertRaises(bootstrap.BootstrapError) as raised:
                    bootstrap._complete_account_credentials(
                        "management-account",
                        account,
                    )
                self.assertNotIn(
                    "mask-shape-canary",
                    str(raised.exception),
                )

    def routing_output(self, routing_input: dict[str, object]) -> bytes:
        invocation = routing_input["invocation_id"]
        actors_input = routing_input["actors"]
        assert isinstance(actors_input, dict)
        actors = {
            role: {
                **actors_input[role],
                "app_password_credential_id": f"{role}-app-password",
            }
            for role in ("recipient", "sender")
        }
        recipient = actors["recipient"]
        message_id = f"<mail-sandbox-routing-{invocation}@local.test>"

        def rejected(
            recipient_address: str,
            submission: str,
            enhanced: str,
        ) -> dict[str, object]:
            return {
                "delivery_status": "no",
                "enhanced_status": enhanced,
                "queue_accepted": False,
                "recipient": recipient_address,
                "smtp_code": 550,
                "submission_created": True,
                "submission_id": submission,
                "undo_status": "pending",
            }

        payload = {
            **routing_input,
            "actors": actors,
            "message_id": message_id,
            "probes": {
                "external": rejected(
                    f"dashboard-routing-{invocation}@example.invalid",
                    "external-submission",
                    "5.1.2",
                ),
                "protected_exact": rejected(
                    "dashboard-management@local.test",
                    "protected-exact-submission",
                    "5.7.1",
                ),
                "protected_subaddress": rejected(
                    f"dashboard-management+routing-{invocation}@local.test",
                    "protected-subaddress-submission",
                    "5.7.1",
                ),
                "registered_local": {
                    "arrival": {
                        "account_id": recipient["account_id"],
                        "matching_email_ids": ["recipient-email-id"],
                        "message_id": message_id,
                    },
                    "delivery_status": "unknown",
                    "enhanced_status": "2.1.5",
                    "queue_accepted": True,
                    "recipient": recipient["address"],
                    "smtp_code": 250,
                    "submission_created": True,
                    "submission_id": "registered-submission",
                    "undo_status": "final",
                },
                "unregistered_local": rejected(
                    f"dashboard-routing-missing-{invocation}@local.test",
                    "unregistered-submission",
                    "5.1.2",
                ),
            },
            "proven_at": self.STARTED,
            "recipient_access_removed": {
                "authentication_status": 401,
                "credential_id": "recipient-app-password",
                "projected_state": "enrollmentRequired",
                "readiness_preflight": {
                    "submission_calls": 0,
                    "upload_calls": 0,
                },
            },
            "schema": "mail-sandbox.stalwart-v016-routing-verifier.v1",
        }
        return canonical_json(payload) + b"\n"

    def routing_input(self) -> dict[str, object]:
        return {
            "actors": {
                "recipient": {
                    "account_id": "recipient-account",
                    "address": (
                        "dashboard-routing-recipient-"
                        f"{self.INVOCATION}@local.test"
                    ),
                },
                "sender": {
                    "account_id": "sender-account",
                    "address": (
                        "dashboard-routing-sender-"
                        f"{self.INVOCATION}@local.test"
                    ),
                },
            },
            "bootstrap_proof": {
                "identity": [1, 2, 33152, 1, 501, 20],
                "name": "bootstrap-proof.json",
                "sha256": "a" * 64,
                "size": 123,
            },
            "invocation_id": self.INVOCATION,
            "management_account_id": "management-account",
            "management_credential_id": "management-credential",
            "preserved_objects_sha256": "b" * 64,
            "schema": "mail-sandbox.stalwart-v016-routing-input.v1",
            "server_version": "0.16.17",
        }

    def dependencies(
        self,
        repository: TemporaryRepository,
        server: FakeRegistryServer,
        events: list[object],
    ) -> object:
        lock_state = {"held": False}

        @contextmanager
        def acquire_lock(root: Path):
            self.assertEqual(root, repository.root)
            self.assertFalse(lock_state["held"])
            lock_state["held"] = True
            lock_state["valid"] = True
            token = SimpleNamespace(path=root / "bootstrap.lock")

            def assert_valid_for(actual_root: Path) -> None:
                self.assertEqual(actual_root, repository.root)
                self.assertTrue(lock_state["held"])
                events.append(("lock-valid", token))
                if not lock_state["valid"]:
                    raise bootstrap.BootstrapError(
                        "Stalwart operation lock namespace changed",
                    )

            token.assert_valid_for = assert_valid_for
            token.invalidate = lambda: lock_state.__setitem__(
                "valid",
                False,
            )
            events.append(("lock-enter", token))
            try:
                yield token
            finally:
                events.append(("lock-exit", token))
                lock_state["held"] = False

        def build_validator(
            paths: object,
            **kwargs: object,
        ) -> object:
            self.assertTrue(lock_state["held"])
            runtime_phase = kwargs["runtime_phase"]
            events.append(
                ("build-validator", runtime_phase, paths, kwargs),
            )

            def validate(path: Path) -> dict[str, object]:
                self.assertTrue(lock_state["held"])
                events.append(
                    ("task6-validate", runtime_phase, path),
                )
                return json.loads(json.dumps(TASK6_APPLY_PAYLOAD))

            return validate

        recovery = bytearray(b"recovery-admin:recovery-password")

        def run_runtime(
            paths: object,
            *,
            operation: object,
            operation_lock: object,
            **kwargs: object,
        ) -> object:
            self.assertTrue(lock_state["held"])
            self.assertIs(operation_lock, events[0][1])
            events.append(("runtime-enter", paths, kwargs))
            runtime = SimpleNamespace(
                base_url="http://127.0.0.1:8443",
                api_url="http://127.0.0.1:8443/jmap/",
                server_version="0.16.17",
                borrow_recovery_credential=lambda: memoryview(recovery).toreadonly(),
            )
            try:
                return operation(runtime)
            finally:
                for index in range(len(recovery)):
                    recovery[index] = 0
                events.append(("runtime-exit",))

        def registry_client(
            credential: FakeCredential,
            **kwargs: object,
        ) -> FakeRegistryClient:
            return FakeRegistryClient(server, credential, **kwargs)

        def ensure_directory(*args: object, **kwargs: object) -> None:
            self.assertTrue(lock_state["held"])
            events.append(("ensure-directory", args, kwargs))

        def route(
            args: list[str],
            *,
            stdin: bytes,
            cwd: Path,
            timeout: int,
        ) -> object:
            self.assertTrue(lock_state["held"])
            self.assertEqual(
                len(server.objects["Authentication"]),
                1,
                "normal Authentication must exist before routing proof",
            )
            self.assertEqual(
                len(server.objects["MtaStageAuth"]),
                1,
                "normal MtaStageAuth must exist before routing proof",
            )
            self.assertEqual(
                len(server.objects["Tracer"]),
                1,
                "normal debug Tracer must exist before routing proof",
            )
            management_ids = [
                account_id
                for account_id, value in server.objects["Account"].items()
                if value.get("name") == "dashboard-management"
            ]
            self.assertEqual(len(management_ids), 1)
            self.assertEqual(
                sorted(
                    credential.get("@type")
                    for credential in server.credentials[
                        management_ids[0]
                    ].values()
                ),
                ["ApiKey", "Password"],
                "management Password must exist before routing proof",
            )
            self.assertEqual(stdin, b"")
            self.assertEqual(
                cwd,
                repository.root / "debug-dashboard",
            )
            self.assertEqual(timeout, 300)
            routing_path = (
                repository.root
                / "debug-dashboard"
                / ".runtime"
                / "stalwart"
                / "bootstrap-routing-input.json"
            )
            raw = routing_path.read_bytes()
            value = json.loads(raw)
            self.assertEqual(raw, canonical_json(value) + b"\n")
            events.append(("routing-command", args, value))
            return bootstrap.RoutingCommandResult(
                returncode=0,
                stdout=self.routing_output(value),
                stderr=b"",
            )

        password_buffers = [
            bytearray(b"routing-sender-password"),
            bytearray(b"routing-recipient-password"),
        ]
        password_index = 0

        def password_factory() -> bytearray:
            nonlocal password_index
            value = password_buffers[password_index]
            password_index += 1
            return value

        dependencies = bootstrap.BootstrapOrchestratorDependencies(
            acquire_operation_lock=acquire_lock,
            ensure_owner_directory=ensure_directory,
            migration_paths_factory=FakeMigrationPaths,
            build_task6_validator=build_validator,
            run_migration_runtime=run_runtime,
            state_runner=lambda *_args, **_kwargs: None,
            runtime_runner=lambda *_args, **_kwargs: None,
            basic_credential_factory=lambda username, password: FakeCredential(
                "basic",
                username,
                password,
            ),
            bearer_credential_factory=lambda token: FakeCredential(
                "bearer",
                token,
            ),
            registry_client_factory=registry_client,
            registry_not_found_error=FakeRegistryNotFound,
            routing_runner=route,
            clock=lambda: self.STARTED,
            invocation_factory=lambda: self.INVOCATION,
            password_factory=password_factory,
        )
        dependencies.test_recovery_buffer = recovery
        dependencies.test_password_buffers = password_buffers
        return dependencies

    def test_success_runs_under_one_lock_and_publishes_the_final_chain(
        self,
    ) -> None:
        with TemporaryRepository() as repository:
            server = FakeRegistryServer()
            events: list[object] = []
            dependencies = self.dependencies(repository, server, events)

            result = bootstrap.run_bootstrap(
                repository.root,
                Path(sys.executable),
                dependencies=dependencies,
            )

            paths = bootstrap.BootstrapPaths.for_repository(repository.root)
            management_ids = [
                account_id
                for account_id, value in server.objects["Account"].items()
                if value.get("name") == "dashboard-management"
            ]
            self.assertEqual(
                result.management_account_id,
                management_ids[0],
            )
            management_credentials = server.credentials[management_ids[0]]
            self.assertEqual(
                sorted(
                    credential["@type"]
                    for credential in management_credentials.values()
                ),
                ["ApiKey", "Password"],
            )
            password = next(
                credential
                for credential in management_credentials.values()
                if credential["@type"] == "Password"
            )
            self.assertEqual(
                password,
                {
                    "@type": "Password",
                    "allowedIps": {},
                    "credentialId": password["credentialId"],
                    "secret": "****",
                },
            )
            self.assertEqual(
                [
                    value
                    for value in server.objects["NetworkListener"].values()
                    if value.get("name") == "submission"
                ],
                [
                    {
                        "bind": {"[::]:587": True},
                        "name": "submission",
                        "protocol": "smtp",
                        "tlsImplicit": False,
                        "useTls": False,
                    },
                ],
            )
            self.assertEqual(
                server.objects["Authentication"],
                {
                    "singleton": {
                        "directoryId": None,
                        "passwordMinLength": 1,
                        "passwordMinStrength": "zero",
                    },
                },
            )
            self.assertEqual(len(server.objects["MtaStageAuth"]), 1)
            self.assertEqual(
                list(server.objects["Tracer"].values()),
                [
                    {
                        "@type": "Stdout",
                        "ansi": False,
                        "buffered": False,
                        "description": "mail-sandbox debug stdout",
                        "enable": True,
                        "events": {},
                        "eventsPolicy": "exclude",
                        "level": "debug",
                        "lossy": False,
                        "multiline": False,
                    },
                ],
            )
            self.assertTrue(paths.final_receipt.is_file())
            self.assertTrue(paths.routing_proof.is_file())
            self.assertTrue(paths.protected_accounts.is_file())
            self.assertFalse(paths.routing_input.exists())
            self.assertFalse(paths.routing_sender_password.exists())
            self.assertFalse(paths.routing_recipient_password.exists())
            self.assertEqual(stat.S_IMODE(paths.management_key.stat().st_mode), 0o600)
            self.assertEqual(
                paths.management_key.read_bytes(),
                b"API_0123456789abcdefghijklmnopqrstuvwxyz_AB",
            )
            self.assertEqual(events[0][0], "lock-enter")
            self.assertEqual(events[-1][0], "lock-exit")
            self.assertTrue(
                all(value == 0 for value in dependencies.test_recovery_buffer),
            )
            self.assertTrue(
                all(
                    all(value == 0 for value in buffer)
                    for buffer in dependencies.test_password_buffers
                ),
            )
            self.assertTrue(all(client.closed for client in server.clients))
            self.assertEqual(
                [
                    value
                    for value in server.objects["Account"].values()
                    if str(value.get("name", "")).startswith(
                        "dashboard-routing-",
                    )
                ],
                [],
            )
            command_event = next(
                event
                for event in events
                if isinstance(event, tuple)
                and event[0] == "routing-command"
            )
            self.assertEqual(
                command_event[1],
                bootstrap.build_routing_verifier_command(
                    repository.root,
                    self.INVOCATION,
                ),
            )
            self.assertGreaterEqual(
                sum(
                    1
                    for event in events
                    if isinstance(event, tuple)
                    and event[0] == "task6-validate"
                ),
                2,
            )
            self.assertEqual(
                [
                    (
                        event[0],
                        (
                            "runtime"
                            if event[0] in {
                                "runtime-enter",
                                "runtime-exit",
                            }
                            else event[1]
                        ),
                    )
                    for event in events
                    if isinstance(event, tuple)
                    and event[0] in {
                        "build-validator",
                        "runtime-enter",
                        "runtime-exit",
                        "task6-validate",
                    }
                ],
                [
                    ("build-validator", "durable-recovery"),
                    ("task6-validate", "durable-recovery"),
                    ("runtime-enter", "runtime"),
                    ("build-validator", "ready"),
                    ("task6-validate", "ready"),
                    ("runtime-exit", "runtime"),
                ],
            )
            event_names = [
                event[0]
                for event in events
                if isinstance(event, tuple)
            ]
            self.assertLess(
                event_names.index("task6-validate"),
                event_names.index("runtime-enter"),
            )
            self.assertLess(
                len(event_names)
                - 1
                - event_names[::-1].index("task6-validate"),
                event_names.index("runtime-exit"),
            )
            first_validation = event_names.index("task6-validate")
            last_validation = (
                len(event_names)
                - 1
                - event_names[::-1].index("task6-validate")
            )
            self.assertIn("lock-valid", event_names[:first_validation])
            self.assertIn("lock-valid", event_names[last_validation + 1 :])
            durable_validation = next(
                index
                for index, event in enumerate(events)
                if event[:2]
                == ("task6-validate", "durable-recovery")
            )
            runtime_enter = next(
                index
                for index, event in enumerate(events)
                if event[0] == "runtime-enter"
            )
            runtime_exit = next(
                index
                for index, event in enumerate(events)
                if event[0] == "runtime-exit"
            )
            ready_build = next(
                index
                for index, event in enumerate(events)
                if event[:2] == ("build-validator", "ready")
            )
            self.assertIn(
                "lock-valid",
                [
                    event[0]
                    for event in events[
                        durable_validation + 1 : runtime_enter
                    ]
                ],
            )
            self.assertIn(
                "lock-valid",
                [
                    event[0]
                    for event in events[runtime_enter + 1 : ready_build]
                ],
            )
            self.assertIn(
                "lock-valid",
                [
                    event[0]
                    for event in events[last_validation + 1 : runtime_exit]
                ],
            )

    def test_completed_bootstrap_reconciles_normal_contract_idempotently(
        self,
    ) -> None:
        with TemporaryRepository() as repository:
            server = FakeRegistryServer()
            first_events: list[object] = []
            bootstrap.run_bootstrap(
                repository.root,
                Path(sys.executable),
                dependencies=self.dependencies(
                    repository,
                    server,
                    first_events,
                ),
            )
            submission_id = next(
                object_id
                for object_id, value
                in server.objects["NetworkListener"].items()
                if value.get("name") == "submission"
            )
            server.objects["NetworkListener"][submission_id]["protocol"] = (
                "imap"
            )
            tracer_ids = tuple(server.objects["Tracer"])
            management_id = next(
                account_id
                for account_id, value in server.objects["Account"].items()
                if value.get("name") == "dashboard-management"
            )
            password_ids = tuple(
                value["credentialId"]
                for value in server.credentials[management_id].values()
                if value["@type"] == "Password"
            )

            second_events: list[object] = []
            bootstrap.run_bootstrap(
                repository.root,
                Path(sys.executable),
                dependencies=self.dependencies(
                    repository,
                    server,
                    second_events,
                ),
            )

            self.assertEqual(
                server.objects["NetworkListener"][submission_id]["protocol"],
                "smtp",
            )
            self.assertEqual(tuple(server.objects["Tracer"]), tracer_ids)
            self.assertEqual(
                tuple(
                    value["credentialId"]
                    for value in server.credentials[management_id].values()
                    if value["@type"] == "Password"
                ),
                password_ids,
            )
            self.assertFalse(
                any(event[0] == "routing-command" for event in second_events),
            )

    def test_normal_contract_reconciliation_resumes_after_ambiguous_create(
        self,
    ) -> None:
        with TemporaryRepository() as repository:
            server = FakeRegistryServer()
            server.fail_after_mutation_number = 12

            with self.assertRaisesRegex(
                RuntimeError,
                "ambiguous dispatch failure",
            ):
                bootstrap.run_bootstrap(
                    repository.root,
                    Path(sys.executable),
                    dependencies=self.dependencies(repository, server, []),
                )

            paths = bootstrap.BootstrapPaths.for_repository(repository.root)
            self.assertTrue(paths.proof.is_file())
            self.assertFalse(paths.final_receipt.exists())
            self.assertEqual(len(server.objects["Authentication"]), 1)

            result = bootstrap.run_bootstrap(
                repository.root,
                Path(sys.executable),
                dependencies=self.dependencies(repository, server, []),
            )

            self.assertTrue(result.final_receipt.path.is_file())
            self.assertEqual(len(server.objects["Authentication"]), 1)
            self.assertEqual(len(server.objects["MtaStageAuth"]), 1)
            self.assertEqual(len(server.objects["Tracer"]), 1)
            self.assertEqual(
                len(
                    [
                        value
                        for value
                        in server.objects["NetworkListener"].values()
                        if value.get("name") == "submission"
                    ],
                ),
                1,
            )

    def test_completed_bootstrap_resets_stale_management_password_and_reproves(
        self,
    ) -> None:
        with TemporaryRepository() as repository:
            server = FakeRegistryServer()
            bootstrap.run_bootstrap(
                repository.root,
                Path(sys.executable),
                dependencies=self.dependencies(repository, server, []),
            )
            management_id = next(
                account_id
                for account_id, value in server.objects["Account"].items()
                if value.get("name") == "dashboard-management"
            )
            password_key = next(
                map_key
                for map_key, value
                in server.credentials[management_id].items()
                if value["@type"] == "Password"
            )
            old_credential_id = server.credentials[management_id][
                password_key
            ]["credentialId"]
            server.password_secrets[management_id][password_key] = "stale"

            bootstrap.run_bootstrap(
                repository.root,
                Path(sys.executable),
                dependencies=self.dependencies(repository, server, []),
            )

            self.assertEqual(
                server.password_secrets[management_id],
                {password_key: "secret"},
            )
            self.assertEqual(
                server.credentials[management_id][password_key][
                    "credentialId"
                ],
                old_credential_id,
            )
            self.assertGreaterEqual(
                sum(
                    1
                    for call in server.calls
                    if call[:3]
                    == (
                        "discover",
                        "basic",
                        "dashboard-management@local.test",
                    )
                ),
                2,
            )

    def test_runtime_recovers_unavailable_mutable_artifacts_before_ready_validation(
        self,
    ) -> None:
        with TemporaryRepository() as repository:
            server = FakeRegistryServer()
            events: list[object] = []
            dependencies = self.dependencies(repository, server, events)
            original_builder = dependencies.build_task6_validator
            original_runtime = dependencies.run_migration_runtime
            runtime_recovered = False

            def build_validator(
                paths: object,
                **kwargs: object,
            ) -> object:
                runtime_phase = kwargs["runtime_phase"]
                validator = original_builder(paths, **kwargs)

                def require_recovered_artifacts(
                    path: Path,
                ) -> dict[str, object]:
                    if runtime_phase == "ready" and not runtime_recovered:
                        raise bootstrap.BootstrapError(
                            "active recovery artifacts are unavailable",
                        )
                    return validator(path)

                return require_recovered_artifacts

            def run_runtime(
                *args: object,
                operation: object,
                **kwargs: object,
            ) -> object:
                def recovered_operation(runtime: object) -> object:
                    nonlocal runtime_recovered
                    runtime_recovered = True
                    return operation(runtime)

                return original_runtime(
                    *args,
                    operation=recovered_operation,
                    **kwargs,
                )

            dependencies.build_task6_validator = build_validator
            dependencies.run_migration_runtime = run_runtime

            result = bootstrap.run_bootstrap(
                repository.root,
                Path(sys.executable),
                dependencies=dependencies,
            )

            self.assertTrue(runtime_recovered)
            self.assertTrue(result.final_receipt.path.is_file())
            self.assertEqual(
                [
                    event[1]
                    for event in events
                    if event[0] == "build-validator"
                ],
                ["durable-recovery", "ready"],
            )

    def test_bootstrap_input_failure_is_delegated_inside_recovery_runtime(
        self,
    ) -> None:
        with TemporaryRepository() as repository:
            server = FakeRegistryServer()
            events: list[object] = []
            dependencies = self.dependencies(repository, server, events)
            failure = bootstrap.BootstrapError(
                "injected immutable bootstrap input failure",
            )

            with (
                mock.patch.object(
                    bootstrap,
                    "load_bootstrap_inputs",
                    side_effect=failure,
                ),
                self.assertRaises(bootstrap.BootstrapError) as raised,
            ):
                bootstrap.run_bootstrap(
                    repository.root,
                    Path(sys.executable),
                    dependencies=dependencies,
                )

            self.assertIs(raised.exception, failure)
            self.assertEqual(
                [
                    (
                        event[0],
                        (
                            event[1]
                            if event[0]
                            in {"build-validator", "task6-validate"}
                            else "runtime"
                        ),
                    )
                    for event in events
                    if event[0]
                    in {
                        "build-validator",
                        "runtime-enter",
                        "runtime-exit",
                        "task6-validate",
                    }
                ],
                [
                    ("build-validator", "durable-recovery"),
                    ("task6-validate", "durable-recovery"),
                    ("runtime-enter", "runtime"),
                    ("runtime-exit", "runtime"),
                ],
            )

    def test_final_ready_failure_and_cancellation_stay_inside_runtime(
        self,
    ) -> None:
        for failure in (
            RuntimeError("injected final ready failure"),
            KeyboardInterrupt("injected final ready cancellation"),
        ):
            with (
                self.subTest(kind=type(failure).__name__),
                TemporaryRepository() as repository,
            ):
                server = FakeRegistryServer()
                events: list[object] = []
                dependencies = self.dependencies(
                    repository,
                    server,
                    events,
                )

                def fail_final_validation(
                    _paths: object,
                    *,
                    task6_validator: object,
                ) -> object:
                    self.assertTrue(callable(task6_validator))
                    events.append(("final-ready-failure", failure))
                    raise failure

                with (
                    mock.patch.object(
                        bootstrap,
                        "validate_final_bootstrap_for_retirement",
                        side_effect=fail_final_validation,
                    ),
                    self.assertRaises(type(failure)) as raised,
                ):
                    bootstrap.run_bootstrap(
                        repository.root,
                        Path(sys.executable),
                        dependencies=dependencies,
                    )

                self.assertIs(raised.exception, failure)
                event_names = [event[0] for event in events]
                self.assertLess(
                    event_names.index("runtime-enter"),
                    event_names.index("final-ready-failure"),
                )
                self.assertLess(
                    event_names.index("final-ready-failure"),
                    event_names.index("runtime-exit"),
                )
                ready_builds = [
                    index
                    for index, event in enumerate(events)
                    if event[:2] == ("build-validator", "ready")
                ]
                self.assertEqual(len(ready_builds), 1)
                self.assertLess(
                    ready_builds[0],
                    next(
                        index
                        for index, event in enumerate(events)
                        if event[0] == "runtime-exit"
                    ),
                )

    def test_runtime_recovery_failure_prevents_ready_finalization(
        self,
    ) -> None:
        with TemporaryRepository() as repository:
            server = FakeRegistryServer()
            events: list[object] = []
            dependencies = self.dependencies(repository, server, events)
            failure = RuntimeError("injected runtime recovery failure")

            def fail_runtime(
                _paths: object,
                *,
                operation_lock: object,
                **_kwargs: object,
            ) -> object:
                operation_lock.assert_valid_for(repository.root)
                events.append(("runtime-recovery-failure", failure))
                raise failure

            dependencies.run_migration_runtime = fail_runtime

            with self.assertRaises(RuntimeError) as raised:
                bootstrap.run_bootstrap(
                    repository.root,
                    Path(sys.executable),
                    dependencies=dependencies,
                )

            self.assertIs(raised.exception, failure)
            self.assertEqual(
                [
                    event[1]
                    for event in events
                    if event[0] == "build-validator"
                ],
                ["durable-recovery"],
            )
            self.assertFalse(
                bootstrap.BootstrapPaths.for_repository(
                    repository.root,
                ).final_receipt.exists(),
            )

    def test_foreign_and_exact_stale_writer_failures_remain_runtime_owned(
        self,
    ) -> None:
        for detail in ("foreign-writer", "exact-stale-writer"):
            with (
                self.subTest(detail=detail),
                TemporaryRepository() as repository,
            ):
                server = FakeRegistryServer()
                events: list[object] = []
                dependencies = self.dependencies(
                    repository,
                    server,
                    events,
                )
                original_builder = dependencies.build_task6_validator
                delegated: list[object] = []
                failure = RuntimeError(detail)
                paths = bootstrap.BootstrapPaths.for_repository(
                    repository.root,
                )
                apply_before = paths.apply_receipt.read_bytes()

                def build_validator(
                    migration_paths: object,
                    **kwargs: object,
                ) -> object:
                    if (
                        kwargs["runtime_phase"] == "ready"
                        and not delegated
                    ):
                        raise AssertionError(
                            "writer recovery was preempted by ready validation",
                        )
                    return original_builder(migration_paths, **kwargs)

                def delegate_runtime(
                    _paths: object,
                    *,
                    operation: object,
                    operation_lock: object,
                    **_kwargs: object,
                ) -> object:
                    operation_lock.assert_valid_for(repository.root)
                    delegated.append(operation)
                    raise failure

                dependencies.build_task6_validator = build_validator
                dependencies.run_migration_runtime = delegate_runtime

                with self.assertRaises(RuntimeError) as raised:
                    bootstrap.run_bootstrap(
                        repository.root,
                        Path(sys.executable),
                        dependencies=dependencies,
                    )

                self.assertIs(raised.exception, failure)
                self.assertEqual(len(delegated), 1)
                self.assertEqual(paths.apply_receipt.read_bytes(), apply_before)
                self.assertFalse(
                    any(
                        path.exists()
                        for path in (
                            paths.attempt,
                            paths.account,
                            paths.replacement,
                            paths.key,
                            paths.proof,
                            paths.routing_intent,
                            paths.routing_proof,
                            paths.final_receipt,
                            paths.management_key,
                            paths.protected_accounts,
                            paths.routing_input,
                            paths.routing_sender_password,
                            paths.routing_recipient_password,
                        )
                    ),
                )

    def test_runtime_cancellation_preserves_identity_and_skips_ready_validation(
        self,
    ) -> None:
        with TemporaryRepository() as repository:
            server = FakeRegistryServer()
            events: list[object] = []
            dependencies = self.dependencies(repository, server, events)
            cancellation = KeyboardInterrupt("runtime-cancellation-canary")

            def cancel_runtime(
                _paths: object,
                *,
                operation_lock: object,
                **_kwargs: object,
            ) -> object:
                operation_lock.assert_valid_for(repository.root)
                raise cancellation

            dependencies.run_migration_runtime = cancel_runtime

            with self.assertRaises(KeyboardInterrupt) as raised:
                bootstrap.run_bootstrap(
                    repository.root,
                    Path(sys.executable),
                    dependencies=dependencies,
                )

            self.assertIs(raised.exception, cancellation)
            self.assertEqual(
                [
                    event[1]
                    for event in events
                    if event[0] == "build-validator"
                ],
                ["durable-recovery"],
            )

    def test_lock_namespace_change_after_final_validation_is_rejected(
        self,
    ) -> None:
        with TemporaryRepository() as repository:
            server = FakeRegistryServer()
            events: list[object] = []
            dependencies = self.dependencies(repository, server, events)
            original_builder = dependencies.build_task6_validator

            def build_validator(
                paths: object,
                **kwargs: object,
            ) -> object:
                validator = original_builder(paths, **kwargs)
                runtime_phase = kwargs["runtime_phase"]

                def invalidate_after_final_validation(
                    path: Path,
                ) -> dict[str, object]:
                    result = validator(path)
                    if runtime_phase == "ready":
                        events[0][1].invalidate()
                    return result

                return invalidate_after_final_validation

            dependencies.build_task6_validator = build_validator

            with self.assertRaisesRegex(
                bootstrap.BootstrapError,
                "lock namespace changed",
            ):
                bootstrap.run_bootstrap(
                    repository.root,
                    Path(sys.executable),
                    dependencies=dependencies,
                )

            self.assertIn("runtime-enter", [event[0] for event in events])
            self.assertEqual(events[-1][0], "lock-exit")

    def test_runner_dependencies_must_be_callable_before_lock_acquisition(
        self,
    ) -> None:
        for name in ("state_runner", "runtime_runner"):
            with (
                self.subTest(name=name),
                TemporaryRepository() as repository,
            ):
                server = FakeRegistryServer()
                events: list[object] = []
                dependencies = self.dependencies(
                    repository,
                    server,
                    events,
                )
                setattr(dependencies, name, object())

                with self.assertRaisesRegex(
                    bootstrap.BootstrapError,
                    name.replace("_", " "),
                ):
                    bootstrap.run_bootstrap(
                        repository.root,
                        Path(sys.executable),
                        dependencies=dependencies,
                    )

                self.assertEqual(events, [])

    def test_malformed_recovery_credential_releases_the_borrowed_view(
        self,
    ) -> None:
        with TemporaryRepository() as repository:
            server = FakeRegistryServer()
            events: list[object] = []
            dependencies = self.dependencies(repository, server, events)
            recovery = bytearray(b"malformed-without-separator")
            borrowed_views: list[memoryview] = []

            def run_runtime(
                _paths: object,
                *,
                operation: object,
                **_kwargs: object,
            ) -> object:
                def borrow() -> memoryview:
                    view = memoryview(recovery).toreadonly()
                    borrowed_views.append(view)
                    return view

                runtime = SimpleNamespace(
                    base_url="http://127.0.0.1:8443",
                    api_url="http://127.0.0.1:8443/jmap/",
                    server_version="0.16.17",
                    borrow_recovery_credential=borrow,
                )
                return operation(runtime)

            dependencies.run_migration_runtime = run_runtime

            with self.assertRaises(bootstrap.BootstrapError):
                bootstrap.run_bootstrap(
                    repository.root,
                    Path(sys.executable),
                    dependencies=dependencies,
                )

            self.assertEqual(len(borrowed_views), 1)
            with self.assertRaises(ValueError):
                borrowed_views[0].tobytes()

    def test_routing_verifier_output_is_one_exact_canonical_object(
        self,
    ) -> None:
        routing_input = self.routing_input()
        valid_stdout = self.routing_output(routing_input)
        parsed = bootstrap._parse_routing_verifier_output(
            bootstrap.RoutingCommandResult(0, valid_stdout, b""),
            routing_input,
        )
        self.assertEqual(
            parsed["schema"],
            "mail-sandbox.stalwart-v016-routing-verifier.v1",
        )

        value = json.loads(valid_stdout)
        changed = json.loads(json.dumps(value))
        changed["management_account_id"] = "other-account"
        extra = json.loads(json.dumps(value))
        extra["unexpected"] = True
        reversed_value = dict(reversed(list(value.items())))
        invalid = (
            bootstrap.RoutingCommandResult(1, b"", b"safe failure\n"),
            bootstrap.RoutingCommandResult(0, valid_stdout, b"warning\n"),
            bootstrap.RoutingCommandResult(0, valid_stdout + b"\n", b""),
            bootstrap.RoutingCommandResult(
                0,
                json.dumps(
                    reversed_value,
                    separators=(",", ":"),
                ).encode("utf-8")
                + b"\n",
                b"",
            ),
            bootstrap.RoutingCommandResult(
                0,
                canonical_json(changed) + b"\n",
                b"",
            ),
            bootstrap.RoutingCommandResult(
                0,
                canonical_json(extra) + b"\n",
                b"",
            ),
        )
        for result in invalid:
            with (
                self.subTest(result=result),
                self.assertRaises(bootstrap.BootstrapError),
            ):
                bootstrap._parse_routing_verifier_output(
                    result,
                    routing_input,
                )

    def test_secret_unlink_validates_metadata_without_reading_bytes(
        self,
    ) -> None:
        with TemporaryRepository() as repository:
            paths = bootstrap.BootstrapPaths.for_repository(repository.root)
            write_file(
                paths.routing_sender_password,
                b"secret-read-canary",
                0o600,
            )

            with mock.patch.object(
                bootstrap,
                "_snapshot_regular",
                side_effect=AssertionError("secret bytes were read"),
            ):
                bootstrap._safe_unlink_0600(
                    paths.routing_sender_password,
                    root=repository.root,
                )

            self.assertFalse(paths.routing_sender_password.exists())

    def test_management_key_reader_uses_only_wipeable_read_buffers(
        self,
    ) -> None:
        with TemporaryRepository() as repository:
            paths = bootstrap.BootstrapPaths.for_repository(repository.root)
            write_file(
                paths.management_key,
                b"API_0123456789abcdefghijklmnopqrstuvwxyz_AB",
                0o600,
            )
            binding = bootstrap._snapshot_secret(
                paths.management_key,
                root=repository.root,
            )

            with mock.patch.object(
                bootstrap.os,
                "read",
                side_effect=AssertionError("immutable secret read"),
            ):
                value = bootstrap._read_secret_mutable(
                    binding,
                    root=repository.root,
                )

            self.assertEqual(
                value,
                bytearray(
                    b"API_0123456789abcdefghijklmnopqrstuvwxyz_AB",
                ),
            )
            bootstrap._wipe_mutable(value)
            self.assertTrue(all(item == 0 for item in value))

    def test_management_key_reader_rejects_named_path_replacement_during_read(
        self,
    ) -> None:
        with TemporaryRepository() as repository:
            paths = bootstrap.BootstrapPaths.for_repository(repository.root)
            raw = b"API_0123456789abcdefghijklmnopqrstuvwxyz_AB"
            write_file(paths.management_key, raw, 0o600)
            binding = bootstrap._snapshot_secret(
                paths.management_key,
                root=repository.root,
            )
            original_readv = bootstrap.os.readv
            replaced = False

            def replacing_readv(
                descriptor: int,
                buffers: list[memoryview],
            ) -> int:
                nonlocal replaced
                count = original_readv(descriptor, buffers)
                if not replaced:
                    replacement = paths.management_key.with_name(
                        "replacement-management-key",
                    )
                    write_file(replacement, raw, 0o600)
                    os.replace(replacement, paths.management_key)
                    replaced = True
                return count

            with mock.patch.object(
                bootstrap.os,
                "readv",
                side_effect=replacing_readv,
            ):
                with self.assertRaises(bootstrap.BootstrapError):
                    bootstrap._read_secret_mutable(
                        binding,
                        root=repository.root,
                    )

    def test_new_only_writer_never_exposes_a_partial_final_path(
        self,
    ) -> None:
        with TemporaryRepository() as repository:
            paths = bootstrap.BootstrapPaths.for_repository(repository.root)
            target = paths.routing_sender_password
            content = bytearray(b"durable-routing-secret")

            with (
                mock.patch.object(
                    bootstrap.os,
                    "fsync",
                    side_effect=OSError("injected file fsync failure"),
                ),
                self.assertRaises(bootstrap.BootstrapError),
            ):
                bootstrap._write_new_mutable_0600(
                    target,
                    content,
                    root=repository.root,
                    maximum=1024,
                )
            self.assertFalse(target.exists())

            with (
                mock.patch.object(
                    bootstrap.os,
                    "link",
                    side_effect=OSError("injected publication failure"),
                ),
                self.assertRaises(bootstrap.BootstrapError),
            ):
                bootstrap._write_new_mutable_0600(
                    target,
                    content,
                    root=repository.root,
                    maximum=1024,
                )
            self.assertFalse(target.exists())
            self.assertEqual(
                list(target.parent.glob(f".{target.name}.*.tmp")),
                [],
            )

    def test_ambiguous_key_create_is_revoked_and_replaced_once_on_resume(
        self,
    ) -> None:
        with TemporaryRepository() as repository:
            server = FakeRegistryServer()
            server.fail_after_api_key_create_once = True
            first_events: list[object] = []
            first = self.dependencies(repository, server, first_events)

            with self.assertRaises(RuntimeError):
                bootstrap.run_bootstrap(
                    repository.root,
                    Path(sys.executable),
                    dependencies=first,
                )

            paths = bootstrap.BootstrapPaths.for_repository(repository.root)
            self.assertFalse(paths.management_key.exists())
            self.assertFalse(paths.key.exists())
            management_id = next(
                account_id
                for account_id, value in server.objects["Account"].items()
                if value.get("name") == "dashboard-management"
            )
            orphan_ids = tuple(server.credentials[management_id])
            self.assertEqual(len(orphan_ids), 1)

            second_events: list[object] = []
            second = self.dependencies(repository, server, second_events)
            result = bootstrap.run_bootstrap(
                repository.root,
                Path(sys.executable),
                dependencies=second,
            )

            self.assertTrue(paths.replacement.is_file())
            self.assertTrue(paths.final_receipt.is_file())
            self.assertNotIn(
                orphan_ids[0],
                server.credentials[result.management_account_id],
            )
            self.assertEqual(
                sorted(
                    value["@type"]
                    for value in server.credentials[
                        result.management_account_id
                    ].values()
                ),
                ["ApiKey", "Password"],
            )
            replacement_payload = json.loads(
                paths.replacement.read_text("utf-8"),
            )["payload"]
            self.assertEqual(
                replacement_payload["orphan_credential_id"],
                orphan_ids[0],
            )

    def test_local_secret_without_key_checkpoint_is_adopted_after_exact_proof(
        self,
    ) -> None:
        with TemporaryRepository() as repository:
            server = FakeRegistryServer()
            dependencies = self.dependencies(repository, server, [])
            paths = bootstrap.BootstrapPaths.for_repository(repository.root)
            original = bootstrap._write_new_envelope_0600
            failed = False

            def fail_key_checkpoint(
                target: Path,
                payload: object,
                *,
                root: Path,
            ) -> None:
                nonlocal failed
                if target == paths.key and not failed:
                    failed = True
                    raise bootstrap.BootstrapError(
                        "injected key checkpoint failure",
                    )
                original(target, payload, root=root)

            with (
                mock.patch.object(
                    bootstrap,
                    "_write_new_envelope_0600",
                    side_effect=fail_key_checkpoint,
                ),
                self.assertRaisesRegex(
                    bootstrap.BootstrapError,
                    "injected key checkpoint failure",
                ),
            ):
                bootstrap.run_bootstrap(
                    repository.root,
                    Path(sys.executable),
                    dependencies=dependencies,
                )

            self.assertTrue(paths.management_key.is_file())
            self.assertFalse(paths.key.exists())
            api_key_creates_before = sum(
                call[0] == "create-api-key"
                for call in server.calls
            )

            resumed = self.dependencies(repository, server, [])
            bootstrap.run_bootstrap(
                repository.root,
                Path(sys.executable),
                dependencies=resumed,
            )

            key_payload = json.loads(paths.key.read_text("utf-8"))["payload"]
            self.assertEqual(key_payload["origin"], "adopted")
            self.assertEqual(
                sum(call[0] == "create-api-key" for call in server.calls),
                api_key_creates_before,
            )

    def test_missing_checkpointed_secret_is_manual_stop_without_replacement(
        self,
    ) -> None:
        with TemporaryRepository() as repository:
            server = FakeRegistryServer()
            server.fail_before_mutation_number = 10
            dependencies = self.dependencies(repository, server, [])

            with self.assertRaises(RuntimeError):
                bootstrap.run_bootstrap(
                    repository.root,
                    Path(sys.executable),
                    dependencies=dependencies,
                )

            paths = bootstrap.BootstrapPaths.for_repository(repository.root)
            self.assertTrue(paths.key.is_file())
            self.assertTrue(paths.management_key.is_file())
            paths.management_key.unlink()
            api_key_creates_before = sum(
                call[0] == "create-api-key"
                for call in server.calls
            )
            resumed = self.dependencies(repository, server, [])

            with self.assertRaisesRegex(
                bootstrap.BootstrapError,
                "manual reconciliation",
            ):
                bootstrap.run_bootstrap(
                    repository.root,
                    Path(sys.executable),
                    dependencies=resumed,
                )

            self.assertEqual(
                sum(call[0] == "create-api-key" for call in server.calls),
                api_key_creates_before,
            )

    def test_unexpected_complete_credential_inventory_stops_before_key_create(
        self,
    ) -> None:
        with TemporaryRepository() as repository:
            server = FakeRegistryServer()
            server.add_password_to_management_account = True
            dependencies = self.dependencies(repository, server, [])

            with self.assertRaises(bootstrap.BootstrapError):
                bootstrap.run_bootstrap(
                    repository.root,
                    Path(sys.executable),
                    dependencies=dependencies,
                )

            self.assertEqual(
                sum(call[0] == "create-api-key" for call in server.calls),
                0,
            )

    def test_each_pre_dispatch_failure_before_routing_cleanup_resumes(
        self,
    ) -> None:
        for failure_number in range(1, 13):
            with (
                self.subTest(failure_number=failure_number),
                TemporaryRepository() as repository,
            ):
                server = FakeRegistryServer()
                server.fail_before_mutation_number = failure_number
                first = self.dependencies(repository, server, [])

                with self.assertRaises(RuntimeError):
                    bootstrap.run_bootstrap(
                        repository.root,
                        Path(sys.executable),
                        dependencies=first,
                    )

                second = self.dependencies(repository, server, [])
                result = bootstrap.run_bootstrap(
                    repository.root,
                    Path(sys.executable),
                    dependencies=second,
                )

                self.assertTrue(result.final_receipt.path.is_file())
                self.assertEqual(
                    [
                        value
                        for value in server.objects["Account"].values()
                        if str(value.get("name", "")).startswith(
                            "dashboard-routing-",
                        )
                    ],
                    [],
                )

    def test_each_ambiguous_management_dispatch_requeries_and_resumes(
        self,
    ) -> None:
        for failure_number in (*range(1, 9), 10):
            with (
                self.subTest(failure_number=failure_number),
                TemporaryRepository() as repository,
            ):
                server = FakeRegistryServer()
                server.fail_after_mutation_number = failure_number
                first = self.dependencies(repository, server, [])

                with self.assertRaises(RuntimeError):
                    bootstrap.run_bootstrap(
                        repository.root,
                        Path(sys.executable),
                        dependencies=first,
                    )

                resumed = self.dependencies(repository, server, [])
                result = bootstrap.run_bootstrap(
                    repository.root,
                    Path(sys.executable),
                    dependencies=resumed,
                )
                self.assertTrue(result.final_receipt.path.is_file())

    def test_each_ambiguous_actor_create_is_discovered_cleaned_and_resumed(
        self,
    ) -> None:
        for role in ("sender", "recipient"):
            with (
                self.subTest(role=role),
                TemporaryRepository() as repository,
            ):
                server = FakeRegistryServer()
                server.fail_after_account_create_name_once = (
                    f"dashboard-routing-{role}-{self.INVOCATION}"
                )
                first = self.dependencies(repository, server, [])

                with self.assertRaises(RuntimeError):
                    bootstrap.run_bootstrap(
                        repository.root,
                        Path(sys.executable),
                        dependencies=first,
                    )

                self.assertEqual(
                    [
                        value
                        for value in server.objects["Account"].values()
                        if str(value.get("name", "")).startswith(
                            "dashboard-routing-",
                        )
                    ],
                    [],
                )
                resumed = self.dependencies(repository, server, [])
                result = bootstrap.run_bootstrap(
                    repository.root,
                    Path(sys.executable),
                    dependencies=resumed,
                )
                self.assertTrue(result.final_receipt.path.is_file())

    def test_each_hard_routing_crash_is_owned_cleaned_and_resumed(
        self,
    ) -> None:
        cases = (
            "after-sender-create",
            "after-recipient-create",
            "before-handoffs",
            "after-sender-password",
            "after-recipient-password",
            "after-routing-input",
            "after-verifier",
        )
        for case in cases:
            with (
                self.subTest(case=case),
                TemporaryRepository() as repository,
            ):
                server = FakeRegistryServer()
                first = self.dependencies(repository, server, [])
                paths = bootstrap.BootstrapPaths.for_repository(
                    repository.root,
                )
                original_mutable = bootstrap._write_new_mutable_0600
                original_json = bootstrap._write_new_canonical_json_0600
                mutable_crash_target: Path | None = None
                crash_before_mutable = False

                if case == "after-sender-create":
                    server.hard_exit_after_account_create_name_once = (
                        f"dashboard-routing-sender-{self.INVOCATION}"
                    )
                elif case == "after-recipient-create":
                    server.hard_exit_after_account_create_name_once = (
                        f"dashboard-routing-recipient-{self.INVOCATION}"
                    )
                elif case == "before-handoffs":
                    mutable_crash_target = paths.routing_sender_password
                    crash_before_mutable = True
                elif case == "after-sender-password":
                    mutable_crash_target = paths.routing_sender_password
                elif case == "after-recipient-password":
                    mutable_crash_target = paths.routing_recipient_password

                def crash_mutable(
                    target: Path,
                    content: bytearray,
                    *,
                    root: Path,
                    maximum: int,
                ) -> None:
                    if (
                        target == mutable_crash_target
                        and crash_before_mutable
                    ):
                        raise SystemExit("injected pre-handoff hard crash")
                    original_mutable(
                        target,
                        content,
                        root=root,
                        maximum=maximum,
                    )
                    if target == mutable_crash_target:
                        raise SystemExit("injected post-handoff hard crash")

                def crash_json(
                    target: Path,
                    payload: object,
                    *,
                    root: Path,
                ) -> None:
                    original_json(target, payload, root=root)
                    if (
                        case == "after-routing-input"
                        and target == paths.routing_input
                    ):
                        raise SystemExit(
                            "injected post-routing-input hard crash",
                        )

                patchers = [
                    mock.patch.object(
                        bootstrap,
                        "_write_new_mutable_0600",
                        side_effect=crash_mutable,
                    ),
                    mock.patch.object(
                        bootstrap,
                        "_write_new_canonical_json_0600",
                        side_effect=crash_json,
                    ),
                ]
                if case == "after-verifier":
                    original_route = first.routing_runner

                    def route_with_residual_app_passwords(
                        *args: object,
                        **kwargs: object,
                    ) -> object:
                        result = original_route(*args, **kwargs)
                        uuid = (
                            f"{self.INVOCATION[:8]}-"
                            f"{self.INVOCATION[8:12]}-"
                            f"{self.INVOCATION[12:16]}-"
                            f"{self.INVOCATION[16:20]}-"
                            f"{self.INVOCATION[20:]}"
                        )
                        for generation, role in enumerate(
                            ("sender", "recipient"),
                            start=1,
                        ):
                            account_id = next(
                                object_id
                                for object_id, value in (
                                    server.objects["Account"].items()
                                )
                                if value.get("name")
                                == (
                                    f"dashboard-routing-{role}-"
                                    f"{self.INVOCATION}"
                                )
                            )
                            credential_id = f"{role}-residual-app-password"
                            server.credentials[account_id][credential_id] = {
                                "@type": "AppPassword",
                                "allowedIps": {},
                                "credentialId": credential_id,
                                "description": (
                                    "mail-sandbox/debug-dashboard/"
                                    f"{uuid}/{generation}"
                                ),
                                "permissions": {
                                    "@type": "Replace",
                                    "permissions": {
                                        name: True
                                        for name in ROUTING_MAIL_PERMISSIONS
                                    },
                                },
                                "secret": "****",
                            }
                        return result

                    first.routing_runner = route_with_residual_app_passwords
                    patchers.append(
                        mock.patch.object(
                            bootstrap,
                            "_destroy_and_requery_actor",
                            side_effect=SystemExit(
                                "injected post-verifier hard crash",
                            ),
                        ),
                    )

                with (
                    patchers[0],
                    patchers[1],
                    (
                        patchers[2]
                        if len(patchers) == 3
                        else nullcontext()
                    ),
                    self.assertRaises(SystemExit),
                ):
                    bootstrap.run_bootstrap(
                        repository.root,
                        Path(sys.executable),
                        dependencies=first,
                    )

                self.assertTrue(paths.routing_intent.is_file())
                self.assertEqual(
                    stat.S_IMODE(paths.routing_intent.stat().st_mode),
                    0o600,
                )
                routing_ids = [
                    object_id
                    for object_id, value in server.objects["Account"].items()
                    if str(value.get("name", "")).startswith(
                        "dashboard-routing-",
                    )
                ]
                self.assertEqual(
                    len(routing_ids),
                    1 if case == "after-sender-create" else 2,
                )
                residual_app_passwords = {
                    account_id: tuple(
                        credential_id
                        for credential_id, credential in (
                            server.credentials[account_id].items()
                        )
                        if credential.get("@type") == "AppPassword"
                    )
                    for account_id in routing_ids
                }
                expected_handoffs = {
                    "after-sender-password": {
                        paths.routing_sender_password,
                    },
                    "after-recipient-password": {
                        paths.routing_sender_password,
                        paths.routing_recipient_password,
                    },
                    "after-routing-input": {
                        paths.routing_sender_password,
                        paths.routing_recipient_password,
                        paths.routing_input,
                    },
                    "after-verifier": {
                        paths.routing_sender_password,
                        paths.routing_recipient_password,
                        paths.routing_input,
                    },
                }.get(case, set())
                self.assertEqual(
                    {
                        path
                        for path in (
                            paths.routing_sender_password,
                            paths.routing_recipient_password,
                            paths.routing_input,
                        )
                        if path.exists()
                    },
                    expected_handoffs,
                )

                resumed = self.dependencies(repository, server, [])
                result = bootstrap.run_bootstrap(
                    repository.root,
                    Path(sys.executable),
                    dependencies=resumed,
                )

                self.assertTrue(result.final_receipt.path.is_file())
                self.assertEqual(
                    [
                        value
                        for value in server.objects["Account"].values()
                        if str(value.get("name", "")).startswith(
                            "dashboard-routing-",
                        )
                    ],
                    [],
                )
                self.assertTrue(
                    all(
                        credential.get("@type") != "AppPassword"
                        for inventory in server.credentials.values()
                        for credential in inventory.values()
                    ),
                )
                self.assertTrue(
                    all(
                        account_id not in server.credentials
                        for account_id in routing_ids
                    ),
                )
                for account_id, credential_ids in (
                    residual_app_passwords.items()
                ):
                    for credential_id in credential_ids:
                        app_destroy = next(
                            index
                            for index, call in enumerate(server.calls)
                            if call
                            == (
                                "destroy",
                                "AppPassword",
                                credential_id,
                                account_id,
                            )
                        )
                        post_destroy_query = next(
                            index
                            for index, call in enumerate(server.calls)
                            if index > app_destroy
                            and call
                            == (
                                "query-credentials",
                                "AppPassword",
                                account_id,
                                100,
                            )
                        )
                        account_destroy = next(
                            index
                            for index, call in enumerate(server.calls)
                            if index > post_destroy_query
                            and call
                            == (
                                "destroy",
                                "Account",
                                account_id,
                                None,
                            )
                        )
                        self.assertLess(app_destroy, post_destroy_query)
                        self.assertLess(
                            post_destroy_query,
                            account_destroy,
                        )
                self.assertTrue(
                    all(
                        not path.exists()
                        for path in (
                            paths.routing_sender_password,
                            paths.routing_recipient_password,
                            paths.routing_input,
                        )
                    ),
                )

    def test_app_password_cleanup_failure_and_cancellation_fail_closed(
        self,
    ) -> None:
        for case in (
            "pre-destroy-failure",
            "destroy-cancellation",
            "absence-query-failure",
        ):
            with (
                self.subTest(case=case),
                TemporaryRepository() as repository,
            ):
                server = FakeRegistryServer()
                server.hard_exit_after_account_create_name_once = (
                    f"dashboard-routing-sender-{self.INVOCATION}"
                )
                with self.assertRaises(SystemExit):
                    bootstrap.run_bootstrap(
                        repository.root,
                        Path(sys.executable),
                        dependencies=self.dependencies(
                            repository,
                            server,
                            [],
                        ),
                    )
                sender_id = next(
                    account_id
                    for account_id, value in server.objects["Account"].items()
                    if value.get("name")
                    == f"dashboard-routing-sender-{self.INVOCATION}"
                )
                credential_id = "sender-residual-app-password"
                invocation_uuid = (
                    f"{self.INVOCATION[:8]}-"
                    f"{self.INVOCATION[8:12]}-"
                    f"{self.INVOCATION[12:16]}-"
                    f"{self.INVOCATION[16:20]}-"
                    f"{self.INVOCATION[20:]}"
                )
                server.credentials[sender_id][credential_id] = {
                    "@type": "AppPassword",
                    "allowedIps": {},
                    "credentialId": credential_id,
                    "description": (
                        "mail-sandbox/debug-dashboard/"
                        f"{invocation_uuid}/1"
                    ),
                    "permissions": {
                        "@type": "Replace",
                        "permissions": {
                            name: True
                            for name in ROUTING_MAIL_PERMISSIONS
                        },
                    },
                    "secret": "****",
                }
                if case == "pre-destroy-failure":
                    server.fail_before_mutation_number = (
                        server.mutation_attempts + 1
                    )
                    expected_failure = RuntimeError
                elif case == "destroy-cancellation":
                    server.fail_after_app_password_destroy_once = (
                        SystemExit(
                            "injected AppPassword destroy cancellation",
                        )
                    )
                    expected_failure = SystemExit
                else:
                    server.fail_credential_query_number = (
                        server.credential_query_attempts + 2
                    )
                    expected_failure = RuntimeError

                with self.assertRaises(expected_failure):
                    bootstrap.run_bootstrap(
                        repository.root,
                        Path(sys.executable),
                        dependencies=self.dependencies(
                            repository,
                            server,
                            [],
                        ),
                    )

                self.assertIn(sender_id, server.objects["Account"])
                self.assertNotIn(
                    (
                        "destroy",
                        "Account",
                        sender_id,
                        None,
                    ),
                    server.calls,
                )
                self.assertTrue(
                    any(
                        call[:3]
                        == (
                            "query-credentials",
                            "AppPassword",
                            sender_id,
                        )
                        for call in server.calls
                    ),
                )

                result = bootstrap.run_bootstrap(
                    repository.root,
                    Path(sys.executable),
                    dependencies=self.dependencies(
                        repository,
                        server,
                        [],
                    ),
                )
                self.assertTrue(result.final_receipt.path.is_file())
                self.assertNotIn(sender_id, server.objects["Account"])
                self.assertNotIn(sender_id, server.credentials)

    def test_ambiguous_app_password_destroy_requeries_and_continues(
        self,
    ) -> None:
        with TemporaryRepository() as repository:
            server = FakeRegistryServer()
            server.hard_exit_after_account_create_name_once = (
                f"dashboard-routing-sender-{self.INVOCATION}"
            )
            with self.assertRaises(SystemExit):
                bootstrap.run_bootstrap(
                    repository.root,
                    Path(sys.executable),
                    dependencies=self.dependencies(
                        repository,
                        server,
                        [],
                    ),
                )
            sender_id = next(
                account_id
                for account_id, value in server.objects["Account"].items()
                if value.get("name")
                == f"dashboard-routing-sender-{self.INVOCATION}"
            )
            credential_id = "sender-residual-app-password"
            invocation_uuid = (
                f"{self.INVOCATION[:8]}-"
                f"{self.INVOCATION[8:12]}-"
                f"{self.INVOCATION[12:16]}-"
                f"{self.INVOCATION[16:20]}-"
                f"{self.INVOCATION[20:]}"
            )
            server.credentials[sender_id][credential_id] = {
                "@type": "AppPassword",
                "allowedIps": {},
                "credentialId": credential_id,
                "description": (
                    "mail-sandbox/debug-dashboard/"
                    f"{invocation_uuid}/1"
                ),
                "permissions": {
                    "@type": "Replace",
                    "permissions": {
                        name: True
                        for name in ROUTING_MAIL_PERMISSIONS
                    },
                },
                "secret": "****",
            }
            server.fail_after_app_password_destroy_once = RuntimeError(
                "injected ambiguous AppPassword destroy",
            )

            result = bootstrap.run_bootstrap(
                repository.root,
                Path(sys.executable),
                dependencies=self.dependencies(repository, server, []),
            )

            self.assertTrue(result.final_receipt.path.is_file())
            self.assertNotIn(sender_id, server.objects["Account"])
            self.assertNotIn(sender_id, server.credentials)
            app_destroy = server.calls.index(
                (
                    "destroy",
                    "AppPassword",
                    credential_id,
                    sender_id,
                ),
            )
            post_query = next(
                index
                for index, call in enumerate(server.calls)
                if index > app_destroy
                and call
                == (
                    "query-credentials",
                    "AppPassword",
                    sender_id,
                    100,
                )
            )
            account_destroy = next(
                index
                for index, call in enumerate(server.calls)
                if index > post_query
                and call
                == (
                    "destroy",
                    "Account",
                    sender_id,
                    None,
                )
            )
            self.assertLess(app_destroy, post_query)
            self.assertLess(post_query, account_destroy)

    def test_missing_routing_intent_never_adopts_a_preexisting_address(
        self,
    ) -> None:
        with TemporaryRepository() as repository:
            server = FakeRegistryServer()
            first = self.dependencies(repository, server, [])
            with (
                mock.patch.object(
                    bootstrap,
                    "_publish_routing_proof",
                    side_effect=SystemExit("stop before routing intent"),
                ),
                self.assertRaises(SystemExit),
            ):
                bootstrap.run_bootstrap(
                    repository.root,
                    Path(sys.executable),
                    dependencies=first,
                )

            paths = bootstrap.BootstrapPaths.for_repository(repository.root)
            self.assertFalse(paths.routing_intent.exists())
            local_part = (
                f"dashboard-routing-sender-{self.INVOCATION}"
            )
            preexisting_id = server._id("account")
            server.objects["Account"][preexisting_id] = {
                "@type": "User",
                "domainId": next(
                    object_id
                    for object_id, value in server.objects["Domain"].items()
                    if value.get("name") == "local.test"
                ),
                "name": local_part,
                "permissions": {"@type": "Inherit"},
                "roles": {"@type": "User"},
            }
            server.credentials[preexisting_id] = {
                "normal-password": {
                    "@type": "Password",
                    "allowedIps": {},
                    "credentialId": "preexisting-password",
                    "secret": "****",
                },
            }
            mutation_count = server.mutation_attempts

            with self.assertRaises(bootstrap.BootstrapError):
                bootstrap.run_bootstrap(
                    repository.root,
                    Path(sys.executable),
                    dependencies=self.dependencies(repository, server, []),
                )

            self.assertIn(preexisting_id, server.objects["Account"])
            self.assertFalse(paths.routing_intent.exists())
            self.assertEqual(server.mutation_attempts, mutation_count)

    def test_owned_routing_resume_rejects_mismatch_and_duplicate_before_delete(
        self,
    ) -> None:
        for case in ("mismatch", "duplicate"):
            with (
                self.subTest(case=case),
                TemporaryRepository() as repository,
            ):
                server = FakeRegistryServer()
                server.hard_exit_after_account_create_name_once = (
                    f"dashboard-routing-recipient-{self.INVOCATION}"
                )
                with self.assertRaises(SystemExit):
                    bootstrap.run_bootstrap(
                        repository.root,
                        Path(sys.executable),
                        dependencies=self.dependencies(
                            repository,
                            server,
                            [],
                        ),
                    )

                paths = bootstrap.BootstrapPaths.for_repository(
                    repository.root,
                )
                self.assertTrue(paths.routing_intent.is_file())
                sender_id = next(
                    object_id
                    for object_id, value in server.objects["Account"].items()
                    if value.get("name")
                    == f"dashboard-routing-sender-{self.INVOCATION}"
                )
                recipient_id = next(
                    object_id
                    for object_id, value in server.objects["Account"].items()
                    if value.get("name")
                    == f"dashboard-routing-recipient-{self.INVOCATION}"
                )
                if case == "mismatch":
                    server.objects["Account"][recipient_id]["roles"] = {
                        "@type": "Admin",
                    }
                else:
                    duplicate_id = server._id("account")
                    server.objects["Account"][duplicate_id] = json.loads(
                        json.dumps(server.objects["Account"][recipient_id]),
                    )
                    server.credentials[duplicate_id] = json.loads(
                        json.dumps(server.credentials[recipient_id]),
                    )
                mutation_count = server.mutation_attempts

                with self.assertRaises(bootstrap.BootstrapError):
                    bootstrap.run_bootstrap(
                        repository.root,
                        Path(sys.executable),
                        dependencies=self.dependencies(
                            repository,
                            server,
                            [],
                        ),
                    )

                self.assertIn(sender_id, server.objects["Account"])
                self.assertIn(recipient_id, server.objects["Account"])
                self.assertEqual(server.mutation_attempts, mutation_count)

    def test_all_actor_credential_queries_finish_before_any_delete(
        self,
    ) -> None:
        for case in ("recipient-query-mismatch", "recipient-query-failure"):
            with (
                self.subTest(case=case),
                TemporaryRepository() as repository,
            ):
                server = FakeRegistryServer()
                server.hard_exit_after_account_create_name_once = (
                    f"dashboard-routing-recipient-{self.INVOCATION}"
                )
                with self.assertRaises(SystemExit):
                    bootstrap.run_bootstrap(
                        repository.root,
                        Path(sys.executable),
                        dependencies=self.dependencies(
                            repository,
                            server,
                            [],
                        ),
                    )
                sender_id = next(
                    object_id
                    for object_id, value in server.objects["Account"].items()
                    if value.get("name")
                    == f"dashboard-routing-sender-{self.INVOCATION}"
                )
                recipient_id = next(
                    object_id
                    for object_id, value in server.objects["Account"].items()
                    if value.get("name")
                    == f"dashboard-routing-recipient-{self.INVOCATION}"
                )
                if case == "recipient-query-mismatch":
                    server.credential_query_overrides[
                        ("AppPassword", recipient_id)
                    ] = ("hidden-recipient-app-password",)
                    expected_failure = bootstrap.BootstrapError
                else:
                    server.fail_credential_query_number = (
                        server.credential_query_attempts + 2
                    )
                    expected_failure = RuntimeError
                destroy_calls_before = sum(
                    call[0] == "destroy"
                    for call in server.calls
                )

                with self.assertRaises(expected_failure):
                    bootstrap.run_bootstrap(
                        repository.root,
                        Path(sys.executable),
                        dependencies=self.dependencies(
                            repository,
                            server,
                            [],
                        ),
                    )

                self.assertIn(sender_id, server.objects["Account"])
                self.assertIn(recipient_id, server.objects["Account"])
                self.assertEqual(
                    sum(
                        call[0] == "destroy"
                        for call in server.calls
                    ),
                    destroy_calls_before,
                )

    def test_routing_verifier_failure_cleans_actors_and_resumes_from_intent(
        self,
    ) -> None:
        with TemporaryRepository() as repository:
            server = FakeRegistryServer()
            dependencies = self.dependencies(repository, server, [])
            dependencies.routing_runner = lambda *_args, **_kwargs: (
                bootstrap.RoutingCommandResult(
                    returncode=1,
                    stdout=b"",
                    stderr=b"Stalwart routing verifier failed\n",
                )
            )

            with self.assertRaisesRegex(
                bootstrap.BootstrapError,
                "routing verifier failed safely",
            ):
                bootstrap.run_bootstrap(
                    repository.root,
                    Path(sys.executable),
                    dependencies=dependencies,
                )

            paths = bootstrap.BootstrapPaths.for_repository(repository.root)
            self.assertFalse(paths.routing_proof.exists())
            self.assertFalse(paths.final_receipt.exists())
            self.assertTrue(paths.routing_input.is_file())
            self.assertTrue(paths.routing_sender_password.is_file())
            self.assertTrue(paths.routing_recipient_password.is_file())
            self.assertEqual(
                [
                    value
                    for value in server.objects["Account"].values()
                    if str(value.get("name", "")).startswith(
                        "dashboard-routing-",
                    )
                ],
                [],
            )
            mutation_count = server.mutation_attempts
            resumed = self.dependencies(repository, server, [])
            result = bootstrap.run_bootstrap(
                repository.root,
                Path(sys.executable),
                dependencies=resumed,
            )
            self.assertTrue(result.final_receipt.path.is_file())
            self.assertGreater(server.mutation_attempts, mutation_count)
            self.assertFalse(paths.routing_input.exists())
            self.assertFalse(paths.routing_sender_password.exists())
            self.assertFalse(paths.routing_recipient_password.exists())

    def test_each_actor_cleanup_dispatch_failure_still_cleans_both_accounts(
        self,
    ) -> None:
        for failure_number in (18, 19):
            with (
                self.subTest(failure_number=failure_number),
                TemporaryRepository() as repository,
            ):
                server = FakeRegistryServer()
                server.fail_before_mutation_number = failure_number
                dependencies = self.dependencies(repository, server, [])

                with self.assertRaises(RuntimeError):
                    bootstrap.run_bootstrap(
                        repository.root,
                        Path(sys.executable),
                        dependencies=dependencies,
                    )

                self.assertEqual(
                    [
                        value
                        for value in server.objects["Account"].values()
                        if str(value.get("name", "")).startswith(
                            "dashboard-routing-",
                        )
                    ],
                    [],
                )
                paths = bootstrap.BootstrapPaths.for_repository(
                    repository.root,
                )
                self.assertTrue(paths.routing_input.is_file())
                self.assertFalse(paths.routing_proof.exists())
                self.assertFalse(paths.final_receipt.exists())

    def test_resume_after_durable_routing_proof_removes_all_handoff_files(
        self,
    ) -> None:
        with TemporaryRepository() as repository:
            server = FakeRegistryServer()
            dependencies = self.dependencies(repository, server, [])
            original = bootstrap._safe_unlink_0600
            failed = False

            def fail_first_unlink(path: Path, *, root: Path) -> None:
                nonlocal failed
                if not failed:
                    failed = True
                    raise bootstrap.BootstrapError(
                        "injected post-proof unlink failure",
                    )
                original(path, root=root)

            with (
                mock.patch.object(
                    bootstrap,
                    "_safe_unlink_0600",
                    side_effect=fail_first_unlink,
                ),
                self.assertRaisesRegex(
                    bootstrap.BootstrapError,
                    "post-proof unlink failure",
                ),
            ):
                bootstrap.run_bootstrap(
                    repository.root,
                    Path(sys.executable),
                    dependencies=dependencies,
                )

            paths = bootstrap.BootstrapPaths.for_repository(repository.root)
            self.assertTrue(paths.routing_proof.is_file())
            self.assertFalse(paths.final_receipt.exists())
            self.assertTrue(paths.routing_input.is_file())

            resumed = self.dependencies(repository, server, [])
            result = bootstrap.run_bootstrap(
                repository.root,
                Path(sys.executable),
                dependencies=resumed,
            )

            self.assertTrue(result.final_receipt.path.is_file())
            self.assertFalse(paths.routing_input.exists())
            self.assertFalse(paths.routing_sender_password.exists())
            self.assertFalse(paths.routing_recipient_password.exists())

    def test_final_bootstrap_rerun_is_validation_only_and_idempotent(
        self,
    ) -> None:
        with TemporaryRepository() as repository:
            server = FakeRegistryServer()
            first = self.dependencies(repository, server, [])
            original = bootstrap.run_bootstrap(
                repository.root,
                Path(sys.executable),
                dependencies=first,
            )
            mutation_count = server.mutation_attempts
            final_bytes = original.final_receipt.path.read_bytes()

            second = self.dependencies(repository, server, [])
            validated = bootstrap.run_bootstrap(
                repository.root,
                Path(sys.executable),
                dependencies=second,
            )

            self.assertEqual(
                validated.bootstrap_receipt_sha256,
                original.bootstrap_receipt_sha256,
            )
            self.assertEqual(server.mutation_attempts, mutation_count)
            self.assertEqual(
                validated.final_receipt.path.read_bytes(),
                final_bytes,
            )


@unittest.skipIf(bootstrap is None, "bootstrap planner is not implemented")
class CliTest(unittest.TestCase):
    def test_bootstrap_cli_requires_exact_repository_and_migration_python(
        self,
    ) -> None:
        parser = bootstrap._build_argument_parser()
        options = parser.parse_args(
            [
                "bootstrap",
                "--repository",
                str(REPOSITORY_ROOT),
                "--migration-python",
                sys.executable,
            ],
        )

        self.assertEqual(options.command, "bootstrap")
        self.assertEqual(options.repository, REPOSITORY_ROOT)
        self.assertEqual(options.migration_python, Path(sys.executable))

    def test_initialize_fresh_cli_has_the_exact_documented_shape(self) -> None:
        parser = bootstrap._build_argument_parser()
        options = parser.parse_args(
            [
                "initialize-fresh",
                "--repository",
                str(REPOSITORY_ROOT),
            ],
        )

        self.assertEqual(options.command, "initialize-fresh")
        self.assertEqual(options.repository, REPOSITORY_ROOT)

    def test_routing_command_is_the_fixed_list_form_contract(self) -> None:
        invocation = "0123456789abcdef0123456789abcdef"
        self.assertEqual(
            bootstrap.build_routing_verifier_command(
                REPOSITORY_ROOT,
                invocation,
            ),
            [
                str(REPOSITORY_ROOT / "debug-dashboard" / "kotlin"),
                "--log-level",
                "off",
                "run",
                "-m",
                "dashboard-server",
                "--main-class",
                (
                    "mail.sandbox.dashboard.server.gate.stalwart."
                    "StalwartRoutingProofCliKt"
                ),
                "--",
                "--dashboard-project-root",
                str(REPOSITORY_ROOT / "debug-dashboard"),
                "--invocation-id",
                invocation,
            ],
        )

    def test_bootstrap_cli_wires_production_dependencies_and_safe_output(
        self,
    ) -> None:
        dependencies = object()
        token = SimpleNamespace(
            final_receipt=SimpleNamespace(
                path=(
                    REPOSITORY_ROOT
                    / "debug-dashboard"
                    / ".runtime"
                    / "stalwart"
                    / "bootstrap.json"
                ),
            ),
        )
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            mock.patch.object(
                bootstrap,
                "production_orchestrator_dependencies",
                return_value=dependencies,
            ),
            mock.patch.object(
                bootstrap,
                "run_bootstrap",
                return_value=token,
            ) as run,
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            result = bootstrap.main(
                [
                    "bootstrap",
                    "--repository",
                    str(REPOSITORY_ROOT),
                    "--migration-python",
                    sys.executable,
                ],
            )

        self.assertEqual(result, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(
            stdout.getvalue(),
            f"{token.final_receipt.path}\n",
        )
        run.assert_called_once_with(
            REPOSITORY_ROOT,
            Path(sys.executable),
            dependencies=dependencies,
        )

    def test_initialize_fresh_cli_wires_production_stages_once(self) -> None:
        dependencies = object()
        receipt = (
            REPOSITORY_ROOT
            / "debug-dashboard"
            / ".runtime"
            / "stalwart"
            / "current.json"
        )
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            mock.patch.object(
                bootstrap,
                "production_fresh_initialization_dependencies",
                return_value=dependencies,
            ),
            mock.patch.object(
                bootstrap,
                "initialize_fresh",
                return_value=receipt,
            ) as initialize,
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            result = bootstrap.main(
                [
                    "initialize-fresh",
                    "--repository",
                    str(REPOSITORY_ROOT),
                ],
            )

        self.assertEqual(result, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(stdout.getvalue(), f"{receipt}\n")
        initialize.assert_called_once_with(
            REPOSITORY_ROOT,
            dependencies=dependencies,
        )

    def test_bootstrap_cli_rejects_any_other_repository_before_live_loading(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            stderr = io.StringIO()
            with (
                mock.patch.object(
                    bootstrap,
                    "production_orchestrator_dependencies",
                ) as production,
                redirect_stderr(stderr),
            ):
                result = bootstrap.main(
                    [
                        "bootstrap",
                        "--repository",
                        str(Path(directory).resolve()),
                        "--migration-python",
                        sys.executable,
                    ],
                )

        self.assertEqual(result, 1)
        self.assertIn("exact repository", stderr.getvalue())
        production.assert_not_called()

    def test_bootstrap_cli_never_prints_dependency_exception_details(
        self,
    ) -> None:
        canary = "routing-password-canary"
        stderr = io.StringIO()
        with (
            mock.patch.object(
                bootstrap,
                "production_orchestrator_dependencies",
                return_value=object(),
            ),
            mock.patch.object(
                bootstrap,
                "run_bootstrap",
                side_effect=bootstrap.BootstrapError(canary),
            ),
            redirect_stderr(stderr),
        ):
            result = bootstrap.main(
                [
                    "bootstrap",
                    "--repository",
                    str(REPOSITORY_ROOT),
                    "--migration-python",
                    sys.executable,
                ],
            )

        self.assertEqual(result, 1)
        self.assertNotIn(canary, stderr.getvalue())
        self.assertEqual(
            stderr.getvalue(),
            "error: Stalwart bootstrap failed safely\n",
        )

    def test_bootstrap_cli_redacts_live_base_exception_details(
        self,
    ) -> None:
        for failure in (
            KeyboardInterrupt("routing-password-canary"),
            SystemExit("routing-password-canary"),
        ):
            with self.subTest(failure=type(failure).__name__):
                stdout = io.StringIO()
                stderr = io.StringIO()
                with (
                    mock.patch.object(
                        bootstrap,
                        "production_orchestrator_dependencies",
                        return_value=object(),
                    ),
                    mock.patch.object(
                        bootstrap,
                        "run_bootstrap",
                        side_effect=failure,
                    ),
                    redirect_stdout(stdout),
                    redirect_stderr(stderr),
                ):
                    result = bootstrap.main(
                        [
                            "bootstrap",
                            "--repository",
                            str(REPOSITORY_ROOT),
                            "--migration-python",
                            sys.executable,
                        ],
                    )

                self.assertEqual(result, 1)
                self.assertEqual(stdout.getvalue(), "")
                self.assertEqual(
                    stderr.getvalue(),
                    "error: Stalwart bootstrap failed safely\n",
                )

    def test_cli_is_validation_only_and_execute_actions_fail_closed(self) -> None:
        parser = bootstrap._build_argument_parser()
        help_text = parser.format_help()
        self.assertIn("validate-assets", help_text)
        self.assertIn(
            "validate the fixed manifest and Sieve policy",
            help_text,
        )
        self.assertNotIn("migration receipt", help_text)
        self.assertIn("bootstrap", help_text)
        self.assertIn("initialize-fresh", help_text)
        self.assertNotIn("execute", help_text)
        self.assertNotIn("apply", help_text)

        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            result = bootstrap.main(["execute"])
        self.assertEqual(result, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("unavailable", stderr.getvalue())

    def test_validate_assets_prints_only_a_safe_fixed_path(self) -> None:
        with TemporaryRepository() as repository:
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                result = bootstrap.main(
                    ["validate-assets", "--repository", str(repository.root)],
                )
            self.assertEqual(result, 0)
            self.assertEqual(
                stdout.getvalue(),
                f"{repository.root / 'stalwart' / 'bootstrap-v016.ndjson'}\n",
            )


if __name__ == "__main__":
    unittest.main()
