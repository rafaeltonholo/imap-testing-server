# Debug Dashboard Gate 0B — Stalwart v0.16.14 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove—or stop safely before migration—that Stalwart v0.16.14 supports the approved protected management credential, Account-bound dashboard AppPasswords, encrypted local credential lifecycle, every required management/mail/submission/deletion contract, and optional structured-log enrichment.

**Architecture:** A protected management Account performs only Account/Domain/Task and optional Log administration. Each ordinary Account creates its own Replace-scoped, mail-only AppPassword while its normal password is present for that request; the read-once value enters a fixed JDK AES-256-GCM snapshot and is leased to direct JMAP calls. No Account, role, API key, AppPassword, fixture, or test receives `impersonate`.

**Tech Stack:** Pinned Stalwart Community v0.16.14, Kotlin/JVM Ktor client gate tests, JDK NIO/cryptography, JMAP Core/Mail/Submission plus Stalwart registry extensions, the official tagged v0.16 migration script, Docker Compose.

---

> **Current live checkpoint (2026-07-29):** the authorized live capture has
> **not** run. The primary checkout's `docker-compose.yml` and
> `stalwart/config.toml` remain the v0.15 runtime inputs, and
> `stalwart/config.json` is not yet the live configuration. The implementation
> and offline tests do not constitute a live migration pass. Do not run
> dry-run, apply, bootstrap, or recovery retirement until Task 5 produces and
> verifies the source receipt.

## Approved credential contract

**Prerequisite:** Gate 0A reports `PASS`; the checked-in `debug-dashboard/kotlin` wrapper and three Toolchain modules exist. Do not substitute Gradle or an ad-hoc Kotlin build for this plan.

The previous global-impersonation proposal is rejected and is not a stop gate to reproduce during implementation. Gate 0B is executable only with these invariants:

- the management API key has Replace permissions containing `authenticate` and only the required `sysAccount*`, `sysDomain*`, `sysTask*`, and optional `sysLog*` methods;
- management has no `impersonate`, mail, blob, Identity, submission, normal-password-specific, API-key-management, or AppPassword-management permission;
- each ordinary Account may own one active credential whose description starts `mail-sandbox/debug-dashboard/`, plus at most one staged or retiring generation during bounded rotation;
- that AppPassword has Replace permissions for only the exact dashboard JMAP mail surface and cannot manage credentials;
- normal passwords are request-scoped inputs for create, enrollment, repair, and explicit rotation only;
- the dashboard's read-once AppPassword values live only in the fixed encrypted snapshot and transient credential leases;
- credential-list revocation follows the documented trusted no-concurrent-external-writer contract because v0.16.14 has no `ifInState` guard for the Account credential-list patch;
- no migration or repository `stalwart-data/` mutation begins until the disposable fixture passes Tasks 1–4.

## Task 1: Build the disposable v0.16.14 fixture and scoped bootstrap

**Files:**

- Create: `debug-dashboard/dashboard-server/testResources/stalwart-gate0b/compose.yml`
- Create: `debug-dashboard/dashboard-server/testResources/stalwart-gate0b/compose.recovery.yml`
- Create: `debug-dashboard/dashboard-server/testResources/stalwart-gate0b/config.json`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/gate/stalwart/GateJmapClient.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/gate/stalwart/GateBootstrap.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/stalwart/GateJmapClientTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/stalwart/StalwartFixtureSecretTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/stalwart/StalwartFixturePrepareLiveTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/stalwart/StalwartBootstrapTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/stalwart/StalwartBootstrapLiveTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/stalwart/StalwartRecoveryRetirementLiveTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/stalwart/StalwartGateCleanupTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/stalwart/StalwartGateCleanupLiveTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/stalwart/StalwartLiveTestEnvironment.kt`
- Create: `docs/debug-dashboard/gates/0b-stalwart.md`

- [ ] Write the failing fixture audit first. It must reject any image other than `stalwartlabs/stalwart:v0.16.14`, an enterprise license, non-loopback publication, `impersonate`, a mount of repository `stalwart-data/`, a missing readiness healthcheck, or scratch state outside ignored `debug-dashboard/.runtime/stalwart-gate0b/`.

- [ ] Create the base fixture with only `127.0.0.1:18443:8080` and the dedicated SMTP proof mapping `127.0.0.1:18587:8587`, a real readiness healthcheck, and gate-owned scratch state. Keep every `STALWART_RECOVERY_*` variable out of the base file.

- [ ] Add a recovery override containing only `STALWART_RECOVERY_MODE=1`, `STALWART_RECOVERY_MODE_PORT=8080`, and the required `STALWART_GATE_RECOVERY_ENV_FILE`. `StalwartFixturePrepareLiveTest` creates:

```text
debug-dashboard/.runtime/stalwart-gate0b/recovery.env
debug-dashboard/.runtime/stalwart-gate0b/recovery-handoff
```

Both are beneath owner-only directories and mode `0600`. `StalwartBootstrapLiveTest` generates the management key and two ordinary passwords and writes them to mode-`0600` `debug-dashboard/.runtime/stalwart-gate0b/fixture-secrets`, which later JVM invocations locate only through `STALWART_GATE_FIXTURE_SECRETS_FILE`. The environment carries a path, never a secret; no secret appears in argv, Compose output, or test evidence.

- [ ] Make every opt-in operation an unconditional class whose name ends in `LiveTest`. Exact class selection is the authorization boundary: prepare requires only exact `STALWART_GATE_PREPARE=1`, cleanup requires only exact `STALWART_GATE_CLEANUP=1`, and networked live classes require `STALWART_LIVE_TESTS=1`, an explicit loopback `STALWART_BASE_URL`, and the fixed handoff path. Missing or conflicting configuration, a raw selected class without environment, or an unreachable endpoint fails the selected suite—it never returns early, uses a JUnit assumption, silently skips, or falls back to another Stalwart instance. Canonical offline and full-suite commands use exactly one exclusion: `mail.sandbox.dashboard.server.gate.stalwart.*LiveTest`.

- [ ] Implement only the typed registry/JMAP calls needed to discover `/.well-known/jmap`, expand the returned `apiUrl`, and create/query registry objects. Accept only the exact `http://127.0.0.1:18443/jmap/` endpoint with no userinfo, query, or fragment. Malformed-but-valid JSON fields/tuples and response-body read failures must become typed, redacted gate failures. Add a test that fails if a legacy `/api/principal` path is requested.

- [ ] Bootstrap the scratch store in this order:

  1. start `compose.yml` plus `compose.recovery.yml`;
  2. wait for the recovery endpoint and authenticate with the generated recovery credential;
  3. create the minimal normal HTTP listener, the loopback-only SMTP proof listener on container port `8587`, `MtaStageAuth` with an empty match map and `[plain]` fallback, SystemSettings, local Domain, one protected management Account/API key, and two ordinary User Accounts/passwords;
  4. fetch and verify every object's type, roles, permissions, credential type, and immutable protected ID;
  5. stop without deleting scratch state;
  6. restart with base `compose.yml` only;
  7. prove the container environment has no `STALWART_RECOVERY_` entry;
  8. through a fresh JVM invocation, prove the retired recovery credential fails while the management key and ordinary passwords from the fixed handoff authenticate.

- [ ] Give the management API key Replace mode and exactly this required baseline:

```text
authenticate
sysAccountGet
sysAccountQuery
sysAccountCreate
sysAccountUpdate
sysAccountDestroy
sysDomainGet
sysDomainQuery
sysDomainCreate
sysTaskGet
sysTaskQuery
```

Add `sysLogGet` and `sysLogQuery` only when the disposable fixture enables structured Log. Fetch the created API-key object and assert effective mode `Replace` with the exact list—not merely the create request. Assert the complete effective permission set contains no wildcard, inherited permission, `impersonate`, mail permission, `sysAccountPassword*`, `sysApiKey*`, or `sysAppPassword*`.

- [ ] Create a temporary otherwise-identical API key without `authenticate`, fetch it to prove the intended permission list, and assert authentication fails. Revoke it before continuing.

- [ ] Run the narrow bootstrap proof:

```bash
cd debug-dashboard
./kotlin test \
  --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.gate.stalwart.*' \
  --exclude-classes 'mail.sandbox.dashboard.server.gate.stalwart.*LiveTest'

DASHBOARD_WEB_ASSETS="$PWD/build/tasks/_dashboard-web_linkWasmJs" \
DASHBOARD_WEB_RESOURCES="$PWD/build/artifacts/PreparedComposeResourcesDirArtifact/dashboard-webcommon" \
DASHBOARD_WEB_ENTRY="dashboard-web.mjs" \
./kotlin test \
  --include-module dashboard-contract \
  --include-module dashboard-server \
  --include-module dashboard-web \
  --exclude-classes 'mail.sandbox.dashboard.server.gate.stalwart.*LiveTest'

STALWART_GATE_PREPARE=1 \
./kotlin test \
  --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.gate.stalwart.StalwartFixturePrepareLiveTest'
cd ..
export STALWART_GATE_RECOVERY_ENV_FILE="$PWD/debug-dashboard/.runtime/stalwart-gate0b/recovery.env"
docker compose -p mail-sandbox-stalwart-gate \
  -f debug-dashboard/dashboard-server/testResources/stalwart-gate0b/compose.yml \
  -f debug-dashboard/dashboard-server/testResources/stalwart-gate0b/compose.recovery.yml \
  up -d --wait
cd debug-dashboard
STALWART_LIVE_TESTS=1 \
STALWART_BASE_URL=http://127.0.0.1:18443 \
STALWART_GATE_FIXTURE_SECRETS_FILE="$PWD/.runtime/stalwart-gate0b/fixture-secrets" \
./kotlin test \
  --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.gate.stalwart.StalwartBootstrapLiveTest'
cd ..
docker compose -p mail-sandbox-stalwart-gate \
  -f debug-dashboard/dashboard-server/testResources/stalwart-gate0b/compose.yml \
  stop stalwart
docker compose -p mail-sandbox-stalwart-gate \
  -f debug-dashboard/dashboard-server/testResources/stalwart-gate0b/compose.yml \
  up -d --wait --force-recreate
if docker compose -p mail-sandbox-stalwart-gate \
  -f debug-dashboard/dashboard-server/testResources/stalwart-gate0b/compose.yml \
  exec -T stalwart /usr/bin/env | rg -q '^STALWART_RECOVERY_'; then
  echo "unexpected recovery variable" >&2
  exit 1
fi
cd debug-dashboard
STALWART_LIVE_TESTS=1 \
STALWART_BASE_URL=http://127.0.0.1:18443 \
STALWART_GATE_FIXTURE_SECRETS_FILE="$PWD/.runtime/stalwart-gate0b/fixture-secrets" \
./kotlin test \
  --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.gate.stalwart.StalwartRecoveryRetirementLiveTest'
```

Expected: the `rg` command prints nothing; all assertions pass, recovery is retired, and no ordinary mail AppPassword exists yet.

- [ ] Commit:

```bash
git add debug-dashboard/dashboard-server \
  docs/debug-dashboard/gates/0b-stalwart.md \
  docs/superpowers/plans/2026-07-23-debug-dashboard-gate-0b-stalwart.md
git commit -m "test: bootstrap scoped Stalwart gate fixture"
```

## Task 2: Prove direct AppPassword and permission semantics

**Files:**

- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/gate/stalwart/GateAppPasswordClient.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/stalwart/GateAppPasswordClientTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/stalwart/StalwartRawBlobCompatibilityLiveTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/stalwart/StalwartPermissionMatrixLiveTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/stalwart/StalwartAppPasswordSemanticsLiveTest.kt`
- Modify: `docs/debug-dashboard/gates/0b-stalwart.md`

- [x] Start with this source-derived AppPassword Replace allowlist:

```kotlin
val dashboardMailPermissions = setOf(
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
```

The live method matrix is authoritative. Pinned-source inspection predicts that
JMAP `EmailSubmission/set` does not need `emailSend`, while SMTP AUTH does.
Prove JMAP submission succeeds without `emailSend` and paired SMTP AUTH fails
before accepting the narrower list. If one required JMAP method reports a
missing permission, add only its exact named permission after a focused negative
test proves the need and record the final set in the gate report. Never switch
to `Inherit`, a wildcard, or unrelated `changes/queryChanges` methods. Fetch
every created AppPassword object and assert declarative mode `Replace` plus the
exact final list, then verify the credential's effective scope through
`/api/account`.

- [x] Before creating any AppPassword, characterize raw HTTP
  `/jmap/upload/{accountId}` and download authorization. Pinned-source
  inspection predicted that these routes bypass `jmapBlobUpload`/`jmapBlobGet`
  and upload membership checks. The disposable v0.16.14 fixture confirmed that
  the management key can upload to its own and an ordinary Account ID and can
  download its own exact probe bytes; cross-Account management download remains
  denied.

  Decision (`2026-07-28`): accept this as a local-only test-provider
  compatibility limitation and continue. It is not credential isolation.
  Preserve loopback-only binding, keep management registry and Account-bound
  mail/Blob clients type-separated, and never route the management credential
  through the product raw Blob client. Any public, shared-untrusted, or
  production use turns this accepted limitation back into `STOP`.

- [x] Write the failing semantics test before the client. Authenticated as the exact ordinary Account with its normal password, create `x:AppPassword` with description `mail-sandbox/debug-dashboard/<store-uuid>/<generation>`. Assert the server generates the secret, returns its plaintext only in `created`, returns only the non-recoverable `"****"` sentinel from later exact-ID get, does not permit secret update, and permits two simultaneous credentials for bounded rotation. Query IDs first and get only those exact IDs; get-all mixes credential types into `notFound`.

- [x] Prove the created AppPassword directly authenticates only its owning Account and can execute the exact mailbox/Email/blob/Identity/submission calls in the allowlist. Prove cross-account username/credential combinations fail.

- [x] Prove the AppPassword cannot call Account/Domain/Task/Log methods, change the normal Password, create/query/update/destroy AppPasswords, create/query/update/destroy API keys, or use `target%credential` impersonation.

- [x] Prove the management key cannot read/mutate/submit mail and cannot create or use another Account's AppPassword through `x:AppPassword`. Through `x:Account/get|set`, prove it can freshly fetch the target's credential list, remove only a known dashboard-reserved secondary credential, submit one update, re-fetch, and verify every unrelated credential object is unchanged.

- [x] Fetch every Account, role, API key, AppPassword, and fixture principal created by the gate and assert no effective permission set contains `impersonate`.

- [x] Encode the trusted test-sandbox concurrency contract in the test: no external writer may edit the Account credential list between the pre-update fetch and post-update verification. Do not send or claim an `ifInState` guard for this patch. Inject a mismatched post-fetch response and require `reconciliationRequired`, never a second blind patch.

- [x] Prove wrong, revoked, protected-Account, management-Account, cross-account, and quota-exhausted cases. Quota exhaustion must leave the existing active credential valid and unchanged.

- [x] Run:

```bash
cd debug-dashboard
export STALWART_GATE_FIXTURE_SECRETS_FILE="$PWD/.runtime/stalwart-gate0b/fixture-secrets"
STALWART_LIVE_TESTS=1 \
STALWART_BASE_URL=http://127.0.0.1:18443 \
./kotlin test \
  --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.gate.stalwart.StalwartRawBlobCompatibilityLiveTest'

STALWART_LIVE_TESTS=1 \
STALWART_BASE_URL=http://127.0.0.1:18443 \
./kotlin test \
  --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.gate.stalwart.StalwartPermissionMatrixLiveTest'

STALWART_LIVE_TESTS=1 \
STALWART_BASE_URL=http://127.0.0.1:18443 \
./kotlin test \
  --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.gate.stalwart.StalwartAppPasswordSemanticsLiveTest'
```

Expected: the accepted local-only raw Blob behavior remains exactly
characterized; direct Account-bound mail access and targeted management
revocation pass with zero `impersonate` grant. Any other required Community
behavior failure records `STOP` before Task 3.

- [x] Commit:

```bash
git add debug-dashboard/dashboard-server docs/debug-dashboard/gates/0b-stalwart.md
git commit -m "test: prove Stalwart AppPassword isolation"
```

## Task 3: Implement and prove the encrypted credential snapshot

**Files:**

- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/provider/stalwart/credential/SecretBytes.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/provider/stalwart/credential/StalwartCredentialRecord.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/provider/stalwart/credential/StalwartCredentialStore.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/provider/stalwart/credential/FileStalwartCredentialStore.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/provider/stalwart/credential/FileStalwartCredentialStoreTest.kt`
- Modify: `debug-dashboard/.gitignore`

- [ ] Write failing tests for the two valid startup shapes:

  - neither key nor ciphertext exists: create a new key plus empty snapshot;
  - both valid files exist: decrypt and return the exact snapshot.

Every lone key, lone ciphertext, wrong key, authentication-tag failure, malformed header, unsupported version, unreadable file, symlink, non-regular file, unsafe mode, or interrupted pair produces `storeUnavailable` and leaves existing bytes untouched.

- [ ] Define a versioned binary envelope with a non-secret magic/version/store UUID and fresh 96-bit nonce header. Bind the entire header plus fixed format identity as AES-GCM associated data. Encrypt a payload containing revision and Account-ID-keyed records:

```kotlin
internal data class StalwartCredentialRecord(
    val accountId: String,
    val addressAtCapture: String,
    val phase: CredentialPhase,
    val active: CredentialGeneration?,
    val other: CredentialGeneration?,
)
```

`other` means staged during successor probing or retiring after the active switch. `SecretBytes` has no revealing `toString`, is not part of browser contracts, and clears mutable bytes on close.

- [ ] Implement only JDK `AES/GCM/NoPadding` with a generated 256-bit key. Do not add Keychain, KMS, vault, automatic expiry, or a second secret copy.

- [ ] Use the exact paths:

```text
debug-dashboard/.runtime/stalwart/app-passwords.v1.enc
debug-dashboard/.runtime/keys/stalwart-app-passwords.v1.key
debug-dashboard/.runtime/stalwart/app-passwords.v1.lock
```

Create owner-only directories and mode-`0600` regular files where POSIX modes exist. Reject symlink path components. Under the stable lock file, write a restrictive same-directory temporary snapshot, `fsync`, atomically replace, and `fsync` the parent where supported.

- [ ] Add fault tests before implementation for concurrent writers, crash before replace, crash after replace, abandoned temporary cleanup, revision mismatch, Account ID/address reuse, and plaintext canary absence from ciphertext, filenames, exceptions, logs, and serialized test diagnostics.

- [ ] Add an explicit quarantine primitive for store reset. It may move unusable key/ciphertext only to owner-only, generated names under `debug-dashboard/.runtime/stalwart/quarantine/`; it never overwrites or silently discards them.

- [ ] Run:

```bash
cd debug-dashboard
./kotlin test \
  --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.provider.stalwart.credential.FileStalwartCredentialStoreTest'
```

Expected: all round-trip, corruption, path, atomicity, and exclusion tests pass.

- [ ] Commit:

```bash
git add debug-dashboard/.gitignore debug-dashboard/dashboard-server
git commit -m "feat: add encrypted Stalwart credential store"
```

## Task 4: Prove the complete mail-access lifecycle and leases

**Files:**

- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/provider/stalwart/credential/StalwartReservedCredential.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/provider/stalwart/credential/StalwartMailAccessState.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/provider/stalwart/credential/StalwartMailAccessResult.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/provider/stalwart/credential/StalwartMailCredentialRemote.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/provider/stalwart/credential/StalwartCredentialLeaseRegistry.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/provider/stalwart/credential/StalwartMailAccessService.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/provider/stalwart/credential/StalwartMailAccessServiceTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/stalwart/StalwartMailAccessLifecycleLiveTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/stalwart/StalwartMailAccessRestartPrepareLiveTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/stalwart/StalwartMailAccessRestartReconcileLiveTest.kt`
- Modify: `docs/debug-dashboard/gates/0b-stalwart.md`

- [ ] Write the pure/fake-remote state tests first. Cover:

  - no local/no reserved remote → `enrollmentRequired`;
  - one matching, directly authenticated generation → `ready`;
  - revoked, mismatched, malformed, or uncaptured reserved remote → `recoveryRequired`;
  - staged or retiring second generation → `rotating`;
  - remotely revoked but locally unerased → `removalPending`;
  - invalid store pair → global `storeUnavailable`, superseding Account states;
  - protected identities have no mail-access action.

These Gate-owned internal state/result types carry no browser DTO and no secret; Foundation later maps them into shared KMP contracts instead of redefining lifecycle semantics.

- [ ] Implement `StalwartCredentialLeaseRegistry` keyed by immutable Account ID. Normal mail calls may acquire a lease only for `ready`; enrollment, repair, rotation, removal, normal-password reset, and Account deletion acquire the exclusive side, block new leases, and wait at most 30 seconds. A timeout changes neither provider nor local credential state and returns a retryable failure.

- [ ] Test enrollment with one request-scoped normal password: inventory reserved credentials first, create exactly one AppPassword as that Account, capture the read-once value durably, probe direct authentication/capabilities, then return `ready`. Clear the request password and temporary secret buffers on every success/failure path.

- [ ] Test a lost create response and a failure after remote creation but before durable capture. The service must remove all reserved credentials for that exact Account through the management path, verify none remain, discard the password, return `enrollmentRequired` plus a `reconciliationRequired` operation result, and require resupply for another attempt. Ambiguous cleanup remains `recoveryRequired` and makes no new credential.

- [ ] Test Repair: under the exclusive lock, inventory and remove every reserved credential, verify cleanup while preserving unrelated credentials, then make at most one replacement attempt with the supplied normal password. An external credential-list mismatch leaves account state `recoveryRequired` and operation state `reconciliationRequired`.

- [ ] Test explicit Remove without a normal password: drain leases, revoke every reserved credential, verify none remain, then erase the local record. Remote success plus local-erasure failure records `removalPending`; local bytes are never erased first.

- [ ] Test rotation in exact durable phases:

  1. drain leases before any create;
  2. inventory quota and leave active unchanged if full;
  3. create/capture/probe one successor;
  4. persist it as staged;
  5. switch active and persist old as retiring;
  6. revoke old through the freshly fetched credential list;
  7. verify old failure/new success;
  8. erase old local bytes and return `ready`.

- [ ] Inject restart at every phase. A valid staged successor is promoted and old retired; an invalid staged successor is revoked and valid old restored; a retiring old generation is revoked before `ready`; durable `removalPending` with verified remote absence completes local erasure; neither valid, missing local material, an unknown remote reserved credential, or unavailable Stalwart creates nothing and returns recovery/reconciliation.

- [ ] Test explicit global store reset from every `storeUnavailable` shape. With the management key, enumerate every Account, remove every `mail-sandbox/debug-dashboard/` credential, preserve every unrelated credential, and verify the global reserved inventory is empty—including protected identities—before quarantining local files and creating a new empty store. Any unproven remote cleanup leaves the unusable store untouched and mail disabled.

- [ ] Keep the live lifecycle fixture isolated at `debug-dashboard/.runtime/stalwart-gate0b/credential-store/` through a test-only validated `CredentialStorePaths` factory. Production configuration tests still require the exact Task 3 paths and reject an override. Live teardown revokes every gate-reserved remote credential, verifies empty global inventory, closes the store, and removes only the resolved gate-owned credential-store directory so no gate Account ID survives into migration.

- [ ] Run the fake and live lifecycle suites:

```bash
cd debug-dashboard
export STALWART_LIVE_TESTS=1
export STALWART_BASE_URL=http://127.0.0.1:18443
export STALWART_GATE_FIXTURE_SECRETS_FILE="$PWD/.runtime/stalwart-gate0b/fixture-secrets"
export STALWART_GATE_CREDENTIAL_ROOT="$PWD/.runtime/stalwart-gate0b/credential-store"
./kotlin test \
  --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartMailAccessServiceTest'

./kotlin test \
  --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.gate.stalwart.StalwartMailAccessLifecycleLiveTest'

for phase in staged retiring removal-pending; do
  STALWART_GATE_RESTART_PHASE="$phase" \
  ./kotlin test \
    --include-module dashboard-server \
    --include-classes 'mail.sandbox.dashboard.server.gate.stalwart.StalwartMailAccessRestartPrepareLiveTest'
  STALWART_GATE_RESTART_PHASE="$phase" \
  ./kotlin test \
    --include-module dashboard-server \
    --include-classes 'mail.sandbox.dashboard.server.gate.stalwart.StalwartMailAccessRestartReconcileLiveTest'
done
```

Expected: every lifecycle, quota, drain, fault, and restart case passes; direct mail never uses the normal password or management key.

- [ ] Commit:

```bash
git add debug-dashboard/dashboard-server docs/debug-dashboard/gates/0b-stalwart.md
git commit -m "feat: prove Stalwart mail credential lifecycle"
```

## Disposable gate decision

- **PASS:** management/AppPassword permissions are disjoint at the JMAP and typed-client boundaries, no `impersonate` exists, direct Account-bound mail works, targeted revocation preserves unrelated credentials, the exact accepted local-only raw Blob behavior remains characterized, and every snapshot/lifecycle test in Tasks 1–4 passes on Community v0.16.14.
- **STOP:** a required method needs a broad/inherited permission; cross-account isolation fails outside the one characterized management raw upload using an ordinary Account ID; management raw Blob behavior exceeds the exact accepted same-Account upload/download plus ordinary-Account-ID upload; read-once capture or targeted revocation cannot be made deterministic; two-credential overlap/quota behavior fails; store recovery would require guessing; or another required Community behavior is unavailable.

On `STOP`, tear down only the named gate project, then run the path-validating cleanup test:

```bash
docker compose -p mail-sandbox-stalwart-gate \
  -f debug-dashboard/dashboard-server/testResources/stalwart-gate0b/compose.yml \
  down
cd debug-dashboard
STALWART_GATE_CLEANUP=1 \
./kotlin test \
  --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.gate.stalwart.StalwartGateCleanupLiveTest'
```

Expected: the resolved target is exactly the gate-owned runtime directory, all fixture secret/store files are removed, and repository `stalwart-data/` plus production credential paths are untouched. Request a new design decision; do not start migration or Gate 0C.

## Task 5: Capture the v0.15 source, then pin the v0.16.14 filesystem/runtime model

**Files:**

- Create: `scripts/capture_stalwart_v015.py`
- Create: `tests/test_capture_stalwart_v015.py`
- Modify: `docker-compose.yml`
- Create: `stalwart/config.json`
- Delete: `stalwart/config.toml`
- Modify: `.gitignore`
- Create: `docs/stalwart-v016-migration.md`

- [ ] Before editing `docker-compose.yml` or deleting `stalwart/config.toml`, write stdlib-only tests and `capture_stalwart_v015.py`. The capture command must:

  1. require the current service to report v0.15.x;
  2. record its resolved image reference, immutable image ID/digest, resolved Compose service, TOML digest, and data manifest;
  3. stop Stalwart and copy the complete stopped `stalwart-data/` plus TOML into a timestamped ignored backup;
  4. write a mode-`0600`, digest-bound source receipt and a pinned runnable rollback definition inside that backup;
  5. boot a copy on another loopback port and require version plus management-read success; and
  6. leave the real source stopped.

  The command refuses symlinks, broad paths, a running copy operation, an unpinned rollback image, or a partial backup. The v0.16 edits below cannot begin until `debug-dashboard/.runtime/stalwart-migration/latest-source.json` points to a verified capture. This ordering is mandatory even when implementation resumes from a later commit; if an existing store has no valid source receipt, stop rather than booting it with v0.16.

  Run the offline capture tests before requesting live authorization:

```bash
python3 -m unittest discover -s tests -p 'test_capture_stalwart_v015.py' -v
```

  Live capture requires a separate, immediate authorization containing this
  exact sentence:

```text
I explicitly authorize the Stalwart capture command and leaving the service stopped.
```

  That sentence authorizes only the following capture command and the
  documented consequence that the real v0.15 service remains stopped. It does
  not authorize migration, deletion, replacement of `stalwart-data/`, or
  starting another production runtime:

```bash
python3 scripts/capture_stalwart_v015.py capture --source-service stalwart
```

  The authorization phrase is an operator/agent approval boundary; it is not a
  prompt emitted by the script. Run the capture while the live Compose file and
  TOML are still v0.15, then run the read-only/isolated proofs:

```bash
python3 scripts/capture_stalwart_v015.py prove-rollback \
  --receipt debug-dashboard/.runtime/stalwart-migration/latest-source.json
python3 scripts/capture_stalwart_v015.py verify \
  --receipt debug-dashboard/.runtime/stalwart-migration/latest-source.json
```

Expected checkpoint: the live Compose labels bind the source to the
repository's primary checkout, the stopped source and full timestamped backup
verify, the primary checkout's fixed and canonical receipts are digest-bound,
and the independently runnable rollback copy proves v0.15 plus management read.
Offline development may happen in a worktree, but the authorized capture
intended for migration and every later live-chain command must run from the
captured primary checkout with the reviewed scripts/assets installed there.
Durable backup/rollback material lives beneath the ignored
`captures/debug-dashboard/stalwart-v015/` root in that primary checkout. The
real v0.15 source remains stopped. Only now modify the primary runtime.

- [ ] Replace `latest`, `/opt/stalwart`, TOML, and `ADMIN_SECRET` with the tested image/runtime:

```yaml
image: stalwartlabs/stalwart:v0.16.14
container_name: stalwart-dev
user: "2000:2000"
restart: unless-stopped
ports:
  - target: 8080
    published: "8443"
    host_ip: 127.0.0.1
    protocol: tcp
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
environment:
  STALWART_PUBLIC_URL: http://127.0.0.1:8443
healthcheck:
  test: ["CMD", "curl", "-fsS", "http://127.0.0.1:8080/healthz/ready"]
  interval: 2s
  timeout: 2s
  retries: 30
  start_period: 2s
```

Use the tagged image's UID/GID 2000 ownership requirement. Mount the whole
tracked `./stalwart` directory read-only at `/etc/stalwart`; do not replace it
with a child-file bind. The initial `stalwart/config.json` is exactly these
pretty-printed bytes:

```json
{
  "@type": "RocksDb",
  "path": "/var/lib/stalwart/"
}
```

The file is exactly 56 bytes, has no final LF, and has SHA-256
`8b48a8b7b4b4923083b045ff2fdd7eef690e3b53df2d449f891491172c791963`.
Verify both before starting v0.16:

```bash
test "$(wc -c < stalwart/config.json | tr -d ' ')" = 56
test "$(shasum -a 256 stalwart/config.json | awk '{print $1}')" = \
  8b48a8b7b4b4923083b045ff2fdd7eef690e3b53df2d449f891491172c791963
test "$(tail -c 1 stalwart/config.json | od -An -tuC | tr -d ' ')" = 125
```

Compact one-line JSON, a trailing LF, or any other reserialization is rejected
even if it is semantically equivalent.

- [ ] Ignore `debug-dashboard/.runtime/stalwart/`,
  `debug-dashboard/.runtime/keys/`,
  `debug-dashboard/.runtime/stalwart-migration/`, and the durable primary
  capture root `captures/debug-dashboard/stalwart-v015/`. Keep migration
  exports and secrets mode `0600`.

- [ ] Run:

```bash
python3 scripts/capture_stalwart_v015.py verify \
  --receipt debug-dashboard/.runtime/stalwart-migration/latest-source.json
docker compose config --quiet
docker compose config --images
```

Expected: the source receipt proves a complete, independently runnable v0.15 backup before the main Compose/config edit; the edited model contains only v0.16.14, loopback publication, and reviewed paths.

- [ ] Commit:

```bash
git add scripts/capture_stalwart_v015.py tests/test_capture_stalwart_v015.py docker-compose.yml stalwart/config.json stalwart/config.toml .gitignore docs/stalwart-v016-migration.md
git commit -m "chore: capture v0.15 and pin Stalwart v0.16.14"
```

## Task 6: Back up, dry-run, migrate, and prove rollback

**Files:**

- Create: `docker-compose.stalwart-migration.yml`
- Create: `scripts/stalwart_v016.py`
- Create: `scripts/bootstrap_stalwart_v016.py`
- Create: `tests/test_stalwart_v016.py`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/stalwart/StalwartMigrationLiveTest.kt`
- Modify: `docs/stalwart-v016-migration.md`

- [ ] Write stdlib-only tests for fixed repository paths, owner-only secret/backup files, list-form subprocesses, pinned images, and refusal to operate while either source or target store is running at an unsafe phase. Reuse `scripts/lib.py` where its API remains valid. Prove migration exports exclude `debug-dashboard/.runtime/stalwart/`, `.runtime/keys/`, quarantine, lock files, and the entire gate secret/store handoff.

- [ ] Load and re-verify Task 5's `latest-source.json`, backup digests, stopped-source marker, captured v0.15 image, and pinned rollback definition before touching real state. Do not try to reconstruct the source from the now-v0.16 main Compose file. A missing, stale, partial, or mismatched receipt is a hard stop. Never edit RocksDB keys.

- [ ] Obtain the tagged migration script from this exact source and checksum:

```text
https://raw.githubusercontent.com/stalwartlabs/stalwart/v0.16.14/resources/scripts/migrate_v016.py
SHA-256 008a490b4c3c60572806958e1960749ecdddf263316683017003797b9c34ca1c
```

Use it to dump v0.15 settings/principals and convert `/opt/stalwart` paths to `/var/lib/stalwart`. The wrapper writes `unmigrated.txt`; an implementer must inspect every entry before `mark-reviewed` creates a digest-bound review receipt.

Provision the upstream script's `requests` and `urllib3` dependencies in a
dedicated owner-only virtual environment, then expose that environment's
absolute Python path as `MIGRATION_PYTHON`. Do not install those dependencies
into the repository's host interpreter or silently fall back to it.

- [ ] Prove the captured backup through its separate rollback working copy and pinned v0.15 definition on another loopback port. Require version plus management-read success. Never boot the immutable archival `source-data` copy directly.

- [ ] Run v0.16.14 against the real store only through the migration override:
  loopback `18080`, temporary mode-`0600` recovery admin environment file,
  recovery mode enabled, no mail listeners, pinned image, and migrated data
  mount. Apply only the reviewed converted migration operations with zero
  failed operations; Task 7 alone owns bootstrap and the routing proof.

- [ ] Keep recovery retirement out of Task 6. `apply` must leave the
  digest-bound recovery artifacts available for Task 7 bootstrap. Only after
  the final Task 7 bootstrap receipt exists may retirement start the normal
  pinned service, inspect its environment, and prove the recovery credential
  fails.

- [ ] On an apply, bootstrap, or retirement failure, stop only an exact
  receipt-bound running container by its full container ID. Never stop an
  unvalidated or foreign candidate. Activate the isolated v0.15 rollback from
  the immutable backup and its scratch working copy. Activation does not copy
  over or restore into the real `stalwart-data/`: the failed real v0.16 store
  remains stopped and preserved for diagnosis. Bind restart state as part of
  identity: migration main/owner require `no`, normal runtime requires
  `unless-stopped`, and `Restarting=true`, `always`, `on-failure`, or a
  malformed policy blocks both stopping and activation. A stopped non-exact
  stale candidate is tolerable only with `Restarting=false` and persistent-stop
  policy `no` or `unless-stopped`.

- [ ] Run the Task 6 live sequence from the captured primary checkout root.
  The fixed scripts, overlay, and assets must be installed in that checkout;
  its receipt must identify the same checkout and real `stalwart-data/`.
  Worktrees remain valid only for offline development/tests and are not a live
  invocation root:

```bash
python3 -m unittest discover -s tests -p 'test_stalwart_v016.py' -v
python3 scripts/capture_stalwart_v015.py verify \
  --receipt debug-dashboard/.runtime/stalwart-migration/latest-source.json
python3 scripts/capture_stalwart_v015.py prove-rollback \
  --receipt debug-dashboard/.runtime/stalwart-migration/latest-source.json
: "${MIGRATION_PYTHON:?set MIGRATION_PYTHON to the absolute migration-venv Python path}"
mkdir -p debug-dashboard/.runtime/stalwart-migration
chmod 0700 debug-dashboard/.runtime/stalwart-migration
curl --proto '=https' --tlsv1.2 -fsSL \
  https://raw.githubusercontent.com/stalwartlabs/stalwart/v0.16.14/resources/scripts/migrate_v016.py \
  -o debug-dashboard/.runtime/stalwart-migration/migrate_v016.py
chmod 0600 debug-dashboard/.runtime/stalwart-migration/migrate_v016.py
echo "008a490b4c3c60572806958e1960749ecdddf263316683017003797b9c34ca1c  debug-dashboard/.runtime/stalwart-migration/migrate_v016.py" \
  | shasum -a 256 --check
python3 scripts/stalwart_v016.py dry-run \
  --script debug-dashboard/.runtime/stalwart-migration/migrate_v016.py \
  --source-receipt debug-dashboard/.runtime/stalwart-migration/latest-source.json \
  --migration-python "$MIGRATION_PYTHON"
wc -l debug-dashboard/.runtime/stalwart-migration/unmigrated.txt
sed -n '1,$p' debug-dashboard/.runtime/stalwart-migration/unmigrated.txt
python3 scripts/stalwart_v016.py mark-reviewed \
  --report debug-dashboard/.runtime/stalwart-migration/unmigrated.txt
python3 scripts/stalwart_v016.py apply \
  --script debug-dashboard/.runtime/stalwart-migration/migrate_v016.py \
  --review-receipt debug-dashboard/.runtime/stalwart-migration/reviewed.json
```

Expected: unit tests pass; the Task 5 source capture re-verifies as v0.15 and
rollback-capable; dry-run, review, and apply each emit a safe receipt path;
checksum says `OK`; `apply` materializes the recovery artifacts, supplies the
fixed migration path variables, and performs the exact primary-root/project
two-file Compose validation before `up`; `apply.json` plus recovery artifacts
are then ready for Task 7. Normal v0.16.14 restart and recovery retirement have
not happened yet. No command prints a credential.

- [ ] Commit:

```bash
git add docker-compose.stalwart-migration.yml scripts/stalwart_v016.py scripts/bootstrap_stalwart_v016.py tests/test_stalwart_v016.py debug-dashboard/dashboard-server docs/stalwart-v016-migration.md
git commit -m "feat: migrate Stalwart state to v0.16.14"
```

## Task 7: Bootstrap protected management and local-only mail policy

**Files:**

- Create: `scripts/bootstrap_stalwart_v016.py`
- Create: `tests/test_bootstrap_stalwart_v016.py`
- Create: `stalwart/bootstrap-v016.ndjson`
- Create: `stalwart/protected-recipients.sieve`
- Modify: `scripts/stalwart_v016.py`
- Modify: `tests/test_stalwart_v016.py`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/stalwart/StalwartRoutingLiveTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/stalwart/StalwartRuntimeCredentialLiveTest.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/provider/stalwart/StalwartRuntimeSecretLoader.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/provider/stalwart/StalwartRuntimeSecretLoaderTest.kt`
- Modify: `docs/stalwart-v016-migration.md`

- [ ] Before any live bootstrap, strictly parse and digest-bind the mode-`0644`,
  symlink-free tracked manifest and Sieve policy. Accept the Task 6 apply
  receipt only through its authoritative full-chain validator and bind a stable
  before/after snapshot; parsing or hashing arbitrary `apply.json` bytes does
  not establish trust. Plan every change from a fresh query: no-op when the
  owned projection already matches, patch only the owned fields while
  preserving unknown fields, create only when absent, and fail on duplicate or
  ambiguous state. When the Domain is absent, create only independent objects,
  then requery and resolve the real Domain ID before planning SystemSettings or
  Account changes; no planner-only reference token may reach Stalwart. A pre-existing
  `dashboard-management@local.test` Account without an owned durable checkpoint
  is ambiguous and must never be adopted or overwritten.

- [ ] Idempotently create the normal HTTP `NetworkListener`, update
  `SystemSettings`, reconcile the enabled non-relaying `local.test` Domain,
  create the named `Local` `MtaRoute`, create the active protected-recipient
  `SieveSystemScript`, and point the `MtaStageRcpt` singleton at that script.
  The owned Domain projection explicitly clears `directoryId` and
  `catchAllAddress`; the RCPT stage also sets `allowRelaying` to constant
  `false`. The Sieve policy rejects both the exact protected address and its
  `dashboard-management+*@local.test` subaddresses before enabled
  sub-addressing can canonicalize them.
  Pinned v0.16.14 exposes `Internal` only as a first-start bootstrap directory,
  not as a registry `Directory` object; do not invent one. Defer a file
  `Tracer` until its writable directory and exact `x:Log` permissions are
  separately proven. Preserve the v0.16.14 default `MtaOutboundStrategy`
  singleton instead of broadening the owned projection. Record its exact four
  default expressions as a separate read-only `preserved_objects` projection;
  it is not a ninth bootstrap-owned object. The live local-delivery proof must
  stop if that default is missing or incompatible.

- [ ] Create exactly one immutable protected management Account/API key with the
  Task 1 permission set. The owned Account projection includes `aliases: {}` so
  no alternate recipient address can bypass the exact and subaddress Sieve
  checks. A fresh authoritative projection must prove it has exactly the one
  intended API key and no Password or AppPassword, and must prove the fetched
  key's exact Account ID, permissions, allowed-IP value, and description. Direct
  authentication must prove the exact management Account. Stalwart's JMAP
  Session does not expose the authenticated credential ID, so the receipt must
  not claim that direct proof; the key ID is instead bound by the exact
  one-credential inventory. Generate:

```text
debug-dashboard/.runtime/secrets/stalwart-management-api-key
debug-dashboard/.runtime/stalwart/protected-accounts.json
```

The first is a mode-`0600` secret value; the second contains only immutable protected Account IDs and is also owner-readable. `StalwartRuntimeSecretLoader` accepts only those fixed, symlink-free regular paths from validated repository configuration, returns a mutable clearable value, and never logs/serializes it. Never add a Stalwart mail operator or any `impersonate` permission.

- [ ] Make bootstrap crash-recoverable with new-only mode-`0600`
  `bootstrap-attempt.json`, `bootstrap-account.json`, `bootstrap-key.json`, and
  `bootstrap-proof.json` checkpoints under the fixed migration root. Publish a
  durable ownership intent before the Account create dispatch so a
  crash-after-create can be distinguished from an unowned pre-existing
  Account. Record the one permitted key replacement in a separate new-only
  transition checkpoint before revocation or replacement; never rewrite the
  original attempt marker to advance a counter. A remote key without a durably
  captured secret is revoked by its exact owned ID before at most one
  replacement attempt. A local secret without its matching checkpoint is
  adopted only after exact Account, key, permission, inventory, and
  authentication proof; it is never silently overwritten. Once
  `bootstrap-key.json` exists, a missing or different raw key is manual
  reconciliation—not replacement—because a new-only key checkpoint cannot be
  rebound to a different credential.

- [ ] Publish a final new-only `bootstrap.json` receipt that binds the validated
  Task 6 apply receipt, tracked manifest and Sieve digests/identities, checkpoint
  chain, safe object projections and immutable IDs, exact permission digest,
  protected-ID digest, explicit management-key IP-restriction decision,
  Stalwart `0.16.14`, and direct authentication as the exact management Account.
  Before publishing it, require a fixed owner-only new-only
  `bootstrap-routing-proof.json` produced by the live verifier. Bind both the
  exact preserved `MtaOutboundStrategy` projection digest and the routing-proof
  file identity/digest. The routing proof records only safe Account, credential,
  submission, and message IDs plus normalized protocol outcomes; it contains no
  password, API-key value, or digest of either.
  Record only the management-key filename, size, and file identity—never its
  bytes or a digest of those bytes. Recovery retirement must validate and bind
  this receipt, its preserved-object projection, and the routing proof before
  deleting the recovery credential; generic HTTP success is insufficient.

- [ ] If the host-through-Docker source address is stable, probe with a temporary unrestricted management credential, issue the `/32`-restricted replacement, prove host success and disposable-container failure, revoke the probe, recreate the Compose network, and re-prove stability. If the address is unstable, retain loopback/network isolation and record why credential IP restriction is disabled.
  The final local fixture decision is
  `disabled-local-only-loopback-network-isolation`: the bootstrap Registry is
  published only on fixed loopback `127.0.0.1:18080`, so the management key
  deliberately uses exact empty `allowedIps` rather than binding a `/32` to an
  unstable host-through-Docker source address. This is a final decision, not a
  pending live-network proof.

- [ ] Do not bootstrap dashboard AppPasswords for migrated ordinary Accounts. Assert they project as `enrollmentRequired`; only a later explicit request carrying that Account's normal password may enroll them.

- [ ] Create disposable sender/recipient Accounts and explicitly enroll both through the request-scoped lifecycle. Live-test external/protected/unregistered recipient rejection and a normal registered `local.test` delivery/arrival with their own AppPasswords. Remove recipient access and prove readiness preflight makes zero upload/submission calls. If the JMAP submission path bypasses the proved local-recipient policy, record `STOP`.

- [ ] Run bootstrap only through `bootstrap_stalwart_v016.py`. It starts the
  receipt-bound migration recovery runtime at
  `http://127.0.0.1:18080`, invokes `StalwartRoutingProofCliKt` itself, and binds
  the resulting owner-only `bootstrap-routing-proof.json` into
  `bootstrap.json`. `StalwartRoutingLiveTest` is a migration-endpoint verifier,
  not a normal-runtime `:8443` check; do not invoke it manually against
  `:8443`.

- [ ] Run `retire-recovery` only after bootstrap has returned the validated
  final `bootstrap.json`. Retirement must bind the final bootstrap/routing
  proof and immutable management Account/API-key IDs, start only the base
  Compose service on loopback `8443`, prove the old recovery credential fails,
  and checkpoint `retire-recovery-proof.json` before deleting recovery
  artifacts. A restart with an attempt but no proof requires reconciliation and
  never replays the credential mutation. A restart with a valid proof resumes
  finalize-only deletion/postflight across all partial-deletion states. A
  substituted partial artifact fails closed, stops only the exact validated
  normal container by full ID, and activates isolated rollback without
  overwriting the failed real v0.16 store.

- [ ] Run and commit:

```bash
python3 -W error -m unittest \
  tests.test_bootstrap_stalwart_v016 \
  tests.test_stalwart_v016
python3 -m py_compile \
  scripts/bootstrap_stalwart_v016.py \
  scripts/stalwart_v016.py \
  tests/test_bootstrap_stalwart_v016.py \
  tests/test_stalwart_v016.py
REPOSITORY_ROOT="$(pwd -P)"
: "${MIGRATION_PYTHON:?set MIGRATION_PYTHON to the absolute migration-venv Python path}"
python3 scripts/bootstrap_stalwart_v016.py validate-assets \
  --repository "$REPOSITORY_ROOT"
python3 scripts/bootstrap_stalwart_v016.py bootstrap \
  --repository "$REPOSITORY_ROOT" \
  --migration-python "$MIGRATION_PYTHON"
python3 scripts/stalwart_v016.py retire-recovery
python3 scripts/stalwart_v016.py normal-runtime-evidence
cd debug-dashboard
./kotlin test --include-module dashboard-server --include-classes 'mail.sandbox.dashboard.server.provider.stalwart.StalwartRuntimeSecretLoaderTest'
STALWART_LIVE_TESTS=1 \
STALWART_BASE_URL=http://127.0.0.1:8443 \
./kotlin test --include-module dashboard-server --include-classes 'mail.sandbox.dashboard.server.gate.stalwart.StalwartMigrationLiveTest'
STALWART_LIVE_TESTS=1 \
STALWART_BASE_URL=http://127.0.0.1:8443 \
./kotlin test --include-module dashboard-server --include-classes 'mail.sandbox.dashboard.server.gate.stalwart.StalwartRuntimeCredentialLiveTest'
cd ..
git add \
  scripts/bootstrap_stalwart_v016.py \
  scripts/stalwart_v016.py \
  tests/test_bootstrap_stalwart_v016.py \
  tests/test_stalwart_v016.py \
  stalwart \
  debug-dashboard/dashboard-server \
  docs/stalwart-v016-migration.md
git commit -m "feat: bootstrap scoped Stalwart runtime"
```

Expected: Python planners and offline tests pass; bootstrap returns the fixed
final receipt only after the routing proof succeeds at `:18080`; retirement
then returns `recovery-retired.json`; the normal-runtime migration proof matches
the pre-migration manifest, preserved credentials, empty encrypted snapshot,
and `enrollmentRequired` projections; the loader and management credential
proof pass at `:8443`; and the unenrolled recipient case records zero
submission calls. Do not record a live pass until these commands actually run.

## Task 8: Prove management, mail, log, password, and deletion contracts

**Files:**

- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/stalwart/StalwartManagementLiveTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/stalwart/StalwartMailLiveTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/stalwart/StalwartDeletionLiveTest.kt`
- Modify: `docs/debug-dashboard/gates/0b-stalwart.md`

- [ ] Discover and use Session `apiUrl`, `uploadUrl`, and `downloadUrl`; add a test that fails on hardcoded `/api` or `/jmap`.

- [ ] Prove `x:Domain/query|get|set(create)` and `x:Account/query|get|set(create/update/destroy)` plus independent `created/updated/destroyed/not*` parsing. Do not claim `ifInState` for Account credential-list updates.

- [ ] Reset a disposable normal Password only after acquiring the Account's exclusive credential lock and draining leases for at most 30 seconds. Freshly fetch the Account credential list, replace only the Password object, submit once under the trusted no-concurrent-writer contract, re-fetch, and prove every AppPassword/API key/unrelated credential is preserved. Verify the new password, verify the test-owned old password fails, and re-probe the active dashboard AppPassword. Drain timeout performs no mutation.

- [ ] With a `ready` Account's leased AppPassword, prove Mailbox list/create/update/delete safety; Email query/get/import/update/destroy; upload/raw download; keyword/membership `ifInState` handling; partial errors/state mismatch; Identity selection; EmailSubmission creation-ID chaining; per-recipient status; recipient arrival read-back using each recipient's own credential; and truthful Sent filing.

- [ ] Prove optional file-backed `x:Log/query|get` only through the management key. Treat server filtering as text-only unless the live response demonstrates otherwise.

- [ ] Delete both a `ready` data-bearing Account and an `enrollmentRequired` Account under the same bounded exclusive credential lock. Required proof is `destroyed`, management lookup by the pre-mutation Account ID returning absent, and ordinary address/account resolution rejecting the identity. When an AppPassword existed, prove the old value fails; then erase its local Account-ID record. Inject local-erasure failure and require `removalPending` plus operation `reconciliationRequired` without relabeling provider deletion as failed. Recreating the address with a new Account ID must not reuse old local material. Drain timeout performs no mutation.

- [ ] Match `DestroyAccount` Task client-side by account fields. Map only Pending/Retry/Failed; observed then absent confirms cleanup, never observed remains `unverified`, and observed Failed makes the operation `reconciliationRequired`. Do not invent a succeeded Task state.

- [ ] Run the Task 8 live contracts and the credential-provider regression:

```bash
cd debug-dashboard
./kotlin test \
  --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.provider.stalwart.credential.*'
STALWART_LIVE_TESTS=1 \
STALWART_BASE_URL=http://127.0.0.1:8443 \
./kotlin test \
  --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.gate.stalwart.StalwartManagementLiveTest'
STALWART_LIVE_TESTS=1 \
STALWART_BASE_URL=http://127.0.0.1:8443 \
./kotlin test \
  --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.gate.stalwart.StalwartMailLiveTest'
STALWART_LIVE_TESTS=1 \
STALWART_BASE_URL=http://127.0.0.1:8443 \
./kotlin test \
  --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.gate.stalwart.StalwartDeletionLiveTest'
cd ..
docker compose config --quiet
```

Expected: pass with safe evidence and no secret value printed.

## Task 9: Retire v0.15 assumptions and decide Gate 0B

**Files:**

- Delete/Replace: `scripts/sync_stalwart_users.py`
- Modify: `scripts/reset.py`
- Create: `scripts/reset_stalwart_v016.py`
- Create: `tests/test_reset_stalwart_v016.py`
- Modify: `scripts/lib.py`
- Modify: `README.md`
- Modify: `CLAUDE.md`
- Modify: `.ai/architecture.md`
- Modify: `.ai/skills/stalwart/SKILL.md`
- Modify: `.ai/skills/stalwart/references/config.md`
- Modify: `.ai/skills/stalwart/references/admin-api.md`
- Modify: `.ai/skills/stalwart/references/oauth2.md`
- Modify: `.ai/skills/docker-compose/references/service-map.md`
- Modify: `.ai/skills/docker-compose/references/volume-mounts.md`
- Modify: `.ai/skills/python-scripts/references/script-inventory.md`
- Modify: `docs/debug-dashboard/gates/0b-stalwart.md`

- [ ] Remove active `latest`, TOML, `/opt/stalwart`, `/api/principal`, `ADMIN_SECRET`, external-OIDC-directory, Basic fallback-admin, shared-Dovecot-credential, mail-operator, and global-impersonation assumptions.

- [ ] Make ordinary `scripts/reset.py` leave `stalwart-data/`, `debug-dashboard/.runtime/stalwart/app-passwords.v1.enc`, `debug-dashboard/.runtime/stalwart/app-passwords.v1.lock`, `debug-dashboard/.runtime/stalwart/quarantine/`, `debug-dashboard/.runtime/keys/stalwart-app-passwords.v1.key`, and the Stalwart management secret/protected-ID files untouched.

- [ ] Implement `scripts/reset_stalwart_v016.py` as the separate explicit fresh-provider reset. Its stdlib test requires a typed confirmation, stopped Stalwart, a successful full backup receipt, exact validated provider/runtime targets, and a new bootstrap. It archives the old dashboard credential files because the new provider cannot contain matching credentials; it never invokes ordinary Clear Local History or edits individual RocksDB keys.

- [ ] Document the trusted local-only concurrency rule: do not edit an Account's credential list in Stalwart UI/another tool while the dashboard is enrolling, repairing, rotating, removing, resetting its password, or deleting it.

- [ ] Run stale-reference, config, stdlib script, unit, live permission/lifecycle/mail/routing/deletion, migration, and rollback checks:

```bash
python3 -m unittest discover -s tests -p 'test_stalwart_v016.py' -v
python3 -m unittest discover -s tests -p 'test_reset_stalwart_v016.py' -v
python3 scripts/capture_stalwart_v015.py verify \
  --receipt debug-dashboard/.runtime/stalwart-migration/latest-source.json
python3 scripts/capture_stalwart_v015.py prove-rollback \
  --receipt debug-dashboard/.runtime/stalwart-migration/latest-source.json
docker compose config --quiet
if rg -n 'stalwartlabs/stalwart:latest|/opt/stalwart|/api/principal|ADMIN_SECRET|management%operator|ordinary%operator' \
  docker-compose.yml stalwart scripts README.md CLAUDE.md .ai; then
  exit 1
fi
cd debug-dashboard
./kotlin test --include-module dashboard-server --include-classes 'mail.sandbox.dashboard.server.provider.stalwart.*'
export STALWART_LIVE_TESTS=1
export STALWART_BASE_URL=http://127.0.0.1:18443
export STALWART_GATE_FIXTURE_SECRETS_FILE="$PWD/.runtime/stalwart-gate0b/fixture-secrets"
export STALWART_GATE_CREDENTIAL_ROOT="$PWD/.runtime/stalwart-gate0b/credential-store"
for fixture_class in \
  StalwartRawBlobCompatibilityLiveTest \
  StalwartPermissionMatrixLiveTest \
  StalwartAppPasswordSemanticsLiveTest \
  StalwartMailAccessLifecycleLiveTest; do
  ./kotlin test \
    --include-module dashboard-server \
    --include-classes "mail.sandbox.dashboard.server.gate.stalwart.$fixture_class"
done
export STALWART_BASE_URL=http://127.0.0.1:8443
unset STALWART_GATE_FIXTURE_SECRETS_FILE
unset STALWART_GATE_CREDENTIAL_ROOT
for runtime_class in \
  StalwartMigrationLiveTest \
  StalwartRuntimeCredentialLiveTest \
  StalwartManagementLiveTest \
  StalwartMailLiveTest \
  StalwartDeletionLiveTest; do
  ./kotlin test \
    --include-module dashboard-server \
    --include-classes "mail.sandbox.dashboard.server.gate.stalwart.$runtime_class"
done
```

Expected: all checks pass and the stale-reference search prints nothing.

- [ ] Record the final decision:

  - **PASS:** all approved management, direct AppPassword, encrypted-store, lifecycle, migration/rollback, local-routing, mail/submission, password, and deletion proofs pass on Community v0.16.14; the exact accepted local-only raw Blob behavior remains characterized. Structured `x:Log` is either proved or recorded capability-disabled with stdout logs retained.
  - **STOP:** direct AppPassword access; exact permission isolation fails outside the accepted management same-Account raw upload/download and management raw upload using an ordinary Account ID; the characterized raw behavior widens; targeted revocation/preservation, two-generation overlap, encrypted-store recovery/reset/restart, safe re-enrollment, migration/rollback, required local routing, or another mandatory Community behavior fails. Unstable optional `/32` restriction, capability-disabled `x:Log`, or a fast never-observed DestroyAccount task recorded `unverified` is not a stop.

- [ ] Always tear down only the named disposable gate project:

```bash
docker compose -p mail-sandbox-stalwart-gate \
  -f debug-dashboard/dashboard-server/testResources/stalwart-gate0b/compose.yml \
  down
cd debug-dashboard
STALWART_GATE_CLEANUP=1 \
./kotlin test \
  --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.gate.stalwart.StalwartGateCleanupLiveTest'
```

Expected: the project is down and the validated gate runtime is absent. Do not pass `-v` unless the resolved volume is gate-owned and checked first.

- [ ] On `PASS`, commit:

```bash
git add docker-compose.yml docker-compose.stalwart-migration.yml .gitignore stalwart scripts tests README.md CLAUDE.md .ai debug-dashboard docs
git commit -m "test: prove Stalwart v0.16.14 gate"
```
