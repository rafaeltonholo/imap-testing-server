# Debug Dashboard Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Establish the stable shared contract, loopback HTTP security boundary, idempotent operation engine, SQLite ledger, safe process boundary, and reconnectable event shell used by every dashboard feature.

**Architecture:** Keep serializable provider truth in the KMP contract module. The JVM server owns exact-origin authentication, validation, orchestration, locks, persistence, subprocess allowlists, and redaction. Mutations become durable operation resources before provider calls; reads remain synchronous.

**Tech Stack:** Kotlin Toolchain, Kotlin/JVM + Wasm shared contracts, Ktor server/client, kotlinx.serialization, SQLite JDBC 3.53.1.0, JDK NIO and ProcessBuilder.

---

**Prerequisite:** Gate reports 0A, 0B, and 0C say `PASS`.

## Task 1: Model provider truth and validation in shared KMP

**Files:**

- Create: `debug-dashboard/dashboard-contract/src/mail/sandbox/dashboard/contract/Account.kt`
- Create: `debug-dashboard/dashboard-contract/src/mail/sandbox/dashboard/contract/Capability.kt`
- Create: `debug-dashboard/dashboard-contract/src/mail/sandbox/dashboard/contract/ProviderKey.kt`
- Create: `debug-dashboard/dashboard-contract/src/mail/sandbox/dashboard/contract/Mail.kt`
- Create: `debug-dashboard/dashboard-contract/src/mail/sandbox/dashboard/contract/Operation.kt`
- Create: `debug-dashboard/dashboard-contract/src/mail/sandbox/dashboard/contract/Problem.kt`
- Create: `debug-dashboard/dashboard-contract/src/mail/sandbox/dashboard/contract/Validation.kt`
- Replace: `debug-dashboard/dashboard-contract/src/mail/sandbox/dashboard/contract/Routes.kt`
- Create: `debug-dashboard/dashboard-contract/test/mail/sandbox/dashboard/contract/AddressValidationTest.kt`
- Create: `debug-dashboard/dashboard-contract/test/mail/sandbox/dashboard/contract/ProviderKeySerializationTest.kt`
- Create: `debug-dashboard/dashboard-contract/test/mail/sandbox/dashboard/contract/OperationContractTest.kt`

- [ ] Write failing tests for the approved address rules: one bare addr-spec, lowercase local part, lowercase ASCII discovered domain, no comments/display names/quotes/newlines/delimiters, and exact provider-returned canonical address.

- [ ] Write failing serialization tests proving provider keys cannot collapse to a generic string:

```kotlin
@Serializable
sealed interface MessageKey {
    @Serializable
    data class Imap(
        val address: String,
        val mailbox: String,
        val uidValidity: ULong,
        val uid: ULong,
    ) : MessageKey

    @Serializable
    data class Jmap(
        val accountId: String,
        val emailId: String,
        val state: String,
    ) : MessageKey
}
```

Mirror this rule for IMAP/JMAP mailbox keys.

- [ ] Add named `ProviderProfile` values `dovecot-imap` and `stalwart-jmap`, capability/readiness DTOs, logical/provider account summaries, mailbox/message/page DTOs, safe message-body/attachment DTOs, request DTOs, `OperationState`, item/provider receipts, cleanup status, correlation confidence, and typed problem details.

- [ ] Encode the legal operation transition table in a pure shared function and test every legal edge plus rejection of terminal-to-running transitions.

- [ ] Define all `/api/v1` route constants centrally. Run:

```bash
cd debug-dashboard
./kotlin test --include-module dashboard-contract
```

Expected: pass on JVM and Wasm.

- [ ] Commit:

```bash
git add debug-dashboard/dashboard-contract
git commit -m "feat: define dashboard provider contracts"
```

## Task 2: Load configuration and enforce the canonical loopback origin

**Files:**

- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/config/DashboardConfig.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/config/RepositoryRoot.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/security/CanonicalOrigin.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/config/DashboardConfigTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/security/CanonicalOriginTest.kt`
- Modify: `debug-dashboard/dashboard-server/resources/application.yaml`

- [ ] Write failing tests that accept only an explicit repository root, runtime root inside `debug-dashboard/.runtime`, one `http://127.0.0.1:<port>` origin, and known provider endpoints. Reject symlinks, missing roots, wildcard bind addresses, `localhost` aliases, non-loopback addresses, and roots outside the worktree.

- [ ] Implement immutable configuration loaded once at startup. Requests never supply service names, provider URLs, repository roots, runtime paths, or origin aliases.

- [ ] Configure Netty to bind `127.0.0.1` only. Add a startup assertion that the resolved connector is loopback.

- [ ] Run:

```bash
./kotlin test --include-module dashboard-server --include-classes 'mail.sandbox.dashboard.server.config.*'
./kotlin test --include-module dashboard-server --include-classes 'mail.sandbox.dashboard.server.security.CanonicalOriginTest'
```

Expected: pass.

## Task 3: Implement the one-time browser bootstrap and request guards

**Files:**

- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/security/BootstrapSecretStore.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/security/SessionStore.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/security/RequestGuards.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/security/SecurityHeaders.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/security/SessionRoutes.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/security/SessionRoutesTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/security/RequestGuardsTest.kt`
- Modify: `debug-dashboard/dashboard-server/src/Application.kt`

- [ ] Write failing tests using an injectable clock and entropy source for:

  - 256-bit bootstrap secret, single use, 60-second expiry;
  - startup URL places the secret after `#`, never in path/query;
  - replay, wrong secret, wrong Host, wrong Origin, and cross-site Fetch Metadata rejection;
  - opaque rotated session cookie with `HttpOnly`, `SameSite=Strict`, host-only, `Path=/`, and no `Secure` on loopback HTTP;
  - session-bound CSRF returned initially in the bootstrap response, required in a custom header for every provider/application mutation;
  - authenticated `POST /api/v1/session/csrf` reacquisition after reload, requiring the valid cookie plus exact Host/Origin/same-origin Fetch Metadata, returning `Cache-Control: no-store`, and accepting no CSRF or query credential;
  - missing/expired session, cross-origin, cross-site, wrong Host, and concurrent-tab behavior for that endpoint; concurrent tabs receive the same current session value;
  - eight-hour absolute session expiry and process-local invalidation;
  - API and SSE authentication through cookie only, never query parameters.

- [ ] Implement in-memory secret/session stores. Compare secret values in constant time, retain only a hash of the bootstrap secret, and derive the current CSRF value with HMAC-SHA-256 from a separate 256-bit process-local key plus the opaque session ID. Bootstrap and reacquisition return that same current value; session/bootstrap rotation or process restart changes it. Overwrite/release transient byte arrays after exchange. The session-maintenance endpoint performs no provider or operation-ledger mutation and is the only authenticated POST exempt from the CSRF header.

- [ ] Add exact Host/Origin/Fetch Metadata guards before route logic. Disable CORS. Add CSP with at least `default-src 'self'`, explicit script/worker/connect/font/image restrictions, `object-src 'none'`, `base-uri 'none'`, and `frame-ancestors 'none'`; also set `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, and no-store on authenticated JSON.

- [ ] Run:

```bash
./kotlin test --include-module dashboard-server --include-classes 'mail.sandbox.dashboard.server.security.*'
```

Expected: pass, including deterministic negative cases.

- [ ] Commit:

```bash
git add debug-dashboard/dashboard-server
git commit -m "feat: secure the loopback dashboard session"
```

## Task 4: Build the operation state machine, idempotency index, and locks

**Files:**

- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/operation/OperationIntent.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/operation/OperationMachine.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/operation/IdempotencyIndex.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/operation/AccountLockRegistry.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/operation/OperationOrchestrator.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/operation/DestructiveGrantStore.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/operation/OperationMachineTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/operation/IdempotencyIndexTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/operation/OperationOrchestratorTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/operation/DestructiveGrantStoreTest.kt`

- [ ] Write failing tests for the exact flow `accepted → preflight → running → terminal`, cooperative cancellation between provider calls, separate provider/item results, partial success becoming `reconciliationRequired`, and no automatic destructive rollback.

- [ ] Define the idempotency fingerprint as `operation kind + normalized logical target + normalized non-secret intent`. Assert same key/same fingerprint resumes; same key/different fingerprint returns a typed conflict.

- [ ] Write a concurrency test proving mutations for one logical account serialize while different accounts may run concurrently. File-global Dovecot locking remains an additional Gate 0C primitive.

- [ ] Implement one shared destructive-preview grant primitive for account, mailbox, and permanent-message deletion. A grant is a 256-bit opaque random value whose server-side hash is bound to the current session, destructive kind, provider profile, canonical account, exact provider-native target keys/state fingerprint, preview digest, and a two-minute expiry. It is process-local, never stored in browser storage/SQLite/logs, and becomes invalid on restart/session expiry.

- [ ] Under the owning logical-account lock, confirmation atomically consumes the grant before re-reading provider state. Missing, forged, altered, expired, reused, cross-session, wrong-kind, wrong-target, or stale-state grants make zero provider calls and require a fresh preview. Once consumed, a provider failure is recorded as an operation result/reconciliation state; the grant is never made reusable. Generic mutation routes cannot represent any of the three destructive operations without a validated grant.

- [ ] Implement the orchestrator against narrow ports and an in-memory ledger fake. Secrets and raw uploads are request-scoped values excluded from `OperationIntent` persistence.

- [ ] Run:

```bash
./kotlin test --include-module dashboard-server --include-classes 'mail.sandbox.dashboard.server.operation.*'
```

Expected: pass.

## Task 5: Persist safe operation/event evidence in SQLite

**Files:**

- Create: `debug-dashboard/dashboard-server/resources/db/001_operations.sql`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/operation/OperationLedger.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/operation/SqliteOperationLedger.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/operation/LedgerRetention.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/operation/SqliteOperationLedgerTest.kt`
- Modify: `debug-dashboard/dashboard-server/module.yaml`

- [ ] Add `org.xerial:sqlite-jdbc:3.53.1.0`.

- [ ] Write failing temp-database tests for atomic operation/result writes, idempotency lookup, ordered event IDs, reconciliation links, 30-day/10,000-operation bounds, 24-hour/50,000-event bounds, and explicit Clear Local History.

- [ ] Write restart tests for every nonterminal state, including the crash window after the `accepted` transaction commits but before scheduler enqueue:

  - `accepted` with a complete persisted, secret-free, replay-safe intent is requeued once under the same operation/idempotency identity and re-enters `preflight`;
  - `accepted` whose discarded request-scoped password/upload/source is required becomes terminal `failed` with `resupplyRequired`, while recording that no provider call began;
  - `preflight` is either safely requeued when the operation kind proves preflight read-only/idempotent, or becomes `reconciliationRequired` by its declared recovery policy;
  - `running` always becomes `reconciliationRequired` with a safe server-interruption reason until provider truth is inspected;
  - terminal operations never move backward.

Assert repeated restarts do not duplicate queue entries, provider calls, or events.

- [ ] Implement operation creation as one transaction that stores `accepted`, its idempotency fingerprint, persisted non-secret intent, recovery policy, and initial event before enqueue. On startup, scan and resolve every nonterminal row before accepting mutations. Implement the schema and direct JDBC repository with prepared statements. Store no request password, authorization header, cookie, API key, bearer value, raw EML, or unredacted native output.

- [ ] Run:

```bash
./kotlin test --include-module dashboard-server --include-classes 'mail.sandbox.dashboard.server.operation.SqliteOperationLedgerTest'
```

Expected: pass.

## Task 6: Establish redaction, typed process execution, and path allowlists

**Files:**

- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/safety/SecretRedactor.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/safety/AllowedPath.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/process/ProcessSpec.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/process/TypedProcessRunner.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/safety/SecretRedactorTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/safety/AllowedPathTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/process/TypedProcessRunnerTest.kt`

- [ ] Write failing tests that redact passwords, Basic/Bearer headers, cookies, API keys, OAuth tokens, recovery credentials, URI credentials, and known structured secret fields before malformed parsing can throw.

- [ ] Write failing path tests for repository fixtures under `mails/`, runtime files under `debug-dashboard/.runtime/`, and generated upload names. Reject traversal, absolute user paths, symlink components, and non-regular targets.

- [ ] Model commands as sealed types such as `ComposeLogs(service)`, `DoveadmAuthTest(address)`, and `DoveadmSave(address, mailbox)`. Tests must prove request strings cannot add commands, flags, services, paths, or working directories.

- [ ] Implement `ProcessBuilder` with fixed executable/arguments, bounded stdout/stderr, timeout/cancellation, optional byte stdin for secrets/content, and redaction before results leave the runner. Never place passwords in process arguments.

- [ ] Run:

```bash
./kotlin test --include-module dashboard-server --include-classes 'mail.sandbox.dashboard.server.safety.*'
./kotlin test --include-module dashboard-server --include-classes 'mail.sandbox.dashboard.server.process.*'
```

Expected: pass.

## Task 7: Expose the versioned API, operation resources, and reconnectable events

**Files:**

- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/api/ProblemMapper.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/api/BootstrapRoutes.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/api/OperationRoutes.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/event/EventBuffer.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/event/EventRoutes.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/api/ApiBoundaryTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/event/EventBufferTest.kt`
- Modify: `debug-dashboard/dashboard-server/src/Application.kt`

- [ ] Write failing Ktor tests for authenticated `GET /api/v1/bootstrap`, operation status/list/cancel/retry/reconcile routes, typed safe problems, required idempotency header, CSRF, monotonic SSE IDs, `Last-Event-ID` resume, and explicit `resync`.

- [ ] Replace the Gate 0A event source with the bounded production `EventBuffer` backed by the ledger. Keep the proven browser behavior.

- [ ] Make mutation routes return an operation resource even when the operation finishes synchronously.

- [ ] Run:

```bash
./kotlin test --include-module dashboard-server
./kotlin test
```

Expected: all foundation and Gate 0A regressions pass.

- [ ] Commit:

```bash
git add debug-dashboard
git commit -m "feat: add dashboard operation foundation"
```
