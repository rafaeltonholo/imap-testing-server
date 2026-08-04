# Debug Dashboard Account Providers Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the live logical account registry plus create, password reset, and delete operations for both `dovecot-imap` and `stalwart-jmap`, preserving separate provider outcomes and deletion truth.

**Architecture:** Promote the proven Gate 0B/0C clients into typed account-admin adapters. Project provider-native state plus safe Stalwart mail-access readiness into a joined logical registry; never make SQLite or the AppPassword snapshot a second account authority. Multi-provider account work runs as a per-address saga, while Stalwart enrollment/repair/rotation/removal use the Gate-0B-proven Account-ID lock, encrypted snapshot, and direct Account-bound credential lifecycle.

**Tech Stack:** Kotlin/JVM, Ktor client/server, kotlinx.serialization, JDK NIO atomic file operations, allowlisted `docker compose`/`doveadm`, Stalwart v0.16.15 JMAP management.

---

## Execution prerequisite

Gate 0B must report `PASS` for the approved direct AppPassword/encrypted-snapshot lifecycle, Gate 0C must report `PASS` for Dovecot, and Foundation's `MailAccess` contracts, `SecretChars`, ephemeral-input registry, operation engine, and account locks must exist. Reuse those exact primitives: no global impersonation, no retained normal password, no second credential store, and no `ifInState` claim for Stalwart Account credential-list updates.

## Task 1: Define account administration ports and registry projection

**Files:**

- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/account/AccountAdminPort.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/account/AccountRegistry.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/account/AccountPolicy.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/account/AccountRegistryTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/account/AccountPolicyTest.kt`

- [ ] Write failing tests for joining Dovecot eligibility entries and Stalwart User Accounts by exact canonical email. Cover Dovecot-only, Stalwart-only, dual-provider, provider-not-ready, protected identities, all per-Account Stalwart mail-access states, and global `storeUnavailable` superseding every Stalwart Account state.

- [ ] Define a narrow port:

```kotlin
interface AccountAdminPort {
    val profile: ProviderProfile
    suspend fun readiness(): ProviderReadiness
    suspend fun list(): List<ProviderAccount>
    suspend fun preflightCreate(intent: CreateProviderAccount): PreflightReceipt
    suspend fun create(intent: CreateProviderAccount, password: SecretChars): ProviderReceipt
    suspend fun resetPassword(intent: ResetProviderPassword, password: SecretChars): ProviderReceipt
    suspend fun delete(intent: DeleteProviderAccount): ProviderReceipt
}
```

`SecretChars` must not be serializable or printable and must clear its backing storage on close.

- [ ] Test policy rules: only discovered local domains, no protected provider IDs, requested profiles must be ready, duplicates rejected per profile, deletion of one profile retains the logical account, the management identity never appears as a mutable target, and no Stalwart mail-operator identity exists.

- [ ] Key every Stalwart readiness overlay by immutable Account ID. Migrated/existing ordinary Accounts with neither a local record nor reserved remote credential are `enrollmentRequired`; protected identities never receive a local credential record or CRUD/mail-access action.

- [ ] Implement the live projection and run:

```bash
cd debug-dashboard
./kotlin test --include-module dashboard-server --include-classes 'mail.sandbox.dashboard.server.account.*'
```

Expected: pass.

## Task 2: Promote the Dovecot eligibility writer and admin probe

**Files:**

- Move/Refactor: Gate 0C Dovecot file/probe classes into `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/provider/dovecot/`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/provider/dovecot/DovecotEligibilityStore.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/provider/dovecot/DovecotPasswordHasher.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/provider/dovecot/DovecotAdminAdapter.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/provider/dovecot/DovecotEligibilityStoreTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/provider/dovecot/DovecotAdminAdapterTest.kt`

- [ ] Reuse Gate 0C's exact passwd-file format. Write failing tests for comments/blank lines, one exact address entry, scheme-prefixed supported hashes, duplicate rejection, delimiter/newline/path injection, and preservation of unrelated entries.

- [ ] Write concurrency/fault tests that require one OS-visible file-global lock from read through post-write verification, restrictive same-directory temporary files, `fsync`, atomic replace, parent-directory `fsync` where supported, preserved mode/ownership, and abandoned-temp cleanup. Include crash-before-replace and crash-after-replace simulations.

- [ ] Implement the store under the fixed canonical `debug-dashboard/.runtime/dovecot/users` path. Do not touch tracked `config/users` or `vmail/`.

- [ ] Wrap the Gate 0C password hasher. Password bytes go through stdin or the gate-proven non-argv secret channel; reject output without an allowed scheme. Implement allowlisted cache flush, session kick, password auth verification, OAuth/LMTP/userdb/operator target probes, and optional supported `doveadm` purge.

- [ ] Implement `DovecotAdminAdapter`:

  - create: hash → locked atomic insert → cache flush → password login/capability verification;
  - reset: locked hash replace → cache flush/session kick → new login; old login only when old secret is request-scoped/test-owned;
  - delete: locked eligibility removal → OAuth invalidation → cache flush/session kick → negative password/OAuth/operator/`doveadm`/LMTP probes → optional separate purge receipt.

On verification failure after a mutation, return the exact achieved state and `reconciliationRequired`; do not conceal or blindly roll back it.

- [ ] Run:

```bash
./kotlin test --include-module dashboard-server --include-classes 'mail.sandbox.dashboard.server.provider.dovecot.*'
```

Expected: unit/fake tests pass.

## Task 3: Promote the Stalwart v0.16 account-management client

**Files:**

- Move/Refactor: Gate 0B JMAP management classes into `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/provider/stalwart/`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/provider/stalwart/JmapSessionDiscovery.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/provider/stalwart/StalwartManagementClient.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/provider/stalwart/StalwartCredentialModels.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/provider/stalwart/StalwartAccountCredentialClient.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/provider/stalwart/StalwartDeletionTracker.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/provider/stalwart/StalwartAdminAdapter.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/provider/stalwart/StalwartMailCredentialRemoteAdapter.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/provider/stalwart/StalwartMailAccessProjector.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/provider/stalwart/StalwartManagementClientTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/provider/stalwart/StalwartAccountCredentialClientTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/provider/stalwart/StalwartAdminAdapterTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/provider/stalwart/StalwartDeletionTrackerTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/provider/stalwart/StalwartMailCredentialRemoteAdapterTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/provider/stalwart/StalwartMailAccessProjectorTest.kt`

- [ ] Write fake-HTTP tests for discovered Session URLs, `x:Domain/query|get|set`, `x:Account/query|get|set`, credential `Replace`, typed method errors, and request/result correlation. Never hardcode legacy `/api/principal`. Account credential-list patches deliberately have no `ifInState`; tests require immediate pre-fetch, one update, and post-fetch verification.

- [ ] Implement `StalwartMailCredentialRemoteAdapter` against the Gate 0B port. Its normal-password method may only create one reserved-prefix AppPassword as the exact ordinary Account. Its management methods may inventory/revoke reserved credentials through a freshly fetched Account credential list but can never create/use an AppPassword or invoke a mail method.

- [ ] Model Password, AppPassword, API-key, and unknown credential objects separately while preserving all unrecognized fields, IDs, permissions, and provider values during a round trip. Test the reserved description `mail-sandbox/debug-dashboard/{store UUID}/{generation}`, Replace mode, the exact Gate-0B mail allowlist, and removal of only matching reserved IDs.

- [ ] Test the exact fetch → remove reserved IDs only → one update → re-fetch/verify sequence. A simulated external writer mismatch preserves the observed provider state, reports Account `recoveryRequired` plus operation `reconciliationRequired`, and never performs a second blind update. Protected/cross-account targets fail before lock, store, or provider mutation.

- [ ] Write password-reset tests under the Account's exclusive credential lock. They prove only the internal `Password` credential changes, every AppPassword/API key/unrelated credential object is preserved, the new password authenticates, the old value is tested only when test-owned/supplied, and the active dashboard AppPassword is re-probed. A 30-second lease-drain timeout performs no password update.

- [ ] Model Stalwart cleanup truth as:

  - principal `destroyed` + management lookup by pre-mutation Account ID and ordinary address/account resolution both absent: logical deletion achieved;
  - matching observed `DestroyAccount` Pending/Retry: cleanup running;
  - matching observed Failed: `reconciliationRequired`;
  - disappearance after prior observation plus negative account/auth probes: confirmed cleanup;
  - never observed because completion was too fast: logical success with `unverified` cleanup.

Write each case as a failing deterministic tracker test before implementation. Do not invent a succeeded Task state.

- [ ] Implement create preflight/domain creation and User Account creation with internal Password credential and User role/inherited permissions. Before releasing that same request password, call the Gate-0B lifecycle once to create/capture/probe the mail-only AppPassword and verify Session capabilities plus Identity. If Account creation succeeds but AppPassword capture/verification does not, keep the Account, return its achieved provider result, mark mail access `recoveryRequired` or `enrollmentRequired` exactly as Gate 0B reports, and require password resupply for retry.

- [ ] Project readiness by immutable Account ID through the Gate 0B store/inventory rules. A missing local and remote reserved credential is `enrollmentRequired`; mismatch/revocation/orphan is `recoveryRequired`; unreadable store is global `storeUnavailable`. Never attach a snapshot record to a new Account merely because its address matches a deleted Account.

- [ ] Implement immutable protected-ID checks in every management and credential method. The management key never reaches a mail client, the AppPassword never reaches management, and there is no operator/impersonation fallback.

- [ ] Run:

```bash
./kotlin test --include-module dashboard-server --include-classes 'mail.sandbox.dashboard.server.provider.stalwart.*'
```

Expected: pass.

## Task 4: Expose Stalwart mail-access lifecycle operations

**Files:**

- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/account/StalwartMailAccessOperationService.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/account/ResetStalwartCredentialStoreOperation.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/api/StalwartMailAccessRoutes.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/api/ServerSetupRoutes.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/account/StalwartMailAccessOperationServiceTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/account/ResetStalwartCredentialStoreOperationTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/api/StalwartMailAccessRoutesTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/api/ServerSetupRoutesTest.kt`
- Modify: `debug-dashboard/dashboard-server/src/Application.kt`

- [ ] Write failing operation tests for status, enroll, repair, rotate, and remove against every Gate 0B state. Enroll/repair/rotate accept a request-scoped normal password and become `resupplyRequired` after it is discarded; remove accepts no password. Protected, wrong-profile, deleted, and stale Account-ID targets make no provider call.

- [ ] Wrap the Gate 0B lifecycle in Foundation operations without persisting secrets. Persist only safe Account ID, provider credential ID, generation label, phase, and outcome. A lost create response/capture ends with the exact cleanup/result from Gate 0B and never auto-retries creation.

- [ ] Add authenticated routes under `/api/v1/accounts/{address}/providers/stalwart-jmap/mail-access`. Require session, exact origin, CSRF, idempotency, and a live address-to-Account-ID match for mutations. Responses expose safe state/action metadata only; route, problem, SSE, and operation serialization tests reject any normal-password or `app_` value.

- [ ] Write global store-reset tests for `/api/v1/server-setup/stalwart-credential-store`. The route is available only in `storeUnavailable`, presents the irreversible local re-enrollment effect, and calls the Gate 0B reset operation. It succeeds only after remote reserved-prefix cleanup is verified; Clear Local History must not call it.

- [ ] Add restart tests for active/staged/retiring/removal phases and for an operation row whose password is gone. Startup reconciles durable provider/store phases before enabling mail actions; it creates no AppPassword during restart. A durable `removalPending` proof may finish local erasure without a password or second remote mutation.

- [ ] Add a lock-order test for logical-account mutation lock → Stalwart credential-exclusive lock. Concurrent mail leases may run for different Account IDs; cancellation/exception releases both layers; reversed acquisition is rejected in tests so password reset/deletion cannot deadlock mail actions.

- [ ] Run:

```bash
./kotlin test --include-module dashboard-server --include-classes 'mail.sandbox.dashboard.server.account.StalwartMailAccessOperationServiceTest'
./kotlin test --include-module dashboard-server --include-classes 'mail.sandbox.dashboard.server.account.ResetStalwartCredentialStoreOperationTest'
./kotlin test --include-module dashboard-server --include-classes 'mail.sandbox.dashboard.server.api.StalwartMailAccessRoutesTest'
./kotlin test --include-module dashboard-server --include-classes 'mail.sandbox.dashboard.server.api.ServerSetupRoutesTest'
```

Expected: pass with no secret-bearing serialized value.

## Task 5: Orchestrate single- and dual-provider account mutations

**Files:**

- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/account/CreateAccountOperation.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/account/ResetPasswordOperation.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/account/DeleteAccountOperation.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/account/AccountDeletionPreview.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/account/CreateAccountOperationTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/account/ResetPasswordOperationTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/account/DeleteAccountOperationTest.kt`

- [ ] Write failing saga tests for Dovecot-only, Stalwart-only, both-success, first-fails-preflight/no mutation, one-provider runtime failure/other-provider success, retry only failed provider, and discarded-secret retry requiring a new secret.

- [ ] Implement create with all-provider preflight before the first mutation, then execute provider steps under the logical-account lock. Persist safe itemized receipts after each step.

- [ ] Implement password reset with one request-scoped new value and separate provider outcomes. For Stalwart, acquire the exclusive credential lock, preserve/re-probe the existing dashboard AppPassword, and optionally rotate it only when the request explicitly selects Rotate dashboard access; that rotation may reuse the new password before it is cleared. Never persist the new or old value.

- [ ] Implement deletion preview data (provider instances, purge semantics, reconciliation warnings), typed-address confirmation, provider selection, and separate Stalwart cleanup/Dovecot purge receipts. Include mailbox/message counts only when the provider mail credential is ready; otherwise return the explicit safe value **unknown — dashboard mail access unavailable** and do not force enrollment. The preview must obtain Foundation's opaque destructive grant bound to the current session, canonical address, selected provider IDs, Dovecot eligibility-file revision and/or Stalwart Account ID/state, exact provider instances, available counts/purge choices, preview digest, and expiry. A ready Stalwart preview also binds the safe active-generation label; unready states bind their exact readiness token.

- [ ] Confirmation requires both the exact typed canonical address and that opaque grant. Under the logical-account lock, atomically consume it and re-read all bound provider state before the first delete. Missing, forged, altered-selection, expired, reused, cross-session, wrong-address, or stale-state grants make zero provider calls and require a fresh preview. No generic account mutation route or direct adapter call may bypass this application-service check.

- [ ] For Stalwart deletion, take the exclusive credential lock and drain for at most 30 seconds. Destroy the principal whether its mail access is ready, unenrolled, or unhealthy; prove absence by pre-mutation Account ID plus address/account resolution, then erase the local record. A negative AppPassword probe is ancillary only when a readable one existed. Provider success plus local-erasure failure becomes `removalPending`/`reconciliationRequired`, and a new same-address Account ID never reuses the record.

- [ ] Run:

```bash
./kotlin test --include-module dashboard-server --include-classes 'mail.sandbox.dashboard.server.account.*OperationTest'
```

Expected: pass.

## Task 6: Add account/readiness API routes

**Files:**

- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/api/AccountRoutes.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/api/ReadinessRoutes.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/api/AccountRoutesTest.kt`
- Modify: `debug-dashboard/dashboard-server/src/Application.kt`

- [ ] Write failing authenticated Ktor tests for:

  - list/refresh logical registry;
  - inspect one provider instance and its live readiness/capabilities;
  - create one or both named profiles;
  - reset one or both provider passwords;
  - optional Stalwart AppPassword rotation during that same password-reset request;
  - deletion preview and confirmed deletion;
  - Stalwart deletion while `enrollmentRequired`, `recoveryRequired`, or `storeUnavailable`, with unknown counts and no temporary enrollment;
  - account deletion with no grant and with forged, expired, reused, cross-session, altered-provider-selection, wrong-address, and stale-provider-state grants, each producing zero delete calls;
  - protected-ID rejection;
  - idempotency conflict, CSRF/origin rejection, and safe error mapping.

- [ ] Implement routes using only application services; no route directly calls a process, file, Docker, or remote provider.

- [ ] Run:

```bash
./kotlin test --include-module dashboard-server --include-classes 'mail.sandbox.dashboard.server.api.AccountRoutesTest'
./kotlin test --include-module dashboard-server
```

Expected: pass.

## Task 7: Run live account parity

**Files:**

- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/live/AccountParityLiveTest.kt`
- Create: `docs/debug-dashboard/evidence/account-parity.md`

- [ ] Against a fresh disposable Compose project, exercise through the application service/API boundary:

  1. create Dovecot-only, Stalwart-only, and dual-provider addresses;
  2. refresh and verify the logical projection plus Stalwart `ready`;
  3. create a migrated-style Stalwart Account with no dashboard credential, observe `enrollmentRequired`, enroll it, rotate it with bounded overlap, remove dashboard access without deleting the Account, and repair one injected orphan/revocation case;
  4. reset each normal password and prove new login; prove the Stalwart AppPassword remains valid unless the explicit rotate option is selected;
  5. make the local store unavailable in the disposable runtime, prove mail is globally disabled, execute explicit reserved-prefix cleanup/reset, and observe all Accounts return to `enrollmentRequired`;
  6. obtain a delete preview, prove no deletion before confirmation, mutate provider state and prove the stale grant fails, then obtain a fresh preview and delete one instance while the other remains;
  7. delete one unenrolled Stalwart Account with unknown counts and no AppPassword probe/enrollment; prove grant replay fails and a recreated same-address Account gets a different ID/no old secret;
  8. exercise partial failure and scoped retry, requiring a fresh grant whenever the destructive scope is retried.

- [ ] Run:

```bash
docker compose config --quiet
cd debug-dashboard
./kotlin test --include-module dashboard-server --include-classes 'mail.sandbox.dashboard.server.live.AccountParityLiveTest'
```

Expected: pass. Save disposable account IDs, safe operation IDs, provider outcomes, and cleanup status—never secrets—in the evidence document.

- [ ] Commit:

```bash
git add debug-dashboard docs/debug-dashboard/evidence/account-parity.md
git commit -m "feat: implement account parity across mail providers"
```
