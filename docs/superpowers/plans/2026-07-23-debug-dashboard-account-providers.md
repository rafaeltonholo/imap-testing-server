# Debug Dashboard Account Providers Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the live logical account registry plus create, password reset, and delete operations for both `dovecot-imap` and `stalwart-jmap`, preserving separate provider outcomes and deletion truth.

**Architecture:** Promote the proven Gate 0B/0C clients into typed account-admin adapters. Project provider-native state into a joined logical registry; never make SQLite a second account authority. Multi-provider account work runs as a per-address saga with preflight, itemized receipts, scoped retry, and reconciliation.

**Tech Stack:** Kotlin/JVM, Ktor client/server, kotlinx.serialization, JDK NIO atomic file operations, allowlisted `docker compose`/`doveadm`, Stalwart v0.16.14 JMAP management.

---

## Execution prerequisite

Do not execute this plan until Gate 0B passes under a user-approved Stalwart mail-credential strategy and this document has been revised and independently reviewed with that strategy. The revision must make account creation, password reset, credential rotation/recovery, and account deletion own the exact mail-credential lifecycle without granting the management client mail access or persisting a user's normal password.

## Task 1: Define account administration ports and registry projection

**Files:**

- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/account/AccountAdminPort.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/account/AccountRegistry.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/account/AccountPolicy.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/account/AccountRegistryTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/account/AccountPolicyTest.kt`

- [ ] Write failing tests for joining Dovecot eligibility entries and Stalwart User Accounts by exact canonical email. Cover Dovecot-only, Stalwart-only, dual-provider, provider-not-ready, and protected identities.

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

- [ ] Test policy rules: only discovered local domains, no protected provider IDs, requested profiles must be ready, duplicates rejected per profile, deletion of one profile retains the logical account, and the management/operator identities never appear as mutable targets.

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
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/provider/stalwart/StalwartDeletionTracker.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/provider/stalwart/StalwartAdminAdapter.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/provider/stalwart/StalwartManagementClientTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/provider/stalwart/StalwartAdminAdapterTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/provider/stalwart/StalwartDeletionTrackerTest.kt`

- [ ] Write fake-HTTP tests for discovered Session URLs, `x:Domain/query|get|set`, `x:Account/query|get|set`, credential `Replace`, typed method errors, `stateMismatch`, and request/result correlation. Never hardcode legacy `/api/principal`.

- [ ] Write password-reset tests proving only the internal `Password` credential changes and unrelated credentials remain byte-for-byte equivalent in the provider model. Verify new authentication; verify the old value only when test-owned or supplied.

- [ ] Model Stalwart cleanup truth as:

  - principal `destroyed` + failed account lookup/authentication: logical deletion achieved;
  - matching observed `DestroyAccount` Pending/Retry: cleanup running;
  - matching observed Failed: `reconciliationRequired`;
  - disappearance after prior observation plus negative account/auth probes: confirmed cleanup;
  - never observed because completion was too fast: logical success with `unverified` cleanup.

Write each case as a failing deterministic tracker test before implementation. Do not invent a succeeded Task state.

- [ ] Implement create preflight/domain creation, User Account creation with internal Password credential, User role/inherited permissions, Session capability verification, and Identity availability verification.

- [ ] Implement immutable protected-ID checks in every method and preserve the Gate 0B management-versus-user-mail credential separation defined by the revised gate. Incorporate its approved provisioning, rotation, recovery, and deletion lifecycle explicitly; do not assume the rejected global-impersonation operator still exists.

- [ ] Run:

```bash
./kotlin test --include-module dashboard-server --include-classes 'mail.sandbox.dashboard.server.provider.stalwart.*'
```

Expected: pass.

## Task 4: Orchestrate single- and dual-provider account mutations

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

- [ ] Implement password reset with one request-scoped new value and separate provider outcomes. Never persist the new or old value.

- [ ] Implement deletion preview data (provider instances, mailbox/message counts, purge semantics, reconciliation warnings), typed-address confirmation, provider selection, and separate Stalwart cleanup/Dovecot purge receipts. The preview must obtain Foundation's opaque destructive grant bound to the current session, canonical address, selected provider IDs, Dovecot eligibility-file revision and/or Stalwart Account state, exact provider instances, counts/purge choices, preview digest, and expiry.

- [ ] Confirmation requires both the exact typed canonical address and that opaque grant. Under the logical-account lock, atomically consume it and re-read all bound provider state before the first delete. Missing, forged, altered-selection, expired, reused, cross-session, wrong-address, or stale-state grants make zero provider calls and require a fresh preview. No generic account mutation route or direct adapter call may bypass this application-service check.

- [ ] Run:

```bash
./kotlin test --include-module dashboard-server --include-classes 'mail.sandbox.dashboard.server.account.*OperationTest'
```

Expected: pass.

## Task 5: Add account/readiness API routes

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
  - deletion preview and confirmed deletion;
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

## Task 6: Run live account parity

**Files:**

- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/live/AccountParityLiveTest.kt`
- Create: `docs/debug-dashboard/evidence/account-parity.md`

- [ ] Against a fresh disposable Compose project, exercise through the application service/API boundary:

  1. create Dovecot-only, Stalwart-only, and dual-provider addresses;
  2. refresh and verify the logical projection;
  3. reset each password and prove new login;
  4. obtain a delete preview, prove no deletion before confirmation, mutate provider state and prove the stale grant fails, then obtain a fresh preview and delete one instance while the other remains;
  5. prove grant replay fails, obtain a new dual-provider preview, confirm it, and run every provider-specific negative path;
  6. exercise partial failure and scoped retry, requiring a fresh grant whenever the destructive scope is retried.

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
