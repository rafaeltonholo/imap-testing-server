# Debug Dashboard Acceptance and Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove the dashboard's complete two-provider usability floor, security boundary, failure behavior, accessibility, responsive composition, and repeatable local operation.

**Architecture:** Run Gate 1 from the browser/API boundary against a newly created disposable Compose environment, with provider-native assertions below the UI. Add deterministic fault seams for partial operations and stale concurrency state. Finish with operator documentation and one clean end-to-end verification run.

**Tech Stack:** Kotlin Toolchain tests, Kotlin/JVM Selenium, Docker Compose, live Dovecot/Postfix/OAuth/Stalwart, SQLite inspection through application repositories.

---

## Execution prerequisite

Do not execute this plan until Gate 0B passes under the approved Stalwart mail-credential strategy and the design, Gate 0B, account-provider, mail-provider, Message Lab/observability, and any affected Compose UI plans have been revised and independently reviewed. Gate 1 must test the approved credential's provisioning, rotation, revocation, recovery, deletion, protected-account denial, and secret-exclusion behavior; it must not retain the rejected global-impersonation assertions as if they were executable.

## Task 1: Create an isolated acceptance harness

**Files:**

- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/acceptance/AcceptanceEnvironment.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/acceptance/DisposableAccounts.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/acceptance/ProviderAssertions.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/acceptance/BrowserHarness.kt`
- Create: `debug-dashboard/dashboard-server/testResources/acceptance/scenarios.json`
- Create: `docs/debug-dashboard/evidence/gate-1.md`

- [ ] Make the harness allocate a unique Compose project name, runtime directory, loopback ports, deterministic seeds, and account prefix. It may delete only resources bearing its generated acceptance marker.

- [ ] Add a preflight test that refuses to run when resolved targets include pre-existing developer accounts, production-like domains, wildcard published addresses, unpinned images, or a non-disposable Stalwart data path.

- [ ] Start services, wait on actual protocol/readiness probes rather than sleeps, build linked Wasm, launch Ktor on an ephemeral loopback port, bootstrap a browser session, and register cleanup in reverse order.

- [ ] Run the preflight alone:

```bash
cd debug-dashboard
./kotlin test --include-module dashboard-server --include-classes 'mail.sandbox.dashboard.server.acceptance.AcceptanceEnvironmentTest'
```

Expected: pass and leave no account/container/runtime residue.

## Task 2: Encode the complete Gate 1 workflow matrix

**Files:**

- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/acceptance/Gate1WorkflowTest.kt`

- [ ] Implement each approved matrix row as a named parameterized test, once for `dovecot-imap` and once for `stalwart-jmap`:

  1. registry/profile selection, including Dovecot-only, Stalwart-only, dual-provider, and provider-tab isolation;
  2. server-wide history/live/pause/resume/reconnect with activity from the test;
  3. account-scoped interleaved logs with exact inclusion and deterministic exclusion;
  4. create account with login, capability, and browser-visible receipt;
  5. authored text, uploaded EML, deterministic random × direct append and delivery, with arrival/content/replay truth;
  6. folder list/create/relist, server-issued delete preview, no deletion before confirmation, stale/altered/reused grant rejection, confirmed empty delete, plus non-empty/child/orphan-choice safety;
  7. message paging/relist, plain, sanitized HTML, attachments, and raw;
  8. password reset/new login and old-login failure when test-owned;
  9. account deletion preview with typed address and server grant, no deletion before confirmation, stale/altered/reused grant rejection, confirmed deletion, and every required provider negative path/cleanup status;
  10. seen/unseen, flag/unflag, move, copy, Trash, and membership removal where supported; for permanent delete, prove preview scope, no deletion before explicit confirmation, stale-preview rejection, one successful confirmation, replay rejection, exact-item deletion, and relist after each;
  11. provider/item receipt, safe native identifiers, correlated evidence, and reconciliation.

- [ ] Every test must drive the dashboard route/application boundary, then verify provider-native postconditions. A lower-level adapter-only pass cannot satisfy a row.

- [ ] Run:

```bash
./kotlin build
./kotlin test --include-module dashboard-server --include-classes 'mail.sandbox.dashboard.server.acceptance.Gate1WorkflowTest'
```

Expected: every row passes for both profiles. Record durations, safe generated identities/operation IDs, and the matrix result in `gate-1.md`.

## Task 3: Prove deterministic fault and recovery behavior

**Files:**

- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/acceptance/FaultAcceptanceTest.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/testing/FaultPoint.kt`
- Modify: `docs/debug-dashboard/evidence/gate-1.md`

- [ ] Add test-only, startup-configured fault points at provider-call boundaries. They must be absent/disabled in normal startup and cannot be selected from a browser request.

- [ ] Cover:

  - one provider stops during a dual-provider operation;
  - crash after durable `accepted` commit but before scheduler enqueue, with replay-safe requeue and secret/source-required terminal resupply cases;
  - server restarts with an operation running;
  - concurrent Dovecot eligibility writers;
  - crash before/after atomic replace and abandoned temporary cleanup;
  - duplicate idempotency key with same/different intent;
  - IMAP UIDVALIDITY change;
  - JMAP `stateMismatch` and partial `set`;
  - permanent-delete preview expiry, provider-state drift, server restart invalidating its process-local session/preview, and one-time confirmation replay, with zero deletion until a new session obtains a fresh preview;
  - invalid/oversized EML;
  - unavailable Identity/submission capability;
  - stale SSE/log cursor and resync;
  - Stalwart deletion Pending/Retry/Failed/fast-complete-not-observed;
  - malformed native output containing secrets.

- [ ] Assert honest achieved state, itemized results, safe remediation, and `reconciliationRequired` where prescribed. Assert no automatic destructive rollback.

- [ ] Run:

```bash
./kotlin test --include-module dashboard-server --include-classes 'mail.sandbox.dashboard.server.acceptance.FaultAcceptanceTest'
```

Expected: pass.

## Task 4: Prove the browser and privilege security boundary

**Files:**

- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/acceptance/SecurityAcceptanceTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/acceptance/SecretLeakAcceptanceTest.kt`
- Modify: `docs/debug-dashboard/evidence/gate-1.md`

- [ ] Test one-time bootstrap replay/expiry, successful same-origin CSRF reacquisition after reload, concurrent-tab reacquisition, reacquisition with missing/expired cookie, Host aliases, Origin mismatch, cross-site Fetch Metadata, missing/wrong CSRF, session expiry, API/SSE query credentials, CORS absence, cookie attributes, CSP, frame denial, MIME nosniff, and no-referrer. Prove the CSRF endpoint performs no provider/operation mutation and remains unreadable/unusable cross-origin.

- [ ] Attempt path traversal/symlink fixtures/uploads, arbitrary Docker service/flags/working directory, unknown `doveadm` commands, protected account mutation, off-domain/protected/unregistered delivery, and non-loopback provider/dashboard connections. For account, mailbox, and permanent-message deletion, attempt the generic mutation route plus missing, forged, altered-scope, expired, reused, cross-session, wrong-kind, wrong-target, and stale-state grants; every case must make zero destructive provider calls.

- [ ] Seed unique canary passwords, API keys, bearer tokens, cookies, and malformed raw lines. After all workflows, query responses, SSE capture, SQLite through the repository, exports, Ktor logs, and Docker logs. Assert every canary's deterministic exclusion from every unauthorized sink.

- [ ] Re-run the approved/revised Gate 0B and Gate 0C negative authorization matrices so later code cannot weaken provider isolation.

- [ ] Run:

```bash
./kotlin test --include-module dashboard-server --include-classes 'mail.sandbox.dashboard.server.acceptance.SecurityAcceptanceTest'
./kotlin test --include-module dashboard-server --include-classes 'mail.sandbox.dashboard.server.acceptance.SecretLeakAcceptanceTest'
```

Expected: pass without printing canary values.

## Task 5: Prove accessibility, responsive structure, and visual integrity

**Files:**

- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/acceptance/AccessibilityAcceptanceTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/acceptance/ResponsiveAcceptanceTest.kt`
- Create: `docs/debug-dashboard/evidence/visual-acceptance.md`
- Modify: `DESIGN.md`

- [ ] Complete the primary account → folder → message → mutation → trace workflow using keyboard input only. Assert semantic roles/names/states, visible focus, dialog focus containment/restoration, status live regions, provider/status non-color cues, and HTML iframe containment.

- [ ] Emulate reduced motion and assert final linked trace state without cursor travel/paper-feed transitions.

- [ ] At wide, medium, and narrow sizes, assert the exact structural modes from the design. Trace must remain reachable and retain cursor context.

- [ ] Capture actual wide/medium/narrow screenshots after deterministic seed setup. Compare manually to the approved Evidence Split reference and inspect typography, density, hierarchy, overflow, clipping, scroll traps, destructive emphasis, and one-red-cursor/provider-color rules. Record accepted token adjustments in `DESIGN.md` and `visual-acceptance.md`.

- [ ] Run:

```bash
./kotlin test --include-module dashboard-server --include-classes 'mail.sandbox.dashboard.server.acceptance.AccessibilityAcceptanceTest'
./kotlin test --include-module dashboard-server --include-classes 'mail.sandbox.dashboard.server.acceptance.ResponsiveAcceptanceTest'
```

Expected: pass.

## Task 6: Write local operator and contributor documentation

**Files:**

- Create: `debug-dashboard/README.md`
- Create: `docs/debug-dashboard/operator-guide.md`
- Modify: `README.md`
- Modify: `.gitignore`

- [ ] Document exact prerequisites, Toolchain wrapper commands, current browser requirement, provider startup/readiness, startup fragment bootstrap, linked Wasm asset discovery, and loopback URLs.

- [ ] Document Stalwart backup/migration/restore, Dovecot seed/runtime eligibility migration, protected identities, secret provisioning/rotation, retention/Clear Local History, and disposable acceptance environment.

- [ ] Document append vs delivery, provider-specific deletion/purge truth, reconciliation, account eligibility, local-only recipients, and every irreversible confirmation.

- [ ] Add a troubleshooting table keyed to typed dashboard codes and gate reports; do not paste secrets or advise direct `vmail/`/RocksDB edits.

- [ ] Ensure generated runtime/build/data/backup/upload paths are ignored while seed configuration, migrations, docs, and wrapper stay tracked.

## Task 7: Run the final verification sequence

**Files:**

- Modify: `docs/debug-dashboard/evidence/gate-1.md`

- [ ] From a clean acceptance environment, run:

```bash
docker compose config --quiet
cd debug-dashboard
./kotlin --version
./kotlin show modules
./kotlin show settings
./kotlin show dependencies
./kotlin build
./kotlin test
```

Expected: all commands exit zero.

- [ ] Audit the forbidden build stack:

```bash
git ls-files debug-dashboard | rg '(^|/)(build\.gradle(\.kts)?|settings\.gradle(\.kts)?|package(-lock)?\.json|yarn\.lock|pnpm-lock\.yaml)$|\.(js|mjs|ts|tsx)$'
```

Expected: no output. Generated ignored `.mjs` linker output is allowed; checked-in handwritten/generated JavaScript is not.

- [ ] Run repository hygiene:

```bash
git diff --check
git status --short
```

Expected: no whitespace errors; only intended implementation/evidence changes before commit.

- [ ] Execute `.ai/self-review.md`, resolve every applicable issue, and repeat the verification commands affected by fixes.

- [ ] Commit:

```bash
git add README.md DESIGN.md .gitignore debug-dashboard docs/debug-dashboard
git commit -m "test: prove debug dashboard release floor"
```

- [ ] Request an independent code review with `superpowers:requesting-code-review`. Address serious findings and rerun the final sequence before claiming completion.
