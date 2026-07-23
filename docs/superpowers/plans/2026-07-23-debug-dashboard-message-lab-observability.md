# Debug Dashboard Message Lab and Observability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add truthful MIME preview/generation, direct append, real delivery, server/account logs, redaction, correlation, and provider-native evidence for every operation.

**Architecture:** A bounded message-source pipeline produces one validated raw message plus a separate local envelope. Append and delivery dispatch to different provider ports and verify mailbox arrival. Docker/stdout and optional Stalwart structured logs enter a redact-first normalization pipeline, then correlation links exact identifiers before cautious time adjacency.

**Tech Stack:** Kotlin/JVM, Angus/Jakarta Mail, Ktor multipart/SSE, allowlisted Docker Compose logs, Dovecot `doveadm save`, Postfix SMTP, Stalwart JMAP upload/import/EmailSubmission, SQLite event cache.

---

## Execution prerequisite

Do not execute this plan until Gate 0B passes under a user-approved Stalwart mail-credential strategy and this document has been revised and independently reviewed. The revision must cover how append, submission, recipient arrival verification, structured-log access, credential revocation, and replay acquire user contexts without global impersonation or retained normal-user passwords.

## Task 1: Build bounded MIME sources and deterministic generation

**Files:**

- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/lab/MessageSource.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/lab/MessageFactory.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/lab/FixtureCatalog.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/lab/UploadSpool.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/lab/MessageFactoryTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/lab/FixtureCatalogTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/lab/UploadSpoolTest.kt`

- [ ] Write failing tests for:

  - authored text with structured From/To/Cc/Bcc/Subject fields;
  - uploaded EML with a 25 MiB default limit;
  - repository fixture selected only beneath canonical `mails/`;
  - deterministic random scenario where equal seed+parameters produce byte-identical semantic content;
  - deterministic multi-message thread with stable Message-ID/In-Reply-To/References;
  - malformed headers, header injection, invalid MIME, oversized upload, traversal, and symlink refusal.

- [ ] Keep envelope recipients separate from display headers. Validate every envelope recipient as a live, non-protected registered local provider instance; never infer the delivery envelope from uploaded EML headers.

- [ ] Implement a generated-name spool beneath `debug-dashboard/.runtime/uploads`, owner-only where supported, with deletion after operation and one-hour crash-recovery cleanup. The ledger retains source kind, fixture-relative path or seed/parameters, and digest—not raw content.

- [ ] Return raw preview, parsed envelope/header summary, size/digest, warnings, and replay metadata before execution.

- [ ] Run:

```bash
cd debug-dashboard
./kotlin test --include-module dashboard-server --include-classes 'mail.sandbox.dashboard.server.lab.*'
```

Expected: pass.

## Task 2: Implement Dovecot append and Postfix delivery

**Files:**

- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/provider/dovecot/DoveadmAppendAdapter.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/provider/dovecot/PostfixSubmissionAdapter.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/provider/dovecot/DoveadmAppendAdapterTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/provider/dovecot/PostfixSubmissionAdapterTest.kt`

- [ ] Write failing tests for direct append that pass raw message bytes through stdin to the fixed allowlisted `doveadm save -u <validated-address> -m <validated-mailbox>` command, capture safe output, and verify the resulting IMAP message by Message-ID/digest. Do not copy user-named files into the container.

- [ ] Write SMTP tests for the local Postfix endpoint using a separate RFC 5321 envelope, multi-recipient itemization, queue/response receipt capture, off-domain/protected/unregistered rejection before submission, and accepted-but-not-arrived distinction.

- [ ] Implement delivery success as both Postfix acceptance and observed arrival in each target Dovecot mailbox. Timeout returns a truthful accepted/pending or reconciliation result, never false success.

- [ ] Run:

```bash
./kotlin test --include-module dashboard-server --include-classes 'mail.sandbox.dashboard.server.provider.dovecot.*AppendAdapterTest'
./kotlin test --include-module dashboard-server --include-classes 'mail.sandbox.dashboard.server.provider.dovecot.PostfixSubmissionAdapterTest'
```

Expected: pass.

## Task 3: Implement Stalwart import and real JMAP submission

**Files:**

- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/provider/stalwart/StalwartBlobClient.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/provider/stalwart/StalwartImportAdapter.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/provider/stalwart/StalwartSubmissionAdapter.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/provider/stalwart/StalwartImportAdapterTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/provider/stalwart/StalwartSubmissionAdapterTest.kt`

- [ ] Write fake-JMAP tests for discovered `uploadUrl`, content upload, `Email/import`, mailbox selection, created/notCreated mapping, and read-back verification.

- [ ] Write submission tests that require:

  - an available user Identity selected truthfully;
  - import of the authored raw message as a draft;
  - `EmailSubmission/set` referencing the imported Email through the v0.16.14 gate-proven result/creation-ID chain;
  - local-only envelope recipients;
  - per-recipient submission/delivery status;
  - target mailbox arrival;
  - Sent filing only when actually observed;
  - explicit failure when Identity/submission capability is absent.

- [ ] Implement direct append as upload + `Email/import`; implement delivery as the separate submission chain. Never label import alone as delivery.

- [ ] Run:

```bash
./kotlin test --include-module dashboard-server --include-classes 'mail.sandbox.dashboard.server.provider.stalwart.*ImportAdapterTest'
./kotlin test --include-module dashboard-server --include-classes 'mail.sandbox.dashboard.server.provider.stalwart.StalwartSubmissionAdapterTest'
```

Expected: pass.

## Task 4: Orchestrate Message Lab operations and expose routes

**Files:**

- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/lab/MessageLabService.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/api/MessageLabRoutes.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/lab/MessageLabServiceTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/api/MessageLabRoutesTest.kt`
- Modify: `debug-dashboard/dashboard-server/src/Application.kt`

- [ ] Write the source × path matrix as parameterized failing tests: authored text, uploaded EML, and deterministic random source × direct append and delivery × both provider profiles. Add thread generation as a separate multi-item scenario.

- [ ] Test preview-before-run, idempotency, upload/source discard, seed replay, dual-provider partial result, multi-recipient itemization, cancellation between items, and retry requiring source re-supply after disposal.

- [ ] Implement `preview` as a synchronous read and `append`/`deliver` as operation resources. Persist safe digests/receipts and refresh affected message lists on completion.

- [ ] Run:

```bash
./kotlin test --include-module dashboard-server --include-classes 'mail.sandbox.dashboard.server.lab.MessageLabServiceTest'
./kotlin test --include-module dashboard-server --include-classes 'mail.sandbox.dashboard.server.api.MessageLabRoutesTest'
```

Expected: pass.

## Task 5: Normalize and redact server logs before storage

**Files:**

- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/log/LogSource.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/log/DockerComposeLogSource.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/log/NormalizedEvent.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/log/DovecotLogParser.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/log/PostfixLogParser.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/log/StalwartLogParser.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/log/StalwartStructuredLogSource.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/log/LogPipelineTest.kt`

- [ ] Write failing tests for bounded history and follow commands using only allowlisted services `dovecot`, `dovecot-operator`, `postfix`, `oauth2-mock`, and `stalwart`; arbitrary service/flags must be unrepresentable. Normalize `dovecot` and `dovecot-operator` as distinct sources within the same Dovecot provider namespace so dashboard-originated operator IMAP activity remains visible without conflating it with ordinary-client traffic.

- [ ] Feed malformed/raw lines containing secrets into the pipeline. Assert redaction occurs before parser dispatch and before parse-error reporting.

- [ ] Normalize timestamp, source/service, level, event kind, safe message, exact account when present, provider identifiers, queue/session/request/object/operation IDs, local sequence, and raw-safe excerpt.

- [ ] Add optional Stalwart `x:Log` enrichment only when Gate 0B proved it. Treat server-side filtering as text-only unless the gate report proves more; apply level/event/time filters to normalized fetched pages without claiming server support.

- [ ] Run:

```bash
./kotlin test --include-module dashboard-server --include-classes 'mail.sandbox.dashboard.server.log.*'
```

Expected: pass, including deterministic secret-exclusion assertions.

## Task 6: Correlate evidence with explicit confidence

**Files:**

- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/log/CorrelationEngine.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/log/LogService.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/api/LogRoutes.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/log/CorrelationEngineTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/api/LogRoutesTest.kt`
- Modify: `debug-dashboard/dashboard-server/src/Application.kt`

- [ ] Write failing tests for confidence ordering:

  1. exact operation/request/account/provider-object identifier, or another stable identifier whose provider+source namespace matches;
  2. linked queue/session/object chain;
  3. selected account exact parsed match;
  4. time adjacency only, labeled low confidence.

Message-ID alone never earns Exact confidence; it may participate only in a deterministic Linked chain with stronger operation, queue, session, or provider-object evidence.

- [ ] Interleave deterministic events for two accounts and cover all adversarial correlation cases:

  - duplicate Message-ID across accounts/providers/sources;
  - missing Message-ID;
  - queue-ID and session-ID reuse in different provider/source namespaces;
  - one multi-recipient event related to more than one account, preserving sender/recipient/delivery relationship roles;
  - malformed parser input and an unparseable time-adjacent line;
  - a redaction failure path that is quarantined before correlation.

For each selected account, assert the exact expected inclusion set and deterministic exclusion set. Namespace every stable identifier by provider and source before matching. Time-adjacent events may appear only in a separate Nearby group, never as account membership or Exact/Linked evidence; malformed/unparseable events remain unmatched.

- [ ] Implement bounded query, source/confidence/time filters, pause/resume over SSE, stale cursor resync, and safe export with retention metadata.

- [ ] Run:

```bash
./kotlin test --include-module dashboard-server --include-classes 'mail.sandbox.dashboard.server.log.*'
./kotlin test --include-module dashboard-server --include-classes 'mail.sandbox.dashboard.server.api.LogRoutesTest'
```

Expected: pass.

## Task 7: Run live Message Lab and log parity

**Files:**

- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/live/MessageLabParityLiveTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/live/LogParityLiveTest.kt`
- Create: `docs/debug-dashboard/evidence/message-lab-and-logs.md`

- [ ] Execute every required source × path cell against newly created target accounts on both profiles. Assert preview truth, receipt truth, arrival/read-back content, replay metadata, provider key, and correlated evidence.

- [ ] Generate interleaved auth, folder, append, delivery, read, mutation, and deletion activity for two accounts. Prove server-wide history/live tail and account-scoped deterministic inclusion/exclusion.

- [ ] Run:

```bash
cd debug-dashboard
./kotlin test --include-module dashboard-server --include-classes 'mail.sandbox.dashboard.server.live.MessageLabParityLiveTest'
./kotlin test --include-module dashboard-server --include-classes 'mail.sandbox.dashboard.server.live.LogParityLiveTest'
./kotlin test
```

Expected: pass. Record safe receipts/correlation examples in the evidence document.

- [ ] Commit:

```bash
git add debug-dashboard docs/debug-dashboard/evidence/message-lab-and-logs.md
git commit -m "feat: add message lab and correlated evidence"
```
