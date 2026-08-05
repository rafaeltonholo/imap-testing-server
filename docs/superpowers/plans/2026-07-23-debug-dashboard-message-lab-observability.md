# Debug Dashboard Message Lab and Observability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add truthful MIME preview/generation, direct append, real delivery, server/account logs, redaction, correlation, and provider-native evidence for every operation.

**Architecture:** A bounded message-source pipeline produces one validated raw message plus a separate local envelope. Append and delivery dispatch to different provider ports and verify mailbox arrival. Every Stalwart append/submission/read-back call uses the exact Account's Gate-0B credential lease, after an all-target readiness preflight that makes zero submission calls on failure. Docker/stdout and optional Stalwart structured logs enter a redact-first normalization pipeline, then correlation links exact identifiers before cautious time adjacency.

**Tech Stack:** Kotlin/JVM, Angus Mail 2.0.5/Jakarta Mail API 2.1.5, Ktor multipart/SSE, allowlisted Docker Compose logs, Dovecot `doveadm save`, Postfix SMTP, Stalwart v0.16.16 JMAP upload/import/EmailSubmission, SQLite JDBC 3.53.2.1 event cache.

---

## Execution prerequisite

Gate 0B, account-provider lifecycle operations, and the Stalwart mail session factory must pass. Message Lab consumes only Account-bound credential leases; it cannot accept a normal password, management credential, impersonation target, or raw snapshot path.

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

- [ ] Encode the same deterministic terminal aggregation for Postfix delivery: `failed` only when every recipient is conclusively rejected and none is accepted; `succeeded` only when every recipient is accepted and the unique marker is relisted/read from every target Dovecot mailbox; `reconciliationRequired` when acceptance is ambiguous or at least one recipient is accepted but any recipient later fails, times out, or remains unverified. Preserve itemized acceptance and arrival receipts; never report a timeout as success.

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
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/provider/stalwart/StalwartDeliveryReadback.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/provider/stalwart/StalwartImportAdapterTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/provider/stalwart/StalwartSubmissionAdapterTest.kt`

- [ ] Write fake-JMAP tests for discovered `uploadUrl`, content upload, `Email/import`, mailbox selection, created/notCreated mapping, and read-back verification. Direct append acquires only the selected target Account's lease and releases it on every terminal/cancellation path.

- [ ] Write submission tests that require:

  - sender plus every selected Stalwart recipient to be `ready` before upload/import/submission; any other lifecycle state returns itemized remediation and makes zero JMAP calls;
  - an available user Identity selected truthfully;
  - import of the authored raw message as a draft using the sender's own leased AppPassword;
  - `EmailSubmission/set` referencing the imported Email through the v0.16.14 gate-proven result/creation-ID chain;
  - local-only envelope recipients;
  - per-recipient submission/delivery status;
  - target mailbox arrival queried with each recipient Account's own independently acquired lease;
  - Sent filing only when actually observed;
  - explicit failure when Identity/submission capability is absent.

- [ ] Encode deterministic terminal aggregation before implementing delivery:

  - `failed` only when the provider conclusively rejects every recipient and accepts none;
  - `succeeded` only when every recipient is accepted and the unique marker is relisted/read from every target mailbox;
  - `reconciliationRequired` when acceptance is ambiguous or at least one recipient was accepted but another later fails, times out, or remains unverified.

Preserve every confirmed arrival/acceptance receipt. An all-recipient delivery with failed Sent filing is `reconciliationRequired` with the delivery sub-result still successful.

- [ ] Implement direct append as upload + `Email/import`; hold the selected target Account's lease across Session discovery, upload, import, and verification. Implement delivery as a separate submission chain: hold the sender lease across Session discovery, upload/import, Identity lookup, `EmailSubmission/set`, and Sent filing; hold each recipient's own lease across its arrival read-back. Release every lease and wipe transient credential bytes on success, failure, timeout, and cooperative cancellation. Apply the aggregation above and never label import or Sent filing alone as delivery.

- [ ] Test a credential becoming revoked after preflight, rotation waiting on active sender/read-back leases, provider timeout after submission, partial multi-recipient acceptance, and missing recipient read-back. Never retry submission automatically when acceptance may have occurred.

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

- [ ] Test preview-before-run, idempotency, upload/source discard, seed replay, dual-provider partial result, multi-recipient itemization/aggregation, cancellation between items, and retry requiring source re-supply after disposal.

- [ ] At the `MessageLabService` boundary, preflight all selected Stalwart sender/recipient Account IDs and acquire no provider resource when one is not `ready`. Return state-specific typed remediation: Enable for `enrollmentRequired`, Repair for `recoveryRequired`, wait/progress for `rotating`, reconciliation/cleanup detail for `removalPending`, and Server Setup credential-store reset for `storeUnavailable`. A migrated Account must be explicitly enrolled before a dashboard-verified delivery.

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

- [ ] Feed malformed/raw lines containing normal passwords, `app_` AppPasswords, API keys, Basic/Bearer values, and encrypted-store errors into the pipeline. Assert redaction occurs before parser dispatch and before parse-error reporting.

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

- [ ] Execute every required source × path cell against newly created `ready` target accounts on both profiles. Assert preview truth, receipt truth, arrival/read-back content, replay metadata, provider key, and correlated evidence. For Stalwart, also prove one unenrolled recipient blocks the entire operation before upload, then enroll it and rerun successfully.

- [ ] Run multi-recipient Stalwart cases for all accepted/all arrived, all conclusively rejected, partial acceptance, ambiguous acceptance, accepted-but-timeout, and successful delivery/failed Sent filing. Assert the exact terminal state and preserved itemized receipts.

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
