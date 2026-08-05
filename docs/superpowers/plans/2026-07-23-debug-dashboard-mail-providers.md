# Debug Dashboard Mail Providers Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement folder lifecycle, message list/read/raw, and all required message mutations through real IMAP and JMAP paths with provider-native identity and concurrency semantics.

**Architecture:** Expose one application-facing mail port with sealed provider-specific keys, but keep two direct adapters. Dovecot uses the Gate 0C isolated master/operator IMAP ingress and UID/UIDVALIDITY commands. Stalwart discovers JMAP Session while directly authenticated with a leased Account-bound AppPassword from the Gate 0B encrypted store; an unready Account fails before any JMAP call. Batch results are itemized and state conflicts remain explicit.

**Tech Stack:** Kotlin/JVM, Jakarta Mail API 2.1.5, Angus Mail 2.0.5, Ktor client, kotlinx.serialization, IMAP UIDPLUS/MOVE where advertised, Stalwart v0.16.16 JMAP Mail.

---

## Execution prerequisite

Gate 0B's direct AppPassword/store/lifecycle proof and the account-provider mail-access routes must pass. Stalwart adapters consume only the approved credential-lease port; they never accept a normal password, management key, raw snapshot path, operator identity, or impersonation target.

## Task 1: Define the mail application port and mutation semantics

**Files:**

- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/mail/MailStorePort.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/mail/MailService.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/mail/MailMutation.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/mail/MailboxDeletionPreview.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/mail/PermanentDeleteConfirmation.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/mail/MailServiceTest.kt`
- Modify: `debug-dashboard/dashboard-contract/src/mail/sandbox/dashboard/contract/Mail.kt`

- [ ] Write failing tests that require:

  - mailbox pages to retain IMAP encoded name/delimiter/UID context or JMAP id/state/role/rights;
  - message pages to retain IMAP UIDVALIDITY+UID or JMAP Email id+state;
  - stale provider keys to fail with a typed concurrency problem;
  - batch mutations to report each requested key independently;
  - `enrollmentRequired`, `rotating`, `recoveryRequired`, `removalPending`, and global `storeUnavailable` to return their typed problem before the provider port is invoked;
  - read/unread and flag/unflag to be reversible;
  - move, copy, Trash, membership removal where supported, and permanent delete to stay distinct.

- [ ] Define `MailStorePort` methods for mailbox list/create/delete, paged message query, structured read, raw stream, and itemized mutation. Avoid one untyped `execute(action: String)`.

- [ ] Define mailbox-delete preview/confirmation DTOs using Foundation's shared destructive grant. Bind the grant to session, profile/account, IMAP encoded name+delimiter+UIDVALIDITY+child/message counts or JMAP Mailbox id+state+rights+child/message counts, orphan-removal choice, preview digest, and expiry.

- [ ] Make mailbox deletion impossible through generic mailbox mutation. Under the logical-account lock, confirmation atomically consumes the grant and re-reads the exact bound state; for JMAP it also sends `ifInState`, and for IMAP it rechecks existence/UIDVALIDITY/counts immediately before the exact delete. Missing, forged, altered, expired, reused, cross-session, wrong-target, or stale grants make zero delete calls and require a fresh preview.

- [ ] Define permanent-delete preview/confirmation DTOs backed by Foundation's shared destructive grant. Bind session, provider profile, account, exact provider-native message keys, current UIDVALIDITY/JMAP state, count, irreversible effect, preview digest, and short expiry. The client receives only the opaque preview ID plus human-readable scope.

- [ ] Make permanent delete impossible through the generic mutation method. Confirmation must present the unexpired preview ID plus an explicit acknowledgement, and the server must atomically consume it only when session, profile, account, item set, and provider state still match. Forged, missing, altered, expired, reused, cross-session, or stale confirmations return a typed problem and perform no provider call.

- [ ] Implement provider selection, policy/preflight, confirmation enforcement, and operation wrapping in `MailService`. Unit tests must prove every rejection above and prove that only a valid confirmation can reach the adapter's destructive method.

- [ ] Run:

```bash
cd debug-dashboard
./kotlin test --include-module dashboard-server --include-classes 'mail.sandbox.dashboard.server.mail.*'
```

Expected: pass against fake ports.

## Task 2: Implement the Dovecot IMAP adapter

**Files:**

- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/provider/dovecot/DovecotImapSessionFactory.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/provider/dovecot/DovecotMailboxMapper.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/provider/dovecot/DovecotMessageMapper.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/provider/dovecot/DovecotMailAdapter.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/provider/dovecot/DovecotMailAdapterTest.kt`
- Modify: `debug-dashboard/dashboard-server/module.yaml`

- [ ] Add compile dependencies `jakarta.mail:jakarta.mail-api:2.1.5` and runtime dependency `org.eclipse.angus:angus-mail:2.0.5`.

- [ ] Write adapter tests around a fake protocol façade for:

  - operator authentication targeting one eligible address;
  - LIST delimiter, attributes, special-use, selectability, counts, and rights;
  - create and empty delete;
  - refusal/preview for non-empty or child mailboxes;
  - UID paging and envelope/bodystructure mapping;
  - raw RFC 5322 retrieval without losing the key;
  - UIDVALIDITY mismatch before mutation;
  - `\Seen`, `\Flagged`, COPY, MOVE, Trash, and UID-scoped permanent deletion;
  - no permanent deletion call until `MailService` supplies a validated one-time confirmation grant;
  - partial batch failure.

- [ ] Implement one bounded session per operation and close folders/stores reliably. Never log the master credential or targeted authentication string.

- [ ] Consume only Gate 0C's atomic active A/B credential reference through its fixed-path secret loader. Snapshot one active credential per operation, reload after rotation without browser involvement, and test that an in-flight operation finishes with its snapshot while every new operation uses the switched slot and the revoked slot fails.

- [ ] Use server-advertised capabilities. Use real MOVE only when advertised; otherwise implement move as UID COPY + mark exact source UIDs `\Deleted` + UID EXPUNGE only when UIDPLUS makes it safe. If neither safe path exists, report unsupported—never run broad EXPUNGE.

- [ ] Parse MIME structure without implicitly setting `\Seen` unless the requested action/read policy says so. Keep raw retrieval and Seen mutation independently testable.

- [ ] Run:

```bash
./kotlin test --include-module dashboard-server --include-classes 'mail.sandbox.dashboard.server.provider.dovecot.DovecotMailAdapterTest'
```

Expected: pass.

## Task 3: Implement the Stalwart JMAP Mail adapter

**Files:**

- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/provider/stalwart/JmapMethodCall.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/provider/stalwart/StalwartLeasedSession.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/provider/stalwart/StalwartMailSessionFactory.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/provider/stalwart/StalwartMailboxMapper.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/provider/stalwart/StalwartMessageMapper.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/provider/stalwart/StalwartMailAdapter.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/provider/stalwart/StalwartMailAdapterTest.kt`

- [ ] Write fake-JMAP tests in which `StalwartMailSessionFactory` acquires a Gate 0B credential lease by immutable Account ID, authenticates directly as that Account, discovers Session URLs/capabilities, verifies the Session's primary account matches, and closes/wipes the lease on success, protocol failure, timeout, and coroutine cancellation.

- [ ] Hold the same `StalwartLeasedSession` through Session discovery and every `apiUrl`, `uploadUrl`, and `downloadUrl` request in one application operation. It cannot expose the AppPassword to callers; it only authorizes bounded requests and closes the underlying lease.

- [ ] Prove `enrollmentRequired`, `rotating`, `recoveryRequired`, `removalPending`, `storeUnavailable`, protected provider IDs, missing Account IDs, and address/ID mismatch are rejected before Session discovery or any JMAP method. Prove there is no normal-password, management-key, `target%operator`, cross-account, or fallback-auth path.

- [ ] When the provider rejects the stored active credential during Session authentication, notify the lifecycle projector, return typed `recoveryRequired`, and never retry with another credential. After that state is recorded, subsequent mail calls make zero JMAP requests until Repair succeeds.

- [ ] Add concurrency tests using the real `StalwartCredentialLeaseRegistry`: ordinary calls hold a generation lease for their bounded operation; explicit credential mutation blocks new sessions and waits for all current adapters to close; a 30-second drain timeout leaves the active generation/provider untouched. After successful rotation every new session uses the successor and the old credential fails.

- [ ] Cover `Mailbox/get|set`, `Email/query|get|set`, and blob/raw download:

  - page by query position/limit and retain query/email state;
  - request explicit body properties and keep blob/body-part IDs distinct;
  - create mailbox with parent/role constraints;
  - preview and enforce rights/non-empty/child/orphan-removal deletion safety;
  - patch keywords and mailbox IDs with `ifInState`;
  - map `notUpdated`, `notDestroyed`, and `stateMismatch` per item.

- [ ] Implement read/unread via `$seen`, flag/unflag via `$flagged`, copy/move through mailbox membership patches, Trash through the role-resolved mailbox, supported membership removal, and confirmation-grant-only permanent destroy. Never flatten JMAP partial `set` results into one boolean.

- [ ] Ensure no request, exception, fake transport capture, log, metric, operation receipt, or test diagnostic serializes the Basic header or `app_` value. The adapter receives secret bytes only through the lease and clears transport copies after request construction.

- [ ] Run:

```bash
./kotlin test --include-module dashboard-server --include-classes 'mail.sandbox.dashboard.server.provider.stalwart.StalwartMailAdapterTest'
```

Expected: pass.

## Task 4: Parse safe structured message content

**Files:**

- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/mail/MimeMessageReader.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/mail/AttachmentPolicy.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/mail/HtmlMessageSanitizer.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/mail/MimeMessageReaderTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/mail/HtmlMessageSanitizerTest.kt`
- Modify: `debug-dashboard/dashboard-server/module.yaml`

- [ ] Add `org.jsoup:jsoup:1.23.1`.

- [ ] Drive parser tests with existing fixtures for plain text, HTML-only, multipart alternative/related, encodings, inline CID/content-location images, attachments, suspicious links, remote images, executable/macro/HTML archives, and malformed structures.

- [ ] Require the parser to return bounded plain text, sanitized HTML, attachment metadata, inline-resource tokens, and warnings. Never resolve remote URLs server-side.

- [ ] Write sanitizer tests that remove scripts, forms, active embeds, event handlers, base/meta redirects, unsafe schemes, top navigation, external stylesheets, and remote media while preserving safe formatting and local tokenized inline resources.

- [ ] Implement download policy with safe filenames, `Content-Disposition: attachment`, fixed content type where dangerous, size bounds, and no inline execution for HTML/executable-like content.

- [ ] Run:

```bash
./kotlin test --include-module dashboard-server --include-classes 'mail.sandbox.dashboard.server.mail.MimeMessageReaderTest'
./kotlin test --include-module dashboard-server --include-classes 'mail.sandbox.dashboard.server.mail.HtmlMessageSanitizerTest'
```

Expected: pass.

## Task 5: Expose mailbox, message, raw, and mutation routes

**Files:**

- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/api/MailboxRoutes.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/api/MailboxDeleteRoutes.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/api/MessageRoutes.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/api/MessageActionRoutes.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/api/PermanentDeleteRoutes.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/api/MailRoutesTest.kt`
- Modify: `debug-dashboard/dashboard-server/src/Application.kt`

- [ ] Write failing Ktor tests for both provider key variants across:

  - mailbox list/create plus dedicated delete preview/confirm;
  - mailbox deletion with no grant and with forged, expired, reused, cross-session, altered-orphan-choice, wrong-target, and stale provider-state grants, each producing zero delete calls;
  - message paging/relist;
  - structured read;
  - raw RFC 5322 download;
  - safe attachment/inline-resource download;
  - every required mutation and reversal;
  - permanent-delete preview and confirm as separate routes;
  - missing, forged, altered, expired, reused, cross-session, and provider-state-stale permanent-delete confirmations performing no deletion;
  - stale UIDVALIDITY/JMAP state;
  - itemized batch failure;
  - origin/session/CSRF/idempotency enforcement.

- [ ] Implement thin routes that call `MailService`; all mutations return operation resources. Generic mailbox/action routes reject mailbox and permanent-message deletion. Dedicated `/mailboxes/delete/preview|confirm` and `/message-actions/permanent-delete/preview|confirm` routes enforce their two-step contracts server-side.

- [ ] Run:

```bash
./kotlin test --include-module dashboard-server --include-classes 'mail.sandbox.dashboard.server.api.MailRoutesTest'
```

Expected: pass.

## Task 6: Run live folder/read/mutation parity

**Files:**

- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/live/MailParityLiveTest.kt`
- Create: `docs/debug-dashboard/evidence/mail-parity.md`

- [ ] For a fresh dual-provider disposable account whose Stalwart instance is `ready` and seeded through supported paths:

  1. list, create, and relist an empty folder; preview deletion, prove no deletion before confirmation, induce stale state and prove rejection, then obtain a fresh grant, confirm once, prove replay rejection, and relist;
  2. prove non-empty/child/orphan-choice deletion safety and that every scope change requires a fresh grant;
  3. page/list and read plain, sanitized HTML, attachments, and raw;
  4. apply/reverse seen and flagged;
  5. copy, move, Trash, and supported membership removal;
  6. relist after every mutation and assert provider-native keys/states;
  7. preview permanent deletion, prove no deletion before confirmation, induce a stale preview and prove rejection, then obtain a fresh preview, confirm once, prove replay rejection, and relist;
  8. induce one stale UIDVALIDITY/JMAP state and one partial batch failure.
  9. remove Stalwart dashboard access and prove list/read/mutation return `enrollmentRequired` with zero JMAP calls; re-enroll request-scoped, then prove the same workflow succeeds again.

- [ ] Run:

```bash
cd debug-dashboard
./kotlin test --include-module dashboard-server --include-classes 'mail.sandbox.dashboard.server.live.MailParityLiveTest'
```

Expected: pass once through each profile. Record safe identifiers and capability evidence in the evidence document.

- [ ] Commit:

```bash
git add debug-dashboard docs/debug-dashboard/evidence/mail-parity.md
git commit -m "feat: implement mail operation parity"
```
