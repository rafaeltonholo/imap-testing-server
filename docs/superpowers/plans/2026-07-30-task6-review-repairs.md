# Task 6 Review Repairs Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the final Task 6 concurrency, interruption, ownership, and proof-quality findings without running Docker or live services.

**Architecture:** A capacity-four production coordinator gives each logical network operation one disposable serialized I/O worker and reserves at most four lazy cancellation actors. Caller-side protocol logic waits against one absolute deadline, while worker-owned buffers are either handed off normally or wiped on late completion. Held IMAP, the production probe, and raw HTTP share the model; focused helpers address the remaining repository and live-proof test findings.

**Tech Stack:** Kotlin/JVM, Java concurrency primitives, Amper `./kotlin` tests, Python stdlib `unittest`.

---

### Task 1: Add the bounded operation coordinator

**Files:**
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/gate/dovecot/DovecotBoundedOperationWorkers.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotBoundedOperationWorkersTest.kt`

- [ ] **Step 1: Write the failing coordinator tests**

Cover one healthy operation; initialization/I/O-worker-start, cancellation
actor-start, and task-submission failure; timeout before dequeue; result
handoff at the deadline; late target registration racing I/O-worker exit; two
identity-distinct targets per operation; rejection of a third target before
ownership; four permanently abandoned operations; fifth admission failing
before its allocation callback; the twenty-actor peak; and late release
reducing active/abandoned counts and allowing another operation. Inject an
actor-start failure and assert its charge is released without leaking an
operation. Use worker-owned write/read arrays and assert never-run and late
results are wiped exactly once.

- [ ] **Step 2: Run the focused test and verify RED**

Run:

```bash
cd debug-dashboard
./kotlin test --include-module dashboard-server \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotBoundedOperationWorkersTest
```

Expected: compilation failure because the wished-for coordinator API does not
exist.

- [ ] **Step 3: Implement the minimal coordinator**

Implement capacity admission before actor creation, a private queue and unique
daemon I/O worker per operation, identity-distinct cancellation registration,
lazy abort/close actors, active/abandoned/active-actor/peak snapshots, absolute
waits, result handoff, and late-result disposal. Reserve at most five actors
per operation and four operations globally.

- [ ] **Step 4: Run the focused test and verify GREEN**

Run the command from Step 2. Expected: all coordinator tests pass.

- [ ] **Step 5: Commit**

```bash
git add debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/gate/dovecot/DovecotBoundedOperationWorkers.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotBoundedOperationWorkersTest.kt
git commit -m "feat: bound Task 6 operation workers"
```

### Task 2: Move the production probe behind caller-bounded I/O

**Files:**
- Modify: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorProbe.kt`
- Modify: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorProbeTest.kt`

- [ ] **Step 1: Write dual-block and capacity regressions**

Use a real probe transport whose command write, `abort()`, and `close()` block
on separate latches. Assert each caller returns within a short injected
absolute deadline, the credential and caller-side source arrays are wiped,
four operations fill the injected coordinator, and the fifth returns
`TransportFailure` without transport allocation. Release all latches and
assert accounting returns to zero and a later scripted probe succeeds.

- [ ] **Step 2: Run `DovecotOperatorProbeTest` and verify RED**

Expected: dual-block callers remain alive or exceed the deadline; capacity and
accounting assertions are unavailable.

Run:

```bash
cd debug-dashboard
./kotlin test --include-module dashboard-server \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotOperatorProbeTest \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotBoundedOperationWorkersTest
```

- [ ] **Step 3: Integrate the coordinator**

Acquire before credential access and transport allocation. Dispatch open,
bounded line/literal reads, writes, and flushes through the operation. Remove
the reusable open executor, unaccounted cancellation threads, and production
watchdog. Register allocated and distinct returned transports. Preserve
mailbox state, response bounds, classification, and caller-owned credential
wiping.

- [ ] **Step 4: Run `DovecotOperatorProbeTest` and coordinator tests**

Expected: both classes pass, including the new cap and late-cleanup cases.

Use the exact command from Step 2.

- [ ] **Step 5: Commit**

```bash
git add debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorProbe.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorProbeTest.kt
git commit -m "fix: bound Dovecot probe callers"
```

### Task 3: Bound Held IMAP and enforce interrupt precedence

**Files:**
- Modify: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotTask6ProofDeadline.kt`
- Modify: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/HeldDovecotOperatorImapSession.kt`
- Modify: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotHeldOperatorImapDeadlineTest.kt`

- [ ] **Step 1: Write failing dual-block regressions**

Cover open/seed, usability NOOP, direct and lease-owned close, and post-close
writes where original I/O, abort, and close all block. Assert bounded callers,
four-operation cap, fifth-call fail-fast, no new actors, late state/accounting
release, joinable terminal replay, retry semantics, and later success.

- [ ] **Step 2: Write failing interrupt-plus-IOException regressions**

For seed/open, usability, and post-close, interrupt the caller and then make
the actual I/O exit via `IOException` or `SocketException`. Assert bounded
cleanup, a redacted `InterruptedException`, and preserved interrupt status.
Post-close must not return success.

- [ ] **Step 3: Run the deadline class and verify RED**

Expected: dual-block callers remain alive and every IOException-plus-interrupt
case is generically classified or accepted.

Run:

```bash
cd debug-dashboard
./kotlin test --include-module dashboard-server \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotHeldOperatorImapDeadlineTest \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotHeldOperatorImapSessionTest \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotOperatorApplicationLeaseRegistryTest \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotBoundedOperationWorkersTest
```

- [ ] **Step 4: Implement Held integration and a workerless deadline**

Give open/seed and each later check a fresh coordinator operation. Store the
coordinator in a successful held session. Dispatch every blocking boundary,
including explicit/lease-owned close, through it. Keep the close API
synchronous and retryable, publish successful late close, remove unaccounted
cancellation/open workers, and make the deadline invoke expiry from absolute
caller waits without a watcher actor.

Before generic classification, perform bounded abandonment cleanup, check the
interrupt flag, restore it, and throw a new redacted `InterruptedException`.

- [ ] **Step 5: Run Held, deadline, and coordinator tests and verify GREEN**

Use the exact command from Step 3.

- [ ] **Step 6: Commit**

```bash
git add debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotTask6ProofDeadline.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/HeldDovecotOperatorImapSession.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotHeldOperatorImapDeadlineTest.kt
git commit -m "fix: bound held IMAP operations"
```

### Task 4: Bound raw HTTP and prove real collector wiping

**Files:**
- Modify: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotBoundedHttpProofClient.kt`
- Modify: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotOAuthProof.kt`
- Modify: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotOAuthProofValidatorTest.kt`

- [ ] **Step 1: Write failing HTTP regressions**

Cover blocking connect/read/write with blocking socket close; absolute
deadline-bounded caller return; active-to-abandoned accounting; capacity
failure before socket allocation; late close release and capacity recovery;
interruption followed by actual `SocketException`; redacted
`InterruptedException` with restored flag; and interruption between socket
allocation and deadline setup. Inject the actual response-buffer factory; make
a fixed-length body collector receive bytes and then fail, and assert its
captured array is wiped.

After all three integrations exist, fill the process-wide coordinator through
its internal production accessor and prove default probe, Held, and HTTP entry
points all fail before their credential/resource factories. Release the
fixtures and verify the shared snapshot returns to zero.

- [ ] **Step 2: Run `DovecotOAuthProofValidatorTest` and verify RED**

Run:

```bash
cd debug-dashboard
./kotlin test --include-module dashboard-server \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotOAuthProofValidatorTest \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotBoundedOperationWorkersTest
```

- [ ] **Step 3: Integrate HTTP with the coordinator**

Acquire before socket allocation, register the socket before connect, and
dispatch connect/write/flush/status/header/body reads through the operation.
Move socket ownership around deadline creation. Promote every flagged generic
failure to redacted interruption after bounded cleanup. Remove
`task6RequireBoundedHttpBody`; use the injected factory in the real collectors
and wipe normal, failed, and late buffers.

- [ ] **Step 4: Run HTTP and coordinator tests and verify GREEN**

Use the exact command from Step 2.

- [ ] **Step 5: Commit**

```bash
git add debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotBoundedHttpProofClient.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotOAuthProof.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotOAuthProofValidatorTest.kt
git commit -m "fix: bound Task 6 HTTP operations"
```

### Task 5: Close repository and terminal replay proof gaps

**Files:**
- Modify: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorDurableRepository.kt`
- Modify: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorDurableRepositoryTest.kt`
- Modify: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorApplicationLeaseRegistryTest.kt`

- [ ] **Step 1: Add a failing growth-probe ownership test**

Use a real extracted readable-channel boundary that captures the one-byte
backing array after returning a growth byte. Expected RED: the helper/API is
absent.

- [ ] **Step 2: Run the repository class and verify RED**

```bash
cd debug-dashboard
./kotlin test --include-module dashboard-server \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotOperatorDurableRepositoryTest
```

Expected: compile failure for the wished-for channel helper.

- [ ] **Step 3: Implement named one-byte ownership**

Allocate `growthProbe`, wrap it, return the read result, and wipe it in
`finally`. Use the helper from `stableRead`.

- [ ] **Step 4: Run the repository class and verify GREEN**

Use the exact command from Step 2.

- [ ] **Step 5: Strengthen terminal replay characterization**

Make the callback increment a counter and fail only on its first invocation.
Assert two runtime closes throw the identical first object, the callback count
is one, and activation is rejected with its secret wiped. This is a
characterization-only test; no production change is expected.

- [ ] **Step 6: Run the terminal characterization immediately**

```bash
cd debug-dashboard
./kotlin test --include-module dashboard-server \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotOperatorApplicationLeaseRegistryTest
```

Expected: the strengthened characterization passes the existing terminal
runtime implementation.

- [ ] **Step 7: Commit**

```bash
git add debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorDurableRepository.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorDurableRepositoryTest.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorApplicationLeaseRegistryTest.kt
git commit -m "test: close Task 6 ownership gaps"
```

### Task 6: Extract executable live-proof fixtures without running live tests

**Files:**
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/Task6DisposableEligibilityFixture.kt`
- Modify: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotIsolationLiveTest.kt`
- Modify: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorRotationLiveTest.kt`
- Modify: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotIsolationMailboxContractTest.kt`
- Modify: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotIsolationProtocolProof.kt`

- [ ] **Step 1: Write failing behavioral fixture tests**

Inject a fake eligibility gateway whose add mutates membership and returns 2.
Assert the fixture marks the attempt first, rechecks membership, removes the
target, and runs rejection proof. Inject the inactive-master orchestration
callback and assert it receives the other fixed suffix with the exact active
credential object.

- [ ] **Step 2: Run `DovecotIsolationMailboxContractTest` and verify RED**

Run:

```bash
cd debug-dashboard
./kotlin test --include-module dashboard-server \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotIsolationMailboxContractTest
```

- [ ] **Step 3: Implement and adopt shared boundaries**

Move password generation, CLI execution, attempt state, membership cleanup,
and rejection proof into the shared fixture. Replace both live-suite
implementations. Extract typed inactive-master orchestration and delete every
source-substring assertion/helper.

- [ ] **Step 4: Run only the non-live contract class and verify GREEN**

Use the exact command from Step 2. Do not select either `*LiveTest`.

- [ ] **Step 5: Commit**

```bash
git add debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/Task6DisposableEligibilityFixture.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotIsolationLiveTest.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorRotationLiveTest.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotIsolationMailboxContractTest.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotIsolationProtocolProof.kt
git commit -m "test: make Task 6 live orchestration executable"
```

### Task 7: Review, evidence, and final verification

**Files:**
- Modify: `docs/debug-dashboard/gates/0c-dovecot.md`

- [ ] **Step 1: Dispatch an adversarial internal review**

Ask a reviewer to attack dual-block behavior, cap/accounting races, late
buffer/transport ownership, interrupt precedence, and fixture cleanup.

- [ ] **Step 2: Run focused and reciprocal non-live suites**

Run all changed classes, then the exact Task 6 reciprocal class selection.
Record actual discovered counts only.

```bash
cd debug-dashboard
./kotlin test --include-module dashboard-server \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotBoundedOperationWorkersTest \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotOperatorCredentialStoreTest \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotOperatorDurableRepositoryTest \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotOperatorRotationStateTest \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotOperatorApplicationLeaseRegistryTest \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotAuthenticationResponseClassifierTest \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotOperatorProbeTest \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotOAuthProofValidatorTest \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotHeldOperatorImapSessionTest \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotHeldOperatorImapDeadlineTest \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotIsolationMailboxContractTest \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotTask6ProcessProofTest \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotTask6TopologyProofTest
```

- [ ] **Step 3: Run proportional broad verification**

Run the exact non-live Dovecot selection plus the 13 static/config selectors,
then the wider non-live dashboard-server selection plus those selectors.
Exclude all live classes, the mixed Docker-backed config methods, and the
browser gate as before.

```bash
cd debug-dashboard
./kotlin test --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.gate.dovecot.*Test' \
  --exclude-classes 'mail.sandbox.dashboard.server.gate.dovecot.*LiveTest' \
  --exclude-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotOperatorConfigTest
```

```bash
cd debug-dashboard
./kotlin test --include-module dashboard-server \
  --exclude-classes '*LiveTest' \
  --exclude-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotOperatorConfigTest \
  --exclude-classes mail.sandbox.dashboard.server.gate.KotlinToolchainBrowserGateTest
```

Run the exact static selectors after each broad command:

```bash
cd debug-dashboard
./kotlin test --include-module dashboard-server \
  --include-test mail.sandbox.dashboard.server.gate.dovecot.DovecotOperatorConfigTest.standaloneOperatorConfigIsTheExactReviewedImapsOnlyMasterBoundary \
  --include-test mail.sandbox.dashboard.server.gate.dovecot.DovecotOperatorConfigTest.defaultComposeOmitsOperatorUntilItsExplicitProfileIsSelected \
  --include-test mail.sandbox.dashboard.server.gate.dovecot.DovecotOperatorConfigTest.resolvedComposeKeepsOperatorIngressLoopbackOnlyAndIsolated \
  --include-test mail.sandbox.dashboard.server.gate.dovecot.DovecotOperatorConfigTest.operatorIngressDocumentationRequiresAQuietOperationalHealthcheck \
  --include-test mail.sandbox.dashboard.server.gate.dovecot.DovecotOperatorConfigTest.operatorAuthDocumentationRequiresPreinitSafeFourPassdbChain \
  --include-test mail.sandbox.dashboard.server.gate.dovecot.DovecotOperatorConfigTest.task5LiveProofDeniesBareTargetLoginBeforeMasterLoginAndWipesBuffers \
  --include-test mail.sandbox.dashboard.server.gate.dovecot.DovecotOperatorConfigTest.repositorySkillReferencesTrackCurrentDovecotTopologyAndAuthorities \
  --include-test mail.sandbox.dashboard.server.gate.dovecot.DovecotOperatorConfigTest.resolvedComposeUsesOnlyReviewedOperatorMountsAndNeverMountsRawSecrets \
  --include-test mail.sandbox.dashboard.server.gate.dovecot.DovecotOperatorConfigTest.resolvedComposePinsBoundedQuietOperationalHealthcheck \
  --include-test mail.sandbox.dashboard.server.gate.dovecot.DovecotOperatorConfigTest.proofOverrideExplicitlyClearsTheProductionOperatorProfile \
  --include-test mail.sandbox.dashboard.server.gate.dovecot.DovecotOperatorConfigTest.resolvedProofComposeUsesOnlyTheFixedIsolatedTopology \
  --include-test mail.sandbox.dashboard.server.gate.dovecot.DovecotOperatorConfigTest.task5RunbookDelegatesToTheCheckedFailClosedLifecycle \
  --include-test mail.sandbox.dashboard.server.gate.dovecot.DovecotOperatorConfigTest.currentAuthoritiesContainNoProtectedOrUnknownMasterIdentity
```

- [ ] **Step 4: Run independent helper and build checks**

```bash
python3 -B -W error -m unittest \
  debug-dashboard/dashboard-server/testResources/dovecot-gate0c/test_network_isolation_check.py
cd debug-dashboard
./kotlin build --module dashboard-server
```

- [ ] **Step 5: Update evidence from actual results**

Document the exact cap, actor accounting, interruption behavior, focused and
broad counts, and pending live status. Do not claim Docker or live evidence.

- [ ] **Step 6: Execute `.ai/self-review.md`**

Review scope, repository conventions, Dovecot correctness, documentation,
validation exclusions, `git diff --check`, and clean status.

- [ ] **Step 7: Commit and request final spec review**

```bash
git add docs/debug-dashboard/gates/0c-dovecot.md
git commit -m "docs: refresh Task 6 bounded-worker evidence"
```

Expected final state: clean worktree, no open review finding, live Task 6
status still pending.
