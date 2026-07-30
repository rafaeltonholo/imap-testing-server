# Task 6 Final Review Repairs Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Repair the six final Task 6 interruption, handoff, cleanup, and deterministic-proof findings without Docker or live services.

**Architecture:** Preserve the bounded coordinator and add authoritative post-claim deadline linearization plus worker-interrupt-safe disposition. Route every Probe result through one interrupt normalizer, and move Held/HTTP classification seams behind unconditional operation cleanup. Add deterministic barriers only at the exact state boundaries under test.

**Tech Stack:** Kotlin/JVM, Java concurrency primitives, Amper `./kotlin` tests, Python stdlib `unittest`.

---

### Task 1: Repair coordinator completion ownership

**Files:**
- Modify: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/gate/dovecot/DovecotBoundedOperationWorkers.kt`
- Modify: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotBoundedOperationWorkersTest.kt`

- [ ] **Step 1: Add deterministic failing tests**

Add a claim-attempt barrier test in which the worker publishes an
`InterruptedException` with its own interrupt flag set while the caller is
held before CAS. Assert the caller receives redacted interruption, not timeout,
and its interrupt flag is restored.

Add result and generic-failure tests whose injected clock returns a
pre-deadline sample while atomically advancing the underlying clock to the
deadline before CAS. Expect timeout, exactly-once result wiping, cancellation,
and zero final accounting. Add a claimed-interruption boundary test proving
interruption still wins at the expired post-CAS sample.

- [ ] **Step 2: Run focused coordinator RED**

```bash
cd debug-dashboard
./kotlin test --include-module dashboard-server \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotBoundedOperationWorkersTest
```

Expected: the worker-side failure is demoted to timeout and the handoff
crossing returns the result/generic failure.

- [ ] **Step 3: Implement the minimal state-machine repair**

Pass an injected no-op claim seam into each `OperationTask`. After a successful
completion-to-`Claimed` CAS, sample the absolute deadline in a `try/finally`
that always signals disposition. Dispose an expired claimed result, time out an
expired generic failure, and preserve a claimed `InterruptedException`.

Make worker disposition waiting record and clear worker interruptions, keep
waiting without declining, and restore the worker flag on exit.

- [ ] **Step 4: Run focused coordinator GREEN**

Run the Step 2 command. Expected: all coordinator tests pass with zero leaked
actors or reservations.

- [ ] **Step 5: Commit**

```bash
git add \
  debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/gate/dovecot/DovecotBoundedOperationWorkers.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotBoundedOperationWorkersTest.kt
git commit -m "fix: linearize Task 6 operation handoff"
```

### Task 2: Normalize every Probe result

**Files:**
- Modify: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorProbe.kt`
- Modify: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorProbeTest.kt`

- [ ] **Step 1: Add three failing interrupt-boundary tests**

Use an injected result-selection barrier to interrupt the caller after a valid
success selection, an early authentication-failure selection, and the
protocol-exception catch. Assert all three return `TransportFailure`, preserve
the caller flag, wipe the credential, and release operation accounting.

- [ ] **Step 2: Run focused Probe RED**

```bash
cd debug-dashboard
./kotlin test --include-module dashboard-server \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotOperatorProbeTest
```

Expected: success/authentication/protocol results escape with the flag set.

- [ ] **Step 3: Implement one outer normalizer**

Move the current body into a private result-producing function whose `finally`
retains all cleanup. The public method invokes the result-selection seam and
then returns `TransportFailure` whenever its caller flag is set, without
clearing the flag.

- [ ] **Step 4: Run focused Probe GREEN**

Run the Step 2 command. Expected: all Probe tests pass.

- [ ] **Step 5: Commit**

```bash
git add \
  debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorProbe.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorProbeTest.kt
git commit -m "fix: normalize interrupted Probe results"
```

### Task 3: Prove real Held generic-I/O classification

**Files:**
- Modify: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/HeldDovecotOperatorImapSession.kt`
- Modify: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotHeldOperatorImapDeadlineTest.kt`

- [ ] **Step 1: Replace self-fulfilling tests and verify RED**

For seed, usability, and post-close, make the worker throw an actual
`IOException`/`SocketException` before the outer path reaches an injected
classification barrier. At the barrier, interrupt the caller and release it
uninterruptibly. Assert redacted interruption and a preserved flag; post-close
must not return normally. Assert the barrier sees the identical injected
failure and runs exactly once.

Add a throwing-barrier regression that asserts message/credential wiping,
transport cleanup, and zero final accounting.

Run:

```bash
cd debug-dashboard
./kotlin test --include-module dashboard-server \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotHeldOperatorImapDeadlineTest
```

Expected: the actual generic failure is classified before the caller flag is
set.

- [ ] **Step 2: Implement cleanup-before-classification**

Inject and retain one Held classification seam. Abandon and perform bounded
cleanup before invoking it, record cleanup interruption, then classify the
actual failure and the post-seam caller flag. Preserve existing redaction and
post-close rejection behavior. Capture the post-close write failure as an
outcome and classify it once outside the surrounding catch so a redacted
interruption cannot re-enter the seam.

- [ ] **Step 3: Add the registered-open triple-block characterization**

Use a factory that registers the transport and then blocks. Block transport
abort and close independently. Assert bounded caller return, one abandoned
reservation with three actors, full-cap rejection, message/credential wiping,
and zero accounting after releasing all three barriers.

This closes a missing integration-proof case rather than a known production
defect. Run it immediately and expect GREEN on the existing coordinator; if it
fails, stop and investigate before changing production behavior.

- [ ] **Step 4: Run focused Held GREEN**

Run the Step 1 command plus:

```bash
./kotlin test --include-module dashboard-server \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotHeldOperatorImapSessionTest
```

- [ ] **Step 5: Commit**

```bash
git add \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/HeldDovecotOperatorImapSession.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotHeldOperatorImapDeadlineTest.kt
git commit -m "fix: classify Held failures after cleanup"
```

### Task 4: Make HTTP cleanup unconditional

**Files:**
- Modify: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotBoundedHttpProofClient.kt`
- Modify: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotOAuthProofValidatorTest.kt`

- [ ] **Step 1: Add a throwing-hook RED regression**

Cause a caller-side status parse failure after request writes. Make
`beforeFailureClassification` throw a unique failure. Assert the desired
socket closure, worker/actor exit, zero reservation accounting, copied-request
wiping, and later capacity recovery. The current ordering must fail those
assertions deterministically.

Run:

```bash
cd debug-dashboard
./kotlin test --include-module dashboard-server \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotOAuthProofValidatorTest
```

- [ ] **Step 2: Reorder cleanup and classification**

Unconditionally abandon and perform bounded cleanup while recording
interruption, then invoke the hook. If it returns, classify both the recorded
state and current caller flag. Keep `finally` wiping request/response ownership
and closing the deadline even when the hook throws.

- [ ] **Step 3: Run focused HTTP GREEN**

Run the Step 1 command. Expected: the throwing-hook regression and existing
SocketException-plus-interrupt test pass with zero final accounting.

- [ ] **Step 4: Commit**

```bash
git add \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotBoundedHttpProofClient.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotOAuthProofValidatorTest.kt
git commit -m "fix: clean HTTP operations before classification"
```

### Task 5: Repeat the reported order and validate proportionally

**Files:**
- Modify: `docs/superpowers/specs/2026-07-30-task6-bounded-operation-workers-design.md`
- Modify: `docs/debug-dashboard/gates/0c-dovecot.md`

- [ ] **Step 1: Repeat the exact 71-order command**

From `debug-dashboard`, run the following at least three consecutive times:

```bash
./kotlin test --include-module dashboard-server \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotBoundedOperationWorkersTest \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotHeldOperatorImapDeadlineTest \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotHeldOperatorImapSessionTest \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotOAuthProofValidatorTest \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotIsolationMailboxContractTest
```

Record every discovered/passed count; the count will increase with new tests.

- [ ] **Step 2: Run focused and reciprocal selections**

Run coordinator, Probe, Held, and HTTP together, then the exact 13-class
reciprocal selection from the prior Task 6 plan. Record actual counts.

- [ ] **Step 3: Run proportional broad verification**

Repeat the quoted non-live Dovecot scan and 13 static selectors, then the wider
non-live dashboard-server scan and the same 13 selectors. Exclude every
`*LiveTest`, the mixed Docker-backed config class, and the production browser
gate exactly as before.

- [ ] **Step 4: Run helper and build checks**

```bash
python3 -B -W error -m unittest \
  debug-dashboard/dashboard-server/testResources/dovecot-gate0c/test_network_isolation_check.py
cd debug-dashboard
./kotlin build --module dashboard-server
```

- [ ] **Step 5: Document exact linearization and evidence**

Update the original worker design and gate evidence with the post-CAS deadline
linearization, worker interrupt ownership, real Held classification barrier,
HTTP cleanup ordering, actual test counts, and pending live status.

- [ ] **Step 6: Obtain independent review**

Ask one reviewer to attack coordinator state transitions, exact deadline
linearization, cleanup ownership, and secret/result disposal. Ask a second
reviewer to assess whether every new test deterministically reaches the
intended boundary rather than creating the result it claims to prove. Resolve
all Important findings and rerun affected commands.

- [ ] **Step 7: Execute repository self-review and commit evidence**

Run `.ai/self-review.md`, `git diff --check`, and verify a clean final
worktree. Do not run Docker, live tests/services, or Stalwart operations.

```bash
git add \
  docs/superpowers/specs/2026-07-30-task6-bounded-operation-workers-design.md \
  docs/debug-dashboard/gates/0c-dovecot.md
git commit -m "docs: close Task 6 final review evidence"
```
