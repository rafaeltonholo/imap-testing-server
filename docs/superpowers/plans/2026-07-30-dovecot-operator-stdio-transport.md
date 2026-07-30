# Dovecot Operator Docker-Exec/Stdio Transport Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:subagent-driven-development` to implement this plan task-by-task.
> Use `superpowers:test-driven-development` for every behavior change,
> `superpowers:systematic-debugging` for every unexpected failure, and
> `superpowers:verification-before-completion` before reporting a task complete.
> Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the invalid host-published Dovecot operator ingress with one
fixed, TLS-verifying `docker compose exec -T`/stdio transport, prove bounded
process ownership and cleanup, and restore Gate 0C Task 6 isolation without
touching any Stalwart service.

**Architecture:** The operator binds IMAPS only to `127.0.0.1` in its own
container, has no published port, and is the sole member of an internal bridge.
The Kotlin/JVM dashboard starts a fixed, non-shell Docker CLI child whose
container-side OpenSSL process turns stdin/stdout into the existing IMAP
transport. The bounded-operation coordinator owns every finite or opening child;
held sessions reserve a drainable application lease before allocation. The
isolated lifecycle proves exact argv/environment, TLS identity, topology,
process inventory, saturation, and zero-orphan cleanup.

**Tech Stack:** Kotlin Toolchain KMP/JVM, Kotlin/JVM `ProcessBuilder`, existing
bounded-operation coordinator and IMAP protocol, Docker Compose, pinned Dovecot
2.4.1/OpenSSL 3.0.17, POSIX shell lifecycle, Python standard-library isolation
helper.

**Authoritative design:**
`docs/superpowers/specs/2026-07-30-dovecot-operator-stdio-transport-design.md`.
When this plan and an older Gate 0C instruction disagree about operator
ingress, the authoritative design wins. All ordinary Dovecot, Postfix, OAuth,
and Stalwart paths stay unchanged.

**Execution prerequisite:** The user confirmed the reviewed amendment by
directing implementation to continue on 2026-07-30. Its status is
`Confirmed; detailed contract reviewed; implementation planned`; implementation
must not begin if that status is reverted to pending.

---

## Guardrails for every task

- Work only in the `feature/debug-dashboard` worktree.
- Use `./kotlin`; never introduce Gradle, React, TypeScript, or Node.
- Do not run ad hoc `docker compose up/down/restart/stop/rm` commands.
- Do not select, inspect, start, stop, recreate, or test Stalwart.
- The only live Docker acceptance command in this plan is
  `debug-dashboard/dashboard-server/testResources/dovecot-gate0c/run-task5-proof.sh`.
- Keep port `2993` only as a forbidden-host-port negative assertion. It is
  never a readiness, authentication, or positive operator endpoint.
- No request value may influence Docker binary, socket, project, files,
  service, profile, executable, host, port, or OpenSSL flags.
- No credential may enter argv, environment, stderr, exception text, retained
  diagnostics, or process inventory.
- Run `.ai/self-review.md` after each material implementation batch and before
  each final response.

## Task 1: Build and prove the trusted launch profile

**Files:**

- Create:
  `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorProcessTransport.kt`
- Create:
  `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorRuntime.kt`
- Create:
  `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorProcessTransportTest.kt`
- Modify:
  `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/gate/dovecot/DovecotTask5ProofProfile.kt`
- Modify:
  `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotLiveTestEnvironmentTest.kt`
- Create:
  `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorRuntimeTest.kt`

- [ ] Add failing launch-profile tests that the Docker CLI is canonical,
  absolute, executable, and selected only at trusted construction time.

- [ ] Add failing launch-profile tests that repository root and ordered Compose
  files are canonical absolute, regular, non-symlink paths below the trusted
  root.

- [ ] Add failing launch-profile tests for strict project-name validation, the
  exact local Unix Docker socket, and exact `dovecot-operator` service/profile.
  The proof project must be exactly `mail-sandbox-task5-proof`.

- [ ] Add failing proof-profile tests that request-derived overrides are
  rejected and `operatorImapsPort` is replaced by exact negative-only
  `forbiddenOperatorHostPort=2993`.

- [ ] Define the exact production construction contract in
  `DovecotOperatorRuntime.production()`:

  - resolve the repository only through
    `DovecotOperatorPaths.production().repositoryRoot`;
  - select Docker once at runtime construction, never inside `open()`;
  - if startup-only `MAIL_SANDBOX_DOCKER_CLI` is present, require an absolute
    executable regular file and canonicalize it with `toRealPath()`; otherwise
    examine only the fixed ordered candidates `/usr/local/bin/docker`,
    `/opt/homebrew/bin/docker`, and `/usr/bin/docker`, select the first
    executable, and canonicalize it;
  - use only `<repository-root>/docker-compose.yml`;
  - derive the explicit Compose project once from the already canonical
    repository-root filename, require exact regex
    `[a-z0-9][a-z0-9_-]*`, and then always pass that unchanged value with
    `--project-name`;
  - fix Docker host to `unix:///var/run/docker.sock`;
  - construct `JvmDockerExecDovecotOperatorTransportFactory(profile)` and inject
    it into `DovecotOperatorProbe`.

  The probe constructor must no longer create or default a transport factory.
  There is not yet a Dovecot HTTP route, so do not initialize an unused process
  runtime from `Application.kt`; the provider API composition task must call
  this single production boundary when it wires the route.

- [ ] Add failing runtime-selection tests for the explicit startup override,
  each fixed Docker candidate, no candidate, and canonicalization.

- [ ] Add failing runtime-construction tests for invalid root/project, the
  single base Compose file, fixed socket, explicit probe injection, and
  proof/production separation.

- [ ] Add exact-list tests for the host argv:

```text
<absolute docker> compose
--project-directory <absolute repository root>
-f <absolute compose file> ...
--project-name <fixed project>
--profile dovecot-operator
exec -T --index 1 dovecot-operator
/usr/bin/openssl s_client
-quiet -no_ign_eof -nocommands -4
-min_protocol TLSv1.2 -max_protocol TLSv1.3
-verify_return_error -verify_hostname localhost
-no-CApath -no-CAstore
-CAfile /etc/dovecot/ssl/tls.crt
-connect 127.0.0.1:31993
-servername localhost
```

  Assert there is no shell token, interpolation, account/address/password,
  arbitrary flag, implicit project selection, or operator host port.

- [ ] Add failing environment tests. Given a hostile inherited map, remove all
  case-sensitive `COMPOSE_*`, `DOCKER_*`, and `DOVECOT_*` entries and set only:

```text
COMPOSE_DISABLE_ENV_FILE=1
DOCKER_HOST=unix:///var/run/docker.sock
```

  Preserve unrelated safe process environment only if it is required to run
  the already absolute Docker binary. Assert `ProcessBuilder` uses the
  canonical repository root and `Redirect.DISCARD` for stderr.

- [ ] Run the focused test and preserve the RED failure:

```bash
cd debug-dashboard
./kotlin test --include-module dashboard-server \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotOperatorProcessTransportTest \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotOperatorRuntimeTest \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotLiveTestEnvironmentTest
```

- [ ] Implement the smallest launch-profile/argv/environment builder that makes
  the tests pass. Keep process creation behind a narrow injectable
  `DovecotOperatorProcessStarter` seam; production must delegate to
  `ProcessBuilder(List<String>)`, never to a command string.

- [ ] Re-run the focused tests, `git diff --check`, and the repository
  self-review checklist.

- [ ] Commit:

```bash
git add \
  debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorProcessTransport.kt \
  debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorRuntime.kt \
  debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/gate/dovecot/DovecotTask5ProofProfile.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorProcessTransportTest.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorRuntimeTest.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotLiveTestEnvironmentTest.kt
git commit -m "test: define fixed Dovecot operator process launch"
```

## Task 2: Implement bounded process transport and finite-probe ownership

**Files:**

- Modify:
  `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorProcessTransport.kt`
- Modify:
  `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorProbe.kt`
- Modify:
  `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/gate/dovecot/DovecotBoundedOperationWorkers.kt`
- Modify:
  `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorProcessTransportTest.kt`
- Modify:
  `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorProbeTest.kt`
- Modify:
  `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotBoundedOperationWorkersTest.kt`

- [ ] Add fake-process tests for stable guarded stream mapping, exact `start()`
  call count, immediate `registerAllocated`, redacted start failure, and
  registration-failure cleanup/reap. Prove that raw process streams never
  escape and that guarded read, bulk write, and flush delegate normally. Run
  only `DovecotOperatorProcessTransportTest` and preserve RED.

- [ ] Implement process start/wrap/register and the bounded pre-registration
  failure cleanup. Re-run that class and require the new cases GREEN.

- [ ] Add graceful natural-close and registration-cleanup tests: an idle,
  synchronously successful stdin close happens first, stdout stays open during
  the at-most-500-ms wait, stdout then closes, exit zero succeeds only for
  normal close, and nonzero normal exit fails. If stdin close is deferred,
  in-progress, or failed, skip that 500-ms EOF wait and enter the bounded
  destroy/force path. Run the class and preserve RED.

- [ ] Implement only the natural-close branch and re-run those cases GREEN.

- [ ] Add termination tests: normal close and registration cleanup close stdout
  before `destroy()` and its 250-ms wait. An abort winner instead completes a
  pre-stream process handshake outside the lifecycle lock: call `destroy()`,
  wait at most 250 ms, force once if still alive, and make one final reap
  attempt of at most 250 ms. Store that result and acknowledge the completed
  handshake before terminal outcome caching. If the child was reaped, the
  lifecycle path then closes both streams without a 500-ms natural-exit wait or
  any repeated destroy/force/wait work. If it was not reaped, clear both stream
  references and cache `reaped=false`, `naturalExit=false`,
  `terminationRequired=true`, `streamsClosed=false`, and `exitCode=null`
  without attempting either potentially contended close. Successful
  termination still requires both stream closes and a reaped child; abort and
  registration cleanup may accept a nonzero exit. Preserve RED.

- [ ] Implement the bounded destroy/force/reap branch and re-run those cases
  GREEN.

- [ ] Add state tests for concurrent idempotent close/abort, a protocol writer
  already admitted to raw stdin, close-first natural-zero completion waiting
  for an in-flight abort handshake acknowledgement, a racing abort making a
  normal outcome termination-required, cached registration-cleanup failure,
  and permanent non-reusability after any failed close. Cover both asynchronous
  `destroy()` return and `destroy()` throwing `Error`: the abort winner must
  complete its force/final-reap handshake while the admitted writer remains
  blocked, and raw stdin close must be deferred until that writer exits. Also
  gate an unreaped final wait: both callers must return fixed failures, cache
  the unreaped outcome, clear both stream references, and make zero new
  stream-close requests before the writer is released. Repeated callers must
  not rerun stream or process lifecycle work. Preserve RED.

- [ ] Implement the synchronized idempotent terminal outcome plus the one-shot
  abort signal monitor. Hold that monitor through the winning bounded
  destroy/wait/force/final-reap handshake, store its reaped result, acknowledge
  before release, release it before entering the lifecycle lock, and use the
  stored result for lifecycle destroy selection and terminal signal
  completion. A stored `false` result must take the fail-bounded path described
  above; otherwise clear each terminal stream reference after its sole close
  attempt. Re-run those cases GREEN.

- [ ] Add one shared stream-admission gate and stable guarded stdin/stdout
  wrappers. Seal both directions atomically at close, abort, and registration
  cleanup entry. Admit read/write/flush under the gate, count the raw call,
  release the gate before raw I/O, and let the last admitted call own one
  deferred best-effort raw close outside every gate/signal lock. A lifecycle
  close request succeeds at its terminal snapshot only when raw close completed
  synchronously and successfully; deferred, in-progress, and failed close
  states remain terminal failure even if raw close later succeeds. Do not add a
  drain wait, thread, executor, or worker.

- [ ] Make each lifecycle stream close a two-phase authorization. While already
  holding the lifecycle lock, acquire the abort-signal monitor and then the
  stream gate (`lifecycle → signal → gate`). Under those locks, either observe
  an acknowledged `reaped=false` abort and refuse the request, or atomically
  reserve the direction and return a one-shot `PreparedClose`. Release signal
  and gate before completing that prepared close; raw stream close must never
  run under either lock. Immediately before each authorization, invoke the
  factory-injected internal
  `beforeLifecycleCloseAuthorization(direction)` checkpoint outside signal and
  gate. Its production default is a no-op; it exists only for deterministic
  latch-driven unit schedules and adds no wait, actor, or runtime behavior.

- [ ] Add deterministic regressions for an unreaped abort acknowledged
  (a) after the old precheck but before stdin authorization, (b) during the
  500-ms natural wait but before stdout authorization with a read already
  admitted, and (c) while an already claimed raw stdout close is blocked before
  terminal caching. The first two must make no new direction-close request;
  the third may complete its already claimed close. In every case cache exactly
  `reaped=false`, `naturalExit=false`, `terminationRequired=true`,
  `streamsClosed=false`, and `exitCode=null`. A stored false result observed at
  either authorization, the post-stdin pre-wait check, process selection, or
  final signal-completion snapshot overrides every generic or natural result.
  Repeated close/abort calls perform no additional stream or process work.

- [ ] Keep public wrapper `close()` separate from the lifecycle-authorized
  close request. After the shared gate is sealed, a stale wrapper close returns
  a fixed redacted `IOException` and cannot request raw close. Before sealing,
  public close may return only after synchronous success; deferred,
  in-progress, or failed close returns a fixed redacted `IOException`.

- [ ] Add tests for caller-interrupt preservation, stale wrapper rejection,
  exactly-once deferred close, no new worker/thread, failed stream-close
  acceptance, discarded stderr, and fixed/redacted `toString()` and
  exceptions. Preserve RED.

- [ ] Document the exact boundedness claim: process waits total at most one
  second on the idle normal path and at most 500 ms in the abort handshake, but
  an idle raw JDK process-stream `close()` has no enforceable wall-clock bound.
  Do not claim otherwise without adding a separate actor, which this transport
  intentionally prohibits.

- [ ] Implement interrupt/redaction details and re-run
  `DovecotOperatorProcessTransportTest` GREEN.

- [ ] Add failing coordinator tests for a finite-success completion transition:
  a closed/reaped finite operation stops its I/O actor and releases capacity
  without becoming a held handoff; an interrupted/expired final clock sample
  cannot publish success or strand cleanup ownership.

- [ ] Implement `completeFinite()` (or the equivalently named explicit
  transition) in `DovecotBoundedOperationWorkers`. Keep `commitHandoff()` only
  for a genuinely live held session; run
  `DovecotBoundedOperationWorkersTest` GREEN.

- [ ] Add probe tests proving success, authentication failure, authorization
  failure, and protocol failure do not become visible before synchronous
  close/reap. Preserve RED.

- [ ] Add probe tests for close failure, timeout, interruption, and
  callback-registration failure; each must return `TransportFailure` and retain
  cleanup ownership. Preserve RED.

  The required shape is:

```kotlin
val protocolResult =
    operation.execute {
        // greeting/authentication/probe exchange
    }
val closeFailure =
    runCatching {
        operation.execute { opened.close() }
    }.exceptionOrNull()
return closeFailure?.let { TransportFailure } ?: protocolResult
```

  Adapt to the existing typed/result helpers; do not literally duplicate
  protocol code. Early authentication/protocol returns must still pass through
  this close gate.

- [ ] Refactor the probe to keep classifications provisional, close/reap
  through the same operation, complete finite ownership, and only then return.
  Remove `JvmJsseDovecotOperatorTransportFactory` and the probe's implicit
  default; production uses `DovecotOperatorRuntime.production()` and
  proof/live callers inject the proof factory.

- [ ] Run the complete focused set GREEN:

```bash
cd debug-dashboard
./kotlin test --include-module dashboard-server \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotOperatorProcessTransportTest \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotOperatorProbeTest \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotBoundedOperationWorkersTest
```

- [ ] Ensure the probe's final `abandon()` remains only exceptional/best-effort
  cleanup. A non-transport typed result must have already completed normal
  close/reap within the five-second operation deadline.

- [ ] Re-run the focused tests, `git diff --check`, and self-review.

- [ ] Commit:

```bash
git add \
  debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorProcessTransport.kt \
  debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorProbe.kt \
  debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/gate/dovecot/DovecotBoundedOperationWorkers.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorProcessTransportTest.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorProbeTest.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotBoundedOperationWorkersTest.kt
git commit -m "feat: use bounded stdio transport for Dovecot operator"
```

## Task 3: Reserve a drainable lease before every held process allocation

**Files:**

- Modify:
  `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorApplicationLeaseRegistry.kt`
- Modify:
  `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/HeldDovecotOperatorImapSession.kt`
- Modify:
  `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorApplicationLeaseRegistryTest.kt`
- Modify:
  `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotHeldOperatorImapSessionTest.kt`
- Modify:
  `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotHeldOperatorImapDeadlineTest.kt`
- Modify:
  `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorRotationLiveTest.kt`
- Modify:
  `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotTask6MailboxProof.kt`
- Modify:
  `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorCredentialStoreTest.kt`
- Modify:
  `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotOAuthProofValidatorTest.kt`

- [ ] Add registry tests that `reserveOpening` consumes an application or
  verification slot before `Process.start()`, carries the opening operation's
  fixed cancellation callback, and releases idempotently. Preserve RED.

- [ ] Implement the visible opening-reservation state and exact 15+1 accounting;
  re-run `DovecotOperatorApplicationLeaseRegistryTest` GREEN.

- [ ] Add tests that `blockAndDrain()` sees/cancels an unbound reservation
  outside the registry lock, and that bind installs exactly one session-close
  callback. Preserve RED.

- [ ] Implement drainable reservation and atomic bind transitions; re-run the
  registry class GREEN.

- [ ] Add the pre-start drain race with latches. Require no process allocation,
  no returned session, bounded release, and zero residual leases; preserve RED.

- [ ] Add the post-allocation/pre-bind drain race. Require synchronous
  close/reap, no returned session, bounded release, and zero residual leases;
  preserve RED.

- [ ] Add the bound/pre-handoff drain race. Require synchronous close/reap,
  failed handoff, no returned session, and zero residual leases; preserve RED.

- [ ] Add one linear-order test for acquire operation → reserve lease → recheck
  → start/register → construct → recheck/bind → recheck/commit → return.
  Preserve RED.

- [ ] Implement the three checkpoint rechecks and failure cleanup in
  `openAndSeedLeased`; run the held-session, deadline, and registry race cases
  GREEN.

- [ ] Add the saturation regression: 15 application reservations plus one
  verification reservation cause exactly 16 process starts; the seventeenth
  attempt starts no process; drain returns both counts to zero. Preserve RED.

- [ ] Implement the final capacity/start ordering and re-run saturation GREEN.

- [ ] Run the complete focused set GREEN:

```bash
cd debug-dashboard
./kotlin test --include-module dashboard-server \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotOperatorApplicationLeaseRegistryTest \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotHeldOperatorImapSessionTest \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotHeldOperatorImapDeadlineTest \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotOperatorCredentialStoreTest \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotOAuthProofValidatorTest
```

- [ ] Audit the resulting `openAndSeedLeased` path against this required order:

  1. acquire the bounded operation;
  2. reserve the correct registry slot;
  3. recheck before process start;
  4. start/register transport and construct the held session;
  5. recheck and bind the session close callback;
  6. recheck, commit handoff, and only then return session plus lease.

  On every exception or rejected checkpoint it must synchronously abort/close/reap,
  abandon/await the bounded operation, and release the reservation. Never let a
  live process escape without a registry entry. The prewritten linear-order
  test must remain GREEN.

- [ ] Migrate every live held-process caller:
  `DovecotOperatorRotationLiveTest` and `DovecotTask6MailboxProof`. Keep the
  unleased helper only for deterministic fake-transport unit tests and make its
  restricted scope/name obvious. Update the held-session fixture in
  `DovecotOAuthProofValidatorTest` so it cannot teach or exercise the old
  live-unleased ordering.

- [ ] Re-run focused tests, `git diff --check`, and self-review.

- [ ] Commit:

```bash
git add \
  debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorApplicationLeaseRegistry.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/HeldDovecotOperatorImapSession.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorApplicationLeaseRegistryTest.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotHeldOperatorImapSessionTest.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotHeldOperatorImapDeadlineTest.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorRotationLiveTest.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotTask6MailboxProof.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorCredentialStoreTest.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotOAuthProofValidatorTest.kt
git commit -m "feat: lease Dovecot operator processes before allocation"
```

## Task 4: Remove operator TCP ingress and harden its listener/health contract

**Files:**

- Modify: `docker-compose.yml`
- Modify: `config/operator/dovecot.conf`
- Modify:
  `debug-dashboard/dashboard-server/testResources/dovecot-gate0c/compose.task5-proof.yml`
- Modify:
  `debug-dashboard/dashboard-server/testResources/dovecot-gate0c/run-task5-proof.sh`
- Modify: `scripts/setup.py`
- Modify:
  `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorConfigTest.kt`
- Modify:
  `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotTask5ProofLifecycleTest.kt`
- Modify:
  `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotBaselineConfigAuditTest.kt`
- Modify: `.ai/skills/docker-compose/references/service-map.md`

- [ ] Add static tests for no base/proof operator publication,
  `operator-ingress.internal=true`, sole operator membership, exact
  `127.0.0.1:31993` listener, and unchanged ordinary service ports/networks.

- [ ] Add mutation tests for base and proof models rejecting `expose`,
  `network_mode: host`, any extra operator network, and any second
  `operator-ingress` member.

- [ ] Add source/lifecycle tests that `2993` is negative-only, both production
  and proof certificates use `CN=localhost` plus exact
  `subjectAltName=DNS:localhost`, and proof hostname verification occurs before
  any service start.

- [ ] Add exact healthcheck tests for one listener:

  - inspect both `/proc/net/tcp` and `/proc/net/tcp6`;
  - count every state `0A` entry whose local port is hex `7CF9`;
  - require count exactly one;
  - require that sole entry is exact IPv4 loopback
    `0100007F:7CF9`;
  - reject wildcard, IPv6, duplicate, absent, or malformed entries;
  - retain all existing `auth` and `imap-login` service-state checks.

- [ ] Run and preserve the non-live RED result:

```bash
cd debug-dashboard
./kotlin test --include-module dashboard-server \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotOperatorConfigTest \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotBaselineConfigAuditTest \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotTask5ProofLifecycleTest
```

- [ ] Implement the Compose/config/certificate changes. Prefer an explicit
  proof `ports: !override []` so a future base publication cannot leak through
  the proof model. Do not start Compose.

- [ ] Update the service map from “target pending implementation” to the actual
  no-publication/internal/control-plane topology, but only after the model
  matches.

- [ ] Run:

```bash
COMPOSE_DISABLE_ENV_FILE=1 docker compose \
  --profile dovecot-operator config --quiet
COMPOSE_DISABLE_ENV_FILE=1 docker compose \
  -f docker-compose.yml \
  -f debug-dashboard/dashboard-server/testResources/dovecot-gate0c/compose.task5-proof.yml \
  --project-name mail-sandbox-task5-proof \
  --profile dovecot-operator config --quiet
cd debug-dashboard
./kotlin test --include-module dashboard-server \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotOperatorConfigTest \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotBaselineConfigAuditTest \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotTask5ProofLifecycleTest
```

  These `config` commands are model validation only. They must not select or
  mutate Stalwart.

- [ ] Run `git diff --check` and self-review, then commit:

```bash
git add \
  docker-compose.yml \
  config/operator/dovecot.conf \
  debug-dashboard/dashboard-server/testResources/dovecot-gate0c/compose.task5-proof.yml \
  debug-dashboard/dashboard-server/testResources/dovecot-gate0c/run-task5-proof.sh \
  scripts/setup.py \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorConfigTest.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotTask5ProofLifecycleTest.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotBaselineConfigAuditTest.kt \
  .ai/skills/docker-compose/references/service-map.md
git commit -m "fix: remove Dovecot operator host ingress"
```

## Task 5: Migrate readiness and raw operator checks to one bounded exchange

**Files:**

- Create:
  `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorBoundedExchange.kt`
- Create:
  `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorBoundedExchangeTest.kt`
- Modify:
  `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotLiveTestEnvironment.kt`
- Modify:
  `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotLiveTestEnvironmentTest.kt`
- Modify:
  `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorStartupLiveTest.kt`
- Modify:
  `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotIsolationProtocolProof.kt`
- Modify:
  `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotIsolationLiveTest.kt`
- Modify:
  `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorRotationLiveTest.kt`
- Modify:
  `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotTask6MailboxProof.kt`
- Modify:
  `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotIsolationMailboxContractTest.kt`

- [ ] Add failing bounded-exchange tests for greeting readiness and capability
  exchange with fixed deadlines, coordinator-bounded I/O, and synchronous
  close/reap before result publication.

- [ ] Add failing bounded-exchange tests for bare-target LOGIN rejection, PLAIN
  authzid/master-form rejection, and combined master-target authentication.
  Require buffer wiping, redacted failures, and no raw process-stream read
  outside an operation worker.

- [ ] Change only `DovecotLiveTestEnvironmentTest` expectations from
  `OPERATOR_IMAPS`/host-port readiness to `OPERATOR_EXEC`/bounded-exchange
  readiness and from `operatorImapsPort` to
  `forbiddenOperatorHostPort`. Preserve RED.

- [ ] Change only startup/isolation/mailbox contract tests to require that
  ordinary IMAPS/POP3, SMTP, and OAuth retain their host sockets while every
  operator helper receives a launch profile/factory and bounded exchange,
  never a positive operator port. Preserve RED.

- [ ] Update `DovecotIsolationMailboxContractTest` for the port-free
  inactive-master/mailbox expected signatures. Assert exact login/credential
  pairing and synchronous cleanup. This is a test-only RED change.

- [ ] Run the focused set and preserve RED:

```bash
cd debug-dashboard
./kotlin test --include-module dashboard-server \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotOperatorBoundedExchangeTest \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotLiveTestEnvironmentTest \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotIsolationMailboxContractTest \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotOperatorProbeTest \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotHeldOperatorImapSessionTest
```

- [ ] Implement `DovecotOperatorBoundedExchange` greeting, LOGIN, PLAIN,
  combined-master-target, and capability operations over the existing
  coordinator. Re-run its dedicated test class GREEN.

- [ ] Implement `OPERATOR_EXEC` readiness and the
  `forbiddenOperatorHostPort` rename in the live environment. Re-run
  `DovecotLiveTestEnvironmentTest` GREEN.

- [ ] Migrate startup, isolation, mailbox, and rotation helpers to the bounded
  exchange. Split/rename the ordinary raw JSSE helper so it cannot accept an
  operator target. Re-run the isolation/mailbox/probe/held test subset GREEN.

- [ ] Remove all remaining references to the old operator socket path and
  inspect every search hit:

```bash
rg -n \
  'JvmJsseDovecotOperatorTransportFactory|OPERATOR_IMAPS|operatorImapsPort|rawImapLogin' \
  debug-dashboard/dashboard-server
```

  Expected: no old factory/enum/property; any remaining raw-login helper is
  explicitly ordinary-Dovecot-only.

- [ ] Re-run the full focused command above and require GREEN.

- [ ] Run `git diff --check` and self-review, then commit:

```bash
git add \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorBoundedExchange.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorBoundedExchangeTest.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotLiveTestEnvironment.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotLiveTestEnvironmentTest.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorStartupLiveTest.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotIsolationProtocolProof.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotIsolationLiveTest.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorRotationLiveTest.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotTask6MailboxProof.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotIsolationMailboxContractTest.kt
git commit -m "test: route Dovecot operator proofs through stdio"
```

## Task 6: Prove exact topology and child-process inventory

**Files:**

- Modify:
  `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotTask6TopologyProof.kt`
- Modify:
  `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotTask6TopologyProofTest.kt`
- Create:
  `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotTask6OperatorProcessInventory.kt`
- Create:
  `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotTask6OperatorProcessInventoryTest.kt`
- Create:
  `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorExecTransportLiveTest.kt`
- Modify:
  `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotTask6ProcessProof.kt`
- Modify:
  `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotTask6ProcessProofTest.kt`
- Modify:
  `debug-dashboard/dashboard-server/testResources/dovecot-gate0c/network-isolation-check.py`
- Modify:
  `debug-dashboard/dashboard-server/testResources/dovecot-gate0c/test_network_isolation_check.py`

- [ ] Change topology tests from exact `31993 -> 2993` publication to exact
  empty operator publication and retain the bridge-IP negative probe. Preserve
  RED.

- [ ] Implement the empty-publication topology rule and re-run
  `DovecotTask6TopologyProofTest` GREEN.

- [ ] Add failing fixed-runner tests for resolving one exact
  newline-terminated 64-hex operator container ID with:

```text
<canonical-docker> compose
  --project-directory <canonical-root>
  -f <absolute-compose-file>...
  --project-name <fixed-project>
  --profile dovecot-operator
  ps --quiet dovecot-operator
```

  Require the launch profile's canonical binary/root/files/project/profile,
  sanitized environment, exit zero, empty stderr, and exactly one ID. Preserve
  RED.

- [ ] Implement the fixed Compose container resolver; reject all other command
  shapes and re-run its focused tests GREEN.

- [ ] Add failing label-inspection tests for exact argv
  `<canonical-docker> inspect --format {{json .Config.Labels}} <id>`. Require
  exact project, `service=dovecot-operator`, and `container-number=1`; malformed
  or additional identity ambiguity is redacted. Preserve RED.

- [ ] Implement label validation and re-run those tests GREEN.

- [ ] Add failing network-inspection tests. First require exact argv
  `<canonical-docker> inspect --format {{json .NetworkSettings.Networks}} <id>`,
  only `<project>_operator-ingress`, and one 64-hex `NetworkID`. Then require
  exact argv
  `<canonical-docker> network inspect --format {{json .}} <network-id>`,
  `Internal=true`, exact network name, and a `Containers` map containing only
  the validated operator ID. Preserve RED.

- [ ] Implement the fixed container/network parsers and exact internal,
  sole-member topology validation; re-run topology tests GREEN.

- [ ] Add failing inventory parser tests for exact argv
  `<canonical-docker> top <container-id> -ww -eo pid,args`, the exact
  `PID COMMAND` header, decimal PIDs, zero/one/sixteen exact OpenSSL rows, and
  exact full command equality. Preserve RED.

- [ ] Add failing parser tests for truncated, malformed, defunct,
  secret-bearing, and unexpected OpenSSL-looking rows. Every failure must be
  `INVALID_INVENTORY` without raw output. Preserve RED.

- [ ] Add failing runner tests for nonzero exit, nonempty stderr, timeout, and
  output overflow. Every failure must be redacted `INVALID_INVENTORY`.
  Preserve RED.

- [ ] Implement the exact inventory runner/parser and redacted result mapping;
  run `DovecotTask6OperatorProcessInventoryTest` and
  `DovecotTask6ProcessProofTest` GREEN.

  Every command must use the launch profile's canonical Docker path, canonical
  working directory, ordered Compose files/project/profile where applicable,
  and the same sanitized child environment as the transport. Keep the existing
  exact 10-second command timeout, 64-KiB stdout/stderr cap, 1-KiB stdin cap,
  three bounded daemon I/O workers, and two-second join/reap bound. Do not add a
  raw process reader or shell.

- [ ] Add live-proof source/fake tests for zero inventory before/after normal,
  authentication-failure, registration-failure, timeout, interruption, and
  abort cases. Preserve RED; do not run Docker.

- [ ] Implement those cases in `DovecotOperatorExecTransportLiveTest` and
  lifecycle fakes; keep them dormant unless the fixed live profile is selected.

- [ ] Add live-proof source/fake tests for one process during a held session,
  exactly 16 during 15+1 saturation, no seventeenth start, and zero after close
  and drain. Preserve RED.

- [ ] Implement the held/saturation inventory cases and re-run their non-live
  source/fake tests GREEN.

- [ ] Rename only Python test expectations to “forbidden operator host port”
  while preserving the same 21 negative paths: port `2993`, non-loopback host
  interfaces, Docker Desktop host alias, explicit host-gateway alias, and
  operator bridge IP `31993`. Run Python tests and preserve RED.

- [ ] Rename the helper constant/labels, add no positive path, and re-run the
  Python tests GREEN.

- [ ] Run the complete non-live set GREEN:

```bash
cd debug-dashboard
./kotlin test --include-module dashboard-server \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotTask6TopologyProofTest \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotTask6OperatorProcessInventoryTest \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotTask6ProcessProofTest \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotOperatorExecTransportLiveTest \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotTask5ProofLifecycleTest
cd ..
python3 -m unittest \
  debug-dashboard/dashboard-server/testResources/dovecot-gate0c/test_network_isolation_check.py
```

- [ ] Confirm the old ambient `"docker"`/`DovecotDockerRouting` proof inputs are
  gone and no container/network ID is accepted before its preceding fixed
  command and exact labels validate it.

- [ ] Run `git diff --check` and self-review, then commit:

```bash
git add \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotTask6TopologyProof.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotTask6TopologyProofTest.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotTask6OperatorProcessInventory.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotTask6OperatorProcessInventoryTest.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorExecTransportLiveTest.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotTask6ProcessProof.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotTask6ProcessProofTest.kt \
  debug-dashboard/dashboard-server/testResources/dovecot-gate0c/network-isolation-check.py \
  debug-dashboard/dashboard-server/testResources/dovecot-gate0c/test_network_isolation_check.py
git commit -m "test: prove Dovecot operator process isolation"
```

## Task 7: Integrate the checked lifecycle without broadening its authority

**Files:**

- Modify:
  `debug-dashboard/dashboard-server/testResources/dovecot-gate0c/run-task5-proof.sh`
- Modify:
  `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotTask5ProofLifecycleTest.kt`
- Modify:
  `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorStartupLiveTest.kt`
- Modify:
  `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotIsolationLiveTest.kt`
- Modify:
  `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorRotationLiveTest.kt`
- Modify:
  `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotTask6ProcessProof.kt`
- Modify:
  `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorExecTransportLiveTest.kt`

- [ ] Update lifecycle source/fake-command tests before touching Docker. Require
  the exact live order:

  1. lifecycle lock and baseline capture;
  2. fixed forbidden-port reservations;
  3. non-live Kotlin/config/Python checks;
  4. disposable `localhost` certificate creation and hostname verification;
  5. ordinary disposable Dovecot/OAuth/Postfix start;
  6. eligibility/operator credential bootstrap;
  7. isolated operator start with `--no-deps --wait`;
  8. bounded exec readiness;
  9. exact topology and zero-process baseline;
  10. startup/negative-isolation/mailbox/rotation/saturation proofs;
  11. exact zero-process final assertion;
  12. cleanup and exact baseline match.

  Any failure must still enter checked cleanup. Stalwart must remain absent from
  every selected service/profile and must never be captured as a lifecycle
  target.

  Add `DovecotOperatorExecTransportLiveTest` to the exact live-class sequence
  and update the fake Kotlin transcript so the lifecycle contract proves its
  placement rather than relying on discovery.

- [ ] Run only the lifecycle contract test and preserve RED:

```bash
cd debug-dashboard
./kotlin test --include-module dashboard-server \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotTask5ProofLifecycleTest
```

- [ ] Implement the lifecycle-script ordering, certificate verification, live
  class list, and zero-inventory checkpoints required by the new fake
  transcript. Do not run the lifecycle itself yet.

- [ ] Make every live class construct its process launch profile only from the
  validated `task5-proof` environment. Reject implicit `COMPOSE_FILE`,
  `COMPOSE_PROJECT_NAME`, Docker context/TLS routing, unexpected service index,
  or noncanonical paths before process start.

- [ ] Re-run `DovecotTask5ProofLifecycleTest` GREEN.

- [ ] Run all non-live lifecycle/config/transport tests:

```bash
cd debug-dashboard
./kotlin test --include-module dashboard-server \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotTask5ProofLifecycleTest \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotOperatorConfigTest \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotOperatorProcessTransportTest \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotOperatorApplicationLeaseRegistryTest \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotOperatorBoundedExchangeTest \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotTask6TopologyProofTest \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotTask6OperatorProcessInventoryTest \
  --include-classes mail.sandbox.dashboard.server.gate.dovecot.DovecotTask6ProcessProofTest
```

- [ ] Search for prohibited positive ingress and unsafe process APIs:

```bash
rg -n \
  '127\.0\.0\.1:2993:31993|JvmJsseDovecotOperatorTransportFactory|OPERATOR_IMAPS|operatorImapsPort' \
  docker-compose.yml config debug-dashboard docs .ai
rg -n \
  'ProcessBuilder\([^L]|Runtime\.getRuntime\(\)\.exec|/bin/(sh|bash|zsh)|waitFor\(\)' \
  debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/gate/dovecot \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot
```

  Review every hit. Expected first search: only historical text explicitly
  labeled superseded and forbidden-port negative checks. Expected second
  search: no shell launcher/unbounded wait in the new transport.

- [ ] Build the JVM server with Kotlin Toolchain:

```bash
cd debug-dashboard
./kotlin build --module dashboard-server
```

- [ ] Run `git diff --check`, execute `.ai/self-review.md`, and dispatch a
  spec-compliance reviewer followed by a code-quality reviewer. Fix findings
  with RED→GREEN tests and repeat review until READY.

- [ ] Commit:

```bash
git add \
  debug-dashboard/dashboard-server/testResources/dovecot-gate0c/run-task5-proof.sh \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotTask5ProofLifecycleTest.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorStartupLiveTest.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotIsolationLiveTest.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorRotationLiveTest.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotTask6ProcessProof.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorExecTransportLiveTest.kt
git commit -m "test: integrate isolated Dovecot stdio lifecycle"
```

## Task 8: Run the one isolated live proof and record evidence

**Files:**

- Modify: `docs/debug-dashboard/gates/0c-dovecot.md`
- Modify:
  `docs/superpowers/specs/2026-07-23-debug-dashboard-design.md`
- Modify:
  `docs/superpowers/specs/2026-07-30-dovecot-operator-stdio-transport-design.md`
- Modify: `docs/superpowers/plans/2026-07-23-debug-dashboard-gate-0c-dovecot.md`
- Modify: `docs/superpowers/plans/2026-07-23-debug-dashboard-implementation.md`

- [ ] Before the live command, record read-only baseline evidence required by
  the checked lifecycle and verify no unrelated worktree changes. Do not
  manually stop/restart/recreate any service.

- [ ] Run the sole live command:

```bash
debug-dashboard/dashboard-server/testResources/dovecot-gate0c/run-task5-proof.sh
```

  Expected:

  - static/config/preflight pass;
  - operator is reachable only through the fixed exec/stdio transport;
  - TLS chain and `localhost` identity verify;
  - ordinary-container, Docker host aliases, host interfaces, host port `2993`,
    and operator bridge-IP ingress are rejected;
  - requested Task 6 mailbox/auth/rotation operations pass;
  - exact process inventory is zero before/after finite cases, exact during held
    and saturation cases, and zero after cleanup;
  - proof containers/volumes/runtime secrets are removed;
  - final captured baseline matches exactly;
  - Stalwart was never selected or mutated.

- [ ] If the lifecycle fails, keep the gate red. Preserve its bounded diagnostic
  output, confirm checked cleanup/baseline match, use
  `superpowers:systematic-debugging`, add a deterministic regression test, and
  rerun from Task 7. Never reinterpret or suppress an isolation failure.

- [ ] On success, update evidence with the exact command, counts, decisive
  assertions, cleanup result, and commit hash. Change the stdio design status
  to confirmed/implemented and remove “target pending implementation” wording.
  Do not claim all of Gate 0C or the dashboard is usable unless its remaining
  tasks separately pass.

- [ ] Run final non-live verification:

```bash
cd debug-dashboard
./kotlin test --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.gate.dovecot.*'
./kotlin build --module dashboard-server
cd ..
python3 -m unittest \
  debug-dashboard/dashboard-server/testResources/dovecot-gate0c/test_network_isolation_check.py
git diff --check
git status --short
```

- [ ] Execute `.ai/self-review.md`, verify all implementation reviews are READY,
  and commit the evidence:

```bash
git add \
  docs/debug-dashboard/gates/0c-dovecot.md \
  docs/superpowers/specs/2026-07-23-debug-dashboard-design.md \
  docs/superpowers/specs/2026-07-30-dovecot-operator-stdio-transport-design.md \
  docs/superpowers/plans/2026-07-23-debug-dashboard-gate-0c-dovecot.md \
  docs/superpowers/plans/2026-07-23-debug-dashboard-implementation.md
git commit -m "docs: record isolated Dovecot stdio proof"
```

## Stop/go condition

This amendment is complete only when Tasks 1–8 are implemented, reviewed,
verified, committed, and the checked lifecycle reports exact cleanup/baseline
match. At that point resume Gate 0C Tasks 7–8 and the remaining provider/API/UI
plans. The overall dashboard goal remains active until every originally
requested operation passes end-to-end against both Dovecot and Stalwart.
