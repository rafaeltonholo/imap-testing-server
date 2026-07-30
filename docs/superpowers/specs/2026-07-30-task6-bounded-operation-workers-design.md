# Task 6 Bounded Operation Workers Design

## Goal

Make every Task 6 Dovecot and raw HTTP network caller return within one
absolute deadline even when the original I/O, abort, and close all block,
without allowing repeated abandoned operations to grow daemon threads without
bound. Preserve interrupt precedence, secret wiping, late transport cleanup,
and every existing Task 6 protocol invariant.

## Root causes

The production Dovecot probe and held-session helpers currently perform
post-open reads, writes, and flushes on the caller. Their deadline callbacks
only start transport abort and close. When both cancellation methods block,
nothing releases the original caller-side I/O.

The open executors cap only open calls. Abort and close use newly created,
unaccounted threads. Repeated abandoned operations can therefore grow threads
without a hard bound.

Held-session and HTTP generic failure branches prioritize a literal
`InterruptedException`, but not an `IOException` or `SocketException` raised
while the caller interrupt flag is set. Post-close validation can consequently
misclassify interruption as proof that a closed transport is unusable.

The Task 6 deadline records an absolute deadline but its watcher waits the
original duration from a later point. HTTP socket allocation also occurs
outside complete ownership cleanup.

## Worker coordinator

Add one production `DovecotBoundedOperationWorkers` coordinator with one
process-wide default capacity of four charged logical operations, shared by
the production probe, Held sessions, and raw HTTP. Tests may inject an owned
coordinator with a smaller capacity.

The absolute deadline is computed first without starting an actor. Admission
then occurs before credential access, socket allocation, or worker creation. A
full coordinator fails fast without starting an actor. Each admitted operation
owns:

- one unique daemon I/O worker with a private task queue;
- at most two identity-distinct cancellation targets, covering an allocated
  and a distinct returned transport; and
- at most one abort and one close daemon per cancellation target.

There is no reusable executor and no watcher thread. One logical operation can
therefore own at most five actors, and the global coordinator can own at most
twenty actors.

The coordinator exposes a secret-free snapshot containing active operations,
abandoned operations, active actors, and peak actors. It maintains
`activeOperations + abandonedOperations <= 4`. A timeout atomically moves one
charged reservation from active to abandoned; it never releases the
reservation. Four permanently dual-blocked operations fill the explicit cap; a
fifth operation fails before allocation or thread creation. Late completion
releases the reservation and permits a later operation.

Every operation has one synchronized cancellation ledger and actor counter.
Only its I/O worker may register cancellation targets. The structural ledger
has exactly two identity slots for the allocated and distinct returned
resource, deduplicates by identity, and rejects a third before accepting
ownership. Timeout, failure, interruption, and late completion share this one
ledger, so an identity can start only one abort/close pair. Target registration
is sealed by the I/O worker in its `finally`.
Cancellation actors are charged under the same lock before they start.
Release is linearized under that lock and is possible only when registration is
sealed and the I/O plus all charged cancellation actors have actually exited.
Successful completion, abandonment, actor-start failure, task-submission
failure, and operation initialization failure all use this one release
predicate. A future's cancelled/done state never drives accounting.

The coordinator starts the I/O worker before the operation can allocate a
resource or accept a task. If initialization or worker start fails, a
coordinator-owned exceptional transition atomically seals the empty target
ledger, marks the absent I/O actor exited, and evaluates the same release
predicate. No resource can exist on that path.

## Deadline and task ownership

All waits derive their duration from one absolute monotonic deadline; equality
is expired. The deadline object has no worker. Expiry is observed by
caller-side task waits and ordinary boundary checks, which synchronously and
idempotently mark the operation abandoned. Once the deadline is exhausted,
cancellation actors are dispatched but the caller performs no additional
cleanup wait.

Protocol parsing and credential access stay on the caller. Only potentially
blocking open, connect, read, write, and flush calls run on the operation's I/O
worker.

At most one I/O task may be outstanding. Submission transfers a worker-owned
write copy into a task state machine. Rejection, worker-start failure,
abandonment before dequeue, and execution all have exactly one winning cleanup
path, so a task that never runs is still wiped. The caller may wipe its source
immediately after timeout without the worker continuing to read it. No caller
array crosses the worker boundary.

Each read collector allocates its bounded buffer on the worker. Result
completion and caller timeout race through an atomic one-winner handoff. The
caller receives a result only if it claims completion before the absolute
deadline. The caller may only claim or decline; it never disposes a
worker-owned result. After producing a result, the I/O worker waits for that
claim/decline decision against the same absolute deadline. If declined, or if
the worker completes after timeout, the I/O worker invokes the late-result
callback exactly once before it can process another task or seal target
registration. It wipes a buffer or registers/cancels a transport on the
worker, preserving the single registration authority. This also covers
timeout before dequeue and completion immediately adjacent to the deadline.

## Cancellation and interruption

Timeout, caller interruption, or generic failure marks the operation
abandoned and starts independent abort and close actors for registered
targets. Timeout has no remaining cleanup wait. Interruption or an earlier
generic failure may wait only to the same absolute deadline and the smaller
fixed cancellation budget. Cleanup never determines caller completion.

After bounded cleanup, every Held open/seed, usability, post-close, and raw
HTTP generic failure path checks the caller interrupt flag. A literal
interruption or any other failure with the flag set becomes a new redacted
`InterruptedException`; the flag is restored before throwing. Post-close never
accepts an interrupted `IOException` as unusability evidence.

The raw HTTP client acquires coordinator capacity before socket allocation and
registers the socket before connect. Connect, request writes, response reads,
and socket cancellation use the same bounded operation. Socket ownership
includes deadline construction and every failure path.

## Held and probe integration

The production probe acquires one operation for open and its complete IMAP
exchange. Its credential remains caller-owned and is wiped before return.
Secret bytes are copied while holding the synchronized credential boundary,
then that boundary is released before a worker wait begins. Worker-owned
encoded writes are independently wiped.

Held open/seed acquires one operation. A successfully returned held session
stores the coordinator, not the completed operation. Each later usability or
post-close check acquires a fresh operation, so a poisoned operation cannot be
reused by another check.

`HeldDovecotOperatorImapSession.close()` also acquires a fresh coordinator
operation and dispatches transport close through its private I/O worker. The
API remains synchronous and retryable, but a blocked close returns at its
absolute deadline and consumes a charged abandoned reservation rather than an
unaccounted thread. A successful late close atomically publishes
`session.isClosed`. The application lease registry still owns joinable close
attempts and terminal outcome replay; routing its callback through the
coordinator does not change leader/follower or same-failure semantics. The
global cap therefore covers probe, Held open/seed, Held NOOP, Held close, Held
post-close validation, and raw HTTP.

## Focused review repairs

- Extract the durable repository trailing-growth read into a real channel
  helper whose named one-byte array is wiped in `finally`.
- Strengthen terminal runtime-close characterization so the close callback
  fails only once, is invoked exactly once, later callers receive the same
  failure object, and activation remains rejected.
- Remove the test-only HTTP body-bound helper. Inject the actual response
  buffer factory, force a failure in the real collector, and observe its
  worker-owned buffer being wiped.
- Extract one injectable disposable eligibility fixture used by both live
  suites. It marks an add attempt before mutation, rechecks membership, removes
  a landed target even when add returns status 2, and proves rejection.
- Replace source-substring matrix tests with typed injected orchestration that
  proves the inactive fixed suffix is paired with the active master
  credential.

## Verification

Every repair starts with a focused failing regression. Deterministic
dual-block tests fill a capacity-four coordinator, verify bounded caller
completion and peak actor count, assert fifth-call fail-fast behavior, release
late workers, and prove capacity recovery. Interrupt regressions set the
caller's flag and make actual I/O exit through `IOException` or
`SocketException`.

Coordinator race tests also cover target registration against release,
timeout before dequeue, worker-start failure, result handoff at the deadline,
two distinct cancellation targets reaching the twenty-actor maximum, and
late-result disposal. Integration tests exercise the same dual-block behavior
through production probe, Held open/seed, Held NOOP, Held post-close, and raw
HTTP. Held close tests additionally prove bounded direct and lease-owned close,
late state publication, retry semantics, and unchanged joinable terminal
replay at the registry boundary.

After focused green runs, rerun the reciprocal Task 6 classes, the exact
non-live Dovecot selection plus static selectors, the wider non-live
dashboard-server selection plus static selectors, the Python network helper,
and the dashboard-server build. Docker, live-service, and Stalwart operations
remain out of scope.
