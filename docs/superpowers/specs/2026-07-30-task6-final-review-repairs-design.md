# Task 6 Final Review Repairs Design

## Goal

Close the six final non-live Task 6 review findings without changing the
four-operation/twenty-actor cap, resource ownership, live orchestration, or
service configuration. Docker, live tests, live services, and Stalwart
operations remain prohibited.

## Root causes

`DovecotOperatorProbe.probe()` selects several results through early returns
and a protocol-specific catch. Caller-side parsing and final result selection
do not pass through one interruption check, so `Success`,
`AuthenticationFailure`, or `ProtocolFailure` can escape while the caller
interrupt flag is set.

`OperationTask.run()` publishes a worker-side failure and then waits for the
caller disposition. If the I/O worker is interrupted, `awaitDisposition()`
immediately throws and changes the published `Failure` to `Declined`. The
caller can consequently observe a timeout instead of the failure. Held
post-close validation can accept that timeout as closed-transport evidence.

The completion handoff samples the deadline before its `Result`/`Failure` to
`Claimed` compare-and-set. The deadline can cross after that sample and before
the ownership transfer, allowing a completion after the promised boundary to
escape.

The existing Held generic-I/O interruption tests interrupt the caller while it
is still waiting in `OperationTask.await()`. That creates a literal caller-side
`InterruptedException`; the later worker `IOException` is declined and never
reaches Held's outer catch. The tests therefore do not prove generic
`IOException`/`SocketException` classification with a caller flag.

The HTTP failure-classification seam runs before abandonment. If that seam
throws after a caller-side parse failure, the operation, I/O worker, and socket
are never unconditionally cancelled.

Finally, the Held open/seed integration tests block the first seed write, not
the registered transport factory after allocation. They do not cover an
allocated transport whose `open`, `abort`, and `close` all remain blocked.

## Coordinator state-machine repair

Keep the existing task states and capacity model. Add an injected no-op
claim-attempt seam solely to make the handoff boundary deterministic in
non-live tests. It runs after the advisory precheck and immediately before the
completion-to-`Claimed` compare-and-set.

The successful compare-and-set transfers ownership to the caller. The caller
then performs the authoritative monotonic deadline sample; that post-CAS
sample is the exact completion linearization point. If the sample is expired:

- a claimed result is disposed exactly once by its new caller owner and the
  caller receives `DovecotBoundedOperationTimeoutException`;
- a claimed generic failure is replaced by the same timeout; and
- a claimed `InterruptedException` retains precedence and is surfaced through
  the existing redacted/restored caller interruption path.

Disposition is signalled in `finally` after the post-claim decision, so an
injected clock failure cannot strand the worker. The terminal task state stays
`Claimed`; abandonment remains responsible for operation cancellation and
accounting.

After publishing a result or failure, the worker waits for disposition in a
loop. A worker interrupt is recorded and cleared by the wait, but it does not
decline the task. The worker continues waiting until the caller claims, the
caller/deadline declines, or the absolute deadline expires, then restores its
interrupt flag before leaving. Only the caller or deadline may change a
published completion to `Declined`.

## Probe result normalization

Split result production/cleanup from public return normalization. Every
selected enum result, including capacity failure, early authentication
failure, mailbox protocol failure, protocol catch, success, and generic catch,
passes through one final boundary after cleanup. A small injected no-op
selection seam allows deterministic caller interruption between selection and
normalization.

If the caller flag is set at that boundary, leave it set and return the
secret-free `TransportFailure`. No `Success`, `AuthenticationFailure`, or
`ProtocolFailure` may return with the caller flag set. The public result remains
an enum, so no transport or protocol exception detail is exposed.

## Held classification and registered-open coverage

Inject one no-op Held failure-classification seam into open/seed and carry it
into a successful held session for usability and post-close checks. On a
failure, first establish cleanup ownership by abandoning the operation and
performing the existing bounded release wait while recording interruption.
Only then invoke the seam with the actual outer failure, and only after it
returns perform final interruption classification.

Tests use the seam as an uninterruptible barrier: they first prove the outer
path received the actual `IOException` or `SocketException`, then set the
caller flag and release classification. Seed, usability, and post-close must
all surface a redacted `InterruptedException` with the flag preserved;
post-close may not return normally. Post-close captures its write failure as
an outcome and classifies it once outside the enclosing failure boundary, so a
redacted interruption is not classified again and the seam is invoked exactly
once. A seam exception may surface, but
abandonment, bounded cleanup, credential/message wiping, and reservation
accounting have already been established and must not leak.

Add a separate factory fixture that calls `onAllocated(transport)` and then
blocks before returning. The registered transport's abort and close methods
also block independently. The caller must return within its deadline, the
single capacity slot must remain charged with three actors, and releasing the
three barriers must close the transport and return all accounting to zero.

## HTTP cleanup ordering

On any HTTP failure, unconditionally abandon the operation and perform bounded
cleanup before invoking `beforeFailureClassification`. Record interruption
encountered during cleanup. After the seam returns, sample the caller flag
again so the existing deterministic `SocketException`-plus-interrupt proof
still promotes to a redacted `InterruptedException`.

If the seam throws, its failure may surface only after cleanup ownership is
established. The surrounding `finally` still wipes request headers and any
owned response body and closes the deadline. A caller-side parse-failure
regression must prove the socket closes, copied request buffers are wiped, the
worker and cancellation actors exit, and the reservation returns to zero.

## Verification

Each defect repair begins with an observed deterministic RED test. The
registered-open triple-block case is a characterization of the existing cap
and ownership behavior and is expected to pass before production changes.
Focused GREEN runs cover coordinator, Probe, Held, and HTTP. The exact
reported flaky order is repeated verbatim:

1. `DovecotBoundedOperationWorkersTest`
2. `DovecotHeldOperatorImapDeadlineTest`
3. `DovecotHeldOperatorImapSessionTest`
4. `DovecotOAuthProofValidatorTest`
5. `DovecotIsolationMailboxContractTest`

After repeated order stability, run the reciprocal Task 6 selection,
proportional non-live Dovecot and dashboard-server scans, the independent
Python helper, the Kotlin module build, documentation-sensitive tests,
`git diff --check`, and `.ai/self-review.md`. Task 6 live evidence remains
pending.
