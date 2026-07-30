# Dovecot Operator Docker-Exec/Stdio Transport Design

**Date:** 2026-07-30

**Status:** Confirmed; detailed contract reviewed; implementation planned

**Scope:** Gate 0C Task 6 operator ingress only

## Context

The first isolated Task 6 lifecycle proved that the operator starts and accepts
the intended master-login flow. The following isolation assertion then failed:

```text
HOST_DOCKER_INTERNAL_REACHABLE
```

The operator's IMAPS listener was published as
`127.0.0.1:2993 -> dovecot-operator:31993`. On Docker Desktop, traffic from a
container to `host.docker.internal:2993` is forwarded through
`com.docker.backend` even though the published address is host loopback. The
loopback bind therefore blocks ordinary LAN clients but does not establish the
container isolation required by Gate 0C.

This is a failed architecture assumption, not a flaky probe. The negative
assertion remains mandatory and its failure must not be hidden with DNS
overrides, firewall rules, or a relabeled result.

## Supersession

This confirmed amendment replaces only the Dovecot operator-ingress
clauses in:

- `2026-07-23-debug-dashboard-design.md` Mail access and Gate 0C step 7,
  which formerly required a loopback host publication on a non-internal
  bridge;
- `2026-07-23-debug-dashboard-gate-0c-dovecot.md` Task 5's formerly required
  `127.0.0.1:2993` topology and host-JSSE readiness;
- that Gate plan's former Task 6 positive/raw operator host-socket helpers and
  runtime publication assertion;
- `.ai/skills/docker-compose/references/service-map.md` former operator
  publication and non-internal-network entries.

All credential, passdb, eligibility, negative-matrix, mailbox, rotation,
cleanup, and stop/go requirements remain in force. The main design, Gate plan,
implementation-plan source-of-truth list, and Gate evidence record must link to
this amendment before implementation is considered aligned.

## Decision

Remove the operator's host TCP publication. The host-native Ktor/JVM dashboard
will reach the operator only by starting a fixed, non-shell
`docker compose exec -T` child process whose stdin/stdout is a verified TLS IMAP
stream inside the operator container.

The fixed container-side command is:

```text
/usr/bin/openssl s_client
  -quiet
  -no_ign_eof
  -nocommands
  -4
  -min_protocol TLSv1.2
  -max_protocol TLSv1.3
  -verify_return_error
  -verify_hostname localhost
  -no-CApath
  -no-CAstore
  -CAfile /etc/dovecot/ssl/tls.crt
  -connect 127.0.0.1:31993
  -servername localhost
```

The pinned `dovecot/dovecot:2.4.1` image digest used by this repository contains
OpenSSL 3.0.17 at `/usr/bin/openssl`. Both the ordinary and proof Compose models
already mount the selected certificate at the fixed CA path. No user,
account, mailbox, credential, hostname, port, executable, or arbitrary flag may
alter this command.

The proof lifecycle changes its disposable certificate identity from
`task5-proof.local` to `localhost` and includes exact
`subjectAltName=DNS:localhost`. The production startup certificate must also
verify for `localhost`; the repository's current local certificate does. Proof
and production certificates remain distinct files and keys despite sharing the
fixed connection identity.

The operator's Dovecot 2.4 listener also sets `listen = 127.0.0.1` inside its
own `inet_listener imaps` block, binding only inside its network namespace
rather than to `0.0.0.0`. The `dovecot-operator` service remains the only member
of `operator-ingress`, the bridge becomes internal, and the service exposes no
host port. Docker's control plane, not a network route, becomes the only
host-to-operator ingress.

## Goals

- Preserve the existing stream-oriented `DovecotOperatorTransport` contract and
  all higher-level authentication, mailbox, rotation, and deadline behavior.
- Make the operator unreachable from ordinary containers, Docker Desktop host
  aliases, host gateway aliases, non-loopback host interfaces, and ordinary
  host TCP clients.
- Keep TLS authentication and hostname verification on the operator hop.
- Keep credentials out of process arguments, environment variables, exception
  messages, retained diagnostics, and Compose logs.
- Make cancellation, timeout, close, and failed startup bounded and leak-free.
- Use the same transport in startup readiness, positive isolation proof,
  rotation proof, and the eventual dashboard runtime.
- Leave the ordinary Dovecot, Postfix, OAuth, and all Stalwart paths unchanged.

## Non-goals

- This change does not implement account, folder, message, or log APIs.
- It does not broaden the existing typed `doveadm` command surface.
- It does not make the Docker control plane safe for untrusted local users.
  Running the local dashboard already assumes a developer who may use Docker.
- It does not add a generic command runner or accept Compose settings from an
  HTTP request.
- It does not weaken or reinterpret the Gate 0C isolation assertion.

## Architecture

### Trusted launch profile

The transport factory receives a construction-time launch profile. The profile
contains only:

- one canonical, executable Docker CLI path selected at trusted process
  startup;
- the canonical repository/project directory;
- the exact ordered Compose files;
- one exact Compose project name selected and validated at trusted process
  startup (the isolated proof always uses `mail-sandbox-task5-proof`);
- one exact local Unix Docker socket selected at trusted process startup;
- the exact service name `dovecot-operator`;
- the fixed profile name `dovecot-operator`.

Production values come from the dashboard's trusted startup configuration.
Proof values come only from the existing fixed `task5-proof` profile. Request
data cannot select a project, Compose file, service, binary, target, or flag.
The launcher always supplies `--project-name`; it does not let the working
directory or an inherited `COMPOSE_PROJECT_NAME` silently choose another
project.

For both production and proof, the child environment removes every inherited
`COMPOSE_*`, `DOCKER_*`, and `DOVECOT_*` key. It then sets only
`COMPOSE_DISABLE_ENV_FILE=1` and the trusted exact `DOCKER_HOST=unix://...`
value. `DOCKER_CONTEXT`, `DOCKER_CONFIG`, TLS routing variables,
`COMPOSE_FILE`, `COMPOSE_PROJECT_NAME`, `COMPOSE_PROFILES`,
`COMPOSE_ENV_FILES`, and implicit `.env` selection cannot redirect the child.
The proof retains its existing stricter startup-environment validation in
addition to this child sanitization.

The launcher uses `ProcessBuilder(List<String>)`; it never invokes `sh`, `bash`,
`zsh`, `-c`, a command string, or interpolation. Its working directory is the
canonical repository root. The proof launcher replaces routing-related
environment entries with the already validated fixed values and rejects
unexpected `COMPOSE_*`, `DOCKER_*`, and `DOVECOT_*` inputs as it does today.

Conceptually, the host-side argv is:

```text
<trusted-absolute-docker-cli> compose
  --project-directory <trusted-repository-root>
  -f <trusted-absolute-compose-file>...
  --project-name <trusted-startup-project>
  --profile dovecot-operator
  exec -T --index 1
  dovecot-operator
  /usr/bin/openssl s_client
  <fixed TLS flags>
```

Angle-bracketed values above are trusted construction-time profile values, not
request values. The implementation tests the exact argv list.
The profile flag is always explicit: it makes the production service part of
the Compose model and is harmless for the proof override that clears the
service's own profile. `exec` still requires a pre-existing running container;
the transport never starts or recreates it.

### Transport mapping

The child process maps directly onto the existing abstraction:

| Transport member | Child-process resource |
|---|---|
| `input` | OpenSSL stdout, containing decrypted IMAP server bytes |
| `outputStream` | OpenSSL stdin, accepting IMAP client bytes |
| `abort()` | Idempotent bounded process/stream termination |
| `close()` | Idempotent bounded process/stream termination |

OpenSSL stderr is redirected to `ProcessBuilder.Redirect.DISCARD` at launch. It
is never merged into the IMAP stream, retained, logged, or copied into an
exception. This avoids an extra drain actor and prevents pipe backpressure while
preserving the existing redacted `TransportFailure` result.

`Process.start()` is the allocation boundary. Immediately after it succeeds,
the factory wraps the process, invokes `registerAllocated`, and only then lets
any potentially blocking protocol read occur. A process that exits before the
verified greeting is observed is a transport failure.

If `registerAllocated` throws after `Process.start()`, ownership never reached
the coordinator. The factory must therefore close stdin/stdout, terminate,
force if necessary, and boundedly reap that process before rethrowing a
redacted transport failure. This pre-registration cleanup path is tested
directly.

### TLS boundary

OpenSSL connects only to `127.0.0.1:31993` in the operator container's own
network namespace. The command:

- trusts only the certificate mounted at `/etc/dovecot/ssl/tls.crt`;
- aborts on certificate-chain verification failure;
- verifies the fixed `localhost` identity;
- sends `localhost` as SNI;
- permits only TLS 1.2 or TLS 1.3;
- disables OpenSSL's interactive single-letter command handling;
- permits EOF to terminate the client rather than retaining a detached
  interactive session.

The IMAP master credential and target address are written only through the
process stdin after TLS succeeds. They never appear in argv or environment.
TLS or process diagnostics remain normalized to the existing fixed failure
types.

### Lifecycle and cancellation

Normal IMAP flows retain their existing stream-close behavior; this transport
change does not add a new IMAP `LOGOUT` exchange. Close and abort use one
idempotent termination state machine:

1. close the child stdin so `-no_ign_eof` ends OpenSSL and its Docker exec;
2. leave stdout open and allow at most 500 ms for natural child exit so EOF
   reaches the remote exec;
3. on natural exit, close stdout and require exit code zero for a normal
   result;
4. if still alive, close stdout, call `destroy()`, and wait at most 250 ms;
5. if still alive, call `destroyForcibly()` and make one final reap attempt of
   at most 250 ms;
6. record whether the child was reaped and whether termination was required.

A normal probe/session close succeeds only after natural exit with code zero.
Needing `destroy`, needing force, observing a nonzero exit, or failing to reap
changes a pending normal result to TransportFailure. Timeout/abort and
post-allocation registration-failure cleanup accept any exit code, but they
must still reap the child within the same fixed one-second aggregate cleanup
bound even when the operation deadline has already expired. That cleanup may
outlive the cancelled caller's 100 ms wait, but not its charged cancellation
actor.

Interrupted callers retain their interrupt flag. Close failures do not make a
transport reusable. No unbounded `waitFor`, thread creation, retry loop, or
stderr buffer is allowed.

Finite probes must synchronously close and reap the process inside their
existing five-second operation deadline before returning any Success,
AuthenticationFailure, AuthorizationFailure, or ProtocolFailure. Failure to
close, observe exit, or reap changes that result to TransportFailure. The
result is not committed first and then cleaned in `finally`.

The normal close call runs through the existing coordinator rather than
receiving an ad hoc deadline parameter. If its fixed termination sequence
outlives the operation deadline, the coordinator caps the caller, changes the
result to TransportFailure, and invokes the same idempotent abort/close state
machine. Charged cleanup may then continue for its fixed one-second actor
bound; no successful result escapes first.

The existing 100 ms post-abandon wait remains only a bound on how long a
cancelled caller waits for best-effort cancellation actors; it is not evidence
that cleanup succeeded. A normal result uses the remaining operation deadline
for synchronous cleanup. An expired/interrupted path is already a
TransportFailure, launches idempotent abort/close, and is additionally covered
by the live no-orphan assertion.

Held sessions are the only transport handoff. A new open-and-lease path reserves
one of the existing `DovecotOperatorApplicationLeaseRegistry` slots before
`Process.start()`, constructs the session while it still owns the bounded
operation reservation, binds the session to that lease, and only then commits
the handoff and returns. No caller can observe a live unleased process.
Lease-capacity, lease-registration, construction, or handoff failure
synchronously closes/reaps and releases the lease reservation.

Explicit held-session close synchronously closes/reaps and reports a redacted
failure without making the session reusable. `DovecotBoundedOperationWorkers`
bounds finite and opening operations; the lease registry separately bounds
handed-off live process transports to fifteen application leases plus one
verification lease. Tests cover that exact maximum and prove that a seventeenth
process is never started.

An opening lease reservation is a visible, drainable registry entry, not an
unbound counter. It holds a fixed cancellation callback to abandon the opening
coordinator operation; once a process is registered, that same operation owns
its abort/close target. `blockAndDrain()` marks the reservation draining and
invokes cancellation without holding the registry lock across
`Process.start()`. The opening path rechecks the reservation before process
start, after allocation/before bind, and before handoff commit. A blocked,
closed, or drained reservation can never bind or return a session. Tests race
rotation/drain at all three points and require bounded cleanup.

The process transport does not create an additional thread or executor. Live
cancellation tests also compare operator process state before and after
injected timeout/abort cases so a lingering `openssl s_client` is a proof
failure.

### Readiness

The `OPERATOR_IMAPS` host-port readiness boundary is retired. Operator readiness
uses the same exec/stdio transport as real operations:

1. acquire the existing bounded operation coordinator and its fixed deadline;
2. start and register the fixed transport;
3. complete certificate and hostname verification;
4. read the bounded Dovecot `* OK` greeting;
5. synchronously close and reap the process before reporting ready.

No default readiness branch performs a naked process-stdout `read()`.
Coordinator cancellation is what bounds a silent child because a process pipe
has no socket read timeout. This also prevents a separate host socket probe from
reintroducing the removed network path.

The same rule applies to startup's bare-target and PLAIN rejection exchanges,
the isolation protocol proof, rotation, and every other live helper. Existing
raw helpers that relied on JSSE `soTimeout` migrate to one coordinator-backed
bounded IMAP exchange helper. No exec/stdio consumer reads or writes a process
stream outside a registered operation/session deadline.

### Compose topology

Both the ordinary Compose model and the isolated proof override:

- remove `ports` from `dovecot-operator`;
- bind the operator's internal listener to exact `127.0.0.1:31993`;
- retain the passive listener healthcheck, count all state `0A` entries for
  port `7CF9` across both `/proc/net/tcp` and `/proc/net/tcp6`, require exactly
  one, and require that sole entry's local address to be exact IPv4
  `0100007F:7CF9`;
- keep `dovecot-operator` as the sole `operator-ingress` member;
- set `operator-ingress.internal: true`;
- retain all existing read-only runtime, operator-auth, and TLS mounts.

The ordinary Dovecot IMAPS port remains on host loopback because it represents
the provider endpoint under test, not privileged operator access.

The old `operatorImapsPort=2993` positive endpoint is removed from
`DovecotTask5ProofProfile` and `DovecotLiveTestEnvironment`. A renamed fixed
`forbiddenOperatorHostPort=2993` exists only for port reservation, `lsof`, LAN,
Docker host-alias, and host-gateway negative checks. No readiness,
authentication, authorization, mailbox, or rotation success path may connect
to it.

## Failure Semantics

The transport exposes no raw Docker or OpenSSL output. All failures map to the
existing fixed operator result categories:

- executable or Compose launch failure -> `TransportFailure`;
- missing/not-running operator service -> `TransportFailure`;
- TLS trust, identity, negotiation, or early EOF failure ->
  `TransportFailure`;
- malformed/bounded IMAP exchange -> `ProtocolFailure`;
- Dovecot authentication rejection -> the existing authentication or
  authorization category;
- deadline, interruption, cancellation, or failed reap ->
  `TransportFailure`.

The exception and `toString()` contracts remain redacted. Passwords, master
secrets, target addresses, Docker output, OpenSSL output, absolute runtime
secret paths, and arbitrary stderr bytes are not surfaced.

## Proof Changes

### Static proof

Tests must reject:

- any operator host port, `expose`, `network_mode: host`, extra network, or
  second member of `operator-ingress`;
- a non-internal `operator-ingress`;
- an operator listener address other than exact container-loopback
  `127.0.0.1`, or a healthcheck that accepts a wildcard/network-interface
  listener;
- any launcher using a shell or a mutable command string;
- any request-controlled project, service, executable, address, port, CA path,
  or OpenSSL flag;
- missing certificate/hostname verification flags;
- proof certificate generation without exact `CN=localhost` and
  `subjectAltName=DNS:localhost`, or a selected startup certificate that does
  not verify for `localhost`;
- stderr merged with stdout or retained without a bound;
- unbounded wait/reap behavior;
- a readiness, startup-negative, isolation, rotation, or mailbox helper that
  reads an exec process pipe without the coordinator-backed bounded exchange.

Tests assert the exact fixed argv for production and proof profiles.
Runtime topology requires an empty published-port set for
`dovecot-operator`; it no longer accepts `31993 -> 2993`. The negative helper
still receives the operator bridge IP and host-address set and continues
probing fixed forbidden host port `2993`.

### Process-inventory proof

The lifecycle first resolves exactly one operator container ID through the
same fixed `docker compose ... ps --quiet dovecot-operator` profile used by the
topology proof. It requires one newline-terminated 64-hex ID and validates the
expected project/service labels before using it. The dynamic ID is therefore a
validated daemon result, never request input.

It then uses one fixed, non-shell, bounded inventory command:

```text
<trusted-absolute-docker-cli> top
  <validated-64-hex-operator-container-id>
  -ww -eo pid,args
```

The exact `-ww -eo pid,args` form was verified against the selected Docker
Desktop daemon and requests an untruncated argument column. Its parser caps
stdout bytes and wall time, requires exit zero and empty stderr, validates the
`PID COMMAND` header and decimal PID column, and counts only rows whose complete
command column is the exact fixed `/usr/bin/openssl s_client ...` argv from
this design. Malformed, truncated, unexpected, or stderr-bearing output fails
with a fixed redacted diagnostic; raw process output is never reported.

Any row that identifies `openssl` but is not that complete exact argv also
fails invalid-inventory, including a truncated command or
`[openssl] <defunct>`. It is never ignored as an unrelated Dovecot row or
miscounted as zero.

The sequential proof requires a zero-OpenSSL baseline before each case and
zero afterward. It checks normal finite close, post-launch registration
failure, timeout, abort, and held-session close. No legitimate held session is
open during a zero assertion, so PID reuse and unrelated Dovecot processes
cannot satisfy or invalidate the count. The separate capacity test expects
exactly sixteen fixed OpenSSL rows at saturation and proves that the
seventeenth process is never started.

### Isolated live proof

The existing lifecycle continues to create only the disposable Dovecot,
operator, Postfix, and OAuth services. Stalwart remains disabled. The checked
sequence becomes:

1. prove the pre-existing Docker/container/network/volume/port baseline;
2. start the isolated stack;
3. require the generated disposable certificate to verify for `localhost`,
   then require ordinary IMAPS, POP3S, SMTP, and OAuth host readiness;
4. require operator readiness through fixed exec/stdio;
5. require the negative helper's exact `OK` result for:
   - operator DNS and direct-IP isolation,
   - `host.docker.internal`,
   - `gateway.docker.internal`,
   - the explicit host-gateway alias,
   - non-loopback host addresses;
6. prove positive operator authentication and mailbox operations through the
   same exec/stdio transport;
7. inject cancellation and require no lingering OpenSSL exec process;
8. run the existing credential-rotation overlap and revocation proof;
9. clean the disposable project and require exact baseline restoration.

No result label is skipped, downgraded, or reinterpreted.

## Alternatives Rejected

### Containerize the Ktor backend

Joining a backend container to provider networks would avoid Docker exec, but it
changes the local Kotlin Toolchain run/debug workflow and materially expands the
current Gate 0C scope. It also gives the entire backend network membership
rather than exposing one typed stream.

### Unix-domain proxy

A host-only Unix socket is conceptually narrow, but Docker Desktop bind-mounted
socket behavior and JSSE-over-Unix support add platform-specific proxy code and
another lifecycle to secure and prove.

### Keep the loopback publication

Alternate loopback addresses, IPv6-only publication, Docker DNS masking, and
host firewall rules preserve the failed assumption or make the proof dependent
on workstation policy. They do not establish the required topology.

## Acceptance Criteria

The redesign is complete only when:

- no host TCP publication exists for `dovecot-operator`;
- the operator listener is live-proven on container loopback only;
- the exact fixed exec/stdio command is the sole dashboard operator transport;
- TLS trust and `localhost` identity verification are live-proven;
- the negative isolation helper returns exact `OK`;
- startup, cancellation, mailbox, authentication/authorization, and rotation
  proofs pass through the new transport;
- no OpenSSL exec child remains after normal close, failure, timeout, or abort;
- the checked lifecycle restores the exact pre-existing Docker and port
  baseline;
- focused and exact Gate 0C test classes pass;
- independent spec and code reviews report no blocking findings;
- no Stalwart service or data is started, stopped, recreated, inspected through
  a mutation, or otherwise changed.
