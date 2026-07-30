# Gate 0C — Dovecot identity and operator ingress

## Status

- **Task 1 — Freeze and inspect the Dovecot baseline:** complete.
- **Task 2 — Replace tracked plaintext runtime authority:** complete.
- **Task 3 — Make OAuth decisions eligibility-aware:** complete.
- **Task 4 — Make Postfix recipient routing eligibility-aware:** complete.
- **Task 5 — Add a physically separate master-only IMAP ingress:** complete.
- **Task 6 — Prove network isolation and credential rotation:** implementation
  and non-live verification complete; the checked Docker Desktop lifecycle is
  pending controller execution.
- **Gate 0C:** in progress. Task 6 live isolation/rotation evidence is pending;
  Tasks 7–9 still own mail behavior, lifecycle, and the final decision. This
  document does not record a Gate 0C PASS.

## Task 1 baseline evidence

The baseline was captured from commit
`79d15652148ea2a52940b3210302ddad52100ac5` on 2026-07-29, before
`docker-compose.yml` was edited. No image pull was needed.

```text
$ docker image inspect dovecot/dovecot:latest --format '{{json .RepoDigests}}'
["dovecot/dovecot@sha256:1296e0f1029cdd95e6849fb82f5d142a6e2a46218451773316cea678de75254b"]
```

The cached image resolved as `linux/arm64`. Its local repository digest matched
the reviewed multi-platform digest, and the permitted dependency-free
ephemeral version check reported:

```text
$ docker compose run --rm --no-deps dovecot dovecot --version
2.4.1 (7d8c0e5759)
```

The effective configuration was captured with:

```text
$ docker compose run --rm --no-deps dovecot doveconf -n
```

That run reported Dovecot `2.4.1`, Pigeonhole `2.4.1`, Debian 12.11 on
`aarch64`, and `dovecot_config_version = 2.4.1`. The bounded fields relevant to
this gate, normalized below for compactness, were:

```text
service imap-login:  imap=31143, imaps=31993
service pop3-login: pop3=31110, pop3s=31990
passdb passwd-file: /etc/dovecot/conf.d/users
passdb oauth2:      mechanisms_filter=xoauth2 oauthbearer
userdb static:      uid=1000, gid=1000, home=/srv/vmail/%{user}
oauth2:             POST introspection at http://oauth2-mock:8080/introspect
```

The full effective configuration was inspected locally. It is intentionally
not copied into this report; the excerpt above freezes only the facts required
for Gate 0C and avoids reproducing unrelated runtime defaults.

## Initial hazard inventory and ownership

| Initial condition | Concrete baseline evidence | Task owner | Task 1 treatment |
|---|---|---|---|
| A static userdb can resolve a non-existent target | The Task 1 baseline contained `userdb static` with a templated `/srv/vmail/%{user}` home | Task 2 | Replaced in Task 2 with an exact passwd-file userdb lookup against `/etc/dovecot/runtime/users` |
| A prefix token can make an arbitrary identity active | The Task 1 mock returned `active: True` for every `token.startswith("valid-")` suffix | Task 3 | Replaced in Task 3 with a fresh canonical eligibility lookup on every OAuth decision |
| Postfix accepts arbitrary local recipients | `postfix/main.cf` had empty `local_recipient_maps` and `smtpd_reject_unlisted_recipient = no` | Task 4 | Replaced in Task 4 with a live full-recipient socketmap and unlisted-recipient rejection |
| Ordinary mail/OAuth host publications were wildcard-bound | Baseline Compose mappings omitted a host address for Dovecot, Postfix, and OAuth | Task 1 | Replaced with the exact loopback mappings below |
| The Dovecot image floated and services had fixed names | Baseline used `dovecot/dovecot:latest` and four `container_name` directives | Task 1 | Image pinned; all fixed names removed |

The focused Kotlin audit's Task 1 assertions initially failed for
the floating image, wildcard/legacy port mappings, and four fixed container
names: 1 test passed and 3 failed. This is the intentional RED evidence.
Task 2 removed the former static-userdb characterization after replacing that
boundary, and Task 3 removed the arbitrary prefix-token characterization after
making OAuth decisions eligibility-aware. Task 4 removed the final deferred
Postfix characterization and added positive exact-assignment invariants.

## Task 1 frozen Compose boundary

Dovecot is pinned exactly to:

```text
dovecot/dovecot:2.4.1@sha256:1296e0f1029cdd95e6849fb82f5d142a6e2a46218451773316cea678de75254b
```

The reviewed ordinary host publications are:

| Protocol | Host publication | Container port |
|---|---:|---:|
| IMAP STARTTLS | `127.0.0.1:1143` | `31143` |
| IMAPS | `127.0.0.1:1993` | `31993` |
| POP3 STARTTLS | `127.0.0.1:1110` | `31110` |
| POP3S | `127.0.0.1:1995` | `31990` |
| SMTP | `127.0.0.1:1025` | `25` |
| SMTPS | `127.0.0.1:1465` | `465` |
| SMTP submission | `127.0.0.1:1587` | `587` |
| OAuth introspection | `127.0.0.1:8080` | `8080` |

No service in the ordinary Compose model has a fixed `container_name`; Compose
project names remain available as the isolation boundary. Task 1 removes
Stalwart's fixed name but does not change its image, configuration, data, or
host publication.

## Task 2 hashed runtime authority

`config/users` was removed. Its address column alone was converted into the
deterministically ordered `config/users.seed`; no legacy password or hash was
printed, retained, or used to initialize runtime state. The root ignore rules
now include exact `/config/users` plus the Dovecot, future Dovecot-operator,
and raw-secret runtime directories. There is no tracked default password.

The fixed production authority is
`debug-dashboard/.runtime/dovecot/users`, with the stable global lock at
`debug-dashboard/.runtime/dovecot/users.lock`. The Kotlin boundary:

- accepts only canonical lowercase ASCII addr-specs and the bounded provider
  form
  `{ARGON2ID}$argon2id$v=19$m=<positive>,t=<positive>,p=<positive>$<salt>$<hash>`,
  with exact parameter order and bounded, unpadded standard Base64 salt and
  digest tokens;
- renders each canonical record as `<address>:<provider-hash>::::::`: eight
  passwd-file columns (`user`, `password`, `uid`, `gid`, `gecos`, `home`,
  `shell`, and `extra_fields`). The six post-password fields are empty because
  Dovecot configuration supplies the UID, GID, and home defaults; their
  delimiters are still required so passwd-file userdb recognizes the record;
- preserves comments, blank lines, and unrelated entries deterministically;
- exposes only `seed`, `add <address>`, `reset <address>`,
  `remove <address>`, and `list`;
- receives bootstrap/add/reset secrets only from stdin and clears mutable
  password and process buffers, including runner-owned capture buffers when
  an output reader completes after failure cleanup;
- uses the fixed no-shell command equivalent to
  `docker compose exec -T dovecot doveadm pw -s ARGON2ID`, with the password
  supplied twice over stdin and bounded output/timeout; and
- holds `FileChannel.lock()` on the stable lock from read through atomic
  replace, parent durability, and post-write verification.

The writer rejects symbolic fixed-path components and non-regular or
incorrectly permissioned target, lock, and temporary files. Its owned
directory is mode `0700`; target, lock, and recognized same-directory
temporaries are mode `0600` on POSIX. Tests tie concurrent JVM-process markers
to immediately before and after the real `FileChannel.lock()` call, cover
metadata preservation and cleanup of only fixed recognizable abandoned
temporaries, prove ordinary pre-move failures durably delete their exact
temporary, and distinguish a genuine crash before replace (old truth plus a
cleanable temporary) from a genuine crash after replace (new truth).

Ordinary Dovecot mounts the containing
`./debug-dashboard/.runtime/dovecot` directory read-only at
`/etc/dovecot/runtime`; it does not mount the replaceable file or any
operator-secret directory. Both passwd-file passdb and userdb use
`/etc/dovecot/runtime/users`. The userdb defaults compile as exact Dovecot 2.4
`uid:default`, `gid:default`, and `home:default` fields.

The pinned image baseline exposed `service doveadm` /
`inet_listener http` on port `8080`. `config/20-doveadm.conf` overrides that
exact listener to `port = 0`; no guessed listener name or network
administration path was added.

### Task 2 RED/GREEN evidence

The focused RED command was:

```bash
cd debug-dashboard
./kotlin test \
  --include-module dashboard-server \
  --include-classes \
  'mail.sandbox.dashboard.server.gate.dovecot.EligibilityFileTest'
```

It exited `1` during `:dashboard-server:compileJvmTest` because the new
`EligibilityEntry`, `EligibilityFile`, fixed paths, hash process boundary, and
CLI symbols did not exist. After the code boundary reached 18/18, a
configuration assertion produced a second intentional RED: 18/19 passed and
the missing `config/20-doveadm.conf` was the sole failure.

Self-review then tightened the provider encoding and tracked-seed assertions.
That regression run was RED at 17/19 because printable
`{ARGON2ID}garbage` was still accepted and the seed inventory was not
lexicographically rendered. Both boundaries were corrected. Independent
review then identified a non-wiping process-output accumulator; its focused
regression was RED at test compilation before the wipeable collector existed.
Spec-review regressions subsequently rejected unproven ARGON2ID versions,
parameter forms, and Base64 variants, and proved that a late output reader
cannot repopulate a closed capture. The final focused run passed 24/24, the
updated Task 1 audit passed 4/4, and the permitted non-live dashboard-server
suite passed 293/293. The audit no longer expects the Task 2 static-userdb
hazard. `docker compose config --quiet` exited `0`.

The permitted dependency-free pinned-image check:

```bash
docker compose run --rm --no-deps dovecot doveconf -n
```

exited `0` and resolved the relevant configuration as:

```text
service doveadm:
  inet_listener http: port=0
passdb passwd-file: /etc/dovecot/runtime/users
passdb oauth2:      mechanisms_filter=xoauth2 oauthbearer
userdb passwd-file: /etc/dovecot/runtime/users
  gid:default=1000
  home:default=/srv/vmail/%{user}
  uid:default=1000
```

No real seed/hash/bootstrap was executed because no new explicit one-time
secret was supplied. The safe `list` path created only the mode-`0700`
Dovecot runtime directory and mode-`0600` stable lock; the runtime `users`
authority remains absent pending an explicit non-legacy bootstrap. No
`docker compose up`, `down`, or `restart`, live Stalwart access, or Stalwart
data operation was performed.

The broad non-live dashboard-server command:

```bash
./kotlin test \
  --include-module dashboard-server \
  --exclude-classes '*LiveTest' \
  --exclude-classes \
  'mail.sandbox.dashboard.server.gate.KotlinToolchainBrowserGateTest'
```

passed 293/293. An earlier unfiltered dashboard-server attempt ran 302 tests:
the then-current 288 passed and 14 environment-gated Stalwart action/live or
production browser tests failed only because their explicit
live/action/assets variables were absent. Those tests were not enabled because
this task neither permits live Stalwart access nor supplies the browser
production bundle environment.

## Task 3 eligibility-aware OAuth boundary

The OAuth mock mounts only the same containing
`./debug-dashboard/.runtime/dovecot` directory, read-only at
`/etc/dovecot/runtime`; it does not mount a replaceable file directly or any
operator-secret directory. Its fixed reader opens
`/etc/dovecot/runtime/users` read-only without following the final symlink,
requires a mode-`0600` regular file, bounds reads to 1 MiB, verifies a stable
file identity, decodes strict UTF-8, and parses the same canonical lowercase
ASCII addresses and exact ARGON2ID PHC form as the Kotlin writer. A missing,
unreadable, replaced-during-read, symbolic, malformed, duplicate, or
incorrectly permissioned authority fails closed.

Authorization, authorization-code exchange, refresh, stored-token
introspection, and direct `valid-<username>` introspection each perform a
fresh eligibility decision. Removing an account therefore prevents new
codes/tokens and makes its existing or test-convention valid token inactive
without restarting the mock. An ineligible refresh grant is also revoked.
Expired, insufficient-scope, and invalid test-token responses retain their
existing behavior. Submitted bearer, authorization-code, refresh, and
password values are absent from diagnostics, errors, and logs; successful
protocol responses still return the newly issued code or tokens required by
OAuth.

### Task 3 RED/GREEN evidence

The first stdlib test run was intentionally RED. It reported the missing
`EligibilityReader`, allowed non-eligible authorization/code/refresh/token
paths, and exposed the submitted bearer value in the introspection log. A
parser-parity regression was then RED for an ARGON2 parameter value that
Kotlin rejects as outside its signed 32-bit range. Review later exposed a
second RED parity case: Python treated U+0085 as blank/comment whitespace
while Kotlin treated it as entry data and rejected the authority. After the
fix, all 23 focused Python tests passed on the host and in the Python 3.12
image. They cover every issuance/recheck transition, immediate deletion,
authority-reader failure, canonical parsing, symbolic and
unreadable/non-regular files, bounded UTF-8 input, no caching, the exact
read-only Compose mount, retained test-token semantics, and secret canaries in
errors/logs. A shared exhaustive UTF-16 fixture is checked against actual
Kotlin/JVM `Char.isWhitespace` and the Python reader, including U+0085 and the
boundaries of every accepted range; blank/comment parsing no longer inherits
Python-only whitespace.

The HTTP form boundary accepts exactly one non-negative ASCII-decimal
`Content-Length`, limits bodies to 16 KiB, limits forms to 32 fields with
bounded names and values, decodes strict UTF-8, and applies a one-second total
body-read deadline. Invalid, duplicate, negative, oversized, incomplete, slow,
or over-populated forms receive the same fixed `400 invalid_request` without
reflecting or logging body data. Actual loopback HTTP regressions prove each
failure and then successfully call `/health` and perform a valid introspection
on the same single-threaded server.

Eligibility now has explicit eligible, ineligible, and unavailable results.
Every unavailable decision still fails closed and mints nothing. Refresh
tokens are revoked only after a valid current snapshot proves the canonical
identity absent; a missing, malformed, or unstable snapshot preserves the
refresh token for a later retry. Authorization codes retain their existing
one-shot exchange behavior, so an unavailable exchange consumes that code but
cannot mint tokens. Introspection response shapes remain unchanged.

`docker compose config --quiet` exited `0`, the focused Kotlin baseline audit
passed `4/4`, and
`docker compose build oauth2-mock` completed successfully. No service was
started or restarted.

## Task 4 live recipient-routing boundary

Postfix now resolves full recipient addresses through:

```text
local_recipient_maps = socketmap:inet:oauth2-mock:10001:eligible
smtpd_reject_unlisted_recipient = yes
smtpd_relay_restrictions = reject_unauth_destination
```

The socketmap listener is internal-only. It accepts bounded netstrings, does
not cache the eligibility authority, and reads its current state before every
exact local eligibility decision. It returns a non-empty `OK` only for an
exact canonical eligible `@local.test` address. Invalid, absent, off-domain,
or protected addresses return `NOTFOUND`; authority unavailability returns
`TEMP`; framing or map-protocol errors return `PERM`.
The protected localparts are `dashboard-management`,
`dashboard-operator-a`, and `dashboard-operator-b`, including every `+`
subaddress. Ordinary `+` subaddresses are not normalized and must themselves
be exact eligible entries.

Each frame has a one-second total read deadline and a 512-byte limit. A
connection handles at most 32 requests, and at most 16 connections are served
concurrently. Idle keep-alives close silently, partial frames fail with a
bounded protocol error, saturated accepts close without an unsolicited
response, and one stalled client cannot serialize another lookup. HTTP
request handlers are threaded but capped at 16 concurrent connections;
overflow closes without a handler thread or reflected request data, capacity
recovers after blocked handlers exit, and the test-only delay knob is capped
at five seconds. Both accept loops use event-polled supervision rather than
potentially blocking shutdown calls: either listener's failure stops the
other, closes both servers, and is propagated. Parsed outcomes log only the
bounded labels `OK`, `NOTFOUND`, `TEMP`, or `protocol-error`; recipient and
raw-payload canaries are absent.

Compose health requires both a bounded OAuth HTTP response and a functional
socketmap request whose exact reply is `NOTFOUND`. Postfix depends directly
on healthy OAuth and Dovecot services, then its entrypoint performs bounded
startup probes for socketmap and LMTP. The resolved Compose JSON proves that
no service publishes target or host port `10001`; the ordinary OAuth
publication remains the reviewed loopback-only HTTP port.

### Task 4 RED/GREEN and build evidence

The first Task 4 stdlib run was intentionally RED at 35 tests with 24
failures: the socketmap symbols, listener, Postfix restrictions, readiness,
and dependencies did not exist. Review-expanded regressions then exposed
persistent-connection, supervision, connection-capacity, protected-address,
outcome-log, and resolved-Compose gaps. The consolidated expanded RED run had
48 tests with 8 failures and 3 errors. An independent review then drove a
49-test RED run with 3 failures and 4 errors around event-polled lifecycle,
observable saturation, and functional health. A second quality review then
drove a 52-test RED run with exactly 2 failures for bounded HTTP concurrency
and a finite delay policy. The final command:

```bash
python3 -B -W error -m unittest oauth2-mock/test_server.py
```

passed `52/52`. It covers fragmented and reused connections, malformed and
oversized netstrings, idle and partial timeouts, independent concurrent
lookups, request/connection caps and recovery, current deletion/update
decisions, exact status semantics, protected subaddresses, safe logs,
bidirectional listener failure, a stop-before-serve race, supervision during
a blocked HTTP handler, bounded HTTP saturation and recovery, finite delay
handling, bounded joins without synchronous shutdown, exact Postfix source
assignments, and the resolved Compose model.

`sh -n postfix/entrypoint.sh` and `docker compose config --quiet` exited `0`.
`docker compose build oauth2-mock postfix` completed successfully. In the
built Postfix image, `postconf -m` includes `socketmap`, while `postconf -n`
shows exactly the three effective recipient/relay lines above. The built
OAuth Python 3.12 source also passed warnings-as-errors compilation.

### Task 4 isolated SMTP proof

The live proof used only Compose project `mail-sandbox-task4-proof`. OAuth and
Dovecot had no host publications; SMTP alone used
`127.0.0.1:21025`. Mail storage and Dovecot logs used disposable named volumes,
while TLS and the copied eligibility authority used proof-owned temporary
directories. The initial Dovecot proof start failed only because the worktree
contains no TLS fixture; bounded logs identified the missing configured
`tls.crt`. A one-day proof-only certificate was generated in the temporary
directory, after which OAuth and Dovecot were healthy.

One disposable address was created through `EligibilityFileCli` with a
generated password supplied only on stdin. Its resulting authority was copied
to the proof runtime; the CLI then removed the feature-runtime entry before
Postfix started, and the verified empty feature authority was removed to
restore the exact pre-proof state. SMTP stopped before DATA and reported:

```text
MAIL FROM:       250
eligible RCPT:   250
absent RCPT:     550 (User unknown in local recipient table)
mailbox entries: 0
```

An explicit `postqueue -p` snapshot was not captured before teardown and is
therefore not claimed as evidence; the proof establishes the required
pre-DATA rejection and empty disposable mailbox volume.

The bounded OAuth log contained only `Socketmap lookup outcome=OK` and
`Socketmap lookup outcome=NOTFOUND`. The proof containers, network, named
volumes, temporary authority, private key, certificate, and override were
then removed. The worktree Dovecot runtime again contains only its original
empty `users.lock`, the worktree `ssl` directory remains empty, and the primary
`postfix-dev`, `dovecot-dev`, `oauth2-mock`, and `stalwart-dev` containers all
remained running with zero restarts.

## Task 5 isolated operator-ingress proof

The operator service uses the same pinned Dovecot 2.4.1 digest as the ordinary
service. It is profile-selected, runs IMAP only, publishes only
`127.0.0.1:2993` to container port `31993`, and is the sole member of the
dedicated `operator-ingress` bridge. The ordinary service never mounts the
operator credential directory or loads a master passdb.

The standalone operator configuration enables SASL LOGIN only. Its effective
passdb order is:

```text
operator-master -> deny-direct -> eligible-target -> deny-missing
```

This order accounts for Dovecot 2.4.1 `auth_preinit` omitting a leading
non-master `skip=unauthenticated` passdb. A verified master continuation skips
`deny-direct`, then must find the target in the shared eligibility authority;
a direct ordinary-password attempt stops at `deny-direct`, while an absent
target reaches `deny-missing`. The operator userdb reads the same eligibility
passwd file.

The authority record was corrected and service-checked as the canonical
eight-column form `<address>:<provider-hash>::::::`. The six empty
post-password columns allow passwd-file userdb to apply the configured
UID/GID/home defaults. Kotlin and Python consume one shared accepted/rejected
shape corpus, including adjacent delimiter boundaries and each non-empty
userdb column. Focused non-live verification passed `115/115`, including the
fake lifecycle suite at `33/33`; the full OAuth
mock/socketmap suite passed `54/54`; and the default, operator-profile, and
proof Compose models all resolved successfully.

The live lifecycle selected only project `mail-sandbox-task5-proof` and exactly
four services:

| Service | Proof publication |
|---|---:|
| ordinary Dovecot IMAPS | `127.0.0.1:1993` |
| operator Dovecot IMAPS | `127.0.0.1:2993` |
| Postfix SMTP | `127.0.0.1:21025` |
| OAuth mock HTTP | `127.0.0.1:28080` |

The reproducible entry point is
`debug-dashboard/dashboard-server/testResources/dovecot-gate0c/run-task5-proof.sh`.
Its checked fail-closed lifecycle accepts no arguments or ambient
Dovecot/Compose/Docker overrides, owns setup and teardown under one trapped
Bash process, and preserves the primary status while independently reporting
cleanup failure. After rejecting every ambient `DOCKER_` variable, it fixes
`DOCKER_HOST=unix:///var/run/docker.sock` for every shell Docker/Compose and
Kotlin subprocess; the active Docker context is never a fallback.
Direct execution through `#!/bin/bash -p` suppresses `BASH_ENV`, imported
functions, and inherited shell options before the first body statement. That
privileged stage rejects arguments and ambient routing, then re-executes
`/bin/bash -p` through absolute `/usr/bin/env -i` with validated `HOME` and
`TMPDIR`, an internal stage marker, and only the fixed trusted PATH. The clean
stage revalidates `HOME`/`TMPDIR` and validates its raw NUL-delimited
environment, exact PATH, traps, and function table before disabling
tracing/automatic export and de-exporting global and function-local token
holders. Process coverage injects a hostile
`BASH_ENV` DEBUG trap plus exported `stat` and `docker` functions and proves
none execute or observe either generated ownership token.

Before its first Docker query, the script validates the exact physical
`/private/tmp` parent, generates an unexported random 64-hex nonce, and
exclusively creates the fixed mode-`0700` host-global lifecycle lock
`/private/tmp/mail-sandbox-task5-proof.lifecycle.lock`. The lock binding is a
readonly literal with no runtime override, so distinct checkouts, worktrees,
and clones targeting the fixed local daemon and Compose project serialize on
one lease. The nonce plus captured directory and mode-`0600` marker
device/inode identities authorize every mutation. The checkout-local proof
root is also created only by exclusive `mkdir`, then receives its own distinct
token, marker identity, and directory identity before any child writer runs. A
collision, symlink, unsafe parent, entropy failure, mode change, marker
replacement (even with a copied token), or directory replacement is rejected
without adopting or deleting foreign state.

Non-live fake-command mutation and concurrent-process tests prove failed
inventories, port collisions, incomplete baselines, foreign root insertion,
main failures, lock/root replacement, and cleanup failures cannot advance or
produce a false-success result. A two-physical-repository fixture shares one
fake daemon and patched global lock: its contender performs no Docker, Kotlin,
Compose, or proof-root mutation while the holder owns the lease, then succeeds
after exact release. INT and TERM delivered after the global-lock `mkdir` but
before parent ownership publication are deferred until exact owned cleanup,
then return `130` and `143`; a failed `mkdir` that leaves an unowned path is
reported and retained. If that critical operation also fails, its nonzero
status remains primary over the queued signal. The signal fixtures run each
lifecycle in a separate session and signal its entire process group, matching
terminal delivery: critical and cleanup children inherit ignored INT/TERM
while the parent records the first signal. Baseline `mktemp`, parent path and
creation-state publication, and owner-only mode validation use the same
deferred transition: INT/TERM after the directory is created cannot kill the
allocation or mode children, and cleanup removes the recorded incomplete
baseline before returning `130`/`143`. Signals delivered while Compose `down`
is paused cannot
interrupt the later inventories, baseline comparison, proof-root removal, or
lock release. A primary `23` remains primary, while a signal becomes the exit
status only after otherwise-successful mandatory cleanup. Root writers require
both current lock and root ownership;
Compose mutation requires current lock ownership. Read-only resource
inventories and the original baseline comparison still run after ownership
loss. The exact lock is released last, after marker/inode and exact-content
allowlist validation, by removing only `owner` and applying `rmdir`, and only
when all cleanup checks pass; otherwise it and any ambiguous root remain as
manual-recovery evidence. The script uses the health-safe
optional-state inspect template, starts only the two explicitly reviewed
service sets, and selects only the startup live class. Initial and cleanup
inventories require both empty project-label queries and successful full name
listings with exact-line absence of all four fixed containers, both fixed
networks, and both fixed volumes; near-name matches do not collide, while
missing or different labels cannot hide an exact fixed resource.

`DovecotOperatorStartupLiveTest` passed `1/1`. It proved:

- an eligible disposable target's own generated password is rejected at the
  operator endpoint;
- `AUTH=LOGIN` is available while `AUTH=PLAIN` and the PLAIN authorization-ID
  master form are rejected;
- the combined `target*dashboard-operator-a` SASL LOGIN succeeds and lists
  `INBOX`;
- ordinary Dovecot, Postfix, and OAuth remain reachable; and
- after the disposable target is removed, operator authentication fails.

Dovecot checks a passwd file at most once per `ioloop_time` wall-clock second.
The post-delete assertion therefore retries only a stale `Success`, using a
fresh consumable credential per attempt and exactly six conditional
250-millisecond delays across seven bounded probes. Authentication failure
completes immediately; protocol, transport, and interruption failures remain
fail-fast, with interruption status restored.

After the proof, the bootstrap eligibility was removed through the Kotlin
writer. All four proof containers, both proof networks, both named volumes,
the proof authority, operator raw secret/hash, Maildir/log data, certificate,
and private key were removed. Ports `1993`, `2993`, `21025`, and `28080` were
free. The five pre-existing containers retained their exact IDs, `StartedAt`,
running/health state, and zero restart count. No Stalwart service was selected,
stopped, restarted, recreated, or otherwise mutated.

## Task 6 isolation and rotation implementation

The existing `DovecotOperatorCredentialStore` remains the sole credential
writer and holds its process plus file lock from state read through final
verification. Its durable repository now owns the typed bounded reads, atomic
replace/delete operations, temporary recovery, permission checks, directory
fsyncs, and a ref-counted process-lock registry that evicts idle path keys. A
pure rotation projection classifies the accepted durable states into explicit
rollback or forward phases before mutation. Rotation uses the fixed, unmounted,
owner-`0600` `dovecot-operator-rotation` intent with the complete grammar `a:b`
or `b:a`. The public boundary remains limited to
`rotateOrRecover(target, runtime)` and `recoverRotation(target, runtime)`.

The implemented A/B sequence is:

1. generate and hash a distinct inactive credential;
2. durably publish intent, inactive raw slot, and ordered old/new hashes;
3. require a bounded fresh-credential IMAP login, `LIST`, read-only `EXAMINE`,
   non-empty `UID SEARCH ALL`, and
   `UID FETCH <first-uid> (BODY.PEEK[HEADER.FIELDS (MESSAGE-ID)])`; the fetched
   literal must contain one syntactically valid `Message-ID`;
4. switch the active reference, copy the credential into the application
   generation holder, and verify a fresh application-owned lease;
5. block and synchronously drain all adapter-owned old-generation sessions;
6. publish only the new hash, require bounded old rejection and new
   acceptance, then delete the old raw slot; and
7. verify the stable projection while the original intent still exists,
   delete intent last, and strictly re-read the one-slot/one-hash result.

The isolation proof does not treat an empty new Maildir as a successful read.
After adding its disposable eligible target, it uses the same pinned operator
transport to append one deterministic, complete RFC 5322 message, closes that
seed session, and then gives the strict full-read probe a separately loaded
credential. The APPEND helper has one five-second total deadline beginning
before byte-oriented message validation and asynchronous transport allocation
and continuing through every authentication, write, flush, APPEND, and response
read. Its coordinator rejects exhausted capacity before transport allocation,
late or duplicate allocations self-close, and successful completion
atomically disarms the remaining deadline. Invalid timeout and all other
pre-open failures still close the credential and wipe the caller's message.
The message remains bounded at 16 KiB and requires exactly one of every fixed
header without first materializing the payload as an immutable string. The
caller also closes the seed session and repeats credential/payload cleanup in
`finally`. The add-attempt marker is set before eligibility mutation, so
cleanup re-reads membership and removes a target even if the add landed before
returning failure; the checked disposable lifecycle owns removal of its
Maildir volume. Zero `EXISTS` and `RECENT` notifications are valid mailbox
metadata. The probe carries the latest exact `EXISTS` count through
`EXAMINE`, `UID SEARCH`, and `UID FETCH`: `EXISTS` may stay level or increase,
an exact `EXPUNGE` decrements it, and a fetch after the count reaches zero is
rejected unless a later positive `EXISTS` arrives. Zero or leading-zero
`FETCH` sequence numbers and an empty or malformed UID search also fail
closed.

The production probe, Held helpers, and raw HTTP client share one process-wide
`DovecotBoundedOperationWorkers` coordinator with a hard capacity of four
logical network operations. Each admitted operation owns one serialized daemon
I/O worker and may register at most two identity-distinct cancellation targets.
Abort and close actors are started lazily and independently for each target, so
one operation owns at most five actors and the process-wide maximum is twenty.
Admission occurs after the absolute monotonic deadline is created but before
credential access, transport/socket allocation, or another actor. A fifth
operation therefore fails before its resource factory runs.

Timeout, interruption, and generic failure move a reservation from active to
abandoned; they do not release it. The reservation remains charged until the
I/O worker and every started cancellation actor actually exit. Connect/open,
read, write, flush, and explicit close all run on the serialized I/O worker,
while caller waits use the one original absolute deadline without a watcher
thread. Worker-owned request copies are wiped whether a task runs or is
declined. Read results use a one-winner handoff; a declined or late result is
wiped on its worker before the operation can release.

Probe and Held cancellation dispatch `abort` and `close` independently and
wait only within the original deadline and a smaller fixed cleanup budget.
Blocked original I/O plus blocked abort and close can consume a charged
reservation, but cannot hold the caller or grow actors past the fixed cap. A
later successful Held cancellation still publishes terminal session state,
while lease-owned explicit `close()` remains synchronous and retryable. Caller
interruption is checked before open/seed allocation, held-session I/O,
closed-session validation, or HTTP socket allocation. For Held and HTTP proof
helpers, even a generic `IOException` or `SocketException` observed with the
caller flag set becomes a new redacted `InterruptedException` with the flag
restored after bounded cleanup; it cannot be mistaken for proof failure or
closed-transport evidence. The production probe instead restores the caller
flag and returns its typed `TransportFailure`.

The rotation proof holds an actual authenticated old-ID IMAP session rather
than a callback-only stand-in. It appends the deterministic read fixture,
proves every `NOOP` write, flush, and read under one coordinator-bound deadline,
registers its real close operation with the old-generation application lease,
and checks the closed transport in a fresh bounded operation before old
credential revocation.

No auth-cache flush, service restart, or recreation is part of convergence.
Each passwd-file observation has at most seven attempts and six conditional
250-millisecond delays. Acceptance retries only authentication failure;
rejection retries only success. Protocol, transport, and interruption fail
immediately, and each attempt owns and wipes a fresh consumable credential.
The lease registry admits at most 15 ordinary application sessions and
reserves the sixteenth tracked slot for the one fresh verification lease.
Application-generation publication and registry activation occur under one
atomic boundary. Runtime close has terminal open/closing/closed state, rejects
and wipes every activation once close begins, and makes concurrent or later
close callers observe the retained terminal outcome. A generation cannot be
activated during its drain. All callers joining one lease close observe the
same attempt, so an ordinary close racing a drain is not a false drain failure.
Old-session closes are submitted concurrently in a per-drain bounded daemon
session and all drain callers share the first caller's one-second deadline;
timeout or any close failure stops rotation before revocation and leaves the
failed lease tracked for explicit retry. Uncooperative callbacks therefore
cannot consume a global close-executor capacity needed by later drains.

Recovery is deterministic: active-old rolls back and active-new completes
forward. It rejects malformed, reversed, duplicate, symbolic, wrong-mode,
oversized, impossible, changed-intent, and identical-raw-slot states. Failed
session closes remain tracked for a later drain attempt. Active-old recovery
first publishes old-only hashes, then repeatedly proves the staged credential
is rejected and the old credential is accepted with fresh wiped credentials
before deleting the staged raw slot or intent. A failed inverse proof retains
both for explicit retry, including when a restart finds the master file already
old-only. Strict hash verification precedes runtime calls or mutation for every
recoverable projection, including corrupt and misrouted slots. Failed atomic
writes retain their exact canonical temporary; only explicit recovery may
remove a recognized owner-only bounded temporary, with observer points around
that deletion. Snapshot recovery from every durable and semantic observer
boundary converges using a fresh store.

The proof override adds only ordinary POP3S
`127.0.0.1:21995 -> 31990`, a read-only fixed network helper in the existing
OAuth container, and the explicit `task6-host-gateway` host-gateway alias.
The helper takes one operator-ingress IPv4 and all discovered non-loopback host
IPv4 addresses through bounded stdin. From the default network it requires
ordinary Dovecot as a positive control, then rejects operator DNS, direct
operator-ingress IP, Docker Desktop gateway names, the explicit host-gateway
alias, and every supplied host address to port `2993`. The Kotlin live matrix
also requires exact runtime publications and network membership, rejects
non-loopback host access to `1993` and `2993`, and proves the master credential
inactive through ordinary IMAPS, ordinary POP3S, Postfix SMTP SASL, and OAuth.
Its raw LOGIN matrix submits the active secret against the other fixed,
inactive `DovecotOperatorId.masterUsername` suffix, independently of the
absent-master, master-as-self, and revoked-old rows. SMTP rejection requires
one terminal `535 <text>` line whose text is HTAB or printable US-ASCII;
`5350...`, `535-...`, empty text, and control-byte lookalikes are
indeterminate rather than accepted rejection evidence.
IMAP and POP3 rejection count as permanent only for their exact tagged
`[AUTHENTICATIONFAILED]` and `-ERR [AUTH]` response forms; unavailable,
temporary, server, bare, malformed, and misleading responses are indeterminate.
OAuth introspection requires one actual JSON boolean `"active": false`;
authorization denial requires the exact fixed
`http://127.0.0.1/callback` origin and path without a port, user information, or
fragment, then parses percent-decoded unique query fields and requires exact
`error=access_denied` plus `state=task6` without any decoded `code` key. A fixed
loopback HTTP/1.0 client acquires the shared coordinator before socket
allocation, registers that socket before connect, and applies one deadline
across connect, both request writes, flush, status, headers, fixed-length or
close-delimited body, and successful socket close. It bounds the status line,
each header line, cumulative header bytes and count, `Location`, declared or
close-delimited body, and rejects duplicate framing headers or transfer
encoding. A fixed-length collector transfers its owned array to the response,
which wipes it on ordinary close; the close-delimited scratch array is wiped
after copying. Collector failure and late result disposal also wipe the owned
array. The fixed Python network helper arms its process-local wall deadline
before argument processing and the bounded stdin read, so a blocked producer
cannot escape the deadline. The two live scenarios now retain only
orchestration; protocol, HTTP, mailbox, process, topology, held-session, and
deadline logic are separate focused components.

### Task 6 non-live evidence and pending live proof

Focused test-driven runs and reciprocal review exposed missing read-probe
support, the impossible empty-mailbox isolation flow, unsafe rollback deletion
before inverse authentication, corrupt or misrouted durable states reaching
runtime work, non-terminal lease/runtime and held-session close outcomes,
overly permissive authentication and OAuth response classification, and HTTP
operations without one total deadline or complete header/body bounds. The
repair review then exposed unbounded reusable/watchdog and cancellation actors,
missing process-wide admission, generic I/O failures taking precedence over a
flagged interruption, incomplete real-collector ownership evidence, a
temporary one-byte repository read without observable wiping, source-text
live-proof assertions, and cleanup that could miss an add which mutated before
returning failure.

Adversarial review approved the coordinator integrations, actual HTTP
collector ownership, repository/terminal replay, and executable live fixtures
with no remaining finding. Focused non-live selections passed:

- HTTP plus coordinator boundaries: `35/35`;
- durable repository plus terminal runtime replay: `12/12`;
- executable isolation-fixture contracts: `5/5`;
- the complete Held deadline class: `26/26`; and
- the Probe-to-HTTP cross-class ordering check: `39/39`.

The current 13-class reciprocal run passed `159/159`:

- the bounded operation coordinator: `19/19`;
- credential recovery, rotation projection, durable repository, and
  application leases: `52/52`;
- exact auth classification and the fixed operator probe: `25/25`;
- OAuth redirect/JSON validation and bounded HTTP transport: `16/16`;
- held-session, deadline, and mailbox contracts: `36/36`; and
- bounded process and topology proofs: `11/11`.

Under the no-Docker verification boundary, the non-live Dovecot class run
passed `236/236` and the 13 non-daemon static/config selectors passed `13/13`,
for `249/249` with zero skips. The four effective-configuration selectors
that invoke `docker run` were not executed. The wider `dashboard-server`
non-live run passed `501/501`, plus a second `13/13` run of those same
selectors, for `514/514`; it excluded all `*LiveTest` classes, the production
browser gate that requires generated `DASHBOARD_WEB_ASSETS`, and the mixed
Docker-backed config class from the broad scan. The independent Python helper
passed `21/21`, and `./kotlin build --module dashboard-server` completed
successfully.

Task 6 live evidence is **pending**, not passed. No Docker daemon or live
service operation was performed while implementing this task. A controller
must run the single checked lifecycle:

```bash
debug-dashboard/dashboard-server/testResources/dovecot-gate0c/run-task5-proof.sh
```

That lifecycle owns startup, runs startup then isolation then rotation live
classes, and performs mandatory cleanup and baseline comparison. If any
bridge, host-gateway, LAN, ordinary-protocol, SMTP, or OAuth path accepts or
reaches the operator credential/port contrary to the matrix, Task 6 is
`BLOCKED/STOP`; the assertion must not be weakened or skipped.

## Verification

The focused audit command is:

```bash
cd debug-dashboard
./kotlin test \
  --include-module dashboard-server \
  --include-classes \
  'mail.sandbox.dashboard.server.gate.dovecot.DovecotBaselineConfigAuditTest'
```

The final run passed `4/4` with zero skipped or failed. It verifies the pinned
Dovecot image inside the Dovecot service, exact service-scoped port lists
(including rejection of duplicates or unreviewed syntax), absence of every
fixed container name, absence of deferred eligibility hazards, and exactly
one assignment for each required Postfix recipient restriction.

`docker compose config --quiet` exited `0`. The expanded
`docker compose config` model was inspected with secret-bearing environment
values redacted and showed:

- the exact pinned Dovecot image and digest;
- no `container_name` field on any service;
- `host_ip: 127.0.0.1` with the exact published/target pairs for all four
  ordinary Dovecot ports, all three Postfix ports, and the OAuth port.
- no publication whose target or host port is `10001`;
- direct healthy Postfix dependencies on OAuth and Dovecot, with OAuth health
  checking HTTP plus an exact functional socketmap request and response.

The unchanged Stalwart publication is outside the Task 1 port scope; only its
fixed container name was removed. Task 4 used only the isolated project
documented above. No primary-stack `up`, `down`, `restart`, live Stalwart
access, or Stalwart data operation was performed.
