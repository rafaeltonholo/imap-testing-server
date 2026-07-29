# Gate 0C — Dovecot identity and operator ingress

## Status

- **Task 1 — Freeze and inspect the Dovecot baseline:** complete.
- **Task 2 — Replace tracked plaintext runtime authority:** complete.
- **Task 3 — Make OAuth decisions eligibility-aware:** complete.
- **Task 4 — Make Postfix recipient routing eligibility-aware:** complete.
- **Gate 0C:** in progress. Tasks 5–9 still own the
  operator-ingress, lifecycle, and final decision work. This document does not
  record a Gate 0C PASS.

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
