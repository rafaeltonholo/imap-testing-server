# Gate 0C — Dovecot identity and operator ingress

## Status

- **Task 1 — Freeze and inspect the Dovecot baseline:** complete.
- **Task 2 — Replace tracked plaintext runtime authority:** complete.
- **Gate 0C:** in progress. Tasks 3–9 still own the OAuth, Postfix,
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
| A prefix token can make an arbitrary identity active | `oauth2-mock/server.py` returns `active: True` for every `token.startswith("valid-")` suffix | Task 3 | Characterized only; unchanged |
| Postfix accepts arbitrary local recipients | `postfix/main.cf` has empty `local_recipient_maps` and `smtpd_reject_unlisted_recipient = no` | Task 4 | Characterized only; unchanged |
| Ordinary mail/OAuth host publications were wildcard-bound | Baseline Compose mappings omitted a host address for Dovecot, Postfix, and OAuth | Task 1 | Replaced with the exact loopback mappings below |
| The Dovecot image floated and services had fixed names | Baseline used `dovecot/dovecot:latest` and four `container_name` directives | Task 1 | Image pinned; all fixed names removed |

The focused Kotlin audit now keeps the two remaining deferred conditions
visible as explicit Task 3/4 assignments. Its Task 1 assertions initially failed for
the floating image, wildcard/legacy port mappings, and four fixed container
names: 1 test passed and 3 failed. This is the intentional RED evidence.
The deferred assertions are temporary characterization, not desired
invariants: Tasks 3 and 4 must remove their entries during their own RED/GREEN
remediation. Task 2 removed the former static-userdb characterization after
replacing that boundary.

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
fixed container name, and the temporary Task 3/4 hazard characterization.

`docker compose config --quiet` exited `0`. The expanded
`docker compose config` model was inspected with secret-bearing environment
values redacted and showed:

- the exact pinned Dovecot image and digest;
- no `container_name` field on any service;
- `host_ip: 127.0.0.1` with the exact published/target pairs for all four
  ordinary Dovecot ports, all three Postfix ports, and the OAuth port.

The unchanged Stalwart publication is outside the Task 1 port scope; only its
fixed container name was removed. No `docker compose up`, `down`, `restart`,
live Stalwart access, or Stalwart data operation was performed.
