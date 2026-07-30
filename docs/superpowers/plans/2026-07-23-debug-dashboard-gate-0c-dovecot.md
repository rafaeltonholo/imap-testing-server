# Debug Dashboard Gate 0C — Dovecot Identity and Operator Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make one hashed runtime eligibility set authoritative across every Dovecot/Postfix/OAuth path and prove an isolated master/operator IMAP ingress can safely administer disposable accounts without retaining user passwords.

**Architecture:** The ordinary Dovecot container never loads a master passdb. A
second Dovecot instance shares the read-only eligibility directory and Maildir
volume but loads a separate hashed master credential, runs IMAP only, binds its
IMAPS listener to container loopback, joins an internal Docker bridge whose
sole service member is the operator, and publishes no host port. The host-native
dashboard reaches it only through the fixed, TLS-verifying,
Docker-exec/stdio transport in
`docs/superpowers/specs/2026-07-30-dovecot-operator-stdio-transport-design.md`.
Postfix and the OAuth mock consult the same atomic eligibility file on every
decision; dashboard/file tools share an OS-visible global lock.

**Tech Stack:** Pinned `dovecot/dovecot:2.4.1` image/digest, Dovecot 2.4 passwd-file/master auth, isolated Docker Compose network, Postfix socketmap, Python standard-library OAuth/socketmap service, Kotlin/JVM gate writer and live tests.

---

## Task 1: Freeze and inspect the Dovecot baseline

**Files:**

- Modify: `docker-compose.yml`
- Create: `docs/debug-dashboard/gates/0c-dovecot.md`

- [ ] Record the currently resolved image/version/config before editing:

```bash
docker image inspect dovecot/dovecot:latest --format '{{json .RepoDigests}}'
docker compose run --rm dovecot dovecot --version
docker compose run --rm dovecot doveconf -n
```

Expected baseline: Dovecot `2.4.1`. Pin:

```yaml
image: dovecot/dovecot:2.4.1@sha256:1296e0f1029cdd95e6849fb82f5d142a6e2a46218451773316cea678de75254b
```

If the digest does not resolve to the expected multi-architecture 2.4.1 image on this host, stop and record the observed platform digest rather than using `latest`.

- [ ] Add a failing configuration audit test (initially documentation/manual assertions are acceptable before the Kotlin module exists) showing the current hazards:

  - `userdb static` accepts non-existent targets;
  - `valid-<anything>` OAuth introspection can be active;
  - empty `local_recipient_maps` plus disabled unlisted-recipient rejection accepts arbitrary local recipients;
  - relevant host port publications use wildcard addresses.

- [ ] Change every ordinary Dovecot, Postfix, and OAuth host publication to loopback high ports: IMAP `1143`, IMAPS `1993`, POP3 `1110`, POP3S `1995`, SMTP `1025`, SMTPS `1465`, submission `1587`, and OAuth `8080`. Remove fixed `container_name` values so disposable Compose project names remain isolated.

- [ ] Run:

```bash
docker compose config --quiet
docker compose config
```

Expected: valid model, pinned image, and no `0.0.0.0`/`[::]` dashboard-relevant host publication.

## Task 2: Replace tracked plaintext runtime authority

**Files:**

- Create: `config/users.seed`
- Delete: `config/users`
- Modify: `config/10-auth.conf`
- Create: `config/20-doveadm.conf`
- Modify: `docker-compose.yml`
- Modify: `.gitignore`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/gate/dovecot/EligibilityEntry.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/gate/dovecot/EligibilityFile.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/gate/dovecot/EligibilityFileCli.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/EligibilityFileTest.kt`

- [ ] Convert `config/users` to a non-secret seed containing canonical addresses only. Ignore:

```text
debug-dashboard/.runtime/dovecot/
debug-dashboard/.runtime/dovecot-operator/
debug-dashboard/.runtime/secrets/
```

Never generate a tracked default password.

- [ ] Add `/config/users` to the root `.gitignore` so a stale script cannot recreate and stage the old plaintext authority; keep `config/users.seed` tracked.

- [ ] Write failing Kotlin tests for parsing the Dovecot 2.4 passwd-file line shape, allowed scheme-prefixed hashes, exact address uniqueness, comments/blank lines, restrictive regular-file path, non-symlink components, mode/ownership preservation, newline/delimiter/path injection, and deterministic rendering.

- [ ] Add cross-process concurrency/fault tests requiring one `FileChannel.lock()` from read through verification, a restrictive same-directory temporary, file `fsync`, atomic replace, parent-directory `fsync` where supported, and abandoned-temporary cleanup. Simulate crashes before and after replace.

- [ ] Implement the fixed canonical file `debug-dashboard/.runtime/dovecot/users` plus stable lock `debug-dashboard/.runtime/dovecot/users.lock`. `EligibilityFileCli` may seed/add/reset/remove/list through the same writer; secrets arrive through stdin and are cleared. It must not accept arbitrary file paths.

The canonical record is `<address>:<provider-hash>::::::`: eight passwd-file columns (`user`, `password`, `uid`, `gid`, `gecos`, `home`, `shell`, and `extra_fields`). The six post-password fields are empty because Dovecot configuration supplies the UID, GID, and home defaults; their delimiters are still required so passwd-file userdb recognizes the record.

- [ ] Mount the containing `debug-dashboard/.runtime/dovecot` directory read-only into the ordinary Dovecot container. Do not bind-mount the file itself: atomic replacement must remain visible inside the container.

- [ ] Replace `userdb static` with the Dovecot 2.4 passwd-file boundary below; retain the existing OAuth passdb after it:

```dovecot
passdb passwd-file {
  passwd_file_path = /etc/dovecot/runtime/users
}

passdb oauth2 {
  mechanisms_filter = xoauth2 oauthbearer
}

userdb passwd-file {
  passwd_file_path = /etc/dovecot/runtime/users
  fields {
    uid:default = 1000
    gid:default = 1000
    home:default = /srv/vmail/%{user}
  }
}
```

The gate must compile-check the exact 2.4.1 `:default` syntax with `doveconf -n`. All successful password/OAuth auth continues through exact userdb existence.

- [ ] Use `doveadm pw -s ARGON2ID` through its proven twice-over-stdin channel and validate the `{ARGON2ID}` output. Seed runtime hashes from an explicit one-time password prompt/owner-readable secret—not the removed tracked values.

- [ ] Disable the image-provided network `doveadm` HTTP listener in `config/20-doveadm.conf` by overriding its observed listener to `port = 0`; compile-check the resolved service with `doveconf -n`. Administration remains fixed, typed `docker compose exec -T dovecot doveadm ...` only.

- [ ] Run:

```bash
cd debug-dashboard
./kotlin test --include-module dashboard-server --include-classes 'mail.sandbox.dashboard.server.gate.dovecot.EligibilityFileTest'
cd ..
docker compose run --rm dovecot doveconf -n
```

Expected: tests pass; both passdb and userdb point at the runtime eligibility file; no static userdb.

## Task 3: Make OAuth issuance, refresh, and introspection eligibility-aware

**Files:**

- Modify: `oauth2-mock/server.py`
- Create: `oauth2-mock/test_server.py`
- Modify: `oauth2-mock/Dockerfile`
- Modify: `docker-compose.yml`

- [ ] Using the `python-scripts` and `oauth2` repository skills, write failing stdlib `unittest` cases for an injectable eligibility reader:

  - authorization rejects a non-eligible username;
  - auth-code exchange rechecks eligibility;
  - refresh rechecks eligibility;
  - stored and prefix-style `valid-<username>` introspection rechecks eligibility;
  - deleted identities become inactive immediately;
  - malformed/symlink/unreadable eligibility fails closed;
  - normal expired/scope/invalid test-token behavior remains.

- [ ] Implement a canonical, read-only eligibility reader. Mount only the eligibility directory into `oauth2-mock`; never expose the operator secret directory.

- [ ] Ensure responses/logging never echo bearer, auth code, refresh, or password values.

- [ ] Run:

```bash
python3 -m unittest oauth2-mock/test_server.py
docker compose build oauth2-mock
```

Expected: tests/build pass.

## Task 4: Make Postfix recipient routing consult the same live authority

**Files:**

- Modify: `oauth2-mock/server.py`
- Modify: `oauth2-mock/test_server.py`
- Modify: `postfix/main.cf`
- Modify: `postfix/entrypoint.sh`
- Modify: `docker-compose.yml`

- [ ] Write failing stdlib tests for the Postfix socketmap netstring protocol. Only exact canonical eligible local addresses return `OK`; absent/malformed/protected addresses return `NOTFOUND`; an unreadable authority returns `TEMP`. Bound request length and reject malformed netstrings.

- [ ] Run the socketmap listener on an internal container port, reading the current eligibility file for each lookup (or a file-change-safe cache). Do not publish this port to the host.

- [ ] Configure:

```text
local_recipient_maps = socketmap:inet:oauth2-mock:10001:eligible
smtpd_reject_unlisted_recipient = yes
```

Keep off-domain relay rejection. Remove permissive settings that can queue arbitrary `local.test` recipients.

- [ ] Start the disposable stack and test SMTP RCPT for one eligible and one absent recipient. Expected: eligible accepted; absent rejected before DATA with a 5xx unlisted-recipient response; no mailbox directory is created.

- [ ] Run:

```bash
python3 -m unittest oauth2-mock/test_server.py
docker compose config --quiet
docker compose up -d --build oauth2-mock dovecot postfix
docker compose logs --no-color --tail 100 oauth2-mock postfix
```

Review the bounded logs for correct lookup outcomes and no secret values.

## Task 5: Add a physically separate master-only IMAP ingress

**Files:**

- Create: `config/operator/dovecot.conf`
- Modify: `docker-compose.yml`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorProbe.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorCredentialStore.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorConfigTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorCredentialStoreTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorStartupLiveTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorRemovalRejectionPolicyTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotLiveTestEnvironment.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotTask5ProofLifecycleTest.kt`
- Create: `debug-dashboard/dashboard-server/testResources/dovecot-gate0c/run-task5-proof.sh`

- [ ] Add a second `dovecot-operator` service using the exact same pinned image. It:

  - mounts the shared `debug-dashboard/.runtime/dovecot` directory and `vmail/`;
  - additionally mounts `debug-dashboard/.runtime/dovecot-operator/` containing the ARGON2ID master passwd file;
  - starts from the standalone `config/operator/dovecot.conf`;
  - runs IMAP only;
  - publishes no host port and sets exact `listen = 127.0.0.1` on its
    container-side IMAPS listener at `31993`;
  - joins only a dedicated internal `operator-ingress` bridge with no other
    service;
  - has a bounded, quiet POSIX `sh` healthcheck that requires a positive
    integer `process_count`, exact `throttle_secs: 0`, and exact
    `doveadm_stop: n` for both `auth` and `imap-login`. It captures each
    `doveadm service status` result before applying exact checks, so any query
    or check failure fails health without relying on non-POSIX `pipefail`. It
    counts every state `0A` entry for port `7CF9` across `/proc/net/tcp` and
    `/proc/net/tcp6`, requires exactly one, and requires exact local address
    `0100007F:7CF9`. It generates no recurring auth/login traffic and remains
    bounded by the fixed three-second timeout; coordinator-backed
    Docker-exec/stdio readiness remains the end-to-end gate; and
  - is excluded from the default clean Compose model behind the explicit `dovecot-operator` profile. The fixed Task 5 proof override clears this production profile because that lifecycle selects the operator service explicitly.

The ordinary `dovecot` service never mounts or loads the master credential directory/passdb.
No other Compose service joins the internal operator bridge. The former host
port `2993` is reserved only as a forbidden negative-probe target; every
positive operator path uses the fixed transport amendment.

- [ ] Configure the operator master passdb as `master = yes` with canonical
  `result_success = continue`, followed by the exact four-stage chain
  `operator-master` → `deny-direct` → `eligible-target` → `deny-missing` and
  then exact userdb lookup against the shared eligibility file. Dovecot 2.4.1
  `auth_preinit` silently omits a first non-master passdb with
  `skip = unauthenticated`, so `deny-direct` is the first non-master passdb and
  uses `skip = authenticated`. The canonical `result_success = continue`
  marks the master password verified, jumps to the first non-master passdb,
  and does not pre-authorize the target. A verified master continuation
  therefore skips `deny-direct`, while a direct bare-target LOGIN remains
  unauthenticated and stops there. `eligible-target` uses
  `skip = unauthenticated`, `result_failure = continue-fail`, and
  `result_internalfail = return-fail`. A found target's default `return-ok`
  finalizes master authentication; a missing target clears any prior success
  and continues to `deny-missing`; an internal eligibility error fails
  immediately instead of being masked. Both deny passdbs set `deny = yes`,
  `nopassword = yes`, and `nodelay = yes`. Enable only the SASL `LOGIN`
  mechanism. The probe must issue `AUTHENTICATE LOGIN` and answer its username
  challenge with exactly `target*dashboard-operator-a` or
  `target*dashboard-operator-b`; it must not use the IMAP `LOGIN` command,
  which Dovecot implements through SASL PLAIN. SASL `LOGIN` has no separate
  authorization-ID field, so the combined username is the only master-login
  form available. Do not enable PLAIN: it would also permit the forbidden
  authorization-ID form
  `target\0dashboard-operator-a\0master-secret`. The live proof must first
  issue bare-target SASL LOGIN with the eligible disposable target's generated
  password and require a tagged `NO` within the coordinator-backed fixed
  exchange deadline. It must then require `AUTH=LOGIN`, reject `AUTH=PLAIN`,
  receive an immediate tagged `NO` or `BAD` for the PLAIN tuple, and prove the
  positive combined master form.

  These two immutable protected master identities are not present in normal passdb/userdb and have no mailboxes. Exactly one identity is active at steady state; both may coexist only inside the locked rotation window.

The critical standalone auth block is:

```dovecot
protocols = imap
auth_mechanisms = login
auth_allow_cleartext = no
auth_master_user_separator = *
auth_username_format = %{user}

passdb operator-master {
  driver = passwd-file
  passwd_file_path = /etc/dovecot/operator-auth/master-users
  master = yes
  result_success = continue
}

passdb deny-direct {
  driver = static
  deny = yes
  skip = authenticated
  fields {
    nopassword = yes
    nodelay = yes
  }
}

passdb eligible-target {
  driver = passwd-file
  passwd_file_path = /etc/dovecot/runtime/users
  skip = unauthenticated
  result_failure = continue-fail
  result_internalfail = return-fail
}

passdb deny-missing {
  driver = static
  deny = yes
  fields {
    nopassword = yes
    nodelay = yes
  }
}

userdb passwd-file {
  passwd_file_path = /etc/dovecot/runtime/users
  fields {
    uid:default = 1000
    gid:default = 1000
    home:default = /srv/vmail/%{user}
  }
}
```

Also configure mail/namespace/TLS/stdout logging explicitly and omit OAuth, POP3, LMTP, auth-inet, submission, and network doveadm listeners.

- [ ] Reserve gitignored raw-secret slots `debug-dashboard/.runtime/secrets/dovecot-operator-a` and `dovecot-operator-b`, plus an atomic `dovecot-operator-active` reference containing only `a` or `b`; every file is mode `0600` and never mounted into a container. Put only the active slot's ARGON2ID hash in `debug-dashboard/.runtime/dovecot-operator/master-users` at steady state. The gate process reads the active slot through a symlink-rejecting fixed-path loader and clears transient in-memory copies after use.

- [ ] Implement the credential store's fixed-path/mode/symlink/atomic-write checks now, with a unit test. Its initial bootstrap creates slot A, hashes through the stdin-only path, atomically writes the one-entry `master-users`, and writes the matching active reference before the operator service starts. Task 6 extends this same store with rotation; it must not introduce a second writer.

- [ ] Write configuration tests that fail if the primary config contains a
  master passdb, the operator enables POP3/LMTP, either protected master
  appears in the user registry, an unknown master identity appears in the
  master file, the operator joins the default network, its container listener
  is not exact loopback, or it has any host publication.

- [ ] Make every selected Dovecot `*LiveTest` use
  `DovecotLiveTestEnvironment`. It requires `DOVECOT_LIVE_TESTS=1`, bounded
  readiness of the exact ordinary loopback endpoints, and
  coordinator-backed exec/stdio readiness for the operator. Missing
  configuration or an unavailable ordinary/operator/Postfix/OAuth service
  fails the selected suite rather than skipping.

- [ ] Preserve this staged activation invariant: first validate the ordinary
  Tasks 2–4 authority, eligibility file, and TLS material; next make only OAuth,
  ordinary Dovecot, and Postfix available; then bootstrap the operator
  credential through the ordinary Dovecot hasher boundary; and only afterward
  make the operator endpoint available. This is explanatory ordering, not a
  second executable workflow. The checked proof script below is Task 5's sole
  mutating invocation. It must never select an unrelated service, and the
  operator remains unavailable until bootstrap atomically installs its
  hash-only `master-users` input. Raw operator secrets remain host-only.

- [ ] After the configuration checks, run only the checked
  `mail-sandbox-task5-proof` fail-closed lifecycle. It accepts no arguments or
  ambient `DOVECOT_`, `COMPOSE_`, or `DOCKER_` overrides and derives every
  fixed path, project, profile, port, and service from its canonical
  non-symbolic repository location. After rejecting ambient Docker routing it
  fixes `DOCKER_HOST=unix:///var/run/docker.sock` for every direct
  Docker/Compose command and Kotlin subprocess; it never falls back to the
  active Docker context. The only supported invocation is direct execution
  through `#!/bin/bash -p`; the privileged first stage suppresses `BASH_ENV`,
  imported functions, and inherited shell options before the body runs. It
  rejects arguments and ambient routing with builtins, then uses absolute
  `/usr/bin/env -i` to re-execute `/bin/bash -p` with only validated
  `HOME`/`TMPDIR`, one internal stage marker, and the fixed trusted `PATH`
  `/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin`. The clean
  stage revalidates `HOME`/`TMPDIR` and validates its raw NUL-delimited
  environment, PATH, traps, and function table before disabling
  tracing/automatic export and de-exporting every global and function-local
  token holder.

- [ ] Run this one exact invocation from the repository root:

```bash
./debug-dashboard/dashboard-server/testResources/dovecot-gate0c/run-task5-proof.sh
```

The script owns preparation, execution, and mandatory cleanup under one Bash
`set -euo pipefail` boundary with `EXIT`, `INT`, and `TERM` handling installed
before mutation. It preserves a primary failure, promotes a cleanup-only
failure to a nonzero result, and reports cleanup failure even when both fail.
The first INT/TERM status is deferred through ownership publication and all
mandatory cleanup; exit precedence is primary failure, then deferred signal,
then cleanup-only failure.
Its invariants are:

- before the first Docker query it validates the exact physical
  `/private/tmp` parent, generates an unexported random 64-hex nonce, and
  exclusively creates the fixed mode-`0700` host-global lifecycle lock
  `/private/tmp/mail-sandbox-task5-proof.lifecycle.lock`. The lock path is a
  readonly literal with no runtime override, so distinct checkouts, worktrees,
  and clones targeting the fixed local daemon/project share one lease. Its
  exact mode-`0600` regular marker, byte-exact nonce, and captured directory
  and marker device/inode identities must all remain current before any
  mutation. A pre-existing, partial, symbolic, remoded, retokened, or replaced
  lock is retained and never stolen. Signals received after exclusive `mkdir`
  but before validated ownership publication are recorded, publication is
  completed, and exact owned cleanup runs before returning `130` or `143`; a
  failed creation that leaves an unowned path is reported and retained, and
  its nonzero operation status remains primary over any queued signal.
  Signal-shielded critical children ignore process-group INT/TERM while the
  parent records the first signal, so terminal delivery cannot kill `mkdir`,
  identity inspection, or marker publication mid-transition.
  Non-live concurrency coverage uses two
  physically distinct fixture repositories with one patched global lock and
  shared fake-daemon state, proves the contender cannot reach Docker, Kotlin,
  Compose, or its proof root while the holder owns the lease, and proves it can
  succeed after exact release;
- the initial project-label container, network, and volume queries must each
  succeed and all be empty before baseline capture. Successful unfiltered name
  listings must also prove exact-line absence of containers
  `mail-sandbox-task5-proof-{dovecot,dovecot-operator,postfix,oauth2-mock}-1`,
  networks `mail-sandbox-task5-proof_{default,operator-ingress}`, and volumes
  `mail-sandbox-task5-proof_task5-proof-{vmail,logs}`, so missing or altered
  labels cannot hide a fixed-name collision;
- `docker ps --quiet` and every per-ID inspection must succeed before the
  baseline becomes valid. Baseline-directory allocation, parent publication,
  and mode validation run under signal deferral; the `mktemp` substitution
  and post-create `chmod` are signal-shielded so process-group INT/TERM cannot
  strand an unrecorded directory. An interrupted successful allocation is
  recorded, reduced to an incomplete baseline during mandatory cleanup, and
  only then returns `130` or `143`, while an allocation/mode failure remains
  primary over a queued signal. The captured ID order is reused after cleanup,
  and exact bytes for ID, `StartedAt`, status, health-or-`none`, and restart
  count are compared with the health-safe template
  `{{with (index .State "Health")}}{{.Status}}{{else}}none{{end}}`;
- ports `1993`, `21995`, `21025`, and `28080` must be queryable and free for
  the proof's ordinary endpoints. Former operator host port `2993` must also be
  queryable and free solely so every forbidden-path negative is unambiguous.
  A collision aborts without stopping its owner;
- `debug-dashboard/.runtime` must already be an exact canonical non-symbolic
  directory and the exact proof root must be absent. The script records its
  creation attempt before exclusive owner-only `mkdir`; it never uses
  directory installation that could adopt a raced path. Only a successfully
  created root with its own exact token, marker device/inode, and directory
  device/inode becomes teardown-owned. Its certificate and private key are
  regular non-symbolic mode-`0600` files, and the Kotlin preflight succeeds
  before any proof service starts;
- the first start is only ordinary `dovecot --no-deps`. The bootstrap password
  is generated and consumed only through pipeline stdin, the operator
  credential is then bootstrapped, and the only full start names exactly
  `dovecot dovecot-operator postfix oauth2-mock`;
- the only live class selected is `DovecotOperatorStartupLiveTest`. It creates
  an eligible disposable target through `EligibilityFileCli`, rejects
  bare-target LOGIN and the PLAIN authorization-ID form, proves the combined
  master LOGIN and mailbox list, and verifies the ordinary Dovecot, Postfix,
  and OAuth endpoints; and
- cleanup attempts bootstrap removal only with current lifecycle-lock and
  proof-root ownership. It runs the exact project
  `down --volumes --remove-orphans` only while lifecycle-lock ownership
  remains current, then independently repeats both label and full exact-name
  inventories for all three resource kinds and compares the original baseline
  even after ownership loss. Root deletion additionally requires exact
  token/inode ownership and proven resource absence. The lock is removed last,
  by deleting only its validated marker and applying `rmdir` to the validated
  lock directory, and only when every cleanup/baseline result succeeded.
  Otherwise the lock and any ambiguous root remain as manual-recovery
  evidence; no PID or stale-age heuristic steals them. Mandatory cleanup runs
  in a signal-shielded child while the parent records process-group INT/TERM;
  `down`, resource inventories, root disposition, baseline comparison, and
  final lock release therefore finish before the parent applies signal exit
  precedence.

No command selects an unrelated service, and no unqualified
`docker compose up` is permitted. Task 6 cannot start until this exact
invocation passes and its teardown restores the pre-proof baseline.

Expected live behavior: while the disposable target is eligible, bare-target
SASL LOGIN with its own generated password receives a tagged `NO` within the
fixed one-second read timeout. The operator capability contains `AUTH=LOGIN`
and not `AUTH=PLAIN`; the explicit PLAIN authorization-ID attempt receives an
immediate tagged `NO` or `BAD`; the combined
`target*dashboard-operator-a` LOGIN exchange and mailbox list succeed. The
test removes its own disposable target in `finally` and proves that target can
no longer authenticate.

Pinned Dovecot 2.4.1 source establishes that `passwd_file_sync()` stats a
passwd file at most once per `ioloop_time` wall-clock second and detects a
change through second-resolution modification time or file size. An immediate
post-delete operator probe can therefore observe the prior valid snapshot.
Cleanup accepts only the exact typed `AuthorizationFailure` emitted after the
valid master credential succeeds but the removed target is denied;
`AuthenticationFailure` instead means the active master credential was
rejected and fails immediately. `Success` alone is retryable.
Persistent `Success` schedules exactly six conditional 250-millisecond
inter-attempt delays (1.5 seconds of scheduled delay) across seven
fresh-credential probes. This is sufficient to place a later request beyond
Dovecot's one-stat-per-`ioloop_time`-second throttle. Each probe has its own
fixed five-second total deadline. The policy adds no unconditional writer-side
sleep, cache flush, or service restart. `ProtocolFailure` and
`TransportFailure` fail immediately, and persistent `Success` fails after the
seventh probe.

Ordinary Dovecot has no master passdb, the operator has exactly one
steady-state protected identity and an eligibility-backed target lookup, and
all four selected proof services remain healthy.

Expected final state: the fixed proof project has no containers or named volumes, the proof-only authority, operator secrets/hash, Maildir, logs, certificate, and private key are removed, and every pre-existing primary or Stalwart-gate container is still running with its original ID, `StartedAt`, health, and restart count. The proof never selects, stops, restarts, recreates, or otherwise mutates Stalwart or any pre-existing container.

## Task 6: Prove network isolation and stage–probe–switch–revoke rotation

**Files:**

- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotIsolationLiveTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorRotationLiveTest.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorApplicationLeaseRegistry.kt`
- Create: `debug-dashboard/dashboard-server/testResources/dovecot-gate0c/network-isolation-check.py`
- Create: `debug-dashboard/dashboard-server/testResources/dovecot-gate0c/test_network_isolation_check.py`
- Modify: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorCredentialStore.kt`
- Modify: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorProbe.kt`
- Modify: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/gate/dovecot/DovecotTask5ProofProfile.kt`
- Modify: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorCredentialStoreTest.kt`
- Modify: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorProbeTest.kt`
- Modify: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorConfigTest.kt`
- Modify: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotLiveTestEnvironment.kt`
- Modify: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotLiveTestEnvironmentTest.kt`
- Modify: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotTask5ProofLifecycleTest.kt`
- Modify: `debug-dashboard/dashboard-server/testResources/dovecot-gate0c/compose.task5-proof.yml`
- Modify: `debug-dashboard/dashboard-server/testResources/dovecot-gate0c/run-task5-proof.sh`
- Modify: `docs/debug-dashboard/gates/0c-dovecot.md`

- [ ] Extend the existing `DovecotOperatorCredentialStore` as the sole writer
  under its existing `withStableLock`; do not add another lock or credential
  writer. Add one fixed, unmounted, owner-`0600` rotation-intent file below
  the existing secrets directory. Its complete grammar is the three ASCII
  bytes `a:b` or `b:a`, without a newline.

- [ ] Expose only the narrow
  `rotateOrRecover(target, runtime)` / `recoverRotation(target, runtime)`
  boundary. A stable state has no intent, exactly one matching raw slot,
  active reference, and master hash. With intent `old:new`, `active=old`
  always recovers backward and `active=new` always recovers forward. Accept
  only one stable master entry or two unique entries in deterministic
  `old,new` order. Unknown, duplicate, reversed, malformed, impossible,
  symbolic, wrong-owner, wrong-mode, or oversized state fails closed.

- [ ] Rotate in this order:

  1. generate the inactive raw value, reject equality with the old value, and
     hash it through the stdin-only boundary;
  2. durably publish intent, then the inactive owner-`0600` raw slot, then the
     ordered old+new hash file;
  3. boundedly observe a staged strict read probe: authenticate, `LIST`,
     read-only `EXAMINE`, require a non-empty well-formed `UID SEARCH ALL`,
     then `UID FETCH` the first selected UID's
     `BODY.PEEK[HEADER.FIELDS (MESSAGE-ID)]` and validate the bounded literal;
  4. atomically switch active, synchronously copy the new credential into the
     narrow application lease holder, and verify a fresh application-owned
     lease/session selects the new ID;
  5. block new old-generation leases and boundedly drain/close all existing
     adapter-owned old sessions;
  6. publish the new-only hash, boundedly observe old
     `AuthenticationFailure`, then new `Success`;
  7. only then durably delete the old raw slot, verify the stable-new
     projection while intent remains, delete intent as the last durable
     mutation, and strictly verify one raw/hash/active result.

- [ ] Before the isolation class's first strict read assertion, APPEND one
  deterministic complete RFC 5322 message through the pinned operator
  transport. Use a fresh active credential for the seed and another for the
  read, close the seed session before probing, and wipe the payload and both
  credentials on every path. Keep an empty UID search a protocol failure.

- [ ] Hold a real authenticated old-ID IMAP session across the rotation
  switch. Register that transport's close operation with its application
  lease, prove it is usable before rotation, and prove it is closed and
  unusable after drain. Cap ordinary application leases at 15, reserve one
  verification lease within the total bound of 16, launch old-session closes
  concurrently, and enforce one shared one-second drain deadline.

- [ ] Do not invoke `doveadm auth cache flush`, restart, or recreate a service
  for convergence. Each positive or negative passwd-file observation gets at
  most seven attempts and six conditional 250-millisecond delays. Await
  accept retries only `AuthenticationFailure`; await reject retries only
  `Success`; protocol, transport, and interruption fail immediately, with
  interruption status restored. Every attempt creates and closes a fresh
  consumable credential.

- [ ] Emit observer points before/after every durable replace and delete, plus
  staged acceptance, application verification, drain completion, old
  rejection, new verification, and final strict state. Snapshot tests recreate
  a fresh store at every point. Before the active switch, explicit recovery
  rolls back. After it, recovery idempotently completes forward. Only explicit
  recovery may delete canonical owner-only
  `<fixed>.tmp-<canonical-UUID>` files; suspicious or unsafe temporaries are
  retained and fail closed.

- [ ] Write the live negative matrix:

  - ordinary IMAPS rejects master syntax/credential;
  - operator master succeeds only for an eligible disposable target;
  - arbitrary, protected, deleted, inactive-master, and master-as-self targets
    fail through the coordinator-backed fixed SASL LOGIN exchange;
  - a target ordinary password cannot become master authentication;
  - the master credential fails through ordinary POP3S, Postfix SMTP SASL,
    and OAuth introspection/authorization;
  - operator runtime publication is empty, its sole network is the internal
    `operator-ingress`, and the sole state `0A` port `7CF9` listener is exact
    container-loopback `0100007F:7CF9`;
  - every discovered non-loopback host IPv4 rejects ordinary `1993`, while
    fixed forbidden operator host port `2993` has no listener on any host path;
  - from the existing proof `oauth2-mock` on the default network, ordinary
    Dovecot resolution/connect is a positive control, operator DNS and direct
    ingress-IP access fail, and `host.docker.internal`,
    `gateway.docker.internal`, the explicit `task6-host-gateway` alias, plus
    every host LAN IPv4 cannot reach host port `2993`.

- [ ] Route operator readiness, bare-target/PLAIN rejection, every positive
  authentication exchange, isolation, rotation, and mailbox proof through the
  fixed Docker-exec/stdio transport. No process-pipe read is allowed outside
  the bounded coordinator/session contract. Require synchronous normal
  close/reap before accepting a result and use the fixed redacted
  `docker top <validated-operator-id> -ww -eo pid,args` inventory to prove zero
  OpenSSL children after normal close, launch/registration failure, timeout,
  abort, and held-session close.

- [ ] Reuse only the checked
  `debug-dashboard/dashboard-server/testResources/dovecot-gate0c/run-task5-proof.sh`
  lifecycle and Compose project `mail-sandbox-task5-proof`. Add proof-only
  `127.0.0.1:21995:31990` for the ordinary POP3S negative, reserve/check it
  with the existing fixed ports, and mount the fixed network helper read-only
  into the existing `oauth2-mock`. Add no service, project, network, or volume.
  The lifecycle runs startup, isolation, then rotation live classes before its
  existing mandatory cleanup and baseline checks.

- [ ] Run the single checked lifecycle:

```bash
debug-dashboard/dashboard-server/testResources/dovecot-gate0c/run-task5-proof.sh
```

Expected: all non-live checks, startup proof, isolation matrix, and rotation
proof pass, followed by mandatory cleanup. Two controller executions have
already completed: the second exposed the loopback-publication failure and
cleaned to the exact baseline. After the stdio transport is implemented, rerun
this lifecycle and keep Task 6 pending until the redesigned path passes.
If any bridge path reaches operator `31993`, if any host-gateway/LAN path
reaches fixed forbidden port `2993`, or if an OpenSSL exec child remains after
its bounded lifecycle, report `BLOCKED/STOP`; do not weaken or skip the
assertion.

## Task 7: Prove operator mail behavior and shared Maildir safety

**Files:**

- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotMailLiveTest.kt`
- Modify: `docs/debug-dashboard/gates/0c-dovecot.md`

- [ ] Create two new eligible disposable users through `EligibilityFileCli`. With the operator ingress, list mailboxes, append/read messages, set/reverse Seen and Flagged, copy, real MOVE, Trash, and UID-scoped permanent delete. Assert UIDVALIDITY/UID semantics.

- [ ] Concurrently access the same disposable Maildir through the ordinary and operator containers. Assert coherent message/flag state and no index corruption; capture relevant `doveadm force-resync`/log evidence only as a diagnostic, not a repair step.

- [ ] Submit through Postfix to the eligible target and require both queue acceptance and IMAP-observed arrival. Submit to absent/off-domain/protected targets and require rejection before queueing.

- [ ] Keep host command execution to the typed Gate 0A/Ktor `doveadm` allowlist. Browser/user data cannot name a command or service.

- [ ] Run:

```bash
cd debug-dashboard
DOVECOT_LIVE_TESTS=1 \
./kotlin test --include-module dashboard-server --include-classes 'mail.sandbox.dashboard.server.gate.dovecot.DovecotMailLiveTest'
```

Expected: pass.

## Task 8: Prove reset/deletion without retaining the old password

**Files:**

- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotLifecycleLiveTest.kt`
- Modify: `scripts/lib.py`
- Modify: `scripts/setup.py`
- Modify: `scripts/create_and_feed_account.py`
- Modify: `scripts/reset.py`
- Modify: `scripts/send_message.py`
- Modify: `scripts/send_thread.py`
- Modify: `scripts/generate_random_emails.py`
- Delete/Replace: `scripts/sync_stalwart_users.py` if Gate 0B has not already retired it
- Modify: `README.md`
- Modify: `CLAUDE.md`
- Modify: `.ai/architecture.md`
- Modify: `.ai/skills/docker-compose/references/service-map.md`
- Modify: `.ai/skills/docker-compose/references/volume-mounts.md`
- Modify: `.ai/skills/dovecot/references/auth.md`
- Modify: `.ai/skills/dovecot/references/config-files.md`
- Modify: `.ai/skills/dovecot/references/doveadm.md`
- Modify: `.ai/skills/postfix/references/config.md`
- Modify: `.ai/skills/postfix/references/mail-flow.md`
- Modify: `.ai/skills/oauth2/references/integration.md`
- Modify: `.ai/skills/oauth2/references/token-conventions.md`
- Modify: `.ai/skills/python-scripts/references/lib-api.md`
- Modify: `.ai/skills/python-scripts/references/script-inventory.md`
- Modify: `.ai/skills/email-testing/references/test-workflows.md`
- Modify: `docs/debug-dashboard/gates/0c-dovecot.md`

- [ ] Reset a disposable user's hash through the shared writer using only the new password. Flush auth cache, kick sessions, and prove new login. In the test, where the old value is owned, also prove old password failure.

- [ ] Delete another disposable identity from eligibility and prove all fail:

  - password login;
  - OAuth authorization/refresh/introspection including `valid-*`;
  - master/operator target;
  - `doveadm user`/mail targeting;
  - LMTP lookup;
  - Postfix RCPT/delivery.

Assert retained Maildir data remains inert and delivery does not recreate/re-enable the account. Exercise optional purge only through supported `doveadm`, never direct `vmail/` edits.

- [ ] Retire every direct Python mutation of `config/users`/runtime users. Existing scripts must call the shared Kotlin writer/tool or become explicitly read-only/deprecated. Replace `reset.py` direct account-file restore and direct mailbox deletion with the supported eligibility/purge boundary. Remove the public `DOCKER_CONTAINER`, generic `docker_exec`, and `docker_cp` surface; expose only fixed service/command helpers that validate exact eligible targets and stream message bytes through stdin.

- [ ] Refresh the listed repository docs and local-skill references so none teach plaintext `config/users`, arbitrary `valid-*` tokens, LAN binds, fixed container names, generic `docker exec`, or implicit Dovecot-to-Stalwart credential sync.

- [ ] Run:

```bash
python3 -m unittest oauth2-mock/test_server.py
cd debug-dashboard
DOVECOT_LIVE_TESTS=1 \
./kotlin test --include-module dashboard-server --include-classes 'mail.sandbox.dashboard.server.gate.dovecot.*LiveTest'
cd ..
docker compose config --quiet
```

Expected: pass.

## Task 9: Decide Gate 0C

**Files:**

- Modify: `docs/debug-dashboard/gates/0c-dovecot.md`

- [ ] Record pinned digest/version, effective primary/operator configs, runtime path/mode, password schemes, actual observed ingress addresses, isolation matrix, A/B rotation/crash-recovery result, shared-Maildir result, routing/OAuth evidence, lifecycle results, and safe disposable IDs.

- [ ] Gate decision:

  - **PASS:** one eligibility set controls password/OAuth/userdb/LMTP/Postfix/`doveadm`/master targeting; operator and network isolation pass; A/B stage–probe–switch–revoke rotation leaves no valid old credential/session; full operator mail behavior works; reset/delete need no retained old password.
  - **STOP:** master credential is usable on an ordinary path, Docker paths bypass loopback/operator isolation, rotation cannot revoke the old credential and drain owned sessions, shared access is unsafe, any identity path bypasses eligibility, or the implementation would need to retain user passwords/directly edit Maildir.

Do not begin shared feature foundation on `STOP`.

- [ ] On `PASS`, commit:

```bash
git add docker-compose.yml config postfix oauth2-mock scripts README.md .gitignore debug-dashboard docs/debug-dashboard/gates/0c-dovecot.md
git commit -m "test: prove isolated Dovecot operator gate"
```
