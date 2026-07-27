# Debug Dashboard Gate 0C — Dovecot Identity and Operator Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make one hashed runtime eligibility set authoritative across every Dovecot/Postfix/OAuth path and prove an isolated master/operator IMAP ingress can safely administer disposable accounts without retaining user passwords.

**Architecture:** The ordinary Dovecot container never loads a master passdb. A second Dovecot instance shares the read-only eligibility directory and Maildir volume but loads a separate hashed master credential, runs IMAP only, joins its own internal Docker network, and publishes only a loopback operator port. Postfix and the OAuth mock consult the same atomic eligibility file on every decision; dashboard/file tools share an OS-visible global lock.

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
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotLiveTestEnvironment.kt`

- [ ] Add a second `dovecot-operator` service using the exact same pinned image. It:

  - mounts the shared `debug-dashboard/.runtime/dovecot` directory and `vmail/`;
  - additionally mounts `debug-dashboard/.runtime/dovecot-operator/` containing the ARGON2ID master passwd file;
  - starts from the standalone `config/operator/dovecot.conf`;
  - runs IMAP only;
  - publishes only `127.0.0.1:2993:31993`;
  - joins only a dedicated `operator-ingress` internal network with no other service; and
  - has a bounded healthcheck that proves the `imap-login` service is running.

The ordinary `dovecot` service never mounts or loads the master credential directory/passdb.

- [ ] Configure the operator master passdb as `master = yes` with `result_success = continue`, followed by a target passwd lookup with `skip = unauthenticated`, then exact userdb lookup against the shared eligibility file. The only accepted login forms are `target*dashboard-operator-a` and `target*dashboard-operator-b`; these two immutable protected master identities are not present in normal passdb/userdb and have no mailboxes. Exactly one identity is active at steady state; both may coexist only inside the locked rotation window.

The critical standalone auth block is:

```dovecot
protocols = imap
auth_mechanisms = plain
auth_allow_cleartext = no
auth_master_user_separator = *
auth_username_format = %{user}

passdb passwd-file {
  passwd_file_path = /etc/dovecot/operator-auth/master-users
  master = yes
  result_success = continue
}

passdb passwd-file {
  passwd_file_path = /etc/dovecot/runtime/users
  skip = unauthenticated
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

- [ ] Write configuration tests that fail if the primary config contains a master passdb, the operator enables POP3/LMTP, either protected master appears in the user registry, an unknown master identity appears in the master file, the operator joins the default network, or its host bind is not exact loopback.

- [ ] Make every selected Dovecot `*LiveTest` use `DovecotLiveTestEnvironment`. It requires `DOVECOT_LIVE_TESTS=1` and bounded readiness of the exact fixed loopback endpoints; missing configuration or an unavailable ordinary/operator/Postfix/OAuth service fails the selected suite rather than skipping.

- [ ] After the configuration checks, recreate the complete ordinary Compose topology—not only one-off containers—and wait for health. `DovecotOperatorStartupLiveTest` creates an eligible disposable target through `EligibilityFileCli`, performs a TLS master login plus mailbox list through `127.0.0.1:2993`, and verifies the ordinary Dovecot, Postfix, and OAuth endpoints are reachable. Task 6 cannot start until this proof passes.

- [ ] Run:

```bash
cd debug-dashboard
./kotlin test --include-module dashboard-server --include-classes 'mail.sandbox.dashboard.server.gate.dovecot.DovecotOperatorConfigTest'
./kotlin test --include-module dashboard-server --include-classes 'mail.sandbox.dashboard.server.gate.dovecot.DovecotOperatorCredentialStoreTest'
cd ..
docker compose config --quiet
docker compose run --rm dovecot doveconf -n
docker compose run --rm dovecot-operator doveconf -n
docker compose up -d --build --force-recreate --wait
docker compose ps
docker compose exec -T dovecot doveadm service status imap-login
docker compose exec -T dovecot-operator doveadm service status imap-login
cd debug-dashboard
DOVECOT_LIVE_TESTS=1 \
./kotlin test \
  --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.gate.dovecot.DovecotOperatorStartupLiveTest'
```

Expected: primary has no master passdb; operator has one master passdb, exactly one steady-state protected identity, and an eligibility-backed target lookup. The recreated full stack is healthy and a real operator login succeeds before Task 6.

## Task 6: Prove network isolation and stage–probe–switch–revoke rotation

**Files:**

- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotIsolationLiveTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorRotationLiveTest.kt`
- Modify: `docs/debug-dashboard/gates/0c-dovecot.md`

- [ ] Write live tests for this negative matrix:

  - ordinary Dovecot endpoint rejects master syntax/credential;
  - operator endpoint accepts the master credential only when targeting an eligible disposable user;
  - arbitrary, protected, deleted, and master-as-self targets fail;
  - ordinary user password cannot become master auth;
  - master credential fails through POP3, SMTP SASL, and OAuth;
  - operator has no POP3/LMTP/SMTP publication;
  - non-loopback host interfaces cannot reach ordinary or operator ports;
  - containers on the default Compose network cannot resolve/reach `dovecot-operator`;
  - Docker host-gateway/LAN paths cannot loop back into `127.0.0.1:2993`.

Use the actual Docker Desktop network path; do not assert that the container observes `127.0.0.1`.

- [ ] If any default-network/host-gateway path reaches the operator, tighten the network/firewall architecture and rerun. If it cannot be isolated while remaining usable by the host Ktor process, mark `STOP`.

- [ ] Implement one exclusive rotation lock and crash-recoverable A/B state machine:

  1. choose the inactive protected identity;
  2. generate its new raw value, hash it through the stdin-only path, and durably write the inactive mode-`0600` secret;
  3. atomically replace `master-users` with both old and staged hashes, flush operator auth cache, and prove a full list/read probe for a disposable target using the staged identity;
  4. atomically switch `dovecot-operator-active`, reload the dependent adapter, and prove an application-path target operation uses the new slot;
  5. prevent new use of the old slot, wait for or force-close every adapter-owned old-slot IMAP session within a bounded drain window, atomically remove the old hash from `master-users`, flush auth cache, and delete the old raw-secret file;
  6. negatively verify the captured old credential and positively verify the new one;
  7. finish with exactly one hash, one raw secret, and one matching active reference.

Before the active-reference switch, recovery removes an abandoned staged slot. After the switch, recovery completes old-slot revocation; it never switches back merely because cleanup was interrupted. Tests inject a crash at every boundary, reject symlink/path/mode corruption, prove no adapter-owned old-slot session survives completion, and prove no secret enters logs, argv, SQLite, receipts, or gate evidence.

- [ ] Run:

```bash
docker compose ps
docker compose exec -T dovecot doveadm service status imap-login
docker compose exec -T dovecot-operator doveadm service status imap-login
cd debug-dashboard
DOVECOT_LIVE_TESTS=1 \
./kotlin test --include-module dashboard-server --include-classes 'mail.sandbox.dashboard.server.gate.dovecot.DovecotIsolationLiveTest'
DOVECOT_LIVE_TESTS=1 \
./kotlin test --include-module dashboard-server --include-classes 'mail.sandbox.dashboard.server.gate.dovecot.DovecotOperatorRotationLiveTest'
```

Expected: the isolation matrix and every rotation/crash-recovery case pass.

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
