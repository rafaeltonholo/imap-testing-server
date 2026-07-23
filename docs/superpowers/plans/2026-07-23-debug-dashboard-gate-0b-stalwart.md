# Debug Dashboard Gate 0B — Stalwart v0.16.14 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove—or stop safely before migration—that Stalwart v0.16.14 can provide isolated management and user-mail credentials plus the required management, mail, submission, log, and deletion contracts.

**Architecture:** Run the protected-target impersonation negative test in a disposable v0.16.14 store before touching `stalwart-data/`. Tagged source inspection predicts the gate will stop because `impersonate` is global and `management%operator` authenticates. Migration and provider work are conditional on a user-approved credential-strategy amendment that restores a server-enforced privilege boundary.

**Tech Stack:** Pinned Stalwart Community v0.16.14, Kotlin/JVM Ktor client gate tests, JMAP Core/Mail/Submission plus Stalwart registry extensions, official tagged v0.16 migration script, Docker Compose.

---

## Known blocking evidence

In tagged v0.16.14, Basic username `target%master` authenticates `master`, checks `authenticate` plus `impersonate`, resolves any target Account globally, and returns that target's access token. There is no target allowlist or protected-account denial. Therefore an operator with `authenticate`+`impersonate` can authenticate as the protected management Account and inherit its management permissions.

Two associated constraints must also be reflected in any amended design:

- a Replace-scoped management API key needs `authenticate` in addition to the method permission allowlist;
- one Account has only one normal Password credential, so an overlap-based stage–probe–switch–revoke rotation needs two permanently protected operator IDs or a different credential strategy.

Do not work around the blocker with an application denylist, hidden user-password persistence, a secret management name, or a weakened negative assertion.

## Task 1: Add the disposable impersonation stop-gate

**Files:**

- Create: `debug-dashboard/dashboard-server/testResources/stalwart-gate0b/compose.yml`
- Create: `debug-dashboard/dashboard-server/testResources/stalwart-gate0b/compose.recovery.yml`
- Create: `debug-dashboard/dashboard-server/testResources/stalwart-gate0b/config.json`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/gate/stalwart/GateJmapClient.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/gate/stalwart/GateBootstrap.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/stalwart/StalwartFixtureSecretTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/stalwart/StalwartBootstrapTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/stalwart/StalwartImpersonationStopGateTest.kt`
- Create: `docs/debug-dashboard/gates/0b-stalwart.md`

- [ ] The fixture must:

  - use exactly `stalwartlabs/stalwart:v0.16.14`;
  - run Community Edition with no enterprise license;
  - use scratch state beneath ignored `debug-dashboard/.runtime/stalwart-gate0b/`;
  - publish only `127.0.0.1:18443:8080`;
  - never mount or modify repository `stalwart-data/`;
  - expose a real readiness health check.

- [ ] Make the base `compose.yml` the normal-runtime fixture and keep it free of every `STALWART_RECOVERY_*` variable. The recovery override adds only:

  - `STALWART_RECOVERY_MODE=1`;
  - `STALWART_RECOVERY_MODE_PORT=8080`;
  - an `env_file` whose path comes from required `STALWART_GATE_RECOVERY_ENV_FILE`.

Before startup, `StalwartFixtureSecretTest` creates that ignored file under `debug-dashboard/.runtime/stalwart-gate0b/` with owner-only directory permissions, mode `0600`, and one generated `STALWART_RECOVERY_ADMIN=<generated-name>:<generated-secret>` entry. It also writes a mode-`0600` handoff used only by the bootstrap/retirement tests. Never pass the secret on argv or emit it through Compose config/log capture.

- [ ] Implement the smallest typed Kotlin JMAP helper required to discover `/.well-known/jmap`, expand/use returned `apiUrl`, create/query registry objects through the disposable recovery credential, and authenticate normal/operator contexts. No legacy `/api/principal` call is allowed.

- [ ] Bootstrap the fresh scratch store in this exact order:

  1. start the named project with `compose.yml` plus `compose.recovery.yml`;
  2. wait for the recovery HTTP endpoint and authenticate using the generated recovery credential;
  3. through the discovered management `apiUrl`, create the minimal normal HTTP `NetworkListener`, `SystemSettings`, local Domain, management Account/key, operator Account/password, and ordinary target needed by the matrix;
  4. fetch every created object and verify its exact roles, Replace permissions, credential type, and protected ID before leaving recovery mode;
  5. stop the container without deleting its scratch bind-mounted store;
  6. restart the same named project using only base `compose.yml`, with neither recovery variable present;
  7. inspect the running container environment to prove no `STALWART_RECOVERY_` entry remains;
  8. prove the retired recovery Basic credential now fails, while the scoped management key, operator credential, and ordinary password still authenticate as intended.

Only after all eight steps pass may the authorization matrix run. This prevents the recovery back door from making the global-impersonation result ambiguous.

- [ ] Provision four disposable resources in the scratch store:

  - management Account with a Replace-scoped API key and only `authenticate` plus Account/Domain/Task and optional Log management methods;
  - mail operator Account with one normal Password and only `authenticate` plus `impersonate`;
  - ordinary target User with internal Password;
  - local Domain.

Persist test secrets only under the scratch runtime directory with mode `0600`; delete them during fixture teardown.

- [ ] Write the negative/positive matrix:

  - API key without `authenticate` fails;
  - API key with `authenticate` and required management methods succeeds;
  - `ordinary%operator` succeeds;
  - `management%operator` **must fail at Stalwart authentication**;
  - operator Account/Domain/Task/Log calls fail;
  - management-key Mailbox/Email/upload/submission/user-mail calls fail;
  - wrong, revoked, expired, and source-IP-mismatched credentials fail.

- [ ] Run:

```bash
cd debug-dashboard
STALWART_GATE_PREPARE=1 \
./kotlin test \
  --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.gate.stalwart.StalwartFixtureSecretTest'
cd ..
export STALWART_GATE_RECOVERY_ENV_FILE="$PWD/debug-dashboard/.runtime/stalwart-gate0b/recovery.env"
docker compose -p mail-sandbox-stalwart-gate \
  -f debug-dashboard/dashboard-server/testResources/stalwart-gate0b/compose.yml \
  -f debug-dashboard/dashboard-server/testResources/stalwart-gate0b/compose.recovery.yml \
  up -d --wait
cd debug-dashboard
STALWART_LIVE_TESTS=1 \
STALWART_BASE_URL=http://127.0.0.1:18443 \
./kotlin test \
  --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.gate.stalwart.StalwartBootstrapTest'

docker compose -p mail-sandbox-stalwart-gate \
  -f dashboard-server/testResources/stalwart-gate0b/compose.yml \
  stop stalwart
docker compose -p mail-sandbox-stalwart-gate \
  -f dashboard-server/testResources/stalwart-gate0b/compose.yml \
  up -d --wait --force-recreate

STALWART_LIVE_TESTS=1 \
STALWART_BASE_URL=http://127.0.0.1:18443 \
./kotlin test \
  --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.gate.stalwart.StalwartImpersonationStopGateTest'
```

The fixture-secret test owns recovery-file generation. The bootstrap test persists its generated scoped test credentials only in mode-`0600` files under the ignored scratch directory, alongside a non-secret fixture manifest. The final test owns cleanup of all of them. Expected on unmodified v0.16.14: bootstrap and recovery-retirement assertions pass, then the authorization test fails specifically because `management%operator` authenticates. Record:

```text
STOP: scoped Stalwart impersonation unavailable on v0.16.14
management%operator returned an authenticated Session
No existing Stalwart data was migrated
```

- [ ] Always tear down only the named disposable project and scratch state:

```bash
docker compose -p mail-sandbox-stalwart-gate \
  -f debug-dashboard/dashboard-server/testResources/stalwart-gate0b/compose.yml \
  down
```

Do not pass `-v` unless the fixture defines a gate-owned named volume and the resolved project/volume names are checked first.

- [ ] Commit the reproducible stop proof:

```bash
git add debug-dashboard/dashboard-server docs/debug-dashboard/gates/0b-stalwart.md
git commit -m "test: add Stalwart v0.16 authorization stop gate"
```

## Gate decision

- **PASS:** only if `ordinary%operator` succeeds and `management%operator` fails server-side while every management/operator permission test remains isolated.
- **STOP (expected):** `management%operator` authenticates, or another required Community-edition permission/isolation rule fails.

On `STOP`, do not execute any remaining task in this document, do not migrate `stalwart-data/`, and do not begin Gate 0C or feature work. Request a credential-strategy design decision.

The recommended amendment to evaluate is direct per-user dashboard credentials (for example, a dedicated revocable AppPassword per ordinary Account kept in an owner-only secret store) with no global impersonation permission. That is a security/product change because it persists one mail-access credential per account; it requires explicit approval and a revised Gate 0B plan.

---

## Conditional continuation after an approved credential amendment

The following tasks describe the remaining provider proof. They are intentionally conditional and are not executable as written after the expected STOP. Before executing them, revise the operator-specific steps, rotation model, threat analysis, and tests to match the approved strategy; also revise the affected account-provider, mail-provider, Message Lab/observability, Compose UI (if setup/recovery changes), and acceptance plans, then run independent review over the complete affected set.

## Task 2: Pin the v0.16.14 filesystem/runtime model

**Files:**

- Modify: `docker-compose.yml`
- Create: `stalwart/config.json`
- Delete: `stalwart/config.toml`
- Modify: `.gitignore`
- Create: `docs/stalwart-v016-migration.md`

- [ ] Replace `latest`, `/opt/stalwart`, TOML, and `ADMIN_SECRET` with:

```yaml
image: stalwartlabs/stalwart:v0.16.14
ports:
  - "127.0.0.1:8443:8080"
volumes:
  - ./stalwart/config.json:/etc/stalwart/config.json:ro
  - ./stalwart-data:/var/lib/stalwart
environment:
  STALWART_PUBLIC_URL: http://127.0.0.1:8443
healthcheck:
  test: ["CMD", "curl", "-fsS", "http://127.0.0.1:8080/healthz/ready"]
```

Use the tagged image's UID/GID 2000 ownership requirements. `stalwart/config.json` initially contains only:

```json
{
  "@type": "RocksDb",
  "path": "/var/lib/stalwart/"
}
```

Live registry objects supply listener/system/domain policy.

- [ ] Ignore `debug-dashboard/.runtime/stalwart/`, `debug-dashboard/.runtime/stalwart-migration/`, and `debug-dashboard/.runtime/stalwart-backups/`. Secrets and migration exports are mode `0600`.

- [ ] Validate:

```bash
docker compose config --quiet
docker compose config --images
```

Expected: v0.16.14 only, loopback publication, current paths.

## Task 3: Back up, dry-run, migrate, and prove rollback

**Files:**

- Create: `docker-compose.stalwart-migration.yml`
- Create: `scripts/stalwart_v016.py`
- Create: `scripts/bootstrap_stalwart_v016.py`
- Create: `scripts/backup_stalwart_v016.py`
- Create: `tests/test_stalwart_v016.py`
- Modify: `docs/stalwart-v016-migration.md`

- [ ] Before touching real state, prove the running binary is v0.15.x, capture image ID/digest/config/data manifest, and stop Stalwart. Copy the complete stopped data and TOML config into a timestamped ignored backup. Never edit RocksDB keys.

- [ ] Obtain the official `resources/scripts/migrate_v016.py` from the exact v0.16.14 tag and verify its source checksum. Use it to dump v0.15 settings/principals, convert paths `/opt/stalwart` → `/var/lib/stalwart`, and review every `unmigrated.txt` entry.

- [ ] Restore the backup copy to a separate scratch directory and boot it with the captured v0.15 image/another loopback port. Require version plus management-read success as rollback proof.

- [ ] Run v0.16.14 against the real store only through the migration override:

  - `127.0.0.1:18080:8080`;
  - `STALWART_RECOVERY_MODE=1`;
  - temporary recovery admin from a mode-0600 ignored environment file;
  - no mail listeners;
  - pinned image and migrated data mount.

Apply converted objects plus the reviewed bootstrap; require zero failed operations. Remove recovery variables and prove the recovery credential fails after normal restart.

- [ ] Any partial failure stops v0.16, preserves failed state for diagnosis, and restores the full v0.15 backup/config/image. No selective repair or destructive fresh reset.

## Task 4: Bootstrap internal accounts and local-only mail policy

**Files:**

- Create: `stalwart/bootstrap-v016.ndjson`
- Create: `stalwart/protected-recipients.sieve`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/stalwart/StalwartRoutingLiveTest.kt`

- [ ] Idempotently create the v0.16 HTTP listener, SystemSettings, enabled `local.test` Domain with no relay/catch-all, internal directory, local delivery route, RCPT-stage protection, and file Tracer used by `x:Log`.

- [ ] Do not recreate external OIDC as the account directory. Stalwart Password updates must modify internal Accounts.

- [ ] Live-test JMAP `EmailSubmission`: external and protected recipients fail before a `QueuedMessage`; a normal registered `local.test` target queues and arrives. If RCPT-stage policy does not execute for JMAP submission, mark `STOP`.

## Task 5: Provision protected management and approved mail credentials

**Files:**

- Create: `scripts/rotate_stalwart_credentials.py`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/stalwart/StalwartCredentialLiveTest.kt`

- [ ] Management Account uses Custom/no inherited roles, API-key Replace mode, and exactly:

```text
authenticate
sysAccountGet
sysAccountQuery
sysAccountCreate
sysAccountUpdate
sysAccountDestroy
sysDomainGet
sysDomainQuery
sysDomainCreate
sysTaskGet
sysTaskQuery
sysLogGet
sysLogQuery
```

Omit optional Log permissions when structured Log is disabled. No impersonation, mail, Domain update/destroy, or Task/Log mutation permission.

- [ ] Derive the credential `/32` from the source Stalwart actually observes for host-through-Docker traffic. Probe with a temporary unrestricted credential, create the restricted credential, prove host success and disposable-container failure, revoke the probe, then recreate the Compose network and re-prove stability.

- [ ] Store management key, protected Account IDs, and the approved mail credential material atomically in owner-only ignored files. Implement a real stage–probe–switch–revoke rotation for each credential class; do not claim overlapping rotation where the provider allows only one credential.

## Task 6: Prove management, mail, submission, log, and deletion contracts

**Files:**

- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/stalwart/StalwartManagementLiveTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/stalwart/StalwartMailLiveTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/stalwart/StalwartDeletionLiveTest.kt`
- Modify: `docs/debug-dashboard/gates/0b-stalwart.md`

- [ ] Discover Session URLs/capabilities; never hardcode `/api` or `/jmap`.

- [ ] Prove `x:Domain/query|get|set(create)` and `x:Account/query|get|set(create/update/destroy)`, `ifInState`, and independent `created/updated/destroyed/not*` parsing.

- [ ] For password reset, fetch the Account, alter only its one Password credential, preserve secondary credentials, update with state, re-fetch/compare, and verify new auth. If concurrent safe round-trip cannot be proven, stop and request the dedicated password permissions.

- [ ] Through the approved user-mail credential strategy, prove:

  - `Mailbox/get|set`, rights/roles/non-empty deletion safety;
  - upload URL expansion, RFC 5322 upload, `Email/import`, query/get/raw download;
  - keyword/membership mutations with `ifInState`, partial errors, state mismatch;
  - exact matching Identity;
  - import creation-ID chaining into `EmailSubmission/set`;
  - explicit envelope, per-recipient status, independent recipient arrival, truthful Sent filing.

- [ ] Prove file-backed `x:Log/query|get`; only text filter is server-side unless the live schema proves otherwise.

- [ ] Destroy a data-bearing disposable Account. Require principal absence and auth failure, then match `x:Task` client-side by account fields. Map only Pending/Retry/Failed; observed then absent confirms cleanup; never observed remains unverified.

## Task 7: Retire v0.15 assumptions and decide Gate 0B

**Files:**

- Delete/Replace: `scripts/sync_stalwart_users.py`
- Modify: `scripts/reset.py`
- Modify: `scripts/lib.py`
- Modify: `README.md`
- Modify: `CLAUDE.md`
- Modify: `.ai/architecture.md`
- Modify: `.ai/skills/stalwart/SKILL.md`
- Modify: `.ai/skills/stalwart/references/config.md`
- Modify: `.ai/skills/stalwart/references/admin-api.md`
- Modify: `.ai/skills/stalwart/references/oauth2.md`
- Modify: `.ai/skills/docker-compose/references/service-map.md`
- Modify: `.ai/skills/docker-compose/references/volume-mounts.md`
- Modify: `.ai/skills/python-scripts/references/script-inventory.md`
- Modify: `docs/debug-dashboard/gates/0b-stalwart.md`

- [ ] Remove active `latest`, TOML, `/opt/stalwart`, `/api/principal`, `ADMIN_SECRET`, external-OIDC-directory, Basic fallback-admin, shared-Dovecot-credential, and ordinary-reset-wipes-Stalwart claims.

- [ ] Make ordinary reset leave migrated Stalwart state alone. Any fresh reset is a separate explicit confirmation, runs while stopped, and creates a backup first.

- [ ] Run stale-reference, config, unit, live management/mail/routing/deletion, permission, rotation, and restore checks.

- [ ] Gate decision:

  - **PASS:** approved mail credentials preserve protected management isolation and every required Community v0.16.14 contract passes.
  - **STOP:** isolation, source IP, local-only routing, migration/rollback, task/log observation, or required Community behavior fails.

- [ ] On `PASS`, commit:

```bash
git add docker-compose.yml docker-compose.stalwart-migration.yml .gitignore stalwart scripts tests README.md CLAUDE.md .ai debug-dashboard docs
git commit -m "test: prove Stalwart v0.16.14 gate"
```
