# Stalwart LAN Runtime Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the final root Stalwart v0.16.17 runtime and Kotlin dashboard usable from physical LAN devices on ports 8443 and 8587 without weakening the captured-store migration boundary.

**Architecture:** A focused Python helper atomically owns the current LAN public URL in an owner-only runtime `env_file`. The normal root Compose model publishes all interfaces and consumes that file; migration, rollback, and gate runtimes stay loopback-only. Python and Kotlin normal-runtime clients validate and consume the same advertised URL, while immutable store/migration receipts remain independent from DHCP address changes.

**Tech Stack:** Python 3 standard library and `unittest`, Docker Compose, POSIX shell, Kotlin Toolchain 1.6.20, Kotlin/JVM, Ktor 3.4.1.

---

### Task 1: Add deterministic LAN public-URL configuration

**Files:**
- Create: `scripts/stalwart_network.py`
- Create: `tests/test_stalwart_network.py`
- Modify: `.gitignore`

- [ ] **Step 1: Write failing validation and atomic-write tests**

Cover an explicit `MAIL_SANDBOX_LAN_HOST=192.168.86.36`, safe local hostnames,
route-detected IPv4, exact one-line output, owner-only ancestors/file, idempotent
replacement, and rejection of loopback, wildcard, multicast, schemes, ports,
paths, credentials, whitespace, newline, non-local hostname resolutions, and
ambiguous detection. Default detection must accept exactly one default-route
interface with exactly one eligible IPv4; ties and missing/ambiguous addresses
fail with the override guidance.

The wished-for API is:

```python
configuration = resolve_network_configuration(
    repository,
    environment={"MAIL_SANDBOX_LAN_HOST": "192.168.86.36"},
    detector=lambda: "192.168.86.99",
)
assert configuration.public_url == "http://192.168.86.36:8443"
assert write_network_environment(configuration).read_bytes() == (
    b"STALWART_PUBLIC_URL=http://192.168.86.36:8443\n"
)
```

- [ ] **Step 2: Run the focused tests and observe RED**

Run:

```bash
python3 -m unittest tests.test_stalwart_network -v
```

Expected: FAIL because `scripts/stalwart_network.py` does not exist.

- [ ] **Step 3: Implement the standard-library helper and CLI**

Provide `prepare --repository <absolute-primary-root>` and `show
--repository <absolute-primary-root>`. Use the explicit override first and an
injected/default-route detector second. Normalize and validate a single host,
atomically publish `debug-dashboard/.runtime/stalwart/network.env` as `0600`
beneath mode-`0700` directories, and print only the safe public URL.

- [ ] **Step 4: Re-run focused tests and CLI smoke checks**

```bash
python3 -m unittest tests.test_stalwart_network -v
MAIL_SANDBOX_LAN_HOST=192.168.86.36 \
  python3 scripts/stalwart_network.py prepare --repository "$(pwd -P)"
python3 scripts/stalwart_network.py show --repository "$(pwd -P)"
```

Expected: PASS; both commands print `http://192.168.86.36:8443` and no secret.

- [ ] **Step 5: Commit**

```bash
git add .gitignore scripts/stalwart_network.py tests/test_stalwart_network.py
git commit -m "feat: prepare Stalwart LAN runtime URL"
```

### Task 2: Amend the normal Compose and Python runtime contracts

**Files:**
- Modify: `scripts/stalwart_runtime_state.py`
- Modify: `scripts/stalwart_v016.py`
- Modify: `scripts/bootstrap_stalwart_v016.py`
- Modify: `tests/test_stalwart_runtime_state.py`
- Modify: `tests/test_stalwart_v016.py`
- Modify: `tests/test_bootstrap_stalwart_v016.py`
- Keep unchanged: `docker-compose.stalwart-migration.yml`
- Keep unchanged: `tests/test_stalwart_migration_compose.py`

- [ ] **Step 1: Invert the normal-runtime tests to require LAN publication**

Expected normal ports:

```yaml
ports:
  - target: 8080
    published: "8443"
    host_ip: 0.0.0.0
    protocol: tcp
  - target: 587
    published: "8587"
    host_ip: 0.0.0.0
    protocol: tcp
```

Require the fixed service `env_file` path and the currently validated public
URL in rendered/runtime inspection. Add regressions rejecting loopback-only
normal publication, a missing/replaced network file, mismatched rendered URL,
and a container using a stale URL. Keep recovery assertions exactly loopback.
Add one cross-file invariant proving every recovery, rollback, rehearsal, and
gate publication is `127.0.0.1` and only the normal service may use `0.0.0.0`.
Build the future normal Compose model in a temporary repository fixture. Also
assert that the real root declaration remains the exact legacy hold and cannot
be selected as current before the authorization gate.

- [ ] **Step 2: Run the focused tests and observe RED**

```bash
python3 -m unittest \
  tests.test_stalwart_runtime_state \
  tests.test_stalwart_v016 \
  tests.test_bootstrap_stalwart_v016 -v
```

Expected: FAIL on the old normal `127.0.0.1` model.

- [ ] **Step 3: Implement the dynamic normal-runtime validators**

Read the generated URL using the helper's strict loader at validation/proof
time. Keep loopback transport constants for recovery. Split normal internal
probe destination (`127.0.0.1:8443`/`:8587`) from the expected advertised JMAP
API URL. Require Docker inspection ports with `HostIp=0.0.0.0` and environment
containing the current `STALWART_PUBLIC_URL`.

Do not place the dynamic URL in capture, dry-run, apply, bootstrap, retirement,
or current-store receipt payloads.

- [ ] **Step 4: Re-run Python tests and static Compose validation**

```bash
python3 -m unittest \
  tests.test_stalwart_runtime_state \
  tests.test_stalwart_migration_compose \
  tests.test_stalwart_v016 \
  tests.test_bootstrap_stalwart_v016 -v
docker compose config --quiet
```

Expected: PASS against the synthetic future model while the real root model
still classifies `migration-required`; no container starts and no normal-store
write occurs.

- [ ] **Step 5: Commit non-cutover code only**

Do not commit the root Compose cutover until the exact live-migration
authorization. Commit validators/tests that accept the reviewed future model
while retaining the legacy classifier for the current root declaration.

```bash
git add scripts/stalwart_runtime_state.py scripts/stalwart_v016.py \
  scripts/bootstrap_stalwart_v016.py tests/test_stalwart_runtime_state.py \
  tests/test_stalwart_v016.py tests/test_bootstrap_stalwart_v016.py
git commit -m "feat: validate LAN Stalwart runtime"
```

### Task 3: Give Kotlin normal-runtime clients a dynamic endpoint

**Files:**
- Modify: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/gate/stalwart/StalwartEndpointProfile.kt`
- Modify: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/local/StalwartDashboardProvider.kt`
- Modify: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/local/LocalDashboardBackend.kt`
- Modify: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/stalwart/GateJmapClientTest.kt`
- Modify: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/local/StalwartDashboardProviderTest.kt`
- Modify: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/local/LocalDashboardBackendTest.kt`
- Modify normal live tests under: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/stalwart/`

- [ ] **Step 1: Write failing endpoint/configuration tests**

Preserve fixed gate and migration profiles. Add a validated normal profile from
`DASHBOARD_STALWART_PUBLIC_URL`, requiring plain HTTP, no user info/query/
fragment, port `8443`, and a non-loopback LAN host. Assert its API URL is
`<base>/jmap/`, session discovery must match it exactly, and production backend
construction fails instead of falling back when CURRENT lacks the URL.

- [ ] **Step 2: Run the focused Kotlin tests and observe RED**

```bash
cd debug-dashboard
./kotlin test --include-module dashboard-server \
  --include-classes \
'mail.sandbox.dashboard.server.gate.stalwart.GateJmapClientTest,mail.sandbox.dashboard.server.local.StalwartDashboardProviderTest,mail.sandbox.dashboard.server.local.LocalDashboardBackendTest'
cd ..
```

Expected: FAIL because normal runtime is still a fixed loopback enum entry.

- [ ] **Step 3: Implement a value-based normal profile**

Keep constants for gate and migration. Represent normal as a validated value
created from the injected environment, pass it through backend/provider
construction, and use it for JMAP/admin requests. Keep host-side SMTP transport
at `127.0.0.1:8587`.

- [ ] **Step 4: Update and run all Stalwart Kotlin unit tests**

```bash
cd debug-dashboard
./kotlin test --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.*Stalwart*Test'
cd ..
```

Expected: PASS; gate/recovery tests remain loopback and normal tests use an
injected LAN URL.

- [ ] **Step 5: Commit**

```bash
git add debug-dashboard/dashboard-server/src \
  debug-dashboard/dashboard-server/test
git commit -m "feat: route dashboard to LAN Stalwart"
```

### Task 4: Propagate one LAN URL through launch and acceptance

**Files:**
- Modify: `debug-dashboard/start-local.sh`
- Modify: `debug-dashboard/run-live-acceptance.sh`
- Modify: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/local/LocalDashboardScriptsTest.kt`
- Modify: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/acceptance/SingleStackAcceptanceEnvironment.kt`
- Modify: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/acceptance/SingleStackUsabilityLiveTest.kt`

- [ ] **Step 1: Write failing propagation tests**

Require `start-local.sh` to prepare/show the network file before current/fresh
Stalwart startup and export exactly the resulting URL as
`DASHBOARD_STALWART_PUBLIC_URL`. Require live acceptance to read the same URL,
probe it from the host, and pass it to Kotlin while retaining the loopback SMTP
endpoint. Reject missing/mismatched values.

- [ ] **Step 2: Run script and acceptance unit tests and observe RED**

```bash
cd debug-dashboard
./kotlin test --include-module dashboard-server \
  --include-classes \
'mail.sandbox.dashboard.server.local.LocalDashboardScriptsTest,mail.sandbox.dashboard.server.acceptance.SingleStackAcceptanceEnvironmentTest'
cd ..
```

- [ ] **Step 3: Implement propagation without implicit `.env`**

Call the Python helper using an absolute repository path, capture its single
safe URL line, export it to the dashboard, and leave
`COMPOSE_DISABLE_ENV_FILE=1`. Add actionable failure text naming
`MAIL_SANDBOX_LAN_HOST`. The launcher may use the URL only when the classifier
has proved the root target model and current receipt. Tests must prove the
`migration-required`, `fresh`, invalid, and unavailable pre-gate paths never
select/start/recreate root Stalwart or pass root `stalwart-data/` to a writer.
Do not add the active DHCP recreation path before Task 7.

- [ ] **Step 4: Run tests and shell syntax checks**

```bash
sh -n debug-dashboard/start-local.sh
sh -n debug-dashboard/run-live-acceptance.sh
cd debug-dashboard
./kotlin test --include-module dashboard-server \
  --include-classes \
'mail.sandbox.dashboard.server.local.LocalDashboardScriptsTest,mail.sandbox.dashboard.server.acceptance.SingleStackAcceptanceEnvironmentTest'
cd ..
```

- [ ] **Step 5: Commit**

```bash
git add debug-dashboard/start-local.sh debug-dashboard/run-live-acceptance.sh \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/local/LocalDashboardScriptsTest.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/acceptance
git commit -m "feat: propagate Stalwart LAN endpoint"
```

### Task 5: Add a disposable-copy migration rehearsal

**Files:**
- Modify: `scripts/stalwart_v016.py`
- Modify: `tests/test_stalwart_v016.py`
- Modify: `docs/stalwart-v016-migration.md`
- Create: `docker-compose.stalwart-rehearsal.yml`
- Create: `tests/test_stalwart_rehearsal_compose.py`

- [ ] **Step 1: Write failing rehearsal-boundary tests**

Add a `rehearse` CLI whose only store input is the immutable captured
`source-data`, whose mutable store is a new owner-only copy below the migration
runtime root, and whose Compose project/container/ports cannot equal the root
or recovery identities. Prove every error path stops known rehearsal containers
and never passes the root `stalwart-data/` to a writer. Require all rehearsal
ports to bind `127.0.0.1` and add an executable pre-authorization guard that
refuses any root normal-service selection, root-store writable mount, or root
Compose mutation.

- [ ] **Step 2: Run the focused tests and observe RED**

```bash
python3 -m unittest \
  tests.test_stalwart_v016.RehearsalContractTest -v
```

Expected: FAIL because the CLI has no `rehearse` command.

- [ ] **Step 3: Implement the minimal rehearsal orchestrator**

Reuse the reviewed dry-run/export validators and migration runtime adapters,
but bind a distinct rehearsal plan and a digest-pinned tracked rehearsal
overlay to a copied store. Use a unique Compose project/container and isolated
loopback ports. Configure the selected LAN public URL and assert that discovery
advertises it, but never follow that URL: route all rehearsal management/JMAP
mutations directly to the isolated loopback API path and all SMTP to the
isolated loopback submission port. Validate migrated account/domain inventory,
password/enrollment state, management CRUD, folder/message read/move/flag/
delete, and restart. Write a secret-free receipt before removing only the known
container and mutable rehearsal copy. Preserve the receipt and logs; retain
failed evidence on failure.

- [ ] **Step 4: Run unit tests, then the live disposable rehearsal**

```bash
python3 -m unittest tests.test_stalwart_v016 -v
python3 -m unittest tests.test_stalwart_rehearsal_compose -v
python3 scripts/stalwart_v016.py rehearse \
  --script debug-dashboard/.runtime/stalwart-migration/migrate_v016.py \
  --review-receipt debug-dashboard/.runtime/stalwart-migration/reviewed.json
```

Expected: PASS and print only the fixed rehearsal receipt path. Afterwards the
root v0.15 service is stopped, `stalwart-data/` matches its capture identity,
and no rehearsal container is running.

- [ ] **Step 5: Commit**

```bash
git add scripts/stalwart_v016.py tests/test_stalwart_v016.py \
  docker-compose.stalwart-rehearsal.yml \
  tests/test_stalwart_rehearsal_compose.py \
  docs/stalwart-v016-migration.md
git commit -m "feat: rehearse Stalwart migration on captured copy"
```

### Task 6: Stop for the existing live-migration authorization

- [ ] **Step 1: Revalidate and display evidence**

Show source `0.15.5`, target `0.16.17` plus OCI digest, snapshot path and
digest, reviewed dry-run receipt, successful rehearsal receipt, exact live
apply command, exact rollback command, and proof that the source is stopped and
normal store unchanged.

- [ ] **Step 2: Require the exact sentence**

```text
I explicitly authorize applying the verified Stalwart migration to the normal store, starting the new runtime, and performing the documented rollback if required.
```

Do not edit the root Stalwart declaration, apply, bootstrap, start the new
normal runtime, or roll back without that sentence.

### Task 7: Apply the LAN target and complete two-provider acceptance

**Files:**
- Modify under authorization: `docker-compose.yml`
- Modify: `README.md`
- Modify: `CLAUDE.md`
- Modify: `.ai/architecture.md`
- Modify: `.ai/skills/docker-compose/references/service-map.md`
- Modify: `.ai/skills/docker-compose/references/volume-mounts.md`
- Modify: `.ai/skills/stalwart/references/config.md`
- Modify: `docs/stalwart-v016-migration.md`
- Modify: `docs/debug-dashboard/dependency-baseline-2026-08-10.md`

- [ ] **Step 1: Under exact authorization, install the root target model**

Generate the current network file, replace only the legacy root Stalwart block
with the reviewed v0.16.17 image/config/LAN ports/env-file model, and validate
`docker compose config --quiet` without printing environment contents.

- [ ] **Step 2: Apply, bootstrap, retire recovery, and prove restart**

Follow `docs/stalwart-v016-migration.md` exactly. On any partial failure, stop,
retain evidence and both stores, and use rollback only within the authorization.

- [ ] **Step 3: Run full root-stack acceptance**

```bash
DASHBOARD_SINGLE_STACK_LIVE_TESTS=1 \
  ./debug-dashboard/run-live-acceptance.sh
```

Expected: all requested account, password, folder, message, read/move/flag/
delete, generation, account/server logs, and protocol-profile operations pass
on both root Dovecot and root Stalwart; pre-existing accounts/mail remain.

- [ ] **Step 4: Prove physical-device reachability**

From the selected LAN URL, verify JMAP discovery advertises the same LAN API
URL and authenticated submission accepts a test account on port 8587. Confirm
the host-side dashboard still passes its loopback diagnostics.

Use an identified remote LAN actor—not the host—to perform the reachability
proof: the Wi-Fi-connected physical test device through an ADB-driven socket/
HTTP probe, or a second named LAN host. The actor must fetch JMAP discovery from
`http://<LAN-host>:8443/.well-known/jmap`, observe the same LAN `apiUrl`, and
open/authenticate submission on `<LAN-host>:8587`. A host request to its own LAN
address is only a preliminary check and cannot complete acceptance. If no
remote actor is available, final physical-device acceptance remains incomplete.

Now add and exercise the DHCP-refresh path once with the same address:
regenerate the network file, force-recreate the Stalwart service with the
following command, restart the dashboard process, reprove discovery from the
remote actor, and verify that migration/current-store receipt hashes did not
change.

```bash
docker compose up -d --force-recreate stalwart
```

- [ ] **Step 5: Run complete non-live validation and self-review**

```bash
python3 -m unittest discover -s tests -v
docker compose config --quiet
cd debug-dashboard
./kotlin build
cd ..
```

Then execute `.ai/self-review.md`, inspect the final diff, and confirm the only
unrelated working-tree changes remain the user's protected edits in
`scripts/lib.py`, `scripts/send_message.py`, and `scripts/send_thread.py`.

- [ ] **Step 6: Commit the authorized cutover and documentation**

Stage only implementation-owned files and commit to local `main`. Retain the
capture until final acceptance is explicitly complete.
