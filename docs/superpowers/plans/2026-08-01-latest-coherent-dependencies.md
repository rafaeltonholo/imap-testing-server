# Latest Coherent Dependency Baseline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Upgrade every active direct dashboard, provider, container, and repository-tool dependency to the latest coherent stable baseline approved in the 2026-08-01 design, and re-prove the Kotlin browser and both provider gates without downgrades.

**Architecture:** Treat dependency freshness as a stop/go gate in four layers: Kotlin/Wasm, Dovecot/Postfix/base images, Stalwart, then cross-stack evidence. Each layer starts with an exact-version RED test, changes only its owned declarations and compatibility code, proves the resolved/runtime graph, and commits independently. Framework-managed and distribution-managed versions remain visible exceptions; no task forces an independently newer artifact into an unsupported parent graph.

**Tech Stack:** Kotlin Toolchain 0.11.1, Kotlin 2.4.10, Compose Multiplatform 1.11.1, Ktor 3.5.2, kotlinx.serialization 1.11.0, JUnit Platform 6.1.2, Dovecot 2.4.4, Stalwart v0.16.16, Python 3.14.6, Debian 13.6, Debian Postfix 3.10.12, Docker Compose, Python stdlib tests, Selenium/Chrome.

**Design:** `docs/superpowers/specs/2026-08-01-latest-coherent-dependencies-design.md`

---

## Execution invariants

- Perform Tasks 1–8 only in `.worktrees/debug-dashboard` on
  `feature/debug-dashboard`. Task 9 integrates those reviewed commits into the
  primary checkout through `superpowers:finishing-a-development-branch`, then
  performs and commits the authorized cutover there. Tasks 10–11 run only from
  that same clean primary checkout after verifying its HEAD contains both the
  Tasks 1–8 integration and Task 9 cutover commit. Never split final evidence
  across the feature-worktree and primary-checkout histories.
- Use `debug-dashboard/kotlin`; do not add or invoke Gradle, npm build tooling,
  React, or TypeScript.
- Recheck official release metadata immediately before each version-changing
  task. If a newer stable parent exists, update the expected version and this
  plan before implementation.
- Use the exact multi-architecture OCI index digests in this plan, never an
  architecture-specific manifest digest.
- Do not rewrite historical gate evidence as though it ran against new
  versions. Add supersession/new-run sections.
- Do not start, stop, recreate, inspect, enumerate, query, migrate, or otherwise
  access the normal repository Stalwart service until the repository's exact
  capture phrase is supplied. That phrase authorizes only capture and leaving
  the source stopped. Migration/store replacement/new-runtime start require a
  second explicit authorization after capture evidence is reported.
  Disposable Gate 0B resources remain permitted only under their existing
  exact project/path/port safeguards and must not inspect the normal service.
- After every disposable provider lifecycle, prove baseline container,
  network, volume, port, runtime-directory, and lock state was restored.
- A failed latest-version build remains RED. Never make it green by restoring
  an older dependency.

## Task 1: Pin and prove the Kotlin Toolchain dependency graph

**Files:**

- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/dependency/DependencyBaselineTest.kt`
- Inspect: `debug-dashboard/kotlin`
- Inspect: `debug-dashboard/kotlin.bat`
- Modify: `debug-dashboard/dashboard-contract/module.yaml`
- Modify: `debug-dashboard/dashboard-server/module.yaml`
- Modify: `debug-dashboard/dashboard-web/module.yaml`

From the repository root, enter `debug-dashboard/` in Step 2, stay there
through Step 5, then return to the repository root before staging.

- [ ] **Step 1: Write the dashboard baseline RED test**

Create `DependencyBaselineTest.kt`. Resolve the repository root using the same
working-directory contract as the existing Gate tests, read the three module
files, and assert exact semantic snippets rather than loose version
substrings. At minimum require:

```kotlin
private val selected = mapOf(
    "toolchain" to "0.11.1",
    "kotlin" to "2.4.10",
    "compose" to "1.11.1",
    "material3" to "1.11.0-alpha07",
    "ktor" to "3.5.2",
    "serialization" to "1.11.0",
    "junit" to "6.1.2",
    "skiko" to "0.144.6",
    "logback" to "1.6.1",
    "selenium" to "4.46.0",
    "joda" to "3.2.0",
)
```

Assert all three modules select Kotlin 2.4.10; only the web module enables
Compose 1.11.1; server and web select Ktor 3.5.2; contract and server select
serialization 1.11.0; JVM-capable modules select JUnit Platform 6.1.2; the
Wasm-only module does not declare JUnit; and the server owns the exact Skiko,
Logback, Selenium, and js-joda dependencies. Reject the old selected versions
`2.3.21`, `1.10.3`, `3.4.3`, `1.10.0`, `6.0.3`, `0.9.37.4`, and `1.5.18` in
active module files.

Require the web module to declare the exact official Compose 1.11.1 component
`org.jetbrains.compose.material3:material3:1.11.0-alpha07` and to contain no
active `$compose.material3` alias. Toolchain 0.11.1's built-in alias predates
Compose 1.11.1, warns that its mapping is unknown, and otherwise falls back to
Material3 1.10.0-alpha05.

Also read both wrapper scripts as text. Require
`kotlin_cli_version=0.11.1`/`set kotlin_cli_version=0.11.1`, require both to
pin distribution SHA-256
`0ded2a434f6bf193b24e2a6d56c3ba443f4232721155a65aaa8372789412112f`,
and calculate the wrapper-file SHA-256 values in the test:

```text
debug-dashboard/kotlin     6dbcdde0bcae41705c187aefb6c91c6c29ef9079c8072a473c2149151f8d7962
debug-dashboard/kotlin.bat 669ecc38f0ea46829a0f82d585243b6f2a08f0c9640d270d090372dd277dd47d
```

This proves the direct Toolchain dependency and its bootstrap chain of trust,
not merely the Kotlin language version selected by module YAML.

- [ ] **Step 2: Run the focused test and verify RED**

Run from the repository root; this enters the Kotlin project for Steps 2–5:

```bash
cd debug-dashboard
./kotlin test \
  --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.dependency.DependencyBaselineTest'
```

Expected: FAIL on the old module pins, not on repository-root discovery.

- [ ] **Step 3: Update module settings and direct dependencies**

Use these ownership boundaries:

```yaml
# dashboard-contract/module.yaml
settings:
  jvm:
    test:
      junitPlatformVersion: 6.1.2
  kotlin:
    version: 2.4.10
    serialization:
      format: json
      version: 1.11.0

test-dependencies@jvm:
  - bom: org.junit:junit-bom:6.1.2
  - org.junit.jupiter:junit-jupiter-api
  - org.junit.jupiter:junit-jupiter-engine: runtime-only
  - org.junit.platform:junit-platform-launcher: runtime-only
```

```yaml
# dashboard-server/module.yaml settings excerpt
settings:
  kotlin:
    version: 2.4.10
    serialization:
      format: json
      version: 1.11.0
  ktor:
    enabled: true
    version: 3.5.2
  jvm:
    mainClass: mail.sandbox.dashboard.server.ApplicationKt
    test:
      junitPlatformVersion: 6.1.2
```

Change server dependencies to Skiko `0.144.6`, Logback `1.6.1`, and retain
js-joda `3.2.0`; retain Selenium `4.46.0`. Add the JUnit 6.1.2 BOM/API/engine/
launcher entries to server test dependencies with engine and launcher
`runtime-only`.

```yaml
# dashboard-web/module.yaml settings excerpt
settings:
  kotlin:
    version: 2.4.10
  compose:
    enabled: true
    version: 1.11.1
    resources:
      packageName: mail.sandbox.dashboard.web.generated.resources
  ktor:
    enabled: true
    version: 3.5.2
```

Replace `$compose.material3` with the exact official Compose 1.11.1 component
`org.jetbrains.compose.material3:material3:1.11.0-alpha07`. This explicit
coordinate is required by Toolchain 0.11.1's unknown-version warning and is a
Compose-owned mapping, not an independently selected child. Do not directly
pin coroutines. Skiko in the web graph must resolve to `0.144.6`, and
Ktor/Compose must resolve coroutines `1.11.0`.

- [ ] **Step 4: Validate the Toolchain model and resolved graph**

```bash
shasum -a 256 kotlin kotlin.bat
./kotlin --version
./kotlin show modules
./kotlin show settings --all-modules
./kotlin show dependencies --all-modules --include-tests
```

Expected: wrapper hashes match Step 1; Toolchain reports exactly `0.11.1`;
model accepted; exact selected top-level versions; no unexplained conflict;
JUnit 6.1.2 wins in JVM test runtime; no JUnit in the Wasm-only app; Material3
1.11.0-alpha07 resolves in every web compile/runtime/test scope without the
unknown-mapping warning; Skiko and coroutines match their approved managed
versions.

- [ ] **Step 5: Rerun the RED test and focused module tests**

```bash
./kotlin test \
  --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.dependency.DependencyBaselineTest'
./kotlin test --include-module dashboard-contract
cd ..
```

Expected: PASS. If Toolchain 0.11.1 rejects a documented YAML field, first add
a failing schema characterization test/probe and use the supported equivalent;
do not remove the version requirement.

- [ ] **Step 6: Commit**

```bash
git add debug-dashboard/dashboard-contract/module.yaml \
  debug-dashboard/dashboard-server/module.yaml \
  debug-dashboard/dashboard-web/module.yaml \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/dependency/DependencyBaselineTest.kt
git commit -m "build: upgrade Kotlin dashboard dependencies"
```

## Task 2: Upgrade and validate the Compose/Skiko browser asset closure

**Files:**

- Modify: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/web/WebAssetBundle.kt`
- Modify: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/web/WebAssetBundleTest.kt`
- Modify: `docs/debug-dashboard/gates/0a-kotlin-toolchain.md`

From the repository root, enter `debug-dashboard/` in Step 1, stay there
through Step 5, then return to the repository root before updating evidence or
staging.

- [ ] **Step 1: Change only the test expectations and verify RED**

Require the exact Compose-compatible Skiko 0.144.6 hashes:

```kotlin
private const val SKIKO_MJS_SHA256 =
    "7fa5652ceb6343affed0360d2a8e5e35dbce1dff6192b2268c7519861af2dff4"
private const val SKIKO_WASM_SHA256 =
    "46caff5f783599bd1c5d3e5e87959d7cb5102c515aac671c9280664368e71dab"
```

Keep the js-joda 3.2.0 path/hash unchanged. Run:

```bash
cd debug-dashboard
./kotlin test \
  --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.web.WebAssetBundleTest'
```

Expected: FAIL because production still requires the old Skiko hashes.

- [ ] **Step 2: Update production pins minimally**

Change both production hash locations in `WebAssetBundle.kt` and no other
allowlist rule. The classpath resource names remain `skiko.mjs` and
`skiko.wasm`.

- [ ] **Step 3: Build the 1.11.1 Wasm app and inspect every reference**

```bash
./kotlin build --module dashboard-web
find build/tasks/_dashboard-web_linkWasmJs -type f -print
rg -n "(^|[^[:alnum:]_])(import|export|new URL)" \
  build/tasks/_dashboard-web_linkWasmJs
```

Expected: successful link and a complete known closure. If Compose 1.11.1
changes an executable static/dynamic import or `new URL` shape, add one focused
RED scanner test for that exact generated shape before adjusting production.
Never broaden acceptance to arbitrary bare/network imports.

- [ ] **Step 4: Run the asset and web route tests**

```bash
./kotlin test \
  --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.web.*'
```

Expected: PASS with the actual 0.144.6 classpath resources and no missing or
duplicate asset.

- [ ] **Step 5: Run the real browser gate**

```bash
DASHBOARD_WEB_ASSETS="$PWD/build/tasks/_dashboard-web_linkWasmJs" \
DASHBOARD_WEB_RESOURCES="$PWD/build/artifacts/PreparedComposeResourcesDirArtifact/dashboard-webcommon" \
DASHBOARD_WEB_ENTRY="dashboard-web.mjs" \
./kotlin test \
  --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.gate.KotlinToolchainBrowserGateTest'
cd ..
```

Expected: 1/1 PASS in Chrome with no console, network, HTTP, MIME, import-map,
Skiko, or Wasm failure.

- [ ] **Step 6: Update Gate 0A without rewriting history**

Append a superseding run dated with the actual UTC execution date containing
Toolchain/Kotlin/Compose/Ktor/JUnit/Skiko versions, resolved managed
exceptions, artifact hashes, browser/driver versions, exact commands, and
PASS/STOP. Keep the original 2.3.21/1.10.3/3.4.3 evidence explicitly
historical; never backdate the new evidence to the design date.

- [ ] **Step 7: Commit**

```bash
git add debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/web/WebAssetBundle.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/web/WebAssetBundleTest.kt \
  docs/debug-dashboard/gates/0a-kotlin-toolchain.md
git commit -m "test: reprove browser gate on latest Compose stack"
```

## Task 3: Correct future dashboard dependency plans

**Files:**

- Modify: `docs/superpowers/plans/2026-07-23-debug-dashboard-implementation.md`
- Modify: `docs/superpowers/plans/2026-07-23-debug-dashboard-foundation.md`
- Modify: `docs/superpowers/plans/2026-07-23-debug-dashboard-account-providers.md`
- Modify: `docs/superpowers/plans/2026-07-23-debug-dashboard-gate-0b-stalwart.md`
- Modify: `docs/superpowers/plans/2026-07-23-debug-dashboard-mail-providers.md`
- Modify: `docs/superpowers/plans/2026-07-23-debug-dashboard-message-lab-observability.md`
- Create: `tests/test_dependency_policy.py`

- [ ] **Step 1: Write future-plan version RED tests**

Using only `unittest` and `pathlib`, require SQLite JDBC `3.53.2.1`, Jakarta
Mail API `2.1.5`, Angus Mail `2.0.5`, and jsoup `1.23.1` in active future
plans. Require Stalwart v0.16.16 in active implementation/provider/mail plans,
while the completed Gate 0B plan retains its v0.16.14 evidence under an
explicit supersession banner. Assert the superseded planned values do not
remain in active dependency declarations. Do not add MCP or optional-Python
expectations yet; Policy Batch 4 owns those after both provider batches.

- [ ] **Step 2: Verify RED**

```bash
python3 -B -W error -m unittest discover \
  -s tests -p 'test_dependency_policy.py' -v
```

Expected: FAIL on stale planned SQLite/jsoup/Stalwart values.

- [ ] **Step 3: Correct future plans**

Update only active dependency declarations/Tech Stack summaries. Add a short
supersession note where an old version is part of historical gate narration;
do not globally replace version-looking data or SMTP enhanced-status codes.

- [ ] **Step 4: Run the focused test**

```bash
python3 -B -W error -m unittest discover \
  -s tests -p 'test_dependency_policy.py' -v
```

Expected: PASS for every active future-plan declaration and the historical
Gate 0B supersession marker.

- [ ] **Step 5: Commit**

```bash
git add docs/superpowers/plans/2026-07-23-debug-dashboard-implementation.md \
  docs/superpowers/plans/2026-07-23-debug-dashboard-foundation.md \
  docs/superpowers/plans/2026-07-23-debug-dashboard-account-providers.md \
  docs/superpowers/plans/2026-07-23-debug-dashboard-gate-0b-stalwart.md \
  docs/superpowers/plans/2026-07-23-debug-dashboard-mail-providers.md \
  docs/superpowers/plans/2026-07-23-debug-dashboard-message-lab-observability.md \
  tests/test_dependency_policy.py
git commit -m "docs: correct future dashboard dependency plans"
```

## Task 4: Upgrade Python, Debian, and direct Postfix packages

**Files:**

- Modify: `oauth2-mock/Dockerfile`
- Modify: `postfix/Dockerfile`
- Modify: `postfix/main.cf`
- Modify: `tests/test_dependency_policy.py`
- Modify: `oauth2-mock/test_server.py` only if Python 3.14 exposes a proven incompatibility

- [ ] **Step 1: Add base-image/package RED tests**

Require exact lines:

```text
FROM python:3.14.6-slim-trixie@sha256:cea0e6040540fb2b965b6e7fb5ffa00871e632eef63719f0ea54bca189ce14a6
FROM debian:13.6-slim@sha256:020c0d20b9880058cbe785a9db107156c3c75c2ac944a6aa7ab59f2add76a7bd
postfix=3.10.12-0+deb13u2
libsasl2-2=2.1.28+dfsg1-9
libsasl2-modules=2.1.28+dfsg1-9
sasl2-bin=2.1.28+dfsg1-9
netcat-openbsd=1.229-1
compatibility_level = 3.6
```

Reject floating base tags and unversioned direct `apt-get install` entries.

- [ ] **Step 2: Verify RED**

```bash
python3 -B -W error -m unittest discover \
  -s tests -p 'test_dependency_policy.py' -v
```

Expected: FAIL on the current Python 3.12/Bookworm/unversioned packages.

- [ ] **Step 3: Update Dockerfiles and Postfix compatibility**

Use exact `package=version` arguments with `--no-install-recommends`. Keep apt
index cleanup in the same layer. Add exactly one
`compatibility_level = 3.6` assignment to `main.cf`; do not alter recipient,
SASL, TLS, wrapper-mode, socketmap, or LMTP behavior.

- [ ] **Step 4: Run the complete OAuth2 suite on the selected host Python**

```bash
test "$(python3.14 -c 'import platform; print(platform.python_version())')" = \
  3.14.6
python3.14 -B -W error -m py_compile oauth2-mock/server.py
python3.14 -B -W error -m unittest discover \
  -s oauth2-mock -p 'test_server.py' -v
```

Expected: the interpreter is exactly 3.14.6, compilation PASS, and every test
PASS, including the test that invokes the host's installed Docker Compose and
the tests that read the shared Gate 0C passwd-shape fixture. This command is
mandatory. If exact host Python 3.14.6 or Docker Compose is unavailable, stop
the task; the plain Python application image cannot substitute for the
Compose-capable host test environment.

- [ ] **Step 5: Verify GREEN static policy**

```bash
python3 -B -W error -m unittest discover \
  -s tests -p 'test_dependency_policy.py' -v
docker compose config --quiet
```

Expected: PASS.

- [ ] **Step 6: Build and characterize bounded disposable images**

```bash
(
set -eu

probe_ports() {
  for probe_port in 1025 1465 1587 8080; do
    probe_output=""
    if probe_output="$(
      LC_ALL=C lsof -nP -iTCP:"$probe_port" -sTCP:LISTEN 2>/dev/null
    )"; then
      printf '%s\n%s\n' "$probe_port:present" "$probe_output"
    else
      probe_lsof_status=$?
      test "$probe_lsof_status" -eq 1
      printf '%s\n' "$probe_port:absent"
    fi
  done
}

probe_ports_before="$(probe_ports)"
test -z "$(docker ps -aq \
  --filter label=mail.sandbox.probe=dependency-base)"
test -z "$(docker ps -aq \
  --filter label=com.docker.compose.project=mail-sandbox-dependency-base-probe)"
test -z "$(docker network ls -q \
  --filter label=com.docker.compose.project=mail-sandbox-dependency-base-probe)"
test -z "$(docker volume ls -q \
  --filter label=com.docker.compose.project=mail-sandbox-dependency-base-probe)"
test ! -e debug-dashboard/.runtime/dependency-base-probe
test ! -e /private/tmp/mail-sandbox-dependency-base-probe.lifecycle.lock

cleanup_dependency_base_probe() {
  probe_incoming_status=$?
  probe_cleanup_status=0
  trap - EXIT INT TERM

  for probe_container_id in $(
    docker ps -aq --filter label=mail.sandbox.probe=dependency-base
  ); do
    test "$(
      docker inspect --format \
        '{{index .Config.Labels "mail.sandbox.probe"}}' \
        "$probe_container_id"
    )" = dependency-base || probe_cleanup_status=1
    if test "$probe_cleanup_status" -eq 0; then
      docker rm -f "$probe_container_id" || probe_cleanup_status=1
    fi
  done
  docker compose -p mail-sandbox-dependency-base-probe \
    down --remove-orphans || probe_cleanup_status=1

  test -z "$(docker ps -aq \
    --filter label=mail.sandbox.probe=dependency-base)" || \
    probe_cleanup_status=1
  test -z "$(docker ps -aq \
    --filter label=com.docker.compose.project=mail-sandbox-dependency-base-probe)" || \
    probe_cleanup_status=1
  test -z "$(docker network ls -q \
    --filter label=com.docker.compose.project=mail-sandbox-dependency-base-probe)" || \
    probe_cleanup_status=1
  test -z "$(docker volume ls -q \
    --filter label=com.docker.compose.project=mail-sandbox-dependency-base-probe)" || \
    probe_cleanup_status=1
  test "$(probe_ports)" = "$probe_ports_before" || probe_cleanup_status=1
  test ! -e debug-dashboard/.runtime/dependency-base-probe || \
    probe_cleanup_status=1
  test ! -e /private/tmp/mail-sandbox-dependency-base-probe.lifecycle.lock || \
    probe_cleanup_status=1

  if test "$probe_incoming_status" -ne 0; then
    exit "$probe_incoming_status"
  fi
  exit "$probe_cleanup_status"
}

trap cleanup_dependency_base_probe EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

docker pull \
  python:3.14.6-slim-trixie@sha256:cea0e6040540fb2b965b6e7fb5ffa00871e632eef63719f0ea54bca189ce14a6
docker pull \
  debian:13.6-slim@sha256:020c0d20b9880058cbe785a9db107156c3c75c2ac944a6aa7ab59f2add76a7bd
docker image inspect \
  python:3.14.6-slim-trixie@sha256:cea0e6040540fb2b965b6e7fb5ffa00871e632eef63719f0ea54bca189ce14a6 \
  --format '{{json .RepoDigests}}'
docker image inspect \
  debian:13.6-slim@sha256:020c0d20b9880058cbe785a9db107156c3c75c2ac944a6aa7ab59f2add76a7bd \
  --format '{{json .RepoDigests}}'

docker compose -p mail-sandbox-dependency-base-probe build --pull \
  oauth2-mock postfix
docker run --rm --network none \
  --name mail-sandbox-dependency-base-python \
  --label mail.sandbox.probe=dependency-base \
  --entrypoint python \
  mail-sandbox-dependency-base-probe-oauth2-mock --version
docker run --rm --network none \
  --name mail-sandbox-dependency-base-python-compile \
  --label mail.sandbox.probe=dependency-base \
  --entrypoint python \
  mail-sandbox-dependency-base-probe-oauth2-mock \
  -B -W error -m py_compile /app/server.py
docker run --rm --network none \
  --name mail-sandbox-dependency-base-postfix \
  --label mail.sandbox.probe=dependency-base \
  --mount "type=bind,source=$PWD/ssl,target=/etc/postfix/ssl,readonly" \
  --entrypoint /bin/sh \
  mail-sandbox-dependency-base-probe-postfix -ec \
  'postfix check;
   dpkg-query -W -f="\${Package}=\${Version}\n" \
     postfix libsasl2-2 libsasl2-modules sasl2-bin netcat-openbsd;
   postconf mail_version compatibility_level;
   postconf -m;
   postconf -n'

exit 0
)
```

Expected: both base-image `RepoDigests` contain the exact selected digest;
Python reports 3.14.6 and the image-contained server source compiles under that
interpreter; the complete Compose-aware OAuth2 suite has already passed under
the exact selected host interpreter in Step 4; `dpkg-query` reports exactly
`postfix=3.10.12-0+deb13u2`,
`libsasl2-2=2.1.28+dfsg1-9`, `libsasl2-modules=2.1.28+dfsg1-9`,
`sasl2-bin=2.1.28+dfsg1-9`, and `netcat-openbsd=1.229-1`; Postfix reports
3.10.12 and compatibility level 3.6; `postfix check` passes; `postconf -m`
contains `socketmap`; reviewed `postconf -n` retains all intended local-sandbox
behavior; every incoming failure/signal exits through cleanup; and container,
network, volume, selected-port, exact runtime-directory, and exact lock state
match the preflight.

- [ ] **Step 7: Commit**

```bash
git add oauth2-mock/Dockerfile postfix/Dockerfile postfix/main.cf \
  oauth2-mock/test_server.py tests/test_dependency_policy.py
git commit -m "build: upgrade Python and Postfix base stack"
```

## Task 5: Upgrade Dovecot to 2.4.4 and remove deleted utility assumptions

**Files:**

- Create: `config/operator/healthcheck.sh`
- Modify: `config/operator/dovecot.conf`
- Modify: `docker-compose.yml`
- Modify: `debug-dashboard/dashboard-server/testResources/dovecot-gate0c/compose.task5-proof.yml`
- Modify: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotBaselineConfigAuditTest.kt`
- Modify: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorConfigTest.kt`
- Modify: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotLiveTestEnvironmentTest.kt`
- Modify: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotTask6TopologyProof.kt`
- Modify: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotTask6TopologyProofTest.kt`
- Modify: `.ai/skills/docker-compose/references/service-map.md`
- Modify: `.ai/skills/docker-compose/references/volume-mounts.md`
- Modify: `.ai/skills/dovecot/references/auth.md`
- Modify: `.ai/skills/dovecot/references/config-files.md`
- Modify: `docs/superpowers/specs/2026-07-23-debug-dashboard-design.md`

- [ ] **Step 1: Change exact Dovecot and POP3S expectations and verify RED**

Tests must require both Dovecot services to use:

```text
dovecot/dovecot:2.4.4@sha256:723e3392fe16c6fad8ddc605ea767cc01b4bad9cd9f13eb1dbac15e79c89b2d4
```

Require POP3S host mappings to target container port `31995` in base and proof
Compose. Require operator config version 2.4.4 and storage version 2.4.3, which
matches the official 2.4.4 image's storage-compatibility declaration. Require
the healthcheck to execute the mounted helper and reject `grep`, `awk`, `sed`,
and `procps` assumptions.

```bash
cd debug-dashboard
./kotlin test \
  --include-module dashboard-server \
  --include-classes \
  'mail.sandbox.dashboard.server.gate.dovecot.DovecotBaselineConfigAuditTest' \
  --include-classes \
  'mail.sandbox.dashboard.server.gate.dovecot.DovecotOperatorConfigTest' \
  --include-classes \
  'mail.sandbox.dashboard.server.gate.dovecot.DovecotTask6TopologyProofTest'
cd ..
```

Expected: FAIL on 2.4.1, port 31990, old config/storage versions, and inline
`grep`/`awk` healthcheck.

- [ ] **Step 2: Implement a dependency-free operator healthcheck**

Write a mode-0755 POSIX `sh` script that uses only shell built-ins plus
`doveadm`. It must:

1. parse `doveadm service status auth` and `imap-login` line by line;
2. require numeric `process_count >= 1`, `throttle_secs = 0`, and
   `doveadm_stop = n` for both;
3. parse `/proc/net/tcp` and `/proc/net/tcp6` using `read`/`case`, validate the
   header and every examined row, and require exactly one LISTEN socket at
   `0100007F:7CF9` (127.0.0.1:31993) with no wildcard/IPv6 duplicate;
4. fail closed on malformed, missing, or duplicate data.

For deterministic tests, permit fixture paths only through
`DOVECOT_OPERATOR_PROC_TCP` and `DOVECOT_OPERATOR_PROC_TCP6`; production
Compose sets neither. Tests execute the real script with a temporary `PATH`
containing a deterministic fake `doveadm` and the existing listener fixtures.
Do not copy absent utilities into the image.

Mount the helper read-only at `/usr/local/bin/operator-healthcheck` and set the
healthcheck to `CMD /usr/local/bin/operator-healthcheck`. Add the mount to both
base Compose and the proof override because the proof uses `volumes:
!override`; run `chmod 0755 config/operator/healthcheck.sh` before staging.

- [ ] **Step 3: Update image, config, and port declarations**

Change both Dovecot image references, both base/proof POP3S target ports, and
operator config/storage versions. Preserve `auth_failure_delay = 0s` and the
reviewed four-passdb semantics. Update active Dovecot auth/service references
to state that 2.4.4 behavior must be proven; preserve historical 2.4.1 gate
records as history.

- [ ] **Step 4: Run focused static/config tests**

```bash
cd debug-dashboard
./kotlin test \
  --include-module dashboard-server \
  --include-classes \
  'mail.sandbox.dashboard.server.gate.dovecot.DovecotBaselineConfigAuditTest' \
  --include-classes \
  'mail.sandbox.dashboard.server.gate.dovecot.DovecotOperatorConfigTest' \
  --include-classes \
  'mail.sandbox.dashboard.server.gate.dovecot.DovecotTask6TopologyProofTest' \
  --include-classes \
  'mail.sandbox.dashboard.server.gate.dovecot.DovecotLiveTestEnvironmentTest'
cd ..
docker compose config --quiet
docker compose --profile dovecot-operator config --quiet
```

Expected: PASS and no reference to target port 31990 in active configuration.

- [ ] **Step 5: Inspect the exact image before live use**

```bash
docker pull \
  dovecot/dovecot:2.4.4@sha256:723e3392fe16c6fad8ddc605ea767cc01b4bad9cd9f13eb1dbac15e79c89b2d4
docker image inspect \
  dovecot/dovecot:2.4.4@sha256:723e3392fe16c6fad8ddc605ea767cc01b4bad9cd9f13eb1dbac15e79c89b2d4
```

Expected: matching `RepoDigests`; multi-architecture reference resolves for
the host; no live service changed.

- [ ] **Step 6: Commit**

```bash
git add config/operator/healthcheck.sh config/operator/dovecot.conf \
  docker-compose.yml \
  debug-dashboard/dashboard-server/testResources/dovecot-gate0c/compose.task5-proof.yml \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotBaselineConfigAuditTest.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotOperatorConfigTest.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotLiveTestEnvironmentTest.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotTask6TopologyProof.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotTask6TopologyProofTest.kt \
  .ai/skills/docker-compose/references/service-map.md \
  .ai/skills/docker-compose/references/volume-mounts.md \
  .ai/skills/dovecot/references/auth.md \
  .ai/skills/dovecot/references/config-files.md \
  docs/superpowers/specs/2026-07-23-debug-dashboard-design.md
git commit -m "build: upgrade Dovecot provider baseline"
```

## Task 6: Re-prove the complete disposable Dovecot/Postfix lifecycle

**Files:**

- Modify: `debug-dashboard/dashboard-server/testResources/dovecot-gate0c/run-task5-proof.sh`
- Modify: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotTask5ProofLifecycleTest.kt`
- Modify only on proven incompatibility: other Gate 0C Kotlin/Python/test-resource files named by the failing proof
- Modify: `docs/debug-dashboard/gates/0c-dovecot.md`

- [ ] **Step 1: Write and run a RED proof-lifecycle isolation test**

Extend `DovecotTask5ProofLifecycleTest.kt` so the real script is rejected if it
uses unfiltered container/network/volume enumeration or inspects an arbitrary
pre-existing container ID. Its fake-Docker lifecycle must fail if any command
could resolve the normal `stalwart` Compose service. Permit inventory only for
the exact proof project/fixed proof names and baseline inspection only for the
explicit ordinary-service allowlist `dovecot`, `postfix`, and `oauth2-mock`.
Run that class alone and expect RED on the current broad `docker ps`, name
inventory, and arbitrary-ID `docker inspect` calls.

- [ ] **Step 2: Scope the lifecycle script and capture its allowed baseline**

Replace every broad inventory with label/name filters for the exact proof
project or an exact fixed proof resource. Build the ordinary baseline from
separate `com.docker.compose.project=dovecot-docker` plus service-label queries
for only `dovecot`, `postfix`, and `oauth2-mock`, and inspect only IDs returned
by those allowlisted queries. Do not inspect the shared normal-project network
or volumes because they can include Stalwart; lifecycle network/volume checks
are limited to the exact proof project.
Do not enumerate, inspect, compare, or mention the normal Stalwart service.
Rerun `DovecotTask5ProofLifecycleTest` and expect PASS.

Record the allowlisted ordinary-service state, exact proof-scoped networks and
volumes, occupied proof ports, `.runtime/task5-proof`, and proof locks. This
baseline deliberately has no assertion about any non-allowlisted service.

- [ ] **Step 3: Run non-live suites first**

```bash
python3 -B -W error -m unittest discover \
  -s oauth2-mock -p 'test_server.py' -v
cd debug-dashboard
./kotlin test \
  --include-module dashboard-server \
  --exclude-classes 'mail.sandbox.dashboard.server.gate.dovecot.*LiveTest' \
  --exclude-classes 'mail.sandbox.dashboard.server.gate.stalwart.*LiveTest'
cd ..
```

Expected: all PASS. Repair actual 2.4.4 incompatibilities with a new RED test
before production changes.

- [ ] **Step 4: Run the bounded Gate 0C lifecycle**

```bash
debug-dashboard/dashboard-server/testResources/dovecot-gate0c/run-task5-proof.sh
```

Expected: startup, topology/network isolation, ordinary password/OAuth,
four-passdb direct/master/missing/deleted-target matrix, operator process
inventory, rotation, IMAP mailbox operations, Postfix SMTP/SASL/socketmap/LMTP
delivery, POP3/POP3S, and cleanup all PASS against the selected versions.

- [ ] **Step 5: Prove container-reported versions and compatibility**

Within the disposable lifecycle evidence require:

```text
dovecot --version -> 2.4.4
python --version -> Python 3.14.6
postconf mail_version -> 3.10.12
postconf compatibility_level -> 3.6
dpkg-query postfix -> 3.10.12-0+deb13u2
dpkg-query libsasl2-2 -> 2.1.28+dfsg1-9
dpkg-query libsasl2-modules -> 2.1.28+dfsg1-9
dpkg-query sasl2-bin -> 2.1.28+dfsg1-9
dpkg-query netcat-openbsd -> 1.229-1
```

Require ordinary and operator `doveconf -n`, corrected POP3S 31995 readiness,
the dependency-free operator healthcheck, and the exact in-container
`dpkg-query -W -f='${Package}=${Version}\n'` output rather than Dockerfile text
alone.

- [ ] **Step 6: Audit cleanup against the captured allowlist**

Expected: no proof container/network/volume/runtime/lock/port remains and the
allowlisted ordinary Dovecot/Postfix/OAuth state is restored as designed. No
normal Stalwart query is part of either baseline or postflight.

- [ ] **Step 7: Append superseding Gate 0C evidence and commit**

Record exact commands/results, versions/digests, failure/repair history, and
cleanup evidence. Preserve the 2.4.1 report as historical.

```bash
git add docs/debug-dashboard/gates/0c-dovecot.md \
  debug-dashboard/dashboard-server/testResources/dovecot-gate0c/run-task5-proof.sh \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotTask5ProofLifecycleTest.kt
git commit -m "test: reprove Dovecot gate on latest provider stack"
```

## Task 7: Add missing mail/account contracts and move active Stalwart targets to v0.16.16

> **Completion-day freshness amendment (2026-08-04):** v0.16.15 was the
> approved latest stable target, but Stalwart published stable v0.16.16 on
> 2026-08-02 before this task began. Policy A therefore requires v0.16.16 and
> its exact OCI index digest. The tagged v0.16.16 migration script is
> byte-identical to v0.16.15, while CLI 1.0.12 remains selected because its
> official `latest`, `1.0`, and `1.0.12` tags share the same index digest.
>
> **Contract correction:** JMAP `Email/copy` is strictly cross-account and
> rejects equal source/target Account IDs. The dashboard's per-account folder
> copy/move requirement uses `Email/set` mailbox-membership patches. Do not add
> impersonation, management mail permissions, or a shared-account ACL only to
> reproduce an upstream cross-account regression that the dashboard will not
> invoke.

**Files:**

- Modify: `docker-compose.stalwart-migration.yml`
- Modify: `scripts/capture_stalwart_v015.py`
- Modify: `scripts/bootstrap_stalwart_v016.py`
- Modify: `scripts/stalwart_v016.py`
- Modify: `scripts/stalwart_v016_registry.py`
- Modify: `docs/stalwart-v016-migration.md`
- Modify: `docs/superpowers/specs/2026-07-23-debug-dashboard-design.md`
- Modify: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/gate/stalwart/GateBootstrap.kt`
- Modify: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/gate/stalwart/StalwartRoutingProofCli.kt`
- Modify if required by the GREEN run: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/gate/stalwart/GateJmapClient.kt`
- Modify: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/stalwart/StalwartDockerMountAudit.kt`
- Modify: `debug-dashboard/dashboard-server/testResources/stalwart-gate0b/compose.yml`
- Modify: `tests/test_stalwart_migration_compose.py`
- Modify: `tests/test_bootstrap_stalwart_v016.py`
- Modify: `tests/test_stalwart_v016.py`
- Modify: `tests/test_capture_stalwart_v015.py`
- Modify: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/stalwart/StalwartFixtureSecretTest.kt`
- Modify: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/stalwart/StalwartGateCleanupTest.kt`
- Modify: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/stalwart/StalwartRoutingProofCliTest.kt`
- Modify if required by the GREEN run: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/stalwart/GateJmapClientTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/stalwart/StalwartMailMutationLiveTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/stalwart/StalwartRegistryRoutingDeletionLiveTest.kt`

- [ ] **Step 1: Change target-identity tests only and verify RED**

Require the exact image:

```text
stalwartlabs/stalwart:v0.16.16@sha256:66ae90f2753ec1dabd70f69cad7da9f0598d2628a04193ce2b08c7263d47aced
```

Require CLI:

```text
stalwartlabs/cli:1.0.12@sha256:fe199affac1d120a8c200ef39ae629765a2976270e0453575c1caf906ee15b52
```

Require the v0.16.16 migration-script URL while retaining script SHA-256
`008a490b4c3c60572806958e1960749ecdddf263316683017003797b9c34ca1c`.
Require migration overlay SHA-256
`77dee99e79f4ce6a6be63edc51b5090e8fbab484fbdc04331cf0bd19f4bc28ca`
when its only semantic target change is the approved image reference.

```bash
python3 -B -W error -m unittest \
  tests.test_stalwart_migration_compose \
  tests.test_bootstrap_stalwart_v016 \
  tests.test_stalwart_v016 \
  tests.test_capture_stalwart_v015 -v
```

Expected: FAIL on the old v0.16.14 target identity.

- [ ] **Step 2: Write the two missing disposable live contracts**

Before changing the disposable image pin, create
`StalwartMailMutationLiveTest.kt`. Against only the Gate fixture it must import
one uniquely marked Email, create a target Mailbox, and prove:

1. same-account copy adds the target mailbox membership while retaining the
   source membership;
2. same-account move atomically adds the target membership and removes the
   source membership in one `Email/set` update;
3. `$seen` and `$flagged` can each be added and removed;
4. stale `ifInState`, method errors, and partial `notUpdated` outcomes remain
   typed failures without broad retry or cross-account `Email/copy`.

Record marker/mailbox/Email IDs before every dispatch and reconcile the exact
marker in a `NonCancellable` `finally`, including lost-response paths.

Create `StalwartRegistryRoutingDeletionLiveTest.kt`. It must take a bounded
`Account/query` snapshot, create one exact uniquely named Gate-owned
`@local.test` User Account, and verify the fetched Registry projection: stable
ID/domain, User role, Inherit permissions, exactly one Password projection,
and no exposed plaintext secret. Route unique messages through both actual
SMTP `AUTH`/`MAIL`/`RCPT`/`DATA` on `127.0.0.1:18587` and JMAP
`EmailSubmission`, then read both through that Account's JMAP credential.
Destroy the exact data-bearing Account and require `destroyed`, `Account/get`
`notFound`, the original bounded query inventory, rejected JMAP authentication,
and rejected SMTP recipient resolution. Its `finally` may reconcile and delete
only the exact Gate-owned Account; it must not perform broad Registry cleanup.

Reuse `GateJmapClient.call()`, the existing fixture-secret abstractions, and
the exact cleanup registry. Do not change a client pre-emptively.

- [ ] **Step 3: Characterize both new contracts while target identity stays RED**

Run the existing Gate 0B fixture prepare → recovery Compose up → bootstrap →
recovery retirement sequence under only project
`mail-sandbox-stalwart-gate`, ports 18443/18587, and
`debug-dashboard/.runtime/stalwart-gate0b`. Execute preparation, both new
classes, and cleanup in this one guarded shell; the EXIT trap is installed
before the first preparation command:

```bash
(
set -eu
gate_repository_root="$PWD"
mail_mutation_status=0
registry_routing_status=0

cleanup_gate0b() {
  gate_incoming_status=$?
  gate_cleanup_status=0
  trap - EXIT INT TERM
  (
    cd "$gate_repository_root/debug-dashboard"
    STALWART_GATE_CLEANUP=1 \
    ./kotlin test \
      --include-module dashboard-server \
      --include-classes \
      'mail.sandbox.dashboard.server.gate.stalwart.StalwartGateCleanupLiveTest'
  ) || gate_cleanup_status=$?
  if test "$gate_incoming_status" -ne 0; then
    exit "$gate_incoming_status"
  fi
  exit "$gate_cleanup_status"
}

trap cleanup_gate0b EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

cd "$gate_repository_root/debug-dashboard"
STALWART_GATE_PREPARE=1 \
./kotlin test \
  --include-module dashboard-server \
  --include-classes \
  'mail.sandbox.dashboard.server.gate.stalwart.StalwartFixturePrepareLiveTest'

cd "$gate_repository_root"
export STALWART_GATE_RECOVERY_ENV_FILE="$gate_repository_root/debug-dashboard/.runtime/stalwart-gate0b/recovery.env"
docker compose -p mail-sandbox-stalwart-gate \
  -f debug-dashboard/dashboard-server/testResources/stalwart-gate0b/compose.yml \
  -f debug-dashboard/dashboard-server/testResources/stalwart-gate0b/compose.recovery.yml \
  config --no-env-resolution --quiet
docker compose -p mail-sandbox-stalwart-gate \
  -f debug-dashboard/dashboard-server/testResources/stalwart-gate0b/compose.yml \
  -f debug-dashboard/dashboard-server/testResources/stalwart-gate0b/compose.recovery.yml \
  up -d --wait

cd "$gate_repository_root/debug-dashboard"
STALWART_LIVE_TESTS=1 \
STALWART_BASE_URL=http://127.0.0.1:18443 \
STALWART_GATE_FIXTURE_SECRETS_FILE="$PWD/.runtime/stalwart-gate0b/fixture-secrets" \
./kotlin test \
  --include-module dashboard-server \
  --include-classes \
  'mail.sandbox.dashboard.server.gate.stalwart.StalwartBootstrapLiveTest'

cd "$gate_repository_root"
docker compose -p mail-sandbox-stalwart-gate \
  -f debug-dashboard/dashboard-server/testResources/stalwart-gate0b/compose.yml \
  stop stalwart
docker compose -p mail-sandbox-stalwart-gate \
  -f debug-dashboard/dashboard-server/testResources/stalwart-gate0b/compose.yml \
  up -d --wait --force-recreate
gate_environment="$(docker compose -p mail-sandbox-stalwart-gate \
  -f debug-dashboard/dashboard-server/testResources/stalwart-gate0b/compose.yml \
  exec -T stalwart /usr/bin/env)"
if printf '%s\n' "$gate_environment" | rg -q '^STALWART_RECOVERY_'; then
  exit 1
fi

cd "$gate_repository_root/debug-dashboard"
STALWART_LIVE_TESTS=1 \
STALWART_BASE_URL=http://127.0.0.1:18443 \
STALWART_GATE_FIXTURE_SECRETS_FILE="$PWD/.runtime/stalwart-gate0b/fixture-secrets" \
./kotlin test \
  --include-module dashboard-server \
  --include-classes \
  'mail.sandbox.dashboard.server.gate.stalwart.StalwartRecoveryRetirementLiveTest'

if STALWART_LIVE_TESTS=1 \
  STALWART_BASE_URL=http://127.0.0.1:18443 \
  STALWART_GATE_FIXTURE_SECRETS_FILE="$PWD/.runtime/stalwart-gate0b/fixture-secrets" \
  ./kotlin test \
    --include-module dashboard-server \
    --include-classes \
    'mail.sandbox.dashboard.server.gate.stalwart.StalwartRegistryRoutingDeletionLiveTest'; then
  registry_routing_status=0
else
  registry_routing_status=$?
fi
if STALWART_LIVE_TESTS=1 \
  STALWART_BASE_URL=http://127.0.0.1:18443 \
  STALWART_GATE_FIXTURE_SECRETS_FILE="$PWD/.runtime/stalwart-gate0b/fixture-secrets" \
  ./kotlin test \
    --include-module dashboard-server \
    --include-classes \
    'mail.sandbox.dashboard.server.gate.stalwart.StalwartMailMutationLiveTest'; then
  mail_mutation_status=0
else
  mail_mutation_status=$?
fi

test "$registry_routing_status" -eq 0
test "$mail_mutation_status" -eq 0
exit 0
)
```

Expected: Registry projection, SMTP/JMAP routing, and Account deletion PASS as
a v0.16.14 characterization; same-account mailbox/keyword mutations also PASS.
The target-identity tests from Step 1 keep the upgrade batch RED until every
active disposable/migration target uses the exact v0.16.16 reference.
`StalwartGateCleanupLiveTest` runs in a guaranteed postflight and proves only
the exact Gate project, ports, and runtime root are absent. Do not query,
enumerate, or compare normal Stalwart.

- [ ] **Step 4: Update target constants and fixtures mechanically but safely**

Replace only active v0.16.14 targets. Preserve tests that deliberately use
v0.16.15 as a wrong-version fixture because it remains an explicit mismatch
for v0.16.16; do not accidentally make negative tests valid. Preserve
deliberate `:latest` negative fixtures that prove floating tags are rejected.

Leave the normal `docker-compose.yml` and `stalwart/config.toml` byte-for-byte
unchanged in this task. They remain the capture source until Task 9 receives
the explicit phrase and records a verified rollback capture. Tests must permit
that one known legacy source model temporarily while requiring v0.16.16 for
every migration target and disposable fixture. The dependency gate remains
incomplete while that source model is present.

- [ ] **Step 5: Run Python and Kotlin offline tests**

```bash
python3 -B -W error -m unittest discover -s tests -p 'test_*stalwart*.py' -v
cd debug-dashboard
./kotlin test \
  --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.gate.stalwart.*' \
  --exclude-classes 'mail.sandbox.dashboard.server.gate.stalwart.*LiveTest'
cd ..
```

Expected: PASS without Docker access or live Stalwart access.

- [ ] **Step 6: Validate models and prove selected image identities**

Run validation-only commands for the migration overlay and both disposable
fixture models. Use `config --quiet` and `--no-env-resolution` where
credentials are involved. Do not validate the future normal v0.16 model by
mutating its still-live v0.15 source, and do not run `ps`, `images`, `inspect`,
`exec`, `up`, `down`, `start`, `stop`, or `restart` against the normal project.

Then operate on images only:

```bash
docker pull \
  stalwartlabs/stalwart:v0.16.16@sha256:66ae90f2753ec1dabd70f69cad7da9f0598d2628a04193ce2b08c7263d47aced
docker pull \
  stalwartlabs/cli:1.0.12@sha256:fe199affac1d120a8c200ef39ae629765a2976270e0453575c1caf906ee15b52
docker image inspect \
  stalwartlabs/stalwart:v0.16.16@sha256:66ae90f2753ec1dabd70f69cad7da9f0598d2628a04193ce2b08c7263d47aced \
  --format '{{json .RepoDigests}} {{.Id}}'
docker image inspect \
  stalwartlabs/cli:1.0.12@sha256:fe199affac1d120a8c200ef39ae629765a2976270e0453575c1caf906ee15b52 \
  --format '{{json .RepoDigests}} {{.Id}}'
docker run --rm --pull never --network none \
  stalwartlabs/cli:1.0.12@sha256:fe199affac1d120a8c200ef39ae629765a2976270e0453575c1caf906ee15b52 \
  --version
docker run --rm --pull never --network none \
  --entrypoint /usr/local/bin/stalwart \
  stalwartlabs/stalwart:v0.16.16@sha256:66ae90f2753ec1dabd70f69cad7da9f0598d2628a04193ce2b08c7263d47aced \
  --version
```

Expected: each `RepoDigests` contains the selected multi-architecture digest;
CLI reports 1.0.12; server reports 0.16.16. Update the documented and tested
platform-local `STALWART_IMAGE_ID` to the `.Id` returned only after that
RepoDigest check. The `.Id` is supplementary host-local evidence, never a
substitute for the approved repository digest.

- [ ] **Step 7: Run both new contracts GREEN on v0.16.16**

Repeat the complete single-shell lifecycle from Step 3 after the v0.16.16 pin,
including installing the EXIT/INT/TERM cleanup handlers before fixture
preparation. Change only the final version-specific assertions:

```bash
test "$registry_routing_status" -eq 0
test "$mail_mutation_status" -eq 0
exit 0
```

Expected: both selected classes PASS without assumption/skip, and the guarded
EXIT handler proves the exact Gate project/container/network/volume/ports,
runtime directory, and lock state are restored before this task may commit.

If v0.16.16 violates the approved provider behavior, leave the batch RED and
stop; never downgrade. If the failure instead demonstrates a client
request/response incompatibility, first add its smallest fixture to
`GateJmapClientTest.kt`, run that focused unit RED, make the minimal
`GateJmapClient.kt` change, rerun the unit GREEN, and then repeat the complete
guarded live lifecycle until both new classes are GREEN.

- [ ] **Step 8: Commit only the GREEN Stalwart target and contracts**

```bash
git add docker-compose.stalwart-migration.yml \
  scripts/capture_stalwart_v015.py scripts/bootstrap_stalwart_v016.py \
  scripts/stalwart_v016.py scripts/stalwart_v016_registry.py \
  docs/stalwart-v016-migration.md \
  docs/superpowers/specs/2026-07-23-debug-dashboard-design.md \
  debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/gate/stalwart/GateBootstrap.kt \
  debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/gate/stalwart/GateJmapClient.kt \
  debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/gate/stalwart/StalwartRoutingProofCli.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/stalwart/GateJmapClientTest.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/stalwart/StalwartDockerMountAudit.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/stalwart/StalwartFixtureSecretTest.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/stalwart/StalwartGateCleanupTest.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/stalwart/StalwartRoutingProofCliTest.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/stalwart/StalwartMailMutationLiveTest.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/stalwart/StalwartRegistryRoutingDeletionLiveTest.kt \
  debug-dashboard/dashboard-server/testResources/stalwart-gate0b/compose.yml \
  tests/test_stalwart_migration_compose.py \
  tests/test_bootstrap_stalwart_v016.py \
  tests/test_stalwart_v016.py tests/test_capture_stalwart_v015.py
git commit -m "build: upgrade Stalwart target baseline"
```

## Task 8: Add a fail-safe runner and re-prove complete disposable Gate 0B

**Files:**

- Create: `debug-dashboard/dashboard-server/testResources/stalwart-gate0b/run-latest-proof.sh`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/stalwart/StalwartLatestProofLifecycleTest.kt`
- Execute: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/stalwart/StalwartMailMutationLiveTest.kt`
- Execute: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/stalwart/StalwartRegistryRoutingDeletionLiveTest.kt`
- Modify if required by a proven regression: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/gate/stalwart/GateJmapClient.kt`
- Modify if required by a proven regression: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/stalwart/GateJmapClientTest.kt`
- Modify: `docs/debug-dashboard/gates/0b-stalwart.md`

- [ ] **Step 1: Write the bounded-runner RED test**

Create `StalwartLatestProofLifecycleTest.kt`. Audit and execute a temporary
mirror of the real runner with a fake `docker` on `PATH` and a fake Kotlin
wrapper at the runner's fixed relative path. Require:

1. `set -eu`, an EXIT cleanup handler, and INT/TERM handlers that call `exit`
   are installed before `StalwartFixturePrepareLiveTest` or any Compose `up`;
2. the handler always selects `StalwartGateCleanupLiveTest`, preserves a
   nonzero incoming status, and turns cleanup failure into failure after a
   successful body;
3. prepare failure, bootstrap failure, each selected live-test failure, restart
   failure, INT, and TERM all execute cleanup exactly once and cannot continue;
4. only project `mail-sandbox-stalwart-gate`, ports 18443/18587, and runtime
   root `.runtime/stalwart-gate0b` are referenced;
5. every canonical class is selected directly, so no loop/last-command status
   can mask an earlier failure;
   Docker output checked with `rg` is first captured by a checked command, so a
   failed Docker command cannot masquerade as a negative match;
6. `StalwartMigrationLiveTest`, `StalwartRoutingLiveTest`, normal project/data,
   broad Docker enumeration/prune, `down -v`, and `--volumes` are absent.

Run the new class from `debug-dashboard/` and expect RED because the runner is
missing.

- [ ] **Step 2: Implement the single-process fail-safe runner**

Move the report's exact prepare → recovery up → bootstrap → recovery retirement
→ base restart sequence into mode-0755 `run-latest-proof.sh`. Install the same
status-preserving handler pattern proven in Task 7 Step 3 before the first
prepare command. The runner must then execute, as individual checked commands:

- `StalwartRecoveryRetirementLiveTest`;
- `StalwartRawBlobCompatibilityLiveTest`;
- `StalwartPermissionMatrixLiveTest`;
- `StalwartAppPasswordSemanticsLiveTest`;
- `StalwartMailAccessLifecycleLiveTest`;
- `StalwartMailAccessRestartPrepareLiveTest` and
  `StalwartMailAccessRestartReconcileLiveTest` for each of `staged`, `retiring`,
  and `removal-pending`;
- `StalwartMailMutationLiveTest`; and
- `StalwartRegistryRoutingDeletionLiveTest`.

Use no command whose failure is consumed by a later passing command. Each new
test must clean its exact Registry/message artifacts before the runner's final
fixture cleanup. The cleanup handler must prove Gate containers/network/runtime
gone, zero new anonymous volumes, ports released, all Gate-owned credentials
and Registry artifacts absent, and lock state restored. It must never query,
enumerate, inspect, or compare normal Stalwart.

- [ ] **Step 3: Prove the runner offline**

```bash
chmod 0755 \
  debug-dashboard/dashboard-server/testResources/stalwart-gate0b/run-latest-proof.sh
cd debug-dashboard
./kotlin test \
  --include-module dashboard-server \
  --include-classes \
  'mail.sandbox.dashboard.server.gate.stalwart.StalwartLatestProofLifecycleTest'
./kotlin test \
  --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.gate.stalwart.*' \
  --exclude-classes 'mail.sandbox.dashboard.server.gate.stalwart.*LiveTest'
cd ..
```

Expected: runner lifecycle test and canonical offline Gate 0B PASS.

- [ ] **Step 4: Run the complete v0.16.16 disposable gate once**

```bash
debug-dashboard/dashboard-server/testResources/stalwart-gate0b/run-latest-proof.sh
```

Expected: every named class/phase executes without assumption/skip; same-account
copy/move/keyword mutation,
Registry projection, actual SMTP delivery, JMAP submission delivery, positive
data-bearing Account deletion, and post-deletion auth/recipient denial PASS;
the EXIT cleanup/postflight passes even if any body command fails.

- [ ] **Step 5: Repair only a demonstrated client incompatibility**

If v0.16.16 itself violates approved behavior, leave Gate 0B RED and stop;
never downgrade. If the runner proves an existing client parser/request
composer incompatible, add the smallest fixture to `GateJmapClientTest.kt`,
run that unit RED, make the minimal `GateJmapClient.kt` change, rerun the unit
GREEN, and rerun the complete guarded runner GREEN. Record both failure and
repair.

- [ ] **Step 6: Append superseding evidence and commit**

Record the v0.16.16 image/digest, reported version, runner hash, every selected
class/phase, commands/results, mail-mutation/Registry/routing/deletion behavior,
and cleanup comparison. Preserve v0.16.14 evidence as historical.

```bash
git add debug-dashboard/dashboard-server/testResources/stalwart-gate0b/run-latest-proof.sh \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/stalwart/StalwartLatestProofLifecycleTest.kt \
  debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/gate/stalwart/GateJmapClient.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/stalwart/GateJmapClientTest.kt \
  docs/debug-dashboard/gates/0b-stalwart.md
git commit -m "test: reprove Stalwart gate on latest provider stack"
```

## Task 9: Perform the normal Stalwart v0.16.16 cutover only after explicit authorization

**Files:**

- Modify: `docker-compose.yml`
- Create: `stalwart/config.json`
- Delete: `stalwart/config.toml`
- Modify: `tests/test_stalwart_migration_compose.py`
- Modify: `tests/test_capture_stalwart_v015.py`
- Modify: `tests/test_stalwart_v016.py`
- Modify: `tests/test_dependency_policy.py`
- Modify only on a proven migration failure: `scripts/capture_stalwart_v015.py`
- Modify: `scripts/stalwart_v016.py`
- Modify: `docs/stalwart-v016-migration.md`
- Modify: `PRODUCT.md`
- Modify: `CLAUDE.md`
- Modify: `.ai/skills/docker-compose/references/service-map.md`
- Modify: `.ai/skills/docker-compose/references/volume-mounts.md`
- Modify: `.ai/skills/stalwart/SKILL.md`
- Modify: `.ai/skills/stalwart/references/config.md`
- Modify: `.ai/skills/stalwart/references/admin-api.md`
- Modify if endpoints changed under the proven runtime: `.ai/skills/stalwart/references/oauth2.md`

- [ ] **Step 1: Integrate the reviewed pre-cutover commits into the primary checkout**

Complete Tasks 1–8 in the linked worktree, run their review/verification, and
commit every owned change. Invoke `superpowers:finishing-a-development-branch`
to integrate only those reviewed commits into the repository's primary
checkout using the selected safe strategy. Do not copy uncommitted files or
apply the future normal Stalwart Compose/config diff. In the primary checkout,
require the expected branch/commit set and a clean working tree; the Stalwart
service must still be the unchanged capture-source model.

- [ ] **Step 2: Stop and request the exact capture-only phrase**

Do not infer authorization from approval of this plan, Policy A, “continue,”
or the local-test security posture. Require exactly:

```text
I explicitly authorize the Stalwart capture command and leaving the service stopped.
```

This authorizes only the documented capture command and leaving its source
stopped. It does not authorize migration, live-store replacement, deletion,
rollback mutation, or starting a new runtime.

- [ ] **Step 3: Capture and verify the unchanged v0.15 source in the primary checkout**

Immediately after the phrase, run only the exact `capture` command from
`docs/stalwart-v016-migration.md` in the primary checkout. After it returns,
review only the output and receipt/proof files that this command already
created; do not invoke separate `verify`, `prove-rollback`, Docker, or migration
commands under the capture-only phrase. The capture itself must report a
stopped source, complete timestamped backup, immutable digest-bound receipt,
and its internally proved isolated rollback copy. Report that evidence to the
user while the source remains stopped.

- [ ] **Step 4: Request separate migration/cutover authorization**

After reporting the capture/rollback evidence, stop and require exactly:

```text
I explicitly authorize applying the Stalwart v0.16.16 migration, replacing the captured normal store, starting the new runtime, and performing the documented rollback if required.
```

Do not infer this second authorization from the capture phrase. Without it,
leave the verified capture and stopped source untouched and report the hold.

- [ ] **Step 5: Pin, assert, and receipt-bind the migration interpreter**

Before any normal-store verification, dry run, or apply, add RED tests in
`tests/test_stalwart_v016.py` that require the migration workflow to reject a
missing or mismatched package version and to include this exact map in its
dry-run, apply-attempt, and successful apply receipts under the exact field
name `migration_python_packages`:

```json
{"requests":"2.34.2","urllib3":"2.7.0"}
```

In the same RED batch, extend `tests/test_dependency_policy.py` to require the
runbook's exact `requests==2.34.2` and `urllib3==2.7.0` installation arguments,
exact host Python 3.14.6 assertion, and canonical distribution-metadata
version check. This static contract must be committed before live migration;
adding it later cannot prove which packages produced the cutover evidence.

Update `scripts/stalwart_v016.py` so it queries distribution metadata through
the absolute migration interpreter, compares the returned map exactly, and
binds the validated map into the dry-run, apply-attempt, and successful-apply
receipts before any upstream migration script can run. Imports alone are not
sufficient. Update the runbook's
owner-only virtual-environment block to use exact host Python 3.14.6 and:

```bash
"$MIGRATION_PYTHON" -m pip install \
  'requests==2.34.2' 'urllib3==2.7.0'
"$MIGRATION_PYTHON" -I -c \
  'import json; from importlib.metadata import version; expected={"requests":"2.34.2","urllib3":"2.7.0"}; observed={name:version(name) for name in expected}; assert observed == expected, (observed, expected); print(json.dumps(observed, sort_keys=True, separators=(",", ":")))'
```

Use the same focused command for both TDD observations:

```bash
python3.14 -B -W error -m unittest discover \
  -s tests -p 'test_stalwart_v016.py' -v
python3.14 -B -W error -m unittest discover \
  -s tests -p 'test_dependency_policy.py' -v
```

Expected before implementation: only the newly added version/receipt and
static-policy cases fail for the intended missing contract. Expected after
implementation: both focused files pass.

The runbook must first assert that `python3.14` reports 3.14.6, and it must
capture the canonical JSON output in the migration evidence. Run the focused
Python suite RED before implementation and GREEN afterward. Do not execute a
Task 9 migration command until the exact packages are installed, the explicit
version assertion passes, and the receipt tests are GREEN.

- [ ] **Step 6: Install the exact normal v0.16.16 runtime model**

Only after both authorization boundaries and capture verification pass,
replace the legacy service with this shape:

```yaml
image: stalwartlabs/stalwart:v0.16.16@sha256:66ae90f2753ec1dabd70f69cad7da9f0598d2628a04193ce2b08c7263d47aced
container_name: stalwart-dev
user: "2000:2000"
restart: unless-stopped
ports:
  - target: 8080
    published: "8443"
    host_ip: 127.0.0.1
    protocol: tcp
volumes:
  - type: bind
    source: ./stalwart
    target: /etc/stalwart
    read_only: true
    bind:
      create_host_path: false
  - type: bind
    source: ./stalwart-data
    target: /var/lib/stalwart
    read_only: false
    bind:
      create_host_path: false
environment:
  STALWART_PUBLIC_URL: http://127.0.0.1:8443
healthcheck:
  test: ["CMD", "curl", "-fsS", "http://127.0.0.1:8080/healthz/ready"]
  interval: 2s
  timeout: 2s
  retries: 30
  start_period: 2s
```

Delete `stalwart/config.toml`. Create `stalwart/config.json` as exactly 56
bytes, with no final LF and SHA-256
`8b48a8b7b4b4923083b045ff2fdd7eef690e3b53df2d449f891491172c791963`:

```json
{
  "@type": "RocksDb",
  "path": "/var/lib/stalwart/"
}
```

Create the semantic file through `apply_patch`, then use the deterministic
formatting command `perl -pi -e 'chomp if eof' stalwart/config.json` to remove
only the final LF. Verify the exact byte count, final byte, and SHA-256 before
any start. Run the existing normal-model tests RED before the edit and GREEN
afterward.

- [ ] **Step 7: Execute the reviewed receipt-bound migration**

Use the existing capture → dry-run → apply → bootstrap/routing proof → recovery
retirement workflow, now bound to v0.16.16, the exact OCI index digest, the
reviewed migration script digest, and the new overlay hash. Never hand-edit a
receipt or reuse a v0.16.14 receipt. Begin with the runbook's separate
`verify` and `prove-rollback` commands now that the second authorization covers
the full documented migration/rollback chain.
Require each newly produced dry-run, apply-attempt, and successful apply
receipt to contain the exact dependency-version map proved in Step 5 under
`migration_python_packages`. Reject old receipts that lack it; never retrofit
the field by hand.

- [ ] **Step 8: Prove normal runtime and data behavior**

Require the v0.16 runtime paths/UID/listener model, exact RepoDigest, health,
management permission matrix, Account/AppPassword access, JMAP list/read/
copy/move/flag/delete, SMTP/JMAP routing, restart persistence, and absence of
recovery credentials. Compare data/account inventory to the captured source.

- [ ] **Step 9: Update current operational docs and commit**

Update the repository-local Stalwart skill and Docker references to the proven
v0.16.16 filesystem/listener/management model. Remove active instructions to
edit `config.toml`, use `ADMIN_SECRET`, call legacy `/api/principal`, mount
`/opt/stalwart`, or publish non-loopback 8443. Preserve historical migration
explanations where explicitly labeled as source history. Verify any OAuth2
endpoint statement against the running selected version before retaining or
changing it.

```bash
git add docker-compose.yml stalwart/config.json stalwart/config.toml \
  tests/test_stalwart_migration_compose.py \
  tests/test_capture_stalwart_v015.py \
  tests/test_stalwart_v016.py \
  tests/test_dependency_policy.py \
  scripts/capture_stalwart_v015.py scripts/stalwart_v016.py \
  docs/stalwart-v016-migration.md PRODUCT.md CLAUDE.md \
  .ai/skills/docker-compose/references/service-map.md \
  .ai/skills/docker-compose/references/volume-mounts.md \
  .ai/skills/stalwart/SKILL.md \
  .ai/skills/stalwart/references/config.md \
  .ai/skills/stalwart/references/admin-api.md \
  .ai/skills/stalwart/references/oauth2.md
git commit -m "build: cut over Stalwart v0.16.16 runtime"
```

## Task 10: Run the final cross-stack dependency and regression audit

**Files:**

- Modify: `.ai/mcp/mcp.json`
- Modify: `scripts/convert_msg.py`
- Create: `docs/debug-dashboard/gates/dependency-baseline.md`
- Modify: `tests/test_dependency_policy.py`
- Modify: `docs/debug-dashboard/gates/0a-kotlin-toolchain.md`
- Modify: `docs/debug-dashboard/gates/0b-stalwart.md`
- Modify: `docs/debug-dashboard/gates/0c-dovecot.md`
- Modify: `README.md`
- Modify: `PRODUCT.md`
- Modify: `CLAUDE.md`

- [ ] **Step 1: Enforce one clean, unified primary-checkout history**

Run from the primary checkout used by Task 9:

```bash
test -d .git
case "$PWD" in
  */.worktrees/*) exit 1 ;;
esac
test -z "$(git status --porcelain)"
git log --format='%H %s' -n 40 | \
  rg ' test: reprove Stalwart gate on latest provider stack$'
git log --format='%H %s' -n 40 | \
  rg ' build: cut over Stalwart v0.16.16 runtime$'
```

Expected: the primary checkout, clean status, and both the integrated Task 8
commit and Task 9 cutover commit in `HEAD` history. If either is missing,
synchronize through `superpowers:finishing-a-development-branch` before any
final evidence; do not run Task 10 partly from each checkout.

- [ ] **Step 2: Add Batch-4 tooling RED tests**

Extend `tests/test_dependency_policy.py` with exact MCP package arguments:

```python
EXPECTED_MCP = {
    "filesystem": "@modelcontextprotocol/server-filesystem@2026.7.10",
    "memory": "@modelcontextprotocol/server-memory@2026.7.4",
    "sequential-thinking":
        "@modelcontextprotocol/server-sequential-thinking@2026.7.4",
}
```

Also require `extract-msg==0.56.0` in the optional conversion instruction.
Keep the already-GREEN static contract for the exact
`requests==2.34.2 urllib3==2.7.0` migration-interpreter pins introduced and
committed before Task 9's live migration; this batch only reasserts it.
Run:

```bash
python3 -B -W error -m unittest discover \
  -s tests -p 'test_dependency_policy.py' -v
```

Expected: RED on unversioned MCP and `extract-msg` optional-tool text; the
migration-interpreter assertion is already GREEN because Task 9 was forbidden
to execute without those exact pins.

- [ ] **Step 3: Pin, prove, and commit Batch-4 tooling**

Change only the MCP package arguments, preserving `npx -y` and server
ownership. Pin only the `extract-msg` optional installation instruction in
this batch, preserve Task 9's migration-interpreter pins, and do not add any of
these packages to the repository's stdlib-only runtime.

```bash
python3 -m json.tool .ai/mcp/mcp.json >/dev/null
python3 -B -W error -m unittest discover \
  -s tests -p 'test_dependency_policy.py' -v
git add .ai/mcp/mcp.json scripts/convert_msg.py \
  tests/test_dependency_policy.py
git commit -m "build: pin repository tooling dependencies"
```

Expected: GREEN without executing an MCP package or installing an optional
Python package; exact registry versions come from the approved audit.

- [ ] **Step 4: Add a RED freshness-evidence contract**

Extend `tests/test_dependency_policy.py` to require
`docs/debug-dashboard/gates/dependency-baseline.md` with one row for every
direct, framework-managed, distribution-managed, container, repository-tool,
optional-tool, and future-plan dependency in the approved design. Parse and
validate these columns rather than checking loose prose:

```text
Queried UTC | Dependency | Authoritative source | Observed stable | Selected | Ownership | Parent | Selection reason
```

Require a timezone-aware UTC timestamp, direct official URL, non-empty observed
and selected versions, one of `direct`, `Compose-managed`, `Ktor-managed`, or
`Debian-managed`, an explicit parent (`self` for direct dependencies), and a
concrete reason. When observed and selected differ, the reason must name the
owning parent and compatibility/distribution constraint. Coroutines 1.11.0
must be `Ktor-managed` with parent Ktor 3.5.2 while recording Compose's shared
graph constraint in the reason.
Require explicit exception rows for standalone Skiko 0.150.1 versus
Compose-selected 0.144.6 and upstream Postfix 3.11.5 versus Debian-selected
3.10.12. Run only this test and expect RED because the matrix does not exist.

- [ ] **Step 5: Re-query and record every authoritative source**

Compare Kotlin, Toolchain, Compose, Ktor, serialization, JUnit, Logback,
Selenium, js-joda, planned libraries, provider images, base images, Debian
packages, npm packages, and optional PyPI packages with the approved policy.
For every row, record the query timestamp, direct official URL, observed latest
stable, selected version, ownership, parent, and selection reason in
`dependency-baseline.md`. Explain plainly that “latest coherent” means direct
dependencies use their newest stable release while parent-owned artifacts use
the exact newest version supported/distributed by that newest parent; forcing
an independently newer child would create an unsupported graph or custom
distribution.

If a newer stable parent exists, update the selected baseline, design, plan,
tests, and all affected proofs before proceeding. If only a managed child is
newer, record it and refresh the parent-metadata/distribution reason; never hide
it or silently call the selected child “latest latest.” Rerun the focused test
and expect GREEN.

- [ ] **Step 6: Run exact static and Toolchain policy tests**

```bash
python3 -B -W error -m unittest discover \
  -s tests -p 'test_dependency_policy.py' -v
cd debug-dashboard
shasum -a 256 kotlin kotlin.bat
./kotlin --version
./kotlin test \
  --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.dependency.DependencyBaselineTest'
./kotlin show settings --all-modules
./kotlin show dependencies --all-modules --include-tests
cd ..
```

Expected: wrapper hashes are respectively
`6dbcdde0bcae41705c187aefb6c91c6c29ef9079c8072a473c2149151f8d7962`
and `669ecc38f0ea46829a0f82d585243b6f2a08f0c9640d270d090372dd277dd47d`;
Toolchain reports 0.11.1; exact selected versions and only the documented
managed exceptions appear.

- [ ] **Step 7: Revalidate every Compose model after the normal-model change**

Run from the repository root. These commands resolve files only and never
query the Docker daemon or normal Stalwart runtime:

```bash
COMPOSE_DISABLE_ENV_FILE=1 COMPOSE_PROFILES= \
docker compose \
  --project-directory "$PWD" \
  --project-name mail-sandbox-config-audit \
  --file docker-compose.yml \
  config --quiet

COMPOSE_DISABLE_ENV_FILE=1 COMPOSE_PROFILES= \
docker compose \
  --project-directory "$PWD" \
  --project-name mail-sandbox-config-audit \
  --file docker-compose.yml \
  --profile dovecot-operator \
  config --quiet

COMPOSE_DISABLE_ENV_FILE=1 COMPOSE_PROFILES= \
docker compose \
  --project-directory "$PWD" \
  --project-name mail-sandbox-task5-proof \
  --file docker-compose.yml \
  --file debug-dashboard/dashboard-server/testResources/dovecot-gate0c/compose.task5-proof.yml \
  config --quiet
```

Gate 0C intentionally selects no profile: its override activates the operator
and puts Stalwart behind unselected `task5-stalwart-disabled`.

Validate both Gate 0B models and the selected migration profile with empty,
owner-only placeholder env files and directories:

```bash
(
  set -eu
  umask 077
  compose_audit_tmp="$(mktemp -d "${TMPDIR:-/tmp}/mail-sandbox-compose-config.XXXXXX")"

  cleanup_compose_audit() {
    compose_audit_status=$?
    trap - EXIT
    rm -f -- \
      "$compose_audit_tmp/gate-recovery.env" \
      "$compose_audit_tmp/migration-recovery.env" || \
      compose_audit_status=1
    rmdir -- "$compose_audit_tmp/migration-config" || compose_audit_status=1
    rmdir -- "$compose_audit_tmp/migration-data" || compose_audit_status=1
    rmdir -- "$compose_audit_tmp" || compose_audit_status=1
    exit "$compose_audit_status"
  }
  trap cleanup_compose_audit EXIT

  mkdir "$compose_audit_tmp/migration-config" \
    "$compose_audit_tmp/migration-data"
  touch "$compose_audit_tmp/gate-recovery.env" \
    "$compose_audit_tmp/migration-recovery.env"
  chmod 0700 "$compose_audit_tmp" \
    "$compose_audit_tmp/migration-config" \
    "$compose_audit_tmp/migration-data"
  chmod 0600 "$compose_audit_tmp/gate-recovery.env" \
    "$compose_audit_tmp/migration-recovery.env"

  COMPOSE_DISABLE_ENV_FILE=1 COMPOSE_PROFILES= \
  docker compose \
    --project-directory \
      "$PWD/debug-dashboard/dashboard-server/testResources/stalwart-gate0b" \
    --project-name mail-sandbox-stalwart-gate \
    --file \
      "$PWD/debug-dashboard/dashboard-server/testResources/stalwart-gate0b/compose.yml" \
    config --quiet

  COMPOSE_DISABLE_ENV_FILE=1 COMPOSE_PROFILES= \
  STALWART_GATE_RECOVERY_ENV_FILE="$compose_audit_tmp/gate-recovery.env" \
  docker compose \
    --project-directory \
      "$PWD/debug-dashboard/dashboard-server/testResources/stalwart-gate0b" \
    --project-name mail-sandbox-stalwart-gate \
    --file \
      "$PWD/debug-dashboard/dashboard-server/testResources/stalwart-gate0b/compose.yml" \
    --file \
      "$PWD/debug-dashboard/dashboard-server/testResources/stalwart-gate0b/compose.recovery.yml" \
    config --no-env-resolution --quiet

  COMPOSE_DISABLE_ENV_FILE=1 COMPOSE_PROFILES= \
  STALWART_MIGRATION_CONFIG_DIR="$compose_audit_tmp/migration-config" \
  STALWART_MIGRATION_DATA_DIR="$compose_audit_tmp/migration-data" \
  STALWART_MIGRATION_RECOVERY_ENV_FILE="$compose_audit_tmp/migration-recovery.env" \
  docker compose \
    --project-directory "$PWD" \
    --project-name mail-sandbox-stalwart-migration-config \
    --file docker-compose.yml \
    --file docker-compose.stalwart-migration.yml \
    --profile stalwart-migration \
    config --no-env-resolution --quiet
)
```

Expected: all six resolved models pass; no credential value is printed or
read; all exact temporary paths are removed.

- [ ] **Step 8: Re-prove every selected image and base at runtime**

Pull the five exact version-plus-index-digest references for Python, Debian,
Dovecot, Stalwart, and Stalwart CLI. For each, inspect
`{{json .RepoDigests}}` and require the selected repository digest. Then run
only no-network, pull-never version probes:

```bash
for selected_image in \
  'python:3.14.6-slim-trixie@sha256:cea0e6040540fb2b965b6e7fb5ffa00871e632eef63719f0ea54bca189ce14a6' \
  'debian:13.6-slim@sha256:020c0d20b9880058cbe785a9db107156c3c75c2ac944a6aa7ab59f2add76a7bd' \
  'dovecot/dovecot:2.4.4@sha256:723e3392fe16c6fad8ddc605ea767cc01b4bad9cd9f13eb1dbac15e79c89b2d4' \
  'stalwartlabs/stalwart:v0.16.16@sha256:66ae90f2753ec1dabd70f69cad7da9f0598d2628a04193ce2b08c7263d47aced' \
  'stalwartlabs/cli:1.0.12@sha256:fe199affac1d120a8c200ef39ae629765a2976270e0453575c1caf906ee15b52'; do
  docker pull "$selected_image"
  docker image inspect "$selected_image" \
    --format '{{json .RepoDigests}}'
done

docker run --rm --pull never --network none \
  --entrypoint python \
  python:3.14.6-slim-trixie@sha256:cea0e6040540fb2b965b6e7fb5ffa00871e632eef63719f0ea54bca189ce14a6 \
  --version
docker run --rm --pull never --network none \
  debian:13.6-slim@sha256:020c0d20b9880058cbe785a9db107156c3c75c2ac944a6aa7ab59f2add76a7bd \
  cat /etc/debian_version
docker run --rm --pull never --network none \
  --entrypoint dovecot \
  dovecot/dovecot:2.4.4@sha256:723e3392fe16c6fad8ddc605ea767cc01b4bad9cd9f13eb1dbac15e79c89b2d4 \
  --version
docker run --rm --pull never --network none \
  --entrypoint /usr/local/bin/stalwart \
  stalwartlabs/stalwart:v0.16.16@sha256:66ae90f2753ec1dabd70f69cad7da9f0598d2628a04193ce2b08c7263d47aced \
  --version
docker run --rm --pull never --network none \
  stalwartlabs/cli:1.0.12@sha256:fe199affac1d120a8c200ef39ae629765a2976270e0453575c1caf906ee15b52 \
  --version
```

Expected: Python 3.14.6, Debian 13.6, Dovecot 2.4.4, Stalwart 0.16.16,
and CLI 1.0.12. The Gate 0C evidence separately proves the rebuilt
Debian-managed Postfix/SASL package versions and configuration.

- [ ] **Step 9: Run the complete non-live build/test suite under selected runtimes**

```bash
docker run --rm --pull never --network none \
  --workdir /repo \
  --mount "type=bind,source=$PWD,target=/repo,readonly" \
  --env PYTHONPYCACHEPREFIX=/tmp/mail-sandbox-pycache \
  --entrypoint python \
  python:3.14.6-slim-trixie@sha256:cea0e6040540fb2b965b6e7fb5ffa00871e632eef63719f0ea54bca189ce14a6 \
  -B -W error -m compileall -q \
  scripts tests oauth2-mock \
  debug-dashboard/dashboard-server/testResources/dovecot-gate0c/network-isolation-check.py \
  debug-dashboard/dashboard-server/testResources/dovecot-gate0c/test_network_isolation_check.py
test "$(python3.14 -c 'import platform; print(platform.python_version())')" = \
  3.14.6
python3.14 -B -W error -m unittest discover -s tests -v
python3.14 -B -W error -m unittest discover \
  -s oauth2-mock -p 'test_server.py' -v
python3.14 -B -W error -m unittest discover \
  -s debug-dashboard/dashboard-server/testResources/dovecot-gate0c \
  -p 'test_network_isolation_check.py' -v
cd debug-dashboard
./kotlin build
DASHBOARD_WEB_ASSETS="$PWD/build/tasks/_dashboard-web_linkWasmJs" \
DASHBOARD_WEB_RESOURCES="$PWD/build/artifacts/PreparedComposeResourcesDirArtifact/dashboard-webcommon" \
DASHBOARD_WEB_ENTRY="dashboard-web.mjs" \
./kotlin test \
  --exclude-classes 'mail.sandbox.dashboard.server.gate.dovecot.*LiveTest' \
  --exclude-classes 'mail.sandbox.dashboard.server.gate.stalwart.*LiveTest'
cd ..
```

Expected: the exact Python 3.14.6 image compiles every listed repository
stdlib Python source, including both Gate 0C network-isolation files. Exact
host Python 3.14.6 then passes the complete `tests/`, OAuth2, and Gate 0C
network-isolation suites in the environment that provides Docker Compose and
the shared repository fixtures. All Kotlin tests PASS with zero unapproved
skips and no Gradle/npm/React/TypeScript build path.

- [ ] **Step 10: Confirm live evidence scope**

Require current successful browser, Gate 0C, disposable Gate 0B, and—after both
separate authorization boundaries—normal Stalwart evidence. A narrow unit
suite cannot substitute for these broad requirements.

- [ ] **Step 11: Audit documentation and alternate stacks**

```bash
git ls-files --cached --others --exclude-standard . \
  | rg '(^|/)(build\.gradle(\.kts)?|settings\.gradle(\.kts)?|gradlew(\.bat)?|gradle\.properties|\.npmrc|package(-lock)?\.json|yarn\.lock|pnpm-lock\.yaml)$|(^|/)gradle/wrapper(/|$)|\.(js|jsx|cjs|mjs|ts|tsx|mts|cts)$'
rg -n '2\.3\.21|1\.10\.3|3\.4\.3|0\.9\.37\.4|1\.5\.18|dovecot/dovecot:2\.4\.1|stalwartlabs/stalwart:v0\.16\.14|python:3\.12-slim|debian:bookworm-slim' \
  --glob '!docs/superpowers/specs/**' \
  --glob '!docs/superpowers/plans/**' \
  --glob '!docs/debug-dashboard/gates/**' \
  --glob '!tests/**' \
  --glob '!**/test/**' \
  --glob '!**/build/**' \
  --glob '!**/.runtime/**' .
rg -n 'stalwart/config\.toml|/opt/stalwart|/api/principal|ADMIN_SECRET|0\.0\.0\.0:8443' \
  README.md CLAUDE.md \
  .ai/skills/stalwart \
  .ai/skills/docker-compose/references/service-map.md \
  .ai/skills/docker-compose/references/volume-mounts.md
```

Expected: all three scans have no output. Historical documents may contain old
values only with clear supersession context.

- [ ] **Step 12: Run repository self-review and commit final evidence**

Execute `.ai/self-review.md`, review `git diff --check`, inspect every changed
file and test result, and ensure no runtime secret/evidence/cache entered Git.

```bash
git add README.md PRODUCT.md CLAUDE.md tests/test_dependency_policy.py \
  docs/debug-dashboard/gates/dependency-baseline.md \
  docs/debug-dashboard/gates/0a-kotlin-toolchain.md \
  docs/debug-dashboard/gates/0b-stalwart.md \
  docs/debug-dashboard/gates/0c-dovecot.md
git commit -m "docs: close latest dependency baseline gate"
```

## Task 11: Resume the dashboard usability implementation

**Files:**

- Modify: `docs/superpowers/plans/2026-07-23-debug-dashboard-implementation.md`

- [ ] **Step 1: Mark only the dependency prerequisite complete**

Record links to the new Gate 0A/0B/0C evidence and selected versions. Do not
mark the dashboard usable or mark any of its nine workflows complete merely
because the dependency gate passes.

- [ ] **Step 2: Select the next unimplemented provider capability**

Continue the existing dashboard plan in dependency order: foundation/session/
operation ledger, provider account operations, folders/messages/basic
operations, message lab/logs, Compose UI, then two-provider acceptance. Use a
fresh feature design only when the next unit changes behavior not already
covered by the approved dashboard design.

- [ ] **Step 3: Commit the plan checkpoint**

```bash
git add docs/superpowers/plans/2026-07-23-debug-dashboard-implementation.md
git commit -m "docs: resume dashboard plan on latest baseline"
```
