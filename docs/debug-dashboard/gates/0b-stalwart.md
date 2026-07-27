# Gate 0B — Stalwart v0.16.14

## Task 1 status

The disposable fixture and scoped bootstrap harness are implemented. The final
Task 1 evidence was completed on `2026-07-27 15:22 ADT`:

- canonical offline Gate 0B contracts, with every `*LiveTest` excluded:
  `31/31`, zero skipped or failed;
- selected scoped cleanup: `1/1`;
- selected fixture preparation: `1/1`;
- selected recovery-mode live bootstrap, including the resolved-mount audit:
  `1/1`;
- base-only recovery environment audit: clean;
- selected fresh-JVM recovery-retirement proof, including a second
  resolved-mount audit: `1/1`;
- production-environment Kotlin Toolchain regression suite, with every Stalwart
  `*LiveTest` excluded: `dashboard-contract` `20/20` and `dashboard-server`
  `56/56`; `76/76` total, zero skipped or failed.

The final run started from an absent named project and absent ignored runtime,
then exercised only the exact unconditional `*LiveTest` classes listed below.
It left the final base-only fixture healthy for the next Gate 0B task. No
credential was printed, and no live command addressed another Compose project,
repository mail data, or a host port other than `18443`.

## Fixed boundary

- Image: `stalwartlabs/stalwart:v0.16.14`
- Compose project: `mail-sandbox-stalwart-gate`
- Published endpoint: `http://127.0.0.1:18443`
- Container service user: UID/GID `2000:2000`
- Scratch state: `debug-dashboard/.runtime/stalwart-gate0b`
- Store config: `{"@type":"RocksDb","path":"/var/lib/stalwart/"}`
- Readiness: `/healthz/ready`

The fixture does not mount repository `stalwart-data/` or `vmail/`, does not use
ports `8443` or `8080` on the host, and does not put a recovery variable in the
base Compose file. Recovery exists only in the recovery override and its
owner-only environment file.

The pinned image declares volume targets `/etc/stalwart` and
`/var/lib/stalwart`. Both fixture services supersede both targets with exactly
two reviewed bind mounts: the fixture directory is read-only at
`/etc/stalwart`, and the ignored Gate data directory is writable at
`/var/lib/stalwart`. The selected bootstrap and retirement branches inspect the
image and both resolved containers. They require exactly those image targets,
exactly those two bind sources and modes, and zero `Type=volume` mounts. The
final explicit inspection showed the same two bind mounts on both services and
zero volume mounts. It also re-confirmed image ID
`sha256:25001929f36a62521cedc50f12527080dac4cf6a0cc31b617b669d921cafc36a`,
the exact `stalwartlabs/stalwart:v0.16.14` image reference, a healthy server, and
the sole host binding `127.0.0.1:18443`. The separate main `stalwart-dev`
container remained healthy. Its live `stalwart-data/LOG` continued to change
while the gate ran, so a whole-tree metadata hash is not stable evidence; the
resolved zero-volume/two-bind audit proves neither disposable container can
address repository `vmail/` or `stalwart-data/`.

`fixture-secrets` contains the generated management API key and two ordinary
passwords. The environment carries only its fixed absolute path. Test diagnostics,
Compose output, arguments, and this evidence file must never contain a credential.

## Bootstrap contract

The recovery-authenticated registry flow creates and re-fetches the HTTP
`NetworkListener`, `local.test` Domain, `SystemSettings` singleton, protected
management User Account, and two ordinary User Accounts. Every fetched ID, type,
role, credential shape, and relevant field is checked. Ordinary Accounts are
Password-only Users. The protected Account starts with a temporary Password and
temporary API-key-management permissions.

Stalwart v0.16.14 constructs its recovery access token with all permissions:
the pinned source's `AccessTokenInner::new_admin()` builds a scope with
`Permissions::all()`. The management UI's omission of `sysApiKey*` entries from
the recovery Account display is not an access-token restriction. The harness
therefore exercises that pinned-version authority directly: recovery creates
one reserved `mail-sandbox/debug-dashboard/recovery-authority-probe` API key
with the exact management baseline, fetches and validates its ID, description,
`Replace` mode, and permissions, destroys the exact ID, proves that ID is
`notFound`, and re-fetches the management Account as Password-only. The returned
probe secret is neither retained nor written to diagnostics or disk.

The normal management login creates an API key in `Replace` mode with exactly:

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
```

The harness fetches that key before retirement. It also creates a temporary key
without `authenticate`, proves only HTTP `401` or `403` is an authentication
rejection, destroys the key, and fetches its exact ID to prove it absent.

Stalwart marks a secondary credential's `credentialId`, `secret`, and
`createdAt` as server-set. Replacing the complete `credentials` map with an
`Account/get` value would replay those fields and is rejected before Account
validation. Retirement instead proves the pre-state is exactly the intended API
key plus one Password, then sends one atomic targeted patch:
`credentials/<fetched-password-map-key>: null` plus the final Account
permissions. It never resends the API-key object or any of that credential's
server-set fields.

The harness re-fetches the Account after that update. The resulting Account and
credential retain the expected stable Account ID, credential ID, API-key type,
effective permission set, and authentication behavior. Raw credential-map keys
are positional Stalwart representation details and are not treated as stable
identity. There is no wildcard, inherited management permission, `impersonate`, mail permission,
`sysAccountPassword*`, `sysApiKey*`, or `sysAppPassword*`. The final Bearer
credential authenticates, while API-key registry access is explicitly
forbidden.

## Live selection

Every opt-in operation is an unconditional class ending in `LiveTest`. Selecting
that exact class is the authorization boundary; there is no phase selector and
no early-return path that can report a false pass. The networked bootstrap and
retirement classes require:

- `STALWART_LIVE_TESTS=1`
- `STALWART_BASE_URL=http://127.0.0.1:18443`
- the fixed absolute `STALWART_GATE_FIXTURE_SECRETS_FILE`

Both networked classes perform a bounded probe of the dedicated readiness
endpoint before using credentials. They do not use assumptions, alternate
servers, or fallback URLs. Both also execute the bind-only resolved-mount audit
before accepting live evidence. Prepare accepts only exact
`STALWART_GATE_PREPARE=1`; cleanup accepts only exact
`STALWART_GATE_CLEANUP=1`. Conflicting gate variables fail closed.

Canonical offline Gate 0B and production-environment commands use exactly this
single exclusion:

```bash
cd debug-dashboard
./kotlin test \
  --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.gate.stalwart.*' \
  --exclude-classes 'mail.sandbox.dashboard.server.gate.stalwart.*LiveTest'

DASHBOARD_WEB_ASSETS="$PWD/build/tasks/_dashboard-web_linkWasmJs" \
DASHBOARD_WEB_RESOURCES="$PWD/build/artifacts/PreparedComposeResourcesDirArtifact/dashboard-webcommon" \
DASHBOARD_WEB_ENTRY="dashboard-web.mjs" \
./kotlin test \
  --include-module dashboard-contract \
  --include-module dashboard-server \
  --include-module dashboard-web \
  --exclude-classes 'mail.sandbox.dashboard.server.gate.stalwart.*LiveTest'
```

## Exact live commands

Run from the repository root. `docker compose config` is validation-only and uses
`--quiet` so the recovery credential cannot enter evidence.

```bash
cd debug-dashboard
STALWART_GATE_PREPARE=1 \
./kotlin test \
  --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.gate.stalwart.StalwartFixturePrepareLiveTest'
cd ..

export STALWART_GATE_RECOVERY_ENV_FILE="$PWD/debug-dashboard/.runtime/stalwart-gate0b/recovery.env"
docker compose -p mail-sandbox-stalwart-gate \
  -f debug-dashboard/dashboard-server/testResources/stalwart-gate0b/compose.yml \
  -f debug-dashboard/dashboard-server/testResources/stalwart-gate0b/compose.recovery.yml \
  config --no-env-resolution --quiet
docker compose -p mail-sandbox-stalwart-gate \
  -f debug-dashboard/dashboard-server/testResources/stalwart-gate0b/compose.yml \
  -f debug-dashboard/dashboard-server/testResources/stalwart-gate0b/compose.recovery.yml \
  up -d --wait

cd debug-dashboard
STALWART_LIVE_TESTS=1 \
STALWART_BASE_URL=http://127.0.0.1:18443 \
STALWART_GATE_FIXTURE_SECRETS_FILE="$PWD/.runtime/stalwart-gate0b/fixture-secrets" \
./kotlin test \
  --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.gate.stalwart.StalwartBootstrapLiveTest'
cd ..

docker compose -p mail-sandbox-stalwart-gate \
  -f debug-dashboard/dashboard-server/testResources/stalwart-gate0b/compose.yml \
  stop stalwart
docker compose -p mail-sandbox-stalwart-gate \
  -f debug-dashboard/dashboard-server/testResources/stalwart-gate0b/compose.yml \
  up -d --wait --force-recreate

if docker compose -p mail-sandbox-stalwart-gate \
  -f debug-dashboard/dashboard-server/testResources/stalwart-gate0b/compose.yml \
  exec -T stalwart /usr/bin/env | rg -q '^STALWART_RECOVERY_'; then
  echo "unexpected recovery variable" >&2
  exit 1
fi

cd debug-dashboard
STALWART_LIVE_TESTS=1 \
STALWART_BASE_URL=http://127.0.0.1:18443 \
STALWART_GATE_FIXTURE_SECRETS_FILE="$PWD/.runtime/stalwart-gate0b/fixture-secrets" \
./kotlin test \
  --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.gate.stalwart.StalwartRecoveryRetirementLiveTest'
```

The fresh retirement JVM requires recovery Basic authentication to fail only with
HTTP `401`/`403`, management Bearer and both ordinary full-address Basic logins to
succeed, and every Session `apiUrl` to equal
`http://127.0.0.1:18443/jmap/`.

## Cleanup

Cleanup is selected explicitly from `debug-dashboard`:

```bash
STALWART_GATE_CLEANUP=1 \
./kotlin test \
  --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.gate.stalwart.StalwartGateCleanupLiveTest'
```

The cleanup test validates the exact reviewed Compose/config bytes and filesystem
identities, the exact ignored runtime/data bind, and the exact named project
immediately before each sensitive command. It derives host UID/GID only from the
real mode-`0700` gate runtime. It stops only `stalwart`, runs a bounded root
helper that performs exact host ownership plus `u+rwX,go-rwx`, runs the exact
named-project `down`, and then deletes only `.runtime/stalwart-gate0b`.
Repository data paths remain untouched. No cleanup command uses `-v` or
`--volumes`.

An earlier pre-fix diagnostic run exposed image-created anonymous volumes. The
bind-only contract above prevents them in the final fixture. The nine historical
detached diagnostic volumes were individually verified as anonymous,
gate-timestamped, and unreferenced, then removed by exact ID. Automated cleanup
still performs no volume deletion, and no broad prune or `down -v` was used.
