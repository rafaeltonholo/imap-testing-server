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
repository mail data, or a host port other than the Task 1 loopback mapping
`18443`. Task 2 later added the separately reviewed SMTP proof mapping `18587`.

## Task 2 raw Blob compatibility decision

On `2026-07-28`, the pinned-source review and disposable live fixture confirmed
that Stalwart v0.16.14 does not use the JMAP Blob permission names as an
authorization boundary for its raw HTTP upload/download routes:

- the management API key, whose exact effective scope contains no `jmap*` or
  Blob permission, uploaded a reserved Blob to its own Account;
- that key downloaded the exact non-secret probe bytes from its own reserved
  Blob;
- that key uploaded a reserved Blob using an ordinary Account ID even though it
  is not a member of that Account;
- management download of the ordinary Account's Blob was denied; a second Blob
  independently seeded by the ordinary Account's normal credential was also
  denied to management.

The initial strict isolation verdict therefore reported the exact violations
`MANAGEMENT_ACCOUNT_UPLOAD_ACCEPTED`,
`MANAGEMENT_ACCOUNT_DOWNLOAD_ACCEPTED`, and
`ORDINARY_ACCOUNT_UPLOAD_ACCEPTED`. No Account ID, Blob ID, credential, payload,
or response body entered its failure diagnostics.

This is accepted as a **local-only compatibility limitation**, not described as
credential isolation. The project exists only to reproduce email-client/provider
issues, binds the disposable fixture to loopback, and has no external users.
The dashboard implementation must still keep management registry operations and
Account-bound mail/Blob operations in separate typed clients; product code must
never route a management credential through the raw Blob client. This is a
misuse-prevention boundary in our code, not a server-enforced security boundary.
Any future public, shared-untrusted, or production use reopens this finding as a
hard stop.

The hardened compatibility proof passed `1/1`. Its offline client/verdict suite
passed `8/8` and covers pinned URLs, exact payload reads, independent seeding,
HTTP `401`/`403`/privacy-preserving `404` denials, redirect rejection,
cancellation propagation, and redaction. Final regression evidence on
`2026-07-28 08:14 ADT` is:

- canonical offline Gate 0B contracts: `39/39`, zero skipped or failed;
- production-environment suite: `dashboard-contract` `20/20` and
  `dashboard-server` `64/64`; `84/84` total, zero skipped or failed;
- Chromium browser gate: passed.

The small probe Blobs exist only in the ignored disposable scratch store and
are removed with the scoped Gate cleanup.

Run the accepted compatibility characterization from `debug-dashboard` with:

```bash
STALWART_LIVE_TESTS=1 \
STALWART_BASE_URL=http://127.0.0.1:18443 \
STALWART_GATE_FIXTURE_SECRETS_FILE="$PWD/.runtime/stalwart-gate0b/fixture-secrets" \
./kotlin test \
  --include-module dashboard-server \
  --include-classes \
  'mail.sandbox.dashboard.server.gate.stalwart.StalwartRawBlobCompatibilityLiveTest'
```

## Task 2 AppPassword and permission decision

The disposable v0.16.14 fixture accepts an Account-owned AppPassword with this
exact `Replace` allowlist:

```text
authenticate
jmapMailboxGet
jmapMailboxCreate
jmapMailboxUpdate
jmapMailboxDestroy
jmapEmailGet
jmapEmailQuery
jmapEmailUpdate
jmapEmailDestroy
jmapEmailImport
jmapIdentityGet
jmapEmailSubmissionGet
jmapEmailSubmissionCreate
jmapBlobGet
jmapBlobUpload
```

The server generates the `app_` secret. Its plaintext exists only in the
`created` result; exact-ID inventory returns the non-recoverable `****` sentinel,
and a secret patch is rejected as `invalidPatch`. Two generations authenticate
simultaneously. The first generation can list, create, rename, and delete a
Mailbox; upload and read a JMAP Blob; import, query, read, move, flag, and delete
an Email; select an Identity; create and read an EmailSubmission; and deliver to
the second registered Account. The recipient reads and removes the delivered
probe with its own credential.

JMAP submission succeeds without `emailSend`. On the dedicated loopback SMTP
proof listener, the ordinary Password control returns
`235 2.7.0 Authentication succeeded.`, while the otherwise valid AppPassword
returns `550 5.7.1 Your account is not authorized to use this service.` This is
an authorization denial, not an authentication failure and not a `535`.

The exact negative matrix denies every allowlisted mail action when the same
AppPassword targets the other ordinary Account, and denies those actions to the
management key. It also denies the AppPassword every Account, Domain, Task, and
Log operation exercised by the management surface; normal-Password mutation;
AppPassword and API-key create/query/update/destroy; cross-Account username
pairing; protected-management username pairing; and `target%credential`
impersonation. A wrong secret and the revoked first generation fail
authentication. Targeted management revocation uses one fresh
`x:Account/get`, one positional credential-leaf removal, and one verification
fetch; it preserves the sibling AppPassword and every unrelated stable
credential object without `ifInState` or a blind retry. If the one update's
response is lost or malformed, cancellation still propagates, but every other
post-dispatch failure proceeds to that same single exact verification fetch.
Only the exact expected stable-ID map reports `Revoked`; every other result is
`ReconciliationRequired`.

Credential inventory requests an explicit bounded first page with
`calculateTotal`, then requires `position == 0` and `total == ids.size` before
an exact-ID get may certify completeness. Numeric query metadata, permission
booleans, and raw Blob sizes must use their native JSON types; string-encoded
lookalikes fail closed. The read-once values copied into Basic/Bearer
credentials have closeable ownership: every owning client closes its
credential, caller-side handoff arrays and temporary Basic encoding buffers are
wiped, and closed or invalidly constructed clients cannot authenticate.

The permission-matrix proof freshly fetches all three fixture Accounts and their
credential objects. Both ordinary Accounts select only the built-in `User` role;
their normal-Password `/api/account` effective sets contain no `impersonate`.
The protected management Account and its API-key credential remain exact
`Replace` objects with the reviewed management baseline, and the management
Bearer effective set equals that baseline. The live AppPassword's declarative
and `/api/account` effective sets both equal the 15 names above. None of those
Account, role selection, API-key, or AppPassword views contains `impersonate` or
a wildcard.

The official pinned image is compiled with enterprise-capable code but, without
a license, `/api/account` reports the exact edition label `community`. The
source-only `oss` label belongs to a binary compiled without that feature. The
Gate therefore accepts only `community` for this exact image and still rejects
`enterprise` and every other label.

Quota behavior is deterministic. The live proof temporarily patches only the
first ordinary Account's `quotas/maxAppPasswords` leaf to `1`, creates one
reserved credential, and receives exact `overQuota` for a second. The first
credential's fetched Account object, exact inventory, effective permission set,
and authentication remain unchanged. A `finally` path removes both reserved
descriptions only after restoring the exact prior quota map and re-proving the
active credential object, inventory, effective scope, and authentication. It
then verifies the exact prior credential inventory.

The mail proof stores its unique marker and mutation-attempt flags before each
create dispatch. Its non-cancellable cleanup therefore handles a lost create
response by reconciling both exact mailbox names, the exact subject on owner and
recipient Accounts, and EmailSubmission objects related to the exact owner
Email IDs. An ambiguous submission receives a bounded late-delivery polling
window, and final exact queries must prove every marker artifact absent.

Current Task 2 evidence on `2026-07-28` is:

- canonical offline Stalwart Gate contracts: `64/64`, zero skipped or failed;
- focused AppPassword client contracts: `25/25`;
- production-environment suite: `dashboard-contract` `20/20` and
  `dashboard-server` `89/89`; `109/109` total, including the Chromium gate;
- selected raw Blob compatibility proof: `1/1`;
- selected AppPassword semantics proof: `1/1`;
- selected permission-matrix and quota-restoration proof: `1/1`.

## Fixed boundary

- Image: `stalwartlabs/stalwart:v0.16.14`
- Compose project: `mail-sandbox-stalwart-gate`
- Published HTTP endpoint: `http://127.0.0.1:18443`
- Published SMTP proof endpoint: `127.0.0.1:18587`
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
the exact host bindings `127.0.0.1:18443` and `127.0.0.1:18587`. The separate
main `stalwart-dev`
container remained healthy. Its live `stalwart-data/LOG` continued to change
while the gate ran, so a whole-tree metadata hash is not stable evidence; the
resolved zero-volume/two-bind audit proves neither disposable container can
address repository `vmail/` or `stalwart-data/`.

`fixture-secrets` contains the generated management API key and two ordinary
passwords. The environment carries only its fixed absolute path. Test diagnostics,
Compose output, arguments, and this evidence file must never contain a credential.

## Bootstrap contract

The recovery-authenticated registry flow creates and re-fetches the HTTP
`NetworkListener`, the dedicated non-TLS `smtp-gate0b` `NetworkListener`,
`MtaStageAuth`, `local.test` Domain, `SystemSettings` singleton, protected
management User Account, and two ordinary User Accounts. The SMTP listener is
published only as `127.0.0.1:18587:8587`. Its authentication stage clears the
default port-dependent match rules and selects only `[plain]`, enabling an
explicit local normal-password control plus the missing-`emailSend`
AppPassword denial proof. Every fetched ID, type, role, credential shape, and
relevant field is checked. Ordinary Accounts are Password-only Users. The
protected Account starts with a temporary Password and temporary
API-key-management permissions.

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
no early-return path that can report a false pass. The five networked bootstrap,
retirement, raw Blob compatibility, permission-matrix, and AppPassword-semantics
classes require:

- `STALWART_LIVE_TESTS=1`
- `STALWART_BASE_URL=http://127.0.0.1:18443`
- the fixed absolute `STALWART_GATE_FIXTURE_SECRETS_FILE`

All five networked classes perform a bounded probe of the dedicated readiness
endpoint before using credentials. They do not use assumptions, alternate
servers, or fallback URLs. All five also execute the bind-only resolved-mount
audit before accepting live evidence. Prepare accepts only exact
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

STALWART_LIVE_TESTS=1 \
STALWART_BASE_URL=http://127.0.0.1:18443 \
STALWART_GATE_FIXTURE_SECRETS_FILE="$PWD/.runtime/stalwart-gate0b/fixture-secrets" \
./kotlin test \
  --include-module dashboard-server \
  --include-classes \
  'mail.sandbox.dashboard.server.gate.stalwart.StalwartRawBlobCompatibilityLiveTest'

STALWART_LIVE_TESTS=1 \
STALWART_BASE_URL=http://127.0.0.1:18443 \
STALWART_GATE_FIXTURE_SECRETS_FILE="$PWD/.runtime/stalwart-gate0b/fixture-secrets" \
./kotlin test \
  --include-module dashboard-server \
  --include-classes \
  'mail.sandbox.dashboard.server.gate.stalwart.StalwartPermissionMatrixLiveTest'

STALWART_LIVE_TESTS=1 \
STALWART_BASE_URL=http://127.0.0.1:18443 \
STALWART_GATE_FIXTURE_SECRETS_FILE="$PWD/.runtime/stalwart-gate0b/fixture-secrets" \
./kotlin test \
  --include-module dashboard-server \
  --include-classes \
  'mail.sandbox.dashboard.server.gate.stalwart.StalwartAppPasswordSemanticsLiveTest'
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
