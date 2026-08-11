# Stalwart v0.15 to v0.16.17 Operator Runbook

This is the operator sequence for the one-time, fail-closed migration of the
real mail-sandbox Stalwart store. It records commands and checkpoints; it is
not evidence that those commands have run.

> **Current status (2026-07-29):** the authorized live capture has not run.
> The primary checkout's `docker-compose.yml` and `stalwart/config.toml` still
> describe the v0.15 runtime. `stalwart/config.json` is not yet the live
> configuration. Do not run migration dry-run, apply, bootstrap, or retirement
> until the capture checkpoint below succeeds.

## Fixed safety boundaries

- Offline development and unit tests may run in a worktree. The authorized
  live capture intended for migration, and every later verify, rollback proof,
  dry-run, review, apply, bootstrap, retirement, and live-proof command, must
  run from the **primary checkout** identified by the running v0.15 container's
  Compose labels.
- The primary checkout owns the real `stalwart-data/`, `docker-compose.yml`,
  fixed live receipts, scripts, assets, and durable ignored capture root.
  Keep its Compose/TOML inputs on v0.15 through capture; install the reviewed
  v0.16 scripts, base Compose/config, migration overlay, and bootstrap assets
  there before continuing.
- The capture is durable beneath
  `<primary-checkout>/captures/debug-dashboard/stalwart-v015/`. The primary
  invocation also publishes its fixed live-chain receipt at
  `debug-dashboard/.runtime/stalwart-migration/latest-source.json`.
- Never edit individual RocksDB keys, copy a rollback over
  `stalwart-data/`, delete a checkpoint to force progress, or start Stalwart
  outside the receipt-validating scripts.
- Keep the migration directory and secret-bearing files owner-only. Do not
  print recovery credentials, the management API key, ordinary passwords, or
  digests of those secret values.

Run every following command from the captured primary checkout root.

## Startup classification is read-only

Normal startup may run only the classifier before deciding what to do:

```bash
REPOSITORY_ROOT="$(pwd -P)"
python3 scripts/stalwart_runtime_state.py classify \
  --repository "$REPOSITORY_ROOT"
```

- `fresh` permits only the explicit `initialize-fresh` command below. That
  command still refuses before creating bytes while root Compose remains on
  the temporary v0.15 hold.
- `current` permits ordinary root Compose startup after receipt validation.
- `migration-required` requires the explicit capture/rehearsal/apply sequence
  in this runbook. Startup never migrates automatically.
- `invalid` is a hard stop for manual investigation.

`migration-required` recognizes only the frozen root v0.15 Stalwart service
declaration: the exact pinned image, legacy `8443:8443` publication,
`config.toml` and legacy data mounts, `ADMIN_SECRET=secret`, restart policy, and
legacy health check. Mixed topology, extra ports/mounts/environment, or a
service-level network override is `invalid`, even when the legacy image text is
present. The current declaration is similarly exact: extra service fields are
not accepted merely because the required image, ports, and mounts also appear.
For either model, the declaration must be the single direct `stalwart` child
of one plain top-level `services:` mapping. Duplicate or alternate-form
`services` keys, and matching declarations nested under extensions or other
parents, are `invalid`.

Any `.mail-sandbox-fresh-initialization-failed` entry in the selected store is
authoritative failure evidence regardless of its file type or whether a valid
`current.json` was published first. The classifier returns `invalid`, and
receipt publication refuses to bless that store. Symlinked config or receipt
ancestor directories are also `invalid`.

For a genuinely empty store, after the root Compose cutover has installed the
reviewed current model, initialize it exactly once:

```bash
python3 scripts/bootstrap_stalwart_v016.py initialize-fresh \
  --repository "$REPOSITORY_ROOT"
```

The command creates the protected management Account with the fixed local-test
Basic password `secret`, proves JMAP and authenticated SMTP before and after a
normal-runtime restart, publishes `current.json`, and requires the classifier
to return `current`. It never seeds or overwrites a nonempty store. A partial
failure is stopped and marked `invalid`; it is not silently retried as fresh.

Capture, rehearsal, migration apply, rollback, and snapshot deletion remain
operator-invoked commands. The classifier performs none of them.

## 1. Capture the live v0.15 source

Before capture, confirm that the primary checkout still contains the live
v0.15 Compose/TOML inputs. Run the offline capture tests:

```bash
python3 -m unittest discover \
  -s tests \
  -p 'test_capture_stalwart_v015.py' \
  -v
```

The live capture is intentionally disruptive: it stops v0.15 and leaves it
stopped. A failure after the stop is attempted also leaves the real source
stopped. Immediately before it, the operator must provide this exact
authorization sentence:

```text
I explicitly authorize the Stalwart capture command and leaving the service stopped.
```

That sentence authorizes only this command:

```bash
python3 scripts/capture_stalwart_v015.py capture \
  --source-service stalwart
```

The phrase is an operator/agent approval boundary, not an interactive prompt
implemented by the script. It does not authorize migration, store replacement,
deletion, or starting a different production runtime.

Expected safe output contains the receipt path and
`source Stalwart state: stopped`. The capture must have:

1. proved the source version is v0.15.x;
2. stopped the real source before copying;
3. copied the complete TOML and full stopped `stalwart-data/` tree, with its
   manifest, to a timestamped primary-checkout backup;
4. written mode-`0600`, digest-bound receipts and a pinned rollback definition;
5. proved an isolated rollback copy by version and management read; and
6. left the real v0.15 source stopped.

Re-verify both receipt and rollback proof:

```bash
python3 scripts/capture_stalwart_v015.py verify \
  --receipt debug-dashboard/.runtime/stalwart-migration/latest-source.json
python3 scripts/capture_stalwart_v015.py prove-rollback \
  --receipt debug-dashboard/.runtime/stalwart-migration/latest-source.json
```

Stop here if either command fails, the receipt does not identify the primary
checkout, the source is not stopped, the canonical receipt/backup is missing,
or any manifest/digest differs.

## 2. Know the rollback state

The rollback runtime is an isolated copy made from the immutable v0.15 backup.
It uses a separate loopback endpoint and scratch `rollback-data`. It never
mounts, restores, or overwrites the real `stalwart-data/`.

Calculate the source-receipt digest without placing credential material in
shell history:

```bash
shasum -a 256 \
  debug-dashboard/.runtime/stalwart-migration/latest-source.json
```

Copy the displayed 64-hex receipt digest into
`<source-receipt-sha256>` in exactly one of these commands.

First reconcile after an interrupted activation or deactivation:

```bash
python3 scripts/capture_stalwart_v015.py reconcile-rollback \
  --receipt debug-dashboard/.runtime/stalwart-migration/latest-source.json \
  --expected-receipt-sha256 <source-receipt-sha256>
```

The result has one of two meanings:

- `rollback reconciliation complete: inactive` means no verified rollback
  runtime is active. It is safe to leave it inactive or explicitly activate it.
- `rollback reconciliation complete: active ...` means the exact
  intent/proof/runtime binding, v0.15 version, and management read all verify.
  Do not activate a second copy.

Activate only when rollback service is intentionally required:

```bash
python3 scripts/capture_stalwart_v015.py activate-rollback \
  --receipt debug-dashboard/.runtime/stalwart-migration/latest-source.json \
  --expected-receipt-sha256 <source-receipt-sha256>
```

The command prints only the verified loopback endpoint and activation-proof
path; the captured real source remains stopped. To retire an active isolated
rollback and refresh its working copy from the immutable backup:

```bash
python3 scripts/capture_stalwart_v015.py deactivate-rollback \
  --receipt debug-dashboard/.runtime/stalwart-migration/latest-source.json \
  --expected-receipt-sha256 <source-receipt-sha256>
```

Never remove rollback containers or activation files by hand. A foreign,
ambiguous, or tampered candidate is a hard stop, not something reconciliation
will adopt or destroy.

## 3. Install the pinned v0.16 runtime model

Only after Step 1 succeeds may the primary checkout be updated to the reviewed
v0.16 model. Its Stalwart service is fixed to:

- image `stalwartlabs/stalwart:v0.16.17@sha256:a8108e19bd927e172d4d8c128907b8dfc93fd180ae8ee07dccdd42cb97eb9dfa`;
- container name `stalwart-dev`;
- user `2000:2000`;
- restart policy `unless-stopped`;
- TCP loopback publication `127.0.0.1:8443` to container port `8080`;
- TCP loopback publication `127.0.0.1:8587` to authenticated submission port
  `587`;
- `STALWART_PUBLIC_URL=http://127.0.0.1:8443`;
- a long-form bind with `type: bind`, `source: ./stalwart`,
  `target: /etc/stalwart`, `read_only: true`, and
  `bind.create_host_path: false`;
- a long-form bind with `type: bind`, `source: ./stalwart-data`,
  `target: /var/lib/stalwart`, `read_only: false`, and
  `bind.create_host_path: false`;
- readiness at `http://127.0.0.1:8080/healthz/ready`; and
- no `ADMIN_SECRET` or `STALWART_RECOVERY_*` variable.

The expected local image ID is
`sha256:a8108e19bd927e172d4d8c128907b8dfc93fd180ae8ee07dccdd42cb97eb9dfa`.
The migration tools validate it locally and use `--pull never`.

`stalwart/config.json` must contain exactly this pretty-printed byte sequence:

```json
{
  "@type": "RocksDb",
  "path": "/var/lib/stalwart/"
}
```

It is exactly 56 bytes, has no final LF, and has SHA-256
`8b48a8b7b4b4923083b045ff2fdd7eef690e3b53df2d449f891491172c791963`.
Compact one-line JSON and a trailing LF are explicitly rejected. Verify the
tracked file without starting Stalwart:

```bash
test "$(wc -c < stalwart/config.json | tr -d ' ')" = 56
test "$(shasum -a 256 stalwart/config.json | awk '{print $1}')" = \
  8b48a8b7b4b4923083b045ff2fdd7eef690e3b53df2d449f891491172c791963
test "$(tail -c 1 stalwart/config.json | od -An -tuC | tr -d ' ')" = 125
docker compose config --quiet
docker compose config --images
```

Do not run `docker compose up` here.

## 4. Prepare and review the migration

Create a dedicated owner-only virtual environment for the upstream script.
Do not install its dependencies into the repository's host interpreter:

```bash
umask 077
test ! -e debug-dashboard/.runtime/stalwart-migration/venv
python3 -m venv \
  debug-dashboard/.runtime/stalwart-migration/venv
MIGRATION_PYTHON="$(pwd -P)/debug-dashboard/.runtime/stalwart-migration/venv/bin/python"
test ! -L debug-dashboard/.runtime/stalwart-migration/venv
test "$(stat -f '%Lp' debug-dashboard/.runtime/stalwart-migration/venv)" = 700
test ! -L "$MIGRATION_PYTHON"
"$MIGRATION_PYTHON" -m pip install requests urllib3
test -x "$MIGRATION_PYTHON"
```

Download only the tagged upstream script and verify its fixed digest:

```bash
curl --proto '=https' --tlsv1.2 -fsSL \
  https://raw.githubusercontent.com/stalwartlabs/stalwart/v0.16.17/resources/scripts/migrate_v016.py \
  -o debug-dashboard/.runtime/stalwart-migration/migrate_v016.py
chmod 0600 \
  debug-dashboard/.runtime/stalwart-migration/migrate_v016.py
echo "008a490b4c3c60572806958e1960749ecdddf263316683017003797b9c34ca1c  debug-dashboard/.runtime/stalwart-migration/migrate_v016.py" \
  | shasum -a 256 --check
```

Run the offline/unit checks and digest-bound dry-run:

```bash
python3 -m unittest discover \
  -s tests \
  -p 'test_stalwart_v016.py' \
  -v
python3 scripts/capture_stalwart_v015.py verify \
  --receipt debug-dashboard/.runtime/stalwart-migration/latest-source.json
python3 scripts/stalwart_v016.py dry-run \
  --script debug-dashboard/.runtime/stalwart-migration/migrate_v016.py \
  --source-receipt debug-dashboard/.runtime/stalwart-migration/latest-source.json \
  --migration-python "$MIGRATION_PYTHON"
```

Inspect every line of the report, including an empty report:

```bash
wc -l \
  debug-dashboard/.runtime/stalwart-migration/unmigrated.txt
sed -n '1,$p' \
  debug-dashboard/.runtime/stalwart-migration/unmigrated.txt
```

Resolve each entry according to the reviewed migration policy. If any entry is
unexplained, stop. Only then bind the exact report:

```bash
python3 scripts/stalwart_v016.py mark-reviewed \
  --report debug-dashboard/.runtime/stalwart-migration/unmigrated.txt
```

Do not issue a manual two-file Compose command here: the required recovery
config and environment do not exist until `apply` materializes and binds them.
The `apply` preflight supplies all three fixed `STALWART_MIGRATION_*` path
variables and performs the exact primary-root, captured-project, two-file
`config --quiet` validation before any `up`.

That internally validated overlay pins v0.16.17, runs the owner helper as root
only for the fixed ownership operation, runs Stalwart as UID/GID 2000,
publishes only `127.0.0.1:8443:8080` and `127.0.0.1:8587:587`, binds the whole
recovery config directory read-only, binds the real data store writable, and
sources the mode-`0600` recovery environment by path.

## 5. Apply, but do not retire recovery

Run apply only after all Step 4 receipts validate:

```bash
python3 scripts/stalwart_v016.py apply \
  --script debug-dashboard/.runtime/stalwart-migration/migrate_v016.py \
  --review-receipt debug-dashboard/.runtime/stalwart-migration/reviewed.json
```

Expected output is the fixed `apply.json` path. At this checkpoint the
digest-bound recovery environment/config must remain available for bootstrap.
Do **not** run `retire-recovery` yet.

Useful secret-free checkpoint paths are:

```text
debug-dashboard/.runtime/stalwart-migration/latest-source.json
debug-dashboard/.runtime/stalwart-migration/dry-run.json
debug-dashboard/.runtime/stalwart-migration/reviewed.json
debug-dashboard/.runtime/stalwart-migration/apply-attempt.json
debug-dashboard/.runtime/stalwart-migration/apply.json
debug-dashboard/.runtime/stalwart-migration/recovery-config/config.json
debug-dashboard/.runtime/stalwart-migration/recovery.env
```

Do not dump the recovery environment or use `docker compose config` in a form
that interpolates and prints its contents.

## 6. Bootstrap at the migration endpoint

Task 7 bootstrap owns the live routing proof. It starts the exact
receipt-bound recovery runtime at `http://127.0.0.1:8443`, invokes
`StalwartRoutingProofCliKt`, and publishes an owner-only
`bootstrap-routing-proof.json` bound into the final `bootstrap.json`.

`StalwartRoutingLiveTest` is configured for the migration endpoint
`127.0.0.1:8443`. Recovery and normal runtime intentionally share that
loopback publication but use different, validated Compose/environment
identities. Do not replace the bootstrap-owned CLI proof with a separate test
invocation.

Validate tracked assets, then bootstrap:

```bash
REPOSITORY_ROOT="$(pwd -P)"
python3 scripts/bootstrap_stalwart_v016.py validate-assets \
  --repository "$REPOSITORY_ROOT"
python3 scripts/bootstrap_stalwart_v016.py bootstrap \
  --repository "$REPOSITORY_ROOT" \
  --migration-python "$MIGRATION_PYTHON"
```

The bootstrap is complete only when it returns the fixed
`debug-dashboard/.runtime/stalwart/bootstrap.json` path and that receipt binds:

- the Task 6 apply receipt;
- tracked manifest and Sieve identities/digests;
- bootstrap attempt/account/key/proof checkpoints;
- immutable management Account and API-key IDs;
- safe owned/preserved object projections;
- the protected-account projection; and
- `bootstrap-routing-proof.json`.

Do not retire recovery if bootstrap fails or any final receipt is absent,
mutable, substituted, or invalid.

## 7. Retire recovery and start the normal runtime

Only after Step 6 succeeds:

```bash
python3 scripts/stalwart_v016.py retire-recovery
```

Retirement revalidates the whole Task 5–7 receipt chain. It starts only the
base Compose Stalwart service on `127.0.0.1:8443`, proves v0.16.17 readiness,
authenticates the exact immutable management Account/API-key binding, proves
the old recovery credential returns 401 or 403, and verifies there is one
expected writer with no migration container. It durably writes
`retire-recovery-proof.json` before deleting the bound recovery environment
and recovery config, then publishes `recovery-retired.json`.

After retirement, run the applicable normal-runtime proofs:

```bash
python3 scripts/stalwart_v016.py normal-runtime-evidence
cd debug-dashboard
STALWART_LIVE_TESTS=1 \
STALWART_BASE_URL=http://127.0.0.1:8443 \
./kotlin test \
  --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.gate.stalwart.StalwartMigrationLiveTest'
STALWART_LIVE_TESTS=1 \
STALWART_BASE_URL=http://127.0.0.1:8443 \
./kotlin test \
  --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.gate.stalwart.StalwartRuntimeCredentialLiveTest'
cd ..
```

`normal-runtime-evidence` is the single authoritative producer consumed by
both Kotlin normal-runtime tests. It does not acquire a migration operation
lock, mutate Stalwart, authenticate to JMAP, or write a receipt. It revalidates
the retired migration/bootstrap chain, performs only the chain validators'
read-only Git and Docker inspection, and emits exactly one canonical,
digest-enveloped, secret-redacted JSON line. Run it only from the captured
primary checkout; a linked worktree is intentionally rejected.

Record a live pass only from the actual command results. This runbook's
presence is not a pass.

## Interruption and recovery matrix

The scripts own recovery. Do not manually remove containers, attempt markers,
proofs, recovery files, or credential objects.

| Observed durable state | Required action |
| --- | --- |
| No valid Task 5 receipt | Keep every v0.16 command stopped; obtain explicit capture authorization. |
| Rollback intent/proof may be incomplete | Run `reconcile-rollback` with the exact source-receipt digest. |
| Reconcile reports active | Use the reported isolated v0.15 endpoint or run validated deactivation; never activate another copy. |
| Reconcile reports inactive | Leave it inactive unless an isolated rollback endpoint is explicitly required. |
| Apply attempt exists after interruption | Re-run the same `apply` command only to enter bound recovery. It does not replay or resume apply: when safe it activates isolated rollback, exits reconciliation-required, and must be followed by `reconcile-rollback` using the exact source-receipt digest. |
| Apply/bootstrap fails after a v0.16 runtime starts | The implementation stops only exact receipt-bound running containers by full 64-hex container ID, then activates isolated rollback. The failed real v0.16 `stalwart-data/` is preserved untouched. |
| Retirement attempt exists with no proof | Do not replay retirement or delete the marker. Re-run `retire-recovery`; it requires reconciliation and uses the durable binding to stop only an exact normal container and activate isolated rollback. |
| Retirement proof exists but recovery deletion is partial | Re-run `retire-recovery`. It performs finalize-only deletion/postflight and does not replay credential mutation or the main executor. |
| Retirement artifact was substituted during partial deletion | Stop. The script fails closed, stops only the exact validated normal container by full ID, and activates isolated rollback; it never deletes a foreign artifact. |
| `recovery-retired.json` validates | Recovery is retired; use base Compose and the normal `:8443` proofs only. |

Direct-ID stopping is an internal safety property, not an operator shortcut:
the recovery path first lists candidates without evaluating mutable Compose
files, inspects full immutable identity, refuses ambiguous/foreign/restarting
candidates, and only then issues `docker container stop --timeout 30` for that
exact full ID. Operators must not substitute a name-based stop.

Restart policy is part of that identity. Exact migration main/owner containers
must use `no`; the exact normal container must use `unless-stopped`. A stopped
non-exact stale candidate is harmless only when `Restarting` is false and its
policy is `no` or `unless-stopped`, so recovery may leave it untouched.
`always`, `on-failure`, an unknown policy, or `Restarting=true` is a latent
writer and blocks both direct stop and rollback activation until an operator
stabilizes it.

In every rollback case, the archival `source-data` and the failed real v0.16
store remain evidence. The isolated rollback uses its refreshable
`rollback-data` copy; it never turns rollback into an implicit reset.
