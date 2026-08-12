# Stalwart LAN Runtime Design Amendment

**Status:** Approved direction, recorded 2026-08-12

**Scope:** Amend the approved single-stack dashboard design so the final normal
Stalwart runtime is usable by physical test devices on the developer's LAN.
This does not authorize writing the normal Stalwart store or starting the new
runtime; those actions retain the separate live-migration authorization gate.

## Context and decision

Publishing a host port is not enough for JMAP. Stalwart places
`STALWART_PUBLIC_URL` into its absolute JMAP and OAuth discovery URLs. A
physical device that receives `http://127.0.0.1:8443/jmap/` tries to connect to
itself, not the developer machine.

The selected design is therefore:

- final normal JMAP/admin: `0.0.0.0:8443` to container port `8080`;
- final normal authenticated submission: `0.0.0.0:8587` to container port
  `587`;
- advertised URL: `http://<validated-LAN-host>:8443`;
- migration recovery, rollback, rehearsal, and gate fixtures remain
  loopback-only;
- container-local readiness remains `http://127.0.0.1:8080/healthz/ready`.

This is intentionally a local debug topology. It is not a production exposure
model and must not be presented as one.

## Runtime network configuration

A small standard-library Python command owns one generated file:

```text
debug-dashboard/.runtime/stalwart/network.env
```

The file is mode `0600` beneath an owner-only directory and contains exactly
one line:

```text
STALWART_PUBLIC_URL=http://<LAN-host>:8443
```

The host comes from the explicit `MAIL_SANDBOX_LAN_HOST` override when set.
Otherwise the command asks the operating system for the one default-route
interface and then for that interface's one non-loopback IPv4 address. No
route, multiple equal-priority default routes, no IPv4, or multiple eligible
IPv4 addresses is a hard stop that names the explicit override. There is no
guess based on interface names or address ordering.

An override may be a plain non-loopback unicast IPv4 address or a safe local
hostname. A hostname must resolve to exactly one eligible IPv4 address and
that address must also appear on a local non-loopback interface. The helper
rejects schemes, paths, credentials, ports, whitespace, loopback, wildcard,
multicast, unspecified, non-local, and ambiguous values, writes the file
atomically, and prints only the resulting public URL.

The normal root Compose service reads this explicit service `env_file`. It does
not depend on Compose's implicit `.env`; project launchers continue to set
`COMPOSE_DISABLE_ENV_FILE=1`. A missing or invalid network file is a startup
error with a command that regenerates it.

The dynamic LAN host is deliberately excluded from immutable migration and
current-store receipts. Those receipts bind image, configuration, and store
identity. Startup and live proof bind the current generated network file to the
rendered Compose model and running container instead. A DHCP address change
therefore requires regeneration, a forced Compose recreation of the Stalwart
service so Docker reloads the service `env_file`, and a dashboard-process
restart so it reloads the same URL. The recreation command is:

```bash
docker compose up -d --force-recreate stalwart
```

Startup then reproves JMAP discovery. Existing migration/current-store receipts
remain valid and no data migration runs.

## Dashboard and protocol behavior

The dashboard receives the same validated public base URL at startup. Normal
Stalwart JMAP clients connect using that base and require the discovered
`apiUrl` to equal `<public-base>/jmap/`. The dashboard's SMTP submission probe
may continue to connect to `127.0.0.1:8587`, because the all-interface
publication includes loopback and the SMTP protocol advertises no JMAP URL.

Endpoint profiles distinguish three identities:

- gate fixture: fixed `127.0.0.1:18443`;
- migration/recovery bootstrap: fixed `127.0.0.1:8443`;
- normal runtime: a validated LAN public URL on port `8443`.

No normal-runtime code may silently fall back to loopback. That would make the
dashboard appear healthy while physical-device discovery remains broken.

## Migration and rehearsal boundary

The captured v0.15 source and normal `stalwart-data/` remain stopped and
untouched until the existing exact live-migration authorization is supplied.
Dry-run and rehearsal operate only through the verified snapshot and disposable
copies. The temporary recovery overlay keeps its loopback publications because
it is an operator-only migration endpoint; only the final normal runtime uses
the LAN publications and advertised LAN URL.

This boundary is executable, not documentary. Before the exact live-migration
authorization, no command path may select or start the root normal Stalwart
service, pass root `stalwart-data/` to a writable mount, or edit the root
Stalwart service declaration. Pre-gate validation is limited to static model
inspection and disposable captured copies. Physical-device and live-LAN
acceptance occurs only after the authorized cutover.

The disposable rehearsal publishes transport only on dedicated loopback ports.
It may start with `STALWART_PUBLIC_URL` set to the selected LAN URL and assert
that discovery advertises that exact value, but it must not follow that URL.
All rehearsal management, JMAP mutation, and SMTP traffic is sent directly to
the isolated loopback endpoint. This proves URL construction without exposing
the rehearsal or risking traffic to the stopped/root service.

The disposable rehearsal must prove, against a captured copy:

- migration output and account inventory;
- JMAP discovery with the configured advertised LAN URL;
- known ordinary-password behavior;
- management create/read/update/delete;
- authenticated SMTP submission on the isolated rehearsal port;
- folder, message read/move/flag/delete operations; and
- stop/start persistence.

It must preserve a receipt and remove only the disposable runtime after proof.
Any failure keeps the original service stopped and normal store unchanged.

## Failure handling

- No usable or unambiguous LAN address: stop before Compose and explain the
  override.
- Invalid or replaced network file: fail before starting or adopting a runtime.
- Rendered ports or public URL differ: fail the Compose/runtime proof.
- JMAP advertises a different URL: fail the client proof; do not rewrite the
  server response.
- Network file refreshed after DHCP: recreate Stalwart, restart the dashboard,
  and reprove discovery; never invalidate or rerun store migration receipts.
- Rehearsal failure: retain evidence, clean only known disposable resources,
  and do not request or perform live apply.
- Live apply failure after separate authorization: follow the existing retained
  snapshot and documented rollback path.

## Test strategy

Tests are added before implementation and cover:

- deterministic override and local-route address generation;
- rejection of unsafe or unusable host values and atomic mode-correct output;
- exact normal Compose LAN publications and service `env_file`;
- loopback-only recovery, rollback, rehearsal, and gate definitions remain
  unchanged;
- runtime/container validators accept only the current generated public URL;
- dashboard construction and JMAP session validation use the dynamic normal
  profile with no loopback fallback;
- scripts propagate one URL to Compose, dashboard, and live acceptance;
- disposable migration rehearsal never mounts the normal store;
- no pre-authorization path can start the normal service or mount the normal
  store writable; and
- physical-device reachability is checked using the selected LAN host only
  after authorized cutover.

The final acceptance gate still requires all requested dashboard operations on
both root providers and preservation of pre-existing accounts and mail.
