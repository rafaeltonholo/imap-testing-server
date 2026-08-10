# Debug Dashboard Single-Stack Provider Integration — Design Specification

**Date:** 2026-08-10

**Status:** Approved architecture; written-spec review pending

**Target:** `debug-dashboard/` and the repository-root Docker Compose mail sandbox

**Supersedes:** The isolated-provider runtime, generated Dovecot eligibility authority,
Dovecot operator credential path, and Stalwart AppPassword lifecycle described in
`2026-07-23-debug-dashboard-design.md`. The all-Kotlin application architecture,
provider-native behavior, requested workflow coverage, and approved visual design remain
in force.

## 1. Goal

Make the dashboard an administrative and diagnostic client for the repository's existing
Dovecot/Postfix/OAuth2 and Stalwart services. The dashboard must show and mutate the real
accounts and mailboxes already present in this sandbox. It must not start or maintain a
second provider universe.

This is a trusted, loopback-only developer test tool. Its job is to reproduce email-client
and provider behavior, including authentication failures. Production credential isolation,
rotation, recovery workflows, and privilege separation are explicitly unnecessary.

The dashboard remains unusable until all originally requested account, folder, message,
mail-operation, delivery, password, deletion, and log workflows pass against both normal
provider instances.

## 2. Problem Being Corrected

The current dashboard launcher creates an isolated Compose project for Dovecot, Postfix,
and OAuth2 and starts a separate Stalwart gate fixture. It therefore reads different account
authorities, mail stores, ports, and logs from the normal sandbox:

| Boundary | Dashboard currently uses | Required target |
|---|---|---|
| Dovecot accounts | `debug-dashboard/.runtime/local-providers/dovecot/users` | `config/users` |
| Dovecot mail | `debug-dashboard/.runtime/local-providers/vmail` | `vmail/` |
| SMTP delivery | isolated Postfix on host port `21025` | root Postfix on host port `1025` |
| Logs | Compose project `mail-sandbox-dashboard` | root Compose project and services |
| Stalwart | gate store under `.runtime/stalwart-gate0b` | root `stalwart-data/` |

The earlier dashboard work also deleted the tracked `config/users` fixture. Its nine
records remain recoverable from Git and every record used the public test password
`secret`. The matching Maildirs under `vmail/` still exist.

The root Stalwart runtime has a second mismatch: the existing running instance is from the
older OIDC-only model, while the dashboard adapter targets the approved current registry
and ordinary password-backed JMAP model. This must be handled as an in-place upgrade of
the existing root store, not by substituting a new store.

## 3. Design Principles

1. **One provider stack.** Root Docker Compose services are the only interactive runtime.
2. **Provider-native truth.** Dovecot and Stalwart own account existence and mailbox state.
3. **No implicit synchronization.** Divergence between providers is valid diagnostic state.
4. **Simple, known test credentials.** Plaintext local fixtures are intentional.
5. **Startup preserves state.** Initialization is create-if-absent; reset is always explicit.
6. **Test as the ordinary user.** Mail and authentication probes use the account credential,
   not an administrative impersonation path.
7. **Current, reproducible dependencies.** Use the newest stable compatible release verified
   at implementation time and pin its exact version and digest.

## 4. Runtime Architecture

```mermaid
flowchart LR
    Browser["Compose/Wasm SPA"] -->|"JSON + SSE"| Server["Ktor/JVM dashboard"]
    Server --> Catalog["Gitignored test metadata and known passwords"]
    Server -->|"docker compose exec -T dovecot doveadm"| Dovecot["Root Dovecot"]
    Server -->|"SMTP :1025"| Postfix["Root Postfix"]
    Server -->|"JMAP/admin :8443; SMTP :8587"| Stalwart["Root Stalwart"]
    Server -->|"docker compose logs"| Logs["Root service logs"]
    Dovecot --> Users["config/users"]
    Dovecot --> Vmail["vmail/"]
    Postfix --> Dovecot
    Stalwart --> Store["stalwart-data/"]
    OAuth["Root OAuth2 mock"] --> Users
```

The Ktor and Compose/Wasm boundaries do not change. All provider routing does:

- every Compose command runs from the repository root against only
  `docker-compose.yml`;
- no product-runtime command supplies the dashboard provider overlay or gate fixture;
- Dovecot administration and mailbox operations execute an allowlisted `doveadm`
  command in the normal `dovecot` service;
- Dovecot delivery uses normal Postfix;
- Stalwart management, JMAP mail, and SMTP use the normal root Stalwart service;
- logs come from the same root services the developer's email client is exercising.

Acceptance fixtures may continue to create throwaway Compose projects. They are test
harnesses only and cannot be selected by normal dashboard wiring.

## 5. Dovecot Account Authority

### 5.1 Active and default files

`config/users` is restored as the single mutable Dovecot account authority. It remains
gitignored so dashboard account changes do not dirty the repository.

A tracked `config/users.defaults` contains the recovered default records:

```text
dev@local.test:{PLAIN}secret
dev1@local.test:{PLAIN}secret
dev2@local.test:{PLAIN}secret
dev3@local.test:{PLAIN}secret
dev4@local.test:{PLAIN}secret
dev5@local.test:{PLAIN}secret
a_very_long-email_for_testing@local.test:{PLAIN}secret
inline_img@local.test:{PLAIN}secret
inline_msg@local.test:{PLAIN}secret
```

The launcher copies `config/users.defaults` to `config/users` only when `config/users`
does not exist. An existing empty file is intentional and must not be repopulated.
Startup never compares, merges, or overwrites the active file. An explicit reset command
or dashboard action may replace it with the defaults after clearly stating that account
authentication state will be reset.

### 5.2 Consumers and mutations

Dovecot passwd-file authentication and userdb, the OAuth2 mock's eligibility checks, the
legacy Python account scripts, and the dashboard all consume this same file. There is no
generated hashed eligibility copy.

Dashboard create, password-change, and delete operations:

1. take a host-side file lock;
2. validate and read the current records;
3. write a complete temporary file in the same directory;
4. atomically replace `config/users`;
5. flush/reload Dovecot authentication state when required by the current server version;
6. verify the resulting account projection with normal `doveadm`.

The default and normal password-change scheme is `{PLAIN}`. Scheme-prefixed hashes may be
accepted later when a hash-specific issue needs reproduction, but they are not part of the
ordinary workflow.

Deleting Dovecot authentication does not silently delete the account's Maildir. Mailbox
purging remains a separate, explicit provider-specific choice.

## 6. Stalwart Account Authority and Upgrade

### 6.1 Preserve the existing store

`stalwart-data/` remains the only Stalwart store. It must never be deleted, replaced with
the gate store, or implicitly reseeded.

Before upgrading the real store, the implementation must:

1. stop Stalwart cleanly;
2. create a recoverable local snapshot of `stalwart-data/`;
3. rehearse and validate the upgrade against a disposable copy;
4. upgrade the original store only after the rehearsal succeeds;
5. retain the snapshot until live acceptance passes.

The implementation first verifies the newest stable Stalwart release from official
sources. It pins the selected tag and image digest. If the newest stable release cannot
satisfy the approved JMAP registry, ordinary password, SMTP, or data-migration contract,
implementation stops and reports the exact incompatibility instead of silently choosing
an older release. Pre-release, nightly, or unreleased source versions are not "latest
stable"; if one is newer, the final dependency report explains that distinction.

### 6.2 Authentication model

The upgraded normal instance uses its internal account directory with ordinary password
credentials. Password reset therefore changes the credential an email client actually
uses. Stalwart's supported built-in OAuth flow may remain available as an additional test
path; an external OIDC directory must not be the sole account authority.

One fixed test management identity receives only the permissions needed for domain and
account listing/CRUD. Prefer a normal password such as `secret`. If the verified current
Stalwart API requires an API-key credential for these operations, use one static,
gitignored test key. Do not implement credential rotation, recovery generations,
AppPassword enrollment, encryption-at-rest, or a management credential lifecycle.

The normal service publishes JMAP/admin HTTP on `127.0.0.1:8443` and authenticated SMTP
submission on `127.0.0.1:8587`. Debug tracing writes to normal container output so the
dashboard's log view observes the same provider.

### 6.3 Existing accounts with unknown passwords

The dashboard enumerates the live Stalwart registry on every refresh. A live account is
shown even when the dashboard has no known plaintext password.

Management operations remain available for such an account. Mail, SMTP, and ordinary-user
authentication operations show **Password required** and offer either:

- supply and verify the existing password for this local session; or
- reset the account to a new known test password.

The dashboard never assumes that an existing account uses `secret` merely because its
address appears in a default fixture.

## 7. Dashboard Catalog

The gitignored dashboard catalog is a convenience cache, not account authority. It may
store:

- provider account ID and canonical address;
- enabled, provider-enforced protocol capabilities;
- the known ordinary plaintext test password;
- safe UI metadata such as the last selected provider.

Records are keyed by provider plus immutable provider account ID where available. The same
email address on Dovecot and Stalwart remains one logical account with independent provider
instances. Deleting or losing the catalog cannot make a live provider account disappear
from the dashboard; it only changes the account to **Password required** where necessary.

There is no encryption, rotation, quarantine, leased-secret, or crash-recovery protocol for
this file. It is gitignored and contains disposable local test values.

## 8. Provider Capabilities and Authentication Reproduction

Provider and protocol selections must describe behavior enforced by the provider:

- Dovecot accounts expose the protocols configured in normal Dovecot, with Postfix as the
  SMTP delivery path.
- Stalwart accounts expose the JMAP and SMTP permissions configured on the real account.
- An unsupported or server-wide capability is not represented as a per-account toggle.

The dashboard has a control plane and a test plane:

- **Control plane:** `doveadm`, Dovecot passwd-file mutation, and Stalwart management calls.
- **Test plane:** ordinary-account IMAP/POP3/SMTP/JMAP/OAuth requests using the selected
  account credential and returning the provider response plus correlated logs.

Administrative success never substitutes for an ordinary-account authentication test.
This separation lets a developer reproduce wrong-password, missing-account, disabled
permission, stale credential, and OAuth-token failures without production security
machinery obscuring the provider behavior.

## 9. Lifecycle and State Preservation

`debug-dashboard/start-local.sh` performs only these provider actions:

1. create TLS fixtures if absent;
2. create `config/users` from defaults if absent;
3. verify or perform the approved Stalwart in-place upgrade;
4. run root `docker compose up -d --wait` for the normal services;
5. build and start the dashboard.

It does not reset accounts, copy data from one provider to another, start a provider
overlay, or create a gate store. It must converge stale containers to the root Compose
definition rather than accepting any running container as sufficient.

Stopping the dashboard stops only the dashboard process. Provider lifecycle remains the
normal root Compose lifecycle. A separately named reset command handles explicit fixture
restoration; reset is never an option hidden inside ordinary stop behavior.

The following paths are preservation boundaries:

- `config/users`;
- `vmail/`;
- `stalwart-data/`;
- unrelated files under `debug-dashboard/.runtime/`.

No startup, migration, acceptance cleanup, or account refresh may broadly delete or
replace them.

## 10. Data Flow and Failure Handling

### Account refresh

1. list Dovecot users from the active passwd file/provider;
2. query the live Stalwart account registry;
3. join by canonical address into logical accounts;
4. overlay catalog metadata without filtering provider records;
5. report provider-specific readiness and errors independently.

### Mutations

Dual-provider operations are itemized, not transactional fiction. If Dovecot succeeds and
Stalwart fails, the response reports both outcomes and preserves the divergence for retry
or diagnosis. The dashboard does not roll back a successful provider mutation unless that
provider offers an explicit, verified inverse requested by the user.

### Startup and migration failures

- a missing `config/users` is initialized; an unreadable or malformed existing file is an
  actionable startup error and is not replaced;
- a failed Stalwart rehearsal leaves the real store untouched;
- a failed real-store upgrade stops startup and retains the snapshot;
- an unavailable provider does not cause its accounts to be removed from the other
  provider or from persistent provider state;
- error messages identify the actual service, endpoint, command, and safe provider receipt.

## 11. Testing and Acceptance

Implementation follows test-first development for behavior changes.

### Automated contract tests

- the normal Dovecot adapter cannot select the overlay Compose file or isolated project;
- all Dovecot account, folder, message, and log commands address the root service;
- Dovecot bootstrap is create-if-absent and preserves an empty or modified active file;
- atomic passwd-file mutations preserve unrelated records;
- OAuth eligibility and legacy scripts use `config/users`;
- Stalwart product wiring uses `:8443`, normal SMTP, and the normal management credential;
- live Stalwart accounts appear without catalog credentials;
- unknown credentials disable only ordinary-user mail/auth actions;
- startup and stop scripts never reference gate or local-provider product runtimes;
- the dashboard catalog cannot hide a provider account;
- provider/protocol claims match actual enforced capabilities.

### Migration proof

The current root Stalwart store is upgraded only after the same operation passes against a
copy. The proof verifies account inventory, JMAP discovery, ordinary-password login,
management CRUD, SMTP submission, and store restart before and after migration.

### Live usability acceptance

Against the normal root services, the suite must verify every requested workflow on both
provider profiles:

1. server and account-related logs;
2. pre-existing account discovery;
3. account create with valid capabilities;
4. EML, authored text, and deterministic random message creation/delivery;
5. folder list/create/delete;
6. message list/read;
7. ordinary-account password change and authentication with the new password;
8. account deletion;
9. read/unread, flag/unflag, copy, move, trash, and permanent delete.

The suite also performs explicit ordinary-account authentication probes and confirms that
their attempts appear in the normal service logs. Cleanup is limited to uniquely generated
acceptance accounts and folders. It never resets the complete passwd file, `vmail/`, or
`stalwart-data/`.

The recovered nine Dovecot accounts and all pre-existing Stalwart accounts must remain
visible after acceptance.

## 12. Dependency Policy

Before changing a toolchain, library, or provider image, implementation checks the official
stable release source. The newest stable compatible release is selected and pinned. A
freshness test or documented check prevents an unreviewed `latest` tag from drifting.

When a numerically newer artifact is not selected, the handoff must name it and explain the
reason—for example, pre-release status, lack of a published stable artifact, unsupported
Kotlin Toolchain metadata, or a demonstrated provider regression. Compatibility is never
assumed, and an older version is never chosen silently.

## 13. Documentation Consequences

The implementation updates:

- root setup, connection, account, and log instructions;
- the Docker Compose service and volume maps;
- Dovecot authentication documentation;
- Stalwart configuration, migration, and admin instructions;
- dashboard start/stop/reset behavior;
- the dependency/version rationale;
- the original dashboard design spec with a prominent supersession link.

References to `mail-sandbox-dashboard`, ports `21025`, `18443`, or `18587`, the product
Stalwart gate store, generated Dovecot eligibility hashes, Dovecot operator credentials,
encrypted AppPassword storage, or automatic Dovecot-to-Stalwart synchronization must not
remain as descriptions of the normal interactive runtime.

## 14. Non-Goals

- production deployment or external users;
- multi-user dashboard authorization;
- encrypted local test credentials;
- credential rotation or recovery ceremonies;
- provider impersonation;
- continuous reconciliation between Dovecot and Stalwart;
- silently upgrading across an unverified provider data format;
- deleting existing mail data to make tests pass;
- redesigning the approved dashboard visual system.

## 15. Completion Criteria

This corrective work is complete only when:

- `config/users` is restored with the nine recoverable defaults without deleting Maildirs;
- the dashboard lists existing Dovecot and Stalwart accounts from live provider state;
- all interactive operations use only the normal root services and data stores;
- the existing Stalwart store is upgraded in place with a retained recovery snapshot;
- ordinary password changes and authentication probes work on both providers;
- the complete two-provider live usability acceptance suite passes;
- startup preserves intentionally divergent or broken authentication state;
- dependency versions are the newest stable compatible releases and the version rationale
  is recorded;
- unrelated user changes remain untouched.
