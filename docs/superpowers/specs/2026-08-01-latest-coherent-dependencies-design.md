# Latest Coherent Dependency Baseline — Design Specification

**Date:** 2026-08-01

**Status:** Policy A approved by the user on 2026-08-01

**Target:** the active `mail-sandbox` repository and `debug-dashboard/`

## 1. Goal

Make current dependencies a hard prerequisite for dashboard usability without
assembling unsupported combinations of independently versioned components.
Every active direct dependency must use the newest stable release available at
the time its implementation batch is verified. Components owned by a stable
framework or operating-system distribution must use the exact versions that
the newest stable parent publishes and tests together.

This specification does not narrow the dashboard goal. The dashboard remains
unusable until all requested Dovecot and Stalwart workflows pass live
acceptance. This dependency baseline is an additional stop/go gate before that
feature work continues.

## 2. Approved Meaning of “Latest”

The user selected **Policy A: latest coherent stable ecosystem**.

The rules are:

1. **Direct application and tool declarations use the latest stable release.**
   Stable means a generally available release, not an alpha, beta, milestone,
   release candidate, nightly, snapshot, or development build.
2. **A latest stable parent owns its managed graph.** If Compose, Ktor, or an
   official BOM publishes an exact compatible runtime version, use that version
   instead of forcing a newer standalone artifact into the graph.
3. **The latest stable operating-system distribution owns its package set.**
   Direct packages use the newest stable/security package in that distribution.
   They are not replaced with bespoke source builds solely to obtain a larger
   upstream version number.
4. **Container images use immutable version-plus-multi-architecture-digest
   references.** Floating tags such as `latest` are forbidden in active
   runtime configuration.
5. **Direct optional and developer-tool dependencies are version-pinned too.**
   They do not become exceptions merely because they run outside the product
   process.
6. **Transitive dependencies remain owned by their latest stable parent.** They
   are not individually overridden unless the parent explicitly supports that
   override or the dependency becomes direct.
7. **No compatibility downgrade is silent.** Every selected version that is
   lower than the newest standalone upstream release appears in Section 4 with
   the exact reason.
8. **Freshness is checked again before each implementation batch and final
   acceptance.** A newly published stable release invalidates the recorded
   baseline until it is incorporated and the affected evidence is rerun.

Generated caches, disabled Toolchain features, protocol/status numbers, data
format schema versions, and historical gate evidence are not active dependency
declarations. Historical reports retain the versions they actually proved and
receive a supersession note instead of being rewritten.

## 3. Approved Baseline as of 2026-08-01

### 3.1 Kotlin dashboard stack

| Dependency | Current | Selected | Ownership |
|---|---:|---:|---|
| Kotlin | 2.3.21 | 2.4.10 | direct, latest stable |
| Kotlin Toolchain CLI/wrapper | 0.11.1 | 0.11.1 | direct, already latest stable |
| Compose Multiplatform | 1.10.3 | 1.11.1 | direct, latest stable |
| Compose Material3 | 1.10.0-alpha05 managed | 1.11.0-alpha07 managed | Compose 1.11.1 bundle |
| Skiko Wasm runtime | 0.9.37.4 | 0.144.6 | Compose 1.11.1 managed runtime |
| Ktor | 3.4.3 | 3.5.2 | direct, latest stable |
| kotlinx.serialization | 1.10.0 effective | 1.11.0 | direct Toolchain setting |
| kotlinx.coroutines | 1.10.2 transitive | 1.11.0 | Ktor/Compose resolved graph |
| JUnit Platform | 6.0.3 runner | 6.1.2 | direct test-runner setting |
| Logback Classic | 1.5.18 | 1.6.1 | direct, latest stable |
| Selenium Java | 4.46.0 | 4.46.0 | direct, already latest stable |
| js-joda WebJar | 3.2.0 | 3.2.0 | direct runtime asset, already latest |

The future implementation plans must also be corrected before these direct
dependencies are introduced:

| Planned dependency | Old planned value | Selected value |
|---|---:|---:|
| SQLite JDBC | 3.53.1.0 | 3.53.2.1 |
| Jakarta Mail API | 2.1.5 | 2.1.5 |
| Angus Mail | 2.0.5 | 2.0.5 |
| jsoup | 1.22.2 | 1.23.1 |

### 3.2 Provider and container stack

| Component | Selected immutable reference/version |
|---|---|
| Dovecot | `dovecot/dovecot:2.4.4@sha256:723e3392fe16c6fad8ddc605ea767cc01b4bad9cd9f13eb1dbac15e79c89b2d4` |
| Stalwart | `stalwartlabs/stalwart:v0.16.15@sha256:4f926193e5dd9ceb1e24ba48160702310381b12e51972c2fb0cc9de020388136` |
| Stalwart CLI | `stalwartlabs/cli:1.0.12@sha256:fe199affac1d120a8c200ef39ae629765a2976270e0453575c1caf906ee15b52` |
| OAuth mock base | `python:3.14.6-slim-trixie@sha256:cea0e6040540fb2b965b6e7fb5ffa00871e632eef63719f0ea54bca189ce14a6` |
| Postfix base | `debian:13.6-slim@sha256:020c0d20b9880058cbe785a9db107156c3c75c2ac944a6aa7ab59f2add76a7bd` |
| Postfix package | `3.10.12-0+deb13u2` from Debian 13 stable-security |
| Cyrus SASL runtime/modules/tools | `2.1.28+dfsg1-9` from Debian 13 |
| netcat-openbsd | `1.229-1` from Debian 13 |

The Postfix image pins every directly installed `apt` package to the selected
Debian 13 version. Package dependencies selected transitively by Debian remain
distribution-managed. `main.cf` explicitly sets `compatibility_level = 3.6`,
the newest compatibility boundary used by the selected Postfix 3.10 line, so a
repository-owned replacement `main.cf` does not accidentally re-enable legacy
defaults.

### 3.3 Repository tooling

| Tool | Selected version |
|---|---:|
| `@modelcontextprotocol/server-filesystem` | 2026.7.10 |
| `@modelcontextprotocol/server-memory` | 2026.7.4 |
| `@modelcontextprotocol/server-sequential-thinking` | 2026.7.4 |
| optional `extract-msg` helper | 0.56.0 |
| Stalwart migration `requests` | 2.34.2 |
| Stalwart migration `urllib3` | 2.7.0 |

The three MCP packages are exact `npx` arguments rather than unversioned
package names. Optional Python installation instructions use `==` pins. The
application and ordinary repository scripts remain Python-standard-library
only; these external Python packages belong only to the explicitly documented
optional conversion or migration environments.

## 4. Why We Are Not Using the “Latest Latest” Everywhere

“Latest standalone artifact” and “latest supported stack” are not always the
same thing. Policy A chooses the latter, with no hidden exceptions.

### 4.1 Compose and Skiko

Standalone `org.jetbrains.skiko:skiko-js-wasm-runtime` 0.150.1 exists, but the
latest stable Compose Multiplatform 1.11.1 module metadata requires Skiko
0.144.6. Skiko supplies the JavaScript bridge and native Wasm binary that must
match the Compose/Skia bindings used at compile time. Forcing 0.150.1 would
create a mixed ABI/runtime that JetBrains did not publish as the Compose 1.11.1
stack. Selecting 0.144.6 is therefore using the newest official Compose stack,
not preserving the old 0.9.37.4 dependency.

Compose 1.11.1 also publishes Material3 1.11.0-alpha07 as its managed Material3
component. Its prerelease-looking suffix is allowed only because it is part of
the stable Compose release's official graph; it is not an independently chosen
prerelease.

The server-side asset allowlist must move to the exact 0.144.6 resources:

| Resource | SHA-256 |
|---|---|
| `skiko.mjs` | `7fa5652ceb6343affed0360d2a8e5e35dbce1dff6192b2268c7519861af2dff4` |
| `skiko.wasm` | `46caff5f783599bd1c5d3e5e87959d7cb5102c515aac671c9280664368e71dab` |

The browser gate must prove that the linked Compose application and these
companions load together. A passing JVM compile alone is insufficient.

### 4.2 Debian and Postfix

Upstream Postfix 3.11.5 exists, while the newest stable-security Postfix in the
latest stable Debian 13 distribution is 3.10.12. Policy A selects Debian's
3.10.12 package because Debian integrates it with the distribution's OpenSSL
3.5, libc, service layout, Cyrus SASL packages, security updates, and package
lifecycle. Building 3.11.5 from source would create a new, repository-owned
Postfix distribution that must independently own all of that integration.

This is not an indefinite exemption. When Debian stable publishes a newer
Postfix package, or a newer stable Debian release becomes the selected parent,
the freshness gate requires the project to move and rerun SMTP, SMTPS,
submission, SASL, socketmap, and LMTP proofs.

## 5. Change Boundaries

The upgrade is implemented in four ordered batches. A later batch cannot hide
or bypass a failure in an earlier one.

### Batch 1 — Kotlin Toolchain graph and browser assets

- Pin Kotlin 2.4.10 in all three modules. Pin serialization 1.11.0 and JUnit
  Platform 6.1.2 in each applicable JVM/shared-JVM setting; do not add JUnit to
  the Wasm-only app.
- In `dashboard-server`, pin Ktor 3.5.2, Logback 1.6.1, the Compose-matched
  Skiko runtime 0.144.6, Selenium 4.46.0, and js-joda 3.2.0.
- In `dashboard-web`, pin Compose 1.11.1 and Ktor 3.5.2; let Compose own its
  Material3 and Skiko graph and let Ktor own its supported coroutines graph.
- Keep the checked-in Toolchain wrapper at verified 0.11.1.
- Update the Skiko classpath-resource hashes and any changed linker/import
  closure in `WebAssetBundle` and its tests.
- Correct future dependency versions in active implementation plans.
- Re-resolve the complete graph and inspect conflicts; do not infer success
  from top-level YAML alone.

### Batch 2 — Dovecot, OAuth mock, and Postfix

- Upgrade both Dovecot services to the exact 2.4.4 index digest.
- Advance and revalidate the standalone operator configuration rather than
  merely changing its declared version.
- Change POP3S container port 31990 to 31995 everywhere active.
- Replace the operator healthcheck's `grep`/`awk` dependency because the
  confined 2.4.4 image no longer contains those tools.
- Upgrade the Python and Debian bases and pin directly installed Debian
  packages.
- Rebuild/recreate only disposable proof services for validation. Dovecot
  master-auth, OAuth, Postfix SASL, socketmap, LMTP, and mailbox behavior are
  all re-proven.

### Batch 3 — Stalwart baseline

- Move every active v0.16 target to the exact v0.16.15 index digest and the
  versioned Stalwart CLI reference.
- Retain the byte-identical v0.16 migration script digest while changing its
  source URL to the v0.16.15 tag.
- Regenerate receipt-bound expectations through the existing migration
  process; never hand-edit runtime receipts.
- Add copy/move coverage for the v0.16.15 `Email/copy` and
  `onSuccessDestroyOriginal` fixes.
- Keep disposable Gate 0B validation separate from the normal Stalwart data
  migration. No live Stalwart capture, restart, migration, or replacement is
  authorized without the repository's existing explicit capture phrase.

### Batch 4 — Tooling pins and evidence

- Pin direct MCP and optional Python tool versions.
- Add exact-version regression checks for active manifests, Dockerfiles, and
  package invocations.
- Update current operational documentation and mark older gate reports as
  superseded without falsifying their historical evidence.
- Recheck authoritative release metadata on the day the batch completes.

## 6. Failure and Upgrade Policy

- If the latest coherent versions do not resolve, compile, link, start, or pass
  protocol proofs, the batch remains red. The implementation adapts the code or
  configuration; it does not silently restore an older dependency.
- If a parent framework publishes a new stable version during implementation,
  its managed graph replaces this snapshot and the affected batch restarts.
- A digest mismatch, missing expected runtime asset, unexpected bare browser
  import, or floating active image tag is a startup/test failure.
- Provider behavior changes are classified with typed proof failures. A timeout
  or partial operation never becomes success merely to keep the upgrade green.
- Existing live Stalwart state is never used as a disposable compatibility
  probe.

## 7. Verification Contract

### Static and resolution evidence

- `./kotlin --version` reports Toolchain 0.11.1.
- `./kotlin show settings --all-modules` reports the selected Kotlin, Compose,
  Ktor, serialization, and JUnit values.
- `./kotlin show dependencies --all-modules --include-tests` proves the resolved
  versions and official managed exceptions.
- Exact-version tests reject old/floating image, Maven, npm, pip, and direct apt
  declarations.
- Default, operator-profile, migration, and proof Compose models resolve.

### Build and test evidence

- Shared JVM/Wasm contract tests, server tests, and the complete Toolchain build
  pass with no Gradle/npm fallback.
- The Compose/Wasm browser gate loads the served application, Skiko bridge,
  Skiko Wasm, js-joda import map, and Compose resources in a real browser.
- Python 3.14 warnings-as-errors compilation and the complete stdlib test suite
  pass.
- The rebuilt Postfix image passes `postfix check`; reviewed `postconf -n` and
  `postconf -m` prove the expected configuration and socketmap support.

### Live disposable evidence

- Gate 0C passes against Dovecot 2.4.4, Python 3.14.6, Debian 13.6, and Postfix
  3.10.12, including ordinary protocols, master isolation, rotation, SMTP
  delivery, and clean teardown.
- Gate 0B passes against Stalwart v0.16.15, including permissions, AppPassword
  lifecycle, Registry projections, Blob behavior, copy/move, deletion, routing,
  and cleanup.
- Container-reported versions and `RepoDigests` match the selected references.
- Baseline service/container/network/volume state is restored after each
  disposable lifecycle.

## 8. Acceptance

The dependency gate passes only when:

1. authoritative sources still identify every direct parent as latest stable;
2. every active direct declaration is exact and matches this policy;
3. every managed exception is visible and matches its parent metadata;
4. the resolved dependency graph contains no unexplained version override;
5. both provider gates and the real browser gate pass on the upgraded stack;
6. current documentation records the new evidence without rewriting history.

Passing this gate permits dashboard feature implementation to continue. It
does not by itself satisfy the dashboard's nine two-provider usability
requirements.

## 9. Authoritative Sources

- Kotlin releases: <https://kotlinlang.org/docs/releases.html>
- Kotlin Toolchain metadata: <https://packages.jetbrains.team/maven/p/amper/amper/org/jetbrains/kotlin/kotlin-cli/maven-metadata.xml>
- Compose 1.11.1 release: <https://github.com/JetBrains/compose-multiplatform/releases/tag/v1.11.1>
- Compose/Skiko Wasm metadata: <https://repo.maven.apache.org/maven2/org/jetbrains/compose/foundation/foundation-wasm-js/1.11.1/foundation-wasm-js-1.11.1.module>
- Ktor releases: <https://ktor.io/docs/releases.html>
- Maven Central metadata: <https://repo.maven.apache.org/maven2/>
- Dovecot 2.4 releases: <https://dovecot.org/releases/2.4/>
- Dovecot image metadata: <https://hub.docker.com/v2/repositories/dovecot/dovecot/tags/2.4.4>
- Stalwart v0.16.15: <https://github.com/stalwartlabs/stalwart/releases/tag/v0.16.15>
- Stalwart image metadata: <https://hub.docker.com/v2/repositories/stalwartlabs/stalwart/tags/v0.16.15>
- Python releases: <https://www.python.org/downloads/>
- Debian releases: <https://www.debian.org/releases/>
- Debian Postfix package: <https://packages.debian.org/trixie/postfix>
- Postfix compatibility guide: <https://www.postfix.org/COMPATIBILITY_README.html>
- npm registry: <https://registry.npmjs.org/>
- PyPI JSON API: <https://pypi.org/pypi/extract-msg/json>
