# Dependency baseline revalidation — 2026-08-10

All publisher metadata in this record was retrieved on 2026-08-10, with the
final UTC checkpoint at `2026-08-10T19:08:53Z`. Versions described as stable
exclude alpha, beta, milestone, release-candidate, development, and nightly
channels. An OCI digest below is the multi-architecture image index digest,
not a platform manifest digest.

## Selected newest-stable baseline

| Dependency | Selected version and channel | Authoritative source | Selection detail |
| --- | --- | --- | --- |
| Kotlin Toolchain | `0.11.1` stable | [JetBrains artifact metadata](https://packages.jetbrains.team/maven/p/amper/amper/org/jetbrains/kotlin/kotlin-cli/maven-metadata.xml) | The wrapper distribution remains pinned by SHA-256 `0ded2a434f6bf193b24e2a6d56c3ba443f4232721155a65aaa8372789412112f`. |
| Kotlin | `2.4.10` stable | [JetBrains release](https://github.com/JetBrains/kotlin/releases/tag/v2.4.10), [artifact metadata](https://repo1.maven.org/maven2/org/jetbrains/kotlin/kotlin-stdlib/maven-metadata.xml) | Latest non-prerelease release. |
| Compose Multiplatform | `1.11.1` stable | [JetBrains release](https://github.com/JetBrains/compose-multiplatform/releases/tag/v1.11.1), [artifact metadata](https://repo1.maven.org/maven2/org/jetbrains/compose/compose-gradle-plugin/maven-metadata.xml) | Latest non-prerelease release. |
| Compose Material3 mapping | `1.11.0-alpha07`, Compose-owned mapping | [Compose 1.11.1 library table](https://github.com/JetBrains/compose-multiplatform/releases/tag/v1.11.1) | This alpha-channel artifact is selected by the stable Compose parent; it is not an independently chosen prerelease. |
| Ktor | `3.5.2` stable | [Ktor release](https://github.com/ktorio/ktor/releases/tag/3.5.2), [artifact metadata](https://repo1.maven.org/maven2/io/ktor/ktor-server-core-jvm/maven-metadata.xml) | Latest non-prerelease release. |
| kotlinx.serialization | `1.11.0` stable | [publisher release](https://github.com/Kotlin/kotlinx.serialization/releases/tag/v1.11.0), [artifact metadata](https://repo1.maven.org/maven2/org/jetbrains/kotlinx/kotlinx-serialization-json-jvm/maven-metadata.xml) | Latest non-prerelease release. |
| JUnit Platform/BOM | `6.1.3` stable | [JUnit release](https://github.com/junit-team/junit-framework/releases/tag/r6.1.3), [artifact metadata](https://repo1.maven.org/maven2/org/junit/junit-bom/maven-metadata.xml) | Replaces `6.1.2`; `6.1.3` was published 2026-08-07. |
| Skiko | `0.144.6`, Compose-managed runtime | [Skiko artifacts](https://repo1.maven.org/maven2/org/jetbrains/skiko/skiko-js-wasm-runtime/maven-metadata.xml), [Skiko releases](https://github.com/JetBrains/skiko/releases) | Kept coherent with the Compose `1.11.1` resolved graph. Standalone `0.151.0` is newer but is not substituted into the parent-managed runtime. |
| Logback | `1.6.1` stable | [Logback release](https://github.com/qos-ch/logback/releases/tag/v_1.6.1), [artifact metadata](https://repo1.maven.org/maven2/ch/qos/logback/logback-classic/maven-metadata.xml) | Latest non-prerelease release. |
| Selenium | `4.47.0` stable | [Selenium release](https://github.com/SeleniumHQ/selenium/releases/tag/selenium-4.47.0), [artifact metadata](https://repo1.maven.org/maven2/org/seleniumhq/selenium/selenium-java/maven-metadata.xml) | Replaces `4.46.0`; `4.47.0` was published during this revalidation on 2026-08-10. |
| js-joda WebJar | `3.2.0` stable | [WebJar artifact metadata](https://repo1.maven.org/maven2/org/webjars/npm/js-joda__core/maven-metadata.xml) | Latest published version of the selected direct coordinate. |
| Jakarta Mail API | `2.1.5` stable | [Maven Central metadata](https://repo1.maven.org/maven2/jakarta/mail/jakarta.mail-api/maven-metadata.xml) | Compile dependency owned exactly once by `dashboard-server`. |
| Angus Mail | `2.0.5` stable | [Maven Central metadata](https://repo1.maven.org/maven2/org/eclipse/angus/angus-mail/maven-metadata.xml) | Runtime-only provider owned exactly once by `dashboard-server`. |
| Dovecot | `2.4.4` stable | [publisher registry tags](https://hub.docker.com/r/dovecot/dovecot/tags), `docker buildx imagetools inspect dovecot/dovecot:2.4.4` | `dovecot/dovecot:2.4.4@sha256:723e3392fe16c6fad8ddc605ea767cc01b4bad9cd9f13eb1dbac15e79c89b2d4`. |
| Stalwart | `v0.16.16` stable final target | [publisher release](https://github.com/stalwartlabs/stalwart/releases/tag/v0.16.16), `docker buildx imagetools inspect stalwartlabs/stalwart:v0.16.16` | Final-target index digest `sha256:66ae90f2753ec1dabd70f69cad7da9f0598d2628a04193ce2b08c7263d47aced`; the normal service is intentionally not cut over in this task. |
| Python | `3.14.7` stable | [Python 3.14.7 release](https://www.python.org/downloads/release/python-3147/), `docker buildx imagetools inspect python:3.14.7-slim-trixie` | `python:3.14.7-slim-trixie@sha256:83c1cebb322d099ac9e3a3a532ba74b0146d702838b25e4c75c02fa81ffeb910`; Python.org published this seventh 3.14 maintenance release on 2026-08-05. |
| Debian | `13.6` stable | [Debian stable release](https://www.debian.org/releases/stable/), `docker buildx imagetools inspect debian:13.6-slim` | `debian:13.6-slim@sha256:3a39a0592364683e6bab97937b72cad5a8fa6dcbbee90edb3bb48c7f8e94f258`; the tag's index was refreshed since the previous pin. |

## Direct Debian packages

The official [Trixie main package index](https://deb.debian.org/debian/dists/trixie/main/binary-amd64/Packages.xz),
[Trixie updates index](https://deb.debian.org/debian/dists/trixie-updates/main/binary-amd64/Packages.xz),
and [Trixie security index](https://security.debian.org/debian-security/dists/trixie-security/main/binary-amd64/Packages.xz)
were compared. The security repository supersedes main's Postfix
`3.10.11-0+deb13u1`; the exact newest installable set remains:

| Package | Selected stable binary version | Repository |
| --- | --- | --- |
| `postfix` | `3.10.12-0+deb13u2` | `trixie-security` |
| `libsasl2-2` | `2.1.28+dfsg1-9` | `trixie/main` |
| `libsasl2-modules` | `2.1.28+dfsg1-9` | `trixie/main` |
| `sasl2-bin` | `2.1.28+dfsg1-9` | `trixie/main` |
| `netcat-openbsd` | `1.229-1` | `trixie/main` |

These are distribution-managed binary versions; upstream project versions are
not forced over the versions published for Debian 13.6.

## Temporary live Stalwart migration hold

The running normal Stalwart container was inspected read-only. It reports
image `stalwartlabs/stalwart:latest`, Compose image ID
`sha256:dcf575db2d53d9ef86d6ced8abe4ba491984659a0f8862cc6079ee7b41c3c568`,
OCI label `org.opencontainers.image.version=v0.15`, source revision
`9aecfc1dfd53a87c8918a6a98123c50af2001998`, and creation time
`2026-02-14T21:18:41.943Z`. Publisher registry inspection of
`stalwartlabs/stalwart:v0.15` returned the identical multi-architecture index
digest. Therefore the root declaration is frozen without a pull, restart, or
data access as:

```text
stalwartlabs/stalwart:v0.15@sha256:dcf575db2d53d9ef86d6ced8abe4ba491984659a0f8862cc6079ee7b41c3c568
```

This is an immutable description of the observed legacy runtime, not the
selected final baseline. `v0.16.16` remains the newest stable target and needs
the separately authorized capture/migration/cutover workflow. No
`stalwart-data` content was read and the running container was not changed.

## Newer non-selected channels and managed exceptions

The following numerically newer entries were visible but are not stable direct
selections:

- Kotlin Toolchain `0.12.0-dev-*` (metadata latest observed
  `0.12.0-dev-4234`) is a development stream without a stable release.
- Kotlin `2.4.20-Beta1` and `2.4.20-Beta2` are beta releases.
- Compose `1.12.0-alpha01`, `1.12.0-alpha02`, `1.12.0-beta01`,
  `1.12.0-beta02`, and `1.12.0-beta03` are prereleases.
- Compose Material3 `1.12.0-alpha01` through `1.12.0-alpha03` are prereleases
  and are not the Compose `1.11.1` mapping.
- Jakarta Mail API `2.2.0-M1` and Angus Mail `2.1.0-M1` are milestone builds.
- Python `3.15.0a1` through `3.15.0a8`, `3.15.0b1` through `3.15.0b4`, and
  [`3.15.0rc1`](https://www.python.org/downloads/release/python-3150rc1/)
  are preview releases. Python.org published `3.15.0rc1` on 2026-08-04 but
  explicitly identifies it as a release-candidate preview not recommended for
  production, so it does not displace stable `3.14.7`.
- Skiko `0.148.1`, `0.148.2`, `0.150.0`, `0.150.1`, and upstream stable
  `0.151.0` are newer standalone artifacts. They are not selected because
  Compose `1.11.1` owns the runtime graph at `0.144.6`; forcing a newer Skiko
  would break the reviewed parent-managed closure.

No numerically newer published entry was visible in the cited stable/artifact
metadata for Ktor, kotlinx.serialization, JUnit, Logback, Selenium, the
selected js-joda WebJar coordinate, Dovecot, or Stalwart. Material3 and Skiko
are the only parent-managed exceptions in the Kotlin graph; the JUnit engine
and launcher versions are BOM-managed, and the Debian binaries are
distribution-managed.
