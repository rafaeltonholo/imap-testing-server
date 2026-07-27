# Gate 0A: Kotlin Toolchain scaffold

Date: 2026-07-27

## Reviewed Toolchain provenance

The global convenience installation was not changed or used to generate this
project. The reviewed, versioned wrapper was downloaded from:

```text
https://packages.jetbrains.team/maven/p/amper/amper/org/jetbrains/kotlin/kotlin-cli/0.11.1/kotlin-cli-0.11.1-wrapper
```

The published wrapper checksum passed before the wrapper was executed:

```text
$gate_cli_dir/kotlin: OK
SHA-256: 6dbcdde0bcae41705c187aefb6c91c6c29ef9079c8072a473c2149151f8d7962
```

The verified wrapper then accepted the downloaded distribution with its
embedded checksum:

```text
SHA-256: 0ded2a434f6bf193b24e2a6d56c3ba443f4232721155a65aaa8372789412112f
Downloading Kotlin Toolchain distribution v0.11.1...
Download complete.
```

Both the versioned wrapper and the generated project wrapper reported exactly:

```text
Kotlin Toolchain version 0.11.1 (801e9d4, 2026-06-05)
```

The generated `debug-dashboard/kotlin` wrapper also has the published wrapper
SHA-256 above. The disposable CLI directory was removed after this proof.

## Initializer evidence

The first non-interactive initializer attempt exposed a Toolchain 0.11.1
behavioral quirk:

```text
Usage: kotlin init [<options>] [<template>]

Error: invalid value for --target-dir: directory "debug-dashboard" is not writable.
```

The worktree root was writable and the absent target remained absent. After
creating an empty `debug-dashboard/` target, the same official initializer
completed:

```text
Extracting template ktor-server to debug-dashboard…
Project successfully generated
```

The generated `kotlin`, `kotlin.bat`, `module.yaml`, `src/`, and `resources/`
were verified before moving the Ktor module content under
`dashboard-server/`.

## Schema red/green evidence

The pre-scaffold RED check failed because `debug-dashboard/` and its local
wrapper did not exist.

The first three-module model check rejected the otherwise valid Ktor catalog
keys in the Wasm module:

```text
No catalog value for the key `ktor.client.core`
No catalog value for the key `ktor.client.contentNegotiation`
No catalog value for the key `ktor.serialization.kotlinx.json`
```

In Toolchain 0.11.1, Ktor aliases are conditional on
`settings.ktor.enabled`. Enabling Ktor in `dashboard-web/module.yaml` made the
model valid. The official 0.11.1 catalog spelling for SSE is `$ktor.sse`;
there is no `$ktor.client.sse`.

The GREEN module model is:

```text
dashboard-contract  kmp/lib
dashboard-server    jvm/app
dashboard-web       wasm-js/app
```

Effective settings prove that the contract has `jvm` and `wasmJs` targets,
the server has only `jvm`, and the web app has only `wasmJs`. The contract's
JSON serialization setting is enabled for its common and platform scopes.

For a multi-module project, the non-interactive 0.11.1 CLI requires
`--all-modules` for settings and dependency reports. The bare shorthand exits
with:

```text
ERROR: Please specify the module(s) to inspect with --module, or use --all-modules to inspect all modules
```

From the repository root, the reproducible non-interactive validation commands
are therefore:

```bash
(
  cd debug-dashboard
  ./kotlin show modules
  ./kotlin show settings --all-modules
  ./kotlin show dependencies --all-modules --include-tests
)
```

## Effective reviewed versions

The unpinned 0.11.1 scaffold first reported Kotlin 2.3.21, Compose 1.10.3, and
Ktor 3.4.3 as its effective defaults. The used versions were then pinned in
the module YAML:

```text
dashboard-contract:
  kotlin.version: 2.3.21
  kotlin.serialization.format: json

dashboard-server:
  kotlin.version: 2.3.21
  ktor.enabled: true
  ktor.version: 3.4.3

dashboard-web:
  kotlin.version: 2.3.21
  compose.enabled: true
  compose.version: 1.10.3
  compose.resources.packageName: mail.sandbox.dashboard.web.generated.resources
  ktor.enabled: true
  ktor.version: 3.4.3
```

The server test scope pins
`org.seleniumhq.selenium:selenium-java:4.46.0`; no other module declares
Selenium.

## Dependency, build, and alternate-stack proof

`./kotlin show dependencies --all-modules --include-tests` exited successfully.
The resolved graph proves:

```text
dashboard-contract [jvm, wasmJs]
  org.jetbrains.kotlinx:kotlinx-serialization-json:1.10.0

dashboard-server [jvm]
  Module dashboard-contract
  io.ktor:ktor-server-core:3.4.3
  io.ktor:ktor-server-netty:3.4.3
  io.ktor:ktor-server-config-yaml:3.4.3
  test: org.seleniumhq.selenium:selenium-java:4.46.0

dashboard-web [wasmJs]
  Module dashboard-contract
  org.jetbrains.compose.foundation:foundation:1.10.3
  org.jetbrains.compose.material3:material3:1.10.0-alpha05
  io.ktor:ktor-client-core:3.4.3
  io.ktor:ktor-client-content-negotiation:3.4.3
  io.ktor:ktor-serialization-kotlinx-json:3.4.3
  io.ktor:ktor-sse:3.4.3
```

Selenium appears as a direct dependency only in the server test graph.

An empty `wasm-js/app` exposes a Toolchain 0.11.1 linker edge case. With the
final Task 1 source-free module, `./kotlin build --module dashboard-web`
reproduced:

```text
error: it is not possible to produce a KLIB ('-Xinclude' is not passed) and
compile the resulting JavaScript artifact ('-Xir-produce-js' is passed) at the
same time with the K2 compiler
```

The debug log showed that the empty `compileWasmJs` task produced no KLIB.
`WebLinkTask` therefore had no path for `-Xinclude` while still requesting
`-Xir-produce-js`. This was not a YAML, platform, or dependency conflict.

To prove the configured stack without starting the later UI task, a temporary
source-only probe was added:

```kotlin
fun main() {
}
```

With that probe, both commands completed successfully:

```text
./kotlin build --module dashboard-web
Build successful

./kotlin build
Build successful
```

The temporary source was then removed. The committed Task 1 scaffold remains
source-free; a full build of that exact state will continue to hit the
0.11.1 empty-app edge case until a later task adds the real Wasm entry point.

From the repository root, the alternate-stack scan of tracked and non-ignored
worktree files completed with no output. It checks the Git index plus untracked
files that are not ignored, so only ignored output such as Toolchain linker
artifacts is omitted:

```bash
git ls-files --cached --others --exclude-standard . \
  | rg '(^|/)(build\.gradle(\.kts)?|settings\.gradle(\.kts)?|gradlew(\.bat)?|gradle\.properties|\.npmrc|package(-lock)?\.json|yarn\.lock|pnpm-lock\.yaml)$|(^|/)gradle/wrapper(/|$)|\.(js|jsx|cjs|mjs|ts|tsx|mts|cts)$'
```
