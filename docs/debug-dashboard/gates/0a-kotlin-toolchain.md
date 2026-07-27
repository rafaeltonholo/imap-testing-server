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

## Task 3: minimal Compose/Wasm gate artifact

All commands in this section were run from `debug-dashboard/` with the
reviewed wrapper and its isolated cache/home:

```bash
export KOTLIN_CLI_BOOTSTRAP_CACHE_DIR=$PWD/.runtime/toolchain-cache
export KOTLIN_CLI_JAVA_HOME='/Applications/Android Studio.app/Contents/jbr/Contents/Home'
export KOTLIN_CLI_JAVA_OPTIONS="-Duser.home=$PWD/.runtime/home"
```

### Reducer TDD and the Wasm test-executor limit

The pure reducer test was written first at
`dashboard-web/test/mail/sandbox/dashboard/web/GateStateTest.kt`, before any
reducer implementation. It covers the two gate routes, API probe status,
sequence advancement, reconnect status, invalid and non-monotonic sequences,
stale/resync state, and every `Increment proof` activation.

With that test present, the required web test command exited 1:

```text
./kotlin test --include-module dashboard-web

ERROR: No test tasks were found for specified include filters
```

`./kotlin show tasks` exits 0 and lists
`:dashboard-web:compileWasmJsTest` and `:dashboard-web:linkWasmJsTest`, but no
Wasm test runtime task. Toolchain 0.11.1 can compile/link a Wasm test binary;
its `test` command cannot execute one.

The approved fallback moved only the pure gate reducer and its test into:

```text
dashboard-contract/src/mail/sandbox/dashboard/contract/gate/GateState.kt
dashboard-contract/test/mail/sandbox/dashboard/contract/gate/GateStateTest.kt
```

The contract RED command exited 1. The expected errors were unresolved
`GateState`, `GateAction`, status types, and `reduceGateState` references:

```text
./kotlin test --include-module dashboard-contract

ERROR: Kotlin compilation failed with 73 errors (see above)
```

After the minimum reducer was implemented, the same command exited 0. A
follow-up RED for truthful initial SSE state exited 1 on the missing
`SseSyncStatus.Pending`; after adding that one state, the final GREEN run
executed 10/10 JVM tests (seven gate tests and the three existing contract
tests) with zero skipped or failed.

A new empty build directory made the final shared Wasm proof independent of
the repository build cache:

```text
mktemp -d /private/tmp/gate0a-task3-final-link.XXXXXX
/private/tmp/gate0a-task3-final-link.YGIsOx

./kotlin task \
  --build-dir=/private/tmp/gate0a-task3-final-link.YGIsOx \
  :dashboard-contract:linkWasmJsTest
```

The task exited 0 after running `compileWasmJs`, `compileWasmJsTest`, and
`linkWasmJsTest`. This is shared-source compilation/link evidence only; no
Wasm test runtime passed.

### Compose entry point, semantics, and resource

`dashboard-web` now has a real `ComposeViewport(document.body!!)` entry point,
an explicit `ExperimentalComposeUiApi` opt-in, and a small Material gate
surface. The UI uses the shared reducer for route and activation state,
pushes `/` and `/gate/details` through browser history, and renders:

- Compose heading semantics for `Mail Flight Recorder` (heading intent, not a
  claim that the canvas text is a native DOM `h1`);
- the keyboard-focusable Material button labeled exactly `Increment proof`;
- text labels for current route, activation count, JSON API status, SSE
  sequence, reconnect status, and sync status;
- truthful initial `pending`/`disconnected` status until Task 5 wires
  transport; and
- the exact marker `GATE_RESOURCE: toolchain-compose-resource-ok`.

Pinned Compose Wasm 1.10.3 mirrors heading semantics as `role="heading"` but
does not add an `aria-level`. The UI also declares polite Compose live-region
semantics for changing status text, while this pinned Wasm semantics mirror
does not currently emit `aria-live`. Keyboard and browser accessibility-tree
behavior therefore remain explicit Task 5 browser-runtime checks.

The checked-in marker is loaded through the generated
`mail.sandbox.dashboard.web.generated.resources.Res.readBytes` API. The
source file and prepared output are byte-identical, 45 bytes including the
trailing newline, with SHA-256:

```text
7b0f843ebd49d2709bcd8e3d1021db98e68413823647895d8377a6657f5e6960
```

Toolchain 0.11.1 did not embed or stage the marker beneath the linker output.
It emitted a separate `text/plain` prepared resource at:

```text
build/artifacts/PreparedComposeResourcesDirArtifact/dashboard-webcommon/files/gate-proof.txt
```

The generated API requests this browser-relative URI:

```text
./composeResources/mail.sandbox.dashboard.web.generated.resources/files/gate-proof.txt
```

These scoped checks prove the marker is absent from the linked code assets and
present in the prepared resource:

```bash
rg -a -l -F 'GATE_RESOURCE: toolchain-compose-resource-ok' \
  build/tasks/_dashboard-web_linkWasmJs
# exit 1, no output

rg -a -l -F 'GATE_RESOURCE: toolchain-compose-resource-ok' \
  build/artifacts/PreparedComposeResourcesDirArtifact/dashboard-webcommon
# exit 0, prints .../files/gate-proof.txt
```

There is no merged prepared-resource artifact in the final build. Serving
only the linker directory would therefore make this resource request return
404; Task 4 must explicitly stage or map the prepared resource root.

### Link artifacts and variant behavior

The final command exited 0:

```text
./kotlin build --module dashboard-web
Build successful
```

The first run after adding Compose resources had exited 1 because the isolated
cache lacked pinned `components-resources:1.10.3` metadata and the sandbox
could not reach Maven. The identical command was allowed to fetch that pinned
metadata, then succeeded; the final cached command above succeeded without
network access.

The exact linker directory and code assets are:

```text
build/tasks/_dashboard-web_linkWasmJs/
```

| Filename | Bytes | SHA-256 |
| --- | ---: | --- |
| `dashboard-web.wasm` | 8,449,717 | `84ed2b509f3892bb1317edb8a1d38f003821154a02a58e25ea8053c4e2feda1a` |
| `dashboard-web.mjs` | 2,833 | `cb4cb2d848a3f7c7959fe7d1b70ce5be34eb999db4d640858e09cbac413c2917` |
| `dashboard-web.import-object.mjs` | 30,042 | `5651da31cf4f09e9a17a4e6b2dcdab181d0769c9ddaaa4b908dbbfbb33d3927e` |
| `dashboard-web.js-builtins.mjs` | 2,095 | `a370c66f8031ae3a8d5718123a7fb1aeed4f43caca681181ef69b512321d5b94` |

The entry module uses relative imports for `dashboard-web.wasm` and
`dashboard-web.import-object.mjs`; the import-object module uses the emitted
`dashboard-web.js-builtins.mjs`. However, it also imports relative
`./skiko.mjs` and bare `@js-joda/core`. The cached `skiko.mjs` in turn fetches
relative `skiko.wasm`. Toolchain output contains neither Skiko companion:

```bash
rg -n "skiko\\.mjs|@js-joda/core|from './" \
  build/tasks/_dashboard-web_linkWasmJs/*.mjs
# exit 0; shows ./skiko.mjs and @js-joda/core imports

find build -type f \( -name 'skiko.mjs' -o -name 'skiko.wasm' \) -print
# exit 0, no output
```

The resolved transitive
`skiko-js-wasm-runtime-0.9.37.4.jar` does contain `skiko.mjs` and
`skiko.wasm`, but Toolchain 0.11.1 does not copy them to its linker output.
Task 3 intentionally did not vendor/copy runtime JavaScript or introduce a
Node/npm packaging stack: doing so would hide the Toolchain-only gate result
and exceed this task's scope. Consequently the compiler and linker succeed,
but the requirement for a complete set of runnable relative companions is
not satisfied by the Toolchain build output.

The explicit release probe also exited 0:

```text
./kotlin build --module dashboard-web --variant release

WARN Explicit -v/--variant argument is ignored because none of the selected
platforms (wasmJs) support build variants.
Build successful
```

No separate release artifact exists in Toolchain 0.11.1. Browser startup,
resource delivery, focus traversal, accessibility-tree output, reducer
interaction, and live transport are not claimed here; those remain Task 4/5
runtime validation.
