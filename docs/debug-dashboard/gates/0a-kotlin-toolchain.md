# Gate 0A: Kotlin Toolchain browser proof

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
`SseSyncStatus.Pending`. A later review RED executed 15 tests and failed the
four targeted transition cases: newer ordinary receipt cleared `Stale`,
ordinary receipt cleared `Resyncing`, equal-cursor completion stayed `Stale`,
and completion replaced `Reconnecting` with `Connected`. The new
invalid/regressive completion test already passed. After separating ordinary
receipt from explicit resync completion, those 15 tests passed. A final guard
RED then executed 16 tests and failed only because completion outside
`Resyncing` advanced the cursor from 12 to 20. After enforcing the active
resync precondition, those 16 tests passed. A re-review RED then executed 18
tests and failed only the duplicate and regressive ordinary-receipt cases,
which changed active `Resyncing` state to `Stale`. After making active resync
sticky for every ordinary receipt, the final GREEN run executed 18/18 JVM
tests (15 gate tests and the three existing contract tests) with zero skipped
or failed.

A new empty build directory made the final shared Wasm proof independent of
the repository build cache:

```text
mktemp -d /private/tmp/gate0a-task3-resync-link.XXXXXX
/private/tmp/gate0a-task3-resync-link.8tTTyi

./kotlin task \
  --build-dir=/private/tmp/gate0a-task3-resync-link.8tTTyi \
  :dashboard-contract:linkWasmJsTest
```

The task exited 0 after running `compileWasmJs`, `compileWasmJsTest`, and
`linkWasmJsTest`. This is shared-source compilation/link evidence only; no
Wasm test runtime passed.

### Compose entry point, semantics, and resource

`dashboard-web` now has a real `ComposeViewport(document.body!!)` entry point,
an explicit `ExperimentalComposeUiApi` opt-in, and a small Material gate
surface. The UI uses the shared reducer for route and activation state,
exposes `Overview` and `Gate details` controls with selected semantics, pushes
only inactive `/` and `/gate/details` selections through browser history, and
renders:

- Compose heading semantics for `Mail Flight Recorder` (heading intent, not a
  claim that the canvas text is a native DOM `h1`);
- the keyboard-focusable Material button labeled exactly `Increment proof`;
- text labels for current route, activation count, JSON API status, SSE
  sequence, reconnect status, and sync status;
- truthful initial `pending`/`disconnected` status before transport starts; and
- the exact marker `GATE_RESOURCE: toolchain-compose-resource-ok`.

Pinned Compose Wasm 1.10.3 mirrors heading semantics as `role="heading"` but
does not add an `aria-level`. The UI also declares polite Compose live-region
semantics for changing status text, while this pinned Wasm semantics mirror
does not currently emit `aria-live`. Task 5's browser-runtime checks below
verify the actual keyboard, focus, and accessibility-tree behavior.

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
404. Task 4 resolves that finding by validating and mapping the prepared
resource root separately, as recorded below.

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

The exact linker directory and current code assets, refreshed by the final
Task 6 build, are:

```text
build/tasks/_dashboard-web_linkWasmJs/
```

| Filename | Bytes | SHA-256 |
| --- | ---: | --- |
| `dashboard-web.wasm` | 9,165,892 | `a799190b3c85994884064907c7f88a549598191e8f1950817901aeefd2240964` |
| `dashboard-web.mjs` | 2,833 | `cb4cb2d848a3f7c7959fe7d1b70ce5be34eb999db4d640858e09cbac413c2917` |
| `dashboard-web.import-object.mjs` | 31,696 | `af1c221d54fbb2fa8e56478772d563cce7d2f1daecd9da4624edf1d75f5313c3` |
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
and exceed this task's scope. This was an intentionally unresolved Task 3
finding about the linker directory in isolation. Task 4 resolves it without
copying either resource into source control: Ktor loads the exact resources
from one pinned Maven artifact, validates their hashes, and adds them to the
immutable production manifest.

The explicit release probe also exited 0:

```text
./kotlin build --module dashboard-web --variant release

WARN Explicit -v/--variant argument is ignored because none of the selected
platforms (wasmJs) support build variants.
Build successful
```

No separate release artifact exists in Toolchain 0.11.1. Browser startup,
resource delivery, focus traversal, accessibility-tree output, reducer
interaction, and live transport are proved by the Task 4/5 evidence below.

## Task 4: validated production asset bundle

Task 4 closes every missing-companion and separately prepared-resource finding
from Task 3. The Ktor `WebAssetBundle` starts only when all three explicit
inputs are present and canonical:

```text
DASHBOARD_WEB_ASSETS=<absolute linker directory>
DASHBOARD_WEB_RESOURCES=<absolute prepared Compose-resource directory>
DASHBOARD_WEB_ENTRY=dashboard-web.mjs
```

The production loader accepts one explicit `.mjs` entry, recursively validates
its executable import and `new URL` closure, snapshots every accepted byte,
rejects traversal, symlinks, ambiguous classpath resources, unreviewed loaders,
unknown bare imports, and unreviewed MIME extensions, and exposes only the
immutable validated manifest. The Compose resource mapper serves the prepared
marker at:

```text
/assets/composeResources/mail.sandbox.dashboard.web.generated.resources/files/gate-proof.txt
```

The authored HTML contains one module entry and one narrow import map. It maps
only `@js-joda/core` to `/assets/js-joda.esm.js`; there is no generated
bootstrap or development server.

Exactly two additional Maven runtime artifacts are ordinary, version-pinned
Toolchain dependencies:

| Maven artifact | Served file | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| `org.jetbrains.skiko:skiko-js-wasm-runtime:0.9.37.4` | `skiko.mjs` | 632,832 | `5dc3302763d61014d4a3277727f6e1af041741ae1f0efcc2acc21f2924cad99e` |
| `org.jetbrains.skiko:skiko-js-wasm-runtime:0.9.37.4` | `skiko.wasm` | 8,642,989 | `69afd1fba0567fc79515d97bac5c0670cfeb180284823f986199637f154a9bbe` |
| `org.webjars.npm:js-joda__core:3.2.0` | `js-joda.esm.js` | 401,606 | `a716a37f4c3bb47f8795688e1cd6451130a08d825d8a6df664ef72b349ec445b` |

The final prepared marker remains 45 bytes with SHA-256
`7b0f843ebd49d2709bcd8e3d1021db98e68413823647895d8377a6657f5e6960`.
The final production bundle is therefore the four current Toolchain-linked
files listed above, this one Toolchain-prepared resource, and the three
hash-pinned classpath resources from exactly two Maven artifacts. No unresolved
browser import remains in the validated manifest.

## Task 5: production browser evidence

The Kotlin/JVM Selenium gate starts the real Ktor `module()` on an ephemeral
loopback port. That production configuration calls
`WebAssetBundle.fromEnvironment()` and consumes all three values above; the
test does not inject a fixture asset bundle or infer the entry filename.

The final explicit browser run used:

```text
Google Chrome: 150.0.7871.182
ChromeDriver: 150.0.7871.124
ChromeDriver build:
9261fd0a595ac4964ea84e6bd4a025c1173a2ffa-refs/branch-heads/7871@{#3359}
```

Chrome ran headlessly with
`--enable-features=WebAssemblyGarbageCollection`. **WasmGC PASS:** the
Toolchain-linked application and Skiko Wasm both loaded, the Compose viewport
rendered, and the browser reported no runtime exception, console error,
uncancelled loading failure, HTTP error, or wrong/unreviewed response MIME.

The observed runtime assertions were:

- **Compose/resource:** the visible Compose canvas exposed the heading
  `Mail Flight Recorder` and the generated-`Res` marker
  `GATE_RESOURCE: toolchain-compose-resource-ok`.
- **API:** same-origin `fetch("/api/v1/gate/probe")` decoded the exact typed
  payload and rendered `API message: ready`.
- **History:** activating `Gate details` pushed `/gate/details`; a full reload
  retained that route and rendered `Selected route: /gate/details`; browser
  Back restored `/` and `Selected route: /`.
- **SSE:** native browser `EventSource` received ordinary IDs `1`, `2`, then
  automatically reconnected with `Last-Event-ID: 2` and received `3`, `4`.
  After the two-item buffer evicted that cursor, the next reconnect received a
  typed `resync` event at ID `6`. CDP observed event IDs
  `[1, 2, 3, 4, 6]`, event names
  `[message, message, message, message, resync]`, and at least three event
  stream requests. The UI rendered `SSE sequence: 4`,
  `SSE sync: resyncing`, and, after the client intentionally closed,
  `Reconnect status: disconnected`. No SSE request carried a query string.
- **Keyboard/focus:** Tab reached `Increment proof`; the semantic focus label
  changed to `Keyboard focus: increment proof`; the active `main` host was
  `#dashboard-root` with a computed solid 3 px outline; Enter rendered
  `Activation count: 1`.
- **Accessibility tree:** Chrome exposed `Mail Flight Recorder` with role
  `heading`, and `Increment proof` with role `button`, the exact accessible
  name, `ignored=false`, and no disabled state.

The deterministic server tests separately prove fresh-page reset, monotonic
resume, invalid/unknown cursor resync, eviction-induced stale cursor resync,
valid closing event-stream framing, and real `Last-Event-ID` handling.

## Task 6: final verification

All commands in this section were rerun against the final Task 5 source before
this report was frozen. Commands ran from `debug-dashboard/` unless noted.

| Command | Exit | Exact result |
| --- | ---: | --- |
| `shasum -a 256 kotlin` | 0 | `6dbcdde0bcae41705c187aefb6c91c6c29ef9079c8072a473c2149151f8d7962` |
| `./kotlin --version` | 0 | `Kotlin Toolchain version 0.11.1 (801e9d4, 2026-06-05)` |
| `./kotlin build` | 0 | `Build successful`; JVM modules compiled and the Wasm app linked |
| `./kotlin build --module dashboard-web --variant release` | 0 | `Build successful`; 0.11.1 warned that Wasm ignores variants, so no separate release artifact exists |
| production-environment explicit `KotlinToolchainBrowserGateTest` | 0 | 1/1 test passed in the browser/driver versions above |
| production-environment `./kotlin test` | 0 | `dashboard-contract`: 20/20 JVM tests; `dashboard-server`: 25/25 JVM tests; 45 total, zero skipped/failed |
| `./kotlin show modules` | 0 | exactly `dashboard-contract` (`kmp/lib`), `dashboard-server` (`jvm/app`), `dashboard-web` (`wasm-js/app`) |
| `./kotlin show settings` | 1 | expected multi-module selector error |
| `./kotlin show settings --all-modules` | 0 | Kotlin `2.3.21`, Compose `1.10.3`, Ktor `3.4.3`; contract targets JVM + WasmJs |
| `./kotlin show dependencies` | 1 | expected multi-module selector error |
| `./kotlin show dependencies --all-modules --include-tests` | 0 | complete graph resolved; includes the two runtime pins and Selenium Java `4.46.0` only in server tests |
| `./kotlin show tasks` | 0 | Toolchain JVM/Wasm/Compose tasks only; no Gradle, npm, Node, React, or TypeScript task |

Toolchain 0.11.1's bare settings and dependency reports are not valid
non-interactive shorthand for this multi-module project. Both exit 1 with:

```text
ERROR: Please specify the module(s) to inspect with --module, or use --all-modules to inspect all modules
```

The successful `--all-modules` reports resolve these reviewed versions:

| Component | Version |
| --- | --- |
| Kotlin Toolchain wrapper/distribution | `0.11.1 (801e9d4, 2026-06-05)` |
| Kotlin | `2.3.21` |
| Kotlinx Serialization JSON | `1.10.0` |
| Compose Multiplatform | `1.10.3` |
| Compose Material 3 | `1.10.0-alpha05` |
| Ktor | `3.4.3` |
| Skiko runtime artifact | `0.9.37.4` |
| JS-Joda WebJar | `3.2.0` |
| Selenium Java, server test scope only | `4.46.0` |

The full Toolchain test command was:

```bash
DASHBOARD_WEB_ASSETS="$PWD/build/tasks/_dashboard-web_linkWasmJs" \
  DASHBOARD_WEB_RESOURCES="$PWD/build/artifacts/PreparedComposeResourcesDirArtifact/dashboard-webcommon" \
  DASHBOARD_WEB_ENTRY="dashboard-web.mjs" \
  ./kotlin test
```

The explicit production browser command was:

```bash
DASHBOARD_WEB_ASSETS="$PWD/build/tasks/_dashboard-web_linkWasmJs" \
  DASHBOARD_WEB_RESOURCES="$PWD/build/artifacts/PreparedComposeResourcesDirArtifact/dashboard-webcommon" \
  DASHBOARD_WEB_ENTRY="dashboard-web.mjs" \
  ./kotlin test \
  --include-module dashboard-server \
  --include-classes \
  'mail.sandbox.dashboard.server.gate.KotlinToolchainBrowserGateTest'
```

The Kotlin Toolchain can compile and link Wasm test artifacts, but 0.11.1 does
not expose a Wasm test-execution task. The 20 shared-contract tests therefore
run on JVM, while `./kotlin build` proves the shared and web sources compile and
link for Wasm and the Chrome gate executes the actual linked Wasm application.
No JavaScript test runner was added.

### Alternate-stack search

From the worktree root, this final scan included the Git index and every
non-ignored untracked file:

```bash
git ls-files --cached --others --exclude-standard . \
  | rg '(^|/)(build\.gradle(\.kts)?|settings\.gradle(\.kts)?|gradlew(\.bat)?|gradle\.properties|\.npmrc|package(-lock)?\.json|yarn\.lock|pnpm-lock\.yaml)$|(^|/)gradle/wrapper(/|$)|\.(js|jsx|cjs|mjs|ts|tsx|mts|cts)$'
```

The pipeline exited 1 with no output because `rg` found no match. This
explicitly covers tracked and non-ignored untracked `.js`, `.jsx`, `.cjs`,
`.mjs`, `.ts`, `.tsx`, `.mts`, and `.cts` files, as well as Gradle and
npm/Node manifests, wrappers, and lockfiles. Ignored Toolchain-generated
`.mjs` files under `build/` are the only JavaScript-family worktree files used
by the browser bundle. Ktor also serves the hash-pinned `skiko.mjs` and
`js-joda.esm.js` resources directly from the two Maven artifacts recorded
above; neither is copied into the worktree. There is no React or TypeScript
path.

## Gate decision

| Design criterion | Result | Evidence |
| --- | --- | --- |
| Compose semantics | **PASS** | Visible heading/resource/button state plus real Chrome heading and enabled-button accessibility-tree assertions |
| Browser loading | **PASS** | Current Toolchain-linked/prepared bytes plus exactly two hash-pinned Maven runtime artifacts load under Chrome with WasmGC and no console, network, HTTP, or MIME failure |
| Ktor hosting | **PASS** | Production `module()` consumes the three explicit environment values, validates the immutable closure, serves authored history HTML, typed JSON, SSE, and every required asset |
| SSE reconnect | **PASS** | Native `EventSource` automatically resumes `1`–`4` through `Last-Event-ID`, then receives typed resync after deterministic buffer eviction; no query credentials |
| Kotlin-authored automation | **PASS** | All state, server, manifest, Ktor, and Selenium automation is Kotlin; the final JVM suites pass and the browser gate drives the actual linked Wasm bundle |

**Gate 0A: PASS. Failed criteria: none.**

All five criteria work from the reviewed Toolchain-linked/prepared output and
only the two explicitly pinned Maven runtime artifacts. No Gradle, npm, Node
build tooling, generated Node tooling, checked-in or handwritten JavaScript,
React, or TypeScript is present. Gate 0B may proceed in a later task; no Gate
0B work is included here.

## 2026-08-04 UTC: latest-stack reproof

This is an appended reproof, not a rewrite of the historical evidence above.
In particular, the earlier Kotlin `2.3.21`, Compose `1.10.3`, Material 3
`1.10.0-alpha05`, Ktor `3.4.3`, and Skiko `0.9.37.4` entries remain historical
Gate 0A evidence. They are not the dependency set proved by this entry.

The current wrapper reports Kotlin Toolchain `0.11.1`; its `dashboard-web`
settings resolve Kotlin `2.4.10`, Compose `1.11.1`, Ktor `3.5.2`, and the
managed Skiko runtime `0.144.6`. The server test configuration resolves JUnit
`6.1.2` and coroutines `1.11.0`. Material 3 is explicitly coordinated as
`org.jetbrains.compose.material3:material3*:1.11.0-alpha07`, because the
Toolchain catalog's default Material 3 coordinate lags the current Compose
runtime. No standalone Skiko `0.150.1` dependency was added; the managed
`0.144.6` runtime is the reviewed artifact. JS-Joda remains `3.2.0`.

The upstream releases checked for this reproof were Kotlin
[2.4.10](https://github.com/JetBrains/kotlin/releases/tag/v2.4.10) and Compose
Multiplatform
[1.11.1](https://github.com/JetBrains/compose-multiplatform/releases/tag/v1.11.1).
The latter's published library table identifies Material 3
`1.11.0-alpha07` for the Compose `1.11.1` release.

The two updated managed runtime bytes are pinned in both the startup
validation constants and the classpath-resource manifest:

| Served file | SHA-256 |
| --- | --- |
| `skiko.mjs` | `7fa5652ceb6343affed0360d2a8e5e35dbce1dff6192b2268c7519861af2dff4` |
| `skiko.wasm` | `46caff5f783599bd1c5d3e5e87959d7cb5102c515aac671c9280664368e71dab` |
| `js-joda.esm.js` (unchanged) | `a716a37f4c3bb47f8795688e1cd6451130a08d825d8a6df664ef72b349ec445b` |

The new `skiko.mjs` uses a JavaScript regular-expression literal containing
an escaped slash-star sequence. The module-reference scanner now tokenizes
regex literals as code rather than mistaking that sequence for a block
comment; focused negative tests still reject executable imports after it. The
new generated Kotlin I/O Node-only ternaries are accepted only for their exact
predicate, loader shape, and four reviewed specifiers (`node:buffer`,
`node:os`, `node:path`, and `node:fs`). The exact shorthand Skiko dead loader
is likewise accepted only under `if (false)`.

Compose `1.11.1` moved the dashboard ShadowRoot below its two light-DOM
wrappers. The browser gate now accepts only the observed topology:

```text
#dashboard-root > div[position:relative] >
  div[position:relative].shadowRoot
  div[position:absolute; top:0; left:0]
```

It does not fall back to the historical root-level ShadowRoot. The strict
focused suite rejects reordered, additional, missing, wrongly styled, and
shadowless containers; an empty root is retried only while the app is mounting.
The contract is consistent with the upstream Compose change in
[PR #2710](https://github.com/JetBrains/compose-multiplatform-core/pull/2710/files).
After Tab, the gate requires the nested shadow-host `div` as document active
element, its focused `canvas` as the deep active element, and the original
`main#dashboard-root` to retain the solid 3 px `:focus-within` outline. The
semantic focus text and Enter activation assertions remain unchanged.

Final commands were run from `debug-dashboard/`:

| Command | Result |
| --- | --- |
| `./kotlin build --module dashboard-web` | PASS; Wasm linked |
| `./kotlin test --include-module dashboard-server --include-classes 'mail.sandbox.dashboard.server.web.WebAssetBundleTest'` | PASS; 21/21 |
| `./kotlin test --include-module dashboard-server --include-classes 'mail.sandbox.dashboard.server.web.*'` | PASS; 25/25 |
| `./kotlin test --include-module dashboard-server --include-classes 'mail.sandbox.dashboard.server.gate.BrowserHostResolverTest'` | PASS; 6/6 |
| production browser command below | PASS; 1/1 |

```bash
DASHBOARD_WEB_ASSETS="$PWD/build/tasks/_dashboard-web_linkWasmJs" \
  DASHBOARD_WEB_RESOURCES="$PWD/build/artifacts/PreparedComposeResourcesDirArtifact/dashboard-webcommon" \
  DASHBOARD_WEB_ENTRY="dashboard-web.mjs" \
  ./kotlin test --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.gate.KotlinToolchainBrowserGateTest'
```

The passing browser result reported Google Chrome `150.0.7871.187` and
ChromeDriver `150.0.7871.124`
(`9261fd0a595ac4964ea84e6bd4a025c1173a2ffa-refs/branch-heads/7871@{#3359}`).
It passed the unchanged canvas, semantics, history, HTTP/SSE transport,
console/network, keyboard, and accessibility assertions.

**Gate 0A latest-stack reproof: PASS. No stop condition remains.**
