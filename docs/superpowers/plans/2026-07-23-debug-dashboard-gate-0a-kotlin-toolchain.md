# Debug Dashboard Gate 0A — Kotlin Toolchain Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove that the installed Kotlin Toolchain can build and test the required Compose/Wasm SPA and Ktor/JVM host without Gradle, npm, generated Node tooling, React, or TypeScript.

**Architecture:** Initialize the project from the official Ktor template, retain one root wrapper, and reshape it into the approved three-module graph. Serve the Toolchain linker output and any empirically required, version-pinned Maven runtime resources through one validated Ktor asset manifest; do not add npm, Node tooling, or checked-in JavaScript to compensate for Toolchain preview gaps. A minimal Compose shell exercises browser history, same-origin JSON, reconnectable SSE, and real keyboard/focus semantics in headless Chrome before any mail feature exists.

**Tech Stack:** Kotlin Toolchain 0.11.1, Kotlin 2.3.x, Compose Multiplatform, Ktor, kotlinx.serialization, Selenium Java 4.46.0, Chrome with WasmGC.

---

## Task 1: Scaffold the exact Toolchain project

**Files:**

- Create: `debug-dashboard/kotlin`
- Create: `debug-dashboard/kotlin.bat`
- Create: `debug-dashboard/project.yaml`
- Create: `debug-dashboard/.gitignore`
- Create: `debug-dashboard/dashboard-contract/module.yaml`
- Create: `debug-dashboard/dashboard-server/module.yaml`
- Create: `debug-dashboard/dashboard-server/resources/application.yaml`
- Create: `debug-dashboard/dashboard-server/resources/logback.xml`
- Create: `debug-dashboard/dashboard-web/module.yaml`
- Create: `docs/debug-dashboard/gates/0a-kotlin-toolchain.md`

- [ ] The globally installed command and the current `https://kotl.in/install.sh` payload were both observed at `0.11.0`, while the reviewed release is `0.11.1`. Do not overwrite the global install or pretend the convenience installer supplies 0.11.1. Fetch the official versioned wrapper into a disposable directory, verify its wrapper checksum, and let its embedded distribution checksum verify the downloaded Toolchain:

```bash
gate_cli_dir="$(mktemp -d)"
curl --proto '=https' --tlsv1.2 -fsSL \
  https://packages.jetbrains.team/maven/p/amper/amper/org/jetbrains/kotlin/kotlin-cli/0.11.1/kotlin-cli-0.11.1-wrapper \
  -o "$gate_cli_dir/kotlin"
echo "6dbcdde0bcae41705c187aefb6c91c6c29ef9079c8072a473c2149151f8d7962  $gate_cli_dir/kotlin" \
  | shasum -a 256 --check
chmod 0700 "$gate_cli_dir/kotlin"
"$gate_cli_dir/kotlin" --version
```

Expected: `Kotlin Toolchain version 0.11.1 (801e9d4, 2026-06-05)`. If the version differs, stop and review the release rather than generating with an unreviewed version.

- [ ] From the worktree root, run the official initializer:

```bash
"$gate_cli_dir/kotlin" init ktor-server --target-dir debug-dashboard
./debug-dashboard/kotlin --version
```

Expected: Toolchain reports a successfully generated project and creates version-0.11.1 `kotlin`/`kotlin.bat` wrappers, `module.yaml`, `src/`, and `resources/`; the project-local version command prints the same 0.11.1 build. Delete the disposable CLI directory after this proof. Record both wrapper checksum/version checks in the gate report.

- [ ] Move the generated Ktor module content under `dashboard-server/`, then write `project.yaml` with exactly:

```yaml
modules:
  - dashboard-contract
  - dashboard-server
  - dashboard-web
```

- [ ] Configure `dashboard-contract` as `kmp/lib` for `[jvm, wasmJs]` with Kotlin JSON serialization; configure `dashboard-server` as `jvm/app` with Ktor enabled and a dependency on `../dashboard-contract`; configure `dashboard-web` as `wasm-js/app` with Compose enabled, `settings.compose.resources.packageName: mail.sandbox.dashboard.web.generated.resources`, and dependencies on `../dashboard-contract`, `$compose.foundation`, `$compose.material3`, and the Ktor client JSON/SSE requirements.

The 0.11.1 CLI/schema product spelling is `wasm-js/app`; the shared KMP platform spelling is `wasmJs`. A disposable 0.11.1 schema/build probe accepted and linked `wasm-js/app`, while rejecting `wasmJs/app` as a product. Re-prove the checked-in model through `./kotlin show modules` and a real build; do not substitute Gradle.

- [ ] Run `./kotlin show settings`, compare the effective Kotlin/Compose/Ktor versions with the reviewed baseline in the index plan, then pin the observed 0.11.1-compatible values in YAML. Add `org.seleniumhq.selenium:selenium-java:4.46.0` only to the server's `test-dependencies`.

- [ ] Ignore only generated/local state in `debug-dashboard/.gitignore`:

```gitignore
/build/
/.runtime/
```

- [ ] Validate the model:

```bash
cd debug-dashboard
./kotlin show modules
./kotlin show settings
./kotlin show dependencies
```

Expected: three modules; `dashboard-contract` resolves JVM and Wasm; the server resolves JVM only; the web app resolves Wasm only. Save the effective version excerpt in `docs/debug-dashboard/gates/0a-kotlin-toolchain.md`.

- [ ] Prove there is no alternate build stack:

```bash
git ls-files . | rg '(^|/)(build\.gradle(\.kts)?|settings\.gradle(\.kts)?|package(-lock)?\.json|yarn\.lock|pnpm-lock\.yaml)$|\.(js|mjs|ts|tsx)$'
```

Expected: no output. Ignored Toolchain linker `.mjs` output is allowed; tracked handwritten or generated JavaScript is not.

- [ ] Commit:

```bash
git add debug-dashboard docs/debug-dashboard/gates/0a-kotlin-toolchain.md
git commit -m "build: scaffold Kotlin Toolchain dashboard"
```

## Task 2: Define the smallest shared browser/server contract

**Files:**

- Create: `debug-dashboard/dashboard-contract/src/mail/sandbox/dashboard/contract/BootstrapContract.kt`
- Create: `debug-dashboard/dashboard-contract/src/mail/sandbox/dashboard/contract/EventContract.kt`
- Create: `debug-dashboard/dashboard-contract/src/mail/sandbox/dashboard/contract/Routes.kt`
- Create: `debug-dashboard/dashboard-contract/test/mail/sandbox/dashboard/contract/ContractSerializationTest.kt`

- [ ] Write a failing serialization test for:

```kotlin
@Serializable
data class GateProbe(val message: String, val sequence: Long)

@Serializable
data class GateEvent(val id: Long, val kind: String, val payload: GateProbe)
```

The test must assert the exact JSON field names and a round trip; route constants must include `/api/v1/gate/probe` and `/api/v1/gate/events`.

- [ ] Run:

```bash
./kotlin test --include-module dashboard-contract
```

Expected before implementation: unresolved contract types. Expected after implementation: pass on both `jvm` and `wasmJs`.

- [ ] Implement only these DTOs and route constants, rerun the module test, then commit:

```bash
git add debug-dashboard/dashboard-contract
git commit -m "test: establish shared dashboard gate contract"
```

## Task 3: Build and validate the Compose/Wasm artifact

**Files:**

- Create: `debug-dashboard/dashboard-web/src/mail/sandbox/dashboard/web/Main.kt`
- Create: `debug-dashboard/dashboard-web/src/mail/sandbox/dashboard/web/GateApp.kt`
- Create: `debug-dashboard/dashboard-web/src/mail/sandbox/dashboard/web/GateState.kt`
- Create: `debug-dashboard/dashboard-web/composeResources/files/gate-proof.txt`
- Create: `debug-dashboard/dashboard-web/test/mail/sandbox/dashboard/web/GateStateTest.kt`

- [ ] Write a failing reducer test covering route selection, API probe state, SSE sequence/resync state, and activation count for the keyboard button.

- [ ] Implement a minimal `GateState` reducer and rerun:

```bash
./kotlin test --include-module dashboard-web
```

Expected: reducer tests pass. If Toolchain cannot execute Wasm tests in the installed environment, move only the pure reducer to `dashboard-contract`; do not introduce a JavaScript test runner.

- [ ] Add `gate-proof.txt` through the Toolchain's module-root `composeResources` convention and load it through the generated `Res` API. Render its deterministic marker in the gate UI. This makes the gate exercise Compose runtime-resource packaging rather than proving code files alone.

- [ ] Implement `main()` with `ComposeViewport(document.body!!)` and an explicit `@OptIn(ExperimentalComposeUiApi::class)`. The rendered gate UI must contain:

  - a visible `h1`-equivalent semantic heading;
  - an actual focusable control labeled `Increment proof`;
  - a route link/control to `/gate/details`;
  - live text for JSON API status;
  - live text for SSE sequence and reconnect status.

- [ ] Build with:

```bash
./kotlin build --module dashboard-web
```

Expected: successful linkage with at least one `.wasm` and one entry `.mjs`. Walk the complete static/dynamic import and `new URL(..., import.meta.url)` graph and classify every referenced companion as linker-emitted, separately prepared by Toolchain, supplied by a version-pinned Maven runtime artifact, or unresolved. Record whether the gate resource is embedded in Wasm or emitted separately and, if separate, its path/MIME. Missing companions are a Gate 0A finding: do not hide them by copying generated JavaScript into source control or introducing npm/Node tooling. A disposable 0.11.1 string-resource probe embedded the value and still rendered it through generated accessors; later file/font/image builds must be observed independently.

The frozen 0.11.1 result is known: the linker emits the four application files below, while `dashboard-web.import-object.mjs` imports an unstaged `./skiko.mjs` and bare `@js-joda/core`; Skiko in turn requires `skiko.wasm`; and `gate-proof.txt` exists only in the prepared Compose-resource artifact. Task 4 must validate the recovery for these exact findings rather than treating missing companions as hypothetical. For reference, the code-only 0.11.0 probe emitted:

```text
build/tasks/_dashboard-web_linkWasmJs/dashboard-web.wasm
build/tasks/_dashboard-web_linkWasmJs/dashboard-web.mjs
build/tasks/_dashboard-web_linkWasmJs/dashboard-web.import-object.mjs
build/tasks/_dashboard-web_linkWasmJs/dashboard-web.js-builtins.mjs
```

Do not turn that reference directory into production logic: the Toolchain documents the task output location as unstable. Observe and record the exact 0.11.1 asset directory and basenames after the first build. If 0.11.1 omits runtime companions that are already resolved as Maven artifacts, Task 4 may test one Kotlin-only recovery: Ktor can expose those exact, pinned classpath resources alongside the linker files. The gate still passes only if Task 5 proves that combined manifest in a real browser.

Run one explicit `./kotlin build --module dashboard-web --variant release` probe and record whether Toolchain 0.11.1 still reports that Wasm ignores variants. If it does, do not pretend a separate release variant exists: for this local product, the linked files plus the validated runtime-resource manifest are the deployable bundle candidate. Gate evidence must prove that bundle runs without a dev server or hot-reload process.

- [ ] Add filenames, byte sizes, and SHA-256 hashes to the gate report. Commit:

```bash
git add debug-dashboard/dashboard-web docs/debug-dashboard/gates/0a-kotlin-toolchain.md
git commit -m "feat: link minimal Compose Wasm dashboard"
```

## Task 4: Serve authored HTML and linked assets from Ktor

**Files:**

- Create: `debug-dashboard/dashboard-server/resources/web/index.html`
- Modify: `debug-dashboard/dashboard-server/module.yaml`
- Modify: `debug-dashboard/dashboard-web/src/mail/sandbox/dashboard/web/Main.kt`
- Replace: `debug-dashboard/dashboard-server/src/Application.kt`
- Replace: `debug-dashboard/dashboard-server/src/Routing.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/web/WebAssetBundle.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/web/WebRoutes.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/gate/GateRoutes.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/web/WebAssetBundleTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/web/WebRoutesTest.kt`

- [ ] Write failing tests that require `WebAssetBundle` to:

  - accept one configured, canonical linker directory and one configured, canonical prepared-Compose-resource directory;
  - accept one explicitly configured entry `.mjs`;
  - recursively resolve the entry's complete relative static `import`, literal dynamic `import(...)`, `export from`, and `new URL(..., import.meta.url)` closure;
  - resolve relative runtime companions missing from the linker directory only from an explicit, version-pinned classpath-resource allowlist; for the observed 0.11.1 graph, pin JAR-root `skiko.mjs` (SHA-256 `5dc3302763d61014d4a3277727f6e1af041741ae1f0efcc2acc21f2924cad99e`) and JAR-root `skiko.wasm` (SHA-256 `69afd1fba0567fc79515d97bac5c0670cfeb180284823f986199637f154a9bbe`) from `org.jetbrains.skiko:skiko-js-wasm-runtime:0.9.37.4`;
  - resolve the observed bare `@js-joda/core` import only through an authored import-map entry targeting `js-joda.esm.js` from `org.webjars.npm:js-joda__core:3.2.0`; the exact classpath resource is `META-INF/resources/webjars/js-joda__core/3.2.0/dist/js-joda.esm.js` with SHA-256 `a716a37f4c3bb47f8795688e1cd6451130a08d825d8a6df664ef72b349ec445b`; reject any unreviewed bare specifier;
  - require every referenced `.mjs` and `.wasm` asset, including both the application and Skiko Wasm binaries, without assuming a fixed application-companion count or basename;
  - recursively enumerate every additional regular file beneath the prepared Compose resource root into an immutable `/assets/composeResources/<generated-package>/...` manifest; assert the observed `files/gate-proof.txt` bytes have SHA-256 `7b0f843ebd49d2709bcd8e3d1021db98e68413823647895d8377a6657f5e6960`;
  - recognize the fixed Kotlin/Skiko non-browser dynamic imports only in their reviewed, environment-dead generated branches; fail on a new generated loader shape rather than broadly allowing `node:`, network, or arbitrary bare imports;
  - reject unreviewed absolute/network/bare imports, traversal, symlinks, missing references, duplicate normalized paths, and filesystem paths outside the configured project;
  - map `.wasm`, `.mjs`, `.js`, CSS, JSON/text, SVG/raster images, and WOFF/WOFF2/TTF/OTF fonts to explicit safe MIME types; both `.mjs` and `.js` use `text/javascript`, and an observed runtime extension without a reviewed mapping fails startup instead of being silently omitted.

- [ ] Add the two observed runtime artifacts as ordinary Maven dependencies in `dashboard-server/module.yaml`, resolved by the Kotlin Toolchain. Do not unpack them into tracked files. Configure Compose web resource URLs in `Main.kt` with `configureWebResources { resourcePathMapping { "/assets/$it" } }`, before creating the viewport, so history routes do not turn the generated path into `/gate/composeResources/...`. Implement the validator without guessing from request input. Startup requires `DASHBOARD_WEB_ASSETS` to supply the observed canonical linker-output directory, `DASHBOARD_WEB_RESOURCES` to supply the observed canonical prepared-resource directory, and `DASHBOARD_WEB_ENTRY` to supply the observed entry basename; it fails closed if any is absent or invalid. The server exposes only files in the validated filesystem/classpath closure plus runtime-resource manifest and verifies the pinned hashes above at startup. Do not hardcode a private `build/tasks/_...` or `build/artifacts/_...` path, the four-file 0.11.0 probe shape, or a developer cache path into production Kotlin.

- [ ] Write failing Ktor tests for:

  - `/` and `/gate/details` returning the authored `index.html`;
  - `/assets/<observed-entry-basename>.mjs`, every linker/classpath code asset in its closure, both Wasm binaries, the imported JS-Joda module specifically returning `text/javascript`, and nested text/image/font fixture resources returning correct content types;
  - `/api/v1/gate/probe` returning `GateProbe`;
  - an unknown `/api/v1/...` returning typed 404 JSON rather than SPA HTML;
  - cache policy: HTML `no-store`, fingerprint-ready assets cacheable.

- [ ] Author `index.html` directly after observing the pinned link output. It must include UTF-8/viewport metadata, a named mount target, full-page/focus-visible CSS, a noscript message, one narrow import map from `@js-joda/core` to `/assets/js-joda.esm.js`, and exactly one `<script type="module" src="/assets/<observed-entry-basename>.mjs"></script>`; it must not contain generated framework bootstrap code or any other dependency mapping.

- [ ] Implement routes and run:

```bash
./kotlin test --include-module dashboard-server --include-classes 'mail.sandbox.dashboard.server.web.*'
./kotlin test --include-module dashboard-server
```

Expected: all pass.

- [ ] Commit:

```bash
git add debug-dashboard/dashboard-server \
  debug-dashboard/dashboard-web/src/mail/sandbox/dashboard/web/Main.kt
git commit -m "feat: serve Toolchain Wasm assets from Ktor"
```

## Task 5: Prove browser history, API, SSE reconnect, and semantics

**Files:**

- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/gate/GateEventSource.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/GateEventSourceTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/KotlinToolchainBrowserGateTest.kt`
- Modify: `debug-dashboard/dashboard-web/src/mail/sandbox/dashboard/web/GateApp.kt`
- Modify: `debug-dashboard/dashboard-web/src/mail/sandbox/dashboard/web/GateState.kt`

- [ ] Write a failing server test for a bounded event source with this deterministic browser sequence: the first connection emits IDs `1`, `2` and closes; the automatic reconnect presents `Last-Event-ID: 2`, receives `3`, `4`, and closes; the source then appends `5`, `6` into its two-event buffer, evicting `3`, `4` before the next automatic reconnect; the next `Last-Event-ID: 4` is therefore outside the buffer and emits a typed `resync` event. Tests must prove the monotonic resume and stale-cursor branches without attempting to set `Last-Event-ID` from browser JavaScript.

- [ ] Implement the minimal Ktor SSE endpoint and browser `EventSource` client. Browser credentials remain same-origin; no session value appears in the event URL.

- [ ] Write `KotlinToolchainBrowserGateTest` in Kotlin/JVM using Selenium. It must start a real loopback Ktor server on an ephemeral port and drive an installed stable Chrome/Chromium with WasmGC. Assert:

  1. the Compose heading becomes visible;
  2. the marker loaded through Compose `Res` becomes visible;
  3. no browser console error, failed resource request, or incorrect response MIME occurs;
  4. the API status renders the expected message;
  5. pushing `/gate/details`, reloading, and browser Back preserve correct route state;
  6. SSE reconnect advances monotonically and exposes the resync state when forced stale;
  7. Tab reaches `Increment proof`, Enter activates it, and focus remains visibly detectable;
  8. the browser accessibility tree exposes the control's accessible name and enabled state.

- [ ] Run the actual production-style sequence:

```bash
./kotlin build
DASHBOARD_WEB_ASSETS="<observed-absolute-0.11.1-linker-directory>" \
  DASHBOARD_WEB_RESOURCES="<observed-absolute-0.11.1-prepared-resource-directory>" \
  DASHBOARD_WEB_ENTRY="<observed-entry-basename>.mjs" \
  ./kotlin test \
  --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.gate.KotlinToolchainBrowserGateTest'
```

The test must start Ktor through the same production configuration loader and consume all three environment values; it may not inject a test-only asset bundle or infer the entry file. Expected: pass in a current WasmGC browser using only Toolchain-linked/prepared output plus the two explicitly pinned Toolchain-resolved Maven runtime artifacts. Record browser and driver versions in the gate report.

- [ ] Run the complete Toolchain suite and inspect the dependency/task graph:

```bash
DASHBOARD_WEB_ASSETS="<observed-absolute-0.11.1-linker-directory>" \
  DASHBOARD_WEB_RESOURCES="<observed-absolute-0.11.1-prepared-resource-directory>" \
  DASHBOARD_WEB_ENTRY="<observed-entry-basename>.mjs" \
  ./kotlin test
./kotlin show tasks
./kotlin show dependencies
```

Expected: pass; no npm/Node build task or Gradle task.

## Task 6: Decide Gate 0A and freeze the proof

**Files:**

- Modify: `docs/debug-dashboard/gates/0a-kotlin-toolchain.md`

- [ ] Complete the report with:

  - wrapper checksum and Toolchain/Kotlin/Compose/Ktor versions;
  - exact build/test commands and exit status;
  - artifact names, sizes, and hashes;
  - browser/driver version and WasmGC result;
  - history/API/SSE/keyboard/accessibility observations;
  - output of the alternate-build-stack search, including tracked `.js`, `.mjs`, `.ts`, and `.tsx`;
  - `PASS` or `STOP`, with every failed criterion listed.

- [ ] Gate decision:

  - **PASS:** all five design criteria work from the validated Toolchain-linked/prepared output and only the two explicitly pinned Maven runtime artifacts above, with Kotlin/JVM browser tests. No npm, Node build tool, checked-in/handwritten JavaScript, or Gradle path is present; ignored `.mjs` emitted by the reviewed Toolchain linker is permitted.
  - **STOP:** Compose semantics, browser loading, Ktor hosting, SSE reconnect, or Kotlin-authored automation cannot be made reliable without Gradle, npm, generated Node tooling, React, or TypeScript.

Do not begin Gate 0B on `STOP`.

- [ ] On `PASS`, commit:

```bash
git add docs/debug-dashboard/gates/0a-kotlin-toolchain.md debug-dashboard
git commit -m "test: prove Kotlin Toolchain browser gate"
```
