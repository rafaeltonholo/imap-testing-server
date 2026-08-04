# Browser Ambient-Global Bootstrap Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Seal browser `process` and `Deno` globals before the generated module graph launches, while narrowing Kotlin IO loader acceptance to its exact generated source and atomic four-loader group.

**Architecture:** Serve an authored, SHA-256-pinned classic bootstrap as the sole application launcher after the import map. The bootstrap synchronously captures its validated entry attribute, seals and verifies both ambient descriptors, and imports exactly once only on success. Keep static lexical-shadow scanning, and bind Kotlin IO dead-import review to the exact filesystem module, unique root container, and exact ordered loader group.

**Tech Stack:** Kotlin/JVM, Kotlin Toolchain CLI, JavaScript, Node `vm`, Ktor test host, Selenium/Chrome, SHA-256.

---

### Task 1: Bootstrap runtime contract in RED

**Files:**
- Create: `debug-dashboard/dashboard-server/testResources/web/browser-bootstrap-harness.mjs`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/web/BrowserBootstrapTest.kt`
- Test: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/web/WebRoutesTest.kt`

- [x] **Step 1: Write the failing bootstrap harness tests**

Use Node 24 with `--experimental-vm-modules` and `vm.runInContext()` to execute the exact authored bootstrap bytes with a controlled `document.currentScript.dataset.dashboardEntry` and `importModuleDynamically` spy. Await the completion promise returned by `vm.runInContext()` in every case. On success, make the callback return the valid namespace from a real `data:` module import; on rejection, throw from the callback and await/assert that rejection. Cover safe-empty globals, configurable fake preseeds, already-safe descriptors, unsafe non-configurable `process`, unsafe non-configurable `Deno`, a sabotaged second descriptor verification, invalid entry spellings, and import rejection. Assert zero imports for every setup/verification failure, exactly one for success/rejection, and no retry after all asynchronous completion settles.

- [x] **Step 2: Write failing HTML contract tests**

Require import-map-before-bootstrap order, one exact parser-blocking external tag, zero module tags, and rejection of duplicate, reordered, inline, `type`, `async`, `defer`, event-handler, extra-attribute, or changed-source launchers.

- [x] **Step 3: Run focused tests and capture RED**

Run:

```bash
./kotlin test --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.web.*'
```

Expected: new bootstrap resource/contract tests fail because the asset and launcher do not exist.

### Task 2: Pinned bootstrap and sole-launcher HTML

**Files:**
- Create: `debug-dashboard/dashboard-server/resources/web/browser-bootstrap.js`
- Modify: `debug-dashboard/dashboard-server/resources/web/index.html`
- Modify: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/web/WebAssetBundle.kt`
- Modify: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/web/WebAssetBundleTest.kt`
- Modify: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/web/WebRoutesTest.kt`

- [x] **Step 1: Implement the bootstrap algorithm**

Capture `document.currentScript` and its dataset synchronously; require `^/assets/[A-Za-z0-9][A-Za-z0-9._-]*\.mjs$`; seal `process` and `Deno` as own undefined, non-writable, non-enumerable, non-configurable data properties; re-read and verify both; then return the single `import(entry)` promise.

- [x] **Step 2: Pin and serve the bootstrap**

Add `browser-bootstrap.js` to `productionWebRuntimeResources()` with its exact SHA-256 and a distinct `ClasspathBootstrap` origin. Add it explicitly during bundle load, reject filesystem shadowing/duplicates/hash changes, include it in required-runtime validation, and exclude only that exact pinned origin from module-reference scanning.

- [x] **Step 3: Tighten the entry and HTML contract**

Restrict `entryFileName` to the ASCII-safe basename grammar. Replace the unconditional module tag with exactly:

```html
<script src="/assets/browser-bootstrap.js" data-dashboard-entry="{{DASHBOARD_WEB_ENTRY}}"></script>
```

Pin the complete authored index bytes before token substitution. Validate one
import map followed by that exact tag, two scripts total, and zero module
scripts as defense in depth.

- [x] **Step 4: Run bootstrap and safe web tests GREEN**

Run the Task 1 command. Expected: all `mail.sandbox.dashboard.server.web.*` tests pass.

### Task 3: KIO source identity and atomic group

**Files:**
- Modify: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/web/WebAssetBundle.kt`
- Modify: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/web/WebAssetBundleTest.kt`

- [x] **Step 1: Add failing identity/group tests**

Use `dashboard-web.import-object.mjs` for the valid fixture. Add copied filename, classpath origin, subset, duplicate, reorder, gap, second group, nested group, extra KIO import, wrong key/specifier, and escaped/local binding cases. Assert each formerly reviewed dynamic import is rejected.

- [x] **Step 2: Pass source identity into scanner references**

Construct the scanner with `fromPublicName`. Preserve a one-argument test constructor. Carry enough reviewed context for `resolveReference()` to require exact normalized source name and `AssetOrigin.Filesystem`.

- [x] **Step 3: Prove one atomic group**

Flatten the four exact full property shapes in buffer/OS/path/filesystem order. Require one direct match under the unique root `js_code`, and authorize only the four exact dynamic-import token indices in that match. Keep the exact eager/deferred container validator and local/escaped-binding rejection.

- [x] **Step 4: Run focused scanner tests GREEN**

Run:

```bash
./kotlin test --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.web.WebAssetBundleTest'
```

Expected: every scanner test passes.

### Task 4: Production browser integrity proof

**Files:**
- Modify: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/KotlinToolchainBrowserGateTest.kt`

- [x] **Step 1: Add descriptor and mutation assertions**

Before checking Compose output, assert exact descriptors for `process` and `Deno`. In strict JavaScript, catch and assert failures for direct/computed concatenation, template, defineProperty, destructuring, Object.assign, Reflect.set, deletion, and redefinition probes; re-read unchanged descriptors.

- [x] **Step 2: Prove configurable preseeds are replaced**

In a fresh isolated Chrome driver/context with network capture installed before navigation, install a new-document script that creates configurable fake values before the authored bootstrap. Assert the bootstrap replaces them, launches once, and the dashboard still renders. Do not reuse this driver for baseline or unsafe cases because preload scripts persist and sealed globals cannot be cleaned up.

- [x] **Step 3: Prove unsafe preseeds launch nothing**

Use a separate fresh Chrome driver/context for baseline, configurable preseeds, unsafe non-configurable `process`, and unsafe non-configurable `Deno`. Install network capture before every navigation. Assert no entry/module request, no Compose root, and the expected bootstrap failure in each unsafe run. The Deno run is also the second-descriptor case where `process` was sealed first.

- [x] **Step 4: Run the production browser gate**

Run the existing production-style `KotlinToolchainBrowserGateTest` command/environment. Expected: all browser integrity and dashboard assertions pass with clean network observations.

### Task 5: Fresh evidence, documentation, and review

**Files:**
- Modify: `docs/debug-dashboard/gates/0a-kotlin-toolchain.md`

- [x] **Step 1: Rebuild and verify closure**

Run:

```bash
./kotlin build --module=dashboard-web
find build/tasks/_dashboard-web_linkWasmJs -maxdepth 1 -type f -print | sort
```

Expected: successful build and the same exact four linker artifacts.

- [x] **Step 2: Run fresh safe test evidence**

Run focused scanner tests, `mail.sandbox.dashboard.server.web.*`, and the production browser gate. Record exact counts, versions, and elapsed browser time.

- [x] **Step 3: Update gate documentation**

Document the browser-only compatibility contract, bootstrap hash/ordering/descriptor behavior, KIO identity/group proof, RED/GREEN cases, safe test counts, unchanged closure, and Chrome evidence.

- [x] **Step 4: Request independent code review**

Ask the independent reviewer to probe bootstrap fail-open ordering, tag/asset tampering, copied/partial KIO groups, escaped bindings, and runtime mutation families. Fix concrete findings and rerun affected tests.

- [x] **Step 5: Execute repository self-review**

Run every check in `.ai/self-review.md`, including `git diff --check`, status/diff inspection, scope audit, and fresh evidence validation. Do not access normal Stalwart.

- [x] **Step 6: Commit only after review and evidence**

Stage the implementation/tests/docs and create a new commit without amending prior commits.
