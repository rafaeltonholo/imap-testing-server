# Browser ambient-global bootstrap design

## Purpose

The generated Wasm module graph contains reviewed Node- and Deno-only dynamic
imports that must remain dead in the supported browser runtime. Static scanning
continues to reject local and lexical environment-object substitutions, but it
cannot prove that arbitrary JavaScript in the graph will never synthesize an
ambient `process` or `Deno` property through aliases, computed names, or dynamic
evaluation.

The browser must therefore establish ambient-global integrity before evaluating
any module in the graph.

## Architecture

An authored classic script, `/assets/browser-bootstrap.js`, is served as a
classpath asset whose bytes are checked against a repository-pinned SHA-256
before the server starts. The configured entry is restricted before HTML
rendering to one ASCII-safe `.mjs` basename; its rendered value is therefore the
strict same-origin path `/assets/<ASCII-safe-basename>.mjs`, with no query,
fragment, slash, traversal segment, or markup character. The authored HTML
contains, in this order:

1. the single reviewed import map;
2. one parser-blocking classic external bootstrap tag carrying the validated
   entry asset in `data-dashboard-entry`, with the exact reviewed `src` and no
   `async`, `defer`, `type`, inline body, event handler, or extra attribute;
3. no unconditional module script.

The bootstrap synchronously captures
`document.currentScript.dataset.dashboardEntry` while the parser-blocking script
is current. It validates that exact same-origin path, defines own `process` and
`Deno` properties on `globalThis` with values of `undefined` and with writable,
enumerable, and configurable all false, and then independently re-reads and
verifies both descriptors. Configurable preseeds are replaced; already-safe
descriptors are accepted. Only after both seals and both verifications succeed
does the sole launcher call `import(entry)` exactly once. Import rejection is
surfaced and cannot trigger a fallback or second launch.

If a hostile or incompatible environment has already installed a
non-configurable unsafe property, defining or verifying the property fails and
the module graph is never launched. Configurable properties are safely replaced.

## Scanner boundary

The bootstrap asset is not passed through the module-reference scanner because
its non-literal launcher is already authorized by its exact pinned bytes.
Every generated module remains scanned normally.

At `Loader.resolveReference`, Kotlin IO loader acceptance is additionally bound
to the exact normalized source filename `dashboard-web.import-object.mjs` and
filesystem origin, one unique root `const js_code = { ... }` container, and one
atomic, ordered, adjacent group of the exact buffer, OS, path, and filesystem
loader properties. The proof marks only the four import token indices in that
group. Copies under another filename, subsets, duplicates, reordering, gaps,
second groups, nested groups, and extra KIO imports are rejected. Existing exact
eager-initializer and deferred-property checks remain as defense in depth.

Lexical and local `process`/`Deno` substitutions remain rejected across direct,
imported, parameter, destructuring, rest, loop, generator, reassignment, and
other binding forms. Escaped identifier spellings such as `pr\u006fcess` and
`D\u0065no` remain tokenizer errors rather than alternate bindings.

## Failure behavior

- A missing, duplicated, reordered, inline, or module bootstrap tag makes bundle
  startup fail.
- A bootstrap byte or pinned-hash mismatch makes bundle startup fail.
- An invalid entry attribute, an unsafe non-configurable `process` or `Deno`, or
  a failure while sealing or verifying either descriptor makes the bootstrap
  throw after zero import calls. A second-descriptor failure cannot launch after
  the first descriptor was sealed.
- A changed KIO filename, property order, adjacency, multiplicity, or container
  makes the corresponding dynamic import unreviewed and bundle startup fail.

## Verification

Unit tests prove the exact HTML ordering and tag contract (including missing,
duplicated, reordered, tampered, or module-tag launchers), pinned bootstrap
bytes, and fail-closed bootstrap control flow. Bootstrap harness cases cover
unsafe non-configurable properties independently, configurable preseeds,
already-safe properties, a second-descriptor verification failure, zero launch
on every failure, exactly one launch on success, and import rejection without a
retry. Scanner tests cover every KIO identity/group mutation above and the full
lexical/escaped-binding inventory.

The production Chrome gate proves that both descriptors are sealed before the
Compose application runs; strict assignment, deletion, and redefinition fail;
and caught computed-concatenation, template, `Object.defineProperty`,
destructuring, `Object.assign`, and `Reflect.set` probes leave the descriptors
unchanged and issue no Node requests. The dashboard must still render and all
browser/network observations remain clean.

This is intentionally a browser-only launch contract. Node, Deno, browser
polyfills that require ambient `process`/`Deno`, and environments with unsafe
non-configurable preseeds fail closed and are not supported dashboard targets.
