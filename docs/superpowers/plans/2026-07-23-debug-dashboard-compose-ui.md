# Debug Dashboard Compose/Wasm UI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver every dashboard workflow through the approved Flight-Recorder Workbench UI, centered on the responsive and keyboard-complete Evidence Split workspace.

**Architecture:** The Wasm client owns only view state, navigation, in-memory CSRF, API DTOs, and event reconciliation. Provider secrets and privileged behavior stay server-side. Pure reducers are tested without a browser; Kotlin/JVM Selenium tests drive the linked Compose artifact for routing, workflows, accessibility, and responsive structure.

**Tech Stack:** Kotlin Toolchain, Compose Multiplatform/Wasm, Ktor client, kotlinx.serialization, browser DOM APIs, Selenium/JVM, Compose resources.

---

## Execution prerequisite

Do not execute this plan until the revised Gate 0B and every affected provider/Message Lab plan pass independent review. If the approved credential strategy changes readiness, setup, recovery, rotation, or deletion UX, revise those surfaces and their browser tests here before implementation; credentials must remain server-side.

## Task 1: Replace the gate shell with production session/API/event clients

**Files:**

- Create: `debug-dashboard/dashboard-web/src/mail/sandbox/dashboard/web/session/SessionBootstrapClient.kt`
- Create: `debug-dashboard/dashboard-web/src/mail/sandbox/dashboard/web/session/SessionCsrfClient.kt`
- Create: `debug-dashboard/dashboard-web/src/mail/sandbox/dashboard/web/api/DashboardApiClient.kt`
- Create: `debug-dashboard/dashboard-web/src/mail/sandbox/dashboard/web/event/DashboardEventClient.kt`
- Create: `debug-dashboard/dashboard-web/src/mail/sandbox/dashboard/web/state/DashboardState.kt`
- Create: `debug-dashboard/dashboard-web/src/mail/sandbox/dashboard/web/state/DashboardStore.kt`
- Create: `debug-dashboard/dashboard-web/test/mail/sandbox/dashboard/web/state/DashboardStoreTest.kt`
- Modify: `debug-dashboard/dashboard-web/src/mail/sandbox/dashboard/web/Main.kt`

- [ ] Write failing pure reducer tests for fragment bootstrap, cookie-session CSRF reacquisition after reload, bootstrap/session expiry, readiness, selected account/provider, independent provider workspace state, route restoration, event monotonicity, gap/resync refresh, operation updates, and safe error display.

- [ ] Implement session startup as:

  1. when `location.hash` contains the startup secret, POST it in the bootstrap body to the exact origin, immediately call `history.replaceState` to remove it, and keep the returned CSRF only in memory;
  2. when no fragment exists, POST with credentials to exact-origin `/api/v1/session/csrf` and keep the reacquired value only in memory;
  3. when reacquisition returns unauthenticated/expired, show the local-bootstrap-required state without retry loops or inventing credentials.

- [ ] Configure same-origin Ktor client JSON. Add CSRF only to mutations; never persist session/CSRF/password values in localStorage, sessionStorage, IndexedDB, URL, or logs.

- [ ] Add a Selenium flow that bootstraps, performs a mutation, full-page reloads a deep link with no fragment, reacquires CSRF through the cookie session, performs a second mutation, and proves the value never appears in URL/storage/logs. Also prove an expired process-local session after reload cannot mutate and asks for a newly printed bootstrap URL.

- [ ] Replace the gate event client with authenticated native `EventSource`, monotonic IDs, reconnect status, and full resource refresh on `resync`.

- [ ] Run:

```bash
cd debug-dashboard
./kotlin test --include-module dashboard-web
./kotlin build --module dashboard-web
```

Expected: pass and link.

## Task 2: Establish visual tokens and the application shell

**Files:**

- Create: `debug-dashboard/dashboard-web/src/mail/sandbox/dashboard/web/theme/ColorTokens.kt`
- Create: `debug-dashboard/dashboard-web/src/mail/sandbox/dashboard/web/theme/TypeTokens.kt`
- Create: `debug-dashboard/dashboard-web/src/mail/sandbox/dashboard/web/theme/LayoutTokens.kt`
- Create: `debug-dashboard/dashboard-web/src/mail/sandbox/dashboard/web/theme/MailFlightRecorderTheme.kt`
- Create: `debug-dashboard/dashboard-web/src/mail/sandbox/dashboard/web/shell/AppShell.kt`
- Create: `debug-dashboard/dashboard-web/src/mail/sandbox/dashboard/web/shell/HealthRail.kt`
- Create: `debug-dashboard/dashboard-web/src/mail/sandbox/dashboard/web/navigation/DashboardRouter.kt`
- Create: `debug-dashboard/dashboard-web/src/mail/sandbox/dashboard/web/navigation/DestinationRail.kt`
- Create: `debug-dashboard/dashboard-web/composeResources/font/ibm_plex_sans_condensed_regular.ttf`
- Create: `debug-dashboard/dashboard-web/composeResources/font/ibm_plex_sans_regular.ttf`
- Create: `debug-dashboard/dashboard-web/composeResources/font/ibm_plex_mono_regular.ttf`
- Create: `debug-dashboard/dashboard-web/composeResources/files/ibm-plex-OFL.txt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/browser/ThemeResourceBrowserTest.kt`
- Modify: `DESIGN.md`

- [ ] Encode the approved named palette exactly: Graphite `#17242A`, Dovecot Cyan `#0B8F9C`, Stalwart Amber `#E58A1F`, Cursor/Destructive Red `#C7473A`, Verified Green `#2F7E62`, Recorder Paper `#F4F2E8`, Panel Fog `#E8E7DE`, and Silkscreen Gray `#687577`.

- [ ] Resolve the provisional typography against an actual Wasm render. Start with open-source IBM Plex Sans Condensed for display/headings, IBM Plex Sans for body, and IBM Plex Mono for machine notation; record exact upstream versions/checksums and check the license into the resource path if retained. Update `DESIGN.md` with the actual family files and fallback stack. If Wasm font loading makes this set unreadable or unstable, choose a metrically suitable open-source replacement and record screenshot evidence—not a silent system-font fallback.

- [ ] Rebuild the linked app and run it through Gate 0A's production `WebAssetBundle`, not a test static server. Record whether each font/resource is embedded or separately emitted. Assert every separately emitted nested asset appears in the runtime manifest and returns the reviewed MIME type without a 404; assert every selected font completes browser/Compose loading and the render produces no console/network error. When files are emitted, the test must fail if one is removed or the manifest serves code while omitting it.

- [ ] Implement flat keylined work zones, low-radius controls, graphite shell, restrained elevation, and provider edge markers. Do not introduce floating card grids, pills, gradients, glow, fake gauges/knobs, or decorative motion.

- [ ] Add destinations Overview, Accounts, All Logs, Fixture Lab, Operations, and Server Setup with history-backed deep links and Back/Forward restoration.

- [ ] Implement a top health rail with service/readiness text and non-disruptive live semantics. Provider color always has a text/shape companion; red is reserved for selected cursor, failure, or destructive action.

- [ ] Build and visually inspect wide/medium/narrow shell renders before continuing. Commit:

```bash
git add debug-dashboard/dashboard-web DESIGN.md
git commit -m "feat: establish Mail Flight Recorder shell"
```

## Task 3: Build the account registry and lifecycle flows

**Files:**

- Create: `debug-dashboard/dashboard-web/src/mail/sandbox/dashboard/web/accounts/AccountRegistryScreen.kt`
- Create: `debug-dashboard/dashboard-web/src/mail/sandbox/dashboard/web/accounts/AccountFilters.kt`
- Create: `debug-dashboard/dashboard-web/src/mail/sandbox/dashboard/web/accounts/CreateAccountSheet.kt`
- Create: `debug-dashboard/dashboard-web/src/mail/sandbox/dashboard/web/accounts/ResetPasswordDialog.kt`
- Create: `debug-dashboard/dashboard-web/src/mail/sandbox/dashboard/web/accounts/DeleteAccountDialog.kt`
- Create: `debug-dashboard/dashboard-web/test/mail/sandbox/dashboard/web/accounts/AccountFormReducerTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/browser/AccountWorkflowBrowserTest.kt`

- [ ] Write reducer tests for account search/profile/status filters, protected rows, address/password validation, named capability profile selection, all-provider preflight, partial results, and cleared secret fields after completion/error.

- [ ] Implement the progressive creation sheet:

  1. canonical address and password;
  2. one or both ready named profiles;
  3. provider-specific preflight;
  4. truthful review/create.

Unsupported combinations are absent, not disabled theater.

- [ ] Implement password reset for one/both profiles with separate result rows and no claim about unrelated OAuth token revocation.

- [ ] Implement account-delete preview with counts, provider selection, Dovecot retain/purge meaning, Stalwart irreversible cleanup truth, reconciliation warnings, grant expiry, and exact typed-address confirmation. The confirm request carries only the server-issued opaque grant, exact typed address, and unchanged selection; dismissal makes no mutation. Missing/expired/stale/reused responses state that nothing was deleted and force a fresh preview.

- [ ] Drive the live API in `AccountWorkflowBrowserTest`: create a dual-provider disposable account, switch provider state, reset, preview deletion, prove dismiss/unconfirmed makes no confirm request, reject stale and altered-selection grants, delete one instance with a fresh grant, reject replay, and inspect partial/provider receipts. Run after a linked web build.

## Task 4: Build the defining Evidence Split workspace

**Files:**

- Create: `debug-dashboard/dashboard-web/src/mail/sandbox/dashboard/web/workspace/EvidenceSplitScreen.kt`
- Create: `debug-dashboard/dashboard-web/src/mail/sandbox/dashboard/web/workspace/AccountHeader.kt`
- Create: `debug-dashboard/dashboard-web/src/mail/sandbox/dashboard/web/workspace/ProviderChannelTabs.kt`
- Create: `debug-dashboard/dashboard-web/src/mail/sandbox/dashboard/web/workspace/FolderPane.kt`
- Create: `debug-dashboard/dashboard-web/src/mail/sandbox/dashboard/web/workspace/MessageListPane.kt`
- Create: `debug-dashboard/dashboard-web/src/mail/sandbox/dashboard/web/workspace/MessageReaderPane.kt`
- Create: `debug-dashboard/dashboard-web/src/mail/sandbox/dashboard/web/workspace/ProviderReceiptPane.kt`
- Create: `debug-dashboard/dashboard-web/src/mail/sandbox/dashboard/web/workspace/EvidenceInspector.kt`
- Create: `debug-dashboard/dashboard-web/src/mail/sandbox/dashboard/web/workspace/TraceRecorder.kt`
- Create: `debug-dashboard/dashboard-web/src/mail/sandbox/dashboard/web/workspace/PermanentDeleteDialog.kt`
- Create: `debug-dashboard/dashboard-web/test/mail/sandbox/dashboard/web/workspace/WorkspaceReducerTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/browser/EvidenceSplitBrowserTest.kt`

- [ ] Write reducer tests proving Dovecot and Stalwart selections, pages, cursors, and readiness do not leak across provider tabs; switching back restores each provider's independent state.

- [ ] Implement the wide 62/38 composition: folders/messages on the left; message/receipt/evidence on the right; contextual trace across the lower edge. Only one provider mailbox is active, with channel plates implemented as accessible tabs.

- [ ] Link trace selection to message/operation/evidence by exact IDs. Selection must use label, geometry, focus, and provider marker—not color alone.

- [ ] Add folder create/delete preview, message paging/read/raw/download, seen/unseen, flag/unflag, copy, move, Trash, membership removal when supported, and permanent delete with itemized operation progress. Folder delete displays exact provider/account/mailbox, child/message counts, orphan choice, grant expiry, and irreversible effect; it confirms only with the server-issued opaque grant, and dismissal or stale/reused/altered scope never calls delete.

- [ ] Permanent delete first requests the server preview and opens a destructive dialog showing provider, account, exact message count, irreversible effect, preview expiry, and “no undo” language. Confirmation stays disabled until the preview is loaded and the user checks an explicit acknowledgement. Dismissal or an unconfirmed dialog performs no mutation. Submit only the opaque preview ID/acknowledgement to the dedicated confirm route; expired/stale/reused errors preserve the current list, explain that nothing was deleted, and require a fresh preview.

- [ ] Implement HTML message rendering through a sandboxed iframe/DOM interop layer whose content is already server-sanitized. Use no `allow-scripts`, no top navigation, restrictive embedded CSP, blocked remote resources, bounded size, and focus containment. Plain text remains the fallback.

- [ ] Browser-test provider switching, folder lifecycle, reader/raw/attachment behavior, each reversible action, trace linkage, stale-state display, partial batch results, keyboard tab order, and blocked top-level navigation. For mailbox and permanent-message deletion, prove dismissal and disabled confirmation make no confirm request, scope/count are visible, stale/altered previews cannot delete, a fresh confirmed preview deletes only its exact target, and replay fails.

## Task 5: Build Fixture Lab, All Logs, Operations, Overview, and Server Setup

**Files:**

- Create: `debug-dashboard/dashboard-web/src/mail/sandbox/dashboard/web/lab/FixtureLabScreen.kt`
- Create: `debug-dashboard/dashboard-web/src/mail/sandbox/dashboard/web/logs/AllLogsScreen.kt`
- Create: `debug-dashboard/dashboard-web/src/mail/sandbox/dashboard/web/operations/OperationsScreen.kt`
- Create: `debug-dashboard/dashboard-web/src/mail/sandbox/dashboard/web/overview/OverviewScreen.kt`
- Create: `debug-dashboard/dashboard-web/src/mail/sandbox/dashboard/web/setup/ServerSetupScreen.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/browser/SecondaryDestinationsBrowserTest.kt`

- [ ] Fixture Lab: source tabs for authored text/upload/fixture/random/thread; visible envelope separate from headers; seed and replay controls; raw preview; target profiles/accounts; explicit Direct append and Deliver actions; provider/item receipts.

- [ ] All Logs: bounded history/live state, source/level/confidence/time filters, selected account, pause/resume, reconnect/resync, raw-safe detail, and export. Label time adjacency as low confidence.

- [ ] Operations: state/progress, provider/item result table, cancellation boundary, scoped retry, source/secret re-supply prompts, reconciliation links, cleanup truth, retention, and Clear Local History.

- [ ] Overview: readiness gates, provider/service health, recent operations, and outstanding reconciliation. Server Setup: discovered versions/endpoints/capabilities/permission probe results only; do not expose secrets or unimplemented protocol toggles.

- [ ] Browser-test one representative complete flow in each destination plus deep-link/reload/Back behavior. Every reload case must reacquire CSRF before its next mutation rather than relying on stale in-memory state.

## Task 6: Implement structural responsive behavior

**Files:**

- Create: `debug-dashboard/dashboard-web/src/mail/sandbox/dashboard/web/responsive/WindowClass.kt`
- Create: `debug-dashboard/dashboard-web/src/mail/sandbox/dashboard/web/responsive/ResponsiveWorkspace.kt`
- Create: `debug-dashboard/dashboard-web/test/mail/sandbox/dashboard/web/responsive/WindowClassTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/browser/ResponsiveBrowserTest.kt`

- [ ] Establish measured breakpoints after the real content render and record them in `LayoutTokens.kt`/`DESIGN.md`.

- [ ] Implement:

  - wide: navigation, folders, messages, reader/receipt/evidence, and trace visible;
  - medium: folder drawer; list and reader/evidence side-by-side; trace docked/resizable;
  - narrow: compact destination control plus ordered list → reader → evidence → trace drill-in, persistent account/provider summary, explicit Back.

The trace is reachable at every width and retains cursor context.

- [ ] Browser-test at least `1440×1000`, `1024×768`, and `390×844`; assert structure/visibility/Back behavior rather than only pixel width.

## Task 7: Complete accessibility and motion behavior

**Files:**

- Create: `debug-dashboard/dashboard-web/src/mail/sandbox/dashboard/web/accessibility/LiveAnnouncements.kt`
- Create: `debug-dashboard/dashboard-web/src/mail/sandbox/dashboard/web/accessibility/FocusCoordinator.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/browser/AccessibilityBrowserTest.kt`
- Modify: all interactive Compose files from Tasks 2–6

- [ ] Add semantic labels/roles/states for tabs, lists/tables, dialogs, menus, progress, filters, trace controls, and destructive confirmations. Every control must show a visible focus state.

- [ ] Coordinate focus on navigation, sheet/dialog open/close, row deletion, narrow-stage Back, and async errors. Announce service/operation updates without stealing focus.

- [ ] Keep state motion within 150–250 ms. Under `prefers-reduced-motion`, remove cursor travel and paper-feed transitions while preserving the final linked selection.

- [ ] In `AccessibilityBrowserTest`, complete account/mail/log operations keyboard-only; inspect accessible names/roles, focus order/restoration, live regions, reduced-motion state, non-color provider/status cues, and iframe containment.

- [ ] Run:

```bash
cd debug-dashboard
./kotlin build
./kotlin test --include-module dashboard-server --include-classes 'mail.sandbox.dashboard.server.browser.*'
./kotlin test
```

Expected: all UI unit and browser workflows pass.

- [ ] Capture and inspect wide/medium/narrow screenshots against the approved visual reference. Fix hierarchy, density, clipping, overflow, and focus defects before committing.

- [ ] Commit:

```bash
git add debug-dashboard DESIGN.md
git commit -m "feat: deliver the Compose dashboard experience"
```
