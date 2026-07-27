# Debug Dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver the local-only Kotlin debug dashboard described in `docs/superpowers/specs/2026-07-23-debug-dashboard-design.md`, with every requested workflow proven through both `dovecot-imap` and `stalwart-jmap`.

**Architecture:** Execute three stop/go feasibility gates before feature work. Then build shared KMP contracts, a loopback Ktor/JVM control plane, direct Dovecot/IMAP/Postfix and Stalwart/JMAP adapters, an evidence pipeline, and a Compose/Wasm Evidence Split SPA. Stalwart mail calls authenticate with the Account's active dashboard AppPassword leased from an owner-only encrypted snapshot; rotation may temporarily retain one staged/retiring generation. Normal passwords exist only inside explicit create, enrollment, repair, reset, or rotation requests. Treat provider work as typed, idempotent operations backed by SQLite while keeping the credential snapshot outside SQLite.

**Tech Stack:** Kotlin Toolchain 0.11.1 wrapper and YAML model, Kotlin 2.3.x, Compose Multiplatform/Wasm, Ktor/JVM, kotlinx.serialization, SQLite JDBC, Jakarta Mail/Angus, jsoup, Selenium/JVM, Docker Compose, Dovecot/Postfix/OAuth mock, Stalwart v0.16.14.

---

## Source of truth

- Approved design: `docs/superpowers/specs/2026-07-23-debug-dashboard-design.md`
- Product contract: `PRODUCT.md`
- Visual system: `DESIGN.md`
- Surface brief: `.impeccable/surfaces/debug-dashboard.md`
- Visual reference: `docs/superpowers/specs/assets/2026-07-23-debug-dashboard-evidence-split.png`
- Repository rules: `AGENTS.md`, `.ai/guidelines.md`, and the repository-local skills under `.ai/skills/`

Do not weaken an acceptance rule in this plan to get a green build. A failed Gate 0A, 0B, or 0C is a deliberate stop condition requiring a new user-approved design decision.

## Approved Stalwart credential decision

The planning-time impersonation blocker is resolved by the approved design. No Stalwart Account, role, API key, fixture, or dashboard path receives `impersonate`.

- The protected management Account uses one Replace-scoped API key with `authenticate` plus only the required Account/Domain/Task and optional Log management methods. It cannot read, mutate, or submit mail and cannot create/use another Account's AppPassword.
- Each ordinary Account may have one active dashboard-owned, mail-only AppPassword whose description starts with `mail-sandbox/debug-dashboard/`, plus at most one staged/retiring generation during rotation. Recovery may discover additional reserved-prefix orphans, which must be cleaned before another create. A new credential is created only while directly authenticated with that Account's request-scoped normal password.
- Read-once AppPassword values live in the fixed owner-only JDK AES-256-GCM snapshot from the approved design. They never enter SQLite, browser data, logs, receipts, exports, or default Stalwart backups.
- Existing/migrated Accounts begin `enrollmentRequired`. Enrollment, repair, and explicit rotation ask for the normal password for that request only; explicit removal and Account deletion do not.
- Management revocation uses a freshly fetched Account credential list under the trusted no-concurrent-external-writer contract. v0.16.14 supplies no `ifInState` guard for that patch, so the adapter preserves unrelated credentials and re-fetches/verifies after one update.
- Gate 0B must prove the complete enrollment/ready/rotation/recovery/removal/global-store-reset lifecycle, reserved-prefix orphan cleanup, lease draining, restart reconciliation, negative permission matrix, and quota behavior before migration or downstream work.

## Working location and command conventions

- Implement only in the worktree `/Users/rafael/dev/pocs/dovecot-docker/.worktrees/debug-dashboard` on branch `feature/debug-dashboard`.
- Commands shown with `cd debug-dashboard` run from the worktree root first.
- Use the checked-in `debug-dashboard/kotlin` wrapper after scaffolding. Do not add Gradle files, an npm project, generated Node tooling, React, or TypeScript.
- Use disposable `gate-*` and `acceptance-*` accounts. Never delete a pre-existing developer account.
- Never edit `vmail/` or `stalwart-data/` directly. Back up Stalwart state before migration.
- Run the applicable repository-local skill before each infrastructure task: `docker-compose`, `stalwart`, `dovecot`, `postfix`, `oauth2`, `python-scripts`, or `email-testing`.

## Dependency order

| Order | Plan | Required outcome |
|---|---|---|
| 0A | `2026-07-23-debug-dashboard-gate-0a-kotlin-toolchain.md` | Toolchain-only Compose/Wasm + Ktor + browser proof |
| 0B | `2026-07-23-debug-dashboard-gate-0b-stalwart.md` | Stalwart v0.16.14 management plus Account-bound AppPassword/store/lifecycle, mail, submission, isolation, and deletion proof |
| 0C | `2026-07-23-debug-dashboard-gate-0c-dovecot.md` | Hashed eligibility authority, isolated operator path, local routing, and deletion proof |
| 1 | `2026-07-23-debug-dashboard-foundation.md` | Shared contracts, HTTP security boundary, operation ledger, API/event shell |
| 2 | `2026-07-23-debug-dashboard-account-providers.md` | Live registry and account create/password/delete on both profiles |
| 3 | `2026-07-23-debug-dashboard-mail-providers.md` | Folder, list/read, raw, and message mutations on both profiles |
| 4 | `2026-07-23-debug-dashboard-message-lab-observability.md` | All sources, append/deliver paths, logs, correlation, and trace evidence |
| 5 | `2026-07-23-debug-dashboard-compose-ui.md` | All destinations and the responsive, accessible Evidence Split SPA |
| 6 | `2026-07-23-debug-dashboard-acceptance.md` | Full Gate 1 matrix, fault/security/accessibility proof, and operator docs |

Each plan ends with a focused commit. For Gates 0A–0C, do not begin downstream work until the gate's verification commands pass and its report contains concrete evidence. For Plans 1–6, do not begin the next numbered plan until the previous plan's verification commands pass.

## Cross-plan engineering rules

### Test-first loop

For every behavior task:

1. Add the smallest failing unit, contract, integration, or browser test.
2. Run the narrow test and record the expected failure reason.
3. Implement only enough production behavior to pass.
4. Run the narrow test, then the owning module's full test set.
5. Commit the test and implementation together.

Scaffolding and documentation-only steps instead use `./kotlin show ...`, schema validation, or `docker compose config --quiet` as their red/green check.

### Fixed module ownership

```text
debug-dashboard/
├── kotlin
├── kotlin.bat
├── project.yaml
├── dashboard-contract/  # kmp/lib, platforms jvm + wasmJs
├── dashboard-server/    # jvm/app, Ktor and all privileged adapters
└── dashboard-web/       # wasm-js/app, Compose browser entry
```

Keep browser/server DTOs, route constants, validation rules, provider-native keys, capability types, operation states, and safe problem details in `dashboard-contract`. Keep Java/JVM-only libraries and privileged behavior out of that module.

### Dependency baseline

Pin versions in the YAML model or a checked-in Toolchain catalog after Gate 0A records the effective settings. The initial verified targets are:

- Kotlin Toolchain wrapper: `0.11.1`;
- Kotlin: `2.3.21`;
- Compose: `1.10.3`;
- Ktor: `3.4.3`;
- Selenium Java: `4.46.0`;
- SQLite JDBC: `3.53.1.0`;
- Angus Mail: `2.0.5` with Jakarta Mail API `2.1.5`;
- jsoup: `1.22.2`.

If a gate requires a dependency change, update the recorded baseline and explain why; never use an unbounded version.

### Safety invariants

- Browser input never becomes a command name, service name, command flag, working directory, or arbitrary path.
- Provider secrets and request passwords never enter JSON responses, SQLite, logs, events, operation receipts, exports, or browser persistence.
- Outside Stalwart's own credential storage, dashboard AppPassword plaintext exists only during creation/capture or a transient leased operation; dashboard persistence is limited to the fixed encrypted snapshot. The snapshot key, ciphertext, temporary files, and secret-bearing lifecycle records never enter SQLite, diagnostic exports, default Stalwart backups, or Clear Local History. Safe Account IDs, provider credential IDs, generations, and lifecycle outcomes may enter the operation ledger.
- Stalwart mail calls require a `ready` Account-bound credential lease. They never fall back to a normal password, management key, global operator, or cross-account credential.
- Stalwart credential mutation takes the Account's exclusive lease lock, drains for at most 30 seconds, and leaves provider/local state unchanged on timeout. External credential-list edits are excluded only by the documented trusted-test-sandbox contract, not by a nonexistent provider state guard.
- Redaction happens before parsing or persistence.
- All mutable Dovecot eligibility writes share one file-global lock and atomic writer.
- Every provider/application mutation requires an idempotency key, exact-origin session, and CSRF header; the no-store CSRF reacquisition POST is session maintenance only and performs no provider/ledger mutation.
- Account, mailbox, and permanent-message deletion require a server-issued preview bound to the exact current provider state plus explicit confirmation; generic mutation routes cannot bypass it.
- Multi-provider work records itemized results and uses `reconciliationRequired`; it does not hide partial success or destructively roll it back.
- Direct append and real delivery remain different operation kinds and different UI actions.

## Completion checklist

- [ ] Gate reports `0a`, `0b`, and `0c` are committed with passing, reproducible evidence.
- [ ] Gate 0B proves no `impersonate` grant exists, management/mail permissions are disjoint, AppPassword secrets survive an approved restart only through the encrypted snapshot, and every enrollment/rotation/recovery/removal/store-reset fault case has a deterministic result.
- [ ] `cd debug-dashboard && ./kotlin show modules && ./kotlin build && ./kotlin test` succeeds.
- [ ] `docker compose config --quiet` succeeds and all dashboard-relevant published ports are loopback-only.
- [ ] The live Gate 1 suite passes every row once through each provider profile.
- [ ] Browser security, redaction, fault, keyboard, reduced-motion, and responsive tests pass.
- [ ] Runtime hygiene uses filename/type/mode/symlink checks plus the purpose-built secret-exclusion test; no recursive grep or diagnostic command prints runtime file contents or secret matches.
- [ ] `git ls-files debug-dashboard | rg '(^|/)(build\.gradle(\.kts)?|settings\.gradle(\.kts)?|package(-lock)?\.json|yarn\.lock|pnpm-lock\.yaml)$|\.(js|mjs|ts|tsx)$'` prints nothing; ignored Toolchain linker `.mjs` output is allowed.
- [ ] README/operator docs identify the local-only threat boundary, backup/restore path, retention, and all irreversible operations.
- [ ] `.ai/self-review.md` is executed against the final diff before completion is claimed.
