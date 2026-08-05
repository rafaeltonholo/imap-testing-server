# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

The primary user is a single developer running the mail sandbox locally on the same machine as Docker Compose. The dashboard is not intended to be a remote, production, or multi-user administration product.

## Product Purpose

The debug dashboard provides one local control surface for observing and exercising the sandbox's Dovecot and Stalwart mail stores. It should shorten the loop between creating test state, performing mail operations, and understanding the resulting server behavior.

The first release is considered usable only when all requested workflows operate against both Dovecot and Stalwart:

- inspect server-wide and account-related logs;
- list, create, update credentials for, and delete accounts;
- create and delete folders;
- list and read messages;
- append or deliver messages from EML, authored text, and generated fixtures;
- perform core mail operations such as read/unread, flagging, moving, copying, and deleting.

## Positioning

Unlike a generic mail client or container-log viewer, the dashboard joins provider-aware mailbox operations, server administration, deterministic test-data generation, and correlated diagnostics in the same local workflow.

## Operating Context

The product runs inside this repository's Docker Compose development environment:

- Dovecot provides the current IMAP mailbox path.
- Postfix provides SMTP delivery to Dovecot.
- Stalwart provides the current JMAP mailbox path.
- The OAuth2 mock supports local authentication testing.
- Existing EML fixtures, generated threads, and Python scripts provide reusable test data and operational knowledge.

Dovecot and Stalwart remain separate mail stores. The dashboard may present a consistent interaction model, but it must preserve each provider's actual capabilities, identifiers, authentication model, and mutation semantics.

When the same email address exists on both servers, the dashboard represents it as one logical account with separate Dovecot and Stalwart provider views. Provider state and operations are never implicitly synchronized.

## Capabilities and Constraints

- The initial dashboard must support the complete requested workflow on both current provider profiles before it is considered usable.
- Account creation starts with capability-driven profiles, including Dovecot with IMAP and Stalwart with JMAP.
- Stalwart v0.16.16 is the supported baseline. The sandbox was migrated from the v0.15 configuration and management model; legacy v0.15 dashboard compatibility is not required.
- A later phase may configure or enable additional protocols on the servers. The interface must not offer unsupported provider/protocol combinations as if they already work.
- Logs and destructive operations are local development tools, but credentials, bearer tokens, and Docker control must still remain server-side and be redacted from browser-visible output.
- Provider-specific failures and partial multi-server outcomes must be shown honestly rather than collapsed into false success.
- The existing Kotlin Multiplatform email library is not required and must not sit on the dashboard's critical path. It may be integrated later only when it provides clear value beyond the dashboard's native adapters.
- The dashboard uses an all-Kotlin architecture: a Compose Multiplatform/Wasm browser application, a Ktor/JVM host service, and shared KMP contracts.
- The project must be created, configured, built, and run through the Kotlin Toolchain wrapper and its YAML project model. Gradle files and a silent Gradle fallback are out of scope.
- Because Kotlin Toolchain support for browser Wasm applications is currently an incomplete preview, implementation begins with a feasibility gate proving Compose compilation, the HTML/bootstrap path, Ktor static hosting, browser startup, navigation, and live-event transport using the Kotlin Toolchain alone.
- Message creation must expose direct mailbox append and protocol-level delivery as distinct, clearly labeled modes. Results must identify the path and provider that actually handled the message.
- Stalwart accounts intentionally use their ordinary local test password. Creating and changing that credential is part of reproducing client/provider behavior; an AppPassword isolation layer is not required for this loopback-only tool.

## Evidence on Hand

- Docker Compose definitions and service configuration in `docker-compose.yml`, `config/`, `postfix/`, `stalwart/`, and `oauth2-mock/`.
- Existing account, folder, mail injection, and fixture-generation behavior in `scripts/`.
- A substantial set of EML fixtures and generated threads in `mails/`.
- An optional Kotlin Multiplatform email library at `/Users/rafael/dev/pocs/email-sync-lib`.
- No incumbent dashboard UI, design system, brand assets, or established visual direction exists in `debug-dashboard/`.

Future work must not invent production-readiness, security, reliability, or protocol-support claims that the local stack does not demonstrate.

## Product Principles

1. Show what the servers actually did, with enough correlation to diagnose an account or operation.
2. Preserve provider truth behind a consistent interface; never hide meaningful IMAP/JMAP differences.
3. Make test state quick to create, inspect, mutate, and reproduce.
4. Keep destructive actions deliberate, scoped, and recoverable where practical.
5. Treat full Dovecot and Stalwart workflow coverage as the release floor, not a future enhancement.
