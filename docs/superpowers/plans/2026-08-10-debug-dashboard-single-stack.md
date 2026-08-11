# Debug Dashboard Single-Stack Provider Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the Kotlin debug dashboard discover and operate the repository's existing Dovecot/Postfix/OAuth2 and Stalwart accounts, mailboxes, logs, and data stores, with every requested workflow passing on both provider profiles.

**Architecture:** Keep the Kotlin Toolchain, Ktor/JVM server, and Compose/Wasm SPA, but replace every product-runtime gate/overlay route with the repository-root Compose services. Use one locked, atomically replaced `config/users` authority for Dovecot and ordinary-user IMAP/JMAP/SMTP sessions for mailbox work; retain `doveadm` and Stalwart management APIs only for control-plane operations. Detect Stalwart migration state during ordinary startup, but keep capture and live-store migration behind separate explicit operator authorization and preservation proofs.

**Tech Stack:** Kotlin Toolchain and Kotlin latest stable verified at execution time (current approved baseline: Toolchain 0.11.1 and Kotlin 2.4.10), Compose Multiplatform/Wasm, Ktor/JVM, kotlinx.serialization, latest stable Jakarta Mail API and Angus Mail verified at execution time, Python 3 stdlib, Docker Compose, Dovecot, Postfix, OAuth2 mock, Stalwart, JUnit, Python `unittest`, Selenium/Chrome.

**Design:** `docs/superpowers/specs/2026-08-10-debug-dashboard-single-stack-design.md`

---

## Execution invariants

- Execute on the local `main` checkout, as requested. Do not create another worktree.
- Preserve the user's unrelated edits in `scripts/lib.py`, `scripts/send_message.py`, and `scripts/send_thread.py`. Stage only the files named by the current task and inspect every diff before each commit.
- Use `debug-dashboard/kotlin` only. Do not add Gradle, React, TypeScript, npm build tooling, or a second frontend.
- Recheck every direct toolchain, library, base image, and provider release against an official stable source immediately before changing it. The newest stable is mandatory. If it is incompatible, leave the failure RED and stop for user direction; do not silently choose an older release.
- Treat pre-release, nightly, unreleased, platform-managed, and framework-managed artifacts explicitly in the dependency report. Explain every numerically newer artifact that is not a selectable latest stable direct dependency.
- Do not leave `latest` image tags. Before the authorized Stalwart cutover, pin the currently running legacy Stalwart image by its observed immutable tag/digest as a temporary preservation state; it is not the selected final dependency. Task 12 atomically changes the root declaration to the newest-stable tag/digest only after migration authorization.
- Do not read, stop, copy, migrate, replace, or restore the live `stalwart-data/` merely because this plan or a normal implementation task was approved. Task 12 contains the separate capture and migration authorization checkpoints.
- Never overwrite an existing `config/users` during startup, including an intentionally empty file. Never broadly delete `vmail/`, `stalwart-data/`, or `debug-dashboard/.runtime/`.
- All host writers of `config/users` use `config/users.lock`, a whole-file POSIX record lock, same-directory temporary output, `fsync`, and atomic replacement.
- Product-runtime code may use `doveadm` only for account verification, diagnostics, authentication-cache handling when the verified Dovecot version requires it, and explicitly labeled direct append. Folder, list, read, flag, copy, move, trash, and delete use the ordinary account's IMAP login.
- Keep historical gate fixtures and evidence as test-only history unless a focused task names them. They must not be reachable from normal dashboard construction or launch scripts.
- The offered `/Users/rafael/dev/pocs/email-sync-lib` is not a build dependency in this plan: it is currently a Gradle project without a Kotlin-Toolchain-consumable published coordinate and does not cover the complete folder/POP3/SMTP surface. Use a small Kotlin JVM adapter around the latest stable Jakarta Mail/Angus runtime. Do not copy library source or invoke Gradle. If a published Toolchain-consumable release exists when implementation begins and fully covers the required surface, report that fact before changing this architecture.
- Each live acceptance account, folder, and message uses a unique `dashboard-acceptance-${epochSeconds}-${randomHex}` prefix. Cleanup may remove only those generated resources.

## File responsibility map

- `scripts/users_file.py`: the Python parser, lock, bootstrap, and atomic mutation authority for `config/users`.
- `config/users.defaults`: tracked nine-account recovery fixture; `config/users`: ignored mutable authority.
- `DovecotUsersFile.kt`: Kotlin implementation of the same grammar, locking, and atomic replacement contract.
- `DovecotProductAdapter.kt`: Dovecot control plane only—account mutation/verification and direct append.
- `DovecotImapClient.kt`: ordinary-user Dovecot folder/message operations and IMAP authentication probe.
- `ProviderAuthenticationProbe.kt`: provider-neutral explicit/readiness probe interface and typed outcomes; Dovecot and Stalwart supply their own transports.
- `LocalAccountCatalog.kt`: ignored convenience cache for provider IDs, capabilities, and verified plaintext test passwords; never provider truth.
- `StalwartProductAdapter.kt`: normal `:8443` registry/JMAP operations using a fixed management login for control-plane calls and account passwords for test-plane calls.
- `scripts/stalwart_runtime_state.py`: read-only startup classification; it never performs migration.
- `SingleStackUsabilityLiveTest.kt`: complete two-provider requested-workflow acceptance against root services.

### Task 1: Revalidate and freeze the latest-stable baseline

**Files:**

- Modify: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/dependency/DependencyBaselineTest.kt`
- Modify: `tests/test_dependency_policy.py`
- Modify if a newer stable exists: `debug-dashboard/kotlin`
- Modify if a newer stable exists: `debug-dashboard/kotlin.bat`
- Modify if a newer stable exists: `debug-dashboard/dashboard-contract/module.yaml`
- Modify: `debug-dashboard/dashboard-server/module.yaml`
- Modify if a newer stable exists: `debug-dashboard/dashboard-web/module.yaml`
- Modify if a newer stable exists: `docker-compose.yml`
- Modify if a newer stable exists: `oauth2-mock/Dockerfile`
- Modify if a newer stable exists: `postfix/Dockerfile`
- Create: `docs/debug-dashboard/dependency-baseline-2026-08-10.md`

- [ ] **Step 1: Query the authoritative stable release sources**

Record the retrieval timestamp, source URL, stable version, release channel, and selected OCI index digest for Kotlin Toolchain, Kotlin, Compose Multiplatform, Compose Material3 mapping, Ktor, kotlinx.serialization, JUnit Platform, Skiko, Logback, Selenium, js-joda, Jakarta Mail API, Angus Mail, Dovecot, Stalwart, Python, Debian, and the direct Debian packages in `postfix/Dockerfile`.

Use official release pages/repositories and the publisher's Maven/OCI repositories. At minimum, retrieve the two newly introduced artifacts and inspect the current provider manifests with these exact commands; use the authoritative URLs already cataloged by the existing baseline plan for the remaining direct dependencies:

```bash
curl -fsSL https://repo1.maven.org/maven2/jakarta/mail/jakarta.mail-api/maven-metadata.xml
curl -fsSL https://repo1.maven.org/maven2/org/eclipse/angus/angus-mail/maven-metadata.xml
curl -fsSL https://api.github.com/repos/stalwartlabs/stalwart/releases/latest
docker buildx imagetools inspect dovecot/dovecot:2.4.4
docker buildx imagetools inspect stalwartlabs/stalwart:v0.16.17
```

Expected: every selected direct dependency is the newest stable release as of the recorded timestamp. A newer alpha, beta, RC, nightly, unreleased tag, or child artifact managed by a selected parent is recorded under “Not selected and why.”

- [ ] **Step 2: Add the newly required mail libraries to the exact baseline tests**

Add verified values rather than copying these historical candidates blindly:

```kotlin
private val mailDependencies = mapOf(
    "jakartaMailApi" to "2.1.5",
    "angusMail" to "2.0.5",
)
```

These are the current reviewed candidates, not permission to skip Step 1. If the official stable metadata has advanced, first change these expected values to the newly verified stable versions and keep the test RED until the module follows.

Assert that `dashboard-server/module.yaml` owns both the Jakarta API and Angus Mail as compile dependencies exactly once, and that no other dashboard module declares them. Task 5 requires the public Angus `IMAPStore`/`IMAPFolder` APIs for native MOVE and targeted UIDPLUS expunge, which the Jakarta API does not expose; Kotlin Toolchain does not expose `runtime-only` dependencies to compilation. Update the existing exact version constants only when Step 1 proves a newer stable.

- [ ] **Step 3: Run the focused tests and verify RED**

```bash
cd debug-dashboard
./kotlin test --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.dependency.DependencyBaselineTest'
cd ..
python3 -m unittest tests.test_dependency_policy -v
```

Expected: FAIL because the verified Jakarta/Angus coordinates are absent, and on any other stale direct pin discovered in Step 1.

- [ ] **Step 4: Update only verified stale declarations**

Add to `dashboard-server/module.yaml`:

```yaml
dependencies:
  - jakarta.mail:jakarta.mail-api:2.1.5
  - org.eclipse.angus:angus-mail:2.0.5
```

If Step 1 advanced either stable release, use the updated exact value established in Step 2 rather than the displayed reviewed candidate.

Apply every other Step 1 update without downgrades. Pin provider images by stable tag plus OCI index digest, except that the live Stalwart declaration is first pinned to the exact currently running legacy image/digest so no ordinary Compose command can pull a migration target early. Record it as a temporary migration hold, not the selected final baseline; Task 12 performs the newest-stable cutover. Update both wrapper hash assertions if and only if the Toolchain wrapper itself changes.

- [ ] **Step 5: Prove the resolved graph and baseline**

```bash
cd debug-dashboard
./kotlin --version
./kotlin show settings --all-modules
./kotlin show dependencies --all-modules --include-tests
./kotlin test --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.dependency.DependencyBaselineTest'
cd ..
python3 -m unittest tests.test_dependency_policy -v
docker compose config --quiet
```

Expected: PASS; the resolved graph contains exactly the selected stable mail implementations and no unexplained older conflict.

- [ ] **Step 6: Commit the freshness gate**

```bash
git add debug-dashboard/kotlin debug-dashboard/kotlin.bat \
  debug-dashboard/dashboard-contract/module.yaml \
  debug-dashboard/dashboard-server/module.yaml \
  debug-dashboard/dashboard-web/module.yaml \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/dependency/DependencyBaselineTest.kt \
  tests/test_dependency_policy.py docker-compose.yml oauth2-mock/Dockerfile \
  postfix/Dockerfile docs/debug-dashboard/dependency-baseline-2026-08-10.md
git commit -m "build: revalidate single-stack dependency baseline"
```

Stage only paths that actually changed.

### Task 2: Restore one canonical Dovecot users authority

**Files:**

- Create: `config/users.defaults`
- Create: `scripts/users_file.py`
- Create: `tests/test_users_file.py`
- Create: `tests/test_script_runtime.py`
- Modify: `.gitignore`
- Modify carefully while preserving and separately staging the user's existing hunks: `scripts/lib.py`
- Modify: `scripts/create_and_feed_account.py`
- Modify: `scripts/reset.py`
- Delete: `scripts/sync_stalwart_users.py`
- Create: `debug-dashboard/reset-local-accounts.sh`

- [ ] **Step 1: Write RED grammar, bootstrap, locking, and reset tests**

In `tests/test_users_file.py`, cover:

```python
CANONICAL = "dev@local.test:{PLAIN}secret::::::\n"

def test_bootstrap_creates_only_a_missing_users_file(self): ...
def test_bootstrap_preserves_existing_empty_and_modified_files_byte_for_byte(self): ...
def test_upsert_preserves_unrelated_records_and_writes_eight_fields(self): ...
def test_delete_removes_only_authentication_record(self): ...
def test_writers_block_on_the_shared_users_lock(self): ...
def test_atomic_replace_leaves_mode_0600_and_no_temporary_file(self): ...
def test_reset_requires_exact_scope_and_never_touches_mail_stores(self): ...
def test_whole_sandbox_reset_requires_destroy_all_provider_data(self): ...
def test_stalwart_bulk_sync_script_is_retired(self): ...
def test_changed_users_reload_and_verify_the_root_dovecot_projection(self): ...
def test_deleted_user_is_verified_absent_from_root_doveadm(self): ...
def test_bootstrap_defers_verification_only_until_launcher_starts_dovecot(self): ...
```

In `tests/test_script_runtime.py`, mock `subprocess.run` and assert `docker_exec` and `docker_cp` build root Compose argv for service `dovecot`; reject direct `docker exec`, `docker cp`, a fixed container name, an overlay file, and an alternate project name.

Reject malformed addresses, duplicate canonical addresses, non-eight-field records, unsupported password scheme prefixes, NUL/newline passwords, symlinks, and files whose final mode is not `0600`.

- [ ] **Step 2: Run the tests and verify RED**

```bash
python3 -m unittest tests.test_users_file -v
python3 -m unittest tests.test_script_runtime -v
```

Expected: FAIL because `scripts.users_file` and `config/users.defaults` do not exist, the sync script still exists, and `scripts/lib.py` still constructs fixed-container commands.

- [ ] **Step 3: Implement the canonical Python authority**

Implement a stdlib-only API with one record model and one mutation primitive:

```python
@dataclass(frozen=True)
class UserRecord:
    address: str
    password_field: str

def mutate_users(users_path: Path, transform: Callable[[list[UserRecord]], list[UserRecord]]) -> None:
    lock_path = users_path.with_name("users.lock")
    with lock_path.open("a+b") as lock_file:
        fcntl.lockf(lock_file.fileno(), fcntl.LOCK_EX)
        records = read_users(users_path)
        write_atomic(users_path, transform(records), mode=0o600)
```

`write_atomic` writes and flushes a same-directory temporary file, calls `os.fsync`, uses `os.replace`, then fsyncs the directory. Expose focused CLI commands `bootstrap-defaults`, `reset-defaults`, `upsert`, `delete`, and `verify`.

Wrap changed mutations in a projection applier that uses the root Compose helper from Step 4 to run `doveadm reload`, then verifies every expected present address with `doveadm user <address>` and every deleted address with an expected nonzero `doveadm user <address>`. For a defaults reset, also compare `doveadm user '*'` with the complete canonical file projection. A reload/verification failure is reported after the durable file mutation and is never disguised as a rollback.

`bootstrap-defaults` is a no-op whenever the destination exists. Its normal mode also verifies. Its narrowly named `--defer-provider-verification` mode is accepted only from `start-local.sh`, which must call `verify` after starting root OAuth2/Dovecot; tests assert that exact ordering so bootstrap never becomes an unverified launcher path.

- [ ] **Step 4: Add the recovered defaults and migrate legacy writers**

Write the nine approved records to `config/users.defaults`, each in exact eight-field form. Add `/config/users.lock` and same-directory user temp patterns to `.gitignore`.

Refactor `scripts/create_and_feed_account.py` to call `upsert_user()` instead of `read_text`, `write_text`, or append. Change only the Docker command construction in `scripts/lib.py` so `docker_exec` and `docker_cp` target the root `dovecot` service through `docker compose -f "${ROOT_DIR}/docker-compose.yml" exec -T` and `docker compose -f "${ROOT_DIR}/docker-compose.yml" cp`. In Python this is an argv list built from `str(ROOT_DIR / "docker-compose.yml")`, not shell interpolation. Keep the user's timeout, retry, date-rewrite, and calling-script changes byte-for-byte otherwise. The new tests cover only the committed Compose-routing behavior and must also pass in a clean checkout without the user's uncommitted hunks.

Delete `scripts/sync_stalwart_users.py`. Automatic Dovecot-to-Stalwart synchronization contradicts the approved independent-provider model, and retaining it would also misread canonical eight-field records. Add a test that the retired path is absent and remove reset/documentation suggestions to invoke it. Account creation for both providers belongs to the dashboard or provider-specific APIs.

Change `scripts/reset.py` so it exits before any mutation unless `--destroy-all-provider-data` is present and the exact confirmation names `vmail/`, `stalwart-data/`, and `config/users`. After its explicitly authorized store cleanup, it starts root OAuth2/Dovecot, restores accounts through the verified `reset_defaults()` path rather than `git checkout`, reloads Dovecot, and verifies the complete projection.

Implement `debug-dashboard/reset-local-accounts.sh --dovecot-defaults [--yes]` as a narrow root-stack command with a non-mutating `--help` path. After confirmation it runs root `docker compose up -d oauth2-mock dovecot`, invokes `reset-defaults`, and lets that command reload and verify the complete Dovecot projection. It may replace only `config/users`; it never touches either mailbox store or Stalwart.

- [ ] **Step 5: Prove all Python mutation paths obey the contract**

```bash
python3 -m unittest tests.test_users_file -v
python3 -m unittest tests.test_script_runtime -v
python3 scripts/users_file.py --help
python3 scripts/create_and_feed_account.py --help
python3 scripts/reset.py --help
./debug-dashboard/reset-local-accounts.sh --help
rg -n 'USERS_FILE\.(write_text|open)|config/users' scripts debug-dashboard \
  --glob '*.py' --glob '*.sh'
rg -n 'open\(.+users' scripts debug-dashboard --glob '*.py'
```

Expected: PASS; no host mutation path bypasses `scripts/users_file.py`, every changed Python mutation has a tested root-Dovecot reload/verification path, no active helper constructs fixed-container `docker exec`/`docker cp`, and the bulk synchronization script is gone. References that only read or name the file are allowed.

- [ ] **Step 6: Commit the users authority**

```bash
git add .gitignore config/users.defaults scripts/users_file.py \
  tests/test_users_file.py tests/test_script_runtime.py \
  scripts/create_and_feed_account.py scripts/reset.py \
  scripts/sync_stalwart_users.py debug-dashboard/reset-local-accounts.sh
git add -p scripts/lib.py
git diff --cached -- scripts/lib.py
git commit -m "feat: restore canonical Dovecot users authority"
```

At the interactive `git add -p`, stage only the root Compose command-construction lines. Split/edit the hunk if necessary. Expected cached diff: no `SAVE_TIMEOUT`, retry-loop, `rewrite_date`, or formatting hunks from the user. Expected unstaged diff after the commit: all three original user-edited files still contain their pre-task changes.

### Task 3: Point Dovecot, OAuth2, and Postfix at the shared authority

**Files:**

- Modify: `docker-compose.yml`
- Modify: `config/10-auth.conf`
- Modify: `oauth2-mock/server.py`
- Modify: `oauth2-mock/test_server.py`
- Modify: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotBaselineConfigAuditTest.kt`
- Modify: `tests/test_dependency_policy.py`

- [ ] **Step 1: Write RED mount and parser tests**

Require the Compose projection to mount the whole host `config/` directory read-only into both consumers, with Dovecot reading `/etc/dovecot/conf.d/users` and OAuth2 reading its service-specific mounted path. Require OAuth eligibility to accept exactly this canonical record:

```text
dev@local.test:{PLAIN}secret::::::
```

Also prove an atomic replacement becomes visible to a long-running parser without remounting, duplicate addresses fail closed, and `{ARGON2ID}` is not required for this test-only authority.

- [ ] **Step 2: Run focused tests and verify RED**

```bash
python3 -m unittest discover -s oauth2-mock -p 'test_server.py' -v
cd debug-dashboard
./kotlin test --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.gate.dovecot.DovecotBaselineConfigAuditTest'
cd ..
```

Expected: FAIL on the `.runtime/dovecot` mount and Argon2-only parser.

- [ ] **Step 3: Replace generated eligibility routing**

In `docker-compose.yml`, remove the normal Dovecot/OAuth2 dependency on `debug-dashboard/.runtime/dovecot`. Keep `./config:/etc/dovecot/conf.d:ro` for Dovecot and mount `./config:/etc/mail-sandbox-config:ro` into OAuth2. Set its users path to `/etc/mail-sandbox-config/users`.

Update `config/10-auth.conf`:

```text
passdb passwd-file {
  passwd_file_path = /etc/dovecot/conf.d/users
}

userdb passwd-file {
  passwd_file_path = /etc/dovecot/conf.d/users
  fields {
    uid:default = 1000
    gid:default = 1000
    home:default = /srv/vmail/%{user}
  }
}
```

Simplify OAuth validation to the shared eight-field grammar and `{PLAIN}` scheme while preserving strict address, duplicate, mode, and malformed-file rejection.

- [ ] **Step 4: Validate configuration and parser behavior**

```bash
docker compose config --quiet
python3 -m unittest discover -s oauth2-mock -p 'test_server.py' -v
cd debug-dashboard
./kotlin test --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.gate.dovecot.DovecotBaselineConfigAuditTest'
cd ..
```

Expected: PASS; rendered Compose contains no normal `.runtime/dovecot` users mount.

- [ ] **Step 5: Commit the shared consumer wiring**

```bash
git add docker-compose.yml config/10-auth.conf oauth2-mock/server.py \
  oauth2-mock/test_server.py \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/gate/dovecot/DovecotBaselineConfigAuditTest.kt \
  tests/test_dependency_policy.py
git commit -m "feat: share Dovecot accounts with OAuth and Postfix"
```

### Task 4: Replace the generated Dovecot registry with the locked passwd file

**Files:**

- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/provider/dovecot/DovecotUsersFile.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/provider/dovecot/DovecotUsersFileTest.kt`
- Modify: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/provider/dovecot/DovecotAccountRegistry.kt`
- Modify: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/provider/dovecot/DovecotCommandRunner.kt`
- Modify: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/provider/dovecot/DovecotProductAdapter.kt`
- Modify: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/provider/dovecot/DovecotProductAdapterTest.kt`

- [ ] **Step 1: Write RED Kotlin file-authority tests**

Cover canonical parse/list, create, password change, auth-only delete, mode `0600`, preservation of unrelated records, same-directory atomic replacement, and a Python-held `fcntl.lockf` blocking a Kotlin mutation.

The interoperability test starts a bounded Python subprocess that prints `locked` after acquiring `config/users.lock`; only then invoke the Kotlin mutation and assert it completes after the Python process releases the lock.

- [ ] **Step 2: Run focused tests and verify RED**

```bash
cd debug-dashboard
./kotlin test --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.provider.dovecot.DovecotUsersFileTest'
```

Expected: FAIL because `DovecotUsersFile` does not exist.

- [ ] **Step 3: Implement the Kotlin side of the same contract**

Use a small immutable record and one lock boundary:

```kotlin
internal data class DovecotUserRecord(val address: String, val passwordField: String) {
    fun plainPasswordOrNull(): String? = passwordField.removePrefix("{PLAIN}")
        .takeIf { passwordField.startsWith("{PLAIN}") }
}

FileChannel.open(lockPath, CREATE, WRITE).use { channel ->
    channel.lock().use {
        val current = readValidated()
        writeAtomic(transform(current))
    }
}
```

Write eight fields, set the temporary file's POSIX mode to `0600`, flush the temporary channel, atomically move it, and flush the parent directory where supported. Reject rather than overwrite malformed input.

- [ ] **Step 4: Narrow the Dovecot product adapter to control-plane work**

Make `DovecotAccountRegistry` delegate to `DovecotUsersFile`; remove its dependency on `EligibilityFile`, Argon2 generation, and dashboard runtime paths. Make the command runner execute only repository-root commands shaped as:

```text
docker compose -f "$repositoryRoot/docker-compose.yml" exec -T dovecot doveadm ...
```

Here `repositoryRoot` is the already validated absolute constructor argument; Kotlin command assembly inserts `repositoryRoot.resolve("docker-compose.yml").toString()` and never accepts user input for it.

Keep account verification, cache flush only if verified necessary, logs/diagnostics, and direct `doveadm save`. Remove folder/message mutation methods from this adapter after Task 5 has replacement call sites; until then keep them deprecated and unreachable from new provider tests.

- [ ] **Step 5: Prove root routing and account mutations**

```bash
./kotlin test --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.provider.dovecot.DovecotUsersFileTest'
./kotlin test --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.provider.dovecot.DovecotProductAdapterTest'
cd ..
```

Expected: PASS; recorded commands contain no `mail-sandbox-dashboard`, overlay Compose file, operator service, or generated eligibility path.

- [ ] **Step 6: Commit the Kotlin Dovecot control plane**

```bash
git add debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/provider/dovecot \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/provider/dovecot/DovecotUsersFileTest.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/provider/dovecot/DovecotProductAdapterTest.kt
git commit -m "refactor: use config users for Dovecot control plane"
```

### Task 5: Execute Dovecot mailbox work as the ordinary account

**Files:**

- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/provider/dovecot/DovecotImapClient.kt`
- Create: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/provider/ProviderAuthenticationProbe.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/provider/dovecot/DovecotImapClientTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/provider/ProviderAuthenticationProbeTest.kt`
- Modify: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/local/DovecotDashboardProvider.kt`
- Modify: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/local/DovecotDashboardProviderTest.kt`
- Modify: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/provider/dovecot/DovecotProductAdapter.kt`

- [ ] **Step 1: Write RED scripted-server tests**

Use bounded local `ServerSocket` fixtures or injected Jakarta Mail stores to prove that the client logs in as the selected account—not an admin—and supports:

```kotlin
interface DovecotMailboxClient {
    fun probe(credentials: AccountCredentials): AuthenticationOutcome
    fun listFolders(credentials: AccountCredentials): List<DovecotFolder>
    fun createFolder(credentials: AccountCredentials, name: String): DovecotFolder
    fun deleteFolder(credentials: AccountCredentials, id: String)
    fun listMessages(credentials: AccountCredentials, folder: String): List<DovecotMessageSummary>
    fun readMessage(
        credentials: AccountCredentials,
        folder: String,
        uid: Long,
        expectedState: DovecotMailboxState,
    ): String
    fun mutate(credentials: AccountCredentials, command: DovecotMessageCommand)
}
```

Test UIDVALIDITY state checking, mark read/unread, flag/unflag, copy, move, trash, targeted permanent delete/expunge, TLS timeout, wrong password, missing account, provider unavailable, and credentials absent. Assert every socket/test worker is closed on success and failure.

- [ ] **Step 2: Run focused tests and verify RED**

```bash
cd debug-dashboard
./kotlin test --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.provider.dovecot.DovecotImapClientTest'
./kotlin test --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.provider.ProviderAuthenticationProbeTest'
```

Expected: FAIL because the ordinary-user transport does not exist.

- [ ] **Step 3: Implement the bounded Jakarta Mail/Angus adapter**

Use `127.0.0.1:1143` with STARTTLS for normal IMAP and `127.0.0.1:1110` with STARTTLS for the POP3 probe. Configure connect/read/write timeouts, trust only the generated local certificate or the explicit loopback development trust setting, and close Store/Folder objects in `finally`.

Represent Dovecot mutation state with at least UIDVALIDITY; refuse a mutation when the refreshed folder state differs. Use UID-based lookup. Implement MOVE with the provider's IMAP MOVE capability when advertised, otherwise copy plus targeted `\Deleted` and targeted expunge. Never expunge unrelated messages.

Implement explicit IMAP and POP3 probes. Add a Postfix submission probe against `127.0.0.1:1587` that authenticates but sends no message. Add explicit XOAUTH2/OAUTHBEARER IMAP and SMTP probes that accept a request-scoped token override and never substitute an administrative credential. Return a typed outcome plus the bounded provider response text needed for debugging.

- [ ] **Step 4: Rewire the Dovecot dashboard provider**

Resolve the password from the active `{PLAIN}` record, falling back to a verified catalog password only for any later supported hashed record. Project the fixed server-wide Dovecot capability set `IMAP`, `POP3`, and `SMTP`; reject any create request claiming a per-account subset. Route folder/list/read/mutation calls through `DovecotMailboxClient`. After account creation writes and verifies the auth record, log in as that new ordinary user and create its default folders over IMAP; `DovecotProductAdapter.createAccount` must not create them with `doveadm`. After password change, require a successful ordinary-user login with the new password before returning `READY`. Keep `DovecotProductAdapter.saveRawEmail` only for `DIRECT_APPEND`; SMTP delivery remains Postfix.

Delete the now-unreachable `doveadm` mailbox/list/read/flag/copy/move/trash/delete methods and update tests to reject their command shapes.

- [ ] **Step 5: Prove the provider boundary**

```bash
./kotlin test --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.provider.dovecot.*Test'
./kotlin test --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.local.DovecotDashboardProviderTest'
cd ..
```

Expected: PASS; user-facing mailbox tests observe ordinary account credentials, while direct append alone records `doveadm save`.

- [ ] **Step 6: Commit ordinary-user Dovecot operations**

```bash
git add debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/provider/dovecot \
  debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/provider/ProviderAuthenticationProbe.kt \
  debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/local/DovecotDashboardProvider.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/provider/dovecot \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/provider/ProviderAuthenticationProbeTest.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/local/DovecotDashboardProviderTest.kt
git commit -m "feat: run Dovecot mail operations over user IMAP"
```

### Task 6: Add credential readiness and password adoption to the shared API

**Files:**

- Modify: `debug-dashboard/dashboard-contract/src/mail/sandbox/dashboard/contract/DashboardContract.kt`
- Modify: `debug-dashboard/dashboard-contract/src/mail/sandbox/dashboard/contract/Routes.kt`
- Modify: `debug-dashboard/dashboard-contract/test/mail/sandbox/dashboard/contract/DashboardContractSerializationTest.kt`
- Modify: `debug-dashboard/dashboard-contract/test/mail/sandbox/dashboard/contract/RoutesTest.kt`
- Modify: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/api/DashboardBackend.kt`
- Modify: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/api/DashboardApiRoutes.kt`
- Modify: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/api/DashboardApiRoutesTest.kt`
- Modify: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/local/LocalAccountCatalog.kt`
- Modify: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/local/LocalAccountCatalogTest.kt`
- Modify: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/local/LocalDashboardBackend.kt`
- Modify: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/local/LocalDashboardBackendTest.kt`
- Modify: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/local/DovecotDashboardProvider.kt`
- Modify: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/local/DovecotDashboardProviderTest.kt`
- Modify: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/local/StalwartDashboardProvider.kt`
- Modify: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/local/StalwartDashboardProviderTest.kt`

- [ ] **Step 1: Write RED contract and catalog tests**

Add and serialize these explicit models:

```kotlin
@Serializable
enum class CredentialReadiness {
    READY, PASSWORD_REQUIRED, AUTHENTICATION_FAILED, PROVIDER_UNAVAILABLE
}

@Serializable
data class AdoptPasswordRequest(val password: String)

@Serializable
data class CredentialUpdateResponse(
    val address: String,
    val provider: Provider,
    val readiness: CredentialReadiness,
    val operation: OperationResponse,
)

@Serializable
enum class ProviderAvailability { READY, DEGRADED, UNAVAILABLE, UPGRADE_REQUIRED }

@Serializable
data class ProviderStatus(
    val provider: Provider,
    val availability: ProviderAvailability,
    val message: String? = null,
)

@Serializable
enum class AuthenticationProtocol {
    IMAP, POP3, SMTP, JMAP, OAUTH_IMAP, OAUTH_SMTP
}

@Serializable
data class AuthenticationProbeRequest(
    val address: String,
    val provider: Provider,
    val protocol: AuthenticationProtocol,
    val credentialOverride: String? = null,
)

@Serializable
data class AuthenticationProbeResponse(
    val address: String,
    val provider: Provider,
    val protocol: AuthenticationProtocol,
    val success: Boolean,
    val providerResponse: String,
    val correlatedLogs: List<String>,
)
```

Extend `AccountInfo` with `providerAccountId: String?`, `credentialReadiness`, `readinessMessage: String?`, and `stale: Boolean = false`. Add `Routes.accountPasswordVerification()` for `POST .../password/verify`; retain `PUT .../password` for reset/change.

Add `Routes.AUTHENTICATION_PROBES = "/api/v1/authentication-probes"`. Password protocols use the remembered verified password when `credentialOverride` is null and the request-scoped override otherwise, allowing deliberate wrong-password reproduction without changing the catalog. An explicit empty override is valid so empty-password behavior can be reproduced; bound its size and reject CR/LF/NUL. OAuth protocols require an override as the bearer token. Responses never echo the supplied credential.

Extend `AccountListResponse` with exactly one `ProviderStatus` for Dovecot and one for Stalwart. This preserves an actionable provider error even when that provider has no cached accounts. `UPGRADE_REQUIRED` is reserved for the read-only Stalwart classifier; one provider's failure must not turn the other provider's status or accounts into an error.

Test that the catalog can retain a live account with `password = null`, migrates existing version-1 JSON without data loss, keys Stalwart records by provider Account ID when known, and cannot filter a live account from backend results.

Test account creation capability semantics: Dovecot requires the exact server-wide set `IMAP`, `POP3`, and `SMTP` and does not persist a misleading per-account subset; Stalwart accepts only a nonempty subset of `JMAP` and `SMTP` and the provider management request must enforce that subset.

- [ ] **Step 2: Run focused tests and verify RED**

```bash
cd debug-dashboard
./kotlin test --include-module dashboard-contract
./kotlin test --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.api.DashboardApiRoutesTest'
./kotlin test --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.local.LocalAccountCatalogTest'
./kotlin test --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.local.DovecotDashboardProviderTest'
./kotlin test --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.local.StalwartDashboardProviderTest'
```

Expected: FAIL because readiness and password verification are absent and catalog passwords are mandatory.

- [ ] **Step 3: Implement nullable cached credentials without weakening provider truth**

Change `LocalAccountRecord.password` to `String?`; remove `providerGeneration`, which belonged to the gate fixture lifecycle. Read version 1 and write version 2. Add `rememberVerifiedPassword` and `forgetPassword` methods. Never persist a supplied password before the provider probe succeeds.

Have the Dovecot provider map its ordinary IMAP probe to all four readiness values. Give `LocalProviderOperations.probeAuthentication` a degraded/unavailable default so the contract compiles while a provider adapter is unavailable; Dovecot overrides it now, and Task 8 replaces Stalwart's temporary current-adapter behavior with the normal-root JMAP/SMTP implementation. Update both provider tests so the new non-null `AccountInfo` readiness is never supplied by a misleading DTO default.

Merge list results as:

```kotlin
val live = provider.listAccounts()
return live.map { account -> account.withCachedMetadata(catalog.findByIdentity(account)) }
```

On provider failure, return only explicitly stale cached projections for that provider with `PROVIDER_UNAVAILABLE`; never mark them live and never let cache data override successful live capabilities.

- [ ] **Step 4: Implement API routes and itemized results**

Add `DashboardBackend.adoptPassword` and `DashboardBackend.probeAuthentication`. Change `changePassword` to return `CredentialUpdateResponse`. Map malformed/blank password requests to 400 and provider authentication rejection to an actionable response without exposing other stored passwords.

For explicit probes, validate the provider/protocol matrix before any socket call: Dovecot permits IMAP, POP3, SMTP, OAUTH_IMAP, and OAUTH_SMTP; Stalwart permits JMAP and SMTP. Capture the account-filtered root log cursor immediately before the request, run exactly one ordinary-user attempt, then poll boundedly and return only new matching log lines with the provider response. A failed probe is a successful HTTP diagnostic result with `success=false`, not an internal server error.

Keep dual-provider mutations independent: one channel's result never rolls back or edits the other channel. Validate the provider-specific create capability rules before any catalog or provider mutation.

- [ ] **Step 5: Prove contract, API, catalog, and backend behavior**

```bash
./kotlin test --include-module dashboard-contract
./kotlin test --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.api.DashboardApiRoutesTest'
./kotlin test --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.local.LocalAccountCatalogTest'
./kotlin test --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.local.LocalDashboardBackendTest'
./kotlin test --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.local.DovecotDashboardProviderTest'
./kotlin test --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.local.StalwartDashboardProviderTest'
cd ..
```

Expected: PASS for all four readiness states, all provider availability states, independent per-provider errors, explicit protocol-matrix validation, failed-auth diagnostic responses with correlated logs, v1-to-v2 catalog migration, live-over-cache capability precedence, and password persistence only after successful auth.

- [ ] **Step 6: Commit the readiness contract**

```bash
git add debug-dashboard/dashboard-contract \
  debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/api \
  debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/local/LocalAccountCatalog.kt \
  debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/local/LocalDashboardBackend.kt \
  debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/local/DovecotDashboardProvider.kt \
  debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/local/StalwartDashboardProvider.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/api/DashboardApiRoutesTest.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/local/LocalAccountCatalogTest.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/local/LocalDashboardBackendTest.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/local/DovecotDashboardProviderTest.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/local/StalwartDashboardProviderTest.kt
git commit -m "feat: expose provider credential readiness"
```

### Task 7: Prepare the normal Stalwart runtime and read-only migration classifier

**Files:**

- Create: `stalwart/config.json`
- Modify: `stalwart/bootstrap-v016.ndjson`
- Modify: `docker-compose.stalwart-migration.yml`
- Create: `scripts/stalwart_runtime_state.py`
- Create: `tests/test_stalwart_runtime_state.py`
- Modify: `scripts/capture_stalwart_v015.py`
- Modify: `scripts/stalwart_v016.py`
- Modify: `scripts/bootstrap_stalwart_v016.py`
- Modify: `tests/test_capture_stalwart_v015.py`
- Modify: `tests/test_stalwart_v016.py`
- Modify: `tests/test_bootstrap_stalwart_v016.py`
- Modify: `tests/test_stalwart_migration_compose.py`
- Modify: `docs/stalwart-v016-migration.md`

- [ ] **Step 1: Write RED state-classification and normal-runtime tests**

Classify exactly:

```python
class RuntimeState(Enum):
    FRESH = "fresh"
    CURRENT = "current"
    MIGRATION_REQUIRED = "migration-required"
    INVALID = "invalid"
```

An absent/empty store is `FRESH`; a nonempty store plus a fully validated receipt for the selected image/config/store identity is `CURRENT`; the known v0.15 store is `MIGRATION_REQUIRED`; malformed/symlinked/contradictory evidence is `INVALID`. The classifier performs no Docker or filesystem mutation. Add a test that starting a fresh store without publishing and revalidating the current receipt can never be classified as `CURRENT`.

Require the reviewed target configuration and migration overlay to select the Step 1 Stalwart tag/digest, bind JMAP/admin to `127.0.0.1:8443`, bind authenticated SMTP to `127.0.0.1:8587`, mount only a caller-selected store copy, and emit debug tracing to stdout. Require a protected management identity excluded from ordinary account projection. The root Compose Stalwart service remains on the exact pinned legacy hold until Task 12.

- [ ] **Step 2: Run offline tests and verify RED**

```bash
python3 -m unittest tests.test_stalwart_runtime_state -v
python3 -m unittest tests.test_stalwart_migration_compose -v
python3 -m unittest tests.test_capture_stalwart_v015 -v
python3 -m unittest tests.test_bootstrap_stalwart_v016 -v
```

Expected: FAIL because the read-only classifier and normal current runtime config are absent.

- [ ] **Step 3: Implement current stable configuration and bootstrap**

Use the latest-stable schema proven in Task 1. Configure internal directory passwords, JMAP, authenticated SMTP, local `local.test` routing, and stdout debug tracing. Extend `scripts/bootstrap_stalwart_v016.py` with this exact fresh-store command:

```bash
python3 scripts/bootstrap_stalwart_v016.py initialize-fresh \
  --repository "$repositoryRoot"
```

It first proves the classifier returns `FRESH` and that rendered root Compose selects the reviewed current image/config/ports. If root Compose is still on the temporary legacy migration hold, it exits before creating any store bytes. It then initializes only the root store, creates the protected management identity with fixed test password `secret` (or one static gitignored API key only if the verified management API cannot use Basic auth), proves registry/JMAP/SMTP and restart, atomically publishes a receipt bound to the selected image digest, config digest, and resulting store identity, and finally requires the classifier to return `CURRENT`. Any failure leaves the partial fresh store stopped and classified `INVALID`; it never overwrites or silently retries it as fresh.

Do not seed or overwrite accounts in a nonempty store. Do not implement AppPassword enrollment, credential generations, key rotation, or encrypted local password storage.

- [ ] **Step 4: Adapt—not bypass—the existing fail-closed migration**

Update version/digest/config expectations to Task 1's verified release. Preserve the existing snapshot, disposable-copy rehearsal, receipt chain, partial-failure retention, and explicit rollback command. Simplify only credential-lifecycle assumptions that no longer apply to the product runtime.

Update the runbook so normal startup may call only `stalwart_runtime_state.py classify`; capture, rehearsal, apply, rollback, and snapshot deletion remain explicit commands.

- [ ] **Step 5: Run the complete offline migration suite**

```bash
python3 -m unittest tests.test_stalwart_runtime_state -v
python3 -m unittest tests.test_stalwart_migration_compose -v
python3 -m unittest tests.test_capture_stalwart_v015 -v
python3 -m unittest tests.test_bootstrap_stalwart_v016 -v
python3 -m unittest tests.test_stalwart_v016_registry -v
python3 -m unittest tests.test_stalwart_v016 -v
docker compose config --quiet
```

Expected: PASS without starting, stopping, reading, copying, or migrating the live Stalwart store.

- [ ] **Step 6: Commit the offline Stalwart preparation**

```bash
git add stalwart docker-compose.stalwart-migration.yml \
  scripts/stalwart_runtime_state.py scripts/capture_stalwart_v015.py \
  scripts/stalwart_v016.py scripts/bootstrap_stalwart_v016.py \
  tests/test_stalwart_runtime_state.py tests/test_stalwart_migration_compose.py \
  tests/test_capture_stalwart_v015.py tests/test_stalwart_v016.py \
  tests/test_bootstrap_stalwart_v016.py docs/stalwart-v016-migration.md
git commit -m "feat: prepare normal Stalwart runtime safely"
```

### Task 8: Wire the dashboard to normal Stalwart accounts and passwords

**Files:**

- Modify: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/provider/stalwart/product/StalwartAccountCredentialCatalog.kt`
- Modify: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/provider/stalwart/product/StalwartProductAdapter.kt`
- Modify: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/provider/stalwart/product/StalwartProductAdapterTest.kt`
- Modify: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/local/StalwartDashboardProvider.kt`
- Modify: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/local/StalwartDashboardProviderTest.kt`
- Modify: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/local/LocalDashboardBackend.kt`

- [ ] **Step 1: Write RED normal-routing and readiness tests**

Prove that normal construction uses `http://127.0.0.1:8443`, fixed management Basic auth (or the Task 7 static key), the root catalog, and `127.0.0.1:8587`. Reject `18443`, `18587`, fixture secret paths, gate bootstrap accounts, generation hashes, and AppPassword lifecycle calls.

Test a live registry with accounts A and B where only A has a cached password: both appear; A probes to `READY`; B is `PASSWORD_REQUIRED`; B's management reset remains available; B's mail actions fail before any JMAP call.

Test explicit JMAP and SMTP authentication requests with remembered and overridden ordinary credentials. Return the provider's bounded authentication response for both success and failure, and never mutate readiness/catalog state merely because an explicit diagnostic probe used an override.

- [ ] **Step 2: Write RED adoption/reset persistence tests**

For adoption: management lookup succeeds, wrong ordinary password returns `AUTHENTICATION_FAILED` and catalog remains unchanged, right password completes JMAP Session auth then persists it and returns `READY`.

For reset: patch the ordinary Password credential, authenticate with the new password, then persist it. If post-reset auth fails, return failure and do not claim/store readiness.

- [ ] **Step 3: Run focused tests and verify RED**

```bash
cd debug-dashboard
./kotlin test --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.provider.stalwart.product.StalwartProductAdapterTest'
./kotlin test --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.local.StalwartDashboardProviderTest'
```

Expected: FAIL on gate fixture construction and missing readiness/adoption behavior.

- [ ] **Step 4: Implement normal Stalwart wiring**

Remove `fixtureCredentialSource`, `GateFixtureManagementCredentialProvider`, and `providerGeneration` from product construction. Keep gate packages available only to their historical tests. Add an ordinary-login probe to `StalwartProductAdapter` and use the existing account credential catalog only as the local verified-password adapter.

On each refresh, query the live registry first, exclude the protected management ID, map live enabled protocols, and overlay catalog values by provider ID/address without filtering. On mail actions, require a verified login and pass it to JMAP. On SMTP delivery, use the same verified ordinary password.

- [ ] **Step 5: Prove all Stalwart unit contracts**

```bash
./kotlin test --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.provider.stalwart.product.StalwartProductAdapterTest'
./kotlin test --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.local.StalwartDashboardProviderTest'
./kotlin test --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.local.LocalDashboardBackendTest'
cd ..
```

Expected: PASS; every existing live account remains visible and no gate path is selected.

- [ ] **Step 6: Commit normal Stalwart product wiring**

```bash
git add debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/provider/stalwart/product \
  debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/local/StalwartDashboardProvider.kt \
  debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/local/LocalDashboardBackend.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/provider/stalwart/product/StalwartProductAdapterTest.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/local/StalwartDashboardProviderTest.kt
git commit -m "feat: use normal Stalwart accounts in dashboard"
```

### Task 9: Route logs, SMTP, startup, and stop to the root stack

**Files:**

- Modify: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/local/DockerComposeLogSource.kt`
- Modify: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/local/DockerComposeLogSourceTest.kt`
- Modify: `debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/local/LocalSmtpClient.kt`
- Modify: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/local/LocalSmtpClientTest.kt`
- Modify: `debug-dashboard/start-local.sh`
- Modify: `debug-dashboard/stop-local.sh`
- Create: `debug-dashboard/stalwart-status.sh`
- Modify: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/local/LocalDashboardScriptsTest.kt`
- Delete: `debug-dashboard/docker-compose.local-providers.yml`
- Delete: `debug-dashboard/start-local-stalwart.sh`

- [ ] **Step 1: Write RED root-routing tests**

Require logs to run from the repository root against `docker-compose.yml` and only services `dovecot`, `postfix`, `oauth2-mock`, and `stalwart`. Require SMTP endpoints `1025` for normal Postfix delivery, `1587` for authenticated Dovecot/Postfix probes, and `8587` for Stalwart submission.

Require the launcher to bootstrap a missing users file, classify Stalwart without migration, start root Dovecot/Postfix/OAuth2, initialize a `FRESH` Stalwart store through Task 7's `initialize-fresh` command, reclassify it as `CURRENT`, start/use Stalwart only after that receipt validation, probe providers independently, and launch Ktor even when one provider is unavailable. Require stop to terminate only the dashboard PID.

Test the exact fresh ordering: `classify FRESH` → `initialize-fresh` → `classify CURRENT` → normal Stalwart readiness probe. Prove initialization failure or a post-bootstrap non-`CURRENT` result prevents normal Stalwart start/use but still launches the dashboard with an independent Stalwart error.

Reject every normal-script/product occurrence of `mail-sandbox-dashboard`, `mail-sandbox-stalwart-gate`, `21025`, `18443`, `18587`, `docker-compose.local-providers.yml`, and `start-local-stalwart.sh`.

- [ ] **Step 2: Run focused tests and verify RED**

```bash
cd debug-dashboard
./kotlin test --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.local.DockerComposeLogSourceTest'
./kotlin test --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.local.LocalSmtpClientTest'
./kotlin test --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.local.LocalDashboardScriptsTest'
```

Expected: FAIL on isolated project, gate, and old port routing.

- [ ] **Step 3: Implement root logs and SMTP endpoint profiles**

Approve only commands shaped as:

```text
docker compose -f "$repositoryRoot/docker-compose.yml" logs --no-color --tail "$lineLimit" "$service"
```

These names describe validated Kotlin values inserted into an argv list; no shell or caller-controlled command string is evaluated.

Preserve account-token boundary filtering and Stalwart provider-ID correlation. Split SMTP endpoint enum values so direct delivery and auth probes cannot silently use the wrong port.

- [ ] **Step 4: Replace the lifecycle scripts**

`start-local.sh` calls `python3 scripts/users_file.py bootstrap-defaults --defer-provider-verification`, calls the read-only Stalwart classifier, runs root `docker compose up -d` for safe Dovecot/Postfix/OAuth2 services without global `--wait`, then calls `python3 scripts/users_file.py verify` once Dovecot is reachable. For `FRESH`, it calls Task 7's exact `initialize-fresh` command and requires a second classification of `CURRENT` before treating Stalwart as started/ready; for an already `CURRENT` store it performs only normal root Compose convergence and readiness. It records independent readiness, builds the web module, writes a dashboard PID file, and runs Ktor. It passes the final classified Stalwart state to Ktor through a fixed enum-valued environment variable so `AccountListResponse.providerStatuses` can expose `UPGRADE_REQUIRED` or an initialization error. It prints `Stalwart upgrade required` with the runbook command when applicable.

`stop-local.sh` validates and terminates only the PID recorded for this dashboard process, then removes that PID file. It never invokes Compose stop/down or fixture cleanup.

Delete the two isolated product-runtime files only after tests prove no normal reference remains. Historical test resources stay in `dashboard-server/testResources/`.

- [ ] **Step 5: Prove lifecycle and routing**

```bash
./kotlin test --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.local.DockerComposeLogSourceTest'
./kotlin test --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.local.LocalSmtpClientTest'
./kotlin test --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.local.LocalDashboardScriptsTest'
cd ..
docker compose config --quiet
```

Expected: PASS; no provider is started/stopped by this offline test.

- [ ] **Step 6: Commit single-stack lifecycle wiring**

```bash
git add debug-dashboard/dashboard-server/src/mail/sandbox/dashboard/server/local \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/local \
  debug-dashboard/start-local.sh debug-dashboard/stop-local.sh \
  debug-dashboard/stalwart-status.sh \
  debug-dashboard/docker-compose.local-providers.yml \
  debug-dashboard/start-local-stalwart.sh
git commit -m "feat: run dashboard against root mail stack"
```

### Task 10: Surface readiness and password adoption in the Compose SPA

**Files:**

- Modify: `debug-dashboard/dashboard-web/src/mail/sandbox/dashboard/web/DashboardApi.kt`
- Modify: `debug-dashboard/dashboard-web/src/mail/sandbox/dashboard/web/DashboardApp.kt`
- Modify: `debug-dashboard/dashboard-server/resources/web/browser-bootstrap.js` only if the existing browser harness needs a new stable selector
- Modify: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/web/BrowserBootstrapTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/web/DashboardReadinessBrowserTest.kt`

- [ ] **Step 1: Write RED controller and browser behavior tests**

Test account cards for all four readiness values, a provider-unavailable stale marker, live protocol chips, and the two provider-level status banners. Include the no-cached-accounts case so Stalwart migration-required and provider-unavailable states remain visible. Test that management actions remain enabled for `PASSWORD_REQUIRED`, while folder/message/generate/mail operations are disabled unless `READY`. In the create dialog, Dovecot shows its fixed IMAP/POP3/SMTP capability set without editable per-account toggles; Stalwart offers only JMAP/SMTP choices and sends the selected enforced subset.

Test an “Authentication probe” panel that offers only the selected provider's supported explicit protocols, defaults to the remembered credential, permits a request-scoped password/token override, and renders success/failure, bounded provider response, and correlated account-log lines. The panel remains usable for `PASSWORD_REQUIRED` when an override is entered; only its remembered-credential option is disabled. Verify the override is cleared after each attempt and is never rendered in the result.

Test two explicit password actions: “Verify existing password” calls the adoption route; “Reset password” calls the change route. A successful response refreshes only that provider channel and workspace.

- [ ] **Step 2: Run the focused browser tests and verify RED**

```bash
cd debug-dashboard
./kotlin test --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.web.DashboardReadinessBrowserTest'
```

Expected: FAIL because readiness controls and adoption UI do not exist.

- [ ] **Step 3: Implement the minimal approved UI extension**

Keep the approved Mail Flight Recorder layout and visual tokens. Add one compact readiness badge per provider channel, an inline actionable error, and a password-required empty state. Reuse the existing password dialog with an explicit verify/reset mode rather than creating a new navigation surface.

The API/controller exposes:

```kotlin
suspend fun adoptPassword(password: String)
suspend fun changePassword(newPassword: String)
suspend fun probeAuthentication(
    protocol: AuthenticationProtocol,
    credentialOverride: String?,
)
val mailActionsEnabled: Boolean
    get() = selectedAccount?.credentialReadiness == CredentialReadiness.READY
```

Use stable semantic text/selectors in browser tests; do not couple tests to pixel positions.

- [ ] **Step 4: Prove controller, web build, and browser behavior**

```bash
./kotlin test --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.web.DashboardReadinessBrowserTest'
./kotlin test --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.web.BrowserBootstrapTest'
./kotlin build --module dashboard-web
cd ..
```

Expected: PASS; the Wasm bundle builds with Kotlin Toolchain and no JS/TS build step, and the explicit IMAP/POP3/SMTP/JMAP/OAuth diagnostic workflow is reachable from the selected account.

- [ ] **Step 5: Commit the readiness UI**

```bash
git add debug-dashboard/dashboard-web \
  debug-dashboard/dashboard-server/resources/web/browser-bootstrap.js \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/web/BrowserBootstrapTest.kt \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/web/DashboardReadinessBrowserTest.kt
git commit -m "feat: show account authentication readiness"
```

### Task 11: Build the complete two-provider live usability acceptance harness

**Files:**

- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/acceptance/SingleStackAcceptanceEnvironment.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/acceptance/SingleStackUsabilityLiveTest.kt`
- Create: `debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/acceptance/SingleStackPreservationTest.kt`
- Create: `debug-dashboard/run-live-acceptance.sh`
- Modify: `.gitignore`

- [ ] **Step 1: Write the opt-in and preservation RED tests**

The selected live class must fail unless `DASHBOARD_SINGLE_STACK_LIVE_TESTS=1`, the repository path is the primary checkout, and root endpoints match exact loopback ports. Missing environment is a hard selected-test error, not a skip or fallback.

Before mutations, snapshot:

- whether `config/users` existed and its exact bytes;
- all pre-existing Dovecot records and Maildir roots;
- all pre-existing ordinary Stalwart provider IDs/addresses;
- the validated Stalwart migration receipt and retained snapshot path;
- root Compose service/project identity.

After cleanup, prove only generated acceptance resources changed. If `config/users` existed, preserve all original records/bytes except the temporary insertion/removal cycle; if absent, preserve the nine bootstrapped defaults. Never assert that an intentionally empty pre-existing file should become nonempty.

- [ ] **Step 2: Write the full requested-workflow matrix**

For both `Provider.DOVECOT` and `Provider.STALWART`, use a generated account and assert in order:

1. server logs and account-filtered logs load from the root service;
2. the pre-existing live inventory remains visible;
3. account create exposes only valid live capabilities;
4. EML, authored text, and seeded-random messages arrive, covering direct import/append and SMTP delivery;
5. folder list/create/delete works;
6. message list/read returns the expected headers and body;
7. password change makes the old login fail and new login pass;
8. read/unread, flag/unflag, copy, move, trash, and permanent delete work;
9. account deletion removes authentication/registry state without affecting the other provider.

Additionally call the public authentication-probe API—not an internal helper—to prove Dovecot IMAP, POP3, SMTP, OAUTH_IMAP, and OAUTH_SMTP attempts and Stalwart JMAP/SMTP attempts return the provider response and new account-correlated root log lines. Include one intentional wrong-password/token attempt per supported family and prove it does not alter the remembered credential.

- [ ] **Step 3: Run the harness's offline contract tests and verify RED**

```bash
cd debug-dashboard
./kotlin test --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.acceptance.SingleStackPreservationTest'
```

Expected: FAIL until the environment/snapshot/cleanup implementation exists. Do not select the live class yet.

- [ ] **Step 4: Implement bounded setup, operations, and cleanup**

Use API/backend calls that exercise the same provider wiring as Ktor. Wrap each generated resource in `try/finally`; record exact provider IDs before cleanup; reject any cleanup target without the unique prefix. Keep the Dovecot Maildir purge separate from auth deletion and allow it only for the generated acceptance account.

`run-live-acceptance.sh` performs preflight, starts no alternate Compose project, selects the one live test class, and always runs preservation comparison in a trap/finally path.

- [ ] **Step 5: Prove offline acceptance mechanics**

```bash
./kotlin test --include-module dashboard-server \
  --include-classes 'mail.sandbox.dashboard.server.acceptance.SingleStackPreservationTest'
cd ..
```

Expected: PASS using temporary fake roots; no live provider access.

- [ ] **Step 6: Commit the acceptance harness**

```bash
git add .gitignore debug-dashboard/run-live-acceptance.sh \
  debug-dashboard/dashboard-server/test/mail/sandbox/dashboard/server/acceptance
git commit -m "test: add single-stack dashboard acceptance"
```

### Task 12: Perform the separately authorized Stalwart capture and migration

**Files:**

- Runtime evidence only: gitignored migration/capture paths defined by `docs/stalwart-v016-migration.md`
- Modify at the authorized cutover: `docker-compose.yml`
- Modify after successful live proof: `docs/stalwart-v016-migration.md`
- Modify after successful live proof: `docs/debug-dashboard/dependency-baseline-2026-08-10.md`

- [ ] **Step 1: Re-prove a clean offline migration suite and inspect preservation boundaries**

```bash
git status --short
python3 -m unittest tests.test_stalwart_runtime_state -v
python3 -m unittest tests.test_stalwart_migration_compose -v
python3 -m unittest tests.test_capture_stalwart_v015 -v
python3 -m unittest tests.test_bootstrap_stalwart_v016 -v
python3 -m unittest tests.test_stalwart_v016_registry -v
python3 -m unittest tests.test_stalwart_v016 -v
```

Expected: PASS; the only pre-existing dirty files are the three preserved user edits. Record `stalwart-data/` identity/size and current root container identity without modifying either.

- [ ] **Step 2: Stop and request exact capture-only authorization**

Present the exact command, source Compose project/path, snapshot destination, current version, and selected target. Require this exact user sentence:

```text
I explicitly authorize the Stalwart capture command and leaving the service stopped.
```

Approval of the spec, plan, “continue,” or this task is not equivalent. Without the sentence, stop here; Dovecot and the degraded dashboard may still be usable.

- [ ] **Step 3: Run capture only and report evidence**

Run only the command bound by the current runbook. Validate the capture receipt and source-store hash/identity. Leave the source stopped. Do not rehearse or apply migration yet.

Expected: a recoverable snapshot and valid receipt; live `stalwart-data/` remains byte-identical.

- [ ] **Step 4: Rehearse on a disposable copy**

Use the captured snapshot, isolated ports/project, selected exact image, and migration overlay. Prove account inventory, JMAP discovery, ordinary-password behavior where known, management CRUD, SMTP submission, message read/mutation, and restart. Destroy only the disposable copy after preserving its receipt.

Expected: PASS. On failure, keep the real source stopped and untouched, report the exact incompatibility, and do not select an older release without user approval.

- [ ] **Step 5: Stop and request exact live migration authorization**

Display source version, target version/digest, snapshot path, rehearsal receipt, apply command, and rollback command. Require this exact user sentence:

```text
I explicitly authorize applying the verified Stalwart migration to the normal store, starting the new runtime, and performing the documented rollback if required.
```

Do not infer it from the capture authorization.

- [ ] **Step 6: Apply the reviewed root declaration, migrate, verify, or retain failure safely**

Within the exact live-migration authorization, change the root Stalwart service from its legacy hold to the reviewed newest-stable tag plus OCI index digest, mount `stalwart/config.json`, publish only `127.0.0.1:8443` and `127.0.0.1:8587`, and retain only the root `stalwart-data/` bind. Validate `docker compose config --quiet`, then run the runbook's apply command. On success, validate the current receipt, account inventory, management login, JMAP, ordinary passwords where known, SMTP, and restart. Retain the snapshot through final Task 13 acceptance.

On partial failure: stop Stalwart, retain both failed live store and snapshot, report paths, and use rollback only within the explicit authorization and runbook confirmation. Never auto-restore or delete evidence.

- [ ] **Step 7: Record the completed migration checkpoint**

Update only factual runbook/dependency evidence after success, then commit:

```bash
git add docs/stalwart-v016-migration.md \
  docs/debug-dashboard/dependency-baseline-2026-08-10.md docker-compose.yml
git commit -m "docs: record normal Stalwart migration"
```

### Task 13: Run full root-stack acceptance and finish documentation

**Files:**

- Modify: `README.md`
- Modify: `CLAUDE.md`
- Modify: `.ai/architecture.md`
- Modify: `docs/debug-dashboard/gates/0b-stalwart.md`
- Modify: `.ai/skills/docker-compose/references/service-map.md`
- Modify: `.ai/skills/docker-compose/references/volume-mounts.md`
- Modify: `.ai/skills/dovecot/references/auth.md`
- Modify: `.ai/skills/dovecot/references/config-files.md`
- Modify: `.ai/skills/dovecot/references/doveadm.md`
- Modify: `.ai/skills/stalwart/references/config.md`
- Modify: `.ai/skills/stalwart/SKILL.md`
- Modify: `.ai/skills/stalwart/references/admin-api.md`
- Modify: `.ai/skills/stalwart/references/oauth2.md`
- Modify: `.ai/skills/postfix/references/config.md`
- Modify: `.ai/skills/postfix/references/mail-flow.md`
- Modify: `.ai/skills/oauth2/references/integration.md`
- Modify: `.ai/skills/python-scripts/references/lib-api.md`
- Modify: `.ai/skills/python-scripts/SKILL.md`
- Modify: `.ai/skills/python-scripts/references/script-inventory.md`
- Modify: `.ai/skills/email-testing/references/test-workflows.md`
- Modify: `docs/superpowers/specs/2026-07-23-debug-dashboard-design.md`
- Modify: `docs/superpowers/specs/2026-08-10-debug-dashboard-single-stack-design.md`

- [ ] **Step 1: Run all offline tests and builds**

```bash
python3 -m unittest discover -s tests -p 'test_*.py' -v
python3 -m unittest discover -s oauth2-mock -p 'test_server.py' -v
docker compose config --quiet
cd debug-dashboard
./kotlin test
./kotlin build
cd ..
```

Expected: PASS. Historical live gate classes remain opt-in and must not silently select normal provider state.

- [ ] **Step 2: Start the normal dashboard in a bounded background session**

```bash
./debug-dashboard/start-local.sh
```

Expected: root Dovecot/Postfix/OAuth2 and migrated root Stalwart are independently ready; the dashboard is served at `http://127.0.0.1:50734`; no alternate Compose project, provider overlay, or gate store starts.

- [ ] **Step 3: Run the complete two-provider live acceptance**

```bash
DASHBOARD_SINGLE_STACK_LIVE_TESTS=1 ./debug-dashboard/run-live-acceptance.sh
```

Expected: PASS for every Task 11 operation on both providers, including pre-existing account visibility, password adoption/reset, all three message sources, folder CRUD, message read/mutations, delivery, and correlated root logs.

- [ ] **Step 4: Inspect the SPA and stop only the dashboard**

Open the dashboard, confirm existing Dovecot and Stalwart channels, readiness badges, account-specific logs, generate dialog, folder/message actions, and provider-unavailable rendering. Run:

```bash
./debug-dashboard/stop-local.sh
docker compose ps
```

Expected: only the dashboard process stops; root provider containers remain under normal Compose lifecycle.

- [ ] **Step 5: Reprove preservation and stale-runtime removal**

```bash
git status --short
rg -n 'mail-sandbox-dashboard|mail-sandbox-stalwart-gate|21025|18443|18587|docker-compose\.local-providers|start-local-stalwart' \
  debug-dashboard README.md docs .ai/skills \
  --glob '!**/testResources/**' --glob '!**/gate/**' --glob '!**/gates/**' \
  --glob '!docs/superpowers/plans/2026-07-23-*'
if rg -n 'sync_stalwart_users\.py|sync users.*Stalwart|synced to Stalwart' \
  README.md CLAUDE.md .ai/architecture.md \
  .ai/skills/stalwart/SKILL.md \
  .ai/skills/stalwart/references/admin-api.md \
  .ai/skills/python-scripts/references/script-inventory.md; then
  echo 'stale active Stalwart synchronization instruction found' >&2
  exit 1
fi
if rg -n 'dovecot-dev|docker exec|debug-dashboard/\.runtime/dovecot' \
  .ai/skills/docker-compose/references/service-map.md \
  .ai/skills/docker-compose/references/volume-mounts.md \
  .ai/skills/dovecot/references/auth.md \
  .ai/skills/dovecot/references/config-files.md \
  .ai/skills/dovecot/references/doveadm.md \
  .ai/skills/python-scripts/SKILL.md \
  .ai/skills/python-scripts/references/lib-api.md \
  .ai/skills/email-testing/references/test-workflows.md; then
  echo 'stale active Dovecot runtime instruction found' >&2
  exit 1
fi
```

Expected: only explicitly historical/test-fixture references remain; no active instruction invokes the retired synchronization script; pre-existing Dovecot records/Maildirs and Stalwart accounts are preserved; only uniquely generated acceptance resources were removed; the user's three unrelated script edits remain unstaged and unchanged.

- [ ] **Step 6: Update active documentation**

Document root ports, single-stack start/stop/reset behavior, Dovecot `config/users.defaults` bootstrap, plaintext test password rationale, readiness/adoption flows, explicit Stalwart migration, account deletion versus mailbox purge, ordinary-user protocol probes, log sources, and the latest-version reasoning report. Add a prominent supersession link to the original dashboard design without rewriting historical evidence as current proof.

- [ ] **Step 7: Run repository self-review and final regression**

Follow `.ai/self-review.md`, then rerun:

```bash
python3 -m unittest discover -s tests -p 'test_*.py' -v
python3 -m unittest discover -s oauth2-mock -p 'test_server.py' -v
docker compose config --quiet
cd debug-dashboard
./kotlin test
./kotlin build
cd ..
git diff --check
```

Expected: PASS with no whitespace errors or unexplained skipped coverage.

- [ ] **Step 8: Commit the accepted single-stack dashboard**

```bash
git add README.md \
  CLAUDE.md \
  .ai/architecture.md \
  docs/debug-dashboard/gates/0b-stalwart.md \
  docs/superpowers/specs/2026-07-23-debug-dashboard-design.md \
  docs/superpowers/specs/2026-08-10-debug-dashboard-single-stack-design.md \
  .ai/skills/docker-compose/references/service-map.md \
  .ai/skills/docker-compose/references/volume-mounts.md \
  .ai/skills/dovecot/references/auth.md \
  .ai/skills/dovecot/references/config-files.md \
  .ai/skills/dovecot/references/doveadm.md \
  .ai/skills/stalwart/SKILL.md \
  .ai/skills/stalwart/references/admin-api.md \
  .ai/skills/stalwart/references/config.md \
  .ai/skills/stalwart/references/oauth2.md \
  .ai/skills/postfix/references/config.md \
  .ai/skills/postfix/references/mail-flow.md \
  .ai/skills/oauth2/references/integration.md \
  .ai/skills/python-scripts/SKILL.md \
  .ai/skills/python-scripts/references/lib-api.md \
  .ai/skills/python-scripts/references/script-inventory.md \
  .ai/skills/email-testing/references/test-workflows.md
git status --short
git commit -m "feat: make mail debug dashboard use root providers"
```

Before committing, unstage the user's unrelated `scripts/lib.py`, `scripts/send_message.py`, and `scripts/send_thread.py` unless a reviewed task intentionally changed an overlapping line and the user explicitly approved including it.

## Completion gate

Do not call the dashboard usable until all of these are evidenced in the final handoff:

- latest stable direct dependency/provider checks with reasons for every newer non-selected artifact;
- missing-only Dovecot bootstrap and byte-preserving existing-file behavior;
- live discovery of pre-existing accounts on both normal providers;
- root-only provider, data-store, port, SMTP, and log routing;
- ordinary-user authentication readiness and password adoption/reset;
- EML, text, random, folder CRUD, list/read, password, deletion, read/unread, flag/unflag, copy, move, trash, and permanent-delete acceptance on both provider profiles;
- retained Stalwart recovery snapshot and validated migration receipt;
- preservation of all unrelated provider data and user worktree changes;
- full Python, Compose, Kotlin test, Kotlin build, browser smoke, and live two-provider acceptance results.
