package mail.sandbox.dashboard.server.acceptance

import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.exists
import kotlin.io.path.readBytes
import kotlin.io.path.writeBytes
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking
import mail.sandbox.dashboard.contract.AccountInfo
import mail.sandbox.dashboard.contract.CredentialReadiness
import mail.sandbox.dashboard.contract.FolderInfo
import mail.sandbox.dashboard.contract.MailProtocol
import mail.sandbox.dashboard.contract.MessageSummary
import mail.sandbox.dashboard.contract.Provider
import mail.sandbox.dashboard.contract.ProviderAvailability
import mail.sandbox.dashboard.server.local.LocalDashboardBackend

class SingleStackPreservationTest {
    @Test
    fun runnerCaptureOrComparisonExecutesOnlyWhenExplicitlySelected() = runBlocking {
        val mode = System.getenv("DASHBOARD_SINGLE_STACK_PRESERVATION_MODE") ?: return@runBlocking
        require(mode == "capture" || mode == "compare") {
            "DASHBOARD_SINGLE_STACK_PRESERVATION_MODE must be capture or compare"
        }
        val selected = SingleStackAcceptanceEnvironment.load()
        LocalDashboardBackend.production(
            repositoryRoot = selected.repositoryRoot,
            environment = System.getenv(),
        ).use { backend ->
            val inventory = backend.listAccounts()
            check(inventory.providerStatuses.all { it.availability == ProviderAvailability.READY }) {
                "Both root providers must be ready for preservation capture/comparison"
            }
            if (mode == "capture") {
                selected.writeSnapshot(selected.capturePreservation(inventory.accounts))
            } else {
                selected.assertPreserved(selected.readSnapshot(), inventory.accounts)
            }
        }
    }

    @Test
    fun selectedEnvironmentRequiresExplicitOptInPrimaryCheckoutAndExactEndpoints() {
        TestRoot().use { fixture ->
            assertFailsWith<IllegalArgumentException> {
                SingleStackAcceptanceEnvironment.load(
                    environment = fixture.environment() - LIVE_KEY,
                    repositoryRoot = fixture.root,
                    commandRunner = fixture.runner,
                )
            }
            assertFailsWith<IllegalArgumentException> {
                SingleStackAcceptanceEnvironment.load(
                    environment = fixture.environment().toMutableMap().apply {
                        this["DASHBOARD_SINGLE_STACK_STALWART_JMAP_ENDPOINT"] =
                            "http://127.0.0.1:18443"
                    },
                    repositoryRoot = fixture.root,
                    commandRunner = fixture.runner,
                )
            }
            assertFailsWith<IllegalArgumentException> {
                SingleStackAcceptanceEnvironment.load(
                    environment = fixture.environment(),
                    repositoryRoot = fixture.root,
                    commandRunner = fixture.runner.copy(primaryCheckout = false),
                )
            }

            val selected = SingleStackAcceptanceEnvironment.load(
                environment = fixture.environment(),
                repositoryRoot = fixture.root,
                commandRunner = fixture.runner,
            )

            assertEquals(fixture.root, selected.repositoryRoot)
            assertEquals(fixture.prefix, selected.run.prefix)
        }
    }

    @Test
    fun existingUsersIncludingAnIntentionallyEmptyFileArePreservedByteForByte() {
        TestRoot(users = ByteArray(0)).use { fixture ->
            val environment = fixture.load()
            val snapshot = environment.capturePreservation(fixture.accounts)

            environment.assertPreserved(snapshot, fixture.accounts)

            fixture.users.writeBytes(fixture.defaults.readBytes())
            assertFailsWith<IllegalStateException> {
                environment.assertPreserved(snapshot, fixture.accounts)
            }
        }
    }

    @Test
    fun absentUsersMayOnlyBecomeTheExactNineBootstrappedDefaults() {
        TestRoot(users = null).use { fixture ->
            val environment = fixture.load()
            val snapshot = environment.capturePreservation(fixture.accounts)
            assertFalse(snapshot.usersInitiallyExisted)

            fixture.users.writeBytes(fixture.defaults.readBytes())
            environment.assertPreserved(snapshot, fixture.accounts)

            fixture.users.writeText("unexpected@local.test:{PLAIN}password::::::\n")
            assertFailsWith<IllegalStateException> {
                environment.assertPreserved(snapshot, fixture.accounts)
            }
        }
    }

    @Test
    fun snapshotDetectsChangesToPreExistingMailProviderMigrationAndComposeState() {
        TestRoot().use { fixture ->
            val environment = fixture.load()
            val snapshot = environment.capturePreservation(fixture.accounts)

            fixture.preExistingMail.writeText("changed")
            assertFailsWith<IllegalStateException> {
                environment.assertPreserved(snapshot, fixture.accounts)
            }
            fixture.preExistingMail.writeText("original")

            assertFailsWith<IllegalStateException> {
                environment.assertPreserved(
                    snapshot,
                    fixture.accounts.filterNot { it.provider == Provider.STALWART },
                )
            }
            assertFailsWith<IllegalStateException> {
                environment.assertPreserved(
                    snapshot,
                    fixture.accounts,
                    commandRunner = fixture.runner.copy(composeContainerSuffix = "changed"),
                )
            }

            fixture.currentReceipt.writeText("{}\n")
            assertFailsWith<IllegalStateException> {
                environment.assertPreserved(snapshot, fixture.accounts)
            }
        }
    }

    @Test
    fun persistedSnapshotRoundTripsForTheRunnerFinallyComparison() {
        TestRoot().use { fixture ->
            val environment = fixture.load()
            val captured = environment.capturePreservation(fixture.accounts)

            environment.writeSnapshot(captured)
            val restored = environment.readSnapshot()

            assertEquals(captured, restored)
            environment.assertPreserved(restored, fixture.accounts)
        }
    }

    @Test
    fun catalogCleanupRemovesOnlyAnAcceptanceCreatedEmptyCatalog() {
        TestRoot().use { fixture ->
            val environment = fixture.load()
            val snapshot = environment.capturePreservation(fixture.accounts)
            val catalog = fixture.root.resolve("debug-dashboard/.runtime/dashboard/accounts.json")
            catalog.parent.createDirectories()
            catalog.writeText("{\"version\":2,\"accounts\":[]}\n")

            environment.removeGeneratedCatalogIfInitiallyAbsent(snapshot)

            assertFalse(catalog.exists())
            catalog.writeText(
                "{\"version\":2,\"accounts\":[{" +
                    "\"provider\":\"DOVECOT\",\"address\":\"existing@local.test\"}]}\n",
            )
            assertFailsWith<IllegalStateException> {
                environment.removeGeneratedCatalogIfInitiallyAbsent(snapshot)
            }
            assertTrue(catalog.exists())
        }
    }

    @Test
    fun cleanupRejectsAnythingOutsideTheUniqueRunPrefixAndPurgesOnlyItsMaildir() {
        TestRoot().use { fixture ->
            val environment = fixture.load()
            val generated = environment.run.accountAddress(Provider.DOVECOT)
            val generatedRoot = fixture.root.resolve("vmail/$generated")
            generatedRoot.resolve("Maildir/new").createDirectories()
            generatedRoot.resolve("Maildir/new/message").writeText("generated")

            assertFailsWith<IllegalArgumentException> {
                environment.requireGeneratedAddress("existing@local.test")
            }
            assertFailsWith<IllegalArgumentException> {
                environment.requireGeneratedFolder("existing-folder")
            }
            assertFailsWith<IllegalArgumentException> {
                environment.requireGeneratedAccount(fixture.accounts.first())
            }
            assertFailsWith<IllegalArgumentException> {
                environment.requireGeneratedAccount(
                    AccountInfo(
                        address = environment.run.accountAddress(Provider.STALWART),
                        provider = Provider.STALWART,
                        protocols = listOf(MailProtocol.JMAP),
                        credentialReadiness = CredentialReadiness.READY,
                        providerAccountId = null,
                    ),
                )
            }
            assertFailsWith<IllegalArgumentException> {
                environment.purgeGeneratedDovecotMaildir("existing@local.test")
            }

            environment.purgeGeneratedDovecotMaildir(generated)

            assertFalse(generatedRoot.exists())
            assertTrue(fixture.preExistingMail.exists())
            assertEquals("original", Files.readString(fixture.preExistingMail))
        }
    }

    @Test
    fun generatedMessagesResolveOpaqueLocalizedFoldersByIdentityAndSubject() {
        val inbox = FolderInfo("opaque-inbox-id", "Boîte de réception", 3, 3)
        val copyTarget = FolderInfo("opaque-copy-id", "Acceptance copy", 1, 1)
        val trash = FolderInfo("opaque-trash-id", "Deleted Items", 1, 1)
        val eml = message("eml-id", inbox.id, "acceptance EML")
        val text = message("text-id", inbox.id, "acceptance text")
        val random = message("random-id", inbox.id, "acceptance random")
        val copied = message("shared-message-id", copyTarget.id, "acceptance random")
        val trashed = message("shared-message-id", trash.id, "acceptance random")
        val initial = listOf(
            inbox to listOf(eml, text, random),
            trash to emptyList(),
        )
        val afterTrash = listOf(
            inbox to listOf(eml, text),
            copyTarget to listOf(copied),
            trash to listOf(trashed),
        )

        assertEquals(
            inbox,
            requireSingleFolderContainingMessageIds(
                initial,
                setOf(eml.id, text.id, random.id),
            ),
        )
        assertEquals(
            trash to trashed,
            requireUniqueMessageBySubject(
                afterTrash,
                "acceptance random",
                excludedFolderIds = setOf(copyTarget.id),
            ),
        )
    }

    @Test
    fun liveRunnerIsOptInSelectsOnlyTheLiveClassAndNeverStartsCompose() {
        val repositoryRoot = generateSequence(
            Path.of(System.getProperty("user.dir")).toAbsolutePath().normalize(),
            Path::getParent,
        ).take(6).first { candidate ->
            Files.isRegularFile(candidate.resolve("docker-compose.yml"))
        }
        val script = Files.readString(repositoryRoot.resolve("debug-dashboard/run-live-acceptance.sh"))

        assertTrue("DASHBOARD_SINGLE_STACK_LIVE_TESTS" in script)
        assertTrue("SingleStackUsabilityLiveTest" in script)
        assertTrue("SingleStackPreservationTest" in script)
        assertTrue("trap" in script)
        assertFalse(Regex("docker\\s+compose(?:\\s+-f\\s+[^\\s]+)*\\s+up").containsMatchIn(script))
        assertFalse("docker-compose up" in script)
        assertFalse("COMPOSE_PROJECT_NAME=" in script)
    }

    private class TestRoot(
        users: ByteArray? = canonicalUsers("existing@local.test", "existing-password"),
    ) : AutoCloseable {
        val root: Path = Files.createTempDirectory("single-stack-preservation-")
            .toAbsolutePath()
            .normalize()
        val prefix = "dashboard-acceptance-1786380000-a1b2c3d4"
        val users = root.resolve("config/users")
        val defaults = root.resolve("config/users.defaults")
        val currentReceipt = root.resolve("debug-dashboard/.runtime/stalwart/current.json")
        private val sourceReceipt = root.resolve(
            "debug-dashboard/.runtime/stalwart-migration/latest-source.json",
        )
        private val retainedSnapshot = root.resolve(
            "captures/debug-dashboard/stalwart-v015/backups/" +
                "stalwart-v015-20260810T120000Z-a1b2c3d4",
        )
        val preExistingMail = root.resolve("vmail/existing@local.test/Maildir/cur/message")
        val accounts = listOf(
            AccountInfo(
                address = "existing@local.test",
                provider = Provider.DOVECOT,
                protocols = listOf(MailProtocol.IMAP, MailProtocol.POP3, MailProtocol.SMTP),
                credentialReadiness = CredentialReadiness.READY,
            ),
            AccountInfo(
                address = "stalwart-existing@local.test",
                provider = Provider.STALWART,
                protocols = listOf(MailProtocol.JMAP, MailProtocol.SMTP),
                credentialReadiness = CredentialReadiness.PASSWORD_REQUIRED,
                providerAccountId = "42",
            ),
        )
        val runner = FakeCommandRunner(root)

        init {
            root.resolve(".git").createDirectories()
            root.resolve("docker-compose.yml").writeText("services: {}\n")
            defaults.parent.createDirectories()
            defaults.writeBytes(DEFAULT_USERS)
            if (users != null) this.users.writeBytes(users)
            preExistingMail.parent.createDirectories()
            preExistingMail.writeText("original")
            currentReceipt.parent.createDirectories()
            currentReceipt.writeText("{\"schema\":\"mail-sandbox.stalwart-current-runtime.v1\"}\n")
            retainedSnapshot.createDirectories()
            sourceReceipt.parent.createDirectories()
            sourceReceipt.writeText(
                """{"payload":{"backup":{"root":"$retainedSnapshot"}},"payload_sha256":"fake-validated-by-runner"}
                """.trimIndent(),
            )
            root.resolve("debug-dashboard/.runtime/acceptance/$prefix").createDirectories()
        }

        fun environment(): Map<String, String> = SingleStackAcceptanceEnvironment.EXACT_ENDPOINTS +
            mapOf(
                LIVE_KEY to "1",
                "DASHBOARD_SINGLE_STACK_RUN_PREFIX" to prefix,
                "DASHBOARD_SINGLE_STACK_SNAPSHOT" to root.resolve(
                    "debug-dashboard/.runtime/acceptance/$prefix/baseline.json",
                ).toString(),
            )

        fun load(): SingleStackAcceptanceEnvironment = SingleStackAcceptanceEnvironment.load(
            environment = environment(),
            repositoryRoot = root,
            commandRunner = runner,
        )

        override fun close() {
            Files.walk(root).use { paths ->
                paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
            }
        }
    }

    private data class FakeCommandRunner(
        val root: Path,
        val primaryCheckout: Boolean = true,
        val composeContainerSuffix: String = "original",
    ) : SingleStackCommandRunner {
        override fun run(argv: List<String>): SingleStackCommandResult = when {
            argv.takeLast(2) == listOf("rev-parse", "--show-toplevel") ->
                success(if (primaryCheckout) root.toString() else root.resolve("worktree").toString())
            argv.takeLast(2) == listOf("rev-parse", "--git-common-dir") ->
                success(if (primaryCheckout) root.resolve(".git").toString() else root.resolve("common.git").toString())
            argv.any { it.endsWith("/stalwart_runtime_state.py") } -> success("current")
            argv.any { it.endsWith("/capture_stalwart_v015.py") } -> success("verified")
            argv.firstOrNull() == "docker" -> success(
                """[
                  {"ID":"dovecot-$composeContainerSuffix","Project":"mail-sandbox","Service":"dovecot"},
                  {"ID":"postfix-$composeContainerSuffix","Project":"mail-sandbox","Service":"postfix"},
                  {"ID":"oauth-$composeContainerSuffix","Project":"mail-sandbox","Service":"oauth2-mock"},
                  {"ID":"stalwart-$composeContainerSuffix","Project":"mail-sandbox","Service":"stalwart"}
                ]
                """.trimIndent(),
            )
            else -> SingleStackCommandResult(2, "", "unexpected command: $argv")
        }

        private fun success(stdout: String) = SingleStackCommandResult(0, "$stdout\n", "")
    }

    private companion object {
        const val LIVE_KEY = "DASHBOARD_SINGLE_STACK_LIVE_TESTS"
        val DEFAULT_USERS = (1..9).joinToString(separator = "") { index ->
            "seed-$index@local.test:{PLAIN}password-$index::::::\n"
        }.toByteArray()

        fun canonicalUsers(address: String, password: String): ByteArray =
            "$address:{PLAIN}$password::::::\n".toByteArray()

        fun message(id: String, folderId: String, subject: String) = MessageSummary(
            id = id,
            folderId = folderId,
            mutationState = "state-$id",
            subject = subject,
            fromAddress = "acceptance-sender@local.test",
            receivedAt = "2026-08-11T12:00:00Z",
            isRead = false,
            isFlagged = false,
        )
    }
}
