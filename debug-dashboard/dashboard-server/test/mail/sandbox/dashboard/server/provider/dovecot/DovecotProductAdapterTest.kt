package mail.sandbox.dashboard.server.provider.dovecot

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.nio.charset.StandardCharsets
import java.util.concurrent.TimeUnit
import kotlin.io.path.createDirectories
import kotlin.io.path.createTempDirectory
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class DovecotProductAdapterTest {
    @Test
    fun accountsAreManagedThroughTheCanonicalRegistryAndVerifiedWithoutReload() {
        val registry = RecordingAccountRegistry()
        val runner = RecordingRunner(
            DovecotCommandResult.success(),
            DovecotCommandResult.success(),
            missingUser(),
        )
        val adapter = DovecotProductAdapter(registry, runner)
        val firstPassword = "first-pass".toByteArray()
        val secondPassword = "second-pass".toByteArray()

        assertEquals(emptyList(), adapter.listAccounts())
        assertEquals(
            DovecotAccount(
                "alice@local.test",
                setOf(DovecotProtocol.Imap, DovecotProtocol.Pop3, DovecotProtocol.Smtp),
            ),
            adapter.createAccount("alice@local.test", firstPassword),
        )
        adapter.changePassword("alice@local.test", secondPassword)
        adapter.deleteAccount("alice@local.test")

        assertEquals(
            listOf(
                AccountCall.Create("alice@local.test", firstPassword.toList()),
                AccountCall.ChangePassword("alice@local.test", secondPassword.toList()),
                AccountCall.Delete("alice@local.test"),
            ),
            registry.calls,
        )
        assertEquals(
            listOf(
                doveadm("user", "alice@local.test"),
                doveadm("user", "alice@local.test"),
                doveadm("user", "alice@local.test"),
            ),
            runner.requests.map(DovecotCommandRequest::argv),
        )
        assertTrue(runner.requests.none { "reload" in it.argv || "mailbox" in it.argv })
    }

    @Test
    fun accountCreationNeverBootstrapsMailboxesThroughDoveadm() {
        val registry = RecordingAccountRegistry()
        val runner = RecordingRunner(DovecotCommandResult.success())
        val adapter = DovecotProductAdapter(registry, runner)

        adapter.createAccount("alice@local.test", "password".toByteArray())

        val expectedCalls: List<AccountCall> = listOf(
            AccountCall.Create("alice@local.test", "password".toByteArray().toList()),
        )
        assertEquals(expectedCalls, registry.calls)
        assertEquals(listOf(doveadm("user", "alice@local.test")), runner.requests.map { it.argv })
    }

    @Test
    fun activePlainPasswordIsExposedWithoutUsingAStaleSecondaryValue() {
        val registry = RecordingAccountRegistry().apply {
            create("alice@local.test", "authority-password".toByteArray()) {}
        }
        val adapter = DovecotProductAdapter(registry, RecordingRunner())

        assertEquals("authority-password", adapter.plainPassword("alice@local.test"))
        assertEquals(null, adapter.plainPassword("missing@local.test"))
    }

    @Test
    fun onlyCanonicalLocalTestAccountsAreAccepted() {
        val registry = RecordingAccountRegistry()
        val runner = RecordingRunner()
        val adapter = DovecotProductAdapter(registry, runner)

        listOf(
            "Alice@local.test",
            "alice@example.com",
            "alice@sub.local.test",
            "alice+bad command@local.test",
        ).forEach { address ->
            assertFailsWith<IllegalArgumentException>(address) {
                adapter.createAccount(address, byteArrayOf(1))
            }
        }

        assertTrue(registry.calls.isEmpty())
        assertTrue(runner.requests.isEmpty())
    }

    @Test
    fun productAdapterExposesNoUserFacingMailboxCommandMethods() {
        val forbidden = setOf(
            "listFolders",
            "createFolder",
            "deleteFolder",
            "listMessages",
            "readRawMessage",
            "markRead",
            "setFlagged",
            "copyMessages",
            "moveMessages",
            "trashMessages",
            "deleteMessages",
        )

        assertTrue(DovecotProductAdapter::class.java.declaredMethods.none {
            it.name in forbidden
        })
    }

    @Test
    fun rawEmlIsTheOnlyMailOperationAndUsesDoveadmSaveStdin() {
        val runner = RecordingRunner(DovecotCommandResult.success())
        val adapter = DovecotProductAdapter(RecordingAccountRegistry(), runner)
        val eml = validEml().toByteArray(StandardCharsets.UTF_8)

        adapter.saveRawEmail("alice@local.test", "INBOX.Client's & 🐞", eml)

        assertEquals(
            doveadm("save", "-u", "alice@local.test", "-m", "INBOX.Client's & 🐞"),
            runner.singleRequest().argv,
        )
        assertContentEquals(eml, runner.singleRequest().stdin)
    }

    @Test
    fun rawEmlRequiresTheDebuggingHeaders() {
        val runner = RecordingRunner()
        val adapter = DovecotProductAdapter(RecordingAccountRegistry(), runner)

        assertFailsWith<IllegalArgumentException> {
            adapter.saveRawEmail(
                "alice@local.test",
                "INBOX",
                "From: sender@local.test\n\nbody".toByteArray(),
            )
        }

        assertTrue(runner.requests.isEmpty())
    }

    @Test
    fun usersFileRegistryReturnsPlainPasswordsAndRemovesOnlyAuthentication() {
        val root = createTempDirectory("dovecot-product-accounts").toRealPath()
        try {
            val users = root.resolve("config/users")
            users.parent.createDirectories()
            val mailbox = root.resolve("vmail/alice@local.test/Maildir").createDirectories()
            val sentinel = mailbox.resolve("message").also { it.writeText("preserve") }
            val registry = UsersFileDovecotAccountRegistry(DovecotUsersFile(users))
            var verifications = 0

            registry.create("alice@local.test", "first".toByteArray()) { verifications++ }
            registry.changePassword("alice@local.test", "second".toByteArray()) {
                verifications++
            }
            assertEquals("second", registry.plainPassword("alice@local.test"))
            assertEquals(
                "alice@local.test:{PLAIN}second::::::\n",
                users.toFile().readText(),
            )
            registry.delete("alice@local.test") { verifications++ }

            assertEquals(null, registry.plainPassword("alice@local.test"))
            assertEquals("preserve", sentinel.toFile().readText())
            assertEquals(3, verifications)
        } finally {
            root.toFile().deleteRecursively()
        }
    }

    @Test
    fun jvmRunnerRoutesOnlyAccountControlAndDirectAppendThroughRootCompose() {
        val root = createTempDirectory("dovecot-root-routing").toRealPath()
        try {
            root.resolve("docker-compose.yml").writeText("services: {}\n")
            val captured = mutableListOf<DovecotCommandRequest>()
            val runner = JvmDovecotCommandRunner(root) { request ->
                captured += request
                CompletedProcess()
            }

            runner.run(DovecotCommandRequest(doveadm("user", "*")))
            runner.run(
                DovecotCommandRequest(
                    doveadm("save", "-u", "alice@local.test", "-m", "INBOX"),
                    stdin = validEml().toByteArray(),
                ),
            )
            listOf(
                arrayOf("mailbox", "list", "-u", "alice@local.test"),
                arrayOf("fetch", "-u", "alice@local.test", "text", "all"),
                arrayOf("flags", "add", "-u", "alice@local.test", "\\Seen", "all"),
                arrayOf("copy", "-u", "alice@local.test", "INBOX.Archive", "all"),
                arrayOf("move", "-u", "alice@local.test", "INBOX.Trash", "all"),
                arrayOf("expunge", "-u", "alice@local.test", "all"),
                arrayOf("batch", "user", "*"),
                arrayOf("exec", "imap", "alice@local.test"),
                arrayOf("-f", "pager", "user", "*"),
                arrayOf("user", "alice@local.test", "unexpected"),
                arrayOf("save", "-u", "alice@local.test", "-m", "INBOX", "unexpected"),
            ).forEach { arguments ->
                assertFailsWith<IllegalArgumentException> {
                    runner.run(DovecotCommandRequest(doveadm(*arguments)))
                }
            }
            assertFailsWith<IllegalArgumentException> {
                runner.run(
                    DovecotCommandRequest(
                        doveadm("user", "alice@local.test"),
                        stdin = "unexpected".toByteArray(),
                    ),
                )
            }
            assertFailsWith<IllegalArgumentException> {
                runner.run(
                    DovecotCommandRequest(
                        doveadm("save", "-u", "alice@local.test", "-m", "INBOX"),
                    ),
                )
            }

            val compose = root.resolve("docker-compose.yml").toString()
            assertEquals(
                listOf(
                    "docker", "compose", "-f", compose,
                    "exec", "-T", "dovecot", "doveadm", "user", "*",
                ),
                captured[0].argv,
            )
            assertEquals(2, captured.size)
            captured.flatMap(DovecotCommandRequest::argv).forEach { argument ->
                assertTrue("mail-sandbox-dashboard" !in argument)
                assertTrue("docker-compose.local-providers.yml" !in argument)
                assertTrue("dovecot-operator" !in argument)
                assertTrue("eligibility" !in argument)
            }
        } finally {
            root.toFile().deleteRecursively()
        }
    }

    @Test
    fun jvmRunnerRejectsAnInvalidRepositoryAtConstruction() {
        val root = createTempDirectory("dovecot-invalid-root").toRealPath()
        try {
            assertFailsWith<IllegalArgumentException> {
                JvmDovecotCommandRunner(root.resolve("missing"))
            }
        } finally {
            root.toFile().deleteRecursively()
        }
    }

    private fun doveadm(vararg arguments: String): List<String> =
        listOf("docker", "compose", "exec", "-T", "dovecot", "doveadm") + arguments

    private fun missingUser(): DovecotCommandResult = DovecotCommandResult(
        exitCode = 67,
        timedOut = false,
        stdout = ByteArray(0),
        stderr = "user doesn't exist".toByteArray(),
    )

    private fun validEml(): String = listOf(
        "From: sender@local.test",
        "To: alice@local.test",
        "Date: Tue, 11 Aug 2026 10:00:00 +0000",
        "Subject: Reproduction",
        "Message-ID: <reproduction@local.test>",
        "MIME-Version: 1.0",
        "Content-Type: text/plain; charset=UTF-8",
        "",
        "Hello",
    ).joinToString("\r\n")
}

private class CompletedProcess : Process() {
    private val stdin = ByteArrayOutputStream()

    override fun getOutputStream(): OutputStream = stdin
    override fun getInputStream(): InputStream = ByteArrayInputStream(ByteArray(0))
    override fun getErrorStream(): InputStream = ByteArrayInputStream(ByteArray(0))
    override fun waitFor(): Int = 0
    override fun waitFor(timeout: Long, unit: TimeUnit): Boolean = true
    override fun exitValue(): Int = 0
    override fun destroy() = Unit
    override fun destroyForcibly(): Process = this
    override fun isAlive(): Boolean = false
}

private sealed interface AccountCall {
    data class Create(val address: String, val password: List<Byte>) : AccountCall
    data class ChangePassword(val address: String, val password: List<Byte>) : AccountCall
    data class Delete(val address: String) : AccountCall
}

private class RecordingAccountRegistry : DovecotAccountRegistry {
    val calls = mutableListOf<AccountCall>()
    private val passwords = linkedMapOf<String, String>()

    override fun list(): List<String> = passwords.keys.toList()

    override fun plainPassword(address: String): String? = passwords[address]

    override fun create(
        address: String,
        password: ByteArray,
        verifyProjection: () -> Unit,
    ) {
        calls += AccountCall.Create(address, password.toList())
        passwords[address] = password.decodeToString()
        verifyProjection()
    }

    override fun changePassword(
        address: String,
        password: ByteArray,
        verifyProjection: () -> Unit,
    ) {
        calls += AccountCall.ChangePassword(address, password.toList())
        passwords[address] = password.decodeToString()
        verifyProjection()
    }

    override fun delete(address: String, verifyProjection: () -> Unit) {
        calls += AccountCall.Delete(address)
        passwords -= address
        verifyProjection()
    }
}

private class RecordingRunner(
    vararg results: DovecotCommandResult,
) : DovecotCommandRunner {
    private val results = ArrayDeque(results.toList())
    val requests = mutableListOf<DovecotCommandRequest>()

    override fun run(request: DovecotCommandRequest): DovecotCommandResult {
        requests += request.copy(stdin = request.stdin.copyOf())
        return results.removeFirstOrNull() ?: error("No result configured")
    }

    fun singleRequest(): DovecotCommandRequest = requests.single()
}
