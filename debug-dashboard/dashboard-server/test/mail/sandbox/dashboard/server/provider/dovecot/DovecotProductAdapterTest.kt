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
                setOf(DovecotProtocol.Imap, DovecotProtocol.Pop3),
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
                doveadm("mailbox", "list", "-u", "alice@local.test"),
                doveadm(
                    "mailbox",
                    "create",
                    "-u",
                    "alice@local.test",
                    "INBOX",
                    "INBOX.Sent",
                    "INBOX.Drafts",
                    "INBOX.Trash",
                ),
                doveadm("user", "alice@local.test"),
                doveadm("user", "alice@local.test"),
            ),
            runner.requests.map(DovecotCommandRequest::argv),
        )
        assertTrue(runner.requests.none { "reload" in it.argv })
    }

    @Test
    fun failedMailboxBootstrapRollsBackTheNewCanonicalAccount() {
        val registry = RecordingAccountRegistry()
        val runner = RecordingRunner(
            DovecotCommandResult.success(),
            DovecotCommandResult.success(),
            DovecotCommandResult(
                exitCode = 75,
                timedOut = false,
                stdout = ByteArray(0),
                stderr = "mail home unavailable".toByteArray(),
            ),
            missingUser(),
        )
        val adapter = DovecotProductAdapter(registry, runner)

        assertFailsWith<DovecotCommandException> {
            adapter.createAccount("alice@local.test", "password".toByteArray())
        }

        assertEquals(
            listOf(
                AccountCall.Create("alice@local.test", "password".toByteArray().toList()),
                AccountCall.Delete("alice@local.test"),
            ),
            registry.calls,
        )
    }

    @Test
    fun deleteThenRecreateReusesRetainedDefaultMailboxesIdempotently() {
        val registry = RecordingAccountRegistry()
        val retained = "INBOX\nINBOX.Sent\nINBOX.Drafts\nINBOX.Trash\n"
        val runner = RecordingRunner(
            DovecotCommandResult.success(),
            DovecotCommandResult.success(),
            DovecotCommandResult.success(),
            missingUser(),
            DovecotCommandResult.success(),
            DovecotCommandResult.success(retained),
        )
        val adapter = DovecotProductAdapter(registry, runner)

        adapter.createAccount("alice@local.test", "first".toByteArray())
        adapter.deleteAccount("alice@local.test")
        adapter.createAccount("alice@local.test", "second".toByteArray())

        assertEquals(
            listOf(
                AccountCall.Create("alice@local.test", "first".toByteArray().toList()),
                AccountCall.Delete("alice@local.test"),
                AccountCall.Create("alice@local.test", "second".toByteArray().toList()),
            ),
            registry.calls,
        )
        assertEquals(6, runner.requests.size)
        assertEquals(
            listOf(
                doveadm("user", "alice@local.test"),
                doveadm("mailbox", "list", "-u", "alice@local.test"),
                doveadm(
                    "mailbox",
                    "create",
                    "-u",
                    "alice@local.test",
                    "INBOX",
                    "INBOX.Sent",
                    "INBOX.Drafts",
                    "INBOX.Trash",
                ),
                doveadm("user", "alice@local.test"),
                doveadm("user", "alice@local.test"),
                doveadm("mailbox", "list", "-u", "alice@local.test"),
            ),
            runner.requests.map { it.argv },
        )
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
    fun logsUseTheFixedDovecotComposeServiceAndParseLines() {
        val runner = RecordingRunner(
            DovecotCommandResult.success("one\ntwo\n"),
        )
        val adapter = DovecotProductAdapter(RecordingAccountRegistry(), runner)

        assertEquals(listOf("one", "two"), adapter.logs(75))
        assertEquals(
            listOf(
                "docker", "compose", "logs", "--no-color", "--tail", "75", "dovecot",
            ),
            runner.singleRequest().argv,
        )
        assertContentEquals(ByteArray(0), runner.singleRequest().stdin)
    }

    @Test
    fun accountLogsFilterTheBoundedLocalLogSnapshotWithoutShellCommands() {
        val runner = RecordingRunner(
            DovecotCommandResult.success(
                "imap: user=<alice@local.test> login\n" +
                    "imap: user=<bob@local.test> login\n" +
                    "lmtp(alice@local.test): saved\n",
            ),
        )
        val adapter = DovecotProductAdapter(RecordingAccountRegistry(), runner)

        assertEquals(
            listOf(
                "imap: user=<alice@local.test> login",
                "lmtp(alice@local.test): saved",
            ),
            adapter.logsForAccount("alice@local.test", 120),
        )
        assertEquals(
            listOf(
                "docker", "compose", "logs", "--no-color", "--tail", "120", "dovecot",
            ),
            runner.singleRequest().argv,
        )
    }

    @Test
    fun folderOperationsUseExactDoveadmCommandsAndDeterministicOutput() {
        val runner = RecordingRunner(
            DovecotCommandResult.success("INBOX.Archive\nINBOX\nINBOX.Trash\n"),
            DovecotCommandResult.success(),
            DovecotCommandResult.success(),
        )
        val adapter = DovecotProductAdapter(RecordingAccountRegistry(), runner)

        assertEquals(
            listOf("INBOX", "INBOX.Archive", "INBOX.Trash").map(::DovecotFolder),
            adapter.listFolders("alice@local.test"),
        )
        adapter.createFolder("alice@local.test", "INBOX.Bug Repro")
        adapter.deleteFolder("alice@local.test", "INBOX.Bug Repro")

        assertEquals(
            listOf(
                doveadm("mailbox", "list", "-u", "alice@local.test"),
                doveadm(
                    "mailbox", "create", "-u", "alice@local.test", "INBOX.Bug Repro",
                ),
                doveadm(
                    "mailbox", "delete", "-s", "-u", "alice@local.test",
                    "INBOX.Bug Repro",
                ),
            ),
            runner.requests.map(DovecotCommandRequest::argv),
        )
    }

    @Test
    fun rawEmlIsSavedThroughStdinWithoutAContainerFile() {
        val runner = RecordingRunner(DovecotCommandResult.success())
        val adapter = DovecotProductAdapter(RecordingAccountRegistry(), runner)
        val eml = validEml().toByteArray(StandardCharsets.UTF_8)

        adapter.saveRawEmail("alice@local.test", "INBOX.Bug Repro", eml)

        assertEquals(
            doveadm(
                "save", "-u", "alice@local.test", "-m", "INBOX.Bug Repro",
            ),
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
    fun rawEmlAcceptsRealisticExternalEnvelopeHeaders() {
        val runner = RecordingRunner(DovecotCommandResult.success())
        val adapter = DovecotProductAdapter(RecordingAccountRegistry(), runner)
        val eml = """
            From: External Sender <sender@example.net>
            To: External QA <qa@example.org>
            Date: Tue, 04 Aug 2026 10:00:00 +0000
            Subject: External reproduction
            Message-ID: <upstream-42@example.net>
            Received: from edge-one.example.net
            Received: from edge-two.example.net

            Realistic provider input.
        """.trimIndent().toByteArray()

        adapter.saveRawEmail("alice@local.test", "INBOX", eml)

        assertContentEquals(eml, runner.singleRequest().stdin)
    }

    @Test
    fun messageListParsesPagerRecordsIncludingFoldedValues() {
        val output = """
            uid: 9
            flags: \Seen \Flagged
            hdr.message-id: <nine@local.test>
            hdr.subject: First line
             second line
            hdr.from: Sender <sender@local.test>
            hdr.date: Tue, 04 Aug 2026 10:00:00 +0000
            
            uid: 12
            flags:
            hdr.message-id: <twelve@local.test>
            hdr.subject: Plain
            hdr.from: sender@local.test
            hdr.date: Tue, 04 Aug 2026 10:01:00 +0000
        """.trimIndent()
        val mailboxState = DovecotMailboxState(
            uidValidity = 1_234,
            mailboxGuid = "0123456789abcdef0123456789abcdef",
        )
        val runner = RecordingRunner(
            DovecotCommandResult.success(mailboxStatus(mailboxState)),
            DovecotCommandResult.success(output),
        )
        val adapter = DovecotProductAdapter(RecordingAccountRegistry(), runner)

        assertEquals(
            listOf(
                DovecotMessageSummary(
                    uid = 9,
                    mailboxState = mailboxState,
                    messageId = "<nine@local.test>",
                    subject = "First line\n second line",
                    from = "Sender <sender@local.test>",
                    date = "Tue, 04 Aug 2026 10:00:00 +0000",
                    flags = setOf("\\Flagged", "\\Seen"),
                ),
                DovecotMessageSummary(
                    uid = 12,
                    mailboxState = mailboxState,
                    messageId = "<twelve@local.test>",
                    subject = "Plain",
                    from = "sender@local.test",
                    date = "Tue, 04 Aug 2026 10:01:00 +0000",
                    flags = emptySet(),
                ),
            ),
            adapter.listMessages("alice@local.test", "INBOX"),
        )
        assertEquals(
            doveadm(
                "-f", "pager", "fetch", "-u", "alice@local.test",
                "uid flags hdr.message-id hdr.subject hdr.from hdr.date",
                "mailbox-guid", mailboxState.mailboxGuid, "all",
            ),
            runner.requests[1].argv,
        )
        assertEquals(
            doveadm(
                "-f", "pager", "mailbox", "status", "-u", "alice@local.test",
                "guid uidvalidity", "INBOX",
            ),
            runner.requests.first().argv,
        )
    }

    @Test
    fun rawMessageReadStripsOnlyThePagerFieldPrefix() {
        val raw = validEml(lineEnding = "\r\n")
        val mailboxState = DovecotMailboxState(
            uidValidity = 1_234,
            mailboxGuid = "0123456789abcdef0123456789abcdef",
        )
        val runner = RecordingRunner(
            DovecotCommandResult.success(mailboxStatus(mailboxState)),
            DovecotCommandResult.success("text: $raw"),
            DovecotCommandResult.success(mailboxStatus(mailboxState)),
        )
        val adapter = DovecotProductAdapter(RecordingAccountRegistry(), runner)

        assertEquals(
            raw,
            adapter.readRawMessage("alice@local.test", "INBOX", 44, mailboxState),
        )
        assertEquals(
            doveadm(
                "-f", "pager", "fetch", "-u", "alice@local.test", "text",
                "mailbox-guid", mailboxState.mailboxGuid, "uid", "44",
            ),
            runner.requests[1].argv,
        )
    }

    @Test
    fun flagReadMoveCopyTrashAndDeleteUseUidScopedQueries() {
        val mailboxState = DovecotMailboxState(
            uidValidity = 1_234,
            mailboxGuid = "0123456789abcdef0123456789abcdef",
        )
        val runner = RecordingRunner(
            *Array(16) { index ->
                if (index % 2 == 0) {
                    DovecotCommandResult.success(mailboxStatus(mailboxState))
                } else {
                    DovecotCommandResult.success()
                }
            },
        )
        val adapter = DovecotProductAdapter(RecordingAccountRegistry(), runner)

        adapter.markRead("alice@local.test", "INBOX", listOf(7), mailboxState, true)
        adapter.markRead("alice@local.test", "INBOX", listOf(7), mailboxState, false)
        adapter.setFlagged("alice@local.test", "INBOX", listOf(7), mailboxState, true)
        adapter.setFlagged("alice@local.test", "INBOX", listOf(7), mailboxState, false)
        adapter.copyMessages("alice@local.test", "INBOX", listOf(7), mailboxState, "INBOX.Copy")
        adapter.moveMessages("alice@local.test", "INBOX", listOf(7), mailboxState, "INBOX.Archive")
        adapter.trashMessages("alice@local.test", "INBOX", listOf(7), mailboxState)
        adapter.deleteMessages("alice@local.test", "INBOX.Trash", listOf(7), mailboxState)

        assertEquals(
            listOf(
                doveadm("flags", "add", "-u", "alice@local.test", "\\Seen", "mailbox-guid", mailboxState.mailboxGuid, "uid", "7"),
                doveadm("flags", "remove", "-u", "alice@local.test", "\\Seen", "mailbox-guid", mailboxState.mailboxGuid, "uid", "7"),
                doveadm("flags", "add", "-u", "alice@local.test", "\\Flagged", "mailbox-guid", mailboxState.mailboxGuid, "uid", "7"),
                doveadm("flags", "remove", "-u", "alice@local.test", "\\Flagged", "mailbox-guid", mailboxState.mailboxGuid, "uid", "7"),
                doveadm("copy", "-u", "alice@local.test", "INBOX.Copy", "mailbox-guid", mailboxState.mailboxGuid, "uid", "7"),
                doveadm("move", "-u", "alice@local.test", "INBOX.Archive", "mailbox-guid", mailboxState.mailboxGuid, "uid", "7"),
                doveadm("move", "-u", "alice@local.test", "INBOX.Trash", "mailbox-guid", mailboxState.mailboxGuid, "uid", "7"),
                doveadm("expunge", "-u", "alice@local.test", "mailbox-guid", mailboxState.mailboxGuid, "uid", "7"),
            ),
            runner.requests.map(DovecotCommandRequest::argv).filterNot { argv ->
                argv.contains("status")
            },
        )
    }

    @Test
    fun changedUidValidityRejectsMutationBeforeTheUidCommand() {
        val expected = DovecotMailboxState(
            uidValidity = 1_234,
            mailboxGuid = "0123456789abcdef0123456789abcdef",
        )
        val changed = expected.copy(uidValidity = 1_235)
        val runner = RecordingRunner(
            DovecotCommandResult.success(mailboxStatus(changed)),
        )
        val adapter = DovecotProductAdapter(RecordingAccountRegistry(), runner)

        assertFailsWith<DovecotCommandException> {
            adapter.deleteMessages("alice@local.test", "INBOX", listOf(7), expected)
        }

        assertEquals(1, runner.requests.size)
        assertTrue(runner.requests.single().argv.contains("status"))
    }

    @Test
    fun changedUidValidityRejectsRawReadBeforeTheUidFetch() {
        val expected = DovecotMailboxState(
            uidValidity = 1_234,
            mailboxGuid = "0123456789abcdef0123456789abcdef",
        )
        val runner = RecordingRunner(
            DovecotCommandResult.success(mailboxStatus(expected.copy(uidValidity = 1_235))),
        )
        val adapter = DovecotProductAdapter(RecordingAccountRegistry(), runner)

        assertFailsWith<DovecotCommandException> {
            adapter.readRawMessage("alice@local.test", "INBOX", 7, expected)
        }

        assertEquals(1, runner.requests.size)
        assertTrue(runner.requests.single().argv.contains("status"))
    }

    @Test
    fun uidValidityRolloverDuringRawReadRejectsTheFetchedBody() {
        val expected = DovecotMailboxState(
            uidValidity = 1_234,
            mailboxGuid = "0123456789abcdef0123456789abcdef",
        )
        val runner = RecordingRunner(
            DovecotCommandResult.success(mailboxStatus(expected)),
            DovecotCommandResult.success("text: old body"),
            DovecotCommandResult.success(mailboxStatus(expected.copy(uidValidity = 1_235))),
        )
        val adapter = DovecotProductAdapter(RecordingAccountRegistry(), runner)

        assertFailsWith<DovecotCommandException> {
            adapter.readRawMessage("alice@local.test", "INBOX", 7, expected)
        }

        assertEquals(3, runner.requests.size)
    }

    @Test
    fun failedOrTimedOutCommandsAreReportedWithoutLeakingStdin() {
        val runner = RecordingRunner(
            DovecotCommandResult(
                exitCode = 23,
                timedOut = false,
                stdout = ByteArray(0),
                stderr = "mailbox missing".toByteArray(),
            ),
        )
        val adapter = DovecotProductAdapter(RecordingAccountRegistry(), runner)

        val failure = assertFailsWith<DovecotCommandException> {
            adapter.listFolders("alice@local.test")
        }

        assertTrue(failure.message.orEmpty().contains("mailbox missing"))
        assertTrue(!failure.message.orEmpty().contains("alice@local.test"))
    }

    @Test
    fun usersFileRegistryStoresPlainPasswordsAndRemovesOnlyAuthentication() {
        val root = createTempDirectory("dovecot-product-accounts").toRealPath()
        try {
            val users = root.resolve("config/users")
            users.parent.createDirectories()
            val mailbox = root.resolve("vmail/alice@local.test/Maildir").createDirectories()
            val sentinel = mailbox.resolve("message").also { it.writeText("preserve") }
            val registry = UsersFileDovecotAccountRegistry(DovecotUsersFile(users))

            registry.create("alice@local.test", "first".toByteArray())
            registry.changePassword("alice@local.test", "second".toByteArray())
            assertEquals(listOf("alice@local.test"), registry.list())
            assertEquals(
                "alice@local.test:{PLAIN}second::::::\n",
                users.toFile().readText(),
            )
            registry.delete("alice@local.test")

            assertEquals(emptyList(), registry.list())
            assertEquals("preserve", sentinel.toFile().readText())
        } finally {
            root.toFile().deleteRecursively()
        }
    }

    @Test
    fun jvmRunnerRoutesDoveadmAndLogsThroughOnlyTheRootComposeFile() {
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
                    listOf(
                        "docker", "compose", "logs", "--no-color", "--tail", "20",
                        "dovecot",
                    ),
                ),
            )

            val compose = root.resolve("docker-compose.yml").toString()
            assertEquals(
                listOf(
                    "docker", "compose", "-f", compose,
                    "exec", "-T", "dovecot", "doveadm", "user", "*",
                ),
                captured[0].argv,
            )
            assertEquals(
                listOf(
                    "docker", "compose", "-f", compose,
                    "logs", "--no-color", "--tail", "20", "dovecot",
                ),
                captured[1].argv,
            )
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

    private fun doveadm(vararg arguments: String): List<String> =
        listOf("docker", "compose", "exec", "-T", "dovecot", "doveadm") + arguments

    private fun missingUser(): DovecotCommandResult = DovecotCommandResult(
        exitCode = 67,
        timedOut = false,
        stdout = ByteArray(0),
        stderr = "user doesn't exist".toByteArray(),
    )

    private fun mailboxStatus(state: DovecotMailboxState): String =
        "mailbox: INBOX\nguid: ${state.mailboxGuid}\nuidvalidity: ${state.uidValidity}\n"

    private fun validEml(lineEnding: String = "\n"): String = listOf(
        "From: sender@local.test",
        "To: alice@local.test",
        "Date: Tue, 04 Aug 2026 10:00:00 +0000",
        "Subject: Reproduction",
        "Message-ID: <reproduction@local.test>",
        "MIME-Version: 1.0",
        "Content-Type: text/plain; charset=UTF-8",
        "",
        "Hello",
    ).joinToString(lineEnding)

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
    private val accounts = linkedSetOf<String>()

    override fun list(): List<String> = accounts.toList()

    override fun create(address: String, password: ByteArray) {
        calls += AccountCall.Create(address, password.toList())
        accounts += address
    }

    override fun changePassword(address: String, password: ByteArray) {
        calls += AccountCall.ChangePassword(address, password.toList())
    }

    override fun delete(address: String) {
        calls += AccountCall.Delete(address)
        accounts -= address
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
