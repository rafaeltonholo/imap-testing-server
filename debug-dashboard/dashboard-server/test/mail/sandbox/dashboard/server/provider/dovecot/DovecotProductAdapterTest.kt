package mail.sandbox.dashboard.server.provider.dovecot

import mail.sandbox.dashboard.server.gate.dovecot.EligibilityFile
import mail.sandbox.dashboard.server.gate.dovecot.EligibilityPasswordHasher
import mail.sandbox.dashboard.server.gate.dovecot.EligibilityPaths
import java.nio.charset.StandardCharsets
import java.nio.file.Files
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
    fun accountsAreManagedThroughTheEligibilityRegistry() {
        val registry = RecordingAccountRegistry()
        val runner = RecordingRunner(*Array(5) { DovecotCommandResult.success() })
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
                doveadm("reload"),
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
                doveadm("reload"),
                doveadm("reload"),
            ),
            runner.requests.map(DovecotCommandRequest::argv),
        )
    }

    @Test
    fun failedMailboxBootstrapRollsBackTheNewEligibilityAccount() {
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
            DovecotCommandResult.success(),
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
            DovecotCommandResult.success(),
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
                doveadm("reload"),
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
                doveadm("reload"),
                doveadm("reload"),
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
    fun eligibilityRegistryHashesAddsResetsAndRemovesAccounts() {
        val root = createTempDirectory("dovecot-product-accounts").toRealPath()
        try {
            root.resolve("debug-dashboard").createDirectories()
            root.resolve("config").createDirectories()
            root.resolve("docker-compose.yml").writeText("services: {}\n")
            root.resolve("debug-dashboard/project.yaml").writeText("modules: []\n")
            root.resolve("config/users.seed").writeText("seed@local.test\n")
            val file = EligibilityFile(EligibilityPaths.testing(root))
            val seenPasswords = mutableListOf<String>()
            val registry = EligibilityDovecotAccountRegistry(
                file,
                EligibilityPasswordHasher { password ->
                    seenPasswords += password.withBytes {
                        String(it, StandardCharsets.UTF_8)
                    }
                    HASH
                },
            )

            registry.create("alice@local.test", "first".toByteArray())
            registry.changePassword("alice@local.test", "second".toByteArray())
            assertEquals(listOf("alice@local.test"), registry.list())
            registry.delete("alice@local.test")

            assertEquals(listOf("first", "second"), seenPasswords)
            assertEquals(emptyList(), registry.list())
        } finally {
            root.toFile().deleteRecursively()
        }
    }

    private fun doveadm(vararg arguments: String): List<String> =
        listOf("docker", "compose", "exec", "-T", "dovecot", "doveadm") + arguments

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

    private companion object {
        const val HASH =
            "{ARGON2ID}\$argon2id\$v=19\$m=65536,t=3,p=1\$YWJjZA\$ZWZnaA"
    }
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
