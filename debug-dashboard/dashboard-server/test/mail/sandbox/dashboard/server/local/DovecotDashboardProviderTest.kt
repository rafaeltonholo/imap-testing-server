package mail.sandbox.dashboard.server.local

import kotlin.io.path.createTempDirectory
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import mail.sandbox.dashboard.contract.CreateAccountRequest
import mail.sandbox.dashboard.contract.GenerateMessageRequest
import mail.sandbox.dashboard.contract.MailProtocol
import mail.sandbox.dashboard.contract.MessageAction
import mail.sandbox.dashboard.contract.MessageDeliveryMode
import mail.sandbox.dashboard.contract.MessageSourceType
import mail.sandbox.dashboard.contract.MutateMessagesRequest
import mail.sandbox.dashboard.contract.Provider
import mail.sandbox.dashboard.server.provider.AccountCredentials
import mail.sandbox.dashboard.server.provider.AuthenticationOutcome
import mail.sandbox.dashboard.server.provider.dovecot.DovecotAccountRegistry
import mail.sandbox.dashboard.server.provider.dovecot.DovecotCommandRequest
import mail.sandbox.dashboard.server.provider.dovecot.DovecotCommandResult
import mail.sandbox.dashboard.server.provider.dovecot.DovecotCommandRunner
import mail.sandbox.dashboard.server.provider.dovecot.DovecotFolder
import mail.sandbox.dashboard.server.provider.dovecot.DovecotImapClient
import mail.sandbox.dashboard.server.provider.dovecot.DovecotImapStoreFactory
import mail.sandbox.dashboard.server.provider.dovecot.DovecotMailboxClient
import mail.sandbox.dashboard.server.provider.dovecot.DovecotMailboxState
import mail.sandbox.dashboard.server.provider.dovecot.DovecotMessageCommand
import mail.sandbox.dashboard.server.provider.dovecot.DovecotMessageSummary
import mail.sandbox.dashboard.server.provider.dovecot.DovecotProductAdapter

class DovecotDashboardProviderTest {
    @Test
    fun activePlainPasswordBeatsTheStaleCatalogForMailboxWork() = runBlocking {
        val directory = createTempDirectory("dovecot-dashboard-authority").toRealPath()
        try {
            val catalog = LocalAccountCatalog(directory.resolve("accounts.json"))
            catalog.put(
                LocalAccountRecord(
                    Provider.DOVECOT,
                    "alice@local.test",
                    "stale-catalog-password",
                    ALL_PROTOCOLS,
                ),
            )
            val registry = MutablePlainAccountRegistry("authority-password")
            val runner = QueueRunner()
            val mailbox = RecordingMailboxClient()
            val provider = DovecotDashboardProvider(
                adapter = DovecotProductAdapter(registry, runner),
                catalog = catalog,
                mailboxClient = mailbox,
            )

            provider.listFolders("alice@local.test")

            assertTrue(mailbox.credentials.isNotEmpty())
            assertTrue(mailbox.credentials.all { it.password == "authority-password" })
            assertTrue(mailbox.credentials.none { it.password == "stale-catalog-password" })
            assertTrue(runner.requests.isEmpty())
        } finally {
            directory.toFile().deleteRecursively()
        }
    }

    @Test
    fun createRequiresTheExactServerWideCapabilitiesAndBootstrapsFoldersAsTheUser() =
        runBlocking {
            val directory = createTempDirectory("dovecot-dashboard-create-imap").toRealPath()
            try {
                val registry = MutablePlainAccountRegistry()
                val runner = QueueRunner(DovecotCommandResult.success())
                val mailbox = RecordingMailboxClient(folders = mutableListOf(DovecotFolder("INBOX")))
                val provider = DovecotDashboardProvider(
                    adapter = DovecotProductAdapter(registry, runner),
                    catalog = LocalAccountCatalog(directory.resolve("accounts.json")),
                    mailboxClient = mailbox,
                )

                assertFailsWith<IllegalArgumentException> {
                    provider.createAccount(
                        CreateAccountRequest(
                            "subset@local.test",
                            "password",
                            Provider.DOVECOT,
                            listOf(MailProtocol.IMAP, MailProtocol.SMTP),
                        ),
                    )
                }
                val account = provider.createAccount(
                    CreateAccountRequest(
                        "alice@local.test",
                        "new-password",
                        Provider.DOVECOT,
                        ALL_PROTOCOLS,
                    ),
                )

                assertEquals(ALL_PROTOCOLS, account.protocols)
                assertEquals(
                    listOf("INBOX.Drafts", "INBOX.Sent", "INBOX.Trash"),
                    mailbox.created.sorted(),
                )
                assertTrue(mailbox.credentials.all {
                    it == AccountCredentials("alice@local.test", "new-password")
                })
                assertTrue(runner.requests.all { "mailbox" !in it.argv })
            } finally {
                directory.toFile().deleteRecursively()
            }
        }

    @Test
    fun passwordChangeMustLogInAsTheUserWithTheChangedPassword() = runBlocking {
        val directory = createTempDirectory("dovecot-dashboard-password-imap").toRealPath()
        try {
            val registry = MutablePlainAccountRegistry("old-password")
            val runner = QueueRunner(DovecotCommandResult.success())
            val mailbox = RecordingMailboxClient()
            val provider = DovecotDashboardProvider(
                adapter = DovecotProductAdapter(registry, runner),
                catalog = LocalAccountCatalog(directory.resolve("accounts.json")),
                mailboxClient = mailbox,
            )

            provider.changePassword("alice@local.test", "changed-password")

            assertEquals(
                AccountCredentials("alice@local.test", "changed-password"),
                mailbox.probed.single(),
            )
            assertTrue(runner.requests.all { "mailbox" !in it.argv })
        } finally {
            directory.toFile().deleteRecursively()
        }
    }

    @Test
    fun passwordChangeDoesNotReportSuccessWhenOrdinaryAuthenticationFails() = runBlocking {
        listOf<AuthenticationOutcome>(
            AuthenticationOutcome.WrongPassword("authentication failed"),
            AuthenticationOutcome.Unavailable("provider unavailable"),
        ).forEachIndexed { index, outcome ->
            val directory = createTempDirectory("dovecot-dashboard-password-failure-$index")
                .toRealPath()
            try {
                val catalog = LocalAccountCatalog(directory.resolve("accounts.json"))
                catalog.put(
                    LocalAccountRecord(
                        Provider.DOVECOT,
                        "alice@local.test",
                        "old-password",
                        ALL_PROTOCOLS,
                    ),
                )
                val registry = MutablePlainAccountRegistry("old-password")
                val provider = DovecotDashboardProvider(
                    adapter = DovecotProductAdapter(
                        registry,
                        QueueRunner(DovecotCommandResult.success()),
                    ),
                    catalog = catalog,
                    mailboxClient = RecordingMailboxClient(probeOutcome = outcome),
                )

                assertFailsWith<IllegalStateException> {
                    provider.changePassword("alice@local.test", "changed-password")
                }

                assertEquals("changed-password", registry.plainPassword("alice@local.test"))
                assertEquals(
                    "old-password",
                    catalog.find(Provider.DOVECOT, "alice@local.test")?.password,
                )
            } finally {
                directory.toFile().deleteRecursively()
            }
        }
    }

    @Test
    fun liveDovecotCapabilitiesIgnoreAStaleCatalogSubset() = runBlocking {
        val directory = createTempDirectory("dovecot-dashboard-fixed-capabilities").toRealPath()
        try {
            val catalog = LocalAccountCatalog(directory.resolve("accounts.json"))
            catalog.put(
                LocalAccountRecord(
                    Provider.DOVECOT,
                    "alice@local.test",
                    "password",
                    listOf(MailProtocol.IMAP),
                ),
            )
            val provider = DovecotDashboardProvider(
                adapter = DovecotProductAdapter(
                    MutablePlainAccountRegistry("password"),
                    QueueRunner(),
                ),
                catalog = catalog,
                mailboxClient = RecordingMailboxClient(),
            )

            assertEquals(ALL_PROTOCOLS, provider.listAccounts().single().protocols)
        } finally {
            directory.toFile().deleteRecursively()
        }
    }

    @Test
    fun userFacingMailboxOperationsNeverInvokeDoveadm() = runBlocking {
        val directory = createTempDirectory("dovecot-dashboard-mailbox-boundary").toRealPath()
        try {
            val runner = QueueRunner()
            val mailbox = RecordingMailboxClient()
            val provider = DovecotDashboardProvider(
                adapter = DovecotProductAdapter(
                    MutablePlainAccountRegistry("authority-password"),
                    runner,
                ),
                catalog = LocalAccountCatalog(directory.resolve("accounts.json")),
                mailboxClient = mailbox,
            )

            provider.listFolders("alice@local.test")
            provider.createFolder("alice@local.test", "Archive")
            provider.deleteFolder("alice@local.test", "INBOX.Archive")
            provider.listMessages("alice@local.test", "INBOX")
            provider.readMessage("alice@local.test", "7", "INBOX")
            provider.mutateMessages(
                "alice@local.test",
                MutateMessagesRequest(
                    account = "alice@local.test",
                    provider = Provider.DOVECOT,
                    messageIds = listOf("7"),
                    mutationStates = mapOf("7" to TEST_MAILBOX_STATE.encode()),
                    action = MessageAction.MARK_READ,
                    sourceFolderId = "INBOX",
                ),
            )

            assertTrue(runner.requests.isEmpty())
            assertTrue(mailbox.credentials.all { it.password == "authority-password" })
            assertEquals(1, mailbox.commands.size)
        } finally {
            directory.toFile().deleteRecursively()
        }
    }

    @Test
    fun logSelectorResolvesTheRegisteredCanonicalAddress() = runBlocking {
        val directory = createTempDirectory("dovecot-dashboard-log-selector").toRealPath()
        try {
            val provider = DovecotDashboardProvider(
                adapter = DovecotProductAdapter(SingleAccount, QueueRunner()),
                catalog = LocalAccountCatalog(directory.resolve("accounts.json")),
            )

            assertEquals(
                DashboardLogAccount("alice@local.test"),
                provider.dashboardLogAccount("ALICE@LOCAL.TEST"),
            )
        } finally {
            directory.toFile().deleteRecursively()
        }
    }

    @Test
    fun defaultMailboxAccountLookupUsesTheCanonicalDovecotRegistry() {
        val adapter = DovecotProductAdapter(
            MutablePlainAccountRegistry("password"),
            QueueRunner(),
        )
        val lookup = DovecotAccountExistence(adapter)
        val client = DovecotImapClient(
            storeFactory = DovecotImapStoreFactory {
                error("Authentication classification must not open a mailbox store")
            },
            authenticationProbe = {
                AuthenticationOutcome.WrongPassword("generic authentication failure")
            },
            accountExists = lookup::contains,
        )

        assertTrue(
            client.probe(AccountCredentials("alice@local.test", "wrong-password")) is
                AuthenticationOutcome.WrongPassword,
        )
        assertTrue(
            client.probe(AccountCredentials("missing@local.test", "wrong-password")) is
                AuthenticationOutcome.MissingAccount,
        )
    }

    @Test
    fun messageReadReturnsDecodedPlainAndHtmlMimeBodies() = runBlocking {
        val raw = lines(
            "Subject: Provider reproduction",
            "From: Sender <sender@example.net>",
            "To: alice@local.test",
            "Date: Wed, 05 Aug 2026 12:00:00 +0000",
            "Content-Type: multipart/alternative; boundary=body",
            "",
            "--body",
            "Content-Type: text/plain; charset=UTF-8",
            "Content-Transfer-Encoding: base64",
            "",
            "cmVhZGFibGUgcGxhaW4=",
            "--body",
            "Content-Type: text/html; charset=UTF-8",
            "Content-Transfer-Encoding: quoted-printable",
            "",
            "<p>readable=20html</p>",
            "--body--",
        )
        val mailbox = RecordingMailboxClient(
            messageSnapshots = listOf(
                listOf(
                    fixtureSummary(
                        uid = 42,
                        messageId = "<message-42@example.net>",
                        subject = "Provider reproduction",
                        flags = setOf("\\Seen"),
                    ),
                ),
            ),
            rawMessage = raw,
        )
        val directory = createTempDirectory("dovecot-dashboard-read").toRealPath()
        try {
            val provider = DovecotDashboardProvider(
                adapter = DovecotProductAdapter(
                    MutablePlainAccountRegistry("password"),
                    QueueRunner(),
                ),
                catalog = LocalAccountCatalog(directory.resolve("accounts.json")),
                mailboxClient = mailbox,
            )

            val detail = provider.readMessage("alice@local.test", "42", "INBOX")

            assertEquals("Provider reproduction", detail.subject)
            assertEquals("readable plain", detail.textBody)
            assertEquals("<p>readable html</p>", detail.htmlBody)
        } finally {
            directory.toFile().deleteRecursively()
        }
    }

    @Test
    fun expectedMessageIdDoesNotFallBackToAnUnrelatedSingletonArrival() = runBlocking {
        val raw = lines(
            "From: sender@local.test",
            "To: alice@local.test",
            "Date: Wed, 05 Aug 2026 12:00:00 +0000",
            "Subject: Correlated fixture",
            "Message-ID: <dashboard-correlated@local.test>",
            "Content-Type: text/plain; charset=UTF-8",
            "",
            "body",
        )
        val runner = QueueRunner(DovecotCommandResult.success())
        val unrelated = fixtureSummary(
            uid = 52,
            messageId = "<unrelated-concurrent@local.test>",
            subject = "Concurrent delivery",
        )
        val correlated = fixtureSummary(
            uid = 51,
            messageId = "<dashboard-correlated@local.test>",
            subject = "Correlated fixture",
        )
        val mailbox = RecordingMailboxClient(
            messageSnapshots = listOf(emptyList(), listOf(unrelated), listOf(correlated, unrelated)),
        )
        val directory = createTempDirectory("dovecot-dashboard-inject").toRealPath()
        try {
            val provider = DovecotDashboardProvider(
                adapter = DovecotProductAdapter(
                    MutablePlainAccountRegistry("password"),
                    runner,
                ),
                catalog = LocalAccountCatalog(directory.resolve("accounts.json")),
                mailboxClient = mailbox,
            )

            val ids = provider.injectMessages(
                GenerateMessageRequest(
                    targetAccount = "alice@local.test",
                    provider = Provider.DOVECOT,
                    sourceType = MessageSourceType.EML,
                    content = raw,
                ),
                listOf(GeneratedMessage(raw)),
            )

            assertEquals(listOf("51"), ids)
        } finally {
            directory.toFile().deleteRecursively()
        }
    }

    @Test
    fun smtpDeliveryUsesPostfixAndReturnsTheArrivedInboxUid() = runBlocking {
        val raw = lines(
            "From: sender@local.test",
            "To: alice@local.test",
            "Date: Wed, 05 Aug 2026 12:00:00 +0000",
            "Subject: SMTP fixture",
            "Message-ID: <smtp-correlated@local.test>",
            "",
            "body",
        )
        val mailbox = RecordingMailboxClient(
            messageSnapshots = listOf(
                emptyList(),
                listOf(
                    fixtureSummary(
                        uid = 61,
                        messageId = "<smtp-correlated@local.test>",
                        subject = "SMTP fixture",
                    ),
                ),
            ),
        )
        val smtp = RecordingSmtpSender()
        val directory = createTempDirectory("dovecot-dashboard-smtp").toRealPath()
        try {
            val catalog = LocalAccountCatalog(directory.resolve("accounts.json"))
            catalog.put(
                LocalAccountRecord(
                    Provider.DOVECOT,
                    "alice@local.test",
                    "password",
                    listOf(MailProtocol.IMAP, MailProtocol.SMTP),
                ),
            )
            val provider = DovecotDashboardProvider(
                adapter = DovecotProductAdapter(SingleAccount, QueueRunner()),
                catalog = catalog,
                mailboxClient = mailbox,
                smtpSender = smtp,
            )

            val ids = provider.deliverMessages(
                GenerateMessageRequest(
                    targetAccount = "alice@local.test",
                    provider = Provider.DOVECOT,
                    sourceType = MessageSourceType.EML,
                    deliveryMode = MessageDeliveryMode.SMTP_DELIVERY,
                    content = raw,
                ),
                listOf(GeneratedMessage(raw)),
            )

            assertEquals(listOf("61"), ids)
            assertEquals(
                SmtpCall("alice@local.test", "alice@local.test", raw, null),
                smtp.calls.single(),
            )
        } finally {
            directory.toFile().deleteRecursively()
        }
    }

    private fun lines(vararg values: String): String = values.joinToString("\r\n")

    companion object {
        val ALL_PROTOCOLS = listOf(MailProtocol.IMAP, MailProtocol.POP3, MailProtocol.SMTP)
    }
}

private val TEST_MAILBOX_STATE = DovecotMailboxState(uidValidity = 4_242)

private object EmptyAccounts : DovecotAccountRegistry {
    override fun list(): List<String> = emptyList()

    override fun create(
        address: String,
        password: ByteArray,
        verifyProjection: () -> Unit,
    ) = verifyProjection()

    override fun changePassword(
        address: String,
        password: ByteArray,
        verifyProjection: () -> Unit,
    ) = verifyProjection()

    override fun delete(address: String, verifyProjection: () -> Unit) = verifyProjection()
}

private object SingleAccount : DovecotAccountRegistry by EmptyAccounts {
    override fun list(): List<String> = listOf("alice@local.test")
}

private class MutablePlainAccountRegistry(
    initialPassword: String? = null,
) : DovecotAccountRegistry {
    private val passwords = linkedMapOf<String, String>().apply {
        if (initialPassword != null) put("alice@local.test", initialPassword)
    }

    override fun list(): List<String> = passwords.keys.toList()

    override fun plainPassword(address: String): String? = passwords[address]

    override fun create(
        address: String,
        password: ByteArray,
        verifyProjection: () -> Unit,
    ) {
        passwords[address] = password.decodeToString()
        verifyProjection()
    }

    override fun changePassword(
        address: String,
        password: ByteArray,
        verifyProjection: () -> Unit,
    ) {
        passwords[address] = password.decodeToString()
        verifyProjection()
    }

    override fun delete(address: String, verifyProjection: () -> Unit) {
        passwords.remove(address)
        verifyProjection()
    }
}

private class RecordingMailboxClient(
    val folders: MutableList<DovecotFolder> = mutableListOf(DovecotFolder("INBOX")),
    messageSnapshots: List<List<DovecotMessageSummary>> = emptyList(),
    private val rawMessage: String = fixtureRawMessage(),
    private val probeOutcome: AuthenticationOutcome =
        AuthenticationOutcome.Authenticated("authenticated"),
) : DovecotMailboxClient {
    private val messageSnapshots = ArrayDeque(messageSnapshots)
    private var lastMessageSnapshot: List<DovecotMessageSummary>? = null
    val credentials = mutableListOf<AccountCredentials>()
    val probed = mutableListOf<AccountCredentials>()
    val created = mutableListOf<String>()
    val commands = mutableListOf<DovecotMessageCommand>()

    override fun probe(credentials: AccountCredentials): AuthenticationOutcome {
        this.credentials += credentials
        probed += credentials
        return probeOutcome
    }

    override fun listFolders(credentials: AccountCredentials): List<DovecotFolder> {
        this.credentials += credentials
        return folders.toList()
    }

    override fun createFolder(
        credentials: AccountCredentials,
        name: String,
    ): DovecotFolder {
        this.credentials += credentials
        created += name
        return DovecotFolder(name).also(folders::add)
    }

    override fun deleteFolder(credentials: AccountCredentials, id: String) {
        this.credentials += credentials
        folders.removeAll { it.name == id }
    }

    override fun listMessages(
        credentials: AccountCredentials,
        folder: String,
    ): List<DovecotMessageSummary> {
        this.credentials += credentials
        val next = messageSnapshots.removeFirstOrNull()
        if (next != null) lastMessageSnapshot = next
        return next ?: lastMessageSnapshot ?: listOf(fixtureSummary())
    }

    override fun readMessage(
        credentials: AccountCredentials,
        folder: String,
        uid: Long,
    ): String {
        this.credentials += credentials
        return rawMessage
    }

    override fun mutate(credentials: AccountCredentials, command: DovecotMessageCommand) {
        this.credentials += credentials
        commands += command
    }
}

private fun fixtureSummary(
    uid: Long = 7,
    messageId: String = "<fixture@local.test>",
    subject: String = "Fixture",
    flags: Set<String> = emptySet(),
): DovecotMessageSummary = DovecotMessageSummary(
    uid = uid,
    mailboxState = TEST_MAILBOX_STATE,
    messageId = messageId,
    subject = subject,
    from = "sender@local.test",
    date = "Tue, 11 Aug 2026 10:00:00 +0000",
    flags = flags,
)

private fun fixtureRawMessage(): String = listOf(
    "From: sender@local.test",
    "To: alice@local.test",
    "Date: Tue, 11 Aug 2026 10:00:00 +0000",
    "Subject: Fixture",
    "Message-ID: <fixture@local.test>",
    "",
    "body",
).joinToString("\r\n")

private data class SmtpCall(
    val envelopeFrom: String,
    val envelopeRecipient: String,
    val rawMessage: String,
    val credentials: LocalSmtpCredentials?,
)

private class RecordingSmtpSender : LocalSmtpSender {
    val calls = mutableListOf<SmtpCall>()

    override fun send(
        envelopeFrom: String,
        envelopeRecipient: String,
        rawMessage: String,
        credentials: LocalSmtpCredentials?,
    ): LocalSmtpSendResult {
        calls += SmtpCall(envelopeFrom, envelopeRecipient, rawMessage, credentials)
        return LocalSmtpSendResult(250, "queued as TEST", "TEST")
    }
}

private class QueueRunner(
    vararg results: DovecotCommandResult,
) : DovecotCommandRunner {
    private val results = ArrayDeque(results.toList())
    val requests = mutableListOf<DovecotCommandRequest>()

    override fun run(request: DovecotCommandRequest): DovecotCommandResult {
        requests += request.copy(stdin = request.stdin.copyOf())
        if ("status" in request.argv) {
            return DovecotCommandResult.success(
                "mailbox: INBOX\n" +
                    "guid: 0123456789abcdef0123456789abcdef\n" +
                    "uidvalidity: 1234\n",
            )
        }
        return results.removeFirstOrNull() ?: error("No Dovecot result configured")
    }
}
