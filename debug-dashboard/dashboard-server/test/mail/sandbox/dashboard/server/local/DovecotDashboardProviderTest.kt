package mail.sandbox.dashboard.server.local

import kotlin.io.path.createTempDirectory
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import mail.sandbox.dashboard.contract.GenerateMessageRequest
import mail.sandbox.dashboard.contract.MailProtocol
import mail.sandbox.dashboard.contract.MessageDeliveryMode
import mail.sandbox.dashboard.contract.MessageSourceType
import mail.sandbox.dashboard.contract.Provider
import mail.sandbox.dashboard.server.provider.dovecot.DovecotAccountRegistry
import mail.sandbox.dashboard.server.provider.dovecot.DovecotCommandRequest
import mail.sandbox.dashboard.server.provider.dovecot.DovecotCommandResult
import mail.sandbox.dashboard.server.provider.dovecot.DovecotCommandRunner
import mail.sandbox.dashboard.server.provider.dovecot.DovecotProductAdapter

class DovecotDashboardProviderTest {
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
        val runner = QueueRunner(
            DovecotCommandResult.success(
                lines(
                    "uid: 42",
                    "flags: \\Seen",
                    "hdr.message-id: <message-42@example.net>",
                    "hdr.subject: Provider reproduction",
                    "hdr.from: Sender <sender@example.net>",
                    "hdr.date: Wed, 05 Aug 2026 12:00:00 +0000",
                ),
            ),
            DovecotCommandResult.success("text: $raw"),
        )
        val directory = createTempDirectory("dovecot-dashboard-read").toRealPath()
        try {
            val provider = DovecotDashboardProvider(
                adapter = DovecotProductAdapter(EmptyAccounts, runner),
                catalog = LocalAccountCatalog(directory.resolve("accounts.json")),
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
        val runner = QueueRunner(
            DovecotCommandResult.success(),
            DovecotCommandResult.success(),
            DovecotCommandResult.success(
                lines(
                    "uid: 52",
                    "flags:",
                    "hdr.message-id: <unrelated-concurrent@local.test>",
                    "hdr.subject: Concurrent delivery",
                    "hdr.from: sender@local.test",
                    "hdr.date: Wed, 05 Aug 2026 12:00:01 +0000",
                ),
            ),
            DovecotCommandResult.success(
                lines(
                    "uid: 51",
                    "flags:",
                    "hdr.message-id: <dashboard-correlated@local.test>",
                    "hdr.subject: Correlated fixture",
                    "hdr.from: sender@local.test",
                    "hdr.date: Wed, 05 Aug 2026 12:00:00 +0000",
                    "\u000c",
                    "uid: 52",
                    "flags:",
                    "hdr.message-id: <unrelated-concurrent@local.test>",
                    "hdr.subject: Concurrent delivery",
                    "hdr.from: sender@local.test",
                    "hdr.date: Wed, 05 Aug 2026 12:00:01 +0000",
                ),
            ),
        )
        val directory = createTempDirectory("dovecot-dashboard-inject").toRealPath()
        try {
            val provider = DovecotDashboardProvider(
                adapter = DovecotProductAdapter(EmptyAccounts, runner),
                catalog = LocalAccountCatalog(directory.resolve("accounts.json")),
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
        val runner = QueueRunner(
            DovecotCommandResult.success(),
            DovecotCommandResult.success(
                lines(
                    "uid: 61",
                    "flags:",
                    "hdr.message-id: <smtp-correlated@local.test>",
                    "hdr.subject: SMTP fixture",
                    "hdr.from: sender@local.test",
                    "hdr.date: Wed, 05 Aug 2026 12:00:00 +0000",
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
                adapter = DovecotProductAdapter(SingleAccount, runner),
                catalog = catalog,
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
}

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

    override fun run(request: DovecotCommandRequest): DovecotCommandResult {
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
