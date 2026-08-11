package mail.sandbox.dashboard.server.local

import java.io.BufferedInputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.util.Base64
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

class LocalSmtpClientTest {
    @Test
    fun sendsRawMessageWithCrlfDotStuffingAndReturnsPostfixQueueId() {
        var receivedData = emptyList<String>()
        ScriptedSmtpServer { smtp ->
            smtp.reply("220 postfix.local.test ESMTP")
            assertEquals("EHLO debug-dashboard.local.test", smtp.readLine())
            smtp.reply(
                "250-postfix.local.test",
                "250-PIPELINING",
                "250 SIZE 5242880",
            )
            assertEquals("MAIL FROM:<sender@local.test>", smtp.readLine())
            smtp.reply("250 2.1.0 Ok")
            assertEquals("RCPT TO:<alice@local.test>", smtp.readLine())
            smtp.reply("250 2.1.5 Ok")
            assertEquals("DATA", smtp.readLine())
            smtp.reply("354 End data with <CR><LF>.<CR><LF>")
            receivedData = smtp.readData()
            smtp.reply("250 2.0.0 Ok: queued as POSTFIX42")
            assertEquals("QUIT", smtp.readLine())
            smtp.reply("221 2.0.0 Bye")
        }.use { server ->
            val client = LocalSmtpClient(
                endpoint = LocalSmtpEndpoint.POSTFIX,
                connectTimeout = Duration.ofMillis(250),
                readTimeout = Duration.ofMillis(500),
                connector = server.connector,
            )
            val rawMessage =
                "From: sender@local.test\n" +
                    "To: alice@local.test\r" +
                    "Subject: SMTP reproduction\r\n" +
                    "Message-ID: <smtp-reproduction@local.test>\n" +
                    "\n" +
                    "first line\r\n" +
                    ".second line\n" +
                    "..third line"

            val result = client.send(
                envelopeFrom = "sender@local.test",
                envelopeRecipient = "alice@local.test",
                rawMessage = rawMessage,
            )
            server.await()

            assertEquals(250, result.responseCode)
            assertEquals("2.0.0 Ok: queued as POSTFIX42", result.acceptanceText)
            assertEquals("POSTFIX42", result.queueId)
            assertEquals(
                listOf(
                    "From: sender@local.test",
                    "To: alice@local.test",
                    "Subject: SMTP reproduction",
                    "Message-ID: <smtp-reproduction@local.test>",
                    "",
                    "first line",
                    "..second line",
                    "...third line",
                ),
                receivedData,
            )
            assertEquals(
                ConnectionRequest("127.0.0.1", 21025, 250, 500),
                server.connectionRequest,
            )
        }
    }

    @Test
    fun authenticatesWithPlainAndUsesTheFixedStalwartEndpoint() {
        var authPayload = ""
        ScriptedSmtpServer { smtp ->
            smtp.reply("220 stalwart.local.test ESMTP")
            assertEquals("EHLO debug-dashboard.local.test", smtp.readLine())
            smtp.reply(
                "250-stalwart.local.test",
                "250-AUTH PLAIN",
                "250 SIZE 5242880",
            )
            val auth = smtp.readLine()
            assertTrue(auth.startsWith("AUTH PLAIN "))
            authPayload = String(
                Base64.getDecoder().decode(auth.substringAfter("AUTH PLAIN ")),
                StandardCharsets.UTF_8,
            )
            smtp.reply("235 2.7.0 Authentication successful")
            assertEquals("MAIL FROM:<sender@local.test>", smtp.readLine())
            smtp.reply("250 2.1.0 Sender accepted")
            assertEquals("RCPT TO:<alice@local.test>", smtp.readLine())
            smtp.reply("250 2.1.5 Recipient accepted")
            assertEquals("DATA", smtp.readLine())
            smtp.reply("354 Start mail input")
            smtp.readData()
            smtp.reply("250 2.0.0 Message accepted for delivery")
            assertEquals("QUIT", smtp.readLine())
            smtp.reply("221 2.0.0 Bye")
        }.use { server ->
            val client = LocalSmtpClient(
                endpoint = LocalSmtpEndpoint.STALWART,
                connector = server.connector,
            )

            val result = client.send(
                envelopeFrom = "sender@local.test",
                envelopeRecipient = "alice@local.test",
                rawMessage = validMessage(),
                credentials = LocalSmtpCredentials(
                    username = "alice@local.test",
                    password = "debug-password",
                ),
            )
            server.await()

            assertEquals("\u0000alice@local.test\u0000debug-password", authPayload)
            assertEquals("2.0.0 Message accepted for delivery", result.acceptanceText)
            assertNull(result.queueId)
            assertEquals("127.0.0.1", server.connectionRequest?.host)
            assertEquals(8587, server.connectionRequest?.port)
        }
    }

    @Test
    fun acceptedMessageSurvivesServerDisconnectBeforeQuitReply() {
        ScriptedSmtpServer { smtp ->
            smtp.reply("220 postfix.local.test ESMTP")
            assertEquals("EHLO debug-dashboard.local.test", smtp.readLine())
            smtp.reply("250 postfix.local.test")
            assertEquals("MAIL FROM:<sender@local.test>", smtp.readLine())
            smtp.reply("250 2.1.0 Ok")
            assertEquals("RCPT TO:<alice@local.test>", smtp.readLine())
            smtp.reply("250 2.1.5 Ok")
            assertEquals("DATA", smtp.readLine())
            smtp.reply("354 Start mail input")
            smtp.readData()
            smtp.reply("250 2.0.0 Ok: queued as ACCEPTED42")
        }.use { server ->
            val result = LocalSmtpClient(
                endpoint = LocalSmtpEndpoint.POSTFIX,
                connector = server.connector,
            ).send(
                envelopeFrom = "sender@local.test",
                envelopeRecipient = "alice@local.test",
                rawMessage = validMessage(),
            )
            server.await()

            assertEquals(250, result.responseCode)
            assertEquals("ACCEPTED42", result.queueId)
        }
    }

    @Test
    fun exposesTheRejectedSmtpStageAndReplyWithoutSendingData() {
        ScriptedSmtpServer { smtp ->
            smtp.reply("220 postfix.local.test ESMTP")
            smtp.readLine()
            smtp.reply("250 postfix.local.test")
            smtp.readLine()
            smtp.reply("250 2.1.0 Ok")
            assertEquals("RCPT TO:<missing@local.test>", smtp.readLine())
            smtp.reply("550 5.1.1 User unknown")
        }.use { server ->
            val client = LocalSmtpClient(
                endpoint = LocalSmtpEndpoint.POSTFIX,
                connector = server.connector,
            )

            val failure = assertFailsWith<LocalSmtpException> {
                client.send(
                    envelopeFrom = "sender@local.test",
                    envelopeRecipient = "missing@local.test",
                    rawMessage = validMessage(),
                )
            }
            server.await()

            assertEquals(LocalSmtpStage.RCPT_TO, failure.stage)
            assertEquals(550, failure.responseCode)
            assertEquals("5.1.1 User unknown", failure.responseText)
        }
    }

    @Test
    fun rejectsInvalidEnvelopeCredentialsMessagesAndTimeoutsBeforeConnecting() {
        var connectionAttempts = 0
        val connector = LocalSmtpSocketConnector { _, _, _, _ ->
            connectionAttempts += 1
            error("The invalid request must not connect")
        }
        val client = LocalSmtpClient(LocalSmtpEndpoint.POSTFIX, connector = connector)

        listOf(
            "Sender@local.test" to "alice@local.test",
            "sender@example.net" to "alice@local.test",
            "sender@local.test" to "alice command@local.test",
        ).forEach { (sender, recipient) ->
            assertFailsWith<IllegalArgumentException> {
                client.send(sender, recipient, validMessage())
            }
        }
        assertFailsWith<IllegalArgumentException> {
            client.send("sender@local.test", "alice@local.test", "header without body")
        }
        assertFailsWith<IllegalArgumentException> {
            client.send(
                "sender@local.test",
                "alice@local.test",
                validMessage() + "\u0000",
            )
        }
        assertFailsWith<IllegalArgumentException> {
            client.send(
                "sender@local.test",
                "alice@local.test",
                validMessage() + "x".repeat(5 * 1024 * 1024),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            client.send(
                "sender@local.test",
                "alice@local.test",
                validMessage(),
                LocalSmtpCredentials("alice@example.net", "password"),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            client.send(
                "sender@local.test",
                "alice@local.test",
                validMessage(),
                LocalSmtpCredentials("alice@local.test", "bad\npassword"),
            )
        }

        listOf(Duration.ZERO, Duration.ofSeconds(31)).forEach { invalid ->
            assertFailsWith<IllegalArgumentException> {
                LocalSmtpClient(
                    LocalSmtpEndpoint.POSTFIX,
                    connectTimeout = invalid,
                    connector = connector,
                )
            }
            assertFailsWith<IllegalArgumentException> {
                LocalSmtpClient(
                    LocalSmtpEndpoint.POSTFIX,
                    readTimeout = invalid,
                    connector = connector,
                )
            }
        }
        assertEquals(0, connectionAttempts)
    }

    private fun validMessage(): String =
        "From: sender@local.test\r\n" +
            "To: alice@local.test\r\n" +
            "Date: Wed, 05 Aug 2026 12:00:00 +0000\r\n" +
            "Subject: SMTP reproduction\r\n" +
            "Message-ID: <smtp-reproduction@local.test>\r\n" +
            "\r\n" +
            "SMTP body"
}

private data class ConnectionRequest(
    val host: String,
    val port: Int,
    val connectTimeoutMillis: Int,
    val readTimeoutMillis: Int,
)

private class ScriptedSmtpServer(
    script: (SmtpPeer) -> Unit,
) : AutoCloseable {
    private val server = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))
    private val activeSocket = AtomicReference<Socket?>()
    private val executor = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "local-smtp-client-test").also { it.isDaemon = true }
    }
    private val future: Future<*> = executor.submit {
        server.accept().use { socket ->
            activeSocket.set(socket)
            socket.soTimeout = 2_000
            script(SmtpPeer(socket))
        }
    }
    var connectionRequest: ConnectionRequest? = null
        private set

    val connector = LocalSmtpSocketConnector { host, port, connectTimeout, readTimeout ->
        connectionRequest = ConnectionRequest(host, port, connectTimeout, readTimeout)
        Socket("127.0.0.1", server.localPort).also { it.soTimeout = readTimeout }
    }

    fun await() {
        future.get(3, TimeUnit.SECONDS)
    }

    override fun close() {
        activeSocket.getAndSet(null)?.runCatching { close() }
        server.close()
        future.cancel(true)
        executor.shutdownNow()
    }
}

private class SmtpPeer(socket: Socket) {
    private val input = BufferedInputStream(socket.getInputStream())
    private val output = socket.getOutputStream()

    fun reply(vararg lines: String) {
        lines.forEach { line ->
            output.write("$line\r\n".toByteArray(StandardCharsets.US_ASCII))
        }
        output.flush()
    }

    fun readLine(): String {
        val bytes = ArrayList<Byte>()
        while (true) {
            val next = input.read()
            check(next >= 0) { "SMTP client closed before completing a line" }
            if (next == '\n'.code) {
                check(bytes.lastOrNull() == '\r'.code.toByte()) {
                    "SMTP client did not use CRLF"
                }
                bytes.removeAt(bytes.lastIndex)
                return bytes.toByteArray().toString(StandardCharsets.US_ASCII)
            }
            bytes += next.toByte()
            check(bytes.size <= 8 * 1024) { "SMTP client line is not bounded" }
        }
    }

    fun readData(): List<String> = buildList {
        while (true) {
            val line = readLine()
            if (line == ".") return@buildList
            add(line)
        }
    }
}
