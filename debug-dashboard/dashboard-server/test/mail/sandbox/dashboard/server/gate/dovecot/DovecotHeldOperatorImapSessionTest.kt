package mail.sandbox.dashboard.server.gate.dovecot

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.OutputStream
import java.nio.charset.StandardCharsets
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class DovecotHeldOperatorImapSessionTest {
    @Test
    fun rotationSeedMessageIdIsStableAndUniqueForEachDisposableTarget() {
        val firstTarget = DovecotOperatorTarget.create(
            "task6-rotation-first@local.test",
        )
        val secondTarget = DovecotOperatorTarget.create(
            "task6-rotation-second@local.test",
        )
        val firstMessage = deterministicRotationMessage(firstTarget)
        val repeatedFirstMessage = deterministicRotationMessage(firstTarget)
        val secondMessage = deterministicRotationMessage(secondTarget)

        try {
            assertContentEquals(firstMessage, repeatedFirstMessage)
            assertEquals(
                "<task6-rotation-read-proof." +
                    "task6-rotation-first@local.test>",
                messageId(firstMessage),
            )
            assertNotEquals(
                messageId(firstMessage),
                messageId(secondMessage),
            )
        } finally {
            firstMessage.fill(0)
            repeatedFirstMessage.fill(0)
            secondMessage.fill(0)
        }
    }

    @Test
    fun seedsTheMailboxProvesTheLiveSessionThenClosesItsTransport() {
        val message = (
            "From: sender@local.test\r\n" +
                "To: task6-held-session@local.test\r\n" +
                "Date: Thu, 30 Jul 2026 12:00:00 +0000\r\n" +
                "Subject: Dovecot Task 6 rotation proof\r\n" +
                "Message-ID: <task6-held-session@local.test>\r\n" +
                "MIME-Version: 1.0\r\n" +
                "Content-Type: text/plain; charset=UTF-8\r\n" +
                "\r\n" +
                "Deterministic Dovecot Task 6 mailbox read proof.\r\n"
            ).toByteArray(StandardCharsets.US_ASCII)
        val expectedMessage = message.copyOf()
        val target = DovecotOperatorTarget.create(
            "task6-held-session@local.test",
        )
        val credential = DovecotOperatorCredential(
            id = DovecotOperatorId.A,
            secret = DovecotOperatorSecret.takeOwnership(
                "held-session-secret".toByteArray(StandardCharsets.US_ASCII),
            ),
        )
        val transport = ScriptedHeldOperatorTransport(
            (
                "* OK Dovecot ready\r\n" +
                    "+ VXNlcm5hbWU6\r\n" +
                    "+ UGFzc3dvcmQ6\r\n" +
                    "A001 OK authenticated\r\n" +
                    "+ OK continue\r\n" +
                    "A002 OK append completed\r\n" +
                    "A003 OK noop completed\r\n"
                ).toByteArray(StandardCharsets.US_ASCII),
        )

        val session = HeldDovecotOperatorImapSession.openAndSeed(
            transportFactory = DovecotOperatorTransportFactory { register ->
                register(transport)
                transport
            },
            target = target,
            credential = credential,
            message = message,
        )
        session.requireUsable()

        assertContentEquals(
            heldSessionExpectedWrites(
                target = target,
                credentialId = DovecotOperatorId.A,
                secret = "held-session-secret",
                message = expectedMessage,
            ),
            transport.writtenBytes(),
        )
        assertTrue(message.all { it == 0.toByte() })
        assertFailsWith<IllegalStateException> {
            credential.withSecretBytes { }
        }
        assertFalse(session.isClosed)
        assertFalse(transport.closed)

        session.close()

        assertTrue(session.isClosed)
        assertTrue(transport.closed)
        session.requireClosedAndUnusable()
    }

    @Test
    fun invalidSeedStillWipesTheMessageAndClosesTheCredential() {
        val invalidMessage =
            "not-an-rfc5322-message".toByteArray(StandardCharsets.US_ASCII)
        val credential = DovecotOperatorCredential(
            id = DovecotOperatorId.A,
            secret = DovecotOperatorSecret.takeOwnership(
                "invalid-seed-secret".toByteArray(StandardCharsets.US_ASCII),
            ),
        )

        assertFailsWith<IllegalArgumentException> {
            HeldDovecotOperatorImapSession.openAndSeed(
                transportFactory = DovecotOperatorTransportFactory {
                    error("Invalid input must fail before opening transport")
                },
                target = DovecotOperatorTarget.create(
                    "task6-invalid-seed@local.test",
                ),
                credential = credential,
                message = invalidMessage,
            )
        }

        assertTrue(invalidMessage.all { it == 0.toByte() })
        assertFailsWith<IllegalStateException> {
            credential.withSecretBytes { }
        }
    }

    @Test
    fun rejectedUnregisteredTransportIsClosed() {
        val message = (
            "From: sender@local.test\r\n" +
                "To: task6-unregistered@local.test\r\n" +
                "Date: Thu, 30 Jul 2026 12:00:00 +0000\r\n" +
                "Subject: Dovecot Task 6 allocation proof\r\n" +
                "Message-ID: <task6-unregistered@local.test>\r\n" +
                "MIME-Version: 1.0\r\n" +
                "Content-Type: text/plain; charset=UTF-8\r\n" +
                "\r\n" +
                "Allocation proof.\r\n"
            ).toByteArray(StandardCharsets.US_ASCII)
        val credential = DovecotOperatorCredential(
            id = DovecotOperatorId.A,
            secret = DovecotOperatorSecret.takeOwnership(
                "unregistered-secret".toByteArray(StandardCharsets.US_ASCII),
            ),
        )
        val transport = ScriptedHeldOperatorTransport(ByteArray(0))

        assertFailsWith<IllegalStateException> {
            HeldDovecotOperatorImapSession.openAndSeed(
                transportFactory = DovecotOperatorTransportFactory {
                    transport
                },
                target = DovecotOperatorTarget.create(
                    "task6-unregistered@local.test",
                ),
                credential = credential,
                message = message,
            )
        }

        assertTrue(transport.closed)
        assertTrue(message.all { it == 0.toByte() })
        assertFailsWith<IllegalStateException> {
            credential.withSecretBytes { }
        }
    }

    @Test
    fun failedTransportCloseLeavesTheSessionOpenForAnExplicitRetry() {
        val message = (
            "From: sender@local.test\r\n" +
                "To: task6-close-retry@local.test\r\n" +
                "Date: Thu, 30 Jul 2026 12:00:00 +0000\r\n" +
                "Subject: Dovecot Task 6 close retry proof\r\n" +
                "Message-ID: <task6-close-retry@local.test>\r\n" +
                "MIME-Version: 1.0\r\n" +
                "Content-Type: text/plain; charset=UTF-8\r\n" +
                "\r\n" +
                "Close retry proof.\r\n"
            ).toByteArray(StandardCharsets.US_ASCII)
        val transport = ScriptedHeldOperatorTransport(
            transcript = (
                "* OK Dovecot ready\r\n" +
                    "+ VXNlcm5hbWU6\r\n" +
                    "+ UGFzc3dvcmQ6\r\n" +
                    "A001 OK authenticated\r\n" +
                    "+ OK continue\r\n" +
                    "A002 OK append completed\r\n"
                ).toByteArray(StandardCharsets.US_ASCII),
            failedCloseAttempts = 1,
        )
        val session = HeldDovecotOperatorImapSession.openAndSeed(
            transportFactory = DovecotOperatorTransportFactory { register ->
                register(transport)
                transport
            },
            target = DovecotOperatorTarget.create(
                "task6-close-retry@local.test",
            ),
            credential = DovecotOperatorCredential(
                id = DovecotOperatorId.A,
                secret = DovecotOperatorSecret.takeOwnership(
                    "close-retry-secret".toByteArray(
                        StandardCharsets.US_ASCII,
                    ),
                ),
            ),
            message = message,
        )

        assertFailsWith<IllegalStateException> {
            session.close()
        }
        assertFalse(session.isClosed)
        assertFalse(transport.closed)

        session.close()

        assertTrue(session.isClosed)
        assertTrue(transport.closed)
        assertEquals(2, transport.closeCalls)
    }

    private fun heldSessionExpectedWrites(
        target: DovecotOperatorTarget,
        credentialId: DovecotOperatorId,
        secret: String,
        message: ByteArray,
    ): ByteArray = ByteArrayOutputStream().use { expected ->
        expected.write("A001 AUTHENTICATE LOGIN\r\n".toByteArray())
        expected.write(
            Base64.getEncoder().encode(
                (
                    target.address +
                        "*" +
                        credentialId.masterUsername
                    ).toByteArray(StandardCharsets.US_ASCII),
            ),
        )
        expected.write("\r\n".toByteArray())
        expected.write(
            Base64.getEncoder().encode(
                secret.toByteArray(StandardCharsets.US_ASCII),
            ),
        )
        expected.write("\r\n".toByteArray())
        expected.write(
            (
                "A002 APPEND \"INBOX\" {${message.size}}\r\n"
                ).toByteArray(StandardCharsets.US_ASCII),
        )
        expected.write(message)
        expected.write("\r\n".toByteArray())
        expected.write("A003 NOOP\r\n".toByteArray())
        expected.toByteArray()
    }

    private fun messageId(message: ByteArray): String =
        message.toString(StandardCharsets.US_ASCII)
            .lineSequence()
            .single { line -> line.startsWith("Message-ID: ") }
            .removePrefix("Message-ID: ")
}

private class ScriptedHeldOperatorTransport(
    transcript: ByteArray,
    private val failedCloseAttempts: Int = 0,
) : DovecotOperatorTransport {
    private val inputBytes = ByteArrayInputStream(transcript)
    private val outputBytes = ByteArrayOutputStream()
    var closed = false
        private set

    var closeCalls = 0
        private set

    override val input = inputBytes
    override val outputStream: OutputStream = object : OutputStream() {
        override fun write(value: Int) {
            check(!closed) { "Held transport is closed" }
            outputBytes.write(value)
        }

        override fun write(
            bytes: ByteArray,
            offset: Int,
            length: Int,
        ) {
            check(!closed) { "Held transport is closed" }
            outputBytes.write(bytes, offset, length)
        }
    }

    fun writtenBytes(): ByteArray = outputBytes.toByteArray()

    override fun abort() {
        close()
    }

    override fun close() {
        closeCalls += 1
        check(closeCalls > failedCloseAttempts) {
            "Scripted held transport close failed"
        }
        closed = true
        inputBytes.close()
        outputBytes.close()
    }
}
