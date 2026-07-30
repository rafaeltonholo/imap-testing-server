package mail.sandbox.dashboard.server.gate.dovecot

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.nio.charset.StandardCharsets
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class DovecotIsolationMailboxContractTest {
    @Test
    fun isolationMailboxProofSeedsBeforeStrictReadAndConsumesFreshCredentials() {
        val target = DovecotOperatorTarget.create(
            "task6-isolation-seed@local.test",
        )
        val fetchedMessageId =
            "Message-ID: <task6-isolation-read-proof." +
                "${target.address}>\r\n\r\n"
        val seedTransport = Task6ScriptedOperatorTransport(
            (
                "* OK Dovecot ready\r\n" +
                    "+ VXNlcm5hbWU6\r\n" +
                    "+ UGFzc3dvcmQ6\r\n" +
                    "A001 OK authenticated\r\n" +
                    "+ OK continue\r\n" +
                    "A002 OK append completed\r\n"
                ).toByteArray(StandardCharsets.US_ASCII),
        )
        val readTransport = Task6ScriptedOperatorTransport(
            (
                "* OK Dovecot ready\r\n" +
                    "+ VXNlcm5hbWU6\r\n" +
                    "+ UGFzc3dvcmQ6\r\n" +
                    "A001 OK authenticated\r\n" +
                    "* LIST (\\HasNoChildren) \".\" INBOX\r\n" +
                    "A002 OK list completed\r\n" +
                    "* 1 EXISTS\r\n" +
                    "A003 OK [READ-ONLY] examine completed\r\n" +
                    "* SEARCH 1\r\n" +
                    "A004 OK search completed\r\n" +
                    "* 1 FETCH (UID 1 " +
                    "BODY[HEADER.FIELDS (MESSAGE-ID)] " +
                    "{${fetchedMessageId.length}}\r\n" +
                    fetchedMessageId +
                    ")\r\n" +
                    "A005 OK fetch completed\r\n"
                ).toByteArray(StandardCharsets.US_ASCII),
        )
        val openIndex = AtomicInteger()
        val transportFactory = DovecotOperatorTransportFactory { register ->
            when (openIndex.getAndIncrement()) {
                0 -> seedTransport
                1 -> {
                    check(seedTransport.closed) {
                        "Seed session must close before the read probe opens"
                    }
                    readTransport
                }
                else -> error("Unexpected Task 6 isolation transport")
            }.also(register)
        }
        val credentials = listOf(
            task6TestCredential("isolation-seed-secret"),
            task6TestCredential("isolation-read-secret"),
        )
        val credentialIndex = AtomicInteger()

        try {
            assertEquals(
                DovecotOperatorProbeResult.Success,
                seedAndProbeTask6IsolationMailbox(
                    transportFactory = transportFactory,
                    target = target,
                    credentialSupplier = {
                        credentials[credentialIndex.getAndIncrement()]
                    },
                ),
            )

            val seedWrites = seedTransport.writtenBytes()
                .toString(StandardCharsets.US_ASCII)
            val appendIndex = seedWrites.indexOf(
                "A002 APPEND \"INBOX\" {",
            )
            val messageIdIndex = seedWrites.indexOf(
                "Message-ID: <task6-isolation-read-proof." +
                    "${target.address}>",
            )
            assertTrue(appendIndex >= 0)
            assertTrue(messageIdIndex > appendIndex)
            assertTrue(
                readTransport.writtenBytes()
                    .toString(StandardCharsets.US_ASCII)
                    .contains("A004 UID SEARCH ALL\r\n"),
            )
            assertEquals(2, openIndex.get())
            assertEquals(2, credentialIndex.get())
            assertTrue(seedTransport.closed)
            assertTrue(readTransport.closed)
            credentials.forEach { credential ->
                assertFailsWith<IllegalStateException> {
                    credential.withSecretBytes { }
                }
            }
        } finally {
            credentials.forEach(DovecotOperatorCredential::close)
            seedTransport.close()
            readTransport.close()
        }
    }

    @Test
    fun ordinaryPasswordEscalationUsesTheActualActiveMasterIdentity() {
        assertEquals(
            "target@local.test*dashboard-operator-a",
            task6MasterLogin(
                "target@local.test",
                DovecotOperatorId.A,
            ),
        )
        assertEquals(
            "target@local.test*dashboard-operator-b",
            task6MasterLogin(
                "target@local.test",
                DovecotOperatorId.B,
            ),
        )
    }

    private fun task6TestCredential(
        secret: String,
    ): DovecotOperatorCredential =
        DovecotOperatorCredential(
            id = DovecotOperatorId.A,
            secret = DovecotOperatorSecret.takeOwnership(
                secret.toByteArray(StandardCharsets.US_ASCII),
            ),
        )
}

private class Task6ScriptedOperatorTransport(
    transcript: ByteArray,
) : DovecotOperatorTransport {
    private val inputBytes = ByteArrayInputStream(transcript)
    private val outputBytes = ByteArrayOutputStream()

    var closed = false
        private set

    override val input: InputStream = inputBytes
    override val outputStream: OutputStream = outputBytes

    fun writtenBytes(): ByteArray = outputBytes.toByteArray()

    override fun abort() {
        close()
    }

    override fun close() {
        if (closed) return
        closed = true
        inputBytes.close()
        outputBytes.close()
    }
}
