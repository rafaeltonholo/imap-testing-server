package mail.sandbox.dashboard.server.gate.dovecot

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.BufferedReader
import java.io.InputStream
import java.io.InputStreamReader
import java.io.OutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.nio.charset.StandardCharsets
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.SSLContext
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertSame
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

    @Test
    fun inactiveMasterRejectionPairsTheOtherFixedIdentityWithTheActiveCredential() {
        DovecotOperatorId.entries.forEach { activeId ->
            val credential = DovecotOperatorCredential(
                id = activeId,
                secret = DovecotOperatorSecret.takeOwnership(
                    "active-master-$activeId"
                        .toByteArray(StandardCharsets.US_ASCII),
                ),
            )
            var observedPort: Int? = null
            var observedLogin: String? = null
            var observedCredential: DovecotOperatorCredential? = null
            try {
                task6RequireInactiveMasterRejected(
                    port = 19_993,
                    targetAddress = "target@local.test",
                    activeCredential = credential,
                    requireRejected = { port, combinedLogin, suppliedCredential ->
                        observedPort = port
                        observedLogin = combinedLogin
                        observedCredential = suppliedCredential
                    },
                )

                val inactiveId = DovecotOperatorId.entries.single {
                    it != activeId
                }
                assertEquals(19_993, observedPort)
                assertEquals(
                    "target@local.test*${inactiveId.masterUsername}",
                    observedLogin,
                )
                assertSame(credential, observedCredential)
            } finally {
                credential.close()
            }
        }
    }

    @Test
    fun disposableEligibilityFixtureCleansUpAnAddThatMutatesBeforeFailure() {
        val address = "task6-fixture@local.test"
        val events = mutableListOf<String>()
        var eligible = false
        val passwordBytes =
            "task6-fixture-password".toByteArray(StandardCharsets.US_ASCII)
        lateinit var fixture: Task6DisposableEligibilityFixture
        val gateway = object : Task6DisposableEligibilityGateway {
            override fun contains(candidate: String): Boolean {
                assertEquals(address, candidate)
                events += "contains:$eligible"
                return eligible
            }

            override fun add(
                candidate: String,
                password: EligibilityPassword,
            ): Int {
                assertEquals(address, candidate)
                assertTrue(fixture.addAttempted)
                password.withBytes { supplied ->
                    assertTrue(supplied.contentEquals(passwordBytes))
                }
                events += "add"
                eligible = true
                return 2
            }

            override fun remove(candidate: String): Int {
                assertEquals(address, candidate)
                events += "remove"
                eligible = false
                return 0
            }
        }
        fixture = Task6DisposableEligibilityFixture(
            address = address,
            passwordFactory = {
                EligibilityPassword.takeOwnership(passwordBytes)
            },
            gateway = gateway,
            rejectionProof = {
                events += "rejection"
                assertFalse(eligible)
            },
        )

        assertFailsWith<IllegalStateException> {
            fixture.run {
                events += "body"
            }
        }

        assertTrue(fixture.addAttempted)
        assertFalse(eligible)
        assertEquals(
            listOf(
                "contains:false",
                "add",
                "contains:true",
                "remove",
                "rejection",
            ),
            events,
        )
        assertTrue(passwordBytes.all { it == 0.toByte() })
    }

    @Test
    fun smtpRejectionRequiresAnExactTerminal535Reply() {
        val proof = task6ProtocolProofForPlainSmtp()
        listOf(
            "5350 malformed",
            "535-continuation",
            "535 \u0000",
            "535 \u007f",
        ).forEachIndexed { index, terminalReply ->
            val credential = task6TestCredential("smtp-malformed-$index")
            try {
                withTask6SmtpServer(terminalReply) { port ->
                    assertFailsWith<IllegalStateException> {
                        proof.requireSmtpRejected(
                            port = port,
                            username =
                                "target@local.test*dashboard-operator-a",
                            credential = credential,
                        )
                    }
                }
            } finally {
                credential.close()
            }
        }

        val acceptedCredential = task6TestCredential("smtp-terminal")
        try {
            withTask6SmtpServer("535 Authentication rejected") { port ->
                proof.requireSmtpRejected(
                    port = port,
                    username =
                        "target@local.test*dashboard-operator-a",
                    credential = acceptedCredential,
                )
            }
        } finally {
            acceptedCredential.close()
        }
    }

    private fun task6ProtocolProofForPlainSmtp():
        DovecotIsolationProtocolProof {
        val constructor =
            DovecotIsolationProtocolProof::class.java.getDeclaredConstructor(
                SSLContext::class.java,
            )
        constructor.isAccessible = true
        return constructor.newInstance(SSLContext.getDefault())
    }

    private fun withTask6SmtpServer(
        terminalReply: String,
        block: (Int) -> Unit,
    ) {
        val loopback = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
        val server = ServerSocket(0, 1, loopback)
        val serverFailure = AtomicReference<Throwable?>()
        val completed = CountDownLatch(1)
        val worker = Thread(
            {
                try {
                    server.accept().use { socket ->
                        val reader = BufferedReader(
                            InputStreamReader(
                                socket.inputStream,
                                StandardCharsets.US_ASCII,
                            ),
                        )
                        fun send(line: String) {
                            val bytes =
                                "$line\r\n".toByteArray(
                                    StandardCharsets.US_ASCII,
                                )
                            try {
                                socket.outputStream.write(bytes)
                                socket.outputStream.flush()
                            } finally {
                                bytes.fill(0)
                            }
                        }

                        send("220 task6-proof ready")
                        checkNotNull(reader.readLine())
                        send("250 task6-proof ready")
                        checkNotNull(reader.readLine())
                        send("334 VXNlcm5hbWU6")
                        checkNotNull(reader.readLine())
                        send("334 UGFzc3dvcmQ6")
                        checkNotNull(reader.readLine())
                        send(terminalReply)
                    }
                } catch (failure: Throwable) {
                    serverFailure.set(failure)
                } finally {
                    completed.countDown()
                }
            },
            "task6-smtp-contract-server",
        ).also {
            it.isDaemon = true
            it.start()
        }

        try {
            block(server.localPort)
        } finally {
            runCatching(server::close)
            assertTrue(
                completed.await(2, TimeUnit.SECONDS),
                "SMTP contract server did not finish",
            )
            serverFailure.get()?.let { throw it }
            worker.join(2_000)
        }
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
