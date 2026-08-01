package mail.sandbox.dashboard.server.gate.dovecot

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.nio.charset.StandardCharsets
import java.util.Base64
import java.util.concurrent.CountDownLatch
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

class DovecotOperatorBoundedExchangeTest {
    @Test
    fun descriptionIsFixedAndCannotRetainFactoryDetails() {
        val sensitiveMarker = "factory-secret-and-target@local.test"
        val factory = object : DovecotOperatorTransportFactory {
            override fun open(
                registerAllocated:
                    (DovecotOperatorTransport) -> Unit,
            ): DovecotOperatorTransport =
                error("Description must not open the transport")

            override fun toString(): String = sensitiveMarker
        }
        val exchange = DovecotOperatorBoundedExchange(factory)

        assertEquals(
            "DovecotOperatorBoundedExchange(fixed, redacted)",
            exchange.toString(),
        )
        assertFalse(exchange.toString().contains(sensitiveMarker))
    }

    @Test
    fun greetingReadinessRegistersBeforeReadingAndClosesBeforeSuccessPublication() {
        val registered = AtomicBoolean()
        val readThread = AtomicReference<String>()
        val closeThread = AtomicReference<String>()
        val closeStarted = CountDownLatch(1)
        val releaseClose = CountDownLatch(1)
        val workers = DovecotBoundedOperationWorkers(maxOperations = 1)
        val transport = RecordingExchangeTransport(
            response = "* OK Dovecot ready\r\n",
            onRead = {
                check(registered.get()) {
                    "Dovecot operator transport was read before registration"
                }
                readThread.compareAndSet(null, Thread.currentThread().name)
            },
            onClose = {
                closeThread.set(Thread.currentThread().name)
                closeStarted.countDown()
                releaseClose.await()
            },
        )
        val exchange = DovecotOperatorBoundedExchange(
            transportFactory = DovecotOperatorTransportFactory { register ->
                register(transport)
                registered.set(true)
                transport
            },
            operationWorkers = workers,
        )
        val result = AtomicReference<DovecotOperatorProbeResult>()
        val failure = AtomicReference<Throwable>()
        val caller = Thread(
            {
                try {
                    result.set(exchange.greetingReadiness())
                } catch (caught: Throwable) {
                    failure.set(caught)
                }
            },
            "test-dovecot-bounded-greeting-caller",
        ).also {
            it.isDaemon = true
            it.start()
        }

        try {
            assertTrue(closeStarted.await(1, TimeUnit.SECONDS))
            caller.join(200)

            assertTrue(
                caller.isAlive,
                "Readiness escaped before synchronous transport close",
            )
            assertNull(result.get())
            assertEquals(
                DovecotBoundedOperationSnapshot(
                    activeOperations = 1,
                    activeActors = 1,
                    peakActors = 1,
                ),
                workers.snapshot(),
            )
        } finally {
            releaseClose.countDown()
            caller.join(2_000)
        }

        assertFalse(caller.isAlive)
        assertNull(failure.get())
        assertEquals(DovecotOperatorProbeResult.Success, result.get())
        assertTrue(transport.closed)
        assertTrue(
            readThread.get()?.startsWith("dovecot-bounded-operation-io-") ==
                true,
        )
        assertTrue(
            closeThread.get()?.startsWith("dovecot-bounded-operation-io-") ==
                true,
        )
        assertEquals(
            DovecotBoundedOperationSnapshot(peakActors = 1),
            workers.snapshot(),
        )
    }

    @Test
    fun capabilityRequiresLoginAndRejectsPlain() {
        val successful = RecordingExchangeTransport(
            response = (
                "* OK Dovecot ready\r\n" +
                    "* CAPABILITY IMAP4rev1 AUTH=LOGIN\r\n" +
                    "A899 OK Capability completed\r\n"
                ),
        )
        val successExchange = exchange(successful)

        assertEquals(
            DovecotOperatorProbeResult.Success,
            successExchange.requireLoginOnlyCapability(),
        )
        assertEquals(
            "A899 CAPABILITY\r\n",
            successful.writtenAscii(),
        )
        assertTrue(successful.closed)

        listOf(
            "* OK ready\r\n" +
                "* CAPABILITY IMAP4rev1\r\n" +
                "A899 OK Capability completed\r\n",
            "* OK ready\r\n" +
                "* CAPABILITY IMAP4rev1 AUTH=LOGIN AUTH=PLAIN\r\n" +
                "A899 OK Capability completed\r\n",
            "* OK ready\r\n" +
                "A899 OK Capability completed\r\n",
            "* OK ready\r\n" +
                "* CAPABILITY AUTH=LOGIN\r\n" +
                "* CAPABILITY AUTH=LOGIN\r\n" +
                "A899 OK Duplicate capability\r\n",
            "* OK ready\r\n" +
                "* CAPABILITY AUTH=LOGIN\r\n" +
                "A899 OK\r\n",
            "* OK ready\r\n" +
                "* CAPABILITY AUTH=LOGIN\r\n" +
                "A899 OK invalid\u0001text\r\n",
        ).forEach { response ->
            val transport = RecordingExchangeTransport(response)

            assertEquals(
                DovecotOperatorProbeResult.ProtocolFailure,
                exchange(transport).requireLoginOnlyCapability(),
            )
            assertTrue(transport.closed)
        }
    }

    @Test
    fun genericBorrowedPasswordLoginUsesTheExactCallerSuppliedUsername() {
        val passwordBytes =
            "ordinary-target-password".toByteArray(StandardCharsets.US_ASCII)
        val password = EligibilityPassword.takeOwnership(passwordBytes)
        val transport = authenticationTransport(
            "A901 NO [AUTHENTICATIONFAILED] Authentication failed\r\n",
        )
        try {
            assertEquals(
                DovecotOperatorProbeResult.AuthenticationFailure,
                exchange(transport).authenticateLogin(
                    username = "arbitrary-login@local.test",
                    password = password,
                ),
            )
            assertEquals(
                expectedLoginWire(
                    username = "arbitrary-login@local.test",
                    password = "ordinary-target-password",
                ),
                transport.writtenAscii(),
            )
            assertTrue(transport.writesOnlyOnBoundedIoActor())
            assertEquals(
                "ordinary-target-password",
                password.withBytes {
                    it.toString(StandardCharsets.US_ASCII)
                },
            )
        } finally {
            password.close()
        }
        assertTrue(passwordBytes.all { it == 0.toByte() })
    }

    @Test
    fun bareTargetLoginDelegatesWithoutAddingTheMasterUsername() {
        val passwordBytes =
            "bare-target-password".toByteArray(StandardCharsets.US_ASCII)
        val password = EligibilityPassword.takeOwnership(passwordBytes)
        val transport = authenticationTransport(
            "A901 NO [AUTHENTICATIONFAILED] Authentication failed\r\n",
        )
        try {
            assertEquals(
                DovecotOperatorProbeResult.AuthenticationFailure,
                exchange(transport).authenticateBareTarget(
                    target = TARGET,
                    password = password,
                ),
            )
            assertEquals(
                expectedLoginWire(
                    username = TARGET.address,
                    password = "bare-target-password",
                ),
                transport.writtenAscii(),
            )
        } finally {
            password.close()
        }
        assertTrue(passwordBytes.all { it == 0.toByte() })
    }

    @Test
    fun genericCredentialLoginPairsTheExactUsernameWithTheActiveSecret() {
        val secretBytes =
            "active-master-secret".toByteArray(StandardCharsets.US_ASCII)
        val credential = credential(secretBytes)
        val suppliedUsername =
            "missing@local.test*${DovecotOperatorId.B.masterUsername}"
        val transport = authenticationTransport(
            "A901 NO [AUTHORIZATIONFAILED] Authorization failed\r\n",
        )

        assertEquals(
            DovecotOperatorProbeResult.AuthorizationFailure,
            exchange(transport).authenticateLogin(
                username = suppliedUsername,
                credential = credential,
            ),
        )
        assertEquals(
            expectedLoginWire(
                username = suppliedUsername,
                password = "active-master-secret",
            ),
            transport.writtenAscii(),
        )
        assertTrue(secretBytes.all { it == 0.toByte() })
    }

    @Test
    fun combinedMasterTargetLoginUsesTheCredentialIdentityAndConsumesIt() {
        val secretBytes =
            "combined-master-secret".toByteArray(StandardCharsets.US_ASCII)
        val credential = credential(secretBytes)
        val transport = authenticationTransport(
            "A901 OK Logged in\r\n",
        )

        assertEquals(
            DovecotOperatorProbeResult.Success,
            exchange(transport).authenticateCombinedMasterTarget(
                target = TARGET,
                credential = credential,
            ),
        )
        assertEquals(
            expectedLoginWire(
                username =
                    "${TARGET.address}*" +
                        DovecotOperatorId.A.masterUsername,
                password = "combined-master-secret",
            ),
            transport.writtenAscii(),
        )
        assertTrue(secretBytes.all { it == 0.toByte() })
    }

    @Test
    fun loginRejectsAlteredChallengesAndIndeterminateCompletions() {
        listOf(
            "* OK ready\r\n" +
                "+ altered-username-challenge\r\n",
            "* OK ready\r\n" +
                "+ VXNlcm5hbWU6\r\n" +
                "+ altered-password-challenge\r\n",
            "* OK ready\r\n" +
                "+ VXNlcm5hbWU6\r\n" +
                "+ UGFzc3dvcmQ6\r\n" +
                "A901 NO Rejected without a typed response code\r\n",
            "* OK ready\r\n" +
                "+ VXNlcm5hbWU6\r\n" +
                "+ UGFzc3dvcmQ6\r\n" +
                "A901 BAD Invalid authentication exchange\r\n",
        ).forEachIndexed { index, response ->
            val secretBytes =
                "adversarial-login-$index-secret"
                    .toByteArray(StandardCharsets.US_ASCII)
            val transport = RecordingExchangeTransport(response)

            assertEquals(
                DovecotOperatorProbeResult.ProtocolFailure,
                exchange(transport).authenticateLogin(
                    username = TARGET.address,
                    credential = credential(secretBytes),
                ),
            )
            assertTrue(secretBytes.all { it == 0.toByte() })
            assertTrue(transport.closed)
        }
    }

    @Test
    fun loginSkipsUntaggedStatusUntilTheTaggedCompletion() {
        val secretBytes =
            "delayed-authentication-secret"
                .toByteArray(StandardCharsets.US_ASCII)
        val transport = authenticationTransport(
            "* OK Waiting for authentication process to respond..\r\n" +
                "A901 NO [AUTHENTICATIONFAILED] Authentication failed.\r\n",
        )

        assertEquals(
            DovecotOperatorProbeResult.AuthenticationFailure,
            exchange(transport).authenticateLogin(
                username = TARGET.address,
                credential = credential(secretBytes),
            ),
        )
        assertTrue(secretBytes.all { it == 0.toByte() })
        assertTrue(transport.closed)
    }

    @Test
    fun plainAuthzidMasterFormIsExactAndWipesEveryWorkerOwnedCommand() {
        val copiedCommands = CopyOnWriteArrayList<ByteArray>()
        val workers = DovecotBoundedOperationWorkers(
            maxOperations = 1,
            copyBytes = { source ->
                source.copyOf().also(copiedCommands::add)
            },
            wipeBytes = { owned -> owned.fill(0) },
        )
        val secretBytes =
            "plain-master-secret".toByteArray(StandardCharsets.US_ASCII)
        val credential = credential(secretBytes)
        val transport = RecordingExchangeTransport(
            response = (
                "* OK Dovecot ready\r\n" +
                    "A900 NO Authentication mechanism is disabled\r\n"
                ),
        )

        assertEquals(
            DovecotOperatorProbeResult.AuthenticationFailure,
            exchange(
                transport = transport,
                operationWorkers = workers,
            ).authenticatePlainAuthzidMaster(
                target = TARGET,
                credential = credential,
            ),
        )
        assertEquals(
            expectedPlainWire(
                target = TARGET.address,
                master = DovecotOperatorId.A.masterUsername,
                secret = "plain-master-secret",
            ),
            transport.writtenAscii(),
        )
        assertTrue(secretBytes.all { it == 0.toByte() })
        assertTrue(copiedCommands.isNotEmpty())
        assertTrue(
            copiedCommands.all { bytes ->
                bytes.all { it == 0.toByte() }
            },
        )
    }

    @Test
    fun plainAuthzidMasterSeparatesRejectionFromAccidentalAcceptance() {
        listOf(
            "A900 BAD Unsupported authentication mechanism\r\n" to
                DovecotOperatorProbeResult.AuthenticationFailure,
            "A900 OK Unexpectedly accepted\r\n" to
                DovecotOperatorProbeResult.Success,
            "A900 NO\r\n" to
                DovecotOperatorProbeResult.ProtocolFailure,
        ).forEachIndexed { index, (completion, expected) ->
            val secretBytes =
                "plain-result-$index-secret"
                    .toByteArray(StandardCharsets.US_ASCII)
            val transport = RecordingExchangeTransport(
                response = "* OK ready\r\n$completion",
            )

            assertEquals(
                expected,
                exchange(transport).authenticatePlainAuthzidMaster(
                    target = TARGET,
                    credential = credential(secretBytes),
                ),
            )
            assertTrue(secretBytes.all { it == 0.toByte() })
            assertTrue(transport.closed)
        }
    }

    @Test
    fun malformedTruncatedOversizedAndExcessResponsesAreTypedAndClosed() {
        val malformed = RecordingExchangeTransport("* BAD invalid\r\n")
        assertEquals(
            DovecotOperatorProbeResult.ProtocolFailure,
            exchange(malformed).greetingReadiness(),
        )
        assertTrue(malformed.closed)

        val malformedFraming =
            RecordingExchangeTransport("* OK invalid\n")
        assertEquals(
            DovecotOperatorProbeResult.ProtocolFailure,
            exchange(malformedFraming).greetingReadiness(),
        )
        assertTrue(malformedFraming.closed)

        val truncated = RecordingExchangeTransport("* OK truncated")
        assertEquals(
            DovecotOperatorProbeResult.TransportFailure,
            exchange(truncated).greetingReadiness(),
        )
        assertTrue(truncated.closed)

        val oversized = RecordingExchangeTransport(
            "* OK " + "x".repeat(16 * 1024) + "\r\n",
        )
        assertEquals(
            DovecotOperatorProbeResult.ProtocolFailure,
            exchange(oversized).greetingReadiness(),
        )
        assertTrue(oversized.closed)

        val excessCapability = RecordingExchangeTransport(
            buildString {
                append("* OK ready\r\n")
                repeat(32) {
                    append("* OK still waiting\r\n")
                }
                append("* CAPABILITY AUTH=LOGIN\r\n")
                append("A899 OK too late\r\n")
            },
        )
        assertEquals(
            DovecotOperatorProbeResult.ProtocolFailure,
            exchange(excessCapability).requireLoginOnlyCapability(),
        )
        assertTrue(excessCapability.closed)
    }

    @Test
    fun silentGreetingDeadlineCancelsIoAndQuiescesAccounting() {
        val workers = DovecotBoundedOperationWorkers(maxOperations = 1)
        val transport = BlockingExchangeTransport()
        val watchdogFired = CountDownLatch(1)
        val watchdog = DovecotOperatorProbeWatchdog { onDeadline ->
            val actor = Thread(
                {
                    check(
                        transport.readStarted.await(
                            1,
                            TimeUnit.SECONDS,
                        ),
                    )
                    watchdogFired.countDown()
                    onDeadline()
                },
                "test-bounded-exchange-watchdog",
            ).also {
                it.isDaemon = true
                it.start()
            }
            AutoCloseable {
                actor.join(1_000)
            }
        }
        val exchange = DovecotOperatorBoundedExchange(
            transportFactory = DovecotOperatorTransportFactory { register ->
                register(transport)
                transport
            },
            operationWorkers = workers,
            watchdog = watchdog,
        )
        val startedAt = System.nanoTime()

        assertEquals(
            DovecotOperatorProbeResult.TransportFailure,
            exchange.greetingReadiness(),
        )

        val elapsed = System.nanoTime() - startedAt
        assertTrue(elapsed < TimeUnit.SECONDS.toNanos(2))
        assertTrue(watchdogFired.await(1, TimeUnit.SECONDS))
        assertTrue(transport.readStarted.await(1, TimeUnit.SECONDS))
        assertTrue(
            transport.readThread.get()
                ?.startsWith("dovecot-bounded-operation-io-") == true,
        )
        assertTrue(transport.abortCalls.get() >= 1)
        assertTrue(transport.closeCalls.get() >= 1)
        assertEventually {
            workers.snapshot().activeOperations == 0 &&
                workers.snapshot().abandonedOperations == 0 &&
                workers.snapshot().activeActors == 0
        }
    }

    @Test
    fun failedFiniteCloseOverridesSuccessAndDrainsCancellationActors() {
        val workers = DovecotBoundedOperationWorkers(maxOperations = 1)
        val transport = FailFirstCloseExchangeTransport()

        assertEquals(
            DovecotOperatorProbeResult.TransportFailure,
            exchange(
                transport = transport,
                operationWorkers = workers,
            ).greetingReadiness(),
        )

        assertTrue(transport.abortCalls.get() >= 1)
        assertTrue(transport.closeCalls.get() >= 2)
        assertEventually {
            workers.snapshot() ==
                DovecotBoundedOperationSnapshot(peakActors = 3)
        }
    }

    @Test
    fun interruptedCredentialLoginRestoresInterruptionAndWipesSecret() {
        val workers = DovecotBoundedOperationWorkers(maxOperations = 1)
        val secretBytes =
            "interrupted-exchange-secret"
                .toByteArray(StandardCharsets.US_ASCII)
        val result = AtomicReference<DovecotOperatorProbeResult>()
        val failure = AtomicReference<Throwable>()
        val interruptedAfter = AtomicBoolean()
        val transport = authenticationTransport("A901 OK Logged in\r\n")
        val caller = Thread(
            {
                Thread.currentThread().interrupt()
                try {
                    result.set(
                        exchange(
                            transport = transport,
                            operationWorkers = workers,
                        ).authenticateLogin(
                            username = TARGET.address,
                            credential = credential(secretBytes),
                        ),
                    )
                } catch (caught: Throwable) {
                    failure.set(caught)
                } finally {
                    interruptedAfter.set(
                        Thread.currentThread().isInterrupted,
                    )
                }
            },
            "test-interrupted-bounded-exchange",
        ).also {
            it.isDaemon = true
            it.start()
        }

        caller.join(2_000)

        assertFalse(caller.isAlive)
        assertNull(failure.get())
        assertEquals(
            DovecotOperatorProbeResult.TransportFailure,
            result.get(),
        )
        assertTrue(interruptedAfter.get())
        assertTrue(secretBytes.all { it == 0.toByte() })
        assertEventually {
            workers.snapshot().activeOperations == 0 &&
                workers.snapshot().abandonedOperations == 0 &&
                workers.snapshot().activeActors == 0
        }
    }

    @Test
    fun transportFailureAndInvalidInputRemainRedactedAndConsumeCredentials() {
        val sensitiveMarker =
            "secret-for-target@local.test from docker stderr"
        val transportSecret =
            "transport-failure-secret"
                .toByteArray(StandardCharsets.US_ASCII)
        val transportFailureExchange = DovecotOperatorBoundedExchange(
            transportFactory = DovecotOperatorTransportFactory {
                throw IOException(sensitiveMarker)
            },
            operationWorkers =
                DovecotBoundedOperationWorkers(maxOperations = 1),
        )

        assertEquals(
            DovecotOperatorProbeResult.TransportFailure,
            transportFailureExchange.authenticateLogin(
                username = TARGET.address,
                credential = credential(transportSecret),
            ),
        )
        assertTrue(transportSecret.all { it == 0.toByte() })
        assertFalse(
            transportFailureExchange.toString().contains(sensitiveMarker),
        )

        val invalidSecret =
            "invalid-login-secret"
                .toByteArray(StandardCharsets.US_ASCII)
        var opens = 0
        val invalidExchange = DovecotOperatorBoundedExchange(
            transportFactory = DovecotOperatorTransportFactory {
                opens += 1
                error("Invalid input must not allocate a transport")
            },
        )
        val failure = assertFailsWith<IllegalArgumentException> {
            invalidExchange.authenticateLogin(
                username = "invalid\n$sensitiveMarker",
                credential = credential(invalidSecret),
            )
        }

        assertEquals(
            "Dovecot operator login username is invalid",
            failure.message,
        )
        assertNull(failure.cause)
        assertFalse(failure.toString().contains(sensitiveMarker))
        assertEquals(0, opens)
        assertTrue(invalidSecret.all { it == 0.toByte() })
    }

    @Test
    fun plainCredentialEchoIsAProtocolFailureAndSecretIsWiped() {
        val secret = "echoed-plain-secret"
        val secretBytes = secret.toByteArray(StandardCharsets.US_ASCII)
        val targetBytes =
            TARGET.address.toByteArray(StandardCharsets.US_ASCII)
        val masterBytes =
            DovecotOperatorId.A.masterUsername.toByteArray(
                StandardCharsets.US_ASCII,
            )
        val payload = ByteArray(
            targetBytes.size + masterBytes.size + secretBytes.size + 2,
        )
        val encoded = try {
            var offset = 0
            targetBytes.copyInto(payload, destinationOffset = offset)
            offset += targetBytes.size + 1
            masterBytes.copyInto(payload, destinationOffset = offset)
            offset += masterBytes.size + 1
            secretBytes.copyInto(payload, destinationOffset = offset)
            Base64.getEncoder().encodeToString(payload)
        } finally {
            targetBytes.fill(0)
            masterBytes.fill(0)
            payload.fill(0)
        }
        val transport = RecordingExchangeTransport(
            "* OK ready\r\nA900 NO echoed=$encoded\r\n",
        )

        assertEquals(
            DovecotOperatorProbeResult.ProtocolFailure,
            exchange(transport).authenticatePlainAuthzidMaster(
                target = TARGET,
                credential = credential(secretBytes),
            ),
        )
        assertTrue(secretBytes.all { it == 0.toByte() })
        assertTrue(transport.closed)
    }

    private fun authenticationTransport(
        completion: String,
    ): RecordingExchangeTransport =
        RecordingExchangeTransport(
            response = (
                "* OK Dovecot ready\r\n" +
                    "+ VXNlcm5hbWU6\r\n" +
                    "+ UGFzc3dvcmQ6\r\n" +
                    completion
                ),
        )

    private fun expectedLoginWire(
        username: String,
        password: String,
    ): String =
        "A901 AUTHENTICATE LOGIN\r\n" +
            Base64.getEncoder().encodeToString(
                username.toByteArray(StandardCharsets.US_ASCII),
            ) +
            "\r\n" +
            Base64.getEncoder().encodeToString(
                password.toByteArray(StandardCharsets.US_ASCII),
            ) +
            "\r\n"

    private fun expectedPlainWire(
        target: String,
        master: String,
        secret: String,
    ): String {
        val targetBytes = target.toByteArray(StandardCharsets.US_ASCII)
        val masterBytes = master.toByteArray(StandardCharsets.US_ASCII)
        val secretBytes = secret.toByteArray(StandardCharsets.US_ASCII)
        val payload = ByteArray(
            targetBytes.size + masterBytes.size + secretBytes.size + 2,
        )
        return try {
            var offset = 0
            targetBytes.copyInto(payload, destinationOffset = offset)
            offset += targetBytes.size + 1
            masterBytes.copyInto(payload, destinationOffset = offset)
            offset += masterBytes.size + 1
            secretBytes.copyInto(payload, destinationOffset = offset)
            "A900 AUTHENTICATE PLAIN " +
                Base64.getEncoder().encodeToString(payload) +
                "\r\n"
        } finally {
            targetBytes.fill(0)
            masterBytes.fill(0)
            secretBytes.fill(0)
            payload.fill(0)
        }
    }

    private fun credential(
        secretBytes: ByteArray,
        id: DovecotOperatorId = DovecotOperatorId.A,
    ): DovecotOperatorCredential =
        DovecotOperatorCredential(
            id = id,
            secret = DovecotOperatorSecret.takeOwnership(secretBytes),
        )

    private fun assertEventually(assertion: () -> Boolean) {
        val deadline =
            System.nanoTime() + TimeUnit.SECONDS.toNanos(2)
        while (!assertion() && System.nanoTime() < deadline) {
            Thread.sleep(10)
        }
        assertTrue(assertion())
    }

    private fun exchange(
        transport: DovecotOperatorTransport,
        operationWorkers: DovecotBoundedOperationWorkers =
            DovecotBoundedOperationWorkers(maxOperations = 1),
    ): DovecotOperatorBoundedExchange =
        DovecotOperatorBoundedExchange(
            transportFactory = DovecotOperatorTransportFactory { register ->
                register(transport)
                transport
            },
            operationWorkers = operationWorkers,
        )

    private companion object {
        val TARGET = DovecotOperatorTarget.create("dev@local.test")
    }
}

private class RecordingExchangeTransport(
    response: String,
    private val onRead: () -> Unit = {},
    private val onClose: () -> Unit = {},
) : DovecotOperatorTransport {
    private val responseInput = ByteArrayInputStream(
        response.toByteArray(StandardCharsets.US_ASCII),
    )
    private val written = ByteArrayOutputStream()
    private val writeThreadNames = CopyOnWriteArrayList<String>()

    override val input: InputStream = object : InputStream() {
        override fun read(): Int {
            onRead()
            return responseInput.read()
        }

        override fun read(
            bytes: ByteArray,
            offset: Int,
            length: Int,
        ): Int {
            onRead()
            return responseInput.read(bytes, offset, length)
        }
    }

    override val outputStream: OutputStream = object : OutputStream() {
        override fun write(value: Int) {
            writeThreadNames += Thread.currentThread().name
            written.write(value)
        }

        override fun write(
            bytes: ByteArray,
            offset: Int,
            length: Int,
        ) {
            writeThreadNames += Thread.currentThread().name
            written.write(bytes, offset, length)
        }

        override fun flush() {
            writeThreadNames += Thread.currentThread().name
            written.flush()
        }
    }

    @Volatile
    var closed: Boolean = false
        private set

    override fun abort() {
        closed = true
    }

    override fun close() {
        onClose()
        closed = true
    }

    fun writtenAscii(): String =
        written.toByteArray().toString(StandardCharsets.US_ASCII)

    fun writesOnlyOnBoundedIoActor(): Boolean =
        writeThreadNames.isNotEmpty() &&
            writeThreadNames.all { name ->
                name.startsWith("dovecot-bounded-operation-io-")
            }

    override fun toString(): String =
        "RecordingExchangeTransport(redacted)"
}

private class BlockingExchangeTransport : DovecotOperatorTransport {
    val readStarted = CountDownLatch(1)
    val readThread = AtomicReference<String>()
    val abortCalls = AtomicInteger()
    val closeCalls = AtomicInteger()
    private val releaseRead = CountDownLatch(1)

    override val input: InputStream = object : InputStream() {
        override fun read(): Int {
            readThread.compareAndSet(null, Thread.currentThread().name)
            readStarted.countDown()
            releaseRead.await()
            throw IOException("injected silent transport release")
        }
    }

    override val outputStream: OutputStream =
        OutputStream.nullOutputStream()

    override fun abort() {
        abortCalls.incrementAndGet()
        releaseRead.countDown()
    }

    override fun close() {
        closeCalls.incrementAndGet()
        releaseRead.countDown()
    }
}

private class FailFirstCloseExchangeTransport :
    DovecotOperatorTransport {
    override val input: InputStream = ByteArrayInputStream(
        "* OK ready\r\n".toByteArray(StandardCharsets.US_ASCII),
    )
    override val outputStream: OutputStream =
        OutputStream.nullOutputStream()
    val abortCalls = AtomicInteger()
    val closeCalls = AtomicInteger()

    override fun abort() {
        abortCalls.incrementAndGet()
    }

    override fun close() {
        if (closeCalls.incrementAndGet() == 1) {
            throw IOException("injected finite close failure")
        }
    }
}
