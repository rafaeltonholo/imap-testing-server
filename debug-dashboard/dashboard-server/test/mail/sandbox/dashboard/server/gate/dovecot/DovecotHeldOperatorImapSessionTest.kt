package mail.sandbox.dashboard.server.gate.dovecot

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.OutputStream
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.util.Base64
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
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
    fun failedTransportCloseLeavesSessionUnusableButRetryable() {
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
        val writeCallsAfterFailedClose = transport.writeCalls

        assertFailsWith<IllegalStateException> {
            session.requireUsable()
        }

        assertEquals(writeCallsAfterFailedClose, transport.writeCalls)

        session.close()

        assertTrue(session.isClosed)
        assertTrue(transport.closed)
        assertEquals(2, transport.closeCalls)
    }

    @Test
    fun postCloseWriteSuccessAbandonsBeforeReleasingCleanupAuthority() {
        val workers = DovecotBoundedOperationWorkers(maxOperations = 1)
        val transport = MisbehavingClosedHeldTransport()
        val session = HeldDovecotOperatorImapSession.openAndSeed(
            transportFactory = DovecotOperatorTransportFactory { register ->
                register(transport)
                transport
            },
            target = DovecotOperatorTarget.create(
                "task6-post-close-cleanup@local.test",
            ),
            credential = DovecotOperatorCredential(
                id = DovecotOperatorId.A,
                secret = DovecotOperatorSecret.takeOwnership(
                    "post-close-cleanup-secret".toByteArray(
                        StandardCharsets.US_ASCII,
                    ),
                ),
            ),
            message = (
                "From: sender@local.test\r\n" +
                    "To: task6-post-close-cleanup@local.test\r\n" +
                    "Date: Thu, 30 Jul 2026 12:00:00 +0000\r\n" +
                    "Subject: Dovecot Task 6 post-close cleanup\r\n" +
                    "Message-ID: <task6-post-close-cleanup@local.test>\r\n" +
                    "MIME-Version: 1.0\r\n" +
                    "Content-Type: text/plain; charset=UTF-8\r\n" +
                    "\r\n" +
                    "Post-close cleanup proof.\r\n"
                ).toByteArray(StandardCharsets.US_ASCII),
            operationWorkers = workers,
        )
        session.close()
        assertEquals(1, transport.closeCalls)
        assertEquals(0, transport.abortCalls)

        assertFailsWith<IllegalStateException> {
            session.requireClosedAndUnusable()
        }

        awaitWorkersReleased(workers)
        assertEquals(1, transport.abortCalls)
        assertEquals(2, transport.closeCalls)
    }

    @Test
    fun usabilityAndExplicitCloseAreSerializedPerHeldSession() {
        val workers = DovecotBoundedOperationWorkers(maxOperations = 1)
        val transport = SerializingHeldOperatorTransport()
        val closeAttempted = CountDownLatch(1)
        val session = openSerializingSession(
            transport = transport,
            workers = workers,
            afterSessionLockContention = {
                if (
                    Thread.currentThread().name ==
                    "task6-serialized-close-contender"
                ) {
                    closeAttempted.countDown()
                }
            },
        )
        transport.blockNextWrite()
        val usabilityFailure = AtomicReference<Throwable?>()
        val usabilityFinished = CountDownLatch(1)
        val usabilityCaller = Thread {
            try {
                session.requireUsable(Duration.ofSeconds(2))
            } catch (failure: Throwable) {
                usabilityFailure.set(failure)
            } finally {
                usabilityFinished.countDown()
            }
        }.also {
            it.isDaemon = true
            it.start()
        }

        assertTrue(transport.blockedWriteStarted.await(1, TimeUnit.SECONDS))
        val closeFailure = AtomicReference<Throwable?>()
        val closeCaller = Thread(
            {
                try {
                    session.close(Duration.ofSeconds(2))
                } catch (failure: Throwable) {
                    closeFailure.set(failure)
                }
            },
            "task6-serialized-close-contender",
        ).also {
            it.isDaemon = true
            it.start()
        }

        try {
            assertTrue(closeAttempted.await(1, TimeUnit.SECONDS))
            assertEquals(
                0,
                transport.closeCalls,
                "Explicit close ran concurrently with the NOOP proof",
            )
        } finally {
            transport.releaseBlockedWrite()
            usabilityCaller.join(2_000)
            closeCaller.join(2_000)
        }

        assertFalse(usabilityCaller.isAlive)
        assertFalse(closeCaller.isAlive)
        assertEquals(null, usabilityFailure.get())
        assertEquals(null, closeFailure.get())
        assertEquals(1, transport.closeCalls)
        assertTrue(session.isClosed)
    }

    @Test
    fun concurrentCloseCallsRunTheTransportCloseExactlyOnce() {
        val workers = DovecotBoundedOperationWorkers(maxOperations = 1)
        val transport = SerializingHeldOperatorTransport(blockClose = true)
        val secondCloseAttempted = CountDownLatch(1)
        val session = openSerializingSession(
            transport = transport,
            workers = workers,
            afterSessionLockContention = {
                if (
                    Thread.currentThread().name ==
                    "task6-second-close-contender"
                ) {
                    secondCloseAttempted.countDown()
                }
            },
        )
        val firstFailure = AtomicReference<Throwable?>()
        val secondFailure = AtomicReference<Throwable?>()
        val first = Thread {
            try {
                session.close(Duration.ofSeconds(2))
            } catch (failure: Throwable) {
                firstFailure.set(failure)
            }
        }.also {
            it.isDaemon = true
            it.start()
        }

        assertTrue(transport.closeStarted.await(1, TimeUnit.SECONDS))
        val second = Thread(
            {
                try {
                    session.close(Duration.ofSeconds(2))
                } catch (failure: Throwable) {
                    secondFailure.set(failure)
                }
            },
            "task6-second-close-contender",
        ).also {
            it.isDaemon = true
            it.start()
        }

        try {
            assertTrue(secondCloseAttempted.await(1, TimeUnit.SECONDS))
            assertEquals(
                1,
                transport.closeCalls,
                "Concurrent close entered the transport twice",
            )
        } finally {
            transport.releaseBlockedClose()
            first.join(2_000)
            second.join(2_000)
        }

        assertFalse(first.isAlive)
        assertFalse(second.isAlive)
        assertEquals(null, firstFailure.get())
        assertEquals(null, secondFailure.get())
        assertEquals(1, transport.closeCalls)
        assertTrue(session.isClosed)
    }

    @Test
    fun postCloseProofWaitsForTheSerializedCloseOutcome() {
        val workers = DovecotBoundedOperationWorkers(maxOperations = 1)
        val transport = SerializingHeldOperatorTransport(blockClose = true)
        val proofAttempted = CountDownLatch(1)
        val session = openSerializingSession(
            transport = transport,
            workers = workers,
            afterSessionLockContention = {
                if (
                    Thread.currentThread().name ==
                    "task6-post-close-proof-contender"
                ) {
                    proofAttempted.countDown()
                }
            },
        )
        val closeFailure = AtomicReference<Throwable?>()
        val closeCaller = Thread {
            try {
                session.close(Duration.ofSeconds(2))
            } catch (failure: Throwable) {
                closeFailure.set(failure)
            }
        }.also {
            it.isDaemon = true
            it.start()
        }

        assertTrue(transport.closeStarted.await(1, TimeUnit.SECONDS))
        val proofFailure = AtomicReference<Throwable?>()
        val proofFinished = CountDownLatch(1)
        val proofCaller = Thread(
            {
                try {
                    session.requireClosedAndUnusable(Duration.ofSeconds(2))
                } catch (failure: Throwable) {
                    proofFailure.set(failure)
                } finally {
                    proofFinished.countDown()
                }
            },
            "task6-post-close-proof-contender",
        ).also {
            it.isDaemon = true
            it.start()
        }

        try {
            assertTrue(proofAttempted.await(1, TimeUnit.SECONDS))
            assertEquals(
                1L,
                proofFinished.count,
                "Post-close proof observed an in-progress close",
            )
        } finally {
            transport.releaseBlockedClose()
            closeCaller.join(2_000)
            proofCaller.join(2_000)
        }

        assertFalse(closeCaller.isAlive)
        assertFalse(proofCaller.isAlive)
        assertEquals(null, closeFailure.get())
        assertEquals(null, proofFailure.get())
        assertTrue(session.isClosed)
    }

    private fun openSerializingSession(
        transport: SerializingHeldOperatorTransport,
        workers: DovecotBoundedOperationWorkers,
        afterSessionLockContention: () -> Unit,
    ): HeldDovecotOperatorImapSession =
        HeldDovecotOperatorImapSession.openAndSeed(
            transportFactory = DovecotOperatorTransportFactory { register ->
                register(transport)
                transport
            },
            target = DovecotOperatorTarget.create(
                "task6-serialized-session@local.test",
            ),
            credential = DovecotOperatorCredential(
                id = DovecotOperatorId.A,
                secret = DovecotOperatorSecret.takeOwnership(
                    "serialized-session-secret".toByteArray(
                        StandardCharsets.US_ASCII,
                    ),
                ),
            ),
            message = (
                "From: sender@local.test\r\n" +
                    "To: task6-serialized-session@local.test\r\n" +
                    "Date: Thu, 30 Jul 2026 12:00:00 +0000\r\n" +
                    "Subject: Dovecot Task 6 serialization proof\r\n" +
                    "Message-ID: <task6-serialized-session@local.test>\r\n" +
                    "MIME-Version: 1.0\r\n" +
                    "Content-Type: text/plain; charset=UTF-8\r\n" +
                    "\r\n" +
                    "Serialization proof.\r\n"
                ).toByteArray(StandardCharsets.US_ASCII),
            operationWorkers = workers,
            afterSessionLockContention = afterSessionLockContention,
        )

    private fun awaitWorkersReleased(
        workers: DovecotBoundedOperationWorkers,
    ) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2)
        while (System.nanoTime() - deadline < 0L) {
            val snapshot = workers.snapshot()
            if (
                snapshot.activeOperations == 0 &&
                snapshot.abandonedOperations == 0 &&
                snapshot.activeActors == 0
            ) {
                return
            }
            Thread.yield()
        }
        assertEquals(
            DovecotBoundedOperationSnapshot(),
            workers.snapshot(),
        )
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

private class MisbehavingClosedHeldTransport :
    DovecotOperatorTransport {
    private val inputBytes = ByteArrayInputStream(
        (
            "* OK Dovecot ready\r\n" +
                "+ VXNlcm5hbWU6\r\n" +
                "+ UGFzc3dvcmQ6\r\n" +
                "A001 OK authenticated\r\n" +
                "+ OK continue\r\n" +
                "A002 OK append completed\r\n"
            ).toByteArray(StandardCharsets.US_ASCII),
    )
    private val closeCounter = AtomicInteger()
    private val abortCounter = AtomicInteger()

    val closeCalls: Int
        get() = closeCounter.get()

    val abortCalls: Int
        get() = abortCounter.get()

    override val input = inputBytes

    override val outputStream: OutputStream = object : OutputStream() {
        override fun write(value: Int) = Unit

        override fun write(
            bytes: ByteArray,
            offset: Int,
            length: Int,
        ) = Unit
    }

    override fun abort() {
        abortCounter.incrementAndGet()
    }

    override fun close() {
        closeCounter.incrementAndGet()
    }
}

private class SerializingHeldOperatorTransport(
    private val blockClose: Boolean = false,
) : DovecotOperatorTransport {
    private val inputBytes = ByteArrayInputStream(
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
    private val blockWrite = AtomicBoolean()
    private val releaseWrite = CountDownLatch(1)
    private val releaseClose = CountDownLatch(1)
    private val closeCounter = AtomicInteger()

    val blockedWriteStarted = CountDownLatch(1)
    val closeStarted = CountDownLatch(1)

    @Volatile
    private var closed = false

    val closeCalls: Int
        get() = closeCounter.get()

    override val input = inputBytes

    override val outputStream: OutputStream = object : OutputStream() {
        override fun write(value: Int) {
            write(byteArrayOf(value.toByte()), 0, 1)
        }

        override fun write(
            bytes: ByteArray,
            offset: Int,
            length: Int,
        ) {
            check(!closed) { "Serialized held transport is closed" }
            if (blockWrite.compareAndSet(true, false)) {
                blockedWriteStarted.countDown()
                releaseWrite.await()
            }
        }
    }

    fun blockNextWrite() {
        blockWrite.set(true)
    }

    fun releaseBlockedWrite() {
        releaseWrite.countDown()
    }

    fun releaseBlockedClose() {
        releaseClose.countDown()
    }

    override fun abort() {
        closed = true
    }

    override fun close() {
        closeCounter.incrementAndGet()
        closeStarted.countDown()
        if (blockClose) {
            while (true) {
                try {
                    releaseClose.await()
                    break
                } catch (_: InterruptedException) {
                    // The explicit test release owns transport close progress.
                }
            }
        }
        closed = true
    }
}

private class ScriptedHeldOperatorTransport(
    transcript: ByteArray,
    private val failedCloseAttempts: Int = 0,
) : DovecotOperatorTransport {
    private val inputBytes = ByteArrayInputStream(transcript)
    private val outputBytes = ByteArrayOutputStream()
    private val writeCounter = AtomicInteger()
    var closed = false
        private set

    var closeCalls = 0
        private set

    val writeCalls: Int
        get() = writeCounter.get()

    override val input = inputBytes
    override val outputStream: OutputStream = object : OutputStream() {
        override fun write(value: Int) {
            check(!closed) { "Held transport is closed" }
            writeCounter.incrementAndGet()
            outputBytes.write(value)
        }

        override fun write(
            bytes: ByteArray,
            offset: Int,
            length: Int,
        ) {
            check(!closed) { "Held transport is closed" }
            writeCounter.incrementAndGet()
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
