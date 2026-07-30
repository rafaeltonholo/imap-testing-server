package mail.sandbox.dashboard.server.gate.dovecot

import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DovecotHeldOperatorImapDeadlineTest {
    @Test
    fun delayedCancellationSuccessEventuallyMarksSessionClosed() {
        val transport = DeadlineTestTransport(
            transcript = SEED_TRANSCRIPT,
            cancellationDelayMillis = 150,
        )
        val session = HeldDovecotOperatorImapSession.openAndSeed(
            transportFactory = factoryFor(transport),
            target = TARGET,
            credential = credential("delayed-cancellation-secret"),
            message = validMessage(),
            timeout = Duration.ofSeconds(1),
        )
        transport.block = DeadlineTestTransport.Block.Write
        transport.armCloseRelease()

        try {
            assertFailsWith<IllegalStateException> {
                session.requireUsable(SHORT_TIMEOUT)
            }
            awaitTrue { session.isClosed }
            assertTrue(transport.closed)
        } finally {
            if (!session.isClosed) {
                session.close()
            }
        }
    }

    @Test
    fun blockedAbortCannotKeepCurrentUsabilityProofBlocked() {
        val transport = DeadlineTestTransport(
            transcript = SEED_TRANSCRIPT,
            blockAbort = true,
        )
        val session = HeldDovecotOperatorImapSession.openAndSeed(
            transportFactory = factoryFor(transport),
            target = TARGET,
            credential = credential("blocked-noop-abort-secret"),
            message = validMessage(),
            timeout = Duration.ofSeconds(1),
        )
        transport.block = DeadlineTestTransport.Block.Write
        transport.armCloseRelease()
        val failure = AtomicReference<Throwable?>()
        val completed = CountDownLatch(1)
        val caller = Thread(
            {
                failure.set(
                    runCatching {
                        session.requireUsable(SHORT_TIMEOUT)
                    }.exceptionOrNull(),
                )
                completed.countDown()
            },
            "task6-blocked-abort-usability-caller",
        ).also {
            it.isDaemon = true
            it.start()
        }

        try {
            assertTrue(transport.awaitAbortStarted())
            assertTrue(
                completed.await(1, TimeUnit.SECONDS),
                "Blocked abort kept the current NOOP proof alive",
            )
            assertTrue(failure.get() is IllegalStateException)
            assertTrue(transport.closed)
            assertTrue(session.isClosed)
        } finally {
            transport.releaseBlockedAbort()
            caller.join(2_000)
        }
    }

    @Test
    fun blockedAbortCannotKeepPostCloseValidationBlocked() {
        val transport = DeadlineTestTransport(
            transcript = SEED_TRANSCRIPT,
            blockAbort = true,
        )
        val session = HeldDovecotOperatorImapSession.openAndSeed(
            transportFactory = factoryFor(transport),
            target = TARGET,
            credential = credential("blocked-post-close-abort-secret"),
            message = validMessage(),
            timeout = Duration.ofSeconds(1),
        )
        session.close()
        transport.block = DeadlineTestTransport.Block.Write
        transport.armCloseRelease()
        val failure = AtomicReference<Throwable?>()
        val completed = CountDownLatch(1)
        val caller = Thread(
            {
                failure.set(
                    runCatching {
                        session.requireClosedAndUnusable(SHORT_TIMEOUT)
                    }.exceptionOrNull(),
                )
                completed.countDown()
            },
            "task6-blocked-abort-post-close-caller",
        ).also {
            it.isDaemon = true
            it.start()
        }

        try {
            assertTrue(transport.awaitAbortStarted())
            assertTrue(
                completed.await(1, TimeUnit.SECONDS),
                "Blocked abort kept post-close validation alive",
            )
            assertEquals(null, failure.get())
            assertTrue(transport.closed)
        } finally {
            transport.releaseBlockedAbort()
            caller.join(2_000)
        }
    }

    @Test
    fun blockedAbortCannotKeepOpenTimeoutCleanupBlocked() {
        val transport = DeadlineTestTransport(
            transcript = SEED_TRANSCRIPT,
            blockAbort = true,
        )
        val message = validMessage()
        val credential = credential("blocked-open-abort-secret")
        val failure = AtomicReference<Throwable?>()
        val completed = CountDownLatch(1)
        val caller = Thread(
            {
                failure.set(
                    runCatching {
                        HeldDovecotOperatorImapSession.openAndSeed(
                            transportFactory =
                                DovecotOperatorTransportFactory { register ->
                                    register(transport)
                                    transport.awaitClose()
                                    transport
                                },
                            target = TARGET,
                            credential = credential,
                            message = message,
                            timeout = SHORT_TIMEOUT,
                        )
                    }.exceptionOrNull(),
                )
                completed.countDown()
            },
            "task6-blocked-abort-open-caller",
        ).also {
            it.isDaemon = true
            it.start()
        }

        try {
            assertTrue(transport.awaitAbortStarted())
            assertTrue(
                completed.await(1, TimeUnit.SECONDS),
                "Blocked abort kept open-timeout cleanup alive",
            )
            assertTrue(failure.get() is IllegalStateException)
            assertTrue(transport.closed)
            assertTrue(message.all { it == 0.toByte() })
            assertCredentialClosed(credential)
        } finally {
            transport.releaseBlockedAbort()
            caller.join(2_000)
        }
    }

    @Test
    fun blockedCancellationCallbackCannotDelayASubsequentDeadline() {
        val blockedCallbackStarted = CountDownLatch(1)
        val releaseBlockedCallback = CountDownLatch(1)
        val subsequentCallbackFired = CountDownLatch(1)
        val blocked = DovecotTask6ProofDeadline(SHORT_TIMEOUT) {
            blockedCallbackStarted.countDown()
            releaseBlockedCallback.await()
        }
        var subsequent: DovecotTask6ProofDeadline? = null

        try {
            assertTrue(blockedCallbackStarted.await(1, TimeUnit.SECONDS))
            subsequent = DovecotTask6ProofDeadline(SHORT_TIMEOUT) {
                subsequentCallbackFired.countDown()
            }

            assertTrue(
                subsequentCallbackFired.await(1, TimeUnit.SECONDS),
                "A blocked cancellation callback delayed a later deadline",
            )
        } finally {
            releaseBlockedCallback.countDown()
            blocked.close()
            subsequent?.close()
        }
    }

    @Test
    fun preInterruptedOpenAndSeedFailsBeforeTransportAllocation() {
        val openCalls = AtomicInteger()
        val message = validMessage()
        val credential = credential("pre-interrupted-open-secret")
        var interruptPreserved = false

        try {
            Thread.currentThread().interrupt()
            assertFailsWith<InterruptedException> {
                HeldDovecotOperatorImapSession.openAndSeed(
                    transportFactory = DovecotOperatorTransportFactory {
                        openCalls.incrementAndGet()
                        error("Pre-interrupted open must not allocate transport")
                    },
                    target = TARGET,
                    credential = credential,
                    message = message,
                    timeout = Duration.ofSeconds(1),
                )
            }
            interruptPreserved = Thread.currentThread().isInterrupted
        } finally {
            Thread.interrupted()
        }

        Thread.sleep(100)
        assertTrue(interruptPreserved)
        assertEquals(0, openCalls.get())
        assertTrue(message.all { it == 0.toByte() })
        assertCredentialClosed(credential)
    }

    @Test
    fun preInterruptedUsabilityProofFailsBeforeTransportIo() {
        val transport = DeadlineTestTransport(SEED_TRANSCRIPT)
        val session = HeldDovecotOperatorImapSession.openAndSeed(
            transportFactory = factoryFor(transport),
            target = TARGET,
            credential = credential("pre-interrupted-noop-secret"),
            message = validMessage(),
            timeout = Duration.ofSeconds(1),
        )
        val readsBefore = transport.readCalls
        val writesBefore = transport.writeCalls
        val flushesBefore = transport.flushCalls
        var interruptPreserved = false

        try {
            Thread.currentThread().interrupt()
            assertFailsWith<InterruptedException> {
                session.requireUsable(Duration.ofSeconds(1))
            }
            interruptPreserved = Thread.currentThread().isInterrupted
        } finally {
            Thread.interrupted()
            session.close()
        }

        assertTrue(interruptPreserved)
        assertEquals(readsBefore, transport.readCalls)
        assertEquals(writesBefore, transport.writeCalls)
        assertEquals(flushesBefore, transport.flushCalls)
    }

    @Test
    fun preInterruptedPostCloseValidationFailsBeforeTransportIo() {
        val transport = DeadlineTestTransport(SEED_TRANSCRIPT)
        val session = HeldDovecotOperatorImapSession.openAndSeed(
            transportFactory = factoryFor(transport),
            target = TARGET,
            credential = credential("pre-interrupted-post-close-secret"),
            message = validMessage(),
            timeout = Duration.ofSeconds(1),
        )
        session.close()
        val readsBefore = transport.readCalls
        val writesBefore = transport.writeCalls
        val flushesBefore = transport.flushCalls
        var interruptPreserved = false

        try {
            Thread.currentThread().interrupt()
            assertFailsWith<InterruptedException> {
                session.requireClosedAndUnusable(Duration.ofSeconds(1))
            }
            interruptPreserved = Thread.currentThread().isInterrupted
        } finally {
            Thread.interrupted()
        }

        assertTrue(interruptPreserved)
        assertEquals(readsBefore, transport.readCalls)
        assertEquals(writesBefore, transport.writeCalls)
        assertEquals(flushesBefore, transport.flushCalls)
    }

    @Test
    fun postCloseValidationDoesNotTreatInterruptionAsUnusability() {
        val transport = DeadlineTestTransport(SEED_TRANSCRIPT)
        val session = HeldDovecotOperatorImapSession.openAndSeed(
            transportFactory = factoryFor(transport),
            target = TARGET,
            credential = credential("interrupted-post-close-secret"),
            message = validMessage(),
            timeout = Duration.ofSeconds(1),
        )
        session.close()
        transport.interruptWrites = true
        var interruptPreserved = false

        try {
            assertFailsWith<InterruptedException> {
                session.requireClosedAndUnusable(Duration.ofSeconds(1))
            }
            interruptPreserved = Thread.currentThread().isInterrupted
        } finally {
            Thread.interrupted()
        }

        assertTrue(interruptPreserved)
    }

    @Test
    fun invalidTimeoutStillClosesCredentialAndWipesMessageBeforeOpening() {
        val message = validMessage()
        val credential = credential("invalid-timeout-secret")

        assertFailsWith<IllegalArgumentException> {
            HeldDovecotOperatorImapSession.openAndSeed(
                transportFactory = DovecotOperatorTransportFactory {
                    error("Invalid timeout must fail before opening transport")
                },
                target = TARGET,
                credential = credential,
                message = message,
                timeout = Duration.ZERO,
            )
        }

        assertTrue(message.all { it == 0.toByte() })
        assertCredentialClosed(credential)
    }

    @Test
    fun successfulCompletionAtomicallyDisarmsTheRemainingDeadline() {
        val fired = CountDownLatch(1)
        val deadline = DovecotTask6ProofDeadline(
            Duration.ofMillis(250),
            fired::countDown,
        )
        val initialRemaining = deadline.remainingNanos()
        Thread.sleep(5)
        val laterRemaining = deadline.remainingNanos()

        deadline.complete()

        assertTrue(laterRemaining in 1 until initialRemaining)
        assertFalse(fired.await(350, TimeUnit.MILLISECONDS))
    }

    @Test
    fun blockedOpenUsesTheTotalDeadlineAndLateAllocationSelfCloses() {
        val transport = DeadlineTestTransport(SEED_TRANSCRIPT)
        val openStarted = CountDownLatch(1)
        val releaseOpen = CountDownLatch(1)
        val message = validMessage()
        val credential = credential("blocked-open-secret")
        val started = System.nanoTime()

        assertFailsWith<IllegalStateException> {
            HeldDovecotOperatorImapSession.openAndSeed(
                transportFactory = DovecotOperatorTransportFactory { register ->
                    openStarted.countDown()
                    while (true) {
                        try {
                            if (releaseOpen.await(10, TimeUnit.MILLISECONDS)) {
                                break
                            }
                        } catch (_: InterruptedException) {
                            // Prove cancellation does not depend on cooperation.
                        }
                    }
                    register(transport)
                    transport
                },
                target = TARGET,
                credential = credential,
                message = message,
                timeout = SHORT_TIMEOUT,
            )
        }
        val elapsed = Duration.ofNanos(System.nanoTime() - started)
        assertTrue(openStarted.await(1, TimeUnit.SECONDS))
        releaseOpen.countDown()
        awaitTrue { transport.closed }

        assertTrue(elapsed < Duration.ofSeconds(1))
        assertTrue(message.all { it == 0.toByte() })
        assertCredentialClosed(credential)
    }

    @Test
    fun watchdogInterruptsBlockedSeedWriteAndFlush() {
        listOf(
            DeadlineTestTransport.Block.Write,
            DeadlineTestTransport.Block.Flush,
        ).forEach { block ->
            val transport = DeadlineTestTransport(
                transcript = SEED_TRANSCRIPT,
                initialBlock = block,
            )
            val message = validMessage()
            val credential = credential("blocked-${block.name}-secret")
            val started = System.nanoTime()

            assertFailsWith<IllegalStateException>(block.name) {
                HeldDovecotOperatorImapSession.openAndSeed(
                    transportFactory = factoryFor(transport),
                    target = TARGET,
                    credential = credential,
                    message = message,
                    timeout = SHORT_TIMEOUT,
                )
            }

            assertTrue(
                Duration.ofNanos(System.nanoTime() - started) <
                    Duration.ofSeconds(1),
            )
            assertTrue(transport.aborted)
            assertTrue(transport.closed)
            assertTrue(message.all { it == 0.toByte() })
            assertCredentialClosed(credential)
        }
    }

    @Test
    fun watchdogInterruptsBlockedNoopWriteFlushAndRead() {
        DeadlineTestTransport.Block.entries.forEach { block ->
            val transport = DeadlineTestTransport(SEED_TRANSCRIPT)
            val session = HeldDovecotOperatorImapSession.openAndSeed(
                transportFactory = factoryFor(transport),
                target = TARGET,
                credential = credential("noop-${block.name}-secret"),
                message = validMessage(),
                timeout = Duration.ofSeconds(1),
            )
            transport.block = block
            val started = System.nanoTime()

            assertFailsWith<IllegalStateException>(block.name) {
                session.requireUsable(SHORT_TIMEOUT)
            }

            assertTrue(
                Duration.ofNanos(System.nanoTime() - started) <
                    Duration.ofSeconds(1),
            )
            assertTrue(transport.aborted)
            assertTrue(transport.closed)
            assertTrue(session.isClosed)
        }
    }

    @Test
    fun postCloseValidationHasAWatchdogAndBoundedCompletion() {
        val transport = DeadlineTestTransport(SEED_TRANSCRIPT)
        val session = HeldDovecotOperatorImapSession.openAndSeed(
            transportFactory = factoryFor(transport),
            target = TARGET,
            credential = credential("post-close-secret"),
            message = validMessage(),
            timeout = Duration.ofSeconds(1),
        )
        session.close()
        transport.block = DeadlineTestTransport.Block.Write
        transport.armCloseRelease()
        val started = System.nanoTime()

        session.requireClosedAndUnusable(SHORT_TIMEOUT)

        assertTrue(
            Duration.ofNanos(System.nanoTime() - started) <
                Duration.ofSeconds(1),
        )
        awaitTrue { transport.aborted }
    }

    @Test
    fun failedDeadlineAbortAndCloseLeaveTheSessionOpenForRetry() {
        val transport = DeadlineTestTransport(
            transcript = SEED_TRANSCRIPT,
            failedAbortAttempts = 2,
            failedCloseAttempts = 2,
        )
        val session = HeldDovecotOperatorImapSession.openAndSeed(
            transportFactory = factoryFor(transport),
            target = TARGET,
            credential = credential("deadline-close-retry-secret"),
            message = validMessage(),
            timeout = Duration.ofSeconds(1),
        )
        transport.block = DeadlineTestTransport.Block.Write

        assertFailsWith<IllegalStateException> {
            session.requireUsable(SHORT_TIMEOUT)
        }

        assertFalse(session.isClosed)
        assertFalse(transport.closed)
        awaitTrue {
            transport.abortCalls >= 2 && transport.closeCalls >= 2
        }
        session.close()
        assertTrue(session.isClosed)
        assertTrue(transport.closed)
        assertTrue(transport.abortCalls >= 2)
        assertTrue(transport.closeCalls >= 3)
    }

    @Test
    fun duplicateAllocatedTransportIsClosedWithTheFirstAllocation() {
        val first = DeadlineTestTransport(ByteArray(0))
        val duplicate = DeadlineTestTransport(ByteArray(0))
        val message = validMessage()
        val credential = credential("duplicate-allocation-secret")

        assertFailsWith<IllegalStateException> {
            HeldDovecotOperatorImapSession.openAndSeed(
                transportFactory = DovecotOperatorTransportFactory { register ->
                    register(first)
                    register(duplicate)
                    first
                },
                target = TARGET,
                credential = credential,
                message = message,
                timeout = Duration.ofSeconds(1),
            )
        }

        assertTrue(first.closed)
        assertTrue(duplicate.closed)
        assertTrue(message.all { it == 0.toByte() })
        assertCredentialClosed(credential)
    }

    private fun validMessage(): ByteArray = VALID_MESSAGE.copyOf()

    private fun credential(secret: String): DovecotOperatorCredential =
        DovecotOperatorCredential(
            id = DovecotOperatorId.A,
            secret = DovecotOperatorSecret.takeOwnership(
                secret.toByteArray(StandardCharsets.US_ASCII),
            ),
        )

    private fun factoryFor(
        transport: DeadlineTestTransport,
    ): DovecotOperatorTransportFactory =
        DovecotOperatorTransportFactory { register ->
            register(transport)
            transport
        }

    private fun assertCredentialClosed(
        credential: DovecotOperatorCredential,
    ) {
        assertFailsWith<IllegalStateException> {
            credential.withSecretBytes { }
        }
    }

    private fun awaitTrue(condition: () -> Boolean) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(1)
        while (!condition() && System.nanoTime() < deadline) {
            Thread.sleep(5)
        }
        assertTrue(condition())
    }

    companion object {
        private val SHORT_TIMEOUT = Duration.ofMillis(50)
        private val TARGET = DovecotOperatorTarget.create(
            "task6-deadline@local.test",
        )
        private val VALID_MESSAGE =
            (
                "From: sender@local.test\r\n" +
                    "To: task6-deadline@local.test\r\n" +
                    "Date: Thu, 30 Jul 2026 12:00:00 +0000\r\n" +
                    "Subject: Dovecot Task 6 deadline proof\r\n" +
                    "Message-ID: <task6-deadline@local.test>\r\n" +
                    "MIME-Version: 1.0\r\n" +
                    "Content-Type: text/plain; charset=UTF-8\r\n" +
                    "\r\n" +
                    "Deadline proof.\r\n"
                ).toByteArray(StandardCharsets.US_ASCII)
        private val SEED_TRANSCRIPT =
            (
                "* OK Dovecot ready\r\n" +
                    "+ VXNlcm5hbWU6\r\n" +
                    "+ UGFzc3dvcmQ6\r\n" +
                    "A001 OK authenticated\r\n" +
                    "+ OK continue\r\n" +
                    "A002 OK append completed\r\n"
                ).toByteArray(StandardCharsets.US_ASCII)
    }
}

private class DeadlineTestTransport(
    transcript: ByteArray,
    initialBlock: Block? = null,
    private val failedAbortAttempts: Int = 0,
    private val failedCloseAttempts: Int = 0,
    private val blockAbort: Boolean = false,
    private val cancellationDelayMillis: Long = 0,
) : DovecotOperatorTransport {
    enum class Block {
        Write,
        Flush,
        Read,
    }

    private val released = CountDownLatch(1)
    private val abortStarted = CountDownLatch(1)
    private val abortRelease = CountDownLatch(1)
    private val closeSignal = CountDownLatch(1)
    private val transcriptInput = ByteArrayInputStream(transcript)

    @Volatile
    private var closeReleasesBlockedIo = false

    @Volatile
    var block: Block? = initialBlock

    @Volatile
    var interruptWrites = false

    @Volatile
    var aborted = false
        private set

    @Volatile
    var closed = false
        private set

    private val abortCounter = AtomicInteger()
    val abortCalls: Int
        get() = abortCounter.get()

    private val closeCounter = AtomicInteger()
    val closeCalls: Int
        get() = closeCounter.get()

    private val readCounter = AtomicInteger()
    val readCalls: Int
        get() = readCounter.get()

    private val writeCounter = AtomicInteger()
    val writeCalls: Int
        get() = writeCounter.get()

    private val flushCounter = AtomicInteger()
    val flushCalls: Int
        get() = flushCounter.get()

    override val input: InputStream = object : InputStream() {
        override fun read(): Int {
            readCounter.incrementAndGet()
            if (block == Block.Read) {
                awaitRelease()
                throw IOException("aborted")
            }
            return transcriptInput.read()
        }
    }

    override val outputStream: OutputStream = object : OutputStream() {
        override fun write(value: Int) {
            write(byteArrayOf(value.toByte()), 0, 1)
        }

        override fun write(
            bytes: ByteArray,
            offset: Int,
            length: Int,
        ) {
            writeCounter.incrementAndGet()
            if (interruptWrites) {
                Thread.currentThread().interrupt()
                throw InterruptedException(
                    "Post-close validation was interrupted",
                )
            }
            if (block == Block.Write) {
                awaitRelease()
                throw IOException("aborted")
            }
        }

        override fun flush() {
            flushCounter.incrementAndGet()
            if (block == Block.Flush) {
                awaitRelease()
                throw IOException("aborted")
            }
        }
    }

    override fun abort() {
        val attempt = abortCounter.incrementAndGet()
        if (cancellationDelayMillis > 0) {
            Thread.sleep(cancellationDelayMillis)
        }
        aborted = true
        abortStarted.countDown()
        if (blockAbort) {
            abortRelease.await()
        }
        released.countDown()
        check(attempt > failedAbortAttempts) {
            "Deadline transport abort failed"
        }
    }

    override fun close() {
        val attempt = closeCounter.incrementAndGet()
        if (cancellationDelayMillis > 0) {
            Thread.sleep(cancellationDelayMillis)
        }
        check(attempt > failedCloseAttempts) {
            "Deadline transport close failed"
        }
        closed = true
        if (aborted || closeReleasesBlockedIo) {
            released.countDown()
        }
        closeSignal.countDown()
        transcriptInput.close()
    }

    fun awaitAbortStarted(): Boolean =
        abortStarted.await(1, TimeUnit.SECONDS)

    fun releaseBlockedAbort() {
        abortRelease.countDown()
    }

    fun armCloseRelease() {
        closeReleasesBlockedIo = true
    }

    fun awaitClose() {
        while (true) {
            try {
                closeSignal.await()
                return
            } catch (_: InterruptedException) {
                // Only independent transport close releases allocation.
            }
        }
    }

    private fun awaitRelease() {
        while (true) {
            try {
                released.await()
                return
            } catch (_: InterruptedException) {
                // The transport abort, not cooperative interruption, releases I/O.
            }
        }
    }
}
