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
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DovecotHeldOperatorImapDeadlineTest {
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
        val started = System.nanoTime()

        session.requireClosedAndUnusable(SHORT_TIMEOUT)

        assertTrue(
            Duration.ofNanos(System.nanoTime() - started) <
                Duration.ofSeconds(1),
        )
        assertTrue(transport.aborted)
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
) : DovecotOperatorTransport {
    enum class Block {
        Write,
        Flush,
        Read,
    }

    private val released = CountDownLatch(1)
    private val transcriptInput = ByteArrayInputStream(transcript)

    @Volatile
    var block: Block? = initialBlock

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

    override val input: InputStream = object : InputStream() {
        override fun read(): Int {
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
            if (block == Block.Write) {
                awaitRelease()
                throw IOException("aborted")
            }
        }

        override fun flush() {
            if (block == Block.Flush) {
                awaitRelease()
                throw IOException("aborted")
            }
        }
    }

    override fun abort() {
        val attempt = abortCounter.incrementAndGet()
        aborted = true
        released.countDown()
        check(attempt > failedAbortAttempts) {
            "Deadline transport abort failed"
        }
    }

    override fun close() {
        val attempt = closeCounter.incrementAndGet()
        check(attempt > failedCloseAttempts) {
            "Deadline transport close failed"
        }
        closed = true
        if (aborted) {
            released.countDown()
        }
        transcriptInput.close()
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
