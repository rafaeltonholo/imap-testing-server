package mail.sandbox.dashboard.server.gate.dovecot

import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.SocketException
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertSame
import kotlin.test.assertTrue

class DovecotHeldOperatorImapDeadlineTest {
    @Test
    fun delayedCancellationSuccessEventuallyMarksSessionClosed() {
        val workers = DovecotBoundedOperationWorkers(maxOperations = 1)
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
            operationWorkers = workers,
        )
        transport.block = DeadlineTestTransport.Block.Write
        transport.armCloseRelease()

        try {
            assertFailsWith<IllegalStateException> {
                session.requireUsable(SHORT_TIMEOUT)
            }
            awaitTrue { session.isClosed }
            awaitTrue { transport.closed }
        } finally {
            if (!session.isClosed) {
                session.close()
            }
            awaitWorkersReleased(workers)
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
            awaitTrue { transport.closed }
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
        val blockedCaller = Thread(
            {
                Thread.sleep(SHORT_TIMEOUT.toMillis() + 10)
                runCatching { blocked.remainingNanos() }
            },
            "task6-workerless-blocked-expiry-caller",
        ).also {
            it.isDaemon = true
            it.start()
        }

        try {
            assertTrue(blockedCallbackStarted.await(1, TimeUnit.SECONDS))
            subsequent = DovecotTask6ProofDeadline(SHORT_TIMEOUT) {
                subsequentCallbackFired.countDown()
            }
            Thread.sleep(SHORT_TIMEOUT.toMillis() + 10)
            assertFailsWith<IllegalStateException> {
                checkNotNull(subsequent).remainingNanos()
            }
            assertTrue(
                subsequentCallbackFired.await(1, TimeUnit.SECONDS),
                "A blocked caller expiry delayed a later caller expiry",
            )
        } finally {
            releaseBlockedCallback.countDown()
            blocked.close()
            subsequent?.close()
            blockedCaller.join(2_000)
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
        val workers = DovecotBoundedOperationWorkers(maxOperations = 1)
        val transport = DeadlineTestTransport(SEED_TRANSCRIPT)
        val session = HeldDovecotOperatorImapSession.openAndSeed(
            transportFactory = factoryFor(transport),
            target = TARGET,
            credential = credential("interrupted-post-close-secret"),
            message = validMessage(),
            timeout = SYNTHETIC_INTERRUPT_TIMEOUT,
            operationWorkers = workers,
        )
        session.close()
        transport.interruptWrites = true
        var interruptPreserved = false

        try {
            assertFailsWith<InterruptedException> {
                session.requireClosedAndUnusable(SYNTHETIC_INTERRUPT_TIMEOUT)
            }
            interruptPreserved = Thread.currentThread().isInterrupted
        } finally {
            Thread.interrupted()
        }

        assertTrue(interruptPreserved)
        awaitWorkersReleased(workers)
    }

    @Test
    fun interruptedSeedIOExceptionIsPromotedToRedactedInterruption() {
        val workers = DovecotBoundedOperationWorkers(maxOperations = 1)
        val injectedFailure = IOException(IO_FAILURE_MARKER)
        val transport = DeadlineTestTransport(
            transcript = SEED_TRANSCRIPT,
            initialBlock = DeadlineTestTransport.Block.Write,
            ioFailure = injectedFailure,
        )
        val message = validMessage()
        val credential = credential("interrupted-seed-credential")
        val failure = AtomicReference<Throwable?>()
        val interruptPreserved = AtomicBoolean()
        val classifiedFailure = AtomicReference<Throwable?>()
        val classificationCalls = AtomicInteger()
        val classificationReached = CountDownLatch(1)
        val releaseClassification = CountDownLatch(1)
        val completed = CountDownLatch(1)
        val caller = Thread(
            {
                try {
                    HeldDovecotOperatorImapSession.openAndSeed(
                        transportFactory = factoryFor(transport),
                        target = TARGET,
                        credential = credential,
                        message = message,
                        timeout = Duration.ofSeconds(1),
                        operationWorkers = workers,
                        beforeFailureClassification = { caught ->
                            classificationCalls.incrementAndGet()
                            classifiedFailure.set(caught)
                            classificationReached.countDown()
                            awaitUninterruptibly(releaseClassification)
                        },
                    )
                } catch (caught: Throwable) {
                    failure.set(caught)
                } finally {
                    interruptPreserved.set(
                        Thread.currentThread().isInterrupted,
                    )
                    Thread.interrupted()
                    completed.countDown()
                }
            },
            "task6-interrupted-seed-ioexception-caller",
        ).also {
            it.isDaemon = true
            it.start()
        }

        try {
            assertTrue(transport.awaitBlockedIo())
            transport.releaseBlockedIo()
            assertTrue(transport.awaitIoExitedWithIOException())
            assertTrue(classificationReached.await(1, TimeUnit.SECONDS))
            assertSame(injectedFailure, classifiedFailure.get())

            caller.interrupt()
            releaseClassification.countDown()
            assertTrue(completed.await(1, TimeUnit.SECONDS))

            val caught = failure.get()
            assertRedactedInterruption(
                caught = caught,
                expectedMessage =
                    "Held Dovecot operator seed proof was interrupted",
            )
            assertTrue(interruptPreserved.get())
            assertEquals(1, classificationCalls.get())
            assertTrue(message.all { it == 0.toByte() })
            assertCredentialClosed(credential)
        } finally {
            releaseClassification.countDown()
            transport.releaseBlockedIo()
            caller.interrupt()
            caller.join(2_000)
        }
        awaitWorkersReleased(workers)
    }

    @Test
    fun interruptedUsabilityIOExceptionIsPromotedToRedactedInterruption() {
        val workers = DovecotBoundedOperationWorkers(maxOperations = 1)
        val injectedFailure = SocketException(IO_FAILURE_MARKER)
        val transport = DeadlineTestTransport(
            transcript = SEED_TRANSCRIPT,
            ioFailure = injectedFailure,
        )
        val classifiedFailure = AtomicReference<Throwable?>()
        val classificationCalls = AtomicInteger()
        val classificationReached = CountDownLatch(1)
        val releaseClassification = CountDownLatch(1)
        val session = HeldDovecotOperatorImapSession.openAndSeed(
            transportFactory = factoryFor(transport),
            target = TARGET,
            credential = credential("interrupted-noop-credential"),
            message = validMessage(),
            timeout = Duration.ofSeconds(1),
            operationWorkers = workers,
            beforeFailureClassification = { caught ->
                classificationCalls.incrementAndGet()
                classifiedFailure.set(caught)
                classificationReached.countDown()
                awaitUninterruptibly(releaseClassification)
            },
        )
        transport.block = DeadlineTestTransport.Block.Write
        val failure = AtomicReference<Throwable?>()
        val interruptPreserved = AtomicBoolean()
        val completed = CountDownLatch(1)
        val caller = Thread(
            {
                try {
                    session.requireUsable(
                        timeout = Duration.ofSeconds(1),
                    )
                } catch (caught: Throwable) {
                    failure.set(caught)
                } finally {
                    interruptPreserved.set(
                        Thread.currentThread().isInterrupted,
                    )
                    Thread.interrupted()
                    completed.countDown()
                }
            },
            "task6-interrupted-noop-ioexception-caller",
        ).also {
            it.isDaemon = true
            it.start()
        }

        try {
            assertTrue(transport.awaitBlockedIo())
            transport.releaseBlockedIo()
            assertTrue(transport.awaitIoExitedWithIOException())
            assertTrue(classificationReached.await(1, TimeUnit.SECONDS))
            assertSame(injectedFailure, classifiedFailure.get())

            caller.interrupt()
            releaseClassification.countDown()
            assertTrue(completed.await(1, TimeUnit.SECONDS))

            val caught = failure.get()
            assertRedactedInterruption(
                caught = caught,
                expectedMessage =
                    "Held Dovecot operator usability proof was interrupted",
            )
            assertTrue(interruptPreserved.get())
            assertEquals(1, classificationCalls.get())
        } finally {
            releaseClassification.countDown()
            transport.releaseBlockedIo()
            caller.interrupt()
            caller.join(2_000)
        }
        awaitWorkersReleased(workers)
    }

    @Test
    fun interruptedPostCloseIOExceptionIsNotAcceptedAsUnusability() {
        val workers = DovecotBoundedOperationWorkers(maxOperations = 1)
        val injectedFailure = IOException(IO_FAILURE_MARKER)
        val transport = DeadlineTestTransport(
            transcript = SEED_TRANSCRIPT,
            ioFailure = injectedFailure,
        )
        val classifiedFailure = AtomicReference<Throwable?>()
        val classificationCalls = AtomicInteger()
        val classificationReached = CountDownLatch(1)
        val releaseClassification = CountDownLatch(1)
        val session = HeldDovecotOperatorImapSession.openAndSeed(
            transportFactory = factoryFor(transport),
            target = TARGET,
            credential = credential("interrupted-post-close-credential"),
            message = validMessage(),
            timeout = Duration.ofSeconds(1),
            operationWorkers = workers,
            beforeFailureClassification = { caught ->
                classificationCalls.incrementAndGet()
                classifiedFailure.set(caught)
                classificationReached.countDown()
                awaitUninterruptibly(releaseClassification)
            },
        )
        session.close()
        transport.block = DeadlineTestTransport.Block.Write
        val returnedNormally = AtomicBoolean()
        val failure = AtomicReference<Throwable?>()
        val interruptPreserved = AtomicBoolean()
        val completed = CountDownLatch(1)
        val caller = Thread(
            {
                try {
                    session.requireClosedAndUnusable(Duration.ofSeconds(1))
                    returnedNormally.set(true)
                } catch (caught: Throwable) {
                    failure.set(caught)
                } finally {
                    interruptPreserved.set(
                        Thread.currentThread().isInterrupted,
                    )
                    Thread.interrupted()
                    completed.countDown()
                }
            },
            "task6-interrupted-post-close-ioexception-caller",
        ).also {
            it.isDaemon = true
            it.start()
        }

        try {
            assertTrue(transport.awaitBlockedIo())
            transport.releaseBlockedIo()
            assertTrue(transport.awaitIoExitedWithIOException())
            assertTrue(classificationReached.await(1, TimeUnit.SECONDS))
            assertSame(injectedFailure, classifiedFailure.get())

            caller.interrupt()
            releaseClassification.countDown()
            assertTrue(completed.await(1, TimeUnit.SECONDS))

            assertFalse(returnedNormally.get())
            val caught = failure.get()
            assertRedactedInterruption(
                caught = caught,
                expectedMessage =
                    "Held Dovecot operator post-close proof was interrupted",
            )
            assertTrue(interruptPreserved.get())
            assertEquals(1, classificationCalls.get())
        } finally {
            releaseClassification.countDown()
            transport.releaseBlockedIo()
            caller.interrupt()
            caller.join(2_000)
        }
        awaitWorkersReleased(workers)
    }

    @Test
    fun throwingSeedFailureClassificationHookRunsAfterCleanup() {
        val workers = DovecotBoundedOperationWorkers(maxOperations = 1)
        val transport = DeadlineTestTransport(
            transcript = "* BAD invalid greeting\r\n".toByteArray(
                StandardCharsets.US_ASCII,
            ),
        )
        val message = validMessage()
        val credential = credential("classification-hook-credential")
        val classifiedFailure = AtomicReference<Throwable?>()
        val classificationCalls = AtomicInteger()
        val sentinel = FailureClassificationSentinel()

        val caught = assertFailsWith<FailureClassificationSentinel> {
            HeldDovecotOperatorImapSession.openAndSeed(
                transportFactory = factoryFor(transport),
                target = TARGET,
                credential = credential,
                message = message,
                timeout = Duration.ofSeconds(1),
                operationWorkers = workers,
                beforeFailureClassification = { failure ->
                    classificationCalls.incrementAndGet()
                    classifiedFailure.set(failure)
                    throw sentinel
                },
            )
        }

        assertSame(sentinel, caught)
        assertTrue(classifiedFailure.get() is IllegalStateException)
        assertEquals(1, classificationCalls.get())
        assertTrue(transport.aborted)
        assertTrue(transport.closed)
        assertTrue(message.all { it == 0.toByte() })
        assertCredentialClosed(credential)
        awaitWorkersReleased(workers)
    }

    @Test
    fun blockedNoopAbortAndCloseCannotKeepCurrentCallerBlocked() {
        val workers = DovecotBoundedOperationWorkers(maxOperations = 1)
        val transport = DeadlineTestTransport(
            transcript = SEED_TRANSCRIPT,
            blockAbort = true,
            blockClose = true,
        )
        val session = HeldDovecotOperatorImapSession.openAndSeed(
            transportFactory = factoryFor(transport),
            target = TARGET,
            credential = credential("dual-block-noop-credential"),
            message = validMessage(),
            timeout = Duration.ofSeconds(1),
            operationWorkers = workers,
        )
        transport.block = DeadlineTestTransport.Block.Write
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
            "task6-dual-block-noop-caller",
        ).also {
            it.isDaemon = true
            it.start()
        }

        try {
            assertTrue(transport.awaitBlockedIo())
            assertTrue(transport.awaitAbortStarted())
            assertTrue(transport.awaitCloseStarted())
            assertTrue(
                completed.await(1, TimeUnit.SECONDS),
                "Blocked I/O, abort, and close kept the NOOP caller alive",
            )
            assertTrue(failure.get() is IllegalStateException)
            assertEquals(
                DovecotBoundedOperationSnapshot(
                    abandonedOperations = 1,
                    activeActors = 3,
                    peakActors = 3,
                ),
                workers.snapshot(),
            )
            assertEquals(
                null,
                workers.tryAcquire(
                    System.nanoTime() + TimeUnit.SECONDS.toNanos(1),
                ),
            )
        } finally {
            transport.releaseBlockedAbort()
            transport.releaseBlockedClose()
            transport.releaseBlockedIo()
            caller.join(2_000)
        }
        awaitWorkersReleased(workers)
        assertTrue(session.isClosed)
    }

    @Test
    fun blockedOpenSeedAbortAndCloseCannotKeepCallerBlocked() {
        val workers = DovecotBoundedOperationWorkers(maxOperations = 1)
        val transport = DeadlineTestTransport(
            transcript = SEED_TRANSCRIPT,
            initialBlock = DeadlineTestTransport.Block.Write,
            blockAbort = true,
            blockClose = true,
        )
        val message = validMessage()
        val credential = credential("dual-block-seed-credential")
        val failure = AtomicReference<Throwable?>()
        val completed = CountDownLatch(1)
        val caller = Thread(
            {
                failure.set(
                    runCatching {
                        HeldDovecotOperatorImapSession.openAndSeed(
                            transportFactory = factoryFor(transport),
                            target = TARGET,
                            credential = credential,
                            message = message,
                            timeout = SHORT_TIMEOUT,
                            operationWorkers = workers,
                        )
                    }.exceptionOrNull(),
                )
                completed.countDown()
            },
            "task6-dual-block-seed-caller",
        ).also {
            it.isDaemon = true
            it.start()
        }

        try {
            assertTrue(transport.awaitBlockedIo())
            assertTrue(transport.awaitAbortStarted())
            assertTrue(transport.awaitCloseStarted())
            assertTrue(
                completed.await(1, TimeUnit.SECONDS),
                "Blocked seed I/O, abort, and close kept the caller alive",
            )
            assertTrue(failure.get() is IllegalStateException)
            assertEquals(
                DovecotBoundedOperationSnapshot(
                    abandonedOperations = 1,
                    activeActors = 3,
                    peakActors = 3,
                ),
                workers.snapshot(),
            )
            assertTrue(message.all { it == 0.toByte() })
            assertCredentialClosed(credential)
        } finally {
            transport.releaseBlockedAbort()
            transport.releaseBlockedClose()
            transport.releaseBlockedIo()
            caller.join(2_000)
        }
        assertTrue(transport.awaitIoExitedWithIOException())
        awaitWorkersReleased(workers)
        assertTrue(transport.closed)
    }

    @Test
    fun registeredOpenAbortAndCloseKeepCapacityUntilEveryActorExits() {
        val workers = DovecotBoundedOperationWorkers(maxOperations = 1)
        val transport = DeadlineTestTransport(
            transcript = SEED_TRANSCRIPT,
            blockAbort = true,
            blockClose = true,
        )
        val openRegistered = CountDownLatch(1)
        val releaseOpen = CountDownLatch(1)
        val message = validMessage()
        val credential = credential("registered-open-capacity-credential")
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
                                    openRegistered.countDown()
                                    awaitUninterruptibly(releaseOpen)
                                    transport
                                },
                            target = TARGET,
                            credential = credential,
                            message = message,
                            timeout = SHORT_TIMEOUT,
                            operationWorkers = workers,
                        )
                    }.exceptionOrNull(),
                )
                completed.countDown()
            },
            "task6-registered-open-capacity-caller",
        ).also {
            it.isDaemon = true
            it.start()
        }

        try {
            assertTrue(openRegistered.await(1, TimeUnit.SECONDS))
            assertTrue(transport.awaitAbortStarted())
            assertTrue(transport.awaitCloseStarted())
            assertTrue(
                completed.await(1, TimeUnit.SECONDS),
                "Registered blocked open kept its caller alive",
            )
            assertTrue(failure.get() is IllegalStateException)
            assertEquals(
                DovecotBoundedOperationSnapshot(
                    abandonedOperations = 1,
                    activeActors = 3,
                    peakActors = 3,
                ),
                workers.snapshot(),
            )
            assertEquals(
                null,
                workers.tryAcquire(
                    System.nanoTime() + TimeUnit.SECONDS.toNanos(1),
                ),
            )

            releaseOpen.countDown()
            awaitTrue {
                workers.snapshot() == DovecotBoundedOperationSnapshot(
                    abandonedOperations = 1,
                    activeActors = 2,
                    peakActors = 3,
                )
            }
            assertEquals(
                null,
                workers.tryAcquire(
                    System.nanoTime() + TimeUnit.SECONDS.toNanos(1),
                ),
            )

            transport.releaseBlockedAbort()
            awaitTrue {
                workers.snapshot() == DovecotBoundedOperationSnapshot(
                    abandonedOperations = 1,
                    activeActors = 1,
                    peakActors = 3,
                )
            }
            assertEquals(
                null,
                workers.tryAcquire(
                    System.nanoTime() + TimeUnit.SECONDS.toNanos(1),
                ),
            )

            transport.releaseBlockedClose()
            awaitWorkersReleased(workers)
            assertTrue(transport.closed)

            val recovered = checkNotNull(
                workers.tryAcquire(
                    System.nanoTime() + TimeUnit.SECONDS.toNanos(1),
                ),
            )
            recovered.complete()
            assertTrue(recovered.awaitRelease())
        } finally {
            releaseOpen.countDown()
            transport.releaseBlockedAbort()
            transport.releaseBlockedClose()
            caller.join(2_000)
        }

        awaitWorkersReleased(workers)
        assertTrue(message.all { it == 0.toByte() })
        assertCredentialClosed(credential)
    }

    @Test
    fun blockedPostCloseIoAbortAndCloseCannotKeepCallerBlocked() {
        val workers = DovecotBoundedOperationWorkers(maxOperations = 1)
        val transport = DeadlineTestTransport(SEED_TRANSCRIPT)
        val session = HeldDovecotOperatorImapSession.openAndSeed(
            transportFactory = factoryFor(transport),
            target = TARGET,
            credential = credential("dual-block-post-close-credential"),
            message = validMessage(),
            timeout = Duration.ofSeconds(1),
            operationWorkers = workers,
        )
        awaitWorkersReleased(workers)
        session.close()
        awaitWorkersReleased(workers)
        transport.block = DeadlineTestTransport.Block.Write
        transport.blockAbort = true
        transport.blockClose = true
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
            "task6-dual-block-post-close-caller",
        ).also {
            it.isDaemon = true
            it.start()
        }

        try {
            assertTrue(transport.awaitBlockedIo())
            assertTrue(transport.awaitAbortStarted())
            awaitTrue { transport.closeCalls >= 2 }
            assertTrue(
                completed.await(1, TimeUnit.SECONDS),
                "Blocked post-close I/O, abort, and close kept the caller alive",
            )
            assertEquals(null, failure.get())
            assertEquals(
                DovecotBoundedOperationSnapshot(
                    abandonedOperations = 1,
                    activeActors = 3,
                    peakActors = 3,
                ),
                workers.snapshot(),
            )
        } finally {
            transport.releaseBlockedAbort()
            transport.releaseBlockedClose()
            transport.releaseBlockedIo()
            caller.join(2_000)
        }
        assertTrue(transport.awaitIoExitedWithIOException())
        awaitWorkersReleased(workers)
    }

    @Test
    fun blockedExplicitCloseReturnsBoundedAndPublishesLateSuccess() {
        val workers = DovecotBoundedOperationWorkers(maxOperations = 1)
        val transport = DeadlineTestTransport(SEED_TRANSCRIPT)
        val session = HeldDovecotOperatorImapSession.openAndSeed(
            transportFactory = factoryFor(transport),
            target = TARGET,
            credential = credential("bounded-explicit-close-credential"),
            message = validMessage(),
            timeout = Duration.ofSeconds(1),
            operationWorkers = workers,
        )
        awaitWorkersReleased(workers)
        transport.blockAbort = true
        transport.blockClose = true
        val failure = AtomicReference<Throwable?>()
        val completed = CountDownLatch(1)
        val started = System.nanoTime()
        val caller = Thread(
            {
                failure.set(
                    runCatching {
                        session.close(SHORT_TIMEOUT)
                    }.exceptionOrNull(),
                )
                completed.countDown()
            },
            "task6-bounded-explicit-close-caller",
        ).also {
            it.isDaemon = true
            it.start()
        }

        try {
            assertTrue(transport.awaitCloseStarted())
            assertTrue(transport.awaitAbortStarted())
            awaitTrue { transport.closeCalls >= 2 }
            assertTrue(
                completed.await(1, TimeUnit.SECONDS),
                "A blocked explicit close exceeded its caller deadline",
            )
            assertTrue(
                Duration.ofNanos(System.nanoTime() - started) <
                    Duration.ofSeconds(1),
            )
            assertTrue(failure.get() is IllegalStateException)
            assertFalse(session.isClosed)
            assertEquals(
                DovecotBoundedOperationSnapshot(
                    abandonedOperations = 1,
                    activeActors = 3,
                    peakActors = 3,
                ),
                workers.snapshot(),
            )

            transport.releaseBlockedClose()
            awaitTrue { session.isClosed }
            awaitTrue {
                workers.snapshot().let { snapshot ->
                    snapshot.abandonedOperations == 1 &&
                        snapshot.activeActors == 1
                }
            }
        } finally {
            transport.releaseBlockedClose()
            transport.releaseBlockedAbort()
            caller.join(2_000)
        }
        awaitWorkersReleased(workers)
        assertTrue(session.isClosed)
    }

    @Test
    fun heldOperationCapacityRejectsFifthBeforeAllocationAndRecovers() {
        val workers = DovecotBoundedOperationWorkers(maxOperations = 4)
        val transports = List(4) {
            DeadlineTestTransport(
                transcript = SEED_TRANSCRIPT,
                blockAbort = true,
                blockClose = true,
            )
        }
        val sessions = transports.mapIndexed { index, transport ->
            HeldDovecotOperatorImapSession.openAndSeed(
                transportFactory = factoryFor(transport),
                target = TARGET,
                credential = credential("capacity-session-$index"),
                message = validMessage(),
                timeout = Duration.ofSeconds(1),
                operationWorkers = workers,
            ).also {
                awaitWorkersReleased(workers)
            }
        }
        transports.forEach { transport ->
            transport.block = DeadlineTestTransport.Block.Write
        }
        val failures = List(4) { AtomicReference<Throwable?>() }
        val callersFinished = CountDownLatch(4)
        val callers = sessions.mapIndexed { index, session ->
            Thread(
                {
                    failures[index].set(
                        runCatching {
                            session.requireUsable(SHORT_TIMEOUT)
                        }.exceptionOrNull(),
                    )
                    callersFinished.countDown()
                },
                "task6-held-capacity-caller-$index",
            ).also {
                it.isDaemon = true
                it.start()
            }
        }

        try {
            transports.forEach { transport ->
                assertTrue(transport.awaitBlockedIo())
                assertTrue(transport.awaitAbortStarted())
                assertTrue(transport.awaitCloseStarted())
            }
            assertTrue(callersFinished.await(2, TimeUnit.SECONDS))
            assertTrue(
                failures.all { failure ->
                    failure.get() is IllegalStateException
                },
            )
            val fullSnapshot = DovecotBoundedOperationSnapshot(
                abandonedOperations = 4,
                activeActors = 12,
                peakActors = 12,
            )
            assertEquals(fullSnapshot, workers.snapshot())

            val fifthAllocations = AtomicInteger()
            val fifthMessage = validMessage()
            val fifthCredential = credential("rejected-fifth-credential")
            assertFailsWith<IllegalStateException> {
                HeldDovecotOperatorImapSession.openAndSeed(
                    transportFactory = DovecotOperatorTransportFactory {
                        fifthAllocations.incrementAndGet()
                        error(
                            "A capacity-rejected Held open allocated transport",
                        )
                    },
                    target = TARGET,
                    credential = fifthCredential,
                    message = fifthMessage,
                    timeout = Duration.ofSeconds(1),
                    operationWorkers = workers,
                )
            }

            assertEquals(0, fifthAllocations.get())
            assertTrue(fifthMessage.all { it == 0.toByte() })
            assertCredentialClosed(fifthCredential)
            assertEquals(fullSnapshot, workers.snapshot())
        } finally {
            transports.forEach { transport ->
                transport.releaseBlockedAbort()
                transport.releaseBlockedClose()
                transport.releaseBlockedIo()
            }
            callers.forEach { caller -> caller.join(2_000) }
        }
        transports.forEach { transport ->
            assertTrue(transport.awaitIoExitedWithIOException())
        }
        awaitWorkersReleased(workers)
        assertTrue(sessions.all { session -> session.isClosed })

        val recoveryTransport = DeadlineTestTransport(SEED_TRANSCRIPT)
        val recovered = HeldDovecotOperatorImapSession.openAndSeed(
            transportFactory = factoryFor(recoveryTransport),
            target = TARGET,
            credential = credential("recovered-capacity-credential"),
            message = validMessage(),
            timeout = Duration.ofSeconds(1),
            operationWorkers = workers,
        )
        awaitWorkersReleased(workers)
        recovered.close(SHORT_TIMEOUT)

        assertTrue(recovered.isClosed)
        awaitWorkersReleased(workers)
    }

    @Test
    fun runtimeCloseCallersJoinAndReplayDelayedHeldCloseFailure() {
        val workers = DovecotBoundedOperationWorkers(maxOperations = 1)
        val transport = DeadlineTestTransport(SEED_TRANSCRIPT)
        val session = HeldDovecotOperatorImapSession.openAndSeed(
            transportFactory = factoryFor(transport),
            target = TARGET,
            credential = credential("runtime-close-replay-credential"),
            message = validMessage(),
            timeout = Duration.ofSeconds(1),
            operationWorkers = workers,
        )
        awaitWorkersReleased(workers)
        transport.blockAbort = true
        transport.blockClose = true
        val registry =
            DovecotOperatorApplicationLeaseRegistry(DovecotOperatorId.A)
        val closeCalls = AtomicInteger()
        registry.acquire(DovecotOperatorId.A) {
            closeCalls.incrementAndGet()
            session.close(REGISTRY_CLOSE_TIMEOUT)
        }
        val runtime = DovecotOperatorLeasedRotationRuntime(
            leases = registry,
            prober = { _, _ -> DovecotOperatorProbeResult.Success },
        )
        val firstFailure = AtomicReference<Throwable?>()
        val secondFailure = AtomicReference<Throwable?>()
        val firstFinished = CountDownLatch(1)
        val secondFinished = CountDownLatch(1)
        var second: Thread? = null
        val first = Thread(
            {
                firstFailure.set(runCatching(runtime::close).exceptionOrNull())
                firstFinished.countDown()
            },
            "task6-delayed-held-close-runtime-leader",
        ).also {
            it.isDaemon = true
            it.start()
        }

        try {
            assertTrue(transport.awaitCloseStarted())
            second = Thread(
                {
                    secondFailure.set(
                        runCatching(runtime::close).exceptionOrNull(),
                    )
                    secondFinished.countDown()
                },
                "task6-delayed-held-close-runtime-follower",
            ).also {
                it.isDaemon = true
                it.start()
            }

            assertFalse(secondFinished.await(50, TimeUnit.MILLISECONDS))
            assertTrue(transport.awaitAbortStarted())
            awaitTrue { transport.closeCalls >= 2 }
            assertTrue(firstFinished.await(1, TimeUnit.SECONDS))
            assertTrue(secondFinished.await(1, TimeUnit.SECONDS))
            first.join(2_000)
            requireNotNull(second).join(2_000)

            assertTrue(firstFailure.get() is IllegalStateException)
            assertSame(firstFailure.get(), secondFailure.get())
            assertEquals(1, closeCalls.get())
            val replay =
                runCatching(runtime::close).exceptionOrNull()
            assertSame(firstFailure.get(), replay)
            assertEquals(1, closeCalls.get())
            assertEquals(
                DovecotBoundedOperationSnapshot(
                    abandonedOperations = 1,
                    activeActors = 3,
                    peakActors = 3,
                ),
                workers.snapshot(),
            )

            transport.releaseBlockedClose()
            awaitTrue { session.isClosed }
            assertEquals(1, registry.openLeaseCount(DovecotOperatorId.A))
        } finally {
            transport.releaseBlockedClose()
            transport.releaseBlockedAbort()
            first.join(2_000)
            second?.join(2_000)
        }
        awaitWorkersReleased(workers)
        assertTrue(session.isClosed)
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
        Thread.sleep(300)

        assertTrue(laterRemaining in 1 until initialRemaining)
        assertFailsWith<IllegalStateException> {
            deadline.remainingNanos()
        }
        assertFalse(fired.await(0, TimeUnit.MILLISECONDS))
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
    fun coordinatorBoundsBlockedSeedWriteAndFlush() {
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
            awaitTrue {
                transport.aborted && transport.closed
            }
            assertTrue(message.all { it == 0.toByte() })
            assertCredentialClosed(credential)
        }
    }

    @Test
    fun coordinatorBoundsBlockedNoopWriteFlushAndRead() {
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
            awaitTrue {
                transport.closed && session.isClosed
            }
        }
    }

    @Test
    fun postCloseValidationUsesCoordinatorAndHasBoundedCompletion() {
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
            transport.abortCalls >= 1 && transport.closeCalls >= 1
        }
        assertFailsWith<IllegalStateException> {
            session.close()
        }
        session.close()
        assertTrue(session.isClosed)
        assertTrue(transport.closed)
        assertTrue(transport.abortCalls >= 1)
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

    private fun assertRedactedInterruption(
        caught: Throwable?,
        expectedMessage: String,
    ) {
        assertTrue(caught is InterruptedException)
        assertEquals(expectedMessage, caught.message)
        assertEquals(null, caught.cause)
        assertTrue(caught.suppressed.isEmpty())
        assertFalse(
            caught.message.orEmpty().contains(IO_FAILURE_MARKER),
            "Interrupted Held failure exposed its transport detail",
        )
    }

    private fun awaitTrue(condition: () -> Boolean) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(1)
        while (!condition() && System.nanoTime() < deadline) {
            Thread.sleep(5)
        }
        assertTrue(condition())
    }

    private fun awaitWorkersReleased(
        workers: DovecotBoundedOperationWorkers,
    ) {
        awaitTrue {
            workers.snapshot().let { snapshot ->
                snapshot.activeOperations == 0 &&
                    snapshot.abandonedOperations == 0 &&
                    snapshot.activeActors == 0
            }
        }
    }

    private fun awaitUninterruptibly(latch: CountDownLatch) {
        var interrupted = false
        while (true) {
            try {
                latch.await()
                break
            } catch (_: InterruptedException) {
                interrupted = true
            }
        }
        if (interrupted) {
            Thread.currentThread().interrupt()
        }
    }

    companion object {
        private val SHORT_TIMEOUT = Duration.ofMillis(50)
        private val REGISTRY_CLOSE_TIMEOUT = Duration.ofMillis(250)
        private val SYNTHETIC_INTERRUPT_TIMEOUT = Duration.ofSeconds(5)
        private const val IO_FAILURE_MARKER =
            "fixture-transport-io-secret-marker"
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
    blockAbort: Boolean = false,
    blockClose: Boolean = false,
    private val cancellationDelayMillis: Long = 0,
    private val ioFailure: IOException = IOException(
        "fixture-transport-io-secret-marker",
    ),
) : DovecotOperatorTransport {
    enum class Block {
        Write,
        Flush,
        Read,
    }

    private val released = CountDownLatch(1)
    private val blockedIoStarted = CountDownLatch(1)
    private val ioExitedWithIOException = CountDownLatch(1)
    private val abortStarted = CountDownLatch(1)
    private val abortRelease = CountDownLatch(1)
    private val closeStarted = CountDownLatch(1)
    private val closeRelease = CountDownLatch(1)
    private val closeSignal = CountDownLatch(1)
    private val transcriptInput = ByteArrayInputStream(transcript)

    @Volatile
    private var closeReleasesBlockedIo = false

    @Volatile
    var block: Block? = initialBlock

    @Volatile
    var interruptWrites = false

    @Volatile
    var blockAbort = blockAbort

    @Volatile
    var blockClose = blockClose

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
                blockedIoStarted.countDown()
                awaitRelease()
                throwFixtureIOException()
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
                blockedIoStarted.countDown()
                awaitRelease()
                throwFixtureIOException()
            }
        }

        override fun flush() {
            flushCounter.incrementAndGet()
            if (block == Block.Flush) {
                blockedIoStarted.countDown()
                awaitRelease()
                throwFixtureIOException()
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
        closeStarted.countDown()
        if (blockClose) {
            awaitUninterruptibly(closeRelease)
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

    fun awaitCloseStarted(): Boolean =
        closeStarted.await(1, TimeUnit.SECONDS)

    fun awaitBlockedIo(): Boolean =
        blockedIoStarted.await(1, TimeUnit.SECONDS)

    fun awaitIoExitedWithIOException(): Boolean =
        ioExitedWithIOException.await(1, TimeUnit.SECONDS)

    fun releaseBlockedAbort() {
        abortRelease.countDown()
    }

    fun releaseBlockedClose() {
        closeRelease.countDown()
    }

    fun releaseBlockedIo() {
        released.countDown()
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
        awaitUninterruptibly(released)
    }

    private fun awaitUninterruptibly(latch: CountDownLatch) {
        while (true) {
            try {
                latch.await()
                return
            } catch (_: InterruptedException) {
                // The transport abort, not cooperative interruption, releases I/O.
            }
        }
    }

    private fun throwFixtureIOException(): Nothing {
        ioExitedWithIOException.countDown()
        throw ioFailure
    }
}

private class FailureClassificationSentinel :
    RuntimeException("Held failure classification sentinel")
