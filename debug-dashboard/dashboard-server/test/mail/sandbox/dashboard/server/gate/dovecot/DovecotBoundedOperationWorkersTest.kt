package mail.sandbox.dashboard.server.gate.dovecot

import java.io.IOException
import java.time.Duration
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotSame
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

class DovecotBoundedOperationWorkersTest {
    @Test
    fun healthyTaskHandsOffItsResultAndReleasesItsCharge() {
        val workers = DovecotBoundedOperationWorkers(maxOperations = 1)
        val operation = workers.tryAcquire(deadlineAfter())!!

        val result = operation.execute(
            disposeLate = { value: ByteArray -> value.fill(0) },
        ) {
            byteArrayOf(1, 2, 3)
        }

        assertEquals(listOf<Byte>(1, 2, 3), result.toList())
        result.fill(0)
        assertTrue(operation.commitHandoff())
        assertEventually {
            workers.snapshot().let {
                it.activeOperations == 0 &&
                    it.abandonedOperations == 0 &&
                    it.activeActors == 0 &&
                    it.peakActors == 1
            }
        }
    }

    @Test
    fun workerExitRetainsReservationUntilCallerCommitsHandoff() {
        val commitReached = CountDownLatch(1)
        val releaseCommit = CountDownLatch(1)
        val committed = AtomicBoolean()
        val callerFailure = AtomicReference<Throwable?>()
        val workers = DovecotBoundedOperationWorkers(
            maxOperations = 1,
            beforeOwnershipCommit = {
                commitReached.countDown()
                awaitUninterruptibly(releaseCommit)
            },
        )
        val operation = workers.tryAcquire(deadlineAfter())!!
        operation.execute<Unit> {}
        val caller = Thread {
            try {
                committed.set(operation.commitHandoff())
            } catch (failure: Throwable) {
                callerFailure.set(failure)
            }
        }.also {
            it.isDaemon = true
            it.start()
        }

        try {
            assertTrue(commitReached.await(1, TimeUnit.SECONDS))
            assertEquals(
                DovecotBoundedOperationSnapshot(
                    activeOperations = 1,
                    peakActors = 1,
                ),
                workers.snapshot(),
            )
            assertNull(workers.tryAcquire(deadlineAfter()))
        } finally {
            releaseCommit.countDown()
            caller.join(1_000)
        }

        assertFalse(caller.isAlive)
        assertEquals(null, callerFailure.get())
        assertTrue(committed.get())
        assertEquals(
            DovecotBoundedOperationSnapshot(peakActors = 1),
            workers.snapshot(),
        )
    }

    @Test
    fun callerInterruptedAfterWorkerExitAbandonsWhileLedgerIsAuthoritative() {
        val commitReached = CountDownLatch(1)
        val releaseCommit = CountDownLatch(1)
        val abortStarted = CountDownLatch(1)
        val closeStarted = CountDownLatch(1)
        val releaseCancellation = CountDownLatch(1)
        val callerFailure = AtomicReference<Throwable?>()
        val interruptRestored = AtomicBoolean()
        val workers = DovecotBoundedOperationWorkers(
            maxOperations = 1,
            beforeOwnershipCommit = {
                commitReached.countDown()
                awaitUninterruptibly(releaseCommit)
            },
        )
        val operation = workers.tryAcquire(deadlineAfter())!!
        operation.execute<Unit> {
            registerCancellationTarget(
                identity = Any(),
                abort = {
                    abortStarted.countDown()
                    releaseCancellation.await()
                },
                close = {
                    closeStarted.countDown()
                    releaseCancellation.await()
                },
            )
        }
        val caller = Thread {
            try {
                operation.commitHandoff()
            } catch (failure: Throwable) {
                callerFailure.set(failure)
                interruptRestored.set(Thread.currentThread().isInterrupted)
            } finally {
                Thread.interrupted()
            }
        }.also {
            it.isDaemon = true
            it.start()
        }

        try {
            assertTrue(commitReached.await(1, TimeUnit.SECONDS))
            assertEquals(1, workers.snapshot().activeOperations)
            assertEquals(0, workers.snapshot().activeActors)

            caller.interrupt()
            releaseCommit.countDown()

            assertTrue(abortStarted.await(1, TimeUnit.SECONDS))
            assertTrue(closeStarted.await(1, TimeUnit.SECONDS))
            caller.join(1_000)
            assertFalse(caller.isAlive)
            assertTrue(callerFailure.get() is InterruptedException)
            assertEquals(
                "Dovecot operation was interrupted",
                callerFailure.get()?.message,
            )
            assertTrue(interruptRestored.get())
            assertEquals(
                DovecotBoundedOperationSnapshot(
                    abandonedOperations = 1,
                    activeActors = 2,
                    peakActors = 2,
                ),
                workers.snapshot(),
            )
            assertNull(workers.tryAcquire(deadlineAfter()))
        } finally {
            releaseCommit.countDown()
            releaseCancellation.countDown()
            caller.join(1_000)
        }

        assertEventually {
            workers.snapshot() ==
                DovecotBoundedOperationSnapshot(peakActors = 2)
        }
    }

    @Test
    fun interruptionDuringFinalClockSampleCannotEscapeWithCommittedOwnership() {
        val interruptOnFinalClock = AtomicBoolean()
        val cancellationCalls = AtomicInteger()
        val callerFailure = AtomicReference<Throwable?>()
        val committed = AtomicBoolean()
        val interruptRestored = AtomicBoolean()
        val workers = DovecotBoundedOperationWorkers(
            maxOperations = 1,
            beforeOwnershipCommit = {
                interruptOnFinalClock.set(true)
            },
            nanoTime = {
                val sampled = System.nanoTime()
                if (interruptOnFinalClock.compareAndSet(true, false)) {
                    Thread.currentThread().interrupt()
                }
                sampled
            },
        )
        val operation = workers.tryAcquire(deadlineAfter())!!
        operation.execute<Unit> {
            registerCancellationTarget(
                identity = Any(),
                abort = cancellationCalls::incrementAndGet,
                close = cancellationCalls::incrementAndGet,
            )
        }
        val caller = Thread {
            try {
                committed.set(operation.commitHandoff())
            } catch (failure: Throwable) {
                callerFailure.set(failure)
                interruptRestored.set(Thread.currentThread().isInterrupted)
            } finally {
                Thread.interrupted()
            }
        }.also {
            it.isDaemon = true
            it.start()
        }

        caller.join(1_000)

        assertFalse(caller.isAlive)
        assertFalse(committed.get())
        assertTrue(callerFailure.get() is InterruptedException)
        assertEquals(
            "Dovecot operation was interrupted",
            callerFailure.get()?.message,
        )
        assertTrue(interruptRestored.get())
        assertEventually {
            cancellationCalls.get() == 2 &&
                workers.snapshot() ==
                DovecotBoundedOperationSnapshot(peakActors = 2)
        }
    }

    @Test
    fun deadlineAfterWorkerExitAbandonsBeforeHandoffCommit() {
        val clock = AtomicLong()
        val deadline = TimeUnit.SECONDS.toNanos(5)
        val commitReached = CountDownLatch(1)
        val releaseCommit = CountDownLatch(1)
        val cancellationStarted = CountDownLatch(2)
        val releaseCancellation = CountDownLatch(1)
        val committed = AtomicBoolean(true)
        val callerFailure = AtomicReference<Throwable?>()
        val workers = DovecotBoundedOperationWorkers(
            maxOperations = 1,
            nanoTime = clock::get,
            beforeOwnershipCommit = {
                commitReached.countDown()
                awaitUninterruptibly(releaseCommit)
            },
        )
        val operation = workers.tryAcquire(deadline)!!
        operation.execute<Unit> {
            registerCancellationTarget(
                identity = Any(),
                abort = {
                    cancellationStarted.countDown()
                    releaseCancellation.await()
                },
                close = {
                    cancellationStarted.countDown()
                    releaseCancellation.await()
                },
            )
        }
        val caller = Thread {
            try {
                committed.set(operation.commitHandoff())
            } catch (failure: Throwable) {
                callerFailure.set(failure)
            }
        }.also {
            it.isDaemon = true
            it.start()
        }

        try {
            assertTrue(commitReached.await(1, TimeUnit.SECONDS))
            assertEquals(1, workers.snapshot().activeOperations)
            assertEquals(0, workers.snapshot().activeActors)

            clock.set(deadline)
            releaseCommit.countDown()

            assertTrue(cancellationStarted.await(1, TimeUnit.SECONDS))
            caller.join(1_000)
            assertFalse(caller.isAlive)
            assertEquals(null, callerFailure.get())
            assertFalse(committed.get())
            assertEquals(
                DovecotBoundedOperationSnapshot(
                    abandonedOperations = 1,
                    activeActors = 2,
                    peakActors = 2,
                ),
                workers.snapshot(),
            )
        } finally {
            releaseCommit.countDown()
            releaseCancellation.countDown()
            caller.join(1_000)
        }

        assertEventually {
            workers.snapshot() ==
                DovecotBoundedOperationSnapshot(peakActors = 2)
        }
    }

    @Test
    fun callerFailureAfterWorkerExitAbandonsAndPreservesTheExactFailure() {
        val failure = IllegalStateException("ownership commit sentinel")
        val cancellationCalls = AtomicInteger()
        val workers = DovecotBoundedOperationWorkers(
            maxOperations = 1,
            beforeOwnershipCommit = { throw failure },
        )
        val operation = workers.tryAcquire(deadlineAfter())!!
        operation.execute<Unit> {
            registerCancellationTarget(
                identity = Any(),
                abort = cancellationCalls::incrementAndGet,
                close = cancellationCalls::incrementAndGet,
            )
        }

        assertSame(
            failure,
            assertFailsWith<IllegalStateException> {
                operation.commitHandoff()
            },
        )

        assertEventually {
            cancellationCalls.get() == 2 &&
                workers.snapshot() ==
                DovecotBoundedOperationSnapshot(peakActors = 2)
        }
    }

    @Test
    fun postExitHookFailureWithoutTargetsReleasesItsReservation() {
        val failure = IllegalStateException("zero-target commit sentinel")
        val failFirstCommit = AtomicBoolean(true)
        val workers = DovecotBoundedOperationWorkers(
            maxOperations = 1,
            beforeOwnershipCommit = {
                if (failFirstCommit.compareAndSet(true, false)) {
                    throw failure
                }
            },
        )
        val operation = workers.tryAcquire(deadlineAfter())!!
        operation.execute<Unit> {}

        assertSame(
            failure,
            assertFailsWith<IllegalStateException> {
                operation.commitHandoff()
            },
        )

        assertZeroTargetCapacityRecovered(workers)
    }

    @Test
    fun postExitInterruptionWithoutTargetsReleasesItsReservation() {
        val commitReached = CountDownLatch(1)
        val releaseCommit = CountDownLatch(1)
        val callerFailure = AtomicReference<Throwable?>()
        val interruptRestored = AtomicBoolean()
        val workers = DovecotBoundedOperationWorkers(
            maxOperations = 1,
            beforeOwnershipCommit = {
                commitReached.countDown()
                awaitUninterruptibly(releaseCommit)
            },
        )
        val operation = workers.tryAcquire(deadlineAfter())!!
        operation.execute<Unit> {}
        val caller = Thread {
            try {
                operation.commitHandoff()
            } catch (failure: Throwable) {
                callerFailure.set(failure)
                interruptRestored.set(Thread.currentThread().isInterrupted)
            } finally {
                Thread.interrupted()
            }
        }.also {
            it.isDaemon = true
            it.start()
        }

        try {
            assertTrue(commitReached.await(1, TimeUnit.SECONDS))
            caller.interrupt()
            releaseCommit.countDown()
            caller.join(1_000)
        } finally {
            releaseCommit.countDown()
            caller.join(1_000)
        }

        assertFalse(caller.isAlive)
        assertTrue(callerFailure.get() is InterruptedException)
        assertTrue(interruptRestored.get())
        assertZeroTargetCapacityRecovered(workers)
    }

    @Test
    fun postExitExpiryWithoutTargetsReleasesItsReservation() {
        val clock = AtomicLong()
        val deadline = TimeUnit.SECONDS.toNanos(5)
        val commitReached = CountDownLatch(1)
        val releaseCommit = CountDownLatch(1)
        val committed = AtomicBoolean(true)
        val callerFailure = AtomicReference<Throwable?>()
        val workers = DovecotBoundedOperationWorkers(
            maxOperations = 1,
            nanoTime = clock::get,
            beforeOwnershipCommit = {
                commitReached.countDown()
                awaitUninterruptibly(releaseCommit)
            },
        )
        val operation = workers.tryAcquire(deadline)!!
        operation.execute<Unit> {}
        val caller = Thread {
            try {
                committed.set(operation.commitHandoff())
            } catch (failure: Throwable) {
                callerFailure.set(failure)
            }
        }.also {
            it.isDaemon = true
            it.start()
        }

        try {
            assertTrue(commitReached.await(1, TimeUnit.SECONDS))
            clock.set(deadline)
            releaseCommit.countDown()
            caller.join(1_000)
        } finally {
            releaseCommit.countDown()
            caller.join(1_000)
        }

        assertFalse(caller.isAlive)
        assertEquals(null, callerFailure.get())
        assertFalse(committed.get())
        assertZeroTargetCapacityRecovered(workers)
    }

    @Test
    fun concurrentHandoffCommitIsRejectedBeforeItCanRaceTheOwner() {
        val commitReached = CountDownLatch(1)
        val releaseCommit = CountDownLatch(1)
        val workers = DovecotBoundedOperationWorkers(
            maxOperations = 1,
            beforeOwnershipCommit = {
                commitReached.countDown()
                awaitUninterruptibly(releaseCommit)
            },
        )
        val operation = workers.tryAcquire(deadlineAfter())!!
        operation.execute<Unit> {}
        val firstCommitted = AtomicBoolean()
        val firstFailure = AtomicReference<Throwable?>()
        val first = Thread {
            try {
                firstCommitted.set(operation.commitHandoff())
            } catch (failure: Throwable) {
                firstFailure.set(failure)
            }
        }.also {
            it.isDaemon = true
            it.start()
        }

        assertTrue(commitReached.await(1, TimeUnit.SECONDS))
        val secondStarted = CountDownLatch(1)
        val secondFailure = AtomicReference<Throwable?>()
        val second = Thread {
            secondStarted.countDown()
            try {
                operation.commitHandoff()
            } catch (failure: Throwable) {
                secondFailure.set(failure)
            }
        }.also {
            it.isDaemon = true
            it.start()
        }

        try {
            assertTrue(secondStarted.await(1, TimeUnit.SECONDS))
            second.join(500)
            assertFalse(
                second.isAlive,
                "A second handoff caller entered the ownership seam",
            )
            assertTrue(secondFailure.get() is IllegalStateException)
            assertEquals(
                "Dovecot operation handoff is already being committed",
                secondFailure.get()?.message,
            )
            assertEquals(1, workers.snapshot().activeOperations)
        } finally {
            releaseCommit.countDown()
            first.join(1_000)
            second.join(1_000)
        }

        assertFalse(first.isAlive)
        assertFalse(second.isAlive)
        assertEquals(null, firstFailure.get())
        assertTrue(firstCommitted.get())
        assertEquals(
            DovecotBoundedOperationSnapshot(peakActors = 1),
            workers.snapshot(),
        )
    }

    @Test
    fun timeoutAbandonsTheChargeAndStartsIndependentCancellationActors() {
        val ioStarted = CountDownLatch(1)
        val releaseIo = CountDownLatch(1)
        val abortStarted = CountDownLatch(1)
        val closeStarted = CountDownLatch(1)
        val releaseCancellation = CountDownLatch(1)
        val workers = DovecotBoundedOperationWorkers(maxOperations = 1)
        val operation = workers.tryAcquire(
            deadlineAfter(Duration.ofMillis(50)),
        )!!

        try {
            assertFailsWith<DovecotBoundedOperationTimeoutException> {
                operation.execute<Unit> {
                    registerCancellationTarget(
                        identity = this,
                        abort = {
                            abortStarted.countDown()
                            releaseCancellation.await()
                        },
                        close = {
                            closeStarted.countDown()
                            releaseCancellation.await()
                        },
                    )
                    ioStarted.countDown()
                    releaseIo.await()
                }
            }

            assertTrue(ioStarted.await(1, TimeUnit.SECONDS))
            assertTrue(abortStarted.await(1, TimeUnit.SECONDS))
            assertTrue(closeStarted.await(1, TimeUnit.SECONDS))
            assertEquals(
                DovecotBoundedOperationSnapshot(
                    activeOperations = 0,
                    abandonedOperations = 1,
                    activeActors = 3,
                    peakActors = 3,
                ),
                workers.snapshot(),
            )
            assertNull(workers.tryAcquire(deadlineAfter()))
        } finally {
            releaseIo.countDown()
            releaseCancellation.countDown()
        }

        assertEventually {
            workers.snapshot().let {
                it.activeOperations == 0 &&
                    it.abandonedOperations == 0 &&
                    it.activeActors == 0
            }
        }
        assertTrue(
            workers.tryAcquire(deadlineAfter())!!.commitHandoff(),
        )
    }

    @Test
    fun fullCapacityRejectsBeforeAllocationOrAnotherActor() {
        val ioStarted = CountDownLatch(1)
        val releaseIo = CountDownLatch(1)
        val workers = DovecotBoundedOperationWorkers(maxOperations = 1)
        val operation = workers.tryAcquire(
            deadlineAfter(Duration.ofMillis(50)),
        )!!
        val callerFinished = CountDownLatch(1)
        val caller = Thread {
            try {
                operation.execute<Unit> {
                    ioStarted.countDown()
                    releaseIo.await()
                }
            } catch (_: DovecotBoundedOperationTimeoutException) {
                // Expected.
            } finally {
                callerFinished.countDown()
            }
        }.also {
            it.isDaemon = true
            it.start()
        }

        try {
            assertTrue(ioStarted.await(1, TimeUnit.SECONDS))
            assertTrue(callerFinished.await(1, TimeUnit.SECONDS))
            val actorsBefore = workers.snapshot().activeActors
            val allocated = AtomicBoolean()

            val rejected = workers.tryAcquire(deadlineAfter())
            if (rejected != null) {
                allocated.set(true)
                rejected.commitHandoff()
            }

            assertNull(rejected)
            assertFalse(allocated.get())
            assertEquals(actorsBefore, workers.snapshot().activeActors)
        } finally {
            releaseIo.countDown()
            caller.join(1_000)
        }
    }

    @Test
    fun cancellationActorStartFailureReleasesItsActorCharge() {
        val ioStarted = CountDownLatch(1)
        val releaseIo = CountDownLatch(1)
        val closeStarted = CountDownLatch(1)
        val releaseClose = CountDownLatch(1)
        val failedStarts = AtomicInteger()
        val launcher = DovecotBoundedActorLauncher { role, name, action ->
            if (role == DovecotBoundedActorRole.Abort) {
                failedStarts.incrementAndGet()
                throw IllegalStateException("injected actor-start failure")
            }
            Thread(action, name).also {
                it.isDaemon = true
                it.start()
            }
        }
        val workers = DovecotBoundedOperationWorkers(
            maxOperations = 1,
            actorLauncher = launcher,
        )
        val operation = workers.tryAcquire(
            deadlineAfter(Duration.ofMillis(50)),
        )!!

        try {
            assertFailsWith<DovecotBoundedOperationTimeoutException> {
                operation.execute<Unit> {
                    registerCancellationTarget(
                        identity = this,
                        abort = {},
                        close = {
                            closeStarted.countDown()
                            releaseClose.await()
                        },
                    )
                    ioStarted.countDown()
                    releaseIo.await()
                }
            }

            assertTrue(ioStarted.await(1, TimeUnit.SECONDS))
            assertTrue(closeStarted.await(1, TimeUnit.SECONDS))
            assertEquals(1, failedStarts.get())
            assertEquals(2, workers.snapshot().activeActors)
        } finally {
            releaseIo.countDown()
            releaseClose.countDown()
        }

        assertEventually {
            workers.snapshot().let {
                it.activeOperations == 0 &&
                    it.abandonedOperations == 0 &&
                    it.activeActors == 0
            }
        }
    }

    @Test
    fun initializationAndIoActorStartFailuresReleaseTheirReservations() {
        val initializationFailure = IllegalStateException("initialization")
        val initializationWorkers = DovecotBoundedOperationWorkers(
            beforeOperationStart = { throw initializationFailure },
        )

        assertSame(
            initializationFailure,
            assertFailsWith<IllegalStateException> {
                initializationWorkers.tryAcquire(deadlineAfter())
            },
        )
        assertEquals(
            DovecotBoundedOperationSnapshot(),
            initializationWorkers.snapshot(),
        )

        val failFirstIoStart = AtomicBoolean(true)
        val actorFailure = IllegalStateException("I/O actor start")
        val actorWorkers = DovecotBoundedOperationWorkers(
            actorLauncher = DovecotBoundedActorLauncher { _, name, action ->
                if (failFirstIoStart.compareAndSet(true, false)) {
                    throw actorFailure
                }
                startDaemon(name, action)
            },
        )

        assertSame(
            actorFailure,
            assertFailsWith<IllegalStateException> {
                actorWorkers.tryAcquire(deadlineAfter())
            },
        )
        assertEquals(
            DovecotBoundedOperationSnapshot(peakActors = 1),
            actorWorkers.snapshot(),
        )
        assertTrue(
            actorWorkers.tryAcquire(deadlineAfter())!!.commitHandoff(),
        )
        assertEventually {
            actorWorkers.snapshot().let {
                it.activeOperations == 0 && it.activeActors == 0
            }
        }
    }

    @Test
    fun operationConstructionFailureReleasesItsReservation() {
        val constructionFailure = IllegalStateException("construction")
        val workers = DovecotBoundedOperationWorkers(
            maxOperations = 1,
            beforeOperationConstruction = { throw constructionFailure },
        )

        assertSame(
            constructionFailure,
            assertFailsWith<IllegalStateException> {
                workers.tryAcquire(deadlineAfter())
            },
        )
        assertEquals(DovecotBoundedOperationSnapshot(), workers.snapshot())
    }

    @Test
    fun taskSubmissionFailureWipesTheUnsubmittedWorkerCopyAndReleases() {
        val capturedCopy = AtomicReference<ByteArray>()
        val wipeCalls = AtomicInteger()
        val failFirstSubmission = AtomicBoolean(true)
        val submissionFailure = IllegalStateException("task submission")
        val workers = DovecotBoundedOperationWorkers(
            beforeTaskSubmission = {
                if (failFirstSubmission.compareAndSet(true, false)) {
                    throw submissionFailure
                }
            },
            copyBytes = { source ->
                source.copyOf().also(capturedCopy::set)
            },
            wipeBytes = { bytes ->
                wipeCalls.incrementAndGet()
                bytes.fill(0)
            },
        )
        val source = byteArrayOf(9, 8, 7)
        val operation = workers.tryAcquire(deadlineAfter())!!

        assertSame(
            submissionFailure,
            assertFailsWith<IllegalStateException> {
                operation.executeWithCopiedBytes<Unit>(
                    source = source,
                ) {
                    error("rejected task must never run")
                }
            },
        )
        assertEquals(listOf<Byte>(9, 8, 7), source.toList())
        assertNotSame(source, capturedCopy.get())
        assertTrue(capturedCopy.get().all { it == 0.toByte() })
        assertEquals(1, wipeCalls.get())
        assertEventually {
            workers.snapshot().let {
                it.activeOperations == 0 &&
                    it.abandonedOperations == 0 &&
                    it.activeActors == 0
            }
        }
        source.fill(0)
    }

    @Test
    fun timeoutBeforeDequeueWipesTheWorkerCopyWithoutRunningTheTask() {
        val releaseIoStart = CountDownLatch(1)
        val taskRan = AtomicBoolean()
        val capturedCopy = AtomicReference<ByteArray>()
        val wipeCalls = AtomicInteger()
        val workers = DovecotBoundedOperationWorkers(
            actorLauncher = DovecotBoundedActorLauncher { _, name, action ->
                startDaemon(name) {
                    releaseIoStart.await()
                    action.run()
                }
            },
            copyBytes = { source ->
                source.copyOf().also(capturedCopy::set)
            },
            wipeBytes = { bytes ->
                wipeCalls.incrementAndGet()
                bytes.fill(0)
            },
        )
        val source = byteArrayOf(6, 5, 4)
        val operation = workers.tryAcquire(
            deadlineAfter(Duration.ofMillis(50)),
        )!!

        assertFailsWith<DovecotBoundedOperationTimeoutException> {
            operation.executeWithCopiedBytes<Unit>(
                source = source,
            ) {
                taskRan.set(true)
            }
        }
        assertFalse(taskRan.get())
        assertEquals(listOf<Byte>(6, 5, 4), source.toList())
        assertNotSame(source, capturedCopy.get())

        releaseIoStart.countDown()
        assertEventually {
            capturedCopy.get().all { it == 0.toByte() } &&
                workers.snapshot().let {
                    it.abandonedOperations == 0 && it.activeActors == 0
                }
        }
        assertEquals(1, wipeCalls.get())
        source.fill(0)
    }

    @Test
    fun completionAtDeadlineIsDeclinedAndDisposedByTheIoWorker() {
        val clock = AtomicLong()
        val deadline = TimeUnit.SECONDS.toNanos(1)
        val blockStarted = CountDownLatch(1)
        val releaseResult = CountDownLatch(1)
        val resultReference = AtomicReference<ByteArray>()
        val disposerThread = AtomicReference<String>()
        val disposalCalls = AtomicInteger()
        val callerFailure = AtomicReference<Throwable>()
        val workers = DovecotBoundedOperationWorkers(nanoTime = clock::get)
        val operation = workers.tryAcquire(deadline)!!
        val caller = Thread {
            try {
                operation.execute(
                    disposeLate = { result: ByteArray ->
                        disposalCalls.incrementAndGet()
                        disposerThread.set(Thread.currentThread().name)
                        result.fill(0)
                    },
                ) {
                    blockStarted.countDown()
                    releaseResult.await()
                    byteArrayOf(3, 2, 1).also(resultReference::set)
                }
            } catch (failure: Throwable) {
                callerFailure.set(failure)
            }
        }.also {
            it.isDaemon = true
            it.start()
        }

        assertTrue(blockStarted.await(1, TimeUnit.SECONDS))
        clock.set(deadline)
        releaseResult.countDown()
        caller.join(1_000)

        assertFalse(caller.isAlive)
        assertTrue(
            callerFailure.get() is DovecotBoundedOperationTimeoutException,
        )
        assertEventually {
            resultReference.get().all { it == 0.toByte() } &&
                workers.snapshot().activeActors == 0
        }
        assertTrue(
            disposerThread.get().startsWith("dovecot-bounded-operation-io-"),
        )
        assertEquals(1, disposalCalls.get())
    }

    @Test
    fun workerInterruptedFailureCannotBeDemotedBeforeCallerClaimsIt() {
        val workerInterruptHandled = CountDownLatch(1)
        val callerFailure = AtomicReference<Throwable>()
        val callerInterruptRestored = AtomicBoolean()
        val workers = DovecotBoundedOperationWorkers(
            beforeTaskClaim = {
                assertTrue(
                    workerInterruptHandled.await(1, TimeUnit.SECONDS),
                )
            },
            afterWorkerDispositionInterrupt = {
                workerInterruptHandled.countDown()
            },
        )
        val operation = workers.tryAcquire(deadlineAfter())!!
        val caller = Thread {
            try {
                operation.execute<Unit> {
                    Thread.currentThread().interrupt()
                    throw InterruptedException("worker interruption")
                }
            } catch (failure: Throwable) {
                callerFailure.set(failure)
                callerInterruptRestored.set(
                    Thread.currentThread().isInterrupted,
                )
            } finally {
                Thread.interrupted()
            }
        }.also {
            it.isDaemon = true
            it.start()
        }

        caller.join(1_000)

        assertFalse(caller.isAlive)
        assertTrue(callerFailure.get() is InterruptedException)
        assertEquals(
            "Dovecot operation was interrupted",
            callerFailure.get().message,
        )
        assertFalse(
            callerFailure.get().toString().contains("worker interruption"),
        )
        assertTrue(callerInterruptRestored.get())
        assertEventually {
            workers.snapshot() ==
                DovecotBoundedOperationSnapshot(peakActors = 1)
        }
    }

    @Test
    fun resultClaimCrossingDeadlineIsTimedOutAndDisposed() {
        val clock = AtomicLong()
        val deadline = TimeUnit.SECONDS.toNanos(5)
        val resultReference = AtomicReference<ByteArray>()
        val disposalCalls = AtomicInteger()
        val workers = DovecotBoundedOperationWorkers(
            nanoTime = handoffClock(clock),
            beforeTaskClaim = { clock.set(deadline) },
        )
        val operation = workers.tryAcquire(deadline)!!

        val failure = runCatching {
            operation.execute(
                disposeLate = { result: ByteArray ->
                    disposalCalls.incrementAndGet()
                    result.fill(0)
                },
            ) {
                byteArrayOf(4, 5, 6).also(resultReference::set)
            }
        }.exceptionOrNull()
        operation.abandon()

        try {
            assertTrue(failure is DovecotBoundedOperationTimeoutException)
            assertEventually {
                resultReference.get().all { it == 0.toByte() } &&
                    workers.snapshot() ==
                    DovecotBoundedOperationSnapshot(peakActors = 1)
            }
            assertEquals(1, disposalCalls.get())
        } finally {
            resultReference.get()?.fill(0)
        }
    }

    @Test
    fun failureClaimCrossingDeadlineIsTimedOut() {
        val clock = AtomicLong()
        val deadline = TimeUnit.SECONDS.toNanos(5)
        val workers = DovecotBoundedOperationWorkers(
            nanoTime = handoffClock(clock),
            beforeTaskClaim = { clock.set(deadline) },
        )
        val operation = workers.tryAcquire(deadline)!!

        val failure = runCatching {
            operation.execute<Unit> {
                throw IOException("worker failure")
            }
        }.exceptionOrNull()

        assertTrue(failure is DovecotBoundedOperationTimeoutException)
        assertEventually {
            workers.snapshot() ==
                DovecotBoundedOperationSnapshot(peakActors = 1)
        }
    }

    @Test
    fun interruptedFailureClaimedAtDeadlineKeepsPrecedence() {
        val clock = AtomicLong()
        val deadline = TimeUnit.SECONDS.toNanos(5)
        val workers = DovecotBoundedOperationWorkers(
            nanoTime = handoffClock(clock),
            beforeTaskClaim = { clock.set(deadline) },
        )
        val operation = workers.tryAcquire(deadline)!!

        try {
            val failure = assertFailsWith<InterruptedException> {
                operation.execute<Unit> {
                    throw InterruptedException("worker interruption")
                }
            }

            assertEquals("Dovecot operation was interrupted", failure.message)
            assertTrue(Thread.currentThread().isInterrupted)
        } finally {
            Thread.interrupted()
        }
        assertEventually {
            workers.snapshot() ==
                DovecotBoundedOperationSnapshot(peakActors = 1)
        }
    }

    @Test
    fun cancellationLedgerDeduplicatesIdentityAndRejectsAThirdTarget() {
        val firstCalls = AtomicInteger()
        val duplicateCalls = AtomicInteger()
        val secondCalls = AtomicInteger()
        val thirdCalls = AtomicInteger()
        val first = Any()
        val second = Any()
        val third = Any()
        val workers = DovecotBoundedOperationWorkers()
        val operation = workers.tryAcquire(deadlineAfter())!!

        assertFailsWith<IllegalStateException> {
            operation.execute<Unit> {
                registerCancellationTarget(
                    first,
                    abort = firstCalls::incrementAndGet,
                    close = firstCalls::incrementAndGet,
                )
                registerCancellationTarget(
                    first,
                    abort = duplicateCalls::incrementAndGet,
                    close = duplicateCalls::incrementAndGet,
                )
                registerCancellationTarget(
                    second,
                    abort = secondCalls::incrementAndGet,
                    close = secondCalls::incrementAndGet,
                )
                registerCancellationTarget(
                    third,
                    abort = thirdCalls::incrementAndGet,
                    close = thirdCalls::incrementAndGet,
                )
            }
        }

        assertEventually {
            workers.snapshot().let {
                it.abandonedOperations == 0 && it.activeActors == 0
            }
        }
        assertEquals(2, firstCalls.get())
        assertEquals(0, duplicateCalls.get())
        assertEquals(2, secondCalls.get())
        assertEquals(0, thirdCalls.get())
    }

    @Test
    fun fourAbandonedDualTargetOperationsReachTwentyActorsAndRecover() {
        val ioStarted = CountDownLatch(4)
        val cancellationStarted = CountDownLatch(16)
        val callersFinished = CountDownLatch(4)
        val releaseAll = CountDownLatch(1)
        val workers = DovecotBoundedOperationWorkers(maxOperations = 4)
        val capacityDeadline = deadlineAfter(Duration.ofMillis(300))
        val operations = List(4) {
            workers.tryAcquire(capacityDeadline)!!
        }
        val callers = operations.mapIndexed { index, operation ->
            Thread {
                try {
                    operation.execute<Unit> {
                        repeat(2) { targetIndex ->
                            registerCancellationTarget(
                                identity = Any(),
                                abort = {
                                    cancellationStarted.countDown()
                                    releaseAll.await()
                                },
                                close = {
                                    cancellationStarted.countDown()
                                    releaseAll.await()
                                },
                            )
                        }
                        ioStarted.countDown()
                        releaseAll.await()
                    }
                } catch (_: DovecotBoundedOperationTimeoutException) {
                    // Expected.
                } finally {
                    callersFinished.countDown()
                }
            }.also {
                it.name = "bounded-cap-caller-$index"
                it.isDaemon = true
                it.start()
            }
        }

        try {
            assertTrue(ioStarted.await(1, TimeUnit.SECONDS))
            assertTrue(callersFinished.await(2, TimeUnit.SECONDS))
            assertTrue(cancellationStarted.await(1, TimeUnit.SECONDS))
            assertEquals(
                DovecotBoundedOperationSnapshot(
                    abandonedOperations = 4,
                    activeActors = 20,
                    peakActors = 20,
                ),
                workers.snapshot(),
            )
            assertNull(workers.tryAcquire(deadlineAfter()))
        } finally {
            releaseAll.countDown()
            callers.forEach { it.join(1_000) }
        }

        assertEventually {
            workers.snapshot().let {
                it.activeOperations == 0 &&
                    it.abandonedOperations == 0 &&
                    it.activeActors == 0 &&
                    it.peakActors == 20
            }
        }
        assertTrue(
            workers.tryAcquire(deadlineAfter())!!.commitHandoff(),
        )
    }

    @Test
    fun aTargetRegisteredAfterTimeoutStillUsesTheSealedLedger() {
        val blockStarted = CountDownLatch(1)
        val releaseRegistration = CountDownLatch(1)
        val cancellationCalls = CountDownLatch(2)
        val callerFinished = CountDownLatch(1)
        val workers = DovecotBoundedOperationWorkers(maxOperations = 1)
        val operation = workers.tryAcquire(
            deadlineAfter(Duration.ofMillis(50)),
        )!!
        val caller = Thread {
            try {
                operation.execute<Unit> {
                    blockStarted.countDown()
                    releaseRegistration.await()
                    registerCancellationTarget(
                        identity = Any(),
                        abort = cancellationCalls::countDown,
                        close = cancellationCalls::countDown,
                    )
                }
            } catch (_: DovecotBoundedOperationTimeoutException) {
                // Expected.
            } finally {
                callerFinished.countDown()
            }
        }.also {
            it.isDaemon = true
            it.start()
        }

        assertTrue(blockStarted.await(1, TimeUnit.SECONDS))
        assertTrue(callerFinished.await(1, TimeUnit.SECONDS))
        assertEquals(1, workers.snapshot().abandonedOperations)
        assertEquals(1, workers.snapshot().activeActors)
        releaseRegistration.countDown()
        assertTrue(cancellationCalls.await(1, TimeUnit.SECONDS))
        caller.join(1_000)
        assertEventually {
            workers.snapshot().let {
                it.abandonedOperations == 0 && it.activeActors == 0
            }
        }
    }

    @Test
    fun explicitAbandonDeclinesAnInFlightCallerWithoutDeadlineWait() {
        val blockStarted = CountDownLatch(1)
        val releaseBlock = CountDownLatch(1)
        val callerFailure = AtomicReference<Throwable>()
        val workers = DovecotBoundedOperationWorkers()
        val operation = workers.tryAcquire(deadlineAfter())!!
        val caller = Thread {
            try {
                operation.execute<Unit> {
                    blockStarted.countDown()
                    releaseBlock.await()
                }
            } catch (failure: Throwable) {
                callerFailure.set(failure)
            }
        }.also {
            it.isDaemon = true
            it.start()
        }

        try {
            assertTrue(blockStarted.await(1, TimeUnit.SECONDS))
            operation.abandon()
            caller.join(500)

            assertFalse(caller.isAlive)
            assertTrue(
                callerFailure.get() is
                    DovecotBoundedOperationTimeoutException,
            )
        } finally {
            releaseBlock.countDown()
            caller.join(1_000)
        }
        assertEventually {
            workers.snapshot().let {
                it.abandonedOperations == 0 && it.activeActors == 0
            }
        }
    }

    @Test
    fun callerInterruptionIsRedactedRestoredAndFullyAccounted() {
        val blockStarted = CountDownLatch(1)
        val releaseBlock = CountDownLatch(1)
        val cancellationCalls = CountDownLatch(2)
        val callerFailure = AtomicReference<Throwable>()
        val interruptRestored = AtomicBoolean()
        val workers = DovecotBoundedOperationWorkers()
        val operation = workers.tryAcquire(deadlineAfter())!!
        val caller = Thread {
            try {
                operation.execute<Unit> {
                    registerCancellationTarget(
                        identity = Any(),
                        abort = cancellationCalls::countDown,
                        close = cancellationCalls::countDown,
                    )
                    blockStarted.countDown()
                    releaseBlock.await()
                }
            } catch (failure: Throwable) {
                callerFailure.set(failure)
                interruptRestored.set(Thread.currentThread().isInterrupted)
            }
        }.also {
            it.isDaemon = true
            it.start()
        }

        try {
            assertTrue(blockStarted.await(1, TimeUnit.SECONDS))
            caller.interrupt()
            caller.join(500)

            assertFalse(caller.isAlive)
            assertTrue(callerFailure.get() is InterruptedException)
            assertEquals(
                "Dovecot operation was interrupted",
                callerFailure.get().message,
            )
            assertTrue(interruptRestored.get())
            assertTrue(cancellationCalls.await(1, TimeUnit.SECONDS))
        } finally {
            releaseBlock.countDown()
            caller.join(1_000)
        }
        assertEventually {
            workers.snapshot().let {
                it.abandonedOperations == 0 && it.activeActors == 0
            }
        }
    }

    @Test
    fun acquisitionDeadlineCannotBeExtendedByALaterTask() {
        val clock = AtomicLong()
        val deadline = 100L
        val taskRan = AtomicBoolean()
        val workers = DovecotBoundedOperationWorkers(nanoTime = clock::get)
        val operation = workers.tryAcquire(deadline)!!

        clock.set(deadline)
        assertFailsWith<DovecotBoundedOperationTimeoutException> {
            operation.execute<Unit> {
                taskRan.set(true)
            }
        }

        assertFalse(taskRan.get())
        assertEventually {
            workers.snapshot().let {
                it.abandonedOperations == 0 && it.activeActors == 0
            }
        }
    }

    @Test
    fun callerCannotReuseTheWorkerContextToRegisterATarget() {
        val workers = DovecotBoundedOperationWorkers()
        val operation = workers.tryAcquire(deadlineAfter())!!
        val context = operation.execute { this }

        assertFailsWith<IllegalStateException> {
            context.registerCancellationTarget(Any(), abort = {}, close = {})
        }
        assertTrue(operation.commitHandoff())
        assertEventually {
            workers.snapshot().activeActors == 0
        }
    }

    @Test
    fun ownedCoordinatorCannotExceedTheProcessWideHardCap() {
        assertFailsWith<IllegalArgumentException> {
            DovecotBoundedOperationWorkers(maxOperations = 5)
        }
    }

    @Test
    fun abandoningAnAlreadyReleasedOperationCannotUnderflowAccounting() {
        val workers = DovecotBoundedOperationWorkers(maxOperations = 1)
        val operation = workers.tryAcquire(deadlineAfter())!!
        assertTrue(operation.commitHandoff())
        assertEventually {
            workers.snapshot().activeOperations == 0
        }

        assertFailsWith<DovecotBoundedOperationTimeoutException> {
            operation.execute<Unit> {}
        }
        assertEquals(
            DovecotBoundedOperationSnapshot(peakActors = 1),
            workers.snapshot(),
        )
    }

    @Test
    fun anExpiredDeadlineIsRejectedBeforeStartingAnActor() {
        val starts = AtomicInteger()
        val workers = DovecotBoundedOperationWorkers(
            actorLauncher = DovecotBoundedActorLauncher { _, _, _ ->
                starts.incrementAndGet()
            },
        )

        assertNull(workers.tryAcquire(System.nanoTime()))
        assertEquals(0, starts.get())
        assertEquals(DovecotBoundedOperationSnapshot(), workers.snapshot())
    }

    private fun deadlineAfter(
        duration: Duration = Duration.ofSeconds(2),
    ): Long = Math.addExact(System.nanoTime(), duration.toNanos())

    private fun handoffClock(clock: AtomicLong): () -> Long = {
        if (
            Thread.currentThread().name.startsWith(
                "dovecot-bounded-operation-io-",
            )
        ) {
            0L
        } else {
            clock.get()
        }
    }

    private fun assertEventually(assertion: () -> Boolean) {
        val deadline = deadlineAfter()
        while (!assertion() && System.nanoTime() - deadline < 0L) {
            Thread.sleep(5)
        }
        assertTrue(assertion())
    }

    private fun assertZeroTargetCapacityRecovered(
        workers: DovecotBoundedOperationWorkers,
    ) {
        assertEventually {
            workers.snapshot().let { snapshot ->
                snapshot.activeOperations == 0 &&
                    snapshot.abandonedOperations == 0 &&
                    snapshot.activeActors == 0
            }
        }
        assertTrue(
            workers.tryAcquire(deadlineAfter())!!.commitHandoff(),
        )
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

    private fun startDaemon(
        name: String,
        action: Runnable,
    ) {
        Thread(action, name).also {
            it.isDaemon = true
            it.start()
        }
    }

    private fun startDaemon(
        name: String,
        action: () -> Unit,
    ) {
        startDaemon(name, Runnable(action))
    }
}
