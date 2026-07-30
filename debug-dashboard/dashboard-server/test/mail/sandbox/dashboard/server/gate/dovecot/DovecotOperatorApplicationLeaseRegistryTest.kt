package mail.sandbox.dashboard.server.gate.dovecot

import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

class DovecotOperatorApplicationLeaseRegistryTest {
    @Test
    fun openingReservationsConsumeExactCapacityBeforeAllocation() {
        val registry =
            DovecotOperatorApplicationLeaseRegistry(DovecotOperatorId.A)
        val allocationActions = AtomicInteger()
        val applicationReservations = (1..15).map {
            registry.reserveOpening(DovecotOperatorId.A) {}
                .also { allocationActions.incrementAndGet() }
        }

        assertFailsWith<IllegalStateException> {
            registry.reserveOpening(DovecotOperatorId.A) {}
            allocationActions.incrementAndGet()
        }
        val verificationReservation =
            registry.reserveVerificationOpening(DovecotOperatorId.A) {}
                .also { allocationActions.incrementAndGet() }
        assertFailsWith<IllegalStateException> {
            registry.reserveVerificationOpening(DovecotOperatorId.A) {}
            allocationActions.incrementAndGet()
        }

        assertEquals(16, allocationActions.get())
        assertEquals(16, registry.openLeaseCount(DovecotOperatorId.A))

        applicationReservations.forEach { reservation ->
            reservation.close()
            reservation.close()
        }
        verificationReservation.close()
        verificationReservation.close()

        assertEquals(0, registry.openLeaseCount(DovecotOperatorId.A))
    }

    @Test
    fun openingReservationReleaseIsIdempotentAndRejectsRecheck() {
        val registry =
            DovecotOperatorApplicationLeaseRegistry(DovecotOperatorId.A)
        val cancellationCalls = AtomicInteger()
        val reservation = registry.reserveOpening(DovecotOperatorId.A) {
            cancellationCalls.incrementAndGet()
        }

        reservation.recheck()
        reservation.close()
        reservation.close()

        assertEquals(0, cancellationCalls.get())
        assertEquals(0, registry.openLeaseCount(DovecotOperatorId.A))
        assertFailsWith<IllegalStateException> {
            reservation.recheck()
        }
    }

    @Test
    fun recheckRejectsAnInactiveOpeningReservation() {
        val registry =
            DovecotOperatorApplicationLeaseRegistry(DovecotOperatorId.A)
        val reservation = registry.reserveOpening(DovecotOperatorId.A) {}

        reservation.recheck()
        registry.activate(DovecotOperatorId.B)

        assertFailsWith<IllegalStateException> {
            reservation.recheck()
        }
        reservation.close()
        assertEquals(0, registry.openLeaseCount(DovecotOperatorId.A))
    }

    @Test
    fun recheckRejectsAnOpeningReservationAfterRuntimeCloseBegins() {
        val registry =
            DovecotOperatorApplicationLeaseRegistry(DovecotOperatorId.A)
        val reservation = registry.reserveOpening(DovecotOperatorId.A) {}

        registry.beginRuntimeClose {}

        assertFailsWith<IllegalStateException> {
            reservation.recheck()
        }
        reservation.close()
        assertEquals(0, registry.openLeaseCount(DovecotOperatorId.A))
    }

    @Test
    fun drainCancelsOpeningOutsideRegistryLockAndWaitsForOwnerRelease() {
        val registry =
            DovecotOperatorApplicationLeaseRegistry(DovecotOperatorId.A)
        val cancellationEntered = CountDownLatch(1)
        val cancellationRelease = CountDownLatch(1)
        val cancellationReturned = CountDownLatch(1)
        val drainFinished = CountDownLatch(1)
        val callbackLeaseCount = AtomicInteger(-1)
        val cancellationCalls = AtomicInteger()
        val drainFailure = AtomicReference<Throwable?>()
        val reservation = registry.reserveOpening(DovecotOperatorId.A) {
            try {
                cancellationCalls.incrementAndGet()
                callbackLeaseCount.set(
                    registry.openLeaseCount(DovecotOperatorId.A),
                )
                cancellationEntered.countDown()
                cancellationRelease.await()
            } finally {
                cancellationReturned.countDown()
            }
        }
        val drain = thread(isDaemon = true, name = "opening-owner-drain") {
            try {
                registry.blockAndDrain(DovecotOperatorId.A)
            } catch (failure: Throwable) {
                drainFailure.set(failure)
            } finally {
                drainFinished.countDown()
            }
        }

        assertTrue(cancellationEntered.await(1, TimeUnit.SECONDS))
        assertEquals(1, callbackLeaseCount.get())
        assertEquals(1, registry.openLeaseCount(DovecotOperatorId.A))
        assertFailsWith<IllegalStateException> {
            reservation.recheck()
        }
        cancellationRelease.countDown()
        assertTrue(cancellationReturned.await(1, TimeUnit.SECONDS))
        assertFalse(drainFinished.await(100, TimeUnit.MILLISECONDS))
        assertEquals(1, registry.openLeaseCount(DovecotOperatorId.A))

        reservation.close()
        assertTrue(drainFinished.await(1, TimeUnit.SECONDS))
        drain.join(1_000)

        assertNull(drainFailure.get())
        assertEquals(1, cancellationCalls.get())
        assertEquals(0, registry.openLeaseCount(DovecotOperatorId.A))
    }

    @Test
    fun drainMarkBeforeOwnerReleaseStillRunsOpeningCancellation() {
        val drainMarked = CountDownLatch(1)
        val closeWorkersRelease = CountDownLatch(1)
        val drainFinished = CountDownLatch(1)
        val cancellationCalls = AtomicInteger()
        val callbackLeaseCount = AtomicInteger(-1)
        val drainFailure = AtomicReference<Throwable?>()
        lateinit var registry: DovecotOperatorApplicationLeaseRegistry
        registry = DovecotOperatorApplicationLeaseRegistry(
            initialActive = DovecotOperatorId.A,
            beforeDrainCloseWorkers = {
                drainMarked.countDown()
                closeWorkersRelease.await()
            },
        )
        val reservation = registry.reserveOpening(DovecotOperatorId.A) {
            cancellationCalls.incrementAndGet()
            callbackLeaseCount.set(
                registry.openLeaseCount(DovecotOperatorId.A),
            )
        }
        val drain = thread(isDaemon = true, name = "marked-owner-release") {
            try {
                registry.blockAndDrain(DovecotOperatorId.A)
            } catch (failure: Throwable) {
                drainFailure.set(failure)
            } finally {
                drainFinished.countDown()
            }
        }

        try {
            assertTrue(drainMarked.await(1, TimeUnit.SECONDS))
            reservation.close()
            assertEquals(0, registry.openLeaseCount(DovecotOperatorId.A))
            assertEquals(0, cancellationCalls.get())
        } finally {
            closeWorkersRelease.countDown()
        }
        assertTrue(drainFinished.await(1, TimeUnit.SECONDS))
        drain.join(1_000)

        assertNull(drainFailure.get())
        assertEquals(1, cancellationCalls.get())
        assertEquals(0, callbackLeaseCount.get())
    }

    @Test
    fun failedOpeningCancellationRemainsTrackedAndIsRetryable() {
        val registry =
            DovecotOperatorApplicationLeaseRegistry(DovecotOperatorId.A)
        val cancellationCalls = AtomicInteger()
        val retryCancellationReturned = CountDownLatch(1)
        val retryDrainFinished = CountDownLatch(1)
        val retryDrainFailure = AtomicReference<Throwable?>()
        val reservation = registry.reserveOpening(DovecotOperatorId.A) {
            if (cancellationCalls.incrementAndGet() == 1) {
                throw TerminalCloseFailure()
            }
            retryCancellationReturned.countDown()
        }

        assertFailsWith<TerminalCloseFailure> {
            registry.blockAndDrain(DovecotOperatorId.A)
        }

        assertEquals(1, registry.openLeaseCount(DovecotOperatorId.A))
        val retryDrain = thread(
            isDaemon = true,
            name = "opening-cancellation-retry",
        ) {
            try {
                registry.blockAndDrain(DovecotOperatorId.A)
            } catch (failure: Throwable) {
                retryDrainFailure.set(failure)
            } finally {
                retryDrainFinished.countDown()
            }
        }
        assertTrue(retryCancellationReturned.await(1, TimeUnit.SECONDS))
        assertFalse(retryDrainFinished.await(100, TimeUnit.MILLISECONDS))
        assertEquals(1, registry.openLeaseCount(DovecotOperatorId.A))

        reservation.close()
        assertTrue(retryDrainFinished.await(1, TimeUnit.SECONDS))
        retryDrain.join(1_000)

        assertNull(retryDrainFailure.get())
        assertEquals(2, cancellationCalls.get())
        assertEquals(0, registry.openLeaseCount(DovecotOperatorId.A))
    }

    @Test
    fun drainWinningBeforeBindPreventsBindAndCommit() {
        val registry =
            DovecotOperatorApplicationLeaseRegistry(DovecotOperatorId.A)
        val cancellationEntered = CountDownLatch(1)
        val drainFinished = CountDownLatch(1)
        val drainFailure = AtomicReference<Throwable?>()
        val sessionCloseCalls = AtomicInteger()
        val reservation = registry.reserveOpening(DovecotOperatorId.A) {
            cancellationEntered.countDown()
        }
        val drain = thread(isDaemon = true, name = "opening-bind-drain") {
            try {
                registry.blockAndDrain(DovecotOperatorId.A)
            } catch (failure: Throwable) {
                drainFailure.set(failure)
            } finally {
                drainFinished.countDown()
            }
        }

        assertTrue(cancellationEntered.await(1, TimeUnit.SECONDS))
        assertFailsWith<IllegalStateException> {
            reservation.bind {
                sessionCloseCalls.incrementAndGet()
            }
        }
        assertFailsWith<IllegalStateException> {
            reservation.commit()
        }
        assertEquals(1, registry.openLeaseCount(DovecotOperatorId.A))

        reservation.close()
        assertTrue(drainFinished.await(1, TimeUnit.SECONDS))
        drain.join(1_000)

        assertNull(drainFailure.get())
        assertEquals(0, sessionCloseCalls.get())
        assertEquals(0, registry.openLeaseCount(DovecotOperatorId.A))
    }

    @Test
    fun bindInstallsExactlyOneSessionCloseCallback() {
        val registry =
            DovecotOperatorApplicationLeaseRegistry(DovecotOperatorId.A)
        val openingCancellationCalls = AtomicInteger()
        val sessionCloseCalls = AtomicInteger()
        val reservation = registry.reserveOpening(DovecotOperatorId.A) {
            openingCancellationCalls.incrementAndGet()
        }

        reservation.bind {
            sessionCloseCalls.incrementAndGet()
        }
        reservation.recheck()
        assertFailsWith<IllegalStateException> {
            reservation.bind {
                sessionCloseCalls.addAndGet(100)
            }
        }
        val lease = reservation.commit()

        lease.close()
        lease.close()

        assertEquals(0, openingCancellationCalls.get())
        assertEquals(1, sessionCloseCalls.get())
        assertEquals(0, registry.openLeaseCount(DovecotOperatorId.A))
    }

    @Test
    fun commitExposesLeaseOnlyFromBoundNonDrainingReservation() {
        val registry =
            DovecotOperatorApplicationLeaseRegistry(DovecotOperatorId.A)
        val unbound = registry.reserveOpening(DovecotOperatorId.A) {}
        assertFailsWith<IllegalStateException> {
            unbound.commit()
        }
        unbound.close()

        val closeEntered = CountDownLatch(1)
        val closeRelease = CountDownLatch(1)
        val drainFinished = CountDownLatch(1)
        val drainFailure = AtomicReference<Throwable?>()
        val draining = registry.reserveOpening(DovecotOperatorId.A) {}
        draining.bind {
            closeEntered.countDown()
            closeRelease.await()
        }
        val drain = thread(isDaemon = true, name = "bound-commit-drain") {
            try {
                registry.blockAndDrain(DovecotOperatorId.A)
            } catch (failure: Throwable) {
                drainFailure.set(failure)
            } finally {
                drainFinished.countDown()
            }
        }
        assertTrue(closeEntered.await(1, TimeUnit.SECONDS))

        assertFailsWith<IllegalStateException> {
            draining.commit()
        }

        closeRelease.countDown()
        assertTrue(drainFinished.await(1, TimeUnit.SECONDS))
        drain.join(1_000)
        assertNull(drainFailure.get())
        assertEquals(0, registry.openLeaseCount(DovecotOperatorId.A))

        registry.activate(DovecotOperatorId.A)
        val available = registry.reserveOpening(DovecotOperatorId.A) {}
        available.bind {}
        val lease = available.commit()

        assertFailsWith<IllegalStateException> {
            available.commit()
        }
        assertTrue(lease.isOpen)
        lease.close()
        assertEquals(0, registry.openLeaseCount(DovecotOperatorId.A))
    }

    @Test
    fun failedBoundCloseRemainsTrackedAndIsRetryable() {
        val registry =
            DovecotOperatorApplicationLeaseRegistry(DovecotOperatorId.A)
        val closeCalls = AtomicInteger()
        val reservation = registry.reserveOpening(DovecotOperatorId.A) {}
        reservation.bind {
            if (closeCalls.incrementAndGet() == 1) {
                throw TerminalCloseFailure()
            }
        }
        val lease = reservation.commit()

        assertFailsWith<TerminalCloseFailure> {
            registry.blockAndDrain(DovecotOperatorId.A)
        }

        assertTrue(lease.isOpen)
        assertEquals(1, registry.openLeaseCount(DovecotOperatorId.A))

        registry.blockAndDrain(DovecotOperatorId.A)

        assertFalse(lease.isOpen)
        assertEquals(2, closeCalls.get())
        assertEquals(0, registry.openLeaseCount(DovecotOperatorId.A))
    }

    @Test
    fun activationPublicationIsAtomicWithLeaseAcquisition() {
        val registry =
            DovecotOperatorApplicationLeaseRegistry(DovecotOperatorId.A)
        val publishEntered = CountDownLatch(1)
        val publishRelease = CountDownLatch(1)
        val publicationComplete = AtomicBoolean()
        val activationFailure = AtomicReference<Throwable?>()
        val activation = thread(isDaemon = true, name = "atomic-activation") {
            try {
                registry.activateAtomically(DovecotOperatorId.B) {
                    publishEntered.countDown()
                    publishRelease.await()
                    publicationComplete.set(true)
                }
            } catch (failure: Throwable) {
                activationFailure.set(failure)
            }
        }
        assertTrue(publishEntered.await(1, TimeUnit.SECONDS))
        val acquisitionFinished = CountDownLatch(1)
        val acquisitionFailure = AtomicReference<Throwable?>()
        val sawPublishedGeneration = AtomicBoolean()
        val acquisition = thread(isDaemon = true, name = "atomic-acquisition") {
            try {
                registry.acquire(DovecotOperatorId.B) {}
                    .use {
                        sawPublishedGeneration.set(publicationComplete.get())
                    }
            } catch (failure: Throwable) {
                acquisitionFailure.set(failure)
            } finally {
                acquisitionFinished.countDown()
            }
        }

        assertFalse(acquisitionFinished.await(100, TimeUnit.MILLISECONDS))
        publishRelease.countDown()
        assertTrue(acquisitionFinished.await(1, TimeUnit.SECONDS))
        activation.join(1_000)
        acquisition.join(1_000)

        assertNull(activationFailure.get())
        assertNull(acquisitionFailure.get())
        assertTrue(sawPublishedGeneration.get())
    }

    @Test
    fun ordinaryCloseRacingDrainJoinsTheSuccessfulCloseAttempt() {
        val registry =
            DovecotOperatorApplicationLeaseRegistry(DovecotOperatorId.A)
        val closeEntered = CountDownLatch(1)
        val closeRelease = CountDownLatch(1)
        val directFinished = CountDownLatch(1)
        val drainFinished = CountDownLatch(1)
        val directFailure = AtomicReference<Throwable?>()
        val drainFailure = AtomicReference<Throwable?>()
        val closeCalls = AtomicInteger()
        val lease = registry.acquire(DovecotOperatorId.A) {
            closeCalls.incrementAndGet()
            closeEntered.countDown()
            closeRelease.await()
        }
        val direct = thread(isDaemon = true, name = "direct-lease-close") {
            try {
                lease.close()
            } catch (failure: Throwable) {
                directFailure.set(failure)
            } finally {
                directFinished.countDown()
            }
        }
        assertTrue(closeEntered.await(1, TimeUnit.SECONDS))
        val drain = thread(isDaemon = true, name = "racing-lease-drain") {
            try {
                registry.blockAndDrain(DovecotOperatorId.A)
            } catch (failure: Throwable) {
                drainFailure.set(failure)
            } finally {
                drainFinished.countDown()
            }
        }

        val drainJoined = !drainFinished.await(200, TimeUnit.MILLISECONDS)
        closeRelease.countDown()
        assertTrue(directFinished.await(1, TimeUnit.SECONDS))
        assertTrue(drainFinished.await(1, TimeUnit.SECONDS))
        direct.join(1_000)
        drain.join(1_000)

        assertTrue(drainJoined)
        assertNull(directFailure.get())
        assertNull(drainFailure.get())
        assertEquals(1, closeCalls.get())
        assertFalse(lease.isOpen)
        assertEquals(0, registry.openLeaseCount(DovecotOperatorId.A))
    }

    @Test
    fun concurrentDrainCallersJoinOneCloseAttempt() {
        val registry =
            DovecotOperatorApplicationLeaseRegistry(DovecotOperatorId.A)
        val closeEntered = CountDownLatch(1)
        val closeRelease = CountDownLatch(1)
        val drainFinished = CountDownLatch(2)
        val failures =
            Collections.synchronizedList(mutableListOf<Throwable>())
        val closeCalls = AtomicInteger()
        val lease = registry.acquire(DovecotOperatorId.A) {
            closeCalls.incrementAndGet()
            closeEntered.countDown()
            closeRelease.await()
        }
        val first = drainThread(
            registry = registry,
            name = "first-concurrent-drain",
            failures = failures,
            finished = drainFinished,
        )
        assertTrue(closeEntered.await(1, TimeUnit.SECONDS))
        val second = drainThread(
            registry = registry,
            name = "second-concurrent-drain",
            failures = failures,
            finished = drainFinished,
        )

        val bothJoined = !drainFinished.await(200, TimeUnit.MILLISECONDS)
        closeRelease.countDown()
        assertTrue(drainFinished.await(1, TimeUnit.SECONDS))
        first.join(1_000)
        second.join(1_000)

        assertTrue(bothJoined)
        assertTrue(failures.isEmpty(), failures.joinToString { it.stackTraceToString() })
        assertEquals(1, closeCalls.get())
        assertFalse(lease.isOpen)
    }

    @Test
    fun lateDrainCallerSharesTheFirstDrainDeadlineAndFailure() {
        val registry =
            DovecotOperatorApplicationLeaseRegistry(DovecotOperatorId.A)
        val closeEntered = CountDownLatch(1)
        val closeRelease = CountDownLatch(1)
        registry.acquire(DovecotOperatorId.A) {
            closeEntered.countDown()
            while (closeRelease.count > 0L) {
                try {
                    closeRelease.await()
                } catch (_: InterruptedException) {
                    // Exercise a close callback that ignores cancellation.
                }
            }
        }
        val firstFailure = AtomicReference<Throwable?>()
        val secondFailure = AtomicReference<Throwable?>()
        val firstFinished = CountDownLatch(1)
        val secondFinished = CountDownLatch(1)
        val started = System.nanoTime()
        val first = thread(isDaemon = true, name = "shared-deadline-first") {
            try {
                registry.blockAndDrain(DovecotOperatorId.A)
            } catch (failure: Throwable) {
                firstFailure.set(failure)
            } finally {
                firstFinished.countDown()
            }
        }
        assertTrue(closeEntered.await(1, TimeUnit.SECONDS))
        Thread.sleep(650)
        val secondStarted = System.nanoTime()
        val second = thread(isDaemon = true, name = "shared-deadline-second") {
            try {
                registry.blockAndDrain(DovecotOperatorId.A)
            } catch (failure: Throwable) {
                secondFailure.set(failure)
            } finally {
                secondFinished.countDown()
            }
        }

        assertTrue(firstFinished.await(1, TimeUnit.SECONDS))
        assertTrue(secondFinished.await(500, TimeUnit.MILLISECONDS))
        val totalElapsed = System.nanoTime() - started
        val secondElapsed = System.nanoTime() - secondStarted
        closeRelease.countDown()
        first.join(1_000)
        second.join(1_000)

        assertTrue(firstFailure.get() is IllegalStateException)
        assertSame(firstFailure.get(), secondFailure.get())
        assertTrue(totalElapsed < TimeUnit.MILLISECONDS.toNanos(1_300))
        assertTrue(secondElapsed < TimeUnit.MILLISECONDS.toNanos(650))
    }

    @Test
    fun uncooperativeCloseAttemptsCannotExhaustFutureDrainCapacity() {
        val callbackEntered = CountDownLatch(16)
        val callbackRelease = CountDownLatch(1)
        val drainsFinished = CountDownLatch(16)
        val registries = (1..16).map {
            DovecotOperatorApplicationLeaseRegistry(DovecotOperatorId.A).also {
                registry ->
                registry.acquire(DovecotOperatorId.A) {
                    callbackEntered.countDown()
                    while (callbackRelease.count > 0L) {
                        try {
                            callbackRelease.await()
                        } catch (_: InterruptedException) {
                            // Permanently occupy the worker until test cleanup.
                        }
                    }
                }
            }
        }
        val drainThreads = registries.mapIndexed { index, registry ->
            thread(isDaemon = true, name = "uncooperative-drain-$index") {
                try {
                    registry.blockAndDrain(DovecotOperatorId.A)
                } catch (_: Throwable) {
                    // Each stubborn close is expected to time out.
                } finally {
                    drainsFinished.countDown()
                }
            }
        }

        try {
            assertTrue(callbackEntered.await(2, TimeUnit.SECONDS))
            assertTrue(drainsFinished.await(2, TimeUnit.SECONDS))
            val healthy =
                DovecotOperatorApplicationLeaseRegistry(DovecotOperatorId.A)
            val healthyCloseCalls = AtomicInteger()
            healthy.acquire(DovecotOperatorId.A) {
                healthyCloseCalls.incrementAndGet()
            }

            healthy.blockAndDrain(DovecotOperatorId.A)

            assertEquals(1, healthyCloseCalls.get())
            assertEquals(0, healthy.openLeaseCount(DovecotOperatorId.A))
        } finally {
            callbackRelease.countDown()
            drainThreads.forEach { it.join(1_000) }
        }
    }

    @Test
    fun leasedRuntimeCannotBeResurrectedAfterClose() {
        val registry =
            DovecotOperatorApplicationLeaseRegistry(DovecotOperatorId.A)
        val runtime = DovecotOperatorLeasedRotationRuntime(
            leases = registry,
            prober = { _, _ -> DovecotOperatorProbeResult.Success },
        )
        runtime.close()
        val activationBytes = "post-close-secret".toByteArray()

        assertFailsWith<IllegalStateException> {
            DovecotOperatorCredential(
                DovecotOperatorId.B,
                DovecotOperatorSecret.takeOwnership(activationBytes),
            ).use(runtime::activateApplication)
        }

        assertTrue(activationBytes.all { it == 0.toByte() })
        assertFailsWith<IllegalStateException> {
            registry.acquire(DovecotOperatorId.B) {}
        }
        runtime.close()
    }

    @Test
    fun failedRuntimeCloseReplaysTheSameTerminalOutcomeToLaterCallers() {
        val registry =
            DovecotOperatorApplicationLeaseRegistry(DovecotOperatorId.A)
        val runtime = DovecotOperatorLeasedRotationRuntime(
            leases = registry,
            prober = { _, _ -> DovecotOperatorProbeResult.Success },
        )
        val terminalFailure = TerminalCloseFailure()
        val closeCalls = AtomicInteger()
        registry.acquire(DovecotOperatorId.A) {
            if (closeCalls.incrementAndGet() == 1) {
                throw terminalFailure
            }
        }

        val first = assertFailsWith<TerminalCloseFailure> {
            runtime.close()
        }
        val second = assertFailsWith<TerminalCloseFailure> {
            runtime.close()
        }

        assertSame(terminalFailure, first)
        assertSame(first, second)
        assertEquals(1, closeCalls.get())

        val activationBytes =
            "terminal-close-rejected-activation".toByteArray()
        assertFailsWith<IllegalStateException> {
            DovecotOperatorCredential(
                DovecotOperatorId.B,
                DovecotOperatorSecret.takeOwnership(activationBytes),
            ).use(runtime::activateApplication)
        }
        assertTrue(activationBytes.all { it == 0.toByte() })
    }

    @Test
    fun activationIsRejectedWhileItsGenerationIsDraining() {
        val registry =
            DovecotOperatorApplicationLeaseRegistry(DovecotOperatorId.A)
        val runtime = DovecotOperatorLeasedRotationRuntime(
            leases = registry,
            prober = { _, _ -> DovecotOperatorProbeResult.Success },
        )
        activate(runtime, DovecotOperatorId.B, "initial-b")
        val closeEntered = CountDownLatch(1)
        val closeRelease = CountDownLatch(1)
        registry.acquire(DovecotOperatorId.B) {
            closeEntered.countDown()
            closeRelease.await()
        }
        val drainFailure = AtomicReference<Throwable?>()
        val drainFinished = CountDownLatch(1)
        val drain = thread(isDaemon = true, name = "activation-race-drain") {
            try {
                runtime.blockAndDrain(DovecotOperatorId.B)
            } catch (failure: Throwable) {
                drainFailure.set(failure)
            } finally {
                drainFinished.countDown()
            }
        }
        assertTrue(closeEntered.await(1, TimeUnit.SECONDS))
        val activationBytes = "racing-b".toByteArray()
        val activationFailure = runCatching {
            DovecotOperatorCredential(
                DovecotOperatorId.B,
                DovecotOperatorSecret.takeOwnership(activationBytes),
            ).use(runtime::activateApplication)
        }.exceptionOrNull()

        closeRelease.countDown()
        assertTrue(drainFinished.await(1, TimeUnit.SECONDS))
        drain.join(1_000)

        assertTrue(activationFailure is IllegalStateException)
        assertTrue(activationBytes.all { it == 0.toByte() })
        assertNull(drainFailure.get())
        assertFailsWith<IllegalStateException> {
            registry.acquire(DovecotOperatorId.B) {}
        }
        runtime.close()
    }

    @Test
    fun closeWinsAgainstActivationWaitingOnCredentialAccess() {
        val registry =
            DovecotOperatorApplicationLeaseRegistry(DovecotOperatorId.A)
        val runtime = DovecotOperatorLeasedRotationRuntime(
            leases = registry,
            prober = { _, _ -> DovecotOperatorProbeResult.Success },
        )
        val activationBytes = "latch-controlled-secret".toByteArray()
        val credential = DovecotOperatorCredential(
            DovecotOperatorId.B,
            DovecotOperatorSecret.takeOwnership(activationBytes),
        )
        val accessEntered = CountDownLatch(1)
        val accessRelease = CountDownLatch(1)
        val activationStarted = CountDownLatch(1)
        val activationFinished = CountDownLatch(1)
        val activationFailure = AtomicReference<Throwable?>()
        val holder = thread(isDaemon = true, name = "credential-access-holder") {
            credential.withSecretBytes {
                accessEntered.countDown()
                accessRelease.await()
            }
        }
        assertTrue(accessEntered.await(1, TimeUnit.SECONDS))
        val activation = thread(isDaemon = true, name = "close-racing-activation") {
            activationStarted.countDown()
            try {
                runtime.activateApplication(credential)
            } catch (failure: Throwable) {
                activationFailure.set(failure)
            } finally {
                activationFinished.countDown()
            }
        }
        assertTrue(activationStarted.await(1, TimeUnit.SECONDS))

        runtime.close()
        accessRelease.countDown()
        assertTrue(activationFinished.await(1, TimeUnit.SECONDS))
        holder.join(1_000)
        activation.join(1_000)
        credential.close()

        assertTrue(activationFailure.get() is IllegalStateException)
        assertTrue(activationBytes.all { it == 0.toByte() })
        assertFailsWith<IllegalStateException> {
            registry.acquire(DovecotOperatorId.B) {}
        }
    }

    private fun drainThread(
        registry: DovecotOperatorApplicationLeaseRegistry,
        name: String,
        failures: MutableList<Throwable>,
        finished: CountDownLatch,
    ): Thread = thread(isDaemon = true, name = name) {
        try {
            registry.blockAndDrain(DovecotOperatorId.A)
        } catch (failure: Throwable) {
            failures += failure
        } finally {
            finished.countDown()
        }
    }

    private fun activate(
        runtime: DovecotOperatorLeasedRotationRuntime,
        id: DovecotOperatorId,
        value: String,
    ) {
        val bytes = value.toByteArray()
        DovecotOperatorCredential(
            id,
            DovecotOperatorSecret.takeOwnership(bytes),
        ).use(runtime::activateApplication)
        assertTrue(bytes.all { it == 0.toByte() })
    }

    private class TerminalCloseFailure : RuntimeException()
}
