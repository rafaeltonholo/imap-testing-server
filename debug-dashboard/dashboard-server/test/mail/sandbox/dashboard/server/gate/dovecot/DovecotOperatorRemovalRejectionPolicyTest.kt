package mail.sandbox.dashboard.server.gate.dovecot

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertSame
import kotlin.test.assertTrue

internal fun interface DovecotOperatorRemovalRejectionSleeper {
    fun sleep(milliseconds: Long)
}

internal fun awaitDovecotOperatorTargetRejection(
    resultSupplier: () -> DovecotOperatorProbeResult,
    sleeper: DovecotOperatorRemovalRejectionSleeper =
        DovecotOperatorRemovalRejectionSleeper(Thread::sleep),
) {
    repeat(REMOVAL_REJECTION_ATTEMPTS) { attempt ->
        when (resultSupplier()) {
            DovecotOperatorProbeResult.AuthorizationFailure -> return
            DovecotOperatorProbeResult.AuthenticationFailure ->
                throw IllegalStateException(
                    "Removed operator target rejection probe rejected the " +
                        "active operator credential",
                )
            DovecotOperatorProbeResult.Success -> {
                if (attempt + 1 == REMOVAL_REJECTION_ATTEMPTS) {
                    throw IllegalStateException(
                        "Removed operator target remained accessible after " +
                            "the bounded rejection window",
                    )
                }
                try {
                    sleeper.sleep(REMOVAL_REJECTION_DELAY_MILLIS)
                } catch (interrupted: InterruptedException) {
                    Thread.currentThread().interrupt()
                    throw interrupted
                }
            }
            DovecotOperatorProbeResult.ProtocolFailure ->
                throw IllegalStateException(
                    "Removed operator target rejection probe failed at the " +
                        "protocol boundary",
                )
            DovecotOperatorProbeResult.TransportFailure ->
                throw IllegalStateException(
                    "Removed operator target rejection probe failed at the " +
                        "transport boundary",
                )
        }
    }
}

private const val REMOVAL_REJECTION_ATTEMPTS = 7
private const val REMOVAL_REJECTION_DELAY_MILLIS = 250L

class DovecotOperatorRemovalRejectionPolicyTest {
    @Test
    fun authorizationFailureCompletesImmediately() {
        var supplierCalls = 0
        val sleeps = mutableListOf<Long>()

        awaitDovecotOperatorTargetRejection(
            resultSupplier = {
                supplierCalls += 1
                DovecotOperatorProbeResult.AuthorizationFailure
            },
            sleeper =
                DovecotOperatorRemovalRejectionSleeper(sleeps::add),
        )

        assertEquals(1, supplierCalls)
        assertEquals(emptyList(), sleeps)
    }

    @Test
    fun successIsRetriedUntilAuthorizationFailure() {
        var supplierCalls = 0
        val sleeps = mutableListOf<Long>()

        awaitDovecotOperatorTargetRejection(
            resultSupplier = {
                supplierCalls += 1
                if (supplierCalls < 3) {
                    DovecotOperatorProbeResult.Success
                } else {
                    DovecotOperatorProbeResult.AuthorizationFailure
                }
            },
            sleeper =
                DovecotOperatorRemovalRejectionSleeper(sleeps::add),
        )

        assertEquals(3, supplierCalls)
        assertEquals(listOf(250L, 250L), sleeps)
    }

    @Test
    fun authenticationFailureDoesNotProveTargetRemoval() {
        var supplierCalls = 0
        val sleeps = mutableListOf<Long>()

        val failure = assertFailsWith<IllegalStateException> {
            awaitDovecotOperatorTargetRejection(
                resultSupplier = {
                    supplierCalls += 1
                    DovecotOperatorProbeResult.AuthenticationFailure
                },
                sleeper =
                    DovecotOperatorRemovalRejectionSleeper(sleeps::add),
            )
        }

        assertEquals(1, supplierCalls)
        assertEquals(emptyList(), sleeps)
        assertEquals(
            "Removed operator target rejection probe rejected the active " +
                "operator credential",
            failure.message,
        )
    }

    @Test
    fun interruptedRetrySleepRestoresTheInterruptFlagAndStopsImmediately() {
        val testThread = Thread.currentThread()
        Thread.interrupted()
        try {
            var supplierCalls = 0
            var sleeperCalls = 0
            val interruption = InterruptedException("retry interrupted")

            val thrown = assertFailsWith<InterruptedException> {
                awaitDovecotOperatorTargetRejection(
                    resultSupplier = {
                        supplierCalls += 1
                        DovecotOperatorProbeResult.Success
                    },
                    sleeper =
                        DovecotOperatorRemovalRejectionSleeper {
                            sleeperCalls += 1
                            throw interruption
                        },
                )
            }

            assertSame(interruption, thrown)
            assertEquals(1, supplierCalls)
            assertEquals(1, sleeperCalls)
            assertTrue(testThread.isInterrupted)
        } finally {
            Thread.interrupted()
        }
    }

    @Test
    fun protocolFailureFailsImmediately() {
        var supplierCalls = 0
        val sleeps = mutableListOf<Long>()

        val failure = assertFailsWith<IllegalStateException> {
            awaitDovecotOperatorTargetRejection(
                resultSupplier = {
                    supplierCalls += 1
                    DovecotOperatorProbeResult.ProtocolFailure
                },
                sleeper =
                    DovecotOperatorRemovalRejectionSleeper(sleeps::add),
            )
        }

        assertEquals(1, supplierCalls)
        assertEquals(emptyList(), sleeps)
        assertEquals(
            "Removed operator target rejection probe failed at the " +
                "protocol boundary",
            failure.message,
        )
    }

    @Test
    fun transportFailureFailsImmediately() {
        var supplierCalls = 0
        val sleeps = mutableListOf<Long>()

        val failure = assertFailsWith<IllegalStateException> {
            awaitDovecotOperatorTargetRejection(
                resultSupplier = {
                    supplierCalls += 1
                    DovecotOperatorProbeResult.TransportFailure
                },
                sleeper =
                    DovecotOperatorRemovalRejectionSleeper(sleeps::add),
            )
        }

        assertEquals(1, supplierCalls)
        assertEquals(emptyList(), sleeps)
        assertEquals(
            "Removed operator target rejection probe failed at the " +
                "transport boundary",
            failure.message,
        )
    }

    @Test
    fun persistentSuccessExhaustsTheFixedBoundedWindow() {
        var supplierCalls = 0
        val sleeps = mutableListOf<Long>()

        val failure = assertFailsWith<IllegalStateException> {
            awaitDovecotOperatorTargetRejection(
                resultSupplier = {
                    supplierCalls += 1
                    DovecotOperatorProbeResult.Success
                },
                sleeper =
                    DovecotOperatorRemovalRejectionSleeper(sleeps::add),
            )
        }

        assertEquals(7, supplierCalls)
        assertEquals(List(6) { 250L }, sleeps)
        assertTrue(sleeps.sum() > 1_000L)
        assertTrue(sleeps.all { delay -> delay <= 2_000L })
        assertEquals(
            "Removed operator target remained accessible after the bounded " +
                "rejection window",
            failure.message,
        )
    }
}
