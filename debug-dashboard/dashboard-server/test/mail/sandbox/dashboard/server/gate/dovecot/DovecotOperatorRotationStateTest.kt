package mail.sandbox.dashboard.server.gate.dovecot

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class DovecotOperatorRotationStateTest {
    @Test
    fun firstRawSlotIsWipedWhenSecondReadFails() {
        val first = "first-slot-canary".toByteArray()

        assertFailsWith<SimulatedReadFailure> {
            DovecotOperatorRawSlotPair.requireDistinct(
                readFirst = { first },
                readSecond = { throw SimulatedReadFailure() },
            )
        }

        assertTrue(first.all { it == 0.toByte() })
    }

    @Test
    fun pureProjectionClassifiesEveryRecoverableRotationPhase() {
        val intent = DovecotOperatorRotationIntent(
            old = DovecotOperatorId.A,
            new = DovecotOperatorId.B,
        )
        val cases = listOf(
            DovecotOperatorRotationProjection(
                intent = intent,
                active = DovecotOperatorId.A,
                masterIds = listOf(
                    DovecotOperatorId.A,
                    DovecotOperatorId.B,
                ),
                rawSlots = setOf(
                    DovecotOperatorId.A,
                    DovecotOperatorId.B,
                ),
            ) to DovecotOperatorRotationPhase.Rollback(
                intent = intent,
                stagedRawPresent = true,
            ),
            DovecotOperatorRotationProjection(
                intent = intent,
                active = DovecotOperatorId.A,
                masterIds = listOf(DovecotOperatorId.A),
                rawSlots = setOf(
                    DovecotOperatorId.A,
                    DovecotOperatorId.B,
                ),
            ) to DovecotOperatorRotationPhase.Rollback(
                intent = intent,
                stagedRawPresent = true,
            ),
            DovecotOperatorRotationProjection(
                intent = intent,
                active = DovecotOperatorId.A,
                masterIds = listOf(DovecotOperatorId.A),
                rawSlots = setOf(DovecotOperatorId.A),
            ) to DovecotOperatorRotationPhase.Rollback(
                intent = intent,
                stagedRawPresent = false,
            ),
            DovecotOperatorRotationProjection(
                intent = intent,
                active = DovecotOperatorId.B,
                masterIds = listOf(
                    DovecotOperatorId.A,
                    DovecotOperatorId.B,
                ),
                rawSlots = setOf(
                    DovecotOperatorId.A,
                    DovecotOperatorId.B,
                ),
            ) to DovecotOperatorRotationPhase.Forward(
                intent = intent,
                oldRawPresent = true,
            ),
            DovecotOperatorRotationProjection(
                intent = intent,
                active = DovecotOperatorId.B,
                masterIds = listOf(DovecotOperatorId.B),
                rawSlots = setOf(DovecotOperatorId.B),
            ) to DovecotOperatorRotationPhase.Forward(
                intent = intent,
                oldRawPresent = false,
            ),
        )

        cases.forEach { (projection, expected) ->
            assertEquals(expected, projection.phase())
        }
    }

    @Test
    fun pureProjectionRejectsImpossibleOrMisroutedRotationStates() {
        val intent = DovecotOperatorRotationIntent(
            old = DovecotOperatorId.A,
            new = DovecotOperatorId.B,
        )
        val invalid = listOf(
            DovecotOperatorRotationProjection(
                intent = intent,
                active = DovecotOperatorId.A,
                masterIds = listOf(DovecotOperatorId.B),
                rawSlots = setOf(
                    DovecotOperatorId.A,
                    DovecotOperatorId.B,
                ),
            ),
            DovecotOperatorRotationProjection(
                intent = intent,
                active = DovecotOperatorId.A,
                masterIds = listOf(
                    DovecotOperatorId.B,
                    DovecotOperatorId.A,
                ),
                rawSlots = setOf(
                    DovecotOperatorId.A,
                    DovecotOperatorId.B,
                ),
            ),
            DovecotOperatorRotationProjection(
                intent = intent,
                active = DovecotOperatorId.A,
                masterIds = listOf(
                    DovecotOperatorId.A,
                    DovecotOperatorId.B,
                ),
                rawSlots = setOf(DovecotOperatorId.A),
            ),
            DovecotOperatorRotationProjection(
                intent = intent,
                active = DovecotOperatorId.B,
                masterIds = listOf(DovecotOperatorId.B),
                rawSlots = setOf(DovecotOperatorId.A),
            ),
        )

        invalid.forEach { projection ->
            assertFailsWith<IllegalStateException> {
                projection.phase()
            }
        }
    }

    private class SimulatedReadFailure : RuntimeException()
}
