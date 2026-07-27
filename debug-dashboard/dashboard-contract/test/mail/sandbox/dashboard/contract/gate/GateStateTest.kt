package mail.sandbox.dashboard.contract.gate

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class GateStateTest {
    @Test
    fun initialTransportStateIsPendingAndDisconnected() {
        val state = GateState()

        assertEquals(ApiProbeStatus.Pending, state.apiProbeStatus)
        assertNull(state.sseSequence)
        assertEquals(SseConnectionStatus.Disconnected, state.sseConnectionStatus)
        assertEquals(SseSyncStatus.Pending, state.sseSyncStatus)
    }

    @Test
    fun routeSelectionRecognizesOverviewAndDetails() {
        val details = reduceGateState(
            GateState(),
            GateAction.RouteSelected("/gate/details"),
        )
        val overview = reduceGateState(
            details,
            GateAction.RouteSelected("/"),
        )
        val unknown = reduceGateState(
            details,
            GateAction.RouteSelected("/not-a-gate-route"),
        )

        assertEquals(GateRoute.Details, details.route)
        assertEquals(GateRoute.Overview, overview.route)
        assertEquals(GateRoute.Details, unknown.route)
    }

    @Test
    fun apiProbeMovesFromPendingThroughProbingToReady() {
        val probing = reduceGateState(GateState(), GateAction.ApiProbeStarted)
        val ready = reduceGateState(probing, GateAction.ApiProbeSucceeded)

        assertEquals(ApiProbeStatus.Probing, probing.apiProbeStatus)
        assertEquals(ApiProbeStatus.Ready, ready.apiProbeStatus)
    }

    @Test
    fun sseSequenceAdvancesAndReconnectPreservesLastSequence() {
        val connected = reduceGateState(GateState(), GateAction.SseConnected)
        val advanced = reduceGateState(
            connected,
            GateAction.SseSequenceReceived(12L),
        )
        val reconnecting = reduceGateState(
            advanced,
            GateAction.SseReconnectScheduled,
        )

        assertEquals(12L, advanced.sseSequence)
        assertEquals(SseSyncStatus.Current, advanced.sseSyncStatus)
        assertEquals(SseConnectionStatus.Connected, advanced.sseConnectionStatus)
        assertEquals(12L, reconnecting.sseSequence)
        assertEquals(SseConnectionStatus.Reconnecting, reconnecting.sseConnectionStatus)
    }

    @Test
    fun invalidAndNonMonotonicSequencesMarkStateStaleWithoutAdvancing() {
        val invalid = reduceGateState(
            GateState(),
            GateAction.SseSequenceReceived(0L),
        )
        val first = reduceGateState(
            GateState(),
            GateAction.SseSequenceReceived(12L),
        )
        val duplicate = reduceGateState(
            first,
            GateAction.SseSequenceReceived(12L),
        )
        val regressive = reduceGateState(
            first,
            GateAction.SseSequenceReceived(11L),
        )

        assertNull(invalid.sseSequence)
        assertEquals(SseSyncStatus.Stale, invalid.sseSyncStatus)
        assertEquals(12L, duplicate.sseSequence)
        assertEquals(SseSyncStatus.Stale, duplicate.sseSyncStatus)
        assertEquals(12L, regressive.sseSequence)
        assertEquals(SseSyncStatus.Stale, regressive.sseSyncStatus)
    }

    @Test
    fun newerOrdinarySequenceAdvancesCursorButKeepsStaleState() {
        val current = reduceGateState(
            GateState(),
            GateAction.SseSequenceReceived(12L),
        )
        val stale = reduceGateState(
            current,
            GateAction.SseSequenceReceived(12L),
        )
        val advanced = reduceGateState(
            stale,
            GateAction.SseSequenceReceived(13L),
        )

        assertEquals(13L, advanced.sseSequence)
        assertEquals(SseSyncStatus.Stale, advanced.sseSyncStatus)
        assertEquals(SseConnectionStatus.Connected, advanced.sseConnectionStatus)
    }

    @Test
    fun ordinarySequenceDuringResyncKeepsResyncingState() {
        val current = reduceGateState(
            GateState(),
            GateAction.SseSequenceReceived(12L),
        )
        val resyncing = reduceGateState(current, GateAction.SseResyncStarted)
        val advanced = reduceGateState(
            resyncing,
            GateAction.SseSequenceReceived(13L),
        )

        assertEquals(13L, advanced.sseSequence)
        assertEquals(SseSyncStatus.Resyncing, advanced.sseSyncStatus)
        assertEquals(SseConnectionStatus.Connected, advanced.sseConnectionStatus)
    }

    @Test
    fun duplicateOrdinarySequenceDuringResyncPreservesResyncAndReconnect() {
        val current = reduceGateState(
            GateState(),
            GateAction.SseSequenceReceived(12L),
        )
        val reconnecting = reduceGateState(current, GateAction.SseReconnectScheduled)
        val resyncing = reduceGateState(reconnecting, GateAction.SseResyncStarted)
        val duplicate = reduceGateState(
            resyncing,
            GateAction.SseSequenceReceived(12L),
        )

        assertEquals(12L, duplicate.sseSequence)
        assertEquals(SseSyncStatus.Resyncing, duplicate.sseSyncStatus)
        assertEquals(SseConnectionStatus.Reconnecting, duplicate.sseConnectionStatus)
    }

    @Test
    fun regressiveOrdinarySequenceDuringResyncPreservesResyncAndReconnect() {
        val current = reduceGateState(
            GateState(),
            GateAction.SseSequenceReceived(12L),
        )
        val reconnecting = reduceGateState(current, GateAction.SseReconnectScheduled)
        val resyncing = reduceGateState(reconnecting, GateAction.SseResyncStarted)
        val regressive = reduceGateState(
            resyncing,
            GateAction.SseSequenceReceived(11L),
        )

        assertEquals(12L, regressive.sseSequence)
        assertEquals(SseSyncStatus.Resyncing, regressive.sseSyncStatus)
        assertEquals(SseConnectionStatus.Reconnecting, regressive.sseConnectionStatus)
    }

    @Test
    fun resyncCompletionAcceptsEqualCursorAndReturnsToCurrent() {
        val current = reduceGateState(
            GateState(),
            GateAction.SseSequenceReceived(12L),
        )
        val resyncing = reduceGateState(current, GateAction.SseResyncStarted)
        val completed = reduceGateState(
            resyncing,
            GateAction.SseResyncCompleted(12L),
        )

        assertEquals(12L, completed.sseSequence)
        assertEquals(SseSyncStatus.Current, completed.sseSyncStatus)
    }

    @Test
    fun resyncCompletionPreservesReconnectingState() {
        val current = reduceGateState(
            GateState(),
            GateAction.SseSequenceReceived(12L),
        )
        val reconnecting = reduceGateState(current, GateAction.SseReconnectScheduled)
        val resyncing = reduceGateState(reconnecting, GateAction.SseResyncStarted)
        val completed = reduceGateState(
            resyncing,
            GateAction.SseResyncCompleted(20L),
        )

        assertEquals(20L, completed.sseSequence)
        assertEquals(SseSyncStatus.Current, completed.sseSyncStatus)
        assertEquals(SseConnectionStatus.Reconnecting, completed.sseConnectionStatus)
    }

    @Test
    fun resyncCompletionWithoutActiveResyncMarksStaleWithoutChangingTransport() {
        val current = reduceGateState(
            GateState(),
            GateAction.SseSequenceReceived(12L),
        )
        val reconnecting = reduceGateState(current, GateAction.SseReconnectScheduled)
        val completed = reduceGateState(
            reconnecting,
            GateAction.SseResyncCompleted(20L),
        )

        assertEquals(12L, completed.sseSequence)
        assertEquals(SseSyncStatus.Stale, completed.sseSyncStatus)
        assertEquals(SseConnectionStatus.Reconnecting, completed.sseConnectionStatus)
    }

    @Test
    fun invalidAndRegressiveResyncCompletionMarkStaleWithoutMovingCursor() {
        val current = reduceGateState(
            GateState(),
            GateAction.SseSequenceReceived(12L),
        )
        val resyncing = reduceGateState(current, GateAction.SseResyncStarted)
        val invalid = reduceGateState(
            resyncing,
            GateAction.SseResyncCompleted(0L),
        )
        val regressive = reduceGateState(
            resyncing,
            GateAction.SseResyncCompleted(11L),
        )

        assertEquals(12L, invalid.sseSequence)
        assertEquals(SseSyncStatus.Stale, invalid.sseSyncStatus)
        assertEquals(12L, regressive.sseSequence)
        assertEquals(SseSyncStatus.Stale, regressive.sseSyncStatus)
    }

    @Test
    fun staleSequenceCanEnterResyncAndResumeAtANewerSequence() {
        val current = reduceGateState(
            GateState(),
            GateAction.SseSequenceReceived(12L),
        )
        val stale = reduceGateState(
            current,
            GateAction.SseSequenceReceived(12L),
        )
        val resyncing = reduceGateState(stale, GateAction.SseResyncStarted)
        val resynced = reduceGateState(
            resyncing,
            GateAction.SseResyncCompleted(20L),
        )

        assertEquals(SseSyncStatus.Stale, stale.sseSyncStatus)
        assertEquals(SseSyncStatus.Resyncing, resyncing.sseSyncStatus)
        assertEquals(20L, resynced.sseSequence)
        assertEquals(SseSyncStatus.Current, resynced.sseSyncStatus)
        assertEquals(SseConnectionStatus.Connected, resynced.sseConnectionStatus)
    }

    @Test
    fun incrementProofCountsEveryActivation() {
        val once = reduceGateState(GateState(), GateAction.IncrementProof)
        val twice = reduceGateState(once, GateAction.IncrementProof)

        assertEquals(2, twice.activationCount)
    }
}
