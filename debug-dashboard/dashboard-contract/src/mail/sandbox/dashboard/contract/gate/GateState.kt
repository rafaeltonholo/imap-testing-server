package mail.sandbox.dashboard.contract.gate

enum class GateRoute(val path: String) {
    Overview("/"),
    Details("/gate/details"),
    ;

    companion object {
        fun fromPath(path: String): GateRoute? = entries.firstOrNull { it.path == path }
    }
}

enum class ApiProbeStatus {
    Pending,
    Probing,
    Ready,
    Failed,
}

enum class SseConnectionStatus {
    Disconnected,
    Connected,
    Reconnecting,
}

enum class SseSyncStatus {
    Pending,
    Current,
    Stale,
    Resyncing,
}

data class GateState(
    val route: GateRoute = GateRoute.Overview,
    val apiProbeStatus: ApiProbeStatus = ApiProbeStatus.Pending,
    val apiProbeMessage: String? = null,
    val sseSequence: Long? = null,
    val sseConnectionStatus: SseConnectionStatus = SseConnectionStatus.Disconnected,
    val sseSyncStatus: SseSyncStatus = SseSyncStatus.Pending,
    val activationCount: Int = 0,
)

sealed interface GateAction {
    data class RouteSelected(val path: String) : GateAction

    data object ApiProbeStarted : GateAction

    data class ApiProbeSucceeded(val message: String) : GateAction

    data class ApiProbeFailed(val message: String) : GateAction

    data object SseConnected : GateAction

    data class SseSequenceReceived(val sequence: Long) : GateAction

    data object SseReconnectScheduled : GateAction

    data object SseDisconnected : GateAction

    data object SseResyncStarted : GateAction

    data class SseResyncCompleted(val sequence: Long) : GateAction

    data object IncrementProof : GateAction
}

fun reduceGateState(state: GateState, action: GateAction): GateState = when (action) {
    is GateAction.RouteSelected -> {
        val route = GateRoute.fromPath(action.path)
        if (route == null) state else state.copy(route = route)
    }

    GateAction.ApiProbeStarted -> state.copy(apiProbeStatus = ApiProbeStatus.Probing)
    is GateAction.ApiProbeSucceeded -> state.copy(
        apiProbeStatus = ApiProbeStatus.Ready,
        apiProbeMessage = action.message,
    )
    is GateAction.ApiProbeFailed -> state.copy(
        apiProbeStatus = ApiProbeStatus.Failed,
        apiProbeMessage = action.message,
    )
    GateAction.SseConnected -> state.copy(sseConnectionStatus = SseConnectionStatus.Connected)
    is GateAction.SseSequenceReceived -> state.receiveSequence(action.sequence)
    GateAction.SseReconnectScheduled -> {
        state.copy(sseConnectionStatus = SseConnectionStatus.Reconnecting)
    }
    GateAction.SseDisconnected -> {
        state.copy(sseConnectionStatus = SseConnectionStatus.Disconnected)
    }

    GateAction.SseResyncStarted -> state.copy(sseSyncStatus = SseSyncStatus.Resyncing)
    is GateAction.SseResyncCompleted -> state.completeResync(action.sequence)
    GateAction.IncrementProof -> state.copy(activationCount = state.activationCount + 1)
}

private fun GateState.receiveSequence(sequence: Long): GateState {
    val isStrictlyNewer = sequence > 0L && (sseSequence == null || sequence > sseSequence)
    return if (isStrictlyNewer) {
        copy(
            sseSequence = sequence,
            sseConnectionStatus = SseConnectionStatus.Connected,
            sseSyncStatus = when (sseSyncStatus) {
                SseSyncStatus.Pending,
                SseSyncStatus.Current,
                -> SseSyncStatus.Current

                SseSyncStatus.Stale -> SseSyncStatus.Stale
                SseSyncStatus.Resyncing -> SseSyncStatus.Resyncing
            },
        )
    } else if (sseSyncStatus == SseSyncStatus.Resyncing) {
        this
    } else {
        copy(sseSyncStatus = SseSyncStatus.Stale)
    }
}

private fun GateState.completeResync(sequence: Long): GateState {
    if (sseSyncStatus != SseSyncStatus.Resyncing) {
        return copy(sseSyncStatus = SseSyncStatus.Stale)
    }

    val isNonRegressive = sequence > 0L && (sseSequence == null || sequence >= sseSequence)
    return if (isNonRegressive) {
        copy(
            sseSequence = sequence,
            sseSyncStatus = SseSyncStatus.Current,
        )
    } else {
        copy(sseSyncStatus = SseSyncStatus.Stale)
    }
}
