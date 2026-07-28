package mail.sandbox.dashboard.server.provider.stalwart.credential

internal data class StalwartMailAccount(
    val accountId: String,
    val address: String,
) {
    init {
        require(accountId.isNotBlank()) { "Stalwart Account ID is absent" }
        require(address.isNotBlank()) { "Stalwart Account address is absent" }
    }
}

internal enum class StalwartMailAccessState {
    EnrollmentRequired,
    Ready,
    Rotating,
    RecoveryRequired,
    RemovalPending,
    StoreUnavailable,
}

internal enum class StalwartMailAccessAction {
    Enroll,
    Repair,
    Rotate,
    Remove,
    Reconcile,
}

internal data class StalwartMailAccessProjection(
    val state: StalwartMailAccessState,
    val actions: Set<StalwartMailAccessAction>,
) {
    init {
        require(actions == actionsFor(state) || actions.isEmpty()) {
            "Stalwart mail-access actions do not match the projected state"
        }
    }

    companion object {
        fun ordinary(state: StalwartMailAccessState): StalwartMailAccessProjection =
            StalwartMailAccessProjection(state, actionsFor(state))

        fun protected(state: StalwartMailAccessState): StalwartMailAccessProjection =
            StalwartMailAccessProjection(state, emptySet())

        private fun actionsFor(
            state: StalwartMailAccessState,
        ): Set<StalwartMailAccessAction> = when (state) {
            StalwartMailAccessState.EnrollmentRequired ->
                setOf(StalwartMailAccessAction.Enroll)
            StalwartMailAccessState.Ready ->
                setOf(
                    StalwartMailAccessAction.Rotate,
                    StalwartMailAccessAction.Remove,
                )
            StalwartMailAccessState.RecoveryRequired ->
                setOf(StalwartMailAccessAction.Repair)
            StalwartMailAccessState.RemovalPending ->
                setOf(StalwartMailAccessAction.Reconcile)
            StalwartMailAccessState.Rotating,
            StalwartMailAccessState.StoreUnavailable,
            -> emptySet()
        }
    }
}
