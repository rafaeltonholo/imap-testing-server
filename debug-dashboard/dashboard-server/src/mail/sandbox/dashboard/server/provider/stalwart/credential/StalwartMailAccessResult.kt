package mail.sandbox.dashboard.server.provider.stalwart.credential

import java.util.UUID

internal enum class StalwartMailAccessReason {
    ProtectedIdentity,
    LeaseDrainTimedOut,
    RemoteUnavailable,
    RemoteStateChanged,
    CredentialRejected,
    CredentialQuotaFull,
    LocalStoreUnavailable,
    LocalRevisionChanged,
    CaptureFailed,
    CleanupUnproven,
    ResetNeedsManualRemediation,
}

internal sealed interface StalwartMailAccessResult {
    val projection: StalwartMailAccessProjection

    data class Completed(
        override val projection: StalwartMailAccessProjection,
    ) : StalwartMailAccessResult

    data class RetryableFailure(
        override val projection: StalwartMailAccessProjection,
        val reason: StalwartMailAccessReason,
    ) : StalwartMailAccessResult

    data class ReconciliationRequired(
        override val projection: StalwartMailAccessProjection,
        val reason: StalwartMailAccessReason,
    ) : StalwartMailAccessResult
}

internal sealed interface StalwartCredentialStoreResetResult {
    data class Completed(
        val storeId: UUID,
    ) : StalwartCredentialStoreResetResult

    data class RetryableFailure(
        val reason: StalwartMailAccessReason,
    ) : StalwartCredentialStoreResetResult

    data class ReconciliationRequired(
        val reason: StalwartMailAccessReason,
    ) : StalwartCredentialStoreResetResult
}
