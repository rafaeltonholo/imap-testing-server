package mail.sandbox.dashboard.server.provider.stalwart.credential

import java.nio.file.Path

internal sealed interface CredentialStoreLoadResult {
    data class Available(
        val snapshot: StalwartCredentialSnapshot,
    ) : CredentialStoreLoadResult

    data object StoreUnavailable : CredentialStoreLoadResult
}

internal sealed interface CredentialStoreWriteResult {
    data class Written(
        val revision: Long,
    ) : CredentialStoreWriteResult

    data class RevisionMismatch(
        val actualRevision: Long,
    ) : CredentialStoreWriteResult

    data object StoreUnavailable : CredentialStoreWriteResult
}

internal sealed interface CredentialStoreQuarantineResult {
    data class Quarantined(
        val files: List<Path>,
    ) : CredentialStoreQuarantineResult

    data class PartiallyQuarantined(
        val files: List<Path>,
    ) : CredentialStoreQuarantineResult

    data object StoreAvailable : CredentialStoreQuarantineResult

    data object StoreUnavailable : CredentialStoreQuarantineResult
}

internal interface StalwartCredentialStore : AutoCloseable {
    fun load(): CredentialStoreLoadResult

    fun replace(
        expectedRevision: Long,
        records: Map<String, StalwartCredentialRecord>,
    ): CredentialStoreWriteResult

    fun quarantineUnavailable(): CredentialStoreQuarantineResult
}
