package mail.sandbox.dashboard.server.provider.stalwart.credential

internal enum class CredentialPhase {
    Active,
    Staged,
    Retiring,
    RemovalPending,
}

internal class CredentialGeneration(
    val credentialId: String,
    val description: String,
    val generation: Long,
    val secret: SecretBytes,
) : AutoCloseable {
    private var closed = false
    private var recordOwnershipClaimed = false

    init {
        if (!secret.claimOwnership()) {
            throw IllegalArgumentException("Credential secret ownership is aliased")
        }
        try {
            require(credentialId.isNotBlank()) { "Credential ID is absent" }
            require(description.isNotBlank()) { "Credential description is absent" }
            require(generation >= 0) { "Credential generation is invalid" }
        } catch (failure: Throwable) {
            closed = true
            secret.close()
            throw failure
        }
    }

    @Synchronized
    internal fun claimRecordOwnership(): Boolean {
        check(!closed) { "Credential generation is closed" }
        if (recordOwnershipClaimed) return false
        recordOwnershipClaimed = true
        return true
    }

    @Synchronized
    override fun close() {
        if (closed) return
        closed = true
        secret.close()
    }

    override fun toString(): String =
        "CredentialGeneration(" +
            "credentialId=$credentialId, " +
            "description=$description, " +
            "generation=$generation, " +
            "secret=redacted" +
            ")"
}

@ConsistentCopyVisibility
internal data class StalwartCredentialRecord private constructor(
    val accountId: String,
    val addressAtCapture: String,
    val phase: CredentialPhase,
    val active: CredentialGeneration?,
    val other: CredentialGeneration?,
) : AutoCloseable {
    init {
        require(accountId.isNotBlank()) { "Account ID is absent" }
        require(addressAtCapture.isNotBlank()) { "Captured address is absent" }
        require(active != null) {
            "An active generation is required for this phase"
        }
        require(active !== other) { "Credential generations must have distinct ownership" }
        require(active.secret !== other?.secret) {
            "Credential secrets must have distinct ownership"
        }
        when (phase) {
            CredentialPhase.Active,
            CredentialPhase.RemovalPending,
            -> require(other == null) {
                "A second generation is permitted only while rotating"
            }
            CredentialPhase.Staged,
            CredentialPhase.Retiring,
            -> require(other != null) {
                "Both generations are required while rotating"
            }
        }
    }

    override fun close() {
        active?.close()
        other?.close()
    }

    companion object {
        fun takeOwnership(
            accountId: String,
            addressAtCapture: String,
            phase: CredentialPhase,
            active: CredentialGeneration?,
            other: CredentialGeneration?,
        ): StalwartCredentialRecord {
            val claimed = mutableListOf<CredentialGeneration>()
            return try {
                active?.let { generation ->
                    require(generation.claimRecordOwnership()) {
                        "Credential generation ownership is aliased"
                    }
                    claimed.add(generation)
                }
                other?.let { generation ->
                    require(generation.claimRecordOwnership()) {
                        "Credential generation ownership is aliased"
                    }
                    claimed.add(generation)
                }
                StalwartCredentialRecord(
                    accountId = accountId,
                    addressAtCapture = addressAtCapture,
                    phase = phase,
                    active = active,
                    other = other,
                )
            } catch (failure: Throwable) {
                claimed.forEach(CredentialGeneration::close)
                throw failure
            }
        }
    }
}

internal class StalwartCredentialSnapshot(
    val storeId: java.util.UUID,
    val revision: Long,
    val records: Map<String, StalwartCredentialRecord>,
) : AutoCloseable {
    override fun close() {
        records.values.forEach(StalwartCredentialRecord::close)
    }

    override fun toString(): String =
        "StalwartCredentialSnapshot(" +
            "storeId=$storeId, " +
            "revision=$revision, " +
            "records=${records.size} redacted record(s)" +
            ")"
}
