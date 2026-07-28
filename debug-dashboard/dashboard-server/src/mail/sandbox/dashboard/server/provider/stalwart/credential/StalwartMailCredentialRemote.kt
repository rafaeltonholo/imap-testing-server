package mail.sandbox.dashboard.server.provider.stalwart.credential

internal sealed interface StalwartRemoteRead<out T> {
    data class Available<T>(
        val value: T,
    ) : StalwartRemoteRead<T>

    data object Unavailable : StalwartRemoteRead<Nothing>
}

internal enum class StalwartRemoteMutationResult {
    Verified,
    ReconciliationRequired,
}

internal enum class StalwartMailCapability {
    Core,
    Mail,
    Submission,
    Blob,
}

internal val STALWART_REQUIRED_MAIL_CAPABILITIES: Set<StalwartMailCapability> =
    StalwartMailCapability.entries.toSet()

internal sealed interface StalwartCredentialProbeResult {
    data class Authenticated(
        val capabilities: Set<StalwartMailCapability>,
    ) : StalwartCredentialProbeResult

    data object Rejected : StalwartCredentialProbeResult

    data object Unavailable : StalwartCredentialProbeResult
}

internal class StalwartBorrowedSecret private constructor(
    private val ownedBytes: ByteArray,
) : AutoCloseable {
    private var closed = false

    @Synchronized
    fun <T> withBytes(block: (ByteArray) -> T): T {
        check(!closed) { "Stalwart credential secret is closed" }
        val temporary = ownedBytes.copyOf()
        return try {
            block(temporary)
        } finally {
            temporary.fill(0)
        }
    }

    @Synchronized
    override fun close() {
        if (closed) return
        closed = true
        ownedBytes.fill(0)
    }

    override fun toString(): String = "StalwartBorrowedSecret(redacted)"

    companion object {
        fun takeOwnership(secret: ByteArray): StalwartBorrowedSecret {
            require(secret.isNotEmpty()) {
                secret.fill(0)
                "Stalwart credential secret is absent"
            }
            return StalwartBorrowedSecret(secret)
        }
    }
}

internal class StalwartNormalPassword private constructor(
    private val ownedChars: CharArray,
) : AutoCloseable {
    private var closed = false

    @Synchronized
    fun <T> withChars(block: (CharArray) -> T): T {
        check(!closed) { "Stalwart normal password is closed" }
        val temporary = ownedChars.copyOf()
        return try {
            block(temporary)
        } finally {
            temporary.fill('\u0000')
        }
    }

    @Synchronized
    override fun close() {
        if (closed) return
        closed = true
        ownedChars.fill('\u0000')
    }

    override fun toString(): String = "StalwartNormalPassword(redacted)"

    companion object {
        fun takeOwnership(password: CharArray): StalwartNormalPassword {
            require(password.isNotEmpty()) {
                password.fill('\u0000')
                "Stalwart normal password is absent"
            }
            return StalwartNormalPassword(password)
        }
    }
}

internal class StalwartCreatedCredential(
    val credentialId: String,
    val description: String,
    secret: ByteArray,
) : AutoCloseable {
    private var ownedSecret: StalwartBorrowedSecret? =
        StalwartBorrowedSecret.takeOwnership(secret)

    init {
        try {
            require(credentialId.isNotBlank()) { "Created credential ID is absent" }
            require(description.startsWith(STALWART_RESERVED_DESCRIPTION_PREFIX)) {
                "Created credential description is outside the dashboard reservation"
            }
        } catch (failure: Throwable) {
            close()
            throw failure
        }
    }

    @Synchronized
    fun takeSecret(): StalwartBorrowedSecret {
        val secret = ownedSecret
            ?: throw IllegalStateException("Created credential secret was already transferred")
        ownedSecret = null
        return secret
    }

    @Synchronized
    override fun close() {
        ownedSecret?.close()
        ownedSecret = null
    }

    override fun toString(): String =
        "StalwartCreatedCredential(" +
            "credentialId=$credentialId, description=$description, secret=redacted)"
}

internal sealed interface StalwartRemoteCreateResult {
    data class Created(
        val credential: StalwartCreatedCredential,
    ) : StalwartRemoteCreateResult

    data object ResponseLost : StalwartRemoteCreateResult

    data object Rejected : StalwartRemoteCreateResult

    data object Unavailable : StalwartRemoteCreateResult
}

internal interface StalwartCredentialManagementRemote {
    suspend fun inventory(
        accountId: String,
    ): StalwartRemoteRead<StalwartReservedInventory>

    suspend fun globalInventory():
        StalwartRemoteRead<StalwartGlobalReservedInventory>

    /**
     * The implementation must perform one fresh Account fetch, one batch patch,
     * and one authoritative verification while preserving every unrelated value.
     */
    suspend fun revokeReserved(
        accountId: String,
        expected: Set<StalwartReservedCredential>,
    ): StalwartRemoteMutationResult
}

internal interface StalwartCredentialOwnerRemote {
    suspend fun createOwned(
        account: StalwartMailAccount,
        description: String,
        normalPassword: StalwartNormalPassword,
    ): StalwartRemoteCreateResult
}

internal interface StalwartMailCredentialProbeRemote {
    /**
     * [secret] remains caller-owned. Implementations may borrow only through its
     * callback and must not retain or mutate credential bytes.
     */
    suspend fun probe(
        accountId: String,
        address: String,
        secret: StalwartBorrowedSecret,
    ): StalwartCredentialProbeResult
}
