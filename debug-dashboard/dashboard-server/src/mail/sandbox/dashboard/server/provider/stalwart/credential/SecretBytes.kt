package mail.sandbox.dashboard.server.provider.stalwart.credential

internal class SecretBytes private constructor(
    private val bytes: ByteArray,
) : AutoCloseable {
    private var closed = false
    private var ownershipClaimed = false

    @Synchronized
    internal fun claimOwnership(): Boolean {
        check(!closed) { "Secret bytes are closed" }
        if (ownershipClaimed) return false
        ownershipClaimed = true
        return true
    }

    @Synchronized
    fun copyForUse(): ByteArray {
        check(!closed) { "Secret bytes are closed" }
        return bytes.copyOf()
    }

    @Synchronized
    internal fun <T> read(block: (ByteArray) -> T): T {
        check(!closed) { "Secret bytes are closed" }
        return block(bytes)
    }

    @Synchronized
    override fun close() {
        if (closed) return
        closed = true
        bytes.fill(0)
    }

    override fun toString(): String = "SecretBytes(redacted)"

    companion object {
        fun takeOwnership(bytes: ByteArray): SecretBytes {
            require(bytes.isNotEmpty()) { "Secret bytes are absent" }
            return SecretBytes(bytes)
        }
    }
}
