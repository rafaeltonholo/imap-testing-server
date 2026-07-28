package mail.sandbox.dashboard.server.provider.stalwart.credential

import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.Condition
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

internal class StalwartMailLeaseMaterial private constructor(
    val accountId: String,
    val generation: Long,
    private var secret: StalwartBorrowedSecret?,
) : AutoCloseable {
    init {
        require(accountId.isNotBlank()) { "Mail lease Account ID is absent" }
        require(generation > 0) { "Mail lease generation is invalid" }
    }

    @Synchronized
    internal fun takeSecret(): StalwartBorrowedSecret {
        val transferred = secret
            ?: throw IllegalStateException("Mail lease material was already transferred")
        secret = null
        return transferred
    }

    @Synchronized
    override fun close() {
        secret?.close()
        secret = null
    }

    override fun toString(): String =
        "StalwartMailLeaseMaterial(" +
            "accountId=$accountId, generation=$generation, secret=redacted)"

    companion object {
        fun takeOwnership(
            accountId: String,
            generation: Long,
            secret: ByteArray,
        ): StalwartMailLeaseMaterial {
            val owned = StalwartBorrowedSecret.takeOwnership(secret)
            return try {
                StalwartMailLeaseMaterial(accountId, generation, owned)
            } catch (failure: Throwable) {
                owned.close()
                throw failure
            }
        }
    }
}

internal class StalwartMailCredentialLease private constructor(
    val accountId: String,
    val generation: Long,
    private val secret: StalwartBorrowedSecret,
    private val releasePermit: () -> Unit,
) : AutoCloseable {
    private var closed = false

    @Synchronized
    fun <T> withSecret(block: (ByteArray) -> T): T {
        check(!closed) { "Mail credential lease is closed" }
        return secret.withBytes(block)
    }

    @Synchronized
    override fun close() {
        if (closed) return
        closed = true
        try {
            secret.close()
        } finally {
            releasePermit()
        }
    }

    fun cancel() = close()

    override fun toString(): String =
        "StalwartMailCredentialLease(" +
            "accountId=$accountId, generation=$generation, secret=redacted)"

    companion object {
        internal fun takeOwnership(
            material: StalwartMailLeaseMaterial,
            releasePermit: () -> Unit,
        ): StalwartMailCredentialLease {
            val secret = material.takeSecret()
            return try {
                StalwartMailCredentialLease(
                    accountId = material.accountId,
                    generation = material.generation,
                    secret = secret,
                    releasePermit = releasePermit,
                )
            } catch (failure: Throwable) {
                secret.close()
                throw failure
            } finally {
                material.close()
            }
        }
    }
}

internal enum class StalwartMailLeaseUnavailableReason {
    MutationPending,
    NotReady,
}

internal sealed interface StalwartMailLeaseAcquireResult {
    data class Acquired(
        val lease: StalwartMailCredentialLease,
    ) : StalwartMailLeaseAcquireResult

    data class Unavailable(
        val reason: StalwartMailLeaseUnavailableReason,
    ) : StalwartMailLeaseAcquireResult
}

internal sealed interface StalwartExclusiveLeaseAcquireResult {
    data class Acquired(
        val lease: StalwartExclusiveCredentialLease,
    ) : StalwartExclusiveLeaseAcquireResult

    data object TimedOut : StalwartExclusiveLeaseAcquireResult

    data object Interrupted : StalwartExclusiveLeaseAcquireResult
}

internal sealed interface StalwartGlobalExclusiveLeaseAcquireResult {
    data class Acquired(
        val lease: StalwartGlobalExclusiveCredentialLease,
    ) : StalwartGlobalExclusiveLeaseAcquireResult

    data object TimedOut : StalwartGlobalExclusiveLeaseAcquireResult

    data object Interrupted : StalwartGlobalExclusiveLeaseAcquireResult
}

internal class StalwartExclusiveCredentialLease internal constructor(
    val accountId: String,
    private val releasePermit: () -> Unit,
) : AutoCloseable {
    private var closed = false

    @Synchronized
    override fun close() {
        if (closed) return
        closed = true
        releasePermit()
    }
}

internal class StalwartGlobalExclusiveCredentialLease internal constructor(
    private val releasePermit: () -> Unit,
) : AutoCloseable {
    private var closed = false

    @Synchronized
    override fun close() {
        if (closed) return
        closed = true
        releasePermit()
    }
}

internal fun interface StalwartLeaseNanoClock {
    fun nanoTime(): Long
}

internal fun interface StalwartLeaseConditionWaiter {
    @Throws(InterruptedException::class)
    fun await(
        condition: Condition,
        remainingNanos: Long,
    )
}

internal class StalwartCredentialLeaseRegistry(
    private val nanoClock: StalwartLeaseNanoClock =
        StalwartLeaseNanoClock(System::nanoTime),
    private val waiter: StalwartLeaseConditionWaiter =
        StalwartLeaseConditionWaiter { condition, remaining ->
            condition.awaitNanos(remaining)
        },
    private val maximumDrainNanos: Long = TimeUnit.SECONDS.toNanos(30),
) {
    private val lock = ReentrantLock()
    private val changed = lock.newCondition()
    private val accounts = mutableMapOf<String, AccountLeaseState>()
    private var activeReaders = 0
    private var globalPendingWriters = 0
    private var globalWriterActive = false

    init {
        require(maximumDrainNanos in 1..TimeUnit.SECONDS.toNanos(30)) {
            "Maximum credential drain timeout is invalid"
        }
    }

    /**
     * The shared permit is acquired before [loadCurrentMaterial] runs. This
     * prevents a rotation from revoking a generation between its load and lease
     * attachment.
     */
    suspend fun acquireMail(
        accountId: String,
        loadCurrentMaterial: suspend () -> StalwartMailLeaseMaterial?,
    ): StalwartMailLeaseAcquireResult {
        require(accountId.isNotBlank()) { "Mail lease Account ID is absent" }
        val permitGranted = lock.withLock {
            val account = state(accountId)
            if (
                globalPendingWriters > 0 ||
                globalWriterActive ||
                account.pendingWriters > 0 ||
                account.writerActive
            ) {
                false
            } else {
                account.readers += 1
                activeReaders += 1
                true
            }
        }
        if (!permitGranted) {
            return StalwartMailLeaseAcquireResult.Unavailable(
                StalwartMailLeaseUnavailableReason.MutationPending,
            )
        }

        var material: StalwartMailLeaseMaterial? = null
        return try {
            material = loadCurrentMaterial()
            if (material == null) {
                releaseReader(accountId)
                StalwartMailLeaseAcquireResult.Unavailable(
                    StalwartMailLeaseUnavailableReason.NotReady,
                )
            } else if (material.accountId != accountId) {
                material.close()
                releaseReader(accountId)
                StalwartMailLeaseAcquireResult.Unavailable(
                    StalwartMailLeaseUnavailableReason.NotReady,
                )
            } else {
                StalwartMailLeaseAcquireResult.Acquired(
                    StalwartMailCredentialLease.takeOwnership(material) {
                        releaseReader(accountId)
                    },
                )
            }
        } catch (failure: Throwable) {
            material?.close()
            releaseReader(accountId)
            throw failure
        }
    }

    fun acquireExclusive(
        accountId: String,
        timeoutNanos: Long = maximumDrainNanos,
    ): StalwartExclusiveLeaseAcquireResult {
        require(accountId.isNotBlank()) { "Exclusive lease Account ID is absent" }
        require(timeoutNanos in 0..maximumDrainNanos) {
            "Exclusive credential drain timeout is invalid"
        }
        lock.lock()
        val account = state(accountId)
        account.pendingWriters += 1
        val started = nanoClock.nanoTime()
        try {
            while (
                account.readers > 0 ||
                account.writerActive ||
                globalPendingWriters > 0 ||
                globalWriterActive
            ) {
                val remaining = remainingNanos(started, timeoutNanos)
                if (remaining <= 0) {
                    account.pendingWriters -= 1
                    changed.signalAll()
                    return StalwartExclusiveLeaseAcquireResult.TimedOut
                }
                try {
                    waiter.await(changed, remaining)
                } catch (_: InterruptedException) {
                    account.pendingWriters -= 1
                    changed.signalAll()
                    Thread.currentThread().interrupt()
                    return StalwartExclusiveLeaseAcquireResult.Interrupted
                }
            }
            account.pendingWriters -= 1
            account.writerActive = true
            return StalwartExclusiveLeaseAcquireResult.Acquired(
                StalwartExclusiveCredentialLease(accountId) {
                    releaseWriter(accountId)
                },
            )
        } finally {
            lock.unlock()
        }
    }

    fun acquireGlobalExclusive(
        timeoutNanos: Long = maximumDrainNanos,
    ): StalwartGlobalExclusiveLeaseAcquireResult {
        require(timeoutNanos in 0..maximumDrainNanos) {
            "Global credential drain timeout is invalid"
        }
        lock.lock()
        globalPendingWriters += 1
        val started = nanoClock.nanoTime()
        try {
            while (
                activeReaders > 0 ||
                globalWriterActive ||
                accounts.values.any { it.writerActive }
            ) {
                val remaining = remainingNanos(started, timeoutNanos)
                if (remaining <= 0) {
                    globalPendingWriters -= 1
                    changed.signalAll()
                    return StalwartGlobalExclusiveLeaseAcquireResult.TimedOut
                }
                try {
                    waiter.await(changed, remaining)
                } catch (_: InterruptedException) {
                    globalPendingWriters -= 1
                    changed.signalAll()
                    Thread.currentThread().interrupt()
                    return StalwartGlobalExclusiveLeaseAcquireResult.Interrupted
                }
            }
            globalPendingWriters -= 1
            globalWriterActive = true
            return StalwartGlobalExclusiveLeaseAcquireResult.Acquired(
                StalwartGlobalExclusiveCredentialLease(::releaseGlobalWriter),
            )
        } finally {
            lock.unlock()
        }
    }

    private fun remainingNanos(
        started: Long,
        timeoutNanos: Long,
    ): Long {
        val elapsed = nanoClock.nanoTime() - started
        return timeoutNanos - elapsed.coerceAtLeast(0)
    }

    private fun releaseReader(accountId: String) {
        lock.withLock {
            val account = requireNotNull(accounts[accountId]) {
                "Mail lease Account state is absent"
            }
            check(account.readers > 0 && activeReaders > 0) {
                "Mail lease reader count is invalid"
            }
            account.readers -= 1
            activeReaders -= 1
            removeIdleAccount(accountId, account)
            changed.signalAll()
        }
    }

    private fun releaseWriter(accountId: String) {
        lock.withLock {
            val account = requireNotNull(accounts[accountId]) {
                "Exclusive lease Account state is absent"
            }
            check(account.writerActive) { "Exclusive lease was not active" }
            account.writerActive = false
            removeIdleAccount(accountId, account)
            changed.signalAll()
        }
    }

    private fun releaseGlobalWriter() {
        lock.withLock {
            check(globalWriterActive) { "Global exclusive lease was not active" }
            globalWriterActive = false
            changed.signalAll()
        }
    }

    private fun state(accountId: String): AccountLeaseState =
        accounts.getOrPut(accountId, ::AccountLeaseState)

    private fun removeIdleAccount(
        accountId: String,
        account: AccountLeaseState,
    ) {
        if (
            account.readers == 0 &&
            account.pendingWriters == 0 &&
            !account.writerActive
        ) {
            accounts.remove(accountId, account)
        }
    }

    private class AccountLeaseState {
        var readers = 0
        var pendingWriters = 0
        var writerActive = false
    }
}
