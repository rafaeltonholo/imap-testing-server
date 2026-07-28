package mail.sandbox.dashboard.server.provider.stalwart.credential

import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.time.Duration.Companion.nanoseconds

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
}

internal sealed interface StalwartGlobalExclusiveLeaseAcquireResult {
    data class Acquired(
        val lease: StalwartGlobalExclusiveCredentialLease,
    ) : StalwartGlobalExclusiveLeaseAcquireResult

    data object TimedOut : StalwartGlobalExclusiveLeaseAcquireResult
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

internal fun interface StalwartLeaseChangeWaiter {
    @Throws(InterruptedException::class)
    suspend fun await(
        change: Deferred<Unit>,
        remainingNanos: Long,
    )
}

internal fun interface StalwartLeaseStateObserver {
    fun changed(trackedAccountCount: Int)
}

internal fun interface StalwartLeasePendingRegistrationObserver {
    fun beforeRegistration()
}

internal fun interface StalwartLeaseHandoffObserver {
    fun beforeHandoff()
}

internal class StalwartCredentialLeaseRegistry(
    private val nanoClock: StalwartLeaseNanoClock =
        StalwartLeaseNanoClock(System::nanoTime),
    private val waiter: StalwartLeaseChangeWaiter =
        StalwartLeaseChangeWaiter { change, remaining ->
            withTimeoutOrNull(remaining.nanoseconds) {
                change.await()
            }
            Unit
        },
    private val maximumDrainNanos: Long = TimeUnit.SECONDS.toNanos(30),
    private val stateObserver: StalwartLeaseStateObserver =
        StalwartLeaseStateObserver { },
    private val pendingRegistrationObserver:
        StalwartLeasePendingRegistrationObserver =
        StalwartLeasePendingRegistrationObserver { },
    private val handoffObserver: StalwartLeaseHandoffObserver =
        StalwartLeaseHandoffObserver { },
) {
    private val state = AtomicReference(RegistryState())

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
        val permitGranted = acquireReader(accountId)
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

    suspend fun acquireExclusive(
        accountId: String,
        timeoutNanos: Long = maximumDrainNanos,
    ): StalwartExclusiveLeaseAcquireResult {
        require(accountId.isNotBlank()) { "Exclusive lease Account ID is absent" }
        require(timeoutNanos in 0..maximumDrainNanos) {
            "Exclusive credential drain timeout is invalid"
        }
        val coroutineContext = currentCoroutineContext()
        coroutineContext.ensureActive()
        throwIfInterrupted()
        val started = nanoClock.nanoTime()
        pendingRegistrationObserver.beforeRegistration()
        coroutineContext.ensureActive()
        throwIfInterrupted()

        var registered = false
        var firstDecision = true
        try {
            if (!registerPendingWriter(accountId, started, timeoutNanos)) {
                return StalwartExclusiveLeaseAcquireResult.TimedOut
            }
            registered = true
            while (true) {
                coroutineContext.ensureActive()
                throwIfInterrupted()
                val current = state.get()
                val account = requireNotNull(current.accounts[accountId]) {
                    "Pending exclusive lease Account state is absent"
                }
                check(account.pendingWriters > 0) {
                    "Pending exclusive lease count is invalid"
                }
                val remaining = remainingNanos(started, timeoutNanos)
                val mayDecide =
                    remaining > 0 || (timeoutNanos == 0L && firstDecision)
                if (!mayDecide) {
                    return StalwartExclusiveLeaseAcquireResult.TimedOut
                }
                if (
                    account.readers == 0 &&
                    !account.writerActive &&
                    current.globalPendingWriters == 0 &&
                    !current.globalWriterActive
                ) {
                    val active = account.copy(
                        pendingWriters = account.pendingWriters - 1,
                        writerActive = true,
                    )
                    val updated = current.copy(
                        accounts = current.accounts + (accountId to active),
                    )
                    if (publish(current, updated)) {
                        registered = false
                        val lease =
                            StalwartExclusiveCredentialLease(accountId) {
                                releaseWriter(accountId)
                            }
                        return handOffLease(
                            lease = lease,
                            result =
                                StalwartExclusiveLeaseAcquireResult.Acquired(
                                    lease,
                                ),
                        )
                    }
                    firstDecision = false
                    continue
                }
                firstDecision = false
                waiter.await(current.changed, remaining.coerceAtLeast(0))
                throwIfInterrupted()
            }
        } catch (interrupted: InterruptedException) {
            Thread.currentThread().interrupt()
            throw interrupted
        } finally {
            if (registered) {
                unregisterPendingWriter(accountId)
            }
        }
    }

    suspend fun acquireGlobalExclusive(
        timeoutNanos: Long = maximumDrainNanos,
    ): StalwartGlobalExclusiveLeaseAcquireResult {
        require(timeoutNanos in 0..maximumDrainNanos) {
            "Global credential drain timeout is invalid"
        }
        val coroutineContext = currentCoroutineContext()
        coroutineContext.ensureActive()
        throwIfInterrupted()
        val started = nanoClock.nanoTime()
        pendingRegistrationObserver.beforeRegistration()
        coroutineContext.ensureActive()
        throwIfInterrupted()

        var registered = false
        var firstDecision = true
        try {
            if (!registerPendingGlobalWriter(started, timeoutNanos)) {
                return StalwartGlobalExclusiveLeaseAcquireResult.TimedOut
            }
            registered = true
            while (true) {
                coroutineContext.ensureActive()
                throwIfInterrupted()
                val current = state.get()
                check(current.globalPendingWriters > 0) {
                    "Pending global exclusive lease count is invalid"
                }
                val remaining = remainingNanos(started, timeoutNanos)
                val mayDecide =
                    remaining > 0 || (timeoutNanos == 0L && firstDecision)
                if (!mayDecide) {
                    return StalwartGlobalExclusiveLeaseAcquireResult.TimedOut
                }
                if (
                    current.activeReaders == 0 &&
                    !current.globalWriterActive &&
                    current.accounts.values.none { it.writerActive }
                ) {
                    val updated = current.copy(
                        globalPendingWriters =
                            current.globalPendingWriters - 1,
                        globalWriterActive = true,
                    )
                    if (publish(current, updated)) {
                        registered = false
                        val lease = StalwartGlobalExclusiveCredentialLease(
                            ::releaseGlobalWriter,
                        )
                        return handOffLease(
                            lease = lease,
                            result =
                                StalwartGlobalExclusiveLeaseAcquireResult.Acquired(
                                    lease,
                                ),
                        )
                    }
                    firstDecision = false
                    continue
                }
                firstDecision = false
                waiter.await(current.changed, remaining.coerceAtLeast(0))
                throwIfInterrupted()
            }
        } catch (interrupted: InterruptedException) {
            Thread.currentThread().interrupt()
            throw interrupted
        } finally {
            if (registered) {
                unregisterPendingGlobalWriter()
            }
        }
    }

    private fun acquireReader(accountId: String): Boolean {
        while (true) {
            val current = state.get()
            if (
                current.globalPendingWriters > 0 ||
                current.globalWriterActive
            ) {
                return false
            }
            val account = current.accounts[accountId] ?: AccountLeaseState()
            if (
                account.pendingWriters > 0 ||
                account.writerActive
            ) {
                return false
            }
            val updated = current.copy(
                accounts = current.accounts + (
                    accountId to account.copy(readers = account.readers + 1)
                ),
                activeReaders = current.activeReaders + 1,
            )
            if (publish(current, updated)) {
                return true
            }
        }
    }

    private suspend fun registerPendingWriter(
        accountId: String,
        started: Long,
        timeoutNanos: Long,
    ): Boolean {
        var firstAttempt = true
        while (true) {
            currentCoroutineContext().ensureActive()
            throwIfInterrupted()
            val remaining = remainingNanos(started, timeoutNanos)
            if (
                remaining <= 0 &&
                !(timeoutNanos == 0L && firstAttempt)
            ) {
                return false
            }
            val current = state.get()
            val account = current.accounts[accountId] ?: AccountLeaseState()
            val updated = current.copy(
                accounts = current.accounts + (
                    accountId to account.copy(
                        pendingWriters = account.pendingWriters + 1,
                    )
                ),
            )
            if (publish(current, updated)) {
                return true
            }
            firstAttempt = false
        }
    }

    private fun unregisterPendingWriter(accountId: String) {
        while (true) {
            val current = state.get()
            val account = requireNotNull(current.accounts[accountId]) {
                "Pending exclusive lease Account state is absent"
            }
            check(account.pendingWriters > 0) {
                "Pending exclusive lease count is invalid"
            }
            val withoutPending = account.copy(
                pendingWriters = account.pendingWriters - 1,
            )
            val updated = current.copy(
                accounts = current.accounts.withAccountOrPruned(
                    accountId,
                    withoutPending,
                ),
            )
            if (publish(current, updated)) {
                return
            }
        }
    }

    private suspend fun registerPendingGlobalWriter(
        started: Long,
        timeoutNanos: Long,
    ): Boolean {
        var firstAttempt = true
        while (true) {
            currentCoroutineContext().ensureActive()
            throwIfInterrupted()
            val remaining = remainingNanos(started, timeoutNanos)
            if (
                remaining <= 0 &&
                !(timeoutNanos == 0L && firstAttempt)
            ) {
                return false
            }
            val current = state.get()
            val updated = current.copy(
                globalPendingWriters = current.globalPendingWriters + 1,
            )
            if (publish(current, updated)) {
                return true
            }
            firstAttempt = false
        }
    }

    private fun unregisterPendingGlobalWriter() {
        while (true) {
            val current = state.get()
            check(current.globalPendingWriters > 0) {
                "Pending global exclusive lease count is invalid"
            }
            val updated = current.copy(
                globalPendingWriters = current.globalPendingWriters - 1,
            )
            if (publish(current, updated)) {
                return
            }
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
        while (true) {
            val current = state.get()
            val account = requireNotNull(current.accounts[accountId]) {
                "Mail lease Account state is absent"
            }
            check(account.readers > 0 && current.activeReaders > 0) {
                "Mail lease reader count is invalid"
            }
            val withoutReader = account.copy(readers = account.readers - 1)
            val updated = current.copy(
                accounts = current.accounts.withAccountOrPruned(
                    accountId,
                    withoutReader,
                ),
                activeReaders = current.activeReaders - 1,
            )
            if (publish(current, updated)) {
                return
            }
        }
    }

    private fun releaseWriter(accountId: String) {
        while (true) {
            val current = state.get()
            val account = requireNotNull(current.accounts[accountId]) {
                "Exclusive lease Account state is absent"
            }
            check(account.writerActive) { "Exclusive lease was not active" }
            val withoutWriter = account.copy(writerActive = false)
            val updated = current.copy(
                accounts = current.accounts.withAccountOrPruned(
                    accountId,
                    withoutWriter,
                ),
            )
            if (publish(current, updated)) {
                return
            }
        }
    }

    private fun releaseGlobalWriter() {
        while (true) {
            val current = state.get()
            check(current.globalWriterActive) {
                "Global exclusive lease was not active"
            }
            val updated = current.copy(globalWriterActive = false)
            if (publish(current, updated)) {
                return
            }
        }
    }

    private fun publish(
        previous: RegistryState,
        updated: RegistryState,
    ): Boolean {
        val next = updated.copy(changed = CompletableDeferred())
        if (!state.compareAndSet(previous, next)) {
            return false
        }
        previous.changed.complete(Unit)
        try {
            stateObserver.changed(next.accounts.size)
        } catch (_: Exception) {
            // Test-only observation must never change registry semantics.
        }
        return true
    }

    private suspend fun <Lease : AutoCloseable, Result> handOffLease(
        lease: Lease,
        result: Result,
    ): Result = suspendCancellableCoroutine { continuation ->
        try {
            handoffObserver.beforeHandoff()
            throwIfInterrupted()
        } catch (failure: Throwable) {
            lease.close()
            throw failure
        }
        continuation.resume(result) { _, _, _ ->
            lease.close()
        }
    }

    private fun throwIfInterrupted() {
        if (Thread.currentThread().isInterrupted) {
            throw InterruptedException("Credential lease drain was interrupted")
        }
    }

    private fun Map<String, AccountLeaseState>.withAccountOrPruned(
        accountId: String,
        account: AccountLeaseState,
    ): Map<String, AccountLeaseState> =
        if (account.isIdle) {
            this - accountId
        } else {
            this + (accountId to account)
        }

    private data class RegistryState(
        val accounts: Map<String, AccountLeaseState> = emptyMap(),
        val activeReaders: Int = 0,
        val globalPendingWriters: Int = 0,
        val globalWriterActive: Boolean = false,
        val changed: CompletableDeferred<Unit> = CompletableDeferred(),
    )

    private data class AccountLeaseState(
        val readers: Int = 0,
        val pendingWriters: Int = 0,
        val writerActive: Boolean = false,
    ) {
        val isIdle: Boolean
            get() = readers == 0 && pendingWriters == 0 && !writerActive
    }
}
