package mail.sandbox.dashboard.server.gate.dovecot

import java.time.Duration
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

internal class DovecotOperatorApplicationLeaseRegistry(
    initialActive: DovecotOperatorId,
) {
    private val lock = ReentrantLock()
    private var active = initialActive
    private val blocked = mutableSetOf<DovecotOperatorId>()
    private val leases = DovecotOperatorId.entries.associateWith {
        linkedSetOf<DovecotOperatorApplicationLease>()
    }
    private val verificationLeases =
        linkedSetOf<DovecotOperatorApplicationLease>()
    private val drainAttempts =
        mutableMapOf<DovecotOperatorId, DrainAttempt>()
    private var activationClosed = false

    fun acquire(
        id: DovecotOperatorId,
        closeSession: () -> Unit,
    ): DovecotOperatorApplicationLease =
        acquire(id, closeSession, verification = false)

    internal fun acquireVerification(
        id: DovecotOperatorId,
        closeSession: () -> Unit,
    ): DovecotOperatorApplicationLease =
        acquire(id, closeSession, verification = true)

    private fun acquire(
        id: DovecotOperatorId,
        closeSession: () -> Unit,
        verification: Boolean,
    ): DovecotOperatorApplicationLease = lock.withLock {
        check(!activationClosed && id == active && id !in blocked) {
            "Dovecot operator application generation is unavailable"
        }
        val trackedCount = leases.values.sumOf { tracked -> tracked.size }
        val applicationCount = trackedCount - verificationLeases.size
        check(
            trackedCount < MAX_TRACKED_LEASES &&
                if (verification) {
                    verificationLeases.isEmpty()
                } else {
                    applicationCount < MAX_APPLICATION_LEASES
                },
        ) {
            "Dovecot operator application lease capacity is exhausted"
        }
        DovecotOperatorApplicationLease(
            id = id,
            closeSession = closeSession,
            release = ::release,
        ).also { lease ->
            leases.getValue(id).add(lease)
            if (verification) {
                verificationLeases.add(lease)
            }
        }
    }

    fun activate(id: DovecotOperatorId) {
        activateAtomically(id) {}
    }

    internal fun <T> activateAtomically(
        id: DovecotOperatorId,
        publish: () -> T,
    ): T = lock.withLock {
        check(!activationClosed && id !in drainAttempts) {
            "Dovecot operator application generation is unavailable"
        }
        check(id !in blocked || leases.getValue(id).isEmpty()) {
            "Dovecot operator application generation has undrained leases"
        }
        val published = publish()
        blocked.remove(id)
        active = id
        published
    }

    fun blockAndDrain(id: DovecotOperatorId) {
        var leader = false
        val attempt = lock.withLock {
            blocked.add(id)
            drainAttempts[id] ?: DrainAttempt(
                deadlineNanos = System.nanoTime() + DRAIN_TIMEOUT.toNanos(),
                leases = leases.getValue(id).toList(),
            ).also { created ->
                drainAttempts[id] = created
                leader = true
            }
        }
        if (leader) {
            val failure = try {
                DovecotOperatorLeaseCloseSession(
                    maximumWorkers = maxOf(1, attempt.leases.size),
                ).use { session ->
                    session.closeAll(
                        leases = attempt.leases,
                        deadlineNanos = attempt.deadlineNanos,
                    )
                }
            } catch (failure: Throwable) {
                failure
            }
            attempt.complete(failure)
            try {
                lock.withLock {
                    drainAttempts.remove(id, attempt)
                }
            } catch (failure: Throwable) {
                attempt.complete(failure)
            }
        }
        attempt.await()?.let { throw it }
    }

    fun openLeaseCount(id: DovecotOperatorId): Int = lock.withLock {
        leases.getValue(id).size
    }

    internal fun activeId(): DovecotOperatorId = lock.withLock { active }

    internal fun <T> beginRuntimeClose(detach: () -> T): T = lock.withLock {
        activationClosed = true
        blocked += DovecotOperatorId.entries
        detach()
    }

    private fun release(lease: DovecotOperatorApplicationLease) {
        lock.withLock {
            leases.getValue(lease.id).remove(lease)
            verificationLeases.remove(lease)
        }
    }

    private class DrainAttempt(
        val deadlineNanos: Long,
        val leases: List<DovecotOperatorApplicationLease>,
    ) {
        private val completion = CountDownLatch(1)
        private val outcome = AtomicReference<DrainOutcome?>()

        fun complete(failure: Throwable?) {
            if (outcome.compareAndSet(null, DrainOutcome(failure))) {
                completion.countDown()
            }
        }

        fun await(): Throwable? {
            while (outcome.get() == null) {
                val remaining = deadlineNanos - System.nanoTime()
                if (remaining <= 0L) {
                    complete(drainTimeoutFailure())
                    break
                }
                try {
                    if (!completion.await(remaining, TimeUnit.NANOSECONDS)) {
                        complete(drainTimeoutFailure())
                    }
                } catch (interrupted: InterruptedException) {
                    Thread.currentThread().interrupt()
                    throw interrupted
                }
            }
            return requireNotNull(outcome.get()).failure
        }
    }

    private data class DrainOutcome(val failure: Throwable?)

    companion object {
        private const val MAX_TRACKED_LEASES = 16
        private const val RESERVED_VERIFICATION_LEASES = 1
        private const val MAX_APPLICATION_LEASES =
            MAX_TRACKED_LEASES - RESERVED_VERIFICATION_LEASES
        private val DRAIN_TIMEOUT = Duration.ofSeconds(1)
    }
}

internal class DovecotOperatorApplicationLease internal constructor(
    internal val id: DovecotOperatorId,
    private val closeSession: () -> Unit,
    private val release: (DovecotOperatorApplicationLease) -> Unit,
) : AutoCloseable {
    private val stateLock = Any()
    private var closed = false
    private var closeAttempt: CloseAttempt? = null

    val isOpen: Boolean
        get() = synchronized(stateLock) { !closed }

    override fun close() {
        var leader = false
        val attempt = synchronized(stateLock) {
            if (closed) return
            closeAttempt ?: CloseAttempt().also { created ->
                closeAttempt = created
                leader = true
            }
        }
        if (leader) {
            val failure = try {
                closeSession()
                release(this)
                null
            } catch (failure: Throwable) {
                failure
            }
            if (failure == null) {
                synchronized(stateLock) {
                    closed = true
                }
            }
            attempt.complete(failure)
            synchronized(stateLock) {
                if (closeAttempt === attempt) {
                    closeAttempt = null
                }
            }
        }
        attempt.await()?.let { throw it }
    }

    override fun toString(): String =
        "DovecotOperatorApplicationLease(id=${id.name}, open=$isOpen)"

    private class CloseAttempt {
        private val completion = CountDownLatch(1)
        private val outcome = AtomicReference<CloseOutcome?>()

        fun complete(failure: Throwable?) {
            if (outcome.compareAndSet(null, CloseOutcome(failure))) {
                completion.countDown()
            }
        }

        fun await(): Throwable? {
            try {
                completion.await()
            } catch (interrupted: InterruptedException) {
                Thread.currentThread().interrupt()
                throw interrupted
            }
            return requireNotNull(outcome.get()).failure
        }
    }

    private data class CloseOutcome(val failure: Throwable?)
}

internal fun interface DovecotOperatorCredentialProber {
    fun probe(
        target: DovecotOperatorTarget,
        credential: DovecotOperatorCredential,
    ): DovecotOperatorProbeResult
}

internal class DovecotOperatorLeasedRotationRuntime(
    private val leases: DovecotOperatorApplicationLeaseRegistry,
    private val prober: DovecotOperatorCredentialProber,
) : DovecotOperatorRotationRuntime, AutoCloseable {
    private val generationLock = Any()
    private var lifecycle = RuntimeLifecycle.Open
    private var generation: RuntimeGeneration? = null
    private var closeAttempt: RuntimeCloseAttempt? = null

    override fun observePasswdFile(
        target: DovecotOperatorTarget,
        credential: DovecotOperatorCredential,
    ): DovecotOperatorProbeResult = prober.probe(target, credential)

    override fun activateApplication(
        credential: DovecotOperatorCredential,
    ) {
        var copied = ByteArray(0)
        val next = try {
            credential.withSecretBytes { bytes ->
                copied = bytes.copyOf()
            }
            RuntimeGeneration(
                id = credential.id,
                secret = DovecotOperatorSecret.takeOwnership(copied),
            )
        } catch (failure: Throwable) {
            copied.fill(0)
            throw failure
        }
        val previous = try {
            synchronized(generationLock) {
                check(lifecycle == RuntimeLifecycle.Open) {
                    "Dovecot operator leased runtime is closed"
                }
                leases.activateAtomically(next.id) {
                    generation.also { generation = next }
                }
            }
        } catch (failure: Throwable) {
            next.close()
            throw failure
        }
        previous?.close()
    }

    override fun verifyApplication(
        target: DovecotOperatorTarget,
        expectedId: DovecotOperatorId,
    ): DovecotOperatorProbeResult {
        var copy = ByteArray(0)
        val credentialAndLease = try {
            synchronized(generationLock) {
                check(lifecycle == RuntimeLifecycle.Open) {
                    "Dovecot operator leased runtime is closed"
                }
                val current = checkNotNull(generation) {
                    "Dovecot operator application generation is absent"
                }
                check(current.id == expectedId) {
                    "Dovecot operator application generation is stale"
                }
                current.secret.withBytes { bytes ->
                    copy = bytes.copyOf()
                }
                val credential = DovecotOperatorCredential(
                    id = current.id,
                    secret = DovecotOperatorSecret.takeOwnership(copy),
                )
                val lease = try {
                    leases.acquireVerification(
                        expectedId,
                        credential::close,
                    )
                } catch (failure: Throwable) {
                    credential.close()
                    throw failure
                }
                credential to lease
            }
        } catch (failure: Throwable) {
            copy.fill(0)
            throw failure
        }
        val (credential, lease) = credentialAndLease
        return lease.use {
            prober.probe(target, credential)
        }
    }

    override fun blockAndDrain(id: DovecotOperatorId) {
        leases.blockAndDrain(id)
    }

    override fun close() {
        val registration = synchronized(generationLock) {
            when (lifecycle) {
                RuntimeLifecycle.Closed -> RuntimeCloseRegistration(
                    attempt = requireNotNull(closeAttempt),
                    leader = false,
                    generation = null,
                )
                RuntimeLifecycle.Closing -> RuntimeCloseRegistration(
                    attempt = requireNotNull(closeAttempt),
                    leader = false,
                    generation = null,
                )
                RuntimeLifecycle.Open -> {
                    lifecycle = RuntimeLifecycle.Closing
                    val attempt = RuntimeCloseAttempt()
                    closeAttempt = attempt
                    var detached: RuntimeGeneration? = null
                    leases.beginRuntimeClose {
                        detached = generation
                        generation = null
                    }
                    RuntimeCloseRegistration(
                        attempt = attempt,
                        leader = true,
                        generation = detached,
                    )
                }
            }
        }
        if (registration.leader) {
            var primary: Throwable? = null
            try {
                registration.generation?.close()
            } catch (failure: Throwable) {
                primary = combineRuntimeCloseFailures(primary, failure)
            }
            DovecotOperatorId.entries.forEach { id ->
                try {
                    leases.blockAndDrain(id)
                } catch (failure: Throwable) {
                    primary = combineRuntimeCloseFailures(primary, failure)
                }
            }
            synchronized(generationLock) {
                lifecycle = RuntimeLifecycle.Closed
            }
            registration.attempt.complete(primary)
        }
        registration.attempt.await()?.let { throw it }
    }

    private class RuntimeGeneration(
        val id: DovecotOperatorId,
        val secret: DovecotOperatorSecret,
    ) : AutoCloseable {
        override fun close() = secret.close()
    }

    private enum class RuntimeLifecycle {
        Open,
        Closing,
        Closed,
    }

    private data class RuntimeCloseRegistration(
        val attempt: RuntimeCloseAttempt,
        val leader: Boolean,
        val generation: RuntimeGeneration?,
    )

    private class RuntimeCloseAttempt {
        private val completion = CountDownLatch(1)
        private val outcome = AtomicReference<RuntimeCloseOutcome?>()

        fun complete(failure: Throwable?) {
            if (outcome.compareAndSet(null, RuntimeCloseOutcome(failure))) {
                completion.countDown()
            }
        }

        fun await(): Throwable? {
            try {
                completion.await()
            } catch (interrupted: InterruptedException) {
                Thread.currentThread().interrupt()
                throw interrupted
            }
            return requireNotNull(outcome.get()).failure
        }
    }

    private data class RuntimeCloseOutcome(val failure: Throwable?)
}

private fun combineRuntimeCloseFailures(
    primary: Throwable?,
    next: Throwable,
): Throwable {
    if (primary == null) return next
    if (primary !== next) {
        primary.addSuppressed(next)
    }
    return primary
}
