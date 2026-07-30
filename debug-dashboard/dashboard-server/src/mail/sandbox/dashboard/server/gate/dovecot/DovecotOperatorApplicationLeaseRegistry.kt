package mail.sandbox.dashboard.server.gate.dovecot

import java.time.Duration
import java.util.concurrent.ExecutionException
import java.util.concurrent.Future
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicInteger
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
        check(id == active && id !in blocked) {
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

    fun activate(id: DovecotOperatorId) = lock.withLock {
        blocked.remove(id)
        active = id
    }

    fun blockAndDrain(id: DovecotOperatorId) {
        val draining = lock.withLock {
            blocked.add(id)
            leases.getValue(id).toList()
        }
        if (draining.isEmpty()) return

        val deadline = System.nanoTime() + DRAIN_TIMEOUT.toNanos()
        val futures = mutableListOf<Future<*>>()
        var primaryFailure: Throwable? = null
        for (lease in draining) {
            try {
                futures += DRAIN_EXECUTOR.submit(lease::close)
            } catch (failure: Throwable) {
                primaryFailure = combineFailures(primaryFailure, failure)
                break
            }
        }
        for (future in futures) {
            val remaining = deadline - System.nanoTime()
            if (remaining <= 0L) {
                primaryFailure = combineFailures(
                    primaryFailure,
                    drainTimeoutFailure(),
                )
                break
            }
            try {
                future.get(remaining, TimeUnit.NANOSECONDS)
            } catch (failure: ExecutionException) {
                primaryFailure = combineFailures(
                    primaryFailure,
                    failure.cause ?: failure,
                )
            } catch (_: TimeoutException) {
                primaryFailure = combineFailures(
                    primaryFailure,
                    drainTimeoutFailure(),
                )
                break
            } catch (failure: InterruptedException) {
                Thread.currentThread().interrupt()
                primaryFailure = combineFailures(
                    primaryFailure,
                    failure,
                )
                break
            } catch (failure: Throwable) {
                primaryFailure = combineFailures(
                    primaryFailure,
                    failure,
                )
            }
        }
        if (primaryFailure != null) {
            futures.forEach { future ->
                if (!future.isDone) {
                    future.cancel(true)
                }
            }
        }
        primaryFailure?.let { throw it }
    }

    fun openLeaseCount(id: DovecotOperatorId): Int = lock.withLock {
        leases.getValue(id).size
    }

    internal fun activeId(): DovecotOperatorId = lock.withLock { active }

    private fun release(lease: DovecotOperatorApplicationLease) {
        lock.withLock {
            leases.getValue(lease.id).remove(lease)
            verificationLeases.remove(lease)
        }
    }

    private fun drainTimeoutFailure(): IllegalStateException =
        IllegalStateException(
            "Dovecot operator application session drain timed out",
        )

    private fun combineFailures(
        primary: Throwable?,
        next: Throwable,
    ): Throwable {
        if (primary == null) return next
        if (primary !== next) {
            primary.addSuppressed(next)
        }
        return primary
    }

    companion object {
        private const val MAX_TRACKED_LEASES = 16
        private const val RESERVED_VERIFICATION_LEASES = 1
        private const val MAX_APPLICATION_LEASES =
            MAX_TRACKED_LEASES - RESERVED_VERIFICATION_LEASES
        private val DRAIN_TIMEOUT = Duration.ofSeconds(1)
        private val DRAIN_THREAD_SEQUENCE = AtomicInteger()
        private val DRAIN_EXECUTOR = ThreadPoolExecutor(
            0,
            MAX_TRACKED_LEASES,
            30,
            TimeUnit.SECONDS,
            SynchronousQueue(),
            { runnable ->
                Thread(
                    runnable,
                    "dovecot-operator-lease-close-" +
                        DRAIN_THREAD_SEQUENCE.incrementAndGet(),
                ).also { thread ->
                    thread.isDaemon = true
                }
            },
            ThreadPoolExecutor.AbortPolicy(),
        )
    }
}

internal class DovecotOperatorApplicationLease internal constructor(
    internal val id: DovecotOperatorId,
    private val closeSession: () -> Unit,
    private val release: (DovecotOperatorApplicationLease) -> Unit,
) : AutoCloseable {
    private val state = AtomicReference(State.Open)

    val isOpen: Boolean
        get() = state.get() != State.Closed

    override fun close() {
        if (!state.compareAndSet(State.Open, State.Closing)) {
            if (state.get() == State.Closed) return
            throw IllegalStateException(
                "Dovecot operator application session close is in progress",
            )
        }
        try {
            closeSession()
        } catch (failure: Throwable) {
            state.compareAndSet(State.Closing, State.Open)
            throw failure
        }
        state.set(State.Closed)
        release(this)
    }

    override fun toString(): String =
        "DovecotOperatorApplicationLease(id=${id.name}, open=$isOpen)"

    private enum class State {
        Open,
        Closing,
        Closed,
    }
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
    private var generation: RuntimeGeneration? = null

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
        val previous = synchronized(generationLock) {
            generation.also { generation = next }
        }
        leases.activate(next.id)
        previous?.close()
    }

    override fun verifyApplication(
        target: DovecotOperatorTarget,
        expectedId: DovecotOperatorId,
    ): DovecotOperatorProbeResult {
        var copy = ByteArray(0)
        val credential = try {
            val id = synchronized(generationLock) {
                val current = checkNotNull(generation) {
                    "Dovecot operator application generation is absent"
                }
                check(current.id == expectedId) {
                    "Dovecot operator application generation is stale"
                }
                current.secret.withBytes { bytes ->
                    copy = bytes.copyOf()
                }
                current.id
            }
            DovecotOperatorCredential(
                id = id,
                secret = DovecotOperatorSecret.takeOwnership(copy),
            )
        } catch (failure: Throwable) {
            copy.fill(0)
            throw failure
        }
        val lease = try {
            leases.acquireVerification(expectedId, credential::close)
        } catch (failure: Throwable) {
            credential.close()
            throw failure
        }
        return lease.use {
            prober.probe(target, credential)
        }
    }

    override fun blockAndDrain(id: DovecotOperatorId) {
        leases.blockAndDrain(id)
    }

    override fun close() {
        val previous = synchronized(generationLock) {
            generation.also { generation = null }
        }
        previous?.close()
        var primary: Throwable? = null
        DovecotOperatorId.entries.forEach { id ->
            try {
                leases.blockAndDrain(id)
            } catch (failure: Throwable) {
                val existing = primary
                if (existing == null) {
                    primary = failure
                } else if (existing !== failure) {
                    existing.addSuppressed(failure)
                }
            }
        }
        primary?.let { throw it }
    }

    private class RuntimeGeneration(
        val id: DovecotOperatorId,
        val secret: DovecotOperatorSecret,
    ) : AutoCloseable {
        override fun close() = secret.close()
    }
}
