package mail.sandbox.dashboard.server.gate.dovecot

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

    fun acquire(
        id: DovecotOperatorId,
        closeSession: () -> Unit,
    ): DovecotOperatorApplicationLease = lock.withLock {
        check(id == active && id !in blocked) {
            "Dovecot operator application generation is unavailable"
        }
        DovecotOperatorApplicationLease(
            id = id,
            closeSession = closeSession,
            release = ::release,
        ).also { lease ->
            leases.getValue(id).add(lease)
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
        var primaryFailure: Throwable? = null
        draining.forEach { lease ->
            try {
                lease.close()
            } catch (failure: Throwable) {
                val primary = primaryFailure
                if (primary == null) {
                    primaryFailure = failure
                } else if (primary !== failure) {
                    primary.addSuppressed(failure)
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
        }
    }
}

internal class DovecotOperatorApplicationLease internal constructor(
    internal val id: DovecotOperatorId,
    private val closeSession: () -> Unit,
    private val release: (DovecotOperatorApplicationLease) -> Unit,
) : AutoCloseable {
    private var open = true

    @get:Synchronized
    val isOpen: Boolean
        get() = open

    @Synchronized
    override fun close() {
        if (!open) return
        closeSession()
        open = false
        release(this)
    }

    override fun toString(): String =
        "DovecotOperatorApplicationLease(id=${id.name}, open=$isOpen)"
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
            leases.acquire(expectedId, credential::close)
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
