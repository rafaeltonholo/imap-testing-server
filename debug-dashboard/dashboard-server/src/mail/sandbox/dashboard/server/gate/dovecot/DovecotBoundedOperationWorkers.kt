package mail.sandbox.dashboard.server.gate.dovecot

import java.io.IOException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

internal enum class DovecotBoundedActorRole {
    Io,
    Abort,
    Close,
}

internal fun interface DovecotBoundedActorLauncher {
    fun start(
        role: DovecotBoundedActorRole,
        name: String,
        action: Runnable,
    )
}

internal data class DovecotBoundedOperationSnapshot(
    val activeOperations: Int = 0,
    val abandonedOperations: Int = 0,
    val activeActors: Int = 0,
    val peakActors: Int = 0,
)

internal class DovecotBoundedOperationTimeoutException :
    IOException("Dovecot operation exceeded its deadline")

internal class DovecotBoundedOperationWorkers(
    private val maxOperations: Int = DEFAULT_MAX_OPERATIONS,
    private val actorLauncher: DovecotBoundedActorLauncher =
        DovecotBoundedActorLauncher { _, name, action ->
            Thread(action, name).also { thread ->
                thread.isDaemon = true
                thread.start()
            }
        },
    private val beforeOperationConstruction: () -> Unit = {},
    private val beforeOperationStart: () -> Unit = {},
    private val beforeTaskSubmission: () -> Unit = {},
    private val beforeTaskClaim: () -> Unit = {},
    private val afterWorkerDispositionInterrupt: () -> Unit = {},
    private val beforeOwnershipCommit: () -> Unit = {},
    private val nanoTime: () -> Long = System::nanoTime,
    private val copyBytes: (ByteArray) -> ByteArray = ByteArray::copyOf,
    private val wipeBytes: (ByteArray) -> Unit = { bytes -> bytes.fill(0) },
) {
    private val lock = Any()
    private var activeOperations = 0
    private var abandonedOperations = 0
    private var activeActors = 0
    private var peakActors = 0

    init {
        require(maxOperations in 1..DEFAULT_MAX_OPERATIONS) {
            "Dovecot operation capacity must be between 1 and " +
                DEFAULT_MAX_OPERATIONS
        }
    }

    fun tryAcquire(deadlineNanos: Long): DovecotBoundedOperation? {
        if (deadlineExpired(deadlineNanos, nanoTime)) return null
        synchronized(lock) {
            if (activeOperations + abandonedOperations >= maxOperations) {
                return null
            }
            activeOperations += 1
        }

        val operation = try {
            beforeOperationConstruction()
            DovecotBoundedOperation(
                owner = this,
                deadlineNanos = deadlineNanos,
                actorLauncher = actorLauncher,
                beforeTaskSubmission = beforeTaskSubmission,
                beforeTaskClaim = beforeTaskClaim,
                afterWorkerDispositionInterrupt =
                    afterWorkerDispositionInterrupt,
                beforeOwnershipCommit = beforeOwnershipCommit,
                nanoTime = nanoTime,
                copyBytes = copyBytes,
                wipeBytes = wipeBytes,
            )
        } catch (failure: Throwable) {
            release(abandoned = false)
            throw failure
        }
        try {
            beforeOperationStart()
            operation.start()
            return operation
        } catch (failure: Throwable) {
            operation.failBeforeStart()
            throw failure
        }
    }

    fun snapshot(): DovecotBoundedOperationSnapshot = synchronized(lock) {
        DovecotBoundedOperationSnapshot(
            activeOperations = activeOperations,
            abandonedOperations = abandonedOperations,
            activeActors = activeActors,
            peakActors = peakActors,
        )
    }

    internal fun chargeActor() {
        synchronized(lock) {
            activeActors += 1
            peakActors = maxOf(peakActors, activeActors)
        }
    }

    internal fun finishActor() {
        synchronized(lock) {
            check(activeActors > 0) {
                "Dovecot operation actor accounting underflow"
            }
            activeActors -= 1
        }
    }

    internal fun markAbandoned() {
        synchronized(lock) {
            check(activeOperations > 0) {
                "Dovecot operation charge is not active"
            }
            activeOperations -= 1
            abandonedOperations += 1
        }
    }

    internal fun release(abandoned: Boolean) {
        synchronized(lock) {
            if (abandoned) {
                check(abandonedOperations > 0) {
                    "Dovecot abandoned operation accounting underflow"
                }
                abandonedOperations -= 1
            } else {
                check(activeOperations > 0) {
                    "Dovecot active operation accounting underflow"
                }
                activeOperations -= 1
            }
        }
    }

    companion object {
        private const val DEFAULT_MAX_OPERATIONS = 4

        val processWide: DovecotBoundedOperationWorkers by lazy {
            DovecotBoundedOperationWorkers()
        }
    }
}

internal class DovecotBoundedOperation internal constructor(
    private val owner: DovecotBoundedOperationWorkers,
    private val deadlineNanos: Long,
    private val actorLauncher: DovecotBoundedActorLauncher,
    private val beforeTaskSubmission: () -> Unit,
    private val beforeTaskClaim: () -> Unit,
    private val afterWorkerDispositionInterrupt: () -> Unit,
    private val beforeOwnershipCommit: () -> Unit,
    private val nanoTime: () -> Long,
    private val copyBytes: (ByteArray) -> ByteArray,
    private val wipeBytes: (ByteArray) -> Unit,
) : AutoCloseable {
    private val lock = ReentrantLock()
    private val workAvailable = lock.newCondition()
    private val released = lock.newCondition()
    private val context = DovecotBoundedOperationContext(this)
    private val targets = ArrayList<CancellationTarget>(MAX_TARGETS)
    private var pendingTask: WorkerTask? = null
    private var inFlightTask: WorkerTask? = null
    private var finishRequested = false
    private var abandoned = false
    private var registrationSealed = false
    private var ioActorCharged = false
    private var ioActorExited = false
    private var ioActorThread: Thread? = null
    private var cancellationActors = 0
    private var commitInProgress = false
    private var handoffCommitted = false
    private var finiteCompleted = false
    private var releaseWithoutHandoff = false
    private var reservationReleased = false

    internal fun start() {
        lock.withLock {
            check(!ioActorCharged && !ioActorExited)
            ioActorCharged = true
            owner.chargeActor()
        }
        try {
            actorLauncher.start(
                DovecotBoundedActorRole.Io,
                actorName("io"),
                Runnable(::runWorker),
            )
        } catch (failure: Throwable) {
            failIoActorStart()
            throw failure
        }
    }

    internal fun failBeforeStart() {
        lock.withLock {
            if (registrationSealed) return
            registrationSealed = true
            ioActorExited = true
            releaseWithoutHandoff = true
            maybeReleaseLocked()
        }
    }

    fun <T> execute(
        disposeLate: (T) -> Unit = {},
        block: DovecotBoundedOperationContext.() -> T,
    ): T {
        val task = OperationTask(
            deadlineNanos = deadlineNanos,
            disposeLate = disposeLate,
            beforeClaim = beforeTaskClaim,
            afterDispositionInterrupt = afterWorkerDispositionInterrupt,
            nanoTime = nanoTime,
            block = { block(context) },
        )
        return executeTask(task)
    }

    fun <T> executeWithCopiedBytes(
        source: ByteArray,
        disposeLate: (T) -> Unit = {},
        block: DovecotBoundedOperationContext.(ByteArray) -> T,
    ): T {
        val owned = try {
            copyBytes(source)
        } catch (failure: Throwable) {
            abandon()
            throw failure
        }
        val wiped = AtomicBoolean()
        val wipeOwned = {
            if (wiped.compareAndSet(false, true)) {
                wipeBytes(owned)
            }
        }
        val task = OperationTask(
            deadlineNanos = deadlineNanos,
            disposeLate = disposeLate,
            disposeBeforeRun = wipeOwned,
            beforeClaim = beforeTaskClaim,
            afterDispositionInterrupt = afterWorkerDispositionInterrupt,
            nanoTime = nanoTime,
            block = {
                try {
                    block(context, owned)
                } finally {
                    wipeOwned()
                }
            },
        )
        return executeTask(task)
    }

    private fun <T> executeTask(
        task: OperationTask<T>,
    ): T {
        try {
            submit(task)
        } catch (interrupted: InterruptedException) {
            task.cancelBeforeRun()
            abandon()
            Thread.currentThread().interrupt()
            throw InterruptedException(
                "Dovecot operation was interrupted",
            )
        } catch (failure: Throwable) {
            task.cancelBeforeRun()
            abandon()
            throw failure
        }
        try {
            return task.await()
        } catch (interrupted: InterruptedException) {
            task.decline()
            abandon()
            Thread.currentThread().interrupt()
            throw InterruptedException(
                "Dovecot operation was interrupted",
            )
        } catch (failure: Throwable) {
            abandon()
            throw failure
        }
    }

    fun abandon() {
        val launches = lock.withLock {
            abandonLocked()
        }
        launchCancellationActors(launches)
    }

    fun commitHandoff(): Boolean =
        completeOwnership(OwnershipCompletion.Handoff)

    fun completeFinite(): Boolean =
        completeOwnership(OwnershipCompletion.Finite)

    private fun completeOwnership(
        completion: OwnershipCompletion,
    ): Boolean {
        when (requestWorkerExit(completion)) {
            HandoffState.Committed -> return true
            HandoffState.Unavailable -> return false
            HandoffState.Pending -> Unit
        }
        val waitDecision = awaitIoActorExit()
        if (waitDecision != null) {
            return resolveHandoffDecision(waitDecision)
        }
        try {
            beforeOwnershipCommit()
        } catch (interrupted: InterruptedException) {
            abandon()
            Thread.currentThread().interrupt()
            throw InterruptedException(
                "Dovecot operation was interrupted",
            )
        } catch (failure: Throwable) {
            abandon()
            throw failure
        }

        val decision = lock.withLock {
            val alreadyCompleted = when (completion) {
                OwnershipCompletion.Handoff -> handoffCommitted
                OwnershipCompletion.Finite -> finiteCompleted
            }
            val conflictingCompletion = when (completion) {
                OwnershipCompletion.Handoff -> finiteCompleted
                OwnershipCompletion.Finite -> handoffCommitted
            }
            when {
                alreadyCompleted -> HandoffDecision.Committed
                abandoned ||
                    conflictingCompletion ||
                    releaseWithoutHandoff ->
                    HandoffDecision.Unavailable
                else -> {
                    val finalRemaining =
                        remainingNanos(deadlineNanos, nanoTime)
                    when {
                        Thread.currentThread().isInterrupted -> {
                            HandoffDecision.Interrupted(abandonLocked())
                        }
                        finalRemaining <= 0L -> {
                            HandoffDecision.Expired(abandonLocked())
                        }
                        else -> {
                            commitInProgress = false
                            when (completion) {
                                OwnershipCompletion.Handoff ->
                                    handoffCommitted = true
                                OwnershipCompletion.Finite ->
                                    finiteCompleted = true
                            }
                            maybeReleaseLocked()
                            HandoffDecision.Committed
                        }
                    }
                }
            }
        }
        return resolveHandoffDecision(decision)
    }

    private fun resolveHandoffDecision(
        decision: HandoffDecision,
    ): Boolean {
        when (decision) {
            HandoffDecision.Committed -> return true
            HandoffDecision.Unavailable -> return false
            is HandoffDecision.Expired -> {
                launchCancellationActors(decision.launches)
                return false
            }
            is HandoffDecision.Interrupted -> {
                launchCancellationActors(decision.launches)
                Thread.currentThread().interrupt()
                throw InterruptedException(
                    "Dovecot operation was interrupted",
                )
            }
        }
    }

    override fun close() {
        abandon()
    }

    fun awaitRelease(): Boolean {
        lock.withLock {
            while (!reservationReleased) {
                val remaining = remainingNanos(deadlineNanos, nanoTime)
                if (remaining <= 0L) return false
                try {
                    released.awaitNanos(remaining)
                } catch (interrupted: InterruptedException) {
                    Thread.currentThread().interrupt()
                    throw interrupted
                }
            }
            return true
        }
    }

    fun awaitReleaseWithin(maxWaitNanos: Long): Boolean {
        require(maxWaitNanos >= 0L) {
            "Dovecot cleanup wait must not be negative"
        }
        val startedAt = nanoTime()
        lock.withLock {
            while (!reservationReleased) {
                val operationRemaining =
                    remainingNanos(deadlineNanos, nanoTime)
                val elapsed = nanoTime() - startedAt
                val budgetRemaining =
                    if (elapsed >= maxWaitNanos) 0L else maxWaitNanos - elapsed
                val remaining = minOf(
                    operationRemaining,
                    budgetRemaining,
                )
                if (remaining <= 0L) return false
                try {
                    released.awaitNanos(remaining)
                } catch (interrupted: InterruptedException) {
                    Thread.currentThread().interrupt()
                    throw interrupted
                }
            }
            return true
        }
    }

    /**
     * Waits for an abandoned operation's actors and accounting to quiesce.
     *
     * Cancellation actions are best effort, so success is not transport
     * close/reap proof.
     */
    fun awaitAbandonedReleaseWithin(maxWaitNanos: Long): Boolean {
        require(maxWaitNanos > 0L) {
            "Dovecot cleanup wait must be positive"
        }
        lock.withLock {
            check(abandoned) {
                "Only an abandoned Dovecot operation may use a fresh " +
                    "cleanup wait"
            }
            var remaining = maxWaitNanos
            while (!reservationReleased) {
                if (remaining <= 0L) return false
                try {
                    remaining = released.awaitNanos(remaining)
                } catch (interrupted: InterruptedException) {
                    Thread.currentThread().interrupt()
                    throw interrupted
                }
            }
            return true
        }
    }

    internal fun isReleased(): Boolean =
        lock.withLock {
            reservationReleased
        }

    internal fun registerCancellationTarget(
        identity: Any,
        abort: () -> Unit,
        close: () -> Unit,
    ) {
        val launches = lock.withLock {
            check(Thread.currentThread() === ioActorThread) {
                "Only the Dovecot I/O worker may register cancellation targets"
            }
            check(!registrationSealed) {
                "Dovecot cancellation registration is sealed"
            }
            if (targets.any { target -> target.identity === identity }) {
                return
            }
            check(targets.size < MAX_TARGETS) {
                "Dovecot operation has too many cancellation targets"
            }
            targets += CancellationTarget(
                identity = identity,
                abort = abort,
                close = close,
            )
            cancellationLaunchesLocked()
        }
        launchCancellationActors(launches)
    }

    private fun submit(
        task: WorkerTask,
    ) {
        lock.withLock {
            while (pendingTask != null || inFlightTask != null) {
                val remaining = remainingNanos(deadlineNanos, nanoTime)
                if (remaining <= 0L) {
                    task.cancelBeforeRun()
                    throw DovecotBoundedOperationTimeoutException()
                }
                try {
                    workAvailable.awaitNanos(remaining)
                } catch (interrupted: InterruptedException) {
                    task.cancelBeforeRun()
                    throw interrupted
                }
            }
            if (
                abandoned ||
                finishRequested ||
                registrationSealed ||
                remainingNanos(deadlineNanos, nanoTime) <= 0L
            ) {
                task.cancelBeforeRun()
                throw DovecotBoundedOperationTimeoutException()
            }
            try {
                beforeTaskSubmission()
            } catch (failure: Throwable) {
                task.cancelBeforeRun()
                throw failure
            }
            pendingTask = task
            workAvailable.signalAll()
        }
    }

    private fun runWorker() {
        var restoreInterrupt = false
        lock.withLock {
            check(ioActorThread == null) {
                "Dovecot I/O worker was started more than once"
            }
            ioActorThread = Thread.currentThread()
        }
        try {
            while (true) {
                val task = lock.withLock {
                    while (
                        pendingTask == null &&
                        !finishRequested &&
                        !abandoned
                    ) {
                        workAvailable.await()
                    }
                    if (abandoned) {
                        pendingTask?.cancelBeforeRun()
                        pendingTask = null
                        return@withLock null
                    }
                    pendingTask?.also {
                        pendingTask = null
                        inFlightTask = it
                    }
                } ?: break

                try {
                    task.run()
                } finally {
                    if (Thread.interrupted()) {
                        restoreInterrupt = true
                    }
                    lock.withLock {
                        inFlightTask = null
                        workAvailable.signalAll()
                    }
                }
            }
        } catch (_: InterruptedException) {
            restoreInterrupt = true
        } finally {
            if (Thread.interrupted()) {
                restoreInterrupt = true
            }
            finishIoActor()
            if (restoreInterrupt) {
                Thread.currentThread().interrupt()
            }
        }
    }

    private fun failIoActorStart() {
        lock.withLock {
            if (ioActorExited) return
            registrationSealed = true
            ioActorExited = true
            releaseWithoutHandoff = true
            if (ioActorCharged) {
                ioActorCharged = false
                owner.finishActor()
            }
            maybeReleaseLocked()
        }
    }

    private fun finishIoActor() {
        lock.withLock {
            pendingTask?.cancelBeforeRun()
            pendingTask = null
            registrationSealed = true
            ioActorExited = true
            if (ioActorCharged) {
                ioActorCharged = false
                owner.finishActor()
            }
            workAvailable.signalAll()
            maybeReleaseLocked()
        }
    }

    private fun requestWorkerExit(
        completion: OwnershipCompletion,
    ): HandoffState = lock.withLock {
        val alreadyCompleted = when (completion) {
            OwnershipCompletion.Handoff -> handoffCommitted
            OwnershipCompletion.Finite -> finiteCompleted
        }
        val conflictingCompletion = when (completion) {
            OwnershipCompletion.Handoff -> finiteCompleted
            OwnershipCompletion.Finite -> handoffCommitted
        }
        when {
            alreadyCompleted -> HandoffState.Committed
            abandoned ||
                conflictingCompletion ||
                releaseWithoutHandoff ||
                reservationReleased ->
                HandoffState.Unavailable
            else -> {
                check(!commitInProgress) {
                    when (completion) {
                        OwnershipCompletion.Handoff ->
                            "Dovecot operation handoff is already being committed"
                        OwnershipCompletion.Finite ->
                            "Dovecot finite operation completion is already in progress"
                    }
                }
                commitInProgress = true
                finishRequested = true
                workAvailable.signalAll()
                HandoffState.Pending
            }
        }
    }

    private fun awaitIoActorExit(): HandoffDecision? = lock.withLock {
        while (!ioActorExited) {
            val remaining = remainingNanos(deadlineNanos, nanoTime)
            if (remaining <= 0L) {
                return@withLock HandoffDecision.Expired(abandonLocked())
            }
            try {
                workAvailable.awaitNanos(remaining)
            } catch (interrupted: InterruptedException) {
                val launches = abandonLocked()
                Thread.currentThread().interrupt()
                return@withLock HandoffDecision.Interrupted(launches)
            }
        }
        null
    }

    private fun abandonLocked(): List<CancellationLaunch> {
        if (
            !abandoned &&
            !handoffCommitted &&
            !finiteCompleted &&
            !releaseWithoutHandoff &&
            !reservationReleased
        ) {
            commitInProgress = false
            abandoned = true
            finishRequested = true
            owner.markAbandoned()
            pendingTask?.cancelBeforeRun()
            pendingTask = null
            inFlightTask?.decline()
            workAvailable.signalAll()
        }
        val launches = cancellationLaunchesLocked()
        maybeReleaseLocked()
        return launches
    }

    private fun cancellationLaunchesLocked(): List<CancellationLaunch> {
        if (!abandoned) return emptyList()
        val launches = ArrayList<CancellationLaunch>(MAX_CANCELLATION_ACTORS)
        targets.forEach { target ->
            if (!target.abortStarted) {
                target.abortStarted = true
                launches += chargeCancellationActorLocked(
                    DovecotBoundedActorRole.Abort,
                    "abort",
                    target.abort,
                )
            }
            if (!target.closeStarted) {
                target.closeStarted = true
                launches += chargeCancellationActorLocked(
                    DovecotBoundedActorRole.Close,
                    "close",
                    target.close,
                )
            }
        }
        return launches
    }

    private fun chargeCancellationActorLocked(
        role: DovecotBoundedActorRole,
        suffix: String,
        action: () -> Unit,
    ): CancellationLaunch {
        cancellationActors += 1
        owner.chargeActor()
        return CancellationLaunch(
            role = role,
            name = actorName(suffix),
            action = action,
        )
    }

    private fun launchCancellationActors(
        launches: List<CancellationLaunch>,
    ) {
        launches.forEach { launch ->
            try {
                actorLauncher.start(
                    launch.role,
                    launch.name,
                    Runnable {
                        try {
                            launch.action()
                        } catch (_: Throwable) {
                            // Cancellation is best effort and accounting is mandatory.
                        } finally {
                            finishCancellationActor()
                        }
                    },
                )
            } catch (_: Throwable) {
                finishCancellationActor()
            }
        }
    }

    private fun finishCancellationActor() {
        lock.withLock {
            check(cancellationActors > 0) {
                "Dovecot cancellation actor accounting underflow"
            }
            cancellationActors -= 1
            owner.finishActor()
            maybeReleaseLocked()
        }
    }

    private fun maybeReleaseLocked() {
        if (
            reservationReleased ||
            !registrationSealed ||
            !ioActorExited ||
            cancellationActors != 0 ||
            (
                !abandoned &&
                    !handoffCommitted &&
                    !finiteCompleted &&
                    !releaseWithoutHandoff
                )
        ) {
            return
        }
        reservationReleased = true
        owner.release(abandoned)
        released.signalAll()
    }

    private data class CancellationTarget(
        val identity: Any,
        val abort: () -> Unit,
        val close: () -> Unit,
        var abortStarted: Boolean = false,
        var closeStarted: Boolean = false,
    )

    private data class CancellationLaunch(
        val role: DovecotBoundedActorRole,
        val name: String,
        val action: () -> Unit,
    )

    private enum class HandoffState {
        Pending,
        Committed,
        Unavailable,
    }

    private enum class OwnershipCompletion {
        Finite,
        Handoff,
    }

    private sealed interface HandoffDecision {
        data object Committed : HandoffDecision

        data object Unavailable : HandoffDecision

        data class Expired(
            val launches: List<CancellationLaunch>,
        ) : HandoffDecision

        data class Interrupted(
            val launches: List<CancellationLaunch>,
        ) : HandoffDecision
    }

    private companion object {
        private const val MAX_TARGETS = 2
        private const val MAX_CANCELLATION_ACTORS = MAX_TARGETS * 2
        private val ACTOR_SEQUENCE = AtomicInteger()

        private fun actorName(suffix: String): String =
            "dovecot-bounded-operation-$suffix-" +
                ACTOR_SEQUENCE.incrementAndGet()
    }
}

internal class DovecotBoundedOperationContext internal constructor(
    private val operation: DovecotBoundedOperation,
) {
    fun registerCancellationTarget(
        identity: Any,
        abort: () -> Unit,
        close: () -> Unit,
    ) {
        operation.registerCancellationTarget(identity, abort, close)
    }
}

private interface WorkerTask {
    fun run()

    fun decline()

    fun cancelBeforeRun()
}

private class OperationTask<T>(
    private val deadlineNanos: Long,
    private val disposeLate: (T) -> Unit,
    private val disposeBeforeRun: () -> Unit = {},
    private val beforeClaim: () -> Unit,
    private val afterDispositionInterrupt: () -> Unit,
    private val nanoTime: () -> Long,
    private val block: () -> T,
) : WorkerTask {
    private val state = AtomicReference(TaskState.Pending)
    private val runStarted = AtomicBoolean()
    private val beforeRunDisposed = AtomicBoolean()
    private val completed = CountDownLatch(1)
    private val disposition = CountDownLatch(1)
    private var result: T? = null
    private var failure: Throwable? = null

    override fun run() {
        runStarted.set(true)
        if (!state.compareAndSet(TaskState.Pending, TaskState.Running)) {
            runStarted.set(false)
            disposeBeforeRunIfNeeded()
            return
        }
        try {
            val completedResult = block()
            result = completedResult
            if (state.compareAndSet(TaskState.Running, TaskState.Result)) {
                completed.countDown()
                awaitDisposition()
            } else {
                dispose(completedResult)
            }
        } catch (caught: Throwable) {
            failure = caught
            if (state.compareAndSet(TaskState.Running, TaskState.Failure)) {
                completed.countDown()
                awaitDisposition()
            }
        }
    }

    fun await(): T {
        val remaining = remainingNanos(deadlineNanos, nanoTime)
        if (
            remaining <= 0L ||
            !completed.await(remaining, TimeUnit.NANOSECONDS)
        ) {
            decline()
            throw DovecotBoundedOperationTimeoutException()
        }
        while (true) {
            when (state.get()) {
                TaskState.Result -> {
                    if (remainingNanos(deadlineNanos, nanoTime) <= 0L) {
                        decline()
                        throw DovecotBoundedOperationTimeoutException()
                    }
                    beforeClaim()
                    if (
                        state.compareAndSet(
                            TaskState.Result,
                            TaskState.Claimed,
                        )
                    ) {
                        @Suppress("UNCHECKED_CAST")
                        return claimedResult(result as T)
                    }
                }
                TaskState.Failure -> {
                    if (remainingNanos(deadlineNanos, nanoTime) <= 0L) {
                        decline()
                        throw DovecotBoundedOperationTimeoutException()
                    }
                    beforeClaim()
                    if (
                        state.compareAndSet(
                            TaskState.Failure,
                            TaskState.Claimed,
                        )
                    ) {
                        claimedFailure(checkNotNull(failure))
                    }
                }
                TaskState.Declined,
                TaskState.Disposed,
                -> throw DovecotBoundedOperationTimeoutException()
                TaskState.Pending,
                TaskState.Running,
                TaskState.Claimed,
                -> error("Dovecot operation task entered an invalid state")
            }
        }
    }

    override fun decline() {
        while (true) {
            when (val current = state.get()) {
                TaskState.Pending,
                TaskState.Running,
                TaskState.Result,
                TaskState.Failure,
                -> if (
                    state.compareAndSet(current, TaskState.Declined)
                ) {
                    completed.countDown()
                    disposition.countDown()
                    return
                }
                TaskState.Claimed,
                TaskState.Declined,
                TaskState.Disposed,
                -> return
            }
        }
    }

    override fun cancelBeforeRun() {
        if (state.compareAndSet(TaskState.Pending, TaskState.Declined)) {
            completed.countDown()
            disposition.countDown()
            disposeBeforeRunIfNeeded()
            return
        }
        decline()
        disposeBeforeRunIfNeeded()
    }

    private fun awaitDisposition() {
        var restoreInterrupt = false
        try {
            while (true) {
                val remaining = remainingNanos(deadlineNanos, nanoTime)
                if (remaining <= 0L) {
                    decline()
                    break
                }
                try {
                    if (disposition.await(remaining, TimeUnit.NANOSECONDS)) {
                        break
                    }
                    decline()
                    break
                } catch (_: InterruptedException) {
                    restoreInterrupt = true
                    afterDispositionInterrupt()
                }
            }
        } finally {
            if (restoreInterrupt) {
                Thread.currentThread().interrupt()
            }
        }
        if (
            state.get() == TaskState.Declined &&
            failure == null
        ) {
            @Suppress("UNCHECKED_CAST")
            dispose(result as T)
            state.compareAndSet(TaskState.Declined, TaskState.Disposed)
        }
    }

    private fun claimedResult(value: T): T {
        var handedOff = false
        try {
            if (remainingNanos(deadlineNanos, nanoTime) <= 0L) {
                throw DovecotBoundedOperationTimeoutException()
            }
            handedOff = true
            return value
        } finally {
            if (!handedOff) {
                dispose(value)
            }
            disposition.countDown()
        }
    }

    private fun claimedFailure(caught: Throwable): Nothing {
        try {
            val expired =
                remainingNanos(deadlineNanos, nanoTime) <= 0L
            if (caught is InterruptedException) {
                throw caught
            }
            if (expired) {
                throw DovecotBoundedOperationTimeoutException()
            }
            throw caught
        } finally {
            disposition.countDown()
        }
    }

    private fun dispose(value: T) {
        try {
            disposeLate(value)
        } catch (_: Throwable) {
            // Disposal must not strand worker or reservation accounting.
        }
    }

    private fun disposeBeforeRunIfNeeded() {
        if (
            !runStarted.get() &&
            beforeRunDisposed.compareAndSet(false, true)
        ) {
            try {
                disposeBeforeRun()
            } catch (_: Throwable) {
                // Rejected task disposal must not strand accounting.
            }
        }
    }

    private enum class TaskState {
        Pending,
        Running,
        Result,
        Failure,
        Claimed,
        Declined,
        Disposed,
    }
}

private fun deadlineExpired(
    deadlineNanos: Long,
    nanoTime: () -> Long,
): Boolean = nanoTime() - deadlineNanos >= 0L

private fun remainingNanos(
    deadlineNanos: Long,
    nanoTime: () -> Long = System::nanoTime,
): Long {
    val now = nanoTime()
    return if (now - deadlineNanos >= 0L) {
        0L
    } else {
        deadlineNanos - now
    }
}
