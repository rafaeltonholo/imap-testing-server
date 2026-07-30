package mail.sandbox.dashboard.server.gate.dovecot

import java.time.Duration
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

internal class DovecotTask6ProofDeadline(
    timeout: Duration,
    private val onDeadline: () -> Unit,
) : AutoCloseable {
    private val timeoutNanos = timeout.requirePositiveNanos()
    private val deadlineNanos = Math.addExact(
        System.nanoTime(),
        timeoutNanos,
    )
    private val state = AtomicReference(State.Active)
    private val watchdog: ScheduledFuture<*> = WATCHDOG.schedule(
        ::expire,
        timeoutNanos,
        TimeUnit.NANOSECONDS,
    )

    fun remainingNanos(): Long {
        if (state.get() != State.Active) {
            error("Dovecot proof operation exceeded its deadline")
        }
        val remaining = deadlineNanos - System.nanoTime()
        if (remaining <= 0L) {
            expire()
            error("Dovecot proof operation exceeded its deadline")
        }
        return remaining
    }

    fun requireRemaining() {
        remainingNanos()
    }

    fun expireNow(): Nothing {
        expire()
        error("Dovecot proof operation exceeded its deadline")
    }

    fun complete() {
        requireRemaining()
        check(state.compareAndSet(State.Active, State.Completed)) {
            "Dovecot proof operation exceeded its deadline"
        }
        watchdog.cancel(false)
    }

    override fun close() {
        state.compareAndSet(State.Active, State.Completed)
        watchdog.cancel(false)
    }

    private fun expire() {
        if (state.compareAndSet(State.Active, State.Expired)) {
            try {
                onDeadline()
            } catch (_: Throwable) {
                // A proof deadline must remain fail-closed if abort also fails.
            }
        }
    }

    private enum class State {
        Active,
        Completed,
        Expired,
    }

    private fun Duration.requirePositiveNanos(): Long {
        val nanos = try {
            toNanos()
        } catch (failure: ArithmeticException) {
            throw IllegalArgumentException(
                "Dovecot proof timeout was out of bounds",
                failure,
            )
        }
        require(nanos > 0L) {
            "Dovecot proof timeout must be positive"
        }
        return nanos
    }

    companion object {
        private val WATCHDOG = Executors.newSingleThreadScheduledExecutor {
            runnable ->
            Thread(runnable, "dovecot-task6-proof-watchdog").also {
                it.isDaemon = true
            }
        }
    }
}
