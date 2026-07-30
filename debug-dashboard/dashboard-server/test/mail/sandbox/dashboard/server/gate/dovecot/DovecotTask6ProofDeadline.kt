package mail.sandbox.dashboard.server.gate.dovecot

import java.time.Duration
import java.util.concurrent.atomic.AtomicReference

internal class DovecotTask6ProofDeadline(
    timeout: Duration,
    private val onDeadline: () -> Unit,
) : AutoCloseable {
    private val timeoutNanos = timeout.requirePositiveNanos()
    val deadlineNanos: Long = try {
        Math.addExact(
            System.nanoTime(),
            timeoutNanos,
        )
    } catch (failure: ArithmeticException) {
        throw IllegalArgumentException(
            "Dovecot proof timeout was out of bounds",
            failure,
        )
    }
    private val state = AtomicReference(State.Active)

    init {
        requireCallerNotInterrupted()
    }

    fun remainingNanos(): Long {
        requireCallerNotInterrupted()
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
        requireCallerNotInterrupted()
        expire()
        error("Dovecot proof operation exceeded its deadline")
    }

    fun complete() {
        requireRemaining()
        check(state.compareAndSet(State.Active, State.Completed)) {
            "Dovecot proof operation exceeded its deadline"
        }
    }

    override fun close() {
        state.compareAndSet(State.Active, State.Completed)
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

    private fun requireCallerNotInterrupted() {
        if (Thread.currentThread().isInterrupted) {
            throw InterruptedException(
                "Dovecot proof operation was interrupted",
            )
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

}
