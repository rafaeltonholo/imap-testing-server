package mail.sandbox.dashboard.server.gate.dovecot

import java.util.concurrent.ExecutionException
import java.util.concurrent.Future
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicInteger

internal class DovecotOperatorLeaseCloseSession(
    maximumWorkers: Int,
) : AutoCloseable {
    private val executor = ThreadPoolExecutor(
        0,
        maximumWorkers,
        1,
        TimeUnit.SECONDS,
        SynchronousQueue(),
        { runnable ->
            Thread(
                runnable,
                "dovecot-operator-lease-close-" +
                    THREAD_SEQUENCE.incrementAndGet(),
            ).also { thread ->
                thread.isDaemon = true
            }
        },
        ThreadPoolExecutor.AbortPolicy(),
    )

    fun closeAll(
        leases: List<DovecotOperatorApplicationLease>,
        deadlineNanos: Long,
    ): Throwable? {
        if (leases.isEmpty()) return null
        val futures = mutableListOf<Future<*>>()
        var primaryFailure: Throwable? = null
        for (lease in leases) {
            try {
                futures += executor.submit(lease::close)
            } catch (failure: Throwable) {
                primaryFailure = combineCloseFailures(primaryFailure, failure)
                break
            }
        }
        for (future in futures) {
            val remaining = deadlineNanos - System.nanoTime()
            if (remaining <= 0L) {
                primaryFailure = combineCloseFailures(
                    primaryFailure,
                    drainTimeoutFailure(),
                )
                break
            }
            try {
                future.get(remaining, TimeUnit.NANOSECONDS)
            } catch (failure: ExecutionException) {
                primaryFailure = combineCloseFailures(
                    primaryFailure,
                    failure.cause ?: failure,
                )
            } catch (_: TimeoutException) {
                primaryFailure = combineCloseFailures(
                    primaryFailure,
                    drainTimeoutFailure(),
                )
                break
            } catch (failure: InterruptedException) {
                Thread.currentThread().interrupt()
                primaryFailure = combineCloseFailures(
                    primaryFailure,
                    failure,
                )
                break
            } catch (failure: Throwable) {
                primaryFailure = combineCloseFailures(
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
        return primaryFailure
    }

    override fun close() {
        executor.shutdownNow()
    }

    companion object {
        private val THREAD_SEQUENCE = AtomicInteger()
    }
}

internal fun drainTimeoutFailure(): IllegalStateException =
    IllegalStateException(
        "Dovecot operator application session drain timed out",
    )

private fun combineCloseFailures(
    primary: Throwable?,
    next: Throwable,
): Throwable {
    if (primary == null) return next
    if (primary !== next) {
        primary.addSuppressed(next)
    }
    return primary
}
