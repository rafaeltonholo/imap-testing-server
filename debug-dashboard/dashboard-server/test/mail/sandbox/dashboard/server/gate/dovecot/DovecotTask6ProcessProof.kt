package mail.sandbox.dashboard.server.gate.dovecot

import java.nio.file.Files
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.TimeUnit

internal class Task6FixedProcessRunner(
    private val dockerRouting: DovecotDockerRouting,
    private val isApprovedCommand: (List<String>) -> Boolean,
    private val processFactory: ((EligibilityProcessRequest) -> Process)? = null,
    private val captureFactory: (Int) -> EligibilityProcessOutputCapture = {
        EligibilityProcessOutputCapture(it)
    },
) : EligibilityProcessRunner {
    override fun run(
        request: EligibilityProcessRequest,
    ): EligibilityProcessResult {
        require(isApprovedCommand(request.argv)) {
            "Task 6 process command is not approved"
        }
        require(
            request.workingDirectory.isAbsolute &&
                request.workingDirectory.normalize() ==
                request.workingDirectory &&
                Files.isRegularFile(
                    request.workingDirectory.resolve("docker-compose.yml"),
                ),
        ) {
            "Task 6 process working directory is invalid"
        }
        require(
            !request.timeout.isNegative &&
                !request.timeout.isZero &&
                request.stdin.size <= MAX_STDIN_BYTES &&
                request.maximumOutputBytes in 1..MAX_OUTPUT_BYTES,
        ) {
            "Task 6 process bounds are invalid"
        }

        var process: Process? = null
        var workers: ExecutorService? = null
        var stdoutCapture: EligibilityProcessOutputCapture? = null
        var stderrCapture: EligibilityProcessOutputCapture? = null
        var stdinFuture: Future<*>? = null
        var stdoutFuture: Future<*>? = null
        var stderrFuture: Future<*>? = null
        var stdout = ByteArray(0)
        var stderr = ByteArray(0)
        var interrupted = false
        return try {
            val started = processFactory?.invoke(request) ?:
                ProcessBuilder(request.argv)
                    .directory(request.workingDirectory.toFile())
                    .also { builder ->
                        dockerRouting.applyTo(builder.environment())
                    }
                    .start()
            process = started
            val ownedStdoutCapture =
                captureFactory(request.maximumOutputBytes)
            stdoutCapture = ownedStdoutCapture
            val ownedStderrCapture =
                captureFactory(request.maximumOutputBytes)
            stderrCapture = ownedStderrCapture
            val ownedWorkers = Executors.newFixedThreadPool(3) { runnable ->
                Thread(runnable, "task6-fixed-process-io").also {
                    it.isDaemon = true
                }
            }
            workers = ownedWorkers
            stdoutFuture = submitGuarded(ownedWorkers, started) {
                ownedStdoutCapture.readFrom(started.inputStream)
            }
            stderrFuture = submitGuarded(ownedWorkers, started) {
                ownedStderrCapture.readFrom(started.errorStream)
            }
            stdinFuture = submitGuarded(ownedWorkers, started) {
                started.outputStream.use { output ->
                    output.write(request.stdin)
                    output.flush()
                }
            }

            val completed = started.waitFor(
                request.timeout.toMillis(),
                TimeUnit.MILLISECONDS,
            )
            if (!completed) {
                terminateAndReap(started) {
                    interrupted = true
                }
                return EligibilityProcessResult(
                    exitCode = null,
                    timedOut = true,
                    stdout = ByteArray(0),
                    stderr = ByteArray(0),
                )
            }
            stdinFuture.get(
                IO_JOIN_TIMEOUT_SECONDS,
                TimeUnit.SECONDS,
            )
            stdoutFuture.get(
                IO_JOIN_TIMEOUT_SECONDS,
                TimeUnit.SECONDS,
            )
            stderrFuture.get(
                IO_JOIN_TIMEOUT_SECONDS,
                TimeUnit.SECONDS,
            )
            stdout = ownedStdoutCapture.snapshot()
            stderr = ownedStderrCapture.snapshot()
            EligibilityProcessResult(
                exitCode = started.exitValue(),
                timedOut = false,
                stdout = stdout,
                stderr = stderr,
            )
        } catch (failure: Exception) {
            stdout.fill(0)
            stderr.fill(0)
            if (failure is InterruptedException) {
                interrupted = true
            }
            throw IllegalStateException("Task 6 fixed process failed")
        } finally {
            stdoutCapture?.close()
            stderrCapture?.close()
            var cleanupFailure: Throwable? = null
            process?.let { started ->
                try {
                    terminateAndReap(started) {
                        interrupted = true
                    }
                } catch (failure: Throwable) {
                    cleanupFailure = failure
                }
            }
            stdinFuture?.cancel(true)
            stdoutFuture?.cancel(true)
            stderrFuture?.cancel(true)
            workers?.shutdownNow()
            val workersStopped = try {
                workers?.let { executor ->
                    awaitTermination(
                        executor,
                        IO_JOIN_TIMEOUT_SECONDS,
                    ) {
                        interrupted = true
                    }
                } ?: true
            } catch (failure: Throwable) {
                if (cleanupFailure == null) {
                    cleanupFailure = failure
                }
                false
            }
            if (!workersStopped && cleanupFailure == null) {
                cleanupFailure =
                    IllegalStateException(
                        "Task 6 fixed process workers did not stop",
                    )
            }
            if (interrupted) {
                Thread.currentThread().interrupt()
            }
            if (cleanupFailure != null) {
                throw IllegalStateException(
                    "Task 6 fixed process cleanup failed",
                )
            }
        }
    }

    private fun awaitTermination(
        workers: ExecutorService,
        timeoutSeconds: Long,
        onInterrupted: () -> Unit,
    ): Boolean {
        val deadline =
            System.nanoTime() +
                TimeUnit.SECONDS.toNanos(timeoutSeconds)
        while (true) {
            val remaining = deadline - System.nanoTime()
            if (remaining <= 0L) return workers.isTerminated
            try {
                return workers.awaitTermination(
                    remaining,
                    TimeUnit.NANOSECONDS,
                )
            } catch (_: InterruptedException) {
                onInterrupted()
            }
        }
    }

    private fun submitGuarded(
        workers: ExecutorService,
        process: Process,
        operation: () -> Unit,
    ): Future<*> = workers.submit {
        try {
            operation()
        } catch (failure: Throwable) {
            runCatching {
                if (process.isAlive) process.destroyForcibly()
            }
            throw failure
        }
    }

    private fun terminateAndReap(
        process: Process,
        onInterrupted: () -> Unit,
    ) {
        if (process.isAlive) {
            process.destroyForcibly()
        }
        closeProcessStreams(process)
        val deadline =
            System.nanoTime() +
                TimeUnit.SECONDS.toNanos(
                    IO_JOIN_TIMEOUT_SECONDS,
                )
        var reaped = false
        while (!reaped) {
            val remaining = deadline - System.nanoTime()
            if (remaining <= 0L) break
            try {
                reaped = process.waitFor(
                    remaining,
                    TimeUnit.NANOSECONDS,
                )
            } catch (_: InterruptedException) {
                onInterrupted()
            }
        }
        check(reaped && !process.isAlive) {
            "Task 6 fixed process could not be reaped"
        }
        closeProcessStreams(process)
    }

    private fun closeProcessStreams(process: Process) {
        runCatching { process.outputStream.close() }
        runCatching { process.inputStream.close() }
        runCatching { process.errorStream.close() }
    }

    companion object {
        private const val MAX_STDIN_BYTES = 1024
        private const val MAX_OUTPUT_BYTES = 64 * 1024
        private const val IO_JOIN_TIMEOUT_SECONDS = 2L
    }
}
