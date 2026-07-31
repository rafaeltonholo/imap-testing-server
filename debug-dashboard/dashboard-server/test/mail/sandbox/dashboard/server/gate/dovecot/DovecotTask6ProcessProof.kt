package mail.sandbox.dashboard.server.gate.dovecot

import java.nio.file.Files
import java.time.Duration
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.TimeUnit

internal fun interface DovecotTask6ProcessInventory {
    fun count(): Int
}

internal enum class DovecotTask6FiniteProcessCase {
    NormalClose,
    AuthenticationFailure,
    RegistrationFailure,
    Timeout,
    Interruption,
    Abort,
}

internal interface DovecotTask6ProcessScenarios {
    fun runFinite(case: DovecotTask6FiniteProcessCase)

    fun withHeldProcess(assertExactlyOne: () -> Unit)

    fun withSaturatedProcesses(
        assertExactlySixteen: () -> Unit,
        assertNoSeventeenthStarted: () -> Unit,
    )
}

internal class DovecotTask6ProcessProof(
    private val inventory: DovecotTask6ProcessInventory,
) {
    fun run(scenarios: DovecotTask6ProcessScenarios) {
        DovecotTask6FiniteProcessCase.entries.forEach { case ->
            withZeroInventory {
                scenarios.runFinite(case)
            }
        }
        withZeroInventory {
            scenarios.withHeldProcess {
                requireExactCount(1)
            }
        }
        withZeroInventory {
            scenarios.withSaturatedProcesses(
                assertExactlySixteen = {
                    requireExactCount(16)
                },
                assertNoSeventeenthStarted = {
                    requireExactCount(16)
                },
            )
        }
    }

    override fun toString(): String =
        "DovecotTask6ProcessProof(fixed, redacted)"

    private fun withZeroInventory(action: () -> Unit) {
        requireExactCount(0)
        var primaryFailure: Throwable? = null
        try {
            action()
        } catch (failure: Throwable) {
            primaryFailure = failure
        }
        val inventoryFailure = try {
            requireExactCount(0)
            null
        } catch (failure: Throwable) {
            failure
        }
        if (primaryFailure != null) {
            if (
                inventoryFailure != null &&
                inventoryFailure !== primaryFailure
            ) {
                primaryFailure.addSuppressed(inventoryFailure)
            }
            throw primaryFailure
        }
        if (inventoryFailure != null) {
            throw inventoryFailure
        }
    }

    private fun requireExactCount(expected: Int) {
        check(inventory.count() == expected) {
            PROCESS_COUNT_FAILURE
        }
    }

    private companion object {
        const val PROCESS_COUNT_FAILURE =
            "Dovecot Task 6 operator process inventory was not exact"
    }
}

internal class Task6LaunchProfileEligibilityAdapter(
    private val profile: DovecotOperatorLaunchProfile,
    processRunner: EligibilityProcessRunner? = null,
) : EligibilityPasswordHasher, DovecotOperatorHashVerifier {
    private val processRunner =
        processRunner ?: Task6FixedProcessRunner(
            profile = profile,
            isApprovedCommand = { command ->
                isApprovedCanonicalEligibilityCommand(
                    profile = profile,
                    command = command,
                )
            },
        )

    override fun hash(password: EligibilityPassword): String {
        var input = ByteArray(0)
        var result: EligibilityProcessResult? = null
        var normalized = ByteArray(0)
        try {
            input = password.withBytes(::twiceOverStdin)
            result = runFixed(
                suffix = CANONICAL_ELIGIBILITY_HASH_SUFFIX,
                stdin = input,
            )
            check(
                !result.timedOut &&
                    result.exitCode == 0 &&
                    result.stderr.isEmpty(),
            ) {
                ELIGIBILITY_HASH_FAILURE
            }
            normalized = stripOneTerminalNewline(result.stdout)
            check(
                normalized.isNotEmpty() &&
                    normalized.all { byte ->
                        byte.toInt() in 0x21..0x7e
                    },
            ) {
                ELIGIBILITY_HASH_FAILURE
            }
            val rendered =
                String(normalized, java.nio.charset.StandardCharsets.US_ASCII)
            EligibilityEntry.requireValidHash(rendered)
            return rendered
        } catch (failure: Exception) {
            if (failure is InterruptedException) {
                Thread.currentThread().interrupt()
            }
            throw IllegalStateException(ELIGIBILITY_HASH_FAILURE)
        } finally {
            input.fill(0)
            normalized.fill(0)
            result?.stdout?.fill(0)
            result?.stderr?.fill(0)
        }
    }

    override fun verify(
        secret: DovecotOperatorSecret,
        providerHash: String,
    ): Boolean {
        require(validEligibilityHash(providerHash)) {
            ELIGIBILITY_PROVIDER_HASH_FAILURE
        }
        var input = ByteArray(0)
        var result: EligibilityProcessResult? = null
        var expectedSuccess = ByteArray(0)
        var expectedMismatch = ByteArray(0)
        try {
            input = secret.withBytes(::onceOverStdin)
            result = runFixed(
                suffix =
                    CANONICAL_ELIGIBILITY_VERIFY_PREFIX +
                        providerHash,
                stdin = input,
            )
            expectedSuccess =
                "$providerHash (verified)\n".toByteArray(
                    java.nio.charset.StandardCharsets.US_ASCII,
                )
            expectedMismatch =
                ELIGIBILITY_MISMATCH_STDERR.toByteArray(
                    java.nio.charset.StandardCharsets.US_ASCII,
                )
            return when {
                !result.timedOut &&
                    result.exitCode == 0 &&
                    result.stdout.contentEquals(expectedSuccess) &&
                    result.stderr.isEmpty() -> true
                !result.timedOut &&
                    result.exitCode == ELIGIBILITY_MISMATCH_EXIT_CODE &&
                    result.stdout.isEmpty() &&
                    result.stderr.contentEquals(expectedMismatch) -> false
                else -> throw IllegalStateException(
                    ELIGIBILITY_VERIFY_FAILURE,
                )
            }
        } catch (failure: Exception) {
            if (failure is InterruptedException) {
                Thread.currentThread().interrupt()
            }
            throw IllegalStateException(ELIGIBILITY_VERIFY_FAILURE)
        } finally {
            input.fill(0)
            expectedSuccess.fill(0)
            expectedMismatch.fill(0)
            result?.stdout?.fill(0)
            result?.stderr?.fill(0)
        }
    }

    override fun toString(): String =
        "Task6LaunchProfileEligibilityAdapter(fixed, redacted)"

    private fun runFixed(
        suffix: List<String>,
        stdin: ByteArray,
    ): EligibilityProcessResult =
        processRunner.run(
            EligibilityProcessRequest(
                argv =
                    canonicalEligibilityComposePrefix(profile) +
                        suffix,
                workingDirectory = profile.repositoryRoot,
                stdin = stdin,
                timeout = ELIGIBILITY_PROCESS_TIMEOUT,
                maximumOutputBytes = ELIGIBILITY_MAXIMUM_OUTPUT_BYTES,
            ),
        )

    private fun twiceOverStdin(password: ByteArray): ByteArray {
        require(
            password.isNotEmpty() &&
                password.size <= ELIGIBILITY_MAXIMUM_PASSWORD_BYTES &&
                password.all { byte ->
                    byte != 0.toByte() &&
                        byte != '\n'.code.toByte() &&
                        byte != '\r'.code.toByte()
                },
        ) {
            ELIGIBILITY_HASH_FAILURE
        }
        val input = ByteArray(
            Math.addExact(
                Math.multiplyExact(password.size, 2),
                2,
            ),
        )
        password.copyInto(input)
        input[password.size] = '\n'.code.toByte()
        password.copyInto(
            input,
            destinationOffset = password.size + 1,
        )
        input[input.lastIndex] = '\n'.code.toByte()
        return input
    }

    private fun onceOverStdin(secret: ByteArray): ByteArray {
        DovecotOperatorSecret.requireValid(secret)
        return ByteArray(secret.size + 1).also { input ->
            secret.copyInto(input)
            input[input.lastIndex] = '\n'.code.toByte()
        }
    }

    private fun stripOneTerminalNewline(output: ByteArray): ByteArray {
        var length = output.size
        if (length > 0 && output[length - 1] == '\n'.code.toByte()) {
            length -= 1
            if (
                length > 0 &&
                output[length - 1] == '\r'.code.toByte()
            ) {
                length -= 1
            }
        }
        return output.copyOf(length)
    }
}

private fun canonicalEligibilityComposePrefix(
    profile: DovecotOperatorLaunchProfile,
): List<String> =
    buildList {
        add(profile.dockerCli.toString())
        add("compose")
        add("--project-directory")
        add(profile.repositoryRoot.toString())
        profile.composeFiles.forEach { composeFile ->
            add("-f")
            add(composeFile.toString())
        }
        add("--project-name")
        add(profile.projectName)
        add("--profile")
        add(profile.composeProfile)
        add("exec")
        add("-T")
        add("--index")
        add("1")
        add("dovecot")
    }

private fun isApprovedCanonicalEligibilityCommand(
    profile: DovecotOperatorLaunchProfile,
    command: List<String>,
): Boolean {
    val prefix = canonicalEligibilityComposePrefix(profile)
    if (command == prefix + CANONICAL_ELIGIBILITY_HASH_SUFFIX) {
        return true
    }
    return command.size ==
        prefix.size + CANONICAL_ELIGIBILITY_VERIFY_PREFIX.size + 1 &&
        command.take(prefix.size) == prefix &&
        command.drop(prefix.size).take(
            CANONICAL_ELIGIBILITY_VERIFY_PREFIX.size,
        ) == CANONICAL_ELIGIBILITY_VERIFY_PREFIX &&
        validEligibilityHash(command.last())
}

private fun validEligibilityHash(candidate: String): Boolean =
    runCatching {
        EligibilityEntry.requireValidHash(candidate)
    }.isSuccess

private val CANONICAL_ELIGIBILITY_HASH_SUFFIX = listOf(
    "doveadm",
    "pw",
    "-s",
    "ARGON2ID",
)
private val CANONICAL_ELIGIBILITY_VERIFY_PREFIX = listOf(
    "doveadm",
    "pw",
    "-t",
)
private val ELIGIBILITY_PROCESS_TIMEOUT = Duration.ofSeconds(30)
private const val ELIGIBILITY_MAXIMUM_OUTPUT_BYTES = 16 * 1024
private const val ELIGIBILITY_MAXIMUM_PASSWORD_BYTES = 511
private const val ELIGIBILITY_MISMATCH_EXIT_CODE = 75
private const val ELIGIBILITY_MISMATCH_STDERR =
    "Fatal: reverse password verification check failed: Password mismatch\n"
private const val ELIGIBILITY_HASH_FAILURE =
    "Task 6 eligibility password hashing failed"
private const val ELIGIBILITY_VERIFY_FAILURE =
    "Task 6 eligibility password verification failed"
private const val ELIGIBILITY_PROVIDER_HASH_FAILURE =
    "Task 6 eligibility provider hash is invalid"

internal class Task6FixedProcessRunner(
    private val profile: DovecotOperatorLaunchProfile,
    private val isApprovedCommand: (List<String>) -> Boolean,
    private val inheritedEnvironment: () -> Map<String, String> = {
        System.getenv()
    },
    private val builderLauncher: (ProcessBuilder) -> Process = { builder ->
        builder.start()
    },
    private val captureFactory: (Int) -> EligibilityProcessOutputCapture = {
        EligibilityProcessOutputCapture(it)
    },
    private val observeSnapshots:
        (stdout: ByteArray, stderr: ByteArray) -> Unit = { _, _ -> },
) : EligibilityProcessRunner {
    override fun run(
        request: EligibilityProcessRequest,
    ): EligibilityProcessResult {
        require(
            request.argv.firstOrNull() == profile.dockerCli.toString() &&
                isApprovedCommand(request.argv),
        ) {
            "Task 6 process command is not approved"
        }
        require(
            request.workingDirectory == profile.repositoryRoot &&
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
            val builder =
                ProcessBuilder(request.argv)
                    .directory(profile.repositoryRoot.toFile())
            builder.environment().apply {
                clear()
                putAll(
                    profile.sanitizedEnvironment(
                        inheritedEnvironment(),
                    ),
                )
            }
            val started = builderLauncher(builder)
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
            observeSnapshots(stdout, stderr)
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
            var cleanupFailure: Throwable? = null

            fun attemptCleanup(action: () -> Unit) {
                try {
                    action()
                } catch (failure: Throwable) {
                    if (cleanupFailure == null) {
                        cleanupFailure = failure
                    }
                }
            }

            attemptCleanup {
                stdoutCapture?.close()
            }
            attemptCleanup {
                stderrCapture?.close()
            }
            process?.let { started ->
                attemptCleanup {
                    terminateAndReap(started) {
                        interrupted = true
                    }
                }
            }
            attemptCleanup {
                stdinFuture?.cancel(true)
            }
            attemptCleanup {
                stdoutFuture?.cancel(true)
            }
            attemptCleanup {
                stderrFuture?.cancel(true)
            }
            attemptCleanup {
                workers?.shutdownNow()
            }
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
                stdout.fill(0)
                stderr.fill(0)
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
