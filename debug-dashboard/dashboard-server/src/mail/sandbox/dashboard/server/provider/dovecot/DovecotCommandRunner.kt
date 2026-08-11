package mail.sandbox.dashboard.server.provider.dovecot

import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.time.Duration
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

internal data class DovecotCommandRequest(
    val argv: List<String>,
    val stdin: ByteArray = ByteArray(0),
    val timeout: Duration = Duration.ofSeconds(30),
    val maximumOutputBytes: Int = 512 * 1024,
)

internal data class DovecotCommandResult(
    val exitCode: Int?,
    val timedOut: Boolean,
    val stdout: ByteArray,
    val stderr: ByteArray,
) {
    companion object {
        fun success(stdout: String = ""): DovecotCommandResult = DovecotCommandResult(
            exitCode = 0,
            timedOut = false,
            stdout = stdout.toByteArray(Charsets.UTF_8),
            stderr = ByteArray(0),
        )
    }
}

internal fun interface DovecotCommandRunner {
    fun run(request: DovecotCommandRequest): DovecotCommandResult
}

/** Runs only Docker Compose commands scoped to this repository's Dovecot service. */
internal class JvmDovecotCommandRunner(
    private val repositoryRoot: Path,
    private val processStarter: ((DovecotCommandRequest) -> Process)? = null,
) : DovecotCommandRunner {
    override fun run(request: DovecotCommandRequest): DovecotCommandResult {
        requireApprovedRequest(request)
        val routedRequest = request.copy(argv = rootComposeCommand(request.argv))
        val process = try {
            processStarter?.invoke(routedRequest) ?: ProcessBuilder(routedRequest.argv)
                .directory(repositoryRoot.toFile())
                .also { builder ->
                    builder.environment().keys
                        .filter { key -> key.startsWith("COMPOSE_") }
                        .forEach(builder.environment()::remove)
                }
                .start()
        } catch (failure: Exception) {
            throw IllegalStateException("Could not start the local Dovecot command", failure)
        }
        val readers = Executors.newFixedThreadPool(2) { runnable ->
            Thread(runnable, "dovecot-dashboard-output").also { it.isDaemon = true }
        }
        val stdoutFuture = readers.submit(
            Callable { readBounded(process.inputStream, request.maximumOutputBytes) },
        )
        val stderrFuture = readers.submit(
            Callable { readBounded(process.errorStream, request.maximumOutputBytes) },
        )
        return try {
            process.outputStream.use { output ->
                output.write(request.stdin)
                output.flush()
            }
            val completed = process.waitFor(request.timeout.toMillis(), TimeUnit.MILLISECONDS)
            if (!completed) {
                process.destroyForcibly()
                process.waitFor(PROCESS_STOP_SECONDS, TimeUnit.SECONDS)
            }
            val stdout = stdoutFuture.get(OUTPUT_JOIN_SECONDS, TimeUnit.SECONDS)
            val stderr = stderrFuture.get(OUTPUT_JOIN_SECONDS, TimeUnit.SECONDS)
            DovecotCommandResult(
                exitCode = if (completed) process.exitValue() else null,
                timedOut = !completed,
                stdout = stdout,
                stderr = stderr,
            )
        } catch (failure: Exception) {
            if (failure is InterruptedException) Thread.currentThread().interrupt()
            throw IllegalStateException("The local Dovecot command failed", failure)
        } finally {
            runCatching { process.outputStream.close() }
            runCatching { process.inputStream.close() }
            runCatching { process.errorStream.close() }
            if (runCatching { process.isAlive }.getOrDefault(false)) {
                runCatching { process.destroyForcibly() }
            }
            stdoutFuture.cancel(true)
            stderrFuture.cancel(true)
            readers.shutdownNow()
        }
    }

    private fun requireApprovedRequest(request: DovecotCommandRequest) {
        require(
            repositoryRoot.isAbsolute &&
                repositoryRoot.normalize() == repositoryRoot &&
                !Files.isSymbolicLink(repositoryRoot) &&
                Files.isDirectory(repositoryRoot, LinkOption.NOFOLLOW_LINKS) &&
                Files.isRegularFile(
                    repositoryRoot.resolve("docker-compose.yml"),
                    LinkOption.NOFOLLOW_LINKS,
                ),
        ) {
            "Dovecot command repository is invalid"
        }
        require(
            request.argv.take(DOVEADM_PREFIX.size) == DOVEADM_PREFIX ||
                isDovecotLogsCommand(request.argv),
        ) {
            "Dovecot command is not approved"
        }
        require(
            !request.timeout.isZero &&
                !request.timeout.isNegative &&
                request.timeout <= MAXIMUM_TIMEOUT &&
                request.maximumOutputBytes in 1..MAXIMUM_CAPTURE_BYTES &&
                request.stdin.size <= MAXIMUM_STDIN_BYTES,
        ) {
            "Dovecot command bounds are invalid"
        }
    }

    private fun isDovecotLogsCommand(argv: List<String>): Boolean =
        argv.size == 7 &&
            argv.take(4) == listOf("docker", "compose", "logs", "--no-color") &&
            argv[4] == "--tail" &&
            argv[5].toIntOrNull() in 1..MAXIMUM_LOG_LINES &&
            argv[6] == "dovecot"

    private fun rootComposeCommand(argv: List<String>): List<String> = buildList {
        add("docker")
        add("compose")
        add("-f")
        add(repositoryRoot.resolve("docker-compose.yml").toString())
        addAll(argv.drop(2))
    }

    private fun readBounded(input: InputStream, maximumBytes: Int): ByteArray {
        val retained = ByteArrayOutputStream(minOf(maximumBytes + 1, READ_BUFFER_BYTES))
        val buffer = ByteArray(READ_BUFFER_BYTES)
        var retainedBytes = 0
        try {
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                val remaining = maximumBytes + 1 - retainedBytes
                if (remaining > 0) {
                    val keep = minOf(count, remaining)
                    retained.write(buffer, 0, keep)
                    retainedBytes += keep
                }
            }
            return retained.toByteArray()
        } finally {
            buffer.fill(0)
            retained.close()
        }
    }

    private companion object {
        val DOVEADM_PREFIX = listOf(
            "docker", "compose", "exec", "-T", "dovecot", "doveadm",
        )
        val MAXIMUM_TIMEOUT: Duration = Duration.ofSeconds(60)
        const val MAXIMUM_CAPTURE_BYTES = 8 * 1024 * 1024
        const val MAXIMUM_STDIN_BYTES = 8 * 1024 * 1024
        const val MAXIMUM_LOG_LINES = 2_000
        const val READ_BUFFER_BYTES = 8 * 1024
        const val OUTPUT_JOIN_SECONDS = 2L
        const val PROCESS_STOP_SECONDS = 2L
    }
}
