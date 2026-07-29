package mail.sandbox.dashboard.server.gate.dovecot

import java.io.InputStream
import java.io.PrintStream
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.time.Duration
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.system.exitProcess

internal class EligibilityPassword private constructor(
    private val bytes: ByteArray,
) : AutoCloseable {
    private var closed = false

    @Synchronized
    fun <T> withBytes(block: (ByteArray) -> T): T {
        check(!closed) { "Eligibility password is closed" }
        return block(bytes)
    }

    @Synchronized
    override fun close() {
        if (closed) return
        closed = true
        bytes.fill(0)
    }

    override fun toString(): String = "EligibilityPassword(redacted)"

    companion object {
        fun takeOwnership(bytes: ByteArray): EligibilityPassword {
            require(bytes.isNotEmpty()) { "Eligibility password is absent" }
            return EligibilityPassword(bytes)
        }

        fun read(input: InputStream): EligibilityPassword {
            val buffer = input.readNBytes(MAX_PASSWORD_BYTES + 3)
            try {
                require(buffer.size <= MAX_PASSWORD_BYTES + 2) {
                    "Eligibility password is too large"
                }
                var length = buffer.size
                if (length > 0 && buffer[length - 1] == '\n'.code.toByte()) {
                    length -= 1
                    if (length > 0 && buffer[length - 1] == '\r'.code.toByte()) {
                        length -= 1
                    }
                }
                require(length in 1..MAX_PASSWORD_BYTES) {
                    "Eligibility password is absent or too large"
                }
                require(
                    (0 until length).all { index ->
                        val byte = buffer[index]
                        byte != 0.toByte() &&
                            byte != '\n'.code.toByte() &&
                            byte != '\r'.code.toByte()
                    },
                ) {
                    "Eligibility password contains an unsupported delimiter"
                }
                return takeOwnership(buffer.copyOf(length))
            } finally {
                buffer.fill(0)
            }
        }

        private const val MAX_PASSWORD_BYTES = 4 * 1024
    }
}

internal fun interface EligibilityPasswordHasher {
    fun hash(password: EligibilityPassword): String
}

internal class EligibilityProcessRequest(
    val argv: List<String>,
    val workingDirectory: Path,
    val stdin: ByteArray,
    val timeout: Duration,
    val maximumOutputBytes: Int,
) {
    override fun toString(): String =
        "EligibilityProcessRequest(argv=fixed, workingDirectory=fixed, stdin=redacted, " +
            "timeout=$timeout, maximumOutputBytes=$maximumOutputBytes)"
}

internal class EligibilityProcessResult(
    val exitCode: Int?,
    val timedOut: Boolean,
    val stdout: ByteArray,
    val stderr: ByteArray,
) {
    override fun toString(): String =
        "EligibilityProcessResult(exitCode=$exitCode, timedOut=$timedOut, output=redacted)"
}

internal fun interface EligibilityProcessRunner {
    fun run(request: EligibilityProcessRequest): EligibilityProcessResult
}

internal class DovecotPasswordHasher(
    private val repositoryRoot: Path,
    private val processRunner: EligibilityProcessRunner = JvmEligibilityProcessRunner,
) : EligibilityPasswordHasher {
    override fun hash(password: EligibilityPassword): String {
        val processInput = password.withBytes(::twiceOverStdin)
        var result: EligibilityProcessResult? = null
        var normalizedOutput = ByteArray(0)
        try {
            val request = EligibilityProcessRequest(
                argv = FIXED_ARGV,
                workingDirectory = repositoryRoot,
                stdin = processInput,
                timeout = PROCESS_TIMEOUT,
                maximumOutputBytes = MAXIMUM_OUTPUT_BYTES,
            )
            result = processRunner.run(request)
            check(
                !result.timedOut &&
                    result.exitCode == 0 &&
                    result.stdout.size <= MAXIMUM_OUTPUT_BYTES &&
                    result.stderr.size <= MAXIMUM_OUTPUT_BYTES,
            ) {
                "Dovecot password hashing failed"
            }
            normalizedOutput = stripOneTerminalNewline(result.stdout)
            check(
                normalizedOutput.isNotEmpty() &&
                    normalizedOutput.all { it.toInt() in 0x21..0x7e },
            ) {
                "Dovecot password hashing returned an invalid result"
            }
            val hash = String(normalizedOutput, StandardCharsets.US_ASCII)
            EligibilityEntry.requireValidHash(hash)
            return hash
        } catch (failure: IllegalArgumentException) {
            throw IllegalStateException("Dovecot password hashing returned an invalid result", failure)
        } finally {
            processInput.fill(0)
            normalizedOutput.fill(0)
            result?.stdout?.fill(0)
            result?.stderr?.fill(0)
        }
    }

    private fun twiceOverStdin(password: ByteArray): ByteArray {
        check(
            password.isNotEmpty() &&
                password.size <= MAX_PASSWORD_BYTES &&
                password.all { byte ->
                    byte != 0.toByte() &&
                        byte != '\n'.code.toByte() &&
                        byte != '\r'.code.toByte()
                },
        ) {
            "Eligibility password is invalid"
        }
        val input = ByteArray(Math.addExact(Math.multiplyExact(password.size, 2), 2))
        password.copyInto(input, destinationOffset = 0)
        input[password.size] = '\n'.code.toByte()
        password.copyInto(input, destinationOffset = password.size + 1)
        input[input.lastIndex] = '\n'.code.toByte()
        return input
    }

    private fun stripOneTerminalNewline(output: ByteArray): ByteArray {
        var length = output.size
        if (length > 0 && output[length - 1] == '\n'.code.toByte()) {
            length -= 1
            if (length > 0 && output[length - 1] == '\r'.code.toByte()) {
                length -= 1
            }
        }
        return output.copyOf(length)
    }

    companion object {
        private val FIXED_ARGV = listOf(
            "docker",
            "compose",
            "exec",
            "-T",
            "dovecot",
            "doveadm",
            "pw",
            "-s",
            "ARGON2ID",
        )
        private val PROCESS_TIMEOUT = Duration.ofSeconds(30)
        private const val MAXIMUM_OUTPUT_BYTES = 16 * 1024
        private const val MAX_PASSWORD_BYTES = 4 * 1024
    }
}

private object JvmEligibilityProcessRunner : EligibilityProcessRunner {
    override fun run(request: EligibilityProcessRequest): EligibilityProcessResult {
        require(
            request.argv == listOf(
                "docker",
                "compose",
                "exec",
                "-T",
                "dovecot",
                "doveadm",
                "pw",
                "-s",
                "ARGON2ID",
            ),
        ) {
            "Eligibility process command is not approved"
        }
        require(
            request.workingDirectory.isAbsolute &&
                request.workingDirectory.normalize() == request.workingDirectory &&
                Files.isRegularFile(
                    request.workingDirectory.resolve("docker-compose.yml"),
                    LinkOption.NOFOLLOW_LINKS,
                ),
        ) {
            "Eligibility process working directory is invalid"
        }
        require(
            !request.timeout.isNegative &&
                !request.timeout.isZero &&
                request.maximumOutputBytes in 1..MAX_ALLOWED_OUTPUT_BYTES,
        ) {
            "Eligibility process bounds are invalid"
        }
        val process = ProcessBuilder(request.argv)
            .directory(request.workingDirectory.toFile())
            .start()
        val readers = Executors.newFixedThreadPool(2) { runnable ->
            Thread(runnable, "eligibility-process-output").also { it.isDaemon = true }
        }
        val stdoutFuture = readers.submit(
            Callable {
                readEligibilityProcessOutputBounded(
                    process.inputStream,
                    request.maximumOutputBytes,
                )
            },
        )
        val stderrFuture = readers.submit(
            Callable {
                readEligibilityProcessOutputBounded(
                    process.errorStream,
                    request.maximumOutputBytes,
                )
            },
        )
        var stdout = ByteArray(0)
        var stderr = ByteArray(0)
        return try {
            try {
                process.outputStream.use { output ->
                    output.write(request.stdin)
                    output.flush()
                }
            } catch (failure: Throwable) {
                process.destroyForcibly()
                throw failure
            }
            val completed = process.waitFor(
                request.timeout.toMillis(),
                TimeUnit.MILLISECONDS,
            )
            if (!completed) {
                process.destroyForcibly()
                process.waitFor(PROCESS_DESTROY_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            }
            stdout = stdoutFuture.get(
                OUTPUT_JOIN_TIMEOUT_SECONDS,
                TimeUnit.SECONDS,
            )
            stderr = stderrFuture.get(
                OUTPUT_JOIN_TIMEOUT_SECONDS,
                TimeUnit.SECONDS,
            )
            EligibilityProcessResult(
                exitCode = if (completed) process.exitValue() else null,
                timedOut = !completed,
                stdout = stdout,
                stderr = stderr,
            )
        } catch (failure: Throwable) {
            stdout.fill(0)
            stderr.fill(0)
            if (stdoutFuture.isDone) {
                runCatching { stdoutFuture.get() }.getOrNull()?.fill(0)
            }
            if (stderrFuture.isDone) {
                runCatching { stderrFuture.get() }.getOrNull()?.fill(0)
            }
            throw failure
        } finally {
            readers.shutdownNow()
            if (process.isAlive) process.destroyForcibly()
        }
    }

    private const val MAX_ALLOWED_OUTPUT_BYTES = 64 * 1024
    private const val PROCESS_DESTROY_TIMEOUT_SECONDS = 2L
    private const val OUTPUT_JOIN_TIMEOUT_SECONDS = 2L
}

internal fun readEligibilityProcessOutputBounded(
    input: InputStream,
    maximumBytes: Int,
    bufferFactory: (Int) -> ByteArray = ::ByteArray,
): ByteArray {
    require(maximumBytes > 0) { "Eligibility process output bound is invalid" }
    val backing = bufferFactory(maximumBytes)
    try {
        require(backing.size == maximumBytes) {
            "Eligibility process output buffer is invalid"
        }
        var size = 0
        while (size < maximumBytes) {
            val read = input.read(backing, size, maximumBytes - size)
            if (read < 0) return backing.copyOf(size)
            if (read > 0) size += read
        }
        check(input.read() < 0) {
            "Eligibility process output exceeded its bound"
        }
        return backing.copyOf(size)
    } finally {
        backing.fill(0)
    }
}

internal class EligibilityFileCli(
    private val pathsProvider: () -> EligibilityPaths = EligibilityPaths::production,
    private val hasherFactory: (Path) -> EligibilityPasswordHasher = { repositoryRoot ->
        DovecotPasswordHasher(repositoryRoot)
    },
) {
    fun execute(
        args: Array<String>,
        stdin: InputStream,
        stdout: PrintStream,
        stderr: PrintStream,
    ): Int = try {
        val command = EligibilityCommand.parse(args)
        val paths = pathsProvider()
        paths.revalidate()
        val file = EligibilityFile(paths)
        when (command) {
            EligibilityCommand.ListAddresses -> {
                file.list().forEach(stdout::println)
            }
            EligibilityCommand.Seed -> {
                require(file.isEmpty()) {
                    "Runtime eligibility authority is not empty"
                }
                val addresses = readSeedInventory(paths)
                EligibilityPassword.read(stdin).use { password ->
                    val hasher = hasherFactory(paths.repositoryRoot)
                    val entries = addresses.map { address ->
                        EligibilityEntry.create(address, hasher.hash(password))
                    }
                    file.seed(entries)
                }
            }
            is EligibilityCommand.Add -> {
                EligibilityPassword.read(stdin).use { password ->
                    val hash = hasherFactory(paths.repositoryRoot).hash(password)
                    file.add(command.address, hash)
                }
            }
            is EligibilityCommand.Reset -> {
                EligibilityPassword.read(stdin).use { password ->
                    val hash = hasherFactory(paths.repositoryRoot).hash(password)
                    file.reset(command.address, hash)
                }
            }
            is EligibilityCommand.Remove -> file.remove(command.address)
        }
        0
    } catch (_: Exception) {
        stderr.println("Eligibility command failed")
        2
    }

    private fun readSeedInventory(paths: EligibilityPaths): List<String> {
        val seed = paths.seed
        val configDirectory = requireNotNull(seed.parent)
        check(
            Files.isDirectory(configDirectory, LinkOption.NOFOLLOW_LINKS) &&
                !Files.isSymbolicLink(configDirectory) &&
                Files.isRegularFile(seed, LinkOption.NOFOLLOW_LINKS) &&
                !Files.isSymbolicLink(seed),
        ) {
            "Seed inventory path is invalid"
        }
        val bytes = Files.readAllBytes(seed)
        try {
            require(bytes.isNotEmpty() && bytes.size <= MAX_SEED_BYTES) {
                "Seed inventory is empty or too large"
            }
            require(bytes.last() == '\n'.code.toByte()) {
                "Seed inventory is not deterministically rendered"
            }
            val text = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
                .decode(java.nio.ByteBuffer.wrap(bytes))
                .toString()
            val addresses = text.removeSuffix("\n").split('\n')
                .map(EligibilityAddress::requireCanonical)
            require(addresses.isNotEmpty() && addresses.size == addresses.toSet().size) {
                "Seed inventory is invalid"
            }
            require(addresses.joinToString(separator = "\n", postfix = "\n") == text) {
                "Seed inventory is not deterministically rendered"
            }
            return addresses
        } finally {
            bytes.fill(0)
        }
    }

    companion object {
        private const val MAX_SEED_BYTES = 64 * 1024

        @JvmStatic
        fun main(args: Array<String>) {
            val exitCode = EligibilityFileCli().execute(
                args = args,
                stdin = System.`in`,
                stdout = System.out,
                stderr = System.err,
            )
            exitProcess(exitCode)
        }
    }
}

private sealed interface EligibilityCommand {
    data object Seed : EligibilityCommand
    data object ListAddresses : EligibilityCommand
    class Add(val address: String) : EligibilityCommand
    class Reset(val address: String) : EligibilityCommand
    class Remove(val address: String) : EligibilityCommand

    companion object {
        fun parse(args: Array<String>): EligibilityCommand = when {
            args.contentEquals(arrayOf("seed")) -> Seed
            args.contentEquals(arrayOf("list")) -> ListAddresses
            args.size == 2 && args[0] == "add" ->
                Add(EligibilityAddress.requireCanonical(args[1]))
            args.size == 2 && args[0] == "reset" ->
                Reset(EligibilityAddress.requireCanonical(args[1]))
            args.size == 2 && args[0] == "remove" ->
                Remove(EligibilityAddress.requireCanonical(args[1]))
            else -> throw IllegalArgumentException("Eligibility command is invalid")
        }
    }
}
