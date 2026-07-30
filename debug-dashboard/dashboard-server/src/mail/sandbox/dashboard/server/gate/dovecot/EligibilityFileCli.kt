package mail.sandbox.dashboard.server.gate.dovecot

import java.io.InputStream
import java.io.PrintStream
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.time.Duration
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.Future
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

internal class DovecotDockerRouting private constructor(
    private val composeEnvironment: Map<String, String>,
) {
    fun applyTo(environment: MutableMap<String, String>) {
        environment.keys
            .filter { key ->
                key.startsWith("COMPOSE_") || key.startsWith("DOCKER_")
            }
            .forEach(environment::remove)
        environment.putAll(composeEnvironment)
    }

    companion object {
        fun localDefault(): DovecotDockerRouting =
            DovecotDockerRouting(
                mapOf(
                    "DOCKER_HOST" to "unix:///var/run/docker.sock",
                    "COMPOSE_FILE" to "docker-compose.yml",
                    "COMPOSE_DISABLE_ENV_FILE" to "1",
                ),
            )

        fun task5Proof(
            profile: DovecotTask5ProofProfile,
        ): DovecotDockerRouting =
            DovecotDockerRouting(profile.dockerRoutingEnvironment)
    }
}

internal class DovecotPasswordHasher(
    private val repositoryRoot: Path,
    private val processRunner: EligibilityProcessRunner = JvmEligibilityProcessRunner(),
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

internal class JvmEligibilityProcessRunner(
    private val dockerRouting: DovecotDockerRouting =
        DovecotDockerRouting.localDefault(),
    private val processFactory: ((EligibilityProcessRequest) -> Process)? = null,
    private val captureFactory: (Int) -> EligibilityProcessOutputCapture = { maximumBytes ->
        EligibilityProcessOutputCapture(maximumBytes)
    },
) : EligibilityProcessRunner {
    override fun run(request: EligibilityProcessRequest): EligibilityProcessResult {
        require(isApprovedArgv(request.argv)) {
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
        var process: Process? = null
        var readers: ExecutorService? = null
        var stdoutCapture: EligibilityProcessOutputCapture? = null
        var stderrCapture: EligibilityProcessOutputCapture? = null
        var stdoutFuture: Future<*>? = null
        var stderrFuture: Future<*>? = null
        var stdout = ByteArray(0)
        var stderr = ByteArray(0)
        return try {
            val startedProcess = processFactory?.invoke(request) ?:
                ProcessBuilder(request.argv)
                    .directory(request.workingDirectory.toFile())
                    .also { builder ->
                        dockerRouting.applyTo(builder.environment())
                    }
                    .start()
            process = startedProcess
            val ownedStdoutCapture = captureFactory(request.maximumOutputBytes)
            stdoutCapture = ownedStdoutCapture
            val ownedStderrCapture = captureFactory(request.maximumOutputBytes)
            stderrCapture = ownedStderrCapture
            val ownedReaders = Executors.newFixedThreadPool(2) { runnable ->
                Thread(runnable, "eligibility-process-output").also { it.isDaemon = true }
            }
            readers = ownedReaders
            val ownedStdoutFuture = ownedReaders.submit {
                ownedStdoutCapture.readFrom(startedProcess.inputStream)
            }
            stdoutFuture = ownedStdoutFuture
            val ownedStderrFuture = ownedReaders.submit {
                ownedStderrCapture.readFrom(startedProcess.errorStream)
            }
            stderrFuture = ownedStderrFuture

            startedProcess.outputStream.use { output ->
                output.write(request.stdin)
                output.flush()
            }
            val completed = startedProcess.waitFor(
                request.timeout.toMillis(),
                TimeUnit.MILLISECONDS,
            )
            if (!completed) {
                return EligibilityProcessResult(
                    exitCode = null,
                    timedOut = true,
                    stdout = ByteArray(0),
                    stderr = ByteArray(0),
                )
            }
            ownedStdoutFuture.get(
                OUTPUT_JOIN_TIMEOUT_SECONDS,
                TimeUnit.SECONDS,
            )
            ownedStderrFuture.get(
                OUTPUT_JOIN_TIMEOUT_SECONDS,
                TimeUnit.SECONDS,
            )
            stdout = ownedStdoutCapture.snapshot()
            stderr = ownedStderrCapture.snapshot()
            EligibilityProcessResult(
                exitCode = startedProcess.exitValue(),
                timedOut = false,
                stdout = stdout,
                stderr = stderr,
            )
        } catch (failure: Exception) {
            stdout.fill(0)
            stderr.fill(0)
            if (failure is InterruptedException) {
                Thread.currentThread().interrupt()
            }
            throw IllegalStateException("Dovecot password hashing process failed")
        } finally {
            stdoutCapture?.close()
            stderrCapture?.close()
            process?.let(::closeAndDestroy)
            stdoutFuture?.cancel(true)
            stderrFuture?.cancel(true)
            readers?.shutdownNow()
            runCatching {
                readers?.awaitTermination(
                    OUTPUT_JOIN_TIMEOUT_SECONDS,
                    TimeUnit.SECONDS,
                )
            }
        }
    }

    private fun closeAndDestroy(process: Process) {
        closeProcessStreams(process)
        if (runCatching { process.isAlive }.getOrDefault(true)) {
            runCatching { process.destroyForcibly() }
            runCatching {
                process.waitFor(
                    PROCESS_DESTROY_TIMEOUT_SECONDS,
                    TimeUnit.SECONDS,
                )
            }
        }
        closeProcessStreams(process)
    }

    private fun closeProcessStreams(process: Process) {
        runCatching { process.outputStream.close() }
        runCatching { process.inputStream.close() }
        runCatching { process.errorStream.close() }
    }

    private fun isApprovedArgv(argv: List<String>): Boolean {
        if (argv == HASH_ARGV) return true
        if (
            argv.size != VERIFY_ARGV_PREFIX.size + 1 ||
            argv.take(VERIFY_ARGV_PREFIX.size) != VERIFY_ARGV_PREFIX
        ) {
            return false
        }
        return runCatching {
            EligibilityEntry.requireValidHash(argv.last())
        }.isSuccess
    }

    companion object {
        private val HASH_ARGV = listOf(
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
        private val VERIFY_ARGV_PREFIX = listOf(
            "docker",
            "compose",
            "exec",
            "-T",
            "dovecot",
            "doveadm",
            "pw",
            "-t",
        )
        private const val MAX_ALLOWED_OUTPUT_BYTES = 64 * 1024
        private const val PROCESS_DESTROY_TIMEOUT_SECONDS = 2L
        private const val OUTPUT_JOIN_TIMEOUT_SECONDS = 2L
    }
}

internal class EligibilityProcessOutputCapture(
    private val maximumBytes: Int,
    backingFactory: (Int) -> ByteArray = ::ByteArray,
    private val localBufferFactory: (Int) -> ByteArray = ::ByteArray,
) : AutoCloseable {
    private val backing = backingFactory(maximumBytes)
    private var size = 0
    private var closed = false

    init {
        if (maximumBytes <= 0 || backing.size != maximumBytes) {
            backing.fill(0)
            throw IllegalArgumentException("Eligibility process output buffer is invalid")
        }
    }

    fun readFrom(input: InputStream) {
        val localSize = minOf(maximumBytes, LOCAL_BUFFER_BYTES)
        val local = localBufferFactory(localSize)
        try {
            require(local.size == localSize) {
                "Eligibility process output buffer is invalid"
            }
            while (true) {
                val read = input.read(local, 0, local.size)
                if (read < 0) return
                if (read > 0 && !append(local, read)) return
            }
        } finally {
            local.fill(0)
        }
    }

    @Synchronized
    fun snapshot(): ByteArray {
        check(!closed) { "Eligibility process output capture is closed" }
        return backing.copyOf(size)
    }

    @Synchronized
    private fun append(
        source: ByteArray,
        length: Int,
    ): Boolean {
        if (closed) return false
        check(length in 1..source.size && size <= maximumBytes - length) {
            "Eligibility process output exceeded its bound"
        }
        source.copyInto(
            destination = backing,
            destinationOffset = size,
            startIndex = 0,
            endIndex = length,
        )
        size += length
        return true
    }

    @Synchronized
    override fun close() {
        if (closed) return
        closed = true
        backing.fill(0)
        size = 0
    }

    companion object {
        private const val LOCAL_BUFFER_BYTES = 8 * 1024
    }
}

internal fun interface EligibilityCommandExecutor {
    fun execute(
        args: Array<String>,
        stdin: InputStream,
        stdout: PrintStream,
        stderr: PrintStream,
    ): Int
}

internal class EligibilityFileCli(
    private val pathsProvider: () -> EligibilityPaths = EligibilityPaths::production,
    private val hasherFactory: (Path) -> EligibilityPasswordHasher = { repositoryRoot ->
        DovecotPasswordHasher(repositoryRoot)
    },
) : EligibilityCommandExecutor {
    override fun execute(
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
            val exitCode = EligibilityFileCliEntrypoint().execute(
                args = args,
                stdin = System.`in`,
                stdout = System.out,
                stderr = System.err,
            )
            exitProcess(exitCode)
        }
    }
}

internal class EligibilityFileCliEntrypoint(
    private val environment: Map<String, String> = System.getenv(),
    private val productionCli: EligibilityCommandExecutor =
        EligibilityFileCli(),
    private val task5ProofCliFactory: () -> EligibilityCommandExecutor = {
        val repositoryRoot = EligibilityPaths.production().repositoryRoot
        val profile = DovecotTask5ProofProfile.load(
            environment = environment,
            repositoryRoot = repositoryRoot,
        )
        profile.requirePreparedTls()
        EligibilityFileCli(
            pathsProvider = profile::eligibilityPaths,
            hasherFactory = { repositoryRoot ->
                DovecotPasswordHasher(
                    repositoryRoot,
                    JvmEligibilityProcessRunner(
                        dockerRouting =
                            DovecotDockerRouting.task5Proof(profile),
                    ),
                )
            },
        )
    },
) : EligibilityCommandExecutor {
    override fun execute(
        args: Array<String>,
        stdin: InputStream,
        stdout: PrintStream,
        stderr: PrintStream,
    ): Int = try {
        if (args.firstOrNull() == TASK5_PROOF_PREFIX) {
            val delegatedArgs = args.drop(1).toTypedArray()
            require(isApprovedTask5ProofCommand(delegatedArgs)) {
                "Task 5 proof eligibility command is invalid"
            }
            val proofCli = task5ProofCliFactory()
            if (delegatedArgs.contentEquals(arrayOf(PREFLIGHT_COMMAND))) {
                stdout.println("Dovecot Task 5 proof preflight complete")
                0
            } else {
                proofCli.execute(
                    args = delegatedArgs,
                    stdin = stdin,
                    stdout = stdout,
                    stderr = stderr,
                )
            }
        } else {
            require(environment[LIVE_PROFILE_KEY] != TASK5_PROOF_PREFIX) {
                "Normal eligibility authority is unavailable during Task 5 proof"
            }
            productionCli.execute(
                args = args,
                stdin = stdin,
                stdout = stdout,
                stderr = stderr,
            )
        }
    } catch (_: Exception) {
        stderr.println("Eligibility command failed")
        2
    }

    private fun isApprovedTask5ProofCommand(args: Array<String>): Boolean =
        args.contentEquals(arrayOf(PREFLIGHT_COMMAND)) ||
            args.contentEquals(arrayOf("list")) ||
            (
                args.size == 2 &&
                    args[0] in setOf("add", "remove") &&
                    runCatching {
                        EligibilityAddress.requireCanonical(args[1])
                    }.isSuccess
                )

    companion object {
        private const val TASK5_PROOF_PREFIX = "task5-proof"
        private const val PREFLIGHT_COMMAND = "preflight"
        private const val LIVE_PROFILE_KEY = "DOVECOT_LIVE_PROFILE"
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
