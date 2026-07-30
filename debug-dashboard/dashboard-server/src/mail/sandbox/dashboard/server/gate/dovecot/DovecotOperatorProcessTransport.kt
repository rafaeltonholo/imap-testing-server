package mail.sandbox.dashboard.server.gate.dovecot

import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.util.Collections
import java.util.concurrent.TimeUnit

internal class DovecotOperatorLaunchProfile(
    val dockerCli: Path,
    val repositoryRoot: Path,
    composeFiles: List<Path>,
    val projectName: String,
) {
    val composeFiles: List<Path> =
        Collections.unmodifiableList(ArrayList(composeFiles))
    val dockerHost: String = DOCKER_HOST
    val service: String = SERVICE
    val composeProfile: String = COMPOSE_PROFILE

    init {
        requireCanonicalDockerCli(dockerCli)
        requireCanonicalRepositoryRoot(repositoryRoot)
        require(this.composeFiles.isNotEmpty()) {
            "Dovecot operator Compose files are invalid"
        }
        this.composeFiles.forEach { composeFile ->
            requireCanonicalComposeFile(
                path = composeFile,
                repositoryRoot = repositoryRoot,
            )
        }
        require(PROJECT_NAME.matches(projectName)) {
            "Dovecot operator Compose project is invalid"
        }
    }

    val argv: List<String> =
        Collections.unmodifiableList(
            ArrayList(
                buildList {
                    add(dockerCli.toString())
                    add("compose")
                    add("--project-directory")
                    add(repositoryRoot.toString())
                    this@DovecotOperatorLaunchProfile
                        .composeFiles
                        .forEach { composeFile ->
                            add("-f")
                            add(composeFile.toString())
                        }
                    add("--project-name")
                    add(projectName)
                    add("--profile")
                    add(composeProfile)
                    add("exec")
                    add("-T")
                    add("--index")
                    add("1")
                    add(service)
                    add("/usr/bin/openssl")
                    add("s_client")
                    add("-quiet")
                    add("-no_ign_eof")
                    add("-nocommands")
                    add("-4")
                    add("-min_protocol")
                    add("TLSv1.2")
                    add("-max_protocol")
                    add("TLSv1.3")
                    add("-verify_return_error")
                    add("-verify_hostname")
                    add("localhost")
                    add("-no-CApath")
                    add("-no-CAstore")
                    add("-CAfile")
                    add("/etc/dovecot/ssl/tls.crt")
                    add("-connect")
                    add("127.0.0.1:31993")
                    add("-servername")
                    add("localhost")
                },
            ),
        )

    @Suppress("UNUSED_PARAMETER")
    fun sanitizedEnvironment(
        inheritedEnvironment: Map<String, String>,
    ): Map<String, String> =
        Collections.unmodifiableMap(
            linkedMapOf(
                "COMPOSE_DISABLE_ENV_FILE" to "1",
                "DOCKER_HOST" to dockerHost,
            ),
        )

    internal companion object {
        const val DOCKER_HOST = "unix:///var/run/docker.sock"
        const val SERVICE = "dovecot-operator"
        const val COMPOSE_PROFILE = "dovecot-operator"

        private val PROJECT_NAME = Regex("[a-z0-9][a-z0-9_-]*")
    }
}

internal fun interface DovecotOperatorProcessStarter {
    fun start(profile: DovecotOperatorLaunchProfile): Process
}

internal class JvmDovecotOperatorProcessStarter(
    private val inheritedEnvironment: () -> Map<String, String> = {
        System.getenv()
    },
    private val builderLauncher: (ProcessBuilder) -> Process = { builder ->
        builder.start()
    },
) : DovecotOperatorProcessStarter {
    override fun start(profile: DovecotOperatorLaunchProfile): Process {
        val builder =
            ProcessBuilder(profile.argv)
                .directory(profile.repositoryRoot.toFile())
                .redirectError(ProcessBuilder.Redirect.DISCARD)
        builder.environment().apply {
            clear()
            putAll(profile.sanitizedEnvironment(inheritedEnvironment()))
        }
        return builderLauncher(builder)
    }
}

internal class JvmDockerExecDovecotOperatorTransportFactory(
    private val profile: DovecotOperatorLaunchProfile,
    private val starter: DovecotOperatorProcessStarter =
        JvmDovecotOperatorProcessStarter(),
) : DovecotOperatorTransportFactory {
    override fun open(
        registerAllocated: (DovecotOperatorTransport) -> Unit,
    ): DovecotOperatorTransport {
        val process = try {
            starter.start(profile)
        } catch (_: Throwable) {
            throw IOException(START_FAILURE_MESSAGE)
        }
        val transport = ManagedDovecotOperatorProcessTransport(process)
        try {
            transport.mapProcessStreams()
        } catch (_: Throwable) {
            transport.cleanupRegistrationFailure()
            throw IOException(ALLOCATION_FAILURE_MESSAGE)
        }
        try {
            registerAllocated(transport)
        } catch (_: Throwable) {
            transport.cleanupRegistrationFailure()
            throw IOException(REGISTRATION_FAILURE_MESSAGE)
        }
        return transport
    }

    override fun toString(): String =
        "JvmDockerExecDovecotOperatorTransportFactory(fixed, redacted)"

    private companion object {
        const val START_FAILURE_MESSAGE =
            "Dovecot operator process transport start failed"
        const val ALLOCATION_FAILURE_MESSAGE =
            "Dovecot operator process transport allocation failed"
        const val REGISTRATION_FAILURE_MESSAGE =
            "Dovecot operator process transport registration failed"
    }
}

private class ManagedDovecotOperatorProcessTransport(
    private val process: Process,
) : DovecotOperatorTransport {
    private val lifecycleLock = Any()
    private var childStdin: OutputStream? = null
    private var childStdout: InputStream? = null
    private var terminationOutcome: TerminationOutcome? = null

    @Volatile
    private var terminal = false

    fun mapProcessStreams() {
        childStdin = process.outputStream
        childStdout = process.inputStream
    }

    override val input: InputStream
        get() {
            check(!terminal) {
                CLOSED_MESSAGE
            }
            return checkNotNull(childStdout) {
                CLOSED_MESSAGE
            }
        }

    override val outputStream: OutputStream
        get() {
            check(!terminal) {
                CLOSED_MESSAGE
            }
            return checkNotNull(childStdin) {
                CLOSED_MESSAGE
            }
        }

    override fun abort() {
        terminate(
            mode = TerminationMode.Abort,
            failureMessage =
                "Dovecot operator process transport abort failed",
        )
    }

    override fun close() {
        terminate(
            mode = TerminationMode.NormalClose,
            failureMessage =
                "Dovecot operator process transport close failed",
        )
    }

    fun cleanupRegistrationFailure() {
        runCatching {
            terminate(
                mode = TerminationMode.RegistrationCleanup,
                failureMessage =
                    "Dovecot operator process transport registration cleanup failed",
            )
        }
    }

    override fun toString(): String =
        "JvmDockerExecDovecotOperatorTransport(redacted)"

    private fun terminate(
        mode: TerminationMode,
        failureMessage: String,
    ) {
        val outcome = synchronized(lifecycleLock) {
            terminationOutcome ?: run {
                terminal = true
                performTermination(mode).also { completed ->
                    terminationOutcome = completed
                }
            }
        }
        val accepted = when (mode) {
            TerminationMode.NormalClose ->
                outcome.reaped &&
                    outcome.naturalExit &&
                    outcome.streamsClosed &&
                    outcome.exitCode == 0
            TerminationMode.Abort,
            TerminationMode.RegistrationCleanup,
            -> outcome.reaped
        }
        if (!accepted) {
            throw IOException(failureMessage)
        }
    }

    private fun performTermination(
        initialMode: TerminationMode,
    ): TerminationOutcome {
        var restoreInterrupt = Thread.currentThread().isInterrupted

        fun awaitProcess(timeoutMillis: Long): Boolean =
            try {
                process.waitFor(timeoutMillis, TimeUnit.MILLISECONDS)
            } catch (_: InterruptedException) {
                restoreInterrupt = true
                false
            } catch (_: Throwable) {
                false
            }

        return try {
            val stdinClosed = closeQuietly(childStdin)
            val naturalExit = awaitProcess(NATURAL_EXIT_WAIT_MILLIS)
            val stdoutClosed = closeQuietly(childStdout)

            var reaped = naturalExit
            if (!reaped) {
                try {
                    process.destroy()
                } catch (_: Throwable) {
                    // Continue to the bounded force/reap sequence.
                }
                reaped = awaitProcess(DESTROY_WAIT_MILLIS)
            }
            if (!reaped) {
                try {
                    process.destroyForcibly()
                } catch (_: Throwable) {
                    // The final bounded reap attempt is still mandatory.
                }
                reaped = awaitProcess(FORCE_WAIT_MILLIS)
            }

            val exitCode =
                if (
                    reaped &&
                    naturalExit &&
                    initialMode != TerminationMode.RegistrationCleanup
                ) {
                    try {
                        process.exitValue()
                    } catch (_: Throwable) {
                        null
                    }
                } else {
                    null
                }
            TerminationOutcome(
                reaped = reaped,
                naturalExit = naturalExit,
                streamsClosed = stdinClosed && stdoutClosed,
                exitCode = exitCode,
            )
        } finally {
            if (restoreInterrupt) {
                Thread.currentThread().interrupt()
            }
        }
    }

    private fun closeQuietly(stream: AutoCloseable?): Boolean =
        try {
            stream?.close()
            true
        } catch (_: Throwable) {
            false
        }

    private companion object {
        const val CLOSED_MESSAGE =
            "Dovecot operator process transport is closed"
        const val NATURAL_EXIT_WAIT_MILLIS = 500L
        const val DESTROY_WAIT_MILLIS = 250L
        const val FORCE_WAIT_MILLIS = 250L
    }

    private enum class TerminationMode {
        NormalClose,
        Abort,
        RegistrationCleanup,
    }

    private data class TerminationOutcome(
        val reaped: Boolean,
        val naturalExit: Boolean,
        val streamsClosed: Boolean,
        val exitCode: Int?,
    )
}

private fun requireCanonicalDockerCli(path: Path) {
    require(
        path.isAbsolute &&
            path.normalize() == path &&
            Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) &&
            !Files.isSymbolicLink(path) &&
            Files.isExecutable(path) &&
            path.isCanonical(),
    ) {
        "Dovecot operator Docker CLI is invalid"
    }
}

private fun requireCanonicalRepositoryRoot(path: Path) {
    require(
        path.isAbsolute &&
            path.normalize() == path &&
            Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS) &&
            !Files.isSymbolicLink(path) &&
            path.isCanonical(),
    ) {
        "Dovecot operator repository root is invalid"
    }
}

private fun requireCanonicalComposeFile(
    path: Path,
    repositoryRoot: Path,
) {
    require(
        path.isAbsolute &&
            path.normalize() == path &&
            path.startsWith(repositoryRoot) &&
            Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) &&
            !Files.isSymbolicLink(path) &&
            path.isCanonical(),
    ) {
        "Dovecot operator Compose files are invalid"
    }
}

private fun Path.isCanonical(): Boolean =
    runCatching { toRealPath() == this }.getOrDefault(false)
