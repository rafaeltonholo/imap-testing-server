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
        } catch (failure: Throwable) {
            restoreInterruptFrom(failure)
            throw IOException(START_FAILURE_MESSAGE)
        }
        val transport = ManagedDovecotOperatorProcessTransport(process)
        try {
            transport.mapProcessStreams()
        } catch (failure: Throwable) {
            transport.cleanupRegistrationFailure()
            restoreInterruptFrom(failure)
            throw IOException(ALLOCATION_FAILURE_MESSAGE)
        }
        try {
            registerAllocated(transport)
        } catch (failure: Throwable) {
            transport.cleanupRegistrationFailure()
            restoreInterruptFrom(failure)
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

private class ProcessStreamAdmissionGate {
    private val lock = Any()
    private var sealed = false

    fun guard(raw: InputStream): GuardedInputStream =
        GuardedInputStream(Direction(raw))

    fun guard(raw: OutputStream): GuardedOutputStream =
        GuardedOutputStream(Direction(raw))

    fun seal() {
        synchronized(lock) {
            sealed = true
        }
    }

    private fun <Stream : AutoCloseable, Result> call(
        direction: Direction<Stream>,
        operation: (Stream) -> Result,
    ): Result {
        synchronized(lock) {
            if (sealed || direction.closeState != CloseState.Open) {
                throw IOException(CLOSED_MESSAGE)
            }
            direction.activeCalls += 1
        }
        return try {
            operation(direction.raw)
        } catch (failure: Throwable) {
            restoreInterruptFrom(failure)
            throw IOException(OPERATION_FAILURE_MESSAGE)
        } finally {
            release(direction)
        }
    }

    private fun <Stream : AutoCloseable> requestClose(
        direction: Direction<Stream>,
        lifecycleAuthorized: Boolean,
    ): CloseRequest {
        val claimed = synchronized(lock) {
            if (!lifecycleAuthorized && sealed) {
                return CloseRequest.RejectedAfterSeal
            }
            when (direction.closeState) {
                CloseState.Open -> {
                    if (direction.activeCalls == 0) {
                        direction.closeState = CloseState.InProgress
                        true
                    } else {
                        direction.closeState = CloseState.Deferred
                        false
                    }
                }
                CloseState.Succeeded ->
                    return CloseRequest.SynchronouslyClosed
                CloseState.Deferred,
                CloseState.InProgress,
                -> return CloseRequest.DeferredOrInProgress
                CloseState.Failed ->
                    return CloseRequest.Failed
            }
        }
        return if (claimed) {
            closeClaimed(direction)
        } else {
            CloseRequest.DeferredOrInProgress
        }
    }

    private fun <Stream : AutoCloseable> release(
        direction: Direction<Stream>,
    ) {
        val closeDeferred = synchronized(lock) {
            direction.activeCalls -= 1
            check(direction.activeCalls >= 0)
            if (
                direction.activeCalls == 0 &&
                direction.closeState == CloseState.Deferred
            ) {
                direction.closeState = CloseState.InProgress
                true
            } else {
                false
            }
        }
        if (closeDeferred) {
            closeClaimed(direction)
        }
    }

    private fun <Stream : AutoCloseable> closeClaimed(
        direction: Direction<Stream>,
    ): CloseRequest {
        val failure = try {
            direction.raw.close()
            null
        } catch (caught: Throwable) {
            restoreInterruptFrom(caught)
            caught
        }
        synchronized(lock) {
            direction.closeState =
                if (failure == null) {
                    CloseState.Succeeded
                } else {
                    CloseState.Failed
                }
        }
        return if (failure == null) {
            CloseRequest.SynchronouslyClosed
        } else {
            CloseRequest.Failed
        }
    }

    inner class GuardedInputStream internal constructor(
        private val direction: Direction<InputStream>,
    ) : InputStream() {
        override fun read(): Int =
            call(direction) { raw -> raw.read() }

        override fun read(
            bytes: ByteArray,
            offset: Int,
            length: Int,
        ): Int =
            call(direction) { raw ->
                raw.read(bytes, offset, length)
            }

        override fun close() {
            when (
                requestClose(
                    direction = direction,
                    lifecycleAuthorized = false,
                )
            ) {
                CloseRequest.SynchronouslyClosed -> Unit
                CloseRequest.RejectedAfterSeal ->
                    throw IOException(CLOSED_MESSAGE)
                CloseRequest.DeferredOrInProgress,
                CloseRequest.Failed,
                -> throw IOException(CLOSE_FAILURE_MESSAGE)
            }
        }

        fun requestCloseForLifecycle(): Boolean =
            requestClose(
                direction = direction,
                lifecycleAuthorized = true,
            ) ==
                CloseRequest.SynchronouslyClosed
    }

    inner class GuardedOutputStream internal constructor(
        private val direction: Direction<OutputStream>,
    ) : OutputStream() {
        override fun write(value: Int) {
            call(direction) { raw -> raw.write(value) }
        }

        override fun write(
            bytes: ByteArray,
            offset: Int,
            length: Int,
        ) {
            call(direction) { raw ->
                raw.write(bytes, offset, length)
            }
        }

        override fun flush() {
            call(direction) { raw -> raw.flush() }
        }

        override fun close() {
            when (
                requestClose(
                    direction = direction,
                    lifecycleAuthorized = false,
                )
            ) {
                CloseRequest.SynchronouslyClosed -> Unit
                CloseRequest.RejectedAfterSeal ->
                    throw IOException(CLOSED_MESSAGE)
                CloseRequest.DeferredOrInProgress,
                CloseRequest.Failed,
                -> throw IOException(CLOSE_FAILURE_MESSAGE)
            }
        }

        fun requestCloseForLifecycle(): Boolean =
            requestClose(
                direction = direction,
                lifecycleAuthorized = true,
            ) ==
                CloseRequest.SynchronouslyClosed
    }

    class Direction<Stream : AutoCloseable>(
        val raw: Stream,
        var activeCalls: Int = 0,
        var closeState: CloseState = CloseState.Open,
    )

    enum class CloseState {
        Open,
        Deferred,
        InProgress,
        Succeeded,
        Failed,
    }

    private enum class CloseRequest {
        SynchronouslyClosed,
        DeferredOrInProgress,
        Failed,
        RejectedAfterSeal,
    }

    private companion object {
        const val CLOSED_MESSAGE =
            "Dovecot operator process transport is closed"
        const val OPERATION_FAILURE_MESSAGE =
            "Dovecot operator process stream operation failed"
        const val CLOSE_FAILURE_MESSAGE =
            "Dovecot operator process stream close failed"
    }
}

private class ManagedDovecotOperatorProcessTransport(
    private val process: Process,
) : DovecotOperatorTransport {
    private val streamGate = ProcessStreamAdmissionGate()
    private val lifecycleLock = Any()
    private var childStdin:
        ProcessStreamAdmissionGate.GuardedOutputStream? = null
    private var childStdout:
        ProcessStreamAdmissionGate.GuardedInputStream? = null
    private var terminationOutcome: TerminationOutcome? = null
    private val terminationSignalLock = Any()
    private var terminationSignal = TerminationSignal.Available
    private var abortHandshakeReaped: Boolean? = null

    @Volatile
    private var terminal = false

    fun mapProcessStreams() {
        childStdin = streamGate.guard(process.outputStream)
        childStdout = streamGate.guard(process.inputStream)
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
        streamGate.seal()
        terminal = true
        var restoreInterrupt = false
        synchronized(terminationSignalLock) {
            if (terminationSignal == TerminationSignal.Available) {
                terminationSignal = TerminationSignal.AbortInFlight
                val handshake = performAbortProcessHandshake()
                abortHandshakeReaped = handshake.reaped
                restoreInterrupt = handshake.restoreInterrupt
                terminationSignal =
                    TerminationSignal.AbortAcknowledged
            }
        }
        try {
            terminate(
                mode = TerminationMode.Abort,
                failureMessage =
                    "Dovecot operator process transport abort failed",
            )
        } finally {
            if (restoreInterrupt) {
                Thread.currentThread().interrupt()
            }
        }
    }

    override fun close() {
        terminate(
            mode = TerminationMode.NormalClose,
            failureMessage =
                "Dovecot operator process transport close failed",
        )
    }

    fun cleanupRegistrationFailure() {
        try {
            terminate(
                mode = TerminationMode.RegistrationCleanup,
                failureMessage =
                    "Dovecot operator process transport registration cleanup failed",
            )
        } catch (failure: Throwable) {
            restoreInterruptFrom(failure)
        }
    }

    override fun toString(): String =
        "JvmDockerExecDovecotOperatorTransport(redacted)"

    private fun terminate(
        mode: TerminationMode,
        failureMessage: String,
    ) {
        streamGate.seal()
        val outcome = synchronized(lifecycleLock) {
            terminationOutcome ?: run {
                terminal = true
                val performed = performTermination(mode)
                val signalCompletion = synchronized(terminationSignalLock) {
                    val completion = TerminationSignalCompletion(
                        signal = terminationSignal,
                        abortReaped = abortHandshakeReaped,
                    )
                    terminationSignal = TerminationSignal.Completed
                    completion
                }
                performed.copy(
                    reaped =
                        performed.reaped ||
                            signalCompletion.abortReaped == true,
                    terminationRequired =
                        performed.terminationRequired ||
                            signalCompletion.signal ==
                            TerminationSignal.AbortAcknowledged ||
                            signalCompletion.signal ==
                            TerminationSignal.LifecycleDestroy,
                ).also { completed ->
                    terminationOutcome = completed
                }
            }
        }
        val accepted = when (mode) {
            TerminationMode.NormalClose ->
                outcome.reaped &&
                    outcome.naturalExit &&
                    !outcome.terminationRequired &&
                    outcome.streamsClosed &&
                    outcome.exitCode == 0
            TerminationMode.Abort,
            TerminationMode.RegistrationCleanup,
            -> outcome.reaped && outcome.streamsClosed
        }
        if (!accepted) {
            throw IOException(failureMessage)
        }
    }

    private fun performAbortProcessHandshake(): AbortProcessHandshake {
        var restoreInterrupt = Thread.currentThread().isInterrupted

        fun rememberInterruption(failure: Throwable) {
            if (failure is InterruptedException) {
                restoreInterrupt = true
            }
        }

        fun awaitProcess(timeoutMillis: Long): Boolean =
            try {
                process.waitFor(
                    timeoutMillis,
                    TimeUnit.MILLISECONDS,
                )
            } catch (failure: InterruptedException) {
                rememberInterruption(failure)
                false
            } catch (_: Throwable) {
                false
            }

        try {
            process.destroy()
        } catch (failure: Throwable) {
            rememberInterruption(failure)
            // Continue to the bounded force/reap sequence.
        }
        var reaped = awaitProcess(DESTROY_WAIT_MILLIS)
        if (!reaped) {
            try {
                process.destroyForcibly()
            } catch (failure: Throwable) {
                rememberInterruption(failure)
                // The final bounded reap attempt is still mandatory.
            }
            reaped = awaitProcess(FORCE_WAIT_MILLIS)
        }
        return AbortProcessHandshake(
            reaped = reaped,
            restoreInterrupt = restoreInterrupt,
        )
    }

    private fun performTermination(
        initialMode: TerminationMode,
    ): TerminationOutcome {
        var restoreInterrupt = Thread.currentThread().isInterrupted

        fun rememberInterruption(failure: Throwable) {
            if (failure is InterruptedException) {
                restoreInterrupt = true
            }
        }

        fun awaitProcess(timeoutMillis: Long): Boolean =
            try {
                process.waitFor(timeoutMillis, TimeUnit.MILLISECONDS)
            } catch (failure: InterruptedException) {
                rememberInterruption(failure)
                false
            } catch (_: Throwable) {
                false
            }

        fun failedUnreapedAbortOutcome(): TerminationOutcome {
            childStdin = null
            childStdout = null
            return TerminationOutcome(
                reaped = false,
                naturalExit = false,
                terminationRequired = true,
                streamsClosed = false,
                exitCode = null,
            )
        }

        return try {
            var acknowledgedAbortReaped =
                acknowledgedAbortReaped()
            if (acknowledgedAbortReaped == false) {
                return failedUnreapedAbortOutcome()
            }
            val stdinClosed = try {
                childStdin?.requestCloseForLifecycle() ?: true
            } finally {
                childStdin = null
            }
            if (acknowledgedAbortReaped == null) {
                acknowledgedAbortReaped =
                    acknowledgedAbortReaped()
            }
            if (acknowledgedAbortReaped == false) {
                return failedUnreapedAbortOutcome()
            }
            val naturalExit =
                if (
                    acknowledgedAbortReaped == null &&
                    stdinClosed
                ) {
                    awaitProcess(NATURAL_EXIT_WAIT_MILLIS)
                } else {
                    false
                }
            val stdoutClosed = try {
                childStdout?.requestCloseForLifecycle() ?: true
            } finally {
                childStdout = null
            }

            var reaped =
                acknowledgedAbortReaped ?: naturalExit
            if (!reaped) {
                val selection = selectProcessTermination()
                if (selection.abortReaped != null) {
                    reaped = selection.abortReaped
                } else if (selection.lifecycleDestroySelected) {
                    try {
                        process.destroy()
                    } catch (failure: Throwable) {
                        rememberInterruption(failure)
                        // Continue to the bounded force/reap sequence.
                    }
                    reaped = awaitProcess(DESTROY_WAIT_MILLIS)
                    if (!reaped) {
                        try {
                            process.destroyForcibly()
                        } catch (failure: Throwable) {
                            rememberInterruption(failure)
                            // The final bounded reap attempt is still mandatory.
                        }
                        reaped = awaitProcess(FORCE_WAIT_MILLIS)
                    }
                }
            }

            val exitCode =
                if (
                    reaped &&
                    naturalExit &&
                    initialMode != TerminationMode.RegistrationCleanup
                ) {
                    try {
                        process.exitValue()
                    } catch (failure: Throwable) {
                        rememberInterruption(failure)
                        null
                    }
                } else {
                    null
                }
            TerminationOutcome(
                reaped = reaped,
                naturalExit = naturalExit,
                terminationRequired = !naturalExit,
                streamsClosed = stdinClosed && stdoutClosed,
                exitCode = exitCode,
            )
        } finally {
            if (restoreInterrupt) {
                Thread.currentThread().interrupt()
            }
        }
    }

    private fun acknowledgedAbortReaped(): Boolean? =
        synchronized(terminationSignalLock) {
            if (
                terminationSignal ==
                TerminationSignal.AbortAcknowledged
            ) {
                checkNotNull(abortHandshakeReaped)
            } else {
                null
            }
        }

    private fun selectProcessTermination(): ProcessTerminationSelection =
        synchronized(terminationSignalLock) {
            if (
                terminationSignal ==
                TerminationSignal.AbortAcknowledged
            ) {
                ProcessTerminationSelection(
                    lifecycleDestroySelected = false,
                    abortReaped = checkNotNull(abortHandshakeReaped),
                )
            } else if (
                terminationSignal ==
                TerminationSignal.Available
            ) {
                terminationSignal =
                    TerminationSignal.LifecycleDestroy
                ProcessTerminationSelection(
                    lifecycleDestroySelected = true,
                    abortReaped = null,
                )
            } else {
                ProcessTerminationSelection(
                    lifecycleDestroySelected = false,
                    abortReaped = null,
                )
            }
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

    private enum class TerminationSignal {
        Available,
        AbortInFlight,
        AbortAcknowledged,
        LifecycleDestroy,
        Completed,
    }

    private data class TerminationOutcome(
        val reaped: Boolean,
        val naturalExit: Boolean,
        val terminationRequired: Boolean,
        val streamsClosed: Boolean,
        val exitCode: Int?,
    )

    private data class AbortProcessHandshake(
        val reaped: Boolean,
        val restoreInterrupt: Boolean,
    )

    private data class TerminationSignalCompletion(
        val signal: TerminationSignal,
        val abortReaped: Boolean?,
    )

    private data class ProcessTerminationSelection(
        val lifecycleDestroySelected: Boolean,
        val abortReaped: Boolean?,
    )
}

private fun restoreInterruptFrom(failure: Throwable) {
    if (failure is InterruptedException) {
        Thread.currentThread().interrupt()
    }
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
