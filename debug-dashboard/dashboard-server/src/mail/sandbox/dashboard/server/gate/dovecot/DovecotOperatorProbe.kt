package mail.sandbox.dashboard.server.gate.dovecot

import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketTimeoutException
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.BasicFileAttributes
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.CertificateFactory
import java.time.Duration
import java.util.Base64
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory

internal class DovecotOperatorTarget private constructor(
    internal val address: String,
) {
    override fun toString(): String = "DovecotOperatorTarget(redacted)"

    companion object {
        fun create(address: String): DovecotOperatorTarget =
            DovecotOperatorTarget(EligibilityAddress.requireCanonical(address))
    }
}

internal enum class DovecotOperatorProbeResult {
    Success,
    AuthenticationFailure,
    ProtocolFailure,
    TransportFailure,
}

internal fun interface DovecotOperatorProbeClock {
    fun nanoTime(): Long
}

internal fun interface DovecotOperatorTransportFactory {
    @Throws(IOException::class)
    fun open(
        registerAllocated: (DovecotOperatorTransport) -> Unit,
    ): DovecotOperatorTransport
}

internal interface DovecotOperatorTransport : AutoCloseable {
    val input: InputStream
    val outputStream: OutputStream

    fun abort()
}

internal fun interface DovecotOperatorProbeWatchdog {
    fun arm(onDeadline: () -> Unit): AutoCloseable
}

internal class DovecotOperatorProbe(
    private val transportFactory: DovecotOperatorTransportFactory =
        JvmJsseDovecotOperatorTransportFactory.production(),
    private val clock: DovecotOperatorProbeClock =
        DovecotOperatorProbeClock(System::nanoTime),
    private val watchdog: DovecotOperatorProbeWatchdog =
        JvmDovecotOperatorProbeWatchdog,
) {
    fun probe(
        target: DovecotOperatorTarget,
        credential: DovecotOperatorCredential,
    ): DovecotOperatorProbeResult {
        val transport = AtomicReference<DovecotOperatorTransport?>()
        val openFuture =
            AtomicReference<Future<DovecotOperatorTransport>?>()
        val timedOut = AtomicBoolean()
        val abandoned = AtomicBoolean()
        var watchdogHandle: AutoCloseable? = null
        return try {
            val deadline = clock.nanoTime() + TOTAL_DEADLINE.toNanos()
            watchdogHandle = watchdog.arm {
                timedOut.set(true)
                abandoned.set(true)
                openFuture.get()?.cancel(true)
                transport.get()?.let(::abortTransport)
            }
            requireBeforeDeadline(deadline)
            val pendingOpen = OPEN_EXECUTOR.submit<DovecotOperatorTransport> {
                val candidate = transportFactory.open { allocated ->
                    if (!transport.compareAndSet(null, allocated)) {
                        abortAndClose(allocated)
                        throw IOException(
                            "Dovecot operator transport allocation is invalid",
                        )
                    }
                    if (abandoned.get()) {
                        abortTransport(allocated)
                    }
                }
                if (transport.get() !== candidate) {
                    abortAndClose(candidate)
                    throw IOException(
                        "Dovecot operator transport allocation is invalid",
                    )
                }
                if (abandoned.get()) {
                    abortAndClose(candidate)
                    throw SocketTimeoutException(
                        "Dovecot operator probe timed out",
                    )
                }
                candidate
            }
            openFuture.set(pendingOpen)
            if (timedOut.get()) {
                pendingOpen.cancel(true)
            }
            val opened = try {
                pendingOpen.get(
                    TOTAL_DEADLINE.toMillis(),
                    TimeUnit.MILLISECONDS,
                )
            } catch (failure: TimeoutException) {
                timedOut.set(true)
                abandoned.set(true)
                pendingOpen.cancel(true)
                throw SocketTimeoutException(
                    "Dovecot operator probe timed out",
                )
            } catch (failure: InterruptedException) {
                abandoned.set(true)
                pendingOpen.cancel(true)
                Thread.currentThread().interrupt()
                throw failure
            }
            if (timedOut.get()) {
                abortTransport(opened)
                throw SocketTimeoutException(
                    "Dovecot operator probe timed out",
                )
            }
            requireBeforeDeadline(deadline)
            requireGreeting(opened.input, deadline)

            authenticateLogin(
                input = opened.input,
                output = opened.outputStream,
                target = target,
                credential = credential,
                deadline = deadline,
            )
            when (
                readTaggedCompletion(
                    input = opened.input,
                    tag = LOGIN_TAG,
                    deadline = deadline,
                )
            ) {
                TaggedCompletion.Ok -> Unit
                TaggedCompletion.No ->
                    return DovecotOperatorProbeResult.AuthenticationFailure
                TaggedCompletion.Bad ->
                    return DovecotOperatorProbeResult.ProtocolFailure
            }

            writeFixedCommand(
                output = opened.outputStream,
                command = LIST_COMMAND,
                deadline = deadline,
            )
            when (
                readTaggedCompletion(
                    input = opened.input,
                    tag = LIST_TAG,
                    deadline = deadline,
                    requiredUntaggedPrefix = LIST_RESPONSE_PREFIX,
                )
            ) {
                TaggedCompletion.Ok -> {
                    requireBeforeDeadline(deadline)
                    if (timedOut.get()) {
                        throw SocketTimeoutException(
                            "Dovecot operator probe timed out",
                        )
                    }
                    DovecotOperatorProbeResult.Success
                }
                TaggedCompletion.No,
                TaggedCompletion.Bad,
                -> DovecotOperatorProbeResult.ProtocolFailure
            }
        } catch (_: DovecotOperatorProtocolException) {
            DovecotOperatorProbeResult.ProtocolFailure
        } catch (_: Exception) {
            DovecotOperatorProbeResult.TransportFailure
        } finally {
            credential.close()
            abandoned.set(true)
            openFuture.get()?.cancel(true)
            transport.get()?.let(::abortAndClose)
            runCatching { watchdogHandle?.close() }
        }
    }

    private fun requireGreeting(
        input: InputStream,
        deadline: Long,
    ) {
        readLine(input, deadline).useBytes { line ->
            if (!line.startsWithToken(GREETING_OK)) {
                throw DovecotOperatorProtocolException()
            }
        }
    }

    private fun readTaggedCompletion(
        input: InputStream,
        tag: ByteArray,
        deadline: Long,
        requiredUntaggedPrefix: ByteArray? = null,
    ): TaggedCompletion {
        var sawRequiredUntagged = requiredUntaggedPrefix == null
        repeat(MAX_RESPONSE_LINES) {
            readLine(input, deadline).useBytes { line ->
                if (
                    requiredUntaggedPrefix != null &&
                    line.startsWithToken(requiredUntaggedPrefix)
                ) {
                    sawRequiredUntagged = true
                }
                if (line.startsWithToken(tag)) {
                    if (!sawRequiredUntagged) {
                        throw DovecotOperatorProtocolException()
                    }
                    val statusOffset = tag.size + 1
                    return when {
                        line.hasTokenAt(statusOffset, STATUS_OK) ->
                            TaggedCompletion.Ok
                        line.hasTokenAt(statusOffset, STATUS_NO) ->
                            TaggedCompletion.No
                        line.hasTokenAt(statusOffset, STATUS_BAD) ->
                            TaggedCompletion.Bad
                        else -> throw DovecotOperatorProtocolException()
                    }
                }
            }
        }
        throw DovecotOperatorProtocolException()
    }

    private fun readLine(
        input: InputStream,
        deadline: Long,
    ): ByteArray {
        val buffer = ByteArray(MAX_LINE_BYTES + 1)
        var size = 0
        try {
            while (true) {
                requireBeforeDeadline(deadline)
                val value = input.read()
                requireBeforeDeadline(deadline)
                if (value < 0) {
                    throw IOException("Dovecot operator response was truncated")
                }
                if (value == LINE_FEED) {
                    if (
                        size == 0 ||
                        buffer[size - 1] != CARRIAGE_RETURN.toByte()
                    ) {
                        throw DovecotOperatorProtocolException()
                    }
                    return buffer.copyOf(size - 1)
                }
                if (size == buffer.size) {
                    throw DovecotOperatorProtocolException()
                }
                buffer[size] = value.toByte()
                size += 1
            }
        } finally {
            buffer.fill(0)
        }
    }

    private fun authenticateLogin(
        input: InputStream,
        output: OutputStream,
        target: DovecotOperatorTarget,
        credential: DovecotOperatorCredential,
        deadline: Long,
    ) {
        writeFixedCommand(
            output = output,
            command = AUTHENTICATE_LOGIN_COMMAND,
            deadline = deadline,
        )
        requireContinuation(
            input = input,
            expected = USERNAME_CHALLENGE,
            deadline = deadline,
        )
        writeCombinedUsername(
            output = output,
            target = target,
            credential = credential,
            deadline = deadline,
        )
        requireContinuation(
            input = input,
            expected = PASSWORD_CHALLENGE,
            deadline = deadline,
        )
        credential.withSecretBytes { secret ->
            writeBase64Response(
                output = output,
                raw = secret,
                deadline = deadline,
            )
        }
    }

    private fun requireContinuation(
        input: InputStream,
        expected: ByteArray,
        deadline: Long,
    ) {
        readLine(input, deadline).useBytes { line ->
            if (!line.contentEquals(expected)) {
                throw DovecotOperatorProtocolException()
            }
        }
    }

    private fun writeCombinedUsername(
        output: OutputStream,
        target: DovecotOperatorTarget,
        credential: DovecotOperatorCredential,
        deadline: Long,
    ) {
        val targetBytes = target.address.toByteArray(Charsets.US_ASCII)
        val masterBytes =
            credential.id.masterUsername.toByteArray(Charsets.US_ASCII)
        val combined = ByteArray(
            targetBytes.size +
                MASTER_SEPARATOR.size +
                masterBytes.size,
        )
        try {
            var offset = 0
            offset = combined.copyAt(offset, targetBytes)
            offset = combined.copyAt(offset, MASTER_SEPARATOR)
            combined.copyAt(offset, masterBytes)
            writeBase64Response(
                output = output,
                raw = combined,
                deadline = deadline,
            )
        } finally {
            targetBytes.fill(0)
            masterBytes.fill(0)
            combined.fill(0)
        }
    }

    private fun writeBase64Response(
        output: OutputStream,
        raw: ByteArray,
        deadline: Long,
    ) {
        val encoded = BASE64_ENCODER.encode(raw)
        val line = ByteArray(encoded.size + CRLF.size)
        try {
            check(encoded.size <= MAX_AUTH_RESPONSE_BYTES) {
                "Dovecot operator authentication response exceeded its bound"
            }
            encoded.copyInto(line)
            CRLF.copyInto(line, destinationOffset = encoded.size)
            writeCommand(output, line, deadline)
        } finally {
            encoded.fill(0)
            line.fill(0)
        }
    }

    private fun writeFixedCommand(
        output: OutputStream,
        command: ByteArray,
        deadline: Long,
    ) {
        val copy = command.copyOf()
        try {
            writeCommand(output, copy, deadline)
        } finally {
            copy.fill(0)
        }
    }

    private fun writeCommand(
        output: OutputStream,
        command: ByteArray,
        deadline: Long,
    ) {
        requireBeforeDeadline(deadline)
        output.write(command, 0, command.size)
        output.flush()
        requireBeforeDeadline(deadline)
    }

    private fun requireBeforeDeadline(deadline: Long) {
        if (clock.nanoTime() - deadline >= 0) {
            throw SocketTimeoutException("Dovecot operator probe timed out")
        }
    }

    private fun abortAndClose(transport: DovecotOperatorTransport) {
        abortTransport(transport)
        try {
            transport.close()
        } catch (_: Exception) {
            // Close failures cannot safely replace the redacted probe result.
        }
    }

    private fun abortTransport(transport: DovecotOperatorTransport) {
        try {
            transport.abort()
        } catch (_: Exception) {
            // The fixed JSSE abort is socket.close(); preserve redacted results.
        }
    }

    private enum class TaggedCompletion {
        Ok,
        No,
        Bad,
    }

    companion object {
        private val TOTAL_DEADLINE = Duration.ofSeconds(5)
        private val OPEN_EXECUTOR = ThreadPoolExecutor(
            0,
            2,
            30,
            TimeUnit.SECONDS,
            SynchronousQueue(),
            { runnable ->
                Thread(runnable, "dovecot-operator-probe-open").also {
                    it.isDaemon = true
                }
            },
            ThreadPoolExecutor.AbortPolicy(),
        )
        private const val MAX_LINE_BYTES = 16 * 1024
        private const val MAX_RESPONSE_LINES = 64
        private const val LINE_FEED = 0x0a
        private const val CARRIAGE_RETURN = 0x0d

        private val GREETING_OK = ascii("* OK")
        private val LOGIN_TAG = ascii("A001")
        private val LIST_TAG = ascii("A002")
        private val LIST_RESPONSE_PREFIX = ascii("* LIST")
        private val STATUS_OK = ascii("OK")
        private val STATUS_NO = ascii("NO")
        private val STATUS_BAD = ascii("BAD")
        private val AUTHENTICATE_LOGIN_COMMAND =
            ascii("A001 AUTHENTICATE LOGIN\r\n")
        private val USERNAME_CHALLENGE = ascii("+ VXNlcm5hbWU6")
        private val PASSWORD_CHALLENGE = ascii("+ UGFzc3dvcmQ6")
        private val MASTER_SEPARATOR = ascii("*")
        private val CRLF = ascii("\r\n")
        private val LIST_COMMAND = ascii("A002 LIST \"\" \"INBOX\"\r\n")
        private val BASE64_ENCODER = Base64.getEncoder()
        private const val MAX_AUTH_RESPONSE_BYTES = 1024
        private fun ascii(value: String): ByteArray =
            value.toByteArray(Charsets.US_ASCII)
    }
}

private object JvmDovecotOperatorProbeWatchdog :
    DovecotOperatorProbeWatchdog {
    override fun arm(onDeadline: () -> Unit): AutoCloseable {
        val future = SCHEDULER.schedule(
            onDeadline,
            WATCHDOG_DELAY_SECONDS,
            TimeUnit.SECONDS,
        )
        return AutoCloseable {
            future.cancel(false)
        }
    }

    private const val WATCHDOG_DELAY_SECONDS = 5L
    private val SCHEDULER = Executors.newSingleThreadScheduledExecutor {
        runnable ->
        Thread(runnable, "dovecot-operator-probe-watchdog").also {
            it.isDaemon = true
        }
    }
}

internal class JvmJsseDovecotOperatorTransportFactory private constructor(
    private val certificatePath: Path,
    private val proofProfile: DovecotTask5ProofProfile?,
) : DovecotOperatorTransportFactory {
    override fun open(
        registerAllocated: (DovecotOperatorTransport) -> Unit,
    ): DovecotOperatorTransport {
        val certificateBytes = proofProfile?.readStableTlsCertificate() ?:
            readBoundedStableCertificate(certificatePath)
        val certificate = try {
            ByteArrayInputStream(certificateBytes).use { input ->
                CertificateFactory
                    .getInstance("X.509")
                    .generateCertificate(input)
            }
        } finally {
            certificateBytes.fill(0)
        }
        val keyStore = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null, null)
            setCertificateEntry("dovecot-operator", certificate)
        }
        val trustManagers =
            TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
                .apply { init(keyStore) }
                .trustManagers
        val sslContext = SSLContext.getInstance("TLS").apply {
            init(null, trustManagers, SecureRandom())
        }
        val socket = sslContext.socketFactory.createSocket() as SSLSocket
        val transport = JvmJsseDovecotOperatorTransport(socket)
        registerAllocated(transport)
        return try {
            socket.enabledProtocols = socket.enabledProtocols.filter { protocol ->
                protocol == "TLSv1.3" || protocol == "TLSv1.2"
            }.toTypedArray()
            socket.soTimeout = SOCKET_TIMEOUT_MILLIS
            socket.connect(LOOPBACK_ENDPOINT, SOCKET_TIMEOUT_MILLIS)
            socket.startHandshake()
            transport
        } catch (failure: Exception) {
            try {
                socket.close()
            } catch (_: Exception) {
                // Preserve the transport setup failure without retaining details.
            }
            throw failure
        }
    }

    override fun toString(): String =
        "JvmJsseDovecotOperatorTransportFactory(fixed, redacted)"

    companion object {
        private const val OPERATOR_TLS_PORT = 2993
        private const val SOCKET_TIMEOUT_MILLIS = 1_000
        private val LOOPBACK_ENDPOINT = InetSocketAddress(
            InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)),
            OPERATOR_TLS_PORT,
        )

        fun production(): JvmJsseDovecotOperatorTransportFactory {
            val repositoryRoot =
                DovecotOperatorPaths.production().repositoryRoot
            return JvmJsseDovecotOperatorTransportFactory(
                repositoryRoot.resolve("ssl/tls.crt"),
                proofProfile = null,
            )
        }

        fun task5Proof(
            profile: DovecotTask5ProofProfile,
        ): JvmJsseDovecotOperatorTransportFactory =
            JvmJsseDovecotOperatorTransportFactory(
                profile.tlsCertificate,
                proofProfile = profile,
            )
    }
}

private class JvmJsseDovecotOperatorTransport(
    private val socket: SSLSocket,
) : DovecotOperatorTransport {
    override val input: InputStream
        get() = socket.inputStream

    override val outputStream: OutputStream
        get() = socket.outputStream

    override fun abort() = socket.close()

    override fun close() = socket.close()

    override fun toString(): String =
        "JvmJsseDovecotOperatorTransport(redacted)"
}

private class DovecotOperatorProtocolException : IOException()

private inline fun <T> ByteArray.useBytes(block: (ByteArray) -> T): T =
    try {
        block(this)
    } finally {
        fill(0)
    }

private fun ByteArray.copyAt(
    offset: Int,
    source: ByteArray,
): Int {
    source.copyInto(this, destinationOffset = offset)
    return offset + source.size
}

private fun ByteArray.startsWithToken(token: ByteArray): Boolean =
    hasTokenAt(0, token)

private fun ByteArray.hasTokenAt(
    offset: Int,
    token: ByteArray,
): Boolean {
    if (
        offset < 0 ||
        size < offset + token.size ||
        (offset > 0 && this[offset - 1] != ' '.code.toByte())
    ) {
        return false
    }
    token.indices.forEach { index ->
        val actual = this[offset + index]
        val expected = token[index]
        if (actual.asciiUppercase() != expected.asciiUppercase()) {
            return false
        }
    }
    val end = offset + token.size
    return end == size || this[end] == ' '.code.toByte()
}

private fun Byte.asciiUppercase(): Byte =
    if (this in 'a'.code.toByte()..'z'.code.toByte()) {
        (toInt() - ASCII_CASE_OFFSET).toByte()
    } else {
        this
    }

private const val ASCII_CASE_OFFSET = 'a'.code - 'A'.code

private fun readBoundedStableCertificate(path: Path): ByteArray {
    if (
        !path.isAbsolute ||
        path.normalize() != path ||
        !Files.isDirectory(
            requireNotNull(path.parent),
            LinkOption.NOFOLLOW_LINKS,
        ) ||
        Files.isSymbolicLink(path.parent) ||
        path.parent.toRealPath() != path.parent ||
        !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) ||
        Files.isSymbolicLink(path) ||
        path.toRealPath() != path
    ) {
        throw IOException("Dovecot operator trust anchor is invalid")
    }
    val before = Files.readAttributes(
        path,
        BasicFileAttributes::class.java,
        LinkOption.NOFOLLOW_LINKS,
    )
    if (before.size() !in 1..MAX_TLS_CERTIFICATE_BYTES) {
        throw IOException("Dovecot operator trust anchor is invalid")
    }
    val bytes = Files.newInputStream(
        path,
        LinkOption.NOFOLLOW_LINKS,
    ).use { input ->
        input.readNBytes(MAX_TLS_CERTIFICATE_BYTES + 1)
    }
    try {
        val after = Files.readAttributes(
            path,
            BasicFileAttributes::class.java,
            LinkOption.NOFOLLOW_LINKS,
        )
        if (
            bytes.size.toLong() != before.size() ||
            !after.isRegularFile ||
            before.fileKey() != after.fileKey() ||
            before.size() != after.size() ||
            before.lastModifiedTime() != after.lastModifiedTime()
        ) {
            throw IOException("Dovecot operator trust anchor changed")
        }
        return bytes
    } catch (failure: Throwable) {
        bytes.fill(0)
        throw failure
    }
}

private const val MAX_TLS_CERTIFICATE_BYTES = 64 * 1024
