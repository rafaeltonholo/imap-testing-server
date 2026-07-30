package mail.sandbox.dashboard.server.gate.dovecot

import java.io.IOException
import java.net.SocketTimeoutException
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.util.Base64
import java.util.concurrent.ExecutionException
import java.util.concurrent.Future
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

internal class HeldDovecotOperatorImapSession private constructor(
    private val transport: DovecotOperatorTransport,
) : AutoCloseable {
    private val closed = AtomicBoolean()

    val isClosed: Boolean
        get() = closed.get()

    @Synchronized
    fun requireUsable(timeout: Duration = SESSION_TIMEOUT) {
        check(!closed.get()) {
            "Held Dovecot operator session is closed"
        }
        val deadline = DovecotTask6ProofDeadline(timeout) {
            closeFromDeadline()
        }
        try {
            writeFixed(
                transport,
                USABILITY_NOOP_COMMAND,
                deadline,
            )
            requireTaggedOkay(
                transport,
                USABILITY_NOOP_TAG,
                deadline,
            )
            deadline.complete()
        } catch (interrupted: InterruptedException) {
            closeFromDeadline()
            Thread.currentThread().interrupt()
            throw interrupted
        } catch (_: Throwable) {
            closeFromDeadline()
            error("Held Dovecot operator usability proof failed")
        } finally {
            deadline.close()
        }
    }

    fun requireClosedAndUnusable(timeout: Duration = SESSION_TIMEOUT) {
        check(closed.get()) {
            "Held Dovecot operator session remains open"
        }
        val deadline = DovecotTask6ProofDeadline(timeout) {
            abortAndClose(transport)
        }
        val command = CLOSED_SESSION_NOOP_COMMAND.copyOf()
        try {
            val rejected = try {
                deadline.requireRemaining()
                transport.outputStream.write(command)
                deadline.requireRemaining()
                transport.outputStream.flush()
                deadline.requireRemaining()
                false
            } catch (interrupted: InterruptedException) {
                Thread.currentThread().interrupt()
                throw interrupted
            } catch (_: Exception) {
                true
            }
            if (rejected) {
                return
            }
            deadline.complete()
            error("Closed Dovecot operator transport remained usable")
        } finally {
            command.fill(0)
            deadline.close()
        }
    }

    @Synchronized
    override fun close() {
        if (closed.get()) return
        transport.close()
        closed.set(true)
    }

    private fun closeFromDeadline() {
        if (abortAndClose(transport)) {
            closed.set(true)
        }
    }

    companion object {
        fun openAndSeed(
            transportFactory: DovecotOperatorTransportFactory,
            target: DovecotOperatorTarget,
            credential: DovecotOperatorCredential,
            message: ByteArray,
            timeout: Duration = SESSION_TIMEOUT,
        ): HeldDovecotOperatorImapSession {
            val allocated =
                AtomicReference<DovecotOperatorTransport?>()
            val returned =
                AtomicReference<DovecotOperatorTransport?>()
            val pending =
                AtomicReference<Future<DovecotOperatorTransport>?>()
            val abandoned = AtomicBoolean()
            val invalidAllocation = AtomicBoolean()
            var deadline: DovecotTask6ProofDeadline? = null
            try {
                val operationDeadline = DovecotTask6ProofDeadline(timeout) {
                    abandoned.set(true)
                    pending.get()?.cancel(true)
                    allocated.get()?.let(::abortAndClose)
                }
                deadline = operationDeadline
                requireValidMessage(message)
                operationDeadline.requireRemaining()
                val openFuture = try {
                    OPEN_EXECUTOR.submit<DovecotOperatorTransport> {
                        val opened = transportFactory.open { candidate ->
                            if (
                                !allocated.compareAndSet(null, candidate)
                            ) {
                                invalidAllocation.set(true)
                                abortAndClose(candidate)
                                error(
                                    "Held Dovecot operator transport " +
                                        "allocation is invalid",
                                )
                            }
                            if (abandoned.get()) {
                                abortAndClose(candidate)
                                error(
                                    "Held Dovecot operator open was abandoned",
                                )
                            }
                        }
                        returned.set(opened)
                        if (
                            invalidAllocation.get() ||
                            allocated.get() !== opened
                        ) {
                            abortAndClose(opened)
                            error(
                                "Held Dovecot operator transport " +
                                    "allocation is invalid",
                            )
                        }
                        if (abandoned.get()) {
                            abortAndClose(opened)
                            throw SocketTimeoutException(
                                "Held Dovecot operator open timed out",
                            )
                        }
                        opened
                    }
                } catch (_: RejectedExecutionException) {
                    error(
                        "Held Dovecot operator open capacity was exhausted",
                    )
                }
                pending.set(openFuture)
                if (abandoned.get()) {
                    openFuture.cancel(true)
                }
                val opened = try {
                    openFuture.get(
                        operationDeadline.remainingNanos(),
                        TimeUnit.NANOSECONDS,
                    )
                } catch (_: TimeoutException) {
                    operationDeadline.expireNow()
                } catch (_: InterruptedException) {
                    abandoned.set(true)
                    openFuture.cancel(true)
                    Thread.currentThread().interrupt()
                    throw InterruptedException(
                        "Held Dovecot operator open was interrupted",
                    )
                } catch (failure: ExecutionException) {
                    throwOpenFailure(failure.cause)
                }
                operationDeadline.requireRemaining()
                requireGreeting(opened, operationDeadline)
                authenticate(
                    transport = opened,
                    target = target,
                    credential = credential,
                    deadline = operationDeadline,
                )
                appendMessage(opened, message, operationDeadline)
                operationDeadline.complete()
                return HeldDovecotOperatorImapSession(opened)
            } catch (failure: Throwable) {
                abandoned.set(true)
                pending.get()?.cancel(true)
                abortDistinct(
                    returned.get(),
                    allocated.get(),
                )
                when (failure) {
                    is InterruptedException -> {
                        Thread.currentThread().interrupt()
                        throw failure
                    }
                    is IllegalArgumentException -> throw failure
                    is IllegalStateException -> throw failure
                    else -> error(
                        "Held Dovecot operator seed proof failed",
                    )
                }
            } finally {
                deadline?.close()
                credential.close()
                message.fill(0)
            }
        }

        private fun requireGreeting(
            transport: DovecotOperatorTransport,
            deadline: DovecotTask6ProofDeadline,
        ) {
            readLine(transport, deadline).useWiped { line ->
                check(line.hasAsciiTokenAt(0, "* OK")) {
                    "Held Dovecot operator greeting was invalid"
                }
            }
        }

        private fun authenticate(
            transport: DovecotOperatorTransport,
            target: DovecotOperatorTarget,
            credential: DovecotOperatorCredential,
            deadline: DovecotTask6ProofDeadline,
        ) {
            writeFixed(
                transport,
                AUTHENTICATE_LOGIN_COMMAND,
                deadline,
            )
            requireExactLine(
                transport,
                USERNAME_CHALLENGE,
                deadline,
            )
            writeCombinedUsername(
                transport,
                target,
                credential.id,
                deadline,
            )
            requireExactLine(
                transport,
                PASSWORD_CHALLENGE,
                deadline,
            )
            credential.withSecretBytes { secret ->
                writeBase64(transport, secret, deadline)
            }
            requireTaggedOkay(transport, "A001", deadline)
        }

        private fun appendMessage(
            transport: DovecotOperatorTransport,
            message: ByteArray,
            deadline: DovecotTask6ProofDeadline,
        ) {
            val appendCommand = (
                "A002 APPEND \"INBOX\" {${message.size}}\r\n"
                ).toByteArray(StandardCharsets.US_ASCII)
            try {
                write(transport, appendCommand, deadline)
            } finally {
                appendCommand.fill(0)
            }
            readLine(transport, deadline).useWiped { continuation ->
                check(
                    continuation.isNotEmpty() &&
                        continuation[0] == '+'.code.toByte(),
                ) {
                    "Held Dovecot operator APPEND continuation was invalid"
                }
            }
            write(transport, message, deadline, appendCrlf = true)
            requireTaggedOkay(transport, "A002", deadline)
        }

        private fun writeCombinedUsername(
            transport: DovecotOperatorTransport,
            target: DovecotOperatorTarget,
            id: DovecotOperatorId,
            deadline: DovecotTask6ProofDeadline,
        ) {
            val targetBytes = target.address.toByteArray(
                StandardCharsets.US_ASCII,
            )
            val masterBytes = id.masterUsername.toByteArray(
                StandardCharsets.US_ASCII,
            )
            val combined = ByteArray(
                targetBytes.size + 1 + masterBytes.size,
            )
            try {
                targetBytes.copyInto(combined)
                combined[targetBytes.size] = '*'.code.toByte()
                masterBytes.copyInto(
                    combined,
                    destinationOffset = targetBytes.size + 1,
                )
                writeBase64(transport, combined, deadline)
            } finally {
                targetBytes.fill(0)
                masterBytes.fill(0)
                combined.fill(0)
            }
        }

        private fun writeBase64(
            transport: DovecotOperatorTransport,
            raw: ByteArray,
            deadline: DovecotTask6ProofDeadline,
        ) {
            val encoded = Base64.getEncoder().encode(raw)
            val line = ByteArray(encoded.size + CRLF.size)
            try {
                check(encoded.size <= MAX_AUTH_RESPONSE_BYTES) {
                    "Held Dovecot operator authentication exceeded its bound"
                }
                encoded.copyInto(line)
                CRLF.copyInto(line, destinationOffset = encoded.size)
                write(transport, line, deadline)
            } finally {
                encoded.fill(0)
                line.fill(0)
            }
        }

        private fun writeFixed(
            transport: DovecotOperatorTransport,
            command: ByteArray,
            deadline: DovecotTask6ProofDeadline,
        ) {
            val copy = command.copyOf()
            try {
                write(transport, copy, deadline)
            } finally {
                copy.fill(0)
            }
        }

        private fun write(
            transport: DovecotOperatorTransport,
            bytes: ByteArray,
            deadline: DovecotTask6ProofDeadline,
            appendCrlf: Boolean = false,
        ) {
            deadline.requireRemaining()
            transport.outputStream.write(bytes)
            deadline.requireRemaining()
            if (appendCrlf) {
                transport.outputStream.write(CRLF)
                deadline.requireRemaining()
            }
            transport.outputStream.flush()
            deadline.requireRemaining()
        }

        private fun requireExactLine(
            transport: DovecotOperatorTransport,
            expected: ByteArray,
            deadline: DovecotTask6ProofDeadline,
        ) {
            readLine(transport, deadline).useWiped { line ->
                check(line.contentEquals(expected)) {
                    "Held Dovecot operator continuation was invalid"
                }
            }
        }

        private fun requireTaggedOkay(
            transport: DovecotOperatorTransport,
            tag: String,
            deadline: DovecotTask6ProofDeadline,
        ) {
            repeat(MAX_RESPONSE_LINES) {
                readLine(transport, deadline).useWiped { line ->
                    if (line.hasAsciiTokenAt(0, tag)) {
                        check(line.hasAsciiTokenAt(tag.length + 1, "OK")) {
                            "Held Dovecot operator command failed"
                        }
                        return
                    }
                }
            }
            error("Held Dovecot operator response exceeded its bound")
        }

        private fun readLine(
            transport: DovecotOperatorTransport,
            deadline: DovecotTask6ProofDeadline,
        ): ByteArray {
            val buffer = ByteArray(MAX_LINE_BYTES + 1)
            var size = 0
            try {
                while (true) {
                    deadline.requireRemaining()
                    val value = transport.input.read()
                    deadline.requireRemaining()
                    if (value < 0) {
                        throw IOException(
                            "Held Dovecot operator response was truncated",
                        )
                    }
                    if (value == '\n'.code) {
                        check(
                            size > 0 &&
                                buffer[size - 1] == '\r'.code.toByte(),
                        ) {
                            "Held Dovecot operator response was invalid"
                        }
                        return buffer.copyOf(size - 1)
                    }
                    check(size < buffer.size) {
                        "Held Dovecot operator response exceeded its bound"
                    }
                    buffer[size] = value.toByte()
                    size += 1
                }
            } finally {
                buffer.fill(0)
            }
        }

        private fun requireValidMessage(message: ByteArray) {
            require(message.size in 1..MAX_MESSAGE_BYTES) {
                "Held Dovecot seed message size is invalid"
            }
            require(
                message.all { byte ->
                    byte == '\r'.code.toByte() ||
                        byte == '\n'.code.toByte() ||
                        byte == '\t'.code.toByte() ||
                        byte.toInt() in 0x20..0x7e
                },
            ) {
                "Held Dovecot seed message encoding is invalid"
            }
            require(message.hasOnlyCrlfLineEndings()) {
                "Held Dovecot seed message line endings are invalid"
            }
            val headerEnd = message.indexOfBytes(CRLF_CRLF)
            require(
                headerEnd > 0 &&
                    message.endsWithBytes(CRLF) &&
                    REQUIRED_MESSAGE_HEADERS.all { header ->
                        message.countHeader(
                            header = header,
                            headerEnd = headerEnd,
                        ) == 1
                    },
            ) {
                "Held Dovecot seed message format is invalid"
            }
        }

        private fun ByteArray.hasOnlyCrlfLineEndings(): Boolean {
            indices.forEach { index ->
                when (this[index]) {
                    '\r'.code.toByte() -> {
                        if (
                            index == lastIndex ||
                            this[index + 1] != '\n'.code.toByte()
                        ) {
                            return false
                        }
                    }
                    '\n'.code.toByte() -> {
                        if (
                            index == 0 ||
                            this[index - 1] != '\r'.code.toByte()
                        ) {
                            return false
                        }
                    }
                }
            }
            return true
        }

        private fun ByteArray.countHeader(
            header: ByteArray,
            headerEnd: Int,
        ): Int {
            var count = 0
            var lineStart = 0
            while (lineStart < headerEnd) {
                if (
                    size - lineStart >= header.size + 1 &&
                    header.indices.all { index ->
                        this[lineStart + index] == header[index]
                    } &&
                    this[lineStart + header.size] == ':'.code.toByte()
                ) {
                    count += 1
                }
                val lineEnd = indexOfBytes(CRLF, lineStart)
                if (lineEnd < 0 || lineEnd >= headerEnd) break
                lineStart = lineEnd + CRLF.size
            }
            return count
        }

        private fun ByteArray.indexOfBytes(
            candidate: ByteArray,
            start: Int = 0,
        ): Int {
            if (
                candidate.isEmpty() ||
                start < 0 ||
                size - start < candidate.size
            ) {
                return -1
            }
            for (offset in start..size - candidate.size) {
                if (
                    candidate.indices.all { index ->
                        this[offset + index] == candidate[index]
                    }
                ) {
                    return offset
                }
            }
            return -1
        }

        private fun ByteArray.endsWithBytes(candidate: ByteArray): Boolean =
            size >= candidate.size &&
                candidate.indices.all { index ->
                    this[size - candidate.size + index] == candidate[index]
                }

        private fun abortDistinct(
            first: DovecotOperatorTransport?,
            second: DovecotOperatorTransport?,
        ) {
            first?.let(::abortAndClose)
            if (second != null && second !== first) {
                abortAndClose(second)
            }
        }

        private fun abortAndClose(
            transport: DovecotOperatorTransport,
        ): Boolean {
            val aborted = runCatching { transport.abort() }.isSuccess
            val closed = runCatching { transport.close() }.isSuccess
            return aborted || closed
        }

        private fun throwOpenFailure(failure: Throwable?): Nothing {
            when (failure) {
                is IllegalArgumentException -> throw failure
                is IllegalStateException -> throw failure
                else -> error("Held Dovecot operator open failed")
            }
        }

        private inline fun <T> ByteArray.useWiped(
            block: (ByteArray) -> T,
        ): T = try {
            block(this)
        } finally {
            fill(0)
        }

        private fun ByteArray.hasAsciiTokenAt(
            offset: Int,
            token: String,
        ): Boolean {
            if (
                offset < 0 ||
                size < offset + token.length ||
                (offset > 0 && this[offset - 1] != ' '.code.toByte())
            ) {
                return false
            }
            token.indices.forEach { index ->
                if (this[offset + index] != token[index].code.toByte()) {
                    return false
                }
            }
            val end = offset + token.length
            return end == size || this[end] == ' '.code.toByte()
        }

        private val SESSION_TIMEOUT = Duration.ofSeconds(5)
        private val OPEN_EXECUTOR = ThreadPoolExecutor(
            0,
            4,
            30,
            TimeUnit.SECONDS,
            SynchronousQueue(),
            { runnable ->
                Thread(runnable, "dovecot-held-session-open").also {
                    it.isDaemon = true
                }
            },
            ThreadPoolExecutor.AbortPolicy(),
        )
        private const val MAX_LINE_BYTES = 16 * 1024
        private const val MAX_RESPONSE_LINES = 64
        private const val MAX_AUTH_RESPONSE_BYTES = 1024
        private const val MAX_MESSAGE_BYTES = 16 * 1024
        private const val USABILITY_NOOP_TAG = "A003"
        private val REQUIRED_MESSAGE_HEADERS = listOf(
            "From",
            "To",
            "Date",
            "Subject",
            "Message-ID",
            "MIME-Version",
            "Content-Type",
        ).map { header ->
            header.toByteArray(StandardCharsets.US_ASCII)
        }
        private val AUTHENTICATE_LOGIN_COMMAND =
            "A001 AUTHENTICATE LOGIN\r\n".toByteArray(
                StandardCharsets.US_ASCII,
            )
        private val USERNAME_CHALLENGE =
            "+ VXNlcm5hbWU6".toByteArray(StandardCharsets.US_ASCII)
        private val PASSWORD_CHALLENGE =
            "+ UGFzc3dvcmQ6".toByteArray(StandardCharsets.US_ASCII)
        private val USABILITY_NOOP_COMMAND =
            "$USABILITY_NOOP_TAG NOOP\r\n".toByteArray(
                StandardCharsets.US_ASCII,
            )
        private val CLOSED_SESSION_NOOP_COMMAND =
            "A099 NOOP\r\n".toByteArray(StandardCharsets.US_ASCII)
        private val CRLF =
            "\r\n".toByteArray(StandardCharsets.US_ASCII)
        private val CRLF_CRLF =
            "\r\n\r\n".toByteArray(StandardCharsets.US_ASCII)
    }
}
