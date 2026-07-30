package mail.sandbox.dashboard.server.gate.dovecot

import java.io.IOException
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.util.Base64
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import java.util.concurrent.locks.ReentrantLock

internal class HeldDovecotOperatorImapSession private constructor(
    private val transport: DovecotOperatorTransport,
    private val operationWorkers: DovecotBoundedOperationWorkers,
    private val beforeFailureClassification: (Throwable) -> Unit,
    private val afterSessionLockContention: () -> Unit,
) : AutoCloseable {
    private val state = AtomicReference(SessionState.Open)
    private val sessionLock = ReentrantLock()
    private var pendingOperation: DovecotBoundedOperation? = null

    val isClosed: Boolean
        get() = state.get() == SessionState.Closed

    fun requireUsable(timeout: Duration = SESSION_TIMEOUT) =
        withSessionLock(
            timeout = timeout,
            interruptionMessage =
                "Held Dovecot operator usability proof was interrupted",
            timeoutMessage =
                "Held Dovecot operator usability proof exceeded its deadline",
            action = ::requireUsableSerialized,
        )

    private fun requireUsableSerialized(
        operationDeadline: DovecotTask6ProofDeadline,
    ) {
        check(state.get() == SessionState.Open) {
            "Held Dovecot operator session is not usable"
        }
        var operation: DovecotBoundedOperation? = null
        try {
            val acquired = acquireOperation(
                operationDeadline.deadlineNanos,
            )
            operation = acquired
            trackOperation(acquired)
            registerTransport(acquired)
            val io = HeldIo(acquired, transport)
            writeFixed(io, USABILITY_NOOP_COMMAND)
            requireTaggedOkay(
                io,
                USABILITY_NOOP_TAG,
            )
            completeOperation(acquired, operationDeadline)
            clearCompletedOperation(acquired)
        } catch (failure: Throwable) {
            markNeedsCloseIfAllocated(operation)
            if (
                abandonPendingAndDetectInterruption(
                    operation = operation,
                    failure = failure,
                )
            ) {
                throwRedactedInterruption(
                    "Held Dovecot operator usability proof was interrupted",
                )
            }
            error("Held Dovecot operator usability proof failed")
        }
    }

    fun requireClosedAndUnusable(timeout: Duration = SESSION_TIMEOUT) =
        withSessionLock(
            timeout = timeout,
            interruptionMessage =
                "Held Dovecot operator post-close proof was interrupted",
            timeoutMessage =
                "Held Dovecot operator post-close proof exceeded its deadline",
            action = ::requireClosedAndUnusableSerialized,
        )

    private fun requireClosedAndUnusableSerialized(
        operationDeadline: DovecotTask6ProofDeadline,
    ) {
        check(state.get() == SessionState.Closed) {
            "Held Dovecot operator session remains open"
        }
        var operation: DovecotBoundedOperation? = null
        val acquired = try {
            acquireOperation(
                operationDeadline.deadlineNanos,
            )
        } catch (failure: Throwable) {
            throwPostCloseProofFailure(operation, failure)
        }
        operation = acquired
        trackOperation(acquired)
        try {
            registerTransport(acquired)
        } catch (failure: Throwable) {
            throwPostCloseProofFailure(operation, failure)
        }
        val io = HeldIo(acquired, transport)
        val writeFailure = try {
            writeFixed(io, CLOSED_SESSION_NOOP_COMMAND)
            null
        } catch (failure: Throwable) {
            failure
        }
        if (writeFailure != null) {
            if (
                abandonPendingAndDetectInterruption(
                    operation = acquired,
                    failure = writeFailure,
                )
            ) {
                throwRedactedInterruption(
                    "Held Dovecot operator post-close proof " +
                        "was interrupted",
                )
            }
            return
        }
        throwPostCloseProofFailure(
            operation,
            IllegalStateException(
                "Closed Dovecot operator transport remained usable",
            ),
        )
    }

    override fun close() = close(SESSION_TIMEOUT)

    fun close(timeout: Duration) =
        withSessionLock(
            timeout = timeout,
            interruptionMessage =
                "Held Dovecot operator close was interrupted",
            timeoutMessage =
                "Held Dovecot operator close exceeded its deadline",
            action = ::closeSerialized,
        )

    private fun closeSerialized(
        operationDeadline: DovecotTask6ProofDeadline,
    ) {
        if (state.get() == SessionState.Closed) return
        var operation: DovecotBoundedOperation? = null
        val succeeded = try {
            val acquired = acquireOperation(
                operationDeadline.deadlineNanos,
            )
            operation = acquired
            trackOperation(acquired)
            val closeSucceeded = acquired.execute {
                registerCancellationTarget(
                    identity = transport,
                    abort = ::abortTransport,
                    close = ::closeTransport,
                )
                try {
                    closeTransport()
                    true
                } catch (interrupted: InterruptedException) {
                    throw interrupted
                } catch (_: Throwable) {
                    false
                }
            }
            completeOperation(acquired, operationDeadline)
            clearCompletedOperation(acquired)
            closeSucceeded
        } catch (failure: Throwable) {
            markNeedsCloseIfAllocated(operation)
            if (
                abandonPendingAndDetectInterruption(
                    operation = operation,
                    failure = failure,
                )
            ) {
                throwRedactedInterruption(
                    "Held Dovecot operator close was interrupted",
                )
            }
            error("Held Dovecot operator close failed")
        }
        if (!succeeded) {
            markNeedsClose()
        }
        check(succeeded) {
            "Held Dovecot operator close failed"
        }
    }

    private fun <T> withSessionLock(
        timeout: Duration,
        interruptionMessage: String,
        timeoutMessage: String,
        action: (DovecotTask6ProofDeadline) -> T,
    ): T {
        var acquired = false
        var serializationDeadline: DovecotTask6ProofDeadline? = null
        try {
            val deadline = DovecotTask6ProofDeadline(timeout) {}
            serializationDeadline = deadline
            deadline.requireRemaining()
            acquired = sessionLock.tryLock()
            if (!acquired) {
                afterSessionLockContention()
                acquired = sessionLock.tryLock(
                    deadline.remainingNanos(),
                    TimeUnit.NANOSECONDS,
                )
            }
            check(acquired) {
                timeoutMessage
            }
            deadline.requireRemaining()
            rejectLivePendingOperation()
            return action(deadline)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            throwRedactedInterruption(interruptionMessage)
        } finally {
            if (acquired) {
                sessionLock.unlock()
            }
            serializationDeadline?.close()
        }
    }

    private fun acquireOperation(
        deadlineNanos: Long,
    ): DovecotBoundedOperation =
        operationWorkers.tryAcquire(deadlineNanos)
            ?: error("Held Dovecot operator capacity was exhausted")

    private fun throwPostCloseProofFailure(
        operation: DovecotBoundedOperation?,
        failure: Throwable,
    ): Nothing {
        if (
            abandonPendingAndDetectInterruption(
                operation = operation,
                failure = failure,
            )
        ) {
            throwRedactedInterruption(
                "Held Dovecot operator post-close proof was interrupted",
            )
        }
        error("Held Dovecot operator post-close proof failed")
    }

    private fun registerTransport(
        operation: DovecotBoundedOperation,
    ) {
        operation.execute {
            registerCancellationTarget(
                identity = transport,
                abort = ::abortTransport,
                close = ::closeTransport,
            )
        }
    }

    private fun rejectLivePendingOperation() {
        val pending = pendingOperation ?: return
        if (pending.isReleased()) {
            pendingOperation = null
            return
        }
        error(
            "Held Dovecot operator previous operation cleanup is still active",
        )
    }

    private fun trackOperation(operation: DovecotBoundedOperation) {
        check(pendingOperation == null) {
            "Held Dovecot operator previous operation cleanup is still active"
        }
        pendingOperation = operation
    }

    private fun clearCompletedOperation(
        operation: DovecotBoundedOperation,
    ) {
        check(operation.isReleased()) {
            "Held Dovecot operator operation handoff remained active"
        }
        if (pendingOperation === operation) {
            pendingOperation = null
        }
    }

    private fun abandonPendingAndDetectInterruption(
        operation: DovecotBoundedOperation?,
        failure: Throwable,
    ): Boolean {
        try {
            return abandonAndDetectInterruption(
                operation = operation,
                failure = failure,
                beforeFailureClassification =
                    beforeFailureClassification,
            )
        } finally {
            if (
                operation != null &&
                operation.isReleased() &&
                pendingOperation === operation
            ) {
                pendingOperation = null
            }
        }
    }

    private fun abortTransport() {
        transport.abort()
        markClosed()
    }

    private fun closeTransport() {
        transport.close()
        markClosed()
    }

    private fun markNeedsCloseIfAllocated(
        operation: DovecotBoundedOperation?,
    ) {
        if (operation != null) {
            markNeedsClose()
        }
    }

    private fun markNeedsClose() {
        state.compareAndSet(
            SessionState.Open,
            SessionState.NeedsClose,
        )
    }

    private fun markClosed() {
        state.set(SessionState.Closed)
    }

    private enum class SessionState {
        Open,
        NeedsClose,
        Closed,
    }

    companion object {
        fun openAndSeed(
            transportFactory: DovecotOperatorTransportFactory,
            target: DovecotOperatorTarget,
            credential: DovecotOperatorCredential,
            message: ByteArray,
            timeout: Duration = SESSION_TIMEOUT,
            operationWorkers: DovecotBoundedOperationWorkers =
                DovecotBoundedOperationWorkers.processWide,
            beforeFailureClassification: (Throwable) -> Unit = {},
            afterSessionConstruction: () -> Unit = {},
            afterSessionLockContention: () -> Unit = {},
        ): HeldDovecotOperatorImapSession {
            var operation: DovecotBoundedOperation? = null
            var deadline: DovecotTask6ProofDeadline? = null
            try {
                val operationDeadline = DovecotTask6ProofDeadline(timeout) {}
                deadline = operationDeadline
                requireValidMessage(message)
                val acquired = operationWorkers.tryAcquire(
                    operationDeadline.deadlineNanos,
                ) ?: error(
                    "Held Dovecot operator capacity was exhausted",
                )
                operation = acquired
                val opened = openTransport(
                    operation = acquired,
                    transportFactory = transportFactory,
                )
                val io = HeldIo(acquired, opened)
                requireGreeting(io)
                authenticate(
                    io = io,
                    target = target,
                    credential = credential,
                )
                appendMessage(io, message)
                val session = HeldDovecotOperatorImapSession(
                    transport = opened,
                    operationWorkers = operationWorkers,
                    beforeFailureClassification =
                        beforeFailureClassification,
                    afterSessionLockContention =
                        afterSessionLockContention,
                )
                afterSessionConstruction()
                completeOperation(acquired, operationDeadline)
                return session
            } catch (failure: Throwable) {
                if (
                    abandonAndDetectInterruption(
                        operation = operation,
                        failure = failure,
                        beforeFailureClassification =
                            beforeFailureClassification,
                    )
                ) {
                    throwRedactedInterruption(
                        "Held Dovecot operator seed proof was interrupted",
                    )
                }
                if (failure is IllegalArgumentException) throw failure
                error("Held Dovecot operator seed proof failed")
            } finally {
                deadline?.close()
                credential.close()
                message.fill(0)
            }
        }

        private fun openTransport(
            operation: DovecotBoundedOperation,
            transportFactory: DovecotOperatorTransportFactory,
        ): DovecotOperatorTransport = operation.execute {
            var allocated: DovecotOperatorTransport? = null
            val opened = transportFactory.open { candidate ->
                registerCancellationTarget(
                    identity = candidate,
                    abort = candidate::abort,
                    close = candidate::close,
                )
                check(allocated == null) {
                    "Held Dovecot operator transport allocation is invalid"
                }
                allocated = candidate
            }
            if (allocated !== opened) {
                registerCancellationTarget(
                    identity = opened,
                    abort = opened::abort,
                    close = opened::close,
                )
                error(
                    "Held Dovecot operator transport allocation is invalid",
                )
            }
            opened
        }

        private fun requireGreeting(io: HeldIo) {
            io.readLine().useWiped { line ->
                check(line.hasAsciiTokenAt(0, "* OK")) {
                    "Held Dovecot operator greeting was invalid"
                }
            }
        }

        private fun authenticate(
            io: HeldIo,
            target: DovecotOperatorTarget,
            credential: DovecotOperatorCredential,
        ) {
            writeFixed(
                io,
                AUTHENTICATE_LOGIN_COMMAND,
            )
            requireExactLine(
                io,
                USERNAME_CHALLENGE,
            )
            writeCombinedUsername(
                io,
                target,
                credential.id,
            )
            requireExactLine(
                io,
                PASSWORD_CHALLENGE,
            )
            val secretCopy = credential.withSecretBytes(ByteArray::copyOf)
            try {
                writeBase64(io, secretCopy)
            } finally {
                secretCopy.fill(0)
            }
            requireTaggedOkay(io, "A001")
        }

        private fun appendMessage(
            io: HeldIo,
            message: ByteArray,
        ) {
            val appendCommand = (
                "A002 APPEND \"INBOX\" {${message.size}}\r\n"
                ).toByteArray(StandardCharsets.US_ASCII)
            try {
                io.write(appendCommand)
            } finally {
                appendCommand.fill(0)
            }
            io.readLine().useWiped { continuation ->
                check(
                    continuation.isNotEmpty() &&
                        continuation[0] == '+'.code.toByte(),
                ) {
                    "Held Dovecot operator APPEND continuation was invalid"
                }
            }
            io.write(message, appendCrlf = true)
            requireTaggedOkay(io, "A002")
        }

        private fun writeCombinedUsername(
            io: HeldIo,
            target: DovecotOperatorTarget,
            id: DovecotOperatorId,
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
                writeBase64(io, combined)
            } finally {
                targetBytes.fill(0)
                masterBytes.fill(0)
                combined.fill(0)
            }
        }

        private fun writeBase64(
            io: HeldIo,
            raw: ByteArray,
        ) {
            val encoded = Base64.getEncoder().encode(raw)
            val line = ByteArray(encoded.size + CRLF.size)
            try {
                check(encoded.size <= MAX_AUTH_RESPONSE_BYTES) {
                    "Held Dovecot operator authentication exceeded its bound"
                }
                encoded.copyInto(line)
                CRLF.copyInto(line, destinationOffset = encoded.size)
                io.write(line)
            } finally {
                encoded.fill(0)
                line.fill(0)
            }
        }

        private fun writeFixed(
            io: HeldIo,
            command: ByteArray,
        ) {
            val copy = command.copyOf()
            try {
                io.write(copy)
            } finally {
                copy.fill(0)
            }
        }

        private fun requireExactLine(
            io: HeldIo,
            expected: ByteArray,
        ) {
            io.readLine().useWiped { line ->
                check(line.contentEquals(expected)) {
                    "Held Dovecot operator continuation was invalid"
                }
            }
        }

        private fun requireTaggedOkay(
            io: HeldIo,
            tag: String,
        ) {
            repeat(MAX_RESPONSE_LINES) {
                io.readLine().useWiped { line ->
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

        private fun completeOperation(
            operation: DovecotBoundedOperation,
            deadline: DovecotTask6ProofDeadline,
        ) {
            deadline.complete()
            check(operation.commitHandoff()) {
                "Held Dovecot operator operation exceeded its deadline"
            }
        }

        private fun abandonAndDetectInterruption(
            operation: DovecotBoundedOperation?,
            failure: Throwable,
            beforeFailureClassification: (Throwable) -> Unit,
        ): Boolean {
            var interrupted = failure is InterruptedException
            operation?.abandon()
            try {
                operation?.awaitReleaseWithin(CANCELLATION_WAIT_NANOS)
            } catch (_: InterruptedException) {
                interrupted = true
                Thread.interrupted()
            }
            if (Thread.interrupted()) {
                interrupted = true
            }
            try {
                beforeFailureClassification(failure)
            } finally {
                if (Thread.interrupted()) {
                    interrupted = true
                }
                if (interrupted) {
                    Thread.currentThread().interrupt()
                }
            }
            return interrupted
        }

        private fun throwRedactedInterruption(message: String): Nothing {
            Thread.currentThread().interrupt()
            throw InterruptedException(message)
        }

        private class HeldIo(
            private val operation: DovecotBoundedOperation,
            private val transport: DovecotOperatorTransport,
        ) {
            fun write(
                source: ByteArray,
                appendCrlf: Boolean = false,
            ) {
                operation.executeWithCopiedBytes<Unit>(source) { owned ->
                    transport.outputStream.write(
                        owned,
                        0,
                        owned.size,
                    )
                    if (appendCrlf) {
                        transport.outputStream.write(
                            CRLF,
                            0,
                            CRLF.size,
                        )
                    }
                    transport.outputStream.flush()
                }
            }

            fun readLine(): ByteArray = operation.execute(
                disposeLate = { bytes: ByteArray -> bytes.fill(0) },
            ) {
                val buffer = ByteArray(MAX_LINE_BYTES + 1)
                var size = 0
                try {
                    while (true) {
                        val value = transport.input.read()
                        if (value < 0) {
                            throw IOException(
                                "Held Dovecot operator response was truncated",
                            )
                        }
                        if (value == '\n'.code) {
                            check(
                                size > 0 &&
                                    buffer[size - 1] ==
                                    '\r'.code.toByte(),
                            ) {
                                "Held Dovecot operator response was invalid"
                            }
                            return@execute buffer.copyOf(size - 1)
                        }
                        check(size < buffer.size) {
                            "Held Dovecot operator response exceeded its bound"
                        }
                        buffer[size] = value.toByte()
                        size += 1
                    }
                    @Suppress("UNREACHABLE_CODE")
                    ByteArray(0)
                } finally {
                    buffer.fill(0)
                }
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
        private const val MAX_LINE_BYTES = 16 * 1024
        private const val MAX_RESPONSE_LINES = 64
        private const val MAX_AUTH_RESPONSE_BYTES = 1024
        private const val MAX_MESSAGE_BYTES = 16 * 1024
        private val CANCELLATION_WAIT_NANOS =
            TimeUnit.MILLISECONDS.toNanos(100)
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
