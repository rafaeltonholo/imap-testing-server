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
    AuthorizationFailure,
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
    private val transportFactory: DovecotOperatorTransportFactory,
    private val clock: DovecotOperatorProbeClock =
        DovecotOperatorProbeClock(System::nanoTime),
    private val watchdog: DovecotOperatorProbeWatchdog =
        DovecotOperatorProbeWatchdog { AutoCloseable {} },
    private val requireMailboxRead: Boolean = false,
    private val operationWorkers: DovecotBoundedOperationWorkers =
        DovecotBoundedOperationWorkers.processWide,
    private val beforeResultNormalization:
        (DovecotOperatorProbeResult) -> Unit = {},
) {
    fun probe(
        target: DovecotOperatorTarget,
        credential: DovecotOperatorCredential,
    ): DovecotOperatorProbeResult {
        val selected = selectResult(target, credential)
        beforeResultNormalization(selected)
        return if (Thread.currentThread().isInterrupted) {
            DovecotOperatorProbeResult.TransportFailure
        } else {
            selected
        }
    }

    private fun selectResult(
        target: DovecotOperatorTarget,
        credential: DovecotOperatorCredential,
    ): DovecotOperatorProbeResult {
        var operation: DovecotBoundedOperation? = null
        var watchdogHandle: AutoCloseable? = null
        return try {
            val deadline = Math.addExact(
                clock.nanoTime(),
                TOTAL_DEADLINE.toNanos(),
            )
            val acquired = operationWorkers.tryAcquire(deadline)
                ?: return DovecotOperatorProbeResult.TransportFailure
            operation = acquired
            watchdogHandle = watchdog.arm {
                acquired.abandon()
            }
            val opened = openTransport(acquired)
            val io = ProbeIo(acquired, opened)
            val provisional = try {
                selectProtocolResult(
                    io = io,
                    target = target,
                    credential = credential,
                    deadline = deadline,
                )
            } catch (_: DovecotOperatorProtocolException) {
                DovecotOperatorProbeResult.ProtocolFailure
            }
            acquired.execute {
                opened.close()
            }
            if (!acquired.completeFinite()) {
                return DovecotOperatorProbeResult.TransportFailure
            }
            operation = null
            provisional
        } catch (_: Exception) {
            DovecotOperatorProbeResult.TransportFailure
        } finally {
            credential.close()
            runCatching { watchdogHandle?.close() }
            operation?.let { pending ->
                pending.abandon()
                runCatching {
                    pending.awaitReleaseWithin(CANCELLATION_WAIT_NANOS)
                }
            }
        }
    }

    private fun selectProtocolResult(
        io: ProbeIo,
        target: DovecotOperatorTarget,
        credential: DovecotOperatorCredential,
        deadline: Long,
    ): DovecotOperatorProbeResult {
        requireBeforeDeadline(deadline)
        requireGreeting(io)

        authenticateLogin(
            io = io,
            target = target,
            credential = credential,
        )
        when (
            readAuthenticationCompletion(
                io = io,
                tag = LOGIN_TAG,
            )
        ) {
            DovecotAuthenticationResponse.Success -> Unit
            DovecotAuthenticationResponse.PermanentFailure ->
                return DovecotOperatorProbeResult.AuthenticationFailure
            DovecotAuthenticationResponse.AuthorizationFailure ->
                return DovecotOperatorProbeResult.AuthorizationFailure
            DovecotAuthenticationResponse.Indeterminate ->
                return DovecotOperatorProbeResult.ProtocolFailure
        }

        writeFixedCommand(
            io = io,
            command = LIST_COMMAND,
        )
        return when (
            readTaggedCompletion(
                io = io,
                tag = LIST_TAG,
                requiredUntaggedPrefix = LIST_RESPONSE_PREFIX,
            )
        ) {
            TaggedCompletion.Ok -> {
                if (requireMailboxRead) {
                    val mailboxReadState = MailboxReadState()
                    writeFixedCommand(
                        io = io,
                        command = EXAMINE_INBOX_COMMAND,
                    )
                    when (
                        readTaggedCompletion(
                            io = io,
                            tag = EXAMINE_TAG,
                            mailboxReadState = mailboxReadState,
                        )
                    ) {
                        TaggedCompletion.Ok -> Unit
                        TaggedCompletion.No,
                        TaggedCompletion.Bad,
                        -> return DovecotOperatorProbeResult.ProtocolFailure
                    }
                    val selectedUid = searchFirstMessageUid(
                        io = io,
                        mailboxReadState = mailboxReadState,
                    )
                    fetchAndValidateMessageId(
                        io = io,
                        uid = selectedUid,
                        mailboxReadState = mailboxReadState,
                    )
                }
                requireBeforeDeadline(deadline)
                DovecotOperatorProbeResult.Success
            }
            TaggedCompletion.No,
            TaggedCompletion.Bad,
            -> DovecotOperatorProbeResult.ProtocolFailure
        }
    }

    private fun openTransport(
        operation: DovecotBoundedOperation,
    ): DovecotOperatorTransport = operation.execute {
        var allocated: DovecotOperatorTransport? = null
        val candidate = transportFactory.open { value ->
            registerCancellationTarget(
                identity = value,
                abort = value::abort,
                close = value::close,
            )
            check(allocated == null) {
                "Dovecot operator transport allocation is invalid"
            }
            allocated = value
        }
        if (allocated !== candidate) {
            registerCancellationTarget(
                identity = candidate,
                abort = candidate::abort,
                close = candidate::close,
            )
            throw IOException(
                "Dovecot operator transport allocation is invalid",
            )
        }
        candidate
    }

    private fun requireGreeting(io: ProbeIo) {
        io.readLine().useBytes { line ->
            if (!line.startsWithToken(GREETING_OK)) {
                throw DovecotOperatorProtocolException()
            }
        }
    }

    private fun readTaggedCompletion(
        io: ProbeIo,
        tag: ByteArray,
        requiredUntaggedPrefix: ByteArray? = null,
        mailboxReadState: MailboxReadState? = null,
    ): TaggedCompletion {
        var sawRequiredUntagged = requiredUntaggedPrefix == null
        repeat(MAX_RESPONSE_LINES) {
            io.readLine().useBytes { line ->
                mailboxReadState?.observe(line)
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

    private fun readAuthenticationCompletion(
        io: ProbeIo,
        tag: ByteArray,
    ): DovecotAuthenticationResponse {
        repeat(MAX_RESPONSE_LINES) {
            io.readLine().useBytes { line ->
                if (line.startsWithToken(tag)) {
                    return DovecotAuthenticationResponseClassifier.classifyImap(
                        line = line,
                        tag = tag,
                    )
                }
            }
        }
        throw DovecotOperatorProtocolException()
    }

    private fun searchFirstMessageUid(
        io: ProbeIo,
        mailboxReadState: MailboxReadState,
    ): Long {
        writeFixedCommand(
            io = io,
            command = UID_SEARCH_COMMAND,
        )
        var selectedUid: Long? = null
        repeat(MAX_RESPONSE_LINES) {
            io.readLine().useBytes { line ->
                mailboxReadState.observe(line)
                if (line.startsWithToken(SEARCH_RESPONSE_PREFIX)) {
                    if (selectedUid != null) {
                        throw DovecotOperatorProtocolException()
                    }
                    selectedUid = parseSearchUids(line)
                }
                if (line.startsWithToken(SEARCH_TAG)) {
                    if (
                        taggedCompletion(line, SEARCH_TAG) !=
                        TaggedCompletion.Ok
                    ) {
                        throw DovecotOperatorProtocolException()
                    }
                    return selectedUid ?:
                        throw DovecotOperatorProtocolException()
                }
            }
        }
        throw DovecotOperatorProtocolException()
    }

    private fun parseSearchUids(line: ByteArray): Long {
        var cursor = SEARCH_RESPONSE_PREFIX.size
        var selectedUid: Long? = null
        var previousUid = 0L
        while (cursor < line.size) {
            if (line[cursor] != SPACE) {
                throw DovecotOperatorProtocolException()
            }
            cursor += 1
            if (cursor == line.size || line[cursor] == SPACE) {
                throw DovecotOperatorProtocolException()
            }
            val parsed = parseDecimal(
                bytes = line,
                offset = cursor,
                maximum = MAX_IMAP_NUMBER,
            )
            val uid = parsed.value
            if (uid <= previousUid) {
                throw DovecotOperatorProtocolException()
            }
            if (selectedUid == null) {
                selectedUid = uid
            }
            previousUid = uid
            cursor = parsed.nextOffset
        }
        return selectedUid ?: throw DovecotOperatorProtocolException()
    }

    private fun fetchAndValidateMessageId(
        io: ProbeIo,
        uid: Long,
        mailboxReadState: MailboxReadState,
    ) {
        writeUidFetch(
            io = io,
            uid = uid,
        )
        var sawFetch = false
        repeat(MAX_RESPONSE_LINES) {
            io.readLine().useBytes { line ->
                mailboxReadState.observe(line)
                val literalSize = parseFetchMarkerOrNull(
                    line = line,
                    expectedUid = uid,
                )
                if (literalSize != null) {
                    mailboxReadState.requireMessageAvailable()
                    if (sawFetch) {
                        throw DovecotOperatorProtocolException()
                    }
                    sawFetch = true
                    io.readLiteral(literalSize).useBytes { literal ->
                        requireValidMessageIdLiteral(literal)
                    }
                    io.readLine().useBytes { closingLine ->
                        if (!closingLine.contentEquals(FETCH_CLOSING_LINE)) {
                            throw DovecotOperatorProtocolException()
                        }
                    }
                } else if (line.startsWithToken(FETCH_TAG)) {
                    if (
                        taggedCompletion(line, FETCH_TAG) !=
                        TaggedCompletion.Ok ||
                        !sawFetch
                    ) {
                        throw DovecotOperatorProtocolException()
                    }
                    return
                }
            }
        }
        throw DovecotOperatorProtocolException()
    }

    private fun parseFetchMarkerOrNull(
        line: ByteArray,
        expectedUid: Long,
    ): Int? {
        if (
            line.size < MINIMUM_FETCH_MARKER_BYTES ||
            line[0] != ASTERISK ||
            line[1] != SPACE
        ) {
            return null
        }
        var cursor = 2
        val sequence = parseDecimalOrNull(
            bytes = line,
            offset = cursor,
            maximum = MAX_IMAP_NUMBER,
        ) ?: return null
        cursor = sequence.nextOffset
        if (cursor >= line.size || line[cursor] != SPACE) {
            return null
        }
        cursor += 1
        if (!line.matchesAsciiIgnoreCase(cursor, FETCH_TOKEN)) {
            return null
        }
        if (
            sequence.value == 0L ||
            (
                line[2] == ASCII_ZERO &&
                    sequence.nextOffset > 3
                )
        ) {
            throw DovecotOperatorProtocolException()
        }
        cursor += FETCH_TOKEN.size
        if (cursor >= line.size || line[cursor] != SPACE) {
            throw DovecotOperatorProtocolException()
        }
        cursor += 1
        if (!line.matchesAsciiIgnoreCase(cursor, FETCH_UID_PREFIX)) {
            throw DovecotOperatorProtocolException()
        }
        cursor += FETCH_UID_PREFIX.size
        val uid = parseDecimal(
            bytes = line,
            offset = cursor,
            maximum = MAX_IMAP_NUMBER,
        )
        if (uid.value != expectedUid) {
            throw DovecotOperatorProtocolException()
        }
        cursor = uid.nextOffset
        if (cursor >= line.size || line[cursor] != SPACE) {
            throw DovecotOperatorProtocolException()
        }
        cursor += 1
        if (!line.matchesAsciiIgnoreCase(cursor, FETCH_LITERAL_PREFIX)) {
            throw DovecotOperatorProtocolException()
        }
        cursor += FETCH_LITERAL_PREFIX.size
        val literalSize = parseDecimal(
            bytes = line,
            offset = cursor,
            maximum = MAX_MESSAGE_ID_LITERAL_BYTES.toLong(),
        )
        cursor = literalSize.nextOffset
        if (
            cursor + 1 != line.size ||
            line[cursor] != CLOSE_BRACE
        ) {
            throw DovecotOperatorProtocolException()
        }
        return literalSize.value.toInt()
    }

    private fun requireValidMessageIdLiteral(literal: ByteArray) {
        if (
            literal.size < MINIMUM_MESSAGE_ID_LITERAL_BYTES ||
            !literal.matchesAsciiIgnoreCase(0, MESSAGE_ID_PREFIX) ||
            !literal.endsWith(CRLF_CRLF)
        ) {
            throw DovecotOperatorProtocolException()
        }
        var cursor = MESSAGE_ID_PREFIX.size
        while (
            cursor < literal.size &&
            (literal[cursor] == SPACE || literal[cursor] == HORIZONTAL_TAB)
        ) {
            cursor += 1
        }
        if (cursor >= literal.size || literal[cursor] != OPEN_ANGLE) {
            throw DovecotOperatorProtocolException()
        }
        cursor += 1
        val valueStart = cursor
        var atOffset = -1
        while (cursor < literal.size && literal[cursor] != CLOSE_ANGLE) {
            val value = literal[cursor]
            if (value == AT_SIGN) {
                if (atOffset >= 0) {
                    throw DovecotOperatorProtocolException()
                }
                atOffset = cursor
            } else if (value != DOT && !value.isMessageIdAtext()) {
                throw DovecotOperatorProtocolException()
            }
            cursor += 1
        }
        if (
            atOffset <= valueStart ||
            atOffset >= cursor - 1 ||
            cursor >= literal.size ||
            literal[cursor] != CLOSE_ANGLE
        ) {
            throw DovecotOperatorProtocolException()
        }
        requireMessageIdDotAtom(literal, valueStart, atOffset)
        requireMessageIdDotAtom(literal, atOffset + 1, cursor)
        cursor += 1
        if (
            cursor + CRLF_CRLF.size != literal.size ||
            !literal.matchesBytes(cursor, CRLF_CRLF)
        ) {
            throw DovecotOperatorProtocolException()
        }
    }

    private fun requireMessageIdDotAtom(
        literal: ByteArray,
        start: Int,
        end: Int,
    ) {
        var previousWasDot = true
        for (index in start until end) {
            val value = literal[index]
            if (value == DOT) {
                if (previousWasDot) {
                    throw DovecotOperatorProtocolException()
                }
                previousWasDot = true
            } else {
                if (!value.isMessageIdAtext()) {
                    throw DovecotOperatorProtocolException()
                }
                previousWasDot = false
            }
        }
        if (previousWasDot) {
            throw DovecotOperatorProtocolException()
        }
    }

    private fun Byte.isMessageIdAtext(): Boolean =
        this in 'A'.code.toByte()..'Z'.code.toByte() ||
            this in 'a'.code.toByte()..'z'.code.toByte() ||
            this in '0'.code.toByte()..'9'.code.toByte() ||
            this in MESSAGE_ID_ATEXT_SPECIALS

    private fun writeUidFetch(
        io: ProbeIo,
        uid: Long,
    ) {
        val uidBytes = uid.toString().toByteArray(Charsets.US_ASCII)
        val command = ByteArray(
            UID_FETCH_COMMAND_PREFIX.size +
                uidBytes.size +
                UID_FETCH_COMMAND_SUFFIX.size,
        )
        try {
            var offset = command.copyAt(0, UID_FETCH_COMMAND_PREFIX)
            offset = command.copyAt(offset, uidBytes)
            command.copyAt(offset, UID_FETCH_COMMAND_SUFFIX)
            io.writeCommand(command)
        } finally {
            uidBytes.fill(0)
            command.fill(0)
        }
    }

    private fun taggedCompletion(
        line: ByteArray,
        tag: ByteArray,
    ): TaggedCompletion {
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

    private fun authenticateLogin(
        io: ProbeIo,
        target: DovecotOperatorTarget,
        credential: DovecotOperatorCredential,
    ) {
        writeFixedCommand(
            io = io,
            command = AUTHENTICATE_LOGIN_COMMAND,
        )
        requireContinuation(
            io = io,
            expected = USERNAME_CHALLENGE,
        )
        writeCombinedUsername(
            io = io,
            target = target,
            credential = credential,
        )
        requireContinuation(
            io = io,
            expected = PASSWORD_CHALLENGE,
        )
        val secretCopy = credential.withSecretBytes(ByteArray::copyOf)
        try {
            writeBase64Response(
                io = io,
                raw = secretCopy,
            )
        } finally {
            secretCopy.fill(0)
        }
    }

    private fun requireContinuation(
        io: ProbeIo,
        expected: ByteArray,
    ) {
        io.readLine().useBytes { line ->
            if (!line.contentEquals(expected)) {
                throw DovecotOperatorProtocolException()
            }
        }
    }

    private fun writeCombinedUsername(
        io: ProbeIo,
        target: DovecotOperatorTarget,
        credential: DovecotOperatorCredential,
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
                io = io,
                raw = combined,
            )
        } finally {
            targetBytes.fill(0)
            masterBytes.fill(0)
            combined.fill(0)
        }
    }

    private fun writeBase64Response(
        io: ProbeIo,
        raw: ByteArray,
    ) {
        val encoded = BASE64_ENCODER.encode(raw)
        val line = ByteArray(encoded.size + CRLF.size)
        try {
            check(encoded.size <= MAX_AUTH_RESPONSE_BYTES) {
                "Dovecot operator authentication response exceeded its bound"
            }
            encoded.copyInto(line)
            CRLF.copyInto(line, destinationOffset = encoded.size)
            io.writeCommand(line)
        } finally {
            encoded.fill(0)
            line.fill(0)
        }
    }

    private fun writeFixedCommand(
        io: ProbeIo,
        command: ByteArray,
    ) {
        val copy = command.copyOf()
        try {
            io.writeCommand(copy)
        } finally {
            copy.fill(0)
        }
    }

    private class ProbeIo(
        private val operation: DovecotBoundedOperation,
        private val transport: DovecotOperatorTransport,
    ) {
        fun readLine(): ByteArray {
            val result = operation.execute<ProbeLineRead>(
                disposeLate = { late ->
                    if (late is ProbeLineRead.Value) {
                        late.bytes.fill(0)
                    }
                },
            ) {
                val buffer = ByteArray(MAX_LINE_BYTES + 1)
                var size = 0
                try {
                    while (true) {
                        val value = transport.input.read()
                        if (value < 0) {
                            throw IOException(
                                "Dovecot operator response was truncated",
                            )
                        }
                        if (value == LINE_FEED) {
                            if (
                                size == 0 ||
                                buffer[size - 1] != CARRIAGE_RETURN.toByte()
                            ) {
                                return@execute ProbeLineRead.ProtocolViolation
                            }
                            return@execute ProbeLineRead.Value(
                                buffer.copyOf(size - 1),
                            )
                        }
                        if (size == buffer.size) {
                            return@execute ProbeLineRead.ProtocolViolation
                        }
                        buffer[size] = value.toByte()
                        size += 1
                    }
                    @Suppress("UNREACHABLE_CODE")
                    ProbeLineRead.Value(ByteArray(0))
                } finally {
                    buffer.fill(0)
                }
            }
            return when (result) {
                is ProbeLineRead.Value -> result.bytes
                ProbeLineRead.ProtocolViolation ->
                    throw DovecotOperatorProtocolException()
            }
        }

        fun readLiteral(size: Int): ByteArray = operation.execute(
            disposeLate = { bytes: ByteArray -> bytes.fill(0) },
        ) {
            val literal = ByteArray(size)
            try {
                var offset = 0
                while (offset < literal.size) {
                    val count = transport.input.read(
                        literal,
                        offset,
                        literal.size - offset,
                    )
                    if (count <= 0) {
                        throw IOException(
                            "Dovecot operator response was truncated",
                        )
                    }
                    offset += count
                }
                literal
            } catch (failure: Throwable) {
                literal.fill(0)
                throw failure
            }
        }

        fun writeCommand(command: ByteArray) {
            operation.executeWithCopiedBytes<Unit>(
                source = command,
            ) { workerOwned ->
                transport.outputStream.write(
                    workerOwned,
                    0,
                    workerOwned.size,
                )
                transport.outputStream.flush()
            }
        }
    }

    private sealed interface ProbeLineRead {
        data class Value(
            val bytes: ByteArray,
        ) : ProbeLineRead

        data object ProtocolViolation : ProbeLineRead
    }

    private fun requireBeforeDeadline(deadline: Long) {
        if (clock.nanoTime() - deadline >= 0) {
            throw SocketTimeoutException("Dovecot operator probe timed out")
        }
    }

    private enum class TaggedCompletion {
        Ok,
        No,
        Bad,
    }

    private class MailboxReadState {
        private var existsCount: Long? = null

        fun observe(line: ByteArray) {
            parseExistsCountOrNull(line)?.let { count ->
                val current = existsCount
                if (current != null && count < current) {
                    throw DovecotOperatorProtocolException()
                }
                existsCount = count
                return
            }
            parseExpungeSequenceOrNull(line)?.let { sequence ->
                val current = existsCount
                    ?: throw DovecotOperatorProtocolException()
                if (sequence == 0L || sequence > current) {
                    throw DovecotOperatorProtocolException()
                }
                existsCount = current - 1L
            }
        }

        fun requireMessageAvailable() {
            if (existsCount == 0L) {
                throw DovecotOperatorProtocolException()
            }
        }

        private fun parseExistsCountOrNull(line: ByteArray): Long? {
            return parseUntaggedCountWithSuffixOrNull(
                line = line,
                suffix = EXISTS_SUFFIX,
            )
        }

        private fun parseExpungeSequenceOrNull(line: ByteArray): Long? {
            return parseUntaggedCountWithSuffixOrNull(
                line = line,
                suffix = EXPUNGE_SUFFIX,
            )
        }

        private fun parseUntaggedCountWithSuffixOrNull(
            line: ByteArray,
            suffix: ByteArray,
        ): Long? {
            if (
                line.size < 4 ||
                line[0] != ASTERISK ||
                line[1] != SPACE
            ) {
                return null
            }
            val count = parseDecimalOrNull(
                bytes = line,
                offset = 2,
                maximum = MAX_IMAP_NUMBER,
            ) ?: return null
            if (
                count.nextOffset + suffix.size != line.size ||
                !line.matchesAsciiIgnoreCase(
                    count.nextOffset,
                    suffix,
                )
            ) {
                return null
            }
            return count.value
        }
    }

    companion object {
        private val TOTAL_DEADLINE = Duration.ofSeconds(5)
        private val CANCELLATION_WAIT_NANOS =
            Duration.ofMillis(100).toNanos()
        private const val MAX_LINE_BYTES = 16 * 1024
        private const val MAX_RESPONSE_LINES = 64
        private const val LINE_FEED = 0x0a
        private const val CARRIAGE_RETURN = 0x0d
        private const val MAX_IMAP_NUMBER = 4_294_967_295L
        private const val MAX_MESSAGE_ID_LITERAL_BYTES = 1024
        private const val MINIMUM_FETCH_MARKER_BYTES = 10
        private const val MINIMUM_MESSAGE_ID_LITERAL_BYTES = 20
        private val SPACE = ' '.code.toByte()
        private val HORIZONTAL_TAB = '\t'.code.toByte()
        private val ASTERISK = '*'.code.toByte()
        private val OPEN_ANGLE = '<'.code.toByte()
        private val CLOSE_ANGLE = '>'.code.toByte()
        private val AT_SIGN = '@'.code.toByte()
        private val DOT = '.'.code.toByte()
        private val CLOSE_BRACE = '}'.code.toByte()
        private val MESSAGE_ID_ATEXT_SPECIALS =
            "!#$%&'*+-/=?^_`{|}~".toByteArray(Charsets.US_ASCII)

        private val GREETING_OK = ascii("* OK")
        private val LOGIN_TAG = ascii("A001")
        private val LIST_TAG = ascii("A002")
        private val EXAMINE_TAG = ascii("A003")
        private val SEARCH_TAG = ascii("A004")
        private val FETCH_TAG = ascii("A005")
        private val LIST_RESPONSE_PREFIX = ascii("* LIST")
        private val SEARCH_RESPONSE_PREFIX = ascii("* SEARCH")
        private val EXISTS_SUFFIX = ascii(" EXISTS")
        private val EXPUNGE_SUFFIX = ascii(" EXPUNGE")
        private val FETCH_TOKEN = ascii("FETCH")
        private val FETCH_UID_PREFIX = ascii("(UID ")
        private val FETCH_LITERAL_PREFIX =
            ascii("BODY[HEADER.FIELDS (MESSAGE-ID)] {")
        private val FETCH_CLOSING_LINE = ascii(")")
        private val MESSAGE_ID_PREFIX = ascii("Message-ID:")
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
        private val EXAMINE_INBOX_COMMAND =
            ascii("A003 EXAMINE \"INBOX\"\r\n")
        private val UID_SEARCH_COMMAND =
            ascii("A004 UID SEARCH ALL\r\n")
        private val UID_FETCH_COMMAND_PREFIX =
            ascii("A005 UID FETCH ")
        private val UID_FETCH_COMMAND_SUFFIX =
            ascii(
                " (BODY.PEEK[HEADER.FIELDS (MESSAGE-ID)])\r\n",
            )
        private val CRLF_CRLF = ascii("\r\n\r\n")
        private val BASE64_ENCODER = Base64.getEncoder()
        private const val MAX_AUTH_RESPONSE_BYTES = 1024
        private fun ascii(value: String): ByteArray =
            value.toByteArray(Charsets.US_ASCII)
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

private data class DecimalParseResult(
    val value: Long,
    val nextOffset: Int,
)

private fun parseDecimalOrNull(
    bytes: ByteArray,
    offset: Int,
    maximum: Long,
): DecimalParseResult? {
    if (
        offset !in bytes.indices ||
        bytes[offset] !in ASCII_ZERO..ASCII_NINE
    ) {
        return null
    }
    var cursor = offset
    var value = 0L
    while (
        cursor < bytes.size &&
        bytes[cursor] in ASCII_ZERO..ASCII_NINE
    ) {
        val digit = bytes[cursor].toInt() - ASCII_ZERO.toInt()
        if (value > (maximum - digit) / 10L) {
            throw DovecotOperatorProtocolException()
        }
        value = value * 10L + digit
        cursor += 1
    }
    return DecimalParseResult(value, cursor)
}

private fun parseDecimal(
    bytes: ByteArray,
    offset: Int,
    maximum: Long,
): DecimalParseResult {
    if (
        offset !in bytes.indices ||
        bytes[offset] !in ASCII_ONE..ASCII_NINE
    ) {
        throw DovecotOperatorProtocolException()
    }
    var cursor = offset
    var value = 0L
    while (
        cursor < bytes.size &&
        bytes[cursor] in ASCII_ZERO..ASCII_NINE
    ) {
        val digit = bytes[cursor].toInt() - ASCII_ZERO.toInt()
        if (value > (maximum - digit) / 10L) {
            throw DovecotOperatorProtocolException()
        }
        value = value * 10L + digit
        cursor += 1
    }
    return DecimalParseResult(value, cursor)
}

private fun ByteArray.matchesAsciiIgnoreCase(
    offset: Int,
    expected: ByteArray,
): Boolean {
    if (offset < 0 || size < offset + expected.size) {
        return false
    }
    expected.indices.forEach { index ->
        if (
            this[offset + index].asciiUppercase() !=
            expected[index].asciiUppercase()
        ) {
            return false
        }
    }
    return true
}

private fun ByteArray.matchesBytes(
    offset: Int,
    expected: ByteArray,
): Boolean {
    if (offset < 0 || size < offset + expected.size) {
        return false
    }
    expected.indices.forEach { index ->
        if (this[offset + index] != expected[index]) {
            return false
        }
    }
    return true
}

private fun ByteArray.endsWith(expected: ByteArray): Boolean =
    matchesBytes(size - expected.size, expected)

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
private val ASCII_ZERO = '0'.code.toByte()
private val ASCII_ONE = '1'.code.toByte()
private val ASCII_NINE = '9'.code.toByte()

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
