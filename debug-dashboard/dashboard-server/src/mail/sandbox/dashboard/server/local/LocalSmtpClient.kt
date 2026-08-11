package mail.sandbox.dashboard.server.local

import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.util.Base64
import java.util.Locale

internal enum class LocalSmtpEndpoint(
    internal val port: Int,
    private val credentialPolicy: LocalSmtpCredentialPolicy,
) {
    POSTFIX_DELIVERY(1025, LocalSmtpCredentialPolicy.FORBIDDEN),
    STALWART_SUBMISSION(8587, LocalSmtpCredentialPolicy.REQUIRED),
    ;

    fun requireCredentialRole(credentials: LocalSmtpCredentials?) {
        require(
            when (credentialPolicy) {
                LocalSmtpCredentialPolicy.FORBIDDEN -> credentials == null
                LocalSmtpCredentialPolicy.REQUIRED -> credentials != null
            },
        ) {
            when (credentialPolicy) {
                LocalSmtpCredentialPolicy.FORBIDDEN ->
                    "Direct Postfix delivery does not accept account credentials"
                LocalSmtpCredentialPolicy.REQUIRED ->
                    "Authenticated SMTP submission requires account credentials"
            }
        }
    }
}

private enum class LocalSmtpCredentialPolicy {
    FORBIDDEN,
    REQUIRED,
}

internal data class LocalSmtpCredentials(
    val username: String,
    val password: String,
)

internal data class LocalSmtpSendResult(
    val responseCode: Int,
    val acceptanceText: String,
    val queueId: String?,
)

internal enum class LocalSmtpStage {
    CONNECT,
    GREETING,
    EHLO,
    AUTH,
    MAIL_FROM,
    RCPT_TO,
    DATA,
    MESSAGE,
    QUIT,
}

internal class LocalSmtpException(
    val stage: LocalSmtpStage,
    val responseCode: Int?,
    val responseText: String,
    cause: Throwable? = null,
) : IllegalStateException(
    buildString {
        append("Local SMTP ")
        append(stage.name.lowercase(Locale.ROOT).replace('_', ' '))
        append(" failed")
        responseCode?.let { append(" with ").append(it) }
        if (responseText.isNotBlank()) append(": ").append(responseText)
    },
    cause,
)

internal fun interface LocalSmtpSocketConnector {
    fun connect(
        host: String,
        port: Int,
        connectTimeoutMillis: Int,
        readTimeoutMillis: Int,
    ): Socket
}

internal interface LocalSmtpSender {
    fun send(
        envelopeFrom: String,
        envelopeRecipient: String,
        rawMessage: String,
        credentials: LocalSmtpCredentials?,
    ): LocalSmtpSendResult
}

internal class LocalSmtpClient(
    private val endpoint: LocalSmtpEndpoint,
    connectTimeout: Duration = DEFAULT_CONNECT_TIMEOUT,
    readTimeout: Duration = DEFAULT_READ_TIMEOUT,
    private val connector: LocalSmtpSocketConnector = JvmLoopbackSmtpSocketConnector,
) : LocalSmtpSender {
    private val connectTimeoutMillis = requireTimeout(connectTimeout, "connect")
    private val readTimeoutMillis = requireTimeout(readTimeout, "read")

    fun send(
        envelopeFrom: String,
        envelopeRecipient: String,
        rawMessage: String,
    ): LocalSmtpSendResult = send(
        envelopeFrom = envelopeFrom,
        envelopeRecipient = envelopeRecipient,
        rawMessage = rawMessage,
        credentials = null,
    )

    override fun send(
        envelopeFrom: String,
        envelopeRecipient: String,
        rawMessage: String,
        credentials: LocalSmtpCredentials?,
    ): LocalSmtpSendResult {
        val sender = requireAddress(envelopeFrom)
        val recipient = requireAddress(envelopeRecipient)
        requireMessage(rawMessage)
        credentials?.let(::requireCredentials)
        endpoint.requireCredentialRole(credentials)

        var stage = LocalSmtpStage.CONNECT
        var acceptedResult: LocalSmtpSendResult? = null
        try {
            return connector.connect(
                LOOPBACK_HOST,
                endpoint.port,
                connectTimeoutMillis,
                readTimeoutMillis,
            ).use { socket ->
                val input = SmtpReplyReader(BufferedInputStream(socket.getInputStream()))
                val output = BufferedOutputStream(socket.getOutputStream())

                stage = LocalSmtpStage.GREETING
                expect(input.readReply(), stage, setOf(220))

                stage = LocalSmtpStage.EHLO
                writeCommand(output, "EHLO $CLIENT_IDENTITY")
                expect(input.readReply(), stage, setOf(250))

                credentials?.let { account ->
                    stage = LocalSmtpStage.AUTH
                    writeCommand(output, "AUTH PLAIN ${plainAuthentication(account)}")
                    expect(input.readReply(), stage, setOf(235))
                }

                stage = LocalSmtpStage.MAIL_FROM
                writeCommand(output, "MAIL FROM:<$sender>")
                expect(input.readReply(), stage, setOf(250))

                stage = LocalSmtpStage.RCPT_TO
                writeCommand(output, "RCPT TO:<$recipient>")
                expect(input.readReply(), stage, setOf(250, 251))

                stage = LocalSmtpStage.DATA
                writeCommand(output, "DATA")
                expect(input.readReply(), stage, setOf(354))

                stage = LocalSmtpStage.MESSAGE
                writeMessageData(output, rawMessage)
                val acceptance = expect(input.readReply(), stage, setOf(250))
                val result = LocalSmtpSendResult(
                    responseCode = acceptance.code,
                    acceptanceText = acceptance.text,
                    queueId = queueId(acceptance.text),
                )
                acceptedResult = result

                stage = LocalSmtpStage.QUIT
                writeCommand(output, "QUIT")
                expect(input.readReply(), stage, setOf(221))
                result
            }
        } catch (failure: Exception) {
            if (failure is InterruptedException) Thread.currentThread().interrupt()
            acceptedResult?.let { return it }
            if (failure is LocalSmtpException) throw failure
            throw LocalSmtpException(
                stage = stage,
                responseCode = null,
                responseText = failure.message.orEmpty().take(MAXIMUM_FAILURE_CHARACTERS),
                cause = failure,
            )
        }
    }

    private fun plainAuthentication(credentials: LocalSmtpCredentials): String {
        val bytes = (
            "\u0000${credentials.username}\u0000${credentials.password}"
            ).toByteArray(StandardCharsets.UTF_8)
        return try {
            Base64.getEncoder().encodeToString(bytes)
        } finally {
            bytes.fill(0)
        }
    }

    private fun writeCommand(output: BufferedOutputStream, command: String) {
        output.write(command.toByteArray(StandardCharsets.US_ASCII))
        output.write(CRLF_BYTES)
        output.flush()
    }

    private fun writeMessageData(output: BufferedOutputStream, rawMessage: String) {
        val normalized = rawMessage.replace("\r\n", "\n").replace('\r', '\n')
        val wireMessage = buildString(normalized.length + 16) {
            var lineStart = true
            normalized.forEach { character ->
                if (lineStart && character == '.') append('.')
                if (character == '\n') {
                    append(CRLF)
                    lineStart = true
                } else {
                    append(character)
                    lineStart = false
                }
            }
            if (!lineStart) append(CRLF)
            append('.').append(CRLF)
        }
        output.write(wireMessage.toByteArray(StandardCharsets.UTF_8))
        output.flush()
    }

    private fun expect(
        reply: SmtpReply,
        stage: LocalSmtpStage,
        acceptedCodes: Set<Int>,
    ): SmtpReply {
        if (reply.code !in acceptedCodes) {
            throw LocalSmtpException(stage, reply.code, reply.text)
        }
        return reply
    }

    private fun requireAddress(value: String): String {
        require(LOCAL_ADDRESS.matches(value)) {
            "SMTP envelope address must be a canonical local.test address"
        }
        return value
    }

    private fun requireCredentials(credentials: LocalSmtpCredentials) {
        requireAddress(credentials.username)
        val passwordBytes = credentials.password.toByteArray(StandardCharsets.UTF_8)
        try {
            require(
                passwordBytes.size in 1..MAXIMUM_PASSWORD_BYTES &&
                    credentials.password.none { it == '\u0000' || it == '\r' || it == '\n' },
            ) {
                "SMTP password is invalid"
            }
        } finally {
            passwordBytes.fill(0)
        }
    }

    private fun requireMessage(rawMessage: String) {
        require(rawMessage.isNotEmpty() && '\u0000' !in rawMessage) {
            "SMTP message is invalid"
        }
        val messageBytes = rawMessage.toByteArray(StandardCharsets.UTF_8)
        try {
            require(messageBytes.size <= MAXIMUM_MESSAGE_BYTES) {
                "SMTP message exceeds the local delivery limit"
            }
        } finally {
            messageBytes.fill(0)
        }
        val normalized = rawMessage.replace("\r\n", "\n").replace('\r', '\n')
        require(normalized.indexOf("\n\n") > 0) {
            "SMTP message must contain RFC 5322 headers and a body"
        }
    }

    private fun queueId(acceptanceText: String): String? =
        QUEUED_AS.find(acceptanceText)?.groupValues?.get(1)
            ?: QUEUE_ID.find(acceptanceText)?.groupValues?.get(1)

    private companion object {
        val DEFAULT_CONNECT_TIMEOUT: Duration = Duration.ofSeconds(3)
        val DEFAULT_READ_TIMEOUT: Duration = Duration.ofSeconds(5)
        val MAXIMUM_TIMEOUT: Duration = Duration.ofSeconds(30)
        val LOCAL_ADDRESS = Regex("[a-z0-9][a-z0-9._+%-]{0,63}@local\\.test")
        val QUEUED_AS = Regex(
            """\bqueued\s+as\s+([A-Za-z0-9][A-Za-z0-9._-]{0,127})\b""",
            RegexOption.IGNORE_CASE,
        )
        val QUEUE_ID = Regex(
            """\bqueue(?:d)?[- ]?id\s*[:=]\s*([A-Za-z0-9][A-Za-z0-9._-]{0,127})\b""",
            RegexOption.IGNORE_CASE,
        )
        val CRLF_BYTES = "\r\n".toByteArray(StandardCharsets.US_ASCII)
        const val LOOPBACK_HOST = "127.0.0.1"
        const val CLIENT_IDENTITY = "debug-dashboard.local.test"
        const val CRLF = "\r\n"
        const val MAXIMUM_PASSWORD_BYTES = 4 * 1024
        const val MAXIMUM_MESSAGE_BYTES = 5 * 1024 * 1024
        const val MAXIMUM_FAILURE_CHARACTERS = 512

        fun requireTimeout(value: Duration, name: String): Int {
            require(
                !value.isZero &&
                    !value.isNegative &&
                    value <= MAXIMUM_TIMEOUT &&
                    value.toMillis() > 0,
            ) {
                "SMTP $name timeout is invalid"
            }
            return value.toMillis().toInt()
        }
    }
}

private object JvmLoopbackSmtpSocketConnector : LocalSmtpSocketConnector {
    override fun connect(
        host: String,
        port: Int,
        connectTimeoutMillis: Int,
        readTimeoutMillis: Int,
    ): Socket {
        check(isApprovedLoopbackSmtpEndpoint(host, port)) {
            "Local SMTP endpoint is not approved"
        }
        val socket = Socket()
        return try {
            socket.connect(InetSocketAddress(host, port), connectTimeoutMillis)
            socket.soTimeout = readTimeoutMillis
            socket
        } catch (failure: Exception) {
            runCatching { socket.close() }
            throw failure
        }
    }
}

internal fun isApprovedLoopbackSmtpEndpoint(host: String, port: Int): Boolean =
    host == "127.0.0.1" && port in setOf(1025, 1587, 8587)

private data class SmtpReply(
    val code: Int,
    val lines: List<String>,
) {
    val text: String = lines.joinToString("\n")
}

private class SmtpReplyReader(
    private val input: BufferedInputStream,
) {
    fun readReply(): SmtpReply {
        var totalBytes = 0
        val first = readLine().also { totalBytes += it.length + 2 }
        val code = replyCode(first)
        val lines = mutableListOf(replyText(first))
        var separator = replySeparator(first)
        while (separator == '-') {
            require(lines.size < MAXIMUM_REPLY_LINES) { "SMTP reply has too many lines" }
            val next = readLine().also { totalBytes += it.length + 2 }
            require(totalBytes <= MAXIMUM_REPLY_BYTES) { "SMTP reply is too large" }
            require(replyCode(next) == code) { "SMTP multiline reply code changed" }
            separator = replySeparator(next)
            lines += replyText(next)
        }
        return SmtpReply(code, lines)
    }

    private fun readLine(): String {
        val bytes = ByteArrayOutputStream()
        var previous = -1
        while (true) {
            val current = input.read()
            if (current < 0) throw EOFException("SMTP server closed the connection")
            if (current == '\n'.code) {
                require(previous == '\r'.code) { "SMTP reply did not use CRLF" }
                val line = bytes.toByteArray()
                return String(line, 0, line.size - 1, StandardCharsets.US_ASCII)
            }
            bytes.write(current)
            previous = current
            require(bytes.size() <= MAXIMUM_REPLY_LINE_BYTES) { "SMTP reply line is too large" }
        }
    }

    private fun replyCode(line: String): Int {
        require(line.length >= 4 && line.take(3).all(Char::isDigit)) {
            "SMTP reply code is invalid"
        }
        return line.substring(0, 3).toInt()
    }

    private fun replySeparator(line: String): Char = line[3].also { separator ->
        require(separator == ' ' || separator == '-') { "SMTP reply separator is invalid" }
    }

    private fun replyText(line: String): String = line.substring(4)

    private companion object {
        const val MAXIMUM_REPLY_LINES = 100
        const val MAXIMUM_REPLY_LINE_BYTES = 8 * 1024
        const val MAXIMUM_REPLY_BYTES = 64 * 1024
    }
}
