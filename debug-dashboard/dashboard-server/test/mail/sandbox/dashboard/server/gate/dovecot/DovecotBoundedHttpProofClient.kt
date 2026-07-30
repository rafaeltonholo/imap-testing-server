package mail.sandbox.dashboard.server.gate.dovecot

import java.io.InputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.util.concurrent.TimeUnit

internal class DovecotBoundedHttpProofClient(
    private val port: Int,
    private val timeoutMillis: Int,
    private val maximumResponseBytes: Int,
) {
    init {
        require(port in 1..65_535)
        require(timeoutMillis > 0)
        require(maximumResponseBytes in 1..MAX_CONFIGURED_RESPONSE_BYTES)
    }

    fun postForm(
        path: String,
        body: ByteArray,
    ): DovecotBoundedHttpResponse {
        require(path in ALLOWED_PATHS) {
            "OAuth proof path was invalid"
        }
        val socket = Socket()
        val deadline = DovecotTask6ProofDeadline(
            timeout = Duration.ofMillis(timeoutMillis.toLong()),
            onDeadline = {
                runCatching(socket::close)
            },
        )
        var requestHeaders = ByteArray(0)
        var responseBody: ByteArray? = null
        try {
            socket.tcpNoDelay = true
            socket.soTimeout = timeoutMillis
            socket.connect(
                InetSocketAddress(LOOPBACK, port),
                deadline.remainingMillis(),
            )
            deadline.requireRemaining()

            requestHeaders = requestHeaders(path, body.size)
            socket.outputStream.write(requestHeaders)
            deadline.requireRemaining()
            socket.outputStream.write(body)
            deadline.requireRemaining()
            socket.outputStream.flush()
            deadline.requireRemaining()

            val input = socket.inputStream
            val status = readStatus(input, deadline)
            val headers = readHeaders(input, deadline)
            responseBody = readBody(
                input = input,
                contentLength = headers.contentLength,
                deadline = deadline,
            )
            deadline.complete()

            val ownedBody = requireNotNull(responseBody)
            val response = DovecotBoundedHttpResponse(
                status = status,
                location = headers.location,
                body = ownedBody,
            )
            responseBody = null
            return response
        } catch (_: Exception) {
            error("OAuth HTTP proof failed")
        } finally {
            responseBody?.fill(0)
            requestHeaders.fill(0)
            deadline.close()
            runCatching(socket::close)
        }
    }

    private fun requestHeaders(
        path: String,
        bodySize: Int,
    ): ByteArray =
        (
            "POST $path HTTP/1.0\r\n" +
                "Host: 127.0.0.1:$port\r\n" +
                "Content-Type: application/x-www-form-urlencoded\r\n" +
                "Content-Length: $bodySize\r\n" +
                "Connection: close\r\n" +
                "\r\n"
            ).toByteArray(StandardCharsets.US_ASCII)

    private fun readStatus(
        input: InputStream,
        deadline: DovecotTask6ProofDeadline,
    ): Int = readLine(
        input = input,
        maximumBytes = MAX_STATUS_LINE_BYTES,
        deadline = deadline,
    ).useWiped { line ->
        check(
            line.size >= MINIMUM_STATUS_LINE_BYTES &&
                (
                    line.startsWithBytes(HTTP_1_0_PREFIX) ||
                        line.startsWithBytes(HTTP_1_1_PREFIX)
                    ) &&
                line[STATUS_REASON_SEPARATOR] == SPACE &&
                line.all { byte -> byte.toInt() in PRINTABLE_ASCII },
        ) {
            "OAuth HTTP status line was invalid"
        }
        val hundreds = line[STATUS_CODE_OFFSET].asciiDigit()
        val tens = line[STATUS_CODE_OFFSET + 1].asciiDigit()
        val ones = line[STATUS_CODE_OFFSET + 2].asciiDigit()
        (hundreds * 100 + tens * 10 + ones).also { status ->
            check(status in 100..599) {
                "OAuth HTTP status code was invalid"
            }
        }
    }

    private fun readHeaders(
        input: InputStream,
        deadline: DovecotTask6ProofDeadline,
    ): ParsedHeaders {
        var totalBytes = 0
        var count = 0
        var location: String? = null
        var contentLength: Int? = null
        while (true) {
            val line = readLine(
                input = input,
                maximumBytes = MAX_HEADER_LINE_BYTES,
                deadline = deadline,
            )
            line.useWiped {
                totalBytes += line.size + CRLF_BYTES
                check(totalBytes <= MAX_HEADER_BYTES) {
                    "OAuth HTTP response headers exceeded their bound"
                }
                if (line.isEmpty()) {
                    return ParsedHeaders(location, contentLength)
                }
                count += 1
                check(count <= MAX_HEADER_COUNT) {
                    "OAuth HTTP response header count exceeded its bound"
                }
                val separator = line.indexOf(COLON)
                check(
                    separator > 0 &&
                        separator + 2 <= line.lastIndex &&
                        line[separator + 1] == SPACE &&
                        line.copyOfRange(0, separator).allHeaderNameBytes() &&
                        line.all { byte -> byte.toInt() in PRINTABLE_ASCII },
                ) {
                    "OAuth HTTP response header was invalid"
                }
                val valueOffset = separator + 2
                when {
                    line.matchesHeaderName(separator, LOCATION_HEADER) -> {
                        check(location == null) {
                            "OAuth HTTP Location header was duplicated"
                        }
                        val valueSize = line.size - valueOffset
                        check(
                            valueSize in 1..MAX_LOCATION_BYTES &&
                                line.indices.drop(valueOffset).all { index ->
                                    line[index].toInt() in URI_ASCII
                                },
                        ) {
                            "OAuth HTTP Location header was invalid"
                        }
                        location = line.copyOfRange(valueOffset, line.size)
                            .useWiped { bytes ->
                                bytes.toString(StandardCharsets.US_ASCII)
                            }
                    }
                    line.matchesHeaderName(
                        separator,
                        CONTENT_LENGTH_HEADER,
                    ) -> {
                        check(contentLength == null) {
                            "OAuth HTTP Content-Length was duplicated"
                        }
                        contentLength = parseContentLength(
                            line = line,
                            offset = valueOffset,
                        )
                    }
                    line.matchesHeaderName(
                        separator,
                        TRANSFER_ENCODING_HEADER,
                    ) -> error(
                        "OAuth HTTP transfer encoding was unsupported",
                    )
                }
            }
        }
    }

    private fun parseContentLength(
        line: ByteArray,
        offset: Int,
    ): Int {
        val size = line.size - offset
        check(
            size in 1..MAX_CONTENT_LENGTH_DIGITS &&
                (
                    size == 1 ||
                        line[offset] != ASCII_ZERO
                    ),
        ) {
            "OAuth HTTP Content-Length was invalid"
        }
        var value = 0
        for (index in offset until line.size) {
            val digit = line[index].asciiDigit()
            val nextValue = value.toLong() * 10L + digit
            check(nextValue <= maximumResponseBytes.toLong()) {
                "OAuth HTTP response body exceeded its bound"
            }
            value = nextValue.toInt()
        }
        return value
    }

    private fun readBody(
        input: InputStream,
        contentLength: Int?,
        deadline: DovecotTask6ProofDeadline,
    ): ByteArray =
        if (contentLength != null) {
            readExactBody(input, contentLength, deadline)
        } else {
            readCloseDelimitedBody(input, deadline)
        }

    private fun readExactBody(
        input: InputStream,
        contentLength: Int,
        deadline: DovecotTask6ProofDeadline,
    ): ByteArray {
        val body = ByteArray(contentLength)
        var offset = 0
        try {
            while (offset < body.size) {
                deadline.requireRemaining()
                val count = input.read(body, offset, body.size - offset)
                deadline.requireRemaining()
                check(count > 0) {
                    "OAuth HTTP response body ended early"
                }
                offset += count
            }
            return body
        } catch (failure: Throwable) {
            body.fill(0)
            throw failure
        }
    }

    private fun readCloseDelimitedBody(
        input: InputStream,
        deadline: DovecotTask6ProofDeadline,
    ): ByteArray {
        val buffer = ByteArray(maximumResponseBytes)
        var size = 0
        try {
            while (true) {
                deadline.requireRemaining()
                val value = input.read()
                deadline.requireRemaining()
                if (value < 0) {
                    return buffer.copyOf(size)
                }
                check(size < buffer.size) {
                    "OAuth HTTP response body exceeded its bound"
                }
                buffer[size] = value.toByte()
                size += 1
            }
        } finally {
            buffer.fill(0)
        }
    }

    private fun readLine(
        input: InputStream,
        maximumBytes: Int,
        deadline: DovecotTask6ProofDeadline,
    ): ByteArray {
        val buffer = ByteArray(maximumBytes + 1)
        var size = 0
        try {
            while (true) {
                deadline.requireRemaining()
                val value = input.read()
                deadline.requireRemaining()
                check(value >= 0) {
                    "OAuth HTTP response ended early"
                }
                if (value == LINE_FEED.toInt()) {
                    check(
                        size > 0 &&
                            buffer[size - 1] == CARRIAGE_RETURN,
                    ) {
                        "OAuth HTTP response line was invalid"
                    }
                    return buffer.copyOf(size - 1)
                }
                check(size < buffer.size) {
                    "OAuth HTTP response line exceeded its bound"
                }
                buffer[size] = value.toByte()
                size += 1
            }
        } finally {
            buffer.fill(0)
        }
    }

    private fun DovecotTask6ProofDeadline.remainingMillis(): Int {
        val nanos = remainingNanos()
        return maxOf(
            1,
            TimeUnit.NANOSECONDS.toMillis(
                nanos + TimeUnit.MILLISECONDS.toNanos(1) - 1,
            ).coerceAtMost(Int.MAX_VALUE.toLong()).toInt(),
        )
    }

    private fun Byte.asciiDigit(): Int {
        check(this in ASCII_ZERO..ASCII_NINE) {
            "OAuth HTTP decimal field was invalid"
        }
        return toInt() - ASCII_ZERO.toInt()
    }

    private fun ByteArray.matchesHeaderName(
        separator: Int,
        expected: ByteArray,
    ): Boolean =
        separator == expected.size &&
            expected.indices.all { index ->
                this[index].asciiLowercase() == expected[index]
            }

    private fun ByteArray.allHeaderNameBytes(): Boolean = all { byte ->
        byte in ASCII_UPPER_A..ASCII_UPPER_Z ||
            byte in ASCII_LOWER_A..ASCII_LOWER_Z ||
            byte in ASCII_ZERO..ASCII_NINE ||
            byte == HYPHEN
    }

    private fun Byte.asciiLowercase(): Byte =
        if (this in ASCII_UPPER_A..ASCII_UPPER_Z) {
            (toInt() + ASCII_CASE_OFFSET).toByte()
        } else {
            this
        }

    private fun ByteArray.startsWithBytes(prefix: ByteArray): Boolean =
        size >= prefix.size &&
            prefix.indices.all { index -> this[index] == prefix[index] }

    private inline fun <T> ByteArray.useWiped(
        block: (ByteArray) -> T,
    ): T = try {
        block(this)
    } finally {
        fill(0)
    }

    private class ParsedHeaders(
        val location: String?,
        val contentLength: Int?,
    )

    companion object {
        private val ALLOWED_PATHS = setOf("/authorize", "/introspect")
        private const val MAX_CONFIGURED_RESPONSE_BYTES = 64 * 1024
        private const val MAX_STATUS_LINE_BYTES = 256
        private const val MINIMUM_STATUS_LINE_BYTES = 13
        private const val MAX_HEADER_LINE_BYTES = 2 * 1024
        private const val MAX_HEADER_BYTES = 8 * 1024
        private const val MAX_HEADER_COUNT = 32
        private const val MAX_LOCATION_BYTES = 1024
        private const val MAX_CONTENT_LENGTH_DIGITS = 10
        private const val CRLF_BYTES = 2
        private const val STATUS_CODE_OFFSET = 9
        private const val STATUS_REASON_SEPARATOR = 12
        private const val ASCII_CASE_OFFSET = 32
        private const val PRINTABLE_ASCII_FIRST = 0x20
        private const val PRINTABLE_ASCII_LAST = 0x7e
        private const val URI_ASCII_FIRST = 0x21
        private const val URI_ASCII_LAST = 0x7e
        private val PRINTABLE_ASCII =
            PRINTABLE_ASCII_FIRST..PRINTABLE_ASCII_LAST
        private val URI_ASCII = URI_ASCII_FIRST..URI_ASCII_LAST
        private val LOOPBACK =
            InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
        private val HTTP_1_0_PREFIX =
            "HTTP/1.0 ".toByteArray(StandardCharsets.US_ASCII)
        private val HTTP_1_1_PREFIX =
            "HTTP/1.1 ".toByteArray(StandardCharsets.US_ASCII)
        private val LOCATION_HEADER =
            "location".toByteArray(StandardCharsets.US_ASCII)
        private val CONTENT_LENGTH_HEADER =
            "content-length".toByteArray(StandardCharsets.US_ASCII)
        private val TRANSFER_ENCODING_HEADER =
            "transfer-encoding".toByteArray(StandardCharsets.US_ASCII)
        private const val SPACE: Byte = 0x20
        private const val COLON: Byte = 0x3a
        private const val HYPHEN: Byte = 0x2d
        private const val CARRIAGE_RETURN: Byte = 0x0d
        private const val LINE_FEED: Byte = 0x0a
        private const val ASCII_ZERO: Byte = 0x30
        private const val ASCII_NINE: Byte = 0x39
        private const val ASCII_UPPER_A: Byte = 0x41
        private const val ASCII_UPPER_Z: Byte = 0x5a
        private const val ASCII_LOWER_A: Byte = 0x61
        private const val ASCII_LOWER_Z: Byte = 0x7a
    }
}

internal class DovecotBoundedHttpResponse(
    val status: Int,
    val location: String?,
    val body: ByteArray,
) : AutoCloseable {
    override fun close() {
        body.fill(0)
    }

    override fun toString(): String =
        "DovecotBoundedHttpResponse(" +
            "status=$status, " +
            "location=${if (location == null) "absent" else "present"}, " +
            "bodyBytes=${body.size}" +
            ")"
}
