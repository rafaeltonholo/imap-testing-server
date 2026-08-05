package mail.sandbox.dashboard.server.local

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.util.Base64
import java.util.Locale

internal data class DovecotParsedMessage(
    val headers: Map<String, String>,
    val textBody: String?,
    val htmlBody: String?,
) {
    fun header(name: String): String? = headers[name.lowercase(Locale.ROOT)]
}

/**
 * A deliberately small MIME reader for the local Dovecot debugging surface.
 *
 * It decodes only textual MIME shapes the dashboard can display. Any malformed
 * or unsupported input remains visible as raw text instead of being presented
 * as successfully decoded content.
 */
internal object DovecotMimeParser {
    fun parse(raw: String): DovecotParsedMessage {
        val root = try {
            splitEntity(raw)
        } catch (_: MimeLimitExceeded) {
            null
        } ?: return DovecotParsedMessage(emptyMap(), raw, null)
        val selection = try {
            parseBody(root.headers, root.body, depth = 0, Traversal())
        } catch (_: MimeLimitExceeded) {
            BodySelection(text = root.body)
        }
        return DovecotParsedMessage(
            headers = root.headers,
            textBody = selection.text ?: if (selection.html == null) root.body else null,
            htmlBody = selection.html,
        )
    }

    private fun parseBody(
        headers: Map<String, String>,
        body: String,
        depth: Int,
        traversal: Traversal,
    ): BodySelection {
        if (depth > MAXIMUM_MIME_DEPTH) throw MimeLimitExceeded
        val contentType = parseContentType(headers[CONTENT_TYPE])
        if (contentType.mediaType.startsWith("multipart/")) {
            val boundary = contentType.parameters[BOUNDARY]
                ?.takeIf(::isValidBoundary)
                ?: return BodySelection(text = body)
            val parts = splitMultipart(body, boundary)
                ?: return BodySelection(text = body)
            if (parts.size > traversal.remainingParts) throw MimeLimitExceeded
            traversal.remainingParts -= parts.size
            var plain: String? = null
            var html: String? = null
            parts.forEach { part ->
                val entity = splitEntity(part)
                if (entity != null && !isAttachment(entity.headers)) {
                    val nested = parseBody(entity.headers, entity.body, depth + 1, traversal)
                    if (plain == null) plain = nested.text
                    if (html == null) html = nested.html
                }
            }
            return if (plain == null && html == null) {
                BodySelection(text = body)
            } else {
                BodySelection(plain, html)
            }
        }

        return when (contentType.mediaType) {
            TEXT_PLAIN -> decodeText(headers, contentType, body)
                ?.let { BodySelection(text = it) }
                ?: BodySelection(text = body)

            TEXT_HTML -> decodeText(headers, contentType, body)
                ?.let { BodySelection(html = it) }
                ?: BodySelection(text = body)

            else -> BodySelection()
        }
    }

    private fun decodeText(
        headers: Map<String, String>,
        contentType: ParsedContentType,
        rawBody: String,
    ): String? {
        val charset = when (
            contentType.parameters[CHARSET]
                ?.trim()
                ?.lowercase(Locale.ROOT)
                ?: US_ASCII
        ) {
            "utf-8", "utf8" -> StandardCharsets.UTF_8
            US_ASCII, "ascii" -> StandardCharsets.US_ASCII
            "iso-8859-1", "iso8859-1", "latin1" -> StandardCharsets.ISO_8859_1
            else -> return null
        }
        val transferEncoding = headers[CONTENT_TRANSFER_ENCODING]
            ?.trim()
            ?.lowercase(Locale.ROOT)
            .orEmpty()
        if (transferEncoding in IDENTITY_ENCODINGS) return rawBody
        val bytes = when (transferEncoding) {
            BASE64 -> decodeBase64(rawBody)
            QUOTED_PRINTABLE -> decodeQuotedPrintable(rawBody)
            else -> null
        } ?: return null
        return try {
            charset.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes))
                .toString()
        } catch (_: CharacterCodingException) {
            null
        } finally {
            bytes.fill(0)
        }
    }

    private fun decodeBase64(value: String): ByteArray? {
        if (value.length > MAXIMUM_ENCODED_PART_CHARACTERS) throw MimeLimitExceeded
        val compact = buildString(value.length) {
            value.forEach { character ->
                if (character != '\r' && character != '\n' && character != ' ' && character != '\t') {
                    append(character)
                }
            }
        }
        return runCatching { Base64.getDecoder().decode(compact) }.getOrNull()
    }

    private fun decodeQuotedPrintable(value: String): ByteArray? {
        if (value.length > MAXIMUM_ENCODED_PART_CHARACTERS) throw MimeLimitExceeded
        val output = ByteArrayOutputStream(value.length)
        var index = 0
        while (index < value.length) {
            val character = value[index]
            if (character != '=') {
                if (character.code > 0x7f) return null
                output.write(character.code)
                index += 1
                continue
            }
            when {
                index + 1 < value.length && value[index + 1] == '\n' -> index += 2
                index + 2 < value.length &&
                    value[index + 1] == '\r' &&
                    value[index + 2] == '\n' -> index += 3

                index + 2 < value.length -> {
                    val high = value[index + 1].hexValue()
                    val low = value[index + 2].hexValue()
                    if (high < 0 || low < 0) return null
                    output.write((high shl 4) or low)
                    index += 3
                }

                else -> return null
            }
        }
        return output.toByteArray()
    }

    private fun splitEntity(raw: String): MimeEntity? {
        val separator = findHeaderSeparator(raw) ?: return null
        val headerBlock = raw.substring(0, separator.index)
        if (headerBlock.length > MAXIMUM_HEADER_CHARACTERS) throw MimeLimitExceeded
        return MimeEntity(
            headers = parseHeaders(headerBlock),
            body = raw.substring(separator.index + separator.length),
        )
    }

    private fun findHeaderSeparator(raw: String): Separator? = listOf(
        "\r\n\r\n",
        "\n\n",
        "\r\r",
    ).mapNotNull { delimiter ->
        raw.indexOf(delimiter).takeIf { it >= 0 }?.let { Separator(it, delimiter.length) }
    }.minByOrNull(Separator::index)

    private fun parseHeaders(headerBlock: String): Map<String, String> {
        val headers = linkedMapOf<String, String>()
        var currentName: String? = null
        normalizeLineEndings(headerBlock).lineSequence().forEach { line ->
            if ((line.startsWith(' ') || line.startsWith('\t')) && currentName != null) {
                headers[currentName] = headers.getValue(currentName) + " " + line.trim()
            } else {
                val delimiter = line.indexOf(':')
                if (delimiter > 0) {
                    val name = line.substring(0, delimiter).trim().lowercase(Locale.ROOT)
                    if (name.isNotEmpty()) {
                        currentName = name
                        headers[name] = line.substring(delimiter + 1).trim()
                        if (headers.size > MAXIMUM_HEADER_COUNT) throw MimeLimitExceeded
                    }
                } else {
                    currentName = null
                }
            }
        }
        return headers
    }

    private fun parseContentType(value: String?): ParsedContentType {
        val source = value?.trim().orEmpty()
        val mediaType = source.substringBefore(';')
            .trim()
            .lowercase(Locale.ROOT)
            .ifEmpty { TEXT_PLAIN }
        val parameters = linkedMapOf<String, String>()
        PARAMETER.findAll(source).forEach { match ->
            val name = match.groupValues[1].lowercase(Locale.ROOT)
            val quotedValue = match.groupValues[2]
            val unquotedValue = match.groupValues[3]
            parameters[name] = if (quotedValue.isNotEmpty()) quotedValue else unquotedValue
        }
        return ParsedContentType(mediaType, parameters)
    }

    private fun splitMultipart(body: String, boundary: String): List<String>? {
        val marker = "--$boundary"
        val closingMarker = "$marker--"
        val parts = mutableListOf<String>()
        var current: StringBuilder? = null
        var closed = false
        normalizeLineEndings(body).split('\n').forEach { line ->
            if (closed) return@forEach
            when (line.trimEnd(' ', '\t')) {
                marker -> {
                    current?.let { parts += it.toString().removeSuffix("\n") }
                    current = StringBuilder()
                }

                closingMarker -> {
                    current?.let { parts += it.toString().removeSuffix("\n") }
                    current = null
                    closed = true
                }

                else -> if (!closed) current?.append(line)?.append('\n')
            }
        }
        return parts.takeIf { closed && it.isNotEmpty() }
    }

    private fun isAttachment(headers: Map<String, String>): Boolean =
        headers[CONTENT_DISPOSITION]
            ?.substringBefore(';')
            ?.trim()
            ?.equals("attachment", ignoreCase = true) == true

    private fun isValidBoundary(value: String): Boolean =
        value.length in 1..MAXIMUM_BOUNDARY_CHARACTERS &&
            value.none { it == '\r' || it == '\n' }

    private fun normalizeLineEndings(value: String): String =
        value.replace("\r\n", "\n").replace('\r', '\n')

    private fun Char.hexValue(): Int = when (this) {
        in '0'..'9' -> code - '0'.code
        in 'a'..'f' -> code - 'a'.code + 10
        in 'A'..'F' -> code - 'A'.code + 10
        else -> -1
    }

    private data class MimeEntity(
        val headers: Map<String, String>,
        val body: String,
    )

    private data class Separator(val index: Int, val length: Int)

    private data class ParsedContentType(
        val mediaType: String,
        val parameters: Map<String, String>,
    )

    private data class BodySelection(
        val text: String? = null,
        val html: String? = null,
    )

    private data class Traversal(var remainingParts: Int = MAXIMUM_MIME_PARTS)

    private object MimeLimitExceeded : RuntimeException()

    private val PARAMETER = Regex(
        """(?:^|;)\s*([A-Za-z0-9!#\$%&'*+.^_`|~-]+)\s*=\s*(?:\"([^\"]*)\"|([^;\s]*))""",
    )
    private val IDENTITY_ENCODINGS = setOf("", "7bit", "8bit", "binary")
    private const val CONTENT_TYPE = "content-type"
    private const val CONTENT_TRANSFER_ENCODING = "content-transfer-encoding"
    private const val CONTENT_DISPOSITION = "content-disposition"
    private const val BOUNDARY = "boundary"
    private const val CHARSET = "charset"
    private const val TEXT_PLAIN = "text/plain"
    private const val TEXT_HTML = "text/html"
    private const val BASE64 = "base64"
    private const val QUOTED_PRINTABLE = "quoted-printable"
    private const val US_ASCII = "us-ascii"
    private const val MAXIMUM_MIME_DEPTH = 8
    private const val MAXIMUM_MIME_PARTS = 256
    private const val MAXIMUM_BOUNDARY_CHARACTERS = 200
    private const val MAXIMUM_HEADER_COUNT = 512
    private const val MAXIMUM_HEADER_CHARACTERS = 256 * 1024
    private const val MAXIMUM_ENCODED_PART_CHARACTERS = 8 * 1024 * 1024
}
