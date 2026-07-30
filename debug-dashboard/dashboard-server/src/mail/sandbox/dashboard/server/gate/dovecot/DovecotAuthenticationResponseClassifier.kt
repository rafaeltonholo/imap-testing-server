package mail.sandbox.dashboard.server.gate.dovecot

internal enum class DovecotAuthenticationResponse {
    Success,
    PermanentFailure,
    Indeterminate,
}

internal object DovecotAuthenticationResponseClassifier {
    fun classifyImap(
        line: ByteArray,
        tag: ByteArray,
    ): DovecotAuthenticationResponse {
        if (
            tag.isEmpty() ||
            line.size <= tag.size ||
            !line.regionMatches(0, tag) ||
            line[tag.size] != SPACE
        ) {
            return DovecotAuthenticationResponse.Indeterminate
        }
        val statusOffset = tag.size + 1
        return when {
            line.hasExactResponse(
                offset = statusOffset,
                status = IMAP_OK,
                responseCode = null,
            ) -> DovecotAuthenticationResponse.Success
            line.hasExactResponse(
                offset = statusOffset,
                status = IMAP_NO,
                responseCode = IMAP_PERMANENT_FAILURE_CODE,
            ) -> DovecotAuthenticationResponse.PermanentFailure
            else -> DovecotAuthenticationResponse.Indeterminate
        }
    }

    fun classifyPop3(line: ByteArray): DovecotAuthenticationResponse =
        when {
            line.hasExactResponse(
                offset = 0,
                status = POP3_OK,
                responseCode = null,
            ) -> DovecotAuthenticationResponse.Success
            line.hasExactResponse(
                offset = 0,
                status = POP3_ERROR,
                responseCode = POP3_PERMANENT_FAILURE_CODE,
            ) -> DovecotAuthenticationResponse.PermanentFailure
            else -> DovecotAuthenticationResponse.Indeterminate
        }

    private fun ByteArray.hasExactResponse(
        offset: Int,
        status: ByteArray,
        responseCode: ByteArray?,
    ): Boolean {
        if (!regionMatches(offset, status)) return false
        var cursor = offset + status.size
        if (cursor >= size || this[cursor] != SPACE) return false
        cursor += 1
        if (responseCode != null) {
            if (!regionMatches(cursor, responseCode)) return false
            cursor += responseCode.size
            if (cursor >= size || this[cursor] != SPACE) return false
            cursor += 1
        }
        if (cursor >= size) return false
        return indices.drop(cursor).all { index ->
            this[index].toInt() in PRINTABLE_ASCII
        }
    }

    private fun ByteArray.regionMatches(
        offset: Int,
        candidate: ByteArray,
    ): Boolean {
        if (offset < 0 || size - offset < candidate.size) return false
        candidate.indices.forEach { index ->
            if (this[offset + index] != candidate[index]) return false
        }
        return true
    }

    private val IMAP_OK = byteArrayOf('O'.code.toByte(), 'K'.code.toByte())
    private val IMAP_NO = byteArrayOf('N'.code.toByte(), 'O'.code.toByte())
    private val IMAP_PERMANENT_FAILURE_CODE =
        byteArrayOf(
            '['.code.toByte(),
            'A'.code.toByte(),
            'U'.code.toByte(),
            'T'.code.toByte(),
            'H'.code.toByte(),
            'E'.code.toByte(),
            'N'.code.toByte(),
            'T'.code.toByte(),
            'I'.code.toByte(),
            'C'.code.toByte(),
            'A'.code.toByte(),
            'T'.code.toByte(),
            'I'.code.toByte(),
            'O'.code.toByte(),
            'N'.code.toByte(),
            'F'.code.toByte(),
            'A'.code.toByte(),
            'I'.code.toByte(),
            'L'.code.toByte(),
            'E'.code.toByte(),
            'D'.code.toByte(),
            ']'.code.toByte(),
        )
    private val POP3_OK =
        byteArrayOf('+'.code.toByte(), 'O'.code.toByte(), 'K'.code.toByte())
    private val POP3_ERROR =
        byteArrayOf(
            '-'.code.toByte(),
            'E'.code.toByte(),
            'R'.code.toByte(),
            'R'.code.toByte(),
        )
    private val POP3_PERMANENT_FAILURE_CODE =
        byteArrayOf(
            '['.code.toByte(),
            'A'.code.toByte(),
            'U'.code.toByte(),
            'T'.code.toByte(),
            'H'.code.toByte(),
            ']'.code.toByte(),
        )
    private val PRINTABLE_ASCII = 0x20..0x7e
    private const val SPACE: Byte = 0x20
}
