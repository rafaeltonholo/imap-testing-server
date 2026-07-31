package mail.sandbox.dashboard.server.gate.dovecot

import java.util.Base64

internal class DovecotOperatorBoundedExchange(
    transportFactory: DovecotOperatorTransportFactory,
    operationWorkers: DovecotBoundedOperationWorkers =
        DovecotBoundedOperationWorkers.processWide,
    clock: DovecotOperatorProbeClock =
        DovecotOperatorProbeClock(System::nanoTime),
    watchdog: DovecotOperatorProbeWatchdog =
        DovecotOperatorProbeWatchdog { AutoCloseable {} },
) {
    private val finiteExchange = DovecotOperatorFiniteExchangeRunner(
        transportFactory = transportFactory,
        clock = clock,
        watchdog = watchdog,
        operationWorkers = operationWorkers,
    )

    fun greetingReadiness(): DovecotOperatorProbeResult =
        executeGreetingProtocol {
            DovecotOperatorProbeResult.Success
        }

    fun requireLoginOnlyCapability(): DovecotOperatorProbeResult =
        executeGreetingProtocol { io ->
            io.writeCommand(CAPABILITY_COMMAND)
            readLoginOnlyCapability(io)
        }

    fun authenticateLogin(
        username: String,
        password: EligibilityPassword,
    ): DovecotOperatorProbeResult {
        val usernameBytes = requireLoginUsername(username)
        return try {
            password.withBytes { passwordBytes ->
                authenticateLogin(
                    usernameBytes = usernameBytes,
                    passwordBytes = passwordBytes,
                )
            }
        } finally {
            usernameBytes.fill(0)
        }
    }

    fun authenticateLogin(
        username: String,
        credential: DovecotOperatorCredential,
    ): DovecotOperatorProbeResult =
        try {
            val usernameBytes = requireLoginUsername(username)
            try {
                credential.withSecretBytes { secretBytes ->
                    authenticateLogin(
                        usernameBytes = usernameBytes,
                        passwordBytes = secretBytes,
                    )
                }
            } finally {
                usernameBytes.fill(0)
            }
        } finally {
            credential.close()
        }

    fun authenticateBareTarget(
        target: DovecotOperatorTarget,
        password: EligibilityPassword,
    ): DovecotOperatorProbeResult =
        authenticateLogin(
            username = target.address,
            password = password,
        )

    fun authenticateCombinedMasterTarget(
        target: DovecotOperatorTarget,
        credential: DovecotOperatorCredential,
    ): DovecotOperatorProbeResult {
        val targetBytes = target.address.toByteArray(Charsets.US_ASCII)
        val masterBytes =
            credential.id.masterUsername.toByteArray(Charsets.US_ASCII)
        val combinedUsername = ByteArray(
            targetBytes.size + MASTER_SEPARATOR.size + masterBytes.size,
        )
        return try {
            var offset = 0
            targetBytes.copyInto(
                combinedUsername,
                destinationOffset = offset,
            )
            offset += targetBytes.size
            MASTER_SEPARATOR.copyInto(
                combinedUsername,
                destinationOffset = offset,
            )
            offset += MASTER_SEPARATOR.size
            masterBytes.copyInto(
                combinedUsername,
                destinationOffset = offset,
            )
            credential.withSecretBytes { secretBytes ->
                authenticateLogin(
                    usernameBytes = combinedUsername,
                    passwordBytes = secretBytes,
                )
            }
        } finally {
            credential.close()
            targetBytes.fill(0)
            masterBytes.fill(0)
            combinedUsername.fill(0)
        }
    }

    fun authenticatePlainAuthzidMaster(
        target: DovecotOperatorTarget,
        credential: DovecotOperatorCredential,
    ): DovecotOperatorProbeResult {
        val targetBytes = target.address.toByteArray(Charsets.US_ASCII)
        val masterBytes =
            credential.id.masterUsername.toByteArray(Charsets.US_ASCII)
        return try {
            credential.withSecretBytes { secretBytes ->
                val payload = ByteArray(
                    targetBytes.size + masterBytes.size +
                        secretBytes.size + PLAIN_SEPARATOR_BYTES,
                )
                try {
                    var offset = 0
                    targetBytes.copyInto(
                        payload,
                        destinationOffset = offset,
                    )
                    offset += targetBytes.size + 1
                    masterBytes.copyInto(
                        payload,
                        destinationOffset = offset,
                    )
                    offset += masterBytes.size + 1
                    secretBytes.copyInto(
                        payload,
                        destinationOffset = offset,
                    )
                    executeGreetingProtocol { io ->
                        writePlainAndReadCompletion(
                            io = io,
                            payload = payload,
                            secretBytes = secretBytes,
                        )
                    }
                } finally {
                    payload.fill(0)
                }
            }
        } finally {
            credential.close()
            targetBytes.fill(0)
            masterBytes.fill(0)
        }
    }

    override fun toString(): String =
        "DovecotOperatorBoundedExchange(fixed, redacted)"

    private fun authenticateLogin(
        usernameBytes: ByteArray,
        passwordBytes: ByteArray,
    ): DovecotOperatorProbeResult =
        executeGreetingProtocol { io ->
            io.writeCommand(AUTHENTICATE_LOGIN_COMMAND)
            requireExactLine(io, USERNAME_CHALLENGE)
            writeBase64Line(io, usernameBytes)
            requireExactLine(io, PASSWORD_CHALLENGE)
            writeBase64Line(io, passwordBytes)
            readAuthenticationCompletion(io)
        }

    private fun executeGreetingProtocol(
        protocol:
            (DovecotOperatorBoundedIo) -> DovecotOperatorProbeResult,
    ): DovecotOperatorProbeResult {
        val selected = finiteExchange.execute { io, _ ->
            try {
                if (hasValidGreeting(io)) {
                    protocol(io)
                } else {
                    DovecotOperatorProbeResult.ProtocolFailure
                }
            } catch (_: DovecotOperatorProtocolException) {
                DovecotOperatorProbeResult.ProtocolFailure
            }
        }
        return if (Thread.currentThread().isInterrupted) {
            DovecotOperatorProbeResult.TransportFailure
        } else {
            selected
        }
    }

    private fun hasValidGreeting(
        io: DovecotOperatorBoundedIo,
    ): Boolean =
        io.readLine().useWiped { greeting ->
            greeting.hasAsciiTokenAt(0, "* OK")
        }

    private fun readLoginOnlyCapability(
        io: DovecotOperatorBoundedIo,
    ): DovecotOperatorProbeResult {
        var sawCapability = false
        repeat(MAX_RESPONSE_LINES) {
            io.readLine().useWiped { line ->
                when {
                    line.hasAsciiTokenAt(0, "* CAPABILITY") -> {
                        if (
                            sawCapability ||
                            !line.hasAsciiToken("AUTH=LOGIN") ||
                            line.hasAsciiToken("AUTH=PLAIN")
                        ) {
                            return DovecotOperatorProbeResult.ProtocolFailure
                        }
                        sawCapability = true
                    }
                    line.hasAsciiTokenAt(0, CAPABILITY_TAG) -> {
                        return if (
                            sawCapability &&
                            line.hasTaggedStatus(
                                CAPABILITY_TAG,
                                "OK",
                            )
                        ) {
                            DovecotOperatorProbeResult.Success
                        } else {
                            DovecotOperatorProbeResult.ProtocolFailure
                        }
                    }
                }
            }
        }
        return DovecotOperatorProbeResult.ProtocolFailure
    }

    private fun requireExactLine(
        io: DovecotOperatorBoundedIo,
        expected: ByteArray,
    ) {
        io.readLine().useWiped { line ->
            if (!line.contentEquals(expected)) {
                throw DovecotOperatorProtocolException()
            }
        }
    }

    private fun readAuthenticationCompletion(
        io: DovecotOperatorBoundedIo,
    ): DovecotOperatorProbeResult =
        io.readLine().useWiped { completion ->
            when (
                DovecotAuthenticationResponseClassifier.classifyImap(
                    line = completion,
                    tag = AUTHENTICATE_LOGIN_TAG,
                )
            ) {
                DovecotAuthenticationResponse.Success ->
                    DovecotOperatorProbeResult.Success
                DovecotAuthenticationResponse.PermanentFailure ->
                    DovecotOperatorProbeResult.AuthenticationFailure
                DovecotAuthenticationResponse.AuthorizationFailure ->
                    DovecotOperatorProbeResult.AuthorizationFailure
                DovecotAuthenticationResponse.Indeterminate ->
                    DovecotOperatorProbeResult.ProtocolFailure
            }
        }

    private fun writeBase64Line(
        io: DovecotOperatorBoundedIo,
        raw: ByteArray,
    ) {
        val encoded = Base64.getEncoder().encode(raw)
        val command = ByteArray(encoded.size + CRLF.size)
        try {
            check(encoded.size <= MAX_AUTH_RESPONSE_BYTES) {
                "Dovecot operator authentication response exceeded its bound"
            }
            encoded.copyInto(command)
            CRLF.copyInto(command, destinationOffset = encoded.size)
            io.writeCommand(command)
        } finally {
            encoded.fill(0)
            command.fill(0)
        }
    }

    private fun writePlainAndReadCompletion(
        io: DovecotOperatorBoundedIo,
        payload: ByteArray,
        secretBytes: ByteArray,
    ): DovecotOperatorProbeResult {
        val encoded = Base64.getEncoder().encode(payload)
        val command = ByteArray(
            AUTHENTICATE_PLAIN_PREFIX.size + encoded.size + CRLF.size,
        )
        try {
            check(encoded.size <= MAX_AUTH_RESPONSE_BYTES) {
                "Dovecot operator authentication response exceeded its bound"
            }
            var offset = 0
            AUTHENTICATE_PLAIN_PREFIX.copyInto(
                command,
                destinationOffset = offset,
            )
            offset += AUTHENTICATE_PLAIN_PREFIX.size
            encoded.copyInto(command, destinationOffset = offset)
            offset += encoded.size
            CRLF.copyInto(command, destinationOffset = offset)
            io.writeCommand(command)
            return io.readLine().useWiped { completion ->
                if (
                    completion.containsBytes(encoded) ||
                    completion.containsBytes(secretBytes)
                ) {
                    DovecotOperatorProbeResult.ProtocolFailure
                } else when {
                    completion.hasTaggedStatus(
                        AUTHENTICATE_PLAIN_TAG_TEXT,
                        "NO",
                    ) ||
                    completion.hasTaggedStatus(
                        AUTHENTICATE_PLAIN_TAG_TEXT,
                        "BAD",
                    ) -> DovecotOperatorProbeResult.AuthenticationFailure
                    completion.hasTaggedStatus(
                        AUTHENTICATE_PLAIN_TAG_TEXT,
                        "OK",
                    ) -> DovecotOperatorProbeResult.Success
                    else -> DovecotOperatorProbeResult.ProtocolFailure
                }
            }
        } finally {
            encoded.fill(0)
            command.fill(0)
        }
    }

    private fun requireLoginUsername(username: String): ByteArray {
        require(username.length in 1..MAX_LOGIN_USERNAME_BYTES) {
            "Dovecot operator login username is invalid"
        }
        require(
            username.all { character ->
                character.code in PRINTABLE_LOGIN_ASCII
            },
        ) {
            "Dovecot operator login username is invalid"
        }
        val bytes = username.toByteArray(Charsets.US_ASCII)
        try {
            require(
                bytes.size == username.length,
            ) {
                "Dovecot operator login username is invalid"
            }
            return bytes
        } catch (failure: Throwable) {
            bytes.fill(0)
            throw failure
        }
    }

    private fun ByteArray.hasTaggedStatus(
        tag: String,
        status: String,
    ): Boolean {
        if (!hasAsciiTokenAt(0, tag)) return false
        val statusOffset = tag.length + 1
        if (!hasAsciiTokenAt(statusOffset, status)) return false
        val textOffset = statusOffset + status.length
        return textOffset + 1 < size &&
            this[textOffset] == ' '.code.toByte() &&
            (textOffset + 1 until size).all { index ->
                this[index].toInt() in PRINTABLE_RESPONSE_ASCII
            }
    }

    private fun ByteArray.containsBytes(candidate: ByteArray): Boolean {
        if (candidate.isEmpty() || candidate.size > size) return false
        return (0..size - candidate.size).any { offset ->
            candidate.indices.all { index ->
                this[offset + index] == candidate[index]
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
            if (
                this[offset + index].asciiUppercase() !=
                token[index].code.toByte().asciiUppercase()
            ) {
                return false
            }
        }
        val end = offset + token.length
        return end == size || this[end] == ' '.code.toByte()
    }

    private fun ByteArray.hasAsciiToken(token: String): Boolean {
        if (token.isEmpty() || token.length > size) return false
        return (0..size - token.length).any { offset ->
            hasAsciiTokenAt(offset, token)
        }
    }

    private fun Byte.asciiUppercase(): Byte =
        if (this in 'a'.code.toByte()..'z'.code.toByte()) {
            (toInt() - ASCII_CASE_OFFSET).toByte()
        } else {
            this
        }

    private companion object {
        const val ASCII_CASE_OFFSET = 'a'.code - 'A'.code
        const val MAX_RESPONSE_LINES = 32
        const val CAPABILITY_TAG = "A899"
        const val AUTHENTICATE_PLAIN_TAG_TEXT = "A900"
        const val AUTHENTICATE_LOGIN_TAG_TEXT = "A901"
        const val MAX_AUTH_RESPONSE_BYTES = 4 * 1024
        const val MAX_LOGIN_USERNAME_BYTES = 1024
        const val PLAIN_SEPARATOR_BYTES = 2
        val PRINTABLE_LOGIN_ASCII = 0x21..0x7e
        val PRINTABLE_RESPONSE_ASCII = 0x20..0x7e
        val CAPABILITY_COMMAND =
            "$CAPABILITY_TAG CAPABILITY\r\n".toByteArray(Charsets.US_ASCII)
        val AUTHENTICATE_PLAIN_PREFIX =
            "$AUTHENTICATE_PLAIN_TAG_TEXT AUTHENTICATE PLAIN "
                .toByteArray(Charsets.US_ASCII)
        val AUTHENTICATE_LOGIN_TAG =
            AUTHENTICATE_LOGIN_TAG_TEXT.toByteArray(Charsets.US_ASCII)
        val AUTHENTICATE_LOGIN_COMMAND =
            "$AUTHENTICATE_LOGIN_TAG_TEXT AUTHENTICATE LOGIN\r\n"
                .toByteArray(Charsets.US_ASCII)
        val USERNAME_CHALLENGE =
            "+ VXNlcm5hbWU6".toByteArray(Charsets.US_ASCII)
        val PASSWORD_CHALLENGE =
            "+ UGFzc3dvcmQ6".toByteArray(Charsets.US_ASCII)
        val MASTER_SEPARATOR = "*".toByteArray(Charsets.US_ASCII)
        val CRLF = "\r\n".toByteArray(Charsets.US_ASCII)
    }
}
