package mail.sandbox.dashboard.server.gate.dovecot

import java.io.ByteArrayInputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.ConnectException
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.NoRouteToHostException
import java.net.Socket
import java.net.SocketTimeoutException
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.CertificateFactory
import java.util.Base64
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory

internal class DovecotIsolationProtocolProof private constructor(
    private val sslContext: SSLContext,
) {
    fun requireImapRejected(
        port: Int,
        combinedUsername: String,
        password: EligibilityPassword,
    ) {
        password.withBytes { bytes ->
            check(
                rawImapLogin(port, combinedUsername, bytes) ==
                    DovecotAuthenticationResponse.PermanentFailure,
            ) {
                "IMAP rejection was not permanent"
            }
        }
    }

    fun requireImapRejected(
        port: Int,
        combinedUsername: String,
        credential: DovecotOperatorCredential,
    ) {
        credential.withSecretBytes { bytes ->
            check(
                rawImapLogin(port, combinedUsername, bytes) ==
                    DovecotAuthenticationResponse.PermanentFailure,
            ) {
                "IMAP rejection was not permanent"
            }
        }
    }

    fun requireRawOperatorRejected(
        port: Int,
        target: String,
        credential: DovecotOperatorCredential,
    ) {
        credential.withSecretBytes { bytes ->
            check(
                rawImapLogin(
                    port = port,
                    username = task6MasterLogin(target, credential.id),
                    password = bytes,
                ) == DovecotAuthenticationResponse.PermanentFailure,
            ) {
                "Operator accepted forbidden raw target"
            }
        }
    }

    fun requirePop3Rejected(
        port: Int,
        username: String,
        credential: DovecotOperatorCredential,
    ) {
        val usernameBytes = username.toByteArray(StandardCharsets.US_ASCII)
        val socket = sslContext.socketFactory.createSocket() as SSLSocket
        try {
            configureTls(socket)
            socket.connect(loopbackEndpoint(port), SOCKET_TIMEOUT_MILLIS)
            socket.startHandshake()
            readBoundedLine(socket.inputStream).useBytes { greeting ->
                require(greeting.startsWithAscii("+OK")) {
                    "POP3 greeting was invalid"
                }
            }
            writeAsciiLine(socket.outputStream, "USER ", usernameBytes)
            val userResponse = readBoundedLine(socket.inputStream).useBytes(
                DovecotAuthenticationResponseClassifier::classifyPop3,
            )
            when (userResponse) {
                DovecotAuthenticationResponse.Success -> Unit
                DovecotAuthenticationResponse.PermanentFailure -> return
                DovecotAuthenticationResponse.Indeterminate ->
                    error("POP3 USER rejection was indeterminate")
            }
            credential.withSecretBytes { secret ->
                writeAsciiLine(socket.outputStream, "PASS ", secret)
            }
            readBoundedLine(socket.inputStream).useBytes { response ->
                check(
                    DovecotAuthenticationResponseClassifier.classifyPop3(
                        response,
                    ) == DovecotAuthenticationResponse.PermanentFailure,
                ) {
                    "POP3 rejection was indeterminate"
                }
            }
        } finally {
            usernameBytes.fill(0)
            runCatching(socket::close)
        }
    }

    fun requireSmtpRejected(
        port: Int,
        username: String,
        credential: DovecotOperatorCredential,
    ) {
        val usernameBytes = username.toByteArray(StandardCharsets.US_ASCII)
        try {
            Socket().use { socket ->
                socket.soTimeout = SOCKET_TIMEOUT_MILLIS
                socket.connect(loopbackEndpoint(port), SOCKET_TIMEOUT_MILLIS)
                readBoundedLine(socket.inputStream).useBytes {
                    require(it.startsWithAscii("220")) {
                        "SMTP greeting was invalid"
                    }
                }
                socket.outputStream.write(SMTP_EHLO)
                socket.outputStream.flush()
                readSmtpReply(socket.inputStream, "250")
                socket.outputStream.write(SMTP_AUTH_LOGIN)
                socket.outputStream.flush()
                requireSmtpCode(socket.inputStream, "334")
                writeBase64Line(socket.outputStream, usernameBytes)
                requireSmtpCode(socket.inputStream, "334")
                credential.withSecretBytes { secret ->
                    writeBase64Line(socket.outputStream, secret)
                }
                readBoundedLine(socket.inputStream).useBytes { response ->
                    check(response.isTerminalSmtpReply("535")) {
                        "SMTP SASL accepted the operator master credential"
                    }
                }
            }
        } finally {
            usernameBytes.fill(0)
        }
    }

    fun requireMasterOauthInactive(
        oauthPort: Int,
        credential: DovecotOperatorCredential,
    ) {
        credential.withSecretBytes { secret ->
            val body = ByteArray(INTROSPECT_PREFIX.size + secret.size)
            try {
                INTROSPECT_PREFIX.copyInto(body)
                secret.copyInto(body, destinationOffset = INTROSPECT_PREFIX.size)
                oauthClient(oauthPort)
                    .postForm("/introspect", body)
                    .use { response ->
                        check(response.status == 200)
                        check(!response.body.containsBytes(secret))
                        DovecotOAuthProofValidator.requireInactive(
                            response.body,
                        )
                    }
            } finally {
                body.fill(0)
            }
        }
    }

    fun requireProtectedOauthDenied(oauthPort: Int) {
        PROTECTED_TARGETS.forEach { protected ->
            val authorizeBody = (
                "action=allow&client_id=task6-client&" +
                    "redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback&" +
                    "scope=imap+smtp&state=task6&username=$protected"
                ).toByteArray(StandardCharsets.US_ASCII)
            try {
                oauthClient(oauthPort)
                    .postForm("/authorize", authorizeBody)
                    .use { response ->
                        check(response.status == 302) {
                            "Protected OAuth identity was not denied"
                        }
                        DovecotOAuthProofValidator
                            .requireAccessDeniedRedirect(
                                response.location.orEmpty(),
                            )
                    }
            } finally {
                authorizeBody.fill(0)
            }
            val tokenBody =
                "token=valid-$protected".toByteArray(StandardCharsets.US_ASCII)
            try {
                oauthClient(oauthPort)
                    .postForm("/introspect", tokenBody)
                    .use { response ->
                        check(response.status == 200)
                        DovecotOAuthProofValidator.requireInactive(
                            response.body,
                        )
                    }
            } finally {
                tokenBody.fill(0)
            }
        }
    }

    private fun rawImapLogin(
        port: Int,
        username: String,
        password: ByteArray,
    ): DovecotAuthenticationResponse {
        val usernameBytes = username.toByteArray(StandardCharsets.US_ASCII)
        val socket = sslContext.socketFactory.createSocket() as SSLSocket
        return try {
            configureTls(socket)
            socket.connect(loopbackEndpoint(port), SOCKET_TIMEOUT_MILLIS)
            socket.startHandshake()
            readBoundedLine(socket.inputStream).useBytes { greeting ->
                require(greeting.startsWithAscii("* OK")) {
                    "IMAP greeting was invalid"
                }
            }
            socket.outputStream.write(IMAP_AUTH_LOGIN)
            socket.outputStream.flush()
            requireContinuation(socket.inputStream, USERNAME_CHALLENGE)
            writeBase64Line(socket.outputStream, usernameBytes)
            requireContinuation(socket.inputStream, PASSWORD_CHALLENGE)
            writeBase64Line(socket.outputStream, password)
            readBoundedLine(socket.inputStream).useBytes { completion ->
                DovecotAuthenticationResponseClassifier.classifyImap(
                    line = completion,
                    tag = IMAP_AUTH_TAG,
                )
            }
        } finally {
            usernameBytes.fill(0)
            runCatching(socket::close)
        }
    }

    private fun oauthClient(port: Int): DovecotBoundedHttpProofClient =
        DovecotBoundedHttpProofClient(
            port = port,
            timeoutMillis = SOCKET_TIMEOUT_MILLIS,
            maximumResponseBytes = MAX_HTTP_RESPONSE_BYTES,
        )

    private fun requireContinuation(
        input: InputStream,
        expected: ByteArray,
    ) {
        readBoundedLine(input).useBytes {
            require(it.contentEquals(expected)) {
                "SASL LOGIN challenge was invalid"
            }
        }
    }

    private fun requireSmtpCode(input: InputStream, code: String) {
        readBoundedLine(input).useBytes {
            require(it.startsWithAscii(code)) {
                "SMTP SASL challenge was invalid"
            }
        }
    }

    private fun readSmtpReply(input: InputStream, code: String) {
        repeat(MAX_SMTP_REPLY_LINES) {
            readBoundedLine(input).useBytes { line ->
                require(line.startsWithAscii(code)) {
                    "SMTP EHLO response was invalid"
                }
                if (
                    line.size > code.length &&
                    line[code.length] == ' '.code.toByte()
                ) {
                    return
                }
            }
        }
        error("SMTP EHLO response exceeded its line bound")
    }

    private fun writeBase64Line(
        output: OutputStream,
        raw: ByteArray,
    ) {
        val encoded = Base64.getEncoder().encode(raw)
        val command = ByteArray(encoded.size + CRLF.size)
        try {
            encoded.copyInto(command)
            CRLF.copyInto(command, destinationOffset = encoded.size)
            output.write(command)
            output.flush()
        } finally {
            encoded.fill(0)
            command.fill(0)
        }
    }

    private fun writeAsciiLine(
        output: OutputStream,
        prefix: String,
        value: ByteArray,
    ) {
        val prefixBytes = prefix.toByteArray(StandardCharsets.US_ASCII)
        val command = ByteArray(prefixBytes.size + value.size + CRLF.size)
        try {
            prefixBytes.copyInto(command)
            value.copyInto(command, destinationOffset = prefixBytes.size)
            CRLF.copyInto(
                command,
                destinationOffset = prefixBytes.size + value.size,
            )
            output.write(command)
            output.flush()
        } finally {
            prefixBytes.fill(0)
            command.fill(0)
        }
    }

    private fun readBoundedLine(input: InputStream): ByteArray {
        val buffer = ByteArray(MAX_PROTOCOL_LINE_BYTES + 1)
        var size = 0
        try {
            while (true) {
                val value = input.read()
                check(value >= 0) { "Protocol response ended early" }
                if (value == '\n'.code) {
                    check(
                        size > 0 &&
                            buffer[size - 1] == '\r'.code.toByte(),
                    ) {
                        "Protocol response line was malformed"
                    }
                    return buffer.copyOf(size - 1)
                }
                check(size < MAX_PROTOCOL_LINE_BYTES) {
                    "Protocol response exceeded its bound"
                }
                buffer[size++] = value.toByte()
            }
        } finally {
            buffer.fill(0)
        }
    }

    private fun ByteArray.startsWithAscii(prefix: String): Boolean {
        val expected = prefix.toByteArray(StandardCharsets.US_ASCII)
        return try {
            size >= expected.size &&
                expected.indices.all { this[it] == expected[it] }
        } finally {
            expected.fill(0)
        }
    }

    private fun ByteArray.isTerminalSmtpReply(code: String): Boolean {
        val expected = code.toByteArray(StandardCharsets.US_ASCII)
        return try {
            size > expected.size + 1 &&
                expected.indices.all { this[it] == expected[it] } &&
                this[expected.size] == ' '.code.toByte() &&
                (expected.size + 1 until size).all { index ->
                    this[index] == '\t'.code.toByte() ||
                        this[index].toInt() in 32..126
                }
        } finally {
            expected.fill(0)
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

    private inline fun <T> ByteArray.useBytes(
        block: (ByteArray) -> T,
    ): T = try {
        block(this)
    } finally {
        fill(0)
    }

    private fun configureTls(socket: SSLSocket) {
        socket.enabledProtocols = socket.enabledProtocols.filter {
            it == "TLSv1.3" || it == "TLSv1.2"
        }.toTypedArray()
        socket.soTimeout = SOCKET_TIMEOUT_MILLIS
    }

    private fun loopbackEndpoint(port: Int): InetSocketAddress =
        InetSocketAddress(LOOPBACK, port)

    companion object {
        fun pinned(
            profile: DovecotTask5ProofProfile,
        ): DovecotIsolationProtocolProof {
            val certificateBytes = profile.readStableTlsCertificate()
            val certificate = try {
                ByteArrayInputStream(certificateBytes).use {
                    CertificateFactory.getInstance("X.509")
                        .generateCertificate(it)
                }
            } finally {
                certificateBytes.fill(0)
            }
            val keyStore =
                KeyStore.getInstance(KeyStore.getDefaultType()).apply {
                    load(null, null)
                    setCertificateEntry("task6-proof", certificate)
                }
            val trustManagers = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm(),
            ).apply {
                init(keyStore)
            }.trustManagers
            val sslContext = SSLContext.getInstance("TLS").apply {
                init(null, trustManagers, SecureRandom())
            }
            return DovecotIsolationProtocolProof(sslContext)
        }

        private const val SOCKET_TIMEOUT_MILLIS = 1_000
        private const val MAX_PROTOCOL_LINE_BYTES = 16 * 1024
        private const val MAX_SMTP_REPLY_LINES = 64
        private const val MAX_HTTP_RESPONSE_BYTES = 16 * 1024
        private val LOOPBACK =
            InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
        private val CRLF =
            "\r\n".toByteArray(StandardCharsets.US_ASCII)
        private val IMAP_AUTH_LOGIN =
            "A601 AUTHENTICATE LOGIN\r\n"
                .toByteArray(StandardCharsets.US_ASCII)
        private val IMAP_AUTH_TAG =
            "A601".toByteArray(StandardCharsets.US_ASCII)
        private val USERNAME_CHALLENGE =
            "+ VXNlcm5hbWU6".toByteArray(StandardCharsets.US_ASCII)
        private val PASSWORD_CHALLENGE =
            "+ UGFzc3dvcmQ6".toByteArray(StandardCharsets.US_ASCII)
        private val SMTP_EHLO =
            "EHLO task6-proof.local\r\n"
                .toByteArray(StandardCharsets.US_ASCII)
        private val SMTP_AUTH_LOGIN =
            "AUTH LOGIN\r\n".toByteArray(StandardCharsets.US_ASCII)
        private val INTROSPECT_PREFIX =
            "token=".toByteArray(StandardCharsets.US_ASCII)
        private val PROTECTED_TARGETS = listOf(
            "dashboard-management@local.test",
            "dashboard-operator-a@local.test",
            "dashboard-operator-b@local.test",
        )
    }
}

internal fun task6MasterLogin(
    targetAddress: String,
    masterId: DovecotOperatorId,
): String = "$targetAddress*${masterId.masterUsername}"

internal fun task6InactiveMasterLogin(
    targetAddress: String,
    activeMasterId: DovecotOperatorId,
): String = task6MasterLogin(
    targetAddress = targetAddress,
    masterId = DovecotOperatorId.entries.single {
        it != activeMasterId
    },
)

internal fun task6RequireInactiveMasterRejected(
    port: Int,
    targetAddress: String,
    activeCredential: DovecotOperatorCredential,
    requireRejected: (
        Int,
        String,
        DovecotOperatorCredential,
    ) -> Unit,
) {
    requireRejected(
        port,
        task6InactiveMasterLogin(targetAddress, activeCredential.id),
        activeCredential,
    )
}

internal fun task6IsHostNonLoopbackIpv4(address: Inet4Address): Boolean =
    !address.isAnyLocalAddress && !address.isLoopbackAddress

internal fun task6IsExpectedTcpRejection(failure: Throwable): Boolean =
    failure is ConnectException ||
        failure is NoRouteToHostException ||
        failure is SocketTimeoutException

internal fun discoverTask6HostNonLoopbackIpv4(): List<Inet4Address> {
    val addresses = NetworkInterface.getNetworkInterfaces()
        ?.toList()
        .orEmpty()
        .filter { it.isUp }
        .flatMap { it.inetAddresses.toList() }
        .filterIsInstance<Inet4Address>()
        .filter(::task6IsHostNonLoopbackIpv4)
        .distinctBy { it.hostAddress }
        .sortedBy { it.hostAddress }
    require(addresses.isNotEmpty()) {
        "No non-loopback host IPv4 address was discoverable"
    }
    return addresses
}

internal fun requireTask6TcpRejected(
    address: InetAddress,
    port: Int,
) {
    val rejected = try {
        Socket().use { socket ->
            socket.connect(
                InetSocketAddress(address, port),
                NETWORK_NEGATIVE_TIMEOUT_MILLIS,
            )
        }
        false
    } catch (failure: Throwable) {
        if (!task6IsExpectedTcpRejection(failure)) {
            throw failure
        }
        true
    }
    check(rejected) {
        "A non-loopback host interface reached a loopback-only proof port"
    }
}

private const val NETWORK_NEGATIVE_TIMEOUT_MILLIS = 500
