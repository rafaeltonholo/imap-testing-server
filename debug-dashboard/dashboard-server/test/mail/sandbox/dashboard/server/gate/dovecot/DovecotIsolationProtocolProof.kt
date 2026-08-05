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

internal const val TASK6_PROTOCOL_CONNECT_TIMEOUT_MILLIS = 1_000
internal const val TASK6_AUTHENTICATION_READ_TIMEOUT_MILLIS = 20_000

internal interface Task6ProtocolReadDeadline {
    fun beforeRead()

    fun afterRead()
}

internal class Task6AuthenticationReadDeadline(
    timeoutMillis: Int,
    private val nanoTime: () -> Long,
    private val applyReadTimeoutMillis: (Int) -> Unit,
) : Task6ProtocolReadDeadline {
    private val timeoutNanos: Long
    private val startedAtNanos: Long

    init {
        require(timeoutMillis > 0) {
            "Authentication response deadline must be positive"
        }
        timeoutNanos = Math.multiplyExact(
            timeoutMillis.toLong(),
            NANOS_PER_MILLISECOND,
        )
        startedAtNanos = nanoTime()
    }

    override fun beforeRead() {
        val remainingNanos = remainingNanosOrThrow()
        val remainingMillis = (
            (remainingNanos - 1L) / NANOS_PER_MILLISECOND + 1L
            ).coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
        applyReadTimeoutMillis(remainingMillis)
    }

    override fun afterRead() {
        remainingNanosOrThrow()
    }

    private fun remainingNanosOrThrow(): Long {
        val elapsedNanos = nanoTime() - startedAtNanos
        val remainingNanos = timeoutNanos - elapsedNanos
        if (remainingNanos <= 0L) {
            throw SocketTimeoutException(
                "Authentication response deadline expired",
            )
        }
        return remainingNanos
    }

    private companion object {
        const val NANOS_PER_MILLISECOND = 1_000_000L
    }
}

internal fun requireDovecotOperatorTargetRejected(
    target: String,
    activeMasterId: DovecotOperatorId,
    response: DovecotOperatorProbeResult,
) {
    val expected =
        if (target == activeMasterId.masterUsername) {
            DovecotOperatorProbeResult.AuthenticationFailure
        } else {
            DovecotOperatorProbeResult.AuthorizationFailure
        }
    check(response == expected) {
        "Operator forbidden target rejection had the wrong failure class"
    }
}

internal class DovecotIsolationProtocolProof private constructor(
    private val sslContext: SSLContext,
    private val operatorExchange: DovecotOperatorBoundedExchange?,
    private val ordinaryImapsPort: Int?,
) {
    private constructor(sslContext: SSLContext) : this(
        sslContext = sslContext,
        operatorExchange = null,
        ordinaryImapsPort = null,
    )

    private constructor(
        sslContext: SSLContext,
        operatorExchange: DovecotOperatorBoundedExchange,
    ) : this(
        sslContext = sslContext,
        operatorExchange = operatorExchange,
        ordinaryImapsPort = null,
    )

    fun requireOperatorImapRejected(
        combinedUsername: String,
        password: EligibilityPassword,
    ) {
        requirePermanentOperatorImapRejection(
            requireOperatorExchange().authenticateLogin(
                username = combinedUsername,
                password = password,
            ),
        )
    }

    fun requireOperatorImapRejected(
        combinedUsername: String,
        credential: DovecotOperatorCredential,
    ) {
        requirePermanentOperatorImapRejection(
            requireOperatorExchange().authenticateLogin(
                username = combinedUsername,
                credential = credential,
            ),
        )
    }

    private fun requirePermanentOperatorImapRejection(
        result: DovecotOperatorProbeResult,
    ) {
        check(result == DovecotOperatorProbeResult.AuthenticationFailure) {
            "Operator IMAP rejection was not permanent: ${result.name}"
        }
    }

    fun requireOrdinaryImapRejected(
        combinedUsername: String,
        credential: DovecotOperatorCredential,
    ) {
        credential.withSecretBytes { bytes ->
            check(
                ordinaryImapLogin(combinedUsername, bytes) ==
                    DovecotAuthenticationResponse.PermanentFailure,
            ) {
                "Ordinary IMAP rejection was not permanent"
            }
        }
    }

    fun requireRawOperatorRejected(
        target: String,
        credential: DovecotOperatorCredential,
    ) {
        val activeMasterId = credential.id
        requireDovecotOperatorTargetRejected(
            target = target,
            activeMasterId = activeMasterId,
            response = requireOperatorExchange()
                .authenticateLogin(
                    username = task6MasterLogin(target, activeMasterId),
                    credential = credential,
                ),
        )
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
            socket.connect(
                loopbackEndpoint(port),
                TASK6_PROTOCOL_CONNECT_TIMEOUT_MILLIS,
            )
            socket.startHandshake()
            readBoundedLine(
                socket.inputStream,
                setupReadDeadline(socket),
            ).useBytes { greeting ->
                require(greeting.startsWithAscii("+OK")) {
                    "POP3 greeting was invalid"
                }
            }
            val readDeadline = authenticationReadDeadline(socket)
            writeAsciiLine(socket.outputStream, "USER ", usernameBytes)
            val userResponse = readBoundedLine(
                socket.inputStream,
                readDeadline,
            ).useBytes(
                DovecotAuthenticationResponseClassifier::classifyPop3,
            )
            when (userResponse) {
                DovecotAuthenticationResponse.Success -> Unit
                DovecotAuthenticationResponse.PermanentFailure -> return
                DovecotAuthenticationResponse.AuthorizationFailure,
                DovecotAuthenticationResponse.Indeterminate ->
                    error("POP3 USER rejection was indeterminate")
            }
            credential.withSecretBytes { secret ->
                writeAsciiLine(socket.outputStream, "PASS ", secret)
            }
            readBoundedLine(socket.inputStream, readDeadline).useBytes { response ->
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
                socket.soTimeout =
                    TASK6_AUTHENTICATION_READ_TIMEOUT_MILLIS
                socket.connect(
                    loopbackEndpoint(port),
                    TASK6_PROTOCOL_CONNECT_TIMEOUT_MILLIS,
                )
                val setupReadDeadline = setupReadDeadline(socket)
                readBoundedLine(socket.inputStream, setupReadDeadline).useBytes {
                    require(it.startsWithAscii("220")) {
                        "SMTP greeting was invalid"
                    }
                }
                socket.outputStream.write(SMTP_EHLO)
                socket.outputStream.flush()
                readSmtpReply(socket.inputStream, "250", setupReadDeadline)
                val readDeadline = authenticationReadDeadline(socket)
                socket.outputStream.write(SMTP_AUTH_LOGIN)
                socket.outputStream.flush()
                requireSmtpCode(socket.inputStream, "334", readDeadline)
                writeBase64Line(socket.outputStream, usernameBytes)
                if (
                    !requireSmtpPasswordOrEarlyRejection(
                        socket.inputStream,
                        readDeadline,
                    )
                ) {
                    return
                }
                credential.withSecretBytes { secret ->
                    writeBase64Line(socket.outputStream, secret)
                }
                readBoundedLine(socket.inputStream, readDeadline).useBytes { response ->
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

    private fun ordinaryImapLogin(
        username: String,
        password: ByteArray,
    ): DovecotAuthenticationResponse {
        val usernameBytes = username.toByteArray(StandardCharsets.US_ASCII)
        val socket = sslContext.socketFactory.createSocket() as SSLSocket
        return try {
            configureTls(socket)
            socket.connect(
                loopbackEndpoint(requireOrdinaryImapsPort()),
                TASK6_PROTOCOL_CONNECT_TIMEOUT_MILLIS,
            )
            socket.startHandshake()
            readBoundedLine(
                socket.inputStream,
                setupReadDeadline(socket),
            ).useBytes { greeting ->
                require(greeting.startsWithAscii("* OK")) {
                    "IMAP greeting was invalid"
                }
            }
            val readDeadline = authenticationReadDeadline(socket)
            ordinaryImapLoginExchange(
                input = socket.inputStream,
                output = socket.outputStream,
                username = usernameBytes,
                password = password,
                readDeadline = readDeadline,
            )
        } finally {
            usernameBytes.fill(0)
            runCatching(socket::close)
        }
    }

    private fun oauthClient(port: Int): DovecotBoundedHttpProofClient =
        DovecotBoundedHttpProofClient(
            port = port,
            timeoutMillis = TASK6_PROTOCOL_CONNECT_TIMEOUT_MILLIS,
            maximumResponseBytes = MAX_HTTP_RESPONSE_BYTES,
        )

    internal fun ordinaryImapLoginExchange(
        input: InputStream,
        output: OutputStream,
        username: ByteArray,
        password: ByteArray,
        readDeadline: Task6ProtocolReadDeadline,
    ): DovecotAuthenticationResponse {
        output.write(IMAP_AUTH_LOGIN)
        output.flush()
        requireContinuation(input, USERNAME_CHALLENGE, readDeadline)
        writeBase64Line(output, username)

        val earlyResult = readBoundedLine(input, readDeadline).useBytes { response ->
            if (response.contentEquals(PASSWORD_CHALLENGE)) {
                null
            } else {
                DovecotAuthenticationResponseClassifier.classifyImap(
                    line = response,
                    tag = IMAP_AUTH_TAG,
                ).also { result ->
                    check(
                        result ==
                            DovecotAuthenticationResponse.PermanentFailure,
                    ) {
                        "Ordinary IMAP early rejection was not permanent"
                    }
                }
            }
        }
        if (earlyResult != null) return earlyResult

        writeBase64Line(output, password)
        return readBoundedLine(input, readDeadline).useBytes { completion ->
            DovecotAuthenticationResponseClassifier.classifyImap(
                line = completion,
                tag = IMAP_AUTH_TAG,
            )
        }
    }

    private fun requireContinuation(
        input: InputStream,
        expected: ByteArray,
        readDeadline: Task6ProtocolReadDeadline,
    ) {
        readBoundedLine(input, readDeadline).useBytes {
            require(it.contentEquals(expected)) {
                "SASL LOGIN challenge was invalid"
            }
        }
    }

    private fun requireSmtpCode(
        input: InputStream,
        code: String,
        readDeadline: Task6ProtocolReadDeadline,
    ) {
        readBoundedLine(input, readDeadline).useBytes {
            require(it.isTerminalSmtpReply(code)) {
                "SMTP SASL challenge was invalid"
            }
        }
    }

    private fun requireSmtpPasswordOrEarlyRejection(
        input: InputStream,
        readDeadline: Task6ProtocolReadDeadline,
    ): Boolean = readBoundedLine(input, readDeadline).useBytes { response ->
        when {
            response.isTerminalSmtpReply("334") -> true
            response.isTerminalSmtpReply("535") -> false
            else -> error("SMTP SASL username response was indeterminate")
        }
    }

    private fun readSmtpReply(
        input: InputStream,
        code: String,
        readDeadline: Task6ProtocolReadDeadline,
    ) {
        repeat(MAX_SMTP_REPLY_LINES) {
            readBoundedLine(input, readDeadline).useBytes { line ->
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

    private fun readBoundedLine(
        input: InputStream,
        readDeadline: Task6ProtocolReadDeadline,
    ): ByteArray {
        val buffer = ByteArray(MAX_PROTOCOL_LINE_BYTES + 1)
        var size = 0
        try {
            while (true) {
                readDeadline.beforeRead()
                val value = input.read()
                readDeadline.afterRead()
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
        socket.soTimeout = TASK6_PROTOCOL_CONNECT_TIMEOUT_MILLIS
    }

    private fun authenticationReadDeadline(
        socket: Socket,
    ): Task6AuthenticationReadDeadline = Task6AuthenticationReadDeadline(
        timeoutMillis = TASK6_AUTHENTICATION_READ_TIMEOUT_MILLIS,
        nanoTime = System::nanoTime,
        applyReadTimeoutMillis = { remainingMillis ->
            socket.soTimeout = remainingMillis
        },
    )

    private fun setupReadDeadline(
        socket: Socket,
    ): Task6AuthenticationReadDeadline = Task6AuthenticationReadDeadline(
        timeoutMillis = TASK6_PROTOCOL_CONNECT_TIMEOUT_MILLIS,
        nanoTime = System::nanoTime,
        applyReadTimeoutMillis = { remainingMillis ->
            socket.soTimeout = remainingMillis
        },
    )

    private fun loopbackEndpoint(port: Int): InetSocketAddress =
        InetSocketAddress(LOOPBACK, port)

    private fun requireOperatorExchange(): DovecotOperatorBoundedExchange =
        checkNotNull(operatorExchange) {
            "Dovecot operator bounded exchange is unavailable"
        }

    private fun requireOrdinaryImapsPort(): Int =
        checkNotNull(ordinaryImapsPort) {
            "Dovecot ordinary IMAP endpoint is unavailable"
        }

    companion object {
        fun pinned(
            profile: DovecotTask5ProofProfile,
            operatorExchange: DovecotOperatorBoundedExchange,
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
            return DovecotIsolationProtocolProof(
                sslContext = sslContext,
                operatorExchange = operatorExchange,
                ordinaryImapsPort = profile.ordinaryImapsPort,
            )
        }

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
    targetAddress: String,
    activeCredential: DovecotOperatorCredential,
    requireRejected: (
        String,
        DovecotOperatorCredential,
    ) -> Unit,
) {
    requireRejected(
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
