package mail.sandbox.dashboard.server.gate.dovecot

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.io.PrintStream
import java.net.ConnectException
import java.net.HttpURLConnection
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.NoRouteToHostException
import java.net.Socket
import java.net.SocketTimeoutException
import java.net.URI
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.CertificateFactory
import java.time.Duration
import java.util.Base64
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DovecotIsolationLiveTest {
    @Test
    fun masterCredentialAndOperatorIngressAreIsolatedFromEveryOtherPath() {
        val repositoryRoot = repositoryRoot()
        val live = DovecotLiveTestEnvironment.load(
            environment = System.getenv(),
            repositoryRoot = repositoryRoot,
        )
        live.awaitReady()
        val topology = FixedTask6DockerTopology(live.profile)
        val runtime = topology.inspect()
        runtime.requireExactIsolation()

        val hostAddresses = discoverHostNonLoopbackIpv4()
        hostAddresses.forEach { address ->
            assertTcpRejected(address, live.ordinaryImapsPort)
            assertTcpRejected(address, live.operatorImapsPort)
        }
        topology.requireDefaultNetworkIsolation(
            operatorIngressAddress = runtime.operatorIngressAddress,
            hostAddresses = hostAddresses,
        )

        val address =
            "task6-isolation-" +
                UUID.randomUUID().toString().replace("-", "") +
                "@local.test"
        val target = DovecotOperatorTarget.create(address)
        val eligibilityPaths = live.profile.eligibilityPaths()
        val eligibilityCli = EligibilityFileCli(
            pathsProvider = { eligibilityPaths },
            hasherFactory = { root ->
                DovecotPasswordHasher(
                    root,
                    JvmEligibilityProcessRunner(
                        dockerRouting =
                            DovecotDockerRouting.task5Proof(live.profile),
                    ),
                )
            },
        )
        val store = DovecotOperatorCredentialStore(
            paths = live.profile.operatorPaths(),
            generator = DovecotOperatorSecretGenerator {
                error("isolation proof must not generate an operator secret")
            },
            hasher = DovecotOperatorHashBoundary {
                error("isolation proof must not hash an operator secret")
            },
            verifier = ExistingDovecotOperatorHashVerifier(
                repositoryRoot,
                JvmEligibilityProcessRunner(
                    dockerRouting =
                        DovecotDockerRouting.task5Proof(live.profile),
                ),
            ),
        )
        val probe = DovecotOperatorProbe(
            transportFactory =
                JvmJsseDovecotOperatorTransportFactory.task5Proof(
                    live.profile,
                ),
            requireMailboxRead = true,
        )
        val sslContext = pinnedSslContext(live.profile)
        var targetAdded = false
        var targetRemoved = false
        var primaryFailure: Throwable? = null
        try {
            require(address !in EligibilityFile(eligibilityPaths).list()) {
                "Disposable isolation target unexpectedly exists"
            }
            generateTargetPassword().use { targetPassword ->
                addEligibleTarget(
                    cli = eligibilityCli,
                    address = address,
                    password = targetPassword,
                )
                targetAdded = true

                assertEquals(
                    DovecotOperatorProbeResult.Success,
                    probe.probe(target, store.loadActive()),
                )
                store.loadActive().use { master ->
                    assertImapRejected(
                        sslContext,
                        live.operatorImapsPort,
                        task6MasterLogin(address, master.id),
                        targetPassword,
                    )
                    assertImapRejected(
                        sslContext,
                        live.operatorImapsPort,
                        "$address*absent-master",
                        targetPassword,
                    )
                    assertImapRejected(
                        sslContext,
                        live.ordinaryImapsPort,
                        task6MasterLogin(address, master.id),
                        master,
                    )
                    assertPop3Rejected(
                        sslContext,
                        live.ordinaryPop3sPort,
                        task6MasterLogin(address, master.id),
                        master,
                    )
                    assertSmtpRejected(
                        live.smtpPort,
                        task6MasterLogin(address, master.id),
                        master,
                    )
                    assertMasterOauthInactive(live.oauthPort, master)
                }

                store.loadActive().use { master ->
                    assertRawOperatorRejected(
                        sslContext,
                        live.operatorImapsPort,
                        "absent-${UUID.randomUUID()}@local.test",
                        master,
                    )
                    PROTECTED_TARGETS.forEach { protected ->
                        assertRawOperatorRejected(
                            sslContext,
                            live.operatorImapsPort,
                            protected,
                            master,
                        )
                    }
                    DovecotOperatorId.entries.forEach { id ->
                        assertRawOperatorRejected(
                            sslContext,
                            live.operatorImapsPort,
                            id.masterUsername,
                            master,
                        )
                    }
                }
                assertProtectedOauthDenied(live.oauthPort)

                removeEligibleTarget(eligibilityCli, address)
                targetRemoved = true
                awaitDovecotOperatorTargetRejection(
                    resultSupplier = {
                        probe.probe(target, store.loadActive())
                    },
                )
            }
        } catch (failure: Throwable) {
            primaryFailure = failure
            throw failure
        } finally {
            try {
                if (
                    targetAdded &&
                    !targetRemoved &&
                    address in EligibilityFile(eligibilityPaths).list()
                ) {
                    removeEligibleTarget(eligibilityCli, address)
                    awaitDovecotOperatorTargetRejection(
                        resultSupplier = {
                            probe.probe(target, store.loadActive())
                        },
                    )
                }
            } catch (cleanupFailure: Throwable) {
                val primary = primaryFailure
                if (primary != null) {
                    primary.addSuppressed(cleanupFailure)
                } else {
                    throw cleanupFailure
                }
            }
        }
    }

    private fun assertImapRejected(
        sslContext: SSLContext,
        port: Int,
        combinedUsername: String,
        password: EligibilityPassword,
    ) {
        password.withBytes { bytes ->
            assertEquals(
                RawAuthenticationResult.AuthenticationFailure,
                rawImapLogin(
                    sslContext,
                    port,
                    combinedUsername,
                    bytes,
                ),
            )
        }
    }

    private fun assertImapRejected(
        sslContext: SSLContext,
        port: Int,
        combinedUsername: String,
        credential: DovecotOperatorCredential,
    ) {
        credential.withSecretBytes { bytes ->
            assertEquals(
                RawAuthenticationResult.AuthenticationFailure,
                rawImapLogin(
                    sslContext,
                    port,
                    combinedUsername,
                    bytes,
                ),
            )
        }
    }

    private fun assertRawOperatorRejected(
        sslContext: SSLContext,
        port: Int,
        target: String,
        credential: DovecotOperatorCredential,
    ) {
        credential.withSecretBytes { bytes ->
            assertEquals(
                RawAuthenticationResult.AuthenticationFailure,
                rawImapLogin(
                    sslContext,
                    port,
                    task6MasterLogin(target, credential.id),
                    bytes,
                ),
                "Operator accepted forbidden raw target",
            )
        }
    }

    private fun rawImapLogin(
        sslContext: SSLContext,
        port: Int,
        username: String,
        password: ByteArray,
    ): RawAuthenticationResult {
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
                when {
                    completion.startsWithAscii("A601 OK") ->
                        RawAuthenticationResult.Success
                    completion.startsWithAscii("A601 NO") ->
                        RawAuthenticationResult.AuthenticationFailure
                    else -> RawAuthenticationResult.ProtocolFailure
                }
            }
        } finally {
            usernameBytes.fill(0)
            runCatching(socket::close)
        }
    }

    private fun assertPop3Rejected(
        sslContext: SSLContext,
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
            val userAccepted = readBoundedLine(socket.inputStream).useBytes {
                it.startsWithAscii("+OK")
            }
            if (!userAccepted) return
            credential.withSecretBytes { secret ->
                writeAsciiLine(socket.outputStream, "PASS ", secret)
            }
            readBoundedLine(socket.inputStream).useBytes { response ->
                assertTrue(
                    response.startsWithAscii("-ERR"),
                    "POP3 accepted the operator master credential",
                )
            }
        } finally {
            usernameBytes.fill(0)
            runCatching(socket::close)
        }
    }

    private fun assertSmtpRejected(
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
                    assertTrue(
                        response.startsWithAscii("535"),
                        "SMTP SASL accepted the operator master credential",
                    )
                }
            }
        } finally {
            usernameBytes.fill(0)
        }
    }

    private fun assertMasterOauthInactive(
        oauthPort: Int,
        credential: DovecotOperatorCredential,
    ) {
        credential.withSecretBytes { secret ->
            val body = ByteArray(INTROSPECT_PREFIX.size + secret.size)
            try {
                INTROSPECT_PREFIX.copyInto(body)
                secret.copyInto(body, destinationOffset = INTROSPECT_PREFIX.size)
                postForm(oauthPort, "/introspect", body).use { response ->
                    assertEquals(200, response.status)
                    assertFalse(response.body.containsBytes(secret))
                    val json = Json.parseToJsonElement(
                        response.body.toString(StandardCharsets.UTF_8),
                    ).jsonObject
                    assertEquals(
                        false,
                        json.getValue("active").jsonPrimitive.content.toBoolean(),
                    )
                }
            } finally {
                body.fill(0)
            }
        }
    }

    private fun assertProtectedOauthDenied(oauthPort: Int) {
        PROTECTED_TARGETS.forEach { protected ->
            val authorizeBody = (
                "action=allow&client_id=task6-client&" +
                    "redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback&" +
                    "scope=imap+smtp&state=task6&username=$protected"
                ).toByteArray(StandardCharsets.US_ASCII)
            try {
                postForm(oauthPort, "/authorize", authorizeBody).use { response ->
                    assertEquals(
                        302,
                        response.status,
                        "Protected OAuth identity was not denied",
                    )
                    val location = response.location.orEmpty()
                    assertTrue("error=access_denied" in location)
                    assertFalse("code=" in location)
                }
            } finally {
                authorizeBody.fill(0)
            }
            val tokenBody =
                "token=valid-$protected".toByteArray(StandardCharsets.US_ASCII)
            try {
                postForm(oauthPort, "/introspect", tokenBody).use { response ->
                    assertEquals(200, response.status)
                    val json = Json.parseToJsonElement(
                        response.body.toString(StandardCharsets.UTF_8),
                    ).jsonObject
                    assertEquals(
                        false,
                        json.getValue("active").jsonPrimitive.content.toBoolean(),
                    )
                }
            } finally {
                tokenBody.fill(0)
            }
        }
    }

    private fun postForm(
        port: Int,
        path: String,
        body: ByteArray,
    ): BoundedHttpResponse {
        val connection = URI(
            "http://127.0.0.1:$port$path",
        ).toURL().openConnection() as HttpURLConnection
        return try {
            connection.connectTimeout = SOCKET_TIMEOUT_MILLIS
            connection.readTimeout = SOCKET_TIMEOUT_MILLIS
            connection.instanceFollowRedirects = false
            connection.requestMethod = "POST"
            connection.doOutput = true
            connection.setFixedLengthStreamingMode(body.size)
            connection.setRequestProperty(
                "Content-Type",
                "application/x-www-form-urlencoded",
            )
            connection.outputStream.use { output ->
                output.write(body)
            }
            val status = connection.responseCode
            val input = if (status >= 400) {
                connection.errorStream
            } else {
                connection.inputStream
            }
            val response = input?.use {
                it.readNBytes(MAX_HTTP_RESPONSE_BYTES + 1)
            } ?: ByteArray(0)
            check(response.size <= MAX_HTTP_RESPONSE_BYTES) {
                "OAuth response exceeded its bound"
            }
            BoundedHttpResponse(
                status = status,
                location = connection.getHeaderField("Location"),
                body = response,
            )
        } finally {
            connection.disconnect()
        }
    }

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

    private fun writeAsciiLine(
        output: OutputStream,
        prefix: String,
        value: String,
    ) {
        val bytes = value.toByteArray(StandardCharsets.US_ASCII)
        try {
            writeAsciiLine(output, prefix, bytes)
        } finally {
            bytes.fill(0)
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

    private fun pinnedSslContext(
        profile: DovecotTask5ProofProfile,
    ): SSLContext {
        val certificateBytes = profile.readStableTlsCertificate()
        val certificate = try {
            ByteArrayInputStream(certificateBytes).use {
                CertificateFactory.getInstance("X.509").generateCertificate(it)
            }
        } finally {
            certificateBytes.fill(0)
        }
        val keyStore = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null, null)
            setCertificateEntry("task6-proof", certificate)
        }
        val trustManagers =
            TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
                .apply { init(keyStore) }
                .trustManagers
        return SSLContext.getInstance("TLS").apply {
            init(null, trustManagers, SecureRandom())
        }
    }

    private fun configureTls(socket: SSLSocket) {
        socket.enabledProtocols = socket.enabledProtocols.filter {
            it == "TLSv1.3" || it == "TLSv1.2"
        }.toTypedArray()
        socket.soTimeout = SOCKET_TIMEOUT_MILLIS
    }

    private fun loopbackEndpoint(port: Int): InetSocketAddress =
        InetSocketAddress(LOOPBACK, port)

    private fun discoverHostNonLoopbackIpv4(): List<Inet4Address> {
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

    private fun assertTcpRejected(address: InetAddress, port: Int) {
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
        assertTrue(
            rejected,
            "A non-loopback host interface reached a loopback-only proof port",
        )
    }

    private fun generateTargetPassword(): EligibilityPassword {
        val bytes = ByteArray(TARGET_PASSWORD_BYTES)
        try {
            bytes.indices.forEach { index ->
                bytes[index] = TARGET_PASSWORD_ALPHABET[
                    SECURE_RANDOM.nextInt(TARGET_PASSWORD_ALPHABET.length)
                ].code.toByte()
            }
            return EligibilityPassword.takeOwnership(bytes)
        } catch (failure: Throwable) {
            bytes.fill(0)
            throw failure
        }
    }

    private fun addEligibleTarget(
        cli: EligibilityFileCli,
        address: String,
        password: EligibilityPassword,
    ) {
        var input = ByteArray(0)
        try {
            password.withBytes { bytes ->
                input = ByteArray(bytes.size + 1)
                bytes.copyInto(input)
                input[input.lastIndex] = '\n'.code.toByte()
            }
            assertEquals(
                0,
                executeEligibility(cli, arrayOf("add", address), input),
                "Disposable isolation target add failed",
            )
        } finally {
            input.fill(0)
        }
    }

    private fun removeEligibleTarget(
        cli: EligibilityFileCli,
        address: String,
    ) {
        assertEquals(
            0,
            executeEligibility(
                cli,
                arrayOf("remove", address),
                ByteArray(0),
            ),
            "Disposable isolation target cleanup failed",
        )
    }

    private fun executeEligibility(
        cli: EligibilityFileCli,
        args: Array<String>,
        stdin: ByteArray,
    ): Int {
        val sink = PrintStream(
            OutputStream.nullOutputStream(),
            true,
            StandardCharsets.UTF_8,
        )
        return sink.use { output ->
            cli.execute(
                args,
                ByteArrayInputStream(stdin),
                output,
                output,
            )
        }
    }

    private fun repositoryRoot(): Path {
        val working = Path.of(System.getProperty("user.dir"))
            .toAbsolutePath()
            .normalize()
        val dashboard =
            if (working.fileName?.toString() == "dashboard-server") {
                requireNotNull(working.parent)
            } else {
                working
            }
        return requireNotNull(dashboard.parent).also {
            require(Files.isRegularFile(it.resolve("docker-compose.yml")))
        }
    }

    private data class BoundedHttpResponse(
        val status: Int,
        val location: String?,
        val body: ByteArray,
    ) : AutoCloseable {
        override fun close() {
            body.fill(0)
        }
    }

    private enum class RawAuthenticationResult {
        Success,
        AuthenticationFailure,
        ProtocolFailure,
    }

    companion object {
        private const val SOCKET_TIMEOUT_MILLIS = 1_000
        private const val NETWORK_NEGATIVE_TIMEOUT_MILLIS = 500
        private const val MAX_PROTOCOL_LINE_BYTES = 16 * 1024
        private const val MAX_SMTP_REPLY_LINES = 64
        private const val MAX_HTTP_RESPONSE_BYTES = 16 * 1024
        private const val TARGET_PASSWORD_BYTES = 48
        private const val TARGET_PASSWORD_ALPHABET =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
        private val SECURE_RANDOM = SecureRandom()
        private val LOOPBACK =
            InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
        private val CRLF =
            "\r\n".toByteArray(StandardCharsets.US_ASCII)
        private val IMAP_AUTH_LOGIN =
            "A601 AUTHENTICATE LOGIN\r\n"
                .toByteArray(StandardCharsets.US_ASCII)
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

private fun task6MasterLogin(
    targetAddress: String,
    masterId: DovecotOperatorId,
): String = "$targetAddress*${masterId.masterUsername}"

private fun task6IsHostNonLoopbackIpv4(address: Inet4Address): Boolean =
    !address.isAnyLocalAddress && !address.isLoopbackAddress

private fun task6IsExpectedTcpRejection(failure: Throwable): Boolean =
    failure is ConnectException ||
        failure is NoRouteToHostException ||
        failure is SocketTimeoutException

private fun task6NetworkIsolationProcessTimeout(
    hostCount: Int,
): Duration {
    require(hostCount in 1..TASK6_MAX_HOST_ADDRESSES) {
        "Task 6 host IPv4 inventory is out of bounds"
    }
    val connectAttempts = Math.addExact(
        hostCount,
        TASK6_FIXED_CONNECT_ATTEMPTS,
    )
    val socketBudgetMillis = Math.multiplyExact(
        connectAttempts.toLong(),
        TASK6_SOCKET_TIMEOUT_MILLIS,
    )
    return Duration.ofMillis(
        Math.addExact(
            maxOf(
                socketBudgetMillis,
                TASK6_NETWORK_HELPER_WALL_MILLIS,
            ),
            TASK6_NETWORK_HELPER_MARGIN_MILLIS,
        ),
    )
}

private const val TASK6_MAX_HOST_ADDRESSES = 32
private const val TASK6_FIXED_CONNECT_ATTEMPTS = 5
private const val TASK6_SOCKET_TIMEOUT_MILLIS = 500L
private const val TASK6_NETWORK_HELPER_WALL_MILLIS = 20_000L
private const val TASK6_NETWORK_HELPER_MARGIN_MILLIS = 5_000L

private class Task6FixedProcessRunner(
    private val dockerRouting: DovecotDockerRouting,
    private val isApprovedCommand: (List<String>) -> Boolean,
    private val processFactory: ((EligibilityProcessRequest) -> Process)? = null,
    private val captureFactory: (Int) -> EligibilityProcessOutputCapture = {
        EligibilityProcessOutputCapture(it)
    },
) : EligibilityProcessRunner {
    override fun run(
        request: EligibilityProcessRequest,
    ): EligibilityProcessResult {
        require(isApprovedCommand(request.argv)) {
            "Task 6 process command is not approved"
        }
        require(
            request.workingDirectory.isAbsolute &&
                request.workingDirectory.normalize() ==
                request.workingDirectory &&
                Files.isRegularFile(
                    request.workingDirectory.resolve("docker-compose.yml"),
                ),
        ) {
            "Task 6 process working directory is invalid"
        }
        require(
            !request.timeout.isNegative &&
                !request.timeout.isZero &&
                request.stdin.size <= MAX_STDIN_BYTES &&
                request.maximumOutputBytes in 1..MAX_OUTPUT_BYTES,
        ) {
            "Task 6 process bounds are invalid"
        }

        var process: Process? = null
        var workers: ExecutorService? = null
        var stdoutCapture: EligibilityProcessOutputCapture? = null
        var stderrCapture: EligibilityProcessOutputCapture? = null
        var stdinFuture: Future<*>? = null
        var stdoutFuture: Future<*>? = null
        var stderrFuture: Future<*>? = null
        var stdout = ByteArray(0)
        var stderr = ByteArray(0)
        var interrupted = false
        return try {
            val started = processFactory?.invoke(request) ?:
                ProcessBuilder(request.argv)
                    .directory(request.workingDirectory.toFile())
                    .also { builder ->
                        dockerRouting.applyTo(builder.environment())
                    }
                    .start()
            process = started
            val ownedStdoutCapture =
                captureFactory(request.maximumOutputBytes)
            stdoutCapture = ownedStdoutCapture
            val ownedStderrCapture =
                captureFactory(request.maximumOutputBytes)
            stderrCapture = ownedStderrCapture
            val ownedWorkers = Executors.newFixedThreadPool(3) { runnable ->
                Thread(runnable, "task6-fixed-process-io").also {
                    it.isDaemon = true
                }
            }
            workers = ownedWorkers
            stdoutFuture = submitGuarded(ownedWorkers, started) {
                ownedStdoutCapture.readFrom(started.inputStream)
            }
            stderrFuture = submitGuarded(ownedWorkers, started) {
                ownedStderrCapture.readFrom(started.errorStream)
            }
            stdinFuture = submitGuarded(ownedWorkers, started) {
                started.outputStream.use { output ->
                    output.write(request.stdin)
                    output.flush()
                }
            }

            val completed = started.waitFor(
                request.timeout.toMillis(),
                TimeUnit.MILLISECONDS,
            )
            if (!completed) {
                terminateAndReap(started) {
                    interrupted = true
                }
                return EligibilityProcessResult(
                    exitCode = null,
                    timedOut = true,
                    stdout = ByteArray(0),
                    stderr = ByteArray(0),
                )
            }
            stdinFuture.get(
                IO_JOIN_TIMEOUT_SECONDS,
                TimeUnit.SECONDS,
            )
            stdoutFuture.get(
                IO_JOIN_TIMEOUT_SECONDS,
                TimeUnit.SECONDS,
            )
            stderrFuture.get(
                IO_JOIN_TIMEOUT_SECONDS,
                TimeUnit.SECONDS,
            )
            stdout = ownedStdoutCapture.snapshot()
            stderr = ownedStderrCapture.snapshot()
            EligibilityProcessResult(
                exitCode = started.exitValue(),
                timedOut = false,
                stdout = stdout,
                stderr = stderr,
            )
        } catch (failure: Exception) {
            stdout.fill(0)
            stderr.fill(0)
            if (failure is InterruptedException) {
                interrupted = true
            }
            throw IllegalStateException("Task 6 fixed process failed")
        } finally {
            stdoutCapture?.close()
            stderrCapture?.close()
            var cleanupFailure: Throwable? = null
            process?.let { started ->
                try {
                    terminateAndReap(started) {
                        interrupted = true
                    }
                } catch (failure: Throwable) {
                    cleanupFailure = failure
                }
            }
            stdinFuture?.cancel(true)
            stdoutFuture?.cancel(true)
            stderrFuture?.cancel(true)
            workers?.shutdownNow()
            val workersStopped = try {
                workers?.let { executor ->
                    awaitTermination(
                        executor,
                        IO_JOIN_TIMEOUT_SECONDS,
                    ) {
                        interrupted = true
                    }
                } ?: true
            } catch (failure: Throwable) {
                if (cleanupFailure == null) {
                    cleanupFailure = failure
                }
                false
            }
            if (!workersStopped && cleanupFailure == null) {
                cleanupFailure =
                    IllegalStateException(
                        "Task 6 fixed process workers did not stop",
                    )
            }
            if (interrupted) {
                Thread.currentThread().interrupt()
            }
            if (cleanupFailure != null) {
                throw IllegalStateException(
                    "Task 6 fixed process cleanup failed",
                )
            }
        }
    }

    private fun awaitTermination(
        workers: ExecutorService,
        timeoutSeconds: Long,
        onInterrupted: () -> Unit,
    ): Boolean {
        val deadline =
            System.nanoTime() +
                TimeUnit.SECONDS.toNanos(timeoutSeconds)
        while (true) {
            val remaining = deadline - System.nanoTime()
            if (remaining <= 0L) return workers.isTerminated
            try {
                return workers.awaitTermination(
                    remaining,
                    TimeUnit.NANOSECONDS,
                )
            } catch (_: InterruptedException) {
                onInterrupted()
            }
        }
    }

    private fun submitGuarded(
        workers: ExecutorService,
        process: Process,
        operation: () -> Unit,
    ): Future<*> = workers.submit {
        try {
            operation()
        } catch (failure: Throwable) {
            runCatching {
                if (process.isAlive) process.destroyForcibly()
            }
            throw failure
        }
    }

    private fun terminateAndReap(
        process: Process,
        onInterrupted: () -> Unit,
    ) {
        if (process.isAlive) {
            process.destroyForcibly()
        }
        closeProcessStreams(process)
        val deadline =
            System.nanoTime() +
                TimeUnit.SECONDS.toNanos(
                    IO_JOIN_TIMEOUT_SECONDS,
                )
        var reaped = false
        while (!reaped) {
            val remaining = deadline - System.nanoTime()
            if (remaining <= 0L) break
            try {
                reaped = process.waitFor(
                    remaining,
                    TimeUnit.NANOSECONDS,
                )
            } catch (_: InterruptedException) {
                onInterrupted()
            }
        }
        check(reaped && !process.isAlive) {
            "Task 6 fixed process could not be reaped"
        }
        closeProcessStreams(process)
    }

    private fun closeProcessStreams(process: Process) {
        runCatching { process.outputStream.close() }
        runCatching { process.inputStream.close() }
        runCatching { process.errorStream.close() }
    }

    companion object {
        private const val MAX_STDIN_BYTES = 1024
        private const val MAX_OUTPUT_BYTES = 64 * 1024
        private const val IO_JOIN_TIMEOUT_SECONDS = 2L
    }
}

private class FixedTask6DockerTopology(
    private val profile: DovecotTask5ProofProfile,
) {
    private val repositoryRoot = profile.repositoryRoot
    private val processRunner = Task6FixedProcessRunner(
        dockerRouting = DovecotDockerRouting.task5Proof(profile),
        isApprovedCommand = ::isFixedCommand,
    )

    fun inspect(): Task6RuntimeTopology {
        val containers = FIXED_SERVICES.associateWith(::composeContainerId)
        val ports = containers.mapValues { (_, id) ->
            inspectJson(id, PORTS_FORMAT)
        }
        val networks = containers.mapValues { (_, id) ->
            inspectJson(id, NETWORKS_FORMAT)
        }
        val operatorNetworks =
            networks.getValue("dovecot-operator").jsonObject
        val operatorIngress = operatorNetworks.entries.single { (name, _) ->
            name.endsWith("_operator-ingress")
        }.value.jsonObject.getValue("IPAddress").jsonPrimitive.content
        return Task6RuntimeTopology(
            ports = ports,
            networks = networks,
            operatorIngressAddress = operatorIngress,
        )
    }

    fun requireDefaultNetworkIsolation(
        operatorIngressAddress: String,
        hostAddresses: List<Inet4Address>,
    ) {
        val processTimeout =
            task6NetworkIsolationProcessTimeout(hostAddresses.size)
        val input = buildString {
            append("operator ")
            append(operatorIngressAddress)
            append('\n')
            hostAddresses.forEach { address ->
                append("host ")
                append(address.hostAddress)
                append('\n')
            }
        }.toByteArray(StandardCharsets.US_ASCII)
        try {
            val result = runFixed(
                listOf(
                    "docker",
                    "compose",
                    "exec",
                    "-T",
                    "oauth2-mock",
                    "python",
                    "-I",
                    "/proof/network-isolation-check.py",
                ),
                input,
                processTimeout,
            )
            check(result.exitCode == 0) {
                "Default-network isolation helper failed: " +
                    "${result.stdout}${result.stderr}"
            }
            check(result.stdout == "OK\n" && result.stderr.isEmpty()) {
                "Default-network isolation helper returned an invalid result"
            }
        } finally {
            input.fill(0)
        }
    }

    private fun composeContainerId(service: String): String {
        require(service in FIXED_SERVICES)
        val result = runFixed(
            listOf(
                "docker",
                "compose",
                "ps",
                "--quiet",
                service,
            ),
            ByteArray(0),
        )
        check(result.exitCode == 0 && result.stderr.isEmpty()) {
            "Fixed proof container lookup failed"
        }
        val id = result.stdout.trim()
        check(CONTAINER_ID.matches(id)) {
            "Fixed proof container identity is invalid"
        }
        return id
    }

    private fun inspectJson(
        containerId: String,
        format: String,
    ) = runFixed(
        listOf(
            "docker",
            "inspect",
            "--format",
            format,
            containerId,
        ),
        ByteArray(0),
    ).let { result ->
        check(result.exitCode == 0 && result.stderr.isEmpty()) {
            "Fixed proof container inspection failed"
        }
        Json.parseToJsonElement(result.stdout.trim())
    }

    private fun runFixed(
        command: List<String>,
        stdin: ByteArray,
        timeout: Duration = PROCESS_TIMEOUT,
    ): FixedProcessResult {
        val result = processRunner.run(
            EligibilityProcessRequest(
                argv = command,
                workingDirectory = repositoryRoot,
                stdin = stdin,
                timeout = timeout,
                maximumOutputBytes = MAX_PROCESS_OUTPUT_BYTES,
            ),
        )
        try {
            check(
                !result.timedOut &&
                    result.exitCode != null,
            ) {
                "Task 6 fixed process timed out"
            }
            return FixedProcessResult(
                exitCode = requireNotNull(result.exitCode),
                stdout = result.stdout.toString(StandardCharsets.UTF_8),
                stderr = result.stderr.toString(StandardCharsets.UTF_8),
            )
        } finally {
            result.stdout.fill(0)
            result.stderr.fill(0)
        }
    }

    private fun isFixedCommand(command: List<String>): Boolean =
        command in FIXED_COMMANDS ||
            (
                command.size == 5 &&
                    command.take(4) ==
                    listOf("docker", "compose", "ps", "--quiet") &&
                    command.last() in FIXED_SERVICES
                ) ||
            (
                command.size == 5 &&
                    command.take(3) ==
                    listOf("docker", "inspect", "--format") &&
                    command[3] in setOf(PORTS_FORMAT, NETWORKS_FORMAT) &&
                    CONTAINER_ID.matches(command[4])
                )

    private data class FixedProcessResult(
        val exitCode: Int,
        val stdout: String,
        val stderr: String,
    )

    companion object {
        private val FIXED_SERVICES = setOf(
            "dovecot",
            "dovecot-operator",
            "postfix",
            "oauth2-mock",
        )
        private const val PORTS_FORMAT =
            "{{json .NetworkSettings.Ports}}"
        private const val NETWORKS_FORMAT =
            "{{json .NetworkSettings.Networks}}"
        private val CONTAINER_ID = Regex("[0-9a-f]{64}")
        private val PROCESS_TIMEOUT = Duration.ofSeconds(10)
        private const val MAX_PROCESS_OUTPUT_BYTES = 64 * 1024
        private val FIXED_COMMANDS = setOf(
            listOf(
                "docker",
                "compose",
                "exec",
                "-T",
                "oauth2-mock",
                "python",
                "-I",
                "/proof/network-isolation-check.py",
            ),
        )
    }
}

private data class Task6RuntimeTopology(
    val ports: Map<String, kotlinx.serialization.json.JsonElement>,
    val networks: Map<String, kotlinx.serialization.json.JsonElement>,
    val operatorIngressAddress: String,
) {
    fun requireExactIsolation() {
        requireExactPublishedPorts(
            service = "dovecot-operator",
            expected = setOf("31993/tcp"),
        )
        requirePort(
            service = "dovecot-operator",
            containerPort = "31993/tcp",
            hostPort = "2993",
        )
        requireExactPublishedPorts(
            service = "dovecot",
            expected = setOf("31993/tcp", "31990/tcp"),
        )
        requirePort("dovecot", "31993/tcp", "1993")
        requirePort("dovecot", "31990/tcp", "21995")
        requireExactPublishedPorts(
            service = "postfix",
            expected = setOf("25/tcp"),
        )
        requirePort("postfix", "25/tcp", "21025")
        requireExactPublishedPorts(
            service = "oauth2-mock",
            expected = setOf("8080/tcp"),
        )
        requirePort("oauth2-mock", "8080/tcp", "28080")

        val operatorNetworks =
            networks.getValue("dovecot-operator").jsonObject.keys
        check(operatorNetworks == setOf(OPERATOR_NETWORK)) {
            "Operator runtime network membership is invalid"
        }
        listOf("dovecot", "postfix", "oauth2-mock").forEach { service ->
            val serviceNetworks = networks.getValue(service).jsonObject.keys
            check(serviceNetworks == setOf(DEFAULT_NETWORK)) {
                "Default service runtime network membership is invalid"
            }
        }
        check(IPV4.matches(operatorIngressAddress)) {
            "Operator ingress address discovery failed"
        }
    }

    private fun requireExactPublishedPorts(
        service: String,
        expected: Set<String>,
    ) {
        val published = ports.getValue(service)
            .jsonObject
            .filterValues { bindings ->
                bindings !is JsonNull &&
                    (bindings !is JsonArray || bindings.isNotEmpty())
            }
            .keys
        check(published == expected) {
            "Proof runtime has an unexpected protocol publication"
        }
    }

    private fun requirePort(
        service: String,
        containerPort: String,
        hostPort: String,
    ) {
        val bindings = ports.getValue(service)
            .jsonObject
            .getValue(containerPort) as JsonArray
        check(bindings.size == 1) {
            "Proof runtime port binding is ambiguous"
        }
        val binding = bindings.single().jsonObject
        check(
            binding.getValue("HostIp").jsonPrimitive.content == "127.0.0.1" &&
                binding.getValue("HostPort").jsonPrimitive.content == hostPort,
        ) {
            "Proof runtime port is not loopback-only"
        }
    }

    companion object {
        private const val DEFAULT_NETWORK =
            "mail-sandbox-task5-proof_default"
        private const val OPERATOR_NETWORK =
            "mail-sandbox-task5-proof_operator-ingress"
        private val IPV4 = Regex(
            "(?:[0-9]{1,3}\\.){3}[0-9]{1,3}",
        )
    }
}

class DovecotIsolationContractTest {
    @Test
    fun ordinaryPasswordEscalationUsesTheActualActiveMasterIdentity() {
        assertEquals(
            "target@local.test*dashboard-operator-a",
            task6MasterLogin(
                "target@local.test",
                DovecotOperatorId.A,
            ),
        )
        assertEquals(
            "target@local.test*dashboard-operator-b",
            task6MasterLogin(
                "target@local.test",
                DovecotOperatorId.B,
            ),
        )
    }

    @Test
    fun hostAddressDiscoveryKeepsLinkLocalIpv4InScope() {
        val linkLocal = InetAddress.getByAddress(
            byteArrayOf(169.toByte(), 254.toByte(), 1, 2),
        ) as Inet4Address
        val loopback = InetAddress.getByAddress(
            byteArrayOf(127, 0, 0, 1),
        ) as Inet4Address
        val wildcard = InetAddress.getByAddress(
            byteArrayOf(0, 0, 0, 0),
        ) as Inet4Address

        assertTrue(task6IsHostNonLoopbackIpv4(linkLocal))
        assertFalse(task6IsHostNonLoopbackIpv4(loopback))
        assertFalse(task6IsHostNonLoopbackIpv4(wildcard))
    }

    @Test
    fun hostTcpNegativeAcceptsOnlyExpectedNetworkRejections() {
        assertTrue(task6IsExpectedTcpRejection(ConnectException()))
        assertTrue(task6IsExpectedTcpRejection(NoRouteToHostException()))
        assertTrue(task6IsExpectedTcpRejection(SocketTimeoutException()))
        assertFalse(task6IsExpectedTcpRejection(IOException()))
        assertFalse(task6IsExpectedTcpRejection(IllegalStateException()))
    }

    @Test
    fun runtimeTopologyIgnoresUnboundExposedPorts() {
        runtimeTopology(includeUnboundPorts = true).requireExactIsolation()
    }

    @Test
    fun runtimeTopologyRejectsUnexpectedPublishedPortsForEveryService() {
        listOf(
            "dovecot",
            "postfix",
            "oauth2-mock",
            "dovecot-operator",
        ).forEach { service ->
            assertFailsWith<IllegalStateException>(service) {
                runtimeTopology(extraPublishedService = service)
                    .requireExactIsolation()
            }
        }
    }

    @Test
    fun worstCaseNetworkHelperTimeoutExceedsItsSocketAttemptBudget() {
        val minimumHostTimeout = task6NetworkIsolationProcessTimeout(1)
        val maximumHostTimeout = task6NetworkIsolationProcessTimeout(32)

        assertEquals(Duration.ofSeconds(25), minimumHostTimeout)
        assertEquals(Duration.ofSeconds(25), maximumHostTimeout)
        assertTrue(minimumHostTimeout > Duration.ofSeconds(20))
        assertTrue(maximumHostTimeout > Duration.ofMillis(18_500))
        assertTrue(maximumHostTimeout <= Duration.ofSeconds(30))
    }

    @Test
    fun pythonAndKotlinNetworkHelperWallDeadlinesStayAligned() {
        val helperSource = Files.readString(
            repositoryRoot().resolve(
                "debug-dashboard/dashboard-server/testResources/" +
                    "dovecot-gate0c/network-isolation-check.py",
            ),
        )
        val wallSeconds = requireNotNull(
            Regex(
                """(?m)^MAX_WALL_SECONDS = ([0-9]+(?:\.[0-9]+)?)$""",
            ).find(helperSource),
        ).groupValues[1].toDouble()

        assertEquals(
            TASK6_NETWORK_HELPER_WALL_MILLIS,
            (wallSeconds * 1_000).toLong(),
        )
    }

    @Test
    fun fixedProcessRunnerAcceptsOutputAtTheConfiguredMemoryLimit() {
        val stdout = ByteArray(8) { 'x'.code.toByte() }
        val process = Task6ControlledProcess(
            stdout = stdout,
            initiallyExited = true,
        )
        val runner = fixedProcessRunner(process)

        val result = runner.run(
            processRequest(maximumOutputBytes = stdout.size),
        )

        assertFalse(result.timedOut)
        assertEquals(0, result.exitCode)
        assertEquals(stdout.toList(), result.stdout.toList())
        assertTrue(result.stderr.isEmpty())
    }

    @Test
    fun fixedProcessRunnerKillsAndReapsOnOutputOverflow() {
        val process = Task6ControlledProcess(
            stdout = ByteArray(9) { 'x'.code.toByte() },
        )
        val runner = fixedProcessRunner(process)

        assertFailsWith<IllegalStateException> {
            runner.run(processRequest(maximumOutputBytes = 8))
        }

        assertTrue(process.destroyed)
        assertTrue(process.reaped)
        assertFalse(process.isAlive)
    }

    @Test
    fun fixedProcessRunnerKillsAndReapsOnTimeout() {
        val process = Task6ControlledProcess(
            stdout = ByteArray(0),
            timeoutBeforeDestroy = true,
        )
        val runner = fixedProcessRunner(process)

        val result = runner.run(
            processRequest(
                timeout = Duration.ofMillis(25),
                maximumOutputBytes = 8,
            ),
        )

        assertTrue(result.timedOut)
        assertEquals(null, result.exitCode)
        assertTrue(process.destroyed)
        assertTrue(process.reaped)
        assertFalse(process.isAlive)
    }

    @Test
    fun fixedProcessRunnerRejectsOversizedInputBeforeStarting() {
        var started = false
        val runner = Task6FixedProcessRunner(
            dockerRouting = DovecotDockerRouting.localDefault(),
            isApprovedCommand = { it == FIXED_TEST_COMMAND },
            processFactory = {
                started = true
                Task6ControlledProcess(ByteArray(0))
            },
        )

        assertFailsWith<IllegalArgumentException> {
            runner.run(
                processRequest(
                    stdin = ByteArray(1_025),
                    maximumOutputBytes = 8,
                ),
            )
        }

        assertFalse(started)
    }

    @Test
    fun fixedProcessRunnerReapsBeforeRestoringCallerInterruption() {
        val waitEntered = CountDownLatch(1)
        val process = Task6ControlledProcess(
            stdout = ByteArray(0),
            waitEntered = waitEntered,
        )
        val runner = fixedProcessRunner(process)
        val failure = AtomicReference<Throwable?>()
        val interruptRestored = AtomicBoolean()
        val caller = Thread(
            {
                try {
                    runner.run(
                        processRequest(
                            timeout = Duration.ofSeconds(5),
                            maximumOutputBytes = 8,
                        ),
                    )
                } catch (caught: Throwable) {
                    failure.set(caught)
                    interruptRestored.set(
                        Thread.currentThread().isInterrupted,
                    )
                }
            },
            "task6-interrupted-runner-test",
        ).also { it.isDaemon = true }

        caller.start()
        assertTrue(waitEntered.await(1, TimeUnit.SECONDS))
        caller.interrupt()
        caller.join(3_000)

        assertFalse(caller.isAlive)
        assertTrue(failure.get() is IllegalStateException)
        assertTrue(interruptRestored.get())
        assertTrue(process.destroyed)
        assertTrue(process.reaped)
        assertFalse(process.isAlive)
        assertFalse(
            Thread.getAllStackTraces().keys.any { thread ->
                thread.isAlive &&
                    thread.name == "task6-fixed-process-io"
            },
        )
    }

    private fun fixedProcessRunner(
        process: Task6ControlledProcess,
    ): Task6FixedProcessRunner =
        Task6FixedProcessRunner(
            dockerRouting = DovecotDockerRouting.localDefault(),
            isApprovedCommand = { it == FIXED_TEST_COMMAND },
            processFactory = { process },
        )

    private fun processRequest(
        stdin: ByteArray = ByteArray(0),
        timeout: Duration = Duration.ofSeconds(1),
        maximumOutputBytes: Int,
    ): EligibilityProcessRequest =
        EligibilityProcessRequest(
            argv = FIXED_TEST_COMMAND,
            workingDirectory = repositoryRoot(),
            stdin = stdin,
            timeout = timeout,
            maximumOutputBytes = maximumOutputBytes,
        )

    private fun runtimeTopology(
        extraPublishedService: String? = null,
        includeUnboundPorts: Boolean = false,
    ): Task6RuntimeTopology {
        val ports = mapOf(
            "dovecot" to portDocument(
                service = "dovecot",
                expected = listOf(
                    "31993/tcp" to "1993",
                    "31990/tcp" to "21995",
                ),
                extraPublishedService = extraPublishedService,
                includeUnboundPorts = includeUnboundPorts,
            ),
            "dovecot-operator" to portDocument(
                service = "dovecot-operator",
                expected = listOf("31993/tcp" to "2993"),
                extraPublishedService = extraPublishedService,
                includeUnboundPorts = includeUnboundPorts,
            ),
            "postfix" to portDocument(
                service = "postfix",
                expected = listOf("25/tcp" to "21025"),
                extraPublishedService = extraPublishedService,
                includeUnboundPorts = includeUnboundPorts,
            ),
            "oauth2-mock" to portDocument(
                service = "oauth2-mock",
                expected = listOf("8080/tcp" to "28080"),
                extraPublishedService = extraPublishedService,
                includeUnboundPorts = includeUnboundPorts,
            ),
        )
        val defaultNetwork = Json.parseToJsonElement(
            """{"mail-sandbox-task5-proof_default":{}}""",
        )
        val operatorNetwork = Json.parseToJsonElement(
            """{"mail-sandbox-task5-proof_operator-ingress":{}}""",
        )
        return Task6RuntimeTopology(
            ports = ports,
            networks = mapOf(
                "dovecot" to defaultNetwork,
                "dovecot-operator" to operatorNetwork,
                "postfix" to defaultNetwork,
                "oauth2-mock" to defaultNetwork,
            ),
            operatorIngressAddress = "172.31.0.5",
        )
    }

    private fun portDocument(
        service: String,
        expected: List<Pair<String, String>>,
        extraPublishedService: String?,
        includeUnboundPorts: Boolean,
    ): kotlinx.serialization.json.JsonElement {
        val entries = expected.map { (containerPort, hostPort) ->
            """"$containerPort":[{"HostIp":"127.0.0.1","HostPort":"$hostPort"}]"""
        }.toMutableList()
        if (includeUnboundPorts) {
            entries += """"65534/tcp":null"""
            entries += """"65533/tcp":[]"""
        }
        if (service == extraPublishedService) {
            entries +=
                """"65535/tcp":[{"HostIp":"127.0.0.1","HostPort":"65535"}]"""
        }
        return Json.parseToJsonElement("{${entries.joinToString(",")}}")
    }

    private fun repositoryRoot(): Path {
        val workingDirectory = Path.of(System.getProperty("user.dir"))
            .toAbsolutePath()
            .normalize()
        val dashboardRoot = when (workingDirectory.fileName?.toString()) {
            "dashboard-server" -> workingDirectory.parent
            "debug-dashboard" -> workingDirectory
            else -> error("unexpected Kotlin test working directory")
        }
        return requireNotNull(dashboardRoot.parent)
    }

    private class Task6ControlledProcess(
        stdout: ByteArray,
        private val timeoutBeforeDestroy: Boolean = false,
        private val waitEntered: CountDownLatch? = null,
        initiallyExited: Boolean = false,
    ) : Process() {
        private val termination =
            CountDownLatch(if (initiallyExited) 0 else 1)
        private val stdin = ByteArrayOutputStream()
        private val stdoutStream = ByteArrayInputStream(stdout)
        private val stderrStream = ByteArrayInputStream(ByteArray(0))

        @Volatile
        private var alive = !initiallyExited

        @Volatile
        var destroyed = false
            private set

        @Volatile
        var reaped = false
            private set

        override fun getOutputStream(): OutputStream = stdin

        override fun getInputStream(): InputStream = stdoutStream

        override fun getErrorStream(): InputStream = stderrStream

        override fun waitFor(): Int {
            termination.await()
            reaped = true
            return exitValue()
        }

        override fun waitFor(
            timeout: Long,
            unit: TimeUnit,
        ): Boolean {
            waitEntered?.countDown()
            if (timeoutBeforeDestroy && alive) return false
            val completed = termination.await(timeout, unit)
            if (completed) reaped = true
            return completed
        }

        override fun exitValue(): Int {
            if (alive) throw IllegalThreadStateException()
            return if (destroyed) 137 else 0
        }

        override fun destroy() {
            destroyForcibly()
        }

        override fun destroyForcibly(): Process {
            destroyed = true
            alive = false
            termination.countDown()
            return this
        }

        override fun isAlive(): Boolean = alive
    }

    companion object {
        private val FIXED_TEST_COMMAND = listOf("task6-fixed-test")
    }
}
