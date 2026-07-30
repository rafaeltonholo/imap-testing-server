package mail.sandbox.dashboard.server.gate.dovecot

import java.io.InputStream
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URI
import java.nio.file.Path
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.CertificateFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory

internal fun interface DovecotTopologyReadinessProbe {
    fun isReady(
        environment: DovecotLiveTestEnvironment,
        boundary: DovecotReadinessBoundary,
    ): Boolean
}

internal enum class DovecotReadinessBoundary(
    val diagnosticLabel: String,
) {
    ORDINARY_IMAPS("ordinary-imaps"),
    ORDINARY_POP3S("ordinary-pop3s"),
    OPERATOR_IMAPS("operator-imaps"),
    SMTP("smtp"),
    OAUTH_HEALTH("oauth-health"),
}

internal fun interface DovecotLiveTestSleeper {
    fun sleep(milliseconds: Long)
}

internal class DovecotLiveTestEnvironment private constructor(
    internal val profile: DovecotTask5ProofProfile,
    val loopbackAddress: String,
    val ordinaryImapsPort: Int,
    val ordinaryPop3sPort: Int,
    val operatorImapsPort: Int,
    val smtpPort: Int,
    val oauthPort: Int,
    val tlsCertificate: Path,
    val composeOverride: Path,
) {
    fun awaitReady(
        maxAttempts: Int = DEFAULT_READINESS_ATTEMPTS,
        delayMillis: Long = DEFAULT_READINESS_DELAY_MILLIS,
        probe: DovecotTopologyReadinessProbe =
            JvmDovecotTopologyReadinessProbe,
        sleeper: DovecotLiveTestSleeper =
            DovecotLiveTestSleeper(Thread::sleep),
    ) {
        require(maxAttempts in 1..MAX_READINESS_ATTEMPTS) {
            "Dovecot readiness attempt bound is invalid"
        }
        require(delayMillis in 0..MAX_READINESS_DELAY_MILLIS) {
            "Dovecot readiness delay bound is invalid"
        }
        var lastFailure: DovecotReadinessFailure? = null
        repeat(maxAttempts) { attempt ->
            val failure = firstReadinessFailure(probe)
            if (failure == null) {
                return
            }
            lastFailure = failure
            if (attempt + 1 < maxAttempts && delayMillis > 0) {
                sleeper.sleep(delayMillis)
            }
        }
        val failure = requireNotNull(lastFailure)
        throw IllegalStateException(
            "The fixed Dovecot proof readiness boundary did not become " +
                "ready: ${failure.boundary.diagnosticLabel}",
            failure.cause,
        )
    }

    private fun firstReadinessFailure(
        probe: DovecotTopologyReadinessProbe,
    ): DovecotReadinessFailure? {
        DovecotReadinessBoundary.entries.forEach { boundary ->
            try {
                if (!probe.isReady(this, boundary)) {
                    return DovecotReadinessFailure(
                        boundary = boundary,
                        cause = null,
                    )
                }
            } catch (cause: Exception) {
                return DovecotReadinessFailure(
                    boundary = boundary,
                    cause = cause,
                )
            }
        }
        return null
    }

    companion object {
        private const val DEFAULT_READINESS_ATTEMPTS = 20
        private const val DEFAULT_READINESS_DELAY_MILLIS = 250L
        private const val MAX_READINESS_ATTEMPTS = 60
        private const val MAX_READINESS_DELAY_MILLIS = 5_000L

        fun load(
            environment: Map<String, String> = System.getenv(),
            repositoryRoot: Path,
        ): DovecotLiveTestEnvironment {
            val profile = DovecotTask5ProofProfile.load(
                environment = environment,
                repositoryRoot = repositoryRoot,
            )
            return DovecotLiveTestEnvironment(
                profile = profile,
                loopbackAddress = profile.loopbackAddress,
                ordinaryImapsPort = profile.ordinaryImapsPort,
                ordinaryPop3sPort = profile.ordinaryPop3sPort,
                operatorImapsPort = profile.operatorImapsPort,
                smtpPort = profile.smtpPort,
                oauthPort = profile.oauthPort,
                tlsCertificate = profile.tlsCertificate,
                composeOverride = profile.composeOverride,
            )
        }
    }
}

private object JvmDovecotTopologyReadinessProbe :
    DovecotTopologyReadinessProbe {
    override fun isReady(
        environment: DovecotLiveTestEnvironment,
        boundary: DovecotReadinessBoundary,
    ): Boolean = when (boundary) {
        DovecotReadinessBoundary.ORDINARY_IMAPS -> tlsGreetingReady(
            pinnedSslContext(environment.profile),
            environment.ordinaryImapsPort,
            "* OK",
        )
        DovecotReadinessBoundary.ORDINARY_POP3S -> tlsGreetingReady(
            pinnedSslContext(environment.profile),
            environment.ordinaryPop3sPort,
            "+OK",
        )
        DovecotReadinessBoundary.OPERATOR_IMAPS -> tlsGreetingReady(
            pinnedSslContext(environment.profile),
            environment.operatorImapsPort,
            "* OK",
        )
        DovecotReadinessBoundary.SMTP ->
            smtpGreetingReady(environment.smtpPort)
        DovecotReadinessBoundary.OAUTH_HEALTH ->
            oauthHealthReady(environment.oauthPort)
    }

    private fun pinnedSslContext(
        profile: DovecotTask5ProofProfile,
    ): SSLContext {
        val bytes = profile.readStableTlsCertificate()
        val certificate = try {
            java.io.ByteArrayInputStream(bytes).use { input ->
                CertificateFactory
                    .getInstance("X.509")
                    .generateCertificate(input)
            }
        } finally {
            bytes.fill(0)
        }
        val keyStore = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null, null)
            setCertificateEntry("dovecot-proof", certificate)
        }
        val trustManagers =
            TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
                .apply { init(keyStore) }
                .trustManagers
        return SSLContext.getInstance("TLS").apply {
            init(null, trustManagers, SecureRandom())
        }
    }

    private fun tlsGreetingReady(
        sslContext: SSLContext,
        port: Int,
        expectedPrefix: String,
    ): Boolean {
        val socket = sslContext.socketFactory.createSocket() as SSLSocket
        return try {
            configureTls(socket)
            socket.connect(loopbackEndpoint(port), SOCKET_TIMEOUT_MILLIS)
            socket.startHandshake()
            readBoundedLine(socket.inputStream).useBytes { greeting ->
                greeting.startsWithAscii(expectedPrefix)
            }
        } finally {
            socket.close()
        }
    }

    private fun configureTls(socket: SSLSocket) {
        socket.enabledProtocols = socket.enabledProtocols.filter { protocol ->
            protocol == "TLSv1.3" || protocol == "TLSv1.2"
        }.toTypedArray()
        socket.soTimeout = SOCKET_TIMEOUT_MILLIS
    }

    private fun smtpGreetingReady(port: Int): Boolean =
        Socket().use { socket ->
            socket.soTimeout = SOCKET_TIMEOUT_MILLIS
            socket.connect(loopbackEndpoint(port), SOCKET_TIMEOUT_MILLIS)
            readBoundedLine(socket.getInputStream()).useBytes { greeting ->
                greeting.startsWithAscii("220")
            }
        }

    private fun oauthHealthReady(port: Int): Boolean {
        val connection = URI(
            "http://127.0.0.1:$port/health",
        ).toURL().openConnection() as HttpURLConnection
        return try {
            connection.connectTimeout = SOCKET_TIMEOUT_MILLIS
            connection.readTimeout = SOCKET_TIMEOUT_MILLIS
            connection.instanceFollowRedirects = false
            connection.requestMethod = "GET"
            connection.responseCode == HttpURLConnection.HTTP_OK
        } finally {
            connection.disconnect()
        }
    }

    private fun loopbackEndpoint(port: Int): InetSocketAddress =
        InetSocketAddress(LOOPBACK, port)

    private fun readBoundedLine(input: InputStream): ByteArray {
        val buffer = ByteArray(MAX_GREETING_BYTES + 1)
        var size = 0
        try {
            while (true) {
                val value = input.read()
                check(value >= 0) { "Dovecot proof greeting ended early" }
                if (value == '\n'.code) {
                    check(
                        size > 0 &&
                            buffer[size - 1] == '\r'.code.toByte(),
                    ) {
                        "Dovecot proof greeting is malformed"
                    }
                    return buffer.copyOf(size - 1)
                }
                check(size < buffer.size) {
                    "Dovecot proof greeting exceeded its bound"
                }
                buffer[size] = value.toByte()
                size += 1
            }
        } finally {
            buffer.fill(0)
        }
    }

    private fun ByteArray.startsWithAscii(prefix: String): Boolean {
        val prefixBytes = prefix.toByteArray(Charsets.US_ASCII)
        return try {
            size >= prefixBytes.size &&
                prefixBytes.indices.all { index ->
                    this[index] == prefixBytes[index]
                }
        } finally {
            prefixBytes.fill(0)
        }
    }

    private inline fun <T> ByteArray.useBytes(
        block: (ByteArray) -> T,
    ): T = try {
        block(this)
    } finally {
        fill(0)
    }

    private const val SOCKET_TIMEOUT_MILLIS = 500
    private const val MAX_GREETING_BYTES = 4 * 1024
    private val LOOPBACK = InetAddress.getByAddress(
        byteArrayOf(127, 0, 0, 1),
    )
}

private data class DovecotReadinessFailure(
    val boundary: DovecotReadinessBoundary,
    val cause: Exception?,
)
