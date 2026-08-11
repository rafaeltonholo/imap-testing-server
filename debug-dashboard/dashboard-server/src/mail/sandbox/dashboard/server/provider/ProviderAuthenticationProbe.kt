package mail.sandbox.dashboard.server.provider

import jakarta.mail.AuthenticationFailedException
import jakarta.mail.MessagingException
import jakarta.mail.Session
import jakarta.mail.Store
import jakarta.mail.Transport
import java.net.SocketTimeoutException
import java.nio.charset.StandardCharsets
import java.security.Provider
import java.security.Security
import java.util.Properties
import javax.security.auth.callback.Callback
import javax.security.auth.callback.CallbackHandler
import javax.security.auth.callback.NameCallback
import javax.security.auth.callback.PasswordCallback
import javax.security.sasl.SaslClient
import javax.security.sasl.SaslClientFactory
import javax.security.sasl.SaslException
import kotlinx.coroutines.CancellationException

internal data class AccountCredentials(
    val address: String,
    val password: String? = null,
    val tokenOverride: String? = null,
)

internal enum class ProviderAuthenticationProtocol(
    val propertyPrefix: String,
    val endpoint: ProviderAuthenticationEndpoint,
) {
    IMAP("imap", ProviderAuthenticationEndpoint("127.0.0.1", 1143, startTls = true)),
    POP3("pop3", ProviderAuthenticationEndpoint("127.0.0.1", 1110, startTls = true)),
    SMTP("smtp", ProviderAuthenticationEndpoint("127.0.0.1", 1587, startTls = true)),
}

internal enum class ProviderAuthenticationMechanism {
    PASSWORD,
    XOAUTH2,
    OAUTHBEARER,
}

internal data class ProviderAuthenticationEndpoint(
    val host: String,
    val port: Int,
    val startTls: Boolean,
) {
    init {
        require(host == "127.0.0.1" && port in 1..65_535) {
            "Provider authentication endpoints must use a valid loopback port"
        }
    }
}

internal data class ProviderAuthenticationRequest(
    val protocol: ProviderAuthenticationProtocol,
    val mechanism: ProviderAuthenticationMechanism,
    val credentials: AccountCredentials,
    val endpointOverride: ProviderAuthenticationEndpoint? = null,
) {
    init {
        require(endpointOverride == null || protocol == ProviderAuthenticationProtocol.SMTP) {
            "Only SMTP authentication probes support a request-scoped endpoint"
        }
    }
}

internal data class ProviderAuthenticationAttempt(
    val protocol: ProviderAuthenticationProtocol,
    val mechanism: ProviderAuthenticationMechanism,
    val endpoint: ProviderAuthenticationEndpoint,
    val address: String,
    val secret: String,
    val authenticateOnly: Boolean,
) {
    fun sessionProperties(): Properties {
        val prefix = protocol.propertyPrefix
        return Properties().apply {
            setProperty("mail.$prefix.host", endpoint.host)
            setProperty("mail.$prefix.port", endpoint.port.toString())
            setProperty("mail.$prefix.connectiontimeout", TIMEOUT_MILLIS.toString())
            setProperty("mail.$prefix.timeout", TIMEOUT_MILLIS.toString())
            setProperty("mail.$prefix.writetimeout", TIMEOUT_MILLIS.toString())
            setProperty("mail.$prefix.starttls.enable", endpoint.startTls.toString())
            setProperty("mail.$prefix.starttls.required", endpoint.startTls.toString())
            setProperty("mail.$prefix.ssl.trust", endpoint.host)
            setProperty("mail.$prefix.auth", "true")
            when (mechanism) {
                ProviderAuthenticationMechanism.PASSWORD -> Unit
                ProviderAuthenticationMechanism.XOAUTH2 -> {
                    setProperty("mail.$prefix.auth.mechanisms", "XOAUTH2")
                    setProperty("mail.$prefix.auth.login.disable", "true")
                    setProperty("mail.$prefix.auth.plain.disable", "true")
                }
                ProviderAuthenticationMechanism.OAUTHBEARER -> {
                    // Also constrain the non-SASL fallback path to a mechanism with no
                    // built-in Angus authenticator, so the token can never become a
                    // PLAIN/LOGIN/NTLM password if SASL initialization is unavailable.
                    setProperty("mail.$prefix.auth.mechanisms", "OAUTHBEARER")
                    setProperty("mail.$prefix.sasl.enable", "true")
                    setProperty("mail.$prefix.sasl.mechanisms", "OAUTHBEARER")
                    setProperty("mail.$prefix.sasl.authorizationid", address)
                    setProperty("mail.$prefix.auth.login.disable", "true")
                    setProperty("mail.$prefix.auth.plain.disable", "true")
                }
            }
        }
    }

    private companion object {
        const val TIMEOUT_MILLIS = 10_000
    }
}

internal sealed interface ProviderAuthenticationTransportOutcome {
    val diagnostic: String

    data class Authenticated(override val diagnostic: String) :
        ProviderAuthenticationTransportOutcome

    data class WrongPassword(override val diagnostic: String) :
        ProviderAuthenticationTransportOutcome

    data class MissingAccount(override val diagnostic: String) :
        ProviderAuthenticationTransportOutcome

    data class Unavailable(override val diagnostic: String) :
        ProviderAuthenticationTransportOutcome

    data class TimedOut(override val diagnostic: String) :
        ProviderAuthenticationTransportOutcome
}

internal sealed interface AuthenticationOutcome {
    val diagnostic: String

    data class Authenticated(override val diagnostic: String) : AuthenticationOutcome
    data class MissingCredentials(override val diagnostic: String) : AuthenticationOutcome
    data class WrongPassword(override val diagnostic: String) : AuthenticationOutcome
    data class MissingAccount(override val diagnostic: String) : AuthenticationOutcome
    data class Unavailable(override val diagnostic: String) : AuthenticationOutcome
    data class TimedOut(override val diagnostic: String) : AuthenticationOutcome
}

internal fun interface ProviderAuthenticationConnector {
    fun authenticate(attempt: ProviderAuthenticationAttempt): ProviderAuthenticationTransportOutcome
}

internal class ProviderAuthenticationProbe(
    private val connector: ProviderAuthenticationConnector = JakartaProviderAuthenticationConnector(),
) {
    fun probe(request: ProviderAuthenticationRequest): AuthenticationOutcome {
        val credentials = request.credentials
        val secret = when (request.mechanism) {
            ProviderAuthenticationMechanism.PASSWORD -> credentials.password
            ProviderAuthenticationMechanism.XOAUTH2,
            ProviderAuthenticationMechanism.OAUTHBEARER,
            -> credentials.tokenOverride
        } ?: return AuthenticationOutcome.MissingCredentials("Credentials are required")

        require(
            request.protocol != ProviderAuthenticationProtocol.POP3 ||
                request.mechanism == ProviderAuthenticationMechanism.PASSWORD,
        ) {
            "POP3 token authentication is not supported by this probe"
        }
        val attempt = ProviderAuthenticationAttempt(
            protocol = request.protocol,
            mechanism = request.mechanism,
            endpoint = request.endpointOverride ?: request.protocol.endpoint,
            address = credentials.address,
            secret = secret,
            authenticateOnly = request.protocol == ProviderAuthenticationProtocol.SMTP,
        )
        return connector.authenticate(attempt).toOutcome(secret)
    }

    private fun ProviderAuthenticationTransportOutcome.toOutcome(secret: String): AuthenticationOutcome {
        val bounded = boundDiagnostic(diagnostic, secret)
        return when (this) {
            is ProviderAuthenticationTransportOutcome.Authenticated ->
                AuthenticationOutcome.Authenticated(bounded)
            is ProviderAuthenticationTransportOutcome.WrongPassword ->
                AuthenticationOutcome.WrongPassword(bounded)
            is ProviderAuthenticationTransportOutcome.MissingAccount ->
                AuthenticationOutcome.MissingAccount(bounded)
            is ProviderAuthenticationTransportOutcome.Unavailable ->
                AuthenticationOutcome.Unavailable(bounded)
            is ProviderAuthenticationTransportOutcome.TimedOut ->
                AuthenticationOutcome.TimedOut(bounded)
        }
    }
}

internal interface ProviderAuthenticationConnection : AutoCloseable {
    fun authenticate()
}

internal fun interface ProviderAuthenticationConnectionFactory {
    fun create(
        attempt: ProviderAuthenticationAttempt,
        properties: Properties,
    ): ProviderAuthenticationConnection
}

internal class JakartaProviderAuthenticationConnector(
    private val connectionFactory: ProviderAuthenticationConnectionFactory =
        JakartaProviderAuthenticationConnectionFactory(),
) : ProviderAuthenticationConnector {
    override fun authenticate(
        attempt: ProviderAuthenticationAttempt,
    ): ProviderAuthenticationTransportOutcome {
        var connection: ProviderAuthenticationConnection? = null
        return try {
            connection = connectionFactory.create(attempt, attempt.sessionProperties())
            connection.authenticate()
            ProviderAuthenticationTransportOutcome.Authenticated("Authentication succeeded")
        } catch (failure: AuthenticationFailedException) {
            val diagnostic = failure.providerDiagnostic()
            if (diagnostic.indicatesMissingAccount()) {
                ProviderAuthenticationTransportOutcome.MissingAccount(diagnostic)
            } else {
                ProviderAuthenticationTransportOutcome.WrongPassword(diagnostic)
            }
        } catch (cancellation: CancellationException) {
            throw cancellation
        } catch (failure: Exception) {
            val diagnostic = failure.providerDiagnostic()
            if (failure.hasCause<SocketTimeoutException>()) {
                ProviderAuthenticationTransportOutcome.TimedOut(diagnostic)
            } else {
                ProviderAuthenticationTransportOutcome.Unavailable(diagnostic)
            }
        } finally {
            runCatching { connection?.close() }
        }
    }
}

internal fun interface JakartaAuthenticationStoreFactory {
    fun create(session: Session, protocol: ProviderAuthenticationProtocol): Store
}

internal fun interface JakartaAuthenticationTransportFactory {
    fun create(session: Session): Transport
}

internal class JakartaProviderAuthenticationConnectionFactory(
    private val storeFactory: JakartaAuthenticationStoreFactory =
        JakartaAuthenticationStoreFactory { session, protocol ->
            session.getStore(protocol.propertyPrefix)
        },
    private val transportFactory: JakartaAuthenticationTransportFactory =
        JakartaAuthenticationTransportFactory { session -> session.getTransport("smtp") },
) : ProviderAuthenticationConnectionFactory {
    override fun create(
        attempt: ProviderAuthenticationAttempt,
        properties: Properties,
    ): ProviderAuthenticationConnection {
        if (attempt.mechanism == ProviderAuthenticationMechanism.OAUTHBEARER) {
            installOAuthBearerSaslProvider()
        }
        val session = Session.getInstance(properties)
        return when (attempt.protocol) {
            ProviderAuthenticationProtocol.IMAP,
            ProviderAuthenticationProtocol.POP3,
            -> StoreAuthenticationConnection(
                store = storeFactory.create(session, attempt.protocol),
                attempt = attempt,
            )
            ProviderAuthenticationProtocol.SMTP -> TransportAuthenticationConnection(
                transport = transportFactory.create(session),
                attempt = attempt,
            )
        }
    }
}

/** RFC 7628 client used because Angus 2.0.5 does not ship OAUTHBEARER SASL. */
internal class OAuthBearerSaslClientFactory : SaslClientFactory {
    override fun createSaslClient(
        mechanisms: Array<out String>,
        authorizationId: String?,
        protocol: String,
        serverName: String,
        props: Map<String, *>?,
        callbackHandler: CallbackHandler?,
    ): SaslClient? = if (OAUTH_BEARER_MECHANISM in mechanisms) {
        OAuthBearerSaslClient(
            authorizationId = authorizationId,
            serverName = serverName,
            callbackHandler = callbackHandler
                ?: throw SaslException("OAUTHBEARER requires a callback handler"),
        )
    } else {
        null
    }

    override fun getMechanismNames(props: Map<String, *>?): Array<String> =
        arrayOf(OAUTH_BEARER_MECHANISM)
}

private class OAuthBearerSaslClient(
    private val authorizationId: String?,
    private val serverName: String,
    private val callbackHandler: CallbackHandler,
) : SaslClient {
    private var sentInitialResponse = false
    private var acknowledgedErrorChallenge = false
    private var disposed = false

    override fun getMechanismName(): String = OAUTH_BEARER_MECHANISM

    override fun hasInitialResponse(): Boolean = true

    override fun evaluateChallenge(challenge: ByteArray): ByteArray {
        check(!disposed) { "OAUTHBEARER SASL client is disposed" }
        if (sentInitialResponse) {
            // RFC 7628 requires a single 0x01 response to an authentication error challenge.
            check(!acknowledgedErrorChallenge) {
                "OAUTHBEARER error challenge was already acknowledged"
            }
            acknowledgedErrorChallenge = true
            return byteArrayOf(1)
        }
        val name = NameCallback("Account address")
        val password = PasswordCallback("Request-scoped OAuth bearer token", false)
        try {
            callbackHandler.handle(arrayOf<Callback>(name, password))
        } catch (failure: Exception) {
            throw SaslException("Could not obtain OAUTHBEARER credentials", failure)
        }
        val address = authorizationId
            ?.takeIf(String::isNotBlank)
            ?: name.name?.takeIf(String::isNotBlank)
            ?: name.defaultName?.takeIf(String::isNotBlank)
            ?: throw SaslException("OAUTHBEARER account address is missing")
        val tokenCharacters = password.password
            ?: throw SaslException("OAUTHBEARER token is missing")
        return try {
            val token = String(tokenCharacters)
            require(token.isNotEmpty()) { "OAUTHBEARER token is missing" }
            sentInitialResponse = true
            buildString {
                append("n,a=")
                append(address.gs2Escape())
                append(",\u0001host=")
                append(serverName)
                append("\u0001auth=Bearer ")
                append(token)
                append("\u0001\u0001")
            }.toByteArray(StandardCharsets.UTF_8)
        } catch (failure: IllegalArgumentException) {
            throw SaslException(failure.message, failure)
        } finally {
            tokenCharacters.fill('\u0000')
            password.clearPassword()
        }
    }

    // Angus checks this before forwarding an IMAP continuation or SMTP 334 challenge.
    // Remaining incomplete after the client-first response lets RFC 7628's error exchange run.
    override fun isComplete(): Boolean = acknowledgedErrorChallenge

    override fun unwrap(incoming: ByteArray, offset: Int, length: Int): ByteArray =
        throw SaslException("OAUTHBEARER does not provide a security layer")

    override fun wrap(outgoing: ByteArray, offset: Int, length: Int): ByteArray =
        throw SaslException("OAUTHBEARER does not provide a security layer")

    override fun getNegotiatedProperty(propertyName: String): Any? {
        check(isComplete()) { "OAUTHBEARER authentication is not complete" }
        return null
    }

    override fun dispose() {
        disposed = true
    }
}

private class OAuthBearerSaslProvider : Provider(
    OAUTH_BEARER_PROVIDER,
    "1.0",
    "RFC 7628 OAUTHBEARER SASL client for the local mail sandbox",
) {
    init {
        put(
            "SaslClientFactory.$OAUTH_BEARER_MECHANISM",
            OAuthBearerSaslClientFactory::class.java.name,
        )
    }
}

private fun installOAuthBearerSaslProvider() {
    synchronized(OAUTH_BEARER_PROVIDER_LOCK) {
        val available = Security.getProviders("SaslClientFactory.$OAUTH_BEARER_MECHANISM")
        if (available.isNullOrEmpty()) {
            Security.addProvider(OAuthBearerSaslProvider())
        }
    }
}

private fun String.gs2Escape(): String = replace("=", "=3D").replace(",", "=2C")

private const val OAUTH_BEARER_MECHANISM = "OAUTHBEARER"
private const val OAUTH_BEARER_PROVIDER = "MailSandboxOAuthBearer"
private val OAUTH_BEARER_PROVIDER_LOCK = Any()

private class StoreAuthenticationConnection(
    private val store: Store,
    private val attempt: ProviderAuthenticationAttempt,
) : ProviderAuthenticationConnection {
    override fun authenticate() {
        store.connect(
            attempt.endpoint.host,
            attempt.endpoint.port,
            attempt.address,
            attempt.secret,
        )
    }

    override fun close() {
        store.close()
    }
}

private class TransportAuthenticationConnection(
    private val transport: Transport,
    private val attempt: ProviderAuthenticationAttempt,
) : ProviderAuthenticationConnection {
    override fun authenticate() {
        transport.connect(
            attempt.endpoint.host,
            attempt.endpoint.port,
            attempt.address,
            attempt.secret,
        )
    }

    override fun close() {
        transport.close()
    }
}

private fun Throwable.providerDiagnostic(): String {
    val messaging = this as? MessagingException
    return sequenceOf(message, messaging?.nextException?.message)
        .filterNotNull()
        .firstOrNull(String::isNotBlank)
        ?: this::class.simpleName.orEmpty().ifBlank { "Provider authentication failed" }
}

private inline fun <reified T : Throwable> Throwable.hasCause(): Boolean {
    var current: Throwable? = this
    val seen = HashSet<Throwable>()
    while (current != null && seen.add(current)) {
        if (current is T) return true
        current = if (current is MessagingException && current.nextException != null) {
            current.nextException
        } else {
            current.cause
        }
    }
    return false
}

private fun String.indicatesMissingAccount(): Boolean {
    val normalized = lowercase()
    return listOf("unknown user", "no such user", "user doesn't exist", "missing account")
        .any(normalized::contains)
}

private fun boundDiagnostic(value: String, secret: String): String = (
    if (secret.isEmpty()) value else value.replace(secret, "[redacted]")
)
    .map { character -> if (character.isISOControl()) ' ' else character }
    .joinToString("")
    .trim()
    .take(MAXIMUM_DIAGNOSTIC_CHARACTERS)
    .ifEmpty { "Provider authentication failed" }

private const val MAXIMUM_DIAGNOSTIC_CHARACTERS = 512
