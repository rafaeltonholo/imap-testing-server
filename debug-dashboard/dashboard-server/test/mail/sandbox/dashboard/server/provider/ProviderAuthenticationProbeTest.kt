package mail.sandbox.dashboard.server.provider

import jakarta.mail.AuthenticationFailedException
import jakarta.mail.Address
import jakarta.mail.Folder
import jakarta.mail.Message
import jakarta.mail.MessagingException
import jakarta.mail.Session
import jakarta.mail.Store
import jakarta.mail.Transport
import jakarta.mail.URLName
import java.net.SocketTimeoutException
import java.util.Properties
import javax.security.auth.callback.NameCallback
import javax.security.auth.callback.PasswordCallback
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

class ProviderAuthenticationProbeTest {
    @Test
    fun passwordAndRequestTokenProbesUseTheFixedLoopbackEndpoints() {
        val connector = RecordingAuthenticationConnector()
        val probe = ProviderAuthenticationProbe(connector)

        assertIs<AuthenticationOutcome.Authenticated>(
            probe.probe(
                ProviderAuthenticationRequest(
                    protocol = ProviderAuthenticationProtocol.IMAP,
                    mechanism = ProviderAuthenticationMechanism.PASSWORD,
                    credentials = AccountCredentials("alice@local.test", "password"),
                ),
            ),
        )
        assertIs<AuthenticationOutcome.Authenticated>(
            probe.probe(
                ProviderAuthenticationRequest(
                    protocol = ProviderAuthenticationProtocol.POP3,
                    mechanism = ProviderAuthenticationMechanism.PASSWORD,
                    credentials = AccountCredentials("alice@local.test", "password"),
                ),
            ),
        )
        assertIs<AuthenticationOutcome.Authenticated>(
            probe.probe(
                ProviderAuthenticationRequest(
                    protocol = ProviderAuthenticationProtocol.SMTP,
                    mechanism = ProviderAuthenticationMechanism.PASSWORD,
                    credentials = AccountCredentials("alice@local.test", "password"),
                ),
            ),
        )
        listOf(
            ProviderAuthenticationMechanism.XOAUTH2,
            ProviderAuthenticationMechanism.OAUTHBEARER,
        ).forEach { mechanism ->
            listOf(
                ProviderAuthenticationProtocol.IMAP,
                ProviderAuthenticationProtocol.SMTP,
            ).forEach { protocol ->
                probe.probe(
                    ProviderAuthenticationRequest(
                        protocol = protocol,
                        mechanism = mechanism,
                        credentials = AccountCredentials(
                            address = "alice@local.test",
                            tokenOverride = "request-token",
                        ),
                    ),
                )
            }
        }

        assertEquals(
            listOf(
                ProviderAuthenticationEndpoint("127.0.0.1", 1143, startTls = true),
                ProviderAuthenticationEndpoint("127.0.0.1", 1110, startTls = true),
                ProviderAuthenticationEndpoint("127.0.0.1", 1587, startTls = true),
                ProviderAuthenticationEndpoint("127.0.0.1", 1143, startTls = true),
                ProviderAuthenticationEndpoint("127.0.0.1", 1587, startTls = true),
                ProviderAuthenticationEndpoint("127.0.0.1", 1143, startTls = true),
                ProviderAuthenticationEndpoint("127.0.0.1", 1587, startTls = true),
            ),
            connector.attempts.map(ProviderAuthenticationAttempt::endpoint),
        )
        assertTrue(connector.attempts.filter {
            it.mechanism != ProviderAuthenticationMechanism.PASSWORD
        }.all { it.secret == "request-token" })
        assertTrue(connector.attempts.filter {
            it.protocol == ProviderAuthenticationProtocol.SMTP
        }.all(ProviderAuthenticationAttempt::authenticateOnly))
        connector.attempts.forEach { attempt ->
            val prefix = attempt.protocol.propertyPrefix
            val properties = attempt.sessionProperties()
            assertEquals("true", properties.getProperty("mail.$prefix.starttls.enable"))
            assertEquals("true", properties.getProperty("mail.$prefix.starttls.required"))
            assertEquals("127.0.0.1", properties.getProperty("mail.$prefix.ssl.trust"))
            listOf("connectiontimeout", "timeout", "writetimeout").forEach { suffix ->
                assertTrue(properties.getProperty("mail.$prefix.$suffix").toInt() in 1..30_000)
            }
            when (attempt.mechanism) {
                ProviderAuthenticationMechanism.PASSWORD -> Unit
                ProviderAuthenticationMechanism.XOAUTH2 -> {
                    assertEquals(
                        "XOAUTH2",
                        properties.getProperty("mail.$prefix.auth.mechanisms"),
                    )
                    assertEquals("true", properties.getProperty("mail.$prefix.auth.plain.disable"))
                    assertEquals("true", properties.getProperty("mail.$prefix.auth.login.disable"))
                }
                ProviderAuthenticationMechanism.OAUTHBEARER -> {
                    assertEquals(
                        "OAUTHBEARER",
                        properties.getProperty("mail.$prefix.auth.mechanisms"),
                    )
                    assertEquals("true", properties.getProperty("mail.$prefix.sasl.enable"))
                    assertEquals(
                        "OAUTHBEARER",
                        properties.getProperty("mail.$prefix.sasl.mechanisms"),
                    )
                    assertEquals(attempt.address, properties.getProperty("mail.$prefix.sasl.authorizationid"))
                    assertEquals("true", properties.getProperty("mail.$prefix.auth.plain.disable"))
                    assertEquals("true", properties.getProperty("mail.$prefix.auth.login.disable"))
                }
            }
        }
    }

    @Test
    fun missingAndProviderFailuresAreTypedAndDiagnosticsAreBounded() {
        val connector = RecordingAuthenticationConnector()
        val probe = ProviderAuthenticationProbe(connector)

        assertIs<AuthenticationOutcome.MissingCredentials>(
            probe.probe(
                ProviderAuthenticationRequest(
                    ProviderAuthenticationProtocol.IMAP,
                    ProviderAuthenticationMechanism.PASSWORD,
                    AccountCredentials("alice@local.test"),
                ),
            ),
        )
        assertIs<AuthenticationOutcome.MissingCredentials>(
            probe.probe(
                ProviderAuthenticationRequest(
                    ProviderAuthenticationProtocol.SMTP,
                    ProviderAuthenticationMechanism.XOAUTH2,
                    AccountCredentials("alice@local.test", password = "must-not-substitute"),
                ),
            ),
        )
        assertTrue(connector.attempts.isEmpty())

        val outcomes = listOf(
            ProviderAuthenticationTransportOutcome.WrongPassword("wrong password"),
            ProviderAuthenticationTransportOutcome.MissingAccount("unknown user"),
            ProviderAuthenticationTransportOutcome.Unavailable("connection refused"),
            ProviderAuthenticationTransportOutcome.TimedOut("read timed out"),
        ).map { transportOutcome ->
            connector.next = transportOutcome
            probe.probe(
                ProviderAuthenticationRequest(
                    ProviderAuthenticationProtocol.IMAP,
                    ProviderAuthenticationMechanism.PASSWORD,
                    AccountCredentials("alice@local.test", "password"),
                ),
            )
        }

        assertIs<AuthenticationOutcome.WrongPassword>(outcomes[0])
        assertIs<AuthenticationOutcome.MissingAccount>(outcomes[1])
        assertIs<AuthenticationOutcome.Unavailable>(outcomes[2])
        assertIs<AuthenticationOutcome.TimedOut>(outcomes[3])

        connector.next = ProviderAuthenticationTransportOutcome.Unavailable("x".repeat(4_096))
        val bounded = probe.probe(
            ProviderAuthenticationRequest(
                ProviderAuthenticationProtocol.IMAP,
                ProviderAuthenticationMechanism.PASSWORD,
                AccountCredentials("alice@local.test", "password"),
            ),
        )
        assertTrue(bounded.diagnostic.length <= 512)
        assertTrue("password" !in bounded.diagnostic)
    }

    @Test
    fun jakartaConnectorClosesAuthenticationConnectionsOnSuccessAndFailure() {
        val successFactory = RecordingConnectionFactory()
        val successConnector = JakartaProviderAuthenticationConnector(successFactory)
        assertIs<ProviderAuthenticationTransportOutcome.Authenticated>(
            successConnector.authenticate(passwordAttempt()),
        )
        assertEquals(1, successFactory.created.single().closeCount)

        val failureFactory = RecordingConnectionFactory(SocketTimeoutException("read timed out"))
        val failureConnector = JakartaProviderAuthenticationConnector(failureFactory)
        assertIs<ProviderAuthenticationTransportOutcome.TimedOut>(
            failureConnector.authenticate(passwordAttempt()),
        )
        assertEquals(1, failureFactory.created.single().closeCount)

        val wrongPasswordFactory = RecordingConnectionFactory(
            AuthenticationFailedException("authentication failed"),
        )
        assertIs<ProviderAuthenticationTransportOutcome.WrongPassword>(
            JakartaProviderAuthenticationConnector(wrongPasswordFactory)
                .authenticate(passwordAttempt()),
        )
        assertEquals(1, wrongPasswordFactory.created.single().closeCount)

        val missingAccountFactory = RecordingConnectionFactory(
            AuthenticationFailedException("unknown user"),
        )
        assertIs<ProviderAuthenticationTransportOutcome.MissingAccount>(
            JakartaProviderAuthenticationConnector(missingAccountFactory)
                .authenticate(passwordAttempt()),
        )
        assertEquals(1, missingAccountFactory.created.single().closeCount)

        val unavailableFactory = RecordingConnectionFactory(
            MessagingException("connection refused"),
        )
        assertIs<ProviderAuthenticationTransportOutcome.Unavailable>(
            JakartaProviderAuthenticationConnector(unavailableFactory)
                .authenticate(passwordAttempt()),
        )
        assertEquals(1, unavailableFactory.created.single().closeCount)

        val wrappedTimeout = MessagingException("provider timeout").apply {
            setNextException(SocketTimeoutException("read timed out"))
        }
        val wrappedTimeoutFactory = RecordingConnectionFactory(wrappedTimeout)
        assertIs<ProviderAuthenticationTransportOutcome.TimedOut>(
            JakartaProviderAuthenticationConnector(wrappedTimeoutFactory)
                .authenticate(passwordAttempt()),
        )
        assertEquals(1, wrappedTimeoutFactory.created.single().closeCount)
    }

    @Test
    fun injectedJakartaStoreReceivesTheExactOrdinaryAccountAndIsClosed() {
        lateinit var store: RecordingJakartaStore
        val connector = JakartaProviderAuthenticationConnector(
            JakartaProviderAuthenticationConnectionFactory(
                storeFactory = JakartaAuthenticationStoreFactory { session, protocol ->
                    assertEquals(ProviderAuthenticationProtocol.IMAP, protocol)
                    RecordingJakartaStore(session).also { store = it }
                },
                transportFactory = JakartaAuthenticationTransportFactory {
                    error("SMTP transport must not be created for an IMAP probe")
                },
            ),
        )

        assertIs<ProviderAuthenticationTransportOutcome.Authenticated>(
            connector.authenticate(passwordAttempt()),
        )

        assertEquals(
            JakartaConnectCall("127.0.0.1", 1143, "alice@local.test", "password"),
            store.connectCall,
        )
        assertEquals("true", store.sessionProperty("mail.imap.starttls.required"))
        assertEquals("10000", store.sessionProperty("mail.imap.connectiontimeout"))
        assertEquals(1, store.closeCount)
    }

    @Test
    fun injectedJakartaSmtpTransportAuthenticatesWithoutSendingAndIsClosed() {
        lateinit var transport: RecordingJakartaTransport
        val connector = JakartaProviderAuthenticationConnector(
            JakartaProviderAuthenticationConnectionFactory(
                storeFactory = JakartaAuthenticationStoreFactory { _, _ ->
                    error("Mail store must not be created for an SMTP probe")
                },
                transportFactory = JakartaAuthenticationTransportFactory { session ->
                    RecordingJakartaTransport(session).also { transport = it }
                },
            ),
        )
        val attempt = ProviderAuthenticationAttempt(
            protocol = ProviderAuthenticationProtocol.SMTP,
            mechanism = ProviderAuthenticationMechanism.PASSWORD,
            endpoint = ProviderAuthenticationEndpoint("127.0.0.1", 1587, startTls = true),
            address = "alice@local.test",
            secret = "password",
            authenticateOnly = true,
        )

        assertIs<ProviderAuthenticationTransportOutcome.Authenticated>(
            connector.authenticate(attempt),
        )

        assertEquals(
            JakartaConnectCall("127.0.0.1", 1587, "alice@local.test", "password"),
            transport.connectCall,
        )
        assertEquals("true", transport.sessionProperty("mail.smtp.starttls.required"))
        assertEquals(0, transport.sendCount)
        assertEquals(1, transport.closeCount)
    }

    @Test
    fun failuresRaisedByAnInjectedJakartaStoreAreTypedAndTheStoreIsClosed() {
        listOf(
            AuthenticationFailedException("authentication failed") to
                ProviderAuthenticationTransportOutcome.WrongPassword::class,
            SocketTimeoutException("read timed out") to
                ProviderAuthenticationTransportOutcome.TimedOut::class,
            MessagingException("connection refused") to
                ProviderAuthenticationTransportOutcome.Unavailable::class,
        ).forEach { (failure, expectedType) ->
            lateinit var store: RecordingJakartaStore
            val connector = JakartaProviderAuthenticationConnector(
                JakartaProviderAuthenticationConnectionFactory(
                    storeFactory = JakartaAuthenticationStoreFactory { session, _ ->
                        RecordingJakartaStore(session, failure).also { store = it }
                    },
                    transportFactory = JakartaAuthenticationTransportFactory {
                        error("SMTP transport must not be created for an IMAP probe")
                    },
                ),
            )

            val outcome = connector.authenticate(passwordAttempt())

            assertTrue(expectedType.isInstance(outcome))
            assertEquals(1, store.closeCount)
        }
    }

    @Test
    fun failureRaisedByAnInjectedJakartaSmtpTransportIsTypedAndClosedWithoutSending() {
        lateinit var transport: RecordingJakartaTransport
        val connector = JakartaProviderAuthenticationConnector(
            JakartaProviderAuthenticationConnectionFactory(
                storeFactory = JakartaAuthenticationStoreFactory { _, _ ->
                    error("Mail store must not be created for an SMTP probe")
                },
                transportFactory = JakartaAuthenticationTransportFactory { session ->
                    RecordingJakartaTransport(
                        session,
                        AuthenticationFailedException("authentication failed"),
                    ).also { transport = it }
                },
            ),
        )
        val attempt = ProviderAuthenticationAttempt(
            protocol = ProviderAuthenticationProtocol.SMTP,
            mechanism = ProviderAuthenticationMechanism.PASSWORD,
            endpoint = ProviderAuthenticationEndpoint("127.0.0.1", 1587, startTls = true),
            address = "alice@local.test",
            secret = "wrong-password",
            authenticateOnly = true,
        )

        assertIs<ProviderAuthenticationTransportOutcome.WrongPassword>(
            connector.authenticate(attempt),
        )
        assertEquals(0, transport.sendCount)
        assertEquals(1, transport.closeCount)
    }

    @Test
    fun oauthBearerSaslClientUsesOnlyTheRequestScopedAddressAndToken() {
        val client = OAuthBearerSaslClientFactory().createSaslClient(
            mechanisms = arrayOf("OAUTHBEARER"),
            authorizationId = null,
            protocol = "imap",
            serverName = "127.0.0.1",
            props = emptyMap<String, Any>(),
        ) { callbacks ->
            callbacks.forEach { callback ->
                when (callback) {
                    is NameCallback -> callback.name = "alice@local.test"
                    is PasswordCallback -> callback.password = "request-token".toCharArray()
                }
            }
        }

        requireNotNull(client)
        assertTrue(client.hasInitialResponse())
        val initialResponse = client.evaluateChallenge(ByteArray(0)).toString(Charsets.UTF_8)
        assertTrue(initialResponse.startsWith("n,a=alice@local.test,"))
        assertTrue("auth=Bearer request-token" in initialResponse)
        assertTrue("password" !in initialResponse)
        assertFalse(
            client.isComplete(),
            "Angus skips evaluateChallenge when isComplete is already true",
        )
        val errorResponse = if (client.isComplete()) {
            ByteArray(0)
        } else {
            client.evaluateChallenge("error".toByteArray())
        }
        assertEquals(listOf(1.toByte()), errorResponse.toList())
        assertTrue(client.isComplete())
    }

    private fun passwordAttempt(): ProviderAuthenticationAttempt =
        ProviderAuthenticationAttempt(
            protocol = ProviderAuthenticationProtocol.IMAP,
            mechanism = ProviderAuthenticationMechanism.PASSWORD,
            endpoint = ProviderAuthenticationEndpoint("127.0.0.1", 1143, startTls = true),
            address = "alice@local.test",
            secret = "password",
            authenticateOnly = false,
        )
}

private class RecordingAuthenticationConnector : ProviderAuthenticationConnector {
    val attempts = mutableListOf<ProviderAuthenticationAttempt>()
    var next: ProviderAuthenticationTransportOutcome =
        ProviderAuthenticationTransportOutcome.Authenticated("authenticated")

    override fun authenticate(
        attempt: ProviderAuthenticationAttempt,
    ): ProviderAuthenticationTransportOutcome {
        attempts += attempt
        return next
    }
}

private class RecordingConnectionFactory(
    private val failure: Exception? = null,
) : ProviderAuthenticationConnectionFactory {
    val created = mutableListOf<RecordingConnection>()

    override fun create(
        attempt: ProviderAuthenticationAttempt,
        properties: Properties,
    ): ProviderAuthenticationConnection = RecordingConnection(failure).also(created::add)
}

private class RecordingConnection(
    private val failure: Exception?,
) : ProviderAuthenticationConnection {
    var closeCount = 0

    override fun authenticate() {
        failure?.let { throw it }
    }

    override fun close() {
        closeCount++
    }
}

private data class JakartaConnectCall(
    val host: String?,
    val port: Int,
    val user: String?,
    val secret: String?,
)

private class RecordingJakartaStore(
    session: Session,
    private val failure: Exception? = null,
) : Store(session, URLName("imap", null, -1, null, null, null)) {
    var connectCall: JakartaConnectCall? = null
    var closeCount: Int = 0

    fun sessionProperty(name: String): String? = session.getProperty(name)

    override fun protocolConnect(
        host: String?,
        port: Int,
        user: String?,
        password: String?,
    ): Boolean {
        connectCall = JakartaConnectCall(host, port, user, password)
        failure?.let { throw it }
        return true
    }

    override fun getDefaultFolder(): Folder = error("Not used by an authentication probe")

    override fun getFolder(name: String): Folder = error("Not used by an authentication probe")

    override fun getFolder(url: URLName): Folder = error("Not used by an authentication probe")

    override fun close() {
        closeCount++
        setConnected(false)
    }
}

private class RecordingJakartaTransport(
    session: Session,
    private val failure: Exception? = null,
) : Transport(session, URLName("smtp", null, -1, null, null, null)) {
    var connectCall: JakartaConnectCall? = null
    var closeCount: Int = 0
    var sendCount: Int = 0

    fun sessionProperty(name: String): String? = session.getProperty(name)

    override fun protocolConnect(
        host: String?,
        port: Int,
        user: String?,
        password: String?,
    ): Boolean {
        connectCall = JakartaConnectCall(host, port, user, password)
        failure?.let { throw it }
        return true
    }

    override fun sendMessage(message: Message, addresses: Array<out Address>) {
        sendCount++
    }

    override fun close() {
        closeCount++
        setConnected(false)
    }
}
