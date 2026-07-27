package mail.sandbox.dashboard.server.gate.stalwart

import java.net.URI
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertSame
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.runBlocking

class GateJmapClientTest {
    @Test
    fun malformedButValidSessionFieldsAreTypedAndRedacted() = runBlocking {
        val marker = "session-response-secret"
        listOf(
            """{"apiUrl":{"secret":"$marker"}}""",
            """{"apiUrl":7}""",
            """{"apiUrl":"/jmap/","username":{"secret":"$marker"}}""",
            """
                {
                  "apiUrl":"/jmap/",
                  "primaryAccounts":{"urn:stalwart:jmap":{"secret":"$marker"}}
                }
            """.trimIndent(),
            """{"apiUrl":"/jmap/[","username":"$marker"}""",
        ).forEach { body ->
            val failure = assertFailsWith<GateJmapException> {
                clientWithSession(body).discoverSession()
            }

            assertEquals(GateJmapFailure.InvalidResponse, failure.kind)
            assertFalse(failure.message.orEmpty().contains(marker))
            assertFalse(failure.toString().contains(marker))
        }
    }

    @Test
    fun malformedButValidMethodTuplesAreTypedAndRedacted() = runBlocking {
        val marker = "method-response-secret"
        listOf(
            """
                {"methodResponses":[
                  [{"secret":"$marker"},{"state":"1"},"gate-1"]
                ]}
            """.trimIndent(),
            """
                {"methodResponses":[
                  ["x:Account/get",{"state":"1"},{"secret":"$marker"}]
                ]}
            """.trimIndent(),
            """
                {"methodResponses":[
                  ["error",{"type":{"secret":"$marker"}},"gate-1"]
                ]}
            """.trimIndent(),
        ).forEach { body ->
            val failure = assertFailsWith<GateJmapException> {
                clientWithSession(
                    sessionBody = validSessionBody,
                    methodBody = body,
                ).registryGet("Account")
            }

            assertEquals(GateJmapFailure.InvalidResponse, failure.kind)
            assertFalse(failure.message.orEmpty().contains(marker))
            assertFalse(failure.toString().contains(marker))
        }
    }

    @Test
    fun methodErrorDiagnosticsDoNotEchoTheServerControlledType() = runBlocking {
        val marker = "method-error-secret"
        val failure = assertFailsWith<GateJmapException> {
            clientWithSession(
                sessionBody = validSessionBody,
                methodBody = """
                    {"methodResponses":[
                      ["error",{"type":"$marker"},"gate-1"]
                    ]}
                """.trimIndent(),
            ).registryGet("Account")
        }

        assertEquals(GateJmapFailure.MethodError(marker), failure.kind)
        assertFalse(failure.message.orEmpty().contains(marker))
        assertFalse(failure.toString().contains(marker))
    }

    @Test
    fun responseBodyReadFailuresAreTypedAndRedacted() = runBlocking {
        val marker = "body-read-secret"

        val failure = assertFailsWith<GateJmapException> {
            readGateHttpResponse(
                status = 200,
                effectiveUrl = URI("http://127.0.0.1:18443/jmap/"),
            ) {
                throw IllegalStateException(marker)
            }
        }

        assertEquals(GateJmapFailure.Transport, failure.kind)
        assertFalse(failure.message.orEmpty().contains(marker))
        assertFalse(failure.toString().contains(marker))
    }

    @Test
    fun requestCancellationRemainsCooperative() = runBlocking {
        val cancellation = CancellationException("request-cancel-marker")

        val thrown = assertFailsWith<CancellationException> {
            executeGateTransportRequest {
                throw cancellation
            }
        }

        assertSame(cancellation, thrown)
    }

    @Test
    fun advertisedApiEndpointMustBeExactlyJmapWithoutUriExtras() = runBlocking {
        listOf(
            "/jmap",
            "/jmap/other",
            "/jmapevil/",
            "http://127.0.0.1:18443/jmap/?unsafe=query",
            "http://127.0.0.1:18443/jmap/#unsafe-fragment",
            "http://gate-user@127.0.0.1:18443/jmap/",
        ).forEach { advertised ->
            val failure = assertFailsWith<GateJmapException> {
                clientWithSession(
                    """{"apiUrl":"$advertised","primaryAccounts":{}}""",
                ).discoverSession()
            }

            assertEquals(GateJmapFailure.InvalidResponse, failure.kind)
            assertFalse(failure.message.orEmpty().contains(advertised))
        }
    }

    private fun clientWithSession(
        sessionBody: String,
        methodBody: String? = null,
    ): GateJmapClient {
        val responses = buildList {
            add(
                GateHttpResponse(
                    status = 200,
                    effectiveUrl = URI("http://127.0.0.1:18443/.well-known/jmap"),
                    body = sessionBody,
                ),
            )
            methodBody?.let {
                add(
                    GateHttpResponse(
                        status = 200,
                        effectiveUrl = URI("http://127.0.0.1:18443/jmap/"),
                        body = it,
                    ),
                )
            }
        }
        return GateJmapClient(
            baseUrl = URI("http://127.0.0.1:18443"),
            credential = GateCredential.bearer("API_test-only".toCharArray()),
            transport = QueueTransport(responses),
        )
    }

    private class QueueTransport(
        responses: List<GateHttpResponse>,
    ) : GateHttpTransport {
        private val responses = ArrayDeque(responses)

        override suspend fun execute(request: GateHttpRequest): GateHttpResponse =
            responses.removeFirst()
    }

    private companion object {
        val validSessionBody = """
            {
              "apiUrl":"/jmap/",
              "username":"gate-recovery",
              "primaryAccounts":{"urn:stalwart:jmap":"recovery-account"}
            }
        """.trimIndent()
    }
}
