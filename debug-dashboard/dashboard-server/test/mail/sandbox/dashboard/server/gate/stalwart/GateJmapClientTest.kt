package mail.sandbox.dashboard.server.gate.stalwart

import java.net.URI
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertSame
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

class GateJmapClientTest {
    @Test
    fun httpResponseCarriesRedirectLocationAsRedactedMetadata() {
        val response = GateHttpResponse(
            status = 307,
            effectiveUrl = URI("http://127.0.0.1:18443/.well-known/jmap"),
            body = "redirect-body-marker",
            location = "/jmap/session",
        )

        assertEquals("/jmap/session", response.location)
        assertFalse(response.toString().contains("redirect-body-marker"))
    }

    @Test
    fun endpointProfilesPinTheOnlyAllowedOriginsAndApiUrls() {
        assertEquals(
            listOf(
                StalwartEndpointProfile.GATE_FIXTURE,
                StalwartEndpointProfile.MIGRATION_BOOTSTRAP,
                StalwartEndpointProfile.NORMAL_RUNTIME,
            ),
            StalwartEndpointProfile.entries,
        )
        assertEquals(
            URI("http://127.0.0.1:18443"),
            StalwartEndpointProfile.GATE_FIXTURE.baseUrl,
        )
        assertEquals(
            URI("http://127.0.0.1:18443/jmap/"),
            StalwartEndpointProfile.GATE_FIXTURE.apiUrl,
        )
        assertEquals(
            URI("http://127.0.0.1:8443"),
            StalwartEndpointProfile.MIGRATION_BOOTSTRAP.baseUrl,
        )
        assertEquals(
            URI("http://127.0.0.1:8443/jmap/"),
            StalwartEndpointProfile.MIGRATION_BOOTSTRAP.apiUrl,
        )
        assertEquals(
            URI("http://127.0.0.1:8443"),
            StalwartEndpointProfile.NORMAL_RUNTIME.baseUrl,
        )
        assertEquals(
            URI("http://127.0.0.1:8443/jmap/"),
            StalwartEndpointProfile.NORMAL_RUNTIME.apiUrl,
        )
    }

    @Test
    fun normalRuntimeProfileAcceptsOnlyItsCanonicalBaseUrlShapes() {
        val profile = StalwartEndpointProfile.NORMAL_RUNTIME

        assertSame(
            profile,
            StalwartEndpointProfile.fromBaseUrl(
                URI("http://127.0.0.1:8443"),
            ),
        )
        assertSame(
            profile,
            StalwartEndpointProfile.fromBaseUrl(
                URI("http://127.0.0.1:8443/"),
            ),
        )
        listOf(
            "http://localhost:8443",
            "https://127.0.0.1:8443",
            "http://127.0.0.1:8443/jmap/",
            "http://127.0.0.1:8443/?query",
            "http://127.0.0.1:8443/#fragment",
            "http://gate-user@127.0.0.1:8443",
        ).forEach { value ->
            assertFailsWith<IllegalArgumentException>(value) {
                StalwartEndpointProfile.fromBaseUrl(URI(value))
            }
        }
    }

    @Test
    fun migrationProfileUsesOnlyItsPinnedDiscoveryAndApiUrls() = runBlocking {
        val profile = StalwartEndpointProfile.MIGRATION_BOOTSTRAP
        val transport = QueueTransport(
            listOf(
                GateHttpResponse(
                    status = 200,
                    effectiveUrl = URI(
                        "http://127.0.0.1:8443/.well-known/jmap",
                    ),
                    body = """{"apiUrl":"/jmap/","primaryAccounts":{}}""",
                ),
            ),
        )

        val session = GateJmapClient(
            profile = profile,
            credential = GateCredential.bearer(
                "API_test-only-migration".toCharArray(),
            ),
            transport = transport,
        ).use { client ->
            client.discoverSession()
        }

        assertEquals(profile.apiUrl, session.apiUrl)
        assertEquals(
            listOf(URI("http://127.0.0.1:8443/.well-known/jmap")),
            transport.requests.map(GateHttpRequest::url),
        )

        val failure = assertFailsWith<GateJmapException> {
            GateJmapClient(
                profile = profile,
                credential = GateCredential.bearer(
                    "API_test-only-migration".toCharArray(),
                ),
                transport = QueueTransport(
                    listOf(
                        GateHttpResponse(
                            status = 200,
                            effectiveUrl = URI(
                                "http://127.0.0.1:8443/.well-known/jmap",
                            ),
                            body = """
                                {
                                  "apiUrl":"http://127.0.0.1:18443/jmap/",
                                  "primaryAccounts":{}
                                }
                            """.trimIndent(),
                        ),
                    ),
                ),
            ).use { client ->
                client.discoverSession()
            }
        }

        assertEquals(GateJmapFailure.InvalidResponse, failure.kind)
    }

    @Test
    fun discoveryFollowsOnlyTheCanonicalSameOriginSessionRedirect() = runBlocking {
        val discoveryUrl = URI("http://127.0.0.1:18443/.well-known/jmap")
        val canonicalSessionUrl = URI("http://127.0.0.1:18443/jmap/session")
        val transport = QueueTransport(
            listOf(
                GateHttpResponse(
                    status = 307,
                    effectiveUrl = discoveryUrl,
                    body = "",
                    location = "/jmap/session",
                ),
                GateHttpResponse(
                    status = 200,
                    effectiveUrl = canonicalSessionUrl,
                    body = validSessionBody,
                ),
            ),
        )

        val session = GateJmapClient(
            profile = StalwartEndpointProfile.GATE_FIXTURE,
            credential = GateCredential.bearer(
                "API_test-only-canonical-redirect".toCharArray(),
            ),
            transport = transport,
        ).use { client ->
            client.discoverSession()
        }

        assertEquals(StalwartEndpointProfile.GATE_FIXTURE.apiUrl, session.apiUrl)
        assertEquals(
            listOf(discoveryUrl, canonicalSessionUrl),
            transport.requests.map(GateHttpRequest::url),
        )

        listOf(
            null,
            "/jmap/",
            "http://127.0.0.1:8443/jmap/session",
            "http://example.test/jmap/session",
        ).forEach { location ->
            val rejectedTransport = QueueTransport(
                listOf(
                    GateHttpResponse(
                        status = 307,
                        effectiveUrl = discoveryUrl,
                        body = "",
                        location = location,
                    ),
                ),
            )
            val failure = assertFailsWith<GateJmapException> {
                GateJmapClient(
                    profile = StalwartEndpointProfile.GATE_FIXTURE,
                    credential = GateCredential.bearer(
                        "API_test-only-rejected-redirect".toCharArray(),
                    ),
                    transport = rejectedTransport,
                ).use { client ->
                    client.discoverSession()
                }
            }

            assertEquals(GateJmapFailure.InvalidResponse, failure.kind)
            assertEquals(listOf(discoveryUrl), rejectedTransport.requests.map(GateHttpRequest::url))
        }
    }

    @Test
    fun jmapTransportRejectsRedirectFollowing() {
        assertFailsWith<IllegalArgumentException> {
            KtorGateHttpTransport(followRedirects = true).close()
        }
        KtorGateHttpTransport().close()
    }

    @Test
    fun discoveryResponseMustRemainOnTheExactPinnedWellKnownUrl() = runBlocking {
        val profile = StalwartEndpointProfile.GATE_FIXTURE
        listOf(
            URI("http://127.0.0.1:18443/redirected"),
            URI("http://127.0.0.1:18443/.well-known/jmap/"),
        ).forEach { effectiveUrl ->
            val transport = QueueTransport(
                listOf(
                    GateHttpResponse(
                        status = 200,
                        effectiveUrl = effectiveUrl,
                        body = validSessionBody,
                    ),
                ),
            )

            val failure = assertFailsWith<GateJmapException> {
                GateJmapClient(
                    profile = profile,
                    credential = GateCredential.bearer(
                        "API_test-only-discovery".toCharArray(),
                    ),
                    transport = transport,
                ).use { client ->
                    client.discoverSession()
                }
            }

            assertEquals(GateJmapFailure.InvalidResponse, failure.kind)
            assertEquals(
                listOf(URI("http://127.0.0.1:18443/.well-known/jmap")),
                transport.requests.map(GateHttpRequest::url),
            )
        }
    }

    @Test
    fun credentialsCopyInputsAndBasicKeepsUtf8Encoding() {
        val username = GateBootstrap.FIRST_USER_ADDRESS
        val basicInput = "päss-test-only".toCharArray()
        val basic = GateCredential.basic(username, basicInput)
        basicInput.fill('\u0000')
        val expectedBasic = "Basic " + java.util.Base64.getEncoder().encodeToString(
            "$username:päss-test-only".encodeToByteArray(),
        )
        assertEquals(expectedBasic, basic.authorizationHeader())

        val bearerInput = "API_test-only-copy".toCharArray()
        val bearer = GateCredential.bearer(bearerInput)
        bearerInput.fill('\u0000')
        assertEquals("Bearer API_test-only-copy", bearer.authorizationHeader())

        basic.close()
        bearer.close()
    }

    @Test
    fun closingAJmapClientClosesItsPrivateCredentialCopyAndCachedSession() =
        runBlocking {
        val input = "app_test-only-close-marker".toCharArray()
        val credential = GateCredential.basic(
            username = GateBootstrap.FIRST_USER_ADDRESS,
            secret = input,
        )
        input.fill('\u0000')
        val client = GateJmapClient(
            baseUrl = URI("http://127.0.0.1:18443"),
            credential = credential,
            transport = QueueTransport(
                listOf(
                    GateHttpResponse(
                        status = 200,
                        effectiveUrl = URI(
                            "http://127.0.0.1:18443/.well-known/jmap",
                        ),
                        body = validSessionBody,
                    ),
                ),
            ),
        )

        assertFalse(credential.authorizationHeader().contains("close-marker"))
        client.discoverSession()
        client.close()
        client.close()

        assertFailsWith<IllegalStateException> {
            credential.authorizationHeader()
        }
        assertFailsWith<IllegalStateException> {
            client.discoverSession()
        }
        Unit
    }

    @Test
    fun invalidJmapClientConstructionClosesTheTransferredCredential() {
        val credential = GateCredential.bearer("API_constructor-marker".toCharArray())

        assertFailsWith<IllegalArgumentException> {
            GateJmapClient(
                baseUrl = URI("http://localhost:18443"),
                credential = credential,
                transport = QueueTransport(emptyList()),
            )
        }

        assertFailsWith<IllegalStateException> {
            credential.authorizationHeader()
        }
    }

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
                clientWithSession(body).use { client ->
                    client.discoverSession()
                }
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
                ).use { client ->
                    client.registryGet("Account")
                }
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
            ).use { client ->
                client.registryGet("Account")
            }
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
                ).use { client ->
                    client.discoverSession()
                }
            }

            assertEquals(GateJmapFailure.InvalidResponse, failure.kind)
            assertFalse(failure.message.orEmpty().contains(advertised))
        }
    }

    @Test
    fun mailMethodUsesOnlyTheExplicitAdvertisedCapabilities() = runBlocking {
        val transport = QueueTransport(
            responses = listOf(
                GateHttpResponse(
                    status = 200,
                    effectiveUrl = URI(
                        "http://127.0.0.1:18443/.well-known/jmap",
                    ),
                    body = validSessionBody,
                ),
                GateHttpResponse(
                    status = 200,
                    effectiveUrl = URI("http://127.0.0.1:18443/jmap/"),
                    body = """
                        {
                          "methodResponses":[
                            [
                              "Mailbox/get",
                              {
                                "accountId":"account7",
                                "state":"state-1",
                                "list":[],
                                "notFound":[]
                              },
                              "gate-1"
                            ]
                          ]
                        }
                    """.trimIndent(),
                ),
            ),
        )
        val client = GateJmapClient(
            baseUrl = URI("http://127.0.0.1:18443"),
            credential = GateCredential.basic(
                username = GateBootstrap.FIRST_USER_ADDRESS,
                secret = "app_test-only".toCharArray(),
            ),
            transport = transport,
        )

        client.use {
            it.call(
                methodName = "Mailbox/get",
                arguments = buildJsonObject {
                    put("accountId", "account7")
                },
                capabilities = listOf(
                    GateJmapCapability.CORE,
                    GateJmapCapability.MAIL,
                    GateJmapCapability.SUBMISSION,
                ),
            )
        }

        val request = transport.requests.last()
        val body = requireNotNull(request.body)
        assertEquals(
            listOf(
                "urn:ietf:params:jmap:core",
                "urn:ietf:params:jmap:mail",
                "urn:ietf:params:jmap:submission",
            ),
            body.getValue("using").jsonArray.map {
                it.jsonPrimitive.content
            },
        )
        val call = body.getValue("methodCalls")
            .jsonArray
            .single()
            .jsonArray
        assertEquals("Mailbox/get", call[0].jsonPrimitive.content)
        assertEquals("gate-1", call[2].jsonPrimitive.content)
        val arguments = call[1] as kotlinx.serialization.json.JsonObject
        assertEquals(setOf("accountId"), arguments.keys)
        assertEquals(
            "account7",
            arguments.getValue("accountId").jsonPrimitive.content,
        )
    }

    @Test
    fun registryQueryExplicitlyRequestsACompleteBoundedFirstPage() = runBlocking {
        val transport = QueueTransport(
            responses = listOf(
                GateHttpResponse(
                    status = 200,
                    effectiveUrl = URI(
                        "http://127.0.0.1:18443/.well-known/jmap",
                    ),
                    body = validSessionBody,
                ),
                GateHttpResponse(
                    status = 200,
                    effectiveUrl = URI("http://127.0.0.1:18443/jmap/"),
                    body = """
                        {
                          "methodResponses":[
                            [
                              "x:AppPassword/query",
                              {
                                "accountId":"account7",
                                "position":0,
                                "ids":[],
                                "total":0
                              },
                              "gate-1"
                            ]
                          ]
                        }
                    """.trimIndent(),
                ),
            ),
        )

        GateJmapClient(
            baseUrl = URI("http://127.0.0.1:18443"),
            credential = GateCredential.bearer("API_test-only".toCharArray()),
            transport = transport,
        ).use { client ->
            client.registryQuery(
                objectType = "AppPassword",
                accountId = "account7",
            )
        }

        val arguments = requireNotNull(
            transport.requests.last().body,
        ).getValue("methodCalls")
            .jsonArray
            .single()
            .jsonArray[1] as kotlinx.serialization.json.JsonObject
        assertEquals("true", arguments.getValue("calculateTotal").jsonPrimitive.content)
        assertEquals("0", arguments.getValue("position").jsonPrimitive.content)
        assertEquals("100", arguments.getValue("limit").jsonPrimitive.content)
    }

    @Test
    fun registryQueryRequestsTheExactNonzeroPage() = runBlocking {
        val transport = QueueTransport(
            responses = listOf(
                GateHttpResponse(
                    status = 200,
                    effectiveUrl = URI(
                        "http://127.0.0.1:18443/.well-known/jmap",
                    ),
                    body = validSessionBody,
                ),
                GateHttpResponse(
                    status = 200,
                    effectiveUrl = URI("http://127.0.0.1:18443/jmap/"),
                    body = """
                        {
                          "methodResponses":[
                            [
                              "x:Account/query",
                              {
                                "accountId":"account7",
                                "position":37,
                                "ids":[],
                                "total":60
                              },
                              "gate-1"
                            ]
                          ]
                        }
                    """.trimIndent(),
                ),
            ),
        )

        GateJmapClient(
            baseUrl = URI("http://127.0.0.1:18443"),
            credential = GateCredential.bearer("API_test-only".toCharArray()),
            transport = transport,
        ).use { client ->
            client.registryQuery(
                objectType = "Account",
                accountId = "account7",
                position = 37,
                limit = 23,
            )
        }

        assertEquals(
            Json.parseToJsonElement(
                """
                    {
                      "using":[
                        "urn:ietf:params:jmap:core",
                        "urn:stalwart:jmap"
                      ],
                      "methodCalls":[
                        [
                          "x:Account/query",
                          {
                            "accountId":"account7",
                            "filter":{},
                            "sort":[],
                            "position":37,
                            "limit":23,
                            "calculateTotal":true
                          },
                          "gate-1"
                        ]
                      ]
                    }
                """.trimIndent(),
            ).jsonObject,
            transport.requests.last().body,
        )
    }

    @Test
    fun registryQueryRejectsInvalidPageBoundsBeforeTransport() = runBlocking {
        listOf(
            -1 to 1,
            0 to 0,
            0 to 101,
        ).forEach { (position, limit) ->
            val transport = QueueTransport(emptyList())
            val client = GateJmapClient(
                baseUrl = URI("http://127.0.0.1:18443"),
                credential = GateCredential.bearer(
                    "API_test-only".toCharArray(),
                ),
                transport = transport,
            )

            client.use {
                assertFailsWith<IllegalArgumentException> {
                    it.registryQuery(
                        objectType = "Account",
                        position = position,
                        limit = limit,
                    )
                }
            }
            assertEquals(emptyList(), transport.requests)
        }
    }

    @Test
    fun jmapMethodResponseMustRemainOnThePinnedApiEndpoint() = runBlocking {
        val transport = QueueTransport(
            responses = listOf(
                GateHttpResponse(
                    status = 200,
                    effectiveUrl = URI(
                        "http://127.0.0.1:18443/.well-known/jmap",
                    ),
                    body = validSessionBody,
                ),
                GateHttpResponse(
                    status = 200,
                    effectiveUrl = URI(
                        "http://127.0.0.1:18443/redirected",
                    ),
                    body = """
                        {
                          "methodResponses":[
                            ["x:Account/get",{"list":[],"notFound":[]},"gate-1"]
                          ]
                        }
                    """.trimIndent(),
                ),
            ),
        )
        val client = GateJmapClient(
            baseUrl = URI("http://127.0.0.1:18443"),
            credential = GateCredential.bearer(
                "API_test-only".toCharArray(),
            ),
            transport = transport,
        )

        val failure = client.use {
            assertFailsWith<GateJmapException> {
                it.registryGet("Account")
            }
        }

        assertEquals(GateJmapFailure.InvalidResponse, failure.kind)
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
        val requests = mutableListOf<GateHttpRequest>()

        override suspend fun execute(request: GateHttpRequest): GateHttpResponse {
            requests += request
            return responses.removeFirst()
        }
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
