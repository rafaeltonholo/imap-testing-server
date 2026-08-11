package mail.sandbox.dashboard.server.local

import java.net.URI
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import mail.sandbox.dashboard.contract.AdoptPasswordRequest
import mail.sandbox.dashboard.contract.AuthenticationProbeRequest
import mail.sandbox.dashboard.contract.AuthenticationProtocol
import mail.sandbox.dashboard.contract.CredentialReadiness
import mail.sandbox.dashboard.contract.GenerateMessageRequest
import mail.sandbox.dashboard.contract.MailProtocol
import mail.sandbox.dashboard.contract.MessageDeliveryMode
import mail.sandbox.dashboard.contract.MessageSourceType
import mail.sandbox.dashboard.contract.Provider
import mail.sandbox.dashboard.contract.ProviderAvailability
import mail.sandbox.dashboard.server.gate.stalwart.GateCredential
import mail.sandbox.dashboard.server.gate.stalwart.GateHttpRequest
import mail.sandbox.dashboard.server.gate.stalwart.GateHttpResponse
import mail.sandbox.dashboard.server.gate.stalwart.GateHttpTransport
import mail.sandbox.dashboard.server.provider.stalwart.product.StalwartManagementCredentialProvider
import mail.sandbox.dashboard.server.provider.stalwart.product.StalwartProductAdapter

class StalwartDashboardProviderTest {
    @Test
    fun staleProviderIdentityStopsDeleteResetAndMailActionsBeforeMutation() = runBlocking {
        repeat(3) { actionIndex ->
            val transport = ArrivalTransport(*accountListingCalls("current-account"))
            val directory = createTempDirectory("stalwart-dashboard-stale-$actionIndex").toRealPath()
            try {
                val catalog = LocalAccountCatalog(directory.resolve("accounts.json"))
                val provider = StalwartDashboardProvider(
                    adapter = StalwartProductAdapter(
                        baseUri = BASE_URI,
                        managementCredentialProvider = StalwartManagementCredentialProvider {
                            GateCredential.basic(
                                "manager@local.test",
                                "management".toCharArray(),
                            )
                        },
                        accountCredentialCatalog = LocalStalwartCredentialCatalog(catalog),
                        transport = transport,
                    ),
                    catalog = catalog,
                )

                assertFailsWith<mail.sandbox.dashboard.server.api.DashboardNotFoundException> {
                    when (actionIndex) {
                        0 -> provider.deleteAccount("alice@local.test", "stale-account")
                        1 -> provider.changePassword(
                            "alice@local.test",
                            "replacement-password",
                            "stale-account",
                        )
                        else -> provider.mutateMessages(
                            "alice@local.test",
                            mail.sandbox.dashboard.contract.MutateMessagesRequest(
                                account = "alice@local.test",
                                provider = Provider.STALWART,
                                providerAccountId = "stale-account",
                                messageIds = listOf("message-one"),
                                mutationStates = mapOf("message-one" to "state-one"),
                                action = mail.sandbox.dashboard.contract.MessageAction.MARK_READ,
                                sourceFolderId = "inbox",
                            ),
                        )
                    }
                }
                transport.assertExhausted()
                provider.close()
            } finally {
                directory.toFile().deleteRecursively()
            }
        }
    }

    @Test
    fun liveUnknownPasswordAccountKeepsLiveIdentityAndCapabilitiesWithHonestReadiness() =
        runBlocking {
            val transport = ArrivalTransport(
                *accountListingCalls("c"),
                *accountListingCalls("c"),
                *accountListingCalls("c"),
            )
            val directory = createTempDirectory("stalwart-dashboard-readiness").toRealPath()
            try {
                val catalog = LocalAccountCatalog(directory.resolve("accounts.json"))
                catalog.put(
                    LocalAccountRecord(
                        provider = Provider.STALWART,
                        address = "stale-address@local.test",
                        password = null,
                        protocols = listOf(MailProtocol.JMAP),
                        providerAccountId = "c",
                    ),
                )
                val provider = StalwartDashboardProvider(
                    adapter = StalwartProductAdapter(
                        baseUri = BASE_URI,
                        managementCredentialProvider = StalwartManagementCredentialProvider {
                            GateCredential.basic(
                                "manager@local.test",
                                "management".toCharArray(),
                            )
                        },
                        accountCredentialCatalog = LocalStalwartCredentialCatalog(catalog),
                        transport = transport,
                    ),
                    catalog = catalog,
                )

                val account = provider.listAccounts().single()

                assertEquals("alice@local.test", account.address)
                assertEquals("c", account.providerAccountId)
                assertEquals(listOf(MailProtocol.JMAP, MailProtocol.SMTP), account.protocols)
                assertEquals(CredentialReadiness.PROVIDER_UNAVAILABLE, account.credentialReadiness)
                assertTrue(account.readinessMessage?.isNotBlank() == true)
                assertEquals(ProviderAvailability.DEGRADED, provider.providerStatus().availability)

                val adoption = provider.adoptPassword(
                    account.address,
                    AdoptPasswordRequest("supplied-password"),
                    "c",
                )
                assertTrue(!adoption.operation.success)
                assertEquals(CredentialReadiness.PROVIDER_UNAVAILABLE, adoption.readiness)
                assertTrue(
                    !provider.probeAuthentication(
                        AuthenticationProbeRequest(
                            address = account.address,
                            provider = Provider.STALWART,
                            protocol = AuthenticationProtocol.JMAP,
                            credentialOverride = "supplied-password",
                            providerAccountId = "c",
                        ),
                    ).response.success,
                )
                assertEquals(null, catalog.findByProviderAccountId(Provider.STALWART, "c")?.password)
                transport.assertExhausted()
                provider.close()
            } finally {
                directory.toFile().deleteRecursively()
            }
        }

    @Test
    fun logSelectorCarriesTheCanonicalAddressAndProviderAccountId() = runBlocking {
        val transport = ArrivalTransport(
            ExpectedJmapCall("x:Account/query", query("management-account", listOf("c"))),
            ExpectedJmapCall(
                "x:Account/get",
                get(
                    "management-account",
                    buildJsonObject {
                        put("id", "c")
                        put("@type", "User")
                        put("name", "alice")
                        put("domainId", "domain-one")
                        put("permissions", buildJsonObject { put("@type", "Inherit") })
                    },
                ),
            ),
            ExpectedJmapCall(
                "x:Domain/get",
                get(
                    "management-account",
                    buildJsonObject {
                        put("id", "domain-one")
                        put("name", "local.test")
                    },
                ),
            ),
        )
        val directory = createTempDirectory("stalwart-dashboard-log-selector").toRealPath()
        try {
            val catalog = LocalAccountCatalog(directory.resolve("accounts.json"))
            val provider = StalwartDashboardProvider(
                adapter = StalwartProductAdapter(
                    baseUri = BASE_URI,
                    managementCredentialProvider = StalwartManagementCredentialProvider {
                        GateCredential.basic("manager@local.test", "management".toCharArray())
                    },
                    accountCredentialCatalog = LocalStalwartCredentialCatalog(catalog),
                    transport = transport,
                ),
                catalog = catalog,
            )

            assertEquals(
                DashboardLogAccount("alice@local.test", providerAccountId = "c"),
                provider.dashboardLogAccount("ALICE@LOCAL.TEST", "c"),
            )
            transport.assertExhausted()
            provider.close()
        } finally {
            directory.toFile().deleteRecursively()
        }
    }

    @Test
    fun expectedMessageIdDoesNotFallBackToAnUnrelatedSingletonArrival() = runBlocking {
        val raw = message("<dashboard-correlated@local.test>")
        val transport = ArrivalTransport(
            ExpectedJmapCall("x:Account/query", query("management-account", listOf("account-one"))),
            ExpectedJmapCall(
                "x:Account/get",
                get(
                    "management-account",
                    buildJsonObject {
                        put("id", "account-one")
                        put("@type", "User")
                        put("name", "alice")
                        put("domainId", "domain-one")
                        put("permissions", buildJsonObject { put("@type", "Inherit") })
                    },
                ),
            ),
            ExpectedJmapCall(
                "x:Domain/get",
                get(
                    "management-account",
                    buildJsonObject {
                        put("id", "domain-one")
                        put("name", "local.test")
                    },
                ),
            ),
            ExpectedJmapCall("Mailbox/get", mailboxPayload()),
            ExpectedJmapCall("Email/query", emailQuery(emptyList())),
            ExpectedJmapCall(
                "Email/query",
                emailQuery(listOf("unrelated")),
            ),
            ExpectedJmapCall(
                "Email/get",
                emailGet(
                    summary("unrelated", "<unrelated-concurrent@local.test>"),
                ),
            ),
            ExpectedJmapCall(
                "Email/query",
                emailQuery(listOf("unrelated", "expected")),
            ),
            ExpectedJmapCall(
                "Email/get",
                emailGet(
                    summary("unrelated", "<unrelated-concurrent@local.test>"),
                    summary("expected", "<dashboard-correlated@local.test>"),
                ),
            ),
        )
        val smtp = StalwartRecordingSmtpSender()
        val directory = createTempDirectory("stalwart-dashboard-arrival").toRealPath()
        try {
            val catalog = LocalAccountCatalog(directory.resolve("accounts.json"))
            catalog.put(
                LocalAccountRecord(
                    provider = Provider.STALWART,
                    address = "alice@local.test",
                    password = "password",
                    protocols = listOf(MailProtocol.JMAP, MailProtocol.SMTP),
                    providerAccountId = "account-one",
                ),
            )
            val adapter = StalwartProductAdapter(
                baseUri = BASE_URI,
                managementCredentialProvider = StalwartManagementCredentialProvider {
                    GateCredential.basic("manager@local.test", "management".toCharArray())
                },
                accountCredentialCatalog = LocalStalwartCredentialCatalog(catalog),
                transport = transport,
            )
            val provider = StalwartDashboardProvider(
                adapter = adapter,
                catalog = catalog,
                smtpSender = smtp,
            )

            val ids = provider.deliverMessages(
                GenerateMessageRequest(
                    targetAccount = "alice@local.test",
                    provider = Provider.STALWART,
                    providerAccountId = "account-one",
                    sourceType = MessageSourceType.EML,
                    deliveryMode = MessageDeliveryMode.SMTP_DELIVERY,
                    content = raw,
                ),
                listOf(GeneratedMessage(raw)),
            )

            assertEquals(listOf("expected"), ids)
            assertEquals(1, smtp.calls)
            transport.assertExhausted()
            provider.close()
        } finally {
            directory.toFile().deleteRecursively()
        }
    }

    @Test
    fun smtpDeliveryRequiresCredentialForTheExactLiveProviderIdentity() = runBlocking {
        val transport = ArrivalTransport(*accountListingCalls("current-account"))
        val smtp = StalwartRecordingSmtpSender()
        val directory = createTempDirectory("stalwart-dashboard-smtp-identity").toRealPath()
        try {
            val catalog = LocalAccountCatalog(directory.resolve("accounts.json"))
            catalog.put(
                LocalAccountRecord(
                    provider = Provider.STALWART,
                    address = "alice@local.test",
                    password = "stale-password",
                    protocols = listOf(MailProtocol.JMAP, MailProtocol.SMTP),
                    providerAccountId = "stale-account",
                ),
            )
            val provider = StalwartDashboardProvider(
                adapter = StalwartProductAdapter(
                    baseUri = BASE_URI,
                    managementCredentialProvider = StalwartManagementCredentialProvider {
                        GateCredential.basic("manager@local.test", "management".toCharArray())
                    },
                    accountCredentialCatalog = LocalStalwartCredentialCatalog(catalog),
                    transport = transport,
                ),
                catalog = catalog,
                smtpSender = smtp,
            )
            val raw = message("<smtp-identity@local.test>")

            assertFailsWith<NoSuchElementException> {
                provider.deliverMessages(
                    GenerateMessageRequest(
                        targetAccount = "alice@local.test",
                        provider = Provider.STALWART,
                        providerAccountId = "current-account",
                        sourceType = MessageSourceType.EML,
                        deliveryMode = MessageDeliveryMode.SMTP_DELIVERY,
                        content = raw,
                    ),
                    listOf(GeneratedMessage(raw)),
                )
            }

            assertEquals(0, smtp.calls)
            transport.assertExhausted()
            provider.close()
        } finally {
            directory.toFile().deleteRecursively()
        }
    }

    private fun message(messageId: String): String =
        "From: sender@local.test\r\n" +
            "To: alice@local.test\r\n" +
            "Date: Wed, 05 Aug 2026 12:00:00 +0000\r\n" +
            "Subject: Correlated fixture\r\n" +
            "Message-ID: $messageId\r\n" +
            "\r\n" +
            "body"

    private companion object {
        val BASE_URI: URI = URI("http://127.0.0.1:18443")
        fun query(accountId: String, ids: List<String>): JsonObject = buildJsonObject {
            put("accountId", accountId)
            put("queryState", "query-state")
            put("canCalculateChanges", true)
            put("position", 0)
            put("ids", JsonArray(ids.map(::JsonPrimitive)))
            put("total", ids.size)
        }

        fun get(accountId: String, vararg values: JsonObject): JsonObject = buildJsonObject {
            put("accountId", accountId)
            put("state", "state")
            put("list", JsonArray(values.toList()))
            put("notFound", buildJsonArray {})
        }

        fun mailboxPayload(): JsonObject = get(
            "account-one",
            buildJsonObject {
                put("id", "inbox")
                put("name", "Inbox")
                put("role", "inbox")
                put("parentId", JsonNull)
                put("totalEmails", 0)
                put("unreadEmails", 0)
            },
        )

        fun emailQuery(ids: List<String>): JsonObject = query("account-one", ids)

        fun emailGet(vararg values: JsonObject): JsonObject = get("account-one", *values)

        fun summary(id: String, messageId: String): JsonObject = buildJsonObject {
            put("id", id)
            put("subject", "Concurrent message")
            put("from", buildJsonArray {})
            put("receivedAt", "2026-08-05T12:00:00Z")
            put("preview", "body")
            put("mailboxIds", buildJsonObject { put("inbox", true) })
            put("keywords", buildJsonObject {})
            put("messageId", buildJsonArray { add(JsonPrimitive(messageId)) })
        }

        fun accountListingCalls(accountId: String): Array<ExpectedJmapCall> = arrayOf(
            ExpectedJmapCall(
                "x:Account/query",
                query("management-account", listOf(accountId)),
            ),
            ExpectedJmapCall(
                "x:Account/get",
                get(
                    "management-account",
                    buildJsonObject {
                        put("id", accountId)
                        put("@type", "User")
                        put("name", "alice")
                        put("domainId", "domain-one")
                        put("permissions", buildJsonObject { put("@type", "Inherit") })
                    },
                ),
            ),
            ExpectedJmapCall(
                "x:Domain/get",
                get(
                    "management-account",
                    buildJsonObject {
                        put("id", "domain-one")
                        put("name", "local.test")
                    },
                ),
            ),
        )
    }
}

private data class ExpectedJmapCall(
    val method: String,
    val payload: JsonObject,
)

private class ArrivalTransport(
    vararg expectedCalls: ExpectedJmapCall,
) : GateHttpTransport {
    private val remaining = ArrayDeque(expectedCalls.toList())

    override suspend fun execute(request: GateHttpRequest): GateHttpResponse {
        if (request.method == "GET") {
            val accountId = if (request.credential.basicUsername == "manager@local.test") {
                "management-account"
            } else {
                "account-one"
            }
            return GateHttpResponse(
                status = 200,
                effectiveUrl = request.url,
                body = buildJsonObject {
                    put("apiUrl", "http://127.0.0.1:18443/jmap/")
                    put("username", request.credential.basicUsername.orEmpty())
                    put(
                        "primaryAccounts",
                        buildJsonObject { put("urn:stalwart:jmap", accountId) },
                    )
                }.toString(),
            )
        }
        val expected = remaining.removeFirstOrNull()
            ?: error("Unexpected JMAP request: ${request.body}")
        val call = requireNotNull(request.body)["methodCalls"]
            ?.jsonArray
            ?.single()
            ?.jsonArray
            ?: error("JMAP request omitted its method call")
        assertEquals(expected.method, call[0].jsonPrimitive.content)
        return GateHttpResponse(
            status = 200,
            effectiveUrl = request.url,
            body = buildJsonObject {
                put(
                    "methodResponses",
                    buildJsonArray {
                        add(
                            buildJsonArray {
                                add(JsonPrimitive(expected.method))
                                add(expected.payload)
                                add(call[2])
                            },
                        )
                    },
                )
            }.toString(),
        )
    }

    fun assertExhausted() {
        assertTrue(remaining.isEmpty(), "Unconsumed JMAP calls: $remaining")
    }
}

private class StalwartRecordingSmtpSender : LocalSmtpSender {
    var calls: Int = 0
        private set

    override fun send(
        envelopeFrom: String,
        envelopeRecipient: String,
        rawMessage: String,
        credentials: LocalSmtpCredentials?,
    ): LocalSmtpSendResult {
        calls += 1
        return LocalSmtpSendResult(250, "accepted", null)
    }
}
