package mail.sandbox.dashboard.server.local

import java.net.URI
import java.nio.file.Files
import java.nio.file.Path
import java.time.Instant
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
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
import mail.sandbox.dashboard.contract.CreateAccountRequest
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
import mail.sandbox.dashboard.server.provider.AuthenticationOutcome
import mail.sandbox.dashboard.server.provider.stalwart.product.StalwartCreateAccount
import mail.sandbox.dashboard.server.provider.stalwart.product.StalwartImportedEmail
import mail.sandbox.dashboard.server.provider.stalwart.product.StalwartManagementCredentialProvider
import mail.sandbox.dashboard.server.provider.stalwart.product.StalwartProductAccount
import mail.sandbox.dashboard.server.provider.stalwart.product.StalwartProductAdapter
import mail.sandbox.dashboard.server.provider.stalwart.product.StalwartProductFolder
import mail.sandbox.dashboard.server.provider.stalwart.product.StalwartProductGateway
import mail.sandbox.dashboard.server.provider.stalwart.product.StalwartProductMessage
import mail.sandbox.dashboard.server.provider.stalwart.product.StalwartProductMessageSummary
import mail.sandbox.dashboard.server.provider.stalwart.product.StalwartProductProtocol

class StalwartDashboardProviderTest {
    @Test
    fun liveRegistryStaysCompleteAndOverlaysReadinessByExactProviderId() = runBlocking {
        withCatalog("stalwart-dashboard-live-overlay") { catalog ->
            catalog.put(
                LocalAccountRecord(
                    provider = Provider.STALWART,
                    address = "alpha@local.test",
                    password = "alpha-password",
                    protocols = listOf(MailProtocol.JMAP),
                    providerAccountId = "account-a",
                ),
            )
            val gateway = RecordingStalwartGateway(
                StalwartProductAccount(
                    "account-a",
                    "alpha@local.test",
                    setOf(StalwartProductProtocol.JMAP),
                ),
                StalwartProductAccount(
                    "account-b",
                    "beta@local.test",
                    setOf(StalwartProductProtocol.JMAP, StalwartProductProtocol.SMTP),
                ),
            ).apply {
                jmapOutcomes += AuthenticationOutcome.Authenticated("JMAP login succeeded")
            }
            val provider = StalwartDashboardProvider(gateway, catalog)

            val accounts = provider.listAccounts()

            assertEquals(listOf("account-a", "account-b"), accounts.map { it.providerAccountId })
            assertEquals(
                listOf(CredentialReadiness.READY, CredentialReadiness.PASSWORD_REQUIRED),
                accounts.map { it.credentialReadiness },
            )
            assertEquals(
                listOf(
                    listOf(MailProtocol.JMAP),
                    listOf(MailProtocol.JMAP, MailProtocol.SMTP),
                ),
                accounts.map { it.protocols },
            )
            assertEquals(
                listOf(StalwartLoginProbe("account-a", "alpha@local.test", "alpha-password")),
                gateway.jmapProbes,
            )
            assertEquals(ProviderAvailability.READY, provider.providerStatus().availability)

            assertFailsWith<IllegalStateException> {
                provider.listFolders("beta@local.test", "account-b")
            }
            assertEquals(1, gateway.accountListingCalls)
            assertEquals(0, gateway.folderListingCalls)
        }
    }

    @Test
    fun sameAddressOldIdPasswordIsNeverInheritedByARecreatedAccount() = runBlocking {
        withCatalog("stalwart-dashboard-recreated-account") { catalog ->
            catalog.put(
                LocalAccountRecord(
                    provider = Provider.STALWART,
                    address = "alice@local.test",
                    password = "old-password",
                    protocols = listOf(MailProtocol.JMAP, MailProtocol.SMTP),
                    providerAccountId = "old-account",
                ),
            )
            val gateway = RecordingStalwartGateway(
                StalwartProductAccount(
                    "new-account",
                    "alice@local.test",
                    setOf(StalwartProductProtocol.JMAP, StalwartProductProtocol.SMTP),
                ),
            )
            val provider = StalwartDashboardProvider(gateway, catalog)

            val account = provider.listAccounts().single()

            assertEquals("new-account", account.providerAccountId)
            assertEquals(CredentialReadiness.PASSWORD_REQUIRED, account.credentialReadiness)
            assertTrue(gateway.jmapProbes.isEmpty())
            assertFailsWith<IllegalStateException> {
                provider.listFolders("alice@local.test", "new-account")
            }
            assertEquals(1, gateway.accountListingCalls)
            assertEquals(0, gateway.folderListingCalls)
        }
    }

    @Test
    fun adoptionStoresOnlyAnExactLoginThatPassedOrdinaryJmapAuthentication() = runBlocking {
        withCatalog("stalwart-dashboard-adoption") { catalog ->
            catalog.put(
                LocalAccountRecord(
                    provider = Provider.STALWART,
                    address = "alice@local.test",
                    password = null,
                    protocols = listOf(MailProtocol.JMAP, MailProtocol.SMTP),
                    providerAccountId = "account-one",
                ),
            )
            val gateway = RecordingStalwartGateway(ordinaryAccount()).apply {
                jmapOutcomes += AuthenticationOutcome.WrongPassword("JMAP rejected credentials")
                jmapOutcomes += AuthenticationOutcome.Authenticated("JMAP login succeeded")
                beforeJmapProbe = {
                    assertNull(
                        catalog.findByProviderAccountId(Provider.STALWART, "account-one")?.password,
                    )
                }
            }
            val provider = StalwartDashboardProvider(gateway, catalog)

            val rejected = provider.adoptPassword(
                "alice@local.test",
                AdoptPasswordRequest("wrong-password"),
                "account-one",
            )
            assertFalse(rejected.operation.success)
            assertEquals(CredentialReadiness.AUTHENTICATION_FAILED, rejected.readiness)
            assertNull(
                catalog.findByProviderAccountId(Provider.STALWART, "account-one")?.password,
            )

            val accepted = provider.adoptPassword(
                "alice@local.test",
                AdoptPasswordRequest("right-password"),
                "account-one",
            )
            assertTrue(accepted.operation.success)
            assertEquals(CredentialReadiness.READY, accepted.readiness)
            assertEquals(
                "right-password",
                catalog.findByProviderAccountId(Provider.STALWART, "account-one")?.password,
            )
            assertEquals(
                listOf("wrong-password", "right-password"),
                gateway.jmapProbes.map(StalwartLoginProbe::password),
            )
        }
    }

    @Test
    fun resetWorksWithoutACachedPasswordAndPersistsOnlyAfterOrdinaryLogin() = runBlocking {
        withCatalog("stalwart-dashboard-reset") { catalog ->
            val gateway = RecordingStalwartGateway(ordinaryAccount()).apply {
                jmapOutcomes += AuthenticationOutcome.Authenticated("JMAP login succeeded")
                beforeJmapProbe = {
                    assertNull(
                        catalog.findByProviderAccountId(Provider.STALWART, "account-one"),
                    )
                }
            }
            val provider = StalwartDashboardProvider(gateway, catalog)

            val response = provider.changePassword(
                "alice@local.test",
                "replacement-password",
                "account-one",
            )

            assertTrue(response.operation.success)
            assertEquals(CredentialReadiness.READY, response.readiness)
            assertEquals(
                listOf("account-one" to "replacement-password"),
                gateway.changedPasswords,
            )
            assertEquals(
                "replacement-password",
                catalog.findByProviderAccountId(Provider.STALWART, "account-one")?.password,
            )
        }
    }

    @Test
    fun failedPostResetAuthenticationForgetsTheObsoletePassword() = runBlocking {
        withCatalog("stalwart-dashboard-reset-failure") { catalog ->
            catalog.put(
                LocalAccountRecord(
                    provider = Provider.STALWART,
                    address = "alice@local.test",
                    password = "old-password",
                    protocols = listOf(MailProtocol.JMAP, MailProtocol.SMTP),
                    providerAccountId = "account-one",
                ),
            )
            val gateway = RecordingStalwartGateway(ordinaryAccount()).apply {
                jmapOutcomes += AuthenticationOutcome.WrongPassword("JMAP rejected credentials")
            }
            val provider = StalwartDashboardProvider(gateway, catalog)

            val response = provider.changePassword(
                "alice@local.test",
                "replacement-password",
                "account-one",
            )

            assertFalse(response.operation.success)
            assertEquals(CredentialReadiness.AUTHENTICATION_FAILED, response.readiness)
            assertNull(
                catalog.findByProviderAccountId(Provider.STALWART, "account-one")?.password,
            )
        }
    }

    @Test
    fun explicitJmapAndSmtpProbesUseRememberedOrOverrideSecretsWithoutChangingTheCatalog() =
        runBlocking {
            withCatalog("stalwart-dashboard-explicit-probes") { catalog ->
                catalog.put(
                    LocalAccountRecord(
                        provider = Provider.STALWART,
                        address = "alice@local.test",
                        password = "remembered-password",
                        protocols = listOf(MailProtocol.JMAP, MailProtocol.SMTP),
                        providerAccountId = "account-one",
                    ),
                )
                val gateway = RecordingStalwartGateway(ordinaryAccount()).apply {
                    jmapOutcomes += AuthenticationOutcome.Authenticated("JMAP login succeeded")
                }
                val smtpProbe = RecordingStalwartSmtpProbe().apply {
                    outcomes += AuthenticationOutcome.WrongPassword(
                        "override-password\n" + "provider-detail".repeat(80),
                    )
                }
                val provider = StalwartDashboardProvider(
                    adapter = gateway,
                    catalog = catalog,
                    smtpAuthenticationProbe = smtpProbe,
                )

                val jmap = provider.probeAuthentication(
                    AuthenticationProbeRequest(
                        address = "alice@local.test",
                        provider = Provider.STALWART,
                        protocol = AuthenticationProtocol.JMAP,
                        providerAccountId = "account-one",
                    ),
                )
                val smtp = provider.probeAuthentication(
                    AuthenticationProbeRequest(
                        address = "alice@local.test",
                        provider = Provider.STALWART,
                        protocol = AuthenticationProtocol.SMTP,
                        credentialOverride = "override-password",
                        providerAccountId = "account-one",
                    ),
                )

                assertTrue(jmap.response.success)
                assertFalse(smtp.response.success)
                assertTrue(smtp.response.providerResponse.length <= 512)
                assertTrue("override-password" !in smtp.response.providerResponse)
                assertEquals(listOf("override-password"), smtp.secretsToRedact)
                assertEquals(
                    listOf(
                        StalwartLoginProbe(
                            "account-one",
                            "alice@local.test",
                            "remembered-password",
                        ),
                    ),
                    gateway.jmapProbes,
                )
                assertEquals(
                    listOf("alice@local.test" to "override-password"),
                    smtpProbe.probes,
                )
                assertEquals(
                    "remembered-password",
                    catalog.findByProviderAccountId(Provider.STALWART, "account-one")?.password,
                )
            }
        }

    @Test
    fun accountCreationVerifiesAndStoresTheExactOrdinaryLogin() = runBlocking {
        withCatalog("stalwart-dashboard-create") { catalog ->
            val gateway = RecordingStalwartGateway().apply {
                createdAccount = ordinaryAccount()
                jmapOutcomes += AuthenticationOutcome.Authenticated("JMAP login succeeded")
                beforeJmapProbe = {
                    assertNull(
                        catalog.findByProviderAccountId(Provider.STALWART, "account-one")?.password,
                    )
                }
            }
            val provider = StalwartDashboardProvider(gateway, catalog)

            val account = provider.createAccount(
                CreateAccountRequest(
                    address = "alice@local.test",
                    password = "created-password",
                    provider = Provider.STALWART,
                    protocols = listOf(MailProtocol.JMAP, MailProtocol.SMTP),
                ),
            )

            assertEquals(CredentialReadiness.READY, account.credentialReadiness)
            assertEquals("account-one", account.providerAccountId)
            assertEquals(
                "created-password",
                catalog.findByProviderAccountId(Provider.STALWART, "account-one")?.password,
            )
        }
    }

    @Test
    fun normalConstructionHasNoGateFixtureRoutesOrCredentialLifecycle() {
        val source = dashboardRoot().resolve(
            "dashboard-server/src/mail/sandbox/dashboard/server/local/" +
                "StalwartDashboardProvider.kt",
        ).toFile().readText()

        assertTrue("http://127.0.0.1:8443" in source)
        assertTrue("dashboard-management@local.test" in source)
        assertTrue("secret" in source)
        listOf(
            "18443",
            "18587",
            "StalwartGateSecretFiles",
            "GateFixtureManagementCredentialProvider",
            "fixtureCredentialSource",
            "providerGeneration",
            "AppPassword",
        ).forEach { forbidden ->
            assertTrue(forbidden !in source, "Production Stalwart source retained $forbidden")
        }
    }

    @Test
    fun staleProviderIdentityStopsDeleteResetAndMailActionsBeforeMutation() = runBlocking {
        repeat(3) { actionIndex ->
            val transport = ArrivalTransport(
                *if (actionIndex < 2) accountListingCalls("current-account") else emptyArray(),
            )
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

                val action = suspend {
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
                if (actionIndex < 2) {
                    assertFailsWith<mail.sandbox.dashboard.server.api.DashboardNotFoundException> {
                        action()
                    }
                } else {
                    assertFailsWith<IllegalStateException> { action() }
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
                assertEquals(CredentialReadiness.PASSWORD_REQUIRED, account.credentialReadiness)
                assertEquals(null, account.readinessMessage)
                assertEquals(ProviderAvailability.READY, provider.providerStatus().availability)

                val adoption = provider.adoptPassword(
                    account.address,
                    AdoptPasswordRequest("supplied-password"),
                    "c",
                )
                assertTrue(!adoption.operation.success)
                assertEquals(CredentialReadiness.AUTHENTICATION_FAILED, adoption.readiness)
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
        val transport = ArrivalTransport()
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

            assertFailsWith<IllegalStateException> {
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

    private suspend fun withCatalog(
        prefix: String,
        block: suspend (LocalAccountCatalog) -> Unit,
    ) {
        val directory = createTempDirectory(prefix).toRealPath()
        try {
            block(LocalAccountCatalog(directory.resolve("accounts.json")))
        } finally {
            directory.toFile().deleteRecursively()
        }
    }

    private fun dashboardRoot(): Path {
        val working = Path.of(System.getProperty("user.dir")).toAbsolutePath().normalize()
        return when {
            Files.isDirectory(working.resolve("dashboard-server")) -> working
            working.fileName.toString() == "dashboard-server" &&
                Files.isDirectory(working.parent.resolve("dashboard-server")) -> working.parent
            Files.isDirectory(working.resolve("debug-dashboard/dashboard-server")) ->
                working.resolve("debug-dashboard")
            else -> error("Could not locate the debug-dashboard source tree from $working")
        }
    }

    private companion object {
        val BASE_URI: URI = URI("http://127.0.0.1:18443")

        fun ordinaryAccount(): StalwartProductAccount = StalwartProductAccount(
            id = "account-one",
            address = "alice@local.test",
            enabledProtocols = setOf(
                StalwartProductProtocol.JMAP,
                StalwartProductProtocol.SMTP,
            ),
        )

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

private data class StalwartLoginProbe(
    val accountId: String,
    val address: String,
    val password: String,
)

private class RecordingStalwartGateway(
    vararg initialAccounts: StalwartProductAccount,
) : StalwartProductGateway {
    private val accounts = initialAccounts.toMutableList()
    val jmapOutcomes = ArrayDeque<AuthenticationOutcome>()
    val jmapProbes = mutableListOf<StalwartLoginProbe>()
    val changedPasswords = mutableListOf<Pair<String, String>>()
    var beforeJmapProbe: (StalwartLoginProbe) -> Unit = {}
    var createdAccount: StalwartProductAccount? = null
    var accountListingCalls = 0
        private set
    var folderListingCalls = 0
        private set

    override suspend fun listAccounts(): List<StalwartProductAccount> {
        accountListingCalls += 1
        return accounts.toList()
    }

    override suspend fun createAccount(request: StalwartCreateAccount): StalwartProductAccount =
        requireNotNull(createdAccount) { "No created Account result was configured" }.also {
            accounts += it
        }

    override suspend fun probeOrdinaryLogin(
        accountId: String,
        address: String,
        password: String,
    ): AuthenticationOutcome {
        val probe = StalwartLoginProbe(accountId, address, password)
        beforeJmapProbe(probe)
        jmapProbes += probe
        return jmapOutcomes.removeFirstOrNull()
            ?: error("No ordinary JMAP outcome was configured")
    }

    override suspend fun changePassword(accountId: String, newPassword: String) {
        changedPasswords += accountId to newPassword
    }

    override suspend fun deleteAccount(accountId: String) {
        accounts.removeAll { it.id == accountId }
    }

    override suspend fun listFolders(accountId: String): List<StalwartProductFolder> {
        folderListingCalls += 1
        return emptyList()
    }

    override suspend fun createFolder(
        accountId: String,
        name: String,
        parentId: String?,
    ): StalwartProductFolder = error("Unexpected createFolder")

    override suspend fun deleteFolder(accountId: String, folderId: String) {
        error("Unexpected deleteFolder")
    }

    override suspend fun listMessages(
        accountId: String,
        mailboxId: String?,
        limit: Int,
    ): List<StalwartProductMessageSummary> = error("Unexpected listMessages")

    override suspend fun readMessage(
        accountId: String,
        emailId: String,
    ): StalwartProductMessage = error("Unexpected readMessage")

    override suspend fun importEml(
        accountId: String,
        mailboxId: String,
        rawEml: String,
        receivedAt: Instant,
    ): StalwartImportedEmail = error("Unexpected importEml")

    override suspend fun setSeen(
        accountId: String,
        emailIds: List<String>,
        expectedState: String,
        seen: Boolean,
    ) {
        error("Unexpected setSeen")
    }

    override suspend fun setFlagged(
        accountId: String,
        emailIds: List<String>,
        expectedState: String,
        flagged: Boolean,
    ) {
        error("Unexpected setFlagged")
    }

    override suspend fun moveMessages(
        accountId: String,
        emailIds: List<String>,
        expectedState: String,
        sourceMailboxId: String,
        targetMailboxId: String,
    ) {
        error("Unexpected moveMessages")
    }

    override suspend fun copyMessages(
        accountId: String,
        emailIds: List<String>,
        expectedState: String,
        targetMailboxId: String,
    ): List<String> = error("Unexpected copyMessages")

    override suspend fun trashMessages(
        accountId: String,
        emailIds: List<String>,
        expectedState: String,
        sourceMailboxId: String,
    ) {
        error("Unexpected trashMessages")
    }

    override suspend fun deleteMessages(
        accountId: String,
        emailIds: List<String>,
        expectedState: String,
    ) {
        error("Unexpected deleteMessages")
    }

    override fun close() = Unit
}

private class RecordingStalwartSmtpProbe : StalwartSmtpAuthenticationProbe {
    val outcomes = ArrayDeque<AuthenticationOutcome>()
    val probes = mutableListOf<Pair<String, String>>()

    override fun probe(address: String, password: String): AuthenticationOutcome {
        probes += address to password
        return outcomes.removeFirstOrNull() ?: error("No SMTP outcome was configured")
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
