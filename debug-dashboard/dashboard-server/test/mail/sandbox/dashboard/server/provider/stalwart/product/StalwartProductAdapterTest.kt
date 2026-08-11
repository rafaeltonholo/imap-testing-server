package mail.sandbox.dashboard.server.provider.stalwart.product

import java.net.URI
import java.time.Instant
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import mail.sandbox.dashboard.server.gate.stalwart.GateCredential
import mail.sandbox.dashboard.server.gate.stalwart.GateHttpRequest
import mail.sandbox.dashboard.server.gate.stalwart.GateHttpResponse
import mail.sandbox.dashboard.server.gate.stalwart.GateHttpTransport
import mail.sandbox.dashboard.server.provider.AuthenticationOutcome
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

class StalwartProductAdapterTest {
    @Test
    fun ordinaryLoginProbeAuthenticatesTheExactAccountWithoutPersistingThePassword() =
        runBlocking {
            val transport = RecordingTransport()
            val catalog = InMemoryStalwartAccountCredentialCatalog()
            val adapter = adapter(transport, catalog)

            val outcome = adapter.probeOrdinaryLogin(
                accountId = "account-one",
                address = "dev@local.test",
                password = "ordinary-password",
            )

            assertTrue(outcome is AuthenticationOutcome.Authenticated)
            assertEquals(
                listOf("dev@local.test" to "ordinary-password"),
                transport.sessionCredentials,
            )
            assertNull(catalog.find("account-one"))
            transport.assertExhausted()
        }

    @Test
    fun ordinaryLoginProbeReportsRejectedCredentialsWithoutLeakingOrPersistingThem() =
        runBlocking {
            val transport = RejectingSessionTransport(
                status = 401,
                responseBody = "ordinary-password must never be echoed",
            )
            val catalog = InMemoryStalwartAccountCredentialCatalog()
            val adapter = adapter(transport, catalog)

            val outcome = adapter.probeOrdinaryLogin(
                accountId = "account-one",
                address = "dev@local.test",
                password = "ordinary-password",
            )

            assertTrue(outcome is AuthenticationOutcome.WrongPassword)
            assertTrue("ordinary-password" !in outcome.diagnostic)
            assertTrue(outcome.diagnostic.length <= 512)
            assertNull(catalog.find("account-one"))
            assertEquals(1, transport.calls)
        }

    @Test
    fun ordinaryLoginProbeAttemptsAnExplicitEmptyPassword() = runBlocking {
        val transport = RecordingTransport()
        val catalog = InMemoryStalwartAccountCredentialCatalog()
        val adapter = adapter(transport, catalog)

        val outcome = adapter.probeOrdinaryLogin(
            accountId = "account-one",
            address = "dev@local.test",
            password = "",
        )

        assertTrue(outcome is AuthenticationOutcome.Authenticated)
        assertEquals(listOf("dev@local.test" to ""), transport.sessionCredentials)
        assertNull(catalog.find("account-one"))
        transport.assertExhausted()
    }

    @Test
    fun ordinaryLoginProbeRejectsAnotherPrimaryAccount() = runBlocking {
        val transport = RecordingTransport()
        val adapter = adapter(transport, InMemoryStalwartAccountCredentialCatalog())

        val outcome = adapter.probeOrdinaryLogin(
            accountId = "different-account",
            address = "dev@local.test",
            password = "ordinary-password",
        )

        assertTrue(outcome is AuthenticationOutcome.MissingAccount)
        assertTrue("ordinary-password" !in outcome.diagnostic)
        transport.assertExhausted()
    }

    @Test
    fun ordinaryLoginProbePropagatesParentTimeoutCancellation() = runBlocking {
        val transport = GateHttpTransport { awaitCancellation() }
        val adapter = adapter(transport, InMemoryStalwartAccountCredentialCatalog())

        assertFailsWith<TimeoutCancellationException> {
            withTimeout(25) {
                adapter.probeOrdinaryLogin(
                    accountId = "account-one",
                    address = "dev@local.test",
                    password = "ordinary-password",
                )
            }
        }
        Unit
    }

    @Test
    fun defaultConstructorOwnsTheKtorTransportWithoutOpeningANetworkSession() {
        StalwartProductAdapter(
            baseUri = BASE_URI,
            managementCredentialProvider = StalwartManagementCredentialProvider {
                GateCredential.basic("manager@local.test", "management".toCharArray())
            },
            accountCredentialCatalog = InMemoryStalwartAccountCredentialCatalog(),
        ).close()
    }

    @Test
    fun listAccountsDecodesRegistryAccountsAndDomains() = runBlocking {
        val transport = RecordingTransport(
            expectedCall(
                "x:Account/query",
                queryPayload(
                    "management-account",
                    listOf("management-account", "account-one"),
                ),
            ),
            expectedCall(
                "x:Account/get",
                getPayload(
                    "management-account",
                    accountObject(
                        id = "management-account",
                        localPart = "dashboard-management",
                        domainId = "domain-one",
                        permissions = buildJsonObject { put("@type", "Inherit") },
                    ),
                    accountObject(
                        id = "account-one",
                        localPart = "dev",
                        domainId = "domain-one",
                        permissions = buildJsonObject { put("@type", "Inherit") },
                    ),
                ),
            ) { arguments ->
                assertEquals(
                    listOf("management-account", "account-one"),
                    arguments.stringArray("ids"),
                )
            },
            expectedCall(
                "x:Domain/get",
                getPayload(
                    "management-account",
                    buildJsonObject {
                        put("id", "domain-one")
                        put("name", "local.test")
                    },
                ),
            ) { arguments ->
                assertEquals(listOf("domain-one"), arguments.stringArray("ids"))
            },
        )
        val catalog = InMemoryStalwartAccountCredentialCatalog()
        catalog.save(
            StalwartAccountLogin(
                accountId = "account-one",
                address = "stale-address@local.test",
                password = "cached-password",
            ),
        )
        val adapter = adapter(transport, catalog)

        assertEquals(
            listOf(
                StalwartProductAccount(
                    id = "account-one",
                    address = "dev@local.test",
                    enabledProtocols = setOf(
                        StalwartProductProtocol.JMAP,
                        StalwartProductProtocol.SMTP,
                    ),
                ),
            ),
            adapter.listAccounts(),
        )
        transport.assertExhausted()
    }

    @Test
    fun createAccountUsesDomainWithoutRememberingAnUnverifiedPassword() = runBlocking {
        val transport = RecordingTransport(
            expectedCall(
                "x:Domain/query",
                queryPayload("management-account", listOf("domain-one")),
            ),
            expectedCall(
                "x:Domain/get",
                getPayload(
                    "management-account",
                    buildJsonObject {
                        put("id", "domain-one")
                        put("name", "local.test")
                    },
                ),
            ),
            expectedCall(
                "x:Account/set",
                setCreatedPayload(
                    accountId = "management-account",
                    creationId = "dashboard-account",
                    objectId = "account-created",
                ),
            ) { arguments ->
                val create = arguments.requiredObject("create")
                    .requiredObject("dashboard-account")
                assertEquals("User", create.requiredString("@type"))
                assertEquals("new-user", create.requiredString("name"))
                assertEquals("domain-one", create.requiredString("domainId"))
                assertEquals(
                    "test-password",
                    create.requiredObject("credentials")
                        .requiredObject("0")
                        .requiredString("secret"),
                )
                val permissions = create.requiredObject("permissions")
                assertEquals("Replace", permissions.requiredString("@type"))
                val enabled = permissions.requiredObject("enabledPermissions")
                assertTrue(enabled["jmapEmailGet"]?.jsonPrimitive?.booleanOrNull == true)
                assertFalse("imapFetch" in enabled)
                assertTrue(enabled["emailSend"]?.jsonPrimitive?.booleanOrNull == true)
            },
        )
        val catalog = InMemoryStalwartAccountCredentialCatalog()
        val adapter = adapter(transport, catalog)

        assertEquals(
            StalwartProductAccount(
                id = "account-created",
                address = "new-user@local.test",
                enabledProtocols = setOf(StalwartProductProtocol.SMTP),
            ),
            adapter.createAccount(
                StalwartCreateAccount(
                    address = "new-user@local.test",
                    password = "test-password",
                    enabledProtocols = setOf(StalwartProductProtocol.SMTP),
                ),
            ),
        )
        assertNull(catalog.find("account-created"))
        transport.assertExhausted()
    }

    @Test
    fun createAccountRejectsNoncanonicalAddressAndUnsupportedPasswordBeforeNetwork() =
        runBlocking {
            val transport = RecordingTransport()
            val adapter = adapter(transport, InMemoryStalwartAccountCredentialCatalog())
            val protocols = setOf(StalwartProductProtocol.JMAP)

            assertFailsWith<IllegalArgumentException> {
                adapter.createAccount(
                    StalwartCreateAccount("Dev@local.test", "password", protocols),
                )
            }
            assertFailsWith<IllegalArgumentException> {
                adapter.createAccount(
                    StalwartCreateAccount("dev@local.test", "line\nbreak", protocols),
                )
            }

            transport.assertExhausted()
        }

    @Test
    fun changePasswordPatchesProviderWithoutRequiringOrRememberingACachedPassword() =
        runBlocking {
        val transport = RecordingTransport(
            expectedCall(
                "x:Account/get",
                getPayload(
                    "management-account",
                    accountObject(
                        id = "account-one",
                        localPart = "dev",
                        domainId = "domain-one",
                    ),
                ),
            ),
            expectedCall(
                "x:Account/set",
                setUpdatedPayload("management-account", "account-one"),
            ) { arguments ->
                assertEquals(
                    "new-password",
                    arguments.requiredObject("update")
                        .requiredObject("account-one")
                        .requiredString("credentials/0/secret"),
                )
            },
        )
        val catalog = InMemoryStalwartAccountCredentialCatalog()
        val adapter = adapter(transport, catalog)

        adapter.changePassword("account-one", "new-password")

        assertNull(catalog.find("account-one"))
        transport.assertExhausted()
    }

    @Test
    fun changePasswordRejectsUnsupportedPasswordBeforeNetwork() = runBlocking {
        val transport = RecordingTransport()
        val catalog = InMemoryStalwartAccountCredentialCatalog().also {
            it.save(StalwartAccountLogin("account-one", "dev@local.test", "old-password"))
        }
        val adapter = adapter(transport, catalog)

        assertFailsWith<IllegalArgumentException> {
            adapter.changePassword("account-one", "line\nbreak")
        }

        assertEquals("old-password", catalog.find("account-one")?.password)
        transport.assertExhausted()
    }

    @Test
    fun deleteAccountDestroysTheRegistryObjectAndForgetsItsLogin() = runBlocking {
        val transport = RecordingTransport(
            expectedCall(
                "x:Account/set",
                setDestroyedPayload("management-account", "account-one"),
            ) { arguments ->
                assertEquals(listOf("account-one"), arguments.stringArray("destroy"))
            },
        )
        val catalog = InMemoryStalwartAccountCredentialCatalog().also {
            it.save(StalwartAccountLogin("account-one", "dev@local.test", "password"))
        }
        val adapter = adapter(transport, catalog)

        adapter.deleteAccount("account-one")

        assertNull(catalog.find("account-one"))
        transport.assertExhausted()
    }

    @Test
    fun folderOperationsUseMailboxGetAndSet() = runBlocking {
        val transport = RecordingTransport(
            expectedCall(
                "Mailbox/get",
                buildJsonObject {
                    put("accountId", "account-one")
                    put("state", "mailboxes-1")
                    put(
                        "list",
                        buildJsonArray {
                            add(
                                buildJsonObject {
                                    put("id", "inbox")
                                    put("name", "Inbox")
                                    put("role", "inbox")
                                    put("parentId", JsonNull)
                                    put("totalEmails", 3)
                                    put("unreadEmails", 1)
                                },
                            )
                        },
                    )
                    put("notFound", buildJsonArray {})
                },
            ),
            expectedCall(
                "Mailbox/set",
                setCreatedPayload(
                    accountId = "account-one",
                    creationId = "dashboard-mailbox",
                    objectId = "folder-created",
                ),
            ) { arguments ->
                val create = arguments.requiredObject("create")
                    .requiredObject("dashboard-mailbox")
                assertEquals("Issues", create.requiredString("name"))
                assertEquals("inbox", create.requiredString("parentId"))
            },
            expectedCall(
                "Mailbox/set",
                setDestroyedPayload("account-one", "folder-created"),
            ),
        )
        val adapter = accountAdapter(transport)

        assertEquals(
            listOf(
                StalwartProductFolder(
                    id = "inbox",
                    name = "Inbox",
                    role = "inbox",
                    parentId = null,
                    totalEmails = 3,
                    unreadEmails = 1,
                ),
            ),
            adapter.listFolders("account-one"),
        )
        assertEquals(
            "folder-created",
            adapter.createFolder("account-one", "Issues", "inbox").id,
        )
        adapter.deleteFolder("account-one", "folder-created")
        transport.assertExhausted()
    }

    @Test
    fun messageListAndReadDecodeEmailQueryAndGet() = runBlocking {
        val transport = RecordingTransport(
            expectedCall(
                "Email/query",
                buildJsonObject {
                    put("accountId", "account-one")
                    put("queryState", "emails-1")
                    put("canCalculateChanges", true)
                    put("position", 0)
                    put("ids", buildJsonArray { add(JsonPrimitive("email-one")) })
                    put("total", 1)
                },
            ) { arguments ->
                assertEquals("inbox", arguments.requiredObject("filter").requiredString("inMailbox"))
                assertEquals(25, arguments.requiredInt("limit"))
            },
            expectedCall(
                "Email/get",
                emailGetPayload(summaryEmailObject()),
            ),
            expectedCall(
                "Email/get",
                emailGetPayload(fullEmailObject()),
            ) { arguments ->
                assertEquals(listOf("email-one"), arguments.stringArray("ids"))
                assertTrue(arguments.requiredBoolean("fetchTextBodyValues"))
            },
        )
        val adapter = accountAdapter(transport)

        assertEquals(
            listOf(
                StalwartProductMessageSummary(
                    id = "email-one",
                    state = "emails-1",
                    subject = "A test message",
                    sender = "Sender <sender@local.test>",
                    receivedAt = "2026-08-05T12:00:00Z",
                    preview = "Hello from the preview",
                    mailboxIds = setOf("inbox"),
                    seen = true,
                    flagged = false,
                ),
            ),
            adapter.listMessages("account-one", "inbox", 25),
        )
        assertEquals(
            StalwartProductMessage(
                summary = StalwartProductMessageSummary(
                    id = "email-one",
                    state = "emails-1",
                    subject = "A test message",
                    sender = "Sender <sender@local.test>",
                    receivedAt = "2026-08-05T12:00:00Z",
                    preview = "Hello from the preview",
                    mailboxIds = setOf("inbox"),
                    seen = true,
                    flagged = false,
                ),
                recipients = listOf("Dev <dev@local.test>"),
                textBody = "Hello from the body",
                htmlBody = null,
            ),
            adapter.readMessage("account-one", "email-one"),
        )
        transport.assertExhausted()
    }

    @Test
    fun messageListQueriesEveryPageBeyondTheJmapPageLimit() = runBlocking {
        val firstPage = (1..100).map { "email-$it" }
        val secondPage = (101..200).map { "email-$it" }
        val thirdPage = listOf("email-201")
        val allIds = firstPage + secondPage + thirdPage
        fun queryPage(position: Int, ids: List<String>): JsonObject = buildJsonObject {
            put("accountId", "account-one")
            put("queryState", "emails-1")
            put("canCalculateChanges", true)
            put("position", position)
            put("ids", JsonArray(ids.map(::JsonPrimitive)))
            put("total", allIds.size)
        }
        val transport = RecordingTransport(
            expectedCall("Email/query", queryPage(0, firstPage)) { arguments ->
                assertEquals(0, arguments.requiredInt("position"))
                assertEquals(100, arguments.requiredInt("limit"))
            },
            expectedCall("Email/query", queryPage(100, secondPage)) { arguments ->
                assertEquals(100, arguments.requiredInt("position"))
                assertEquals(100, arguments.requiredInt("limit"))
            },
            expectedCall("Email/query", queryPage(200, thirdPage)) { arguments ->
                assertEquals(200, arguments.requiredInt("position"))
                assertEquals(100, arguments.requiredInt("limit"))
            },
            expectedCall(
                "Email/get",
                buildJsonObject {
                    put("accountId", "account-one")
                    put("state", "emails-1")
                    put(
                        "list",
                        JsonArray(firstPage.map { id -> summaryEmailObject(id) }),
                    )
                    put("notFound", buildJsonArray {})
                },
            ) { arguments ->
                assertEquals(firstPage, arguments.stringArray("ids"))
            },
            expectedCall(
                "Email/get",
                buildJsonObject {
                    put("accountId", "account-one")
                    put("state", "emails-1")
                    put(
                        "list",
                        JsonArray(secondPage.map { id -> summaryEmailObject(id) }),
                    )
                    put("notFound", buildJsonArray {})
                },
            ) { arguments ->
                assertEquals(secondPage, arguments.stringArray("ids"))
            },
            expectedCall(
                "Email/get",
                buildJsonObject {
                    put("accountId", "account-one")
                    put("state", "emails-1")
                    put(
                        "list",
                        JsonArray(thirdPage.map { id -> summaryEmailObject(id) }),
                    )
                    put("notFound", buildJsonArray {})
                },
            ) { arguments ->
                assertEquals(thirdPage, arguments.stringArray("ids"))
            },
        )
        val adapter = accountAdapter(transport)

        assertEquals(allIds, adapter.listMessages("account-one", "inbox").map { it.id })
        transport.assertExhausted()
    }

    @Test
    fun messageListRejectsChangedQueryStateBeforeFetchingEmails() = runBlocking {
        fun queryPage(
            queryState: String,
            position: Int,
            ids: List<String>,
        ): JsonObject = buildJsonObject {
            put("accountId", "account-one")
            put("queryState", queryState)
            put("canCalculateChanges", true)
            put("position", position)
            put("ids", JsonArray(ids.map(::JsonPrimitive)))
            put("total", 3)
        }
        val transport = RecordingTransport(
            expectedCall("Email/query", queryPage("emails-1", 0, listOf("email-1", "email-2"))),
            expectedCall("Email/query", queryPage("emails-2", 2, listOf("email-3"))),
        )
        val adapter = accountAdapter(transport)

        val failure = assertFailsWith<StalwartProductException> {
            adapter.listMessages("account-one", "inbox", limit = 2)
        }

        assertEquals("Stalwart Email query changed during pagination", failure.message)
        transport.assertExhausted()
    }

    @Test
    fun messageListRejectsDuplicateIdsAcrossPagesBeforeFetchingEmails() = runBlocking {
        fun queryPage(position: Int, ids: List<String>): JsonObject = buildJsonObject {
            put("accountId", "account-one")
            put("queryState", "emails-1")
            put("canCalculateChanges", true)
            put("position", position)
            put("ids", JsonArray(ids.map(::JsonPrimitive)))
            put("total", 3)
        }
        val transport = RecordingTransport(
            expectedCall("Email/query", queryPage(0, listOf("email-1", "email-2"))),
            expectedCall("Email/query", queryPage(2, listOf("email-2"))),
        )
        val adapter = accountAdapter(transport)

        val failure = assertFailsWith<StalwartProductException> {
            adapter.listMessages("account-one", "inbox", limit = 2)
        }

        assertEquals("Stalwart Email query returned duplicate Email IDs", failure.message)
        transport.assertExhausted()
    }

    @Test
    fun importEmlUploadsInlineRfc822ThenImportsTheBlob() = runBlocking {
        val rawEml = "From: sender@local.test\r\nTo: dev@local.test\r\n\r\nHello"
        val transport = RecordingTransport(
            expectedCall(
                "Blob/upload",
                setCreatedPayload(
                    accountId = "account-one",
                    creationId = "dashboard-blob",
                    objectId = "blob-one",
                    extraCreated = buildJsonObject {
                        put("type", "message/rfc822")
                        put("size", rawEml.encodeToByteArray().size)
                    },
                ),
            ) { arguments ->
                val blob = arguments.requiredObject("create")
                    .requiredObject("dashboard-blob")
                assertEquals("message/rfc822", blob.requiredString("type"))
                assertEquals(
                    rawEml,
                    blob.requiredArray("data").single().jsonObject.requiredString("data:asText"),
                )
            },
            expectedCall(
                "Email/import",
                setCreatedPayload(
                    accountId = "account-one",
                    creationId = "dashboard-email",
                    objectId = "email-imported",
                ),
            ) { arguments ->
                val email = arguments.requiredObject("emails")
                    .requiredObject("dashboard-email")
                assertEquals("blob-one", email.requiredString("blobId"))
                assertTrue(
                    email.requiredObject("mailboxIds")["inbox"]
                        ?.jsonPrimitive?.booleanOrNull == true,
                )
                assertEquals("2026-08-05T12:00:00Z", email.requiredString("receivedAt"))
            },
        )
        val adapter = accountAdapter(transport)

        assertEquals(
            StalwartImportedEmail("email-imported", "blob-one"),
            adapter.importEml(
                accountId = "account-one",
                mailboxId = "inbox",
                rawEml = rawEml,
                receivedAt = Instant.parse("2026-08-05T12:00:00Z"),
            ),
        )
        transport.assertExhausted()
    }

    @Test
    fun keywordMoveAndDeleteOperationsUseEmailSetPatches() = runBlocking {
        val transport = RecordingTransport(
            emailUpdateCall("email-one") { patch ->
                assertTrue(patch["keywords/\$seen"]?.jsonPrimitive?.booleanOrNull == true)
            },
            emailUpdateCall("email-one") { patch ->
                assertEquals(JsonNull, patch["keywords/\$flagged"])
            },
            emailUpdateCall("email-one") { patch ->
                assertEquals(JsonNull, patch["mailboxIds/inbox"])
                assertTrue(patch["mailboxIds/archive"]?.jsonPrimitive?.booleanOrNull == true)
                assertFalse("mailboxIds/label-kept" in patch)
            },
            expectedCall(
                "Email/set",
                setDestroyedPayload("account-one", "email-one"),
            ) { arguments ->
                assertEquals("emails-1", arguments.requiredString("ifInState"))
                assertEquals(listOf("email-one"), arguments.stringArray("destroy"))
            },
        )
        val adapter = accountAdapter(transport)

        adapter.setSeen("account-one", listOf("email-one"), "emails-1", seen = true)
        adapter.setFlagged("account-one", listOf("email-one"), "emails-1", flagged = false)
        adapter.moveMessages("account-one", listOf("email-one"), "emails-1", "inbox", "archive")
        adapter.deleteMessages("account-one", listOf("email-one"), "emails-1")
        transport.assertExhausted()
    }

    @Test
    fun oneEmailSetCarriesTheReadStateForTheWholeBatch() = runBlocking {
        val transport = RecordingTransport(
            expectedCall(
                "Email/set",
                buildJsonObject {
                    put("accountId", "account-one")
                    put("oldState", "emails-1")
                    put("newState", "emails-2")
                    put(
                        "updated",
                        buildJsonObject {
                            put("email-one", JsonNull)
                            put("email-two", JsonNull)
                        },
                    )
                    put("notUpdated", buildJsonObject {})
                },
            ) { arguments ->
                assertEquals("emails-1", arguments.requiredString("ifInState"))
                assertEquals(
                    setOf("email-one", "email-two"),
                    arguments.requiredObject("update").keys,
                )
            },
        )
        val adapter = accountAdapter(transport)

        adapter.setSeen(
            "account-one",
            listOf("email-one", "email-two"),
            "emails-1",
            seen = true,
        )

        transport.assertExhausted()
    }

    @Test
    fun copyAddsMailboxMembershipAndReturnsTheExistingMessageId() = runBlocking {
        val transport = RecordingTransport(
            emailUpdateCall("email-one") { patch ->
                assertTrue(patch["mailboxIds/archive"]?.jsonPrimitive?.booleanOrNull == true)
            },
        )
        val adapter = accountAdapter(transport)

        assertEquals(
            listOf("email-one"),
            adapter.copyMessages("account-one", listOf("email-one"), "emails-1", "archive"),
        )
        transport.assertExhausted()
    }

    @Test
    fun trashFindsTheTrashMailboxThenMovesTheMessage() = runBlocking {
        val transport = RecordingTransport(
            expectedCall(
                "Mailbox/get",
                buildJsonObject {
                    put("accountId", "account-one")
                    put("state", "mailboxes-1")
                    put(
                        "list",
                        buildJsonArray {
                            add(
                                buildJsonObject {
                                    put("id", "trash")
                                    put("name", "Trash")
                                    put("role", "trash")
                                    put("parentId", JsonNull)
                                    put("totalEmails", 0)
                                    put("unreadEmails", 0)
                                },
                            )
                        },
                    )
                    put("notFound", buildJsonArray {})
                },
            ),
            emailUpdateCall("email-one") { patch ->
                assertEquals(JsonNull, patch["mailboxIds/inbox"])
                assertTrue(patch["mailboxIds/trash"]?.jsonPrimitive?.booleanOrNull == true)
            },
        )
        val adapter = accountAdapter(transport)

        adapter.trashMessages("account-one", listOf("email-one"), "emails-1", "inbox")

        transport.assertExhausted()
    }

    private suspend fun accountAdapter(
        transport: RecordingTransport,
    ): StalwartProductAdapter {
        val catalog = InMemoryStalwartAccountCredentialCatalog()
        catalog.save(StalwartAccountLogin("account-one", "dev@local.test", "password"))
        return adapter(transport, catalog)
    }

    private fun adapter(
        transport: GateHttpTransport,
        catalog: StalwartAccountCredentialCatalog,
    ): StalwartProductAdapter = StalwartProductAdapter(
        baseUri = BASE_URI,
        managementCredentialProvider = StalwartManagementCredentialProvider {
            GateCredential.basic("manager@local.test", "management".toCharArray())
        },
        accountCredentialCatalog = catalog,
        transport = transport,
    )

    private data class ExpectedCall(
        val method: String,
        val payload: JsonObject,
        val inspect: (JsonObject) -> Unit,
    )

    private class RecordingTransport(
        vararg calls: ExpectedCall,
    ) : GateHttpTransport {
        private val remaining = ArrayDeque(calls.toList())
        val sessionCredentials = mutableListOf<Pair<String, String>>()

        override suspend fun execute(request: GateHttpRequest): GateHttpResponse {
            if (request.method == "GET") {
                val username = request.credential.basicUsername
                sessionCredentials += decodeBasicCredential(request)
                val accountId = if (username == "manager@local.test") {
                    "management-account"
                } else {
                    "account-one"
                }
                return GateHttpResponse(
                    status = 200,
                    effectiveUrl = request.url,
                    body = buildJsonObject {
                        put("apiUrl", API_URI.toString())
                        put("username", username)
                        put(
                            "primaryAccounts",
                            buildJsonObject {
                                put("urn:stalwart:jmap", accountId)
                            },
                        )
                    }.toString(),
                )
            }

            val expected = remaining.removeFirstOrNull()
                ?: error("Unexpected JMAP call: ${request.body}")
            val tuple = requireNotNull(request.body)
                .requiredArray("methodCalls")
                .single()
                .jsonArray
            assertEquals(expected.method, tuple[0].jsonPrimitive.content)
            val arguments = tuple[1].jsonObject
            expected.inspect(arguments)
            val callId = tuple[2].jsonPrimitive.content
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
                                    add(JsonPrimitive(callId))
                                },
                            )
                        },
                    )
                }.toString(),
            )
        }

        fun assertExhausted() {
            assertTrue(remaining.isEmpty(), "Unconsumed calls: $remaining")
        }
    }

    private class RejectingSessionTransport(
        private val status: Int,
        private val responseBody: String,
    ) : GateHttpTransport {
        var calls = 0
            private set

        override suspend fun execute(request: GateHttpRequest): GateHttpResponse {
            calls += 1
            return GateHttpResponse(
                status = status,
                effectiveUrl = request.url,
                body = responseBody,
            )
        }
    }

    private companion object {
        val BASE_URI: URI = URI("http://127.0.0.1:8443")
        val API_URI: URI = URI("http://127.0.0.1:8443/jmap/")

        fun decodeBasicCredential(request: GateHttpRequest): Pair<String, String> {
            val encoded = request.credential.authorizationHeader().removePrefix("Basic ")
            val decoded = java.util.Base64.getDecoder().decode(encoded).decodeToString()
            return decoded.substringBefore(':') to decoded.substringAfter(':')
        }

        fun expectedCall(
            method: String,
            payload: JsonObject,
            inspect: (JsonObject) -> Unit = {},
        ): ExpectedCall = ExpectedCall(method, payload, inspect)

        fun queryPayload(accountId: String, ids: List<String>): JsonObject =
            buildJsonObject {
                put("accountId", accountId)
                put("queryState", "query-1")
                put("canCalculateChanges", true)
                put("position", 0)
                put("ids", JsonArray(ids.map(::JsonPrimitive)))
                put("total", ids.size)
            }

        fun getPayload(accountId: String, vararg values: JsonObject): JsonObject =
            buildJsonObject {
                put("accountId", accountId)
                put("state", "state-1")
                put("list", JsonArray(values.toList()))
                put("notFound", buildJsonArray {})
            }

        fun accountObject(
            id: String,
            localPart: String,
            domainId: String,
            permissions: JsonObject = buildJsonObject {
                put("@type", "Replace")
                put(
                    "enabledPermissions",
                    buildJsonObject {
                        put("jmapEmailGet", true)
                        put("imapFetch", true)
                        put("emailSend", true)
                    },
                )
                put("disabledPermissions", buildJsonObject {})
            },
        ): JsonObject = buildJsonObject {
            put("id", id)
            put("@type", "User")
            put("name", localPart)
            put("domainId", domainId)
            put(
                "credentials",
                buildJsonObject {
                    put(
                        "0",
                        buildJsonObject {
                            put("@type", "Password")
                            put("credentialId", "password-one")
                            put("secret", "********")
                            put("allowedIps", buildJsonObject {})
                        },
                    )
                },
            )
            put("permissions", permissions)
        }

        fun setCreatedPayload(
            accountId: String,
            creationId: String,
            objectId: String,
            extraCreated: JsonObject = buildJsonObject {},
        ): JsonObject = buildJsonObject {
            put("accountId", accountId)
            put("oldState", "old")
            put("newState", "new")
            put(
                "created",
                buildJsonObject {
                    put(
                        creationId,
                        buildJsonObject {
                            put("id", objectId)
                            extraCreated.forEach { (key, value) -> put(key, value) }
                        },
                    )
                },
            )
            put("notCreated", buildJsonObject {})
        }

        fun setUpdatedPayload(accountId: String, objectId: String): JsonObject =
            buildJsonObject {
                put("accountId", accountId)
                put("oldState", "old")
                put("newState", "new")
                put("updated", buildJsonObject { put(objectId, JsonNull) })
                put("notUpdated", buildJsonObject {})
            }

        fun setDestroyedPayload(accountId: String, objectId: String): JsonObject =
            buildJsonObject {
                put("accountId", accountId)
                put("oldState", "old")
                put("newState", "new")
                put("destroyed", buildJsonArray { add(JsonPrimitive(objectId)) })
                put("notDestroyed", buildJsonObject {})
            }

        fun emailGetPayload(email: JsonObject): JsonObject = buildJsonObject {
            put("accountId", "account-one")
            put("state", "emails-1")
            put("list", buildJsonArray { add(email) })
            put("notFound", buildJsonArray {})
        }

        fun summaryEmailObject(id: String = "email-one"): JsonObject = buildJsonObject {
            put("id", id)
            put("subject", "A test message")
            put(
                "from",
                buildJsonArray {
                    add(
                        buildJsonObject {
                            put("name", "Sender")
                            put("email", "sender@local.test")
                        },
                    )
                },
            )
            put("receivedAt", "2026-08-05T12:00:00Z")
            put("preview", "Hello from the preview")
            put("mailboxIds", buildJsonObject { put("inbox", true) })
            put(
                "keywords",
                buildJsonObject {
                    put("\$seen", true)
                },
            )
        }

        fun fullEmailObject(): JsonObject = buildJsonObject {
            summaryEmailObject().forEach { (key, value) -> put(key, value) }
            put(
                "to",
                buildJsonArray {
                    add(
                        buildJsonObject {
                            put("name", "Dev")
                            put("email", "dev@local.test")
                        },
                    )
                },
            )
            put(
                "textBody",
                buildJsonArray {
                    add(buildJsonObject { put("partId", "text-part") })
                },
            )
            put("htmlBody", buildJsonArray {})
            put(
                "bodyValues",
                buildJsonObject {
                    put(
                        "text-part",
                        buildJsonObject {
                            put("value", "Hello from the body")
                            put("isTruncated", false)
                        },
                    )
                },
            )
        }

        fun emailUpdateCall(
            emailId: String,
            inspectPatch: (JsonObject) -> Unit,
        ): ExpectedCall = expectedCall(
            "Email/set",
            setUpdatedPayload("account-one", emailId),
        ) { arguments ->
            assertEquals("emails-1", arguments.requiredString("ifInState"))
            inspectPatch(
                arguments.requiredObject("update").requiredObject(emailId),
            )
        }

        fun JsonObject.requiredObject(name: String): JsonObject =
            this[name] as? JsonObject ?: error("$name was not an object: $this")

        fun JsonObject.requiredArray(name: String): JsonArray =
            this[name] as? JsonArray ?: error("$name was not an array: $this")

        fun JsonObject.requiredString(name: String): String =
            this[name]?.jsonPrimitive?.content ?: error("$name was not a string: $this")

        fun JsonObject.requiredInt(name: String): Int =
            this[name]?.jsonPrimitive?.content?.toIntOrNull()
                ?: error("$name was not an integer: $this")

        fun JsonObject.requiredBoolean(name: String): Boolean =
            this[name]?.jsonPrimitive?.booleanOrNull
                ?: error("$name was not a boolean: $this")

        fun JsonObject.stringArray(name: String): List<String> =
            requiredArray(name).map { value -> value.jsonPrimitive.content }
    }
}
