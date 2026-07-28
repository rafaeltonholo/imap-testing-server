package mail.sandbox.dashboard.server.gate.stalwart

import java.net.URI
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.util.UUID
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put

class StalwartPermissionMatrixLiveTest {
    @Test
    fun provesFixturePrincipalScopesAndQuotaIsolation() = runBlocking {
        val environment = System.getenv()
        val projectRoot = dashboardProjectRoot()
        val live = StalwartLiveTestEnvironment.load(
            environment = environment,
            projectRoot = projectRoot,
        )
        live.awaitReady()
        StalwartDockerMountAudit.assertReviewedLiveMounts(projectRoot)

        StalwartGateSecretFiles.readFixtureSecrets(
            projectRoot = projectRoot,
            environment = environment,
        ).use { fixture ->
            KtorGateHttpTransport().use { transport ->
                GateJmapClient(
                    baseUrl = live.baseUrl,
                    credential = GateCredential.bearer(fixture.managementApiKey),
                    transport = transport,
                ).use { manager ->
                    GateJmapClient(
                        baseUrl = live.baseUrl,
                        credential = GateCredential.basic(
                            username = GateBootstrap.FIRST_USER_ADDRESS,
                            secret = fixture.firstUserPassword,
                        ),
                        transport = transport,
                    ).use { owner ->
                        GateJmapClient(
                            baseUrl = live.baseUrl,
                            credential = GateCredential.basic(
                                username = GateBootstrap.SECOND_USER_ADDRESS,
                                secret = fixture.secondUserPassword,
                            ),
                            transport = transport,
                        ).use { recipient ->

                            val managementSession = manager.discoverSession()
                            val ownerSession = owner.discoverSession()
                            val recipientSession = recipient.discoverSession()
                            val managementAccountId = requireAccountSession(
                                session = managementSession,
                                expectedUsername = GateBootstrap.MANAGEMENT_ADDRESS,
                            )
                            val ownerAccountId = requireAccountSession(
                                session = ownerSession,
                                expectedUsername = GateBootstrap.FIRST_USER_ADDRESS,
                            )
                            val recipientAccountId = requireAccountSession(
                                session = recipientSession,
                                expectedUsername = GateBootstrap.SECOND_USER_ADDRESS,
                            )
                            assertEquals(fixture.managementAccountId, managementAccountId)
                            val expectedAccountIds = setOf(
                                managementAccountId,
                                ownerAccountId,
                                recipientAccountId,
                            )
                            assertEquals(3, expectedAccountIds.size)

                            val enrollment = GateAppPasswordEnrollmentClient(
                                registry = owner,
                                ownerAccountId = ownerAccountId,
                                ownerAddress = GateBootstrap.FIRST_USER_ADDRESS,
                            )
                            cleanupReservedCredentials(enrollment)

                            val baselineAccounts = fetchFixtureAccounts(
                                manager = manager,
                                managementAccountId = managementAccountId,
                                expectedAccountIds = expectedAccountIds,
                            )
                            assertFixturePrincipalMatrix(
                                accounts = baselineAccounts,
                                managementAccountId = managementAccountId,
                                ownerAccountId = ownerAccountId,
                                recipientAccountId = recipientAccountId,
                                expectedOwnerAppPassword = null,
                            )
                            val baselineOwner = baselineAccounts.getValue(ownerAccountId)
                            val baselineQuotas = requiredObject(baselineOwner, "quotas")
                            val baselineCredentials = requiredObject(
                                baselineOwner,
                                "credentials",
                            )
                            val priorMaxAppPasswords = baselineQuotas["maxAppPasswords"]
                            requireOptionalPositiveQuota(priorMaxAppPasswords)

                            assertEffectivePrincipalScopes(
                                live = live,
                                fixture = fixture,
                            )

                            var quotaMutationAttempted = false
                            var activeId: String? = null
                            var activeSecret = CharArray(0)
                            var activeCredentialSnapshot: JsonObject? = null
                            var primaryFailure: Throwable? = null
                            try {
                                quotaMutationAttempted = true
                                patchMaxAppPasswords(
                                    manager = manager,
                                    managementAccountId = managementAccountId,
                                    ownerAccountId = ownerAccountId,
                                    value = JsonPrimitive(1),
                                )
                                val quotaAccount = fetchExactAccount(
                                    manager = manager,
                                    managementAccountId = managementAccountId,
                                    accountId = ownerAccountId,
                                )
                                assertEquals(
                                    1L,
                                    requiredObject(quotaAccount, "quotas")
                                        .getValue("maxAppPasswords")
                                        .jsonPrimitive
                                        .longOrNull,
                                )

                                val created = enrollment.create(QUOTA_DESCRIPTION)
                                activeId = created.use {
                                    activeSecret = it.copySecret()
                                    it.id
                                }
                                val createdActiveId = assertNotNull(activeId)
                                val storedBeforeRejection = enrollment.inventory().single {
                                    it.id == createdActiveId
                                }
                                assertStoredAppPassword(
                                    value = storedBeforeRejection,
                                    expectedId = createdActiveId,
                                    expectedDescription = QUOTA_DESCRIPTION,
                                )
                                val accountCredentialBeforeRejection =
                                    appPasswordCredential(
                                        account = fetchExactAccount(
                                            manager = manager,
                                            managementAccountId = managementAccountId,
                                            accountId = ownerAccountId,
                                        ),
                                        credentialId = createdActiveId,
                                    )
                                activeCredentialSnapshot = accountCredentialBeforeRejection

                                appPasswordClient(
                                    live = live,
                                    transport = transport,
                                    secret = activeSecret,
                                ).use { app ->
                                    assertPermissionDenialMatrix(
                                        app = app,
                                        manager = manager,
                                        ownerAccountId = ownerAccountId,
                                        recipientAccountId = recipientAccountId,
                                    )
                                }

                                val rejection = when (
                                    val result = enrollment.tryCreate(
                                        QUOTA_REJECTED_DESCRIPTION,
                                    )
                                ) {
                                    is GateAppPasswordCreateResult.Rejected -> result
                                    is GateAppPasswordCreateResult.Created ->
                                        result.credential.use {
                                            throw AssertionError(
                                                "Quota exhaustion unexpectedly created a second AppPassword",
                                            )
                                        }
                                }
                                assertEquals("overQuota", rejection.type)

                                val storedAfterRejection = enrollment.inventory().single {
                                    it.id == createdActiveId
                                }
                                assertStoredAppPassword(
                                    value = storedAfterRejection,
                                    expectedId = createdActiveId,
                                    expectedDescription = QUOTA_DESCRIPTION,
                                )
                                assertEquals(
                                    accountCredentialBeforeRejection,
                                    appPasswordCredential(
                                        account = fetchExactAccount(
                                            manager = manager,
                                            managementAccountId = managementAccountId,
                                            accountId = ownerAccountId,
                                        ),
                                        credentialId = createdActiveId,
                                    ),
                                    "Quota rejection changed the existing Account credential",
                                )
                                    assertEquals(
                                        ownerAccountId,
                                        appPasswordClient(
                                            live = live,
                                            transport = transport,
                                            secret = activeSecret,
                                        ).use {
                                            it.discoverSession().primaryAccountId
                                        },
                                        "Quota rejection invalidated the existing AppPassword",
                                    )
                                KtorGateHttpTransport(followRedirects = false).use { effectiveTransport ->
                                    val scope = GateEffectivePermissionClient(
                                        baseUrl = live.baseUrl,
                                        credential = GateCredential.basic(
                                            username = GateBootstrap.FIRST_USER_ADDRESS,
                                            secret = activeSecret,
                                        ),
                                        transport = effectiveTransport,
                                    ).use { it.fetch() }
                                    assertEquals(DASHBOARD_MAIL_PERMISSIONS, scope.permissions)
                                    assertFalse("impersonate" in scope.permissions)
                                }

                                assertFixturePrincipalMatrix(
                                    accounts = fetchFixtureAccounts(
                                        manager = manager,
                                        managementAccountId = managementAccountId,
                                        expectedAccountIds = expectedAccountIds,
                                    ),
                                    managementAccountId = managementAccountId,
                                    ownerAccountId = ownerAccountId,
                                    recipientAccountId = recipientAccountId,
                                    expectedOwnerAppPassword = ExpectedAppPassword(
                                        id = createdActiveId,
                                        description = QUOTA_DESCRIPTION,
                                    ),
                                )
                            } catch (failure: Throwable) {
                                primaryFailure = failure
                                throw failure
                            } finally {
                                withContext(NonCancellable) {
                                    var cleanupFailure: Throwable? = null

                                    suspend fun attemptCleanup(block: suspend () -> Unit) {
                                        try {
                                            block()
                                        } catch (failure: Throwable) {
                                            cleanupFailure?.addSuppressed(failure)
                                                ?: run { cleanupFailure = failure }
                                        }
                                    }

                                    if (quotaMutationAttempted) {
                                        attemptCleanup {
                                            patchMaxAppPasswords(
                                                manager = manager,
                                                managementAccountId = managementAccountId,
                                                ownerAccountId = ownerAccountId,
                                                value = priorMaxAppPasswords ?: JsonNull,
                                            )
                                        }
                                    }
                                    val cleanupActiveId = activeId
                                    val cleanupActiveSnapshot = activeCredentialSnapshot
                                    if (
                                        cleanupActiveId != null &&
                                        cleanupActiveSnapshot != null &&
                                        activeSecret.isNotEmpty()
                                    ) {
                                        attemptCleanup {
                                            assertEquals(
                                                cleanupActiveSnapshot,
                                                appPasswordCredential(
                                                    account = fetchExactAccount(
                                                        manager = manager,
                                                        managementAccountId = managementAccountId,
                                                        accountId = ownerAccountId,
                                                    ),
                                                    credentialId = cleanupActiveId,
                                                ),
                                                "Quota restoration changed the active Account credential",
                                            )
                                            assertStoredAppPassword(
                                                value = enrollment.inventory().single {
                                                    it.id == cleanupActiveId
                                                },
                                                expectedId = cleanupActiveId,
                                                expectedDescription = QUOTA_DESCRIPTION,
                                            )
                                            assertEquals(
                                                ownerAccountId,
                                                appPasswordClient(
                                                    live = live,
                                                    transport = transport,
                                                    secret = activeSecret,
                                                ).use {
                                                    it.discoverSession().primaryAccountId
                                                },
                                                "Quota restoration invalidated the active AppPassword",
                                            )
                                            KtorGateHttpTransport(
                                                followRedirects = false,
                                            ).use { effectiveTransport ->
                                                assertEquals(
                                                    DASHBOARD_MAIL_PERMISSIONS,
                                                    GateEffectivePermissionClient(
                                                        baseUrl = live.baseUrl,
                                                        credential = GateCredential.basic(
                                                            username =
                                                                GateBootstrap.FIRST_USER_ADDRESS,
                                                            secret = activeSecret,
                                                        ),
                                                        transport = effectiveTransport,
                                                    ).use { it.fetch().permissions },
                                                )
                                            }
                                        }
                                    }
                                    attemptCleanup {
                                        cleanupReservedCredentials(enrollment)
                                    }
                                    attemptCleanup {
                                        val restored = fetchExactAccount(
                                            manager = manager,
                                            managementAccountId = managementAccountId,
                                            accountId = ownerAccountId,
                                        )
                                        assertEquals(
                                            baselineQuotas,
                                            requiredObject(restored, "quotas"),
                                            "Quota cleanup did not restore the exact prior map",
                                        )
                                        assertEquals(
                                            baselineCredentials,
                                            requiredObject(restored, "credentials"),
                                            "Quota proof did not restore the prior credential inventory",
                                        )
                                    }
                                    activeSecret.fill('\u0000')
                                    cleanupFailure?.let { failure ->
                                        primaryFailure?.addSuppressed(failure)
                                            ?: throw failure
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    private suspend fun assertPermissionDenialMatrix(
        app: GateJmapClient,
        manager: GateJmapClient,
        ownerAccountId: String,
        recipientAccountId: String,
    ) {
        mailPermissionOperations(
            client = app,
            accountId = recipientAccountId,
        ).forEach { operation ->
            assertForbidden("Cross-Account ${operation.label}", operation.call)
        }
        mailPermissionOperations(
            client = manager,
            accountId = ownerAccountId,
        ).forEach { operation ->
            assertForbidden("Management ${operation.label}", operation.call)
        }
        mailPermissionOperations(
            client = app,
            accountId = ownerAccountId,
        ).filter { operation ->
            operation.label in DISALLOWED_APP_MAIL_OPERATIONS
        }.forEach { operation ->
            assertForbidden("AppPassword ${operation.label}", operation.call)
        }
        registryPermissionOperations(
            app = app,
            ownerAccountId = ownerAccountId,
        ).forEach { operation ->
            assertForbidden("AppPassword ${operation.label}", operation.call)
        }
    }

    private fun mailPermissionOperations(
        client: GateJmapClient,
        accountId: String,
    ): List<DeniedOperation> = listOf(
        DeniedOperation("Mailbox/get") {
            client.call(
                methodName = "Mailbox/get",
                arguments = buildJsonObject {
                    put("accountId", accountId)
                    put("ids", JsonNull)
                },
                capabilities = MAIL_CAPABILITIES,
            )
        },
        DeniedOperation("Mailbox/create") {
            client.call(
                methodName = "Mailbox/set",
                arguments = buildJsonObject {
                    put("accountId", accountId)
                    put(
                        "create",
                        buildJsonObject {
                            put("forbidden-create", buildJsonObject {})
                        },
                    )
                },
                capabilities = MAIL_CAPABILITIES,
            )
        },
        DeniedOperation("Mailbox/update") {
            client.call(
                methodName = "Mailbox/set",
                arguments = buildJsonObject {
                    put("accountId", accountId)
                    put(
                        "update",
                        buildJsonObject {
                            put(
                                "forbidden-mailbox",
                                buildJsonObject {
                                    put("name", "forbidden-update")
                                },
                            )
                        },
                    )
                },
                capabilities = MAIL_CAPABILITIES,
            )
        },
        DeniedOperation("Mailbox/destroy") {
            client.call(
                methodName = "Mailbox/set",
                arguments = buildJsonObject {
                    put("accountId", accountId)
                    put(
                        "destroy",
                        strings("forbidden-mailbox"),
                    )
                },
                capabilities = MAIL_CAPABILITIES,
            )
        },
        DeniedOperation("Email/get") {
            client.call(
                methodName = "Email/get",
                arguments = buildJsonObject {
                    put("accountId", accountId)
                    put("ids", strings("forbidden-email"))
                },
                capabilities = MAIL_CAPABILITIES,
            )
        },
        DeniedOperation("Email/query") {
            client.call(
                methodName = "Email/query",
                arguments = buildJsonObject {
                    put("accountId", accountId)
                    put("filter", buildJsonObject {})
                    put("sort", JsonArray(emptyList()))
                },
                capabilities = MAIL_CAPABILITIES,
            )
        },
        DeniedOperation("Email/update") {
            client.call(
                methodName = "Email/set",
                arguments = buildJsonObject {
                    put("accountId", accountId)
                    put(
                        "update",
                        buildJsonObject {
                            put(
                                "forbidden-email",
                                buildJsonObject {
                                    put("keywords/\$flagged", true)
                                },
                            )
                        },
                    )
                },
                capabilities = MAIL_CAPABILITIES,
            )
        },
        DeniedOperation("Email/destroy") {
            client.call(
                methodName = "Email/set",
                arguments = buildJsonObject {
                    put("accountId", accountId)
                    put("destroy", strings("forbidden-email"))
                },
                capabilities = MAIL_CAPABILITIES,
            )
        },
        DeniedOperation("Email/import") {
            client.call(
                methodName = "Email/import",
                arguments = buildJsonObject {
                    put("accountId", accountId)
                    put(
                        "emails",
                        buildJsonObject {
                            put("forbidden-import", buildJsonObject {})
                        },
                    )
                },
                capabilities = MAIL_CAPABILITIES,
            )
        },
        DeniedOperation("Identity/get") {
            client.call(
                methodName = "Identity/get",
                arguments = buildJsonObject {
                    put("accountId", accountId)
                    put("ids", JsonNull)
                },
                capabilities = MAIL_CAPABILITIES,
            )
        },
        DeniedOperation("Identity/create") {
            client.call(
                methodName = "Identity/set",
                arguments = buildJsonObject {
                    put("accountId", accountId)
                    put(
                        "create",
                        buildJsonObject {
                            put("forbidden-identity", buildJsonObject {})
                        },
                    )
                },
                capabilities = MAIL_CAPABILITIES,
            )
        },
        DeniedOperation("Identity/update") {
            client.call(
                methodName = "Identity/set",
                arguments = buildJsonObject {
                    put("accountId", accountId)
                    put(
                        "update",
                        buildJsonObject {
                            put(
                                "forbidden-identity",
                                buildJsonObject {
                                    put("name", "forbidden-update")
                                },
                            )
                        },
                    )
                },
                capabilities = MAIL_CAPABILITIES,
            )
        },
        DeniedOperation("Identity/destroy") {
            client.call(
                methodName = "Identity/set",
                arguments = buildJsonObject {
                    put("accountId", accountId)
                    put("destroy", strings("forbidden-identity"))
                },
                capabilities = MAIL_CAPABILITIES,
            )
        },
        DeniedOperation("EmailSubmission/get") {
            client.call(
                methodName = "EmailSubmission/get",
                arguments = buildJsonObject {
                    put("accountId", accountId)
                    put("ids", strings("forbidden-submission"))
                },
                capabilities = MAIL_CAPABILITIES,
            )
        },
        DeniedOperation("EmailSubmission/create") {
            client.call(
                methodName = "EmailSubmission/set",
                arguments = buildJsonObject {
                    put("accountId", accountId)
                    put(
                        "create",
                        buildJsonObject {
                            put("forbidden-submission", buildJsonObject {})
                        },
                    )
                },
                capabilities = MAIL_CAPABILITIES,
            )
        },
        DeniedOperation("EmailSubmission/update") {
            client.call(
                methodName = "EmailSubmission/set",
                arguments = buildJsonObject {
                    put("accountId", accountId)
                    put(
                        "update",
                        buildJsonObject {
                            put(
                                "forbidden-submission",
                                buildJsonObject {
                                    put("undoStatus", "canceled")
                                },
                            )
                        },
                    )
                },
                capabilities = MAIL_CAPABILITIES,
            )
        },
        DeniedOperation("EmailSubmission/destroy") {
            client.call(
                methodName = "EmailSubmission/set",
                arguments = buildJsonObject {
                    put("accountId", accountId)
                    put("destroy", strings("forbidden-submission"))
                },
                capabilities = MAIL_CAPABILITIES,
            )
        },
        DeniedOperation("Blob/get") {
            client.call(
                methodName = "Blob/get",
                arguments = buildJsonObject {
                    put("accountId", accountId)
                    put("ids", strings("forbidden-blob"))
                    put("properties", strings("data:asText"))
                },
                capabilities = MAIL_CAPABILITIES,
            )
        },
        DeniedOperation("Blob/upload") {
            client.call(
                methodName = "Blob/upload",
                arguments = buildJsonObject {
                    put("accountId", accountId)
                    put(
                        "create",
                        buildJsonObject {
                            put("forbidden-upload", buildJsonObject {})
                        },
                    )
                },
                capabilities = MAIL_CAPABILITIES,
            )
        },
    )

    private fun registryPermissionOperations(
        app: GateJmapClient,
        ownerAccountId: String,
    ): List<DeniedOperation> = listOf(
        DeniedOperation("Account/get") {
            app.registryGet(
                objectType = "Account",
                ids = listOf(ownerAccountId),
                accountId = ownerAccountId,
            )
        },
        DeniedOperation("Account/query") {
            app.registryQuery(
                objectType = "Account",
                accountId = ownerAccountId,
            )
        },
        DeniedOperation("Account/create") {
            app.registryCreate(
                objectType = "Account",
                creationId = "forbidden-account",
                value = buildJsonObject {},
                accountId = ownerAccountId,
            )
        },
        DeniedOperation("Account/update") {
            app.registryUpdate(
                objectType = "Account",
                objectId = "forbidden-account",
                patch = buildJsonObject {
                    put("description", "forbidden-update")
                },
                accountId = ownerAccountId,
            )
        },
        DeniedOperation("Account/destroy") {
            app.registryDestroy(
                objectType = "Account",
                objectId = "forbidden-account",
                accountId = ownerAccountId,
            )
        },
        DeniedOperation("Domain/get") {
            app.registryGet(
                objectType = "Domain",
                ids = listOf("forbidden-domain"),
                accountId = ownerAccountId,
            )
        },
        DeniedOperation("Domain/query") {
            app.registryQuery(
                objectType = "Domain",
                accountId = ownerAccountId,
            )
        },
        DeniedOperation("Domain/create") {
            app.registryCreate(
                objectType = "Domain",
                creationId = "forbidden-domain",
                value = buildJsonObject {},
                accountId = ownerAccountId,
            )
        },
        DeniedOperation("Domain/update") {
            app.registryUpdate(
                objectType = "Domain",
                objectId = "forbidden-domain",
                patch = buildJsonObject {
                    put("description", "forbidden-update")
                },
                accountId = ownerAccountId,
            )
        },
        DeniedOperation("Domain/destroy") {
            app.registryDestroy(
                objectType = "Domain",
                objectId = "forbidden-domain",
                accountId = ownerAccountId,
            )
        },
        DeniedOperation("Task/get") {
            app.registryGet(
                objectType = "Task",
                ids = listOf("forbidden-task"),
                accountId = ownerAccountId,
            )
        },
        DeniedOperation("Task/query") {
            app.registryQuery(
                objectType = "Task",
                accountId = ownerAccountId,
            )
        },
        DeniedOperation("Log/get") {
            app.registryGet(
                objectType = "Log",
                ids = listOf("forbidden-log"),
                accountId = ownerAccountId,
            )
        },
        DeniedOperation("Log/query") {
            app.registryQuery(
                objectType = "Log",
                accountId = ownerAccountId,
            )
        },
    )

    private suspend fun assertForbidden(
        label: String,
        operation: suspend () -> JsonObject,
    ) {
        val failure = kotlin.test.assertFailsWith<GateJmapException> {
            operation()
        }
        assertEquals(
            "forbidden",
            (failure.kind as? GateJmapFailure.MethodError)?.type,
            "$label failed for an unrelated reason",
        )
    }

    private suspend fun assertEffectivePrincipalScopes(
        live: StalwartLiveTestEnvironment,
        fixture: GateFixtureSecrets,
    ) {
        KtorGateHttpTransport(followRedirects = false).use { transport ->
            val management = GateEffectivePermissionClient(
                baseUrl = live.baseUrl,
                credential = GateCredential.bearer(fixture.managementApiKey),
                transport = transport,
            ).use { it.fetch() }
            assertEquals(GateBootstrap.managementPermissions, management.permissions)

            val owner = GateEffectivePermissionClient(
                baseUrl = live.baseUrl,
                credential = GateCredential.basic(
                    username = GateBootstrap.FIRST_USER_ADDRESS,
                    secret = fixture.firstUserPassword,
                ),
                transport = transport,
            ).use { it.fetch() }
            val recipient = GateEffectivePermissionClient(
                baseUrl = live.baseUrl,
                credential = GateCredential.basic(
                    username = GateBootstrap.SECOND_USER_ADDRESS,
                    secret = fixture.secondUserPassword,
                ),
                transport = transport,
            ).use { it.fetch() }
            for (scope in listOf(management, owner, recipient)) {
                assertEquals("community", scope.edition)
                assertFalse("impersonate" in scope.permissions)
                assertFalse(scope.permissions.any { "*" in it })
            }
            assertTrue(owner.permissions.containsAll(DASHBOARD_MAIL_PERMISSIONS))
            assertEquals(owner.permissions, recipient.permissions)
        }
    }

    private suspend fun fetchFixtureAccounts(
        manager: GateJmapClient,
        managementAccountId: String,
        expectedAccountIds: Set<String>,
    ): Map<String, JsonObject> {
        val query = registryPayload(
            response = manager.registryQuery(
                objectType = "Account",
                accountId = managementAccountId,
            ),
            expectedMethod = "x:Account/query",
        )
        assertEquals(managementAccountId, requiredString(query, "accountId"))
        val ids = requiredArray(query, "ids").map(::requiredString)
        assertEquals(ids.size, ids.toSet().size)
        assertEquals(
            expectedAccountIds,
            ids.toSet(),
            "Management Account query did not return the exact gate principals",
        )

        val get = registryPayload(
            response = manager.registryGet(
                objectType = "Account",
                ids = ids,
                accountId = managementAccountId,
            ),
            expectedMethod = "x:Account/get",
        )
        assertEquals(managementAccountId, requiredString(get, "accountId"))
        assertTrue(requiredArray(get, "notFound").isEmpty())
        val accounts = requiredArray(get, "list")
            .map(::requiredObject)
            .associateBy { requiredString(it, "id") }
        assertEquals(expectedAccountIds, accounts.keys)
        return accounts
    }

    private suspend fun fetchExactAccount(
        manager: GateJmapClient,
        managementAccountId: String,
        accountId: String,
    ): JsonObject {
        val payload = registryPayload(
            response = manager.registryGet(
                objectType = "Account",
                ids = listOf(accountId),
                accountId = managementAccountId,
            ),
            expectedMethod = "x:Account/get",
        )
        assertTrue(requiredArray(payload, "notFound").isEmpty())
        val account = requiredObject(requiredArray(payload, "list").single())
        assertEquals(accountId, requiredString(account, "id"))
        return account
    }

    private fun assertFixturePrincipalMatrix(
        accounts: Map<String, JsonObject>,
        managementAccountId: String,
        ownerAccountId: String,
        recipientAccountId: String,
        expectedOwnerAppPassword: ExpectedAppPassword?,
    ) {
        val management = accounts.getValue(managementAccountId)
        val owner = accounts.getValue(ownerAccountId)
        val recipient = accounts.getValue(recipientAccountId)

        assertUserRole(management)
        assertUserRole(owner)
        assertUserRole(recipient)
        assertNoImpersonate(management)
        assertNoImpersonate(owner)
        assertNoImpersonate(recipient)

        val managementPermissions = requiredObject(management, "permissions")
        assertEquals(
            "Replace",
            requiredString(managementPermissions, "@type"),
        )
        assertEquals(
            GateBootstrap.managementPermissions,
            enabledKeys(managementPermissions, "enabledPermissions"),
        )
        assertTrue(
            requiredObject(managementPermissions, "disabledPermissions").isEmpty(),
        )
        val managementCredentials = credentials(management)
        assertEquals(1, managementCredentials.size)
        val managementApiKey = managementCredentials.single()
        assertEquals("ApiKey", requiredString(managementApiKey, "@type"))
        assertEquals(
            "mail-sandbox/debug-dashboard/management",
            requiredString(managementApiKey, "description"),
        )
        assertCredentialPermissions(
            credential = managementApiKey,
            expected = GateBootstrap.managementPermissions,
        )

        assertInheritedOrdinaryAccount(owner)
        assertInheritedOrdinaryAccount(recipient)
        val ownerCredentials = credentials(owner)
        val ownerPasswords = ownerCredentials.filter {
            requiredString(it, "@type") == "Password"
        }
        val ownerAppPasswords = ownerCredentials.filter {
            requiredString(it, "@type") == "AppPassword"
        }
        assertEquals(1, ownerPasswords.size)
        assertEquals(
            if (expectedOwnerAppPassword == null) 0 else 1,
            ownerAppPasswords.size,
        )
        if (expectedOwnerAppPassword != null) {
            val appPassword = ownerAppPasswords.single()
            assertEquals(
                expectedOwnerAppPassword.id,
                requiredString(appPassword, "credentialId"),
            )
            assertEquals(
                expectedOwnerAppPassword.description.value,
                requiredString(appPassword, "description"),
            )
            assertCredentialPermissions(
                credential = appPassword,
                expected = DASHBOARD_MAIL_PERMISSIONS,
            )
        }
        assertEquals(
            listOf("Password"),
            credentials(recipient).map { requiredString(it, "@type") },
        )
    }

    private fun assertInheritedOrdinaryAccount(account: JsonObject) {
        val permissions = requiredObject(account, "permissions")
        assertEquals("Inherit", requiredString(permissions, "@type"))
    }

    private fun assertUserRole(account: JsonObject) {
        val roles = requiredObject(account, "roles")
        assertEquals("User", requiredString(roles, "@type"))
        assertEquals(setOf("@type"), roles.keys)
    }

    private fun assertCredentialPermissions(
        credential: JsonObject,
        expected: Set<String>,
    ) {
        val permissions = requiredObject(credential, "permissions")
        assertEquals("Replace", requiredString(permissions, "@type"))
        assertEquals(expected, enabledKeys(permissions, "permissions"))
    }

    private fun enabledKeys(
        value: JsonObject,
        property: String,
    ): Set<String> =
        requiredObject(value, property).map { (name, enabled) ->
            assertEquals(
                true,
                enabled.jsonPrimitive.contentOrNull?.toBooleanStrictOrNull(),
                "$property contained a disabled or malformed entry",
            )
            name
        }.toSet()

    private fun assertNoImpersonate(value: JsonElement) {
        when (value) {
            is JsonObject -> value.forEach { (name, child) ->
                assertFalse(
                    name.equals("impersonate", ignoreCase = true),
                    "Fixture principal contained impersonation authority",
                )
                assertNoImpersonate(child)
            }
            is JsonArray -> value.forEach(::assertNoImpersonate)
            is JsonPrimitive -> if (value.isString) {
                assertFalse(
                    value.content.equals("impersonate", ignoreCase = true),
                    "Fixture principal contained impersonation authority",
                )
            }
        }
    }

    private suspend fun patchMaxAppPasswords(
        manager: GateJmapClient,
        managementAccountId: String,
        ownerAccountId: String,
        value: JsonElement,
    ) {
        val payload = registryPayload(
            response = manager.registryUpdate(
                objectType = "Account",
                objectId = ownerAccountId,
                patch = buildJsonObject {
                    put("quotas/maxAppPasswords", value)
                },
                accountId = managementAccountId,
            ),
            expectedMethod = "x:Account/set",
        )
        assertTrue((payload["notUpdated"] as? JsonObject).orEmpty().isEmpty())
        assertTrue(
            ownerAccountId in (payload["updated"] as? JsonObject).orEmpty(),
            "Account quota patch did not confirm the exact owner",
        )
    }

    private suspend fun cleanupReservedCredentials(
        enrollment: GateAppPasswordEnrollmentClient,
    ) {
        val credentials = enrollment.inventory()
            .filter {
                it.description.value in setOf(
                    QUOTA_DESCRIPTION.value,
                    QUOTA_REJECTED_DESCRIPTION.value,
                )
            }
        var cleanupFailure: Throwable? = null
        credentials.forEach { credential ->
            try {
                enrollment.destroy(credential.id)
            } catch (failure: Throwable) {
                cleanupFailure?.addSuppressed(failure)
                    ?: run { cleanupFailure = failure }
            }
        }
        try {
            assertTrue(
                enrollment.inventory().none {
                    it.description.value in setOf(
                        QUOTA_DESCRIPTION.value,
                        QUOTA_REJECTED_DESCRIPTION.value,
                    )
                },
                "Permission-matrix AppPasswords remained after cleanup",
            )
        } catch (failure: Throwable) {
            cleanupFailure?.addSuppressed(failure)
                ?: run { cleanupFailure = failure }
        }
        cleanupFailure?.let { throw it }
    }

    private fun appPasswordCredential(
        account: JsonObject,
        credentialId: String,
    ): JsonObject =
        credentials(account).single {
            requiredString(it, "@type") == "AppPassword" &&
                requiredString(it, "credentialId") == credentialId
        }

    private fun credentials(account: JsonObject): List<JsonObject> =
        requiredObject(account, "credentials").values.map(::requiredObject)

    private fun assertStoredAppPassword(
        value: GateStoredAppPassword,
        expectedId: String,
        expectedDescription: GateAppPasswordDescription,
    ) {
        assertEquals(expectedId, value.id)
        assertEquals(expectedDescription.value, value.description.value)
        assertEquals(DASHBOARD_MAIL_PERMISSIONS, value.permissions)
    }

    private fun requireOptionalPositiveQuota(value: JsonElement?) {
        if (value == null || value == JsonNull) return
        assertTrue(
            value.jsonPrimitive.longOrNull?.let { it > 0 } == true,
            "Existing maxAppPasswords quota was malformed",
        )
    }

    private fun requireAccountSession(
        session: GateJmapSession,
        expectedUsername: String,
    ): String {
        assertEquals(EXPECTED_API_URL, session.apiUrl)
        assertEquals(expectedUsername, session.username)
        return assertNotNull(session.primaryAccountId).also {
            assertTrue(it.isNotBlank())
        }
    }

    private fun appPasswordClient(
        live: StalwartLiveTestEnvironment,
        transport: GateHttpTransport,
        secret: CharArray,
    ): GateJmapClient =
        GateJmapClient(
            baseUrl = live.baseUrl,
            credential = GateCredential.basic(
                username = GateBootstrap.FIRST_USER_ADDRESS,
                secret = secret,
            ),
            transport = transport,
        )

    private fun registryPayload(
        response: JsonObject,
        expectedMethod: String,
    ): JsonObject {
        val responses = response["methodResponses"] as? JsonArray
        assertNotNull(responses, "$expectedMethod omitted methodResponses")
        assertEquals(1, responses.size)
        val tuple = responses.single() as? JsonArray
        assertNotNull(tuple, "$expectedMethod returned a malformed tuple")
        assertEquals(3, tuple.size)
        assertEquals(expectedMethod, requiredString(tuple[0]))
        assertTrue(requiredString(tuple[2]).isNotBlank())
        return requiredObject(tuple[1])
    }

    private fun requiredObject(value: JsonElement?): JsonObject =
        value as? JsonObject
            ?: throw AssertionError("Registry response object was absent or malformed")

    private fun requiredObject(
        value: JsonObject,
        property: String,
    ): JsonObject =
        requiredObject(value[property])

    private fun requiredArray(
        value: JsonObject,
        property: String,
    ): JsonArray =
        value[property] as? JsonArray
            ?: throw AssertionError("$property was absent or malformed")

    private fun requiredString(value: JsonElement): String {
        val primitive = value as? JsonPrimitive
        assertNotNull(primitive, "Registry response string was malformed")
        assertTrue(primitive.isString, "Registry response value was not a string")
        return primitive.content
    }

    private fun requiredString(
        value: JsonObject,
        property: String,
    ): String =
        value[property]?.let(::requiredString)
            ?: throw AssertionError("$property was absent")

    private fun strings(vararg values: String): JsonArray =
        JsonArray(values.map(::JsonPrimitive))

    private fun dashboardProjectRoot(): Path {
        val working = Paths.get(System.getProperty("user.dir"))
            .toAbsolutePath()
            .normalize()
        val candidate = if (working.fileName?.toString() == "dashboard-server") {
            assertNotNull(working.parent)
        } else {
            working
        }
        assertEquals("debug-dashboard", candidate.fileName?.toString())
        assertTrue(Files.isRegularFile(candidate.resolve("project.yaml")))
        return candidate.toRealPath()
    }

    private class ExpectedAppPassword(
        val id: String,
        val description: GateAppPasswordDescription,
    )

    private class DeniedOperation(
        val label: String,
        val call: suspend () -> JsonObject,
    )

    private companion object {
        val EXPECTED_API_URL: URI = URI("http://127.0.0.1:18443/jmap/")
        val MAIL_CAPABILITIES = listOf(
            GateJmapCapability.CORE,
            GateJmapCapability.MAIL,
            GateJmapCapability.SUBMISSION,
            GateJmapCapability.BLOB,
        )
        val DISALLOWED_APP_MAIL_OPERATIONS = setOf(
            "Identity/create",
            "Identity/update",
            "Identity/destroy",
            "EmailSubmission/update",
            "EmailSubmission/destroy",
        )
        val QUOTA_STORE_ID: UUID =
            UUID.fromString("f248608b-10b4-4a86-8fd8-b0261bf9c8e0")
        val QUOTA_DESCRIPTION =
            GateAppPasswordDescription.reserved(QUOTA_STORE_ID, 1u)
        val QUOTA_REJECTED_DESCRIPTION =
            GateAppPasswordDescription.reserved(QUOTA_STORE_ID, 2u)
    }
}
