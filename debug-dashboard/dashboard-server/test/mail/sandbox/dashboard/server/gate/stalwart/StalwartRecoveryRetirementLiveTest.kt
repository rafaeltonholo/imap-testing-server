package mail.sandbox.dashboard.server.gate.stalwart

import java.net.URI
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonPrimitive

class StalwartRecoveryRetirementLiveTest {
    @Test
    fun recoveryIsRetiredAndOnlyReviewedPersistentCredentialsRemain() = runBlocking {
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
            StalwartGateSecretFiles.readRecoveryHandoff(
                projectRoot = projectRoot,
                fixtureSecretsPath = live.fixtureSecretsPath,
            ).use { recovery ->
                KtorGateHttpTransport().use { transport ->
                    GateJmapClient(
                        baseUrl = live.baseUrl,
                        credential = GateCredential.bearer(fixture.managementApiKey),
                        transport = transport,
                    ).use { manager ->
                        // A successful bounded request separates retired authentication
                        // from an unavailable or otherwise unrelated endpoint failure.
                        val managerSession = manager.discoverSession()
                        assertSession(
                            session = managerSession,
                            expectedAccountId = fixture.managementAccountId,
                        )

                        GateJmapClient(
                            baseUrl = live.baseUrl,
                            credential = GateCredential.basic(
                                username = recovery.username,
                                secret = recovery.secret,
                            ),
                            transport = transport,
                        ).use { recoveryClient ->
                            assertRecoveryAuthenticationRejected(recoveryClient)
                        }

                        val firstUserSession = GateJmapClient(
                            baseUrl = live.baseUrl,
                            credential = GateCredential.basic(
                                username = GateBootstrap.FIRST_USER_ADDRESS,
                                secret = fixture.firstUserPassword,
                            ),
                            transport = transport,
                        ).use { it.discoverSession() }
                        assertSession(firstUserSession)

                        val secondUserSession = GateJmapClient(
                            baseUrl = live.baseUrl,
                            credential = GateCredential.basic(
                                username = GateBootstrap.SECOND_USER_ADDRESS,
                                secret = fixture.secondUserPassword,
                            ),
                            transport = transport,
                        ).use { it.discoverSession() }
                        assertSession(secondUserSession)

                        val firstUserId = assertNotNull(firstUserSession.primaryAccountId)
                        val secondUserId = assertNotNull(secondUserSession.primaryAccountId)
                        assertEquals(
                            3,
                            setOf(
                                fixture.managementAccountId,
                                firstUserId,
                                secondUserId,
                            ).size,
                            "Gate credentials must authenticate three distinct Accounts",
                        )

                        val managementAccount = requireSingleRegistryObject(
                            response = manager.registryGet(
                                objectType = "Account",
                                ids = listOf(fixture.managementAccountId),
                            ),
                            expectedMethod = "x:Account/get",
                        )
                        assertManagementAccount(
                            account = managementAccount,
                            expectedAccountId = fixture.managementAccountId,
                        )

                        val ordinaryAccounts = requireRegistryObjects(
                            response = manager.registryGet(
                                objectType = "Account",
                                ids = listOf(firstUserId, secondUserId),
                            ),
                            expectedMethod = "x:Account/get",
                        )
                        assertEquals(
                            setOf(firstUserId, secondUserId),
                            ordinaryAccounts.map(::accountId).toSet(),
                            "Account/get returned the wrong ordinary Accounts",
                        )
                        ordinaryAccounts.forEach(::assertPasswordOnlyOrdinaryAccount)
                    }
                }
            }
        }
    }

    private suspend fun assertRecoveryAuthenticationRejected(client: GateJmapClient) {
        val failure = assertFailsWith<GateJmapException> {
            client.discoverSession()
        }
        val status = (failure.kind as? GateJmapFailure.HttpStatus)?.status
        assertTrue(
            status == 401 || status == 403,
            "Retired recovery authentication failed for an unrelated reason",
        )
    }

    private fun assertSession(
        session: GateJmapSession,
        expectedAccountId: String? = null,
    ) {
        assertEquals(EXPECTED_API_URL, session.apiUrl)
        val primaryAccountId = assertNotNull(
            session.primaryAccountId,
            "Authenticated Session did not identify its primary Account",
        )
        assertTrue(primaryAccountId.isNotBlank())
        expectedAccountId?.let {
            assertEquals(it, primaryAccountId)
        }
    }

    private fun assertManagementAccount(
        account: JsonObject,
        expectedAccountId: String,
    ) {
        assertEquals(expectedAccountId, accountId(account))
        assertEquals("User", requiredString(account, "@type"))
        assertTypeTag(requiredObject(account, "roles"), "User")

        val credentials = requiredObject(account, "credentials")
        assertEquals(
            1,
            credentials.size,
            "Management Account must preserve exactly one credential",
        )
        val credential = credentials.values.single() as? JsonObject
        assertNotNull(credential, "Management credential is malformed")
        assertEquals("ApiKey", requiredString(credential, "@type"))
        assertTrue(requiredString(credential, "credentialId").isNotBlank())
        assertReplacePermissions(
            value = requiredObject(credential, "permissions"),
            permissionsProperty = "permissions",
            expected = GateBootstrap.managementPermissions,
        )

        assertReplacePermissions(
            value = requiredObject(account, "permissions"),
            permissionsProperty = "enabledPermissions",
            expected = GateBootstrap.managementPermissions,
        )
    }

    private fun assertPasswordOnlyOrdinaryAccount(account: JsonObject) {
        assertEquals("User", requiredString(account, "@type"))
        assertTypeTag(requiredObject(account, "roles"), "User")
        val credentials = requiredObject(account, "credentials")
        assertEquals(
            1,
            credentials.size,
            "Ordinary Account must contain exactly one normal Password",
        )
        val credential = credentials.values.single() as? JsonObject
        assertNotNull(credential, "Ordinary Account credential is malformed")
        assertEquals("Password", requiredString(credential, "@type"))
        assertFalse(
            credentials.values.any { value ->
                (value as? JsonObject)
                    ?.get("@type")
                    ?.jsonPrimitive
                    ?.content in setOf("ApiKey", "AppPassword")
            },
            "Ordinary Account unexpectedly contains a persistent dashboard credential",
        )
    }

    private fun assertReplacePermissions(
        value: JsonObject,
        permissionsProperty: String,
        expected: Set<String>,
    ) {
        assertTypeTag(value, "Replace")
        val permissions = requiredObject(value, permissionsProperty)
        assertTrue(
            permissions.values.all { it.jsonPrimitive.boolean },
            "Effective permission map contains a disabled or non-boolean value",
        )
        assertEquals(expected, permissions.keys)
        val disabledPermissions = value["disabledPermissions"] as? JsonObject
        if (disabledPermissions != null) {
            assertTrue(
                disabledPermissions.isEmpty(),
                "Replace permission object unexpectedly contains disabled permissions",
            )
        }
        assertFalse(permissions.keys.any { "*" in it })
    }

    private fun assertTypeTag(value: JsonObject, expected: String) {
        assertEquals(expected, requiredString(value, "@type"))
    }

    private fun requireSingleRegistryObject(
        response: JsonObject,
        expectedMethod: String,
    ): JsonObject {
        val objects = requireRegistryObjects(response, expectedMethod)
        assertEquals(1, objects.size, "Registry get did not return exactly one object")
        return objects.single()
    }

    private fun requireRegistryObjects(
        response: JsonObject,
        expectedMethod: String,
    ): List<JsonObject> {
        val methodResponses = response["methodResponses"] as? JsonArray
        assertNotNull(methodResponses, "Registry response omitted methodResponses")
        assertEquals(1, methodResponses.size, "Registry response contained extra methods")
        val method = methodResponses.single() as? JsonArray
        assertNotNull(method, "Registry method response is malformed")
        assertEquals(3, method.size, "Registry method response has an invalid tuple")
        assertEquals(expectedMethod, method[0].jsonPrimitive.content)
        val payload = method[1] as? JsonObject
        assertNotNull(payload, "Registry method payload is malformed")
        val notFound = payload["notFound"] as? JsonArray
        assertNotNull(notFound, "Registry get omitted notFound")
        assertTrue(notFound.isEmpty(), "Registry get reported a missing Account")
        val values = payload["list"] as? JsonArray
        assertNotNull(values, "Registry get omitted its object list")
        return values.map { value ->
            value as? JsonObject
                ?: throw AssertionError("Registry get returned a malformed object")
        }
    }

    private fun accountId(account: JsonObject): String =
        requiredString(account, "id")

    private fun requiredObject(value: JsonObject, property: String): JsonObject =
        value[property] as? JsonObject
            ?: throw AssertionError("$property is absent or malformed")

    private fun requiredString(value: JsonObject, property: String): String =
        value[property]?.jsonPrimitive?.content
            ?: throw AssertionError("$property is absent")

    private fun dashboardProjectRoot(): Path {
        val working = Paths.get(System.getProperty("user.dir"))
            .toAbsolutePath()
            .normalize()
        val candidate = if (working.fileName?.toString() == "dashboard-server") {
            assertNotNull(working.parent)
        } else {
            working
        }
        assertEquals(
            "debug-dashboard",
            candidate.fileName?.toString(),
            "Live gate must run from debug-dashboard or dashboard-server",
        )
        assertTrue(
            Files.isRegularFile(candidate.resolve("project.yaml")),
            "Live gate project root is missing project.yaml",
        )
        return candidate.toRealPath()
    }

    private companion object {
        val EXPECTED_API_URL: URI = URI("http://127.0.0.1:18443/jmap/")
    }
}
