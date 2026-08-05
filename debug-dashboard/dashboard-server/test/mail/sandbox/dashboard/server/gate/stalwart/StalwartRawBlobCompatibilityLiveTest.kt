package mail.sandbox.dashboard.server.gate.stalwart

import java.net.URI
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonPrimitive

class StalwartRawBlobCompatibilityLiveTest {
    @Test
    fun characterizesTheAcceptedLocalOnlyRawBlobBehavior() = runBlocking {
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
            KtorGateHttpTransport().use { jmapTransport ->
                val managementSession = GateJmapClient(
                    baseUrl = live.baseUrl,
                    credential = GateCredential.bearer(fixture.managementApiKey),
                    transport = jmapTransport,
                ).use { manager ->
                    manager.discoverSession().also { session ->
                        assertEquals(
                            fixture.managementAccountId,
                            session.primaryAccountId,
                        )
                        assertEquals(EXPECTED_API_URL, session.apiUrl)
                        assertExactManagementScope(
                            response = manager.registryGet(
                                objectType = "Account",
                                ids = listOf(fixture.managementAccountId),
                            ),
                            expectedAccountId = fixture.managementAccountId,
                        )
                    }
                }

                val ordinarySession = GateJmapClient(
                    baseUrl = live.baseUrl,
                    credential = GateCredential.basic(
                        username = GateBootstrap.FIRST_USER_ADDRESS,
                        secret = fixture.firstUserPassword,
                    ),
                    transport = jmapTransport,
                ).use { it.discoverSession() }
                assertEquals(EXPECTED_API_URL, ordinarySession.apiUrl)
                val ordinaryAccountId = assertNotNull(
                    ordinarySession.primaryAccountId,
                    "Ordinary Session did not identify its primary Account",
                )
                assertTrue(ordinaryAccountId.isNotBlank())
                assertFalse(ordinaryAccountId == fixture.managementAccountId)

                KtorGateRawBlobTransport().use { rawTransport ->
                    GateAppPasswordClient(
                        session = managementSession,
                        credential = GateCredential.bearer(fixture.managementApiKey),
                        transport = rawTransport,
                    ).use { rawClient ->
                        val managementProbes =
                            listOf(
                                probe(
                                    client = rawClient,
                                    target = GateRawBlobProbeTarget.MANAGEMENT_ACCOUNT,
                                    accountId = fixture.managementAccountId,
                                    payload = MANAGEMENT_PAYLOAD,
                                ),
                                probe(
                                    client = rawClient,
                                    target = GateRawBlobProbeTarget.ORDINARY_ACCOUNT,
                                    accountId = ordinaryAccountId,
                                    payload = ORDINARY_PAYLOAD,
                                ),
                            )
                        GateAppPasswordClient(
                            session = ordinarySession,
                            credential = GateCredential.basic(
                                username = GateBootstrap.FIRST_USER_ADDRESS,
                                secret = fixture.firstUserPassword,
                            ),
                            transport = rawTransport,
                        ).use { authorizedClient ->
                            val authorizedUpload = authorizedClient.rawUpload(
                                accountId = ordinaryAccountId,
                                payload = INDEPENDENT_PAYLOAD,
                            )
                            val seededBlob = when (authorizedUpload) {
                                is GateRawBlobUploadResult.Accepted -> authorizedUpload.blob
                                is GateRawBlobUploadResult.Denied ->
                                    throw AssertionError(
                                        "Authorized raw-blob seed upload was denied",
                                    )
                            }
                            val independentManagementDownload = rawClient.rawDownload(
                                accountId = ordinaryAccountId,
                                blobId = seededBlob.blobId,
                                expectedPayload = INDEPENDENT_PAYLOAD,
                            )

                            GateRawBlobCompatibility.requirePinnedLocalOnlyBehavior(
                                managementProbes = managementProbes,
                                independentDownload = GateRawBlobIndependentDownloadProbe(
                                    authorizedUpload = authorizedUpload,
                                    managementDownload = independentManagementDownload,
                                ),
                            )
                        }
                    }
                }
            }
        }
    }

    private suspend fun probe(
        client: GateAppPasswordClient,
        target: GateRawBlobProbeTarget,
        accountId: String,
        payload: ByteArray,
    ): GateRawBlobProbeResult {
        val upload = client.rawUpload(accountId, payload)
        val download = when (upload) {
            is GateRawBlobUploadResult.Denied -> null
            is GateRawBlobUploadResult.Accepted ->
                client.rawDownload(
                    accountId = accountId,
                    blobId = upload.blob.blobId,
                    expectedPayload = payload,
                )
        }
        return GateRawBlobProbeResult(
            target = target,
            upload = upload,
            download = download,
        )
    }

    private fun assertExactManagementScope(
        response: JsonObject,
        expectedAccountId: String,
    ) {
        val account = requireSingleRegistryObject(response)
        assertEquals(expectedAccountId, requiredString(account, "id"))
        assertEquals("User", requiredString(account, "@type"))
        assertReplacePermissions(
            value = requiredObject(account, "permissions"),
            permissionsProperty = "enabledPermissions",
        )

        val credentials = requiredObject(account, "credentials")
        assertEquals(
            1,
            credentials.size,
            "Management Account must contain exactly one credential",
        )
        val credential = credentials.values.single() as? JsonObject
        assertNotNull(credential, "Management credential is malformed")
        assertEquals("ApiKey", requiredString(credential, "@type"))
        assertReplacePermissions(
            value = requiredObject(credential, "permissions"),
            permissionsProperty = "permissions",
        )
    }

    private fun assertReplacePermissions(
        value: JsonObject,
        permissionsProperty: String,
    ) {
        assertEquals("Replace", requiredString(value, "@type"))
        val permissions = requiredObject(value, permissionsProperty)
        assertTrue(
            permissions.values.all { it.jsonPrimitive.boolean },
            "Management scope contains a disabled or non-boolean permission",
        )
        assertEquals(GateBootstrap.managementPermissions, permissions.keys)
    }

    private fun requireSingleRegistryObject(response: JsonObject): JsonObject {
        val methodResponses = response["methodResponses"] as? JsonArray
        assertNotNull(methodResponses, "Registry response omitted methodResponses")
        assertEquals(1, methodResponses.size, "Registry response contained extra methods")
        val method = methodResponses.single() as? JsonArray
        assertNotNull(method, "Registry method response is malformed")
        assertEquals(3, method.size, "Registry method response has an invalid tuple")
        assertEquals("x:Account/get", method[0].jsonPrimitive.content)
        val payload = method[1] as? JsonObject
        assertNotNull(payload, "Registry method payload is malformed")
        val notFound = payload["notFound"] as? JsonArray
        assertNotNull(notFound, "Registry get omitted notFound")
        assertTrue(notFound.isEmpty(), "Registry get reported a missing Account")
        val values = payload["list"] as? JsonArray
        assertNotNull(values, "Registry get omitted its object list")
        assertEquals(1, values.size, "Registry get returned the wrong Account count")
        return values.single() as? JsonObject
            ?: throw AssertionError("Registry get returned a malformed Account")
    }

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
        val MANAGEMENT_PAYLOAD =
            "mail-sandbox-gate0b-management-raw-blob-probe".encodeToByteArray()
        val ORDINARY_PAYLOAD =
            "mail-sandbox-gate0b-cross-account-raw-blob-probe".encodeToByteArray()
        val INDEPENDENT_PAYLOAD =
            "mail-sandbox-gate0b-independent-download-probe".encodeToByteArray()
    }
}
