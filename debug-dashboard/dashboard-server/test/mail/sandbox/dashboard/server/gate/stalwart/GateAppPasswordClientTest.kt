package mail.sandbox.dashboard.server.gate.stalwart

import java.net.URI
import java.util.UUID
import mail.sandbox.dashboard.server.provider.stalwart.credential.STALWART_REQUIRED_MAIL_CAPABILITIES
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartBorrowedSecret
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartCredentialProbeResult
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartMailCapability
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartMailAccount
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartNormalPassword
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartRemoteCreateResult
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartRemoteMutationResult
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartRemoteRead
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartReservedCredential
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

class GateAppPasswordClientTest {
    @Test
    fun enrollmentAcceptsOnlyTheInjectedEndpointProfileApiUrl() = runBlocking {
        val ownerAccountId = "account7"
        val ownerAddress =
            "dashboard-routing-sender-" +
                "0123456789abcdef0123456789abcdef@local.test"
        val registry = RecordingAppPasswordRegistry(
            session = GateJmapSession(
                apiUrl = StalwartEndpointProfile.MIGRATION_BOOTSTRAP.apiUrl,
                username = ownerAddress,
                primaryAccountId = ownerAccountId,
            ),
            queryResponses = listOf(
                registryResponse(
                    method = "x:AppPassword/query",
                    payload = """
                        {
                          "accountId":"$ownerAccountId",
                          "queryState":"state-1",
                          "canCalculateChanges":false,
                          "position":0,
                          "ids":[],
                          "total":0
                        }
                    """.trimIndent(),
                ),
            ),
        )

        val inventory = GateAppPasswordEnrollmentClient(
            registry = registry,
            ownerAccountId = ownerAccountId,
            ownerAddress = ownerAddress,
            endpointProfile = StalwartEndpointProfile.MIGRATION_BOOTSTRAP,
        ).inventory()

        assertTrue(inventory.isEmpty())
        assertEquals(1, registry.discoveryCount)
        assertEquals(1, registry.queryCount)
    }

    @Test
    fun createdSecretWrapperRejectsMalformedInputsAndUseAfterClose() {
        val description = GateAppPasswordDescription.reserved(
            storeId = UUID.fromString("0f34f2c8-779f-4cc2-b4be-e3a6ef8f27f8"),
            generation = 2u,
        )
        listOf(
            "" to "app_test-only".toCharArray(),
            "credential2" to "invalid-secret".toCharArray(),
        ).forEach { (id, secret) ->
            assertFailsWith<IllegalArgumentException> {
                GateCreatedAppPassword(
                    id = id,
                    description = description,
                    secret = secret,
                )
            }
        }

        val created = GateCreatedAppPassword(
            id = "credential2",
            description = description,
            secret = "app_test-only-read-once".toCharArray(),
        )
        created.close()
        created.close()

        assertFailsWith<IllegalStateException> {
            created.copySecret()
        }
    }

    @Test
    fun closingSpecializedClientsClosesTheirPrivateCredentialCopies() {
        val rawCredential = GateCredential.bearer("API_raw-close-marker".toCharArray())
        val rawClient = GateAppPasswordClient(
            session = GateJmapSession(
                apiUrl = URI("http://127.0.0.1:18443/jmap/"),
                username = GateBootstrap.MANAGEMENT_ADDRESS,
                primaryAccountId = "management7",
            ),
            credential = rawCredential,
            transport = RecordingRawBlobTransport(emptyList()),
        )
        val effectiveCredential = GateCredential.basic(
            username = GateBootstrap.FIRST_USER_ADDRESS,
            secret = "app_effective-close-marker".toCharArray(),
        )
        val effectiveClient = GateEffectivePermissionClient(
            baseUrl = URI("http://127.0.0.1:18443"),
            credential = effectiveCredential,
            transport = RecordingGateHttpTransport(emptyList()),
        )

        rawClient.close()
        effectiveClient.close()

        assertFailsWith<IllegalStateException> {
            rawCredential.authorizationHeader()
        }
        assertFailsWith<IllegalStateException> {
            effectiveCredential.authorizationHeader()
        }

        val invalidCredential = GateCredential.bearer(
            "API_invalid-effective-marker".toCharArray(),
        )
        assertFailsWith<IllegalArgumentException> {
            GateEffectivePermissionClient(
                baseUrl = URI("http://localhost:18443"),
                credential = invalidCredential,
                transport = RecordingGateHttpTransport(emptyList()),
            )
        }
        assertFailsWith<IllegalStateException> {
            invalidCredential.authorizationHeader()
        }
    }

    @Test
    fun rawBlobRequestsUseOnlyThePinnedLoopbackUrls() = runBlocking {
        val payload = "probe-payload".encodeToByteArray()
        val transport = RecordingRawBlobTransport(
            responses = listOf(
                { request ->
                    GateRawBlobHttpResponse(
                        status = 200,
                        effectiveUrl = request.url,
                        body = """
                            {
                              "accountId":"account7",
                              "blobId":"blob7",
                              "type":"application/octet-stream",
                              "size":${payload.size}
                            }
                        """.trimIndent().encodeToByteArray(),
                    )
                },
                { request ->
                    GateRawBlobHttpResponse(
                        status = 403,
                        effectiveUrl = request.url,
                        body = "rejected-body".encodeToByteArray(),
                    )
                },
            ),
        )
        val client = client(transport)

        client.use {
            val upload = assertIs<GateRawBlobUploadResult.Accepted>(
                it.rawUpload("account7", payload),
            )
            assertEquals("account7", upload.blob.accountId)
            assertEquals("blob7", upload.blob.blobId)
            assertEquals(payload.size, upload.blob.size)
            val download = assertIs<GateRawBlobDownloadResult.Denied>(
                it.rawDownload(
                    accountId = "account7",
                    blobId = upload.blob.blobId,
                    expectedPayload = payload,
                ),
            )
            assertEquals(403, download.status)
        }

        val uploadRequest = transport.requests[0]
        assertEquals("POST", uploadRequest.method)
        assertEquals(
            URI("http://127.0.0.1:18443/jmap/upload/account7"),
            uploadRequest.url,
        )
        assertEquals("application/octet-stream", uploadRequest.contentType)
        assertContentEquals(payload, uploadRequest.body)

        val downloadRequest = transport.requests[1]
        assertEquals("GET", downloadRequest.method)
        assertEquals(
            URI(
                "http://127.0.0.1:18443/jmap/download/" +
                    "account7/blob7/gate0b-probe.bin",
            ),
            downloadRequest.url,
        )
        assertEquals(null, downloadRequest.contentType)
        assertContentEquals(ByteArray(0), downloadRequest.body)
    }

    @Test
    fun onlyPermissionDenialStatusesCountAsDenied() = runBlocking {
        listOf(401, 403, 404).forEach { status ->
            val result = client(singleResponse(status)).use {
                it.rawUpload(
                    accountId = "account7",
                    payload = byteArrayOf(1),
                )
            }
            assertEquals(status, assertIs<GateRawBlobUploadResult.Denied>(result).status)
        }

        listOf(401, 403).forEach { status ->
            val result = client(singleResponse(status)).use {
                it.rawDownload(
                    accountId = "account7",
                    blobId = "blob7",
                    expectedPayload = byteArrayOf(1),
                )
            }
            assertEquals(status, assertIs<GateRawBlobDownloadResult.Denied>(result).status)
        }

        listOf(302, 400, 500).forEach { status ->
            val failure = assertFailsWith<GateRawBlobException> {
                client(singleResponse(status)).use {
                    it.rawUpload(
                        accountId = "account7",
                        payload = byteArrayOf(1),
                    )
                }
            }
            assertEquals(
                GateRawBlobFailure.UnexpectedStatus(status),
                failure.kind,
            )
        }

        val hiddenDownload = client(singleResponse(404)).use {
            it.rawDownload(
                accountId = "account7",
                blobId = "blob7",
                expectedPayload = byteArrayOf(1),
            )
        }
        assertEquals(
            404,
            assertIs<GateRawBlobDownloadResult.Denied>(hiddenDownload).status,
        )

        val acceptedPayload = byteArrayOf(1)
        val acceptedDownload = client(
            singleResponse(
                status = 200,
                body = acceptedPayload,
            ),
        ).use {
            it.rawDownload(
                accountId = "account7",
                blobId = "blob7",
                expectedPayload = acceptedPayload,
            )
        }
        assertEquals(
            GateRawBlobDownloadResult.Accepted(
                status = 200,
                byteCount = 1,
            ),
            acceptedDownload,
        )
    }

    @Test
    fun successfulUploadResponseMustBeExactTypedAndRedacted() = runBlocking {
        val marker = "server-controlled-secret-marker"
        listOf(
            """not-json-$marker""",
            """{"accountId":{"value":"$marker"},"blobId":"blob7","type":"application/octet-stream","size":1}""",
            """{"accountId":"account7","blobId":{"value":"$marker"},"type":"application/octet-stream","size":1}""",
            """{"accountId":"account7","blobId":"blob7","type":"$marker","size":1}""",
            """{"accountId":"account7","blobId":"blob7","type":"application/octet-stream","size":"$marker"}""",
            """{"accountId":"account7","blobId":"blob7","type":"application/octet-stream","size":"1"}""",
            """{"accountId":"$marker","blobId":"blob7","type":"application/octet-stream","size":1}""",
            """{"accountId":"account7","blobId":"blob7/$marker","type":"application/octet-stream","size":1}""",
            """{"accountId":"account7","blobId":"blob7","type":"application/octet-stream","size":2}""",
        ).forEach { body ->
            val failure = assertFailsWith<GateRawBlobException> {
                client(singleResponse(status = 200, body = body.encodeToByteArray()))
                    .use {
                        it.rawUpload(
                            accountId = "account7",
                            payload = byteArrayOf(1),
                        )
                    }
            }

            assertEquals(GateRawBlobFailure.InvalidResponse, failure.kind)
            assertFalse(failure.message.orEmpty().contains(marker))
            assertFalse(failure.toString().contains(marker))
        }
    }

    @Test
    fun successfulDownloadMustReturnTheExactProbePayloadWithoutDisclosure() =
        runBlocking {
            val marker = "download-probe-secret-marker"
            val expected = marker.encodeToByteArray()
            val accepted = client(
                singleResponse(
                    status = 200,
                    body = expected,
                ),
            ).use {
                it.rawDownload(
                    accountId = "account7",
                    blobId = "blob7",
                    expectedPayload = expected,
                )
            }
            assertEquals(
                expected.size,
                assertIs<GateRawBlobDownloadResult.Accepted>(accepted).byteCount,
            )

            val mismatch = assertFailsWith<GateRawBlobException> {
                client(
                    singleResponse(
                        status = 200,
                        body = "different-download".encodeToByteArray(),
                    ),
                ).use {
                    it.rawDownload(
                        accountId = "account7",
                        blobId = "blob7",
                        expectedPayload = expected,
                    )
                }
            }
            assertEquals(GateRawBlobFailure.InvalidResponse, mismatch.kind)
            assertFalse(mismatch.message.orEmpty().contains(marker))
            assertFalse(mismatch.toString().contains(marker))
        }

    @Test
    fun urlsRedirectsCredentialsAndBodiesFailClosedWithoutDisclosure() = runBlocking {
        listOf(
            "http://localhost:18443/jmap/",
            "http://127.0.0.1:8443/jmap/",
            "https://127.0.0.1:18443/jmap/",
            "http://gate-user@127.0.0.1:18443/jmap/",
            "http://127.0.0.1:18443/jmap/?query",
            "http://127.0.0.1:18443/jmap/#fragment",
            "http://127.0.0.1:18443/jmap",
            "http://127.0.0.1:18443/jmap/other",
        ).forEach { unsafe ->
            val credential = GateCredential.bearer("API_secret".toCharArray())
            assertFailsWith<IllegalArgumentException> {
                GateAppPasswordClient(
                    session = GateJmapSession(
                        apiUrl = URI(unsafe),
                        username = null,
                        primaryAccountId = null,
                    ),
                    credential = credential,
                    transport = singleResponse(403),
                )
            }
            assertFailsWith<IllegalStateException> {
                credential.authorizationHeader()
            }
        }

        val client = client(singleResponse(403))
        client.use {
            listOf("", "../other", "other/account", "other?query", "other#fragment")
                .forEach { unsafeAccountId ->
                    assertFailsWith<IllegalArgumentException> {
                        it.rawUpload(unsafeAccountId, byteArrayOf(1))
                    }
                }
        }

        val redirected = RecordingRawBlobTransport(
            listOf(
                {
                    GateRawBlobHttpResponse(
                        status = 403,
                        effectiveUrl = URI("http://127.0.0.1:18443/jmap/other"),
                        body = ByteArray(0),
                    )
                },
            ),
        )
        val redirectFailure = assertFailsWith<GateRawBlobException> {
            client(redirected).use {
                it.rawUpload("account7", byteArrayOf(1))
            }
        }
        assertEquals(GateRawBlobFailure.InvalidResponse, redirectFailure.kind)

        val credentialMarker = "credential-secret-marker"
        val bodyMarker = "body-secret-marker"
        GateCredential.bearer(credentialMarker.toCharArray()).use { credential ->
            val request = GateRawBlobHttpRequest(
                method = "POST",
                url = URI("http://127.0.0.1:18443/jmap/upload/account7"),
                credential = credential,
                contentType = "application/octet-stream",
                body = bodyMarker.encodeToByteArray(),
            )
            val response = GateRawBlobHttpResponse(
                status = 200,
                effectiveUrl = request.url,
                body = bodyMarker.encodeToByteArray(),
            )
            assertFalse(request.toString().contains(credentialMarker))
            assertFalse(request.toString().contains(bodyMarker))
            assertFalse(request.toString().contains("account7"))
            assertFalse(response.toString().contains(bodyMarker))
            assertFalse(response.toString().contains("account7"))
        }
    }

    @Test
    fun transportAndBodyReadCancellationRemainCooperativeAndFailuresAreRedacted() =
        runBlocking {
            val requestCancellation = CancellationException("request-cancel-marker")
            val requestThrown = assertFailsWith<CancellationException> {
                executeGateRawBlobTransportRequest {
                    throw requestCancellation
                }
            }
            assertSame(requestCancellation, requestThrown)

            val readCancellation = CancellationException("read-cancel-marker")
            val readThrown = assertFailsWith<CancellationException> {
                readGateRawBlobHttpResponse(
                    status = 200,
                    effectiveUrl = URI("http://127.0.0.1:18443/jmap/upload/account7"),
                ) {
                    throw readCancellation
                }
            }
            assertSame(readCancellation, readThrown)

            val marker = "transport-secret-marker"
            val readFailure = assertFailsWith<GateRawBlobException> {
                readGateRawBlobHttpResponse(
                    status = 201,
                    effectiveUrl = URI(
                        "http://127.0.0.1:18443/jmap/upload/account7",
                    ),
                ) {
                    throw IllegalStateException(marker)
                }
            }
            assertEquals(
                GateRawBlobFailure.ResponseBody(status = 201),
                readFailure.kind,
            )
            assertFalse(readFailure.message.orEmpty().contains(marker))
            assertFalse(readFailure.toString().contains(marker))

            val failure = assertFailsWith<GateRawBlobException> {
                executeGateRawBlobTransportRequest {
                    throw IllegalStateException(marker)
                }
            }
            assertEquals(GateRawBlobFailure.Transport, failure.kind)
            assertFalse(failure.message.orEmpty().contains(marker))
            assertFalse(failure.toString().contains(marker))
        }

    @Test
    fun isolationVerdictStopsOnAcceptedOperationsWithoutDisclosingBlobIds() {
        GateRawBlobIsolation.requireDenied(
            listOf(
                GateRawBlobProbeResult(
                    target = GateRawBlobProbeTarget.MANAGEMENT_ACCOUNT,
                    upload = GateRawBlobUploadResult.Denied(403),
                    download = null,
                ),
                GateRawBlobProbeResult(
                    target = GateRawBlobProbeTarget.ORDINARY_ACCOUNT,
                    upload = GateRawBlobUploadResult.Denied(404),
                    download = null,
                ),
            ),
        )

        val blobMarker = "blob-secret-marker"
        val accepted = GateRawBlobUploadResult.Accepted(
            GateUploadedBlob(
                accountId = "account7",
                blobId = blobMarker,
                size = 1,
            ),
        )
        val stop = assertFailsWith<GateRawBlobIsolationStop> {
            GateRawBlobIsolation.requireDenied(
                listOf(
                    GateRawBlobProbeResult(
                        target = GateRawBlobProbeTarget.MANAGEMENT_ACCOUNT,
                        upload = accepted,
                        download = GateRawBlobDownloadResult.Accepted(
                            status = 200,
                            byteCount = 1,
                        ),
                    ),
                    GateRawBlobProbeResult(
                        target = GateRawBlobProbeTarget.ORDINARY_ACCOUNT,
                        upload = accepted,
                        download = GateRawBlobDownloadResult.Denied(404),
                    ),
                ),
            )
        }

        assertEquals(
            setOf(
                GateRawBlobIsolationViolation.MANAGEMENT_ACCOUNT_UPLOAD_ACCEPTED,
                GateRawBlobIsolationViolation.MANAGEMENT_ACCOUNT_DOWNLOAD_ACCEPTED,
                GateRawBlobIsolationViolation.ORDINARY_ACCOUNT_UPLOAD_ACCEPTED,
            ),
            stop.violations,
        )
        assertTrue(stop.message.orEmpty().startsWith("STOP:"))
        assertFalse(stop.message.orEmpty().contains(blobMarker))
        assertFalse(stop.toString().contains(blobMarker))
    }

    @Test
    fun acceptedLocalOnlyCompatibilityRequiresAnIndependentAuthorizedSeed() {
        val blobMarker = "independent-blob-secret-marker"
        val accepted = GateRawBlobUploadResult.Accepted(
            GateUploadedBlob(
                accountId = "account7",
                blobId = blobMarker,
                size = 1,
            ),
        )
        val managementProbes = listOf(
            GateRawBlobProbeResult(
                target = GateRawBlobProbeTarget.MANAGEMENT_ACCOUNT,
                upload = accepted,
                download = GateRawBlobDownloadResult.Accepted(
                    status = 200,
                    byteCount = 1,
                ),
            ),
            GateRawBlobProbeResult(
                target = GateRawBlobProbeTarget.ORDINARY_ACCOUNT,
                upload = accepted,
                download = GateRawBlobDownloadResult.Denied(404),
            ),
        )

        GateRawBlobCompatibility.requirePinnedLocalOnlyBehavior(
            managementProbes = managementProbes,
            independentDownload = GateRawBlobIndependentDownloadProbe(
                authorizedUpload = accepted,
                managementDownload = GateRawBlobDownloadResult.Denied(404),
            ),
        )

        val mismatch = assertFailsWith<IllegalArgumentException> {
            GateRawBlobCompatibility.requirePinnedLocalOnlyBehavior(
                managementProbes = managementProbes,
                independentDownload = GateRawBlobIndependentDownloadProbe(
                    authorizedUpload = GateRawBlobUploadResult.Denied(403),
                    managementDownload = GateRawBlobDownloadResult.Denied(404),
                ),
            )
        }
        assertFalse(mismatch.message.orEmpty().contains(blobMarker))
        assertFalse(mismatch.toString().contains(blobMarker))
    }

    @Test
    fun enrollmentCreatesReadOnceReplaceCredentialThenInventoriesExactIds() =
        runBlocking {
            val ownerAccountId = "account7"
            val ownerAddress = "gate-one@local.test"
            val secretMarker = "app_test-only-read-once-marker"
            val credentialId = "credential2"
            val description = GateAppPasswordDescription.reserved(
                storeId = UUID.fromString("0f34f2c8-779f-4cc2-b4be-e3a6ef8f27f8"),
                generation = 2u,
            )
            val registry = RecordingAppPasswordRegistry(
                session = GateJmapSession(
                    apiUrl = URI("http://127.0.0.1:18443/jmap/"),
                    username = ownerAddress,
                    primaryAccountId = ownerAccountId,
                ),
                createResponses = listOf(
                    registryResponse(
                        method = "x:AppPassword/set",
                        payload = """
                            {
                              "accountId":"$ownerAccountId",
                              "created":{
                                "dashboard-app-password":{
                                  "id":"$credentialId",
                                  "secret":"$secretMarker"
                                }
                              },
                              "notCreated":{}
                            }
                        """.trimIndent(),
                    ),
                ),
                queryResponses = listOf(
                    registryResponse(
                        method = "x:AppPassword/query",
                        payload = """
                            {
                              "accountId":"$ownerAccountId",
                              "queryState":"state-1",
                              "canCalculateChanges":false,
                              "position":0,
                              "ids":["$credentialId"],
                              "total":1
                            }
                        """.trimIndent(),
                    ),
                ),
                getResponses = listOf(
                    registryResponse(
                        method = "x:AppPassword/get",
                        payload = """
                            {
                              "accountId":"$ownerAccountId",
                              "state":"state-1",
                              "list":[{
                                "id":"$credentialId",
                                "description":"${description.value}",
                                "secret":"****",
                                "permissions":{
                                  "@type":"Replace",
                                  "permissions":${permissionJson()}
                                },
                                "allowedIps":{}
                              }],
                              "notFound":[]
                            }
                        """.trimIndent(),
                    ),
                ),
            )
            val client = GateAppPasswordEnrollmentClient(
                registry = registry,
                ownerAccountId = ownerAccountId,
                ownerAddress = ownerAddress,
            )

            client.create(description).use { created ->
                assertEquals(credentialId, created.id)
                assertEquals(description.value, created.description.value)
                val secret = created.copySecret()
                try {
                    assertContentEquals(secretMarker.toCharArray(), secret)
                } finally {
                    secret.fill('\u0000')
                }
                assertFalse(created.toString().contains(secretMarker))
            }

            val create = registry.creates.single()
            assertEquals("AppPassword", create.objectType)
            assertEquals("dashboard-app-password", create.creationId)
            assertEquals(ownerAccountId, create.accountId)
            assertEquals(description.value, create.value["description"]?.jsonPrimitive?.content)
            assertEquals(buildJsonObject {}, create.value["allowedIps"])
            assertEquals(
                buildJsonObject {
                    put("@type", "Replace")
                    put("permissions", dashboardPermissionObject())
                },
                create.value["permissions"],
            )
            assertFalse("secret" in create.value)

            val inventory = client.inventory()
            assertEquals(listOf(credentialId), registry.gets.single().ids)
            assertEquals(ownerAccountId, registry.gets.single().accountId)
            assertEquals(1, inventory.size)
            assertEquals(credentialId, inventory.single().id)
            assertEquals(description.value, inventory.single().description.value)
            assertEquals(DASHBOARD_MAIL_PERMISSIONS, inventory.single().permissions)
            assertFalse(inventory.single().toString().contains(secretMarker))
        }

    @Test
    fun inventoryRejectsATruncatedQueryBeforeClaimingItIsComplete() =
        runBlocking {
            val ownerAccountId = "account7"
            val registry = RecordingAppPasswordRegistry(
                session = GateJmapSession(
                    apiUrl = URI("http://127.0.0.1:18443/jmap/"),
                    username = GateBootstrap.FIRST_USER_ADDRESS,
                    primaryAccountId = ownerAccountId,
                ),
                queryResponses = listOf(
                    registryResponse(
                        method = "x:AppPassword/query",
                        payload = """
                            {
                              "accountId":"$ownerAccountId",
                              "queryState":"state-1",
                              "canCalculateChanges":false,
                              "position":0,
                              "ids":["credential2"],
                              "total":2
                            }
                        """.trimIndent(),
                    ),
                ),
            )
            val client = GateAppPasswordEnrollmentClient(
                registry = registry,
                ownerAccountId = ownerAccountId,
                ownerAddress = GateBootstrap.FIRST_USER_ADDRESS,
            )

            val failure = assertFailsWith<GateJmapException> {
                client.inventory()
            }

            assertEquals(GateJmapFailure.InvalidResponse, failure.kind)
            assertEquals(1, registry.queryCount)
            assertTrue(registry.gets.isEmpty())
        }

    @Test
    fun inventoryRejectsStringEncodedQueryNumbers() = runBlocking {
        val ownerAccountId = "account7"
        listOf(
            "\"0\"" to "1",
            "0" to "\"1\"",
        ).forEach { (position, total) ->
            val registry = RecordingAppPasswordRegistry(
                session = GateJmapSession(
                    apiUrl = URI("http://127.0.0.1:18443/jmap/"),
                    username = GateBootstrap.FIRST_USER_ADDRESS,
                    primaryAccountId = ownerAccountId,
                ),
                queryResponses = listOf(
                    registryResponse(
                        method = "x:AppPassword/query",
                        payload = """
                            {
                              "accountId":"$ownerAccountId",
                              "queryState":"state-1",
                              "canCalculateChanges":false,
                              "position":$position,
                              "ids":["credential2"],
                              "total":$total
                            }
                        """.trimIndent(),
                    ),
                ),
            )
            val client = GateAppPasswordEnrollmentClient(
                registry = registry,
                ownerAccountId = ownerAccountId,
                ownerAddress = GateBootstrap.FIRST_USER_ADDRESS,
            )

            val failure = assertFailsWith<GateJmapException> {
                client.inventory()
            }

            assertEquals(GateJmapFailure.InvalidResponse, failure.kind)
            assertEquals(1, registry.queryCount)
            assertTrue(registry.gets.isEmpty())
        }
    }

    @Test
    fun enrollmentSurfacesQuotaSecretImmutabilityAndExactDestroySemantics() =
        runBlocking {
            val ownerAccountId = "account7"
            val ownerAddress = GateBootstrap.FIRST_USER_ADDRESS
            val credentialId = "credential2"
            val description = GateAppPasswordDescription.reserved(
                storeId = UUID.fromString("0f34f2c8-779f-4cc2-b4be-e3a6ef8f27f8"),
                generation = 2u,
            )
            val mutationMarker = "app_test-only-mutation-marker"
            val registry = RecordingAppPasswordRegistry(
                session = GateJmapSession(
                    apiUrl = URI("http://127.0.0.1:18443/jmap/"),
                    username = ownerAddress,
                    primaryAccountId = ownerAccountId,
                ),
                createResponses = listOf(
                    registryResponse(
                        method = "x:AppPassword/set",
                        payload = """
                            {
                              "accountId":"$ownerAccountId",
                              "created":{},
                              "notCreated":{
                                "dashboard-app-password":{
                                  "type":"overQuota",
                                  "description":"server-controlled"
                                }
                              }
                            }
                        """.trimIndent(),
                    ),
                ),
                updateResponses = listOf(
                    registryResponse(
                        method = "x:AppPassword/set",
                        payload = """
                            {
                              "accountId":"$ownerAccountId",
                              "updated":{},
                              "notUpdated":{
                                "$credentialId":{
                                  "type":"invalidPatch",
                                  "description":"server-controlled"
                                }
                              }
                            }
                        """.trimIndent(),
                    ),
                ),
                destroyResponses = listOf(
                    registryResponse(
                        method = "x:AppPassword/set",
                        payload = """
                            {
                              "accountId":"$ownerAccountId",
                              "destroyed":["$credentialId"],
                              "notDestroyed":{}
                            }
                        """.trimIndent(),
                    ),
                ),
            )
            val client = GateAppPasswordEnrollmentClient(
                registry = registry,
                ownerAccountId = ownerAccountId,
                ownerAddress = ownerAddress,
            )

            val quota = assertIs<GateAppPasswordCreateResult.Rejected>(
                client.tryCreate(description),
            )
            assertEquals("overQuota", quota.type)

            val denial = client.requireSecretUpdateRejected(
                credentialId = credentialId,
                replacement = mutationMarker.toCharArray(),
            )
            assertEquals("invalidPatch", denial.type)
            assertFalse(denial.toString().contains(mutationMarker))
            assertEquals(
                mutationMarker,
                registry.updates.single()
                    .patch
                    .getValue("secret")
                    .jsonPrimitive
                    .content,
            )

            client.destroy(credentialId)
            assertEquals(
                DestroyCall(
                    objectType = "AppPassword",
                    objectId = credentialId,
                    accountId = ownerAccountId,
                ),
                registry.destroys.single(),
            )
        }

    @Test
    fun lifecycleOwnerMapsOnlyPostDispatchCancellationToResponseLost() =
        runBlocking {
            val account = StalwartMailAccount(
                accountId = "account7",
                address = GateBootstrap.FIRST_USER_ADDRESS,
            )
            val baseUrl = URI("http://127.0.0.1:18443")
            val sessionResponse = GateHttpResponse(
                status = 200,
                effectiveUrl = baseUrl.resolve("/.well-known/jmap"),
                body = """
                    {
                      "apiUrl":"/jmap/",
                      "username":"${account.address}",
                      "primaryAccounts":{"urn:stalwart:jmap":"${account.accountId}"}
                    }
                """.trimIndent(),
            )
            val postDispatchCancellation =
                CancellationException("post-dispatch create cancellation")
            val postDispatchTransport = RecordingGateHttpTransport(
                responses = listOf(sessionResponse),
                failuresByCall = mapOf(2 to postDispatchCancellation),
            )
            val result = StalwartNormalPassword.takeOwnership(
                "owner-password".toCharArray(),
            ).use { password ->
                GateStalwartCredentialOwnerRemote(
                    baseUrl = baseUrl,
                    transport = postDispatchTransport,
                ).createOwned(
                    account = account,
                    description =
                        "mail-sandbox/debug-dashboard/" +
                            "0f34f2c8-779f-4cc2-b4be-e3a6ef8f27f8/2",
                    normalPassword = password,
                )
            }

            assertEquals(StalwartRemoteCreateResult.ResponseLost, result)
            assertEquals(2, postDispatchTransport.requests.size)

            val preDispatchCancellation =
                CancellationException("pre-dispatch create cancellation")
            val preDispatchTransport = RecordingGateHttpTransport(
                responses = emptyList(),
                failuresByCall = mapOf(1 to preDispatchCancellation),
            )
            val propagated = assertFailsWith<CancellationException> {
                StalwartNormalPassword.takeOwnership(
                    "owner-password".toCharArray(),
                ).use { password ->
                    GateStalwartCredentialOwnerRemote(
                        baseUrl = baseUrl,
                        transport = preDispatchTransport,
                    ).createOwned(
                        account = account,
                        description =
                            "mail-sandbox/debug-dashboard/" +
                                "0f34f2c8-779f-4cc2-b4be-e3a6ef8f27f8/2",
                        normalPassword = password,
                    )
                }
            }
            assertSame(preDispatchCancellation, propagated)
            assertEquals(1, preDispatchTransport.requests.size)
        }

    @Test
    fun secretMutationDenialRequiresAnExactlyEmptyUpdatedMap() = runBlocking {
        val ownerAccountId = "account7"
        val credentialId = "credential2"
        val registry = RecordingAppPasswordRegistry(
            session = GateJmapSession(
                apiUrl = URI("http://127.0.0.1:18443/jmap/"),
                username = GateBootstrap.FIRST_USER_ADDRESS,
                primaryAccountId = ownerAccountId,
            ),
            updateResponses = listOf(
                registryResponse(
                    method = "x:AppPassword/set",
                    payload = """
                        {
                          "accountId":"$ownerAccountId",
                          "updated":{"unrelated":null},
                          "notUpdated":{
                            "$credentialId":{"type":"invalidPatch"}
                          }
                        }
                    """.trimIndent(),
                ),
            ),
        )
        val client = GateAppPasswordEnrollmentClient(
            registry = registry,
            ownerAccountId = ownerAccountId,
            ownerAddress = GateBootstrap.FIRST_USER_ADDRESS,
        )

        val failure = assertFailsWith<GateJmapException> {
            client.requireSecretUpdateRejected(
                credentialId = credentialId,
                replacement = "replacement-marker".toCharArray(),
            )
        }

        assertEquals(GateJmapFailure.InvalidResponse, failure.kind)
    }

    @Test
    fun inventoryTurnsMalformedPermissionValuesIntoTypedFailures() = runBlocking {
        val ownerAccountId = "account7"
        val description = GateAppPasswordDescription.reserved(
            storeId = UUID.fromString("0f34f2c8-779f-4cc2-b4be-e3a6ef8f27f8"),
            generation = 2u,
        )
        val malformedPermissions = permissionJson().replace(
            oldValue = "\"authenticate\":true",
            newValue = "\"authenticate\":{}",
        )
        val registry = RecordingAppPasswordRegistry(
            session = GateJmapSession(
                apiUrl = URI("http://127.0.0.1:18443/jmap/"),
                username = GateBootstrap.FIRST_USER_ADDRESS,
                primaryAccountId = ownerAccountId,
            ),
            queryResponses = listOf(
                registryResponse(
                    method = "x:AppPassword/query",
                    payload = """
                        {
                          "accountId":"$ownerAccountId",
                          "position":0,
                          "ids":["credential2"],
                          "total":1
                        }
                    """.trimIndent(),
                ),
            ),
            getResponses = listOf(
                registryResponse(
                    method = "x:AppPassword/get",
                    payload = """
                        {
                          "accountId":"$ownerAccountId",
                          "list":[{
                            "id":"credential2",
                            "description":"${description.value}",
                            "secret":"****",
                            "permissions":{
                              "@type":"Replace",
                              "permissions":$malformedPermissions
                            },
                            "allowedIps":{}
                          }],
                          "notFound":[]
                        }
                    """.trimIndent(),
                ),
            ),
        )
        val client = GateAppPasswordEnrollmentClient(
            registry = registry,
            ownerAccountId = ownerAccountId,
            ownerAddress = GateBootstrap.FIRST_USER_ADDRESS,
        )

        val failure = assertFailsWith<GateJmapException> {
            client.inventory()
        }

        assertEquals(GateJmapFailure.InvalidResponse, failure.kind)
    }

    @Test
    fun inventoryRejectsStringEncodedPermissionBooleans() = runBlocking {
        val ownerAccountId = "account7"
        val description = GateAppPasswordDescription.reserved(
            storeId = UUID.fromString("0f34f2c8-779f-4cc2-b4be-e3a6ef8f27f8"),
            generation = 2u,
        )
        val malformedPermissions = permissionJson().replace(
            oldValue = "\"authenticate\":true",
            newValue = "\"authenticate\":\"true\"",
        )
        val registry = RecordingAppPasswordRegistry(
            session = GateJmapSession(
                apiUrl = URI("http://127.0.0.1:18443/jmap/"),
                username = GateBootstrap.FIRST_USER_ADDRESS,
                primaryAccountId = ownerAccountId,
            ),
            queryResponses = listOf(
                registryResponse(
                    method = "x:AppPassword/query",
                    payload = """
                        {
                          "accountId":"$ownerAccountId",
                          "position":0,
                          "ids":["credential2"],
                          "total":1
                        }
                    """.trimIndent(),
                ),
            ),
            getResponses = listOf(
                registryResponse(
                    method = "x:AppPassword/get",
                    payload = """
                        {
                          "accountId":"$ownerAccountId",
                          "list":[{
                            "id":"credential2",
                            "description":"${description.value}",
                            "secret":"****",
                            "permissions":{
                              "@type":"Replace",
                              "permissions":$malformedPermissions
                            },
                            "allowedIps":{}
                          }],
                          "notFound":[]
                        }
                    """.trimIndent(),
                ),
            ),
        )
        val client = GateAppPasswordEnrollmentClient(
            registry = registry,
            ownerAccountId = ownerAccountId,
            ownerAddress = GateBootstrap.FIRST_USER_ADDRESS,
        )

        val failure = assertFailsWith<GateJmapException> {
            client.inventory()
        }

        assertEquals(GateJmapFailure.InvalidResponse, failure.kind)
    }

    @Test
    fun protectedManagementAccountEnrollmentIsRejectedBeforeTransport() {
        val registry = RecordingAppPasswordRegistry(
            session = GateJmapSession(
                apiUrl = URI("http://127.0.0.1:18443/jmap/"),
                username = GateBootstrap.MANAGEMENT_ADDRESS,
                primaryAccountId = "management7",
            ),
        )

        assertFailsWith<IllegalArgumentException> {
            GateAppPasswordEnrollmentClient(
                registry = registry,
                ownerAccountId = "management7",
                ownerAddress = GateBootstrap.MANAGEMENT_ADDRESS,
            )
        }

        assertEquals(0, registry.callCount)
    }

    @Test
    fun managementRevocationUsesFreshPositionAndReconcilesByStableCredentialId() =
        runBlocking {
            val managementAccountId = "management7"
            val targetAccountId = "account7"
            val targetCredentialId = "credential2"
            val targetDescription = GateAppPasswordDescription.reserved(
                storeId = UUID.fromString("0f34f2c8-779f-4cc2-b4be-e3a6ef8f27f8"),
                generation = 2u,
            )
            val before = accountGetResponse(
                requestAccountId = managementAccountId,
                objectAccountId = targetAccountId,
                credentials = """
                    {
                      "0":${passwordCredential()},
                      "17":${appPasswordCredential(
                          credentialId = targetCredentialId,
                          description = targetDescription.value,
                      )},
                      "49":${appPasswordCredential(
                          credentialId = "credential3",
                          description = "team-owned/unrelated",
                      )}
                    }
                """.trimIndent(),
            )
            val after = accountGetResponse(
                requestAccountId = managementAccountId,
                objectAccountId = targetAccountId,
                credentials = """
                    {
                      "8":${passwordCredential()},
                      "3":${appPasswordCredential(
                          credentialId = "credential3",
                          description = "team-owned/unrelated",
                      )}
                    }
                """.trimIndent(),
            )
            val registry = RecordingAppPasswordRegistry(
                session = GateJmapSession(
                    apiUrl = URI("http://127.0.0.1:18443/jmap/"),
                    username = GateBootstrap.MANAGEMENT_ADDRESS,
                    primaryAccountId = managementAccountId,
                ),
                getResponses = listOf(before, after),
                updateResponses = listOf(
                    registryResponse(
                        method = "x:Account/set",
                        payload = """
                            {
                              "accountId":"$managementAccountId",
                              "updated":{"$targetAccountId":null},
                              "notUpdated":{}
                            }
                        """.trimIndent(),
                    ),
                ),
            )

            val result = GateManagementAppPasswordRevoker(
                registry = registry,
                managementAccountId = managementAccountId,
            ).revoke(
                targetAccountId = targetAccountId,
                targetCredentialId = targetCredentialId,
                expectedDescription = targetDescription,
            )

            assertIs<GateTargetedRevocationResult.Revoked>(result)
            val update = registry.updates.single()
            assertEquals("Account", update.objectType)
            assertEquals(targetAccountId, update.objectId)
            assertEquals(managementAccountId, update.accountId)
            assertEquals(
                buildJsonObject {
                    put("credentials/17", JsonNull)
                },
                update.patch,
            )
            assertFalse("ifInState" in update.patch)
            assertEquals(2, registry.gets.size)
            assertEquals(
                List(2) {
                    GetCall(
                        objectType = "Account",
                        ids = listOf(targetAccountId),
                        accountId = managementAccountId,
                    )
                },
                registry.gets,
            )
        }

    @Test
    fun lifecycleManagementInventoryCountsAllAppPasswordsAndParsesQuota() =
        runBlocking {
            val managementAccountId = "management7"
            val targetAccountId = "account7"
            val reserved = StalwartReservedCredential(
                credentialId = "credential2",
                description =
                    "mail-sandbox/debug-dashboard/" +
                        "0f34f2c8-779f-4cc2-b4be-e3a6ef8f27f8/2",
            )
            val registry = RecordingAppPasswordRegistry(
                session = GateJmapSession(
                    apiUrl = URI("http://127.0.0.1:18443/jmap/"),
                    username = GateBootstrap.MANAGEMENT_ADDRESS,
                    primaryAccountId = managementAccountId,
                ),
                getResponses = listOf(
                    accountGetResponse(
                        requestAccountId = managementAccountId,
                        objectAccountId = targetAccountId,
                        credentials = """
                            {
                              "0":${passwordCredential()},
                              "17":${appPasswordCredential(
                                  credentialId = reserved.credentialId,
                                  description = reserved.description,
                              )},
                              "49":${appPasswordCredential(
                                  credentialId = "credential3",
                                  description = "team-owned/unrelated",
                              )}
                            }
                        """.trimIndent(),
                        quotas = """{"maxAppPasswords":3}""",
                    ),
                ),
            )

            val result = GateStalwartCredentialManagementRemote(
                registry = registry,
                managementAccountId = managementAccountId,
                protectedAccountIds = setOf(managementAccountId),
            ).inventory(targetAccountId)

            val inventory =
                assertIs<StalwartRemoteRead.Available<*>>(result).value
            val typed = assertIs<
                mail.sandbox.dashboard.server.provider.stalwart.credential.
                    StalwartReservedInventory
                >(inventory)
            assertEquals(targetAccountId, typed.accountId)
            assertEquals(listOf(reserved), typed.reserved)
            assertEquals(2, typed.appPasswordCount)
            assertEquals(3, typed.appPasswordLimit)
            assertEquals(1, registry.gets.size)
        }

    @Test
    fun lifecycleManagementRevokesOneExactBatchIncludingProtectedAccount() =
        runBlocking {
            val managementAccountId = "management7"
            val first = StalwartReservedCredential(
                credentialId = "credential2",
                description =
                    "mail-sandbox/debug-dashboard/" +
                        "0f34f2c8-779f-4cc2-b4be-e3a6ef8f27f8/2",
            )
            val second = StalwartReservedCredential(
                credentialId = "credential4",
                description =
                    "mail-sandbox/debug-dashboard/" +
                        "0f34f2c8-779f-4cc2-b4be-e3a6ef8f27f8/4",
            )
            val sibling = appPasswordCredential(
                credentialId = "credential3",
                description = "team-owned/unrelated",
            )
            val registry = RecordingAppPasswordRegistry(
                session = GateJmapSession(
                    apiUrl = URI("http://127.0.0.1:18443/jmap/"),
                    username = GateBootstrap.MANAGEMENT_ADDRESS,
                    primaryAccountId = managementAccountId,
                ),
                getResponses = listOf(
                    accountGetResponse(
                        requestAccountId = managementAccountId,
                        objectAccountId = managementAccountId,
                        credentials = """
                            {
                              "0":${passwordCredential()},
                              "17":${appPasswordCredential(
                                  credentialId = first.credentialId,
                                  description = first.description,
                              )},
                              "29":${appPasswordCredential(
                                  credentialId = second.credentialId,
                                  description = second.description,
                              )},
                              "49":$sibling
                            }
                        """.trimIndent(),
                    ),
                    accountGetResponse(
                        requestAccountId = managementAccountId,
                        objectAccountId = managementAccountId,
                        credentials = """
                            {
                              "8":${passwordCredential()},
                              "3":$sibling
                            }
                        """.trimIndent(),
                    ),
                ),
                updateResponses = listOf(
                    registryResponse(
                        method = "x:Account/set",
                        payload = """
                            {
                              "accountId":"$managementAccountId",
                              "updated":{"$managementAccountId":null},
                              "notUpdated":{}
                            }
                        """.trimIndent(),
                    ),
                ),
            )

            val result = GateStalwartCredentialManagementRemote(
                registry = registry,
                managementAccountId = managementAccountId,
                protectedAccountIds = setOf(managementAccountId),
            ).revokeReserved(
                accountId = managementAccountId,
                expected = setOf(first, second),
            )

            assertEquals(StalwartRemoteMutationResult.Verified, result)
            assertEquals(
                buildJsonObject {
                    put("credentials/17", JsonNull)
                    put("credentials/29", JsonNull)
                },
                registry.updates.single().patch,
            )
            assertEquals(1, registry.updates.size)
            assertEquals(2, registry.gets.size)
        }

    @Test
    fun lifecycleManagementRevokesOnlyTheTargetFromAnExactReservedInventory() =
        runBlocking {
            val managementAccountId = "management7"
            val targetAccountId = "account7"
            val old = StalwartReservedCredential(
                credentialId = "credential2",
                description =
                    "mail-sandbox/debug-dashboard/" +
                        "0f34f2c8-779f-4cc2-b4be-e3a6ef8f27f8/2",
            )
            val successor = StalwartReservedCredential(
                credentialId = "credential3",
                description =
                    "mail-sandbox/debug-dashboard/" +
                        "0f34f2c8-779f-4cc2-b4be-e3a6ef8f27f8/3",
            )
            val registry = RecordingAppPasswordRegistry(
                session = GateJmapSession(
                    apiUrl = URI("http://127.0.0.1:18443/jmap/"),
                    username = GateBootstrap.MANAGEMENT_ADDRESS,
                    primaryAccountId = managementAccountId,
                ),
                getResponses = listOf(
                    accountGetResponse(
                        requestAccountId = managementAccountId,
                        objectAccountId = targetAccountId,
                        credentials = """
                            {
                              "0":${passwordCredential()},
                              "17":${appPasswordCredential(
                                  credentialId = old.credentialId,
                                  description = old.description,
                              )},
                              "29":${appPasswordCredential(
                                  credentialId = successor.credentialId,
                                  description = successor.description,
                              )}
                            }
                        """.trimIndent(),
                    ),
                    accountGetResponse(
                        requestAccountId = managementAccountId,
                        objectAccountId = targetAccountId,
                        credentials = """
                            {
                              "0":${passwordCredential()},
                              "29":${appPasswordCredential(
                                  credentialId = successor.credentialId,
                                  description = successor.description,
                              )}
                            }
                        """.trimIndent(),
                    ),
                ),
                updateResponses = listOf(
                    registryResponse(
                        method = "x:Account/set",
                        payload = """
                            {
                              "accountId":"$managementAccountId",
                              "updated":{"$targetAccountId":null},
                              "notUpdated":{}
                            }
                        """.trimIndent(),
                    ),
                ),
            )

            val result = GateStalwartCredentialManagementRemote(
                registry = registry,
                managementAccountId = managementAccountId,
                protectedAccountIds = setOf(managementAccountId),
            ).revokeReserved(
                accountId = targetAccountId,
                expected = setOf(old, successor),
                targets = setOf(old),
            )

            assertEquals(StalwartRemoteMutationResult.Verified, result)
            assertEquals(
                buildJsonObject {
                    put("credentials/17", JsonNull)
                },
                registry.updates.single().patch,
            )
            assertEquals(2, registry.gets.size)
        }

    @Test
    fun lifecycleManagementRejectsAReservedListThatChangedBeforeDispatch() =
        runBlocking {
            val managementAccountId = "management7"
            val targetAccountId = "account7"
            val expected = StalwartReservedCredential(
                credentialId = "credential2",
                description =
                    "mail-sandbox/debug-dashboard/" +
                        "0f34f2c8-779f-4cc2-b4be-e3a6ef8f27f8/2",
            )
            val newlyObserved = StalwartReservedCredential(
                credentialId = "credential3",
                description =
                    "mail-sandbox/debug-dashboard/" +
                        "0f34f2c8-779f-4cc2-b4be-e3a6ef8f27f8/3",
            )
            val sibling = appPasswordCredential(
                credentialId = "credential4",
                description = "team-owned/unrelated",
            )
            val registry = RecordingAppPasswordRegistry(
                session = GateJmapSession(
                    apiUrl = URI("http://127.0.0.1:18443/jmap/"),
                    username = GateBootstrap.MANAGEMENT_ADDRESS,
                    primaryAccountId = managementAccountId,
                ),
                getResponses = listOf(
                    accountGetResponse(
                        requestAccountId = managementAccountId,
                        objectAccountId = targetAccountId,
                        credentials = """
                            {
                              "0":${passwordCredential()},
                              "17":${appPasswordCredential(
                                  credentialId = expected.credentialId,
                                  description = expected.description,
                              )},
                              "29":${appPasswordCredential(
                                  credentialId = newlyObserved.credentialId,
                                  description = newlyObserved.description,
                              )},
                              "49":$sibling
                            }
                        """.trimIndent(),
                    ),
                    accountGetResponse(
                        requestAccountId = managementAccountId,
                        objectAccountId = targetAccountId,
                        credentials = """
                            {
                              "0":${passwordCredential()},
                              "29":${appPasswordCredential(
                                  credentialId = newlyObserved.credentialId,
                                  description = newlyObserved.description,
                              )},
                              "49":$sibling
                            }
                        """.trimIndent(),
                    ),
                ),
                updateResponses = listOf(
                    registryResponse(
                        method = "x:Account/set",
                        payload = """
                            {
                              "accountId":"$managementAccountId",
                              "updated":{"$targetAccountId":null},
                              "notUpdated":{}
                            }
                        """.trimIndent(),
                    ),
                ),
            )

            val result = GateStalwartCredentialManagementRemote(
                registry = registry,
                managementAccountId = managementAccountId,
                protectedAccountIds = setOf(managementAccountId),
            ).revokeReserved(
                accountId = targetAccountId,
                expected = setOf(expected),
            )

            assertEquals(
                StalwartRemoteMutationResult.ReconciliationRequired,
                result,
            )
            assertTrue(registry.updates.isEmpty())
            assertEquals(1, registry.gets.size)
        }

    @Test
    fun lifecycleManagementVerifiesAfterPostDispatchCancellation() =
        runBlocking {
            val managementAccountId = "management7"
            val targetAccountId = "account7"
            val target = StalwartReservedCredential(
                credentialId = "credential2",
                description =
                    "mail-sandbox/debug-dashboard/" +
                        "0f34f2c8-779f-4cc2-b4be-e3a6ef8f27f8/2",
            )
            val before = accountGetResponse(
                requestAccountId = managementAccountId,
                objectAccountId = targetAccountId,
                credentials = """
                    {
                      "0":${passwordCredential()},
                      "17":${appPasswordCredential(
                          credentialId = target.credentialId,
                          description = target.description,
                      )}
                    }
                """.trimIndent(),
            )
            val after = accountGetResponse(
                requestAccountId = managementAccountId,
                objectAccountId = targetAccountId,
                credentials = """{"0":${passwordCredential()}}""",
            )
            val updateCancellation =
                CancellationException("post-dispatch revoke cancellation")
            val registry = RecordingAppPasswordRegistry(
                session = GateJmapSession(
                    apiUrl = URI("http://127.0.0.1:18443/jmap/"),
                    username = GateBootstrap.MANAGEMENT_ADDRESS,
                    primaryAccountId = managementAccountId,
                ),
                getResponses = listOf(before, after),
                updateFailures = listOf(updateCancellation),
            )

            val result = GateStalwartCredentialManagementRemote(
                registry = registry,
                managementAccountId = managementAccountId,
                protectedAccountIds = setOf(managementAccountId),
            ).revokeReserved(
                accountId = targetAccountId,
                expected = setOf(target),
            )

            assertEquals(StalwartRemoteMutationResult.Verified, result)
            assertEquals(1, registry.updates.size)
            assertEquals(2, registry.gets.size)
        }

    @Test
    fun lifecycleManagementPropagatesCancellationBeforeMutationDispatch() =
        runBlocking {
            val managementAccountId = "management7"
            val targetAccountId = "account7"
            val target = StalwartReservedCredential(
                credentialId = "credential2",
                description =
                    "mail-sandbox/debug-dashboard/" +
                        "0f34f2c8-779f-4cc2-b4be-e3a6ef8f27f8/2",
            )
            val preDispatchCancellation =
                CancellationException("pre-dispatch revoke cancellation")
            val registry = RecordingAppPasswordRegistry(
                session = GateJmapSession(
                    apiUrl = URI("http://127.0.0.1:18443/jmap/"),
                    username = GateBootstrap.MANAGEMENT_ADDRESS,
                    primaryAccountId = managementAccountId,
                ),
                getFailuresByCall = mapOf(1 to preDispatchCancellation),
            )

            val propagated = assertFailsWith<CancellationException> {
                GateStalwartCredentialManagementRemote(
                    registry = registry,
                    managementAccountId = managementAccountId,
                    protectedAccountIds = setOf(managementAccountId),
                ).revokeReserved(
                    accountId = targetAccountId,
                    expected = setOf(target),
                )
            }

            assertSame(preDispatchCancellation, propagated)
            assertTrue(registry.updates.isEmpty())
            assertEquals(1, registry.gets.size)
        }

    @Test
    fun lifecycleGlobalInventoryRequiresCompleteQueryAndIncludesProtected() =
        runBlocking {
            val managementAccountId = "management7"
            val ordinaryAccountId = "account7"
            val reserved = StalwartReservedCredential(
                credentialId = "credential2",
                description =
                    "mail-sandbox/debug-dashboard/" +
                        "0f34f2c8-779f-4cc2-b4be-e3a6ef8f27f8/2",
            )
            val completeRegistry = RecordingAppPasswordRegistry(
                session = GateJmapSession(
                    apiUrl = URI("http://127.0.0.1:18443/jmap/"),
                    username = GateBootstrap.MANAGEMENT_ADDRESS,
                    primaryAccountId = managementAccountId,
                ),
                queryResponses = listOf(
                    accountQueryResponse(
                        requestAccountId = managementAccountId,
                        ids = listOf(managementAccountId, ordinaryAccountId),
                        total = 2,
                    ),
                    accountQueryResponse(
                        requestAccountId = managementAccountId,
                        ids = listOf(managementAccountId, ordinaryAccountId),
                        total = 2,
                    ),
                ),
                getResponses = listOf(
                    accountsGetResponse(
                        requestAccountId = managementAccountId,
                        accounts = listOf(
                            accountObject(
                                managementAccountId,
                                """{"0":${passwordCredential()}}""",
                            ),
                            accountObject(
                                ordinaryAccountId,
                                """
                                    {
                                      "0":${passwordCredential()},
                                      "17":${appPasswordCredential(
                                          reserved.credentialId,
                                          reserved.description,
                                      )}
                                    }
                                """.trimIndent(),
                            ),
                        ),
                    ),
                ),
            )
            val remote = GateStalwartCredentialManagementRemote(
                registry = completeRegistry,
                managementAccountId = managementAccountId,
                protectedAccountIds = setOf(managementAccountId),
            )

            val available =
                assertIs<StalwartRemoteRead.Available<*>>(
                    remote.globalInventory(),
                )
            val global = assertIs<
                mail.sandbox.dashboard.server.provider.stalwart.credential.
                    StalwartGlobalReservedInventory
                >(available.value)
            assertEquals(
                listOf(managementAccountId, ordinaryAccountId),
                global.accounts.map { it.accountId },
            )
            assertTrue(global.accounts.first().protectedIdentity)
            assertEquals(listOf(reserved), global.accounts.last().reserved)

            val incompleteRegistry = RecordingAppPasswordRegistry(
                session = GateJmapSession(
                    apiUrl = URI("http://127.0.0.1:18443/jmap/"),
                    username = GateBootstrap.MANAGEMENT_ADDRESS,
                    primaryAccountId = managementAccountId,
                ),
                queryResponses = listOf(
                    accountQueryResponse(
                        requestAccountId = managementAccountId,
                        ids = listOf(managementAccountId),
                        total = 2,
                    ),
                ),
            )
            val incomplete = GateStalwartCredentialManagementRemote(
                registry = incompleteRegistry,
                managementAccountId = managementAccountId,
                protectedAccountIds = setOf(managementAccountId),
            ).globalInventory()
            assertIs<StalwartRemoteRead.Unavailable>(incomplete)
            assertTrue(incompleteRegistry.gets.isEmpty())
        }

    @Test
    fun lifecycleGlobalInventoryCollectsEveryAccountQueryPage() =
        runBlocking {
            val managementAccountId = "management7"
            val firstAccountId = "account7"
            val secondAccountId = "account8"
            val registry = RecordingAppPasswordRegistry(
                session = GateJmapSession(
                    apiUrl = URI("http://127.0.0.1:18443/jmap/"),
                    username = GateBootstrap.MANAGEMENT_ADDRESS,
                    primaryAccountId = managementAccountId,
                ),
                queryResponses = listOf(
                    accountQueryResponse(
                        requestAccountId = managementAccountId,
                        ids = listOf(managementAccountId, firstAccountId),
                        total = 3,
                    ),
                    accountQueryResponse(
                        requestAccountId = managementAccountId,
                        ids = listOf(secondAccountId),
                        total = 3,
                        position = 2,
                    ),
                    accountQueryResponse(
                        requestAccountId = managementAccountId,
                        ids = listOf(managementAccountId, firstAccountId),
                        total = 3,
                    ),
                    accountQueryResponse(
                        requestAccountId = managementAccountId,
                        ids = listOf(secondAccountId),
                        total = 3,
                        position = 2,
                    ),
                ),
                getResponses = listOf(
                    accountsGetResponse(
                        requestAccountId = managementAccountId,
                        accounts = listOf(
                            accountObject(
                                managementAccountId,
                                """{"0":${passwordCredential()}}""",
                            ),
                            accountObject(
                                firstAccountId,
                                """{"0":${passwordCredential()}}""",
                            ),
                            accountObject(
                                secondAccountId,
                                """{"0":${passwordCredential()}}""",
                            ),
                        ),
                    ),
                ),
            )

            val available = assertIs<StalwartRemoteRead.Available<*>>(
                GateStalwartCredentialManagementRemote(
                    registry = registry,
                    managementAccountId = managementAccountId,
                    protectedAccountIds = setOf(managementAccountId),
                ).globalInventory(),
            )
            val global = assertIs<
                mail.sandbox.dashboard.server.provider.stalwart.credential.
                    StalwartGlobalReservedInventory
                >(available.value)

            assertEquals(
                listOf(managementAccountId, firstAccountId, secondAccountId),
                global.accounts.map { it.accountId },
            )
            assertEquals(
                listOf(
                    QueryCall("Account", managementAccountId, 0, 100),
                    QueryCall("Account", managementAccountId, 2, 100),
                    QueryCall("Account", managementAccountId, 0, 100),
                    QueryCall("Account", managementAccountId, 2, 100),
                ),
                registry.queries,
            )
        }

    @Test
    fun lifecycleGlobalInventoryFetchesAccountsInBoundedChunks() =
        runBlocking {
            val managementAccountId = "management7"
            val accountIds =
                listOf(managementAccountId) +
                    (0 until 100).map { index ->
                        "account${index.toString().padStart(3, '0')}"
                    }
            val firstPage = accountIds.take(100)
            val secondPage = accountIds.drop(100)
            val accounts = accountIds.associateWith { accountId ->
                accountObject(
                    accountId = accountId,
                    credentials = """{"0":${passwordCredential()}}""",
                )
            }
            val registry = RecordingAppPasswordRegistry(
                session = GateJmapSession(
                    apiUrl = URI("http://127.0.0.1:18443/jmap/"),
                    username = GateBootstrap.MANAGEMENT_ADDRESS,
                    primaryAccountId = managementAccountId,
                ),
                queryResponses = listOf(
                    accountQueryResponse(
                        requestAccountId = managementAccountId,
                        ids = firstPage,
                        total = accountIds.size,
                    ),
                    accountQueryResponse(
                        requestAccountId = managementAccountId,
                        ids = secondPage,
                        total = accountIds.size,
                        position = firstPage.size,
                    ),
                    accountQueryResponse(
                        requestAccountId = managementAccountId,
                        ids = firstPage,
                        total = accountIds.size,
                    ),
                    accountQueryResponse(
                        requestAccountId = managementAccountId,
                        ids = secondPage,
                        total = accountIds.size,
                        position = firstPage.size,
                    ),
                ),
                getResponses = listOf(
                    accountsGetResponse(
                        requestAccountId = managementAccountId,
                        accounts = firstPage.map(accounts::getValue),
                    ),
                    accountsGetResponse(
                        requestAccountId = managementAccountId,
                        accounts = secondPage.map(accounts::getValue),
                    ),
                ),
            )

            val available = assertIs<StalwartRemoteRead.Available<*>>(
                GateStalwartCredentialManagementRemote(
                    registry = registry,
                    managementAccountId = managementAccountId,
                    protectedAccountIds = setOf(managementAccountId),
                ).globalInventory(),
            )
            val global = assertIs<
                mail.sandbox.dashboard.server.provider.stalwart.credential.
                    StalwartGlobalReservedInventory
                >(available.value)

            assertEquals(accountIds, global.accounts.map { it.accountId })
            assertEquals(
                listOf(firstPage, secondPage),
                registry.gets.map { requireNotNull(it.ids) },
            )
            assertTrue(registry.gets.all { requireNotNull(it.ids).size <= 100 })
            assertEquals(4, registry.queries.size)
        }

    @Test
    fun lifecycleGlobalInventoryRejectsAChangedFinalQuerySnapshot() =
        runBlocking {
            val managementAccountId = "management7"
            val ordinaryAccountId = "account7"
            val ids = listOf(managementAccountId, ordinaryAccountId)
            val registry = RecordingAppPasswordRegistry(
                session = GateJmapSession(
                    apiUrl = URI("http://127.0.0.1:18443/jmap/"),
                    username = GateBootstrap.MANAGEMENT_ADDRESS,
                    primaryAccountId = managementAccountId,
                ),
                queryResponses = listOf(
                    accountQueryResponse(
                        requestAccountId = managementAccountId,
                        ids = ids,
                        total = ids.size,
                        queryState = "account-query-state-1",
                    ),
                    accountQueryResponse(
                        requestAccountId = managementAccountId,
                        ids = ids,
                        total = ids.size,
                        queryState = "account-query-state-2",
                    ),
                ),
                getResponses = listOf(
                    accountsGetResponse(
                        requestAccountId = managementAccountId,
                        accounts = ids.map { accountId ->
                            accountObject(
                                accountId,
                                """{"0":${passwordCredential()}}""",
                            )
                        },
                    ),
                ),
            )

            val result = GateStalwartCredentialManagementRemote(
                registry = registry,
                managementAccountId = managementAccountId,
                protectedAccountIds = setOf(managementAccountId),
            ).globalInventory()

            assertIs<StalwartRemoteRead.Unavailable>(result)
            assertEquals(2, registry.queries.size)
            assertEquals(1, registry.gets.size)
        }

    @Test
    fun lifecycleGlobalInventoryRequiresEveryProtectedAccountInTheQuery() =
        runBlocking {
            val managementAccountId = "management7"
            val missingProtectedAccountId = "protected8"
            val ordinaryAccountId = "account7"
            val visibleIds = listOf(managementAccountId, ordinaryAccountId)
            val registry = RecordingAppPasswordRegistry(
                session = GateJmapSession(
                    apiUrl = URI("http://127.0.0.1:18443/jmap/"),
                    username = GateBootstrap.MANAGEMENT_ADDRESS,
                    primaryAccountId = managementAccountId,
                ),
                queryResponses = listOf(
                    accountQueryResponse(
                        requestAccountId = managementAccountId,
                        ids = visibleIds,
                        total = visibleIds.size,
                    ),
                ),
            )

            val result = GateStalwartCredentialManagementRemote(
                registry = registry,
                managementAccountId = managementAccountId,
                protectedAccountIds = setOf(
                    managementAccountId,
                    missingProtectedAccountId,
                ),
            ).globalInventory()

            assertIs<StalwartRemoteRead.Unavailable>(result)
            assertTrue(registry.gets.isEmpty())
        }

    @Test
    fun lifecycleMailProbeProvesEveryCapabilityWithReadOnlyMethods() =
        runBlocking {
            val accountId = "account7"
            val address = "dashboard-routing-sender@local.test"
            val transport = RecordingGateHttpTransport(
                responses = completeMailProbeResponses(
                    accountId = accountId,
                    address = address,
                ),
            )
            val secret = StalwartBorrowedSecret.takeOwnership(
                "app_test-only-probe".encodeToByteArray(),
            )

            val result = secret.use {
                GateStalwartMailCredentialProbeRemote(
                    endpointProfile = StalwartEndpointProfile.MIGRATION_BOOTSTRAP,
                    transport = transport,
                ).probe(
                    accountId = accountId,
                    address = address,
                    secret = it,
                )
            }

            val authenticated =
                assertIs<StalwartCredentialProbeResult.Authenticated>(result)
            assertEquals(
                STALWART_REQUIRED_MAIL_CAPABILITIES,
                authenticated.capabilities,
            )
            val calls = transport.requests.drop(1).map { request ->
                val body = requireNotNull(request.body)
                val call = body.getValue("methodCalls")
                    .jsonArray
                    .single()
                    .jsonArray
                val using = body.getValue("using").jsonArray.map {
                    it.jsonPrimitive.content
                }
                Triple(
                    call[0].jsonPrimitive.content,
                    using,
                    call[1].jsonObject,
                )
            }
            assertEquals(
                listOf(
                    "Core/echo",
                    "Mailbox/get",
                    "EmailSubmission/get",
                    "Blob/get",
                ),
                calls.map(Triple<String, List<String>, JsonObject>::first),
            )
            assertEquals(
                listOf(
                    listOf("urn:ietf:params:jmap:core"),
                    listOf(
                        "urn:ietf:params:jmap:core",
                        "urn:ietf:params:jmap:mail",
                    ),
                    listOf(
                        "urn:ietf:params:jmap:core",
                        "urn:ietf:params:jmap:submission",
                    ),
                    listOf(
                        "urn:ietf:params:jmap:core",
                        "urn:ietf:params:jmap:blob",
                    ),
                ),
                calls.map(Triple<String, List<String>, JsonObject>::second),
            )
            assertTrue(
                calls.none { (methodName) ->
                    methodName.endsWith("/set") ||
                        methodName.endsWith("/upload") ||
                        methodName.endsWith("/import")
                },
            )
        }

    @Test
    fun lifecycleMailProbeReportsOnlyCapabilitiesWhoseMethodsSucceeded() =
        runBlocking {
            val accountId = "account7"
            val address = "dashboard-routing-sender@local.test"
            val responses = completeMailProbeResponses(
                accountId = accountId,
                address = address,
            ).toMutableList()
            responses[3] = jmapMethodErrorResponse(
                callId = "gate-3",
                type = "unknownMethod",
            )
            val transport = RecordingGateHttpTransport(responses)
            val secret = StalwartBorrowedSecret.takeOwnership(
                "app_test-only-partial-probe".encodeToByteArray(),
            )

            val result = secret.use {
                GateStalwartMailCredentialProbeRemote(
                    endpointProfile = StalwartEndpointProfile.MIGRATION_BOOTSTRAP,
                    transport = transport,
                ).probe(
                    accountId = accountId,
                    address = address,
                    secret = it,
                )
            }

            val authenticated =
                assertIs<StalwartCredentialProbeResult.Authenticated>(result)
            assertEquals(
                setOf(
                    StalwartMailCapability.Core,
                    StalwartMailCapability.Mail,
                    StalwartMailCapability.Blob,
                ),
                authenticated.capabilities,
            )
            assertEquals(5, transport.requests.size)
        }

    @Test
    fun authenticatedSessionProvesCoreWhenCoreEchoIsPermissionDenied() =
        runBlocking {
            val accountId = "account7"
            val address = "dashboard-routing-sender@local.test"
            val responses = completeMailProbeResponses(
                accountId = accountId,
                address = address,
            ).toMutableList()
            responses[1] = jmapMethodErrorResponse(
                callId = "gate-1",
                type = "forbidden",
            )
            val transport = RecordingGateHttpTransport(responses)
            val secret = StalwartBorrowedSecret.takeOwnership(
                "app_test-only-core-session-probe".encodeToByteArray(),
            )

            val result = secret.use {
                GateStalwartMailCredentialProbeRemote(
                    endpointProfile = StalwartEndpointProfile.MIGRATION_BOOTSTRAP,
                    transport = transport,
                ).probe(
                    accountId = accountId,
                    address = address,
                    secret = it,
                )
            }

            val authenticated =
                assertIs<StalwartCredentialProbeResult.Authenticated>(result)
            assertEquals(
                STALWART_REQUIRED_MAIL_CAPABILITIES,
                authenticated.capabilities,
            )
            assertEquals(5, transport.requests.size)
        }

    @Test
    fun managementRevocationNeverBlindlyRetriesAfterPostFetchMismatch() =
        runBlocking {
            val managementAccountId = "management7"
            val targetAccountId = "account7"
            val targetCredentialId = "credential2"
            val targetDescription = GateAppPasswordDescription.reserved(
                storeId = UUID.fromString("0f34f2c8-779f-4cc2-b4be-e3a6ef8f27f8"),
                generation = 2u,
            )
            val registry = RecordingAppPasswordRegistry(
                session = GateJmapSession(
                    apiUrl = URI("http://127.0.0.1:18443/jmap/"),
                    username = GateBootstrap.MANAGEMENT_ADDRESS,
                    primaryAccountId = managementAccountId,
                ),
                getResponses = listOf(
                    accountGetResponse(
                        requestAccountId = managementAccountId,
                        objectAccountId = targetAccountId,
                        credentials = """
                            {
                              "0":${passwordCredential()},
                              "17":${appPasswordCredential(
                                  credentialId = targetCredentialId,
                                  description = targetDescription.value,
                              )},
                              "49":${appPasswordCredential(
                                  credentialId = "credential3",
                                  description = "team-owned/unrelated",
                              )}
                            }
                        """.trimIndent(),
                    ),
                    accountGetResponse(
                        requestAccountId = managementAccountId,
                        objectAccountId = targetAccountId,
                        credentials = """
                            {
                              "0":${passwordCredential()},
                              "1":${appPasswordCredential(
                                  credentialId = "credential3",
                                  description = "externally-changed",
                              )}
                            }
                        """.trimIndent(),
                    ),
                ),
                updateResponses = listOf(
                    registryResponse(
                        method = "x:Account/set",
                        payload = """
                            {
                              "accountId":"$managementAccountId",
                              "updated":{"$targetAccountId":null},
                              "notUpdated":{}
                            }
                        """.trimIndent(),
                    ),
                ),
            )

            val result = GateManagementAppPasswordRevoker(
                registry = registry,
                managementAccountId = managementAccountId,
            ).revoke(
                targetAccountId = targetAccountId,
                targetCredentialId = targetCredentialId,
                expectedDescription = targetDescription,
            )

            assertIs<GateTargetedRevocationResult.ReconciliationRequired>(result)
            assertEquals(1, registry.updates.size)
            assertEquals(2, registry.gets.size)
        }

    @Test
    fun managementRevocationReconcilesAnAppliedUpdateAfterItsResponseIsLost() =
        runBlocking {
            val managementAccountId = "management7"
            val targetAccountId = "account7"
            val targetCredentialId = "credential2"
            val targetDescription = GateAppPasswordDescription.reserved(
                storeId = UUID.fromString("0f34f2c8-779f-4cc2-b4be-e3a6ef8f27f8"),
                generation = 2u,
            )
            val sibling = appPasswordCredential(
                credentialId = "credential3",
                description = "team-owned/unrelated",
            )
            val registry = RecordingAppPasswordRegistry(
                session = GateJmapSession(
                    apiUrl = URI("http://127.0.0.1:18443/jmap/"),
                    username = GateBootstrap.MANAGEMENT_ADDRESS,
                    primaryAccountId = managementAccountId,
                ),
                getResponses = listOf(
                    accountGetResponse(
                        requestAccountId = managementAccountId,
                        objectAccountId = targetAccountId,
                        credentials = """
                            {
                              "0":${passwordCredential()},
                              "17":${appPasswordCredential(
                                  credentialId = targetCredentialId,
                                  description = targetDescription.value,
                              )},
                              "49":$sibling
                            }
                        """.trimIndent(),
                    ),
                    accountGetResponse(
                        requestAccountId = managementAccountId,
                        objectAccountId = targetAccountId,
                        credentials = """
                            {
                              "8":${passwordCredential()},
                              "3":$sibling
                            }
                        """.trimIndent(),
                    ),
                ),
                updateFailures = listOf(
                    GateJmapException(
                        kind = GateJmapFailure.Transport,
                        message = "response lost after dispatch",
                    ),
                ),
            )

            val result = GateManagementAppPasswordRevoker(
                registry = registry,
                managementAccountId = managementAccountId,
            ).revoke(
                targetAccountId = targetAccountId,
                targetCredentialId = targetCredentialId,
                expectedDescription = targetDescription,
            )

            assertIs<GateTargetedRevocationResult.Revoked>(result)
            assertEquals(1, registry.updates.size)
            assertEquals(2, registry.gets.size)
        }

    @Test
    fun managementRevocationDoesNotRetryWhenAFailedUpdateWasNotApplied() =
        runBlocking {
            val managementAccountId = "management7"
            val targetAccountId = "account7"
            val targetCredentialId = "credential2"
            val targetDescription = GateAppPasswordDescription.reserved(
                storeId = UUID.fromString("0f34f2c8-779f-4cc2-b4be-e3a6ef8f27f8"),
                generation = 2u,
            )
            val unchanged = accountGetResponse(
                requestAccountId = managementAccountId,
                objectAccountId = targetAccountId,
                credentials = """
                    {
                      "0":${passwordCredential()},
                      "17":${appPasswordCredential(
                          credentialId = targetCredentialId,
                          description = targetDescription.value,
                      )},
                      "49":${appPasswordCredential(
                          credentialId = "credential3",
                          description = "team-owned/unrelated",
                      )}
                    }
                """.trimIndent(),
            )
            val registry = RecordingAppPasswordRegistry(
                session = GateJmapSession(
                    apiUrl = URI("http://127.0.0.1:18443/jmap/"),
                    username = GateBootstrap.MANAGEMENT_ADDRESS,
                    primaryAccountId = managementAccountId,
                ),
                getResponses = listOf(unchanged, unchanged),
                updateFailures = listOf(
                    GateJmapException(
                        kind = GateJmapFailure.Transport,
                        message = "request failed before apply",
                    ),
                ),
            )

            val result = GateManagementAppPasswordRevoker(
                registry = registry,
                managementAccountId = managementAccountId,
            ).revoke(
                targetAccountId = targetAccountId,
                targetCredentialId = targetCredentialId,
                expectedDescription = targetDescription,
            )

            assertIs<GateTargetedRevocationResult.ReconciliationRequired>(result)
            assertEquals(1, registry.updates.size)
            assertEquals(2, registry.gets.size)
        }

    @Test
    fun managementRevocationPropagatesBeforeDispatchAndVerifiesAfterDispatch() =
        runBlocking {
            val managementAccountId = "management7"
            val targetAccountId = "account7"
            val targetCredentialId = "credential2"
            val targetDescription = GateAppPasswordDescription.reserved(
                storeId = UUID.fromString("0f34f2c8-779f-4cc2-b4be-e3a6ef8f27f8"),
                generation = 2u,
            )
            val before = accountGetResponse(
                requestAccountId = managementAccountId,
                objectAccountId = targetAccountId,
                credentials = """
                    {
                      "0":${passwordCredential()},
                      "17":${appPasswordCredential(
                          credentialId = targetCredentialId,
                          description = targetDescription.value,
                      )}
                    }
                """.trimIndent(),
            )
            val after = accountGetResponse(
                requestAccountId = managementAccountId,
                objectAccountId = targetAccountId,
                credentials = """{"0":${passwordCredential()}}""",
            )
            val session = GateJmapSession(
                apiUrl = URI("http://127.0.0.1:18443/jmap/"),
                username = GateBootstrap.MANAGEMENT_ADDRESS,
                primaryAccountId = managementAccountId,
            )

            val preDispatchCancellation =
                CancellationException("pre-dispatch cancelled")
            val preDispatchCancelled = RecordingAppPasswordRegistry(
                session = session,
                getFailuresByCall = mapOf(1 to preDispatchCancellation),
            )
            val propagated = assertFailsWith<CancellationException> {
                GateManagementAppPasswordRevoker(
                    registry = preDispatchCancelled,
                    managementAccountId = managementAccountId,
                ).revoke(
                    targetAccountId = targetAccountId,
                    targetCredentialId = targetCredentialId,
                    expectedDescription = targetDescription,
                )
            }
            assertSame(preDispatchCancellation, propagated)
            assertTrue(preDispatchCancelled.updates.isEmpty())
            assertEquals(1, preDispatchCancelled.gets.size)

            val updateCancellation = CancellationException("update cancelled")
            val updateCancelled = RecordingAppPasswordRegistry(
                session = session,
                getResponses = listOf(before, after),
                updateFailures = listOf(updateCancellation),
            )
            val reconciledUpdate =
                GateManagementAppPasswordRevoker(
                    registry = updateCancelled,
                    managementAccountId = managementAccountId,
                ).revoke(
                    targetAccountId = targetAccountId,
                    targetCredentialId = targetCredentialId,
                    expectedDescription = targetDescription,
                )
            assertEquals(
                GateTargetedRevocationResult.Revoked,
                reconciledUpdate,
            )
            assertEquals(1, updateCancelled.updates.size)
            assertEquals(2, updateCancelled.gets.size)

            val postFetchCancellation = CancellationException("post-fetch cancelled")
            val postFetchCancelled = RecordingAppPasswordRegistry(
                session = session,
                getResponses = listOf(before),
                getFailuresByCall = mapOf(2 to postFetchCancellation),
                updateResponses = listOf(
                    registryResponse(
                        method = "x:Account/set",
                        payload = """
                            {
                              "accountId":"$managementAccountId",
                              "updated":{"$targetAccountId":null},
                              "notUpdated":{}
                            }
                        """.trimIndent(),
                    ),
                ),
            )
            val reconciledPostFetch =
                GateManagementAppPasswordRevoker(
                    registry = postFetchCancelled,
                    managementAccountId = managementAccountId,
                ).revoke(
                    targetAccountId = targetAccountId,
                    targetCredentialId = targetCredentialId,
                    expectedDescription = targetDescription,
                )
            assertEquals(
                GateTargetedRevocationResult.ReconciliationRequired,
                reconciledPostFetch,
            )
            assertEquals(1, postFetchCancelled.updates.size)
            assertEquals(2, postFetchCancelled.gets.size)
        }

    @Test
    fun effectiveScopeComesOnlyFromPinnedAuthenticatedAccountEndpoint() =
        runBlocking {
            val transport = RecordingGateHttpTransport(
                responses = listOf(
                    GateHttpResponse(
                        status = 200,
                        effectiveUrl = URI(
                            "http://127.0.0.1:18443/api/account",
                        ),
                        body = """
                            {
                              "permissions":${Json.encodeToString(
                                  DASHBOARD_MAIL_PERMISSIONS.toList(),
                              )},
                              "edition":"community",
                              "locale":"en"
                            }
                        """.trimIndent(),
                    ),
                ),
            )
            val credentialMarker = "app_test-only-effective-scope-marker"
            val scope = GateEffectivePermissionClient(
                baseUrl = URI("http://127.0.0.1:18443"),
                credential = GateCredential.basic(
                    username = GateBootstrap.FIRST_USER_ADDRESS,
                    secret = credentialMarker.toCharArray(),
                ),
                transport = transport,
            ).use { it.fetch() }

            assertEquals(DASHBOARD_MAIL_PERMISSIONS, scope.permissions)
            assertEquals("community", scope.edition)
            assertEquals("en", scope.locale)
            assertFalse(scope.toString().contains(credentialMarker))

            val request = transport.requests.single()
            assertEquals("GET", request.method)
            assertEquals(
                URI("http://127.0.0.1:18443/api/account"),
                request.url,
            )
            assertEquals(null, request.body)
            assertFalse(request.toString().contains(credentialMarker))
        }

    @Test
    fun effectiveScopeRejectsEveryNonCommunityImageLabel() = runBlocking {
        for (edition in listOf("oss", "enterprise", "unknown")) {
            val transport = RecordingGateHttpTransport(
                responses = listOf(
                    GateHttpResponse(
                        status = 200,
                        effectiveUrl = URI(
                            "http://127.0.0.1:18443/api/account",
                        ),
                        body = """
                            {
                              "permissions":[],
                              "edition":"$edition",
                              "locale":"en"
                            }
                        """.trimIndent(),
                    ),
                ),
            )
            val failure = assertFailsWith<GateJmapException> {
                GateEffectivePermissionClient(
                    baseUrl = URI("http://127.0.0.1:18443"),
                    credential = GateCredential.basic(
                        username = GateBootstrap.FIRST_USER_ADDRESS,
                        secret = "app_test-only-edition-marker".toCharArray(),
                    ),
                    transport = transport,
                ).use { it.fetch() }
            }
            assertEquals(GateJmapFailure.InvalidResponse, failure.kind)
            assertFalse(failure.toString().contains(edition))
        }
    }

    private fun client(transport: GateRawBlobTransport): GateAppPasswordClient =
        GateAppPasswordClient(
            session = GateJmapSession(
                apiUrl = URI("http://127.0.0.1:18443/jmap/"),
                username = "dashboard-management@local.test",
                primaryAccountId = "account7",
            ),
            credential = GateCredential.bearer("API_test-only".toCharArray()),
            transport = transport,
        )

    private fun registryResponse(
        method: String,
        payload: String,
    ): JsonObject =
        Json.parseToJsonElement(
            """
                {
                  "methodResponses":[
                    ["$method", $payload, "gate-test"]
                  ]
                }
            """.trimIndent(),
        ).jsonObject

    private fun permissionJson(): String =
        DASHBOARD_MAIL_PERMISSIONS.joinToString(
            prefix = "{",
            postfix = "}",
        ) { permission ->
            Json.encodeToString(permission) + ":true"
        }

    private fun dashboardPermissionObject(): JsonObject = buildJsonObject {
        DASHBOARD_MAIL_PERMISSIONS.forEach { put(it, true) }
    }

    private fun accountGetResponse(
        requestAccountId: String,
        objectAccountId: String,
        credentials: String,
        quotas: String = """{"maxAppPasswords":null}""",
    ): JsonObject =
        registryResponse(
            method = "x:Account/get",
            payload = """
                {
                  "accountId":"$requestAccountId",
                  "state":"account-state",
                  "list":[{
                    "id":"$objectAccountId",
                    "@type":"User",
                    "credentials":$credentials,
                    "quotas":$quotas
                  }],
                  "notFound":[]
                }
            """.trimIndent(),
        )

    private fun accountQueryResponse(
        requestAccountId: String,
        ids: List<String>,
        total: Int,
        position: Int = 0,
        queryState: String = "account-query-state",
    ): JsonObject =
        registryResponse(
            method = "x:Account/query",
            payload = """
                {
                  "accountId":"$requestAccountId",
                  "queryState":"$queryState",
                  "canCalculateChanges":false,
                  "position":$position,
                  "ids":${Json.encodeToString(ids)},
                  "total":$total
                }
            """.trimIndent(),
        )

    private fun accountsGetResponse(
        requestAccountId: String,
        accounts: List<JsonObject>,
    ): JsonObject =
        registryResponse(
            method = "x:Account/get",
            payload = """
                {
                  "accountId":"$requestAccountId",
                  "state":"account-state",
                  "list":${Json.encodeToString(accounts)},
                  "notFound":[]
                }
            """.trimIndent(),
        )

    private fun accountObject(
        accountId: String,
        credentials: String,
    ): JsonObject =
        Json.parseToJsonElement(
            """
                {
                  "id":"$accountId",
                  "@type":"User",
                  "credentials":$credentials,
                  "quotas":{"maxAppPasswords":null}
                }
            """.trimIndent(),
        ).jsonObject

    private fun completeMailProbeResponses(
        accountId: String,
        address: String,
    ): List<GateHttpResponse> =
        listOf(
            GateHttpResponse(
                status = 200,
                effectiveUrl = URI(
                    "http://127.0.0.1:18080/.well-known/jmap",
                ),
                body = """
                    {
                      "apiUrl":"/jmap/",
                      "username":"$address",
                      "primaryAccounts":{"urn:stalwart:jmap":"$accountId"}
                    }
                """.trimIndent(),
            ),
            jmapMethodResponse(
                method = "Core/echo",
                callId = "gate-1",
                payload = """{"probe":"mail-sandbox-debug-dashboard"}""",
            ),
            jmapMethodResponse(
                method = "Mailbox/get",
                callId = "gate-2",
                payload = """
                    {
                      "accountId":"$accountId",
                      "state":"mailbox-state",
                      "list":[{"id":"mailbox7","name":"Inbox","role":"inbox"}],
                      "notFound":[]
                    }
                """.trimIndent(),
            ),
            jmapMethodResponse(
                method = "EmailSubmission/get",
                callId = "gate-3",
                payload = """
                    {
                      "accountId":"$accountId",
                      "state":"submission-state",
                      "list":[],
                      "notFound":["mailSandboxProbeAbsent"]
                    }
                """.trimIndent(),
            ),
            jmapMethodResponse(
                method = "Blob/get",
                callId = "gate-4",
                payload = """
                    {
                      "accountId":"$accountId",
                      "state":"blob-state",
                      "list":[],
                      "notFound":["mailSandboxProbeAbsent"]
                    }
                """.trimIndent(),
            ),
        )

    private fun jmapMethodResponse(
        method: String,
        callId: String,
        payload: String,
    ): GateHttpResponse =
        GateHttpResponse(
            status = 200,
            effectiveUrl = URI("http://127.0.0.1:18080/jmap/"),
            body = """
                {
                  "methodResponses":[
                    ["$method",$payload,"$callId"]
                  ]
                }
            """.trimIndent(),
        )

    private fun jmapMethodErrorResponse(
        callId: String,
        type: String,
    ): GateHttpResponse =
        jmapMethodResponse(
            method = "error",
            callId = callId,
            payload = """{"type":"$type"}""",
        )

    private fun passwordCredential(): String =
        """
            {
              "@type":"Password",
              "credentialId":"credential1",
              "secret":"****",
              "allowedIps":{}
            }
        """.trimIndent()

    private fun appPasswordCredential(
        credentialId: String,
        description: String,
    ): String =
        """
            {
              "@type":"AppPassword",
              "credentialId":"$credentialId",
              "description":"$description",
              "secret":"****",
              "permissions":{
                "@type":"Replace",
                "permissions":${permissionJson()}
              },
              "allowedIps":{}
            }
        """.trimIndent()

    private fun singleResponse(
        status: Int,
        body: ByteArray = ByteArray(0),
    ): RecordingRawBlobTransport =
        RecordingRawBlobTransport(
            listOf(
                { request ->
                    GateRawBlobHttpResponse(
                        status = status,
                        effectiveUrl = request.url,
                        body = body,
                    )
                },
            ),
        )

    private class RecordingRawBlobTransport(
        responses: List<(GateRawBlobHttpRequest) -> GateRawBlobHttpResponse>,
    ) : GateRawBlobTransport {
        private val responses = ArrayDeque(responses)
        val requests = mutableListOf<GateRawBlobHttpRequest>()

        override suspend fun execute(
            request: GateRawBlobHttpRequest,
        ): GateRawBlobHttpResponse {
            requests += request
            return responses.removeFirst()(request)
        }
    }

    private class RecordingGateHttpTransport(
        responses: List<GateHttpResponse>,
        private val failuresByCall: Map<Int, Exception> = emptyMap(),
    ) : GateHttpTransport {
        private val responses = ArrayDeque(responses)
        val requests = mutableListOf<GateHttpRequest>()

        override suspend fun execute(request: GateHttpRequest): GateHttpResponse {
            requests += request
            failuresByCall[requests.size]?.let { throw it }
            return responses.removeFirst()
        }
    }

    private class RecordingAppPasswordRegistry(
        private val session: GateJmapSession,
        createResponses: List<JsonObject> = emptyList(),
        queryResponses: List<JsonObject> = emptyList(),
        getResponses: List<JsonObject> = emptyList(),
        private val getFailuresByCall: Map<Int, Exception> = emptyMap(),
        updateResponses: List<JsonObject> = emptyList(),
        updateFailures: List<Exception> = emptyList(),
        destroyResponses: List<JsonObject> = emptyList(),
    ) : GateRegistryApi {
        private val createResponses = ArrayDeque(createResponses)
        private val queryResponses = ArrayDeque(queryResponses)
        private val getResponses = ArrayDeque(getResponses)
        private val updateResponses = ArrayDeque(updateResponses)
        private val updateFailures = ArrayDeque(updateFailures)
        private val destroyResponses = ArrayDeque(destroyResponses)
        val creates = mutableListOf<CreateCall>()
        val gets = mutableListOf<GetCall>()
        val queries = mutableListOf<QueryCall>()
        val updates = mutableListOf<UpdateCall>()
        val destroys = mutableListOf<DestroyCall>()
        var discoveryCount = 0
        var queryCount = 0
        val callCount: Int
            get() = discoveryCount + queryCount +
                creates.size + gets.size + updates.size + destroys.size

        override suspend fun discoverSession(): GateJmapSession {
            discoveryCount += 1
            return session
        }

        override suspend fun registryGet(
            objectType: String,
            ids: List<String>?,
            accountId: String?,
        ): JsonObject {
            gets += GetCall(objectType, ids, accountId)
            getFailuresByCall[gets.size]?.let { throw it }
            return getResponses.removeFirst()
        }

        override suspend fun registryQuery(
            objectType: String,
            filter: JsonObject,
            accountId: String?,
            position: Int,
            limit: Int,
        ): JsonObject {
            queryCount += 1
            queries += QueryCall(objectType, accountId, position, limit)
            return queryResponses.removeFirst()
        }

        override suspend fun registryCreate(
            objectType: String,
            creationId: String,
            value: JsonObject,
            accountId: String?,
        ): JsonObject {
            creates += CreateCall(
                objectType = objectType,
                creationId = creationId,
                value = value,
                accountId = accountId,
            )
            return createResponses.removeFirst()
        }

        override suspend fun registryUpdate(
            objectType: String,
            objectId: String,
            patch: JsonObject,
            accountId: String?,
        ): JsonObject {
            updates += UpdateCall(
                objectType = objectType,
                objectId = objectId,
                patch = patch,
                accountId = accountId,
            )
            if (updateFailures.isNotEmpty()) {
                throw updateFailures.removeFirst()
            }
            return updateResponses.removeFirst()
        }

        override suspend fun registryDestroy(
            objectType: String,
            objectId: String,
            accountId: String?,
        ): JsonObject {
            destroys += DestroyCall(
                objectType = objectType,
                objectId = objectId,
                accountId = accountId,
            )
            return destroyResponses.removeFirst()
        }

        override fun close() = Unit
    }

    private data class CreateCall(
        val objectType: String,
        val creationId: String,
        val value: JsonObject,
        val accountId: String?,
    )

    private data class GetCall(
        val objectType: String,
        val ids: List<String>?,
        val accountId: String?,
    )

    private data class QueryCall(
        val objectType: String,
        val accountId: String?,
        val position: Int,
        val limit: Int,
    )

    private data class UpdateCall(
        val objectType: String,
        val objectId: String,
        val patch: JsonObject,
        val accountId: String?,
    )

    private data class DestroyCall(
        val objectType: String,
        val objectId: String,
        val accountId: String?,
    )
}
