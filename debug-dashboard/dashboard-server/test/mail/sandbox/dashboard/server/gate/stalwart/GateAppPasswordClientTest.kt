package mail.sandbox.dashboard.server.gate.stalwart

import java.net.URI
import java.util.UUID
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
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

class GateAppPasswordClientTest {
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
    fun managementRevocationPropagatesUpdateAndPostFetchCancellation() =
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
            val session = GateJmapSession(
                apiUrl = URI("http://127.0.0.1:18443/jmap/"),
                username = GateBootstrap.MANAGEMENT_ADDRESS,
                primaryAccountId = managementAccountId,
            )

            val updateCancellation = CancellationException("update cancelled")
            val updateCancelled = RecordingAppPasswordRegistry(
                session = session,
                getResponses = listOf(before),
                updateFailures = listOf(updateCancellation),
            )
            val propagatedUpdate = assertFailsWith<CancellationException> {
                GateManagementAppPasswordRevoker(
                    registry = updateCancelled,
                    managementAccountId = managementAccountId,
                ).revoke(
                    targetAccountId = targetAccountId,
                    targetCredentialId = targetCredentialId,
                    expectedDescription = targetDescription,
                )
            }
            assertSame(updateCancellation, propagatedUpdate)
            assertEquals(1, updateCancelled.updates.size)
            assertEquals(1, updateCancelled.gets.size)

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
            val propagatedPostFetch = assertFailsWith<CancellationException> {
                GateManagementAppPasswordRevoker(
                    registry = postFetchCancelled,
                    managementAccountId = managementAccountId,
                ).revoke(
                    targetAccountId = targetAccountId,
                    targetCredentialId = targetCredentialId,
                    expectedDescription = targetDescription,
                )
            }
            assertSame(postFetchCancellation, propagatedPostFetch)
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
                    "credentials":$credentials
                  }],
                  "notFound":[]
                }
            """.trimIndent(),
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
    ) : GateHttpTransport {
        private val responses = ArrayDeque(responses)
        val requests = mutableListOf<GateHttpRequest>()

        override suspend fun execute(request: GateHttpRequest): GateHttpResponse {
            requests += request
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
        ): JsonObject {
            queryCount += 1
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
