package mail.sandbox.dashboard.server.gate.stalwart

import java.net.URI
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

class GateAppPasswordClientTest {
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

        val upload = assertIs<GateRawBlobUploadResult.Accepted>(
            client.rawUpload("account7", payload),
        )
        assertEquals("account7", upload.blob.accountId)
        assertEquals("blob7", upload.blob.blobId)
        assertEquals(payload.size, upload.blob.size)
        val download = assertIs<GateRawBlobDownloadResult.Denied>(
            client.rawDownload(
                accountId = "account7",
                blobId = upload.blob.blobId,
                expectedPayload = payload,
            ),
        )
        assertEquals(403, download.status)

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
            val result = client(singleResponse(status)).rawUpload(
                accountId = "account7",
                payload = byteArrayOf(1),
            )
            assertEquals(status, assertIs<GateRawBlobUploadResult.Denied>(result).status)
        }

        listOf(401, 403).forEach { status ->
            val result = client(singleResponse(status)).rawDownload(
                accountId = "account7",
                blobId = "blob7",
                expectedPayload = byteArrayOf(1),
            )
            assertEquals(status, assertIs<GateRawBlobDownloadResult.Denied>(result).status)
        }

        listOf(302, 400, 500).forEach { status ->
            val failure = assertFailsWith<GateRawBlobException> {
                client(singleResponse(status)).rawUpload(
                    accountId = "account7",
                    payload = byteArrayOf(1),
                )
            }
            assertEquals(
                GateRawBlobFailure.UnexpectedStatus(status),
                failure.kind,
            )
        }

        val hiddenDownload = client(singleResponse(404)).rawDownload(
            accountId = "account7",
            blobId = "blob7",
            expectedPayload = byteArrayOf(1),
        )
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
        ).rawDownload(
            accountId = "account7",
            blobId = "blob7",
            expectedPayload = acceptedPayload,
        )
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
            """{"accountId":"$marker","blobId":"blob7","type":"application/octet-stream","size":1}""",
            """{"accountId":"account7","blobId":"blob7/$marker","type":"application/octet-stream","size":1}""",
            """{"accountId":"account7","blobId":"blob7","type":"application/octet-stream","size":2}""",
        ).forEach { body ->
            val failure = assertFailsWith<GateRawBlobException> {
                client(singleResponse(status = 200, body = body.encodeToByteArray()))
                    .rawUpload(
                        accountId = "account7",
                        payload = byteArrayOf(1),
                    )
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
            ).rawDownload(
                accountId = "account7",
                blobId = "blob7",
                expectedPayload = expected,
            )
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
                ).rawDownload(
                    accountId = "account7",
                    blobId = "blob7",
                    expectedPayload = expected,
                )
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
            assertFailsWith<IllegalArgumentException> {
                GateAppPasswordClient(
                    session = GateJmapSession(
                        apiUrl = URI(unsafe),
                        username = null,
                        primaryAccountId = null,
                    ),
                    credential = GateCredential.bearer("API_secret".toCharArray()),
                    transport = singleResponse(403),
                )
            }
        }

        val client = client(singleResponse(403))
        listOf("", "../other", "other/account", "other?query", "other#fragment")
            .forEach { unsafeAccountId ->
                assertFailsWith<IllegalArgumentException> {
                    client.rawUpload(unsafeAccountId, byteArrayOf(1))
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
            client(redirected).rawUpload("account7", byteArrayOf(1))
        }
        assertEquals(GateRawBlobFailure.InvalidResponse, redirectFailure.kind)

        val credentialMarker = "credential-secret-marker"
        val bodyMarker = "body-secret-marker"
        val request = GateRawBlobHttpRequest(
            method = "POST",
            url = URI("http://127.0.0.1:18443/jmap/upload/account7"),
            credential = GateCredential.bearer(credentialMarker.toCharArray()),
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
}
