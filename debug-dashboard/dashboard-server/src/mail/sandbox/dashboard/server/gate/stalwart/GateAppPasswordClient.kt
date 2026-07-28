package mail.sandbox.dashboard.server.gate.stalwart

import io.ktor.client.HttpClient
import io.ktor.client.engine.cio.CIO
import io.ktor.client.plugins.HttpTimeout
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsBytes
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.contentType
import java.net.URI
import kotlinx.coroutines.CancellationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.longOrNull

internal class GateRawBlobHttpRequest(
    val method: String,
    val url: URI,
    val credential: GateCredential,
    val contentType: String?,
    body: ByteArray,
) {
    val body: ByteArray = body.copyOf()

    init {
        require(method == "GET" || method == "POST") {
            "Unsupported raw-blob HTTP method"
        }
        require(
            (method == "GET" && contentType == null && this.body.isEmpty()) ||
                (
                    method == "POST" &&
                        contentType == RAW_BLOB_CONTENT_TYPE &&
                        this.body.isNotEmpty()
                    ),
        ) {
            "Raw-blob HTTP request shape is invalid"
        }
    }

    override fun toString(): String =
        "GateRawBlobHttpRequest(" +
            "method=$method, url=redacted, credential=$credential, " +
            "contentType=$contentType, body=redacted)"
}

internal class GateRawBlobHttpResponse(
    val status: Int,
    val effectiveUrl: URI,
    body: ByteArray,
) {
    val body: ByteArray = body.copyOf()

    override fun toString(): String =
        "GateRawBlobHttpResponse(" +
            "status=$status, effectiveUrl=redacted, body=redacted)"
}

internal fun interface GateRawBlobTransport {
    suspend fun execute(request: GateRawBlobHttpRequest): GateRawBlobHttpResponse
}

internal sealed interface GateRawBlobFailure {
    data class UnexpectedStatus(val status: Int) : GateRawBlobFailure

    data class ResponseBody(val status: Int) : GateRawBlobFailure

    data object InvalidResponse : GateRawBlobFailure

    data object Transport : GateRawBlobFailure
}

internal class GateRawBlobException(
    val kind: GateRawBlobFailure,
    message: String,
) : IllegalStateException(message)

internal class GateUploadedBlob(
    val accountId: String,
    val blobId: String,
    val size: Int,
) {
    override fun toString(): String = "GateUploadedBlob(values=redacted)"
}

internal sealed interface GateRawBlobUploadResult {
    data class Denied(val status: Int) : GateRawBlobUploadResult

    data class Accepted(
        val blob: GateUploadedBlob,
    ) : GateRawBlobUploadResult
}

internal sealed interface GateRawBlobDownloadResult {
    data class Denied(val status: Int) : GateRawBlobDownloadResult

    data class Accepted(
        val status: Int,
        val byteCount: Int,
    ) : GateRawBlobDownloadResult
}

internal enum class GateRawBlobProbeTarget {
    MANAGEMENT_ACCOUNT,
    ORDINARY_ACCOUNT,
}

internal class GateRawBlobProbeResult(
    val target: GateRawBlobProbeTarget,
    val upload: GateRawBlobUploadResult,
    val download: GateRawBlobDownloadResult?,
) {
    override fun toString(): String =
        "GateRawBlobProbeResult(target=$target, results=redacted)"
}

internal enum class GateRawBlobIsolationViolation {
    MANAGEMENT_ACCOUNT_UPLOAD_ACCEPTED,
    MANAGEMENT_ACCOUNT_DOWNLOAD_ACCEPTED,
    ORDINARY_ACCOUNT_UPLOAD_ACCEPTED,
    ORDINARY_ACCOUNT_DOWNLOAD_ACCEPTED,
}

internal class GateRawBlobIsolationStop(
    val violations: Set<GateRawBlobIsolationViolation>,
) : AssertionError(
        "STOP: Stalwart raw Blob isolation failed (" +
            violations.joinToString(separator = ",") +
            ")",
    )

internal object GateRawBlobIsolation {
    fun requireDenied(results: List<GateRawBlobProbeResult>) {
        val violations = violations(results)
        if (violations.isNotEmpty()) {
            throw GateRawBlobIsolationStop(violations)
        }
    }

    fun violations(
        results: List<GateRawBlobProbeResult>,
    ): Set<GateRawBlobIsolationViolation> {
        require(
            results.size == GateRawBlobProbeTarget.entries.size &&
                results.map { it.target }.toSet() ==
                GateRawBlobProbeTarget.entries.toSet(),
        ) {
            "Raw-blob isolation requires each exact probe target once"
        }

        val violations = linkedSetOf<GateRawBlobIsolationViolation>()
        results.forEach { result ->
            when (val upload = result.upload) {
                is GateRawBlobUploadResult.Denied -> {
                    require(
                        upload.status == 401 ||
                            upload.status == 403 ||
                            upload.status == 404,
                    ) {
                        "Raw-blob upload denial status is invalid"
                    }
                    require(result.download == null) {
                        "Denied raw-blob upload cannot have a download probe"
                    }
                }

                is GateRawBlobUploadResult.Accepted -> {
                    require(result.download != null) {
                        "Accepted raw-blob upload requires its paired download probe"
                    }
                    violations += result.target.uploadViolation()
                }
            }

            when (val download = result.download) {
                null -> Unit
                is GateRawBlobDownloadResult.Denied -> {
                    require(download.status == 401 || download.status == 403 ||
                        download.status == 404) {
                        "Raw-blob download denial status is invalid"
                    }
                }

                is GateRawBlobDownloadResult.Accepted -> {
                    require(download.status in 200..299) {
                        "Raw-blob accepted download status is invalid"
                    }
                    violations += result.target.downloadViolation()
                }
            }
        }

        return violations
    }

    private fun GateRawBlobProbeTarget.uploadViolation():
        GateRawBlobIsolationViolation =
        when (this) {
            GateRawBlobProbeTarget.MANAGEMENT_ACCOUNT ->
                GateRawBlobIsolationViolation.MANAGEMENT_ACCOUNT_UPLOAD_ACCEPTED
            GateRawBlobProbeTarget.ORDINARY_ACCOUNT ->
                GateRawBlobIsolationViolation.ORDINARY_ACCOUNT_UPLOAD_ACCEPTED
        }

    private fun GateRawBlobProbeTarget.downloadViolation():
        GateRawBlobIsolationViolation =
        when (this) {
            GateRawBlobProbeTarget.MANAGEMENT_ACCOUNT ->
                GateRawBlobIsolationViolation.MANAGEMENT_ACCOUNT_DOWNLOAD_ACCEPTED
            GateRawBlobProbeTarget.ORDINARY_ACCOUNT ->
                GateRawBlobIsolationViolation.ORDINARY_ACCOUNT_DOWNLOAD_ACCEPTED
        }
}

internal class GateRawBlobIndependentDownloadProbe(
    val authorizedUpload: GateRawBlobUploadResult,
    val managementDownload: GateRawBlobDownloadResult,
) {
    override fun toString(): String =
        "GateRawBlobIndependentDownloadProbe(results=redacted)"
}

internal object GateRawBlobCompatibility {
    private val pinnedLocalOnlyViolations = setOf(
        GateRawBlobIsolationViolation.MANAGEMENT_ACCOUNT_UPLOAD_ACCEPTED,
        GateRawBlobIsolationViolation.MANAGEMENT_ACCOUNT_DOWNLOAD_ACCEPTED,
        GateRawBlobIsolationViolation.ORDINARY_ACCOUNT_UPLOAD_ACCEPTED,
    )

    fun requirePinnedLocalOnlyBehavior(
        managementProbes: List<GateRawBlobProbeResult>,
        independentDownload: GateRawBlobIndependentDownloadProbe,
    ) {
        require(
            GateRawBlobIsolation.violations(managementProbes) ==
                pinnedLocalOnlyViolations,
        ) {
            "Pinned Stalwart raw-blob management behavior changed"
        }
        require(
            independentDownload.authorizedUpload is
                GateRawBlobUploadResult.Accepted,
        ) {
            "Authorized raw-blob seed upload did not succeed"
        }
        val managementDownload = independentDownload.managementDownload
        require(
            managementDownload is GateRawBlobDownloadResult.Denied &&
                managementDownload.status in setOf(401, 403, 404),
        ) {
            "Independent cross-Account raw-blob download was not denied"
        }
    }
}

internal class GateAppPasswordClient(
    session: GateJmapSession,
    private val credential: GateCredential,
    private val transport: GateRawBlobTransport,
) {
    private val apiUrl = session.apiUrl

    init {
        require(
            apiUrl.scheme == "http" &&
                apiUrl.host == "127.0.0.1" &&
                apiUrl.port == 18443 &&
                apiUrl.rawPath == "/jmap/" &&
                apiUrl.rawUserInfo == null &&
                apiUrl.rawQuery == null &&
                apiUrl.rawFragment == null,
        ) {
            "Stalwart raw-blob Session must use the dedicated JMAP endpoint"
        }
    }

    suspend fun rawUpload(
        accountId: String,
        payload: ByteArray,
    ): GateRawBlobUploadResult {
        val safeAccountId = safeSegment(accountId, "Account ID")
        require(payload.isNotEmpty() && payload.size <= MAX_PROBE_PAYLOAD_BYTES) {
            "Raw-blob probe payload size is invalid"
        }
        val request = GateRawBlobHttpRequest(
            method = "POST",
            url = endpoint("upload/$safeAccountId"),
            credential = credential,
            contentType = RAW_BLOB_CONTENT_TYPE,
            body = payload,
        )
        val response = transport.execute(request)
        requireUnredirected(request, response)
        return when (response.status) {
            401, 403, 404 -> GateRawBlobUploadResult.Denied(response.status)
            in 200..299 -> GateRawBlobUploadResult.Accepted(
                parseSuccessfulUpload(
                    body = response.body,
                    expectedAccountId = safeAccountId,
                    expectedSize = payload.size,
                ),
            )

            else -> unexpectedStatus(response.status, "Raw blob upload")
        }
    }

    suspend fun rawDownload(
        accountId: String,
        blobId: String,
        expectedPayload: ByteArray,
    ): GateRawBlobDownloadResult {
        val safeAccountId = safeSegment(accountId, "Account ID")
        val safeBlobId = safeSegment(blobId, "Blob ID")
        require(
            expectedPayload.isNotEmpty() &&
                expectedPayload.size <= MAX_PROBE_PAYLOAD_BYTES,
        ) {
            "Raw-blob expected download payload size is invalid"
        }
        val request = GateRawBlobHttpRequest(
            method = "GET",
            url = endpoint(
                "download/$safeAccountId/$safeBlobId/$DOWNLOAD_FILENAME",
            ),
            credential = credential,
            contentType = null,
            body = ByteArray(0),
        )
        val response = transport.execute(request)
        requireUnredirected(request, response)
        return when (response.status) {
            401, 403, 404 -> GateRawBlobDownloadResult.Denied(response.status)
            in 200..299 -> {
                if (
                    response.body.size > MAX_DOWNLOAD_RESPONSE_BYTES ||
                    !response.body.contentEquals(expectedPayload)
                ) {
                    invalidResponse(
                        "Raw blob download response did not match the probe",
                    )
                }
                GateRawBlobDownloadResult.Accepted(
                    status = response.status,
                    byteCount = response.body.size,
                )
            }

            else -> unexpectedStatus(response.status, "Raw blob download")
        }
    }

    private fun parseSuccessfulUpload(
        body: ByteArray,
        expectedAccountId: String,
        expectedSize: Int,
    ): GateUploadedBlob {
        if (body.isEmpty() || body.size > MAX_UPLOAD_RESPONSE_BYTES) {
            invalidResponse("Raw blob upload response size was invalid")
        }
        val value = try {
            Json.parseToJsonElement(body.decodeToString()).jsonObject
        } catch (_: Exception) {
            invalidResponse("Raw blob upload response was not valid JSON")
        }
        val accountId = requiredString(value["accountId"])
        val blobId = requiredString(value["blobId"])
        val type = requiredString(value["type"])
        val size = (value["size"] as? JsonPrimitive)?.longOrNull
            ?: invalidResponse("Raw blob upload response size was malformed")
        if (
            accountId != expectedAccountId ||
                runCatching { safeSegment(blobId, "Blob ID") }.isFailure ||
                type != RAW_BLOB_CONTENT_TYPE ||
                size != expectedSize.toLong()
        ) {
            invalidResponse("Raw blob upload response did not match the probe")
        }
        return GateUploadedBlob(
            accountId = accountId,
            blobId = blobId,
            size = size.toInt(),
        )
    }

    private fun requiredString(value: JsonElement?): String {
        val primitive = value as? JsonPrimitive
        if (primitive == null || !primitive.isString) {
            invalidResponse("Raw blob upload response field was malformed")
        }
        return primitive.content
    }

    private fun requireUnredirected(
        request: GateRawBlobHttpRequest,
        response: GateRawBlobHttpResponse,
    ) {
        if (response.effectiveUrl != request.url) {
            invalidResponse("Raw blob request did not remain on its pinned URL")
        }
    }

    private fun endpoint(path: String): URI = apiUrl.resolve(path)

    private fun safeSegment(value: String, label: String): String {
        require(value.length in 1..MAX_SEGMENT_LENGTH && SEGMENT.matches(value)) {
            "$label is invalid"
        }
        return value
    }

    private fun unexpectedStatus(status: Int, operation: String): Nothing {
        throw GateRawBlobException(
            kind = GateRawBlobFailure.UnexpectedStatus(status),
            message = "$operation returned an inconclusive HTTP status",
        )
    }

    private fun invalidResponse(message: String): Nothing {
        throw GateRawBlobException(
            kind = GateRawBlobFailure.InvalidResponse,
            message = message,
        )
    }

    private companion object {
        val SEGMENT = Regex("[A-Za-z0-9]+")
        const val MAX_SEGMENT_LENGTH = 1_024
        const val MAX_PROBE_PAYLOAD_BYTES = 1_024
        const val MAX_UPLOAD_RESPONSE_BYTES = 64 * 1_024
        const val MAX_DOWNLOAD_RESPONSE_BYTES = 64 * 1_024
        const val DOWNLOAD_FILENAME = "gate0b-probe.bin"
    }
}

internal class KtorGateRawBlobTransport(
    private val client: HttpClient = HttpClient(CIO) {
        followRedirects = false
        install(HttpTimeout) {
            requestTimeoutMillis = 5_000
            connectTimeoutMillis = 3_000
            socketTimeoutMillis = 5_000
        }
    },
) : GateRawBlobTransport, AutoCloseable {
    override suspend fun execute(
        request: GateRawBlobHttpRequest,
    ): GateRawBlobHttpResponse {
        val response = executeGateRawBlobTransportRequest {
            when (request.method) {
                "GET" -> client.get(request.url.toString()) {
                    header(
                        HttpHeaders.Authorization,
                        request.credential.authorizationHeader(),
                    )
                }

                "POST" -> client.post(request.url.toString()) {
                    header(
                        HttpHeaders.Authorization,
                        request.credential.authorizationHeader(),
                    )
                    contentType(ContentType.Application.OctetStream)
                    setBody(request.body)
                }

                else -> error("GateRawBlobHttpRequest validated its method")
            }
        }
        return readGateRawBlobHttpResponse(
            status = response.status.value,
            effectiveUrl = URI(response.call.request.url.toString()),
        ) {
            response.bodyAsBytes()
        }
    }

    override fun close() {
        client.close()
    }
}

internal suspend fun <T> executeGateRawBlobTransportRequest(
    request: suspend () -> T,
): T =
    try {
        request()
    } catch (failure: CancellationException) {
        throw failure
    } catch (failure: Exception) {
        throw GateRawBlobException(
            kind = GateRawBlobFailure.Transport,
            message = "Stalwart raw-blob transport failed (${failure::class.simpleName})",
        )
    }

internal suspend fun readGateRawBlobHttpResponse(
    status: Int,
    effectiveUrl: URI,
    bodyReader: suspend () -> ByteArray,
): GateRawBlobHttpResponse =
    try {
        GateRawBlobHttpResponse(
            status = status,
            effectiveUrl = effectiveUrl,
            body = bodyReader(),
        )
    } catch (failure: CancellationException) {
        throw failure
    } catch (_: Exception) {
        throw GateRawBlobException(
            kind = GateRawBlobFailure.ResponseBody(status),
            message = "Stalwart raw-blob response body could not be read",
        )
    }

private const val RAW_BLOB_CONTENT_TYPE = "application/octet-stream"
