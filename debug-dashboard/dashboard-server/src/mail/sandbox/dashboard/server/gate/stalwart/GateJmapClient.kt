package mail.sandbox.dashboard.server.gate.stalwart

import io.ktor.client.HttpClient
import io.ktor.client.engine.cio.CIO
import io.ktor.client.plugins.HttpTimeout
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.contentType
import java.net.URI
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.StandardCharsets
import java.util.Base64
import kotlinx.coroutines.CancellationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put

internal sealed class GateCredential(
    val scheme: String,
) : AutoCloseable {
    internal open val basicUsername: String? = null

    internal abstract fun authorizationHeader(): String

    final override fun toString(): String = "GateCredential(scheme=$scheme, value=redacted)"

    companion object {
        fun basic(username: String, secret: CharArray): GateCredential {
            require(username.isNotBlank() && ':' !in username) { "Basic username is invalid" }
            require(secret.isNotEmpty()) { "Basic secret is absent" }
            return Basic(username, secret)
        }

        fun bearer(secret: CharArray): GateCredential {
            require(secret.isNotEmpty()) { "Bearer secret is absent" }
            return Bearer(secret)
        }

        private const val BASIC_PREFIX = "Basic "
        private const val BEARER_PREFIX = "Bearer "
    }

    private class Basic(
        override val basicUsername: String,
        secret: CharArray,
    ) : GateCredential("Basic") {
        private val secret = secret.copyOf()
        private var closed = false

        @Synchronized
        override fun authorizationHeader(): String {
            check(!closed) { "Gate credential is closed" }
            val clearText = CharArray(basicUsername.length + 1 + secret.size)
            var utf8Buffer: ByteBuffer? = null
            var utf8Bytes = ByteArray(0)
            var encodedBytes = ByteArray(0)
            var headerChars = CharArray(0)
            return try {
                basicUsername.toCharArray(clearText, destinationOffset = 0)
                clearText[basicUsername.length] = ':'
                secret.copyInto(
                    destination = clearText,
                    destinationOffset = basicUsername.length + 1,
                )
                utf8Buffer = StandardCharsets.UTF_8.encode(CharBuffer.wrap(clearText))
                utf8Bytes = ByteArray(requireNotNull(utf8Buffer).remaining())
                requireNotNull(utf8Buffer).get(utf8Bytes)
                encodedBytes = Base64.getEncoder().encode(utf8Bytes)
                headerChars = CharArray(BASIC_PREFIX.length + encodedBytes.size)
                BASIC_PREFIX.toCharArray(headerChars, destinationOffset = 0)
                encodedBytes.forEachIndexed { index, byte ->
                    headerChars[BASIC_PREFIX.length + index] =
                        byte.toInt().toChar()
                }
                headerChars.concatToString()
            } finally {
                clearText.fill('\u0000')
                utf8Bytes.fill(0)
                encodedBytes.fill(0)
                headerChars.fill('\u0000')
                utf8Buffer?.takeIf(ByteBuffer::hasArray)?.array()?.fill(0)
            }
        }

        @Synchronized
        override fun close() {
            if (closed) return
            closed = true
            secret.fill('\u0000')
        }
    }

    private class Bearer(
        secret: CharArray,
    ) : GateCredential("Bearer") {
        private val secret = secret.copyOf()
        private var closed = false

        @Synchronized
        override fun authorizationHeader(): String {
            check(!closed) { "Gate credential is closed" }
            val header = CharArray(BEARER_PREFIX.length + secret.size)
            return try {
                BEARER_PREFIX.toCharArray(header, destinationOffset = 0)
                secret.copyInto(
                    destination = header,
                    destinationOffset = BEARER_PREFIX.length,
                )
                header.concatToString()
            } finally {
                header.fill('\u0000')
            }
        }

        @Synchronized
        override fun close() {
            if (closed) return
            closed = true
            secret.fill('\u0000')
        }
    }

}

internal class GateHttpRequest(
    val method: String,
    val url: URI,
    val credential: GateCredential,
    val body: JsonObject? = null,
) {
    init {
        require(method == "GET" || method == "POST") { "Unsupported gate HTTP method" }
        require(!url.path.orEmpty().startsWith("/api/principal")) {
            "The removed legacy principal API is forbidden"
        }
    }

    override fun toString(): String =
        "GateHttpRequest(method=$method, url=$url, credential=$credential, body=redacted)"
}

internal class GateHttpResponse(
    val status: Int,
    val effectiveUrl: URI,
    val body: String,
    val location: String? = null,
) {
    override fun toString(): String =
        "GateHttpResponse(status=$status, effectiveUrl=$effectiveUrl, body=redacted)"
}

internal fun interface GateHttpTransport {
    suspend fun execute(request: GateHttpRequest): GateHttpResponse
}

internal sealed interface GateJmapFailure {
    data class HttpStatus(val status: Int) : GateJmapFailure

    data class MethodError(val type: String) : GateJmapFailure

    data object InvalidResponse : GateJmapFailure

    data object Transport : GateJmapFailure
}

internal class GateJmapException(
    val kind: GateJmapFailure,
    message: String,
) : IllegalStateException(message)

internal data class GateJmapSession(
    val apiUrl: URI,
    val username: String?,
    val primaryAccountId: String?,
)

internal enum class GateJmapCapability(
    val urn: String,
) {
    CORE("urn:ietf:params:jmap:core"),
    MAIL("urn:ietf:params:jmap:mail"),
    SUBMISSION("urn:ietf:params:jmap:submission"),
    BLOB("urn:ietf:params:jmap:blob"),
    STALWART("urn:stalwart:jmap"),
}

internal class GateJmapClient(
    private val profile: StalwartEndpointProfile,
    private val credential: GateCredential,
    private val transport: GateHttpTransport,
) : GateRegistryApi, AutoCloseable {
    private var cachedSession: GateJmapSession? = null
    private var callSequence = 0L
    private var closed = false

    internal constructor(
        baseUrl: URI,
        credential: GateCredential,
        transport: GateHttpTransport,
    ) : this(
        profile = try {
            StalwartEndpointProfile.fromBaseUrl(baseUrl)
        } catch (exception: IllegalArgumentException) {
            credential.close()
            throw exception
        },
        credential = credential,
        transport = transport,
    )

    override suspend fun discoverSession(): GateJmapSession {
        requireOpen()
        cachedSession?.let { return it }
        val discoveryUrl = profile.baseUrl.resolve("/.well-known/jmap")
        val discoveryResponse = transport.execute(
            GateHttpRequest(
                method = "GET",
                url = discoveryUrl,
                credential = credential,
            ),
        )
        if (discoveryResponse.effectiveUrl != discoveryUrl) {
            invalidResponse(
                "JMAP Session discovery did not remain on its pinned URL",
            )
        }
        val response = if (discoveryResponse.status == CANONICAL_REDIRECT_STATUS) {
            val canonicalSessionUrl = profile.baseUrl.resolve(CANONICAL_SESSION_PATH)
            val location = discoveryResponse.location
                ?: invalidResponse("JMAP Session redirect omitted Location")
            val redirectUrl = try {
                discoveryUrl.resolve(location)
            } catch (_: Exception) {
                invalidResponse("JMAP Session redirect Location was malformed")
            }
            if (redirectUrl != canonicalSessionUrl) {
                invalidResponse("JMAP Session redirect target was not canonical")
            }
            transport.execute(
                GateHttpRequest(
                    method = "GET",
                    url = canonicalSessionUrl,
                    credential = credential,
                ),
            ).also { redirected ->
                if (redirected.effectiveUrl != canonicalSessionUrl) {
                    invalidResponse(
                        "JMAP Session response did not remain on its canonical URL",
                    )
                }
            }
        } else {
            discoveryResponse
        }
        requireSuccess(response, "JMAP Session discovery")
        val json = parseObject(response.body, "JMAP Session")
        val apiText = requiredString(
            value = json["apiUrl"],
            invalidMessage = "JMAP Session did not advertise a valid apiUrl",
        )
        val apiUrl = try {
            response.effectiveUrl.resolve(apiText)
        } catch (_: Exception) {
            invalidResponse("JMAP Session advertised a malformed apiUrl")
        }
        requireSafeApiUrl(apiUrl)
        val primaryAccounts = when (val value = json["primaryAccounts"]) {
            null, JsonNull -> null
            is JsonObject -> value
            else -> invalidResponse("JMAP Session primaryAccounts was malformed")
        }
        val primaryAccountId = optionalString(
            value = primaryAccounts?.get(STALWART_CAPABILITY),
            invalidMessage = "JMAP Session primary Account was malformed",
        )
        return GateJmapSession(
            apiUrl = apiUrl,
            username = optionalString(
                value = json["username"],
                invalidMessage = "JMAP Session username was malformed",
            ),
            primaryAccountId = primaryAccountId,
        ).also { cachedSession = it }
    }

    override suspend fun registryGet(
        objectType: String,
        ids: List<String>?,
        accountId: String?,
    ): JsonObject = call(
        methodName = "x:${validateObjectType(objectType)}/get",
        arguments = buildJsonObject {
            accountId?.let { put("accountId", it) }
            if (ids != null) {
                put("ids", JsonArray(ids.map(::stringElement)))
            }
        },
    )

    override suspend fun registryQuery(
        objectType: String,
        filter: JsonObject,
        accountId: String?,
        position: Int,
        limit: Int,
    ): JsonObject = call(
        methodName = "x:${validateObjectType(objectType)}/query",
        arguments = buildJsonObject {
            require(position >= 0) {
                "Registry query position is invalid"
            }
            require(limit in 1..MAX_REGISTRY_QUERY_PAGE) {
                "Registry query limit is invalid"
            }
            accountId?.let { put("accountId", it) }
            put("filter", filter)
            put("sort", JsonArray(emptyList()))
            put("position", position)
            put("limit", limit)
            put("calculateTotal", true)
        },
    )

    override suspend fun registryCreate(
        objectType: String,
        creationId: String,
        value: JsonObject,
        accountId: String?,
    ): JsonObject = call(
        methodName = "x:${validateObjectType(objectType)}/set",
        arguments = buildJsonObject {
            accountId?.let { put("accountId", it) }
            put(
                "create",
                buildJsonObject {
                    put(creationId, value)
                },
            )
        },
    )

    override suspend fun registryUpdate(
        objectType: String,
        objectId: String,
        patch: JsonObject,
        accountId: String?,
    ): JsonObject = call(
        methodName = "x:${validateObjectType(objectType)}/set",
        arguments = buildJsonObject {
            accountId?.let { put("accountId", it) }
            put(
                "update",
                buildJsonObject {
                    put(objectId, patch)
                },
            )
        },
    )

    override suspend fun registryDestroy(
        objectType: String,
        objectId: String,
        accountId: String?,
    ): JsonObject = call(
        methodName = "x:${validateObjectType(objectType)}/set",
        arguments = buildJsonObject {
            accountId?.let { put("accountId", it) }
            put("destroy", JsonArray(listOf(stringElement(objectId))))
        },
    )

    suspend fun call(
        methodName: String,
        arguments: JsonObject,
        capabilities: List<GateJmapCapability> = REGISTRY_CAPABILITIES,
    ): JsonObject {
        requireOpen()
        require(!methodName.contains("/api/principal")) {
            "The removed legacy principal API is forbidden"
        }
        require(
            capabilities.isNotEmpty() &&
                capabilities.first() == GateJmapCapability.CORE &&
                capabilities.size == capabilities.toSet().size,
        ) {
            "JMAP capabilities must be explicit, unique, and Core-first"
        }
        val session = discoverSession()
        val callId = "gate-${++callSequence}"
        val requestBody = buildJsonObject {
            put(
                "using",
                buildJsonArray {
                    capabilities.forEach { capability ->
                        add(stringElement(capability.urn))
                    }
                },
            )
            put(
                "methodCalls",
                buildJsonArray {
                    add(
                        buildJsonArray {
                            add(stringElement(methodName))
                            add(arguments)
                            add(stringElement(callId))
                        },
                    )
                },
            )
        }
        val response = transport.execute(
            GateHttpRequest(
                method = "POST",
                url = session.apiUrl,
                credential = credential,
                body = requestBody,
            ),
        )
        if (response.effectiveUrl != session.apiUrl) {
            invalidResponse(
                "JMAP method response did not remain on the pinned API URL",
            )
        }
        requireSuccess(response, "JMAP method")
        val parsed = parseObject(response.body, "JMAP method response")
        val methodResponses = parsed["methodResponses"] as? JsonArray
            ?: throw GateJmapException(
                kind = GateJmapFailure.InvalidResponse,
                message = "JMAP response did not contain methodResponses",
            )
        if (methodResponses.size != 1) {
            throw GateJmapException(
                kind = GateJmapFailure.InvalidResponse,
                message = "JMAP response did not contain exactly one result",
            )
        }
        val result = methodResponses.single() as? JsonArray
            ?: throw GateJmapException(
                kind = GateJmapFailure.InvalidResponse,
                message = "JMAP method result was malformed",
            )
        if (result.size != 3) {
            invalidResponse("JMAP method response tuple was malformed")
        }
        val responseMethod = requiredString(
            value = result[0],
            invalidMessage = "JMAP response method was malformed",
        )
        val responseArguments = result[1] as? JsonObject
            ?: invalidResponse("JMAP response arguments were malformed")
        val responseCallId = requiredString(
            value = result[2],
            invalidMessage = "JMAP response call ID was malformed",
        )
        if (responseCallId != callId) {
            throw GateJmapException(
                kind = GateJmapFailure.InvalidResponse,
                message = "JMAP response call ID did not match the request",
            )
        }
        if (responseMethod == "error") {
            val type = requiredString(
                value = responseArguments["type"],
                invalidMessage = "JMAP method error type was malformed",
            )
            throw GateJmapException(
                kind = GateJmapFailure.MethodError(type),
                message = "JMAP method returned a typed error",
            )
        }
        if (responseMethod != methodName) {
            throw GateJmapException(
                kind = GateJmapFailure.InvalidResponse,
                message = "JMAP response method did not match the request",
            )
        }
        return parsed
    }

    private fun requireSafeApiUrl(url: URI) {
        if (url == profile.apiUrl) {
            return
        }
        invalidResponse("JMAP Session advertised an unsafe API URL")
    }

    private fun requireSuccess(response: GateHttpResponse, operation: String) {
        if (response.status !in 200..299) {
            throw GateJmapException(
                kind = GateJmapFailure.HttpStatus(response.status),
                message = "$operation failed with HTTP status ${response.status}",
            )
        }
    }

    private fun parseObject(value: String, label: String): JsonObject =
        runCatching { Json.parseToJsonElement(value).jsonObject }
            .getOrElse {
                throw GateJmapException(
                    kind = GateJmapFailure.InvalidResponse,
                    message = "$label was not valid JSON",
                )
            }

    private fun requiredString(
        value: JsonElement?,
        invalidMessage: String,
    ): String {
        val primitive = value as? JsonPrimitive
        if (primitive == null || !primitive.isString) {
            invalidResponse(invalidMessage)
        }
        return primitive.content
    }

    private fun optionalString(
        value: JsonElement?,
        invalidMessage: String,
    ): String? {
        if (value == null || value == JsonNull) return null
        return requiredString(value, invalidMessage)
    }

    private fun invalidResponse(message: String): Nothing {
        throw GateJmapException(
            kind = GateJmapFailure.InvalidResponse,
            message = message,
        )
    }

    private fun validateObjectType(value: String): String {
        require(Regex("[A-Za-z][A-Za-z0-9]*").matches(value)) {
            "Registry object type is invalid"
        }
        return value
    }

    override fun close() {
        if (closed) return
        closed = true
        credential.close()
    }

    private fun requireOpen() {
        check(!closed) { "Gate JMAP client is closed" }
    }

    private companion object {
        val REGISTRY_CAPABILITIES = listOf(
            GateJmapCapability.CORE,
            GateJmapCapability.STALWART,
        )
        const val STALWART_CAPABILITY = "urn:stalwart:jmap"
        const val MAX_REGISTRY_QUERY_PAGE = 100
        const val CANONICAL_REDIRECT_STATUS = 307
        const val CANONICAL_SESSION_PATH = "/jmap/session"
    }
}

internal class KtorGateHttpTransport(
    followRedirects: Boolean = false,
    private val client: HttpClient = createGateHttpClient(followRedirects),
) : GateHttpTransport, AutoCloseable {
    init {
        require(!followRedirects) {
            "Gate JMAP transport must not follow redirects"
        }
    }

    override suspend fun execute(request: GateHttpRequest): GateHttpResponse {
        val response = executeGateTransportRequest {
            when (request.method) {
                "GET" -> client.get(request.url.toString()) {
                    header(HttpHeaders.Authorization, request.credential.authorizationHeader())
                }

                "POST" -> client.post(request.url.toString()) {
                    header(HttpHeaders.Authorization, request.credential.authorizationHeader())
                    contentType(ContentType.Application.Json)
                    setBody(requireNotNull(request.body).toString())
                }

                else -> error("GateHttpRequest validated its method")
            }
        }
        return readGateHttpResponse(
            status = response.status.value,
            effectiveUrl = URI(response.call.request.url.toString()),
            location = response.headers[HttpHeaders.Location],
        ) {
            response.bodyAsText()
        }
    }

    override fun close() {
        client.close()
    }
}

private fun createGateHttpClient(followRedirects: Boolean): HttpClient {
    require(!followRedirects) {
        "Gate JMAP transport must not follow redirects"
    }
    return HttpClient(CIO) {
        this.followRedirects = false
        install(HttpTimeout) {
            requestTimeoutMillis = 5_000
            connectTimeoutMillis = 3_000
            socketTimeoutMillis = 5_000
        }
    }
}

internal suspend fun <T> executeGateTransportRequest(
    request: suspend () -> T,
): T =
    try {
        request()
    } catch (failure: CancellationException) {
        throw failure
    } catch (failure: Exception) {
        throw GateJmapException(
            kind = GateJmapFailure.Transport,
            message = "Stalwart request transport failed (${failure::class.simpleName})",
        )
    }

internal suspend fun readGateHttpResponse(
    status: Int,
    effectiveUrl: URI,
    location: String? = null,
    bodyReader: suspend () -> String,
): GateHttpResponse =
    try {
        GateHttpResponse(
            status = status,
            effectiveUrl = effectiveUrl,
            body = bodyReader(),
            location = location,
        )
    } catch (failure: CancellationException) {
        throw failure
    } catch (_: Exception) {
        throw GateJmapException(
            kind = GateJmapFailure.Transport,
            message = "Stalwart response body could not be read",
        )
    }

private fun stringElement(value: String): JsonElement =
    kotlinx.serialization.json.JsonPrimitive(value)
