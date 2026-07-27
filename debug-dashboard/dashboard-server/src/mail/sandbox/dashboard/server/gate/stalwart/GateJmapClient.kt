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
) {
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
    }

    private class Basic(
        override val basicUsername: String,
        secret: CharArray,
    ) : GateCredential("Basic") {
        private val secret = secret.copyOf()

        override fun authorizationHeader(): String {
            val bytes =
                "$basicUsername:${secret.concatToString()}".toByteArray(Charsets.UTF_8)
            return "Basic ${Base64.getEncoder().encodeToString(bytes)}"
        }
    }

    private class Bearer(
        secret: CharArray,
    ) : GateCredential("Bearer") {
        private val secret = secret.copyOf()

        override fun authorizationHeader(): String = "Bearer ${secret.concatToString()}"
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

internal class GateJmapClient(
    private val baseUrl: URI,
    private val credential: GateCredential,
    private val transport: GateHttpTransport,
) : GateRegistryApi {
    private var cachedSession: GateJmapSession? = null
    private var callSequence = 0L

    init {
        require(
            baseUrl.scheme == "http" &&
                baseUrl.host == "127.0.0.1" &&
                baseUrl.port == 18443 &&
                baseUrl.rawUserInfo == null &&
                baseUrl.rawQuery == null &&
                baseUrl.rawFragment == null &&
                (baseUrl.path.isNullOrEmpty() || baseUrl.path == "/"),
        ) {
            "Stalwart gate base URL must be the dedicated loopback endpoint"
        }
    }

    override suspend fun discoverSession(): GateJmapSession {
        cachedSession?.let { return it }
        val discoveryUrl = baseUrl.resolve("/.well-known/jmap")
        val response = transport.execute(
            GateHttpRequest(
                method = "GET",
                url = discoveryUrl,
                credential = credential,
            ),
        )
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
    ): JsonObject = call(
        methodName = "x:${validateObjectType(objectType)}/query",
        arguments = buildJsonObject {
            accountId?.let { put("accountId", it) }
            put("filter", filter)
            put("sort", JsonArray(emptyList()))
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
    ): JsonObject {
        require(!methodName.contains("/api/principal")) {
            "The removed legacy principal API is forbidden"
        }
        val session = discoverSession()
        val callId = "gate-${++callSequence}"
        val requestBody = buildJsonObject {
            put(
                "using",
                buildJsonArray {
                    add(stringElement(CORE_CAPABILITY))
                    add(stringElement(STALWART_CAPABILITY))
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
        if (
            url.scheme == baseUrl.scheme &&
                url.host == baseUrl.host &&
                url.port == baseUrl.port &&
                url.rawPath == "/jmap/" &&
                url.rawUserInfo == null &&
                url.rawQuery == null &&
                url.rawFragment == null
        ) {
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

    private companion object {
        const val CORE_CAPABILITY = "urn:ietf:params:jmap:core"
        const val STALWART_CAPABILITY = "urn:stalwart:jmap"
    }
}

internal class KtorGateHttpTransport(
    private val client: HttpClient = HttpClient(CIO) {
        install(HttpTimeout) {
            requestTimeoutMillis = 5_000
            connectTimeoutMillis = 3_000
            socketTimeoutMillis = 5_000
        }
    },
) : GateHttpTransport, AutoCloseable {
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
        ) {
            response.bodyAsText()
        }
    }

    override fun close() {
        client.close()
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
    bodyReader: suspend () -> String,
): GateHttpResponse =
    try {
        GateHttpResponse(
            status = status,
            effectiveUrl = effectiveUrl,
            body = bodyReader(),
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
