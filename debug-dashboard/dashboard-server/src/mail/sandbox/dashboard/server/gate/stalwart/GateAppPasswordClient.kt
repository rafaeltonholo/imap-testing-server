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
import java.util.UUID
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put
import mail.sandbox.dashboard.server.provider.stalwart.credential.STALWART_RESERVED_DESCRIPTION_PREFIX
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartCredentialManagementRemote
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartGlobalReservedAccount
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartGlobalReservedInventory
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartRemoteMutationResult
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartRemoteRead
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartReservedCredential
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartReservedInventory

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

internal val DASHBOARD_MAIL_PERMISSIONS: Set<String> = linkedSetOf(
    "authenticate",
    "jmapMailboxGet",
    "jmapMailboxCreate",
    "jmapMailboxUpdate",
    "jmapMailboxDestroy",
    "jmapEmailGet",
    "jmapEmailQuery",
    "jmapEmailUpdate",
    "jmapEmailDestroy",
    "jmapEmailImport",
    "jmapIdentityGet",
    "jmapEmailSubmissionGet",
    "jmapEmailSubmissionCreate",
    "jmapBlobGet",
    "jmapBlobUpload",
)

internal class GateAppPasswordDescription private constructor(
    val value: String,
) {
    init {
        require(value.length in 1..256 && '\u0000' !in value) {
            "AppPassword description is invalid"
        }
    }

    override fun toString(): String = value

    companion object {
        private const val PREFIX = "mail-sandbox/debug-dashboard/"

        fun reserved(
            storeId: UUID,
            generation: UInt,
        ): GateAppPasswordDescription {
            require(generation > 0u) {
                "AppPassword generation must be positive"
            }
            return GateAppPasswordDescription("$PREFIX$storeId/$generation")
        }

        internal fun fromServer(value: String): GateAppPasswordDescription =
            GateAppPasswordDescription(value)
    }
}

internal class GateCreatedAppPassword(
    val id: String,
    val description: GateAppPasswordDescription,
    secret: CharArray,
) : AutoCloseable {
    private val secret = validatedSecretCopy(id, secret)
    private var closed = false

    @Synchronized
    fun copySecret(): CharArray {
        check(!closed) { "Created AppPassword secret is closed" }
        return secret.copyOf()
    }

    @Synchronized
    override fun close() {
        if (closed) return
        closed = true
        secret.fill('\u0000')
    }

    override fun toString(): String =
        "GateCreatedAppPassword(id=$id, description=$description, secret=redacted)"

    private companion object {
        fun validatedSecretCopy(
            id: String,
            source: CharArray,
        ): CharArray {
            val copy = source.copyOf()
            return try {
                require(id.isSafeGateId()) {
                    "Created AppPassword ID is invalid"
                }
                require(
                    copy.size >= 4 &&
                        copy[0] == 'a' &&
                        copy[1] == 'p' &&
                        copy[2] == 'p' &&
                        copy[3] == '_',
                ) {
                    "Created AppPassword secret format is invalid"
                }
                copy
            } catch (failure: Throwable) {
                copy.fill('\u0000')
                throw failure
            }
        }
    }
}

internal class GateStoredAppPassword(
    val id: String,
    val description: GateAppPasswordDescription,
    val permissions: Set<String>,
) {
    override fun toString(): String =
        "GateStoredAppPassword(id=$id, description=$description, secret=redacted)"
}

internal class GateEffectivePermissionScope(
    val permissions: Set<String>,
    val edition: String,
    val locale: String,
) {
    override fun toString(): String =
        "GateEffectivePermissionScope(" +
            "permissionCount=${permissions.size}, edition=$edition, locale=$locale)"
}

internal class GateEffectivePermissionClient(
    private val baseUrl: URI,
    private val credential: GateCredential,
    private val transport: GateHttpTransport,
) : AutoCloseable {
    private var closed = false

    init {
        if (baseUrl != URI("http://127.0.0.1:18443")) {
            credential.close()
            throw IllegalArgumentException(
                "Effective permission endpoint must use the dedicated loopback fixture",
            )
        }
    }

    suspend fun fetch(): GateEffectivePermissionScope {
        requireOpen()
        val endpoint = baseUrl.resolve("/api/account")
        val response = transport.execute(
            GateHttpRequest(
                method = "GET",
                url = endpoint,
                credential = credential,
            ),
        )
        if (response.effectiveUrl != endpoint) {
            invalidRegistryResponse(
                "Effective permission request did not remain on its pinned URL",
            )
        }
        if (response.status !in 200..299) {
            throw GateJmapException(
                kind = GateJmapFailure.HttpStatus(response.status),
                message = "Effective permission request was rejected",
            )
        }
        if (response.body.length !in 2..MAX_SCOPE_RESPONSE_CHARS) {
            invalidRegistryResponse(
                "Effective permission response size was invalid",
            )
        }
        val value = try {
            Json.parseToJsonElement(response.body).jsonObject
        } catch (_: Exception) {
            invalidRegistryResponse(
                "Effective permission response was not valid JSON",
            )
        }
        val permissions = value["permissions"] as? JsonArray
            ?: invalidRegistryResponse(
                "Effective permission response omitted permissions",
            )
        val permissionNames = permissions.map { permission ->
            requiredString(
                permission,
                "Effective permission response contained a malformed permission",
            )
        }
        if (
            permissionNames.size != permissionNames.toSet().size ||
                permissionNames.any { !PERMISSION_NAME.matches(it) }
        ) {
            invalidRegistryResponse(
                "Effective permission response contained an invalid permission set",
            )
        }
        val edition = requiredString(
            value["edition"],
            "Effective permission response omitted its edition",
        )
        if (edition != "community") {
            invalidRegistryResponse(
                "Effective permission response was not Community edition",
            )
        }
        val locale = requiredString(
            value["locale"],
            "Effective permission response omitted its locale",
        )
        if (locale.isBlank() || locale.length > 64) {
            invalidRegistryResponse(
                "Effective permission response locale was invalid",
            )
        }
        return GateEffectivePermissionScope(
            permissions = permissionNames.toSet(),
            edition = edition,
            locale = locale,
        )
    }

    override fun close() {
        if (closed) return
        closed = true
        credential.close()
    }

    private fun requireOpen() {
        check(!closed) { "Effective permission client is closed" }
    }

    private companion object {
        val PERMISSION_NAME = Regex("[A-Za-z][A-Za-z0-9]*")
        const val MAX_SCOPE_RESPONSE_CHARS = 64 * 1_024
    }
}

internal sealed interface GateAppPasswordCreateResult {
    class Created(
        val credential: GateCreatedAppPassword,
    ) : GateAppPasswordCreateResult {
        override fun toString(): String =
            "GateAppPasswordCreateResult.Created(credential=$credential)"
    }

    class Rejected(
        val type: String,
    ) : GateAppPasswordCreateResult {
        override fun toString(): String =
            "GateAppPasswordCreateResult.Rejected(type=redacted)"
    }
}

internal class GateAppPasswordUpdateDenial(
    val type: String,
) {
    override fun toString(): String =
        "GateAppPasswordUpdateDenial(type=$type, replacement=redacted)"
}

internal class GateAppPasswordEnrollmentClient(
    private val registry: GateRegistryApi,
    private val ownerAccountId: String,
    private val ownerAddress: String,
) {
    init {
        require(ownerAccountId.isSafeGateId()) {
            "AppPassword owner Account ID is invalid"
        }
        require(
            OWNER_ADDRESS.matches(ownerAddress) &&
                ownerAddress.endsWith("@${GateBootstrap.DOMAIN}") &&
                ownerAddress != GateBootstrap.MANAGEMENT_ADDRESS,
        ) {
            "AppPassword owner address is invalid"
        }
    }

    suspend fun create(
        description: GateAppPasswordDescription,
    ): GateCreatedAppPassword =
        when (val result = tryCreate(description)) {
            is GateAppPasswordCreateResult.Created -> result.credential
            is GateAppPasswordCreateResult.Rejected ->
                throw IllegalStateException("AppPassword create was rejected")
        }

    suspend fun tryCreate(
        description: GateAppPasswordDescription,
    ): GateAppPasswordCreateResult {
        requireOwnerSession()
        val response = registry.registryCreate(
            objectType = APP_PASSWORD_OBJECT,
            creationId = CREATION_ID,
            value = buildJsonObject {
                put("description", description.value)
                put(
                    "permissions",
                    buildJsonObject {
                        put("@type", "Replace")
                        put(
                            "permissions",
                            buildJsonObject {
                                DASHBOARD_MAIL_PERMISSIONS.forEach {
                                    put(it, true)
                                }
                            },
                        )
                    },
                )
                put("allowedIps", buildJsonObject {})
            },
            accountId = ownerAccountId,
        )
        val payload = methodPayload(
            response = response,
            expectedMethod = "x:AppPassword/set",
        )
        requireAccount(payload)
        val notCreated = (payload["notCreated"] as? JsonObject).orEmpty()
        val createdMap = (payload["created"] as? JsonObject).orEmpty()
        if (CREATION_ID in notCreated) {
            if (createdMap.isNotEmpty() || notCreated.size != 1) {
                invalidRegistryResponse(
                    "AppPassword create returned conflicting outcomes",
                )
            }
            val rejection = notCreated[CREATION_ID] as? JsonObject
                ?: invalidRegistryResponse(
                    "AppPassword create rejection was malformed",
                )
            val type = requiredString(
                rejection["type"],
                "AppPassword create rejection type was malformed",
            )
            if (!ERROR_TYPE.matches(type)) {
                invalidRegistryResponse(
                    "AppPassword create rejection type was invalid",
                )
            }
            return GateAppPasswordCreateResult.Rejected(type)
        }
        if (notCreated.isNotEmpty() || createdMap.size != 1) {
            invalidRegistryResponse(
                "AppPassword create returned an invalid outcome",
            )
        }
        val created = createdMap[CREATION_ID] as? JsonObject
            ?: invalidRegistryResponse("AppPassword create result was absent")
        val id = requiredString(
            created["id"],
            "AppPassword create ID was malformed",
        )
        val secret = requiredString(
            created["secret"],
            "AppPassword create secret was absent",
        ).toCharArray()
        return try {
            GateAppPasswordCreateResult.Created(
                GateCreatedAppPassword(
                    id = id,
                    description = description,
                    secret = secret,
                ),
            )
        } finally {
            secret.fill('\u0000')
        }
    }

    suspend fun requireSecretUpdateRejected(
        credentialId: String,
        replacement: CharArray,
    ): GateAppPasswordUpdateDenial {
        require(credentialId.isSafeGateId()) {
            "AppPassword ID is invalid"
        }
        require(replacement.isNotEmpty()) {
            "AppPassword mutation probe is absent"
        }
        requireOwnerSession()
        val payload = methodPayload(
            response = registry.registryUpdate(
                objectType = APP_PASSWORD_OBJECT,
                objectId = credentialId,
                patch = buildJsonObject {
                    put("secret", replacement.concatToString())
                },
                accountId = ownerAccountId,
            ),
            expectedMethod = "x:AppPassword/set",
        )
        requireAccount(payload)
        val updated = payload["updated"] as? JsonObject
            ?: invalidRegistryResponse(
                "AppPassword secret mutation omitted updated",
            )
        if (updated.isNotEmpty()) {
            invalidRegistryResponse(
                "AppPassword secret mutation unexpectedly succeeded",
            )
        }
        val failures = payload["notUpdated"] as? JsonObject
            ?: invalidRegistryResponse(
                "AppPassword secret mutation omitted notUpdated",
            )
        if (failures.keys != setOf(credentialId)) {
            invalidRegistryResponse(
                "AppPassword secret mutation returned an invalid outcome",
            )
        }
        val failure = failures[credentialId] as? JsonObject
            ?: invalidRegistryResponse(
                "AppPassword secret mutation omitted the exact ID",
            )
        val type = requiredString(
            failure["type"],
            "AppPassword secret mutation rejection was malformed",
        )
        if (type != "invalidPatch") {
            invalidRegistryResponse(
                "AppPassword secret mutation used an unexpected rejection type",
            )
        }
        return GateAppPasswordUpdateDenial(type)
    }

    suspend fun destroy(credentialId: String) {
        require(credentialId.isSafeGateId()) {
            "AppPassword ID is invalid"
        }
        requireOwnerSession()
        val payload = methodPayload(
            response = registry.registryDestroy(
                objectType = APP_PASSWORD_OBJECT,
                objectId = credentialId,
                accountId = ownerAccountId,
            ),
            expectedMethod = "x:AppPassword/set",
        )
        requireAccount(payload)
        if (!(payload["notDestroyed"] as? JsonObject).orEmpty().isEmpty()) {
            invalidRegistryResponse("AppPassword destroy was rejected")
        }
        val destroyed = payload["destroyed"] as? JsonArray
            ?: invalidRegistryResponse(
                "AppPassword destroy omitted its result",
            )
        if (
            destroyed.size != 1 ||
                requiredString(
                    destroyed.single(),
                    "AppPassword destroyed ID was malformed",
                ) != credentialId
        ) {
            invalidRegistryResponse(
                "AppPassword destroy did not confirm the exact ID",
            )
        }
    }

    suspend fun inventory(): List<GateStoredAppPassword> {
        requireOwnerSession()
        val queryPayload = methodPayload(
            response = registry.registryQuery(
                objectType = APP_PASSWORD_OBJECT,
                filter = buildJsonObject {},
                accountId = ownerAccountId,
            ),
            expectedMethod = "x:AppPassword/query",
        )
        requireAccount(queryPayload)
        val ids = (queryPayload["ids"] as? JsonArray)
            ?.map { value ->
                requiredString(
                    value,
                    "AppPassword query returned a malformed ID",
                ).also {
                    if (!it.isSafeGateId()) {
                        invalidRegistryResponse(
                            "AppPassword query returned an invalid ID",
                        )
                    }
                }
            }
            ?: invalidRegistryResponse("AppPassword query omitted IDs")
        if (ids.size != ids.toSet().size) {
            invalidRegistryResponse("AppPassword query returned duplicate IDs")
        }
        val positionPrimitive = queryPayload["position"] as? JsonPrimitive
        val position = positionPrimitive
            ?.takeUnless(JsonPrimitive::isString)
            ?.longOrNull
            ?: invalidRegistryResponse(
                "AppPassword query position was malformed",
            )
        val totalPrimitive = queryPayload["total"] as? JsonPrimitive
        val total = totalPrimitive
            ?.takeUnless(JsonPrimitive::isString)
            ?.longOrNull
            ?: invalidRegistryResponse(
                "AppPassword query total was malformed",
            )
        if (
            position != 0L ||
                total < 0L ||
                total != ids.size.toLong()
        ) {
            invalidRegistryResponse(
                "AppPassword query result was incomplete",
            )
        }
        if (ids.isEmpty()) return emptyList()

        val getPayload = methodPayload(
            response = registry.registryGet(
                objectType = APP_PASSWORD_OBJECT,
                ids = ids,
                accountId = ownerAccountId,
            ),
            expectedMethod = "x:AppPassword/get",
        )
        requireAccount(getPayload)
        val notFound = getPayload["notFound"] as? JsonArray
            ?: invalidRegistryResponse("AppPassword get omitted notFound")
        if (notFound.isNotEmpty()) {
            invalidRegistryResponse("AppPassword inventory changed during its exact get")
        }
        val list = getPayload["list"] as? JsonArray
            ?: invalidRegistryResponse("AppPassword get omitted its list")
        val values = list.map(::storedAppPassword)
        if (
            values.size != ids.size ||
                values.map { it.id }.toSet() != ids.toSet()
        ) {
            invalidRegistryResponse(
                "AppPassword get did not return the exact queried IDs",
            )
        }
        return ids.map { id -> values.single { it.id == id } }
    }

    private suspend fun requireOwnerSession() {
        val session = registry.discoverSession()
        require(
            session.primaryAccountId == ownerAccountId &&
                session.username == ownerAddress &&
                session.apiUrl == PINNED_JMAP_API_URL,
        ) {
            "Normal-password enrollment authenticated the wrong Account"
        }
    }

    private fun storedAppPassword(value: JsonElement): GateStoredAppPassword {
        val objectValue = value as? JsonObject
            ?: invalidRegistryResponse("AppPassword get returned a malformed object")
        val id = requiredString(
            objectValue["id"],
            "Stored AppPassword ID was malformed",
        )
        if (!id.isSafeGateId()) {
            invalidRegistryResponse("Stored AppPassword ID was invalid")
        }
        val description = GateAppPasswordDescription.fromServer(
            requiredString(
                objectValue["description"],
                "Stored AppPassword description was malformed",
            ),
        )
        if (
            requiredString(
                objectValue["secret"],
                "Stored AppPassword secret sentinel was malformed",
            ) != MASKED_SECRET
        ) {
            invalidRegistryResponse(
                "Stored AppPassword did not contain the masked secret sentinel",
            )
        }
        val permissions = objectValue["permissions"] as? JsonObject
            ?: invalidRegistryResponse("Stored AppPassword permissions were absent")
        if (
            requiredString(
                permissions["@type"],
                "Stored AppPassword permission mode was malformed",
            ) != "Replace"
        ) {
            invalidRegistryResponse(
                "Stored AppPassword permission mode was not Replace",
            )
        }
        val permissionMap = permissions["permissions"] as? JsonObject
            ?: invalidRegistryResponse(
                "Stored AppPassword permission map was absent",
            )
        if (
            permissionMap.values.any { value ->
                val primitive = value as? JsonPrimitive
                primitive == null ||
                    primitive.isString ||
                    primitive.booleanOrNull != true
            }
        ) {
            invalidRegistryResponse(
                "Stored AppPassword contained a disabled permission",
            )
        }
        val effective = permissionMap.keys
        if (effective != DASHBOARD_MAIL_PERMISSIONS) {
            invalidRegistryResponse(
                "Stored AppPassword permissions differed from the baseline",
            )
        }
        val allowedIps = objectValue["allowedIps"] as? JsonObject
            ?: invalidRegistryResponse(
                "Stored AppPassword allowed IP map was absent",
            )
        if (allowedIps.isNotEmpty()) {
            invalidRegistryResponse(
                "Stored AppPassword unexpectedly restricted source addresses",
            )
        }
        return GateStoredAppPassword(
            id = id,
            description = description,
            permissions = effective,
        )
    }

    private fun requireAccount(payload: JsonObject) {
        if (
            requiredString(
                payload["accountId"],
                "AppPassword response Account ID was malformed",
            ) != ownerAccountId
        ) {
            invalidRegistryResponse(
                "AppPassword response belonged to the wrong Account",
            )
        }
    }

    private companion object {
        val OWNER_ADDRESS =
            Regex("[a-z0-9][a-z0-9._+-]{0,63}@[a-z0-9.-]{1,190}")
        val PINNED_JMAP_API_URL = URI("http://127.0.0.1:18443/jmap/")
        const val APP_PASSWORD_OBJECT = "AppPassword"
        const val CREATION_ID = "dashboard-app-password"
        const val MASKED_SECRET = "****"
        val ERROR_TYPE = Regex("[A-Za-z][A-Za-z0-9]*")
    }
}

internal sealed interface GateTargetedRevocationResult {
    data object Revoked : GateTargetedRevocationResult

    data object ReconciliationRequired : GateTargetedRevocationResult
}

internal class GateManagementAppPasswordRevoker(
    private val registry: GateRegistryApi,
    private val managementAccountId: String,
) {
    init {
        require(managementAccountId.isSafeGateId()) {
            "Management Account ID is invalid"
        }
    }

    suspend fun revoke(
        targetAccountId: String,
        targetCredentialId: String,
        expectedDescription: GateAppPasswordDescription,
    ): GateTargetedRevocationResult {
        require(
            targetAccountId.isSafeGateId() &&
                targetAccountId != managementAccountId,
        ) {
            "Target Account ID is invalid"
        }
        require(targetCredentialId.isSafeGateId()) {
            "Target AppPassword ID is invalid"
        }
        requireManagementSession()

        val before = credentialEntries(fetchTargetAccount(targetAccountId))
        val targetKey = CredentialStableId(
            type = "AppPassword",
            credentialId = targetCredentialId,
        )
        val target = before.entries.singleOrNull { entry ->
            entry.stableId == targetKey &&
                requiredString(
                    entry.value["description"],
                    "Target AppPassword description was malformed",
                ) == expectedDescription.value
        } ?: return GateTargetedRevocationResult.ReconciliationRequired

        try {
            val updatePayload = methodPayload(
                response = registry.registryUpdate(
                    objectType = "Account",
                    objectId = targetAccountId,
                    patch = buildJsonObject {
                        put("credentials/${target.mapKey}", JsonNull)
                    },
                    accountId = managementAccountId,
                ),
                expectedMethod = "x:Account/set",
            )
            requireManagementResponseAccount(updatePayload)
        } catch (failure: CancellationException) {
            throw failure
        } catch (_: Exception) {
            // The mutation may have been applied before its response was lost.
            // The single exact verification below is authoritative.
        }

        val after = try {
            credentialEntries(fetchTargetAccount(targetAccountId))
        } catch (failure: CancellationException) {
            throw failure
        } catch (_: Exception) {
            return GateTargetedRevocationResult.ReconciliationRequired
        }
        val expectedAfter = before.byStableId - targetKey
        return if (after.byStableId == expectedAfter) {
            GateTargetedRevocationResult.Revoked
        } else {
            GateTargetedRevocationResult.ReconciliationRequired
        }
    }

    private suspend fun requireManagementSession() {
        val session = registry.discoverSession()
        require(
            session.primaryAccountId == managementAccountId &&
                session.username == GateBootstrap.MANAGEMENT_ADDRESS &&
                session.apiUrl == PINNED_JMAP_API_URL,
        ) {
            "Targeted revocation authenticated the wrong management Account"
        }
    }

    private suspend fun fetchTargetAccount(targetAccountId: String): JsonObject {
        val payload = methodPayload(
            response = registry.registryGet(
                objectType = "Account",
                ids = listOf(targetAccountId),
                accountId = managementAccountId,
            ),
            expectedMethod = "x:Account/get",
        )
        requireManagementResponseAccount(payload)
        if (!(payload["notFound"] as? JsonArray).orEmpty().isEmpty()) {
            invalidRegistryResponse(
                "Target Account disappeared during credential reconciliation",
            )
        }
        val list = payload["list"] as? JsonArray
            ?: invalidRegistryResponse("Target Account get omitted its list")
        if (list.size != 1) {
            invalidRegistryResponse(
                "Target Account get did not return exactly one Account",
            )
        }
        val account = list.single() as? JsonObject
            ?: invalidRegistryResponse("Target Account get was malformed")
        if (
            requiredString(
                account["id"],
                "Target Account ID was malformed",
            ) != targetAccountId
        ) {
            invalidRegistryResponse("Target Account get returned the wrong Account")
        }
        return account
    }

    private fun credentialEntries(
        account: JsonObject,
    ): CredentialEntries {
        val credentials = account["credentials"] as? JsonObject
            ?: invalidRegistryResponse("Target Account credentials were absent")
        val entries = credentials.map { (mapKey, value) ->
            if (mapKey.toUIntOrNull() == null) {
                invalidRegistryResponse(
                    "Target Account credential position was malformed",
                )
            }
            val credential = value as? JsonObject
                ?: invalidRegistryResponse(
                    "Target Account credential was malformed",
                )
            val stableId = CredentialStableId(
                type = requiredString(
                    credential["@type"],
                    "Target Account credential type was malformed",
                ),
                credentialId = requiredString(
                    credential["credentialId"],
                    "Target Account credential ID was malformed",
                ),
            )
            if (!stableId.credentialId.isSafeGateId()) {
                invalidRegistryResponse(
                    "Target Account credential ID was invalid",
                )
            }
            CredentialEntry(
                mapKey = mapKey,
                stableId = stableId,
                value = credential,
            )
        }
        val byStableId = entries.associate { it.stableId to it.value }
        if (byStableId.size != entries.size) {
            invalidRegistryResponse(
                "Target Account contained duplicate stable credential IDs",
            )
        }
        return CredentialEntries(
            entries = entries,
            byStableId = byStableId,
        )
    }

    private fun requireManagementResponseAccount(payload: JsonObject) {
        if (
            requiredString(
                payload["accountId"],
                "Management registry response Account ID was malformed",
            ) != managementAccountId
        ) {
            invalidRegistryResponse(
                "Management registry response used the wrong Account context",
            )
        }
    }

    private data class CredentialStableId(
        val type: String,
        val credentialId: String,
    )

    private data class CredentialEntry(
        val mapKey: String,
        val stableId: CredentialStableId,
        val value: JsonObject,
    )

    private data class CredentialEntries(
        val entries: List<CredentialEntry>,
        val byStableId: Map<CredentialStableId, JsonObject>,
    )

    private companion object {
        val PINNED_JMAP_API_URL = URI("http://127.0.0.1:18443/jmap/")
    }
}

/**
 * Management-key adapter for the credential lifecycle. Every mutation uses a
 * fresh Account read, one positional batch patch, and one authoritative read.
 */
internal class GateStalwartCredentialManagementRemote(
    private val registry: GateRegistryApi,
    private val managementAccountId: String,
    protectedAccountIds: Set<String>,
) : StalwartCredentialManagementRemote {
    private val protectedAccountIds = protectedAccountIds.toSet()
    private val mutex = Mutex()

    init {
        require(
            managementAccountId.isSafeGateId() &&
                managementAccountId in this.protectedAccountIds &&
                this.protectedAccountIds.all(String::isSafeGateId),
        ) {
            "Lifecycle management Account protection is invalid"
        }
    }

    override suspend fun inventory(
        accountId: String,
    ): StalwartRemoteRead<StalwartReservedInventory> = mutex.withLock {
        if (!accountId.isSafeGateId()) {
            return@withLock StalwartRemoteRead.Unavailable
        }
        try {
            requireManagementSession()
            StalwartRemoteRead.Available(
                inventoryFromAccount(fetchExactAccount(accountId)),
            )
        } catch (failure: CancellationException) {
            throw failure
        } catch (_: Exception) {
            StalwartRemoteRead.Unavailable
        }
    }

    override suspend fun globalInventory():
        StalwartRemoteRead<StalwartGlobalReservedInventory> = mutex.withLock {
        try {
            requireManagementSession()
            val ids = queryEveryAccountId()
            val accounts = fetchExactAccounts(ids)
            StalwartRemoteRead.Available(
                StalwartGlobalReservedInventory(
                    ids.map { accountId ->
                        val account = requireNotNull(accounts[accountId])
                        StalwartGlobalReservedAccount(
                            accountId = accountId,
                            protectedIdentity =
                                accountId in protectedAccountIds,
                            reserved = credentialEntries(account).reserved,
                        )
                    },
                ),
            )
        } catch (failure: CancellationException) {
            throw failure
        } catch (_: Exception) {
            StalwartRemoteRead.Unavailable
        }
    }

    override suspend fun revokeReserved(
        accountId: String,
        expected: Set<StalwartReservedCredential>,
    ): StalwartRemoteMutationResult = mutex.withLock {
        revokeReservedLocked(accountId, expected)
    }

    private suspend fun revokeReservedLocked(
        accountId: String,
        expected: Set<StalwartReservedCredential>,
    ): StalwartRemoteMutationResult {
        if (!accountId.isSafeGateId() || expected.isEmpty()) {
            return StalwartRemoteMutationResult.ReconciliationRequired
        }
        return try {
            requireManagementSession()
            val before = credentialEntries(fetchExactAccount(accountId))
            val targets = mutableListOf<LifecycleCredentialEntry>()
            for (credential in expected) {
                val stableId = LifecycleCredentialStableId(
                    type = APP_PASSWORD_TYPE,
                    credentialId = credential.credentialId,
                )
                val target = before.entries.singleOrNull { entry ->
                    entry.stableId == stableId &&
                        requiredString(
                            entry.value["description"],
                            "Lifecycle AppPassword description was malformed",
                        ) == credential.description
                } ?: return StalwartRemoteMutationResult.ReconciliationRequired
                targets += target
            }
            if (targets.map { it.stableId }.toSet().size != targets.size) {
                return StalwartRemoteMutationResult.ReconciliationRequired
            }

            try {
                val update = methodPayload(
                    response = registry.registryUpdate(
                        objectType = "Account",
                        objectId = accountId,
                        patch = buildJsonObject {
                            targets.sortedBy { it.mapKey.toUInt() }.forEach {
                                put("credentials/${it.mapKey}", JsonNull)
                            }
                        },
                        accountId = managementAccountId,
                    ),
                    expectedMethod = "x:Account/set",
                )
                requireManagementResponseAccount(update)
                val notUpdated =
                    (update["notUpdated"] as? JsonObject).orEmpty()
                val updated = (update["updated"] as? JsonObject).orEmpty()
                if (
                    notUpdated.isNotEmpty() ||
                    updated.keys != setOf(accountId)
                ) {
                    invalidRegistryResponse(
                        "Lifecycle credential batch update was not exact",
                    )
                }
            } catch (failure: CancellationException) {
                throw failure
            } catch (_: Exception) {
                // Dispatch may have succeeded. The single post-fetch decides.
            }

            val after = credentialEntries(fetchExactAccount(accountId))
            val expectedAfter =
                before.byStableId - targets.map { it.stableId }.toSet()
            if (after.byStableId == expectedAfter) {
                StalwartRemoteMutationResult.Verified
            } else {
                StalwartRemoteMutationResult.ReconciliationRequired
            }
        } catch (failure: CancellationException) {
            throw failure
        } catch (_: Exception) {
            StalwartRemoteMutationResult.ReconciliationRequired
        }
    }

    private suspend fun requireManagementSession() {
        val session = registry.discoverSession()
        require(
            session.primaryAccountId == managementAccountId &&
                session.username == GateBootstrap.MANAGEMENT_ADDRESS &&
                session.apiUrl == PINNED_JMAP_API_URL,
        ) {
            "Lifecycle management authenticated the wrong Account"
        }
    }

    private suspend fun queryEveryAccountId(): List<String> {
        val payload = methodPayload(
            response = registry.registryQuery(
                objectType = "Account",
                accountId = managementAccountId,
            ),
            expectedMethod = "x:Account/query",
        )
        requireManagementResponseAccount(payload)
        val position = requiredNativeLong(
            payload["position"],
            "Lifecycle Account query position was malformed",
        )
        val total = requiredNativeLong(
            payload["total"],
            "Lifecycle Account query total was malformed",
        )
        val ids = payload["ids"] as? JsonArray
            ?: invalidRegistryResponse(
                "Lifecycle Account query omitted IDs",
            )
        val parsed = ids.map { value ->
            requiredString(
                value,
                "Lifecycle Account query ID was malformed",
            ).also {
                if (!it.isSafeGateId()) {
                    invalidRegistryResponse(
                        "Lifecycle Account query ID was invalid",
                    )
                }
            }
        }
        if (
            position != 0L ||
            total != parsed.size.toLong() ||
            parsed.size != parsed.toSet().size
        ) {
            invalidRegistryResponse(
                "Lifecycle Account query was incomplete",
            )
        }
        return parsed
    }

    private suspend fun fetchExactAccount(accountId: String): JsonObject =
        fetchExactAccounts(listOf(accountId)).getValue(accountId)

    private suspend fun fetchExactAccounts(
        accountIds: List<String>,
    ): Map<String, JsonObject> {
        if (accountIds.isEmpty()) return emptyMap()
        val payload = methodPayload(
            response = registry.registryGet(
                objectType = "Account",
                ids = accountIds,
                accountId = managementAccountId,
            ),
            expectedMethod = "x:Account/get",
        )
        requireManagementResponseAccount(payload)
        if (!(payload["notFound"] as? JsonArray).orEmpty().isEmpty()) {
            invalidRegistryResponse(
                "Lifecycle Account inventory lost an Account",
            )
        }
        val list = payload["list"] as? JsonArray
            ?: invalidRegistryResponse(
                "Lifecycle Account inventory omitted its list",
            )
        val accounts = list.map { value ->
            val account = value as? JsonObject
                ?: invalidRegistryResponse(
                    "Lifecycle Account inventory entry was malformed",
                )
            val accountId = requiredString(
                account["id"],
                "Lifecycle Account inventory ID was malformed",
            )
            if (!accountId.isSafeGateId()) {
                invalidRegistryResponse(
                    "Lifecycle Account inventory ID was invalid",
                )
            }
            accountId to account
        }.toMap()
        if (
            accounts.size != list.size ||
            accounts.keys != accountIds.toSet()
        ) {
            invalidRegistryResponse(
                "Lifecycle Account inventory was not exact",
            )
        }
        return accounts
    }

    private fun inventoryFromAccount(
        account: JsonObject,
    ): StalwartReservedInventory {
        val accountId = requiredString(
            account["id"],
            "Lifecycle Account ID was malformed",
        )
        val credentials = credentialEntries(account)
        val quotas = account["quotas"] as? JsonObject
            ?: invalidRegistryResponse(
                "Lifecycle Account quotas were absent",
            )
        val limit = when (val value = quotas["maxAppPasswords"]) {
            null, JsonNull -> null
            is JsonPrimitive -> {
                if (value.isString) {
                    invalidRegistryResponse(
                        "Lifecycle AppPassword quota was not native",
                    )
                }
                value.longOrNull
                    ?.takeIf { it in 1..Int.MAX_VALUE.toLong() }
                    ?.toInt()
                    ?: invalidRegistryResponse(
                        "Lifecycle AppPassword quota was invalid",
                    )
            }
            else -> invalidRegistryResponse(
                "Lifecycle AppPassword quota was malformed",
            )
        }
        return StalwartReservedInventory(
            accountId = accountId,
            reserved = credentials.reserved,
            appPasswordCount = credentials.appPasswordCount,
            appPasswordLimit = limit,
        )
    }

    private fun credentialEntries(
        account: JsonObject,
    ): LifecycleCredentialEntries {
        val credentials = account["credentials"] as? JsonObject
            ?: invalidRegistryResponse(
                "Lifecycle Account credentials were absent",
            )
        var appPasswordCount = 0
        val reserved = mutableListOf<StalwartReservedCredential>()
        val entries = credentials.map { (mapKey, value) ->
            if (mapKey.toUIntOrNull() == null) {
                invalidRegistryResponse(
                    "Lifecycle credential position was malformed",
                )
            }
            val credential = value as? JsonObject
                ?: invalidRegistryResponse(
                    "Lifecycle credential was malformed",
                )
            val stableId = LifecycleCredentialStableId(
                type = requiredString(
                    credential["@type"],
                    "Lifecycle credential type was malformed",
                ),
                credentialId = requiredString(
                    credential["credentialId"],
                    "Lifecycle credential ID was malformed",
                ),
            )
            if (!stableId.credentialId.isSafeGateId()) {
                invalidRegistryResponse(
                    "Lifecycle credential ID was invalid",
                )
            }
            if (stableId.type == APP_PASSWORD_TYPE) {
                appPasswordCount += 1
                val description = requiredString(
                    credential["description"],
                    "Lifecycle AppPassword description was malformed",
                )
                if (
                    description.startsWith(
                        STALWART_RESERVED_DESCRIPTION_PREFIX,
                    )
                ) {
                    reserved += StalwartReservedCredential(
                        credentialId = stableId.credentialId,
                        description = description,
                    )
                }
            }
            LifecycleCredentialEntry(
                mapKey = mapKey,
                stableId = stableId,
                value = credential,
            )
        }
        val byStableId = entries.associate { it.stableId to it.value }
        if (byStableId.size != entries.size) {
            invalidRegistryResponse(
                "Lifecycle Account contained duplicate credential IDs",
            )
        }
        return LifecycleCredentialEntries(
            entries = entries,
            byStableId = byStableId,
            reserved = reserved,
            appPasswordCount = appPasswordCount,
        )
    }

    private fun requireManagementResponseAccount(payload: JsonObject) {
        if (
            requiredString(
                payload["accountId"],
                "Lifecycle management response Account ID was malformed",
            ) != managementAccountId
        ) {
            invalidRegistryResponse(
                "Lifecycle management response used the wrong Account",
            )
        }
    }

    private data class LifecycleCredentialStableId(
        val type: String,
        val credentialId: String,
    )

    private data class LifecycleCredentialEntry(
        val mapKey: String,
        val stableId: LifecycleCredentialStableId,
        val value: JsonObject,
    )

    private data class LifecycleCredentialEntries(
        val entries: List<LifecycleCredentialEntry>,
        val byStableId: Map<LifecycleCredentialStableId, JsonObject>,
        val reserved: List<StalwartReservedCredential>,
        val appPasswordCount: Int,
    )

    private companion object {
        val PINNED_JMAP_API_URL = URI("http://127.0.0.1:18443/jmap/")
        const val APP_PASSWORD_TYPE = "AppPassword"
    }
}

private fun requiredNativeLong(
    value: JsonElement?,
    message: String,
): Long {
    val primitive = value as? JsonPrimitive
    if (
        primitive == null ||
        primitive.isString ||
        primitive.longOrNull == null
    ) {
        invalidRegistryResponse(message)
    }
    return requireNotNull(primitive.longOrNull)
}

private fun String.isSafeGateId(): Boolean =
    length in 1..1_024 && GATE_ID.matches(this)

private fun methodPayload(
    response: JsonObject,
    expectedMethod: String,
): JsonObject {
    val responses = response["methodResponses"] as? JsonArray
        ?: invalidRegistryResponse("Registry response omitted methodResponses")
    if (responses.size != 1) {
        invalidRegistryResponse(
            "Registry response did not contain exactly one method",
        )
    }
    val method = responses.single() as? JsonArray
        ?: invalidRegistryResponse("Registry method response was malformed")
    if (method.size != 3) {
        invalidRegistryResponse("Registry method response tuple was malformed")
    }
    if (
        requiredString(
            method[0],
            "Registry response method was malformed",
        ) != expectedMethod
    ) {
        invalidRegistryResponse("Registry response method did not match")
    }
    requiredString(method[2], "Registry response call ID was malformed")
    return method[1] as? JsonObject
        ?: invalidRegistryResponse("Registry response payload was malformed")
}

private fun requiredString(
    value: JsonElement?,
    message: String,
): String {
    val primitive = value as? JsonPrimitive
    if (primitive == null || !primitive.isString) {
        invalidRegistryResponse(message)
    }
    return primitive.content
}

private fun invalidRegistryResponse(message: String): Nothing =
    throw GateJmapException(
        kind = GateJmapFailure.InvalidResponse,
        message = message,
    )

private val GATE_ID = Regex("[A-Za-z0-9]+")

internal class GateAppPasswordClient(
    session: GateJmapSession,
    private val credential: GateCredential,
    private val transport: GateRawBlobTransport,
) : AutoCloseable {
    private val apiUrl = session.apiUrl
    private var closed = false

    init {
        if (
            apiUrl.scheme != "http" ||
            apiUrl.host != "127.0.0.1" ||
            apiUrl.port != 18443 ||
            apiUrl.rawPath != "/jmap/" ||
            apiUrl.rawUserInfo != null ||
            apiUrl.rawQuery != null ||
            apiUrl.rawFragment != null
        ) {
            credential.close()
            throw IllegalArgumentException(
                "Stalwart raw-blob Session must use the dedicated JMAP endpoint",
            )
        }
    }

    suspend fun rawUpload(
        accountId: String,
        payload: ByteArray,
    ): GateRawBlobUploadResult {
        requireOpen()
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
        requireOpen()
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
        val sizePrimitive = value["size"] as? JsonPrimitive
        val size = sizePrimitive
            ?.takeUnless(JsonPrimitive::isString)
            ?.longOrNull
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

    override fun close() {
        if (closed) return
        closed = true
        credential.close()
    }

    private fun requireOpen() {
        check(!closed) { "Raw-blob client is closed" }
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
