package mail.sandbox.dashboard.server.gate.stalwart

import java.nio.CharBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonObject

internal data class GateRegistryQuerySnapshot(
    val ids: List<String>,
    val queryState: String,
)

internal suspend fun collectGateRegistryQuerySnapshot(
    registry: GateRegistryApi,
    objectType: String,
    accountId: String,
    pageSize: Int = 100,
    maximumRecords: Int = 10_000,
    maximumPages: Int = 100,
): GateRegistryQuerySnapshot {
    require(pageSize in 1..100)
    require(maximumRecords in 1..10_000)
    require(maximumPages in 1..100)
    val collected = mutableListOf<String>()
    val seenIds = mutableSetOf<String>()
    var position = 0
    var expectedTotal: Int? = null
    var expectedQueryState: String? = null
    repeat(maximumPages) {
        val response = registry.registryQuery(
            objectType = objectType,
            filter = buildJsonObject {},
            accountId = accountId,
            position = position,
            limit = pageSize,
        )
        val page = decodeGateRegistryQueryPage(
            response = response,
            objectType = objectType,
            accountId = accountId,
            requestedPageSize = pageSize,
        )
        require(page.position == position) {
            "Registry query response position is inconsistent"
        }
        require(page.total in 0..maximumRecords) {
            "Registry query response total is outside the record bound"
        }
        expectedTotal?.let { total ->
            require(page.total == total) {
                "Registry query response total changed between pages"
            }
        } ?: run {
            expectedTotal = page.total
        }
        expectedQueryState?.let { queryState ->
            require(page.queryState == queryState) {
                "Registry query state changed between pages"
            }
        } ?: run {
            expectedQueryState = page.queryState
        }
        require(page.ids.size <= pageSize) {
            "Registry query response exceeded the requested page size"
        }
        require(collected.size + page.ids.size <= page.total) {
            "Registry query response exceeded its declared total"
        }
        page.ids.forEach { id ->
            require(seenIds.add(id)) {
                "Registry query response contains a duplicate ID"
            }
        }
        collected += page.ids
        if (collected.size == page.total) {
            return GateRegistryQuerySnapshot(
                ids = collected.toList(),
                queryState = requireNotNull(expectedQueryState),
            )
        }
        require(page.ids.isNotEmpty()) {
            "Registry query response made no pagination progress"
        }
        position += page.ids.size
    }
    throw IllegalArgumentException("Registry query pagination exceeded its page bound")
}

private data class GateRegistryQueryPage(
    val ids: List<String>,
    val position: Int,
    val queryState: String,
    val total: Int,
)

private fun decodeGateRegistryQueryPage(
    response: JsonObject,
    objectType: String,
    accountId: String,
    requestedPageSize: Int,
): GateRegistryQueryPage {
    val responses = response["methodResponses"] as? JsonArray
        ?: throw IllegalArgumentException("Registry query response is malformed")
    require(responses.size == 1) {
        "Registry query response is malformed"
    }
    val tuple = responses.single() as? JsonArray
        ?: throw IllegalArgumentException("Registry query response is malformed")
    require(tuple.size == 3) {
        "Registry query response is malformed"
    }
    require(tuple[0].requiredPageString() == "x:$objectType/query") {
        "Registry query response is malformed"
    }
    require(tuple[2].requiredPageString().isBoundedGateRegistryOpaqueText()) {
        "Registry query response call ID is malformed"
    }
    val payload = tuple[1] as? JsonObject
        ?: throw IllegalArgumentException("Registry query response is malformed")
    require(
        payload.keys.containsAll(REQUIRED_QUERY_RESPONSE_PROPERTIES) &&
            payload.keys.all(ALLOWED_QUERY_RESPONSE_PROPERTIES::contains),
    ) {
        "Registry query response has an invalid property set"
    }
    payload["accountId"]?.let {
        require(it.requiredPageString() == accountId) {
            "Registry query response belongs to another Account"
        }
    }
    val canCalculateChanges = payload["canCalculateChanges"] as? JsonPrimitive
    require(
        canCalculateChanges != null &&
            !canCalculateChanges.isString &&
            canCalculateChanges.booleanOrNull != null,
    ) {
        "Registry query change capability is malformed"
    }
    val ids = (payload["ids"] as? JsonArray)
        ?.map { it.requiredPageString() }
        ?: throw IllegalArgumentException("Registry query IDs are malformed")
    require(ids.all(String::isSafeGateRegistryId)) {
        "Registry query response contains an invalid ID"
    }
    payload["limit"]?.let {
        require(payload.requiredPageInt("limit") in 0..requestedPageSize) {
            "Registry query response limit is malformed"
        }
    }
    val queryState = payload["queryState"]?.requiredPageString()
        ?: throw IllegalArgumentException("Registry query response is malformed")
    require(queryState.isBoundedGateRegistryOpaqueText()) {
        "Registry query state is malformed"
    }
    return GateRegistryQueryPage(
        ids = ids,
        position = payload.requiredPageInt("position"),
        queryState = queryState,
        total = payload.requiredPageInt("total"),
    )
}

private fun JsonObject.requiredPageInt(name: String): Int {
    val value = this[name] as? JsonPrimitive
        ?: throw IllegalArgumentException("Registry query response is malformed")
    require(!value.isString) {
        "Registry query response is malformed"
    }
    return value.content.toIntOrNull()
        ?: throw IllegalArgumentException("Registry query response is malformed")
}

private fun kotlinx.serialization.json.JsonElement.requiredPageString(): String =
    (this as? JsonPrimitive)
        ?.takeIf(JsonPrimitive::isString)
        ?.content
        ?: throw IllegalArgumentException("Registry query response is malformed")

internal fun String.isSafeGateRegistryId(): Boolean =
    SAFE_REGISTRY_ID.matches(this)

internal fun String.isBoundedGateRegistryOpaqueText(): Boolean {
    if (isEmpty()) return false
    val encoded = try {
        Charsets.UTF_8.newEncoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .encode(CharBuffer.wrap(this))
    } catch (_: CharacterCodingException) {
        return false
    }
    return encoded.remaining() <= MAXIMUM_OPAQUE_TEXT_BYTES
}

private val ALLOWED_QUERY_RESPONSE_PROPERTIES = setOf(
    "accountId",
    "canCalculateChanges",
    "ids",
    "limit",
    "position",
    "queryState",
    "total",
)
private val REQUIRED_QUERY_RESPONSE_PROPERTIES =
    ALLOWED_QUERY_RESPONSE_PROPERTIES - setOf("accountId", "limit")
private val SAFE_REGISTRY_ID = Regex("[A-Za-z0-9_-]{1,255}")
private const val MAXIMUM_OPAQUE_TEXT_BYTES = 4_096
