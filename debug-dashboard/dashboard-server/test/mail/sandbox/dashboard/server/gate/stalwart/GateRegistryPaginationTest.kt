package mail.sandbox.dashboard.server.gate.stalwart

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class GateRegistryPaginationTest {
    @Test
    fun acceptsAnEmptyRegistryOnItsFirstPage() = runBlocking {
        val registry = PagedRegistry(
            listOf(page(position = 0, total = 0, ids = emptyList())),
        )

        assertEquals(
            GateRegistryQuerySnapshot(
                ids = emptyList(),
                queryState = "opaque/state:rev-β",
            ),
            collectGateRegistryQuerySnapshot(
                registry = registry,
                objectType = "Account",
                accountId = "management-id",
                pageSize = 2,
            ),
        )
        assertEquals(
            listOf(QueryCall("Account", "management-id", 0, 2)),
            registry.queries,
        )
    }

    @Test
    fun collectsEveryBoundedPageUsingTheReturnedProgress() = runBlocking {
        val registry = PagedRegistry(
            listOf(
                page(position = 0, total = 5, ids = listOf("a", "b")),
                page(
                    position = 2,
                    total = 5,
                    ids = listOf("c", "d"),
                    accountId = null,
                    limit = JsonPrimitive(2),
                ) {
                    this["canCalculateChanges"] = JsonPrimitive(false)
                },
                page(
                    position = 4,
                    total = 5,
                    ids = listOf("e"),
                    limit = JsonPrimitive(0),
                ),
            ),
        )

        val snapshot = collectGateRegistryQuerySnapshot(
            registry = registry,
            objectType = "Account",
            accountId = "management-id",
            pageSize = 2,
        )

        assertEquals(
            GateRegistryQuerySnapshot(
                ids = listOf("a", "b", "c", "d", "e"),
                queryState = "opaque/state:rev-β",
            ),
            snapshot,
        )
        assertEquals(
            listOf(
                QueryCall("Account", "management-id", 0, 2),
                QueryCall("Account", "management-id", 2, 2),
                QueryCall("Account", "management-id", 4, 2),
            ),
            registry.queries,
        )
    }

    @Test
    fun rejectsChangingTotalsDuplicateIdsAndLackOfProgress() = runBlocking {
        val invalidPages = listOf(
            listOf(
                page(position = 0, total = 3, ids = listOf("a", "b")),
                page(position = 2, total = 4, ids = listOf("c")),
            ),
            listOf(
                page(position = 0, total = 3, ids = listOf("a", "b")),
                page(
                    position = 2,
                    total = 3,
                    ids = listOf("c"),
                    queryState = "changed-query-state",
                ),
            ),
            listOf(
                page(position = 0, total = 2, ids = listOf("a", "a")),
            ),
            listOf(
                page(position = 0, total = 3, ids = listOf("a", "b")),
                page(position = 2, total = 3, ids = listOf("b")),
            ),
            listOf(
                page(position = 0, total = 1, ids = emptyList()),
            ),
        )

        invalidPages.forEach { pages ->
            assertFailsWith<IllegalArgumentException> {
                collectGateRegistryQuerySnapshot(
                    registry = PagedRegistry(pages),
                    objectType = "Account",
                    accountId = "management-id",
                    pageSize = 2,
                    maximumPages = 2,
                )
            }
        }
    }

    @Test
    fun rejectsWrongPositionOversizedPagesAndRecordOverflow() = runBlocking {
        val invalid = listOf(
            PagedCase(
                pages = listOf(
                    page(position = 1, total = 1, ids = listOf("a")),
                ),
            ),
            PagedCase(
                pages = listOf(
                    page(
                        position = 0,
                        total = 3,
                        ids = listOf("a", "b", "c"),
                    ),
                ),
            ),
            PagedCase(
                pages = listOf(
                    page(position = 0, total = 1, ids = listOf("a", "b")),
                ),
            ),
            PagedCase(
                pages = listOf(
                    page(position = 0, total = 3, ids = listOf("a", "b")),
                    page(position = 2, total = 3, ids = listOf("c")),
                ),
                maximumRecords = 2,
            ),
            PagedCase(
                pages = listOf(
                    page(position = 0, total = -1, ids = emptyList()),
                ),
            ),
        )

        invalid.forEach { case ->
            assertFailsWith<IllegalArgumentException> {
                collectGateRegistryQuerySnapshot(
                    registry = PagedRegistry(case.pages),
                    objectType = "Account",
                    accountId = "management-id",
                    pageSize = 2,
                    maximumRecords = case.maximumRecords,
                )
            }
        }
    }

    @Test
    fun rejectsWrongAccountAndStopsAtThePageBound() = runBlocking {
        assertFailsWith<IllegalArgumentException> {
            collectGateRegistryQuerySnapshot(
                registry = PagedRegistry(
                    listOf(
                        page(
                            position = 0,
                            total = 1,
                            ids = listOf("a"),
                            accountId = "other-account",
                        ),
                    ),
                ),
                objectType = "Account",
                accountId = "management-id",
            )
        }

        val bounded = PagedRegistry(
            listOf(
                page(position = 0, total = 2, ids = listOf("a")),
                page(position = 1, total = 2, ids = listOf("b")),
            ),
        )
        assertFailsWith<IllegalArgumentException> {
            collectGateRegistryQuerySnapshot(
                registry = bounded,
                objectType = "Account",
                accountId = "management-id",
                pageSize = 1,
                maximumPages = 1,
            )
        }
        assertEquals(1, bounded.queries.size)
    }

    @Test
    fun requiresTheExactPinnedQueryResponsePropertiesAndNativeTypes() =
        runBlocking {
            val marker = "server-controlled-property-marker"
            val missing = listOf(
                "canCalculateChanges",
                "ids",
                "position",
                "queryState",
                "total",
            ).map { property ->
                page(position = 0, total = 0, ids = emptyList()) {
                    remove(property)
                }
            }
            val malformed = listOf(
                page(position = 0, total = 0, ids = emptyList()) {
                    this["canCalculateChanges"] = JsonPrimitive("true")
                },
                page(position = 0, total = 0, ids = emptyList()) {
                    this["ids"] = JsonObject(emptyMap())
                },
                page(position = 0, total = 0, ids = emptyList()) {
                    this["position"] = JsonPrimitive("0")
                },
                page(position = 0, total = 0, ids = emptyList()) {
                    this["queryState"] = JsonPrimitive(true)
                },
                page(position = 0, total = 0, ids = emptyList()) {
                    this["total"] = JsonPrimitive("0")
                },
                page(position = 0, total = 0, ids = emptyList()) {
                    this[marker] = JsonPrimitive(marker)
                },
            )

            (missing + malformed).forEach { response ->
                val failure = assertFailsWith<IllegalArgumentException> {
                    collectGateRegistryQuerySnapshot(
                        registry = PagedRegistry(listOf(response)),
                        objectType = "Account",
                        accountId = "management-id",
                    )
                }
                assertFalse(marker in failure.toString())
            }
        }

    @Test
    fun rejectsMalformedLimitsIdsAndOpaqueTokens() = runBlocking {
        val marker = "server-controlled-id-marker"
        val invalid = listOf(
            page(
                position = 0,
                total = 0,
                ids = emptyList(),
                limit = JsonPrimitive("2"),
            ),
            page(
                position = 0,
                total = 0,
                ids = emptyList(),
                limit = JsonPrimitive(-1),
            ),
            page(
                position = 0,
                total = 0,
                ids = emptyList(),
                limit = JsonPrimitive(3),
            ),
            page(position = 0, total = 1, ids = listOf("$marker/unsafe")),
            page(position = 0, total = 1, ids = listOf("x".repeat(256))),
            page(position = 0, total = 1, ids = listOf("safe")) {
                this["ids"] = JsonArray(listOf(JsonPrimitive(7)))
            },
            page(
                position = 0,
                total = 0,
                ids = emptyList(),
                queryState = "",
            ),
            page(
                position = 0,
                total = 0,
                ids = emptyList(),
                queryState = "x".repeat(4_097),
            ),
            page(
                position = 0,
                total = 0,
                ids = emptyList(),
                callId = JsonPrimitive(""),
            ),
            page(
                position = 0,
                total = 0,
                ids = emptyList(),
                callId = JsonPrimitive("x".repeat(4_097)),
            ),
        )

        invalid.forEach { response ->
            val failure = assertFailsWith<IllegalArgumentException> {
                collectGateRegistryQuerySnapshot(
                    registry = PagedRegistry(listOf(response)),
                    objectType = "Account",
                    accountId = "management-id",
                    pageSize = 2,
                )
            }
            assertFalse(marker in failure.toString())
        }
    }

    private class PagedRegistry(
        responses: List<JsonObject>,
    ) : GateRegistryApi {
        private val responses = ArrayDeque(responses)
        val queries = mutableListOf<QueryCall>()

        override suspend fun discoverSession(): GateJmapSession =
            error("Unexpected Session discovery")

        override suspend fun registryGet(
            objectType: String,
            ids: List<String>?,
            accountId: String?,
        ): JsonObject = error("Unexpected Registry get")

        override suspend fun registryQuery(
            objectType: String,
            filter: JsonObject,
            accountId: String?,
            position: Int,
            limit: Int,
        ): JsonObject {
            queries += QueryCall(
                objectType = objectType,
                accountId = accountId,
                position = position,
                limit = limit,
            )
            return responses.removeFirst()
        }

        override suspend fun registryCreate(
            objectType: String,
            creationId: String,
            value: JsonObject,
            accountId: String?,
        ): JsonObject = error("Unexpected Registry create")

        override suspend fun registryUpdate(
            objectType: String,
            objectId: String,
            patch: JsonObject,
            accountId: String?,
        ): JsonObject = error("Unexpected Registry update")

        override suspend fun registryDestroy(
            objectType: String,
            objectId: String,
            accountId: String?,
        ): JsonObject = error("Unexpected Registry destroy")

        override fun close() = Unit
    }

    private data class QueryCall(
        val objectType: String,
        val accountId: String?,
        val position: Int,
        val limit: Int,
    )

    private data class PagedCase(
        val pages: List<JsonObject>,
        val maximumRecords: Int = 10_000,
    )

    private companion object {
        fun page(
            position: Int,
            total: Int,
            ids: List<String>,
            accountId: String? = "management-id",
            queryState: String = "opaque/state:rev-β",
            limit: JsonElement? = null,
            callId: JsonElement = JsonPrimitive("gate-${position + 1}"),
            mutatePayload: MutableMap<String, JsonElement>.() -> Unit = {},
        ): JsonObject {
            val payload = linkedMapOf<String, JsonElement>(
                "canCalculateChanges" to JsonPrimitive(true),
                "ids" to JsonArray(ids.map(::JsonPrimitive)),
                "position" to JsonPrimitive(position),
                "queryState" to JsonPrimitive(queryState),
                "total" to JsonPrimitive(total),
            )
            accountId?.let { payload["accountId"] = JsonPrimitive(it) }
            limit?.let { payload["limit"] = it }
            payload.mutatePayload()
            return JsonObject(
                mapOf(
                    "methodResponses" to JsonArray(
                        listOf(
                            JsonArray(
                                listOf(
                                    JsonPrimitive("x:Account/query"),
                                    JsonObject(payload),
                                    callId,
                                ),
                            ),
                        ),
                    ),
                ),
            )
        }
    }
}
