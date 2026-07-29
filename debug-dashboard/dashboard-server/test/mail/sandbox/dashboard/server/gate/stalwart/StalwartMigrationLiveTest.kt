package mail.sandbox.dashboard.server.gate.stalwart

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import mail.sandbox.dashboard.server.provider.stalwart.StalwartRuntimeSecretLoader
import mail.sandbox.dashboard.server.provider.stalwart.StalwartRuntimeSecretPaths
import mail.sandbox.dashboard.server.provider.stalwart.credential.CredentialStoreLoadResult
import mail.sandbox.dashboard.server.provider.stalwart.credential.CredentialStorePaths
import mail.sandbox.dashboard.server.provider.stalwart.credential.FileStalwartCredentialStore
import mail.sandbox.dashboard.server.provider.stalwart.credential.STALWART_RESERVED_DESCRIPTION_PREFIX
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartBorrowedSecret
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartCredentialLeaseRegistry
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartCredentialManagementRemote
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartCredentialOwnerRemote
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartCredentialProbeResult
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartGlobalReservedAccount
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartGlobalReservedInventory
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartMailAccessService
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartMailAccessState
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartMailAccount
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartMailCredentialProbeRemote
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartNormalPassword
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartRemoteCreateResult
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartRemoteMutationResult
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartRemoteRead
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartReservedCredential
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartReservedInventory

class StalwartMigrationLiveTest {
    @Test
    fun migratedAccountsAndCredentialsSurviveIntoEnrollmentRequired() = runBlocking {
        val live = StalwartNormalRuntimeEnvironment.load()
        val dashboardRoot = dashboardProjectRoot()
        val repositoryRoot = requireNotNull(dashboardRoot.parent)
        val evidence = StalwartNormalRuntimeEvidence.load(repositoryRoot)
        val managementEvidence = evidence.management
        val runtimeSecrets = StalwartRuntimeSecretLoader(
            StalwartRuntimeSecretPaths.production(dashboardRoot),
        ).load()
        var apiKey = CharArray(0)
        try {
            assertEquals(
                evidence.protectedAccountIds.toSet(),
                runtimeSecrets.protectedAccountIds,
            )
            apiKey = runtimeSecrets.withManagementApiKey(::asciiChars)
            KtorGateHttpTransport().use { transport ->
                GateJmapClient(
                    baseUrl = live.baseUrl,
                    credential = GateCredential.bearer(apiKey),
                    transport = transport,
                ).use { manager ->
                    val session = manager.discoverSession()
                    require(
                        session.apiUrl ==
                            StalwartEndpointProfile.NORMAL_RUNTIME.apiUrl,
                    ) {
                        "Normal-runtime Session API URL did not match"
                    }
                    require(
                        session.primaryAccountId == managementEvidence.accountId,
                    ) {
                        "Normal-runtime Session Account did not match"
                    }
                    require(session.username == MANAGEMENT_ADDRESS) {
                        "Normal-runtime Session username did not match"
                    }

                    val accountQuery = collectGateRegistryQuerySnapshot(
                        registry = manager,
                        objectType = "Account",
                        accountId = managementEvidence.accountId,
                    )
                    val accounts = registryObjectsInChunks(
                        querySnapshot = accountQuery,
                        objectType = "Account",
                        accountId = managementEvidence.accountId,
                        fetch = { chunk ->
                            manager.registryGet(
                                objectType = "Account",
                                ids = chunk,
                                accountId = managementEvidence.accountId,
                            )
                        },
                        requery = {
                            collectGateRegistryQuerySnapshot(
                                registry = manager,
                                objectType = "Account",
                                accountId = managementEvidence.accountId,
                            )
                        },
                    )
                    accounts.values.forEach(::assertNoReservedDashboardCredential)
                    val domainQuery = collectGateRegistryQuerySnapshot(
                        registry = manager,
                        objectType = "Domain",
                        accountId = managementEvidence.accountId,
                    )
                    val domainNames = registryObjectsInChunks(
                        querySnapshot = domainQuery,
                        objectType = "Domain",
                        accountId = managementEvidence.accountId,
                        fetch = { chunk ->
                            manager.registryGet(
                                objectType = "Domain",
                                ids = chunk,
                                accountId = managementEvidence.accountId,
                            )
                        },
                        requery = {
                            collectGateRegistryQuerySnapshot(
                                registry = manager,
                                objectType = "Domain",
                                accountId = managementEvidence.accountId,
                            )
                        },
                    ).mapValues { (_, domain) ->
                        requiredString(domain, "name")
                    }

                    val ordinary = accounts - managementEvidence.accountId
                    val expectedIdentities =
                        evidence.migratedAccounts.map { it.identity }
                            .sortedWith(compareBy({ it.first }, { it.second }))
                    val actualIdentities = ordinary.values.map {
                        accountIdentity(it, domainNames)
                    }.sortedWith(compareBy({ it.first }, { it.second }))
                    require(actualIdentities == expectedIdentities) {
                        "The apply-bound pre-migration Account manifest changed"
                    }
                    val inventories = linkedMapOf<String, StalwartReservedInventory>()
                    val matchedAccounts = linkedMapOf<String, JsonObject>()
                    val unusedAccounts = ordinary.toMutableMap()
                    evidence.migratedAccounts.forEach { expected ->
                        val match = unusedAccounts.entries.single {
                            accountIdentity(it.value, domainNames) ==
                                expected.identity
                        }
                        val account = match.value
                        unusedAccounts.remove(match.key)
                        matchedAccounts[match.key] = account
                        assertExpectedProjection(
                            resolveMigratedAccountProjection(
                                expected,
                                domainNames,
                            ),
                            account,
                        )
                        assertCredentialSurvival(expected, account)
                        val accountId = requiredString(account, "id")
                        val credentials = credentials(account)
                        inventories[accountId] = StalwartReservedInventory(
                            accountId = accountId,
                            reserved = emptyList(),
                            appPasswordCount = credentials.count {
                                requiredString(it, "@type") == "AppPassword"
                            },
                            appPasswordLimit = appPasswordLimit(account),
                        )
                    }
                    assertTrue(unusedAccounts.isEmpty())

                    val credentialPaths = CredentialStorePaths.production(dashboardRoot)
                    FileStalwartCredentialStore(credentialPaths).use { store ->
                        val initialized = assertIs<CredentialStoreLoadResult.Available>(
                            store.load(),
                        )
                        initialized.snapshot.use { snapshot ->
                            assertTrue(
                                snapshot.records.isEmpty(),
                                "The initialized encrypted credential snapshot is not empty",
                            )
                        }
                        val management = ObservedInventoryRemote(
                            inventories = inventories,
                            protectedAccountId = managementEvidence.accountId,
                        )
                        val service = StalwartMailAccessService(
                            store = store,
                            management = management,
                            owner = NoCreateOwner,
                            probe = NoCredentialProbe,
                            leases = StalwartCredentialLeaseRegistry(),
                            protectedAccountIds = evidence.protectedAccountIds.toSet(),
                        )
                        evidence.migratedAccounts.forEach { expected ->
                            val account = matchedAccounts.values.single {
                                accountIdentity(it, domainNames) ==
                                    expected.identity
                            }
                            val projection = service.project(
                                StalwartMailAccount(
                                    accountId = requiredString(account, "id"),
                                    address = accountAddress(account, domainNames),
                                ),
                            )
                            assertEquals(
                                StalwartMailAccessState.EnrollmentRequired,
                                projection.state,
                                "A migrated ordinary Account did not require enrollment",
                            )
                        }
                    }
                }
            }
        } finally {
            apiKey.fill('\u0000')
            runtimeSecrets.close()
        }
    }

    private fun assertExpectedProjection(expected: JsonObject, actual: JsonObject) {
        assertEquals(
            expected.keys + setOf("credentials", "id"),
            actual.keys,
            "Migrated Account returned an unexpected property set",
        )
        expected.forEach { (name, value) ->
            assertEquals(
                value,
                actual[name],
                "Migrated Account property $name changed",
            )
        }
    }

    private fun assertCredentialSurvival(
        expected: StalwartMigratedAccountEvidence,
        account: JsonObject,
    ) {
        assertMigratedCredentialProjections(
            expected = expected.credentialProjections,
            actual = credentialEntries(account),
        )
    }

    private fun assertNoReservedDashboardCredential(account: JsonObject) {
        credentials(account)
            .filter { requiredString(it, "@type") == "AppPassword" }
            .forEach { credential ->
                val description = requiredString(credential, "description")
                assertTrue(
                    !description.startsWith(STALWART_RESERVED_DESCRIPTION_PREFIX),
                    "Migration/bootstrap created a reserved dashboard AppPassword",
                )
            }
    }

    private fun accountAddress(
        account: JsonObject,
        domainNames: Map<String, String>,
    ): String {
        val name = requiredString(account, "name")
        val domainId = requiredString(account, "domainId")
        val domain = domainNames[domainId]
            ?: throw AssertionError("Migrated Account Domain is absent")
        return "$name@$domain"
    }

    private fun accountIdentity(
        account: JsonObject,
        domainNames: Map<String, String>,
    ): Pair<String, String> {
        val domainId = requiredString(account, "domainId")
        val domainName = domainNames[domainId]
            ?: throw AssertionError("Migrated Account Domain is absent")
        return requiredString(account, "name") to domainName
    }

    private fun appPasswordLimit(account: JsonObject): Int? {
        val quotas = account["quotas"] as? JsonObject ?: return null
        val value = quotas["maxAppPasswords"]
        if (value == null || value is JsonNull) return null
        return (value as? JsonPrimitive)
            ?.takeIf { !it.isString }
            ?.content
            ?.toIntOrNull()
            ?.takeIf { it > 0 }
            ?: throw AssertionError("Account AppPassword quota is malformed")
    }

    private class ObservedInventoryRemote(
        private val inventories: Map<String, StalwartReservedInventory>,
        private val protectedAccountId: String,
    ) : StalwartCredentialManagementRemote {
        override suspend fun inventory(
            accountId: String,
        ): StalwartRemoteRead<StalwartReservedInventory> =
            inventories[accountId]
                ?.let { StalwartRemoteRead.Available(it) }
                ?: StalwartRemoteRead.Unavailable

        override suspend fun globalInventory():
            StalwartRemoteRead<StalwartGlobalReservedInventory> =
            StalwartRemoteRead.Available(
                StalwartGlobalReservedInventory(
                    inventories.map { (accountId, inventory) ->
                        StalwartGlobalReservedAccount(
                            accountId = accountId,
                            protectedIdentity = accountId == protectedAccountId,
                            reserved = inventory.reserved,
                        )
                    },
                ),
            )

        override suspend fun revokeReserved(
            accountId: String,
            expected: Set<StalwartReservedCredential>,
            targets: Set<StalwartReservedCredential>,
        ): StalwartRemoteMutationResult =
            StalwartRemoteMutationResult.ReconciliationRequired
    }

    private object NoCreateOwner : StalwartCredentialOwnerRemote {
        override suspend fun createOwned(
            account: StalwartMailAccount,
            description: String,
            normalPassword: StalwartNormalPassword,
        ): StalwartRemoteCreateResult = StalwartRemoteCreateResult.Rejected
    }

    private object NoCredentialProbe : StalwartMailCredentialProbeRemote {
        override suspend fun probe(
            accountId: String,
            address: String,
            secret: StalwartBorrowedSecret,
        ): StalwartCredentialProbeResult =
            StalwartCredentialProbeResult.Unavailable
    }

    private fun dashboardProjectRoot(): Path {
        val working = Path.of(System.getProperty("user.dir"))
            .toAbsolutePath()
            .normalize()
        val dashboard = if (working.fileName?.toString() == "dashboard-server") {
            requireNotNull(working.parent)
        } else {
            working
        }
        require(
            dashboard.fileName?.toString() == "debug-dashboard" &&
                Files.isRegularFile(
                    dashboard.resolve("project.yaml"),
                    java.nio.file.LinkOption.NOFOLLOW_LINKS,
                ) &&
                !Files.isSymbolicLink(dashboard),
        ) {
            "Normal-runtime live gate must run from debug-dashboard"
        }
        return dashboard.toRealPath()
    }

    private companion object {
        const val MANAGEMENT_ADDRESS = "dashboard-management@local.test"
    }
}

internal fun registryObjects(
    response: JsonObject,
    expectedMethod: String,
    accountId: String,
): Map<String, JsonObject> =
    registryObjectSnapshot(
        response = response,
        expectedMethod = expectedMethod,
        accountId = accountId,
    ).objects

private data class GateRegistryObjectSnapshot(
    val objects: Map<String, JsonObject>,
    val state: String,
)

private fun registryObjectSnapshot(
    response: JsonObject,
    expectedMethod: String,
    accountId: String,
): GateRegistryObjectSnapshot {
    val payload = registryPayload(response, expectedMethod)
    require(payload.keys == setOf("accountId", "list", "notFound", "state")) {
        "Registry get returned an unexpected property set"
    }
    require(requiredString(payload, "accountId") == accountId) {
        "Registry get Account did not match the request"
    }
    val state = (payload["state"] as? JsonPrimitive)
        ?.takeIf(JsonPrimitive::isString)
        ?.content
        ?: throw AssertionError("Registry get state is malformed")
    require(state.isBoundedGateRegistryOpaqueText()) {
        "Registry get state is malformed"
    }
    val notFound = payload["notFound"] as? JsonArray
        ?: throw AssertionError("Registry get omitted notFound")
    notFound.forEach { value ->
        val objectId = (value as? JsonPrimitive)
            ?.takeIf(JsonPrimitive::isString)
            ?.content
        require(objectId != null && objectId.isSafeGateRegistryId()) {
            "Registry get returned an invalid notFound object ID"
        }
    }
    require(notFound.isEmpty()) {
        "Registry get reported an unexpected notFound object"
    }
    val values = payload["list"] as? JsonArray
        ?: throw AssertionError("Registry get omitted its object list")
    val objects = values.map { value ->
        val objectValue = value as? JsonObject
            ?: throw AssertionError("Registry get returned a malformed object")
        val objectId = requiredString(objectValue, "id")
        require(objectId.isSafeGateRegistryId()) {
            "Registry get returned an invalid object ID"
        }
        objectId to objectValue
    }.toMap()
    require(values.size == objects.size) {
        "Registry get returned duplicate object IDs"
    }
    return GateRegistryObjectSnapshot(objects = objects, state = state)
}

internal suspend fun registryObjectsInChunks(
    querySnapshot: GateRegistryQuerySnapshot,
    objectType: String,
    accountId: String,
    fetch: suspend (List<String>) -> JsonObject,
    requery: suspend () -> GateRegistryQuerySnapshot,
): Map<String, JsonObject> {
    val ids = querySnapshot.ids
    require(ids.size == ids.toSet().size) {
        "Registry query returned duplicate object IDs"
    }
    val merged = linkedMapOf<String, JsonObject>()
    var expectedGetState: String? = null
    ids.chunked(MAXIMUM_REGISTRY_GET_IDS).forEach { chunk ->
        val snapshot = registryObjectSnapshot(
            response = fetch(chunk),
            expectedMethod = "x:$objectType/get",
            accountId = accountId,
        )
        expectedGetState?.let { state ->
            require(snapshot.state == state) {
                "Registry get state changed between chunks"
            }
        } ?: run {
            expectedGetState = snapshot.state
        }
        val objects = snapshot.objects
        require(objects.keys == chunk.toSet()) {
            "Registry get did not return the exact requested object IDs"
        }
        require(objects.keys.none(merged::containsKey)) {
            "Registry get returned duplicate object IDs across chunks"
        }
        merged.putAll(objects)
    }
    require(merged.keys == ids.toSet()) {
        "Registry get result did not match the queried object IDs"
    }
    val finalQuery = requery()
    require(finalQuery.queryState == querySnapshot.queryState) {
        "Registry query state changed during object reads"
    }
    require(finalQuery.ids == querySnapshot.ids) {
        "Registry query IDs changed during object reads"
    }
    return merged
}

private fun registryPayload(response: JsonObject, expectedMethod: String): JsonObject {
    val responses = response["methodResponses"] as? JsonArray
        ?: throw AssertionError("Registry response omitted methodResponses")
    require(responses.size == 1) {
        "Registry response did not contain exactly one method"
    }
    val tuple = responses.single() as? JsonArray
        ?: throw AssertionError("Registry method response is malformed")
    require(tuple.size == 3) {
        "Registry method response tuple is malformed"
    }
    val responseMethod = (tuple[0] as? JsonPrimitive)
        ?.takeIf(JsonPrimitive::isString)
        ?.content
        ?: throw AssertionError("Registry method response name is malformed")
    require(responseMethod == expectedMethod) {
        "Registry method response did not match the request"
    }
    val callId = (tuple[2] as? JsonPrimitive)
        ?.takeIf(JsonPrimitive::isString)
        ?.content
        ?: throw AssertionError("Registry method request ID is malformed")
    require(callId.isBoundedGateRegistryOpaqueText()) {
        "Registry method request ID is malformed"
    }
    return tuple[1] as? JsonObject
        ?: throw AssertionError("Registry method payload is malformed")
}

internal fun credentials(account: JsonObject): List<JsonObject> {
    val values = account["credentials"] as? JsonObject
        ?: throw AssertionError("Account credentials are absent")
    return values.values.map {
        it as? JsonObject ?: throw AssertionError("Account credential is malformed")
    }
}

internal fun credentialEntries(
    account: JsonObject,
): List<Pair<String, JsonObject>> {
    val values = account["credentials"] as? JsonObject
        ?: throw AssertionError("Account credentials are absent")
    return values.map { (slot, value) ->
        slot to (
            value as? JsonObject
                ?: throw AssertionError("Account credential is malformed")
            )
    }
}

internal fun resolveMigratedAccountProjection(
    expected: StalwartMigratedAccountEvidence,
    liveDomainNames: Map<String, String>,
): JsonObject {
    val liveIdsByClient = linkedMapOf<String, String>()
    expected.domainReferences.forEach { reference ->
        val liveIds = liveDomainNames.filterValues {
            it == reference.domainName
        }.keys
        require(liveIds.size == 1) {
            "Migrated Domain reference did not resolve uniquely"
        }
        liveIdsByClient[reference.clientId] = liveIds.single()
    }
    require(liveIdsByClient.values.size == liveIdsByClient.values.toSet().size) {
        "Migrated Domain references did not resolve uniquely"
    }

    fun resolve(value: JsonElement): JsonElement =
        when (value) {
            is JsonObject -> JsonObject(
                value.mapValues { (name, child) ->
                    if (name == "domainId") {
                        val reference = (child as? JsonPrimitive)
                            ?.takeIf(JsonPrimitive::isString)
                            ?.content
                            ?.takeIf { it.startsWith("#") }
                            ?.drop(1)
                            ?: throw IllegalArgumentException(
                                "Migrated Domain reference is malformed",
                            )
                        JsonPrimitive(
                            liveIdsByClient[reference]
                                ?: throw IllegalArgumentException(
                                    "Migrated Domain reference is unresolved",
                                ),
                        )
                    } else {
                        resolve(child)
                    }
                },
            )
            is JsonArray -> JsonArray(value.map(::resolve))
            is JsonPrimitive, JsonNull -> value
        }

    return resolve(expected.accountProjection) as JsonObject
}

internal fun assertMigratedCredentialProjections(
    expected: List<StalwartMigratedCredentialProjection>,
    actual: List<Pair<String, JsonObject>>,
) {
    require(expected.size == actual.size) {
        "Migrated credential multiplicity changed"
    }
    val actualBySlot = actual.toMap()
    require(
        actualBySlot.size == actual.size &&
            actualBySlot.keys == expected.map { it.slot }.toSet(),
    ) {
        "Migrated credential slots changed"
    }
    val generatedIds = mutableSetOf<String>()
    expected.forEach { expectedEntry ->
        val actualProjection = requireNotNull(actualBySlot[expectedEntry.slot]) {
            "Migrated credential slot is absent"
        }
        val allowedKeys =
            expectedEntry.projection.keys + setOf("allowedIps", "credentialId")
        require(actualProjection.keys == allowedKeys) {
            "Migrated credential returned an unexpected property set"
        }
        val credentialId = requiredString(actualProjection, "credentialId")
        require(generatedIds.add(credentialId)) {
            "Migrated credential IDs are not unique"
        }
        require((actualProjection["allowedIps"] as? JsonObject).orEmpty().isEmpty()) {
            "Migrated credential generated an unexpected IP restriction"
        }
        expectedEntry.projection.forEach { (name, expectedValue) ->
            val actualValue = actualProjection[name]
            require(
                normalizeLiveCredentialValue(name, actualValue) == expectedValue,
            ) {
                "Migrated credential safe projection changed"
            }
        }
    }
}

private fun normalizeLiveCredentialValue(
    name: String,
    value: kotlinx.serialization.json.JsonElement?,
): kotlinx.serialization.json.JsonElement? {
    if (name == "secret" || name == "otpAuth") {
        val marker = (value as? JsonPrimitive)
            ?.takeIf(JsonPrimitive::isString)
            ?.content
        require(marker != null && marker.length >= 4 && marker.all { it == '*' }) {
            "Migrated credential did not return masked secret metadata"
        }
        return JsonPrimitive("****")
    }
    return when (value) {
        is JsonObject -> JsonObject(
            value.mapValues { (childName, child) ->
                normalizeLiveCredentialValue(childName, child)
                    ?: throw AssertionError(
                        "Migrated credential safe projection is malformed",
                    )
            },
        )
        is JsonArray -> JsonArray(
            value.map {
                normalizeLiveCredentialValue("", it)
                    ?: throw AssertionError(
                        "Migrated credential safe projection is malformed",
                    )
            },
        )
        else -> value
    }
}

internal fun requiredString(value: JsonObject, property: String): String =
    (value[property] as? JsonPrimitive)
        ?.takeIf(JsonPrimitive::isString)
        ?.content
        ?.takeIf(String::isNotBlank)
        ?: throw AssertionError("$property is absent or malformed")

private const val MAXIMUM_REGISTRY_GET_IDS = 100

internal fun asciiChars(bytes: ByteArray): CharArray =
    CharArray(bytes.size) { index ->
        val value = bytes[index].toInt() and 0xff
        require(value in 0x21..0x7e) {
            "Stalwart management API key encoding is invalid"
        }
        value.toChar()
    }
