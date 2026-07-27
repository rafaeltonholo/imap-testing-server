package mail.sandbox.dashboard.server.gate.stalwart

import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermission
import java.nio.file.attribute.PosixFilePermissions
import java.security.SecureRandom
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

internal object StalwartFixtureAudit {
    private const val IMAGE = "stalwartlabs/stalwart:v0.16.14"
    private const val PUBLIC_URL = "http://127.0.0.1:18443"
    private const val CONFIG_JSON =
        "{\"@type\":\"RocksDb\",\"path\":\"/var/lib/stalwart/\"}\n"
    private const val SCRATCH_MOUNT =
        "../../../.runtime/stalwart-gate0b/data:/var/lib/stalwart"
    private const val CONFIG_MOUNT = "./:/etc/stalwart:ro"
    private const val RECOVERY_ENV_INTERPOLATION =
        "\${STALWART_GATE_RECOVERY_ENV_FILE:?required}"
    private val BASE_COMPOSE =
        """
        services:
          stalwart-data-owner:
            image: $IMAGE
            user: "0:0"
            entrypoint: ["/bin/sh", "-c"]
            command: ["chown 2000:2000 /var/lib/stalwart && chmod 0700 /var/lib/stalwart"]
            volumes:
              - $CONFIG_MOUNT
              - $SCRATCH_MOUNT

          stalwart:
            image: $IMAGE
            user: "2000:2000"
            depends_on:
              stalwart-data-owner:
                condition: service_completed_successfully
            ports:
              - "127.0.0.1:18443:8080"
            environment:
              STALWART_PUBLIC_URL: $PUBLIC_URL
            volumes:
              - $CONFIG_MOUNT
              - $SCRATCH_MOUNT
            healthcheck:
              test: ["CMD", "curl", "-fsS", "http://127.0.0.1:8080/healthz/ready"]
              interval: 2s
              timeout: 2s
              retries: 30
              start_period: 2s
        """.trimIndent() + "\n"
    private val RECOVERY_COMPOSE =
        """
        services:
          stalwart:
            env_file:
              - $RECOVERY_ENV_INTERPOLATION
            environment:
              STALWART_RECOVERY_MODE: "1"
              STALWART_RECOVERY_MODE_PORT: "8080"
        """.trimIndent() + "\n"

    fun validate(
        baseCompose: String,
        recoveryCompose: String,
        configJson: String,
    ) {
        validateBase(baseCompose, configJson)
        validateRecovery(recoveryCompose)
    }

    fun validateBase(baseCompose: String, configJson: String) {
        require(baseCompose == BASE_COMPOSE) {
            "Base fixture bytes differ from the complete reviewed allowlist"
        }

        require(configJson == CONFIG_JSON) {
            "Fixture config bytes differ from the complete reviewed allowlist"
        }
        require(
            Json.parseToJsonElement(configJson) is JsonObject,
        ) {
            "Fixture config must be a JSON object"
        }
    }

    private fun validateRecovery(recoveryCompose: String) {
        require(recoveryCompose == RECOVERY_COMPOSE) {
            "Recovery fixture bytes differ from the complete reviewed allowlist"
        }
    }
}

internal interface GateRegistryApi {
    suspend fun discoverSession(): GateJmapSession

    suspend fun registryGet(
        objectType: String,
        ids: List<String>? = null,
        accountId: String? = null,
    ): JsonObject

    suspend fun registryQuery(
        objectType: String,
        filter: JsonObject = buildJsonObject {},
        accountId: String? = null,
    ): JsonObject

    suspend fun registryCreate(
        objectType: String,
        creationId: String,
        value: JsonObject,
        accountId: String? = null,
    ): JsonObject

    suspend fun registryUpdate(
        objectType: String,
        objectId: String,
        patch: JsonObject,
        accountId: String? = null,
    ): JsonObject

    suspend fun registryDestroy(
        objectType: String,
        objectId: String,
        accountId: String? = null,
    ): JsonObject
}

internal fun interface GateRegistryClientFactory {
    fun create(credential: GateCredential): GateRegistryApi
}

internal class GateBootstrapInputs(
    managementPassword: CharArray,
    firstUserPassword: CharArray,
    secondUserPassword: CharArray,
) : AutoCloseable {
    val managementPassword = managementPassword.copyOf()
    val firstUserPassword = firstUserPassword.copyOf()
    val secondUserPassword = secondUserPassword.copyOf()

    init {
        require(this.managementPassword.isNotEmpty()) { "Management password is absent" }
        require(this.firstUserPassword.isNotEmpty()) { "First user password is absent" }
        require(this.secondUserPassword.isNotEmpty()) { "Second user password is absent" }
    }

    override fun close() {
        managementPassword.fill('\u0000')
        firstUserPassword.fill('\u0000')
        secondUserPassword.fill('\u0000')
    }

    override fun toString(): String = "GateBootstrapInputs(redacted)"
}

internal class GateBootstrapResult(
    val managementAccountId: String,
    managementApiKey: CharArray,
    val firstUserAccountId: String,
    val secondUserAccountId: String,
    val effectiveManagementPermissions: Set<String>,
) : AutoCloseable {
    val managementApiKey = managementApiKey.copyOf()

    override fun close() {
        managementApiKey.fill('\u0000')
    }

    override fun toString(): String = "GateBootstrapResult(secrets=redacted)"
}

internal object GateBootstrap {
    const val DOMAIN = "local.test"
    const val MANAGEMENT_ADDRESS = "dashboard-management@local.test"
    const val FIRST_USER_ADDRESS = "gate-one@local.test"
    const val SECOND_USER_ADDRESS = "gate-two@local.test"

    val managementPermissions: Set<String> = linkedSetOf(
        "authenticate",
        "sysAccountGet",
        "sysAccountQuery",
        "sysAccountCreate",
        "sysAccountUpdate",
        "sysAccountDestroy",
        "sysDomainGet",
        "sysDomainQuery",
        "sysDomainCreate",
        "sysTaskGet",
        "sysTaskQuery",
    )
    val temporaryApiKeyPermissions: Set<String> = linkedSetOf(
        "sysApiKeyCreate",
        "sysApiKeyGet",
        "sysApiKeyQuery",
        "sysApiKeyDestroy",
    )
    val managementPermissionsWithTemporaryApiKeyAccess: Set<String> =
        managementPermissions + temporaryApiKeyPermissions
    val forbiddenManagementPermissionFragments: Set<String> = setOf(
        "impersonate",
        "jmap",
        "imap",
        "pop3",
        "smtp",
        "email",
        "blob",
        "identity",
        "submission",
        "sysAccountPassword",
        "sysApiKey",
        "sysAppPassword",
    )

    suspend fun bootstrap(
        recovery: GateRegistryApi,
        clientFactory: GateRegistryClientFactory,
        inputs: GateBootstrapInputs,
    ): GateBootstrapResult {
        val listenerId = requireCreated(
            response = recovery.registryCreate(
                objectType = "NetworkListener",
                creationId = "http-listener",
                value = networkListener(),
            ),
            creationId = "http-listener",
        ).id
        require(listenerId.isNotBlank()) { "Network listener ID is absent" }

        val domainId = requireCreated(
            response = recovery.registryCreate(
                objectType = "Domain",
                creationId = "local-domain",
                value = localDomain(),
            ),
            creationId = "local-domain",
        ).id
        require(domainId.isNotBlank()) { "Domain ID is absent" }

        requireUpdated(
            response = recovery.registryUpdate(
                objectType = "SystemSettings",
                objectId = "singleton",
                patch = buildJsonObject {
                    put("defaultHostname", "stalwart.local.test")
                    put("defaultDomainId", domainId)
                },
            ),
            objectId = "singleton",
        )

        val managementId = requireCreated(
            response = recovery.registryCreate(
                objectType = "Account",
                creationId = "management",
                value = account(
                    address = MANAGEMENT_ADDRESS,
                    domainId = domainId,
                    password = inputs.managementPassword,
                    permissions = managementPermissionsWithTemporaryApiKeyAccess,
                ),
            ),
            creationId = "management",
        ).id
        val firstUserId = requireCreated(
            response = recovery.registryCreate(
                objectType = "Account",
                creationId = "first-user",
                value = account(
                    address = FIRST_USER_ADDRESS,
                    domainId = domainId,
                    password = inputs.firstUserPassword,
                    permissions = null,
                ),
            ),
            creationId = "first-user",
        ).id
        val secondUserId = requireCreated(
            response = recovery.registryCreate(
                objectType = "Account",
                creationId = "second-user",
                value = account(
                    address = SECOND_USER_ADDRESS,
                    domainId = domainId,
                    password = inputs.secondUserPassword,
                    permissions = null,
                ),
            ),
            creationId = "second-user",
        ).id

        validateNetworkListener(
            value = requireSingleGet(
                recovery.registryGet(
                    objectType = "NetworkListener",
                    ids = listOf(listenerId),
                ),
            ),
            expectedId = listenerId,
        )
        validateDomain(
            value = requireSingleGet(
                recovery.registryGet(
                    objectType = "Domain",
                    ids = listOf(domainId),
                ),
            ),
            expectedId = domainId,
        )
        validateSystemSettings(
            value = requireSingleGet(
                recovery.registryGet(
                    objectType = "SystemSettings",
                    ids = listOf("singleton"),
                ),
            ),
            expectedDomainId = domainId,
        )
        validateCreatedUserAccount(
            value = requireSingleGet(
                recovery.registryGet(
                    objectType = "Account",
                    ids = listOf(managementId),
                ),
            ),
            expectedId = managementId,
            expectedName = MANAGEMENT_ADDRESS.substringBefore('@'),
            expectedDomainId = domainId,
            expectedPermissions = managementPermissionsWithTemporaryApiKeyAccess,
        )
        validateCreatedUserAccount(
            value = requireSingleGet(
                recovery.registryGet(
                    objectType = "Account",
                    ids = listOf(firstUserId),
                ),
            ),
            expectedId = firstUserId,
            expectedName = FIRST_USER_ADDRESS.substringBefore('@'),
            expectedDomainId = domainId,
            expectedPermissions = null,
        )
        validateCreatedUserAccount(
            value = requireSingleGet(
                recovery.registryGet(
                    objectType = "Account",
                    ids = listOf(secondUserId),
                ),
            ),
            expectedId = secondUserId,
            expectedName = SECOND_USER_ADDRESS.substringBefore('@'),
            expectedDomainId = domainId,
            expectedPermissions = null,
        )

        exerciseRecoveryAuthorityProbe(
            recovery = recovery,
            managementAccountId = managementId,
            domainId = domainId,
        )

        val manager = clientFactory.create(
            GateCredential.basic(
                username = MANAGEMENT_ADDRESS,
                secret = inputs.managementPassword,
            ),
        )
        val managerSession = manager.discoverSession()
        require(managerSession.primaryAccountId == managementId) {
            "Management password authenticated the wrong primary Account"
        }

        val managementKey = requireCreated(
            response = manager.registryCreate(
                objectType = "ApiKey",
                creationId = "management-key",
                value = apiKey(
                    description = "mail-sandbox/debug-dashboard/management",
                    permissions = managementPermissions,
                ),
                accountId = managementId,
            ),
            creationId = "management-key",
        )
        val managementKeySecret = managementKey.secret
            ?: throw IllegalStateException("Management API key secret was not returned at creation")
        require(managementKeySecret.startsWith("API_")) {
            "Management API key did not use the v0.16 API credential format"
        }
        validateApiKey(
            value = requireSingleGet(
                manager.registryGet(
                    objectType = "ApiKey",
                    ids = listOf(managementKey.id),
                    accountId = managementId,
                ),
            ),
            expectedId = managementKey.id,
            expectedPermissions = managementPermissions,
            expectedDescription = "mail-sandbox/debug-dashboard/management",
        )

        val noAuthenticatePermissions = managementPermissions - "authenticate"
        val noAuthenticateKey = requireCreated(
            response = manager.registryCreate(
                objectType = "ApiKey",
                creationId = "no-auth-key",
                value = apiKey(
                    description = "mail-sandbox/debug-dashboard/no-auth-proof",
                    permissions = noAuthenticatePermissions,
                ),
                accountId = managementId,
            ),
            creationId = "no-auth-key",
        )
        val noAuthenticateSecret = noAuthenticateKey.secret
            ?: throw IllegalStateException("No-auth API key secret was not returned at creation")
        validateApiKey(
            value = requireSingleGet(
                manager.registryGet(
                    objectType = "ApiKey",
                    ids = listOf(noAuthenticateKey.id),
                    accountId = managementId,
                ),
            ),
            expectedId = noAuthenticateKey.id,
            expectedPermissions = noAuthenticatePermissions,
            expectedDescription = "mail-sandbox/debug-dashboard/no-auth-proof",
        )
        val noAuthenticateClient = clientFactory.create(
            GateCredential.bearer(noAuthenticateSecret.toCharArray()),
        )
        val rejected = runCatching {
            requireAuthenticationRejected(noAuthenticateClient)
        }
        requireDestroyed(
            response = manager.registryDestroy(
                objectType = "ApiKey",
                objectId = noAuthenticateKey.id,
                accountId = managementId,
            ),
            objectId = noAuthenticateKey.id,
        )
        requireNotFound(
            response = manager.registryGet(
                objectType = "ApiKey",
                ids = listOf(noAuthenticateKey.id),
                accountId = managementId,
            ),
            objectId = noAuthenticateKey.id,
        )
        rejected.getOrThrow()

        val beforeRetirement = requireSingleGet(
            recovery.registryGet("Account", ids = listOf(managementId)),
        )
        val preservedApiKey = exactCredentialEntry(
            account = beforeRetirement,
            type = "ApiKey",
            credentialId = managementKey.id,
        )
        val temporaryPassword = exactCredentialEntry(
            account = beforeRetirement,
            type = "Password",
        )
        require(accountCredentials(beforeRetirement).size == 2) {
            "Management Account did not contain only the intended API key and temporary Password"
        }
        require(exactCredentialCount(beforeRetirement, "AppPassword") == 0) {
            "Management Account unexpectedly contained an AppPassword"
        }
        require(preservedApiKey.mapKey != temporaryPassword.mapKey) {
            "Management Account credentials reused a map key"
        }
        require(temporaryPassword.mapKey.toUIntOrNull() != null) {
            "Temporary Password used an invalid credential map key"
        }
        requireUpdated(
            response = recovery.registryUpdate(
                objectType = "Account",
                objectId = managementId,
                patch = buildJsonObject {
                    put("credentials/${temporaryPassword.mapKey}", JsonNull)
                    put("permissions", permissions(managementPermissions))
                },
            ),
            objectId = managementId,
        )

        val finalAccount = requireSingleGet(
            recovery.registryGet("Account", ids = listOf(managementId)),
        )
        val effectivePermissions = validateFinalManagementAccount(
            account = finalAccount,
            expectedAccountId = managementId,
            expectedApiKeyId = managementKey.id,
        )

        val managementBearer = clientFactory.create(
            GateCredential.bearer(managementKeySecret.toCharArray()),
        )
        val bearerSession = managementBearer.discoverSession()
        require(bearerSession.primaryAccountId == managementId) {
            "Management API key authenticated the wrong primary Account"
        }
        requireRegistryMethodForbidden {
            managementBearer.registryGet(
                objectType = "ApiKey",
                ids = listOf(managementKey.id),
                accountId = managementId,
            )
        }

        return GateBootstrapResult(
            managementAccountId = managementId,
            managementApiKey = managementKeySecret.toCharArray(),
            firstUserAccountId = firstUserId,
            secondUserAccountId = secondUserId,
            effectiveManagementPermissions = effectivePermissions,
        )
    }

    suspend fun requireRegistryMethodForbidden(
        operation: suspend () -> JsonObject,
    ) {
        val failure = runCatching { operation() }.exceptionOrNull()
        check(failure != null) {
            "Registry operation unexpectedly succeeded after privilege retirement"
        }
        require(
            failure is GateJmapException &&
                (failure.kind as? GateJmapFailure.MethodError)?.type == "forbidden",
        ) {
            "Registry privilege-retirement proof failed for an unrelated reason"
        }
    }

    suspend fun requireAuthenticationRejected(client: GateRegistryApi) {
        val failure = runCatching { client.discoverSession() }.exceptionOrNull()
        check(failure != null) {
            "API key without authenticate unexpectedly authenticated"
        }
        require(
            failure is GateJmapException &&
                (failure.kind as? GateJmapFailure.HttpStatus)?.status in setOf(401, 403),
        ) {
            "API-key authentication proof failed for an unrelated reason"
        }
    }

    private suspend fun exerciseRecoveryAuthorityProbe(
        recovery: GateRegistryApi,
        managementAccountId: String,
        domainId: String,
    ) {
        val probeId = requireCreatedId(
            recovery.registryCreate(
                objectType = "ApiKey",
                creationId = "recovery-authority-probe",
                value = apiKey(
                    description = "mail-sandbox/debug-dashboard/recovery-authority-probe",
                    permissions = managementPermissions,
                ),
                accountId = managementAccountId,
            ),
            creationId = "recovery-authority-probe",
        )
        validateApiKey(
            value = requireSingleGet(
                recovery.registryGet(
                    objectType = "ApiKey",
                    ids = listOf(probeId),
                    accountId = managementAccountId,
                ),
            ),
            expectedId = probeId,
            expectedPermissions = managementPermissions,
            expectedDescription = "mail-sandbox/debug-dashboard/recovery-authority-probe",
        )
        requireDestroyed(
            response = recovery.registryDestroy(
                objectType = "ApiKey",
                objectId = probeId,
                accountId = managementAccountId,
            ),
            objectId = probeId,
        )
        requireNotFound(
            response = recovery.registryGet(
                objectType = "ApiKey",
                ids = listOf(probeId),
                accountId = managementAccountId,
            ),
            objectId = probeId,
        )
        validateCreatedUserAccount(
            value = requireSingleGet(
                recovery.registryGet(
                    objectType = "Account",
                    ids = listOf(managementAccountId),
                ),
            ),
            expectedId = managementAccountId,
            expectedName = MANAGEMENT_ADDRESS.substringBefore('@'),
            expectedDomainId = domainId,
            expectedPermissions = managementPermissionsWithTemporaryApiKeyAccess,
        )
    }

    private fun networkListener(): JsonObject = buildJsonObject {
        put("name", "http")
        put(
            "bind",
            buildJsonObject {
                put("[::]:8080", true)
            },
        )
        put("protocol", "http")
        put("useTls", false)
        put("tlsImplicit", false)
    }

    private fun localDomain(): JsonObject = buildJsonObject {
        put("name", DOMAIN)
        put("aliases", buildJsonObject {})
        put("isEnabled", true)
        put("certificateManagement", typed("Manual"))
        put("dkimManagement", typed("Manual"))
        put("dnsManagement", typed("Manual"))
        put("subAddressing", typed("Enabled"))
        put("allowRelaying", false)
    }

    private fun account(
        address: String,
        domainId: String,
        password: CharArray,
        permissions: Set<String>?,
    ): JsonObject {
        val localPart = address.substringBefore('@')
        require(address == "$localPart@$DOMAIN") { "Gate Account address is outside local.test" }
        return buildJsonObject {
            put("@type", "User")
            put("name", localPart)
            put("domainId", domainId)
            put(
                "credentials",
                buildJsonObject {
                    put(
                        "0",
                        buildJsonObject {
                            put("@type", "Password")
                            put("secret", password.concatToString())
                            put("allowedIps", buildJsonObject {})
                        },
                    )
                },
            )
            put("roles", typed("User"))
            put(
                "permissions",
                permissions?.let(::permissions) ?: typed("Inherit"),
            )
        }
    }

    private fun apiKey(
        description: String,
        permissions: Set<String>,
    ): JsonObject = buildJsonObject {
        put("description", description)
        put("permissions", credentialPermissions(permissions))
        put("allowedIps", buildJsonObject {})
    }

    private fun permissions(values: Set<String>): JsonObject = buildJsonObject {
        put("@type", "Replace")
        put(
            "enabledPermissions",
            buildJsonObject {
                values.forEach { put(it, true) }
            },
        )
        put("disabledPermissions", buildJsonObject {})
    }

    private fun credentialPermissions(values: Set<String>): JsonObject = buildJsonObject {
        put("@type", "Replace")
        put(
            "permissions",
            buildJsonObject {
                values.forEach { put(it, true) }
            },
        )
    }

    private fun typed(type: String): JsonObject =
        buildJsonObject { put("@type", type) }

    private fun validateNetworkListener(
        value: JsonObject,
        expectedId: String,
    ) {
        requireObjectId(value, expectedId, "NetworkListener")
        require(value["name"]?.jsonPrimitive?.content == "http") {
            "Fetched NetworkListener name did not match"
        }
        require(value["protocol"]?.jsonPrimitive?.content == "http") {
            "Fetched NetworkListener protocol did not match"
        }
        require(enabledMap(value, "bind") == setOf("[::]:8080")) {
            "Fetched NetworkListener bind set did not match"
        }
        require(value["useTls"]?.jsonPrimitive?.boolean == false) {
            "Fetched NetworkListener unexpectedly enabled TLS"
        }
        require(value["tlsImplicit"]?.jsonPrimitive?.boolean == false) {
            "Fetched NetworkListener unexpectedly enabled implicit TLS"
        }
        requireNoImpersonate(value, "NetworkListener")
    }

    private fun validateDomain(
        value: JsonObject,
        expectedId: String,
    ) {
        requireObjectId(value, expectedId, "Domain")
        require(value["name"]?.jsonPrimitive?.content == DOMAIN) {
            "Fetched Domain name did not match"
        }
        require((value["aliases"] as? JsonObject).orEmpty().isEmpty()) {
            "Fetched Domain aliases were not empty"
        }
        require(value["isEnabled"]?.jsonPrimitive?.boolean == true) {
            "Fetched Domain was not enabled"
        }
        listOf("certificateManagement", "dkimManagement", "dnsManagement").forEach {
            require(
                (value[it] as? JsonObject)?.get("@type")?.jsonPrimitive?.content == "Manual",
            ) {
                "Fetched Domain management mode did not match"
            }
        }
        require(
            (value["subAddressing"] as? JsonObject)
                ?.get("@type")
                ?.jsonPrimitive
                ?.content == "Enabled",
        ) {
            "Fetched Domain sub-addressing mode did not match"
        }
        require(value["allowRelaying"]?.jsonPrimitive?.boolean == false) {
            "Fetched Domain unexpectedly allowed relaying"
        }
        requireNoImpersonate(value, "Domain")
    }

    private fun validateSystemSettings(
        value: JsonObject,
        expectedDomainId: String,
    ) {
        requireObjectId(value, "singleton", "SystemSettings")
        require(value["defaultHostname"]?.jsonPrimitive?.content == "stalwart.local.test") {
            "Fetched SystemSettings hostname did not match"
        }
        require(value["defaultDomainId"]?.jsonPrimitive?.content == expectedDomainId) {
            "Fetched SystemSettings Domain ID did not match"
        }
        requireNoImpersonate(value, "SystemSettings")
    }

    private fun validateCreatedUserAccount(
        value: JsonObject,
        expectedId: String,
        expectedName: String,
        expectedDomainId: String,
        expectedPermissions: Set<String>?,
    ) {
        requireObjectId(value, expectedId, "Account")
        require(value["@type"]?.jsonPrimitive?.content == "User") {
            "Fetched Account type was not User"
        }
        require(value["name"]?.jsonPrimitive?.content == expectedName) {
            "Fetched Account name did not match"
        }
        require(value["domainId"]?.jsonPrimitive?.content == expectedDomainId) {
            "Fetched Account Domain ID did not match"
        }
        require(
            (value["roles"] as? JsonObject)?.get("@type")?.jsonPrimitive?.content == "User",
        ) {
            "Fetched Account role was not User"
        }
        require(exactCredentialCount(value, "Password") == 1) {
            "Fetched Account was not Password-only"
        }
        require(accountCredentials(value).size == 1) {
            "Fetched Account contained an unexpected credential"
        }
        require(exactCredentialCount(value, "AppPassword") == 0) {
            "Fetched Account contained an AppPassword"
        }
        require(exactCredentialCount(value, "ApiKey") == 0) {
            "Fetched Account contained an unexpected API key"
        }
        val permissionObject = value["permissions"] as? JsonObject
            ?: throw IllegalStateException("Fetched Account permissions are absent")
        if (expectedPermissions == null) {
            require(permissionObject["@type"]?.jsonPrimitive?.content == "Inherit") {
                "Ordinary Account permissions did not inherit the User role"
            }
        } else {
            require(permissionObject["@type"]?.jsonPrimitive?.content == "Replace") {
                "Protected Account permission mode was not Replace"
            }
            require(enabledMap(permissionObject, "enabledPermissions") == expectedPermissions) {
                "Protected Account permissions differed from the reviewed bootstrap set"
            }
            require(
                (permissionObject["disabledPermissions"] as? JsonObject).orEmpty().isEmpty(),
            ) {
                "Protected Account contained inherited disable rules"
            }
        }
        requireNoImpersonate(value, "Account")
    }

    private fun requireObjectId(
        value: JsonObject,
        expectedId: String,
        label: String,
    ) {
        require(value["id"]?.jsonPrimitive?.content == expectedId) {
            "Fetched $label ID did not match its immutable created ID"
        }
    }

    private fun requireNoImpersonate(value: JsonObject, label: String) {
        require(!value.toString().contains("impersonate", ignoreCase = true)) {
            "Fetched $label contained impersonation authority"
        }
    }

    private fun validateApiKey(
        value: JsonObject,
        expectedId: String,
        expectedPermissions: Set<String>,
        expectedDescription: String,
    ) {
        require(value["id"]?.jsonPrimitive?.content == expectedId) {
            "Fetched API key ID did not match"
        }
        require(value["description"]?.jsonPrimitive?.content == expectedDescription) {
            "Fetched API key description did not match its exact reserved purpose"
        }
        val permissions = value["permissions"] as? JsonObject
            ?: throw IllegalStateException("Fetched API key permissions are absent")
        require(permissions["@type"]?.jsonPrimitive?.content == "Replace") {
            "Fetched API key permission mode is not Replace"
        }
        val effective = enabledMap(permissions, "permissions")
        require(effective == expectedPermissions) {
            "Fetched API key permissions differ from the exact baseline"
        }
        require(effective.none(::isForbiddenManagementPermission)) {
            "Fetched API key contains a forbidden management permission"
        }
        require(effective.none { "*" in it }) {
            "Fetched API key contains a wildcard permission"
        }
        requireNoImpersonate(value, "API key")
    }

    private fun validateFinalManagementAccount(
        account: JsonObject,
        expectedAccountId: String,
        expectedApiKeyId: String,
    ): Set<String> {
        require(account["id"]?.jsonPrimitive?.content == expectedAccountId) {
            "Final management Account ID did not match"
        }
        require(account["@type"]?.jsonPrimitive?.content == "User") {
            "Final management principal is not a User Account"
        }
        require(
            (account["roles"] as? JsonObject)
                ?.get("@type")
                ?.jsonPrimitive
                ?.content == "User",
        ) {
            "Final management Account has a privileged or custom role"
        }
        require(exactCredentialCount(account, "Password") == 0) {
            "Temporary management Password was not retired"
        }
        require(exactCredentialCount(account, "AppPassword") == 0) {
            "Final management Account contains an AppPassword"
        }
        val apiKeyCredential =
            exactCredentialEntry(account, "ApiKey", expectedApiKeyId).value
        val credentialPermissionObject = apiKeyCredential["permissions"] as? JsonObject
            ?: throw IllegalStateException("Final API-key credential permissions are absent")
        require(credentialPermissionObject["@type"]?.jsonPrimitive?.content == "Replace") {
            "Final API-key credential permission mode is not Replace"
        }
        require(
            enabledMap(credentialPermissionObject, "permissions") == managementPermissions,
        ) {
            "Final API-key credential permissions differ from the exact baseline"
        }
        require(accountCredentials(account).size == 1) {
            "Final management Account must preserve exactly one API key credential"
        }
        val permissionObject = account["permissions"] as? JsonObject
            ?: throw IllegalStateException("Final management Account permissions are absent")
        require(permissionObject["@type"]?.jsonPrimitive?.content == "Replace") {
            "Final management Account permission mode is not Replace"
        }
        require(
            (permissionObject["disabledPermissions"] as? JsonObject).orEmpty().isEmpty(),
        ) {
            "Final management Account contains inherited disable rules"
        }
        val effective = enabledMap(permissionObject, "enabledPermissions")
        require(effective == managementPermissions) {
            "Final management Account permissions differ from the exact baseline"
        }
        require(effective.none(::isForbiddenManagementPermission)) {
            "Final management Account contains a forbidden permission"
        }
        requireNoImpersonate(account, "final management Account")
        return effective
    }

    private fun isForbiddenManagementPermission(permission: String): Boolean =
        forbiddenManagementPermissionFragments.any { permission.contains(it) } ||
            "*" in permission

    private fun accountCredentials(account: JsonObject): JsonObject =
        account["credentials"] as? JsonObject
            ?: throw IllegalStateException("Account credentials are absent")

    private fun exactCredentialCount(account: JsonObject, type: String): Int =
        accountCredentials(account).values.count {
            (it as? JsonObject)?.get("@type")?.jsonPrimitive?.content == type
        }

    private fun exactCredentialEntry(
        account: JsonObject,
        type: String,
        credentialId: String? = null,
    ): AccountCredentialEntry {
        val matches = accountCredentials(account).mapNotNull { (mapKey, element) ->
            (element as? JsonObject)?.let { credential ->
                if (
                    credential["@type"]?.jsonPrimitive?.content == type &&
                    (
                        credentialId == null ||
                            credential["credentialId"]?.jsonPrimitive?.content == credentialId
                        )
                ) {
                    AccountCredentialEntry(mapKey, credential)
                } else {
                    null
                }
            }
        }
        require(matches.size == 1) {
            "Account did not contain exactly one expected $type credential"
        }
        return matches.single()
    }

    private fun enabledMap(value: JsonObject, property: String): Set<String> {
        val map = value[property] as? JsonObject
            ?: throw IllegalStateException("$property is absent")
        require(map.values.all { it.jsonPrimitive.boolean }) {
            "$property contains a disabled or non-boolean value"
        }
        return map.keys
    }

    private fun requireCreated(
        response: JsonObject,
        creationId: String,
    ): CreatedObject {
        val payload = methodPayload(response)
        require((payload["notCreated"] as? JsonObject).orEmpty().isEmpty()) {
            "Registry create failed"
        }
        val created = (payload["created"] as? JsonObject)
            ?.get(creationId) as? JsonObject
            ?: throw IllegalStateException("Registry create did not return the expected ID")
        val id = created["id"]?.jsonPrimitive?.content
            ?: throw IllegalStateException("Registry create returned no ID")
        return CreatedObject(
            id = id,
            secret = created["secret"]?.jsonPrimitive?.content,
        )
    }

    private fun requireCreatedId(
        response: JsonObject,
        creationId: String,
    ): String {
        val payload = methodPayload(response)
        require((payload["notCreated"] as? JsonObject).orEmpty().isEmpty()) {
            "Registry authority probe create failed"
        }
        return ((payload["created"] as? JsonObject)
            ?.get(creationId) as? JsonObject)
            ?.get("id")
            ?.jsonPrimitive
            ?.content
            ?: throw IllegalStateException(
                "Registry authority probe did not return its exact created ID",
            )
    }

    private fun requireUpdated(response: JsonObject, objectId: String) {
        val payload = methodPayload(response)
        require((payload["notUpdated"] as? JsonObject).orEmpty().isEmpty()) {
            "Registry update failed"
        }
        require(objectId in (payload["updated"] as? JsonObject).orEmpty()) {
            "Registry update did not confirm the expected object"
        }
    }

    private fun requireDestroyed(response: JsonObject, objectId: String) {
        val payload = methodPayload(response)
        require((payload["notDestroyed"] as? JsonObject).orEmpty().isEmpty()) {
            "Registry destroy failed"
        }
        require(
            (payload["destroyed"] as? JsonArray)
                ?.map { it.jsonPrimitive.content }
                ?.singleOrNull() == objectId,
        ) {
            "Registry destroy did not confirm the expected object"
        }
    }

    private fun requireNotFound(response: JsonObject, objectId: String) {
        val payload = methodPayload(response)
        require((payload["list"] as? JsonArray).orEmpty().isEmpty()) {
            "Destroyed registry object was still returned"
        }
        require(
            (payload["notFound"] as? JsonArray)
                ?.map { it.jsonPrimitive.content } == listOf(objectId),
        ) {
            "Registry get did not prove the exact destroyed object absent"
        }
    }

    private fun requireSingleGet(response: JsonObject): JsonObject {
        val payload = methodPayload(response)
        require((payload["notFound"] as? JsonArray).orEmpty().isEmpty()) {
            "Registry get reported a missing object"
        }
        val values = payload["list"] as? JsonArray
            ?: throw IllegalStateException("Registry get did not return a list")
        require(values.size == 1) { "Registry get did not return exactly one object" }
        return values.single().jsonObject
    }

    private fun methodPayload(response: JsonObject): JsonObject {
        val method = (response["methodResponses"] as? JsonArray)
            ?.singleOrNull() as? JsonArray
            ?: throw IllegalStateException("Registry response did not contain exactly one method")
        require(method.size == 3) { "Registry method response was malformed" }
        return method[1].jsonObject
    }

    private data class CreatedObject(
        val id: String,
        val secret: String?,
    )

    private data class AccountCredentialEntry(
        val mapKey: String,
        val value: JsonObject,
    )
}

internal class GateFixtureSecrets(
    managementAccountId: String,
    managementApiKey: CharArray,
    firstUserPassword: CharArray,
    secondUserPassword: CharArray,
) : AutoCloseable {
    val managementAccountId: String = managementAccountId
    val managementApiKey: CharArray = managementApiKey.copyOf()
    val firstUserPassword: CharArray = firstUserPassword.copyOf()
    val secondUserPassword: CharArray = secondUserPassword.copyOf()

    init {
        require(managementAccountId.isNotBlank()) { "Management Account ID is absent" }
        require(this.managementApiKey.isNotEmpty()) { "Management API key is absent" }
        require(this.firstUserPassword.isNotEmpty()) { "First user password is absent" }
        require(this.secondUserPassword.isNotEmpty()) { "Second user password is absent" }
    }

    override fun close() {
        managementApiKey.fill('\u0000')
        firstUserPassword.fill('\u0000')
        secondUserPassword.fill('\u0000')
    }

    override fun toString(): String = "GateFixtureSecrets(redacted)"
}

internal class GateRecoveryCredential(
    val username: String,
    secret: CharArray,
) : AutoCloseable {
    val secret: CharArray = secret.copyOf()

    override fun close() {
        secret.fill('\u0000')
    }

    override fun toString(): String = "GateRecoveryCredential(username=$username, secret=redacted)"
}

internal data class PreparedStalwartGateFiles(
    val runtimeDirectory: Path,
    val dataDirectory: Path,
    val recoveryEnv: Path,
    val recoveryHandoff: Path,
    val fixtureSecrets: Path,
)

internal object StalwartGateSecretFiles {
    private const val FIXTURE_PATH_ENV = "STALWART_GATE_FIXTURE_SECRETS_FILE"
    private const val RUNTIME_RELATIVE = ".runtime/stalwart-gate0b"
    private const val RECOVERY_USERNAME = "gate-recovery"
    private const val MAX_SECRET_FILE_BYTES = 64 * 1024L
    private val directoryPermissions =
        PosixFilePermissions.fromString("rwx------")
    private val filePermissions =
        PosixFilePermissions.fromString("rw-------")
    private val fileAttribute =
        PosixFilePermissions.asFileAttribute(filePermissions)
    private val random = SecureRandom()

    fun prepareRecovery(
        projectRoot: Path,
        secret: CharArray = generateSecret(),
    ): PreparedStalwartGateFiles {
        val root = validateProjectRoot(projectRoot)
        validateSecret(secret, "recovery secret")
        val runtime = root.resolve(RUNTIME_RELATIVE)
        requireNoSymbolicLink(root.resolve(".runtime"))
        Files.createDirectories(runtime)
        requireNoSymbolicLink(runtime)
        ensureOwnerOnlyDirectory(runtime)

        val data = runtime.resolve("data")
        Files.createDirectories(data)
        requireNoSymbolicLink(data)
        ensureOwnerOnlyDirectory(data)

        val recoveryEnv = runtime.resolve("recovery.env")
        val recoveryHandoff = runtime.resolve("recovery-handoff")
        val fixtureSecrets = runtime.resolve("fixture-secrets")
        deleteSafeRegularFileIfPresent(fixtureSecrets, runtime)

        val secretText = secret.concatToString()
        writeOwnerOnly(
            recoveryEnv,
            "STALWART_RECOVERY_ADMIN=$RECOVERY_USERNAME:$secretText\n",
            runtime,
        )
        writeOwnerOnly(
            recoveryHandoff,
            buildString {
                appendLine("version=1")
                appendLine("recoveryUsername=$RECOVERY_USERNAME")
                appendLine("recoverySecret=$secretText")
            },
            runtime,
        )
        secret.fill('\u0000')

        return PreparedStalwartGateFiles(
            runtimeDirectory = runtime,
            dataDirectory = data,
            recoveryEnv = recoveryEnv,
            recoveryHandoff = recoveryHandoff,
            fixtureSecrets = fixtureSecrets,
        )
    }

    fun writeFixtureSecrets(
        projectRoot: Path,
        path: Path,
        secrets: GateFixtureSecrets,
    ) {
        val expected = fixedFixtureSecretsPath(projectRoot)
        val normalized = path.toAbsolutePath().normalize()
        require(normalized.parent.toRealPath().resolve(normalized.fileName) == expected) {
            "Fixture secrets must use the fixed anchored handoff"
        }
        val runtime = expected.parent
        requireOwnerOnlyDirectory(runtime)
        validateSafeValue(secrets.managementAccountId, "management Account ID")
        validateSecret(secrets.managementApiKey, "management API key")
        validateSecret(secrets.firstUserPassword, "first user password")
        validateSecret(secrets.secondUserPassword, "second user password")
        writeOwnerOnly(
            normalized,
            buildString {
                appendLine("version=1")
                appendLine("managementAccountId=${secrets.managementAccountId}")
                appendLine("managementApiKey=${secrets.managementApiKey.concatToString()}")
                appendLine("firstUserPassword=${secrets.firstUserPassword.concatToString()}")
                appendLine("secondUserPassword=${secrets.secondUserPassword.concatToString()}")
            },
            runtime,
        )
    }

    fun fixtureSecretsPath(
        projectRoot: Path,
        environment: Map<String, String>,
    ): Path {
        val root = validateProjectRoot(projectRoot)
        val configured = environment[FIXTURE_PATH_ENV]?.takeIf { it.isNotBlank() }
            ?: throw IllegalArgumentException(
                "Required environment variable $FIXTURE_PATH_ENV is absent",
            )
        val configuredPath = Path.of(configured)
        require(configuredPath.isAbsolute) {
            "$FIXTURE_PATH_ENV must be an absolute fixed handoff path"
        }
        val normalized = configuredPath.normalize()
        val expected = fixedFixtureSecretsPath(root)
        require(normalized.fileName.toString() == "fixture-secrets") {
            "$FIXTURE_PATH_ENV must name the fixed gate handoff"
        }
        val canonicalConfigured =
            normalized.parent.toRealPath().resolve(normalized.fileName)
        require(canonicalConfigured == expected) {
            "$FIXTURE_PATH_ENV must name the fixed gate handoff"
        }
        requireNoSymbolicLink(root.resolve(".runtime"))
        requireNoSymbolicLink(expected.parent)
        requireOwnerOnlyDirectory(expected.parent)
        return expected
    }

    fun readFixtureSecrets(
        projectRoot: Path,
        environment: Map<String, String>,
    ): GateFixtureSecrets {
        val path = fixtureSecretsPath(projectRoot, environment)
        val values = readOwnerOnlyProperties(
            path = path,
            expectedKeys = setOf(
                "version",
                "managementAccountId",
                "managementApiKey",
                "firstUserPassword",
                "secondUserPassword",
            ),
        )
        require(values.getValue("version") == "1") {
            "Unsupported fixture-secret handoff version"
        }
        return GateFixtureSecrets(
            managementAccountId = values.getValue("managementAccountId"),
            managementApiKey = values.getValue("managementApiKey").toCharArray(),
            firstUserPassword = values.getValue("firstUserPassword").toCharArray(),
            secondUserPassword = values.getValue("secondUserPassword").toCharArray(),
        )
    }

    fun readRecoveryHandoff(
        projectRoot: Path,
        fixtureSecretsPath: Path,
    ): GateRecoveryCredential {
        val expected = fixedFixtureSecretsPath(projectRoot)
        val normalized = fixtureSecretsPath.toAbsolutePath().normalize()
        require(normalized.parent.toRealPath().resolve(normalized.fileName) == expected) {
            "Recovery handoff must use the fixed anchored fixture-secrets sibling"
        }
        requireOwnerOnlyDirectory(expected.parent)
        val recoveryPath = expected.resolveSibling("recovery-handoff")
        val values = readOwnerOnlyProperties(
            path = recoveryPath,
            expectedKeys = setOf("version", "recoveryUsername", "recoverySecret"),
        )
        require(values.getValue("version") == "1") {
            "Unsupported recovery handoff version"
        }
        return GateRecoveryCredential(
            username = values.getValue("recoveryUsername"),
            secret = values.getValue("recoverySecret").toCharArray(),
        )
    }

    private fun readOwnerOnlyProperties(
        path: Path,
        expectedKeys: Set<String>,
    ): Map<String, String> {
        require(Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
            "Required gate handoff is absent"
        }
        require(!Files.isSymbolicLink(path)) { "Gate handoff cannot be a symbolic link" }
        require(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
            "Gate handoff must be a regular file"
        }
        require(path.toRealPath(LinkOption.NOFOLLOW_LINKS).parent == path.parent.toRealPath()) {
            "Gate handoff escaped its fixed runtime directory"
        }
        require(Files.size(path) in 1..MAX_SECRET_FILE_BYTES) {
            "Gate handoff has an invalid size"
        }
        require(Files.getPosixFilePermissions(path) == filePermissions) {
            "Gate handoff must have mode 0600"
        }
        requireOwnerOnlyDirectory(path.parent)

        val values = linkedMapOf<String, String>()
        Files.readAllLines(path, StandardCharsets.UTF_8).forEach { line ->
            require(line.isNotBlank()) { "Gate handoff contains a blank record" }
            val separator = line.indexOf('=')
            require(separator > 0) { "Gate handoff contains an invalid record" }
            val key = line.substring(0, separator)
            val value = line.substring(separator + 1)
            require(key in expectedKeys && values.put(key, value) == null) {
                "Gate handoff contains an unexpected or duplicate key"
            }
            validateSafeValue(value, "gate handoff value")
        }
        require(values.keys == expectedKeys) {
            "Gate handoff does not contain the exact expected keys"
        }
        return values
    }

    private fun writeOwnerOnly(
        path: Path,
        value: String,
        requiredParent: Path?,
    ) {
        requireNotNull(requiredParent) { "Gate handoff parent is absent" }
        requireNoSymbolicLink(requiredParent)
        require(path.toAbsolutePath().normalize().parent == requiredParent.toAbsolutePath().normalize()) {
            "Gate handoff escaped its fixed runtime directory"
        }
        if (Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
            require(!Files.isSymbolicLink(path)) { "Gate handoff cannot be a symbolic link" }
            require(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
                "Gate handoff must be a regular file"
            }
        }
        val temporary = Files.createTempFile(requiredParent, ".handoff-", ".tmp", fileAttribute)
        try {
            Files.writeString(
                temporary,
                value,
                StandardCharsets.UTF_8,
                StandardOpenOption.TRUNCATE_EXISTING,
            )
            Files.setPosixFilePermissions(temporary, filePermissions)
            runCatching {
                Files.move(
                    temporary,
                    path,
                    StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING,
                )
            }.getOrElse {
                Files.move(temporary, path, StandardCopyOption.REPLACE_EXISTING)
            }
            Files.setPosixFilePermissions(path, filePermissions)
        } finally {
            Files.deleteIfExists(temporary)
        }
    }

    private fun deleteSafeRegularFileIfPresent(path: Path, requiredParent: Path) {
        if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) return
        require(path.parent == requiredParent) { "Cleanup target escaped the gate runtime" }
        require(!Files.isSymbolicLink(path)) { "Cleanup target cannot be a symbolic link" }
        require(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
            "Cleanup target must be a regular file"
        }
        Files.delete(path)
    }

    private fun validateProjectRoot(projectRoot: Path): Path {
        val root = projectRoot.toAbsolutePath().normalize()
        require(Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS)) {
            "Dashboard project root is absent"
        }
        require(!Files.isSymbolicLink(root)) { "Dashboard project root cannot be a symbolic link" }
        return root.toRealPath()
    }

    private fun fixedFixtureSecretsPath(projectRoot: Path): Path {
        val root = validateProjectRoot(projectRoot)
        val runtime = root.resolve(RUNTIME_RELATIVE)
        requireNoSymbolicLink(root.resolve(".runtime"))
        requireNoSymbolicLink(runtime)
        requireOwnerOnlyDirectory(runtime)
        return runtime.resolve("fixture-secrets")
    }

    private fun requireNoSymbolicLink(path: Path) {
        if (Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
            require(!Files.isSymbolicLink(path)) { "Gate runtime path cannot be a symbolic link" }
            require(Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) {
                "Gate runtime path must be a directory"
            }
        }
    }

    private fun ensureOwnerOnlyDirectory(path: Path) {
        if (Files.getPosixFilePermissions(path) != directoryPermissions) {
            Files.setPosixFilePermissions(path, directoryPermissions)
        }
        requireOwnerOnlyDirectory(path)
    }

    private fun requireOwnerOnlyDirectory(path: Path) {
        require(!Files.isSymbolicLink(path)) {
            "Gate runtime directory cannot be a symbolic link"
        }
        require(Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) {
            "Gate runtime directory is absent"
        }
        require(Files.getPosixFilePermissions(path) == directoryPermissions) {
            "Gate runtime directory must have mode 0700"
        }
    }

    private fun validateSecret(value: CharArray, label: String) {
        require(value.isNotEmpty()) { "$label is absent" }
        validateSafeValue(value.concatToString(), label)
    }

    private fun validateSafeValue(value: String, label: String) {
        require(
            value.isNotEmpty() &&
                value.none { it == '\r' || it == '\n' || it == '\u0000' },
        ) {
            "$label contains an invalid character"
        }
    }

    private fun generateSecret(): CharArray {
        val alphabet =
            "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_".toCharArray()
        return CharArray(48) { alphabet[random.nextInt(alphabet.size)] }
    }
}
