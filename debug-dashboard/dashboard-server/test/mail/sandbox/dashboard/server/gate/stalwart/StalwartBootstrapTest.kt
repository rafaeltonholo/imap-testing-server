package mail.sandbox.dashboard.server.gate.stalwart

import java.net.URI
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlin.io.path.createDirectories
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

class StalwartBootstrapTest {
    @Test
    fun temporarySecretArraysAreClearedAfterSuccessAndFailure() {
        lateinit var successfulArray: CharArray
        val returned = "temporary-secret".withGateSecretChars { secret ->
            successfulArray = secret
            secret.concatToString()
        }

        assertEquals("temporary-secret", returned)
        assertContentEquals(CharArray(successfulArray.size), successfulArray)

        lateinit var failedArray: CharArray
        assertFailsWith<IllegalStateException> {
            "another-secret".withGateSecretChars { secret ->
                failedArray = secret
                error("expected failure")
            }
        }
        assertContentEquals(CharArray(failedArray.size), failedArray)
    }

    @Test
    fun liveEnvironmentRequiresExplicitLoopbackAndFixedSecretHandoff() {
        withTemporaryProject { projectRoot ->
            val expectedSecrets = projectRoot.resolve(
                ".runtime/stalwart-gate0b/fixture-secrets",
            )
            val valid = mapOf(
                "STALWART_LIVE_TESTS" to "1",
                "STALWART_BASE_URL" to "http://127.0.0.1:18443",
                "STALWART_GATE_FIXTURE_SECRETS_FILE" to expectedSecrets.toString(),
            )

            val environment = StalwartLiveTestEnvironment.load(
                environment = valid,
                projectRoot = projectRoot,
            )
            assertEquals(URI("http://127.0.0.1:18443"), environment.baseUrl)
            assertEquals(
                expectedSecrets.parent.toRealPath().resolve(expectedSecrets.fileName),
                environment.fixtureSecretsPath,
            )

            listOf(
                emptyMap(),
                valid - "STALWART_BASE_URL",
                valid + ("STALWART_LIVE_TESTS" to "true"),
                valid + ("STALWART_BASE_URL" to "http://localhost:18443"),
                valid + ("STALWART_BASE_URL" to "https://127.0.0.1:18443"),
                valid + ("STALWART_BASE_URL" to "http://127.0.0.1:8443"),
                valid + ("STALWART_GATE_PHASE" to "bootstrap"),
                valid + ("STALWART_GATE_PREPARE" to "1"),
                valid + ("STALWART_GATE_CLEANUP" to "1"),
                valid + (
                    "STALWART_GATE_FIXTURE_SECRETS_FILE" to
                        projectRoot.resolve("other").toString()
                    ),
            ).forEach { invalid ->
                assertFailsWith<IllegalArgumentException> {
                    StalwartLiveTestEnvironment.load(invalid, projectRoot)
                }
            }
        }
    }

    @Test
    fun explicitActionSelectionsRequireExactNonConflictingEnvironment() {
        StalwartGateActionSelection.requirePrepare(
            mapOf("STALWART_GATE_PREPARE" to "1"),
        )
        StalwartGateActionSelection.requireCleanup(
            mapOf("STALWART_GATE_CLEANUP" to "1"),
        )

        listOf(
            emptyMap(),
            mapOf("STALWART_GATE_PREPARE" to "true"),
            mapOf(
                "STALWART_GATE_PREPARE" to "1",
                "STALWART_GATE_CLEANUP" to "1",
            ),
            mapOf(
                "STALWART_GATE_PREPARE" to "1",
                "STALWART_LIVE_TESTS" to "1",
            ),
        ).forEach { invalid ->
            assertFailsWith<IllegalArgumentException> {
                StalwartGateActionSelection.requirePrepare(invalid)
            }
        }
        listOf(
            emptyMap(),
            mapOf("STALWART_GATE_CLEANUP" to "true"),
            mapOf(
                "STALWART_GATE_CLEANUP" to "1",
                "STALWART_GATE_PREPARE" to "1",
            ),
            mapOf(
                "STALWART_GATE_CLEANUP" to "1",
                "STALWART_GATE_FIXTURE_SECRETS_FILE" to "/tmp/unreviewed",
            ),
        ).forEach { invalid ->
            assertFailsWith<IllegalArgumentException> {
                StalwartGateActionSelection.requireCleanup(invalid)
            }
        }
    }

    @Test
    fun mailAccessEnvironmentRequiresExactCredentialRootAndRestartPhase() {
        withTemporaryProject { projectRoot ->
            val fixtureSecrets = projectRoot.resolve(
                ".runtime/stalwart-gate0b/fixture-secrets",
            )
            val credentialRoot = projectRoot.resolve(
                ".runtime/stalwart-gate0b/credential-store",
            )
            val valid = mapOf(
                "STALWART_LIVE_TESTS" to "1",
                "STALWART_BASE_URL" to "http://127.0.0.1:18443",
                "STALWART_GATE_FIXTURE_SECRETS_FILE" to
                    fixtureSecrets.toString(),
                "STALWART_GATE_CREDENTIAL_ROOT" to
                    credentialRoot.toString(),
            )

            val lifecycle = StalwartMailAccessLiveEnvironment.lifecycle(
                environment = valid,
                projectRoot = projectRoot,
            )
            assertEquals(credentialRoot, lifecycle.credentialPaths.runtimeRoot)
            assertEquals(null, lifecycle.restartPhase)

            StalwartMailAccessRestartPhase.entries.forEach { phase ->
                val restart = StalwartMailAccessLiveEnvironment.restart(
                    environment = valid + (
                        "STALWART_GATE_RESTART_PHASE" to
                            phase.environmentValue
                        ),
                    projectRoot = projectRoot,
                )
                assertEquals(phase, restart.restartPhase)
                assertEquals(
                    credentialRoot,
                    restart.credentialPaths.runtimeRoot,
                )
            }

            listOf(
                valid - "STALWART_GATE_CREDENTIAL_ROOT",
                valid + (
                    "STALWART_GATE_CREDENTIAL_ROOT" to
                        projectRoot.resolve(".runtime").toString()
                    ),
                valid + ("STALWART_GATE_CREDENTIAL_ROOT" to "credential-store"),
                valid + ("STALWART_GATE_RESTART_PHASE" to "staged"),
            ).forEach { invalid ->
                assertFailsWith<IllegalArgumentException> {
                    StalwartMailAccessLiveEnvironment.lifecycle(
                        environment = invalid,
                        projectRoot = projectRoot,
                    )
                }
            }

            listOf(
                valid,
                valid + ("STALWART_GATE_RESTART_PHASE" to ""),
                valid + ("STALWART_GATE_RESTART_PHASE" to "active"),
                valid + ("STALWART_GATE_RESTART_PHASE" to "removalPending"),
            ).forEach { invalid ->
                assertFailsWith<IllegalArgumentException> {
                    StalwartMailAccessLiveEnvironment.restart(
                        environment = invalid,
                        projectRoot = projectRoot,
                    )
                }
            }

            assertFailsWith<IllegalArgumentException> {
                StalwartGateActionSelection.requirePrepare(
                    mapOf(
                        "STALWART_GATE_PREPARE" to "1",
                        "STALWART_GATE_CREDENTIAL_ROOT" to
                            credentialRoot.toString(),
                    ),
                )
            }
        }
    }

    @Test
    fun readinessIsBoundedAndUsesOnlyTheDedicatedReadyEndpoint() = runBlocking {
        val environment = StalwartLiveTestEnvironment(
            baseUrl = URI("http://127.0.0.1:18443"),
            fixtureSecretsPath = Path.of("/unused-by-readiness"),
        )
        val observed = mutableListOf<URI>()
        environment.awaitReady(
            maxAttempts = 3,
            delayMillis = 0,
        ) { url ->
            observed += url
            observed.size == 2
        }
        assertEquals(
            listOf(
                URI("http://127.0.0.1:18443/healthz/ready"),
                URI("http://127.0.0.1:18443/healthz/ready"),
            ),
            observed,
        )

        var failedAttempts = 0
        assertFailsWith<IllegalStateException> {
            environment.awaitReady(
                maxAttempts = 3,
                delayMillis = 0,
            ) {
                failedAttempts += 1
                false
            }
        }
        assertEquals(3, failedAttempts)
        Unit
    }

    @Test
    fun discoversRelativeApiUrlAndSendsRegistryJmapToTheExpandedEndpoint() = runBlocking {
        val transport = RecordingTransport(
            GateHttpResponse(
                status = 200,
                effectiveUrl = URI("http://127.0.0.1:18443/jmap/session"),
                body = """
                    {
                      "apiUrl": "/jmap/",
                      "username": "gate-recovery",
                      "primaryAccounts": {
                        "urn:stalwart:jmap": "recovery-account"
                      }
                    }
                """.trimIndent(),
            ),
            GateHttpResponse(
                status = 200,
                effectiveUrl = URI("http://127.0.0.1:18443/jmap/"),
                body = """
                    {
                      "methodResponses": [
                        ["x:Account/get", {"state":"1","list":[],"notFound":[]}, "gate-1"]
                      ]
                    }
                """.trimIndent(),
            ),
        )
        val (session, result) = GateJmapClient(
            baseUrl = URI("http://127.0.0.1:18443"),
            credential = GateCredential.basic(
                username = "gate-recovery",
                secret = "never-record-this-secret".toCharArray(),
            ),
            transport = transport,
        ).use { client ->
            client.discoverSession() to client.registryGet("Account")
        }

        assertEquals("recovery-account", session.primaryAccountId)
        assertEquals(
            listOf(
                URI("http://127.0.0.1:18443/.well-known/jmap"),
                URI("http://127.0.0.1:18443/jmap/"),
            ),
            transport.requests.map { it.url },
        )
        assertEquals(listOf("GET", "POST"), transport.requests.map { it.method })
        assertTrue(transport.requests.all { it.credential.scheme == "Basic" })
        val body = requireNotNull(transport.requests[1].body)
        assertEquals(
            listOf("urn:ietf:params:jmap:core", "urn:stalwart:jmap"),
            body.getValue("using").jsonArray.map { it.jsonPrimitive.content },
        )
        val call = body.getValue("methodCalls").jsonArray.single().jsonArray
        assertEquals("x:Account/get", call[0].jsonPrimitive.content)
        assertEquals("gate-1", call[2].jsonPrimitive.content)
        assertEquals(
            "x:Account/get",
            result.getValue("methodResponses").jsonArray.single().jsonArray[0]
                .jsonPrimitive.content,
        )
        assertFalse(transport.requests.joinToString().contains("never-record-this-secret"))
    }

    @Test
    fun rejectsLegacyPrincipalApiAndRedactsFailedResponseBodies() = runBlocking {
        val legacy = RecordingTransport(
            GateHttpResponse(
                status = 200,
                effectiveUrl = URI("http://127.0.0.1:18443/jmap/session"),
                body = """{"apiUrl":"/api/principal","primaryAccounts":{}}""",
            ),
        )
        val legacyFailure = GateJmapClient(
            baseUrl = URI("http://127.0.0.1:18443"),
            credential = GateCredential.basic("gate-recovery", "secret".toCharArray()),
            transport = legacy,
        ).use { legacyClient ->
            assertFailsWith<GateJmapException> {
                legacyClient.discoverSession()
            }
        }
        assertEquals(GateJmapFailure.InvalidResponse, legacyFailure.kind)
        assertEquals(1, legacy.requests.size)

        val secretBody = "response-body-secret-must-not-leak"
        val failed = RecordingTransport(
            GateHttpResponse(
                status = 401,
                effectiveUrl = URI("http://127.0.0.1:18443/jmap/session"),
                body = secretBody,
            ),
        )
        val failure = GateJmapClient(
            baseUrl = URI("http://127.0.0.1:18443"),
            credential = GateCredential.bearer("API_secret".toCharArray()),
            transport = failed,
        ).use { failedClient ->
            assertFailsWith<GateJmapException> {
                failedClient.discoverSession()
            }
        }
        assertFalse(failure.message.orEmpty().contains(secretBody))
        assertFalse(failure.toString().contains("API_secret"))
    }

    @Test
    fun registryHelpersUseCreationReferencesWithoutEmbeddingSecretsInDiagnostics() = runBlocking {
        val transport = RecordingTransport(
            GateHttpResponse(
                status = 200,
                effectiveUrl = URI("http://127.0.0.1:18443/jmap/session"),
                body = """
                    {
                      "apiUrl":"http://127.0.0.1:18443/jmap/",
                      "primaryAccounts":{"urn:stalwart:jmap":"manager-id"}
                    }
                """.trimIndent(),
            ),
            GateHttpResponse(
                status = 200,
                effectiveUrl = URI("http://127.0.0.1:18443/jmap/"),
                body = """
                    {
                      "methodResponses":[
                        ["x:Domain/set",{"created":{"domain":{"id":"domain-id"}}},"gate-1"]
                      ]
                    }
                """.trimIndent(),
            ),
        )
        val created = GateJmapClient(
            baseUrl = URI("http://127.0.0.1:18443"),
            credential = GateCredential.bearer("API_secret".toCharArray()),
            transport = transport,
        ).use { client ->
            client.registryCreate(
                objectType = "Domain",
                creationId = "domain",
                value = buildJsonObject { put("name", "local.test") },
            )
        }

        assertEquals("domain-id", created.createdId("domain"))
        assertFalse(transport.requests[1].toString().contains("local.test"))
        assertFalse(transport.requests[1].toString().contains("API_secret"))
    }

    @Test
    fun bootstrapUsesReviewedRegistryOrderAndRetiresEveryTemporaryPrivilege() = runBlocking {
        val recovery = ScriptedRegistryClient("recovery")
        val manager = ScriptedRegistryClient("manager")
        val noAuthenticate = ScriptedRegistryClient("no-auth")
        val managementBearer = ScriptedRegistryClient("management-bearer")
        val factory = QueueClientFactory(manager, noAuthenticate, managementBearer)
        val inputs = GateBootstrapInputs(
            managementPassword = "temporary-manager-password".toCharArray(),
            firstUserPassword = "first-user-password".toCharArray(),
            secondUserPassword = "second-user-password".toCharArray(),
        )

        val result = GateBootstrap.bootstrap(
            recovery = recovery,
            clientFactory = factory,
            inputs = inputs,
        )

        assertEquals(
            listOf(
                "create:NetworkListener",
                "create:NetworkListener",
                "update:MtaStageAuth:singleton",
                "create:Domain",
                "update:SystemSettings:singleton",
                "create:Account",
                "create:Account",
                "create:Account",
            ),
            recovery.operations.take(8).map { it.label },
        )
        assertEquals(
            listOf(
                "get:NetworkListener:http-listener-id",
                "get:NetworkListener:smtp-listener-id",
                "get:MtaStageAuth:singleton",
                "get:Domain:domain-id",
                "get:SystemSettings:singleton",
                "get:Account:management-id",
                "get:Account:first-user-id",
                "get:Account:second-user-id",
            ),
            recovery.operations.filter { it.label.startsWith("get:") }
                .take(8)
                .map { it.label },
        )
        val smtpListener = recovery.operations.single {
            it.creationId == "smtp-listener"
        }.value
        assertEquals("smtp-gate0b", smtpListener?.get("name")?.jsonPrimitive?.content)
        assertEquals("smtp", smtpListener?.get("protocol")?.jsonPrimitive?.content)
        assertEquals(
            setOf("[::]:8587"),
            smtpListener
                ?.get("bind")
                ?.jsonObject
                ?.keys,
        )
        val smtpAuth = requireNotNull(
            recovery.operations.single {
                it.label == "update:MtaStageAuth:singleton"
            }.value,
        )
        assertEquals(
            buildJsonObject {
                put("match", buildJsonObject {})
                put("else", "[plain]")
            },
            smtpAuth["saslMechanisms"],
        )
        val accountCreates = recovery.operations
            .filter { it.label == "create:Account" }
        assertEquals(3, accountCreates.size)

        val management = requireNotNull(accountCreates[0].value)
        assertEquals("management", accountCreates[0].creationId)
        assertEquals(
            "dashboard-management",
            management.getValue("name").jsonPrimitive.content,
        )
        assertCredentialTypes(management, listOf("Password"))
        assertEquals(
            GateBootstrap.managementPermissionsWithTemporaryApiKeyAccess,
            enabledPermissions(management),
        )
        val firstUser = requireNotNull(accountCreates[1].value)
        val secondUser = requireNotNull(accountCreates[2].value)
        assertEquals("gate-one", firstUser.getValue("name").jsonPrimitive.content)
        assertEquals("gate-two", secondUser.getValue("name").jsonPrimitive.content)
        assertCredentialTypes(firstUser, listOf("Password"))
        assertCredentialTypes(secondUser, listOf("Password"))
        assertFalse(firstUser.toString().contains("AppPassword"))
        assertFalse(secondUser.toString().contains("AppPassword"))

        val recoveryProbeIndex = recovery.operations.indexOfFirst {
            it.creationId == "recovery-authority-probe"
        }
        assertTrue(recoveryProbeIndex >= 0)
        assertEquals(
            listOf(
                "create:ApiKey",
                "get:ApiKey:recovery-probe-id",
                "destroy:ApiKey:recovery-probe-id",
                "get:ApiKey:recovery-probe-id",
                "get:Account:management-id",
            ),
            recovery.operations.drop(recoveryProbeIndex).take(5).map { it.label },
        )
        val recoveryProbe = requireNotNull(recovery.operations[recoveryProbeIndex].value)
        assertEquals(
            "mail-sandbox/debug-dashboard/recovery-authority-probe",
            recoveryProbe.getValue("description").jsonPrimitive.content,
        )
        assertEquals(
            GateBootstrap.managementPermissions,
            recoveryProbe.getValue("permissions")
                .jsonObject
                .getValue("permissions")
                .jsonObject
                .keys,
        )

        assertEquals(
            listOf("Basic", "Bearer", "Bearer"),
            factory.credentials.map { it.scheme },
        )
        assertEquals(
            listOf(GateBootstrap.MANAGEMENT_ADDRESS, null, null),
            factory.credentials.map { it.basicUsername },
        )
        assertEquals("management-id", manager.discoveredPrimaryAccountId)
        assertTrue(noAuthenticate.discoveryAttempted)
        assertTrue(noAuthenticate.discoveryRejected)
        assertTrue(
            manager.operations.any {
                it.label == "destroy:ApiKey:no-auth-key-id"
            },
        )
        val noAuthDestroyIndex = manager.operations.indexOfFirst {
            it.label == "destroy:ApiKey:no-auth-key-id"
        }
        assertEquals(
            "get:ApiKey:no-auth-key-id",
            manager.operations[noAuthDestroyIndex + 1].label,
        )
        assertEquals(
            listOf("get:ApiKey:management-key-id"),
            managementBearer.operations.map { it.label },
        )

        val retirement = recovery.operations.single {
            it.label == "update:Account:management-id"
        }
        val retirementPatch = requireNotNull(retirement.value)
        assertEquals(
            setOf("credentials/0", "permissions"),
            retirementPatch.keys,
        )
        assertEquals(JsonNull, retirementPatch.getValue("credentials/0"))
        assertEquals(GateBootstrap.managementPermissions, enabledPermissions(retirementPatch))
        assertTrue(
            GateBootstrap.temporaryApiKeyPermissions.none {
                it in enabledPermissions(retirementPatch)
            },
        )
        assertFalse("credentials" in retirementPatch)
        assertFalse(retirementPatch.toString().contains("Password"))
        assertFalse(retirementPatch.toString().contains("ApiKey"))

        assertEquals("management-id", result.managementAccountId)
        assertEquals("API_good-secret", result.managementApiKey.concatToString())
        assertEquals("first-user-id", result.firstUserAccountId)
        assertEquals("second-user-id", result.secondUserAccountId)
        assertEquals(
            GateBootstrap.managementPermissions,
            result.effectiveManagementPermissions,
        )
        assertTrue(
            GateBootstrap.forbiddenManagementPermissionFragments.none { fragment ->
                result.effectiveManagementPermissions.any { it.contains(fragment) }
            },
        )
        assertFalse(result.effectiveManagementPermissions.any { "*" in it })
        assertEquals(0, recovery.closeCount)
        assertEquals(1, manager.closeCount)
        assertEquals(1, noAuthenticate.closeCount)
        assertEquals(1, managementBearer.closeCount)
        result.close()
        inputs.close()
    }

    @Test
    fun noAuthenticateProbeMustFailClosed() = runBlocking {
        val unexpectedlyAuthenticated = object : GateRegistryApi by ScriptedRegistryClient("bad") {
            override suspend fun discoverSession(): GateJmapSession =
                GateJmapSession(
                    apiUrl = URI("http://127.0.0.1:18443/jmap/"),
                    username = "management@local.test",
                    primaryAccountId = "management-id",
                )
        }

        assertFailsWith<IllegalStateException> {
            GateBootstrap.requireAuthenticationRejected(unexpectedlyAuthenticated)
        }

        val unrelatedFailure = object : GateRegistryApi by ScriptedRegistryClient("bad") {
            override suspend fun discoverSession(): GateJmapSession =
                throw GateJmapException(
                    kind = GateJmapFailure.Transport,
                    message = "Stalwart request transport failed",
                )
        }
        assertFailsWith<IllegalArgumentException> {
            GateBootstrap.requireAuthenticationRejected(unrelatedFailure)
        }
        Unit
    }

    @Test
    fun postRetirementRegistryDenialAcceptsOnlyTheExactForbiddenMethodError() = runBlocking {
        GateBootstrap.requireRegistryMethodForbidden {
            throw GateJmapException(
                kind = GateJmapFailure.MethodError("forbidden"),
                message = "JMAP method returned error type forbidden",
            )
        }
        assertFailsWith<IllegalStateException> {
            GateBootstrap.requireRegistryMethodForbidden {
                buildJsonObject {}
            }
        }
        assertFailsWith<IllegalArgumentException> {
            GateBootstrap.requireRegistryMethodForbidden {
                throw GateJmapException(
                    kind = GateJmapFailure.HttpStatus(403),
                    message = "JMAP failed with HTTP status 403",
                )
            }
        }
        Unit
    }

    private class RecordingTransport(
        vararg responses: GateHttpResponse,
    ) : GateHttpTransport {
        private val responses = ArrayDeque(responses.toList())
        val requests = mutableListOf<GateHttpRequest>()

        override suspend fun execute(request: GateHttpRequest): GateHttpResponse {
            requests += request
            return responses.removeFirst()
        }
    }

    private class QueueClientFactory(
        vararg clients: GateRegistryApi,
    ) : GateRegistryClientFactory {
        private val clients = ArrayDeque(clients.toList())
        val credentials = mutableListOf<GateCredential>()

        override fun create(credential: GateCredential): GateRegistryApi {
            credentials += credential
            val client = clients.removeFirst()
            return object : GateRegistryApi by client {
                override fun close() {
                    try {
                        client.close()
                    } finally {
                        credential.close()
                    }
                }
            }
        }
    }

    private class GateOperation(
        val label: String,
        val objectType: String,
        val creationId: String? = null,
        val objectId: String? = null,
        val value: JsonObject? = null,
        val accountId: String? = null,
    ) {
        override fun toString(): String = "GateOperation(label=$label, body=redacted)"
    }

    private class ScriptedRegistryClient(
        private val name: String,
    ) : GateRegistryApi {
        val operations = mutableListOf<GateOperation>()
        var discoveryAttempted = false
        var discoveryRejected = false
        var discoveredPrimaryAccountId: String? = null
        var closeCount = 0
        private var managementRetired = false
        private var managementGetCount = 0
        private val destroyedApiKeyIds = mutableSetOf<String>()

        override suspend fun discoverSession(): GateJmapSession {
            discoveryAttempted = true
            if (name == "no-auth") {
                discoveryRejected = true
                throw GateJmapException(
                    kind = GateJmapFailure.HttpStatus(401),
                    message = "JMAP Session discovery failed with HTTP status 401",
                )
            }
            val accountId = if (name == "recovery") "recovery-id" else "management-id"
            discoveredPrimaryAccountId = accountId
            return GateJmapSession(
                apiUrl = URI("http://127.0.0.1:18443/jmap/"),
                username = "$name@local.test",
                primaryAccountId = accountId,
            )
        }

        override suspend fun registryCreate(
            objectType: String,
            creationId: String,
            value: JsonObject,
            accountId: String?,
        ): JsonObject {
            operations += GateOperation(
                label = "create:$objectType",
                objectType = objectType,
                creationId = creationId,
                value = value,
                accountId = accountId,
            )
            val (id, extra) = when {
                objectType == "NetworkListener" &&
                    creationId == "http-listener" ->
                    "http-listener-id" to emptyMap()
                objectType == "NetworkListener" &&
                    creationId == "smtp-listener" ->
                    "smtp-listener-id" to emptyMap()
                objectType == "Domain" -> "domain-id" to emptyMap()
                objectType == "Account" && creationId == "management" ->
                    "management-id" to emptyMap()
                objectType == "Account" && creationId == "first-user" ->
                    "first-user-id" to emptyMap()
                objectType == "Account" && creationId == "second-user" ->
                    "second-user-id" to emptyMap()
                objectType == "ApiKey" && creationId == "recovery-authority-probe" ->
                    "recovery-probe-id" to mapOf("secret" to "API_recovery-probe-secret")
                objectType == "ApiKey" && creationId == "management-key" ->
                    "management-key-id" to mapOf("secret" to "API_good-secret")
                objectType == "ApiKey" && creationId == "no-auth-key" ->
                    "no-auth-key-id" to mapOf("secret" to "API_no-auth-secret")
                else -> error("Unexpected scripted create $objectType/$creationId")
            }
            return setCreatedResponse(objectType, creationId, id, extra)
        }

        override suspend fun registryGet(
            objectType: String,
            ids: List<String>?,
            accountId: String?,
        ): JsonObject {
            operations += GateOperation(
                label = "get:$objectType:${ids?.joinToString().orEmpty()}",
                objectType = objectType,
                accountId = accountId,
            )
            return when (objectType) {
                "NetworkListener" -> getResponse(
                    objectType,
                    networkListenerObject(requireNotNull(ids).single()),
                )

                "MtaStageAuth" -> getResponse(
                    objectType,
                    smtpAuthenticationStageObject(requireNotNull(ids).single()),
                )

                "Domain" -> getResponse(
                    objectType,
                    domainObject(requireNotNull(ids).single()),
                )

                "SystemSettings" -> getResponse(
                    objectType,
                    systemSettingsObject(requireNotNull(ids).single()),
                )

                "ApiKey" -> {
                    val id = requireNotNull(ids).single()
                    if (name == "management-bearer") {
                        throw GateJmapException(
                            kind = GateJmapFailure.MethodError("forbidden"),
                            message = "JMAP method returned error type forbidden",
                        )
                    }
                    if (id in destroyedApiKeyIds) {
                        getNotFoundResponse(objectType, id)
                    } else {
                        getResponse(
                            objectType = objectType,
                            value = apiKeyObject(
                                id = id,
                                permissions = when (id) {
                                    "management-key-id", "recovery-probe-id" ->
                                        GateBootstrap.managementPermissions
                                    else ->
                                        GateBootstrap.managementPermissions - "authenticate"
                                },
                                description = when (id) {
                                    "recovery-probe-id" ->
                                        "mail-sandbox/debug-dashboard/recovery-authority-probe"
                                    "no-auth-key-id" ->
                                        "mail-sandbox/debug-dashboard/no-auth-proof"
                                    else ->
                                        "mail-sandbox/debug-dashboard/management"
                                },
                            ),
                        )
                    }
                }

                "Account" -> {
                    val id = requireNotNull(ids).single()
                    getResponse(
                        objectType = objectType,
                        value = if (id == "management-id") {
                            managementGetCount += 1
                            managementAccountObject(
                                retired = managementRetired,
                                includeApiKey = managementGetCount >= 3,
                            )
                        } else {
                            ordinaryAccountObject(id)
                        },
                    )
                }

                else -> error("Unexpected scripted get $objectType")
            }
        }

        override suspend fun registryUpdate(
            objectType: String,
            objectId: String,
            patch: JsonObject,
            accountId: String?,
        ): JsonObject {
            operations += GateOperation(
                label = "update:$objectType:$objectId",
                objectType = objectType,
                objectId = objectId,
                value = patch,
                accountId = accountId,
            )
            if (objectType == "Account" && objectId == "management-id") {
                managementRetired = true
            }
            return setUpdatedResponse(objectType, objectId)
        }

        override suspend fun registryDestroy(
            objectType: String,
            objectId: String,
            accountId: String?,
        ): JsonObject {
            operations += GateOperation(
                label = "destroy:$objectType:$objectId",
                objectType = objectType,
                objectId = objectId,
                accountId = accountId,
            )
            if (objectType == "ApiKey") {
                destroyedApiKeyIds += objectId
            }
            return setDestroyedResponse(objectType, objectId)
        }

        override suspend fun registryQuery(
            objectType: String,
            filter: JsonObject,
            accountId: String?,
        ): JsonObject = error("Unexpected scripted query $objectType")

        override fun close() {
            closeCount += 1
        }

        private fun networkListenerObject(id: String): JsonObject = buildJsonObject {
            put("id", id)
            val isSmtp = id == "smtp-listener-id"
            put("name", if (isSmtp) "smtp-gate0b" else "http")
            put(
                "bind",
                buildJsonObject {
                    put(if (isSmtp) "[::]:8587" else "[::]:8080", true)
                },
            )
            put("protocol", if (isSmtp) "smtp" else "http")
            put("useTls", false)
            put("tlsImplicit", false)
        }

        private fun smtpAuthenticationStageObject(id: String): JsonObject =
            buildJsonObject {
                put("id", id)
                put(
                    "saslMechanisms",
                    buildJsonObject {
                        put("match", buildJsonObject {})
                        put("else", "[plain]")
                    },
                )
            }

        private fun domainObject(id: String): JsonObject = buildJsonObject {
            put("id", id)
            put("name", "local.test")
            put("aliases", buildJsonObject {})
            put("isEnabled", true)
            put("certificateManagement", buildJsonObject { put("@type", "Manual") })
            put("dkimManagement", buildJsonObject { put("@type", "Manual") })
            put("dnsManagement", buildJsonObject { put("@type", "Manual") })
            put("subAddressing", buildJsonObject { put("@type", "Enabled") })
            put("allowRelaying", false)
        }

        private fun systemSettingsObject(id: String): JsonObject = buildJsonObject {
            put("id", id)
            put("defaultHostname", "stalwart.local.test")
            put("defaultDomainId", "domain-id")
        }

        private fun managementAccountObject(
            retired: Boolean,
            includeApiKey: Boolean,
        ): JsonObject =
            buildJsonObject {
                put("id", "management-id")
                put("@type", "User")
                put("name", "dashboard-management")
                put("domainId", "domain-id")
                put(
                    "credentials",
                    if (retired) {
                        jsonMap(
                            "credential-map-slot" to apiKeyCredential(),
                        )
                    } else if (includeApiKey) {
                        jsonMap(
                            "0" to passwordCredential(),
                            "credential-map-slot" to apiKeyCredential(),
                        )
                    } else {
                        jsonMap(
                            "0" to passwordCredential(),
                        )
                    },
                )
                put(
                    "roles",
                    buildJsonObject { put("@type", "User") },
                )
                put(
                    "permissions",
                    permissionsObject(
                        if (retired) {
                            GateBootstrap.managementPermissions
                        } else {
                            GateBootstrap.managementPermissionsWithTemporaryApiKeyAccess
                        },
                    ),
                )
            }

        private fun ordinaryAccountObject(id: String): JsonObject = buildJsonObject {
            val localPart = when (id) {
                "first-user-id" -> "gate-one"
                "second-user-id" -> "gate-two"
                else -> error("Unexpected ordinary Account ID")
            }
            put("id", id)
            put("@type", "User")
            put("name", localPart)
            put("domainId", "domain-id")
            put("credentials", jsonMap("0" to passwordCredential()))
            put("roles", buildJsonObject { put("@type", "User") })
            put("permissions", buildJsonObject { put("@type", "Inherit") })
        }

        private fun apiKeyCredential(): JsonObject = buildJsonObject {
            put("@type", "ApiKey")
            put("credentialId", "management-key-id")
            put("description", "mail-sandbox/debug-dashboard/management")
            put("secret", "********")
            put("permissions", credentialPermissions(GateBootstrap.managementPermissions))
            put("allowedIps", buildJsonObject {})
        }

        private fun passwordCredential(): JsonObject = buildJsonObject {
            put("@type", "Password")
            put("credentialId", "password-id")
            put("secret", "********")
            put("allowedIps", buildJsonObject {})
        }
    }

    private fun withTemporaryProject(block: (Path) -> Unit) {
        val root = createTempDirectory("stalwart-gate0b-live-env-test")
        try {
            Files.writeString(root.resolve("project.yaml"), "product: test\n")
            val runtime = root.resolve(".runtime/stalwart-gate0b")
            runtime.createDirectories()
            Files.setPosixFilePermissions(
                runtime,
                PosixFilePermissions.fromString("rwx------"),
            )
            block(root.toRealPath())
        } finally {
            Files.walk(root).use { entries ->
                entries.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
            }
        }
    }

    private fun assertCredentialTypes(value: JsonObject, expected: List<String>) {
        val types = value.getValue("credentials").jsonObject.values.map {
            it.jsonObject.getValue("@type").jsonPrimitive.content
        }
        assertEquals(expected, types)
    }

    private fun enabledPermissions(value: JsonObject): Set<String> =
        value.getValue("permissions")
            .jsonObject
            .getValue("enabledPermissions")
            .jsonObject
            .filterValues { it.jsonPrimitive.boolean }
            .keys

}

private fun JsonObject.createdId(creationId: String): String =
    getValue("methodResponses").jsonArray
        .single()
        .jsonArray[1]
        .jsonObject
        .getValue("created")
        .jsonObject
        .getValue(creationId)
        .jsonObject
        .getValue("id")
        .jsonPrimitive
        .content

private fun setCreatedResponse(
    objectType: String,
    creationId: String,
    id: String,
    extra: Map<String, String>,
): JsonObject = buildJsonObject {
    put(
        "methodResponses",
        kotlinx.serialization.json.buildJsonArray {
            add(
                kotlinx.serialization.json.buildJsonArray {
                    add(kotlinx.serialization.json.JsonPrimitive("x:$objectType/set"))
                    add(
                        buildJsonObject {
                            put(
                                "created",
                                buildJsonObject {
                                    put(
                                        creationId,
                                        buildJsonObject {
                                            put("id", id)
                                            extra.forEach(::put)
                                        },
                                    )
                                },
                            )
                        },
                    )
                    add(kotlinx.serialization.json.JsonPrimitive("gate-script"))
                },
            )
        },
    )
}

private fun setUpdatedResponse(
    objectType: String,
    id: String,
): JsonObject = buildJsonObject {
    put(
        "methodResponses",
        kotlinx.serialization.json.buildJsonArray {
            add(
                kotlinx.serialization.json.buildJsonArray {
                    add(kotlinx.serialization.json.JsonPrimitive("x:$objectType/set"))
                    add(
                        buildJsonObject {
                            put(
                                "updated",
                                buildJsonObject {
                                    put(id, JsonObject(emptyMap()))
                                },
                            )
                        },
                    )
                    add(kotlinx.serialization.json.JsonPrimitive("gate-script"))
                },
            )
        },
    )
}

private fun setDestroyedResponse(
    objectType: String,
    id: String,
): JsonObject = buildJsonObject {
    put(
        "methodResponses",
        kotlinx.serialization.json.buildJsonArray {
            add(
                kotlinx.serialization.json.buildJsonArray {
                    add(kotlinx.serialization.json.JsonPrimitive("x:$objectType/set"))
                    add(
                        buildJsonObject {
                            put(
                                "destroyed",
                                kotlinx.serialization.json.buildJsonArray {
                                    add(kotlinx.serialization.json.JsonPrimitive(id))
                                },
                            )
                        },
                    )
                    add(kotlinx.serialization.json.JsonPrimitive("gate-script"))
                },
            )
        },
    )
}

private fun getResponse(
    objectType: String,
    value: JsonObject,
): JsonObject = buildJsonObject {
    put(
        "methodResponses",
        kotlinx.serialization.json.buildJsonArray {
            add(
                kotlinx.serialization.json.buildJsonArray {
                    add(kotlinx.serialization.json.JsonPrimitive("x:$objectType/get"))
                    add(
                        buildJsonObject {
                            put(
                                "list",
                                kotlinx.serialization.json.buildJsonArray { add(value) },
                            )
                            put("notFound", kotlinx.serialization.json.buildJsonArray {})
                        },
                    )
                    add(kotlinx.serialization.json.JsonPrimitive("gate-script"))
                },
            )
        },
    )
}

private fun getNotFoundResponse(
    objectType: String,
    id: String,
): JsonObject = buildJsonObject {
    put(
        "methodResponses",
        kotlinx.serialization.json.buildJsonArray {
            add(
                kotlinx.serialization.json.buildJsonArray {
                    add(kotlinx.serialization.json.JsonPrimitive("x:$objectType/get"))
                    add(
                        buildJsonObject {
                            put("list", kotlinx.serialization.json.buildJsonArray {})
                            put(
                                "notFound",
                                kotlinx.serialization.json.buildJsonArray {
                                    add(kotlinx.serialization.json.JsonPrimitive(id))
                                },
                            )
                        },
                    )
                    add(kotlinx.serialization.json.JsonPrimitive("gate-script"))
                },
            )
        },
    )
}

private fun apiKeyObject(
    id: String,
    permissions: Set<String>,
    description: String,
): JsonObject = buildJsonObject {
    put("id", id)
    put("description", description)
    put("secret", "********")
    put("permissions", credentialPermissions(permissions))
    put("allowedIps", buildJsonObject {})
}

private fun permissionsObject(permissions: Set<String>): JsonObject = buildJsonObject {
    put("@type", "Replace")
    put(
        "enabledPermissions",
        buildJsonObject {
            permissions.forEach { put(it, true) }
        },
    )
    put("disabledPermissions", buildJsonObject {})
}

private fun credentialPermissions(permissions: Set<String>): JsonObject = buildJsonObject {
    put("@type", "Replace")
    put(
        "permissions",
        buildJsonObject {
            permissions.forEach { put(it, true) }
        },
    )
}

private fun jsonMap(vararg entries: Pair<String, JsonObject>): JsonObject =
    buildJsonObject {
        entries.forEach { (key, value) -> put(key, value) }
    }
