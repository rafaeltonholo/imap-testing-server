package mail.sandbox.dashboard.server.gate.stalwart

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive
import mail.sandbox.dashboard.server.provider.stalwart.StalwartRuntimeSecretLoader
import mail.sandbox.dashboard.server.provider.stalwart.StalwartRuntimeSecretPaths

class StalwartRuntimeCredentialLiveTest {
    @Test
    fun protectedManagementCredentialMatchesTheRetiredNormalRuntime() = runBlocking {
        val live = StalwartNormalRuntimeEnvironment.load()
        val dashboardRoot = dashboardProjectRoot()
        val repositoryRoot = requireNotNull(dashboardRoot.parent)
        val evidence = StalwartNormalRuntimeEvidence.load(repositoryRoot)
        val management = evidence.management
        val runtimeSecrets = StalwartRuntimeSecretLoader(
            StalwartRuntimeSecretPaths.production(dashboardRoot),
        ).load()
        var apiKey = CharArray(0)
        try {
            assertEquals(
                evidence.protectedAccountIds.toSet(),
                runtimeSecrets.protectedAccountIds,
                "Protected Account state differs from the receipt-bound identity",
            )
            apiKey = runtimeSecrets.withManagementApiKey(::asciiChars)
            KtorGateHttpTransport().use { transport ->
                GateJmapClient(
                    baseUrl = live.baseUrl,
                    credential = GateCredential.bearer(apiKey),
                    transport = transport,
                ).use { manager ->
                    val session = manager.discoverSession()
                    assertEquals(
                        StalwartEndpointProfile.NORMAL_RUNTIME.apiUrl,
                        session.apiUrl,
                    )
                    assertEquals(management.accountId, session.primaryAccountId)
                    assertEquals(MANAGEMENT_ADDRESS, session.username)

                    val account = registryObjects(
                        manager.registryGet(
                            objectType = "Account",
                            ids = listOf(management.accountId),
                            accountId = management.accountId,
                        ),
                        "x:Account/get",
                        management.accountId,
                    ).values.single()
                    assertExactSafeObject(
                        expected = management.accountProjection,
                        actual = account,
                        generatedKeys = setOf("credentials"),
                    )
                    val accountCredentials = credentials(account)
                    assertEquals(
                        management.credentialInventory.size,
                        accountCredentials.size,
                        "Protected management Account credential inventory is not exact",
                    )
                    val credential = accountCredentials.single()
                    assertExactManagementCredential(
                        expected = management.credentialInventory.single(),
                        actual = credential,
                    )

                    val apiKeyObject = registryObjects(
                        manager.registryGet(
                            objectType = "ApiKey",
                            ids = listOf(management.apiKeyId),
                            accountId = management.accountId,
                        ),
                        "x:ApiKey/get",
                        management.accountId,
                    ).values.single()
                    assertExactSafeObject(
                        expected = management.apiKeyProjection,
                        actual = apiKeyObject,
                        generatedKeys = setOf("secret"),
                    )

                    assertTrue(
                        evidence.oldRecoveryAuthenticationStatus == 401 ||
                            evidence.oldRecoveryAuthenticationStatus == 403,
                        "Validated retirement proof does not reject recovery authentication",
                    )
                }
            }
        } finally {
            apiKey.fill('\u0000')
            runtimeSecrets.close()
        }
    }

    private fun assertExactSafeObject(
        expected: StalwartSafeObjectProjection,
        actual: JsonObject,
        generatedKeys: Set<String>,
    ) {
        assertEquals(
            expected.value.keys + generatedKeys + "id",
            actual.keys,
            "Management object returned an unexpected property set",
        )
        assertEquals(expected.id, requiredString(actual, "id"))
        expected.value.forEach { (property, value) ->
            assertEquals(
                value,
                actual[property],
                "Management safe projection property $property changed",
            )
        }
        if ("secret" in generatedKeys) {
            requireMasked(actual["secret"])
        }
    }

    private fun assertExactManagementCredential(
        expected: JsonObject,
        actual: JsonObject,
    ) {
        val expectedKeys = setOf(
            "@type",
            "allowedIps",
            "credentialId",
            "description",
            "permissions",
            "secret",
        )
        assertEquals(
            expectedKeys,
            actual.keys,
            "Management Account credential returned an unexpected property set",
        )
        require(
            requiredString(actual, "@type") ==
                requiredString(expected, "credential_type") &&
                requiredString(actual, "credentialId") ==
                requiredString(expected, "credential_id") &&
                actual["allowedIps"] == expected["allowed_ips"] &&
                actual["description"] == expected["description"] &&
                actual["permissions"] == expected["permissions"],
        ) {
            "Management Account credential safe projection changed"
        }
        requireMasked(actual["secret"])
    }

    private fun requireMasked(value: kotlinx.serialization.json.JsonElement?) {
        val marker = value?.jsonPrimitive?.content
        require(marker != null && marker.length >= 4 && marker.all { it == '*' }) {
            "Management credential secret was not masked"
        }
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
