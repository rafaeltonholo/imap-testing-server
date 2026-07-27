package mail.sandbox.dashboard.server.gate.stalwart

import java.nio.file.Files
import java.nio.file.Path
import java.security.SecureRandom
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking

class StalwartBootstrapLiveTest {
    @Test
    fun bootstrapsTheFixtureAndWritesOnlyTheFixedSecretHandoff() = runBlocking {
        val environment = System.getenv()
        val projectRoot = dashboardProjectRoot()
        val live = StalwartLiveTestEnvironment.load(environment, projectRoot)
        live.awaitReady()
        StalwartDockerMountAudit.assertReviewedLiveMounts(projectRoot)

        val managementPassword = newGateSecret()
        val firstUserPassword = newGateSecret()
        val secondUserPassword = newGateSecret()
        try {
            StalwartGateSecretFiles.readRecoveryHandoff(
                projectRoot = projectRoot,
                fixtureSecretsPath = live.fixtureSecretsPath,
            ).use { recoveryCredential ->
                KtorGateHttpTransport().use { transport ->
                    val recovery = GateJmapClient(
                        baseUrl = live.baseUrl,
                        credential = GateCredential.basic(
                            username = recoveryCredential.username,
                            secret = recoveryCredential.secret,
                        ),
                        transport = transport,
                    )
                    val factory = GateRegistryClientFactory { credential ->
                        GateJmapClient(
                            baseUrl = live.baseUrl,
                            credential = credential,
                            transport = transport,
                        )
                    }
                    GateBootstrapInputs(
                        managementPassword = managementPassword,
                        firstUserPassword = firstUserPassword,
                        secondUserPassword = secondUserPassword,
                    ).use { inputs ->
                        GateBootstrap.bootstrap(
                            recovery = recovery,
                            clientFactory = factory,
                            inputs = inputs,
                        ).use { result ->
                            assertEquals(
                                GateBootstrap.managementPermissions,
                                result.effectiveManagementPermissions,
                            )
                            assertEquals(
                                3,
                                setOf(
                                    result.managementAccountId,
                                    result.firstUserAccountId,
                                    result.secondUserAccountId,
                                ).size,
                            )
                            GateFixtureSecrets(
                                managementAccountId = result.managementAccountId,
                                managementApiKey = result.managementApiKey,
                                firstUserPassword = firstUserPassword,
                                secondUserPassword = secondUserPassword,
                            ).use { fixtureSecrets ->
                                StalwartGateSecretFiles.writeFixtureSecrets(
                                    projectRoot = projectRoot,
                                    path = live.fixtureSecretsPath,
                                    secrets = fixtureSecrets,
                                )
                            }
                        }
                    }
                }
            }

            StalwartGateSecretFiles.readFixtureSecrets(
                projectRoot = projectRoot,
                environment = environment,
            ).use { written ->
                assertTrue(written.managementAccountId.isNotBlank())
                assertTrue(
                    written.managementApiKey.size > 4 &&
                        written.managementApiKey[0] == 'A' &&
                        written.managementApiKey[1] == 'P' &&
                        written.managementApiKey[2] == 'I' &&
                        written.managementApiKey[3] == '_',
                    "Written management credential did not have the pinned API-key format",
                )
                assertTrue(written.firstUserPassword.isNotEmpty())
                assertTrue(written.secondUserPassword.isNotEmpty())
            }
        } finally {
            managementPassword.fill('\u0000')
            firstUserPassword.fill('\u0000')
            secondUserPassword.fill('\u0000')
        }
        Unit
    }

    private fun dashboardProjectRoot(): Path {
        val working = Path.of(System.getProperty("user.dir")).toAbsolutePath().normalize()
        val candidate = if (working.fileName?.toString() == "dashboard-server") {
            requireNotNull(working.parent)
        } else {
            working
        }
        require(candidate.fileName?.toString() == "debug-dashboard") {
            "Live gate must run from debug-dashboard or dashboard-server"
        }
        require(Files.isRegularFile(candidate.resolve("project.yaml"))) {
            "Live gate project root is missing project.yaml"
        }
        return candidate.toRealPath()
    }

    private fun newGateSecret(): CharArray {
        val alphabet =
            "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_".toCharArray()
        return CharArray(48) { alphabet[secureRandom.nextInt(alphabet.size)] }
    }

    private companion object {
        val secureRandom = SecureRandom()
    }
}
