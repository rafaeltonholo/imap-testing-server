package mail.sandbox.dashboard.server.gate.dovecot

import java.io.File
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotSame
import kotlin.test.assertSame
import kotlin.test.assertTrue

class DovecotOperatorRuntimeTest {
    @Test
    fun productionDockerCandidateAllowlistHasTheAuditedImmutableOrder() {
        val candidates =
            DovecotOperatorRuntime.productionDockerCandidates

        assertEquals(
            listOf(
                Path.of("/usr/local/bin/docker"),
                Path.of("/opt/homebrew/bin/docker"),
                Path.of("/usr/bin/docker"),
            ),
            candidates,
        )
        assertFailsWith<UnsupportedOperationException> {
            (candidates as MutableList<Path>)[0] =
                Path.of("/request/docker")
        }
    }

    @Test
    fun explicitStartupOverrideWinsOverEveryCandidate() =
        withRuntimeFixture { fixture ->
            val fallback = fixture.executable("fallback-docker")

            val runtime = DovecotOperatorRuntime.production(
                paths = fixture.operatorPaths(),
                startupEnvironment = mapOf(
                    DOCKER_OVERRIDE_KEY to fixture.docker.toString(),
                ),
                dockerCandidates = listOf(fallback),
            )

            assertEquals(fixture.docker, runtime.launchProfile.dockerCli)
        }

    @Test
    fun explicitStartupOverrideIsCanonicalizedThroughASymbolicLink() =
        withRuntimeFixture { fixture ->
            val symbolicDocker =
                fixture.workspace.resolve("symbolic-docker")
            Files.createSymbolicLink(symbolicDocker, fixture.docker)

            val runtime = DovecotOperatorRuntime.production(
                paths = fixture.operatorPaths(),
                startupEnvironment = mapOf(
                    DOCKER_OVERRIDE_KEY to symbolicDocker.toString(),
                ),
                dockerCandidates = emptyList(),
            )

            assertEquals(fixture.docker, runtime.launchProfile.dockerCli)
            assertFalse(Files.isSymbolicLink(runtime.launchProfile.dockerCli))
        }

    @Test
    fun absentOverrideSelectsTheFirstUsableCandidateAtEveryOrderedPosition() =
        withRuntimeFixture { fixture ->
            val second = fixture.executable("second-docker")
            val third = fixture.executable("third-docker")
            val missing = fixture.workspace.resolve("missing-docker")
            val nonExecutable =
                fixture.regularFile(
                    name = "non-executable-docker",
                    executable = false,
                )
            val cases = listOf(
                listOf(fixture.docker, second, third) to fixture.docker,
                listOf(missing, second, third) to second,
                listOf(missing, nonExecutable, third) to third,
            )

            cases.forEach { (candidates, expected) ->
                val runtime = DovecotOperatorRuntime.production(
                    paths = fixture.operatorPaths(),
                    startupEnvironment = emptyMap(),
                    dockerCandidates = candidates,
                )

                assertEquals(expected, runtime.launchProfile.dockerCli)
            }
        }

    @Test
    fun invalidExplicitOverrideFailsClosedWithoutCandidateFallback() =
        withRuntimeFixture { fixture ->
            val invalidDirectory =
                Files.createDirectory(
                    fixture.workspace.resolve("invalid-docker-directory"),
                )
            val nonExecutable =
                fixture.regularFile(
                    name = "invalid-non-executable-docker",
                    executable = false,
                )
            val invalidOverrides = listOf(
                "relative-docker-canary",
                fixture.workspace.resolve("missing-docker-canary").toString(),
                invalidDirectory.toString(),
                nonExecutable.toString(),
            )

            invalidOverrides.forEach { invalidOverride ->
                val failure = assertFailsWith<IllegalArgumentException> {
                    DovecotOperatorRuntime.production(
                        paths = fixture.operatorPaths(),
                        startupEnvironment = mapOf(
                            DOCKER_OVERRIDE_KEY to invalidOverride,
                        ),
                        dockerCandidates = listOf(fixture.docker),
                    )
                }

                assertEquals(INVALID_DOCKER_MESSAGE, failure.message)
                assertFalse(failure.message.orEmpty().contains("canary"))
            }
        }

    @Test
    fun absentOverrideAndNoUsableCandidateFailsWithARedactedMessage() =
        withRuntimeFixture { fixture ->
            val unavailable =
                fixture.workspace.resolve("unavailable-docker-canary")
            val directory =
                Files.createDirectory(
                    fixture.workspace.resolve("docker-directory-canary"),
                )
            val nonExecutable =
                fixture.regularFile(
                    name = "non-executable-candidate-canary",
                    executable = false,
                )

            val failure = assertFailsWith<IllegalStateException> {
                DovecotOperatorRuntime.production(
                    paths = fixture.operatorPaths(),
                    startupEnvironment = emptyMap(),
                    dockerCandidates =
                        listOf(unavailable, directory, nonExecutable),
                )
            }

            assertEquals(UNAVAILABLE_DOCKER_MESSAGE, failure.message)
            assertFalse(failure.message.orEmpty().contains("canary"))
        }

    @Test
    fun productionOwnsOneCanonicalBaseComposeProfileWithFixedRouting() =
        withRuntimeFixture(
            repositoryName = "mail-sandbox-runtime_1",
        ) { fixture ->
            val runtime = fixture.productionRuntime()
            val profile = runtime.launchProfile

            assertEquals(fixture.docker, profile.dockerCli)
            assertEquals(fixture.repository, profile.repositoryRoot)
            assertEquals(listOf(fixture.compose), profile.composeFiles)
            assertEquals("mail-sandbox-runtime_1", profile.projectName)
            assertEquals(
                "unix:///var/run/docker.sock",
                profile.dockerHost,
            )
            assertEquals("dovecot-operator", profile.service)
            assertEquals("dovecot-operator", profile.composeProfile)
            assertEquals(1, profile.argv.count { it == "-f" })
    }

    @Test
    fun productionRejectsARepositoryRootChangedAfterPathValidation() {
        withRuntimeFixture { fixture ->
            val stalePaths = fixture.operatorPaths()
            Files.move(
                fixture.repository,
                fixture.workspace.resolve("moved-repository"),
            )

            val failure = assertFailsWith<IllegalArgumentException> {
                DovecotOperatorRuntime.production(
                    paths = stalePaths,
                    startupEnvironment = emptyMap(),
                    dockerCandidates = listOf(fixture.docker),
                )
            }

            assertEquals(INVALID_REPOSITORY_MESSAGE, failure.message)
        }
    }

    @Test
    fun productionRejectsAnInvalidRepositoryRootProjectName() {
        withRuntimeFixture(
            repositoryName = "Invalid.Project",
        ) { fixture ->
            val failure = assertFailsWith<IllegalArgumentException> {
                fixture.productionRuntime()
            }

            assertEquals(INVALID_PROJECT_MESSAGE, failure.message)
        }
    }

    @Test
    fun proofUsesItsValidatedOrderedFilesAndNeverAliasesProduction() =
        withRuntimeFixture(
            repositoryName = "mail-sandbox-production",
        ) { fixture ->
            val production = fixture.productionRuntime()
            val proof = DovecotOperatorRuntime.task5Proof(
                profile = fixture.proofProfile(),
                selectedDockerCli = fixture.docker,
            )

            assertNotSame(
                production.launchProfile,
                proof.launchProfile,
            )
            assertEquals(
                listOf(fixture.compose),
                production.launchProfile.composeFiles,
            )
            assertEquals(
                listOf(fixture.compose, fixture.composeOverride),
                proof.launchProfile.composeFiles,
            )
            assertEquals(
                "mail-sandbox-production",
                production.launchProfile.projectName,
            )
            assertEquals(
                "mail-sandbox-task5-proof",
                proof.launchProfile.projectName,
            )
            assertEquals(
                "unix:///var/run/docker.sock",
                proof.launchProfile.dockerHost,
            )
            assertEquals("dovecot-operator", proof.launchProfile.service)
            assertEquals(
                "dovecot-operator",
                proof.launchProfile.composeProfile,
            )
            assertEquals(
                mapOf(
                    "COMPOSE_DISABLE_ENV_FILE" to "1",
                    "DOCKER_HOST" to "unix:///var/run/docker.sock",
                ),
                proof.launchProfile.sanitizedEnvironment(
                    mapOf(
                        "COMPOSE_FILE" to "request-compose.yml",
                        "COMPOSE_PROJECT_NAME" to "request-project",
                        "DOCKER_CONTEXT" to "request-context",
                        "DOVECOT_TARGET" to "request-target",
                    ),
                ),
            )
    }

    @Test
    fun productionBindsOneFactoryToTheFrozenProfileAndOpensOnlyOnUse() =
        withRuntimeFixture { fixture ->
            val symbolicDocker =
                fixture.workspace.resolve("startup-only-docker")
            Files.createSymbolicLink(symbolicDocker, fixture.docker)
            val environment = CountingStartupEnvironment(
                mapOf(DOCKER_OVERRIDE_KEY to symbolicDocker.toString()),
            )
            val binding = RecordingRuntimeTransportBinding()
            val runtime = DovecotOperatorRuntime.production(
                paths = fixture.operatorPaths(),
                startupEnvironment = environment,
                dockerCandidates = emptyList(),
                transportFactoryProvider = binding::create,
            )
            Files.delete(symbolicDocker)

            assertEquals(1, binding.providerCalls)
            assertSame(runtime.launchProfile, binding.boundProfile)
            assertEquals(fixture.docker, binding.boundProfile?.dockerCli)
            assertEquals(0, binding.opens)
            val probe = runtime.probe()
            val secondProbe = runtime.probe()

            assertEquals(1, environment.dockerOverrideReads)
            assertEquals(1, binding.providerCalls)
            assertEquals(0, binding.opens)
            assertNotSame(probe, secondProbe)
            assertEquals(fixture.docker, runtime.launchProfile.dockerCli)
            val secretBytes =
                "runtime-bound-probe-secret"
                    .toByteArray(StandardCharsets.US_ASCII)
            val result = probe.probe(
                target = DovecotOperatorTarget.create("dev@local.test"),
                credential = DovecotOperatorCredential(
                    id = DovecotOperatorId.A,
                    secret = DovecotOperatorSecret.takeOwnership(secretBytes),
                ),
            )
            assertEquals(
                DovecotOperatorProbeResult.TransportFailure,
                result,
            )
            assertEquals(1, binding.opens)
            assertEquals(1, binding.providerCalls)
            assertEquals(1, environment.dockerOverrideReads)
            assertTrue(secretBytes.all { it == 0.toByte() })
        }

    @Test
    fun task5ProofBindsOneFactoryToItsFrozenProfileAndOpensOnlyOnUse() =
        withRuntimeFixture { fixture ->
            val binding = RecordingRuntimeTransportBinding()
            val runtime = DovecotOperatorRuntime.task5Proof(
                profile = fixture.proofProfile(),
                selectedDockerCli = fixture.docker,
                transportFactoryProvider = binding::create,
            )

            assertEquals(1, binding.providerCalls)
            assertSame(runtime.launchProfile, binding.boundProfile)
            assertEquals(
                listOf(fixture.compose, fixture.composeOverride),
                binding.boundProfile?.composeFiles,
            )
            assertEquals(0, binding.opens)
            val probe = runtime.probe()
            assertEquals(1, binding.providerCalls)
            assertEquals(0, binding.opens)
            val secretBytes =
                "proof-runtime-bound-secret"
                    .toByteArray(StandardCharsets.US_ASCII)

            assertEquals(
                DovecotOperatorProbeResult.TransportFailure,
                probe.probe(
                    target =
                        DovecotOperatorTarget.create("proof@local.test"),
                    credential = DovecotOperatorCredential(
                        id = DovecotOperatorId.A,
                        secret =
                            DovecotOperatorSecret.takeOwnership(secretBytes),
                    ),
                ),
            )

            assertEquals(1, binding.opens)
            assertEquals(1, binding.providerCalls)
            assertTrue(secretBytes.all { it == 0.toByte() })
        }

    @Test
    fun productionDefaultsToTheProcessTransportWithoutStartingIt() =
        withRuntimeFixture { fixture ->
            val runtime = fixture.productionRuntime()

            assertTrue(
                runtimeTransportFactory(runtime) is
                    JvmDockerExecDovecotOperatorTransportFactory,
            )
            runtime.probe()

            assertTrue(
                runtimeTransportFactory(runtime) is
                    JvmDockerExecDovecotOperatorTransportFactory,
            )
        }

    @Test
    fun runtimeOffersOnlyZeroArgumentProbeConstruction() =
        withRuntimeFixture { fixture ->
            val binding = RecordingRuntimeTransportBinding()
            val runtime = DovecotOperatorRuntime.production(
                paths = fixture.operatorPaths(),
                startupEnvironment = emptyMap(),
                dockerCandidates = listOf(fixture.docker),
                transportFactoryProvider = binding::create,
            )

            runtime.probe()

            assertEquals(1, binding.providerCalls)
            assertEquals(0, binding.opens)
            val runtimeMethods =
                DovecotOperatorRuntime::class.java.declaredMethods
            assertTrue(
                runtimeMethods.none {
                    it.name.substringBefore('$') == "open"
                },
            )
            assertEquals(
                listOf(0),
                runtimeMethods
                    .filter {
                        it.name.substringBefore('$') == "probe"
                    }
                    .map { it.parameterCount },
            )
            assertTrue(
                DovecotOperatorProbe::class.java.declaredConstructors
                    .none { it.parameterCount == 0 },
            )
        }

    @Test
    fun jsseFactoryRetainsOnlyProofProfileConstructionUntilTask5Migration() {
        val factoryClass =
            JvmJsseDovecotOperatorTransportFactory::class.java
        val companionClass = factoryClass.declaredClasses.single {
            it.simpleName == "Companion"
        }

        assertTrue(
            companionClass.declaredMethods.none {
                it.name == "production"
            },
        )
        val task5Proof = companionClass.declaredMethods.single {
            it.name == "task5Proof"
        }
        assertEquals(
            listOf(DovecotTask5ProofProfile::class.java),
            task5Proof.parameterTypes.toList(),
        )
        val constructor =
            factoryClass.declaredConstructors
                .filterNot { it.isSynthetic }
                .single()
        assertEquals(
            listOf(DovecotTask5ProofProfile::class.java),
            constructor.parameterTypes.toList(),
        )
    }
}

private class RecordingRuntimeTransportBinding {
    var providerCalls: Int = 0
        private set
    var opens: Int = 0
        private set
    var boundProfile: DovecotOperatorLaunchProfile? = null
        private set

    fun create(
        profile: DovecotOperatorLaunchProfile,
    ): DovecotOperatorTransportFactory {
        providerCalls += 1
        check(boundProfile == null)
        boundProfile = profile
        return DovecotOperatorTransportFactory { _ ->
            opens += 1
            throw IOException("runtime-transport-open-canary")
        }
    }
}

private fun runtimeTransportFactory(
    runtime: DovecotOperatorRuntime,
): DovecotOperatorTransportFactory {
    val field =
        DovecotOperatorRuntime::class.java.getDeclaredField("transportFactory")
    field.isAccessible = true
    return field.get(runtime) as DovecotOperatorTransportFactory
}

private data class RuntimeFixture(
    val workspace: Path,
    val repository: Path,
    val compose: Path,
    val composeOverride: Path,
    val docker: Path,
) {
    fun operatorPaths(): DovecotOperatorPaths =
        DovecotOperatorPaths.testing(repository)

    fun productionRuntime(): DovecotOperatorRuntime =
        DovecotOperatorRuntime.production(
            paths = operatorPaths(),
            startupEnvironment = emptyMap(),
            dockerCandidates = listOf(docker),
        )

    fun proofProfile(): DovecotTask5ProofProfile =
        DovecotTask5ProofProfile.load(
            environment = mapOf(
                "DOVECOT_LIVE_TESTS" to "1",
                "DOVECOT_LIVE_PROFILE" to "task5-proof",
                "COMPOSE_PROJECT_NAME" to "mail-sandbox-task5-proof",
                "COMPOSE_FILE" to (
                    "docker-compose.yml" +
                        File.pathSeparator +
                        PROOF_OVERRIDE_RELATIVE_PATH
                    ),
                "COMPOSE_DISABLE_ENV_FILE" to "1",
                "DOCKER_HOST" to "unix:///var/run/docker.sock",
            ),
            repositoryRoot = repository,
        )

    fun executable(name: String): Path =
        regularFile(name = name, executable = true)

    fun regularFile(
        name: String,
        executable: Boolean,
    ): Path {
        val path = Files.createFile(workspace.resolve(name)).toRealPath()
        check(path.toFile().setExecutable(executable, false))
        check(Files.isExecutable(path) == executable)
        return path
    }
}

private inline fun withRuntimeFixture(
    repositoryName: String = "mail-sandbox-runtime",
    block: (RuntimeFixture) -> Unit,
) {
    val workspace =
        Files.createTempDirectory("dovecot-operator-runtime-").toRealPath()
    try {
        val repository =
            Files.createDirectory(workspace.resolve(repositoryName)).toRealPath()
        val compose =
            Files.writeString(
                repository.resolve("docker-compose.yml"),
                "services: {}\n",
            ).toRealPath()
        val dashboard =
            Files.createDirectory(repository.resolve("debug-dashboard"))
                .toRealPath()
        Files.writeString(
            dashboard.resolve("project.yaml"),
            "product: jvm/app\n",
        )
        val proofResources = Files.createDirectories(
            repository.resolve(
                "debug-dashboard/dashboard-server/testResources/" +
                    "dovecot-gate0c",
            ),
        )
        val composeOverride =
            Files.writeString(
                proofResources.resolve("compose.task5-proof.yml"),
                "services: {}\n",
            ).toRealPath()
        val docker =
            Files.createFile(workspace.resolve("docker")).toRealPath()
        check(docker.toFile().setExecutable(true, false))
        check(Files.isExecutable(docker))

        block(
            RuntimeFixture(
                workspace = workspace,
                repository = repository,
                compose = compose,
                composeOverride = composeOverride,
                docker = docker,
            ),
        )
    } finally {
        check(workspace.toFile().deleteRecursively())
    }
}

private class CountingStartupEnvironment(
    private val delegateMap: Map<String, String>,
) : Map<String, String> by delegateMap {
    var dockerOverrideReads: Int = 0
        private set

    override fun get(key: String): String? {
        if (key == DOCKER_OVERRIDE_KEY) {
            dockerOverrideReads += 1
        }
        return delegateMap[key]
    }
}

private const val DOCKER_OVERRIDE_KEY = "MAIL_SANDBOX_DOCKER_CLI"
private const val INVALID_DOCKER_MESSAGE =
    "Dovecot operator Docker CLI is invalid"
private const val UNAVAILABLE_DOCKER_MESSAGE =
    "Dovecot operator Docker CLI is unavailable"
private const val INVALID_REPOSITORY_MESSAGE =
    "Dovecot operator repository root is invalid"
private const val INVALID_PROJECT_MESSAGE =
    "Dovecot operator Compose project is invalid"
private const val PROOF_OVERRIDE_RELATIVE_PATH =
    "debug-dashboard/dashboard-server/testResources/" +
        "dovecot-gate0c/compose.task5-proof.yml"
