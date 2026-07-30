package mail.sandbox.dashboard.server.gate.dovecot

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertSame
import kotlin.test.assertTrue

class DovecotOperatorProcessTransportTest {
    @Test
    fun launchProfileRetainsCanonicalPathsInOrderAndFixesOperatorIdentity() =
        withLaunchFixture { fixture ->
            val suppliedComposeFiles =
                mutableListOf(fixture.compose, fixture.composeOverride)

            val profile = fixture.profile(
                composeFiles = suppliedComposeFiles,
            )
            suppliedComposeFiles.clear()

            assertEquals(fixture.docker, profile.dockerCli)
            assertEquals(fixture.repository, profile.repositoryRoot)
            assertEquals(
                listOf(fixture.compose, fixture.composeOverride),
                profile.composeFiles,
            )
            assertEquals("mail-sandbox-test_1", profile.projectName)
            assertEquals(
                "unix:///var/run/docker.sock",
                profile.dockerHost,
            )
            assertEquals("dovecot-operator", profile.service)
            assertEquals("dovecot-operator", profile.composeProfile)
            assertFailsWith<UnsupportedOperationException> {
                (profile.composeFiles as MutableList<Path>).clear()
            }
        }

    @Test
    fun launchProfileRejectsEveryNonCanonicalOrNonExecutableDockerPath() =
        withLaunchFixture { fixture ->
            val nonExecutable = Files.createFile(
                fixture.workspace.resolve("docker-not-executable"),
            ).toRealPath()
            check(nonExecutable.toFile().setExecutable(false, false))
            val nested = Files.createDirectory(
                fixture.workspace.resolve("docker-path-segment"),
            )
            val nonCanonical =
                nested.resolve("..").resolve(fixture.docker.fileName)
            val symbolicLink =
                fixture.workspace.resolve("docker-symbolic-link")
            Files.createSymbolicLink(symbolicLink, fixture.docker)

            listOf(
                Path.of("docker"),
                fixture.workspace.resolve("missing-docker"),
                fixture.repository,
                nonExecutable,
                nonCanonical,
                symbolicLink,
            ).forEach { invalidDocker ->
                assertFailsWith<IllegalArgumentException>(
                    "Docker path should be rejected: $invalidDocker",
                ) {
                    fixture.profile(dockerCli = invalidDocker)
                }
            }
        }

    @Test
    fun launchProfileRejectsEveryNonCanonicalOrSymbolicRepositoryRoot() =
        withLaunchFixture { fixture ->
            val nested = Files.createDirectory(
                fixture.repository.resolve("root-path-segment"),
            )
            val nonCanonical = nested.resolve("..")
            val symbolicLink =
                fixture.workspace.resolve("repository-symbolic-link")
            Files.createSymbolicLink(symbolicLink, fixture.repository)

            listOf(
                Path.of("repository"),
                fixture.workspace.resolve("missing-repository"),
                fixture.compose,
                nonCanonical,
                symbolicLink,
            ).forEach { invalidRepository ->
                assertFailsWith<IllegalArgumentException>(
                    "Repository root should be rejected: $invalidRepository",
                ) {
                    DovecotOperatorLaunchProfile(
                        dockerCli = fixture.docker,
                        repositoryRoot = invalidRepository,
                        composeFiles = listOf(fixture.compose),
                        projectName = "mail-sandbox-test_1",
                    )
                }
            }
        }

    @Test
    fun launchProfileRejectsImplicitOrUntrustedComposeFiles() =
        withLaunchFixture { fixture ->
            val composeDirectory =
                Files.createDirectory(fixture.repository.resolve("compose-dir"))
            val nested =
                Files.createDirectory(
                    fixture.repository.resolve("compose-path-segment"),
                )
            val nonCanonical =
                nested.resolve("..").resolve(fixture.compose.fileName)
            val symbolicLink =
                fixture.repository.resolve("compose-symbolic-link.yml")
            Files.createSymbolicLink(symbolicLink, fixture.compose)
            val outside =
                Files.createFile(fixture.workspace.resolve("outside-compose.yml"))
                    .toRealPath()

            val invalidLists = listOf(
                emptyList(),
                listOf(Path.of("compose.yml")),
                listOf(fixture.repository.resolve("missing-compose.yml")),
                listOf(composeDirectory),
                listOf(nonCanonical),
                listOf(symbolicLink),
                listOf(outside),
            )

            invalidLists.forEach { invalidComposeFiles ->
                assertFailsWith<IllegalArgumentException>(
                    "Compose files should be rejected: $invalidComposeFiles",
                ) {
                    fixture.profile(composeFiles = invalidComposeFiles)
                }
            }
        }

    @Test
    fun launchProfileAcceptsOnlyStrictComposeProjectNames() =
        withLaunchFixture { fixture ->
            listOf(
                "a",
                "0",
                "mail-sandbox",
                "mail_sandbox_1",
                "9project-",
            ).forEach { validProject ->
                assertEquals(
                    validProject,
                    fixture.profile(projectName = validProject).projectName,
                )
            }

            listOf(
                "",
                "-project",
                "_project",
                "Project",
                "project.name",
                "project name",
                "project/name",
                "project\nname",
            ).forEach { invalidProject ->
                assertFailsWith<IllegalArgumentException>(
                    "Project should be rejected: $invalidProject",
                ) {
                    fixture.profile(projectName = invalidProject)
                }
            }
        }

    @Test
    fun argvIsTheExactFixedNonShellDockerComposeExecList() =
        withLaunchFixture { fixture ->
            val profile = fixture.profile(
                composeFiles = listOf(
                    fixture.compose,
                    fixture.composeOverride,
                ),
            )

            assertEquals(expectedArgv(fixture), profile.argv)
            assertEquals(2, profile.argv.count { it == "-f" })
            assertEquals(1, profile.argv.count { it == "--project-directory" })
            assertEquals(1, profile.argv.count { it == "--project-name" })
            assertEquals(1, profile.argv.count { it == "--profile" })
            assertFailsWith<UnsupportedOperationException> {
                (profile.argv as MutableList<String>).clear()
            }

            val shellTokens = setOf(
                "sh",
                "bash",
                "zsh",
                "/bin/sh",
                "/bin/bash",
                "/bin/zsh",
                "-c",
            )
            assertTrue(profile.argv.none(shellTokens::contains))
            assertTrue(
                profile.argv.none { argument ->
                    "`" in argument ||
                        "$(" in argument ||
                        "\${" in argument
                },
            )
            listOf(
                "request-user",
                "dev@local.test",
                "request-password",
                "operator.example.test",
                "2993",
                "/usr/bin/curl",
                "--request-flag",
            ).forEach { untrustedValue ->
                assertFalse(
                    profile.argv.any { untrustedValue in it },
                    "argv contains untrusted value $untrustedValue",
                )
            }
        }

    @Test
    fun sanitizedEnvironmentRemovesExactControlNamespacesAndFixesRouting() =
        withLaunchFixture { fixture ->
            val profile = fixture.profile()
            val inherited = linkedMapOf(
                "PATH" to "/trusted/bin",
                "LANG" to "C.UTF-8",
                "COMPOSE_FILE" to "hostile-compose.yml",
                "COMPOSE_PROJECT_NAME" to "hostile-project",
                "COMPOSE_PROFILES" to "hostile-profile",
                "COMPOSE_DISABLE_ENV_FILE" to "0",
                "DOCKER_HOST" to "tcp://hostile.example.test:2375",
                "DOCKER_CONTEXT" to "hostile-context",
                "DOCKER_CONFIG" to "/hostile/config",
                "DOCKER_TLS_VERIFY" to "1",
                "DOVECOT_USER" to "request-user",
                "DOVECOT_PASSWORD" to "request-password",
                "XCOMPOSE_FILE" to "preserved",
                "docker_host" to "case-sensitive-preserved",
                "Compose_Project" to "case-sensitive-preserved",
            )

            val sanitized = profile.sanitizedEnvironment(inherited)
            inherited.clear()

            assertEquals(
                mapOf(
                    "PATH" to "/trusted/bin",
                    "LANG" to "C.UTF-8",
                    "XCOMPOSE_FILE" to "preserved",
                    "docker_host" to "case-sensitive-preserved",
                    "Compose_Project" to "case-sensitive-preserved",
                    "COMPOSE_DISABLE_ENV_FILE" to "1",
                    "DOCKER_HOST" to "unix:///var/run/docker.sock",
                ),
                sanitized,
            )
            assertEquals(
                setOf("COMPOSE_DISABLE_ENV_FILE"),
                sanitized.keys.filter { it.startsWith("COMPOSE_") }.toSet(),
            )
            assertEquals(
                setOf("DOCKER_HOST"),
                sanitized.keys.filter { it.startsWith("DOCKER_") }.toSet(),
            )
            assertTrue(
                sanitized.keys.none { it.startsWith("DOVECOT_") },
            )
            assertFailsWith<UnsupportedOperationException> {
                (sanitized as MutableMap<String, String>).clear()
            }
        }

    @Test
    fun jvmStarterConfiguresOneExactProcessBuilderWithoutExecutingDocker() =
        withLaunchFixture { fixture ->
            val profile = fixture.profile(
                composeFiles = listOf(
                    fixture.compose,
                    fixture.composeOverride,
                ),
            )
            val inherited = linkedMapOf(
                "PATH" to "/trusted/bin",
                "COMPOSE_FILE" to "hostile-compose.yml",
                "DOCKER_HOST" to "tcp://hostile.example.test:2375",
                "DOVECOT_PASSWORD" to "request-password",
            )
            val expectedProcess = UnstartedTestProcess()
            var launches = 0
            lateinit var capturedBuilder: ProcessBuilder
            val starter: DovecotOperatorProcessStarter =
                JvmDovecotOperatorProcessStarter(
                    inheritedEnvironment = { inherited },
                    builderLauncher = { builder ->
                        launches += 1
                        capturedBuilder = builder
                        expectedProcess
                    },
                )

            val actualProcess = starter.start(profile)

            assertSame(expectedProcess, actualProcess)
            assertEquals(1, launches)
            assertEquals(expectedArgv(fixture), capturedBuilder.command())
            assertEquals(
                fixture.repository.toFile(),
                capturedBuilder.directory(),
            )
            assertEquals(
                ProcessBuilder.Redirect.DISCARD,
                capturedBuilder.redirectError(),
            )
            assertEquals(
                ProcessBuilder.Redirect.PIPE,
                capturedBuilder.redirectInput(),
            )
            assertEquals(
                ProcessBuilder.Redirect.PIPE,
                capturedBuilder.redirectOutput(),
            )
            assertFalse(capturedBuilder.redirectErrorStream())
            assertEquals(
                profile.sanitizedEnvironment(inherited),
                capturedBuilder.environment(),
            )
        }

    private fun expectedArgv(fixture: LaunchFixture): List<String> =
        listOf(
            fixture.docker.toString(),
            "compose",
            "--project-directory",
            fixture.repository.toString(),
            "-f",
            fixture.compose.toString(),
            "-f",
            fixture.composeOverride.toString(),
            "--project-name",
            "mail-sandbox-test_1",
            "--profile",
            "dovecot-operator",
            "exec",
            "-T",
            "--index",
            "1",
            "dovecot-operator",
            "/usr/bin/openssl",
            "s_client",
            "-quiet",
            "-no_ign_eof",
            "-nocommands",
            "-4",
            "-min_protocol",
            "TLSv1.2",
            "-max_protocol",
            "TLSv1.3",
            "-verify_return_error",
            "-verify_hostname",
            "localhost",
            "-no-CApath",
            "-no-CAstore",
            "-CAfile",
            "/etc/dovecot/ssl/tls.crt",
            "-connect",
            "127.0.0.1:31993",
            "-servername",
            "localhost",
        )
}

private data class LaunchFixture(
    val workspace: Path,
    val repository: Path,
    val docker: Path,
    val compose: Path,
    val composeOverride: Path,
) {
    fun profile(
        dockerCli: Path = docker,
        repositoryRoot: Path = repository,
        composeFiles: List<Path> = listOf(compose),
        projectName: String = "mail-sandbox-test_1",
    ): DovecotOperatorLaunchProfile =
        DovecotOperatorLaunchProfile(
            dockerCli = dockerCli,
            repositoryRoot = repositoryRoot,
            composeFiles = composeFiles,
            projectName = projectName,
        )
}

private inline fun withLaunchFixture(
    block: (LaunchFixture) -> Unit,
) {
    val workspace =
        Files.createTempDirectory("dovecot-operator-launch").toRealPath()
    try {
        val repository =
            Files.createDirectory(workspace.resolve("repository")).toRealPath()
        val docker =
            Files.createFile(workspace.resolve("docker")).toRealPath()
        check(docker.toFile().setExecutable(true, true))
        val compose =
            Files.createFile(repository.resolve("docker-compose.yml"))
                .toRealPath()
        val composeOverride =
            Files.createFile(repository.resolve("compose.override.yml"))
                .toRealPath()
        block(
            LaunchFixture(
                workspace = workspace,
                repository = repository,
                docker = docker,
                compose = compose,
                composeOverride = composeOverride,
            ),
        )
    } finally {
        check(workspace.toFile().deleteRecursively())
    }
}

private class UnstartedTestProcess : Process() {
    override fun getOutputStream(): OutputStream = ByteArrayOutputStream()

    override fun getInputStream(): InputStream =
        ByteArrayInputStream(ByteArray(0))

    override fun getErrorStream(): InputStream =
        ByteArrayInputStream(ByteArray(0))

    override fun waitFor(): Int =
        error("The test process must never be awaited")

    override fun waitFor(
        timeout: Long,
        unit: TimeUnit,
    ): Boolean =
        error("The test process must never be awaited")

    override fun exitValue(): Int =
        error("The test process was not started")

    override fun destroy() =
        error("The test process must never be destroyed")
}
