package mail.sandbox.dashboard.server.gate.stalwart

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlin.io.path.createDirectories
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class StalwartGateCleanupTest {
    @Test
    fun cleanupIsPinnedToTheNamedProjectAndExactIgnoredRuntime() {
        withTemporaryDashboardProject { projectRoot ->
            val runtime = projectRoot.resolve(".runtime/stalwart-gate0b")
            runtime.resolve("data").createDirectories()
            Files.writeString(runtime.resolve("fixture-secrets"), "canary")
            val repositoryData = projectRoot.resolveSibling("stalwart-data")
            val repositoryVmail = projectRoot.resolveSibling("vmail")
            repositoryData.createDirectories()
            repositoryVmail.createDirectories()
            Files.writeString(repositoryData.resolve("untouched"), "data")
            Files.writeString(repositoryVmail.resolve("untouched"), "mail")

            val plan = StalwartGateCleanup.plan(
                projectRoot = projectRoot,
                requestedProjectName = "mail-sandbox-stalwart-gate",
                requestedRuntimeDirectory = runtime,
            )

            assertEquals("mail-sandbox-stalwart-gate", plan.projectName)
            assertEquals(runtime.toRealPath(), plan.runtimeDirectory)
            assertEquals(
                listOf(
                    "docker",
                    "compose",
                    "-p",
                    "mail-sandbox-stalwart-gate",
                    "-f",
                    projectRoot.resolve(
                        "dashboard-server/testResources/stalwart-gate0b/compose.yml",
                    ).toRealPath().toString(),
                    "down",
                ),
                plan.composeDownCommand,
            )
            assertEquals(
                listOf(
                    "docker",
                    "compose",
                    "-p",
                    "mail-sandbox-stalwart-gate",
                    "-f",
                    plan.baseComposeFile.toString(),
                    "stop",
                    "stalwart",
                ),
                plan.composeStopCommand,
            )
            assertEquals(
                listOf(
                    "docker",
                    "compose",
                    "-p",
                    "mail-sandbox-stalwart-gate",
                    "-f",
                    plan.baseComposeFile.toString(),
                    "run",
                    "--rm",
                    "--no-deps",
                    "--user",
                    "0:0",
                    "--entrypoint",
                    "/bin/sh",
                    "stalwart-data-owner",
                    "-c",
                    "chown -R ${unixId(runtime, "uid")}:" +
                        "${unixId(runtime, "gid")} " +
                        "/var/lib/stalwart && " +
                        "chmod -R u+rwX,go-rwx /var/lib/stalwart",
                ),
                plan.dataReleaseCommand,
            )
            assertTrue(
                (plan.composeStopCommand + plan.dataReleaseCommand + plan.composeDownCommand)
                    .none { it == "-v" || it == "--volumes" },
            )
            assertFalse(plan.dataReleaseCommand.contains("/"))
            assertFalse(plan.dataReleaseCommand.any { "o+rwX" in it })

            val executed = mutableListOf<List<String>>()
            StalwartGateCleanup.cleanup(plan) { command ->
                executed += command
                0
            }

            assertEquals(
                listOf(
                    plan.composeStopCommand,
                    plan.dataReleaseCommand,
                    plan.composeDownCommand,
                ),
                executed,
            )
            assertFalse(Files.exists(runtime))
            assertTrue(Files.exists(repositoryData.resolve("untouched")))
            assertTrue(Files.exists(repositoryVmail.resolve("untouched")))
        }
    }

    @Test
    fun cleanupRequiresSuccessfulScopedReleaseAndNamedProjectDownBeforeDeletion() {
        withTemporaryDashboardProject { projectRoot ->
            val runtime = projectRoot.resolve(".runtime/stalwart-gate0b")
            runtime.createDirectories()
            Files.writeString(runtime.resolve("store"), "data")
            val plan = StalwartGateCleanup.plan(
                projectRoot = projectRoot,
                requestedProjectName = "mail-sandbox-stalwart-gate",
                requestedRuntimeDirectory = runtime,
            )

            assertFailsWith<IllegalStateException> {
                StalwartGateCleanup.cleanup(plan) { command ->
                    if (command == plan.dataReleaseCommand) 1 else 0
                }
            }
            assertTrue(Files.exists(runtime.resolve("store")))

            val commands = mutableListOf<List<String>>()
            assertFailsWith<IllegalStateException> {
                StalwartGateCleanup.cleanup(plan) { command ->
                    commands += command
                    if (command == plan.composeDownCommand) 1 else 0
                }
            }
            assertEquals(
                listOf(
                    plan.composeStopCommand,
                    plan.dataReleaseCommand,
                    plan.composeDownCommand,
                ),
                commands,
            )
            assertTrue(Files.exists(runtime.resolve("store")))
        }
    }

    @Test
    fun cleanupReleaseLeavesFailureStateOwnedAndOwnerOnly() {
        withTemporaryDashboardProject { projectRoot ->
            val runtime = projectRoot.resolve(".runtime/stalwart-gate0b")
            val data = runtime.resolve("data")
            val store = data.resolve("store")
            Files.writeString(store, "data")
            Files.setPosixFilePermissions(data, PosixFilePermissions.fromString("rwx------"))
            Files.setPosixFilePermissions(store, PosixFilePermissions.fromString("rw-------"))
            val plan = cleanupPlan(projectRoot)

            assertFalse(plan.dataReleaseCommand.any { "o+rwX" in it })
            assertTrue(
                plan.dataReleaseCommand.last() ==
                    "chown -R ${plan.hostOwner.uid}:${plan.hostOwner.gid} " +
                    "/var/lib/stalwart && " +
                    "chmod -R u+rwX,go-rwx /var/lib/stalwart",
            )
            assertFailsWith<IllegalStateException> {
                StalwartGateCleanup.cleanup(plan) { command ->
                    if (command == plan.dataReleaseCommand) {
                        Files.setPosixFilePermissions(
                            data,
                            PosixFilePermissions.fromString("rwx------"),
                        )
                        Files.setPosixFilePermissions(
                            store,
                            PosixFilePermissions.fromString("rw-------"),
                        )
                    }
                    if (command == plan.composeDownCommand) 1 else 0
                }
            }

            assertEquals(
                "rwx------",
                PosixFilePermissions.toString(Files.getPosixFilePermissions(data)),
            )
            assertEquals(
                "rw-------",
                PosixFilePermissions.toString(Files.getPosixFilePermissions(store)),
            )
        }
    }

    @Test
    fun cleanupRequiresTheRealGateRuntimeToRemainOwnerOnly() {
        withTemporaryDashboardProject { projectRoot ->
            val runtime = projectRoot.resolve(".runtime/stalwart-gate0b")
            Files.setPosixFilePermissions(
                runtime,
                PosixFilePermissions.fromString("rwxr-x---"),
            )

            assertFailsWith<IllegalArgumentException> {
                cleanupPlan(projectRoot)
            }
        }
    }

    @Test
    fun selectedCleanupCommandRunnerIsBoundedAndRedactsFailures() {
        val completed = ScriptedCommandProcess(
            waits = mutableListOf(true),
            exitCode = 7,
        )
        assertEquals(
            7,
            StalwartBoundedCommandRunner.run(
                command = listOf("docker", "compose"),
                processStarter = { completed },
            ),
        )
        assertEquals(listOf(30L), completed.observedTimeoutSeconds)
        assertFalse(completed.destroyed)

        val timedOut = ScriptedCommandProcess(
            waits = mutableListOf(false, true),
            exitCode = 0,
        )
        val timeoutFailure = assertFailsWith<IllegalStateException> {
            StalwartBoundedCommandRunner.run(
                command = listOf("docker", "compose"),
                processStarter = { timedOut },
            )
        }
        assertEquals(listOf(30L, 5L), timedOut.observedTimeoutSeconds)
        assertTrue(timedOut.destroyed)
        assertFalse(timeoutFailure.message.orEmpty().contains("docker"))

        val secretFailure = assertFailsWith<IllegalStateException> {
            StalwartBoundedCommandRunner.run(
                command = listOf("docker", "compose"),
                processStarter = { throw IllegalStateException("API_do-not-leak") },
            )
        }
        assertFalse(secretFailure.message.orEmpty().contains("API_do-not-leak"))
    }

    @Test
    fun cleanupRejectsUnreviewedFixtureBytesBeforePlanning() {
        listOf<(CleanupFixture) -> Unit>(
            { fixture -> Files.writeString(fixture.compose, "services: {}\n") },
            { fixture ->
                Files.writeString(
                    fixture.compose,
                    Files.readString(fixture.compose).replace(
                        "stalwartlabs/stalwart:v0.16.14",
                        "stalwartlabs/stalwart:latest",
                    ),
                )
            },
            { fixture ->
                Files.writeString(
                    fixture.config,
                    """{ "path": "/var/lib/stalwart/", "@type": "RocksDb" }""",
                )
            },
        ).forEach { mutate ->
            withTemporaryDashboardProject { projectRoot ->
                mutate(cleanupFixture(projectRoot))
                assertFailsWith<IllegalArgumentException> {
                    cleanupPlan(projectRoot)
                }
            }
        }
    }

    @Test
    fun cleanupPinsFixtureIdentityAcrossPlanAndExecution() {
        listOf<(CleanupFixture) -> Unit>(
            { fixture ->
                val bytes = Files.readAllBytes(fixture.compose)
                Files.delete(fixture.compose)
                Files.write(fixture.compose, bytes)
            },
            { fixture ->
                val original = fixture.compose.resolveSibling("compose.reviewed.yml")
                Files.move(fixture.compose, original)
                Files.createSymbolicLink(fixture.compose, original.fileName)
            },
            { fixture ->
                Files.writeString(fixture.config, "{}\n")
            },
        ).forEach { mutate ->
            withTemporaryDashboardProject { projectRoot ->
                val plan = cleanupPlan(projectRoot)
                mutate(cleanupFixture(projectRoot))
                val commands = mutableListOf<List<String>>()

                assertFailsWith<IllegalArgumentException> {
                    StalwartGateCleanup.cleanup(plan) { command ->
                        commands += command
                        0
                    }
                }

                assertTrue(commands.isEmpty())
            }
        }
    }

    @Test
    fun cleanupRevalidatesFixtureAndDataBeforeEverySensitiveCommand() {
        withTemporaryDashboardProject { projectRoot ->
            val fixture = cleanupFixture(projectRoot)
            val plan = cleanupPlan(projectRoot)
            val commands = mutableListOf<List<String>>()

            assertFailsWith<IllegalArgumentException> {
                StalwartGateCleanup.cleanup(plan) { command ->
                    commands += command
                    if (command == plan.composeStopCommand) {
                        Files.writeString(fixture.compose, "services: {}\n")
                    }
                    0
                }
            }

            assertEquals(listOf(plan.composeStopCommand), commands)
            assertFalse(plan.dataReleaseCommand in commands)
        }

        withTemporaryDashboardProject { projectRoot ->
            val fixture = cleanupFixture(projectRoot)
            val outside = projectRoot.resolveSibling("outside-gate-data")
            outside.createDirectories()
            val plan = cleanupPlan(projectRoot)
            val commands = mutableListOf<List<String>>()

            assertFailsWith<IllegalArgumentException> {
                StalwartGateCleanup.cleanup(plan) { command ->
                    commands += command
                    if (command == plan.composeStopCommand) {
                        Files.delete(fixture.data)
                        Files.createSymbolicLink(fixture.data, outside)
                    }
                    0
                }
            }

            assertEquals(listOf(plan.composeStopCommand), commands)
            assertFalse(plan.dataReleaseCommand in commands)
        }

        withTemporaryDashboardProject { projectRoot ->
            val fixture = cleanupFixture(projectRoot)
            val plan = cleanupPlan(projectRoot)
            val commands = mutableListOf<List<String>>()

            assertFailsWith<IllegalArgumentException> {
                StalwartGateCleanup.cleanup(plan) { command ->
                    commands += command
                    if (command == plan.dataReleaseCommand) {
                        Files.writeString(fixture.config, "{}\n")
                    }
                    0
                }
            }

            assertEquals(
                listOf(plan.composeStopCommand, plan.dataReleaseCommand),
                commands,
            )
            assertFalse(plan.composeDownCommand in commands)
        }

        withTemporaryDashboardProject { projectRoot ->
            val runtime = projectRoot.resolve(".runtime/stalwart-gate0b")
            val plan = cleanupPlan(projectRoot)
            val commands = mutableListOf<List<String>>()

            assertFailsWith<IllegalArgumentException> {
                StalwartGateCleanup.cleanup(plan) { command ->
                    commands += command
                    if (command == plan.composeStopCommand) {
                        Files.setPosixFilePermissions(
                            runtime,
                            PosixFilePermissions.fromString("rwxr-x---"),
                        )
                    }
                    0
                }
            }

            assertEquals(listOf(plan.composeStopCommand), commands)
            assertFalse(plan.dataReleaseCommand in commands)
        }
    }

    @Test
    fun cleanupRejectsEveryProjectPathAndSymlinkEscape() {
        withTemporaryDashboardProject { projectRoot ->
            val runtime = projectRoot.resolve(".runtime/stalwart-gate0b")
            runtime.createDirectories()
            listOf(
                "mail-sandbox",
                "mail-sandbox-stalwart",
                "mail-sandbox-stalwart-gate ",
            ).forEach { wrongProject ->
                assertFailsWith<IllegalArgumentException> {
                    StalwartGateCleanup.plan(
                        projectRoot = projectRoot,
                        requestedProjectName = wrongProject,
                        requestedRuntimeDirectory = runtime,
                    )
                }
            }
            listOf(
                projectRoot,
                projectRoot.parent,
                projectRoot.resolveSibling("stalwart-data"),
                projectRoot.resolveSibling("vmail"),
                projectRoot.resolve(".runtime"),
            ).forEach { wrongPath ->
                assertFailsWith<IllegalArgumentException> {
                    StalwartGateCleanup.plan(
                        projectRoot = projectRoot,
                        requestedProjectName = "mail-sandbox-stalwart-gate",
                        requestedRuntimeDirectory = wrongPath,
                    )
                }
            }

            val outside = projectRoot.resolveSibling("outside-gate-runtime")
            outside.createDirectories()
            Files.delete(runtime.resolve("data"))
            Files.delete(runtime)
            Files.createSymbolicLink(runtime, outside)
            assertFailsWith<IllegalArgumentException> {
                StalwartGateCleanup.plan(
                    projectRoot = projectRoot,
                    requestedProjectName = "mail-sandbox-stalwart-gate",
                    requestedRuntimeDirectory = runtime,
                )
            }
        }
    }

    private fun withTemporaryDashboardProject(block: (Path) -> Unit) {
        val sandbox = createTempDirectory("stalwart-gate-cleanup-test")
        val projectRoot = sandbox.resolve("debug-dashboard")
        try {
            projectRoot.createDirectories()
            Files.writeString(projectRoot.resolve("project.yaml"), "product: jvm/app\n")
            Files.writeString(projectRoot.resolve(".gitignore"), "/build/\n/.runtime/\n")
            val runtime = projectRoot.resolve(".runtime/stalwart-gate0b")
            runtime.resolve("data").createDirectories()
            Files.setPosixFilePermissions(
                runtime,
                PosixFilePermissions.fromString("rwx------"),
            )
            val fixture = projectRoot.resolve(
                "dashboard-server/testResources/stalwart-gate0b",
            )
            fixture.createDirectories()
            val reviewedFixture = dashboardProjectRoot().resolve(
                "dashboard-server/testResources/stalwart-gate0b",
            )
            Files.writeString(
                fixture.resolve("compose.yml"),
                Files.readString(reviewedFixture.resolve("compose.yml")),
            )
            Files.writeString(
                fixture.resolve("config.json"),
                Files.readString(reviewedFixture.resolve("config.json")),
            )
            block(projectRoot)
        } finally {
            Files.walk(sandbox).use { entries ->
                entries.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
            }
        }
    }

    private fun dashboardProjectRoot(): Path {
        val working = Path.of(System.getProperty("user.dir")).toAbsolutePath().normalize()
        return if (working.fileName?.toString() == "dashboard-server") {
            requireNotNull(working.parent).toRealPath()
        } else {
            working.toRealPath()
        }
    }

    private fun cleanupPlan(projectRoot: Path): StalwartGateCleanupPlan =
        StalwartGateCleanup.plan(
            projectRoot = projectRoot,
            requestedProjectName = "mail-sandbox-stalwart-gate",
            requestedRuntimeDirectory = projectRoot.resolve(".runtime/stalwart-gate0b"),
        )

    private fun cleanupFixture(projectRoot: Path): CleanupFixture {
        val fixture = projectRoot.resolve(
            "dashboard-server/testResources/stalwart-gate0b",
        )
        return CleanupFixture(
            compose = fixture.resolve("compose.yml"),
            config = fixture.resolve("config.json"),
            data = projectRoot.resolve(".runtime/stalwart-gate0b/data"),
        )
    }

    private data class CleanupFixture(
        val compose: Path,
        val config: Path,
        val data: Path,
    )

    private fun unixId(path: Path, attribute: String): Int =
        (Files.getAttribute(path, "unix:$attribute") as Number).toInt()

    private class ScriptedCommandProcess(
        private val waits: MutableList<Boolean>,
        private val exitCode: Int,
    ) : StalwartCommandProcess {
        val observedTimeoutSeconds = mutableListOf<Long>()
        var destroyed = false

        override fun waitFor(timeoutSeconds: Long): Boolean {
            observedTimeoutSeconds += timeoutSeconds
            return waits.removeFirst()
        }

        override fun destroyForcibly() {
            destroyed = true
        }

        override fun exitValue(): Int = exitCode
    }
}
