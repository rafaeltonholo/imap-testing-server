package mail.sandbox.dashboard.server.local

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermission
import java.util.concurrent.TimeUnit
import kotlin.io.path.createTempDirectory
import kotlin.io.path.isExecutable
import kotlin.io.path.readLines
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class LocalDashboardScriptsTest {
    private val dashboardRoot: Path = Path.of(System.getProperty("user.dir"))
        .toAbsolutePath()
        .normalize()
        .let { working ->
            if (working.fileName?.toString() == "dashboard-server") working.parent else working
        }
    private val repositoryRoot: Path = dashboardRoot.parent

    @Test
    fun normalRuntimeSourcesContainNoRetiredProjectOverlayOrPorts() {
        val normalSources = listOf(
            dashboardRoot.resolve("start-local.sh"),
            dashboardRoot.resolve("stop-local.sh"),
            dashboardRoot.resolve("stalwart-status.sh"),
            dashboardRoot.resolve(
                "dashboard-server/src/mail/sandbox/dashboard/server/local/" +
                    "DockerComposeLogSource.kt",
            ),
            dashboardRoot.resolve(
                "dashboard-server/src/mail/sandbox/dashboard/server/local/LocalSmtpClient.kt",
            ),
            dashboardRoot.resolve(
                "dashboard-server/src/mail/sandbox/dashboard/server/local/" +
                    "LocalDashboardBackend.kt",
            ),
        )
        val forbidden = listOf(
            "mail-sandbox-dashboard",
            "mail-sandbox-stalwart-gate",
            "21025",
            "18443",
            "18587",
            "docker-compose.local-providers.yml",
            "start-local-stalwart.sh",
        )

        normalSources.forEach { path ->
            assertTrue(Files.isRegularFile(path), "${path.fileName} is missing")
            val source = path.readText()
            forbidden.forEach { token ->
                assertFalse(token in source, "${path.fileName} retains forbidden '$token'")
            }
        }
        assertFalse(Files.exists(dashboardRoot.resolve("docker-compose.local-providers.yml")))
        assertFalse(Files.exists(dashboardRoot.resolve("start-local-stalwart.sh")))
    }

    @Test
    fun launcherUsesOnlyRootLifecycleAndKotlinToolchain() {
        val script = dashboardRoot.resolve("start-local.sh")

        assertTrue(Files.isRegularFile(script), "start-local.sh is missing")
        assertTrue(script.isExecutable(), "start-local.sh must be executable")
        val source = script.readText()

        assertTrue("bootstrap-defaults" in source)
        assertTrue("--defer-provider-verification" in source)
        assertTrue("--lifecycle dashboard-start-local" in source)
        assertTrue("stalwart-status.sh" in source)
        assertTrue("initialize-fresh" in source)
        assertTrue("up -d oauth2-mock dovecot postfix" in source)
        assertFalse("up -d --wait" in source)
        assertTrue("python3 \"\$dashboard_users_script\" verify" in source)
        assertTrue("DASHBOARD_STALWART_RUNTIME_STATE" in source)
        assertTrue("dashboard-server.pid" in source)
        assertTrue("\"\$dashboard_kotlin\" build --module dashboard-web" in source)
        assertTrue("DASHBOARD_WEB_ASSETS=" in source)
        assertTrue("DASHBOARD_WEB_RESOURCES=" in source)
        assertTrue("DASHBOARD_WEB_ENTRY=dashboard-web.mjs" in source)
        assertTrue("\"\$dashboard_kotlin\" run" in source)
        assertTrue("--module dashboard-server" in source)
        assertTrue("--working-dir=\"\$dashboard_repository_root\"" in source)
        assertFalse(Regex("\\b(?:gradle|npm|node|yarn|pnpm)\\b").containsMatchIn(source))
    }

    @Test
    fun freshStoreIsInitializedAndReclassifiedBeforeNormalStalwartUse() {
        LauncherFixture(dashboardRoot).use { fixture ->
            val result = fixture.run(
                firstState = "fresh",
                secondState = "current",
            )

            assertEquals(0, result.exitCode, result.output)
            val trace = result.trace
            assertInOrder(
                trace,
                "python|users_file.py bootstrap-defaults --defer-provider-verification " +
                    "--lifecycle dashboard-start-local",
                "python|stalwart_runtime_state.py classify --repository ${fixture.root}",
                "docker|compose -f ${fixture.root}/docker-compose.yml " +
                    "up -d oauth2-mock dovecot postfix",
                "python|users_file.py verify",
                "python|bootstrap_stalwart_v016.py initialize-fresh --repository ${fixture.root}",
                "python|stalwart_runtime_state.py classify --repository ${fixture.root}",
                "docker|compose -f ${fixture.root}/docker-compose.yml up -d stalwart",
                "curl|http://127.0.0.1:8443/healthz/ready",
                "kotlin|state=CURRENT|build --module dashboard-web",
                "kotlin|state=CURRENT|run --module dashboard-server " +
                    "--working-dir=${fixture.root}",
            )
            assertTrue(Files.isRegularFile(fixture.dashboardPidFile))
        }
    }

    @Test
    fun freshInitializationFailuresNeverStartOrProbeStalwartButStillLaunchKtor() {
        listOf(
            LauncherScenario(
                name = "initializer failure",
                firstState = "fresh",
                secondState = "current",
                failInitialization = true,
            ),
            LauncherScenario(
                name = "post-initialization receipt is not current",
                firstState = "fresh",
                secondState = "invalid",
            ),
        ).forEach { scenario ->
            LauncherFixture(dashboardRoot).use { fixture ->
                val result = fixture.run(
                    firstState = scenario.firstState,
                    secondState = scenario.secondState,
                    failInitialization = scenario.failInitialization,
                )

                assertEquals(0, result.exitCode, "${scenario.name}: ${result.output}")
                assertTrue(
                    result.trace.any {
                        it.startsWith("kotlin|state=INITIALIZATION_FAILED|run ")
                    },
                    scenario.name,
                )
                assertTrue(result.trace.none { it.endsWith("up -d stalwart") }, scenario.name)
                assertTrue(result.trace.none { it.startsWith("curl|") }, scenario.name)
            }
        }
    }

    @Test
    fun providersRemainIndependentAndMigrationRequiredIsActionable() {
        LauncherFixture(dashboardRoot).use { fixture ->
            val dovecotUnavailable = fixture.run(
                firstState = "current",
                failUsersVerify = true,
            )

            assertEquals(0, dovecotUnavailable.exitCode, dovecotUnavailable.output)
            assertTrue(dovecotUnavailable.trace.any { it.endsWith("up -d stalwart") })
            assertTrue(
                dovecotUnavailable.trace.any { it.startsWith("kotlin|state=CURRENT|run ") },
            )
        }

        LauncherFixture(dashboardRoot).use { fixture ->
            val stalwartUnavailable = fixture.run(
                firstState = "current",
                failStalwartStart = true,
            )

            assertEquals(0, stalwartUnavailable.exitCode, stalwartUnavailable.output)
            assertTrue(stalwartUnavailable.trace.any { it == "python|users_file.py verify" })
            assertTrue(
                stalwartUnavailable.trace.any { it.startsWith("kotlin|state=UNAVAILABLE|run ") },
            )
            assertTrue(stalwartUnavailable.trace.none { it.startsWith("curl|") })
        }

        LauncherFixture(dashboardRoot).use { fixture ->
            val upgradeRequired = fixture.run(firstState = "migration-required")

            assertEquals(0, upgradeRequired.exitCode, upgradeRequired.output)
            assertTrue("Stalwart upgrade required" in upgradeRequired.output)
            assertTrue("docs/stalwart-v016-migration.md" in upgradeRequired.output)
            assertTrue(
                "python3 scripts/capture_stalwart_v015.py capture --source-service stalwart" in
                    upgradeRequired.output,
            )
            assertTrue(upgradeRequired.trace.none { "initialize-fresh" in it })
            assertTrue(upgradeRequired.trace.none { it.endsWith("up -d stalwart") })
            assertTrue(upgradeRequired.trace.none { it.startsWith("curl|") })
            assertTrue(
                upgradeRequired.trace.any {
                    it.startsWith("kotlin|state=MIGRATION_REQUIRED|run ")
                },
            )
        }
    }

    @Test
    fun stalwartStatusIsReadOnlyAndReportsTheOperatorRunbook() {
        val status = dashboardRoot.resolve("stalwart-status.sh")
        assertTrue(status.isExecutable(), "stalwart-status.sh must be executable")
        val source = status.readText()
        assertTrue("stalwart_runtime_state.py" in source)
        assertTrue("docs/stalwart-v016-migration.md" in source)
        assertFalse("docker compose" in source)
        assertFalse("initialize-fresh" in source)
        assertFalse("capture_stalwart" in source)
    }

    @Test
    fun stopTerminatesOnlyTheRecordedDashboardPidAndNeverTouchesCompose() {
        val source = dashboardRoot.resolve("stop-local.sh").readText()
        assertFalse("docker" in source)
        assertTrue(Regex("\\bkill\\b").containsMatchIn(source))

        StopFixture(dashboardRoot).use { fixture ->
            val dashboardProcess = ProcessBuilder("sleep", "30").start()
            try {
                fixture.writePidFile(dashboardProcess.pid())

                val result = fixture.runStop()

                assertEquals(0, result.exitCode, result.output)
                assertTrue(dashboardProcess.waitFor(3, TimeUnit.SECONDS))
                assertFalse(Files.exists(fixture.pidFile))
                assertFalse("docker" in result.output)
            } finally {
                dashboardProcess.destroyForcibly()
            }
        }
    }

    @Test
    fun stopRejectsAStalePidFingerprintWithoutSignallingThatProcess() {
        StopFixture(dashboardRoot).use { fixture ->
            val unrelated = ProcessBuilder("sleep", "30").start()
            try {
                fixture.writePidFile(unrelated.pid(), startedOverride = "not-the-process-start")

                val result = fixture.runStop()

                assertTrue(result.exitCode != 0, result.output)
                assertTrue(unrelated.isAlive)
                assertTrue(Files.exists(fixture.pidFile))
            } finally {
                unrelated.destroyForcibly()
                unrelated.waitFor(3, TimeUnit.SECONDS)
            }
        }
    }

    private fun assertInOrder(trace: List<String>, vararg expected: String) {
        var position = -1
        expected.forEach { event ->
            val found = ((position + 1)..<trace.size).firstOrNull { index ->
                trace[index] == event
            } ?: -1
            assertTrue(
                found > position,
                "Expected '$event' after index $position, trace was:\n${trace.joinToString("\n")}",
            )
            position = found
        }
    }
}

private data class LauncherScenario(
    val name: String,
    val firstState: String,
    val secondState: String,
    val failInitialization: Boolean = false,
)

private data class ScriptResult(
    val exitCode: Int,
    val output: String,
    val trace: List<String>,
)

private class LauncherFixture(
    sourceDashboardRoot: Path,
) : AutoCloseable {
    val root: Path = createTempDirectory("dashboard-start-local-").toRealPath()
    private val dashboard = root.resolve("debug-dashboard")
    private val fakeBin = root.resolve("fake-bin")
    private val traceFile = root.resolve("trace.log")
    private val classifyCount = root.resolve("classify-count")
    val dashboardPidFile: Path = dashboard.resolve(".runtime/dashboard-server.pid")

    init {
        Files.createDirectories(dashboard)
        Files.createDirectories(fakeBin)
        Files.createDirectories(root.resolve("scripts"))
        Files.createDirectories(root.resolve("ssl"))
        Files.writeString(root.resolve("docker-compose.yml"), "services: {}\n")
        Files.writeString(root.resolve("ssl/tls.crt"), "test certificate\n")
        Files.writeString(root.resolve("ssl/tls.key"), "test key\n")
        listOf(
            "users_file.py",
            "stalwart_runtime_state.py",
            "bootstrap_stalwart_v016.py",
            "setup.py",
        ).forEach { name -> Files.writeString(root.resolve("scripts/$name"), "# fixture\n") }
        copyExecutable(sourceDashboardRoot.resolve("start-local.sh"), dashboard.resolve("start-local.sh"))
        copyExecutable(
            sourceDashboardRoot.resolve("stalwart-status.sh"),
            dashboard.resolve("stalwart-status.sh"),
        )
        writeExecutable(dashboard.resolve("kotlin"), FAKE_KOTLIN)
        writeExecutable(fakeBin.resolve("python3"), FAKE_PYTHON)
        writeExecutable(fakeBin.resolve("docker"), FAKE_DOCKER)
        writeExecutable(fakeBin.resolve("curl"), FAKE_CURL)
        writeExecutable(fakeBin.resolve("sleep"), "#!/bin/sh\nexit 0\n")
    }

    fun run(
        firstState: String,
        secondState: String = firstState,
        failInitialization: Boolean = false,
        failUsersVerify: Boolean = false,
        failStalwartStart: Boolean = false,
    ): ScriptResult {
        Files.deleteIfExists(traceFile)
        Files.deleteIfExists(classifyCount)
        Files.deleteIfExists(dashboardPidFile)
        val process = ProcessBuilder(dashboard.resolve("start-local.sh").toString())
            .redirectErrorStream(true)
            .apply {
                environment()["PATH"] = "$fakeBin:${environment()["PATH"].orEmpty()}"
                environment()["DASHBOARD_TEST_TRACE"] = traceFile.toString()
                environment()["DASHBOARD_TEST_CLASSIFY_COUNT"] = classifyCount.toString()
                environment()["DASHBOARD_TEST_FIRST_STATE"] = firstState
                environment()["DASHBOARD_TEST_SECOND_STATE"] = secondState
                environment()["DASHBOARD_TEST_FAIL_INITIALIZATION"] =
                    if (failInitialization) "1" else "0"
                environment()["DASHBOARD_TEST_FAIL_USERS_VERIFY"] =
                    if (failUsersVerify) "1" else "0"
                environment()["DASHBOARD_TEST_FAIL_STALWART_START"] =
                    if (failStalwartStart) "1" else "0"
            }
            .start()
        val output = process.inputStream.bufferedReader().use { it.readText() }
        check(process.waitFor(5, TimeUnit.SECONDS)) { "start-local.sh did not finish" }
        return ScriptResult(
            exitCode = process.exitValue(),
            output = output,
            trace = if (Files.exists(traceFile)) traceFile.readLines() else emptyList(),
        )
    }

    override fun close() {
        root.toFile().deleteRecursively()
    }

    private companion object {
        val FAKE_PYTHON = """
            |#!/bin/sh
            |set -u
            |script=${'$'}{1##*/}
            |shift
            |printf 'python|%s %s\n' "${'$'}script" "${'$'}*" >> "${'$'}DASHBOARD_TEST_TRACE"
            |case "${'$'}script ${'$'}*" in
            |  "stalwart_runtime_state.py classify "*)
            |    count=0
            |    if test -f "${'$'}DASHBOARD_TEST_CLASSIFY_COUNT"; then
            |      count=${'$'}(sed -n '1p' "${'$'}DASHBOARD_TEST_CLASSIFY_COUNT")
            |    fi
            |    count=${'$'}((count + 1))
            |    printf '%s\n' "${'$'}count" > "${'$'}DASHBOARD_TEST_CLASSIFY_COUNT"
            |    if test "${'$'}count" -eq 1; then
            |      printf '%s\n' "${'$'}DASHBOARD_TEST_FIRST_STATE"
            |    else
            |      printf '%s\n' "${'$'}DASHBOARD_TEST_SECOND_STATE"
            |    fi
            |    ;;
            |  "bootstrap_stalwart_v016.py initialize-fresh "*)
            |    test "${'$'}DASHBOARD_TEST_FAIL_INITIALIZATION" != 1
            |    ;;
            |  "users_file.py verify")
            |    test "${'$'}DASHBOARD_TEST_FAIL_USERS_VERIFY" != 1
            |    ;;
            |esac
        """.trimMargin()

        val FAKE_DOCKER = """
            |#!/bin/sh
            |set -u
            |printf 'docker|%s\n' "${'$'}*" >> "${'$'}DASHBOARD_TEST_TRACE"
            |case "${'$'}*" in
            |  *" up -d stalwart")
            |    test "${'$'}DASHBOARD_TEST_FAIL_STALWART_START" != 1
            |    ;;
            |esac
        """.trimMargin()

        val FAKE_CURL = """
            |#!/bin/sh
            |set -u
            |for argument in "${'$'}@"; do url=${'$'}argument; done
            |printf 'curl|%s\n' "${'$'}url" >> "${'$'}DASHBOARD_TEST_TRACE"
        """.trimMargin()

        val FAKE_KOTLIN = """
            |#!/bin/sh
            |set -u
            |printf 'kotlin|state=%s|%s\n' \
            |  "${'$'}{DASHBOARD_STALWART_RUNTIME_STATE-unset}" "${'$'}*" \
            |  >> "${'$'}DASHBOARD_TEST_TRACE"
        """.trimMargin()
    }
}

private class StopFixture(
    sourceDashboardRoot: Path,
) : AutoCloseable {
    private val root = createTempDirectory("dashboard-stop-local-").toRealPath()
    private val dashboard = root.resolve("debug-dashboard")
    private val stop = dashboard.resolve("stop-local.sh")
    val pidFile: Path = dashboard.resolve(".runtime/dashboard-server.pid")

    init {
        Files.createDirectories(pidFile.parent)
        copyExecutable(sourceDashboardRoot.resolve("stop-local.sh"), stop)
    }

    fun writePidFile(pid: Long, startedOverride: String? = null) {
        val started = startedOverride ?: processStart(pid)
        pidFile.writeText(
            "pid=$pid\n" +
                "started=$started\n" +
                "repository=$root\n",
        )
    }

    fun runStop(): ScriptResult {
        val process = ProcessBuilder(stop.toString()).redirectErrorStream(true).start()
        val output = process.inputStream.bufferedReader().use { it.readText() }
        check(process.waitFor(5, TimeUnit.SECONDS)) { "stop-local.sh did not finish" }
        return ScriptResult(process.exitValue(), output, emptyList())
    }

    override fun close() {
        root.toFile().deleteRecursively()
    }

    private fun processStart(pid: Long): String {
        val process = ProcessBuilder("ps", "-p", pid.toString(), "-o", "lstart=")
            .redirectErrorStream(true)
            .start()
        val output = process.inputStream.bufferedReader().use { it.readText() }.trim()
        check(process.waitFor(3, TimeUnit.SECONDS) && process.exitValue() == 0)
        return output
    }
}

private fun copyExecutable(source: Path, target: Path) {
    Files.copy(source, target)
    Files.setPosixFilePermissions(
        target,
        setOf(
            PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE,
            PosixFilePermission.OWNER_EXECUTE,
        ),
    )
}

private fun writeExecutable(path: Path, source: String) {
    Files.writeString(path, source + "\n")
    Files.setPosixFilePermissions(
        path,
        setOf(
            PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE,
            PosixFilePermission.OWNER_EXECUTE,
        ),
    )
}
