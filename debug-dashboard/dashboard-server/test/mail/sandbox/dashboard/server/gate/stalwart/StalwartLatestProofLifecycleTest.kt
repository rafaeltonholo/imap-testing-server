package mail.sandbox.dashboard.server.gate.stalwart

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.time.Duration
import java.util.concurrent.TimeUnit
import kotlin.io.path.createDirectories
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class StalwartLatestProofLifecycleTest {
    private val repositoryRoot = repositoryRoot()
    private val runner = repositoryRoot.resolve(
        "debug-dashboard/dashboard-server/testResources/" +
            "stalwart-gate0b/run-latest-proof.sh",
    )

    @Test
    fun runnerHasTheBoundedFailClosedStaticContract() {
        assertTrue(Files.isRegularFile(runner), "Latest proof runner is missing")
        assertTrue(Files.isExecutable(runner), "Latest proof runner is not executable")

        val syntax = runProcess(
            command = listOf("/bin/sh", "-n", runner.toString()),
            workingDirectory = repositoryRoot,
        )
        assertEquals(0, syntax.exitCode, syntax.output)

        val source = Files.readString(runner)
        assertTrue(source.startsWith("#!/bin/sh\nset -eu\n"))
        assertEquals(1, source.countOccurrences("trap cleanup_gate0b EXIT"))
        assertEquals(1, source.countOccurrences("trap 'exit 130' INT"))
        assertEquals(1, source.countOccurrences("trap 'exit 143' TERM"))
        assertEquals(1, source.countOccurrences(CLEANUP_CLASS))
        assertTrue("gate_incoming_status=\$?" in source)
        assertTrue("if test \"\$gate_incoming_status\" -ne 0; then" in source)
        assertTrue("exit \"\$gate_incoming_status\"" in source)
        assertTrue("exit \"\$gate_cleanup_status\"" in source)

        val exitTrap = source.indexOf("trap cleanup_gate0b EXIT")
        val interruptTrap = source.indexOf("trap 'exit 130' INT")
        val terminateTrap = source.indexOf("trap 'exit 143' TERM")
        val prepare = source.indexOf(PREPARE_CLASS)
        val firstComposeUp = source.indexOf("up -d --wait")
        assertTrue(exitTrap in 0 until prepare)
        assertTrue(interruptTrap in 0 until prepare)
        assertTrue(terminateTrap in 0 until prepare)
        assertTrue(exitTrap < firstComposeUp)
        assertTrue(interruptTrap < firstComposeUp)
        assertTrue(terminateTrap < firstComposeUp)

        assertEquals(1, source.countOccurrences(PROJECT_NAME))
        assertTrue("http://127.0.0.1:18443" in source)
        assertTrue("127.0.0.1:18587:8587" in source)
        assertTrue(".runtime/stalwart-gate0b" in source)
        listOf(
            "18443",
            "18587",
        ).forEach { allowedPort ->
            assertTrue(allowedPort in source, allowedPort)
        }
        listOf(
            "StalwartMigrationLiveTest",
            "StalwartRoutingLiveTest",
            "stalwart-data",
            "docker-compose.yml",
            "docker ps",
            "docker container ls",
            "docker network ls",
            "docker volume ls",
            "docker system",
            "prune",
            "down -v",
            "--volumes",
        ).forEach { forbidden ->
            assertFalse(forbidden in source, forbidden)
        }
        assertFalse(Regex("""(^|\s)(for|while)\s""", RegexOption.MULTILINE).containsMatchIn(source))
        assertFalse("mail-sandbox-stalwart-gate-" in source)

        expectedSelections.groupingBy { it }.eachCount().forEach { (selection, count) ->
            assertEquals(count, source.countOccurrences(selection), selection)
        }
        assertTrue(
            Regex(
                """gate_environment="\$\(docker compose[\s\S]*?/usr/bin/env\)""",
            ).containsMatchIn(source),
            "Docker environment output must be captured by a checked assignment",
        )
        val capture = source.indexOf("gate_environment=\"\$(docker compose")
        val environmentAudit = source.indexOf("rg -q '^STALWART_RECOVERY_'")
        assertTrue(capture >= 0)
        assertTrue(environmentAudit > capture)
    }

    @Test
    fun successfulBodyRunsEverySelectionAndCleansExactlyOnce() {
        val result = runMirror()

        assertEquals(0, result.exitCode, result.output)
        assertEquals(expectedInvocationTokens, result.kotlinTokens)
        assertEquals(1, result.cleanupCount)
        assertEquals(CLEANUP_TOKEN, result.kotlinTokens.last())
        assertTrue(result.dockerCommands.isNotEmpty())
        assertTrue(
            result.dockerCommands.all { command ->
                " compose -p $PROJECT_NAME " in " $command "
            },
        )
        assertTrue(result.dockerCommands.none { " -v " in " $it " })
        assertTrue(result.dockerCommands.none { " --volumes " in " $it " })
    }

    @Test
    fun preparationBootstrapAndEverySelectedLiveCommandFailClosed() {
        val failures = listOf(
            PREPARE_TOKEN,
            BOOTSTRAP_TOKEN,
        ) + liveInvocationTokens

        failures.forEach { failedToken ->
            val result = runMirror(
                failSelection = failedToken,
                failStatus = BODY_FAILURE,
            )

            assertEquals(BODY_FAILURE, result.exitCode, "$failedToken\n${result.output}")
            assertEquals(1, result.cleanupCount, failedToken)
            assertEquals(CLEANUP_TOKEN, result.kotlinTokens.last(), failedToken)
            assertEquals(1, result.kotlinTokens.count { it == failedToken }, failedToken)
            assertFalse(
                expectedInvocationTokens
                    .drop(expectedInvocationTokens.indexOf(failedToken) + 1)
                    .dropLast(1)
                    .any(result.kotlinTokens::contains),
                "Runner continued after $failedToken: ${result.kotlinTokens}",
            )
        }
    }

    @Test
    fun everyComposeUpAndBaseRestartFailureCleansExactlyOnce() {
        listOf(
            "compose.recovery.yml up -d --wait",
            "stop stalwart",
            "up -d --wait --force-recreate",
        ).forEach { failingCommand ->
            val result = runMirror(
                failDockerMatch = failingCommand,
                failStatus = DOCKER_FAILURE,
            )

            assertEquals(DOCKER_FAILURE, result.exitCode, "$failingCommand\n${result.output}")
            assertEquals(1, result.cleanupCount, failingCommand)
            assertEquals(CLEANUP_TOKEN, result.kotlinTokens.last(), failingCommand)
        }
    }

    @Test
    fun failedDockerEnvironmentCaptureCannotMasqueradeAsANegativeMatch() {
        val result = runMirror(
            failDockerMatch = "exec -T stalwart /usr/bin/env",
            failStatus = DOCKER_FAILURE,
        )

        assertEquals(DOCKER_FAILURE, result.exitCode, result.output)
        assertEquals(1, result.cleanupCount)
        assertFalse(RECOVERY_TOKEN in result.kotlinTokens)
        assertEquals(CLEANUP_TOKEN, result.kotlinTokens.last())
    }

    @Test
    fun cleanupFailureFailsASuccessfulBodyButCannotMaskItsFailure() {
        val successfulBody = runMirror(
            failCleanup = true,
            cleanupFailureStatus = CLEANUP_FAILURE,
        )
        assertEquals(CLEANUP_FAILURE, successfulBody.exitCode, successfulBody.output)
        assertEquals(1, successfulBody.cleanupCount)

        val failedBody = runMirror(
            failSelection = RAW_BLOB_TOKEN,
            failStatus = BODY_FAILURE,
            failCleanup = true,
            cleanupFailureStatus = CLEANUP_FAILURE,
        )
        assertEquals(BODY_FAILURE, failedBody.exitCode, failedBody.output)
        assertEquals(1, failedBody.cleanupCount)
    }

    @Test
    fun interruptAndTerminateExitThroughCleanupExactlyOnce() {
        listOf(
            "INT" to 130,
            "TERM" to 143,
        ).forEach { (signal, expectedStatus) ->
            val result = runMirror(
                signalSelection = RAW_BLOB_TOKEN,
                signal = signal,
            )

            assertEquals(expectedStatus, result.exitCode, "$signal\n${result.output}")
            assertEquals(1, result.cleanupCount, signal)
            assertEquals(CLEANUP_TOKEN, result.kotlinTokens.last(), signal)
            assertFalse(PERMISSION_TOKEN in result.kotlinTokens, signal)
        }
    }

    private fun runMirror(
        failSelection: String? = null,
        failDockerMatch: String? = null,
        failStatus: Int = BODY_FAILURE,
        failCleanup: Boolean = false,
        cleanupFailureStatus: Int = CLEANUP_FAILURE,
        signalSelection: String? = null,
        signal: String? = null,
    ): MirrorResult {
        val sandbox = createTempDirectory("stalwart-latest-proof-").toRealPath()
        try {
            val mirrorRunner = sandbox.resolve(
                "debug-dashboard/dashboard-server/testResources/" +
                    "stalwart-gate0b/run-latest-proof.sh",
            )
            mirrorRunner.parent.createDirectories()
            Files.copy(runner, mirrorRunner)
            makeExecutable(mirrorRunner)

            val fixtureDirectory = mirrorRunner.parent
            Files.copy(
                runner.parent.resolve("compose.yml"),
                fixtureDirectory.resolve("compose.yml"),
            )
            Files.copy(
                runner.parent.resolve("compose.recovery.yml"),
                fixtureDirectory.resolve("compose.recovery.yml"),
            )

            val dashboardRoot = sandbox.resolve("debug-dashboard")
            Files.writeString(dashboardRoot.resolve("project.yaml"), "product: jvm/app\n")
            val log = sandbox.resolve("lifecycle.log")
            val fakeKotlin = dashboardRoot.resolve("kotlin")
            Files.writeString(fakeKotlin, fakeKotlinScript())
            makeExecutable(fakeKotlin)

            val fakeBin = sandbox.resolve("fake-bin")
            fakeBin.createDirectories()
            val fakeDocker = fakeBin.resolve("docker")
            Files.writeString(fakeDocker, fakeDockerScript())
            makeExecutable(fakeDocker)

            val builder = ProcessBuilder(mirrorRunner.toString())
                .directory(sandbox.toFile())
                .redirectErrorStream(true)
            val environment = builder.environment()
            environment.keys
                .filter { key ->
                    key.startsWith("STALWART_") || key.startsWith("FAKE_")
                }
                .toList()
                .forEach(environment::remove)
            environment["PATH"] = "$fakeBin:${requireNotNull(System.getenv("PATH"))}"
            environment["FAKE_LOG"] = log.toString()
            failSelection?.let { environment["FAKE_FAIL_SELECTION"] = it }
            failDockerMatch?.let { environment["FAKE_FAIL_DOCKER_MATCH"] = it }
            environment["FAKE_FAIL_STATUS"] = failStatus.toString()
            if (failCleanup) {
                environment["FAKE_FAIL_CLEANUP"] = "1"
            }
            environment["FAKE_CLEANUP_FAILURE_STATUS"] = cleanupFailureStatus.toString()
            signalSelection?.let { environment["FAKE_SIGNAL_SELECTION"] = it }
            signal?.let { environment["FAKE_SIGNAL"] = it }

            val process = builder.start()
            val completed = process.waitFor(PROCESS_TIMEOUT.seconds, TimeUnit.SECONDS)
            if (!completed) {
                process.destroyForcibly()
                throw AssertionError("Mirrored Stalwart runner exceeded its timeout")
            }
            val output = process.inputStream.bufferedReader().use { it.readText() }
            val entries = if (Files.exists(log)) Files.readAllLines(log) else emptyList()
            val kotlinTokens = entries
                .filter { it.startsWith("kotlin|") }
                .map { it.removePrefix("kotlin|") }
            val dockerCommands = entries
                .filter { it.startsWith("docker|") }
                .map { it.removePrefix("docker|") }
            return MirrorResult(
                exitCode = process.exitValue(),
                output = output,
                kotlinTokens = kotlinTokens,
                dockerCommands = dockerCommands,
            )
        } finally {
            Files.walk(sandbox).use { paths ->
                paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
            }
        }
    }

    private fun fakeKotlinScript(): String =
        """
        #!/bin/sh
        set -eu
        selected=''
        previous=''
        for argument in "${'$'}@"; do
          if test "${'$'}previous" = '--include-classes'; then
            selected="${'$'}argument"
          fi
          previous="${'$'}argument"
        done
        test -n "${'$'}selected"
        class_name="${'$'}{selected##*.}"
        phase="${'$'}{STALWART_GATE_RESTART_PHASE:-none}"
        token="${'$'}class_name:${'$'}phase"
        printf 'kotlin|%s\n' "${'$'}token" >> "${'$'}FAKE_LOG"

        if test "${'$'}class_name" = 'StalwartGateCleanupLiveTest'; then
          if test "${'$'}{FAKE_FAIL_CLEANUP:-0}" = '1'; then
            exit "${'$'}FAKE_CLEANUP_FAILURE_STATUS"
          fi
          exit 0
        fi
        if test "${'$'}{FAKE_SIGNAL_SELECTION:-}" = "${'$'}token"; then
          kill -s "${'$'}FAKE_SIGNAL" "${'$'}PPID"
        fi
        if test "${'$'}{FAKE_FAIL_SELECTION:-}" = "${'$'}token"; then
          exit "${'$'}FAKE_FAIL_STATUS"
        fi
        exit 0
        """.trimIndent() + "\n"

    private fun fakeDockerScript(): String =
        """
        #!/bin/sh
        set -eu
        printf 'docker|%s\n' "${'$'}*" >> "${'$'}FAKE_LOG"
        case " ${'$'}* " in
          *"${'$'}{FAKE_FAIL_DOCKER_MATCH:-__never_match__}"*)
            exit "${'$'}FAKE_FAIL_STATUS"
            ;;
        esac
        case " ${'$'}* " in
          *' exec -T stalwart /usr/bin/env '*)
            printf '%s\n' 'STALWART_PUBLIC_URL=http://127.0.0.1:18443'
            ;;
        esac
        exit 0
        """.trimIndent() + "\n"

    private fun makeExecutable(path: Path) {
        Files.setPosixFilePermissions(
            path,
            PosixFilePermissions.fromString("rwxr-xr-x"),
        )
    }

    private fun repositoryRoot(): Path {
        var current = Path.of(System.getProperty("user.dir")).toAbsolutePath().normalize()
        while (current.parent != null) {
            if (
                Files.isRegularFile(current.resolve("AGENTS.md")) &&
                Files.isDirectory(current.resolve("debug-dashboard"))
            ) {
                return current.toRealPath()
            }
            current = current.parent
        }
        throw IllegalStateException("Repository root was not found")
    }

    private fun runProcess(
        command: List<String>,
        workingDirectory: Path,
    ): ProcessResult {
        val process = ProcessBuilder(command)
            .directory(workingDirectory.toFile())
            .redirectErrorStream(true)
            .start()
        val completed = process.waitFor(PROCESS_TIMEOUT.seconds, TimeUnit.SECONDS)
        if (!completed) {
            process.destroyForcibly()
            throw AssertionError("Process exceeded its timeout")
        }
        return ProcessResult(
            exitCode = process.exitValue(),
            output = process.inputStream.bufferedReader().use { it.readText() },
        )
    }

    private fun String.countOccurrences(needle: String): Int =
        windowed(needle.length).count { it == needle }

    private data class ProcessResult(
        val exitCode: Int,
        val output: String,
    )

    private data class MirrorResult(
        val exitCode: Int,
        val output: String,
        val kotlinTokens: List<String>,
        val dockerCommands: List<String>,
    ) {
        val cleanupCount: Int
            get() = kotlinTokens.count { it == CLEANUP_TOKEN }
    }

    private companion object {
        val PROCESS_TIMEOUT: Duration = Duration.ofSeconds(20)
        const val PROJECT_NAME = "mail-sandbox-stalwart-gate"
        const val BODY_FAILURE = 41
        const val DOCKER_FAILURE = 52
        const val CLEANUP_FAILURE = 79
        const val PREPARE_CLASS = "StalwartFixturePrepareLiveTest"
        const val BOOTSTRAP_CLASS = "StalwartBootstrapLiveTest"
        const val CLEANUP_CLASS = "StalwartGateCleanupLiveTest"
        const val RECOVERY_CLASS = "StalwartRecoveryRetirementLiveTest"
        const val RAW_BLOB_CLASS = "StalwartRawBlobCompatibilityLiveTest"
        const val PERMISSION_CLASS = "StalwartPermissionMatrixLiveTest"
        const val APP_PASSWORD_CLASS = "StalwartAppPasswordSemanticsLiveTest"
        const val MAIL_ACCESS_CLASS = "StalwartMailAccessLifecycleLiveTest"
        const val RESTART_PREPARE_CLASS = "StalwartMailAccessRestartPrepareLiveTest"
        const val RESTART_RECONCILE_CLASS = "StalwartMailAccessRestartReconcileLiveTest"
        const val MAIL_MUTATION_CLASS = "StalwartMailMutationLiveTest"
        const val REGISTRY_ROUTING_CLASS = "StalwartRegistryRoutingDeletionLiveTest"

        const val PREPARE_TOKEN = "$PREPARE_CLASS:none"
        const val BOOTSTRAP_TOKEN = "$BOOTSTRAP_CLASS:none"
        const val CLEANUP_TOKEN = "$CLEANUP_CLASS:none"
        const val RECOVERY_TOKEN = "$RECOVERY_CLASS:none"
        const val RAW_BLOB_TOKEN = "$RAW_BLOB_CLASS:none"
        const val PERMISSION_TOKEN = "$PERMISSION_CLASS:none"

        val expectedSelections = listOf(
            PREPARE_CLASS,
            BOOTSTRAP_CLASS,
            CLEANUP_CLASS,
            RECOVERY_CLASS,
            RAW_BLOB_CLASS,
            PERMISSION_CLASS,
            APP_PASSWORD_CLASS,
            MAIL_ACCESS_CLASS,
            RESTART_PREPARE_CLASS,
            RESTART_PREPARE_CLASS,
            RESTART_PREPARE_CLASS,
            RESTART_RECONCILE_CLASS,
            RESTART_RECONCILE_CLASS,
            RESTART_RECONCILE_CLASS,
            MAIL_MUTATION_CLASS,
            REGISTRY_ROUTING_CLASS,
        )

        val liveInvocationTokens = listOf(
            RECOVERY_TOKEN,
            RAW_BLOB_TOKEN,
            PERMISSION_TOKEN,
            "$APP_PASSWORD_CLASS:none",
            "$MAIL_ACCESS_CLASS:none",
            "$RESTART_PREPARE_CLASS:staged",
            "$RESTART_RECONCILE_CLASS:staged",
            "$RESTART_PREPARE_CLASS:retiring",
            "$RESTART_RECONCILE_CLASS:retiring",
            "$RESTART_PREPARE_CLASS:removal-pending",
            "$RESTART_RECONCILE_CLASS:removal-pending",
            "$MAIL_MUTATION_CLASS:none",
            "$REGISTRY_ROUTING_CLASS:none",
        )

        val expectedInvocationTokens =
            listOf(PREPARE_TOKEN, BOOTSTRAP_TOKEN) +
                liveInvocationTokens +
                CLEANUP_TOKEN
    }
}
