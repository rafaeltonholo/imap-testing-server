package mail.sandbox.dashboard.server.gate.dovecot

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.nio.file.Files
import java.nio.file.Path
import java.time.Duration
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertSame
import kotlin.test.assertTrue

class DovecotTask6ProcessProofTest {
    @Test
    fun execTransportLiveProofIsDormantWithoutExplicitFixedSelection() {
        assertFalse(dovecotTask6ExecLiveProofSelected(emptyMap()))
        assertTrue(
            dovecotTask6ExecLiveProofSelected(
                mapOf(
                    "DOVECOT_LIVE_TESTS" to "1",
                    "DOVECOT_LIVE_PROFILE" to "task5-proof",
                ),
            ),
        )
        assertFailsWith<IllegalArgumentException> {
            dovecotTask6ExecLiveProofSelected(
                mapOf("DOVECOT_LIVE_TESTS" to "1"),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            dovecotTask6ExecLiveProofSelected(
                mapOf(
                    "DOVECOT_LIVE_TESTS" to "0",
                    "DOVECOT_LIVE_PROFILE" to "task5-proof",
                ),
            )
        }
    }

    @Test
    fun fixedProcessRunnerUsesOnlyTheExactLaunchProfileBoundary() {
        val profile = launchProfile()
        val hostileEnvironment = linkedMapOf(
            "PATH" to "/hostile",
            "COMPOSE_FILE" to "/tmp/hostile.yml",
            "COMPOSE_PROJECT_NAME" to "hostile",
            "DOCKER_CONTEXT" to "remote",
            "DOCKER_HOST" to "tcp://attacker.invalid:2375",
            "DOVECOT_TARGET" to "victim@local.test",
        )
        val capturedBuilder = AtomicReference<ProcessBuilder>()
        val process = Task6ControlledProcess(
            stdout = ByteArray(0),
            initiallyExited = true,
        )
        val runner = Task6FixedProcessRunner(
            profile = profile,
            isApprovedCommand = { it == fixedTestCommand(profile) },
            inheritedEnvironment = { hostileEnvironment },
            builderLauncher = { builder ->
                capturedBuilder.set(builder)
                process
            },
        )

        val result = runner.run(
            processRequest(
                profile = profile,
                maximumOutputBytes = 8,
            ),
        )

        assertFalse(result.timedOut)
        assertEquals(0, result.exitCode)
        val builder = capturedBuilder.get()
        assertEquals(fixedTestCommand(profile), builder.command())
        assertEquals(profile.repositoryRoot.toFile(), builder.directory())
        assertEquals(
            profile.sanitizedEnvironment(hostileEnvironment),
            builder.environment(),
        )
        assertEquals(
            setOf("COMPOSE_DISABLE_ENV_FILE", "DOCKER_HOST"),
            builder.environment().keys,
        )
    }

    @Test
    fun fixedProcessRunnerRejectsAmbientDockerAndForeignWorkingDirectory() {
        val profile = launchProfile()
        var starts = 0
        val runner = Task6FixedProcessRunner(
            profile = profile,
            isApprovedCommand = { true },
            builderLauncher = {
                starts += 1
                Task6ControlledProcess(
                    stdout = ByteArray(0),
                    initiallyExited = true,
                )
            },
        )

        assertFailsWith<IllegalArgumentException> {
            runner.run(
                processRequest(
                    profile = profile,
                    argv = listOf("docker", "version"),
                    maximumOutputBytes = 8,
                ),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            runner.run(
                processRequest(
                    profile = profile,
                    workingDirectory =
                        profile.repositoryRoot.resolve("debug-dashboard"),
                    maximumOutputBytes = 8,
                ),
            )
        }

        assertEquals(0, starts)
    }

    @Test
    fun launchProfileEligibilityAdapterRunsOnlyCanonicalHashAndVerifyCommands() {
        val profile = launchProfile()
        val captured = mutableListOf<EligibilityProcessRequest>()
        val capturedInput = mutableListOf<ByteArray>()
        val validHash =
            "{ARGON2ID}\$argon2id\$v=19\$m=65536,t=3,p=1" +
                "\$c2FsdA\$ZGlnZXN0"
        val results = ArrayDeque(
            listOf(
                EligibilityProcessResult(
                    exitCode = 0,
                    timedOut = false,
                    stdout = "$validHash\n".toByteArray(),
                    stderr = ByteArray(0),
                ),
                EligibilityProcessResult(
                    exitCode = 0,
                    timedOut = false,
                    stdout =
                        "$validHash (verified)\n".toByteArray(),
                    stderr = ByteArray(0),
                ),
            ),
        )
        val adapter = Task6LaunchProfileEligibilityAdapter(
            profile = profile,
            processRunner = EligibilityProcessRunner { request ->
                captured += request
                capturedInput += request.stdin.copyOf()
                results.removeFirst()
            },
        )
        val passwordBytes = "hash-input".toByteArray()
        val secretBytes = "verify-input".toByteArray()

        val renderedHash =
            EligibilityPassword.takeOwnership(passwordBytes).use {
                adapter.hash(it)
            }
        val verified =
            DovecotOperatorSecret.takeOwnership(secretBytes).use {
                adapter.verify(it, validHash)
            }

        assertEquals(validHash, renderedHash)
        assertTrue(verified)
        assertTrue(results.isEmpty())
        assertEquals(2, captured.size)
        assertEquals(
            fixedComposeExecPrefix(profile) +
                listOf("doveadm", "pw", "-s", "ARGON2ID"),
            captured[0].argv,
        )
        assertEquals(
            fixedComposeExecPrefix(profile) +
                listOf("doveadm", "pw", "-t", validHash),
            captured[1].argv,
        )
        assertEquals(
            "hash-input\nhash-input\n",
            capturedInput[0].toString(Charsets.US_ASCII),
        )
        assertEquals(
            "verify-input\n",
            capturedInput[1].toString(Charsets.US_ASCII),
        )
        assertTrue(passwordBytes.all { it == 0.toByte() })
        assertTrue(secretBytes.all { it == 0.toByte() })
        assertTrue(captured.all { request ->
            request.stdin.all { it == 0.toByte() }
        })
        captured.forEach { request ->
            assertEquals(profile.repositoryRoot, request.workingDirectory)
            assertEquals(Duration.ofSeconds(30), request.timeout)
            assertEquals(16 * 1024, request.maximumOutputBytes)
            assertEquals(
                profile.dockerCli.toString(),
                request.argv.first(),
            )
            assertFalse(
                request.argv.any { token ->
                    token == "sh" ||
                        token == "bash" ||
                        token == "docker"
                },
            )
        }
    }

    @Test
    fun launchProfileEligibilityAdapterRejectsInvalidOrUnexpectedResultsWithoutLeaking() {
        val profile = launchProfile()
        val sensitiveMarker =
            "request-password and target@local.test from docker stderr"
        var executions = 0
        val adapter = Task6LaunchProfileEligibilityAdapter(
            profile = profile,
            processRunner = EligibilityProcessRunner {
                executions += 1
                EligibilityProcessResult(
                    exitCode = 7,
                    timedOut = false,
                    stdout = ByteArray(0),
                    stderr = sensitiveMarker.toByteArray(),
                )
            },
        )
        val passwordFailure = assertFailsWith<IllegalStateException> {
            EligibilityPassword.takeOwnership(
                "hash-input".toByteArray(),
            ).use(adapter::hash)
        }
        assertEquals(
            "Task 6 eligibility password hashing failed",
            passwordFailure.message,
        )
        assertFalse(passwordFailure.toString().contains(sensitiveMarker))
        assertEquals(1, executions)

        assertFailsWith<IllegalArgumentException> {
            DovecotOperatorSecret.takeOwnership(
                "verify-input".toByteArray(),
            ).use { secret ->
                adapter.verify(secret, "request-password")
            }
        }
        assertEquals(1, executions)
        assertEquals(
            "Task6LaunchProfileEligibilityAdapter(fixed, redacted)",
            adapter.toString(),
        )
    }

    @Test
    fun processProofChecksEveryFiniteHeldAndSaturationBoundaryExactly() {
        val counts = ArrayDeque(
            listOf(
                0, 0,
                0, 0,
                0, 0,
                0, 0,
                0, 0,
                0, 0,
                0, 1, 0,
                0, 16, 16, 0,
            ),
        )
        val observedCounts = CopyOnWriteArrayList<Int>()
        val inventory = DovecotTask6ProcessInventory {
            counts.removeFirst().also(observedCounts::add)
        }
        val events = mutableListOf<String>()
        val scenarios = object : DovecotTask6ProcessScenarios {
            override fun runFinite(
                case: DovecotTask6FiniteProcessCase,
            ) {
                events += "finite:${case.name}"
            }

            override fun withHeldProcess(
                assertExactlyOne: () -> Unit,
            ) {
                events += "held:opened"
                assertExactlyOne()
                events += "held:closed"
            }

            override fun withSaturatedProcesses(
                assertExactlySixteen: () -> Unit,
                assertNoSeventeenthStarted: () -> Unit,
            ) {
                events += "saturation:opened"
                assertExactlySixteen()
                events += "saturation:seventeenth-rejected"
                assertNoSeventeenthStarted()
                events += "saturation:drained"
            }
        }

        DovecotTask6ProcessProof(inventory).run(scenarios)

        assertTrue(counts.isEmpty())
        assertEquals(
            listOf(
                "finite:NormalClose",
                "finite:AuthenticationFailure",
                "finite:RegistrationFailure",
                "finite:Timeout",
                "finite:Interruption",
                "finite:Abort",
                "held:opened",
                "held:closed",
                "saturation:opened",
                "saturation:seventeenth-rejected",
                "saturation:drained",
            ),
            events,
        )
        assertEquals(
            listOf(
                0, 0,
                0, 0,
                0, 0,
                0, 0,
                0, 0,
                0, 0,
                0, 1, 0,
                0, 16, 16, 0,
            ),
            observedCounts,
        )
    }

    @Test
    fun processProofStillChecksZeroAfterAFailedScenario() {
        val primary = IllegalStateException("scenario failed")
        val counts = ArrayDeque(listOf(0, 0))
        val scenarios = object : DovecotTask6ProcessScenarios {
            override fun runFinite(
                case: DovecotTask6FiniteProcessCase,
            ) {
                assertEquals(
                    DovecotTask6FiniteProcessCase.NormalClose,
                    case,
                )
                throw primary
            }

            override fun withHeldProcess(
                assertExactlyOne: () -> Unit,
            ) = error("Held proof must not run after a finite failure")

            override fun withSaturatedProcesses(
                assertExactlySixteen: () -> Unit,
                assertNoSeventeenthStarted: () -> Unit,
            ) = error("Saturation proof must not run after a finite failure")
        }

        val failure = assertFailsWith<IllegalStateException> {
            DovecotTask6ProcessProof {
                counts.removeFirst()
            }.run(scenarios)
        }

        assertSame(primary, failure)
        assertTrue(counts.isEmpty())
    }

    @Test
    fun processProofRejectsWrongHeldCountWithAFixedRedactedFailure() {
        val sensitiveMarker = "process-secret-target@local.test"
        val counts = ArrayDeque(
            listOf(
                0, 0,
                0, 0,
                0, 0,
                0, 0,
                0, 0,
                0, 0,
                0, 2, 0,
            ),
        )
        val scenarios = object : DovecotTask6ProcessScenarios {
            override fun runFinite(
                case: DovecotTask6FiniteProcessCase,
            ) = Unit

            override fun withHeldProcess(
                assertExactlyOne: () -> Unit,
            ) {
                assertExactlyOne()
            }

            override fun withSaturatedProcesses(
                assertExactlySixteen: () -> Unit,
                assertNoSeventeenthStarted: () -> Unit,
            ) = error(sensitiveMarker)
        }

        val failure = assertFailsWith<IllegalStateException> {
            DovecotTask6ProcessProof {
                counts.removeFirst()
            }.run(scenarios)
        }

        assertEquals(
            "Dovecot Task 6 operator process inventory was not exact",
            failure.message,
        )
        assertFalse(failure.toString().contains(sensitiveMarker))
        assertTrue(counts.isEmpty())
    }

    @Test
    fun seventeenthRejectionRejectsATransientTransportStart() {
        val starts = Task6OperatorTransportStartCounter(
            DovecotOperatorTransportFactory {
                throw IllegalStateException(
                    "Transient process started and cleaned up",
                )
            },
        )

        val failure = assertFailsWith<IllegalStateException> {
            requireTask6SeventeenthRejectedWithoutTransportStart(
                startCount = starts::snapshot,
                attempt = {
                    starts.open {}
                },
            )
        }

        assertEquals(
            "The seventeenth operator process started transport",
            failure.message,
        )
        assertEquals(1, starts.snapshot())
    }

    @Test
    fun fixedProcessRunnerAcceptsOutputAtTheConfiguredMemoryLimit() {
        val profile = launchProfile()
        val stdout = ByteArray(8) { 'x'.code.toByte() }
        val stderr = "err".toByteArray()
        val process = Task6ControlledProcess(
            stdout = stdout,
            stderr = stderr,
            initiallyExited = true,
        )
        val runner = fixedProcessRunner(profile, process)

        val result = runner.run(
            processRequest(
                profile = profile,
                maximumOutputBytes = stdout.size,
            ),
        )

        assertFalse(result.timedOut)
        assertEquals(0, result.exitCode)
        assertEquals(stdout.toList(), result.stdout.toList())
        assertEquals(stderr.toList(), result.stderr.toList())
    }

    @Test
    fun fixedProcessRunnerWipesSnapshotsBeforeCleanupFailureEscapes() {
        val profile = launchProfile()
        val capturedSnapshots =
            AtomicReference<Pair<ByteArray, ByteArray>>()
        val stdout = "captured-stdout".toByteArray()
        val stderr = "captured-stderr".toByteArray()
        val process = Task6ControlledProcess(
            stdout = stdout,
            stderr = stderr,
            initiallyExited = true,
            failCleanupReapAfterSuccessfulWait = true,
        )
        val runner = Task6FixedProcessRunner(
            profile = profile,
            isApprovedCommand = {
                it == fixedTestCommand(profile)
            },
            builderLauncher = { process },
            observeSnapshots = { capturedStdout, capturedStderr ->
                capturedSnapshots.set(
                    capturedStdout to capturedStderr,
                )
            },
        )

        val failure = assertFailsWith<IllegalStateException> {
            runner.run(
                processRequest(
                    profile = profile,
                    maximumOutputBytes = 32,
                ),
            )
        }

        assertEquals(
            "Task 6 fixed process cleanup failed",
            failure.message,
        )
        val snapshots = checkNotNull(capturedSnapshots.get())
        assertEquals(stdout.size, snapshots.first.size)
        assertEquals(stderr.size, snapshots.second.size)
        assertTrue(
            snapshots.first.all { it == 0.toByte() },
        )
        assertTrue(
            snapshots.second.all { it == 0.toByte() },
        )
    }

    @Test
    fun fixedProcessRunnerKillsAndReapsOnOutputOverflow() {
        val profile = launchProfile()
        val process = Task6ControlledProcess(
            stdout = ByteArray(9) { 'x'.code.toByte() },
        )
        val runner = fixedProcessRunner(profile, process)

        assertFailsWith<IllegalStateException> {
            runner.run(
                processRequest(
                    profile = profile,
                    maximumOutputBytes = 8,
                ),
            )
        }

        assertTrue(process.destroyed)
        assertTrue(process.reaped)
        assertFalse(process.isAlive)
    }

    @Test
    fun fixedProcessRunnerKillsAndReapsOnTimeout() {
        val profile = launchProfile()
        val process = Task6ControlledProcess(
            stdout = ByteArray(0),
            timeoutBeforeDestroy = true,
        )
        val runner = fixedProcessRunner(profile, process)

        val result = runner.run(
            processRequest(
                profile = profile,
                timeout = Duration.ofMillis(25),
                maximumOutputBytes = 8,
            ),
        )

        assertTrue(result.timedOut)
        assertEquals(null, result.exitCode)
        assertTrue(process.destroyed)
        assertTrue(process.reaped)
        assertFalse(process.isAlive)
    }

    @Test
    fun fixedProcessRunnerRejectsOversizedInputBeforeStarting() {
        val profile = launchProfile()
        var started = false
        val runner = Task6FixedProcessRunner(
            profile = profile,
            isApprovedCommand = { it == fixedTestCommand(profile) },
            builderLauncher = {
                started = true
                Task6ControlledProcess(ByteArray(0))
            },
        )

        assertFailsWith<IllegalArgumentException> {
            runner.run(
                processRequest(
                    profile = profile,
                    stdin = ByteArray(1_025),
                    maximumOutputBytes = 8,
                ),
            )
        }

        assertFalse(started)
    }

    @Test
    fun fixedProcessRunnerReapsBeforeRestoringCallerInterruption() {
        val profile = launchProfile()
        val waitEntered = CountDownLatch(1)
        val process = Task6ControlledProcess(
            stdout = ByteArray(0),
            waitEntered = waitEntered,
        )
        val runner = fixedProcessRunner(profile, process)
        val failure = AtomicReference<Throwable?>()
        val interruptRestored = AtomicBoolean()
        val caller = Thread(
            {
                try {
                    runner.run(
                        processRequest(
                            profile = profile,
                            timeout = Duration.ofSeconds(5),
                            maximumOutputBytes = 8,
                        ),
                    )
                } catch (caught: Throwable) {
                    failure.set(caught)
                    interruptRestored.set(
                        Thread.currentThread().isInterrupted,
                    )
                }
            },
            "task6-interrupted-runner-test",
        ).also { it.isDaemon = true }

        caller.start()
        assertTrue(waitEntered.await(1, TimeUnit.SECONDS))
        caller.interrupt()
        caller.join(3_000)

        assertFalse(caller.isAlive)
        assertTrue(failure.get() is IllegalStateException)
        assertTrue(interruptRestored.get())
        assertTrue(process.destroyed)
        assertTrue(process.reaped)
        assertFalse(process.isAlive)
        assertFalse(
            Thread.getAllStackTraces().keys.any { thread ->
                thread.isAlive &&
                    thread.name == "task6-fixed-process-io"
            },
        )
    }

    private fun fixedProcessRunner(
        profile: DovecotOperatorLaunchProfile,
        process: Task6ControlledProcess,
    ): Task6FixedProcessRunner =
        Task6FixedProcessRunner(
            profile = profile,
            isApprovedCommand = { it == fixedTestCommand(profile) },
            builderLauncher = { process },
        )

    private fun processRequest(
        profile: DovecotOperatorLaunchProfile,
        argv: List<String> = fixedTestCommand(profile),
        workingDirectory: Path = profile.repositoryRoot,
        stdin: ByteArray = ByteArray(0),
        timeout: Duration = Duration.ofSeconds(1),
        maximumOutputBytes: Int,
    ): EligibilityProcessRequest =
        EligibilityProcessRequest(
            argv = argv,
            workingDirectory = workingDirectory,
            stdin = stdin,
            timeout = timeout,
            maximumOutputBytes = maximumOutputBytes,
        )

    private fun launchProfile(): DovecotOperatorLaunchProfile {
        val root = repositoryRoot()
        val dockerCli = listOf(
            Path.of("/usr/bin/true"),
            Path.of("/bin/true"),
        ).firstNotNullOfOrNull { candidate ->
            runCatching { candidate.toRealPath() }
                .getOrNull()
                ?.takeIf(Files::isExecutable)
        } ?: error("No fixed executable is available for the runner test")
        return DovecotOperatorLaunchProfile(
            dockerCli = dockerCli,
            repositoryRoot = root,
            composeFiles = listOf(root.resolve("docker-compose.yml")),
            projectName = "task6-runner-test",
        )
    }

    private fun fixedTestCommand(
        profile: DovecotOperatorLaunchProfile,
    ): List<String> = listOf(
        profile.dockerCli.toString(),
        "version",
    )

    private fun fixedComposeExecPrefix(
        profile: DovecotOperatorLaunchProfile,
    ): List<String> =
        buildList {
            add(profile.dockerCli.toString())
            add("compose")
            add("--project-directory")
            add(profile.repositoryRoot.toString())
            profile.composeFiles.forEach { composeFile ->
                add("-f")
                add(composeFile.toString())
            }
            add("--project-name")
            add(profile.projectName)
            add("--profile")
            add(profile.composeProfile)
            add("exec")
            add("-T")
            add("--index")
            add("1")
            add("dovecot")
        }

    private fun repositoryRoot(): Path {
        val workingDirectory = Path.of(System.getProperty("user.dir"))
            .toAbsolutePath()
            .normalize()
        val dashboardRoot = when (workingDirectory.fileName?.toString()) {
            "dashboard-server" -> workingDirectory.parent
            "debug-dashboard" -> workingDirectory
            else -> error("unexpected Kotlin test working directory")
        }
        return requireNotNull(dashboardRoot.parent)
    }

    private class Task6ControlledProcess(
        stdout: ByteArray,
        stderr: ByteArray = ByteArray(0),
        private val timeoutBeforeDestroy: Boolean = false,
        private val waitEntered: CountDownLatch? = null,
        initiallyExited: Boolean = false,
        private val failCleanupReapAfterSuccessfulWait:
            Boolean = false,
    ) : Process() {
        private val termination =
            CountDownLatch(if (initiallyExited) 0 else 1)
        private val stdin = ByteArrayOutputStream()
        private val stdoutStream = ByteArrayInputStream(stdout)
        private val stderrStream = ByteArrayInputStream(stderr)
        private var timedWaitCalls = 0

        @Volatile
        private var alive = !initiallyExited

        @Volatile
        var destroyed = false
            private set

        @Volatile
        var reaped = false
            private set

        override fun getOutputStream(): OutputStream = stdin

        override fun getInputStream(): InputStream = stdoutStream

        override fun getErrorStream(): InputStream = stderrStream

        override fun waitFor(): Int {
            termination.await()
            reaped = true
            return exitValue()
        }

        override fun waitFor(
            timeout: Long,
            unit: TimeUnit,
        ): Boolean {
            timedWaitCalls += 1
            waitEntered?.countDown()
            if (
                failCleanupReapAfterSuccessfulWait &&
                timedWaitCalls > 1
            ) {
                return false
            }
            if (timeoutBeforeDestroy && alive) return false
            val completed = termination.await(timeout, unit)
            if (completed) reaped = true
            return completed
        }

        override fun exitValue(): Int {
            if (alive) throw IllegalThreadStateException()
            return if (destroyed) 137 else 0
        }

        override fun destroy() {
            destroyForcibly()
        }

        override fun destroyForcibly(): Process {
            destroyed = true
            alive = false
            termination.countDown()
            return this
        }

        override fun isAlive(): Boolean = alive
    }

}
