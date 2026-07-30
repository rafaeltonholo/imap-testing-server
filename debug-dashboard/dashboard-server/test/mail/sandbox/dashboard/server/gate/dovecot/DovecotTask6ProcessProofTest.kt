package mail.sandbox.dashboard.server.gate.dovecot

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.nio.file.Path
import java.time.Duration
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DovecotTask6ProcessProofTest {
    @Test
    fun fixedProcessRunnerAcceptsOutputAtTheConfiguredMemoryLimit() {
        val stdout = ByteArray(8) { 'x'.code.toByte() }
        val process = Task6ControlledProcess(
            stdout = stdout,
            initiallyExited = true,
        )
        val runner = fixedProcessRunner(process)

        val result = runner.run(
            processRequest(maximumOutputBytes = stdout.size),
        )

        assertFalse(result.timedOut)
        assertEquals(0, result.exitCode)
        assertEquals(stdout.toList(), result.stdout.toList())
        assertTrue(result.stderr.isEmpty())
    }

    @Test
    fun fixedProcessRunnerKillsAndReapsOnOutputOverflow() {
        val process = Task6ControlledProcess(
            stdout = ByteArray(9) { 'x'.code.toByte() },
        )
        val runner = fixedProcessRunner(process)

        assertFailsWith<IllegalStateException> {
            runner.run(processRequest(maximumOutputBytes = 8))
        }

        assertTrue(process.destroyed)
        assertTrue(process.reaped)
        assertFalse(process.isAlive)
    }

    @Test
    fun fixedProcessRunnerKillsAndReapsOnTimeout() {
        val process = Task6ControlledProcess(
            stdout = ByteArray(0),
            timeoutBeforeDestroy = true,
        )
        val runner = fixedProcessRunner(process)

        val result = runner.run(
            processRequest(
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
        var started = false
        val runner = Task6FixedProcessRunner(
            dockerRouting = DovecotDockerRouting.localDefault(),
            isApprovedCommand = { it == FIXED_TEST_COMMAND },
            processFactory = {
                started = true
                Task6ControlledProcess(ByteArray(0))
            },
        )

        assertFailsWith<IllegalArgumentException> {
            runner.run(
                processRequest(
                    stdin = ByteArray(1_025),
                    maximumOutputBytes = 8,
                ),
            )
        }

        assertFalse(started)
    }

    @Test
    fun fixedProcessRunnerReapsBeforeRestoringCallerInterruption() {
        val waitEntered = CountDownLatch(1)
        val process = Task6ControlledProcess(
            stdout = ByteArray(0),
            waitEntered = waitEntered,
        )
        val runner = fixedProcessRunner(process)
        val failure = AtomicReference<Throwable?>()
        val interruptRestored = AtomicBoolean()
        val caller = Thread(
            {
                try {
                    runner.run(
                        processRequest(
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
        process: Task6ControlledProcess,
    ): Task6FixedProcessRunner =
        Task6FixedProcessRunner(
            dockerRouting = DovecotDockerRouting.localDefault(),
            isApprovedCommand = { it == FIXED_TEST_COMMAND },
            processFactory = { process },
        )

    private fun processRequest(
        stdin: ByteArray = ByteArray(0),
        timeout: Duration = Duration.ofSeconds(1),
        maximumOutputBytes: Int,
    ): EligibilityProcessRequest =
        EligibilityProcessRequest(
            argv = FIXED_TEST_COMMAND,
            workingDirectory = repositoryRoot(),
            stdin = stdin,
            timeout = timeout,
            maximumOutputBytes = maximumOutputBytes,
        )

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
        private val timeoutBeforeDestroy: Boolean = false,
        private val waitEntered: CountDownLatch? = null,
        initiallyExited: Boolean = false,
    ) : Process() {
        private val termination =
            CountDownLatch(if (initiallyExited) 0 else 1)
        private val stdin = ByteArrayOutputStream()
        private val stdoutStream = ByteArrayInputStream(stdout)
        private val stderrStream = ByteArrayInputStream(ByteArray(0))

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
            waitEntered?.countDown()
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

    companion object {
        private val FIXED_TEST_COMMAND = listOf("task6-fixed-test")
    }
}
