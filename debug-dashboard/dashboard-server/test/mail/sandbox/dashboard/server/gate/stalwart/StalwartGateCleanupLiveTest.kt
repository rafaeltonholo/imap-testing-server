package mail.sandbox.dashboard.server.gate.stalwart

import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertFalse

class StalwartGateCleanupLiveTest {
    @Test
    fun deletesOnlyTheRealGateRuntime() {
        StalwartGateActionSelection.requireCleanup(System.getenv())
        val projectRoot = dashboardProjectRoot()
        val plan = StalwartGateCleanup.plan(
            projectRoot = projectRoot,
            requestedProjectName = "mail-sandbox-stalwart-gate",
            requestedRuntimeDirectory = projectRoot.resolve(".runtime/stalwart-gate0b"),
        )

        StalwartGateCleanup.cleanup(plan, StalwartBoundedCommandRunner::run)

        assertFalse(Files.exists(plan.runtimeDirectory))
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
}

internal interface StalwartCommandProcess {
    fun waitFor(timeoutSeconds: Long): Boolean

    fun destroyForcibly()

    fun exitValue(): Int
}

internal object StalwartBoundedCommandRunner {
    private const val COMMAND_TIMEOUT_SECONDS = 30L
    private const val TERMINATION_TIMEOUT_SECONDS = 5L

    fun run(
        command: List<String>,
        processStarter: (List<String>) -> StalwartCommandProcess = ::start,
    ): Int {
        val process = safely {
            processStarter(command)
        }
        val completed = safely {
            process.waitFor(COMMAND_TIMEOUT_SECONDS)
        }
        if (!completed) {
            safely {
                process.destroyForcibly()
                process.waitFor(TERMINATION_TIMEOUT_SECONDS)
            }
            throw IllegalStateException("Gate cleanup command exceeded its bounded timeout")
        }
        return safely(process::exitValue)
    }

    private fun start(command: List<String>): StalwartCommandProcess {
        val process = ProcessBuilder(command)
            .redirectOutput(ProcessBuilder.Redirect.DISCARD)
            .redirectError(ProcessBuilder.Redirect.DISCARD)
            .start()
        return object : StalwartCommandProcess {
            override fun waitFor(timeoutSeconds: Long): Boolean =
                process.waitFor(timeoutSeconds, TimeUnit.SECONDS)

            override fun destroyForcibly() {
                process.destroyForcibly()
            }

            override fun exitValue(): Int = process.exitValue()
        }
    }

    private inline fun <T> safely(block: () -> T): T =
        try {
            block()
        } catch (_: Exception) {
            throw IllegalStateException("Gate cleanup command failed safely")
        }
}
