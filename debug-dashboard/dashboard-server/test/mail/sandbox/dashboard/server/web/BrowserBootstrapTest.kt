package mail.sandbox.dashboard.server.web

import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class BrowserBootstrapTest {
    @Test
    fun sealsBothAmbientGlobalsBeforeTheOnlyEntryImportAndFailsClosed() {
        val projectRoot = dashboardProjectRoot()
        val bootstrap = projectRoot.resolve("dashboard-server/resources/web/browser-bootstrap.js")
        val harness = projectRoot.resolve(
            "dashboard-server/testResources/web/browser-bootstrap-harness.mjs",
        )
        val cases = listOf(
            "safe-empty" to null,
            "configurable-preseeds" to null,
            "already-safe" to null,
            "unsafe-process" to null,
            "unsafe-deno" to null,
            "second-verification-failure" to null,
            "import-rejection" to null,
            "invalid-entry-quote-markup" to "/assets/gate\" onerror=\"evil.mjs",
            "invalid-entry-query" to "/assets/gate.mjs?debug=1",
            "invalid-entry-fragment" to "/assets/gate.mjs#debug",
            "invalid-entry-traversal" to "/assets/../gate.mjs",
            "invalid-entry-slash" to "/assets/nested/gate.mjs",
            "invalid-entry-backslash" to "/assets/gate\\evil.mjs",
            "invalid-entry-non-ascii" to "/assets/gáte.mjs",
            "invalid-entry-cross-origin" to "https://attacker.invalid/gate.mjs",
        )

        cases.forEach { (caseName, entryOverride) ->
            val command = mutableListOf(
                "node",
                "--experimental-vm-modules",
                harness.toString(),
                bootstrap.toString(),
                caseName,
            ).apply {
                if (entryOverride != null) add(entryOverride)
            }
            val process = ProcessBuilder(command).redirectErrorStream(true).start()
            val finished = process.waitFor(10, TimeUnit.SECONDS)
            if (!finished) {
                process.destroy()
                if (!process.waitFor(1, TimeUnit.SECONDS)) process.destroyForcibly()
            }
            assertTrue(finished, "$caseName timed out")
            val output = process.inputStream.bufferedReader().use { it.readText() }

            assertEquals(0, process.exitValue(), "$caseName failed:\n$output")
            assertTrue(output.contains("PASS $caseName"), "$caseName produced:\n$output")
        }
    }
}

private fun dashboardProjectRoot(): Path =
    Path.of(System.getProperty("user.dir")).toRealPath().let { workingDirectory ->
        if (workingDirectory.fileName.toString() == "dashboard-server") {
            workingDirectory.parent
        } else {
            workingDirectory
        }
    }
