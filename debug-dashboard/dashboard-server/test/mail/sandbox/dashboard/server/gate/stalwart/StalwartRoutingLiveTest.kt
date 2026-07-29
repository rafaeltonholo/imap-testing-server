package mail.sandbox.dashboard.server.gate.stalwart

import java.io.ByteArrayOutputStream
import java.io.PrintStream
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject

class StalwartRoutingLiveTest {
    @Test
    fun provesTheFixedMigrationRoutingWorkflow() = runBlocking {
        val environment = System.getenv()
        StalwartGateActionSelection.requireLive(environment)
        require(environment["STALWART_LIVE_TESTS"] == "1") {
            "STALWART_LIVE_TESTS=1 is required for the selected live gate"
        }
        require(
            environment["STALWART_BASE_URL"] ==
                StalwartEndpointProfile.MIGRATION_BOOTSTRAP.baseUrl.toString(),
        ) {
            "STALWART_BASE_URL must select the migration bootstrap endpoint"
        }
        val dashboardRoot = dashboardProjectRoot()
        val inputPath = dashboardRoot.resolve(
            ".runtime/stalwart/bootstrap-routing-input.json",
        )
        val paths = StalwartRoutingProofPaths.fixed(dashboardRoot)
        val inputText = Files.readString(inputPath, StandardCharsets.UTF_8)
        val invocationId = INVOCATION_PATTERN.find(inputText)
            ?.groupValues
            ?.get(1)
            ?: throw IllegalArgumentException(
                "Routing live input has no exact invocation ID",
            )
        val stdout = ByteArrayOutputStream()
        val stderr = ByteArrayOutputStream()
        val senderPassword = StalwartRoutingPassword.read(
            root = dashboardRoot,
            path = paths.senderPassword,
        ).use(StalwartRoutingPassword::copyValue)
        var recipientPassword = CharArray(0)

        try {
            recipientPassword = StalwartRoutingPassword.read(
                root = dashboardRoot,
                path = paths.recipientPassword,
            ).use(StalwartRoutingPassword::copyValue)
            val exitCode = StalwartRoutingProofCli(
                workflowFactory = StalwartRoutingProofWorkflowFactory {
                    StalwartRoutingLiveWorkflow()
                },
            ).execute(
                args = arrayOf(
                    "--dashboard-project-root",
                    dashboardRoot.toString(),
                    "--invocation-id",
                    invocationId,
                ),
                stdout = PrintStream(
                    stdout,
                    true,
                    StandardCharsets.UTF_8,
                ),
                stderr = PrintStream(
                    stderr,
                    true,
                    StandardCharsets.UTF_8,
                ),
            )

            assertEquals(
                0,
                exitCode,
                stderr.toString(StandardCharsets.UTF_8),
            )
            assertEquals("", stderr.toString(StandardCharsets.UTF_8))
            val output = stdout.toString(StandardCharsets.UTF_8)
            assertEquals(1, output.count { it == '\n' })
            val payload = Json.parseToJsonElement(output.trimEnd())
                .jsonObject
            assertEquals(
                "mail-sandbox.stalwart-v016-routing-verifier.v1",
                payload.getValue("schema").toString().trim('"'),
            )
            assertEquals(
                invocationId,
                payload.getValue("invocation_id").toString().trim('"'),
            )
            StalwartRoutingEvidenceSecretAudit.requireSecretFree(
                value = payload,
                forbiddenValues = listOf(
                    senderPassword,
                    recipientPassword,
                ),
            )
        } finally {
            senderPassword.fill('\u0000')
            recipientPassword.fill('\u0000')
        }
    }

    private fun dashboardProjectRoot(): Path {
        val working = Path.of(System.getProperty("user.dir"))
            .toAbsolutePath()
            .normalize()
        val candidate = if (
            working.fileName?.toString() == "dashboard-server"
        ) {
            requireNotNull(working.parent)
        } else {
            working
        }
        require(candidate.fileName?.toString() == "debug-dashboard") {
            "Routing live gate must run from the Kotlin project"
        }
        require(Files.isRegularFile(candidate.resolve("project.yaml"))) {
            "Routing live gate project root is incomplete"
        }
        return candidate.toRealPath()
    }

    private companion object {
        val INVOCATION_PATTERN =
            Regex("\"invocation_id\":\"([0-9a-f]{32})\"")
    }
}
