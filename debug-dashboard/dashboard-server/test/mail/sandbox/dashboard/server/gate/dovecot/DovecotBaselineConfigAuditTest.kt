package mail.sandbox.dashboard.server.gate.dovecot

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class DovecotBaselineConfigAuditTest {
    private val repositoryRoot = repositoryRoot()
    private val compose = Files.readString(repositoryRoot.resolve("docker-compose.yml"))

    @Test
    fun dovecotImageIsPinnedToTheInspectedVersionAndDigest() {
        val dovecotImage = Regex("""(?m)^\s*image:\s*(dovecot/dovecot:\S+)\s*$""")
            .find(serviceLines("dovecot").joinToString("\n"))
            ?.groupValues
            ?.get(1)

        assertEquals(
            "dovecot/dovecot:2.4.1@" +
                "sha256:1296e0f1029cdd95e6849fb82f5d142a6e2a46218451773316cea678de75254b",
            dovecotImage,
        )
    }

    @Test
    fun dashboardRelevantPublicationsUseOnlyTheReviewedLoopbackMappings() {
        assertEquals(
            mapOf(
                "dovecot" to listOf(
                    "127.0.0.1:1143:31143",
                    "127.0.0.1:1993:31993",
                    "127.0.0.1:1110:31110",
                    "127.0.0.1:1995:31990",
                ),
                "postfix" to listOf(
                    "127.0.0.1:1025:25",
                    "127.0.0.1:1465:465",
                    "127.0.0.1:1587:587",
                ),
                "oauth2-mock" to listOf(
                    "127.0.0.1:8080:8080",
                ),
            ),
            listOf("dovecot", "postfix", "oauth2-mock").associateWith { service ->
                servicePublications(service)
            },
        )
    }

    @Test
    fun composeUsesProjectScopedContainerNames() {
        val fixedContainerNames = compose.lineSequence()
            .filter { line ->
                Regex("""^\s*container_name\s*:""").containsMatchIn(line)
            }
            .toList()

        assertTrue(
            fixedContainerNames.isEmpty(),
            "fixed container names break disposable Compose project isolation: " +
                fixedContainerNames.joinToString(),
        )
    }

    @Test
    fun remainingDeferredEligibilityHazardIsCharacterizedUntilItsOwningTaskRemovesIt() {
        val authConfig = Files.readString(repositoryRoot.resolve("config/10-auth.conf"))
        val postfixConfig = Files.readString(repositoryRoot.resolve("postfix/main.cf"))

        val observedHazards = buildMap {
            if (Regex("""(?m)^\s*userdb\s+static\s*\{""").containsMatchIn(authConfig)) {
                put("userdb static accepts non-existent targets", "Gate 0C Task 2")
            }
            if (
                Regex("""(?m)^local_recipient_maps\s*=\s*$""")
                    .containsMatchIn(postfixConfig) &&
                Regex("""(?m)^smtpd_reject_unlisted_recipient\s*=\s*no\s*$""")
                    .containsMatchIn(postfixConfig)
            ) {
                put(
                    "Postfix accepts arbitrary local recipients",
                    "Gate 0C Task 4",
                )
            }
        }

        // These are temporary characterization expectations, not desired
        // invariants. Task 4 must remove its entry as it remediates it.
        assertEquals(
            mapOf(
                "Postfix accepts arbitrary local recipients" to "Gate 0C Task 4",
            ),
            observedHazards,
        )
    }

    private fun servicePublications(service: String): List<String> {
        val serviceLines = serviceLines(service)
        val portsStart = serviceLines.indexOf("    ports:")
        require(portsStart >= 0) { "missing ports block for Compose service: $service" }
        val portsEnd = serviceLines.indices
            .drop(portsStart + 1)
            .firstOrNull { index ->
                Regex("""^    \S""").containsMatchIn(serviceLines[index])
            }
            ?: serviceLines.size

        return serviceLines.subList(portsStart + 1, portsEnd)
            .filterNot { line ->
                line.isBlank() || line.trimStart().startsWith("#")
            }
            .map { line ->
                Regex("""^\s{6}-\s+"([^"]+)"(?:\s+#.*)?$""")
                    .matchEntire(line)
                    ?.groupValues
                    ?.get(1)
                    ?: "<unreviewed-port-syntax:${line.trim()}>"
            }
    }

    private fun serviceLines(service: String): List<String> {
        val lines = compose.lines()
        val serviceStart = lines.indexOf("  $service:")
        require(serviceStart >= 0) { "missing Compose service: $service" }
        val serviceEnd = lines.indices
            .drop(serviceStart + 1)
            .firstOrNull { index ->
                Regex("""^  [A-Za-z0-9_-]+:\s*$""").matches(lines[index])
            }
            ?: lines.size
        return lines.subList(serviceStart + 1, serviceEnd)
    }

    private fun repositoryRoot(): Path {
        val workingDirectory = Path.of(System.getProperty("user.dir"))
            .toAbsolutePath()
            .normalize()
        val dashboardRoot = if (
            workingDirectory.fileName?.toString() == "dashboard-server"
        ) {
            workingDirectory.parent
        } else {
            workingDirectory
        }
        val root = requireNotNull(dashboardRoot.parent)
        require(Files.isRegularFile(root.resolve("docker-compose.yml"))) {
            "expected repository root above dashboard project: $root"
        }
        return root
    }
}
