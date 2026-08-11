package mail.sandbox.dashboard.server.gate.dovecot

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DovecotBaselineConfigAuditTest {
    private val repositoryRoot = repositoryRoot()
    private val compose = Files.readString(repositoryRoot.resolve("docker-compose.yml"))
    private val proofCompose = Files.readString(
        repositoryRoot.resolve(
            "debug-dashboard/dashboard-server/testResources/" +
                "dovecot-gate0c/compose.task5-proof.yml",
        ),
    )

    @Test
    fun dovecotImageIsPinnedToTheInspectedVersionAndDigest() {
        val dovecotImage = Regex("""(?m)^\s*image:\s*(dovecot/dovecot:\S+)\s*$""")
            .find(serviceLines("dovecot").joinToString("\n"))
            ?.groupValues
            ?.get(1)

        assertEquals(
            "dovecot/dovecot:2.4.4@" +
                "sha256:723e3392fe16c6fad8ddc605ea767cc01b4bad9cd9f13eb1dbac15e79c89b2d4",
            dovecotImage,
        )
    }

    @Test
    fun ordinaryMailPortsSupportLanDevicesAndKeepDashboardLoopbackAliases() {
        assertEquals(
            mapOf(
                "dovecot" to listOf(
                    "0.0.0.0:143:31143",
                    "0.0.0.0:993:31993",
                    "0.0.0.0:110:31110",
                    "0.0.0.0:995:31995",
                    "127.0.0.1:1143:31143",
                    "127.0.0.1:1993:31993",
                    "127.0.0.1:1110:31110",
                    "127.0.0.1:1995:31995",
                ),
                "postfix" to listOf(
                    "0.0.0.0:1025:25",
                    "0.0.0.0:465:465",
                    "0.0.0.0:587:587",
                    "127.0.0.1:1465:465",
                    "127.0.0.1:1587:587",
                ),
                "oauth2-mock" to listOf(
                    "0.0.0.0:8080:8080",
                ),
            ),
            listOf("dovecot", "postfix", "oauth2-mock").associateWith { service ->
                servicePublications(service)
            },
        )
    }

    @Test
    fun operatorHasNoPublicationAndForbiddenPortIsAbsentFromComposeSources() {
        assertTrue(
            servicePublicationsOrEmpty("dovecot-operator").isEmpty(),
            "The base operator must not publish a host port",
        )
        assertFalse(
            "2993" in compose,
            "The forbidden operator host port must not occur in base Compose",
        )
        assertFalse(
            "2993" in proofCompose,
            "The forbidden operator host port must not occur in proof Compose",
        )
    }

    @Test
    fun setupGeneratesTheExactLocalhostCertificateIdentity() {
        val setupSource = Files.readString(repositoryRoot.resolve("scripts/setup.py"))
        val argumentBlock = requireNotNull(
            Regex(
                """subprocess\.run\(\s*\[\s*([\s\S]*?)\s*],\s*check=True""",
            ).find(setupSource),
        ).groupValues[1]
        val arguments = argumentBlock
            .split(',')
            .map(String::trim)
            .filter(String::isNotEmpty)

        assertEquals(
            listOf(
                "\"openssl\"",
                "\"req\"",
                "\"-x509\"",
                "\"-nodes\"",
                "\"-days\"",
                "\"365\"",
                "\"-newkey\"",
                "\"rsa:2048\"",
                "\"-keyout\"",
                "str(key)",
                "\"-out\"",
                "str(cert)",
                "\"-subj\"",
                "\"/CN=localhost\"",
                "\"-addext\"",
                "\"subjectAltName=DNS:localhost\"",
            ),
            arguments,
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
    fun ordinaryConsumersUseTheSharedCanonicalUsersAuthority() {
        val authConfig = Files.readString(repositoryRoot.resolve("config/10-auth.conf"))
        val oauthSource = Files.readString(repositoryRoot.resolve("oauth2-mock/server.py"))
        val dovecotService = serviceLines("dovecot").joinToString("\n")
        val oauthService = serviceLines("oauth2-mock").joinToString("\n")

        assertTrue("- ./config:/etc/dovecot/conf.d:ro" in dovecotService)
        assertFalse(".runtime/dovecot" in dovecotService)
        assertTrue("- ./config:/etc/mail-sandbox-config:ro" in oauthService)
        assertFalse(".runtime/dovecot" in oauthService)
        assertEquals(
            2,
            Regex(
                """(?m)^\s*passwd_file_path\s*=\s*/etc/dovecot/conf\.d/users\s*$""",
            ).findAll(authConfig).count(),
        )
        assertFalse("/etc/dovecot/runtime/users" in authConfig)
        assertTrue(
            "ELIGIBILITY_FILE = Path(\"/etc/mail-sandbox-config/users\")" in oauthSource,
        )
        assertTrue("PLAIN_PREFIX = \"{PLAIN}\"" in oauthSource)
        assertFalse("ARGON2_HASH" in oauthSource)
        assertFalse("{ARGON2ID}" in oauthSource)
    }

    @Test
    fun deferredEligibilityHazardsAreAbsentAfterTheirOwningTasksRemoveThem() {
        val authConfig = Files.readString(repositoryRoot.resolve("config/10-auth.conf"))
        val postfixConfig = Files.readString(repositoryRoot.resolve("postfix/main.cf"))
        val recipientMapAssignments = postfixConfig.lineSequence()
            .filter { Regex("""^\s*local_recipient_maps\s*=""").containsMatchIn(it) }
            .toList()
        val unlistedRecipientAssignments = postfixConfig.lineSequence()
            .filter {
                Regex("""^\s*smtpd_reject_unlisted_recipient\s*=""")
                    .containsMatchIn(it)
            }
            .toList()

        assertEquals(
            listOf(
                "local_recipient_maps = socketmap:inet:oauth2-mock:10001:eligible",
            ),
            recipientMapAssignments,
        )
        assertEquals(
            listOf("smtpd_reject_unlisted_recipient = yes"),
            unlistedRecipientAssignments,
        )

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

        assertEquals(emptyMap(), observedHazards)
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

    private fun servicePublicationsOrEmpty(service: String): List<String> {
        val serviceLines = serviceLines(service)
        return if ("    ports:" in serviceLines) {
            servicePublications(service)
        } else {
            emptyList()
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
