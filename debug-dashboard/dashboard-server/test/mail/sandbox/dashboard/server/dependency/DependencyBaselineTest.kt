package mail.sandbox.dashboard.server.dependency

import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFalse

class DependencyBaselineTest {
    @Test
    fun dashboardDependencyOwnershipMatchesTheApprovedBaseline() {
        val selected = mapOf(
            "toolchain" to "0.11.1",
            "kotlin" to "2.4.10",
            "compose" to "1.11.1",
            "material3" to "1.11.0-alpha07",
            "ktor" to "3.5.2",
            "serialization" to "1.11.0",
            "junit" to "6.1.2",
            "skiko" to "0.144.6",
            "logback" to "1.6.1",
            "selenium" to "4.46.0",
            "joda" to "3.2.0",
        )
        assertEquals(
            mapOf(
                "toolchain" to "0.11.1",
                "kotlin" to "2.4.10",
                "compose" to "1.11.1",
                "material3" to "1.11.0-alpha07",
                "ktor" to "3.5.2",
                "serialization" to "1.11.0",
                "junit" to "6.1.2",
                "skiko" to "0.144.6",
                "logback" to "1.6.1",
                "selenium" to "4.46.0",
                "joda" to "3.2.0",
            ),
            selected,
        )

        val root = repositoryRoot()
        val contract = Files.readString(root.resolve("debug-dashboard/dashboard-contract/module.yaml"))
        val server = Files.readString(root.resolve("debug-dashboard/dashboard-server/module.yaml"))
        val web = Files.readString(root.resolve("debug-dashboard/dashboard-web/module.yaml"))

        assertSnippet(
            contract,
            """
            settings:
              kotlin:
                version: 2.4.10
                serialization:
                  format: json
                  version: 1.11.0
              jvm:
                test:
                  junitPlatformVersion: 6.1.2
            """,
        )
        assertJUnitOwnership(contract, "test-dependencies@jvm")

        assertSnippet(
            server,
            """
            settings:
              kotlin:
                version: 2.4.10
                serialization:
                  format: json
                  version: 1.11.0
              ktor:
                enabled: true
                version: 3.5.2
              jvm:
                mainClass: mail.sandbox.dashboard.server.ApplicationKt
                test:
                  junitPlatformVersion: 6.1.2
            """,
        )
        assertSnippet(
            server,
            """
            dependencies:
              - ../dashboard-contract
              - ${'$'}ktor.server.core
              - ${'$'}ktor.server.netty
              - ${'$'}ktor.server.config.yaml
              - ${'$'}ktor.client.core
              - ${'$'}ktor.client.cio
              - ${'$'}kotlin.serialization.json
              - org.jetbrains.skiko:skiko-js-wasm-runtime:0.144.6
              - org.webjars.npm:js-joda__core:3.2.0
              - ch.qos.logback:logback-classic:1.6.1
            """,
        )
        assertSnippet(
            server,
            """
            test-dependencies:
              - ${'$'}ktor.server.testHost
              - org.seleniumhq.selenium:selenium-java:4.46.0
              - bom: org.junit:junit-bom:6.1.2
              - org.junit.jupiter:junit-jupiter-api
              - org.junit.jupiter:junit-jupiter-engine: runtime-only
              - org.junit.platform:junit-platform-launcher: runtime-only
            """,
        )
        assertSnippet(
            web,
            """
            settings:
              kotlin:
                version: 2.4.10
              compose:
                enabled: true
                version: 1.11.1
                resources:
                  packageName: mail.sandbox.dashboard.web.generated.resources
              ktor:
                enabled: true
                version: 3.5.2
            """,
        )
        assertSnippet(
            web,
            """
            dependencies:
              - ../dashboard-contract
              - ${'$'}compose.foundation
              - org.jetbrains.compose.material3:material3:1.11.0-alpha07
              - ${'$'}ktor.client.core
              - ${'$'}ktor.client.contentNegotiation
              - ${'$'}ktor.serialization.kotlinx.json
              - ${'$'}ktor.sse
            """,
        )

        assertFalse(contract.contains("\n  compose:"), "Only the web module may enable Compose")
        assertFalse(server.contains("\n  compose:"), "Only the web module may enable Compose")
        assertFalse(contract.contains("\n  ktor:"), "Only server and web may enable Ktor")
        assertFalse(web.contains("\n  serialization:"), "Only contract and server may configure serialization")
        assertFalse(web.contains("junit"), "The Wasm web module must not own JUnit")
        assertFalse(web.contains("- ${'$'}compose.material3"), "Web must not use the stale Material3 catalog alias")

        listOf(contract, server, web).forEach { module ->
            assertFalse(module.contains("2.3.21"), "Old Kotlin pin must not remain active")
            assertFalse(module.contains("1.10.3"), "Old Compose pin must not remain active")
            assertFalse(module.contains("3.4.3"), "Old Ktor pin must not remain active")
            assertFalse(module.contains("1.10.0"), "Old serialization pin must not remain active")
            assertFalse(module.contains("6.0.3"), "Old JUnit pin must not remain active")
            assertFalse(module.contains("0.9.37.4"), "Old Skiko pin must not remain active")
            assertFalse(module.contains("1.5.18"), "Old Logback pin must not remain active")
        }

        assertWrapper(
            root.resolve("debug-dashboard/kotlin"),
            "kotlin_cli_version=0.11.1",
            "6dbcdde0bcae41705c187aefb6c91c6c29ef9079c8072a473c2149151f8d7962",
        )
        assertWrapper(
            root.resolve("debug-dashboard/kotlin.bat"),
            "set kotlin_cli_version=0.11.1",
            "669ecc38f0ea46829a0f82d585243b6f2a08f0c9640d270d090372dd277dd47d",
        )
    }

    private fun assertJUnitOwnership(module: String, section: String) {
        assertSnippet(
            module,
            """
            $section:
              - bom: org.junit:junit-bom:6.1.2
              - org.junit.jupiter:junit-jupiter-api
              - org.junit.jupiter:junit-jupiter-engine: runtime-only
              - org.junit.platform:junit-platform-launcher: runtime-only
            """,
        )
    }

    private fun assertWrapper(path: Path, versionSyntax: String, expectedHash: String) {
        val wrapper = Files.readString(path)
        assertContains(wrapper, versionSyntax)
        assertContains(
            wrapper,
            "kotlin_cli_sha256=0ded2a434f6bf193b24e2a6d56c3ba443f4232721155a65aaa8372789412112f",
        )
        assertEquals(expectedHash, sha256(path), "Unexpected wrapper checksum for $path")
    }

    private fun assertSnippet(module: String, expected: String) {
        assertContains(module, expected.trimIndent())
    }

    private fun sha256(path: Path): String =
        MessageDigest.getInstance("SHA-256")
            .digest(Files.readAllBytes(path))
            .joinToString("") { byte -> "%02x".format(byte) }

    private fun repositoryRoot(): Path {
        val workingDirectory = Path.of(System.getProperty("user.dir"))
            .toAbsolutePath()
            .normalize()
        val dashboardRoot = when (workingDirectory.fileName?.toString()) {
            "dashboard-server" -> workingDirectory.parent
            "debug-dashboard" -> workingDirectory
            else -> error("Unexpected Kotlin test working directory")
        }
        return requireNotNull(dashboardRoot.parent).also { root ->
            require(Files.isRegularFile(root.resolve("docker-compose.yml"))) {
                "expected repository root above dashboard project: $root"
            }
        }
    }
}
