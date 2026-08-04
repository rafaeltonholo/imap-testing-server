package mail.sandbox.dashboard.server.dependency

import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class DependencyBaselineTest {
    private val selected = mapOf(
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

    private val prohibitedVersions = setOf(
        "2.3.21",
        "1.10.3",
        "3.4.3",
        "1.10.0",
        "6.0.3",
        "0.9.37.4",
        "1.5.18",
    )

    @Test
    fun moduleSettingsAndDependencyOwnershipMatchApprovedBaseline() {
        val modules = moduleYamls()
        val contract = modules.getValue("dashboard-contract")
        val server = modules.getValue("dashboard-server")
        val web = modules.getValue("dashboard-web")

        assertSnippet(
            contract,
            """
            settings:
              kotlin:
                version: ${selected.getValue("kotlin")}
                serialization:
                  format: json
                  version: ${selected.getValue("serialization")}
              jvm:
                test:
                  junitPlatformVersion: ${selected.getValue("junit")}
            """,
        )
        assertJUnitOwnership(contract, "test-dependencies@jvm")

        assertSnippet(
            server,
            """
            settings:
              kotlin:
                version: ${selected.getValue("kotlin")}
                serialization:
                  format: json
                  version: ${selected.getValue("serialization")}
              ktor:
                enabled: true
                version: ${selected.getValue("ktor")}
              jvm:
                mainClass: mail.sandbox.dashboard.server.ApplicationKt
                test:
                  junitPlatformVersion: ${selected.getValue("junit")}
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
              - org.jetbrains.skiko:skiko-js-wasm-runtime:${selected.getValue("skiko")}
              - org.webjars.npm:js-joda__core:${selected.getValue("joda")}
              - ch.qos.logback:logback-classic:${selected.getValue("logback")}
            """,
        )
        assertSnippet(
            server,
            """
            test-dependencies:
              - ${'$'}ktor.server.testHost
              - org.seleniumhq.selenium:selenium-java:${selected.getValue("selenium")}
              - bom: org.junit:junit-bom:${selected.getValue("junit")}
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
                version: ${selected.getValue("kotlin")}
              compose:
                enabled: true
                version: ${selected.getValue("compose")}
                resources:
                  packageName: mail.sandbox.dashboard.web.generated.resources
              ktor:
                enabled: true
                version: ${selected.getValue("ktor")}
            """,
        )
        assertSnippet(
            web,
            """
            dependencies:
              - ../dashboard-contract
              - ${'$'}compose.foundation
              - org.jetbrains.compose.material3:material3:${selected.getValue("material3")}
              - ${'$'}ktor.client.core
              - ${'$'}ktor.client.contentNegotiation
              - ${'$'}ktor.serialization.kotlinx.json
              - ${'$'}ktor.sse
            """,
        )

        assertNoActiveKey(contract, "compose")
        assertNoActiveKey(server, "compose")
        assertNoActiveKey(contract, "ktor")
        assertNoActiveKey(web, "serialization")
        assertNoActiveJUnitOwnership(web)
    }

    @Test
    fun prohibitedActiveDeclarationsAreAbsent() {
        val modules = moduleYamls().values
        val versionFindings = modules.flatMap { module ->
            scanActiveYamlValues(module.content).flatMap { declaration ->
                declaration.versionTokens()
                    .filter { version -> version in prohibitedVersions }
                    .map { version ->
                        "${module.name} (${module.path}):${declaration.lineNumber}: " +
                            "prohibited version $version in '${declaration.value}'"
                    }
            }
        }
        val aliasFindings = modules.flatMap { module ->
            staleMaterial3Aliases(scanActiveYamlValues(module.content)).map { declaration ->
                "${module.name} (${module.path}):${declaration.lineNumber}: " +
                    "prohibited dependency '${declaration.value}'"
            }
        }

        assertEquals(emptyList(), versionFindings, "Prohibited active YAML versions were found")
        assertEquals(emptyList(), aliasFindings, "The stale Material3 alias is still active")
    }

    @Test
    fun wrapperIntegrityMatchesApprovedBaseline() {
        val root = repositoryRoot()
        val distributionSha256 = "0ded2a434f6bf193b24e2a6d56c3ba443f4232721155a65aaa8372789412112f"
        val wrappers = listOf(
            WrapperExpectation(
                path = root.resolve("debug-dashboard/kotlin"),
                versionSyntax = "kotlin_cli_version=${selected.getValue("toolchain")}",
                distributionSyntax = "kotlin_cli_sha256=$distributionSha256",
                fileSha256 = "6dbcdde0bcae41705c187aefb6c91c6c29ef9079c8072a473c2149151f8d7962",
            ),
            WrapperExpectation(
                path = root.resolve("debug-dashboard/kotlin.bat"),
                versionSyntax = "set kotlin_cli_version=${selected.getValue("toolchain")}",
                distributionSyntax = "set kotlin_cli_sha256=$distributionSha256",
                fileSha256 = "669ecc38f0ea46829a0f82d585243b6f2a08f0c9640d270d090372dd277dd47d",
            ),
        )

        wrappers.forEach { expectation ->
            val wrapper = Files.readString(expectation.path)
            assertTrue(
                expectation.versionSyntax in wrapper,
                "${expectation.path} does not select ${selected.getValue("toolchain")}",
            )
            assertTrue(
                expectation.distributionSyntax in wrapper,
                "${expectation.path} does not pin the approved distribution checksum",
            )
            assertEquals(
                expectation.fileSha256,
                sha256(expectation.path),
                "Unexpected wrapper checksum for ${expectation.path}",
            )
        }
    }

    @Test
    fun activeYamlScannerIgnoresCommentsOutsideQuotes() {
        val yaml =
            """
            # version: 2.3.21
            version: 2.4.10 # previous 2.3.21
            note: "hash # stays"
            """.trimIndent()

        val values = scanActiveYamlValues(yaml)

        assertEquals(
            listOf(
                ActiveYamlValue(lineNumber = 2, key = "version", value = "2.4.10", isListItem = false),
                ActiveYamlValue(
                    lineNumber = 3,
                    key = "note",
                    value = "\"hash # stays\"",
                    isListItem = false,
                ),
            ),
            values,
        )
        assertEquals(emptyList(), prohibitedVersionDeclarations(values))
    }

    @Test
    fun activeYamlScannerRecognizesQuotedMaterial3Aliases() {
        val yaml =
            """
            dependencies:
              - '${'$'}compose.material3'
              - "${'$'}compose.material3"
              - ${'$'}compose.material3 # stale alias
              - '${'$'}compose.material3 # literal suffix'
            """.trimIndent()

        assertEquals(
            listOf(2, 3, 4),
            staleMaterial3Aliases(scanActiveYamlValues(yaml)).map { declaration ->
                declaration.lineNumber
            },
        )
    }

    @Test
    fun activeYamlScannerKeepsQualifiedVersionTokensDistinct() {
        val yaml =
            """
            qualified: 1.10.0-alpha05
            newer: org.example:thing:1.10.0.1
            current: 1.11.0
            old: 1.10.0
            """.trimIndent()
        val values = scanActiveYamlValues(yaml)

        assertEquals(
            listOf("1.10.0-alpha05", "1.10.0.1", "1.11.0", "1.10.0"),
            values.flatMap { declaration -> declaration.versionTokens() },
        )
        assertEquals(
            listOf(ActiveVersion(lineNumber = 4, version = "1.10.0")),
            prohibitedVersionDeclarations(values),
        )
    }

    @Test
    fun activeYamlScannerRetainsQuotedKeysAndIgnoresCommentedOwnershipWords() {
        val yaml =
            """
            "compose":
            'ktor': enabled
            # "serialization": enabled
            note: harmless # junit
            """.trimIndent()
        val declarations = scanActiveYamlValues(yaml)

        assertEquals(
            listOf(
                ActiveYamlValue(lineNumber = 1, key = "compose", value = "", isListItem = false),
                ActiveYamlValue(lineNumber = 2, key = "ktor", value = "enabled", isListItem = false),
                ActiveYamlValue(lineNumber = 4, key = "note", value = "harmless", isListItem = false),
            ),
            declarations,
        )
        assertEquals(listOf(1), activeKeyDeclarations(declarations, "compose").map { it.lineNumber })
        assertEquals(listOf(2), activeKeyDeclarations(declarations, "ktor").map { it.lineNumber })
        assertEquals(emptyList(), junitOwnershipDeclarations(declarations))
    }

    @Test
    fun activeYamlScannerPreservesEmbeddedPlainScalarHashes() {
        val values = scanActiveYamlValues("source: artifact#2.3.21")

        assertEquals(
            listOf(
                ActiveYamlValue(
                    lineNumber = 1,
                    key = "source",
                    value = "artifact#2.3.21",
                    isListItem = false,
                ),
            ),
            values,
        )
        assertEquals(
            listOf(ActiveVersion(lineNumber = 1, version = "2.3.21")),
            prohibitedVersionDeclarations(values),
        )
    }

    private fun assertJUnitOwnership(module: ModuleYaml, section: String) {
        assertSnippet(
            module,
            """
            $section:
              - bom: org.junit:junit-bom:${selected.getValue("junit")}
              - org.junit.jupiter:junit-jupiter-api
              - org.junit.jupiter:junit-jupiter-engine: runtime-only
              - org.junit.platform:junit-platform-launcher: runtime-only
            """,
        )
    }

    private fun assertSnippet(module: ModuleYaml, expected: String) {
        val snippet = expected.trimIndent()
        assertTrue(
            snippet in module.content,
            "${module.name} (${module.path}) is missing the exact semantic snippet:\n$snippet",
        )
    }

    private fun assertNoActiveKey(module: ModuleYaml, prohibitedKey: String) {
        val findings = activeKeyDeclarations(scanActiveYamlValues(module.content), prohibitedKey)
            .map { declaration ->
                "${module.name} (${module.path}):${declaration.lineNumber}: active key '$prohibitedKey'"
            }
        assertEquals(emptyList(), findings, "Prohibited active YAML key was found")
    }

    private fun assertNoActiveJUnitOwnership(module: ModuleYaml) {
        val findings = junitOwnershipDeclarations(scanActiveYamlValues(module.content)).map { declaration ->
            "${module.name} (${module.path}):${declaration.lineNumber}: " +
                "active JUnit declaration '${declaration.key ?: declaration.value}'"
        }
        assertEquals(emptyList(), findings, "The Wasm web module must not own JUnit")
    }

    private fun moduleYamls(): Map<String, ModuleYaml> {
        val root = repositoryRoot()
        return listOf(
            moduleYaml(root, "dashboard-contract"),
            moduleYaml(root, "dashboard-server"),
            moduleYaml(root, "dashboard-web"),
        ).associateBy { module -> module.name }
    }

    private fun moduleYaml(root: Path, name: String): ModuleYaml {
        val path = root.resolve("debug-dashboard/$name/module.yaml")
        return ModuleYaml(name = name, path = path, content = Files.readString(path))
    }

    private fun scanActiveYamlValues(source: String): List<ActiveYamlValue> =
        source.lineSequence().mapIndexedNotNull { index, rawLine ->
            val activeLine = stripYamlComment(rawLine).trim()
            if (activeLine.isEmpty()) return@mapIndexedNotNull null

            val isListItem = activeLine.startsWith("- ")
            val key: String?
            val value: String
            if (isListItem) {
                key = null
                value = activeLine.removePrefix("- ").trim()
            } else {
                val separator = firstUnquotedIndex(activeLine, ':')
                if (separator < 0) return@mapIndexedNotNull null
                key = activeLine.substring(0, separator).trim().unquotedYamlScalar()
                value = activeLine.substring(separator + 1).trim()
            }
            if (isListItem && value.isEmpty()) return@mapIndexedNotNull null

            ActiveYamlValue(
                lineNumber = index + 1,
                value = value,
                isListItem = isListItem,
                key = key,
            )
        }.toList()

    private fun stripYamlComment(line: String): String {
        val comment = firstYamlCommentIndex(line)
        return if (comment < 0) line else line.substring(0, comment)
    }

    private fun firstYamlCommentIndex(value: String): Int {
        var inSingleQuotes = false
        var inDoubleQuotes = false
        var index = 0
        while (index < value.length) {
            val character = value[index]
            when {
                character == '\'' && !inDoubleQuotes -> {
                    if (inSingleQuotes && value.getOrNull(index + 1) == '\'') {
                        index += 2
                        continue
                    }
                    inSingleQuotes = !inSingleQuotes
                }
                character == '"' && !inSingleQuotes && !value.isEscaped(index) -> {
                    inDoubleQuotes = !inDoubleQuotes
                }
                character == '#' &&
                    !inSingleQuotes &&
                    !inDoubleQuotes &&
                    (index == 0 || value[index - 1].isWhitespace()) -> return index
            }
            index++
        }
        return -1
    }

    private fun firstUnquotedIndex(value: String, target: Char): Int {
        var inSingleQuotes = false
        var inDoubleQuotes = false
        var index = 0
        while (index < value.length) {
            val character = value[index]
            when {
                character == '\'' && !inDoubleQuotes -> {
                    if (inSingleQuotes && value.getOrNull(index + 1) == '\'') {
                        index += 2
                        continue
                    }
                    inSingleQuotes = !inSingleQuotes
                }
                character == '"' && !inSingleQuotes && !value.isEscaped(index) -> {
                    inDoubleQuotes = !inDoubleQuotes
                }
                character == target && !inSingleQuotes && !inDoubleQuotes -> return index
            }
            index++
        }
        return -1
    }

    private fun String.isEscaped(index: Int): Boolean {
        var backslashes = 0
        var cursor = index - 1
        while (cursor >= 0 && this[cursor] == '\\') {
            backslashes++
            cursor--
        }
        return backslashes % 2 == 1
    }

    private fun ActiveYamlValue.versionTokens(): List<String> =
        VERSION_TOKEN.findAll(value).map { match -> match.value }.toList()

    private fun prohibitedVersionDeclarations(values: List<ActiveYamlValue>): List<ActiveVersion> =
        values.flatMap { declaration ->
            declaration.versionTokens()
                .filter { version -> version in prohibitedVersions }
                .map { version -> ActiveVersion(declaration.lineNumber, version) }
        }

    private fun staleMaterial3Aliases(values: List<ActiveYamlValue>): List<ActiveYamlValue> =
        values.filter { declaration ->
            declaration.isListItem && declaration.value.unquotedYamlScalar() == "${'$'}compose.material3"
        }

    private fun activeKeyDeclarations(
        values: List<ActiveYamlValue>,
        key: String,
    ): List<ActiveYamlValue> = values.filter { declaration -> declaration.key == key }

    private fun junitOwnershipDeclarations(values: List<ActiveYamlValue>): List<ActiveYamlValue> =
        values.filter { declaration ->
            declaration.key?.contains("junit", ignoreCase = true) == true ||
                declaration.isListItem &&
                declaration.value.unquotedYamlScalar().contains("junit", ignoreCase = true)
        }

    private fun String.unquotedYamlScalar(): String {
        val scalar = trim()
        return when {
            scalar.length >= 2 && scalar.first() == '\'' && scalar.last() == '\'' ->
                scalar.substring(1, scalar.lastIndex).replace("''", "'")
            scalar.length >= 2 && scalar.first() == '"' && scalar.last() == '"' ->
                scalar.substring(1, scalar.lastIndex)
            else -> scalar
        }
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

    private data class ModuleYaml(
        val name: String,
        val path: Path,
        val content: String,
    )

    private data class WrapperExpectation(
        val path: Path,
        val versionSyntax: String,
        val distributionSyntax: String,
        val fileSha256: String,
    )

    private data class ActiveYamlValue(
        val lineNumber: Int,
        val value: String,
        val isListItem: Boolean,
        val key: String? = null,
    )

    private data class ActiveVersion(
        val lineNumber: Int,
        val version: String,
    )

    private companion object {
        val VERSION_TOKEN = Regex(
            """(?<![A-Za-z0-9.])\d+(?:\.\d+)+(?:[-+][A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*)?(?![A-Za-z0-9.-])""",
        )
    }
}
