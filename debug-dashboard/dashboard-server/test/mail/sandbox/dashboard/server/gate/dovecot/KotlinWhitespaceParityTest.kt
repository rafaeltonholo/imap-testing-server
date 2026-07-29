package mail.sandbox.dashboard.server.gate.dovecot

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals

class KotlinWhitespaceParityTest {
    @Test
    fun sharedFixtureMatchesKotlinCharIsWhitespace() {
        val fixture = Files.readAllLines(
            repositoryRoot().resolve("oauth2-mock/kotlin-whitespace-fixture.txt"),
        )
        val records = fixture
            .filterNot { line -> line.isBlank() || line.startsWith("#") }
            .map { line ->
                val fields = line.split(' ')
                require(fields.size == 2) { "Invalid Kotlin whitespace fixture line" }
                val bounds = fields[0].split('-').map { value -> value.toInt(16) }
                require(bounds.size in 1..2) {
                    "Invalid Kotlin whitespace fixture range"
                }
                require(
                    bounds.first() <= bounds.last() &&
                        bounds.first() >= Char.MIN_VALUE.code &&
                        bounds.last() <= Char.MAX_VALUE.code,
                ) {
                    "Kotlin whitespace fixture range is outside UTF-16"
                }
                val range = bounds.first()..bounds.last()
                val expected = fields[1].toBooleanStrict()
                range to expected
            }
        val expectedWhitespace = records
            .filter { (_, expected) -> expected }
            .flatMap { (range, _) -> range }
            .toSet()

        records
            .filterNot { (_, expected) -> expected }
            .flatMap { (range, _) -> range }
            .forEach { codePoint ->
                require(codePoint !in expectedWhitespace) {
                    "Conflicting Kotlin whitespace fixture record"
                }
            }
        (Char.MIN_VALUE.code..Char.MAX_VALUE.code).forEach { codePoint ->
            assertEquals(
                codePoint in expectedWhitespace,
                codePoint.toChar().isWhitespace(),
                "Unexpected Kotlin whitespace classification for U+%04X"
                    .format(codePoint),
            )
        }
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
        return requireNotNull(dashboardRoot.parent).also { root ->
            require(Files.isRegularFile(root.resolve("docker-compose.yml"))) {
                "expected repository root above dashboard project: $root"
            }
        }
    }
}
