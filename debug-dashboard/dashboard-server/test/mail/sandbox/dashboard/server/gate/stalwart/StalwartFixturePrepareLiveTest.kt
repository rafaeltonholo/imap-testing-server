package mail.sandbox.dashboard.server.gate.stalwart

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse

class StalwartFixturePrepareLiveTest {
    @Test
    fun createsOnlyTheIgnoredDisposableRecoveryHandoffs() {
        val environment = System.getenv()
        StalwartGateActionSelection.requirePrepare(environment)
        val projectRoot = dashboardProjectRoot()

        val prepared = StalwartGateSecretFiles.prepareRecovery(projectRoot)

        assertEquals(
            projectRoot.resolve(".runtime/stalwart-gate0b").toRealPath(),
            prepared.runtimeDirectory.toRealPath(),
        )
        assertEquals(
            setOf("STALWART_RECOVERY_ADMIN"),
            parseKeys(prepared.recoveryEnv),
        )
        assertOwnerOnlyDirectory(prepared.runtimeDirectory)
        assertOwnerOnlyFile(prepared.recoveryEnv)
        assertOwnerOnlyFile(prepared.recoveryHandoff)
        assertFalse(Files.exists(prepared.fixtureSecrets))
    }

    private fun dashboardProjectRoot(): Path {
        val working = Paths.get(System.getProperty("user.dir"))
            .toAbsolutePath()
            .normalize()
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

    private fun parseKeys(path: Path): Set<String> =
        Files.readAllLines(path)
            .filter(String::isNotBlank)
            .map { line -> line.substringBefore('=') }
            .toSet()

    private fun assertOwnerOnlyDirectory(path: Path) {
        assertEquals(
            "rwx------",
            PosixFilePermissions.toString(Files.getPosixFilePermissions(path)),
        )
    }

    private fun assertOwnerOnlyFile(path: Path) {
        assertEquals(
            "rw-------",
            PosixFilePermissions.toString(Files.getPosixFilePermissions(path)),
        )
    }
}
