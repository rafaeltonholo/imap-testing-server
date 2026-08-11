package mail.sandbox.dashboard.server.web

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertTrue

class DashboardWebControllerSourceTest {
    @Test
    fun successfulCredentialUpdateIsRequiredBeforeReadinessRefresh() {
        val source = Files.readString(dashboardRoot().resolve(
            "dashboard-web/src/mail/sandbox/dashboard/web/DashboardApi.kt",
        ))
        val changeStart = source.indexOf("suspend fun changePassword(newPassword: String)")
        val changeEnd = source.indexOf("suspend fun deleteSelectedAccount()", changeStart)
        assertTrue(changeStart >= 0 && changeEnd > changeStart)
        val changePassword = source.substring(changeStart, changeEnd)

        val requireSuccess = changePassword.indexOf(".requireAchievedOperation()")
        val refreshReadiness = changePassword.indexOf("refreshAccounts(target)")
        assertTrue(requireSuccess >= 0, "Credential update success must be checked")
        assertTrue(
            refreshReadiness > requireSuccess,
            "Account readiness must refresh only after the provider operation succeeds",
        )
    }

    private fun dashboardRoot(): Path {
        val working = Path.of(System.getProperty("user.dir")).toAbsolutePath().normalize()
        return generateSequence(working) { it.parent }
            .firstOrNull { Files.isDirectory(it.resolve("dashboard-web")) }
            ?: error("Could not locate the debug-dashboard project root")
    }
}
