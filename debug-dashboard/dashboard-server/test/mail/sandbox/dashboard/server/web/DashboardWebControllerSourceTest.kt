package mail.sandbox.dashboard.server.web

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DashboardWebControllerSourceTest {
    @Test
    fun generatedMessageRetainsTheDialogIdentityAndRejectsStaleTargets() {
        val root = dashboardRoot()
        val appSource = Files.readString(root.resolve(
            "dashboard-web/src/mail/sandbox/dashboard/web/DashboardApp.kt",
        ))
        val dialog = appSource.section(
            "private fun GenerateMessageDialog(",
            "private fun DeliveryPathChoice(",
        )
        assertTrue(
            "providerAccountId = resolvedTarget.providerAccountId" in dialog,
            "The dialog request must retain its exact provider identity",
        )

        val apiSource = Files.readString(root.resolve(
            "dashboard-web/src/mail/sandbox/dashboard/web/DashboardApi.kt",
        ))
        val controller = apiSource.section(
            "suspend fun generateMessage(request: GenerateMessageRequest)",
            "suspend fun mutateSelectedMessage(",
        )
        assertTrue(
            "accounts.firstOrNull(request::targetsExactly)" in controller,
            "The controller must reject a same-address account with a replacement identity",
        )
        assertTrue(
            "api.generateMessage(request)" in controller,
            "The controller must send the immutable request unchanged",
        )
        assertFalse(
            "copy(providerAccountId" in controller,
            "The controller must never substitute a freshly resolved provider identity",
        )
    }

    @Test
    fun failedCredentialUpdateRefreshesReadinessBeforeReportingTheFailure() {
        val source = Files.readString(dashboardRoot().resolve(
            "dashboard-web/src/mail/sandbox/dashboard/web/DashboardApi.kt",
        ))
        val changeStart = source.indexOf("suspend fun changePassword(newPassword: String)")
        val changeEnd = source.indexOf("suspend fun deleteSelectedAccount()", changeStart)
        assertTrue(changeStart >= 0 && changeEnd > changeStart)
        val changePassword = source.substring(changeStart, changeEnd)

        val clearReceipt = changePassword.indexOf("lastReceipt = null")
        val requireSuccess = changePassword.indexOf(".requireAchievedOperation()")
        val refreshReadiness = changePassword.indexOf("refreshAccounts(target)")
        val successReceipt = changePassword.indexOf("lastReceipt = result.operation.message")
        assertTrue(clearReceipt >= 0, "A failed credential update must leave no receipt")
        assertTrue(requireSuccess >= 0, "Credential update success must be checked")
        assertTrue(
            refreshReadiness > clearReceipt && refreshReadiness < requireSuccess,
            "Readiness must refresh before a failed provider operation is reported",
        )
        assertTrue(
            successReceipt > requireSuccess,
            "A receipt may be published only after the provider operation succeeds",
        )

        val refreshAccounts = source.section(
            "suspend fun refreshAccounts(",
            "suspend fun selectAccount(",
        )
        val operation = source.section(
            "private suspend fun operation(",
            "private fun containsTarget(",
        )
        assertTrue("failure.rethrowIfCancellation()" in refreshAccounts)
        assertTrue("failure.rethrowIfCancellation()" in operation)
    }

    private fun dashboardRoot(): Path {
        val working = Path.of(System.getProperty("user.dir")).toAbsolutePath().normalize()
        return generateSequence(working) { it.parent }
            .firstOrNull { Files.isDirectory(it.resolve("dashboard-web")) }
            ?: error("Could not locate the debug-dashboard project root")
    }

    private fun String.section(start: String, end: String): String {
        val startIndex = indexOf(start)
        val endIndex = indexOf(end, startIndex)
        assertTrue(startIndex >= 0 && endIndex > startIndex)
        return substring(startIndex, endIndex)
    }
}
