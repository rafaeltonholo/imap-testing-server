package mail.sandbox.dashboard.server.web

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Browser-facing source contract for the Compose/Wasm dashboard.
 *
 * The JVM server test module cannot link the Wasm application. These checks pin the semantic
 * browser surface and controller wiring; the production browser gate then exercises the linked
 * bundle, while `dashboard-web` remains built exclusively by the Kotlin Toolchain.
 */
class DashboardReadinessBrowserTest {
    @Test
    fun controllerRetainsProviderStatusAndGatesOnlyMailPlaneActions() {
        val api = dashboardSource("DashboardApi.kt")
        val refresh = api.section(
            "suspend fun refreshAccounts(",
            "suspend fun selectAccount(",
        )

        assertTrue("var providerStatuses by mutableStateOf" in api)
        assertTrue("providerStatuses = response.providerStatuses" in refresh)
        assertTrue("val mailActionsEnabled: Boolean" in api)
        assertTrue(
            "selectedAccount?.credentialReadiness == CredentialReadiness.READY" in api,
        )
        assertTrue(
            "if (!mailActionsEnabled)" in api,
            "Mailbox refresh must stop before a provider mail call when credentials are not ready",
        )
    }

    @Test
    fun accountRailExposesReadinessStalenessLiveProtocolsAndBothProviderStatuses() {
        val app = dashboardSource("DashboardApp.kt")
        val accountsPane = app.section("private fun AccountsPane(", "private fun AccountGroup(")
        val channel = app.section("private fun ProviderChannelButton(", "private fun AccountHeader(")
        val statusRail = app.section("private fun ProviderStatusRail(", "private fun ProviderStatusBanner(")
        val surface = app.section("private fun DashboardSurface(", "private fun RuntimeStrip(")

        assertTrue("ProviderStatusRail(" in app)
        assertTrue("Provider.entries.forEach" in statusRail)
        assertTrue("statuses = controller.providerStatuses" in surface)
        assertTrue("ReadinessBadge(" in channel)
        assertTrue("Stale snapshot" in channel)
        assertTrue("ProtocolChip(" in channel)
        assertTrue("Protocol ${'$'}{protocol.name}: ${'$'}evidence" in app)
        assertTrue("Provider status ${'$'}{provider.displayName()}" in app)
        assertTrue(
            "controller.accounts.isEmpty()" !in statusRail,
            "Provider status must not disappear when there are no cached accounts",
        )
        assertTrue("No account channels" in accountsPane)

        listOf(
            "Ready",
            "Password required",
            "Authentication failed",
            "Provider unavailable",
        ).forEach { label -> assertTrue("\"$label\"" in app, "Missing readiness label: $label") }
    }

    @Test
    fun passwordRequiredKeepsManagementAvailableWhileMailControlsStayDisabled() {
        val app = dashboardSource("DashboardApp.kt")
        val accountHeader = app.section("private fun AccountHeader(", "private fun CompactAccountSummary(")
        val folderPane = app.section("private fun FolderPane(", "private fun FolderRow(")
        val readerPane = app.section("private fun MessageReaderPane(", "private fun ColumnScope.MessageReader(")
        val generateDialog = app.section("private fun GenerateMessageDialog(", "private fun DeliveryPathChoice(")

        assertTrue("Verify existing password" in accountHeader)
        assertTrue("Reset password" in accountHeader)
        assertTrue("enabled = controller.busyLabel == null" in accountHeader)
        assertTrue("controller.mailActionsEnabled" in folderPane)
        assertTrue("MailReadinessEmptyState(" in folderPane)
        assertTrue("controller.mailActionsEnabled" in readerPane)
        assertTrue("MailReadinessEmptyState(" in readerPane)
        assertTrue("CredentialReadiness.READY" in generateDialog)
        assertTrue("mailActionsEnabled" in app)
    }

    @Test
    fun createDialogUsesFixedDovecotCapabilitiesAndAnEnforcedStalwartSubset() {
        val app = dashboardSource("DashboardApp.kt")
        val dialog = app.section("private fun CreateAccountDialog(", "private fun ProtocolToggle(")

        assertTrue("Dovecot fixed account capabilities" in dialog)
        assertTrue("DOVECOT_FIXED_PROTOCOLS.forEach" in dialog)
        assertTrue("Provider.STALWART" in dialog)
        assertTrue("ProtocolToggle(" in dialog)
        assertTrue("provider.creationProtocols(protocols)" in dialog)
        assertTrue("Provider.DOVECOT -> DOVECOT_FIXED_PROTOCOLS" in app)
        assertTrue("MailProtocol.IMAP" in app)
        assertTrue("MailProtocol.POP3" in app)
        assertTrue("MailProtocol.SMTP" in app)
        assertTrue(
            "Provider.STALWART -> STALWART_SELECTABLE_PROTOCOLS.filter(selected::contains)" in app,
        )
        assertFalse(
            dialog.substringBefore("Provider.STALWART ->").contains("ProtocolToggle("),
            "Dovecot capabilities must not be editable per account",
        )
    }

    @Test
    fun passwordDialogHasExplicitVerifyAndResetModesWithTargetedControllerRoutes() {
        val api = dashboardSource("DashboardApi.kt")
        val app = dashboardSource("DashboardApp.kt")
        val adopt = api.section("suspend fun adoptPassword(password: String)", "suspend fun changePassword(newPassword: String)")
        val change = api.section("suspend fun changePassword(newPassword: String)", "suspend fun deleteSelectedAccount()")
        val dialog = app.section("private fun PasswordDialog(", "private fun AuthenticationProbePane(")

        assertTrue("api.adoptPassword(target, AdoptPasswordRequest(password))" in adopt)
        assertTrue("applyAuthoritativeCredentialUpdate(target, result)" in adopt)
        assertTrue("refreshWorkspace()" in adopt)
        assertTrue("api.changePassword(target, ChangePasswordRequest(newPassword))" in change)
        assertTrue("applyAuthoritativeCredentialUpdate(target, result)" in change)
        assertTrue("refreshWorkspace()" in change)
        assertTrue("Verify existing password" in dialog)
        assertTrue("Reset password" in dialog)
        assertTrue("PasswordActionMode.VERIFY" in dialog)
        assertTrue("PasswordActionMode.RESET" in dialog)
    }

    @Test
    fun authenticationProbeOffersOnlyProviderProtocolsAndNeverRendersItsOverride() {
        val api = dashboardSource("DashboardApi.kt")
        val app = dashboardSource("DashboardApp.kt")
        val controllerProbe = api.section(
            "suspend fun probeAuthentication(",
            "suspend fun createAccount(",
        )
        val probePane = app.section(
            "private fun AuthenticationProbePane(",
            "private fun ProbeResult(",
        )
        val supported = app.section(
            "private fun AccountInfo.supportedAuthenticationProtocols()",
            "private fun AuthenticationProtocol.displayName()",
        )

        assertTrue("AuthenticationProbeRequest(" in controllerProbe)
        assertTrue("providerAccountId = target.providerAccountId" in controllerProbe)
        assertTrue("credentialOverride = credentialOverride" in controllerProbe)
        assertTrue("redacted(credentialOverride)" in controllerProbe)
        assertTrue("Authentication probe" in probePane)
        assertTrue("Remembered credential" in probePane)
        assertTrue("Request override" in probePane)
        assertTrue("credentialOverride = \"\"" in probePane)
        assertTrue("CredentialReadiness.PASSWORD_REQUIRED" in probePane)
        assertTrue("controller.probeAuthentication(" in probePane)
        assertFalse(
            "Text(credentialOverride" in probePane,
            "The request-scoped secret must never be rendered as evidence",
        )
        assertTrue("Provider.DOVECOT" in supported)
        assertTrue("AuthenticationProtocol.IMAP" in supported)
        assertTrue("AuthenticationProtocol.POP3" in supported)
        assertTrue("AuthenticationProtocol.SMTP" in supported)
        assertTrue("AuthenticationProtocol.OAUTH_IMAP" in supported)
        assertTrue("AuthenticationProtocol.OAUTH_SMTP" in supported)
        assertTrue("Provider.STALWART" in supported)
        assertTrue("AuthenticationProtocol.JMAP" in supported)
        assertTrue("MailProtocol.JMAP" in supported)
    }

    @Test
    fun authenticationProbeRemainsAReachableResponsiveStageWithSemanticSelectors() {
        val app = dashboardSource("DashboardApp.kt")

        assertTrue("Authentication(\"Authentication\")" in app)
        assertTrue("NarrowStage.Authentication -> AuthenticationProbePane(" in app)
        assertTrue("contentDescription = \"Authentication probe panel\"" in app)
        assertTrue("contentDescription = \"Readiness ${'$'}{readiness.name.lowercase()}\"" in app)
        assertTrue("contentDescription = \"Stale provider snapshot\"" in app)
        assertFalse("offset(" in app, "Readiness controls must not depend on pixel-position selectors")
    }

    private fun dashboardSource(fileName: String): String = Files.readString(
        dashboardRoot().resolve("dashboard-web/src/mail/sandbox/dashboard/web/$fileName"),
    )

    private fun dashboardRoot(): Path {
        val working = Path.of(System.getProperty("user.dir")).toAbsolutePath().normalize()
        return generateSequence(working) { it.parent }
            .firstOrNull { Files.isDirectory(it.resolve("dashboard-web")) }
            ?: error("Could not locate the debug-dashboard project root")
    }

    private fun String.section(start: String, end: String): String {
        val startIndex = indexOf(start)
        val endIndex = indexOf(end, startIndex.coerceAtLeast(0))
        assertTrue(startIndex >= 0, "Missing section start: $start")
        assertTrue(endIndex > startIndex, "Missing section end: $end")
        return substring(startIndex, endIndex)
    }
}
