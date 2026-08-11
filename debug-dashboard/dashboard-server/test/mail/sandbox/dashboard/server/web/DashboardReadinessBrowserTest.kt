package mail.sandbox.dashboard.server.web

import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import java.nio.file.Files
import java.nio.file.Path
import java.time.Duration
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.runBlocking
import mail.sandbox.dashboard.contract.AccountInfo
import mail.sandbox.dashboard.contract.AccountListResponse
import mail.sandbox.dashboard.contract.AdoptPasswordRequest
import mail.sandbox.dashboard.contract.AuthenticationProbeRequest
import mail.sandbox.dashboard.contract.AuthenticationProbeResponse
import mail.sandbox.dashboard.contract.AuthenticationProtocol
import mail.sandbox.dashboard.contract.ChangePasswordRequest
import mail.sandbox.dashboard.contract.CredentialReadiness
import mail.sandbox.dashboard.contract.CredentialUpdateResponse
import mail.sandbox.dashboard.contract.CreateAccountRequest
import mail.sandbox.dashboard.contract.CreateFolderRequest
import mail.sandbox.dashboard.contract.FolderInfo
import mail.sandbox.dashboard.contract.FolderListResponse
import mail.sandbox.dashboard.contract.GenerateMessageRequest
import mail.sandbox.dashboard.contract.GenerateMessageResponse
import mail.sandbox.dashboard.contract.LogResponse
import mail.sandbox.dashboard.contract.LogService
import mail.sandbox.dashboard.contract.MailProtocol
import mail.sandbox.dashboard.contract.MessageDetail
import mail.sandbox.dashboard.contract.MessageListResponse
import mail.sandbox.dashboard.contract.MutateMessagesRequest
import mail.sandbox.dashboard.contract.OperationResponse
import mail.sandbox.dashboard.contract.Provider
import mail.sandbox.dashboard.contract.ProviderAvailability
import mail.sandbox.dashboard.contract.ProviderStatus
import mail.sandbox.dashboard.server.api.DashboardBackend
import mail.sandbox.dashboard.server.configureDashboard
import mail.sandbox.dashboard.server.gate.resolveDashboardHost
import org.openqa.selenium.By
import org.openqa.selenium.JavascriptExecutor
import org.openqa.selenium.SearchContext
import org.openqa.selenium.WebDriver
import org.openqa.selenium.WebElement
import org.openqa.selenium.chrome.ChromeDriver
import org.openqa.selenium.chrome.ChromeOptions
import org.openqa.selenium.devtools.HasDevTools
import org.openqa.selenium.devtools.v150.accessibility.Accessibility
import org.openqa.selenium.support.ui.WebDriverWait

/** Browser-facing source and rendered-interaction contracts for the Compose/Wasm dashboard. */
class DashboardReadinessBrowserTest {
    @Test
    fun narrowReadinessGateAndZeroAccountProviderStatusRenderInTheRealWasmApp() {
        val backend = ReadinessBrowserBackend()
        readinessBrowser(backend, windowSize = "760,1000") { driver, wait ->
            waitForAccessibleName(wait, "Provider status Dovecot: ready")
            waitForAccessibleName(wait, "Provider status Stalwart: ready")

            clickComposeText(driver, wait, "Dovecot")
            waitForSemanticText(
                wait,
                "Verify the existing password or reset it before reading or changing mailbox state.",
            )
            waitForSemanticText(wait, "Verify existing password")
            waitForSemanticText(wait, "Reset password")
            waitForSemanticText(wait, "Delete account")
            wait.until { backend.accountLogRequests.contains("bravo@local.test") }
            assertTrue(
                backend.folderRequests.none { it == "bravo@local.test" },
                "PASSWORD_REQUIRED must block mailbox loading without blocking management controls",
            )

            clickComposeText(driver, wait, "Authentication")
            waitForAccessibleName(wait, "Authentication probe panel")
            waitForSemanticText(
                wait,
                "Password required: enter a request override to keep this diagnostic available.",
            )

            backend.accountSnapshot = emptyList()
            backend.providerStatusSnapshot = listOf(
                ProviderStatus(Provider.DOVECOT, ProviderAvailability.UNAVAILABLE),
                ProviderStatus(Provider.STALWART, ProviderAvailability.UPGRADE_REQUIRED),
            )
            clickComposeText(driver, wait, "Refresh")
            waitForAccessibleName(wait, "Provider status Dovecot: unavailable")
            waitForAccessibleName(wait, "Provider status Stalwart: upgrade required")
            clickComposeText(driver, wait, "Accounts")
            waitForSemanticText(wait, "No account channels")
        }
    }

    @Test
    fun latestAuthenticationProbeWinsAcrossAnAccountRoundTripInTheRealWasmApp() {
        val backend = ReadinessBrowserBackend()
        readinessBrowser(backend) { driver, wait ->
            waitForSemanticText(wait, "Mail Flight Recorder")
            waitForSemanticText(wait, "alpha@local.test")

            clickComposeText(driver, wait, "Run authentication probe")
            assertTrue(
                backend.firstAlphaProbeStarted.await(5, TimeUnit.SECONDS),
                "The first Alpha probe did not reach the fake backend",
            )

            clickComposeText(driver, wait, "Dovecot")
            waitForSemanticText(wait, "Dovecot · bravo@local.test")
            clickComposeText(driver, wait, "Stalwart")
            waitForSemanticText(wait, "Stalwart · alpha@local.test")
            clickComposeText(driver, wait, "Run authentication probe")
            waitForSemanticText(wait, NEW_ALPHA_RESPONSE)

            backend.releaseFirstAlphaProbe.complete(Unit)
            wait.until { current ->
                authenticationProbeResourceCount(current) >= 2L
            }
            settleRenderedFrames(driver)

            assertEquals(
                listOf(ALPHA_PROVIDER_ACCOUNT_ID, ALPHA_PROVIDER_ACCOUNT_ID),
                backend.alphaProbeRequests.map(AuthenticationProbeRequest::providerAccountId),
            )
            assertTrue(
                semanticElements(driver).none { it.semanticText() == OLD_ALPHA_RESPONSE },
                "The invalidated first probe replaced the newer result",
            )
            assertNotNull(waitForSemanticText(wait, NEW_ALPHA_RESPONSE))
        }
    }

    @Test
    fun newReadinessEvidenceUsesAaTextContrast() {
        val app = dashboardSource("DashboardApp.kt")
        val badge = app.section("private fun ReadinessBadge(", "private fun StaleMarker(")
        val stale = app.section("private fun StaleMarker(", "private fun ProtocolChip(")
        val protocol = app.section("private fun ProtocolChip(", "private fun ReadinessNotice(")

        assertTrue(
            "color = InstrumentGraphite" in badge,
            "Readiness badge text must use the AA-safe graphite foreground",
        )
        assertTrue(
            "color = InstrumentGraphite" in stale,
            "The 10sp stale marker must use the AA-safe graphite foreground",
        )
        assertTrue(
            "color = InstrumentGraphite" in protocol,
            "The 10sp protocol chip must use the AA-safe graphite foreground",
        )

        val graphite = app.color("InstrumentGraphite")
        listOf("GreenWash", "ErrorWash", "PanelFogDark", "RecorderPaper", "PanelFog")
            .forEach { background ->
                val ratio = contrastRatio(graphite, app.color(background))
                assertTrue(ratio >= 4.5, "$background contrast was $ratio:1")
            }
    }

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
            "account.credentialReadiness == CredentialReadiness.READY" in api,
        )
        assertTrue(
            "account.supportsMailboxOperations()" in api,
            "A ready SMTP-only account must not trigger mailbox requests",
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

    private fun String.color(name: String): Int {
        val match = Regex("private val $name = Color\\(0xFF([0-9A-F]{6})\\)").find(this)
        return requireNotNull(match) { "Missing color token: $name" }.groupValues[1].toInt(16)
    }

    private fun contrastRatio(first: Int, second: Int): Double {
        val firstLuminance = relativeLuminance(first)
        val secondLuminance = relativeLuminance(second)
        return (maxOf(firstLuminance, secondLuminance) + 0.05) /
            (minOf(firstLuminance, secondLuminance) + 0.05)
    }

    private fun relativeLuminance(rgb: Int): Double {
        fun component(shift: Int): Double {
            val value = ((rgb shr shift) and 0xFF) / 255.0
            return if (value <= 0.04045) value / 12.92 else Math.pow((value + 0.055) / 1.055, 2.4)
        }
        return 0.2126 * component(16) + 0.7152 * component(8) + 0.0722 * component(0)
    }
}

private fun readinessBrowser(
    backend: ReadinessBrowserBackend,
    windowSize: String = "1440,1200",
    block: (ChromeDriver, WebDriverWait) -> Unit,
) {
    val dashboardRoot = dashboardProjectRoot()
    val server = embeddedServer(
        factory = Netty,
        port = 0,
        host = "127.0.0.1",
    ) {
        configureDashboard(
            webAssets = WebAssetBundle.fromEnvironment(projectRoot = dashboardRoot),
            dashboardBackend = backend,
        )
    }.start(wait = false)
    val driver = ChromeDriver(
        ChromeOptions().apply {
            setBinary("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
            addArguments(
                "--headless=new",
                "--enable-features=WebAssemblyGarbageCollection",
                "--force-renderer-accessibility=complete",
                "--window-size=$windowSize",
                "--disable-search-engine-choice-screen",
                "--disable-background-networking",
            )
        },
    )
    try {
        val devTools = (driver as HasDevTools).devTools
        devTools.createSession()
        devTools.send(Accessibility.enable())
        val port = runBlocking { server.engine.resolvedConnectors().single().port }
        driver.get("http://127.0.0.1:$port/")
        block(driver, WebDriverWait(driver, Duration.ofSeconds(45)))
    } catch (failure: Throwable) {
        println("READINESS_BROWSER_URL=${driver.currentUrl}")
        println("READINESS_BROWSER_SOURCE=${driver.pageSource.take(2_000)}")
        println(
            "READINESS_BROWSER_SHADOW=" + runCatching {
                dashboardShadow(driver).findElements(By.cssSelector("*")).map { element ->
                    "${element.tagName}:${element.getDomAttribute("id")}:${element.semanticText()}"
                }
            }.getOrElse { listOf("ERROR:$it") },
        )
        println("READINESS_BROWSER_LOGS=${runCatching { driver.manage().logs().get("browser").all }.getOrNull()}")
        throw failure
    } finally {
        runCatching { driver.quit() }
        server.stop(gracePeriodMillis = 500, timeoutMillis = 2_000)
    }
}

private fun dashboardProjectRoot(): Path {
    val working = Path.of(System.getProperty("user.dir")).toAbsolutePath().normalize()
    return generateSequence(working) { it.parent }
        .firstOrNull { Files.isDirectory(it.resolve("dashboard-web")) }
        ?: error("Could not locate the debug-dashboard project root")
}

private fun waitForSemanticText(wait: WebDriverWait, expected: String): WebElement = wait.until { driver ->
    runCatching {
        semanticElements(driver).firstOrNull { element ->
            element.semanticText() == expected
        }
    }.getOrNull()
}

private fun waitForAccessibleName(wait: WebDriverWait, expected: String): WebElement = wait.until { driver ->
    runCatching {
        semanticElements(driver).firstOrNull { element ->
            element.accessibleName.orEmpty().trim() == expected
        }
    }.getOrNull()
}

private fun clickComposeText(
    driver: ChromeDriver,
    wait: WebDriverWait,
    expected: String,
) {
    val control = wait.until { current ->
        runCatching {
            semanticElements(current).firstOrNull { element ->
                element.ariaRole == "button" && element.semanticText().lineSequence().any {
                    it.trim() == expected
                }
            }
        }.getOrNull()
    }
    (driver as JavascriptExecutor).executeScript("arguments[0].click();", control)
}

private fun semanticElements(driver: WebDriver): List<WebElement> =
    dashboardShadow(driver).findElements(By.cssSelector("#cmp_a11y_root *"))

private fun dashboardShadow(driver: WebDriver): SearchContext =
    resolveDashboardHost(driver.findElement(By.id("dashboard-root")))

private fun WebElement.semanticText(): String =
    getDomProperty("innerText")?.trim().orEmpty().ifBlank { accessibleName.orEmpty().trim() }

private fun authenticationProbeResourceCount(driver: WebDriver): Long =
    ((driver as JavascriptExecutor).executeScript(
        "return performance.getEntriesByType('resource')" +
            ".filter((entry) => entry.name.endsWith('/api/v1/authentication-probes')).length;",
    ) as Number).toLong()

private fun settleRenderedFrames(driver: WebDriver) {
    (driver as JavascriptExecutor).executeAsyncScript(
        "const done = arguments[arguments.length - 1];" +
            "requestAnimationFrame(() => requestAnimationFrame(done));",
    )
}

private class ReadinessBrowserBackend : DashboardBackend {
    val firstAlphaProbeStarted = CountDownLatch(1)
    val releaseFirstAlphaProbe = CompletableDeferred<Unit>()
    val alphaProbeRequests = CopyOnWriteArrayList<AuthenticationProbeRequest>()
    val accountLogRequests = CopyOnWriteArrayList<String>()
    val folderRequests = CopyOnWriteArrayList<String>()
    private val alphaProbeCount = AtomicInteger()

    @Volatile
    var accountSnapshot: List<AccountInfo> = listOf(
        AccountInfo(
            address = "alpha@local.test",
            provider = Provider.STALWART,
            protocols = listOf(MailProtocol.JMAP, MailProtocol.SMTP),
            credentialReadiness = CredentialReadiness.READY,
            providerAccountId = ALPHA_PROVIDER_ACCOUNT_ID,
        ),
        AccountInfo(
            address = "bravo@local.test",
            provider = Provider.DOVECOT,
            protocols = listOf(MailProtocol.IMAP, MailProtocol.POP3, MailProtocol.SMTP),
            credentialReadiness = CredentialReadiness.PASSWORD_REQUIRED,
        ),
    )

    @Volatile
    var providerStatusSnapshot: List<ProviderStatus> = listOf(
        ProviderStatus(Provider.DOVECOT, ProviderAvailability.READY),
        ProviderStatus(Provider.STALWART, ProviderAvailability.READY),
    )

    override suspend fun listAccounts(): AccountListResponse = AccountListResponse(
        accounts = accountSnapshot,
        providerStatuses = providerStatusSnapshot,
    )

    override suspend fun probeAuthentication(request: AuthenticationProbeRequest): AuthenticationProbeResponse {
        if (request.address == "alpha@local.test") {
            alphaProbeRequests += request
            if (alphaProbeCount.incrementAndGet() == 1) {
                firstAlphaProbeStarted.countDown()
                releaseFirstAlphaProbe.await()
                return request.response(OLD_ALPHA_RESPONSE)
            }
            return request.response(NEW_ALPHA_RESPONSE)
        }
        return request.response("bravo response")
    }

    override suspend fun logs(service: LogService): LogResponse = LogResponse(service, lines = emptyList())

    override suspend fun accountLogs(
        address: String,
        provider: Provider,
        providerAccountId: String?,
    ): LogResponse {
        accountLogRequests += address
        return LogResponse(LogService.ALL, account = address, lines = emptyList())
    }

    override suspend fun listFolders(
        address: String,
        provider: Provider,
        providerAccountId: String?,
    ): FolderListResponse {
        folderRequests += address
        return FolderListResponse(emptyList())
    }

    override suspend fun listMessages(
        address: String,
        provider: Provider,
        providerAccountId: String?,
        folderId: String?,
    ): MessageListResponse = MessageListResponse(emptyList())

    override suspend fun createAccount(request: CreateAccountRequest): AccountInfo = unsupported()
    override suspend fun deleteAccount(
        address: String,
        provider: Provider,
        providerAccountId: String?,
    ): OperationResponse = unsupported()
    override suspend fun adoptPassword(
        address: String,
        provider: Provider,
        providerAccountId: String?,
        request: AdoptPasswordRequest,
    ): CredentialUpdateResponse = unsupported()
    override suspend fun changePassword(
        address: String,
        provider: Provider,
        providerAccountId: String?,
        request: ChangePasswordRequest,
    ): CredentialUpdateResponse = unsupported()
    override suspend fun createFolder(
        address: String,
        provider: Provider,
        providerAccountId: String?,
        request: CreateFolderRequest,
    ): FolderInfo = unsupported()
    override suspend fun deleteFolder(
        address: String,
        provider: Provider,
        providerAccountId: String?,
        folderId: String,
    ): OperationResponse = unsupported()
    override suspend fun readMessage(
        address: String,
        provider: Provider,
        providerAccountId: String?,
        messageId: String,
        folderId: String?,
    ): MessageDetail = unsupported()
    override suspend fun mutateMessages(
        address: String,
        provider: Provider,
        providerAccountId: String?,
        request: MutateMessagesRequest,
    ): OperationResponse = unsupported()
    override suspend fun generateMessage(request: GenerateMessageRequest): GenerateMessageResponse = unsupported()

    private fun AuthenticationProbeRequest.response(providerResponse: String) = AuthenticationProbeResponse(
        address = address,
        provider = provider,
        protocol = protocol,
        success = true,
        providerResponse = providerResponse,
        correlatedLogs = listOf("correlated $providerResponse"),
    )

    private fun <T> unsupported(): T = error("Unexpected browser-backend operation")
}

private const val ALPHA_PROVIDER_ACCOUNT_ID = "stalwart-alpha-id"
private const val OLD_ALPHA_RESPONSE = "old alpha probe response"
private const val NEW_ALPHA_RESPONSE = "new alpha probe response"
