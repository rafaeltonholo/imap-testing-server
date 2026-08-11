package mail.sandbox.dashboard.server.web

import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import java.nio.file.Files
import java.nio.file.Path
import java.time.Duration
import java.util.Optional
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
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
import mail.sandbox.dashboard.server.gate.resolveDashboardShadowHost
import org.openqa.selenium.By
import org.openqa.selenium.JavascriptExecutor
import org.openqa.selenium.OutputType
import org.openqa.selenium.SearchContext
import org.openqa.selenium.TakesScreenshot
import org.openqa.selenium.WebDriver
import org.openqa.selenium.WebElement
import org.openqa.selenium.chrome.ChromeDriver
import org.openqa.selenium.chrome.ChromeOptions
import org.openqa.selenium.devtools.HasDevTools
import org.openqa.selenium.devtools.v150.accessibility.Accessibility
import org.openqa.selenium.devtools.v150.input.Input
import org.openqa.selenium.devtools.v150.input.model.MouseButton
import org.openqa.selenium.support.ui.WebDriverWait

/** Rendered credential workflows against the production Compose/Wasm bundle and public API. */
class DashboardReadinessCredentialsBrowserTest {
    @Test
    fun passwordRequiredStalwartCredentialsStayTargetedRedactedAndUnlockMail() {
        val backend = CredentialsBrowserBackend()
        credentialsBrowser(backend) { driver, wait ->
            waitForCredentialsText(wait, CREDENTIAL_ACCOUNT)
            clickCredentialsButton(driver, wait, "Stalwart")
            waitForCredentialsAccessibleName(wait, "Readiness password_required")

            clickCredentialsButton(driver, wait, "Authentication")
            waitForCredentialsAccessibleName(wait, "Authentication probe panel")
            assertEquals(
                setOf("JMAP password", "SMTP password"),
                authenticationProtocolControls(driver),
                "The selected Stalwart channel must expose only its reported JMAP and SMTP probes",
            )

            clickCredentialsButton(driver, wait, "SMTP password")
            clickCredentialsButton(driver, wait, "Request override")
            enterCredentialsText(wait, driver, "Password override", PROBE_SECRET)
            clickCredentialsButton(driver, wait, "Run authentication probe")

            wait.until { backend.authenticationProbes.size == 1 }
            assertEquals(
                AuthenticationProbeRequest(
                    address = CREDENTIAL_ACCOUNT,
                    provider = Provider.STALWART,
                    protocol = AuthenticationProtocol.SMTP,
                    credentialOverride = PROBE_SECRET,
                    providerAccountId = CREDENTIAL_PROVIDER_ID,
                ),
                backend.authenticationProbes.single(),
            )
            waitForCredentialsAccessibleName(wait, "Authentication probe failed")
            waitForCredentialsText(wait, "provider rejected [redacted]")
            waitForCredentialsText(wait, "correlated credential=[redacted]")
            wait.until {
                credentialsTextField(it, "Password override")
                    ?.getDomProperty("innerText")
                    .isNullOrEmpty()
            }
            assertFalse(
                renderedCredentialsSurface(driver).contains(PROBE_SECRET),
                "The request-scoped probe secret remained in the rendered accessibility surface",
            )

            clickCredentialsButton(driver, wait, "Mailbox")
            waitForCredentialsText(wait, "Password required")
            clickCredentialsButton(driver, wait, "Verify existing password")
            enterCredentialsText(wait, driver, "Existing password", ADOPTED_PASSWORD)
            clickCredentialsButton(driver, wait, "Verify existing password", preferLast = true)

            wait.until { backend.adoptPasswordCalls.size == 1 }
            assertEquals(
                CredentialInvocation(
                    address = CREDENTIAL_ACCOUNT,
                    provider = Provider.STALWART,
                    providerAccountId = CREDENTIAL_PROVIDER_ID,
                    password = ADOPTED_PASSWORD,
                ),
                backend.adoptPasswordCalls.single(),
            )
            assertTrue(backend.changePasswordCalls.isEmpty(), "Verification must not call password reset")
            wait.until { backend.folderRequests.isNotEmpty() }
            assertEquals(
                1,
                backend.listAccountCalls.get(),
                "Password adoption must use its targeted response instead of refetching account inventory",
            )
            driver.navigate().refresh()
            waitForCredentialsText(wait, CREDENTIAL_ACCOUNT)
            clickCredentialsButton(driver, wait, "Stalwart")
            waitForCredentialsAccessibleName(wait, "Readiness ready")
            waitForCredentialsAccessibleName(wait, "Inbox 0 unread / 0 total")
            assertEquals(CREDENTIAL_TARGET, backend.folderRequests.last())
            val listAccountCallsAfterAdoptionRefresh = backend.listAccountCalls.get()

            val folderLoadsAfterAdoption = backend.folderRequests.size
            clickCredentialsButton(driver, wait, "Reset password")
            enterCredentialsText(wait, driver, "New password", RESET_PASSWORD)
            clickCredentialsButton(driver, wait, "Reset password", preferLast = true)

            wait.until { backend.changePasswordCalls.size == 1 }
            assertEquals(
                CredentialInvocation(
                    address = CREDENTIAL_ACCOUNT,
                    provider = Provider.STALWART,
                    providerAccountId = CREDENTIAL_PROVIDER_ID,
                    password = RESET_PASSWORD,
                ),
                backend.changePasswordCalls.single(),
            )
            assertEquals(1, backend.adoptPasswordCalls.size, "Reset must not repeat password adoption")
            wait.until { backend.folderRequests.size > folderLoadsAfterAdoption }
            assertEquals(
                listAccountCallsAfterAdoptionRefresh,
                backend.listAccountCalls.get(),
                "Password reset must use its targeted response instead of refetching account inventory",
            )
            driver.navigate().refresh()
            waitForCredentialsText(wait, CREDENTIAL_ACCOUNT)
            clickCredentialsButton(driver, wait, "Stalwart")
            waitForCredentialsAccessibleName(wait, "Readiness ready")
            waitForCredentialsAccessibleName(wait, "Inbox 0 unread / 0 total")
        }
    }
}

private fun credentialsBrowser(
    backend: CredentialsBrowserBackend,
    block: (ChromeDriver, WebDriverWait) -> Unit,
) {
    val dashboardRoot = credentialsDashboardProjectRoot()
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
                "--window-size=760,1000",
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
        val screenshot = Files.createTempFile("dashboard-readiness-credentials-", ".png")
        Files.write(screenshot, (driver as TakesScreenshot).getScreenshotAs(OutputType.BYTES))
        println("CREDENTIALS_BROWSER_URL=${driver.currentUrl}")
        println("CREDENTIALS_BROWSER_SCREENSHOT=$screenshot")
        println(
            "CREDENTIALS_BROWSER_BACKEND=" +
                "probes=${backend.authenticationProbes.size}," +
                "adoptions=${backend.adoptPasswordCalls.size}," +
                "resets=${backend.changePasswordCalls.size}," +
                "folders=${backend.folderRequests.size}",
        )
        println("CREDENTIALS_BROWSER_SURFACE=${runCatching { renderedCredentialsSurface(driver) }.getOrNull()}")
        println("CREDENTIALS_BROWSER_LOGS=${runCatching { driver.manage().logs().get("browser").all }.getOrNull()}")
        throw failure
    } finally {
        runCatching { driver.quit() }
        server.stop(gracePeriodMillis = 500, timeoutMillis = 2_000)
    }
}

private fun credentialsDashboardProjectRoot(): Path {
    val working = Path.of(System.getProperty("user.dir")).toAbsolutePath().normalize()
    return generateSequence(working) { it.parent }
        .firstOrNull { Files.isDirectory(it.resolve("dashboard-web")) }
        ?: error("Could not locate the debug-dashboard project root")
}

private fun waitForCredentialsText(wait: WebDriverWait, expected: String): WebElement = wait.until { driver ->
    runCatching {
        credentialsSemanticElements(driver).firstOrNull { element ->
            element.credentialsSemanticValues().any { value -> value == expected }
        }
    }.getOrNull()
}

private fun waitForCredentialsAccessibleName(wait: WebDriverWait, expected: String): WebElement =
    wait.until { driver ->
        runCatching {
            credentialsSemanticElements(driver).firstOrNull { element ->
                element.accessibleName.orEmpty().trim() == expected
            }
        }.getOrNull()
    }

private fun authenticationProtocolControls(driver: WebDriver): Set<String> {
    val authenticationLabels = setOf(
        "IMAP password",
        "POP3 password",
        "SMTP password",
        "JMAP password",
        "IMAP OAuth",
        "SMTP OAuth",
    )
    return credentialsSemanticElements(driver)
        .asSequence()
        .filter { it.ariaRole == "button" }
        .flatMap { it.credentialsSemanticValues().asSequence() }
        .flatMap { it.lineSequence() }
        .map(String::trim)
        .filter(authenticationLabels::contains)
        .toSet()
}

private fun clickCredentialsButton(
    driver: ChromeDriver,
    wait: WebDriverWait,
    expected: String,
    preferLast: Boolean = false,
) {
    val control = wait.until { current ->
        runCatching {
            val matches = credentialsSemanticElements(current).filter { element ->
                element.ariaRole == "button" &&
                    element.credentialsSemanticValues().any { value ->
                        value.lineSequence().any { line -> line.trim() == expected }
                    }
            }
            if (preferLast) matches.lastOrNull() else matches.firstOrNull()
        }.getOrNull()
    }
    dispatchTrustedCredentialsClick(driver, control)
}

private fun enterCredentialsText(
    wait: WebDriverWait,
    driver: ChromeDriver,
    label: String,
    value: String,
): WebElement {
    val field = wait.until { current -> credentialsTextField(current, label) }
    (driver as JavascriptExecutor).executeScript(
        "arguments[0].scrollIntoView({block: 'center', inline: 'center'});",
        field,
    )
    driver.executeAsyncScript(
        "const done = arguments[arguments.length - 1];" +
            "requestAnimationFrame(() => requestAnimationFrame(done));",
    )
    dispatchTrustedCredentialsClick(driver, field)
    wait.until { current ->
        credentialsDashboardShadow(current)
            .findElements(By.cssSelector("input, textarea"))
            .firstOrNull()
    }
    (driver as HasDevTools).devTools.send(Input.insertText(value))
    return wait.until { current ->
        credentialsTextField(current, label)?.takeIf {
            it.getDomProperty("innerText").orEmpty().isNotEmpty()
        }
    }
}

private fun dispatchTrustedCredentialsClick(driver: ChromeDriver, element: WebElement) {
    val rect = element.rect
    assertTrue(rect.width > 0 && rect.height > 0, "Control has no hit-test bounds")
    val centerX = rect.x + rect.width / 2
    val centerY = rect.y + rect.height / 2
    val devTools = (driver as HasDevTools).devTools
    fun dispatchMouse(
        type: Input.DispatchMouseEventType,
        button: MouseButton,
        buttons: Int,
        clickCount: Int,
    ) {
        devTools.send(
            Input.dispatchMouseEvent(
                type,
                centerX,
                centerY,
                Optional.empty(),
                Optional.empty(),
                Optional.of(button),
                Optional.of(buttons),
                Optional.of(clickCount),
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
            ),
        )
    }
    dispatchMouse(Input.DispatchMouseEventType.MOUSEMOVED, MouseButton.NONE, 0, 0)
    dispatchMouse(Input.DispatchMouseEventType.MOUSEPRESSED, MouseButton.LEFT, 1, 1)
    dispatchMouse(Input.DispatchMouseEventType.MOUSERELEASED, MouseButton.LEFT, 0, 1)
}

private fun credentialsTextField(driver: WebDriver, label: String): WebElement? = runCatching {
    credentialsSemanticElements(driver).firstOrNull { element ->
        element.ariaRole == "textbox" &&
            element.credentialsSemanticValues().any { value ->
            value.lineSequence().any { line -> line.trim() == label }
        }
    }
}.getOrNull()

private fun renderedCredentialsSurface(driver: ChromeDriver): String = buildString {
    credentialsSemanticElements(driver).forEach { element ->
        element.credentialsSemanticValues().forEach {
            append(it)
            append('\n')
        }
        append(element.getDomProperty("value").orEmpty())
        append('\n')
    }
    credentialsDashboardShadow(driver)
        .findElements(By.cssSelector("input, textarea, [contenteditable='true']"))
        .forEach { element ->
            append(element.getDomProperty("value").orEmpty())
            append(element.getDomProperty("innerText").orEmpty())
            append('\n')
        }
    append(
        (driver as JavascriptExecutor).executeScript(
            "return arguments[0].shadowRoot ? arguments[0].shadowRoot.innerHTML : '';",
            resolveDashboardShadowHost(driver.findElement(By.id("dashboard-root"))),
        )?.toString().orEmpty(),
    )
}

private fun credentialsSemanticElements(driver: WebDriver): List<WebElement> =
    credentialsDashboardShadow(driver).findElements(By.cssSelector("#cmp_a11y_root *"))

private fun credentialsDashboardShadow(driver: WebDriver): SearchContext =
    resolveDashboardHost(driver.findElement(By.id("dashboard-root")))

private fun WebElement.credentialsSemanticValues(): List<String> = listOf(
    getDomProperty("innerText").orEmpty().trim(),
    accessibleName.orEmpty().trim(),
).filter(String::isNotEmpty)

private data class CredentialTarget(
    val address: String,
    val provider: Provider,
    val providerAccountId: String?,
)

private data class CredentialInvocation(
    val address: String,
    val provider: Provider,
    val providerAccountId: String?,
    val password: String,
)

private class CredentialsBrowserBackend : DashboardBackend {
    private val ready = AtomicBoolean(false)
    val listAccountCalls = AtomicInteger(0)
    val authenticationProbes = CopyOnWriteArrayList<AuthenticationProbeRequest>()
    val adoptPasswordCalls = CopyOnWriteArrayList<CredentialInvocation>()
    val changePasswordCalls = CopyOnWriteArrayList<CredentialInvocation>()
    val folderRequests = CopyOnWriteArrayList<CredentialTarget>()

    override suspend fun listAccounts(): AccountListResponse {
        listAccountCalls.incrementAndGet()
        return AccountListResponse(
            accounts = listOf(
                AccountInfo(
                    address = CREDENTIAL_ACCOUNT,
                    provider = Provider.STALWART,
                    protocols = listOf(MailProtocol.JMAP, MailProtocol.SMTP),
                    credentialReadiness = if (ready.get()) {
                        CredentialReadiness.READY
                    } else {
                        CredentialReadiness.PASSWORD_REQUIRED
                    },
                    providerAccountId = CREDENTIAL_PROVIDER_ID,
                ),
            ),
            providerStatuses = listOf(
                ProviderStatus(Provider.DOVECOT, ProviderAvailability.READY),
                ProviderStatus(Provider.STALWART, ProviderAvailability.READY),
            ),
        )
    }

    override suspend fun probeAuthentication(
        request: AuthenticationProbeRequest,
    ): AuthenticationProbeResponse {
        authenticationProbes += request
        val secret = request.credentialOverride.orEmpty()
        return AuthenticationProbeResponse(
            address = request.address,
            provider = request.provider,
            protocol = request.protocol,
            success = false,
            providerResponse = "provider rejected $secret",
            correlatedLogs = listOf("correlated credential=$secret"),
        )
    }

    override suspend fun adoptPassword(
        address: String,
        provider: Provider,
        providerAccountId: String?,
        request: AdoptPasswordRequest,
    ): CredentialUpdateResponse {
        adoptPasswordCalls += CredentialInvocation(address, provider, providerAccountId, request.password)
        ready.set(true)
        return credentialReadyResponse(address, provider, "Existing password verified")
    }

    override suspend fun changePassword(
        address: String,
        provider: Provider,
        providerAccountId: String?,
        request: ChangePasswordRequest,
    ): CredentialUpdateResponse {
        changePasswordCalls += CredentialInvocation(address, provider, providerAccountId, request.newPassword)
        ready.set(true)
        return credentialReadyResponse(address, provider, "Password reset")
    }

    override suspend fun listFolders(
        address: String,
        provider: Provider,
        providerAccountId: String?,
    ): FolderListResponse {
        folderRequests += CredentialTarget(address, provider, providerAccountId)
        return FolderListResponse(
            folders = listOf(FolderInfo(id = "INBOX", name = "Inbox", totalMessages = 0, unreadMessages = 0)),
        )
    }

    override suspend fun listMessages(
        address: String,
        provider: Provider,
        providerAccountId: String?,
        folderId: String?,
    ): MessageListResponse = MessageListResponse(emptyList())

    override suspend fun logs(service: LogService): LogResponse = LogResponse(service, lines = emptyList())

    override suspend fun accountLogs(
        address: String,
        provider: Provider,
        providerAccountId: String?,
    ): LogResponse = LogResponse(LogService.ALL, account = address, lines = emptyList())

    override suspend fun createAccount(request: CreateAccountRequest): AccountInfo = unexpected()

    override suspend fun deleteAccount(
        address: String,
        provider: Provider,
        providerAccountId: String?,
    ): OperationResponse = unexpected()

    override suspend fun createFolder(
        address: String,
        provider: Provider,
        providerAccountId: String?,
        request: CreateFolderRequest,
    ): FolderInfo = unexpected()

    override suspend fun deleteFolder(
        address: String,
        provider: Provider,
        providerAccountId: String?,
        folderId: String,
    ): OperationResponse = unexpected()

    override suspend fun readMessage(
        address: String,
        provider: Provider,
        providerAccountId: String?,
        messageId: String,
        folderId: String?,
    ): MessageDetail = unexpected()

    override suspend fun mutateMessages(
        address: String,
        provider: Provider,
        providerAccountId: String?,
        request: MutateMessagesRequest,
    ): OperationResponse = unexpected()

    override suspend fun generateMessage(request: GenerateMessageRequest): GenerateMessageResponse = unexpected()

    private fun credentialReadyResponse(
        address: String,
        provider: Provider,
        message: String,
    ): CredentialUpdateResponse = CredentialUpdateResponse(
        address = address,
        provider = provider,
        readiness = CredentialReadiness.READY,
        operation = OperationResponse(success = true, message = message),
    )

    private fun <T> unexpected(): T = error("Unexpected credentials browser-backend operation")
}

private const val CREDENTIAL_ACCOUNT = "credentials@local.test"
private const val CREDENTIAL_PROVIDER_ID = "stalwart-credential-account-id"
private const val PROBE_SECRET = "probe-only-secret-8F6B44"
private const val ADOPTED_PASSWORD = "existing-password-2C8D61"
private const val RESET_PASSWORD = "reset-password-4A7E93"
private val CREDENTIAL_TARGET = CredentialTarget(
    address = CREDENTIAL_ACCOUNT,
    provider = Provider.STALWART,
    providerAccountId = CREDENTIAL_PROVIDER_ID,
)
