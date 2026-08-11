package mail.sandbox.dashboard.server.web

import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import java.nio.file.Files
import java.nio.file.Path
import java.time.Duration
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking
import mail.sandbox.dashboard.contract.AccountInfo
import mail.sandbox.dashboard.contract.AccountListResponse
import mail.sandbox.dashboard.contract.AdoptPasswordRequest
import mail.sandbox.dashboard.contract.AuthenticationProbeRequest
import mail.sandbox.dashboard.contract.AuthenticationProbeResponse
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
import org.openqa.selenium.interactions.Actions
import org.openqa.selenium.support.ui.WebDriverWait

/** Rendered account-creation contracts for the production Compose/Wasm dashboard. */
class DashboardReadinessCreationBrowserTest {
    @Test
    fun accountCreationEnforcesProviderCapabilitiesInTheRealWasmApp() {
        val backend = CreationBrowserBackend()

        withCreationBrowser(backend) { driver, wait ->
            waitForCreationAccessibleName(wait, "Provider status Dovecot: ready")
            waitForCreationAccessibleName(wait, "Provider status Stalwart: ready")
            waitForCreationText(wait, "No account channels")

            clickCreationButton(driver, wait, "Add account")
            waitForCreationText(wait, "Create account channel")
            waitForCreationText(wait, "Dovecot fixed account capabilities")
            assertEquals(
                setOf(
                    "Protocol IMAP: live",
                    "Protocol POP3: live",
                    "Protocol SMTP: live",
                ),
                creationSemanticElements(driver)
                    .map { it.accessibleName.orEmpty() }
                    .filter { it.startsWith("Protocol ") }
                    .toSet(),
                "Dovecot must render exactly its fixed IMAP, POP3, and SMTP protocol chips",
            )
            assertEquals(
                emptyList(),
                creationSemanticElements(driver).filter { element ->
                    element.ariaRole == "button" && element.accessibleName in setOf(
                        STALWART_JMAP_TOGGLE_NAME,
                        STALWART_SMTP_TOGGLE_NAME,
                    )
                },
                "Dovecot capabilities must be fixed text/chips, not editable protocol toggles",
            )

            fillCreationTextField(driver, wait, "Email address", DOVECOT_CREATION_ADDRESS)
            fillCreationTextField(driver, wait, "Account password", CREATION_PASSWORD)
            clickCreationButton(driver, wait, "Create account")
            wait.until { backend.createRequests.size == 1 }

            assertEquals(
                CreateAccountRequest(
                    address = DOVECOT_CREATION_ADDRESS,
                    password = CREATION_PASSWORD,
                    provider = Provider.DOVECOT,
                    protocols = listOf(MailProtocol.IMAP, MailProtocol.POP3, MailProtocol.SMTP),
                ),
                backend.createRequests.single(),
            )
            driver.navigate().refresh()
            waitForCreationText(wait, DOVECOT_CREATION_ADDRESS)

            clickCreationButton(driver, wait, "Add account")
            waitForCreationText(wait, "Create account channel")
            clickCreationButton(driver, wait, "Stalwart")
            waitForCreationText(
                wait,
                "Select the enforced Stalwart account permissions. At least one is required.",
            )

            waitForCreationToggle(wait, STALWART_JMAP_TOGGLE_NAME)
            val smtpToggle = waitForCreationToggle(wait, STALWART_SMTP_TOGGLE_NAME)
            val mailProtocolNames = MailProtocol.entries.map(MailProtocol::name).toSet()
            assertEquals(
                setOf(STALWART_JMAP_TOGGLE_NAME, STALWART_SMTP_TOGGLE_NAME),
                creationSemanticElements(driver)
                    .asSequence()
                    .filter { it.ariaRole == "button" }
                    .map { it.accessibleName.orEmpty() }
                    .filter { it.substringBefore(' ') in mailProtocolNames }
                    .toSet(),
                "Stalwart must render exactly the JMAP and SMTP protocol choices",
            )
            (driver as JavascriptExecutor).executeScript("arguments[0].click();", smtpToggle)

            fillCreationTextField(driver, wait, "Email address", STALWART_CREATION_ADDRESS)
            fillCreationTextField(driver, wait, "Account password", CREATION_PASSWORD)
            clickCreationButton(driver, wait, "Create account")
            wait.until { backend.createRequests.size == 2 }

            assertEquals(
                CreateAccountRequest(
                    address = STALWART_CREATION_ADDRESS,
                    password = CREATION_PASSWORD,
                    provider = Provider.STALWART,
                    protocols = listOf(MailProtocol.JMAP),
                ),
                backend.createRequests.last(),
            )
            wait.until {
                backend.folderRequests.any {
                    it.address == STALWART_CREATION_ADDRESS &&
                        it.provider == Provider.STALWART &&
                        it.providerAccountId == STALWART_CREATION_PROVIDER_ID
                }
            }
            waitForCreationText(wait, STALWART_CREATION_ADDRESS)
        }
    }
}

private fun withCreationBrowser(
    backend: CreationBrowserBackend,
    block: (ChromeDriver, WebDriverWait) -> Unit,
) {
    val projectRoot = creationDashboardProjectRoot()
    val server = embeddedServer(
        factory = Netty,
        port = 0,
        host = "127.0.0.1",
    ) {
        configureDashboard(
            webAssets = WebAssetBundle.fromEnvironment(projectRoot = projectRoot),
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
                "--window-size=1440,1200",
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
        println("CREATION_BROWSER_URL=${driver.currentUrl}")
        println("CREATION_BROWSER_SOURCE=${driver.pageSource.take(2_000)}")
        println(
            "CREATION_BROWSER_SHADOW=" + runCatching {
                creationDashboardShadow(driver).findElements(By.cssSelector("*")).map { element ->
                    "${element.tagName}:${element.ariaRole}:${element.accessibleName}:${element.creationSemanticText()}"
                }
            }.getOrElse { listOf("ERROR:$it") },
        )
        println("CREATION_BROWSER_LOGS=${runCatching { driver.manage().logs().get("browser").all }.getOrNull()}")
        throw failure
    } finally {
        runCatching { driver.quit() }
        server.stop(gracePeriodMillis = 500, timeoutMillis = 2_000)
    }
}

private fun creationDashboardProjectRoot(): Path {
    val working = Path.of(System.getProperty("user.dir")).toAbsolutePath().normalize()
    return generateSequence(working) { it.parent }
        .firstOrNull { Files.isDirectory(it.resolve("dashboard-web")) }
        ?: error("Could not locate the debug-dashboard project root")
}

private fun waitForCreationText(wait: WebDriverWait, expected: String): WebElement = wait.until { driver ->
    runCatching {
        creationSemanticElements(driver).firstOrNull { element ->
            element.creationSemanticText() == expected
        }
    }.getOrNull()
}

private fun waitForCreationAccessibleName(wait: WebDriverWait, expected: String): WebElement = wait.until { driver ->
    runCatching {
        creationSemanticElements(driver).firstOrNull { element ->
            element.accessibleName.orEmpty().trim() == expected
        }
    }.getOrNull()
}

private fun clickCreationButton(
    driver: ChromeDriver,
    wait: WebDriverWait,
    expected: String,
) {
    val button = wait.until { current ->
        runCatching {
            creationSemanticElements(current).firstOrNull { element ->
                element.ariaRole == "button" &&
                    element.getDomAttribute("aria-disabled") != "true" &&
                    element.creationSemanticText().lineSequence().any { it.trim() == expected }
            }
        }.getOrNull()
    }
    (driver as JavascriptExecutor).executeScript("arguments[0].click();", button)
}

private fun fillCreationTextField(
    driver: ChromeDriver,
    wait: WebDriverWait,
    accessibleLabel: String,
    value: String,
) {
    val field = wait.until { driver ->
        runCatching {
            creationSemanticElements(driver)
                .firstOrNull { element ->
                    element.ariaRole == "textbox" && element.accessibleName == accessibleLabel
                }
        }.getOrNull()
    }
    val rect = field.rect
    assertTrue(rect.width > 0 && rect.height > 0, "$accessibleLabel has no hit-test bounds")
    Actions(driver)
        .moveToLocation(rect.x + rect.width / 2, rect.y + rect.height / 2)
        .click()
        .sendKeys(value)
        .perform()
    wait.until {
        val renderedValue = field.creationSemanticText()
        renderedValue.isNotBlank() && (accessibleLabel != "Email address" || renderedValue == value)
    }
}

private fun waitForCreationToggle(wait: WebDriverWait, accessibleName: String): WebElement = wait.until { driver ->
    runCatching {
        creationSemanticElements(driver).firstOrNull { element ->
            element.ariaRole == "button" && element.accessibleName == accessibleName
        }
    }.getOrNull()
}

private fun creationSemanticElements(driver: WebDriver): List<WebElement> =
    creationDashboardShadow(driver).findElements(By.cssSelector("#cmp_a11y_root *"))

private fun creationDashboardShadow(driver: WebDriver): SearchContext =
    resolveDashboardHost(driver.findElement(By.id("dashboard-root")))

private fun WebElement.creationSemanticText(): String =
    getDomProperty("innerText")?.trim().orEmpty().ifBlank { accessibleName.orEmpty().trim() }

private data class CreationFolderRequest(
    val address: String,
    val provider: Provider,
    val providerAccountId: String?,
)

private class CreationBrowserBackend : DashboardBackend {
    val createRequests = CopyOnWriteArrayList<CreateAccountRequest>()
    val folderRequests = CopyOnWriteArrayList<CreationFolderRequest>()
    private val accounts = CopyOnWriteArrayList<AccountInfo>()

    override suspend fun listAccounts(): AccountListResponse = AccountListResponse(
        accounts = accounts.toList(),
        providerStatuses = listOf(
            ProviderStatus(Provider.DOVECOT, ProviderAvailability.READY),
            ProviderStatus(Provider.STALWART, ProviderAvailability.READY),
        ),
    )

    override suspend fun createAccount(request: CreateAccountRequest): AccountInfo {
        createRequests += request
        return AccountInfo(
            address = request.address,
            provider = request.provider,
            protocols = request.protocols,
            credentialReadiness = CredentialReadiness.READY,
            providerAccountId = STALWART_CREATION_PROVIDER_ID.takeIf {
                request.provider == Provider.STALWART
            },
        ).also(accounts::add)
    }

    override suspend fun logs(service: LogService): LogResponse = LogResponse(service, lines = emptyList())

    override suspend fun accountLogs(
        address: String,
        provider: Provider,
        providerAccountId: String?,
    ): LogResponse = LogResponse(LogService.ALL, account = address, lines = emptyList())

    override suspend fun listFolders(
        address: String,
        provider: Provider,
        providerAccountId: String?,
    ): FolderListResponse {
        folderRequests += CreationFolderRequest(address, provider, providerAccountId)
        return FolderListResponse(emptyList())
    }

    override suspend fun listMessages(
        address: String,
        provider: Provider,
        providerAccountId: String?,
        folderId: String?,
    ): MessageListResponse = MessageListResponse(emptyList())

    override suspend fun deleteAccount(
        address: String,
        provider: Provider,
        providerAccountId: String?,
    ): OperationResponse = creationUnsupported()

    override suspend fun adoptPassword(
        address: String,
        provider: Provider,
        providerAccountId: String?,
        request: AdoptPasswordRequest,
    ): CredentialUpdateResponse = creationUnsupported()

    override suspend fun changePassword(
        address: String,
        provider: Provider,
        providerAccountId: String?,
        request: ChangePasswordRequest,
    ): CredentialUpdateResponse = creationUnsupported()

    override suspend fun probeAuthentication(
        request: AuthenticationProbeRequest,
    ): AuthenticationProbeResponse = creationUnsupported()

    override suspend fun createFolder(
        address: String,
        provider: Provider,
        providerAccountId: String?,
        request: CreateFolderRequest,
    ): FolderInfo = creationUnsupported()

    override suspend fun deleteFolder(
        address: String,
        provider: Provider,
        providerAccountId: String?,
        folderId: String,
    ): OperationResponse = creationUnsupported()

    override suspend fun readMessage(
        address: String,
        provider: Provider,
        providerAccountId: String?,
        messageId: String,
        folderId: String?,
    ): MessageDetail = creationUnsupported()

    override suspend fun mutateMessages(
        address: String,
        provider: Provider,
        providerAccountId: String?,
        request: MutateMessagesRequest,
    ): OperationResponse = creationUnsupported()

    override suspend fun generateMessage(
        request: GenerateMessageRequest,
    ): GenerateMessageResponse = creationUnsupported()

    private fun <T> creationUnsupported(): T = error("Unexpected account-creation browser operation")
}

private const val DOVECOT_CREATION_ADDRESS = "browser-dovecot@local.test"
private const val STALWART_CREATION_ADDRESS = "browser-stalwart@local.test"
private const val STALWART_CREATION_PROVIDER_ID = "stalwart-browser-account-id"
private const val CREATION_PASSWORD = "browser-password"
private const val STALWART_JMAP_TOGGLE_NAME = "JMAP Stalwart JMAP mailbox operations"
private const val STALWART_SMTP_TOGGLE_NAME = "SMTP Message submission and delivery"
