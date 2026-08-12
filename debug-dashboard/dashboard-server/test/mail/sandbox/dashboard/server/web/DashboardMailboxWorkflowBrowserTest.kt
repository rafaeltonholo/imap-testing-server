package mail.sandbox.dashboard.server.web

import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import java.nio.file.Files
import java.nio.file.Path
import java.time.Duration
import java.util.Optional
import java.util.concurrent.CopyOnWriteArrayList
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
import mail.sandbox.dashboard.contract.MessageAction
import mail.sandbox.dashboard.contract.MessageDeliveryMode
import mail.sandbox.dashboard.contract.MessageDetail
import mail.sandbox.dashboard.contract.MessageListResponse
import mail.sandbox.dashboard.contract.MessageSourceType
import mail.sandbox.dashboard.contract.MessageSummary
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
import org.openqa.selenium.interactions.Actions
import org.openqa.selenium.support.ui.WebDriverWait

/** Rendered mailbox workflows against the production Compose/Wasm dashboard and HTTP API. */
class DashboardMailboxWorkflowBrowserTest {
    @Test
    fun mailboxFolderMessageAndAccountOperationsUseTheExactSelectedChannel() {
        val backend = MailboxWorkflowBrowserBackend()

        withMailboxWorkflowBrowser(backend) { driver, wait ->
            waitForMailboxText(wait, MAILBOX_ACCOUNT)
            waitForMailboxText(wait, ACCOUNT_TRACE_LINE)
            wait.until { backend.accountLogTargets.isNotEmpty() }
            assertEquals(MAILBOX_TARGET, backend.accountLogTargets.last())

            clickMailboxControl(driver, wait, "Server logs")
            clickMailboxAccessibleControl(driver, wait, "Stalwart")
            waitForMailboxText(wait, STALWART_TRACE_LINE)
            wait.until { backend.globalLogRequests.lastOrNull() == LogService.STALWART }

            createMailboxFolder(driver, wait, backend, "Scratch", expectedRequestCount = 1)
            clickMailboxAccessibleControl(driver, wait, "Delete folder Scratch")
            waitForMailboxText(wait, "Delete folder?")
            clickMailboxControl(driver, wait, "Delete folder", preferLast = true)
            wait.until { backend.deletedFolderIds == listOf("scratch") }
            driver.navigate().refresh()
            waitForMailboxAccessibleNameToDisappear(wait, "Delete folder Scratch")

            createMailboxFolder(driver, wait, backend, "Archive", expectedRequestCount = 2)
            clickMailboxControl(driver, wait, "Inbox")
            clickMailboxAccessibleControl(driver, wait, INITIAL_MESSAGE_ACCESSIBLE_NAME)
            waitForMailboxText(wait, INITIAL_MESSAGE_BODY)
            wait.until { backend.readTargets.isNotEmpty() }
            assertEquals(MAILBOX_TARGET, backend.readTargets.last().target)
            assertEquals(INITIAL_MESSAGE_ID, backend.readTargets.last().messageId)
            assertEquals(INBOX_ID, backend.readTargets.last().folderId)

            clickMailboxControl(driver, wait, "Mark read")
            waitForMailboxAccessibleName(wait, READ_MESSAGE_ACCESSIBLE_NAME)
            wait.until { backend.mutationRequests.size == 1 }
            clickMailboxControl(driver, wait, "Mark unread")
            waitForMailboxAccessibleName(wait, INITIAL_MESSAGE_ACCESSIBLE_NAME)
            wait.until { backend.mutationRequests.size == 2 }
            clickMailboxControl(driver, wait, "Flag")
            waitForMailboxAccessibleName(wait, FLAGGED_MESSAGE_ACCESSIBLE_NAME)
            wait.until { backend.mutationRequests.size == 3 }
            clickMailboxControl(driver, wait, "Unflag")
            waitForMailboxAccessibleName(wait, INITIAL_MESSAGE_ACCESSIBLE_NAME)
            wait.until { backend.mutationRequests.size == 4 }

            clickMailboxAccessibleControl(driver, wait, "Message destination Archive")
            clickMailboxControl(driver, wait, "Copy")
            wait.until { backend.mutationRequests.size == 5 }
            clickMailboxControl(driver, wait, "Move")
            wait.until { backend.mutationRequests.size == 6 }
            waitForMailboxAccessibleNameToDisappear(wait, INITIAL_MESSAGE_ACCESSIBLE_NAME)

            clickMailboxControl(driver, wait, "Archive")
            clickMailboxAccessibleControl(driver, wait, INITIAL_MESSAGE_ACCESSIBLE_NAME)
            waitForMailboxText(wait, INITIAL_MESSAGE_BODY)
            clickMailboxAccessibleControl(driver, wait, "Trash message")
            wait.until { backend.mutationRequests.size == 7 }

            clickMailboxControl(driver, wait, "Trash")
            clickMailboxAccessibleControl(driver, wait, INITIAL_MESSAGE_ACCESSIBLE_NAME)
            clickMailboxControl(driver, wait, "Delete permanently")
            waitForMailboxText(wait, "Delete message permanently?")
            clickMailboxControl(driver, wait, "Delete message")
            wait.until { backend.mutationRequests.size == 8 }
            driver.navigate().refresh()
            waitForMailboxText(wait, "This folder is empty")

            clickMailboxControl(driver, wait, "Delete account")
            waitForMailboxText(wait, "Delete account channel?")
            clickMailboxControl(driver, wait, "Delete account", preferLast = true)
            wait.until { !backend.accountExists }
            driver.navigate().refresh()
            waitForMailboxText(wait, "No account channels")

            assertEquals(listOf("Scratch", "Archive"), backend.createdFolderNames)
            assertEquals(
                listOf(
                    MessageAction.MARK_READ,
                    MessageAction.MARK_UNREAD,
                    MessageAction.FLAG,
                    MessageAction.UNFLAG,
                    MessageAction.COPY,
                    MessageAction.MOVE,
                    MessageAction.TRASH,
                    MessageAction.DELETE,
                ),
                backend.mutationRequests.map(MutateMessagesRequest::action),
            )
            assertEquals("archive", backend.mutationRequests[4].destinationFolderId)
            assertEquals("archive", backend.mutationRequests[5].destinationFolderId)
            assertEquals(null, backend.mutationRequests[6].destinationFolderId)
            assertEquals(null, backend.mutationRequests[7].destinationFolderId)
            assertEquals(INBOX_ID, backend.mutationRequests[4].sourceFolderId)
            assertEquals(INBOX_ID, backend.mutationRequests[5].sourceFolderId)
            assertEquals("archive", backend.mutationRequests[6].sourceFolderId)
            assertEquals(TRASH_ID, backend.mutationRequests[7].sourceFolderId)
            backend.mutationRequests.forEach { request ->
                assertEquals(MAILBOX_ACCOUNT, request.account)
                assertEquals(Provider.STALWART, request.provider)
                assertEquals(MAILBOX_PROVIDER_ACCOUNT_ID, request.providerAccountId)
            }
            assertTrue(backend.targetCalls.isNotEmpty(), "The workflow did not exercise targeted API routes")
            assertEquals(
                setOf(MAILBOX_TARGET),
                backend.targetCalls.map(WorkflowTargetCall::target).toSet(),
                "Every route must retain the exact address/provider/providerAccountId channel identity",
            )
            assertFalse(backend.accountExists)
        }
    }

    @Test
    fun emlTextAndSeededSmtpGenerationRenderAndSendExactRequests() {
        val backend = MailboxWorkflowBrowserBackend()

        withMailboxWorkflowBrowser(backend) { driver, wait ->
            waitForMailboxText(wait, MAILBOX_ACCOUNT)

            clickMailboxControl(driver, wait, "Generate message")
            waitForMailboxText(wait, "Create test message")
            clickMailboxControl(driver, wait, "Raw EML")
            enterMailboxText(driver, wait, "Raw .eml / RFC 5322 content", RAW_EML)
            clickMailboxControl(driver, wait, "Append message")
            wait.until { backend.generationRequests.size == 1 }
            driver.navigate().refresh()
            clickMailboxAccessibleControl(driver, wait, EML_MESSAGE_ACCESSIBLE_NAME)
            wait.until { backend.readTargets.any { it.messageId == "generated-1" } }
            waitForMailboxText(wait, EML_BODY)

            clickMailboxControl(driver, wait, "Generate message")
            enterMailboxText(driver, wait, "Plain-text body", AUTHORED_BODY)
            clickMailboxControl(driver, wait, "Append message")
            wait.until { backend.generationRequests.size == 2 }
            driver.navigate().refresh()
            clickMailboxAccessibleControl(driver, wait, GENERATED_MESSAGE_ACCESSIBLE_NAME)
            waitForMailboxText(wait, AUTHORED_BODY)

            clickMailboxControl(driver, wait, "Generate message")
            clickMailboxControl(driver, wait, "SMTP delivery")
            clickMailboxControl(driver, wait, "Random fixture")
            enterMailboxText(driver, wait, "Deterministic seed (optional)", RANDOM_SEED.toString())
            clickMailboxControl(driver, wait, "Send via SMTP")
            wait.until { backend.generationRequests.size == 3 }
            driver.navigate().refresh()
            clickMailboxAccessibleControl(
                driver,
                wait,
                GENERATED_MESSAGE_ACCESSIBLE_NAME,
                preferLast = true,
            )
            waitForMailboxText(wait, RANDOM_BODY)

            assertEquals(
                listOf(
                    GenerateMessageRequest(
                        targetAccount = MAILBOX_ACCOUNT,
                        provider = Provider.STALWART,
                        providerAccountId = MAILBOX_PROVIDER_ACCOUNT_ID,
                        sourceType = MessageSourceType.EML,
                        deliveryMode = MessageDeliveryMode.DIRECT_APPEND,
                        content = RAW_EML,
                        subject = DEFAULT_GENERATED_SUBJECT,
                        seed = null,
                        folderId = INBOX_ID,
                        count = 1,
                        fromAddress = DEFAULT_GENERATED_FROM,
                    ),
                    GenerateMessageRequest(
                        targetAccount = MAILBOX_ACCOUNT,
                        provider = Provider.STALWART,
                        providerAccountId = MAILBOX_PROVIDER_ACCOUNT_ID,
                        sourceType = MessageSourceType.TEXT,
                        deliveryMode = MessageDeliveryMode.DIRECT_APPEND,
                        content = AUTHORED_BODY,
                        subject = DEFAULT_GENERATED_SUBJECT,
                        seed = null,
                        folderId = INBOX_ID,
                        count = 1,
                        fromAddress = DEFAULT_GENERATED_FROM,
                    ),
                    GenerateMessageRequest(
                        targetAccount = MAILBOX_ACCOUNT,
                        provider = Provider.STALWART,
                        providerAccountId = MAILBOX_PROVIDER_ACCOUNT_ID,
                        sourceType = MessageSourceType.RANDOM,
                        deliveryMode = MessageDeliveryMode.SMTP_DELIVERY,
                        content = null,
                        subject = DEFAULT_GENERATED_SUBJECT,
                        seed = RANDOM_SEED,
                        folderId = null,
                        count = 1,
                        fromAddress = DEFAULT_GENERATED_FROM,
                    ),
                ),
                backend.generationRequests,
            )
            assertEquals(
                setOf(MAILBOX_ACCOUNT),
                backend.generationRequests.map(GenerateMessageRequest::targetAccount).toSet(),
            )
            assertEquals(
                setOf(Provider.STALWART),
                backend.generationRequests.map(GenerateMessageRequest::provider).toSet(),
            )
            assertEquals(
                setOf(MAILBOX_PROVIDER_ACCOUNT_ID),
                backend.generationRequests.map(GenerateMessageRequest::providerAccountId).toSet(),
            )
        }
    }
}

private fun createMailboxFolder(
    driver: ChromeDriver,
    wait: WebDriverWait,
    backend: MailboxWorkflowBrowserBackend,
    name: String,
    expectedRequestCount: Int,
) {
    clickMailboxAccessibleControl(driver, wait, "Create folder")
    waitForMailboxText(wait, "Create folder")
    enterMailboxText(driver, wait, "Folder name", name)
    clickMailboxControl(driver, wait, "Create folder", preferLast = true)
    wait.until { backend.createdFolderNames.size == expectedRequestCount }
    driver.navigate().refresh()
    waitForMailboxAccessibleName(wait, "Delete folder $name")
}

private fun withMailboxWorkflowBrowser(
    backend: MailboxWorkflowBrowserBackend,
    block: (ChromeDriver, WebDriverWait) -> Unit,
) {
    val projectRoot = mailboxWorkflowProjectRoot()
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
                "--window-size=1600,2000",
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
        val screenshot = Files.createTempFile("dashboard-mailbox-workflow-", ".png")
        Files.write(screenshot, (driver as TakesScreenshot).getScreenshotAs(OutputType.BYTES))
        println("MAILBOX_BROWSER_URL=${driver.currentUrl}")
        println("MAILBOX_BROWSER_SCREENSHOT=$screenshot")
        println(
            "MAILBOX_BROWSER_BACKEND=" +
                "targets=${backend.targetCalls.size}," +
                "folders=${backend.createdFolderNames}," +
                "mutations=${backend.mutationRequests.map(MutateMessagesRequest::action)}," +
                "generations=${backend.generationRequests.map(GenerateMessageRequest::sourceType)}",
        )
        println("MAILBOX_BROWSER_SURFACE=${runCatching { renderedMailboxSurface(driver) }.getOrNull()}")
        println("MAILBOX_BROWSER_LOGS=${runCatching { driver.manage().logs().get("browser").all }.getOrNull()}")
        throw failure
    } finally {
        runCatching { driver.quit() }
        server.stop(gracePeriodMillis = 500, timeoutMillis = 2_000)
    }
}

private fun mailboxWorkflowProjectRoot(): Path {
    val working = Path.of(System.getProperty("user.dir")).toAbsolutePath().normalize()
    return generateSequence(working) { it.parent }
        .firstOrNull { Files.isDirectory(it.resolve("dashboard-web")) }
        ?: error("Could not locate the debug-dashboard project root")
}

private fun waitForMailboxText(wait: WebDriverWait, expected: String): WebElement = wait.until { driver ->
    runCatching {
        mailboxWorkflowSemanticElements(driver).firstOrNull { element ->
            element.mailboxSemanticValues().any { value ->
                value == expected || value.lineSequence().any { line -> line.trim() == expected }
            }
        }
    }.getOrNull()
}

private fun waitForMailboxAccessibleName(wait: WebDriverWait, expected: String): WebElement =
    wait.until { driver ->
        runCatching {
            mailboxWorkflowSemanticElements(driver).firstOrNull { element ->
                element.accessibleName.orEmpty().trim() == expected
            }
        }.getOrNull()
    }

private fun waitForMailboxAccessibleNameToDisappear(wait: WebDriverWait, expected: String) {
    wait.until { driver ->
        runCatching {
            mailboxWorkflowSemanticElements(driver).none { element ->
                element.accessibleName.orEmpty().trim() == expected
            }
        }.getOrDefault(false)
    }
}

private fun clickMailboxControl(
    driver: ChromeDriver,
    wait: WebDriverWait,
    expected: String,
    preferLast: Boolean = false,
) {
    val control = wait.until { current ->
        runCatching {
            val matches = mailboxWorkflowSemanticElements(current).filter { element ->
                element.ariaRole in MAILBOX_CLICKABLE_ROLES &&
                    element.getDomAttribute("aria-disabled") != "true" &&
                    element.mailboxSemanticValues().any { value ->
                        value.lineSequence().any { line -> line.trim() == expected }
                    }
            }
            if (preferLast) matches.lastOrNull() else matches.firstOrNull()
        }.getOrNull()
    }
    dispatchTrustedMailboxClick(driver, control)
}

private fun clickMailboxAccessibleControl(
    driver: ChromeDriver,
    wait: WebDriverWait,
    expected: String,
    preferLast: Boolean = false,
) {
    wait.until { current ->
        runCatching {
            val matches = mailboxWorkflowSemanticElements(current).filter { element ->
                element.ariaRole in MAILBOX_CLICKABLE_ROLES &&
                    element.getDomAttribute("aria-disabled") != "true" &&
                    element.accessibleName.orEmpty().trim() == expected
            }
            val control = if (preferLast) matches.lastOrNull() else matches.firstOrNull()
            control?.let {
                dispatchTrustedMailboxClick(driver, it)
                true
            }
        }.getOrNull() == true
    }
}

private fun enterMailboxText(
    driver: ChromeDriver,
    wait: WebDriverWait,
    label: String,
    value: String,
) {
    val field = wait.until { current -> mailboxTextField(current, label) }
    (driver as JavascriptExecutor).executeScript(
        "arguments[0].scrollIntoView({block: 'center', inline: 'center'});",
        field,
    )
    driver.executeAsyncScript(
        "const done = arguments[arguments.length - 1];" +
            "requestAnimationFrame(() => requestAnimationFrame(done));",
    )
    dispatchTrustedMailboxClick(driver, field)
    wait.until { current ->
        mailboxWorkflowShadow(current)
            .findElements(By.cssSelector("input, textarea"))
            .firstOrNull()
    }
    Actions(driver).sendKeys(value).perform()
    driver.executeAsyncScript(
        "const done = arguments[arguments.length - 1];" +
            "requestAnimationFrame(() => requestAnimationFrame(done));",
    )
}

private fun mailboxTextField(driver: WebDriver, label: String): WebElement? = runCatching {
    mailboxWorkflowSemanticElements(driver).firstOrNull { element ->
        element.ariaRole == "textbox" &&
            element.mailboxSemanticValues().any { value ->
                value.lineSequence().any { line -> line.trim() == label }
            }
    }
}.getOrNull()

private fun dispatchTrustedMailboxClick(driver: ChromeDriver, element: WebElement) {
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

private fun renderedMailboxSurface(driver: ChromeDriver): String = buildString {
    mailboxWorkflowSemanticElements(driver).forEach { element ->
        element.mailboxSemanticValues().forEach {
            append(it)
            append('\n')
        }
    }
}

private fun mailboxWorkflowSemanticElements(driver: WebDriver): List<WebElement> =
    mailboxWorkflowShadow(driver).findElements(By.cssSelector("#cmp_a11y_root *"))

private fun mailboxWorkflowShadow(driver: WebDriver): SearchContext =
    resolveDashboardHost(driver.findElement(By.id("dashboard-root")))

private fun WebElement.mailboxSemanticValues(): List<String> = listOf(
    getDomProperty("innerText").orEmpty().trim(),
    accessibleName.orEmpty().trim(),
).filter(String::isNotEmpty)

private data class WorkflowTarget(
    val address: String,
    val provider: Provider,
    val providerAccountId: String?,
)

private data class WorkflowTargetCall(
    val operation: String,
    val target: WorkflowTarget,
)

private data class WorkflowReadCall(
    val target: WorkflowTarget,
    val messageId: String,
    val folderId: String?,
)

private data class MutableWorkflowMessage(
    val id: String,
    var folderId: String,
    var mutationState: String,
    var subject: String,
    val fromAddress: String,
    val toAddresses: List<String>,
    val body: String,
    var isRead: Boolean,
    var isFlagged: Boolean,
)

private class MailboxWorkflowBrowserBackend : DashboardBackend {
    private val lock = Any()
    private val mutationStateSequence = AtomicInteger(1)
    private val generationSequence = AtomicInteger()
    private val folders = linkedMapOf(
        INBOX_ID to "Inbox",
        TRASH_ID to "Trash",
    )
    private val messages = linkedMapOf(
        INITIAL_MESSAGE_ID to MutableWorkflowMessage(
            id = INITIAL_MESSAGE_ID,
            folderId = INBOX_ID,
            mutationState = "state-1",
            subject = INITIAL_MESSAGE_SUBJECT,
            fromAddress = INITIAL_MESSAGE_FROM,
            toAddresses = listOf(MAILBOX_ACCOUNT),
            body = INITIAL_MESSAGE_BODY,
            isRead = false,
            isFlagged = false,
        ),
    )

    @Volatile
    var accountExists: Boolean = true
        private set

    val targetCalls = CopyOnWriteArrayList<WorkflowTargetCall>()
    val accountLogTargets = CopyOnWriteArrayList<WorkflowTarget>()
    val readTargets = CopyOnWriteArrayList<WorkflowReadCall>()
    val globalLogRequests = CopyOnWriteArrayList<LogService>()
    val createdFolderNames = CopyOnWriteArrayList<String>()
    val deletedFolderIds = CopyOnWriteArrayList<String>()
    val mutationRequests = CopyOnWriteArrayList<MutateMessagesRequest>()
    val generationRequests = CopyOnWriteArrayList<GenerateMessageRequest>()

    override suspend fun listAccounts(): AccountListResponse = AccountListResponse(
        accounts = if (accountExists) listOf(MAILBOX_ACCOUNT_INFO) else emptyList(),
        providerStatuses = READY_PROVIDER_STATUSES,
    )

    override suspend fun logs(service: LogService): LogResponse {
        globalLogRequests += service
        return LogResponse(
            service = service,
            lines = listOf(
                if (service == LogService.STALWART) STALWART_TRACE_LINE else "${service.name.lowercase()} global trace",
            ),
        )
    }

    override suspend fun accountLogs(
        address: String,
        provider: Provider,
        providerAccountId: String?,
    ): LogResponse {
        val target = recordTarget("accountLogs", address, provider, providerAccountId)
        accountLogTargets += target
        return LogResponse(LogService.ALL, account = address, lines = listOf(ACCOUNT_TRACE_LINE))
    }

    override suspend fun listFolders(
        address: String,
        provider: Provider,
        providerAccountId: String?,
    ): FolderListResponse {
        recordTarget("listFolders", address, provider, providerAccountId)
        return synchronized(lock) {
            FolderListResponse(
                folders.map { (id, name) ->
                    val folderMessages = messages.values.filter { it.folderId == id }
                    FolderInfo(
                        id = id,
                        name = name,
                        totalMessages = folderMessages.size,
                        unreadMessages = folderMessages.count { !it.isRead },
                    )
                },
            )
        }
    }

    override suspend fun createFolder(
        address: String,
        provider: Provider,
        providerAccountId: String?,
        request: CreateFolderRequest,
    ): FolderInfo {
        recordTarget("createFolder", address, provider, providerAccountId)
        val id = request.name.lowercase()
        synchronized(lock) {
            check(id !in folders) { "Folder already exists: ${request.name}" }
            folders[id] = request.name
        }
        createdFolderNames += request.name
        return FolderInfo(id, request.name, totalMessages = 0, unreadMessages = 0)
    }

    override suspend fun deleteFolder(
        address: String,
        provider: Provider,
        providerAccountId: String?,
        folderId: String,
    ): OperationResponse {
        recordTarget("deleteFolder", address, provider, providerAccountId)
        synchronized(lock) {
            check(folderId != INBOX_ID && folders.remove(folderId) != null) { "Folder not found: $folderId" }
            messages.entries.removeIf { it.value.folderId == folderId }
        }
        deletedFolderIds += folderId
        return OperationResponse(true, "Folder deleted: $folderId")
    }

    override suspend fun listMessages(
        address: String,
        provider: Provider,
        providerAccountId: String?,
        folderId: String?,
    ): MessageListResponse {
        recordTarget("listMessages", address, provider, providerAccountId)
        val resolvedFolderId = folderId ?: INBOX_ID
        return synchronized(lock) {
            MessageListResponse(
                messages.values
                    .filter { it.folderId == resolvedFolderId }
                    .map(MutableWorkflowMessage::summary),
            )
        }
    }

    override suspend fun readMessage(
        address: String,
        provider: Provider,
        providerAccountId: String?,
        messageId: String,
        folderId: String?,
    ): MessageDetail {
        val target = recordTarget("readMessage", address, provider, providerAccountId)
        readTargets += WorkflowReadCall(target, messageId, folderId)
        return synchronized(lock) {
            val message = requireNotNull(messages[messageId]) { "Message not found: $messageId" }
            check(folderId == null || message.folderId == folderId) { "Message folder does not match" }
            message.detail()
        }
    }

    override suspend fun mutateMessages(
        address: String,
        provider: Provider,
        providerAccountId: String?,
        request: MutateMessagesRequest,
    ): OperationResponse {
        recordTarget("mutateMessages", address, provider, providerAccountId)
        check(request.account == address)
        check(request.provider == provider)
        check(request.providerAccountId == providerAccountId)
        mutationRequests += request
        synchronized(lock) {
            request.messageIds.forEach { id ->
                val message = requireNotNull(messages[id]) { "Message not found: $id" }
                check(request.mutationStates[id] == message.mutationState) { "Stale mutation state for $id" }
                check(request.sourceFolderId == message.folderId) { "Source folder does not match for $id" }
                when (request.action) {
                    MessageAction.MARK_READ -> message.isRead = true
                    MessageAction.MARK_UNREAD -> message.isRead = false
                    MessageAction.FLAG -> message.isFlagged = true
                    MessageAction.UNFLAG -> message.isFlagged = false
                    MessageAction.COPY -> {
                        val destination = requireNotNull(request.destinationFolderId)
                        check(destination in folders)
                        val copyId = "$id-copy-${mutationStateSequence.incrementAndGet()}"
                        messages[copyId] = message.copy(
                            id = copyId,
                            folderId = destination,
                            mutationState = nextMutationState(),
                            subject = "${message.subject} copy",
                        )
                    }
                    MessageAction.MOVE -> {
                        val destination = requireNotNull(request.destinationFolderId)
                        check(destination in folders)
                        message.folderId = destination
                    }
                    MessageAction.TRASH -> message.folderId = TRASH_ID
                    MessageAction.DELETE -> messages.remove(id)
                }
                if (request.action != MessageAction.DELETE) {
                    message.mutationState = nextMutationState()
                }
            }
        }
        return OperationResponse(true, "${request.action.name.lowercase()} complete")
    }

    override suspend fun generateMessage(request: GenerateMessageRequest): GenerateMessageResponse {
        check(request.targetAccount == MAILBOX_ACCOUNT)
        check(request.provider == Provider.STALWART)
        check(request.providerAccountId == MAILBOX_PROVIDER_ACCOUNT_ID)
        generationRequests += request
        val id = "generated-${generationSequence.incrementAndGet()}"
        val folderId = when (request.deliveryMode) {
            MessageDeliveryMode.DIRECT_APPEND -> request.folderId ?: INBOX_ID
            MessageDeliveryMode.SMTP_DELIVERY -> INBOX_ID
        }
        val subject = when (request.sourceType) {
            MessageSourceType.EML -> RAW_EML.header("Subject") ?: "(no subject)"
            MessageSourceType.TEXT,
            MessageSourceType.RANDOM,
            -> request.subject ?: "(no subject)"
        }
        val from = when (request.sourceType) {
            MessageSourceType.EML -> RAW_EML.header("From") ?: DEFAULT_GENERATED_FROM
            MessageSourceType.TEXT,
            MessageSourceType.RANDOM,
            -> request.fromAddress ?: DEFAULT_GENERATED_FROM
        }
        val body = when (request.sourceType) {
            MessageSourceType.EML -> RAW_EML.substringAfter("\n\n")
            MessageSourceType.TEXT -> request.content.orEmpty()
            MessageSourceType.RANDOM -> "Random fixture seed ${request.seed}"
        }
        synchronized(lock) {
            check(folderId in folders)
            messages[id] = MutableWorkflowMessage(
                id = id,
                folderId = folderId,
                mutationState = nextMutationState(),
                subject = subject,
                fromAddress = from,
                toAddresses = listOf(MAILBOX_ACCOUNT),
                body = body,
                isRead = false,
                isFlagged = false,
            )
        }
        return GenerateMessageResponse(
            messageIds = listOf(id),
            operation = OperationResponse(true, "Generated ${request.sourceType.name.lowercase()} message"),
        )
    }

    override suspend fun deleteAccount(
        address: String,
        provider: Provider,
        providerAccountId: String?,
    ): OperationResponse {
        recordTarget("deleteAccount", address, provider, providerAccountId)
        accountExists = false
        synchronized(lock) {
            folders.clear()
            messages.clear()
        }
        return OperationResponse(true, "Account deleted")
    }

    override suspend fun createAccount(request: CreateAccountRequest): AccountInfo = unsupported()
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
    override suspend fun probeAuthentication(
        request: AuthenticationProbeRequest,
    ): AuthenticationProbeResponse = unsupported()

    private fun recordTarget(
        operation: String,
        address: String,
        provider: Provider,
        providerAccountId: String?,
    ): WorkflowTarget {
        val target = WorkflowTarget(address, provider, providerAccountId)
        targetCalls += WorkflowTargetCall(operation, target)
        return target
    }

    private fun nextMutationState(): String = "state-${mutationStateSequence.incrementAndGet()}"

    private fun <T> unsupported(): T = error("Unexpected mailbox-workflow browser operation")
}

private fun MutableWorkflowMessage.summary(): MessageSummary = MessageSummary(
    id = id,
    folderId = folderId,
    mutationState = mutationState,
    subject = subject,
    fromAddress = fromAddress,
    receivedAt = "2026-08-12T12:00:00Z",
    isRead = isRead,
    isFlagged = isFlagged,
)

private fun MutableWorkflowMessage.detail(): MessageDetail = MessageDetail(
    id = id,
    folderId = folderId,
    mutationState = mutationState,
    subject = subject,
    fromAddress = fromAddress,
    toAddresses = toAddresses,
    sentAt = "2026-08-12T12:00:00Z",
    textBody = body,
    htmlBody = null,
    isRead = isRead,
    isFlagged = isFlagged,
)

private fun String.header(name: String): String? = lineSequence()
    .firstOrNull { it.startsWith("$name:", ignoreCase = true) }
    ?.substringAfter(':')
    ?.trim()

private val MAILBOX_TARGET = WorkflowTarget(
    address = "workflow@local.test",
    provider = Provider.STALWART,
    providerAccountId = "stalwart-workflow-account-id",
)
private val MAILBOX_ACCOUNT_INFO = AccountInfo(
    address = MAILBOX_TARGET.address,
    provider = MAILBOX_TARGET.provider,
    protocols = listOf(MailProtocol.JMAP, MailProtocol.SMTP),
    credentialReadiness = CredentialReadiness.READY,
    providerAccountId = MAILBOX_TARGET.providerAccountId,
)
private val READY_PROVIDER_STATUSES = listOf(
    ProviderStatus(Provider.DOVECOT, ProviderAvailability.READY),
    ProviderStatus(Provider.STALWART, ProviderAvailability.READY),
)
private val MAILBOX_CLICKABLE_ROLES = setOf("button", "radio")
private const val MAILBOX_ACCOUNT = "workflow@local.test"
private const val MAILBOX_PROVIDER_ACCOUNT_ID = "stalwart-workflow-account-id"
private const val INBOX_ID = "INBOX"
private const val TRASH_ID = "trash"
private const val INITIAL_MESSAGE_ID = "workflow-message-1"
private const val INITIAL_MESSAGE_SUBJECT = "Workflow seed"
private const val INITIAL_MESSAGE_FROM = "sender@local.test"
private const val INITIAL_MESSAGE_BODY = "Rendered mailbox workflow body."
private const val INITIAL_MESSAGE_ACCESSIBLE_NAME = "Unread, Workflow seed, from sender@local.test"
private const val READ_MESSAGE_ACCESSIBLE_NAME = "Read, Workflow seed, from sender@local.test"
private const val FLAGGED_MESSAGE_ACCESSIBLE_NAME = "Unread, flagged, Workflow seed, from sender@local.test"
private const val ACCOUNT_TRACE_LINE = "account trace workflow@local.test via stalwart-workflow-account-id"
private const val STALWART_TRACE_LINE = "stalwart global trace"
private const val DEFAULT_GENERATED_SUBJECT = "Dashboard reproduction"
private const val DEFAULT_GENERATED_FROM = "debugger@local.test"
private const val EML_SUBJECT = "Rendered EML fixture"
private const val EML_BODY = "Rendered raw EML body."
private const val AUTHORED_BODY = "Rendered authored text body."
private const val EML_MESSAGE_ACCESSIBLE_NAME =
    "Unread, Rendered EML fixture, from eml-author@local.test"
private const val GENERATED_MESSAGE_ACCESSIBLE_NAME =
    "Unread, Dashboard reproduction, from debugger@local.test"
private const val RANDOM_SEED = 424242L
private const val RANDOM_BODY = "Random fixture seed 424242"
private val RAW_EML = """
    From: eml-author@local.test
    To: workflow@local.test
    Date: Wed, 12 Aug 2026 12:00:00 +0000
    Subject: $EML_SUBJECT
    Message-ID: <rendered-eml-20260812@local.test>

    $EML_BODY
""".trimIndent()
