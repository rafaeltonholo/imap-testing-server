package mail.sandbox.dashboard.server.gate

import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import java.lang.reflect.Proxy
import java.net.URI
import java.nio.file.Files
import java.nio.file.Path
import java.time.Duration
import java.util.Optional
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.io.path.absolutePathString
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking
import mail.sandbox.dashboard.server.module
import org.openqa.selenium.By
import org.openqa.selenium.Keys
import org.openqa.selenium.OutputType
import org.openqa.selenium.SearchContext
import org.openqa.selenium.NoSuchShadowRootException
import org.openqa.selenium.TimeoutException
import org.openqa.selenium.WebDriver
import org.openqa.selenium.WebElement
import org.openqa.selenium.chrome.ChromeDriver
import org.openqa.selenium.chrome.ChromeOptions
import org.openqa.selenium.devtools.HasDevTools
import org.openqa.selenium.devtools.v150.accessibility.Accessibility
import org.openqa.selenium.devtools.v150.accessibility.model.AXNode
import org.openqa.selenium.devtools.v150.accessibility.model.AXPropertyName
import org.openqa.selenium.devtools.v150.log.Log
import org.openqa.selenium.devtools.v150.log.model.LogEntry
import org.openqa.selenium.devtools.v150.network.Network
import org.openqa.selenium.devtools.v150.network.model.EventSourceMessageReceived
import org.openqa.selenium.devtools.v150.runtime.Runtime
import org.openqa.selenium.devtools.v150.runtime.model.ConsoleAPICalled
import org.openqa.selenium.interactions.Actions
import org.openqa.selenium.support.ui.WebDriverWait

class BrowserGateCleanupTest {
    @Test
    fun restoresWorkingDirectoryWhenServerShutdownThrows() {
        val calls = mutableListOf<String>()

        val failure = assertFailsWith<IllegalStateException> {
            finalizeBrowserGate(
                quitDriver = { calls += "quit" },
                stopServer = {
                    calls += "stop"
                    error("shutdown failed")
                },
                restoreWorkingDirectory = { calls += "restore" },
            )
        }

        assertEquals("shutdown failed", failure.message)
        assertEquals(listOf("quit", "stop", "restore"), calls)
    }
}

class BrowserHostResolverTest {
    @Test
    fun resolvesTheCompose111NestedShadowHostShape() {
        val nestedShadow = searchContext()
        val shadowContainer = webElement(
            style = "position: relative;",
            shadow = nestedShadow,
        )
        val interopContainer = webElement(
            style = "position: absolute; top: 0px; left: 0px;",
        )
        val positioningContainer = webElement(
            directChildren = listOf(shadowContainer, interopContainer),
            style = "position: relative;",
        )
        val dashboardRoot = webElement(directChildren = listOf(positioningContainer))

        assertSame(shadowContainer, resolveDashboardShadowHost(dashboardRoot))
        assertSame(nestedShadow, resolveDashboardHost(dashboardRoot))
    }

    @Test
    fun rejectsAnUnsupportedLightDomHostShape() {
        val dashboardRoot = webElement(
            directChildren = listOf(
                webElement(
                    directChildren = listOf(
                        webElement(style = "position: relative;"),
                        webElement(style = "position: absolute; top: 0px; left: 0px;"),
                    ),
                    style = "position: relative;",
                ),
            ),
        )

        assertFailsWith<NoSuchShadowRootException> {
            resolveDashboardHost(dashboardRoot)
        }
    }

    @Test
    fun rejectsLightDomHostWithUnexpectedContainerCardinality() {
        val dashboardRoot = webElement(
            directChildren = listOf(
                webElement(style = "position: relative;"),
                webElement(style = "position: relative;"),
            ),
        )

        val failure = assertFailsWith<NoSuchShadowRootException> {
            resolveDashboardHost(dashboardRoot)
        }

        assertTrue(
            failure.message.orEmpty().startsWith(
                "Dashboard host is not the reviewed Compose 1.11.1 nested Shadow DOM shape: " +
                    "root direct div count=2",
            ),
        )
    }

    @Test
    fun rejectsReorderedAndWronglyStyledComposeContainers() {
        val nestedShadow = searchContext()
        val reordered = dashboardRootWith(
            firstLayer = webElement(style = "position: absolute; top: 0px; left: 0px;"),
            secondLayer = webElement(style = "position: relative;", shadow = nestedShadow),
        )
        val wronglyStyled = dashboardRootWith(
            firstLayer = webElement(style = "display: contents;", shadow = nestedShadow),
            secondLayer = webElement(style = "position: absolute; top: 0px; left: 0px;"),
        )

        listOf(reordered, wronglyStyled).forEach { dashboardRoot ->
            assertFailsWith<NoSuchShadowRootException> {
                resolveDashboardHost(dashboardRoot)
            }
        }
    }

    @Test
    fun rejectsTheHistoricalRootShadowHostTopology() {
        assertFailsWith<NoSuchShadowRootException> {
            resolveDashboardHost(webElement(shadow = searchContext()))
        }
    }

    @Test
    fun treatsAnEmptyDashboardRootAsNotReadyForTheBrowserWait() {
        assertFailsWith<NoSuchShadowRootException> {
            resolveDashboardHost(webElement())
        }
    }
}

class KotlinToolchainBrowserGateTest {
    @Test
    fun productionBundlePassesTheBrowserHistoryTransportAndSemanticsGate() {
        val originalWorkingDirectory = System.getProperty("user.dir")
        val projectRoot = Path.of(originalWorkingDirectory).toRealPath().let { testWorkingDirectory ->
            if (testWorkingDirectory.fileName.toString() == "dashboard-server") {
                testWorkingDirectory.parent
            } else {
                testWorkingDirectory
            }
        }
        requiredProductionEnvironment(projectRoot)
        System.setProperty("user.dir", projectRoot.toString())
        val server = try {
            embeddedServer(
                factory = Netty,
                port = 0,
                host = "127.0.0.1",
            ) {
                module()
            }.start(wait = false)
        } catch (failure: Throwable) {
            System.setProperty("user.dir", originalWorkingDirectory)
            throw failure
        }
        var driver: ChromeDriver? = null

        try {
            val port = runBlocking {
                server.engine.resolvedConnectors().single().port
            }
            val baseUrl = "http://127.0.0.1:$port"
            val observations = BrowserObservations()
            driver = ChromeDriver(chromeOptions())
            val devTools = (driver as HasDevTools).devTools
            devTools.createSession()
            observations.install(devTools)

            val wait = WebDriverWait(driver, Duration.ofSeconds(30))
            driver.get("$baseUrl/")

            val canvas = wait.until { current ->
                dashboardShadow(current).findElements(By.cssSelector("canvas"))
                    .firstOrNull { it.isDisplayed && it.size.width > 0 && it.size.height > 0 }
            }
            assertNotNull(canvas, "Compose did not expose a visible non-empty canvas")
            waitForSemanticText(wait, "Mail Flight Recorder")
            waitForSemanticText(wait, "GATE_RESOURCE: toolchain-compose-resource-ok")
            waitForSemanticText(wait, "API message: ready")
            waitForSemanticText(wait, "SSE sequence: 4")
            waitForSemanticText(wait, "SSE sync: resyncing")
            waitForSemanticText(wait, "Reconnect status: disconnected")

            wait.until {
                observations.sseMessages.count { it.eventName != "resync" } >= 4 &&
                    observations.sseMessages.any { it.eventName == "resync" }
            }
            val firstCycle = observations.sseMessages
                .sortedBy { it.timestamp.toJson().toDouble() }
                .take(5)
            assertEquals(listOf("1", "2", "3", "4", "6"), firstCycle.map { it.eventId })
            assertEquals(
                listOf("message", "message", "message", "message", "resync"),
                firstCycle.map { it.eventName },
            )

            val heading = waitForAxNode(
                devTools = devTools,
                wait = wait,
                accessibleName = "Mail Flight Recorder",
                expectedRole = "heading",
            )
            assertEquals("heading", heading.role.flatMap { it.value }.orElse(null))

            clickComposeControl(driver, wait, "Gate details")
            wait.until { URI(driver.currentUrl).path == "/gate/details" }
            waitForSemanticText(wait, "Selected route: /gate/details")

            driver.navigate().refresh()
            wait.until { URI(driver.currentUrl).path == "/gate/details" }
            waitForSemanticText(wait, "Selected route: /gate/details")
            waitForSemanticText(wait, "GATE_RESOURCE: toolchain-compose-resource-ok")

            driver.navigate().back()
            wait.until { URI(driver.currentUrl).path == "/" }
            waitForSemanticText(wait, "Selected route: /")

            focusIncrementProofWithTab(driver)
            waitForSemanticText(wait, "Keyboard focus: increment proof")
            val dashboardRoot = driver.findElement(By.id("dashboard-root"))
            val shadowHost = resolveDashboardShadowHost(dashboardRoot)
            val activeElement = driver.switchTo().activeElement()
            assertEquals(shadowHost, activeElement)
            assertEquals("div", activeElement.tagName.lowercase())
            val deepActiveElement = shadowHost.shadowRoot.findElement(By.cssSelector("canvas:focus"))
            assertEquals("canvas", deepActiveElement.tagName.lowercase())
            assertTrue(deepActiveElement.isDisplayed)
            assertEquals("main", dashboardRoot.tagName.lowercase())
            assertEquals("dashboard-root", dashboardRoot.getDomAttribute("id"))
            assertEquals("solid", dashboardRoot.getCssValue("outline-style"))
            assertEquals("3px", dashboardRoot.getCssValue("outline-width"))

            Actions(driver).sendKeys(Keys.ENTER).perform()
            waitForSemanticText(wait, "Activation count: 1")

            val incrementNode = waitForAxNode(
                devTools = devTools,
                wait = wait,
                accessibleName = "Increment proof",
                expectedRole = "button",
            )
            assertFalse(incrementNode.ignored, "Increment proof is ignored by the AX tree")
            val disabled = incrementNode.properties.orElse(emptyList())
                .firstOrNull { it.name == AXPropertyName.DISABLED }
                ?.value
                ?.value
                ?.orElse(false) == true
            assertFalse(disabled, "Increment proof is disabled in the AX tree")

            observations.assertClean(baseUrl)
            reportVersions(driver)
        } catch (failure: Throwable) {
            val evidence = captureFailureEvidence(driver, failure)
            throw AssertionError("$failure\nBrowser evidence: $evidence", failure)
        } finally {
            finalizeBrowserGate(
                quitDriver = { driver?.quit() },
                stopServer = {
                    server.stop(gracePeriodMillis = 500, timeoutMillis = 2_000)
                },
                restoreWorkingDirectory = {
                    System.setProperty("user.dir", originalWorkingDirectory)
                },
            )
        }
    }

    private fun requiredProductionEnvironment(projectRoot: Path) {
        val assets = Path.of(requiredEnvironment("DASHBOARD_WEB_ASSETS"))
        val resources = Path.of(requiredEnvironment("DASHBOARD_WEB_RESOURCES"))
        val entry = requiredEnvironment("DASHBOARD_WEB_ENTRY")

        assertTrue(assets.isAbsolute && assets.toRealPath().startsWith(projectRoot))
        assertTrue(resources.isAbsolute && resources.toRealPath().startsWith(projectRoot))
        assertEquals("dashboard-web.mjs", entry)
    }

    private fun requiredEnvironment(name: String): String {
        val value = System.getenv(name)
        require(!value.isNullOrBlank()) {
            "The production-style browser gate requires $name"
        }
        return value
    }

    private fun chromeOptions(): ChromeOptions = ChromeOptions().apply {
        setBinary("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
        addArguments(
            "--headless=new",
            "--enable-features=WebAssemblyGarbageCollection",
            "--window-size=1440,1200",
            "--disable-search-engine-choice-screen",
            "--disable-background-networking",
        )
    }

    private fun waitForSemanticText(wait: WebDriverWait, expected: String): WebElement =
        wait.until { driver ->
            semanticElements(driver).firstOrNull { element ->
                element.getDomProperty("innerText")?.trim() == expected ||
                    element.accessibleName == expected
            }
        }

    private fun semanticElements(driver: WebDriver): List<WebElement> =
        dashboardShadow(driver).findElements(By.cssSelector("#cmp_a11y_root *"))

    private fun dashboardShadow(driver: WebDriver): SearchContext =
        resolveDashboardHost(driver.findElement(By.id("dashboard-root")))

    private fun clickComposeControl(
        driver: ChromeDriver,
        wait: WebDriverWait,
        accessibleName: String,
    ) {
        val control = wait.until { current ->
            semanticElements(current).firstOrNull { it.accessibleName == accessibleName }
        }
        val rect = control.rect
        assertTrue(rect.width > 0 && rect.height > 0, "$accessibleName has no hit-test bounds")
        Actions(driver)
            .moveToLocation(rect.x + rect.width / 2, rect.y + rect.height / 2)
            .click()
            .perform()
    }

    private fun focusIncrementProofWithTab(driver: ChromeDriver) {
        repeat(8) {
            Actions(driver).sendKeys(Keys.TAB).perform()
            val focused = try {
                WebDriverWait(driver, Duration.ofMillis(700)).until { current ->
                    semanticElements(current).any { element ->
                        element.getDomProperty("innerText")?.trim() ==
                            "Keyboard focus: increment proof"
                    }
                }
            } catch (_: TimeoutException) {
                false
            }
            if (focused) return
        }
        throw AssertionError("Tab did not reach Increment proof within the gate controls")
    }

    private fun waitForAxNode(
        devTools: org.openqa.selenium.devtools.DevTools,
        wait: WebDriverWait,
        accessibleName: String,
        expectedRole: String,
    ): AXNode = wait.until {
        devTools.send(
            Accessibility.getFullAXTree(Optional.empty(), Optional.empty()),
        ).firstOrNull { candidate ->
            val name = candidate.name.flatMap { it.value }
                .map { it.toString() }
                .orElse(null)
            val role = candidate.role.flatMap { it.value }.orElse(null)
            name == accessibleName && role == expectedRole
        }
    }

    private fun reportVersions(driver: ChromeDriver) {
        val capabilities = driver.capabilities
        val chrome = capabilities.getCapability("chrome") as? Map<*, *>
        val driverVersion = chrome?.get("chromedriverVersion")?.toString().orEmpty()
        println("GATE_BROWSER_VERSION=${capabilities.browserVersion}")
        println("GATE_DRIVER_VERSION=$driverVersion")
    }

    private fun captureFailureEvidence(
        driver: ChromeDriver?,
        failure: Throwable,
    ): String {
        val directory = Path.of("build", "temp", "browser-gate").toAbsolutePath()
        return runCatching {
            Files.createDirectories(directory)
            Files.writeString(directory.resolve("failure.txt"), failure.stackTraceToString())
            if (driver != null) {
                val screenshot = driver.getScreenshotAs(OutputType.FILE).toPath()
                Files.copy(
                    screenshot,
                    directory.resolve("failure.png"),
                    java.nio.file.StandardCopyOption.REPLACE_EXISTING,
                )
                Files.writeString(directory.resolve("page-source.html"), driver.pageSource)
            }
            directory.absolutePathString()
        }.getOrElse { evidenceFailure ->
            "capture failed: $evidenceFailure"
        }
    }
}

internal fun resolveDashboardHost(root: WebElement): SearchContext =
    resolveDashboardShadowHost(root).shadowRoot

internal fun resolveDashboardShadowHost(root: WebElement): WebElement {
    val rootContainers = root.findElements(By.cssSelector(":scope > div"))
    if (rootContainers.isEmpty()) {
        throw NoSuchShadowRootException("Dashboard root is not ready: root direct div count=0")
    }
    val positioningContainer = rootContainers.singleOrNull()
    val composeLayers = positioningContainer?.findElements(By.cssSelector(":scope > div"))
    val shadowContainer = composeLayers?.getOrNull(0)
    val interopContainer = composeLayers?.getOrNull(1)
    return if (
        positioningContainer != null &&
        positioningContainer.tagName.equals("div", ignoreCase = true) &&
        positioningContainer.getDomAttribute("style") == "position: relative;" &&
        composeLayers?.size == 2 &&
        shadowContainer != null &&
        shadowContainer.tagName.equals("div", ignoreCase = true) &&
        shadowContainer.getDomAttribute("style") == "position: relative;" &&
        interopContainer != null &&
        interopContainer.tagName.equals("div", ignoreCase = true) &&
        interopContainer.getDomAttribute("style") == "position: absolute; top: 0px; left: 0px;"
    ) {
        shadowContainer
    } else {
        throw NoSuchShadowRootException(
            "Dashboard host is not the reviewed Compose 1.11.1 nested Shadow DOM shape: " +
                "root direct div count=${rootContainers.size}",
        )
    }
}

private fun finalizeBrowserGate(
    quitDriver: () -> Unit,
    stopServer: () -> Unit,
    restoreWorkingDirectory: () -> Unit,
) {
    try {
        runCatching { quitDriver() }
        stopServer()
    } finally {
        restoreWorkingDirectory()
    }
}

private fun searchContext(): SearchContext = Proxy.newProxyInstance(
    SearchContext::class.java.classLoader,
    arrayOf(SearchContext::class.java),
) { _, method, _ ->
    error("Unexpected SearchContext invocation: ${method.name}")
} as SearchContext

private fun webElement(
    shadow: SearchContext? = null,
    directChildren: List<WebElement> = emptyList(),
    style: String? = null,
): WebElement = Proxy.newProxyInstance(
    WebElement::class.java.classLoader,
    arrayOf(WebElement::class.java),
) { proxy, method, arguments ->
    when (method.name) {
        "getShadowRoot" -> shadow ?: throw NoSuchShadowRootException("no test shadow root")
        "findElements" -> {
            val selector = arguments?.singleOrNull()?.toString()
            check(selector == "By.cssSelector: :scope > div") { "Unexpected selector: $selector" }
            directChildren
        }

        "getTagName" -> "div"
        "getDomAttribute" -> if (arguments?.singleOrNull() == "style") style else null
        "equals" -> proxy === arguments?.singleOrNull()
        "hashCode" -> System.identityHashCode(proxy)
        "toString" -> "test WebElement"
        else -> error("Unexpected WebElement invocation: ${method.name}")
    }
} as WebElement

private fun dashboardRootWith(
    firstLayer: WebElement,
    secondLayer: WebElement,
): WebElement = webElement(
    directChildren = listOf(
        webElement(
            directChildren = listOf(firstLayer, secondLayer),
            style = "position: relative;",
        ),
    ),
)

private data class ResponseObservation(
    val url: String,
    val status: Int,
    val mimeType: String,
)

private class BrowserObservations {
    val sseMessages = CopyOnWriteArrayList<EventSourceMessageReceived>()
    private val requestUrls = java.util.concurrent.ConcurrentHashMap<String, String>()
    private val responses = CopyOnWriteArrayList<ResponseObservation>()
    private val networkFailures = CopyOnWriteArrayList<String>()
    private val consoleErrors = CopyOnWriteArrayList<String>()

    fun install(devTools: org.openqa.selenium.devtools.DevTools) {
        devTools.send(
            Network.enable(
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
            ),
        )
        devTools.send(Runtime.enable())
        devTools.send(Log.enable())
        devTools.send(Accessibility.enable())

        devTools.addListener(Network.requestWillBeSent()) { request ->
            requestUrls[request.requestId.toString()] = request.request.url
        }
        devTools.addListener(Network.responseReceived()) { received ->
            val response = received.response
            responses += ResponseObservation(
                url = response.url,
                status = response.status,
                mimeType = response.mimeType,
            )
        }
        devTools.addListener(Network.loadingFailed()) { failed ->
            if (!failed.canceled.orElse(false)) {
                networkFailures += buildString {
                    append(requestUrls[failed.requestId.toString()] ?: failed.requestId)
                    append(": ")
                    append(failed.errorText)
                    failed.blockedReason.ifPresent { append(" ($it)") }
                }
            }
        }
        devTools.addListener(Network.eventSourceMessageReceived()) { message ->
            sseMessages += message
        }
        devTools.addListener(Runtime.exceptionThrown()) { thrown ->
            val details = thrown.exceptionDetails
            consoleErrors += details.exception
                .flatMap { it.description }
                .orElse(details.text)
        }
        devTools.addListener(Runtime.consoleAPICalled()) { called ->
            if (called.type in setOf(
                    ConsoleAPICalled.Type.ERROR,
                    ConsoleAPICalled.Type.ASSERT,
                )
            ) {
                consoleErrors += called.args.joinToString(" ") { argument ->
                    argument.description.orElseGet {
                        argument.value.map { it.toString() }.orElse("<console value>")
                    }
                }
            }
        }
        devTools.addListener(Log.entryAdded()) { entry ->
            if (entry.level == LogEntry.Level.ERROR) {
                consoleErrors += entry.text
            }
        }
    }

    fun assertClean(baseUrl: String) {
        assertTrue(networkFailures.isEmpty(), "Failed resource requests: $networkFailures")
        val localResponses = responses.filter { it.url.startsWith(baseUrl) }
        assertTrue(localResponses.isNotEmpty(), "CDP did not observe local responses")
        val eventStreams = localResponses.filter {
            URI(it.url).path == "/api/v1/gate/events"
        }
        assertTrue(eventStreams.size >= 3, "Automatic SSE reconnects were not observed")
        assertTrue(
            eventStreams.all { URI(it.url).rawQuery == null },
            "SSE request URL exposed query credentials: $eventStreams",
        )
        val badStatus = localResponses.filter { it.status >= 400 }
        assertTrue(badStatus.isEmpty(), "HTTP failures: $badStatus")
        assertTrue(consoleErrors.isEmpty(), "Browser console errors: $consoleErrors")

        val wrongMime = localResponses.mapNotNull { response ->
            val expected = expectedMime(URI(response.url).path) ?: return@mapNotNull response
            response.takeIf { it.mimeType != expected }
        }
        assertTrue(wrongMime.isEmpty(), "Wrong or unreviewed response MIME: $wrongMime")
    }

    private fun expectedMime(path: String): String? = when {
        path == "/" || path == "/gate/details" -> "text/html"
        path == "/api/v1/gate/probe" -> "application/json"
        path == "/api/v1/gate/events" -> "text/event-stream"
        path.endsWith(".mjs") || path.endsWith(".js") -> "text/javascript"
        path.endsWith(".wasm") -> "application/wasm"
        path.endsWith(".txt") -> "text/plain"
        path.endsWith(".css") -> "text/css"
        path.endsWith(".json") -> "application/json"
        path.endsWith(".svg") -> "image/svg+xml"
        path.endsWith(".png") -> "image/png"
        path.endsWith(".jpg") || path.endsWith(".jpeg") -> "image/jpeg"
        path.endsWith(".gif") -> "image/gif"
        path.endsWith(".webp") -> "image/webp"
        path.endsWith(".ico") -> "image/x-icon"
        path.endsWith(".woff") -> "font/woff"
        path.endsWith(".woff2") -> "font/woff2"
        path.endsWith(".ttf") -> "font/ttf"
        path.endsWith(".otf") -> "font/otf"
        else -> null
    }
}
