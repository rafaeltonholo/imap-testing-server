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
import org.openqa.selenium.Dimension
import org.openqa.selenium.JavascriptExecutor
import org.openqa.selenium.OutputType
import org.openqa.selenium.SearchContext
import org.openqa.selenium.NoSuchShadowRootException
import org.openqa.selenium.WebDriver
import org.openqa.selenium.WebElement
import org.openqa.selenium.chrome.ChromeDriver
import org.openqa.selenium.chrome.ChromeOptions
import org.openqa.selenium.devtools.HasDevTools
import org.openqa.selenium.devtools.DevTools
import org.openqa.selenium.devtools.v150.accessibility.Accessibility
import org.openqa.selenium.devtools.v150.log.Log
import org.openqa.selenium.devtools.v150.log.model.LogEntry
import org.openqa.selenium.devtools.v150.network.Network
import org.openqa.selenium.devtools.v150.network.model.EventSourceMessageReceived
import org.openqa.selenium.devtools.v150.page.Page
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
        val dashboardRoot = Path.of(originalWorkingDirectory).toRealPath().let { testWorkingDirectory ->
            if (testWorkingDirectory.fileName.toString() == "dashboard-server") {
                testWorkingDirectory.parent
            } else {
                testWorkingDirectory
            }
        }
        val repositoryRoot = requireNotNull(dashboardRoot.parent) {
            "Dashboard project must live directly under the mail-sandbox repository"
        }
        requiredProductionEnvironment(dashboardRoot)
        System.setProperty("user.dir", repositoryRoot.toString())
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
            verifyConfigurablePreseedsAreReplaced(baseUrl)
            verifyUnsafePreseedFailsClosed(baseUrl, "process")
            verifyUnsafePreseedFailsClosed(baseUrl, "Deno")

            val observations = BrowserObservations()
            driver = ChromeDriver(chromeOptions())
            val devTools = (driver as HasDevTools).devTools
            devTools.createSession()
            observations.install(devTools)

            val wait = WebDriverWait(driver, Duration.ofSeconds(30))
            driver.get("$baseUrl/")
            assertSealedAmbientGlobals(driver)
            assertAmbientMutationProbesFail(driver)

            val canvas = wait.until { current ->
                dashboardShadow(current).findElements(By.cssSelector("canvas"))
                    .firstOrNull { it.isDisplayed && it.size.width > 0 && it.size.height > 0 }
            }
            assertNotNull(canvas, "Compose did not expose a visible non-empty canvas")
            val productHeading = waitForSemanticText(wait, "Mail Flight Recorder")
            assertEquals("heading", productHeading.ariaRole)
            waitForSemanticText(wait, "GATE_RESOURCE: toolchain-compose-resource-ok")
            waitForSemanticText(wait, "API message: ready")
            waitForSemanticText(wait, "SSE sequence: 4")
            waitForSemanticText(wait, "SSE sync: resyncing")
            waitForSemanticText(wait, "Reconnect status: disconnected")
            verifyDashboardWorkspaceAtDesktop(driver, wait)

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

            val launchesBeforeRefresh = observations.requestCount("/assets/dashboard-web.mjs")
            assertEquals(1, launchesBeforeRefresh)
            assertEquals(
                launchesBeforeRefresh,
                observations.requestCount("/assets/browser-bootstrap.js"),
            )
            driver.navigate().refresh()
            wait.until {
                observations.requestCount("/assets/dashboard-web.mjs") ==
                    launchesBeforeRefresh + 1
            }
            assertEquals(
                launchesBeforeRefresh + 1,
                observations.requestCount("/assets/browser-bootstrap.js"),
            )
            wait.until { URI(driver.currentUrl).path == "/" }
            waitForSemanticText(wait, "Selected route: /")
            waitForSemanticText(wait, "GATE_RESOURCE: toolchain-compose-resource-ok")
            verifyDashboardWorkspaceAtNarrowWidth(driver, wait)

            observations.assertClean(baseUrl)
            assertEquals(
                observations.requestCount("/assets/browser-bootstrap.js"),
                observations.requestCount("/assets/dashboard-web.mjs"),
            )
            reportVersions(driver)
        } catch (failure: Throwable) {
            if (driver == null) throw failure
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

    private fun verifyConfigurablePreseedsAreReplaced(baseUrl: String) {
        withFreshBrowser(
            label = "configurable ambient preseeds",
            preload = CONFIGURABLE_PRESEED,
        ) { driver, _, observations ->
            val wait = WebDriverWait(driver, Duration.ofSeconds(30))
            driver.get("$baseUrl/")

            assertEquals(
                "node:preseeded",
                (driver as JavascriptExecutor).executeScript(
                    "return globalThis.__dashboardPreseedProof",
                ),
                "Preload proof was absent; console=${observations.consoleErrorSnapshot()}",
            )
            assertSealedAmbientGlobals(driver)
            val canvas = wait.until { current ->
                dashboardShadow(current).findElements(By.cssSelector("canvas"))
                    .firstOrNull { it.isDisplayed && it.size.width > 0 && it.size.height > 0 }
            }
            assertNotNull(canvas, "Compose did not render after configurable preseeds")
            waitForSemanticText(wait, "Mail Flight Recorder")
            wait.until { observations.requestCount("/assets/dashboard-web.mjs") >= 1 }
            assertEquals(1, observations.requestCount("/assets/dashboard-web.mjs"))
            assertEquals(1, observations.requestCount("/assets/browser-bootstrap.js"))
            observations.assertSuccessful(baseUrl)
        }
    }

    private fun verifyDashboardWorkspaceAtDesktop(
        driver: ChromeDriver,
        wait: WebDriverWait,
    ) {
        listOf(
            "Account channels",
            "Folders",
            "Message reader + operations",
            "Trace lens",
        ).forEach { expected -> waitForSemanticText(wait, expected) }
        waitForSemanticTextStartingWith(wait, "Messages")

        clickComposeControl(driver, wait, "Add account")
        listOf(
            "Create account channel",
            "Dovecot",
            "Stalwart",
            "Client protocol profile",
        ).forEach { expected -> waitForSemanticText(wait, expected) }
        clickComposeControl(driver, wait, "Cancel")
        waitForSemanticTextToDisappear(wait, "Create account channel")
    }

    private fun verifyDashboardWorkspaceAtNarrowWidth(
        driver: ChromeDriver,
        wait: WebDriverWait,
    ) {
        driver.manage().window().size = Dimension(760, 1_000)
        val canvas = wait.until { current ->
            dashboardShadow(current).findElements(By.cssSelector("canvas"))
                .firstOrNull { it.size.width in 700..760 && it.size.height > 0 }
        }
        assertNotNull(canvas, "Compose did not resize its canvas for the narrow viewport")
        val viewport = (driver as JavascriptExecutor).executeScript(
            "return [window.innerWidth, document.documentElement.scrollWidth]",
        ) as List<*>
        val innerWidth = (viewport[0] as Number).toInt()
        val documentWidth = (viewport[1] as Number).toInt()
        assertTrue(documentWidth <= innerWidth, "Narrow layout overflows horizontally: $viewport")
        driver.manage().window().size = Dimension(1_440, 1_200)
        wait.until { current ->
            dashboardShadow(current).findElements(By.cssSelector("canvas"))
                .any { it.size.width >= 1_040 && it.size.height > 0 }
        }
    }

    private fun verifyUnsafePreseedFailsClosed(baseUrl: String, name: String) {
        require(name == "process" || name == "Deno")
        withFreshBrowser(
            label = "unsafe non-configurable $name preseed",
            preload = unsafePreseed(name),
        ) { driver, _, observations ->
            val wait = WebDriverWait(driver, Duration.ofSeconds(10))
            driver.get("$baseUrl/")

            wait.until {
                observations.hasConsoleErrorContaining(
                    "Dashboard bootstrap cannot seal unsafe $name",
                )
            }
            wait.until { observations.requestCount("/assets/browser-bootstrap.js") == 1 }
            assertEquals(0, observations.requestCount("/assets/dashboard-web.mjs"))
            assertEquals(
                setOf("/assets/browser-bootstrap.js"),
                observations.localAssetRequestPaths(baseUrl),
                "Unsafe $name preseed requested part of the module graph",
            )
            val dashboardRoot = driver.findElement(By.id("dashboard-root"))
            assertTrue(
                dashboardRoot.findElements(By.cssSelector(":scope > div")).isEmpty(),
                "Compose rendered despite unsafe $name preseed",
            )
            if (name == "Deno") {
                assertSealedAmbientGlobal(driver, "process")
            }
            observations.assertOnlyConsoleErrorsContaining(
                "Dashboard bootstrap cannot seal unsafe $name",
            )
            observations.assertTransportSuccessful(baseUrl)
        }
    }

    private fun withFreshBrowser(
        label: String,
        preload: String,
        block: (ChromeDriver, DevTools, BrowserObservations) -> Unit,
    ) {
        val driver = ChromeDriver(chromeOptions())
        try {
            val devTools = (driver as HasDevTools).devTools
            devTools.createSession()
            devTools.send(Page.enable(Optional.empty()))
            val observations = BrowserObservations()
            observations.install(devTools)
            devTools.send(
                Page.addScriptToEvaluateOnNewDocument(
                    preload,
                    Optional.empty(),
                    Optional.empty(),
                    Optional.empty(),
                ),
            )
            block(driver, devTools, observations)
        } catch (failure: Throwable) {
            val evidence = captureFailureEvidence(driver, failure)
            throw AssertionError(
                "$label failed: $failure\nBrowser evidence: $evidence",
                failure,
            )
        } finally {
            runCatching { driver.quit() }
        }
    }

    private fun assertSealedAmbientGlobals(driver: ChromeDriver) {
        assertSealedAmbientGlobal(driver, "process")
        assertSealedAmbientGlobal(driver, "Deno")
    }

    private fun assertSealedAmbientGlobal(driver: ChromeDriver, name: String) {
        val actual = (driver as JavascriptExecutor).executeScript(
            """
            const name = arguments[0];
            const descriptor = Object.getOwnPropertyDescriptor(globalThis, name);
            return [
              Object.hasOwn(globalThis, name),
              descriptor?.value === undefined,
              descriptor?.writable,
              descriptor?.enumerable,
              descriptor?.configurable,
            ];
            """.trimIndent(),
            name,
        )
        assertEquals(
            listOf(true, true, false, false, false),
            actual,
            "$name is not an own sealed undefined data property",
        )
    }

    private fun assertAmbientMutationProbesFail(driver: ChromeDriver) {
        val actual = (driver as JavascriptExecutor).executeScript(
            """
            return (function probeAmbientMutations() {
              'use strict';
              const results = [];
              const fake = { release: { name: 'node' } };
              const recordThrow = (label, action) => {
                try {
                  action();
                  results.push([label, 'succeeded']);
                } catch (failure) {
                  results.push([label, failure.name]);
                }
              };
              const recordReturn = (label, action) => {
                try {
                  results.push([label, String(action())]);
                } catch (failure) {
                  results.push([label, failure.name]);
                }
              };
              const probe = (name, direct, concatenated, templated, destructured, deleted) => {
                recordThrow(name + '.direct', direct);
                recordThrow(name + '.concatenated', concatenated);
                recordThrow(name + '.template', templated);
                recordThrow(name + '.defineProperty', () => {
                  Object.defineProperty(globalThis, name, { value: fake });
                });
                recordThrow(name + '.destructuring', destructured);
                recordThrow(name + '.objectAssign', () => {
                  Object.assign(globalThis, { [name]: fake });
                });
                recordReturn(name + '.reflectSet', () => Reflect.set(globalThis, name, fake));
                recordThrow(name + '.deletion', deleted);
                recordReturn(name + '.redefinition', () =>
                  Reflect.defineProperty(globalThis, name, { value: fake })
                );
              };
              probe(
                'process',
                () => { globalThis.process = fake; },
                () => { globalThis['pro' + 'cess'] = fake; },
                () => { globalThis[`pro${'$'}{'cess'}`] = fake; },
                () => { ({ value: globalThis.process } = { value: fake }); },
                () => { delete globalThis.process; },
              );
              probe(
                'Deno',
                () => { globalThis.Deno = fake; },
                () => { globalThis['De' + 'no'] = fake; },
                () => { globalThis[`De${'$'}{'no'}`] = fake; },
                () => { ({ value: globalThis.Deno } = { value: fake }); },
                () => { delete globalThis.Deno; },
              );
              return results;
            })();
            """.trimIndent(),
        )
        val expected = listOf("process", "Deno").flatMap { name ->
            listOf(
                listOf("$name.direct", "TypeError"),
                listOf("$name.concatenated", "TypeError"),
                listOf("$name.template", "TypeError"),
                listOf("$name.defineProperty", "TypeError"),
                listOf("$name.destructuring", "TypeError"),
                listOf("$name.objectAssign", "TypeError"),
                listOf("$name.reflectSet", "false"),
                listOf("$name.deletion", "TypeError"),
                listOf("$name.redefinition", "false"),
            )
        }

        assertEquals(expected, actual)
        assertSealedAmbientGlobals(driver)
    }

    private fun unsafePreseed(name: String): String =
        """
        'use strict';
        Object.defineProperty(globalThis, '$name', {
          value: {},
          writable: false,
          enumerable: false,
          configurable: false,
        });
        """.trimIndent()

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
            runCatching {
                semanticElements(driver).firstOrNull { element ->
                    runCatching {
                        element.getDomProperty("innerText")?.trim() == expected ||
                            element.accessibleName.orEmpty().trim() == expected
                    }.getOrDefault(false)
                }
            }.getOrNull()
        }

    private fun waitForSemanticTextToDisappear(wait: WebDriverWait, expected: String) {
        wait.until { driver ->
            runCatching {
                semanticElements(driver).none { element ->
                    runCatching {
                        element.isDisplayed && (
                            element.getDomProperty("innerText")?.trim() == expected ||
                                element.accessibleName.orEmpty().trim() == expected
                            )
                    }.getOrDefault(false)
                }
            }.getOrDefault(false)
        }
    }

    private fun waitForSemanticTextStartingWith(wait: WebDriverWait, prefix: String): WebElement =
        wait.until { driver ->
            runCatching {
                semanticElements(driver).firstOrNull { element ->
                    runCatching {
                        element.getDomProperty("innerText")?.trim()?.startsWith(prefix) == true ||
                            element.accessibleName.orEmpty().trim().startsWith(prefix)
                    }.getOrDefault(false)
                }
            }.getOrNull()
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
            runCatching {
                semanticElements(current).firstOrNull {
                    runCatching {
                        it.getDomProperty("innerText")?.trim() == accessibleName ||
                            it.accessibleName.orEmpty().trim() == accessibleName
                    }.getOrDefault(false)
                }
            }.getOrNull()
        }
        val rect = control.rect
        assertTrue(rect.width > 0 && rect.height > 0, "$accessibleName has no hit-test bounds")
        Actions(driver)
            .moveToLocation(rect.x + rect.width / 2, rect.y + rect.height / 2)
            .click()
            .perform()
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

    private companion object {
        val CONFIGURABLE_PRESEED =
            """
            'use strict';
            Object.defineProperty(globalThis, 'process', {
              value: { release: { name: 'node' } },
              writable: true,
              enumerable: true,
              configurable: true,
            });
            Object.defineProperty(globalThis, 'Deno', {
              value: { marker: 'preseeded' },
              writable: true,
              enumerable: true,
              configurable: true,
            });
            globalThis.__dashboardPreseedProof =
              globalThis.process.release.name + ':' + globalThis.Deno.marker;
            """.trimIndent()
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

    fun requestCount(path: String): Int = requestUrls.values.count { url ->
        URI(url).path == path
    }

    fun localAssetRequestPaths(baseUrl: String): Set<String> = requestUrls.values
        .asSequence()
        .filter { url -> url.startsWith(baseUrl) }
        .map { url -> URI(url).path }
        .filter { path -> path.startsWith("/assets/") }
        .toSet()

    fun hasConsoleErrorContaining(expected: String): Boolean =
        consoleErrors.any { error -> error.contains(expected) }

    fun consoleErrorSnapshot(): List<String> = consoleErrors.toList()

    fun assertOnlyConsoleErrorsContaining(expected: String) {
        assertTrue(consoleErrors.isNotEmpty(), "Expected a browser console failure containing $expected")
        assertTrue(
            consoleErrors.all { error -> error.contains(expected) },
            "Unexpected browser console errors: $consoleErrors",
        )
    }

    fun assertTransportSuccessful(baseUrl: String) {
        assertTrue(networkFailures.isEmpty(), "Failed resource requests: $networkFailures")
        val localResponses = responses.filter { it.url.startsWith(baseUrl) }
        assertTrue(localResponses.isNotEmpty(), "CDP did not observe local responses")
        val badStatus = localResponses.filter { it.status >= 400 }
        assertTrue(badStatus.isEmpty(), "HTTP failures: $badStatus")

        val wrongMime = localResponses.mapNotNull { response ->
            val expected = expectedMime(URI(response.url).path) ?: return@mapNotNull response
            response.takeIf { it.mimeType != expected }
        }
        assertTrue(wrongMime.isEmpty(), "Wrong or unreviewed response MIME: $wrongMime")
    }

    fun assertSuccessful(baseUrl: String) {
        assertTransportSuccessful(baseUrl)
        assertTrue(consoleErrors.isEmpty(), "Browser console errors: $consoleErrors")
    }

    fun assertClean(baseUrl: String) {
        assertSuccessful(baseUrl)
        val localResponses = responses.filter { it.url.startsWith(baseUrl) }
        val eventStreams = localResponses.filter {
            URI(it.url).path == "/api/v1/gate/events"
        }
        assertTrue(eventStreams.size >= 3, "Automatic SSE reconnects were not observed")
        assertTrue(
            eventStreams.all { URI(it.url).rawQuery == null },
            "SSE request URL exposed query credentials: $eventStreams",
        )
    }

    private fun expectedMime(path: String): String? = when {
        path == "/" || path == "/gate/details" -> "text/html"
        path == "/api/v1/gate/probe" -> "application/json"
        path == "/api/v1/gate/events" -> "text/event-stream"
        path.startsWith("/api/v1/") -> "application/json"
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
