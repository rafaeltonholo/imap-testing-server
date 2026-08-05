package mail.sandbox.dashboard.server.local

import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import mail.sandbox.dashboard.contract.LogService

class DockerComposeLogSourceTest {
    private val repositoryRoot = Path.of("/work/mail-sandbox")

    @Test
    fun readsDashboardAndDedicatedStalwartServicesWithFixedCommands() {
        val runner = RecordingLogRunner(
            ComposeLogResult(0, "dovecot | ready\n"),
            ComposeLogResult(0, "oauth2-mock | ready\n"),
            ComposeLogResult(0, "stalwart | ready\n"),
        )
        val source = DockerComposeLogSource(repositoryRoot, runner)

        assertEquals(listOf("dovecot | ready"), source.read(LogService.DOVECOT).lines)
        assertEquals(
            listOf("oauth2-mock | ready"),
            source.read(LogService.valueOf("OAUTH2")).lines,
        )
        assertEquals(listOf("stalwart | ready"), source.read(LogService.STALWART).lines)
        assertEquals(
            listOf(
                "docker", "compose", "-p", "mail-sandbox-dashboard",
                "-f", repositoryRoot.resolve("docker-compose.yml").toString(),
                "-f", repositoryRoot.resolve(
                    "debug-dashboard/docker-compose.local-providers.yml",
                ).toString(),
                "logs", "--no-color", "--tail", "500", "dovecot",
            ),
            runner.requests[0].argv,
        )
        assertEquals(
            listOf(
                "docker", "compose", "-p", "mail-sandbox-dashboard",
                "-f", repositoryRoot.resolve("docker-compose.yml").toString(),
                "-f", repositoryRoot.resolve(
                    "debug-dashboard/docker-compose.local-providers.yml",
                ).toString(),
                "logs", "--no-color", "--tail", "500", "oauth2-mock",
            ),
            runner.requests[1].argv,
        )
        assertEquals(
            listOf(
                "docker", "compose", "-p", "mail-sandbox-stalwart-gate", "-f",
                repositoryRoot.resolve(
                    "debug-dashboard/dashboard-server/testResources/stalwart-gate0b/compose.yml",
                ).toString(),
                "logs", "--no-color", "--tail", "500", "stalwart",
            ),
            runner.requests[2].argv,
        )
    }

    @Test
    fun allLogsAreLabeledAndAccountFilterIsCaseInsensitive() {
        val runner = RecordingLogRunner(
            ComposeLogResult(0, "dovecot | alice@local.test login\ndovecot | bob login\n"),
            ComposeLogResult(0, "postfix | to=<ALICE@LOCAL.TEST> delivered\n"),
            ComposeLogResult(0, "oauth2-mock | subject=alice@local.test active=true\n"),
            ComposeLogResult(0, "stalwart | unrelated\n"),
        )
        val source = DockerComposeLogSource(repositoryRoot, runner)

        val response = source.read(
            service = LogService.ALL,
            account = DashboardLogAccount("alice@local.test"),
            limit = 50,
        )

        assertEquals(
            listOf(
                "[dovecot] dovecot | alice@local.test login",
                "[postfix] postfix | to=<ALICE@LOCAL.TEST> delivered",
                "[oauth2] oauth2-mock | subject=alice@local.test active=true",
            ),
            response.lines,
        )
        assertEquals(LogService.ALL, response.service)
        assertEquals("alice@local.test", response.account)
    }

    @Test
    fun allLogsShareTheLimitFairlyAcrossEverySource() {
        fun lines(service: String): String = (1..4).joinToString("\n", postfix = "\n") {
            "$service | line $it"
        }
        val source = DockerComposeLogSource(
            repositoryRoot,
            RecordingLogRunner(
                ComposeLogResult(0, lines("dovecot")),
                ComposeLogResult(0, lines("postfix")),
                ComposeLogResult(0, lines("oauth2-mock")),
                ComposeLogResult(0, lines("stalwart")),
            ),
        )

        val response = source.read(LogService.ALL, limit = 8)

        assertEquals(8, response.lines.size)
        listOf("dovecot", "postfix", "oauth2", "stalwart").forEach { service ->
            assertEquals(
                2,
                response.lines.count { it.startsWith("[$service]") },
                "Expected ALL to retain an equal share of $service logs",
            )
        }
    }

    @Test
    fun runnerApprovalRequiresExactDedicatedProjectAndComposeFiles() {
        val runner = JvmComposeLogRunner(repositoryRoot)
        val approval = runner.javaClass.declaredMethods
            .single { method -> method.name == "isApproved" }
            .apply { isAccessible = true }

        fun isApproved(argv: List<String>): Boolean = approval.invoke(runner, argv) as Boolean
        fun dashboardCommand(service: String): List<String> = listOf(
            "docker", "compose", "-p", "mail-sandbox-dashboard",
            "-f", repositoryRoot.resolve("docker-compose.yml").toString(),
            "-f", repositoryRoot.resolve(
                "debug-dashboard/docker-compose.local-providers.yml",
            ).toString(),
            "logs", "--no-color", "--tail", "500", service,
        )

        listOf("dovecot", "postfix", "oauth2-mock").forEach { service ->
            assertTrue(isApproved(dashboardCommand(service)))
        }
        assertTrue(
            isApproved(
                listOf(
                    "docker", "compose", "-p", "mail-sandbox-stalwart-gate", "-f",
                    repositoryRoot.resolve(
                        "debug-dashboard/dashboard-server/testResources/stalwart-gate0b/compose.yml",
                    ).toString(),
                    "logs", "--no-color", "--tail", "500", "stalwart",
                ),
            ),
        )
        assertEquals(
            false,
            isApproved(
                listOf(
                    "docker", "compose", "logs", "--no-color", "--tail", "500", "dovecot",
                ),
            ),
        )
        assertEquals(
            false,
            isApproved(
                dashboardCommand("dovecot").toMutableList().apply {
                    this[5] = repositoryRoot.resolve("other-compose.yml").toString()
                },
            ),
        )
    }

    @Test
    fun rejectsUnboundedRequestsAndCommandFailures() {
        val source = DockerComposeLogSource(
            repositoryRoot,
            RecordingLogRunner(ComposeLogResult(1, "", "container absent")),
        )

        assertFailsWith<IllegalArgumentException> {
            source.read(LogService.DOVECOT, limit = 0)
        }
        assertFailsWith<IllegalStateException> {
            source.read(LogService.DOVECOT)
        }
    }

    @Test
    fun accountLogFiltersAcceptEverySupportedLocalAddressCharacter() {
        val source = DockerComposeLogSource(
            repositoryRoot,
            RecordingLogRunner(
                ComposeLogResult(0, "dovecot | qa%tag@local.test login\n"),
            ),
        )

        assertEquals(
            listOf("dovecot | qa%tag@local.test login"),
            source.read(
                LogService.DOVECOT,
                account = DashboardLogAccount("qa%tag@local.test"),
            ).lines,
        )
    }

    @Test
    fun accountAddressFilteringRequiresExactEmailTokenBoundaries() {
        val source = DockerComposeLogSource(
            repositoryRoot,
            RecordingLogRunner(
                ComposeLogResult(
                    0,
                    listOf(
                        "dovecot | mydev@local.test login",
                        "dovecot | dev@local.test.evil login",
                        "dovecot | user=<dev@local.test> login",
                        "dovecot | user=DEV@LOCAL.TEST logout",
                    ).joinToString("\n", postfix = "\n"),
                ),
            ),
        )

        assertEquals(
            listOf(
                "dovecot | user=<dev@local.test> login",
                "dovecot | user=DEV@LOCAL.TEST logout",
            ),
            source.read(
                LogService.DOVECOT,
                account = DashboardLogAccount("dev@local.test"),
            ).lines,
        )
    }

    @Test
    fun stalwartAccountLogsMatchAddressOrExactDecodedStructuredAccountId() {
        val runner = RecordingLogRunner(
            ComposeLogResult(
                0,
                listOf(
                    "stalwart | accountId = 30, event = Lookalike",
                    "stalwart | accountId = 3x, event = Malformed",
                    "stalwart | accountId = 3, event = JmapRequest",
                    "stalwart | recipient = ALICE@LOCAL.TEST, event = Delivery",
                ).joinToString("\n", postfix = "\n"),
            ),
        )
        val source = DockerComposeLogSource(repositoryRoot, runner)

        val response = source.read(
            service = LogService.STALWART,
            account = DashboardLogAccount(
                address = "alice@local.test",
                providerAccountId = "d",
            ),
            limit = 50,
        )

        assertEquals(
            listOf(
                "stalwart | accountId = 3, event = JmapRequest",
                "stalwart | recipient = ALICE@LOCAL.TEST, event = Delivery",
            ),
            response.lines,
        )
        assertEquals("alice@local.test", response.account)
        assertEquals("2000", runner.requests.single().argv.dropLast(1).last())
    }

    @Test
    fun accountFilteringReadsADeepSnapshotAndCapsTheResponseAtFiveHundredLines() {
        val matching = (1..600).joinToString("\n", postfix = "\n") { index ->
            "stalwart | accountId = 1, sequence = $index"
        }
        val runner = RecordingLogRunner(ComposeLogResult(0, matching))
        val source = DockerComposeLogSource(repositoryRoot, runner)

        val response = source.read(
            service = LogService.STALWART,
            account = DashboardLogAccount("alice@local.test", providerAccountId = "b"),
            limit = 2_000,
        )

        assertEquals(500, response.lines.size)
        assertTrue(response.lines.first().endsWith("sequence = 101"))
        assertTrue(response.lines.last().endsWith("sequence = 600"))
        assertEquals("2000", runner.requests.single().argv.dropLast(1).last())
    }

    @Test
    fun decodesOnlyCanonicalNonOverflowingStalwartNumericIds() {
        assertEquals(0UL, decodeStalwartAccountId("a"))
        assertEquals(1UL, decodeStalwartAccountId("b"))
        assertEquals(63UL, decodeStalwartAccountId("b3"))
        assertEquals(ULong.MAX_VALUE, decodeStalwartAccountId("p333333333333"))

        listOf(
            "",
            "A",
            "aa",
            "a7",
            "8",
            "-",
            "qaaaaaaaaaaaa",
            "p333333333333a",
        ).forEach { value ->
            assertFailsWith<IllegalArgumentException>("Expected '$value' to be rejected") {
                decodeStalwartAccountId(value)
            }
        }
    }
}

private class RecordingLogRunner(
    vararg results: ComposeLogResult,
) : ComposeLogRunner {
    private val results = ArrayDeque(results.toList())
    val requests = mutableListOf<ComposeLogRequest>()

    override fun run(request: ComposeLogRequest): ComposeLogResult {
        requests += request
        return results.removeFirst()
    }
}
