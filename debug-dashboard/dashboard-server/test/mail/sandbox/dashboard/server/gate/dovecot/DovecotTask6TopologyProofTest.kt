package mail.sandbox.dashboard.server.gate.dovecot

import java.io.IOException
import java.net.ConnectException
import java.net.Inet4Address
import java.net.InetAddress
import java.net.NoRouteToHostException
import java.net.SocketTimeoutException
import java.nio.file.Files
import java.nio.file.Path
import java.time.Duration
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DovecotTask6TopologyProofTest {
    @Test
    fun networkHelperFailureDiagnosticIsExactAllowlistedAndRedacted() {
        listOf(
            "CHECK_ERROR",
            "DOVECOT_UNREACHABLE",
            "OPERATOR_DNS_RESOLVED",
            "OPERATOR_IP_REACHABLE",
            "HOST_DOCKER_INTERNAL_REACHABLE",
            "HOST_DOCKER_INTERNAL_UNRESOLVED",
            "GATEWAY_DOCKER_INTERNAL_REACHABLE",
            "GATEWAY_DOCKER_INTERNAL_UNRESOLVED",
            "TASK6_HOST_GATEWAY_REACHABLE",
            "TASK6_HOST_GATEWAY_UNRESOLVED",
            "HOST_IP_REACHABLE",
        ).forEach { diagnostic ->
            assertEquals(
                diagnostic,
                task6NetworkIsolationFailureDiagnostic(
                    exitCode = 1,
                    stdout = "$diagnostic\n",
                    stderr = "",
                ),
            )
        }
        listOf("INVALID_INVOCATION", "INVALID_INPUT").forEach { diagnostic ->
            assertEquals(
                diagnostic,
                task6NetworkIsolationFailureDiagnostic(
                    exitCode = 2,
                    stdout = "$diagnostic\n",
                    stderr = "",
                ),
            )
        }
        assertEquals(
            null,
            task6NetworkIsolationFailureDiagnostic(
                exitCode = 0,
                stdout = "OK\n",
                stderr = "",
            ),
        )

        val canary = "network-helper-secret-canary"
        listOf(
            Triple(0, "$canary\n", ""),
            Triple(0, "OK\n", canary),
            Triple(0, "CHECK_ERROR\n", ""),
            Triple(0, "OK", ""),
            Triple(0, "OK\r\n", ""),
            Triple(0, "OK\nOK\n", ""),
            Triple(1, "$canary\n", ""),
            Triple(1, "CHECK_ERROR\n$canary\n", ""),
            Triple(1, "CHECK_ERROR", ""),
            Triple(1, "CHECK_ERROR\n", canary),
            Triple(2, "CHECK_ERROR\n", ""),
            Triple(3, "INVALID_INPUT\n", ""),
        ).forEach { (exitCode, stdout, stderr) ->
            val diagnostic = task6NetworkIsolationFailureDiagnostic(
                exitCode = exitCode,
                stdout = stdout,
                stderr = stderr,
            )
            assertEquals("INVALID_RESULT", diagnostic)
            assertFalse(diagnostic.orEmpty().contains(canary))
        }

        requireTask6NetworkIsolationResult(
            exitCode = 0,
            stdout = "OK\n",
            stderr = "",
        )
        val fixedFailure = assertFailsWith<IllegalStateException> {
            requireTask6NetworkIsolationResult(
                exitCode = 1,
                stdout = "HOST_IP_REACHABLE\n",
                stderr = "",
            )
        }
        assertEquals(
            "Default-network isolation helper failed: HOST_IP_REACHABLE",
            fixedFailure.message,
        )
        val redactedFailure = assertFailsWith<IllegalStateException> {
            requireTask6NetworkIsolationResult(
                exitCode = 0,
                stdout = "$canary\n",
                stderr = canary,
            )
        }
        assertEquals(
            "Default-network isolation helper failed: INVALID_RESULT",
            redactedFailure.message,
        )
        assertFalse(redactedFailure.toString().contains(canary))
    }

    @Test
    fun hostAddressDiscoveryKeepsLinkLocalIpv4InScope() {
        val linkLocal = InetAddress.getByAddress(
            byteArrayOf(169.toByte(), 254.toByte(), 1, 2),
        ) as Inet4Address
        val loopback = InetAddress.getByAddress(
            byteArrayOf(127, 0, 0, 1),
        ) as Inet4Address
        val wildcard = InetAddress.getByAddress(
            byteArrayOf(0, 0, 0, 0),
        ) as Inet4Address

        assertTrue(task6IsHostNonLoopbackIpv4(linkLocal))
        assertFalse(task6IsHostNonLoopbackIpv4(loopback))
        assertFalse(task6IsHostNonLoopbackIpv4(wildcard))
    }

    @Test
    fun hostTcpNegativeAcceptsOnlyExpectedNetworkRejections() {
        assertTrue(task6IsExpectedTcpRejection(ConnectException()))
        assertTrue(task6IsExpectedTcpRejection(NoRouteToHostException()))
        assertTrue(task6IsExpectedTcpRejection(SocketTimeoutException()))
        assertFalse(task6IsExpectedTcpRejection(IOException()))
        assertFalse(task6IsExpectedTcpRejection(IllegalStateException()))
    }

    @Test
    fun runtimeTopologyIgnoresUnboundExposedPorts() {
        runtimeTopology(includeUnboundPorts = true).requireExactIsolation()
    }

    @Test
    fun runtimeTopologyRejectsUnexpectedPublishedPortsForEveryService() {
        listOf(
            "dovecot",
            "postfix",
            "oauth2-mock",
            "dovecot-operator",
        ).forEach { service ->
            assertFailsWith<IllegalStateException>(service) {
                runtimeTopology(extraPublishedService = service)
                    .requireExactIsolation()
            }
        }
    }

    @Test
    fun worstCaseNetworkHelperTimeoutExceedsItsSocketAttemptBudget() {
        val minimumHostTimeout = task6NetworkIsolationProcessTimeout(1)
        val maximumHostTimeout = task6NetworkIsolationProcessTimeout(32)

        assertEquals(Duration.ofSeconds(25), minimumHostTimeout)
        assertEquals(Duration.ofSeconds(25), maximumHostTimeout)
        assertTrue(minimumHostTimeout > Duration.ofSeconds(20))
        assertTrue(maximumHostTimeout > Duration.ofMillis(18_500))
        assertTrue(maximumHostTimeout <= Duration.ofSeconds(30))
    }

    @Test
    fun pythonAndKotlinNetworkHelperWallDeadlinesStayAligned() {
        val helperSource = Files.readString(
            repositoryRoot().resolve(
                "debug-dashboard/dashboard-server/testResources/" +
                    "dovecot-gate0c/network-isolation-check.py",
            ),
        )
        val wallSeconds = requireNotNull(
            Regex(
                """(?m)^MAX_WALL_SECONDS = ([0-9]+(?:\.[0-9]+)?)$""",
            ).find(helperSource),
        ).groupValues[1].toDouble()

        assertEquals(
            TASK6_NETWORK_HELPER_WALL_MILLIS,
            (wallSeconds * 1_000).toLong(),
        )
    }

    private fun runtimeTopology(
        extraPublishedService: String? = null,
        includeUnboundPorts: Boolean = false,
    ): Task6RuntimeTopology {
        val ports = mapOf(
            "dovecot" to portDocument(
                service = "dovecot",
                expected = listOf(
                    "31993/tcp" to "1993",
                    "31990/tcp" to "21995",
                ),
                extraPublishedService = extraPublishedService,
                includeUnboundPorts = includeUnboundPorts,
            ),
            "dovecot-operator" to portDocument(
                service = "dovecot-operator",
                expected = listOf("31993/tcp" to "2993"),
                extraPublishedService = extraPublishedService,
                includeUnboundPorts = includeUnboundPorts,
            ),
            "postfix" to portDocument(
                service = "postfix",
                expected = listOf("25/tcp" to "21025"),
                extraPublishedService = extraPublishedService,
                includeUnboundPorts = includeUnboundPorts,
            ),
            "oauth2-mock" to portDocument(
                service = "oauth2-mock",
                expected = listOf("8080/tcp" to "28080"),
                extraPublishedService = extraPublishedService,
                includeUnboundPorts = includeUnboundPorts,
            ),
        )
        val defaultNetwork = Json.parseToJsonElement(
            """{"mail-sandbox-task5-proof_default":{}}""",
        )
        val operatorNetwork = Json.parseToJsonElement(
            """{"mail-sandbox-task5-proof_operator-ingress":{}}""",
        )
        return Task6RuntimeTopology(
            ports = ports,
            networks = mapOf(
                "dovecot" to defaultNetwork,
                "dovecot-operator" to operatorNetwork,
                "postfix" to defaultNetwork,
                "oauth2-mock" to defaultNetwork,
            ),
            operatorIngressAddress = "172.31.0.5",
        )
    }

    private fun portDocument(
        service: String,
        expected: List<Pair<String, String>>,
        extraPublishedService: String?,
        includeUnboundPorts: Boolean,
    ): kotlinx.serialization.json.JsonElement {
        val entries = expected.map { (containerPort, hostPort) ->
            """"$containerPort":[{"HostIp":"127.0.0.1","HostPort":"$hostPort"}]"""
        }.toMutableList()
        if (includeUnboundPorts) {
            entries += """"65534/tcp":null"""
            entries += """"65533/tcp":[]"""
        }
        if (service == extraPublishedService) {
            entries +=
                """"65535/tcp":[{"HostIp":"127.0.0.1","HostPort":"65535"}]"""
        }
        return Json.parseToJsonElement("{${entries.joinToString(",")}}")
    }

    private fun repositoryRoot(): Path {
        val workingDirectory = Path.of(System.getProperty("user.dir"))
            .toAbsolutePath()
            .normalize()
        val dashboardRoot = when (workingDirectory.fileName?.toString()) {
            "dashboard-server" -> workingDirectory.parent
            "debug-dashboard" -> workingDirectory
            else -> error("unexpected Kotlin test working directory")
        }
        return requireNotNull(dashboardRoot.parent)
    }
}
