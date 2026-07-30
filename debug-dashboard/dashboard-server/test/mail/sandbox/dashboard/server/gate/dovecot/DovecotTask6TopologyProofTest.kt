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
