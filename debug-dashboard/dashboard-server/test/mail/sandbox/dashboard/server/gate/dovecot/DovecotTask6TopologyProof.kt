package mail.sandbox.dashboard.server.gate.dovecot

import java.net.Inet4Address
import java.nio.charset.StandardCharsets
import java.time.Duration
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

internal fun task6NetworkIsolationProcessTimeout(
    hostCount: Int,
): Duration {
    require(hostCount in 1..TASK6_MAX_HOST_ADDRESSES) {
        "Task 6 host IPv4 inventory is out of bounds"
    }
    val connectAttempts = Math.addExact(
        hostCount,
        TASK6_FIXED_CONNECT_ATTEMPTS,
    )
    val socketBudgetMillis = Math.multiplyExact(
        connectAttempts.toLong(),
        TASK6_SOCKET_TIMEOUT_MILLIS,
    )
    return Duration.ofMillis(
        Math.addExact(
            maxOf(
                socketBudgetMillis,
                TASK6_NETWORK_HELPER_WALL_MILLIS,
            ),
            TASK6_NETWORK_HELPER_MARGIN_MILLIS,
        ),
    )
}

internal const val TASK6_NETWORK_HELPER_WALL_MILLIS = 20_000L
private const val TASK6_MAX_HOST_ADDRESSES = 32
private const val TASK6_FIXED_CONNECT_ATTEMPTS = 5
private const val TASK6_SOCKET_TIMEOUT_MILLIS = 500L
private const val TASK6_NETWORK_HELPER_MARGIN_MILLIS = 5_000L

internal class FixedTask6DockerTopology(
    private val profile: DovecotTask5ProofProfile,
) {
    private val repositoryRoot = profile.repositoryRoot
    private val processRunner = Task6FixedProcessRunner(
        dockerRouting = DovecotDockerRouting.task5Proof(profile),
        isApprovedCommand = ::isFixedCommand,
    )

    fun inspect(): Task6RuntimeTopology {
        val containers = FIXED_SERVICES.associateWith(::composeContainerId)
        val ports = containers.mapValues { (_, id) ->
            inspectJson(id, PORTS_FORMAT)
        }
        val networks = containers.mapValues { (_, id) ->
            inspectJson(id, NETWORKS_FORMAT)
        }
        val operatorNetworks =
            networks.getValue("dovecot-operator").jsonObject
        val operatorIngress = operatorNetworks.entries.single { (name, _) ->
            name.endsWith("_operator-ingress")
        }.value.jsonObject.getValue("IPAddress").jsonPrimitive.content
        return Task6RuntimeTopology(
            ports = ports,
            networks = networks,
            operatorIngressAddress = operatorIngress,
        )
    }

    fun requireDefaultNetworkIsolation(
        operatorIngressAddress: String,
        hostAddresses: List<Inet4Address>,
    ) {
        val processTimeout =
            task6NetworkIsolationProcessTimeout(hostAddresses.size)
        val input = buildString {
            append("operator ")
            append(operatorIngressAddress)
            append('\n')
            hostAddresses.forEach { address ->
                append("host ")
                append(address.hostAddress)
                append('\n')
            }
        }.toByteArray(StandardCharsets.US_ASCII)
        try {
            val result = runFixed(
                listOf(
                    "docker",
                    "compose",
                    "exec",
                    "-T",
                    "oauth2-mock",
                    "python",
                    "-I",
                    "/proof/network-isolation-check.py",
                ),
                input,
                processTimeout,
            )
            check(result.exitCode == 0) {
                "Default-network isolation helper failed"
            }
            check(result.stdout == "OK\n" && result.stderr.isEmpty()) {
                "Default-network isolation helper returned an invalid result"
            }
        } finally {
            input.fill(0)
        }
    }

    private fun composeContainerId(service: String): String {
        require(service in FIXED_SERVICES)
        val result = runFixed(
            listOf(
                "docker",
                "compose",
                "ps",
                "--quiet",
                service,
            ),
            ByteArray(0),
        )
        check(result.exitCode == 0 && result.stderr.isEmpty()) {
            "Fixed proof container lookup failed"
        }
        val id = result.stdout.trim()
        check(CONTAINER_ID.matches(id)) {
            "Fixed proof container identity is invalid"
        }
        return id
    }

    private fun inspectJson(
        containerId: String,
        format: String,
    ) = runFixed(
        listOf(
            "docker",
            "inspect",
            "--format",
            format,
            containerId,
        ),
        ByteArray(0),
    ).let { result ->
        check(result.exitCode == 0 && result.stderr.isEmpty()) {
            "Fixed proof container inspection failed"
        }
        Json.parseToJsonElement(result.stdout.trim())
    }

    private fun runFixed(
        command: List<String>,
        stdin: ByteArray,
        timeout: Duration = PROCESS_TIMEOUT,
    ): FixedProcessResult {
        val result = processRunner.run(
            EligibilityProcessRequest(
                argv = command,
                workingDirectory = repositoryRoot,
                stdin = stdin,
                timeout = timeout,
                maximumOutputBytes = MAX_PROCESS_OUTPUT_BYTES,
            ),
        )
        try {
            check(
                !result.timedOut &&
                    result.exitCode != null,
            ) {
                "Task 6 fixed process timed out"
            }
            return FixedProcessResult(
                exitCode = requireNotNull(result.exitCode),
                stdout = result.stdout.toString(StandardCharsets.UTF_8),
                stderr = result.stderr.toString(StandardCharsets.UTF_8),
            )
        } finally {
            result.stdout.fill(0)
            result.stderr.fill(0)
        }
    }

    private fun isFixedCommand(command: List<String>): Boolean =
        command in FIXED_COMMANDS ||
            (
                command.size == 5 &&
                    command.take(4) ==
                    listOf("docker", "compose", "ps", "--quiet") &&
                    command.last() in FIXED_SERVICES
                ) ||
            (
                command.size == 5 &&
                    command.take(3) ==
                    listOf("docker", "inspect", "--format") &&
                    command[3] in setOf(PORTS_FORMAT, NETWORKS_FORMAT) &&
                    CONTAINER_ID.matches(command[4])
                )

    private data class FixedProcessResult(
        val exitCode: Int,
        val stdout: String,
        val stderr: String,
    )

    companion object {
        private val FIXED_SERVICES = setOf(
            "dovecot",
            "dovecot-operator",
            "postfix",
            "oauth2-mock",
        )
        private const val PORTS_FORMAT =
            "{{json .NetworkSettings.Ports}}"
        private const val NETWORKS_FORMAT =
            "{{json .NetworkSettings.Networks}}"
        private val CONTAINER_ID = Regex("[0-9a-f]{64}")
        private val PROCESS_TIMEOUT = Duration.ofSeconds(10)
        private const val MAX_PROCESS_OUTPUT_BYTES = 64 * 1024
        private val FIXED_COMMANDS = setOf(
            listOf(
                "docker",
                "compose",
                "exec",
                "-T",
                "oauth2-mock",
                "python",
                "-I",
                "/proof/network-isolation-check.py",
            ),
        )
    }
}

internal data class Task6RuntimeTopology(
    val ports: Map<String, kotlinx.serialization.json.JsonElement>,
    val networks: Map<String, kotlinx.serialization.json.JsonElement>,
    val operatorIngressAddress: String,
) {
    fun requireExactIsolation() {
        requireExactPublishedPorts(
            service = "dovecot-operator",
            expected = setOf("31993/tcp"),
        )
        requirePort(
            service = "dovecot-operator",
            containerPort = "31993/tcp",
            hostPort = "2993",
        )
        requireExactPublishedPorts(
            service = "dovecot",
            expected = setOf("31993/tcp", "31990/tcp"),
        )
        requirePort("dovecot", "31993/tcp", "1993")
        requirePort("dovecot", "31990/tcp", "21995")
        requireExactPublishedPorts(
            service = "postfix",
            expected = setOf("25/tcp"),
        )
        requirePort("postfix", "25/tcp", "21025")
        requireExactPublishedPorts(
            service = "oauth2-mock",
            expected = setOf("8080/tcp"),
        )
        requirePort("oauth2-mock", "8080/tcp", "28080")

        val operatorNetworks =
            networks.getValue("dovecot-operator").jsonObject.keys
        check(operatorNetworks == setOf(OPERATOR_NETWORK)) {
            "Operator runtime network membership is invalid"
        }
        listOf("dovecot", "postfix", "oauth2-mock").forEach { service ->
            val serviceNetworks = networks.getValue(service).jsonObject.keys
            check(serviceNetworks == setOf(DEFAULT_NETWORK)) {
                "Default service runtime network membership is invalid"
            }
        }
        check(IPV4.matches(operatorIngressAddress)) {
            "Operator ingress address discovery failed"
        }
    }

    private fun requireExactPublishedPorts(
        service: String,
        expected: Set<String>,
    ) {
        val published = ports.getValue(service)
            .jsonObject
            .filterValues { bindings ->
                bindings !is JsonNull &&
                    (bindings !is JsonArray || bindings.isNotEmpty())
            }
            .keys
        check(published == expected) {
            "Proof runtime has an unexpected protocol publication"
        }
    }

    private fun requirePort(
        service: String,
        containerPort: String,
        hostPort: String,
    ) {
        val bindings = ports.getValue(service)
            .jsonObject
            .getValue(containerPort) as JsonArray
        check(bindings.size == 1) {
            "Proof runtime port binding is ambiguous"
        }
        val binding = bindings.single().jsonObject
        check(
            binding.getValue("HostIp").jsonPrimitive.content == "127.0.0.1" &&
                binding.getValue("HostPort").jsonPrimitive.content == hostPort,
        ) {
            "Proof runtime port is not loopback-only"
        }
    }

    companion object {
        private const val DEFAULT_NETWORK =
            "mail-sandbox-task5-proof_default"
        private const val OPERATOR_NETWORK =
            "mail-sandbox-task5-proof_operator-ingress"
        private val IPV4 = Regex(
            "(?:[0-9]{1,3}\\.){3}[0-9]{1,3}",
        )
    }
}
