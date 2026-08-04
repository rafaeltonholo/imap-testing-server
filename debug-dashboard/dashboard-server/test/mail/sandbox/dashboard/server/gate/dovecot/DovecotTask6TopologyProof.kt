package mail.sandbox.dashboard.server.gate.dovecot

import java.net.Inet4Address
import java.nio.charset.StandardCharsets
import java.time.Duration
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

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

internal fun task6NetworkIsolationFailureDiagnostic(
    exitCode: Int,
    stdout: String,
    stderr: String,
): String? {
    if (exitCode == 0) {
        return if (stdout == "OK\n" && stderr.isEmpty()) {
            null
        } else {
            TASK6_INVALID_NETWORK_HELPER_RESULT
        }
    }
    if (stderr.isNotEmpty()) return TASK6_INVALID_NETWORK_HELPER_RESULT
    val expected = when (exitCode) {
        1 -> TASK6_NETWORK_HELPER_FAILURES
        2 -> TASK6_NETWORK_HELPER_INPUT_FAILURES
        else -> return TASK6_INVALID_NETWORK_HELPER_RESULT
    }
    val candidate = stdout.removeSuffix("\n")
    return if (stdout == "$candidate\n" && candidate in expected) {
        candidate
    } else {
        TASK6_INVALID_NETWORK_HELPER_RESULT
    }
}

internal fun requireTask6NetworkIsolationResult(
    exitCode: Int,
    stdout: String,
    stderr: String,
) {
    val failureDiagnostic = task6NetworkIsolationFailureDiagnostic(
        exitCode = exitCode,
        stdout = stdout,
        stderr = stderr,
    )
    check(failureDiagnostic == null) {
        "Default-network isolation helper failed: $failureDiagnostic"
    }
}

private val TASK6_NETWORK_HELPER_FAILURES = setOf(
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
)
private val TASK6_NETWORK_HELPER_INPUT_FAILURES = setOf(
    "INVALID_INVOCATION",
    "INVALID_INPUT",
)
private const val TASK6_INVALID_NETWORK_HELPER_RESULT = "INVALID_RESULT"
private const val TASK6_INVALID_RUNTIME_TOPOLOGY =
    "Dovecot Task 6 runtime topology is invalid"
private val TASK6_IPV4 = Regex(
    "(?:[0-9]{1,3}\\.){3}[0-9]{1,3}",
)

internal class FixedTask6DockerTopology(
    private val launchProfile: DovecotOperatorLaunchProfile,
    processRunner: EligibilityProcessRunner? = null,
) {
    private val repositoryRoot = launchProfile.repositoryRoot
    private val composeCommandPrefix =
        buildList {
            add(launchProfile.dockerCli.toString())
            add("compose")
            add("--project-directory")
            add(repositoryRoot.toString())
            launchProfile.composeFiles.forEach { composeFile ->
                add("-f")
                add(composeFile.toString())
            }
            add("--project-name")
            add(launchProfile.projectName)
            add("--profile")
            add(launchProfile.composeProfile)
        }
    private val processRunner =
        processRunner ?: Task6FixedProcessRunner(
            profile = launchProfile,
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
        val operatorIngress = operatorIngressAddress(networks)
        return Task6RuntimeTopology(
            ports = ports,
            networks = networks,
            operatorIngressAddress = operatorIngress,
        )
    }

    private fun operatorIngressAddress(
        networks: Map<String, JsonElement>,
    ): String {
        val operatorNetworks =
            networks["dovecot-operator"]
                ?.task6TopologyObject()
                ?: invalidTask6RuntimeTopology()
        val candidates = operatorNetworks.entries.filter { (name, _) ->
            name.endsWith("_operator-ingress")
        }
        if (candidates.size != 1) {
            invalidTask6RuntimeTopology()
        }
        val network = candidates.single().value.task6TopologyObject()
        val address = network.task6TopologyString("IPAddress")
        if (!TASK6_IPV4.matches(address)) {
            invalidTask6RuntimeTopology()
        }
        return address
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
                composeCommand(
                    "exec",
                    "-T",
                    "--index",
                    "1",
                    "oauth2-mock",
                    "python",
                    "-I",
                    "/proof/network-isolation-check.py",
                ),
                input,
                processTimeout,
            )
            requireTask6NetworkIsolationResult(
                exitCode = result.exitCode,
                stdout = result.stdout,
                stderr = result.stderr,
            )
        } finally {
            input.fill(0)
        }
    }

    private fun composeContainerId(service: String): String {
        require(service in FIXED_SERVICES)
        val result = runFixed(
            composeCommand("ps", "--quiet", service),
            ByteArray(0),
        )
        check(result.exitCode == 0 && result.stderr.isEmpty()) {
            "Fixed proof container lookup failed"
        }
        val id = result.stdout.removeSuffix("\n")
        check(
            result.stdout == "$id\n" &&
                CONTAINER_ID.matches(id),
        ) {
            "Fixed proof container identity is invalid"
        }
        requireContainerLabels(
            containerId = id,
            service = service,
        )
        return id
    }

    private fun requireContainerLabels(
        containerId: String,
        service: String,
    ) {
        val result = runFixed(
            inspectCommand(
                containerId = containerId,
                format = LABELS_FORMAT,
            ),
            ByteArray(0),
        )
        val valid = try {
            if (result.exitCode != 0 || result.stderr.isNotEmpty()) {
                false
            } else {
                val labels = parseExactJsonObject(result.stdout.trim())
                labels.exactString(COMPOSE_PROJECT_LABEL) ==
                    launchProfile.projectName &&
                    labels.exactString(COMPOSE_SERVICE_LABEL) == service &&
                    labels.exactString(COMPOSE_CONTAINER_NUMBER_LABEL) == "1"
            }
        } catch (_: Exception) {
            false
        }
        check(valid) {
            "Fixed proof container identity labels are invalid"
        }
    }

    private fun parseExactJsonObject(document: String): JsonObject {
        val rawKeys = requireUniqueObjectKeys(document)
        val parsed =
            Json.parseToJsonElement(document) as? JsonObject
                ?: throw IllegalStateException()
        check(rawKeys == parsed.keys)
        return parsed
    }

    private fun requireUniqueObjectKeys(
        document: String,
    ): Set<String> {
        check(document.firstOrNull() == '{' && document.lastOrNull() == '}')
        val frames = ArrayDeque<JsonContainerFrame>()
        var root: JsonContainerFrame? = null
        var previousSignificant: Char? = null
        var index = 0
        while (index < document.length) {
            when (val character = document[index]) {
                '"' -> {
                    val frame = frames.lastOrNull()
                    val keyPosition =
                        frame?.objectContainer == true &&
                            (
                                previousSignificant == '{' ||
                                    previousSignificant == ','
                                )
                    val start = index + 1
                    var escaped = false
                    index += 1
                    while (index < document.length) {
                        val current = document[index]
                        if (escaped) {
                            escaped = false
                        } else if (current == '\\') {
                            escaped = true
                        } else if (current == '"') {
                            break
                        }
                        index += 1
                    }
                    check(index < document.length && !escaped)
                    if (keyPosition) {
                        val key = document.substring(start, index)
                        check('\\' !in key)
                        check(frame.keys.add(key))
                    }
                    previousSignificant = '"'
                }
                '{' -> {
                    val frame = JsonContainerFrame(
                        objectContainer = true,
                    )
                    if (frames.isEmpty()) {
                        check(root == null)
                        root = frame
                    }
                    frames.addLast(frame)
                    previousSignificant = character
                }
                '[' -> {
                    frames.addLast(
                        JsonContainerFrame(
                            objectContainer = false,
                        ),
                    )
                    previousSignificant = character
                }
                '}' -> {
                    check(
                        frames.isNotEmpty() &&
                            frames.removeLast().objectContainer,
                    )
                    previousSignificant = character
                }
                ']' -> {
                    check(
                        frames.isNotEmpty() &&
                            !frames.removeLast().objectContainer,
                    )
                    previousSignificant = character
                }
                ' ', '\t', '\n', '\r' -> Unit
                else -> previousSignificant = character
            }
            index += 1
        }
        check(frames.isEmpty())
        return checkNotNull(root).keys.toSet()
    }

    private fun JsonObject.exactString(key: String): String? =
        (get(key) as? JsonPrimitive)
            ?.takeIf { it.isString }
            ?.content

    private fun inspectJson(
        containerId: String,
        format: String,
    ) = runFixed(
        inspectCommand(
            containerId = containerId,
            format = format,
        ),
        ByteArray(0),
    ).let { result ->
        check(result.exitCode == 0 && result.stderr.isEmpty()) {
            "Fixed proof container inspection failed"
        }
        try {
            val document = result.stdout.trim()
            val rawKeys = requireUniqueObjectKeys(document)
            val parsed =
                Json.parseToJsonElement(document) as? JsonObject
                    ?: invalidTask6RuntimeTopology()
            check(rawKeys == parsed.keys)
            parsed
        } catch (_: Exception) {
            invalidTask6RuntimeTopology()
        }
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
        command == networkIsolationCommand ||
            FIXED_SERVICES.any { service ->
                command == composeCommand("ps", "--quiet", service)
            } ||
            (
                command.size == 5 &&
                    command.take(3) == listOf(
                        launchProfile.dockerCli.toString(),
                        "inspect",
                        "--format",
                    ) &&
                    command[3] in setOf(
                        LABELS_FORMAT,
                        PORTS_FORMAT,
                        NETWORKS_FORMAT,
                    ) &&
                    CONTAINER_ID.matches(command[4])
                )

    private fun composeCommand(
        vararg suffix: String,
    ): List<String> = composeCommandPrefix + suffix

    private fun inspectCommand(
        containerId: String,
        format: String,
    ): List<String> =
        listOf(
            launchProfile.dockerCli.toString(),
            "inspect",
            "--format",
            format,
            containerId,
        )

    private data class FixedProcessResult(
        val exitCode: Int,
        val stdout: String,
        val stderr: String,
    )

    private data class JsonContainerFrame(
        val objectContainer: Boolean,
        val keys: MutableSet<String> = mutableSetOf(),
    )

    companion object {
        private val FIXED_SERVICES = listOf(
            "dovecot",
            "dovecot-operator",
            "postfix",
            "oauth2-mock",
        )
        private const val LABELS_FORMAT =
            "{{json .Config.Labels}}"
        private const val PORTS_FORMAT =
            "{{json .NetworkSettings.Ports}}"
        private const val NETWORKS_FORMAT =
            "{{json .NetworkSettings.Networks}}"
        private const val COMPOSE_PROJECT_LABEL =
            "com.docker.compose.project"
        private const val COMPOSE_SERVICE_LABEL =
            "com.docker.compose.service"
        private const val COMPOSE_CONTAINER_NUMBER_LABEL =
            "com.docker.compose.container-number"
        private val CONTAINER_ID = Regex("[0-9a-f]{64}")
        private val PROCESS_TIMEOUT = Duration.ofSeconds(10)
        private const val MAX_PROCESS_OUTPUT_BYTES = 64 * 1024
    }

    private val networkIsolationCommand =
        composeCommand(
            "exec",
            "-T",
            "--index",
            "1",
            "oauth2-mock",
            "python",
            "-I",
            "/proof/network-isolation-check.py",
        )
}

internal data class Task6RuntimeTopology(
    val ports: Map<String, JsonElement>,
    val networks: Map<String, JsonElement>,
    val operatorIngressAddress: String,
) {
    fun requireExactIsolation() {
        requireExactPublishedPorts(
            service = "dovecot-operator",
            expected = emptySet(),
        )
        requireExactPublishedPorts(
            service = "dovecot",
            expected = setOf("31993/tcp", "31995/tcp"),
        )
        requirePort("dovecot", "31993/tcp", "1993")
        requirePort("dovecot", "31995/tcp", "21995")
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
            networkDocument("dovecot-operator").keys
        check(operatorNetworks == setOf(OPERATOR_NETWORK)) {
            "Operator runtime network membership is invalid"
        }
        listOf("dovecot", "postfix", "oauth2-mock").forEach { service ->
            val serviceNetworks = networkDocument(service).keys
            check(serviceNetworks == setOf(DEFAULT_NETWORK)) {
                "Default service runtime network membership is invalid"
            }
        }
        check(TASK6_IPV4.matches(operatorIngressAddress)) {
            "Operator ingress address discovery failed"
        }
    }

    private fun requireExactPublishedPorts(
        service: String,
        expected: Set<String>,
    ) {
        val published = portDocument(service)
            .mapNotNull { (containerPort, bindings) ->
                when (bindings) {
                    JsonNull -> null
                    is JsonArray ->
                        containerPort.takeIf { bindings.isNotEmpty() }
                    else -> invalidTask6RuntimeTopology()
                }
            }
            .toSet()
        check(published == expected) {
            "Proof runtime has an unexpected protocol publication"
        }
    }

    private fun requirePort(
        service: String,
        containerPort: String,
        hostPort: String,
    ) {
        val bindings =
            portDocument(service)[containerPort] as? JsonArray
                ?: invalidTask6RuntimeTopology()
        check(bindings.size == 1) {
            "Proof runtime port binding is ambiguous"
        }
        val binding = bindings.single().task6TopologyObject()
        check(
            binding.task6TopologyString("HostIp") == "127.0.0.1" &&
                binding.task6TopologyString("HostPort") == hostPort,
        ) {
            "Proof runtime port is not loopback-only"
        }
    }

    private fun portDocument(service: String): JsonObject =
        ports[service]?.task6TopologyObject()
            ?: invalidTask6RuntimeTopology()

    private fun networkDocument(service: String): JsonObject =
        networks[service]?.task6TopologyObject()
            ?: invalidTask6RuntimeTopology()

    companion object {
        private const val DEFAULT_NETWORK =
            "mail-sandbox-task5-proof_default"
        private const val OPERATOR_NETWORK =
            "mail-sandbox-task5-proof_operator-ingress"
    }
}

private fun JsonElement.task6TopologyObject(): JsonObject =
    this as? JsonObject ?: invalidTask6RuntimeTopology()

private fun JsonObject.task6TopologyString(key: String): String {
    val primitive = get(key) as? JsonPrimitive
        ?: invalidTask6RuntimeTopology()
    if (!primitive.isString) {
        invalidTask6RuntimeTopology()
    }
    return primitive.content
}

private fun invalidTask6RuntimeTopology(): Nothing =
    throw IllegalStateException(TASK6_INVALID_RUNTIME_TOPOLOGY)
