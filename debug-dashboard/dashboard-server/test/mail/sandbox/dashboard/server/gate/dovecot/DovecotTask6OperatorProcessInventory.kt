package mail.sandbox.dashboard.server.gate.dovecot

import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.util.ArrayDeque
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull

internal class DovecotTask6OperatorProcessInventory(
    private val profile: DovecotOperatorLaunchProfile,
    private val processRunner: EligibilityProcessRunner =
        Task6FixedProcessRunner(
            profile = profile,
            isApprovedCommand = { command ->
                isApprovedCommand(profile, command)
            },
        ),
) : DovecotTask6ProcessInventory {
    override fun count(): Int =
        try {
            countValidated()
        } catch (failure: Exception) {
            if (failure is InterruptedException) {
                Thread.currentThread().interrupt()
            }
            invalidInventory()
        }

    override fun toString(): String =
        "DovecotTask6OperatorProcessInventory(fixed, redacted)"

    private fun countValidated(): Int {
        val containerId = resolveContainerId()
        requireExactLabels(containerId)
        val network = resolveSoleOperatorNetwork(containerId)
        requireExactInternalNetwork(
            containerId = containerId,
            network = network,
        )
        return parseTop(
            runFixed(
                listOf(
                    profile.dockerCli.toString(),
                    "top",
                    containerId,
                    "-ww",
                    "-eo",
                    "pid,args",
                ),
            ),
        )
    }

    private fun resolveContainerId(): String {
        val output = runFixed(composePrefix() + listOf(
            "ps",
            "--quiet",
            profile.service,
        ))
        val candidate = output.removeSuffix("\n")
        check(
            output == "$candidate\n" &&
                CONTAINER_ID.matches(candidate),
        )
        return candidate
    }

    private fun requireExactLabels(containerId: String) {
        val labels = parseJsonObject(
            runFixed(
                listOf(
                    profile.dockerCli.toString(),
                    "inspect",
                    "--format",
                    LABELS_FORMAT,
                    containerId,
                ),
            ),
        )
        check(
            labels.exactString(COMPOSE_PROJECT_LABEL) ==
                profile.projectName &&
                labels.exactString(COMPOSE_SERVICE_LABEL) ==
                profile.service &&
                labels.exactString(COMPOSE_CONTAINER_NUMBER_LABEL) ==
                "1",
        )
    }

    private fun resolveSoleOperatorNetwork(
        containerId: String,
    ): ValidatedNetwork {
        val networks = parseJsonObject(
            runFixed(
                listOf(
                    profile.dockerCli.toString(),
                    "inspect",
                    "--format",
                    NETWORKS_FORMAT,
                    containerId,
                ),
            ),
        )
        val expectedName = "${profile.projectName}_operator-ingress"
        check(networks.keys == setOf(expectedName))
        val network = networks.getValue(expectedName) as? JsonObject
        check(network != null)
        val networkId = network.exactString(NETWORK_ID_KEY)
        check(networkId != null && CONTAINER_ID.matches(networkId))
        return ValidatedNetwork(
            name = expectedName,
            id = networkId,
        )
    }

    private fun requireExactInternalNetwork(
        containerId: String,
        network: ValidatedNetwork,
    ) {
        val inspected = parseJsonObject(
            runFixed(
                listOf(
                    profile.dockerCli.toString(),
                    "network",
                    "inspect",
                    "--format",
                    NETWORK_FORMAT,
                    network.id,
                ),
            ),
        )
        check(
            inspected.exactString("Name") == network.name &&
                inspected.exactString("Id") == network.id &&
                inspected.exactBoolean("Internal") == true,
        )
        val containers = inspected["Containers"] as? JsonObject
        check(
            containers != null &&
                containers.keys == setOf(containerId) &&
                containers.getValue(containerId) is JsonObject,
        )
    }

    private fun parseTop(output: String): Int {
        check(
            output.endsWith('\n') &&
                '\r' !in output &&
                '\u0000' !in output,
        )
        val lines = output.split('\n')
        check(
            lines.size >= 2 &&
                lines.last().isEmpty() &&
                TOP_HEADER.matches(lines.first()),
        )
        val seenPids = mutableSetOf<String>()
        var count = 0
        lines.subList(1, lines.lastIndex).forEach { line ->
            check(line.isNotEmpty())
            val separator = line.indexOf(' ')
            check(separator > 0)
            val pid = line.substring(0, separator)
            check(
                PID.matches(pid) &&
                    pid.toLongOrNull() in 1..Int.MAX_VALUE.toLong() &&
                    seenPids.add(pid),
            )
            var commandOffset = separator
            while (
                commandOffset < line.length &&
                line[commandOffset] == ' '
            ) {
                commandOffset += 1
            }
            check(commandOffset < line.length)
            val command = line.substring(commandOffset)
            check(
                command.isNotEmpty() &&
                    command.first() != ' ' &&
                    command.last() != ' ',
            )
            if (command == expectedOpenSslCommand()) {
                count = Math.addExact(count, 1)
                check(count <= MAX_OPENSSL_PROCESSES)
            } else {
                check(!command.contains("openssl", ignoreCase = true))
            }
        }
        return count
    }

    private fun expectedOpenSslCommand(): String {
        val start = profile.argv.indexOf(OPENSSL_EXECUTABLE)
        check(start >= 0)
        return profile.argv.drop(start).joinToString(" ")
    }

    private fun runFixed(command: List<String>): String {
        var result: EligibilityProcessResult? = null
        try {
            result = processRunner.run(
                EligibilityProcessRequest(
                    argv = command,
                    workingDirectory = profile.repositoryRoot,
                    stdin = ByteArray(0),
                    timeout = PROCESS_TIMEOUT,
                    maximumOutputBytes = MAX_PROCESS_OUTPUT_BYTES,
                ),
            )
            check(
                !result.timedOut &&
                    result.exitCode == 0 &&
                    result.stdout.size <= MAX_PROCESS_OUTPUT_BYTES &&
                    result.stderr.size <= MAX_PROCESS_OUTPUT_BYTES &&
                    result.stderr.isEmpty(),
            )
            return decodeUtf8Strict(result.stdout)
        } finally {
            result?.stdout?.fill(0)
            result?.stderr?.fill(0)
        }
    }

    private fun parseJsonObject(output: String): JsonObject {
        check(
            output.endsWith('\n') &&
                output.count { it == '\n' } == 1 &&
                '\r' !in output &&
                '\u0000' !in output,
        )
        val document = output.dropLast(1)
        val parsed = Json.parseToJsonElement(document) as? JsonObject
        check(parsed != null)
        val rawKeys = requireUniqueObjectKeys(document)
        check(
            rawKeys == parsed.keys,
        )
        return parsed
    }

    private fun requireUniqueObjectKeys(document: String): Set<String> {
        check(document.firstOrNull() == '{' && document.lastOrNull() == '}')
        val frames = ArrayDeque<JsonContainerFrame>()
        var root: JsonContainerFrame? = null
        var previousSignificant: Char? = null
        var index = 0
        while (index < document.length) {
            when (val character = document[index]) {
                '"' -> {
                    val frame = frames.peekLast()
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
            ?.contentOrNull

    private fun JsonObject.exactBoolean(key: String): Boolean? =
        (get(key) as? JsonPrimitive)
            ?.takeUnless { it.isString }
            ?.booleanOrNull

    private data class ValidatedNetwork(
        val name: String,
        val id: String,
    )

    private data class JsonContainerFrame(
        val objectContainer: Boolean,
        val keys: MutableSet<String> = mutableSetOf(),
    )

    private fun composePrefix(): List<String> =
        buildList {
            add(profile.dockerCli.toString())
            add("compose")
            add("--project-directory")
            add(profile.repositoryRoot.toString())
            profile.composeFiles.forEach { composeFile ->
                add("-f")
                add(composeFile.toString())
            }
            add("--project-name")
            add(profile.projectName)
            add("--profile")
            add(profile.composeProfile)
        }

    companion object {
        private const val INVALID_INVENTORY = "INVALID_INVENTORY"
        private const val OPENSSL_EXECUTABLE = "/usr/bin/openssl"
        private const val LABELS_FORMAT = "{{json .Config.Labels}}"
        private const val NETWORKS_FORMAT =
            "{{json .NetworkSettings.Networks}}"
        private const val NETWORK_FORMAT = "{{json .}}"
        private const val COMPOSE_PROJECT_LABEL =
            "com.docker.compose.project"
        private const val COMPOSE_SERVICE_LABEL =
            "com.docker.compose.service"
        private const val COMPOSE_CONTAINER_NUMBER_LABEL =
            "com.docker.compose.container-number"
        private const val NETWORK_ID_KEY = "NetworkID"
        private val TOP_HEADER = Regex("PID +COMMAND")
        private const val MAX_OPENSSL_PROCESSES = 16
        private const val MAX_PROCESS_OUTPUT_BYTES = 64 * 1024
        private val PROCESS_TIMEOUT: Duration = Duration.ofSeconds(10)
        private val CONTAINER_ID = Regex("[0-9a-f]{64}")
        private val PID = Regex("[1-9][0-9]*")

        internal fun isApprovedCommand(
            profile: DovecotOperatorLaunchProfile,
            command: List<String>,
        ): Boolean {
            val docker = profile.dockerCli.toString()
            val composePs = buildList {
                add(docker)
                add("compose")
                add("--project-directory")
                add(profile.repositoryRoot.toString())
                profile.composeFiles.forEach { composeFile ->
                    add("-f")
                    add(composeFile.toString())
                }
                add("--project-name")
                add(profile.projectName)
                add("--profile")
                add(profile.composeProfile)
                add("ps")
                add("--quiet")
                add(profile.service)
            }
            return command == composePs ||
                (
                    command.size == 5 &&
                        command.take(3) ==
                        listOf(docker, "inspect", "--format") &&
                        command[3] in
                        setOf(LABELS_FORMAT, NETWORKS_FORMAT) &&
                        CONTAINER_ID.matches(command[4])
                    ) ||
                (
                    command.size == 6 &&
                        command.take(4) ==
                        listOf(
                            docker,
                            "network",
                            "inspect",
                            "--format",
                        ) &&
                        command[4] == NETWORK_FORMAT &&
                        CONTAINER_ID.matches(command[5])
                    ) ||
                (
                    command.size == 6 &&
                        command.take(2) == listOf(docker, "top") &&
                        CONTAINER_ID.matches(command[2]) &&
                        command.drop(3) ==
                        listOf("-ww", "-eo", "pid,args")
                    )
        }

        private fun decodeUtf8Strict(bytes: ByteArray): String =
            StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes))
                .toString()

        private fun invalidInventory(): Nothing =
            throw IllegalStateException(INVALID_INVENTORY)
    }
}
