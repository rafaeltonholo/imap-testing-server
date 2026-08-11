package mail.sandbox.dashboard.server.gate.stalwart

import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.TimeUnit

internal data class StalwartResolvedMount(
    val type: String,
    val source: Path,
    val destination: String,
    val readWrite: Boolean,
)

internal object StalwartDockerMountAudit {
    private const val IMAGE =
        "stalwartlabs/stalwart:v0.16.17@sha256:a8108e19bd927e172d4d8c128907b8dfc93fd180ae8ee07dccdd42cb97eb9dfa"
    private const val PROJECT = "mail-sandbox-stalwart-gate"
    private const val COMPOSE_RELATIVE =
        "dashboard-server/testResources/stalwart-gate0b/compose.yml"
    private const val DATA_RELATIVE = ".runtime/stalwart-gate0b/data"
    private val services = listOf("stalwart-data-owner", "stalwart")
    private val containerId = Regex("[a-f0-9]{12,64}")

    fun assertReviewedLiveMounts(projectRoot: Path) {
        val root = existingDirectory(projectRoot, "dashboard project root")
        val compose = root.resolve(COMPOSE_RELATIVE)
        require(Files.isRegularFile(compose)) {
            "Gate Compose file is absent"
        }
        val fixtureDirectory = existingDirectory(compose.parent, "fixture directory")
        val dataDirectory = existingDirectory(root.resolve(DATA_RELATIVE), "gate data directory")

        validateImageVolumeTargets(
            run(
                listOf(
                    "docker",
                    "image",
                    "inspect",
                    "--format",
                    "{{range \$target, \$_ := .Config.Volumes}}" +
                        "{{println \$target}}{{end}}",
                    IMAGE,
                ),
            ).lineSequence().filter(String::isNotBlank).toSet(),
        )

        services.forEach { service ->
            val id = run(
                listOf(
                    "docker",
                    "compose",
                    "-p",
                    PROJECT,
                    "-f",
                    compose.toString(),
                    "ps",
                    "--all",
                    "--quiet",
                    service,
                ),
            ).lineSequence().filter(String::isNotBlank).singleOrNull()
                ?: throw IllegalStateException(
                    "Gate mount audit did not resolve exactly one $service container",
                )
            require(containerId.matches(id)) {
                "Gate mount audit returned an invalid container ID"
            }
            val mounts = parseResolvedMounts(
                run(
                    listOf(
                        "docker",
                        "inspect",
                        "--format",
                        "{{range .Mounts}}{{printf \"%s\\t%s\\t%s\\t%t\\n\" " +
                            ".Type .Source .Destination .RW}}{{end}}",
                        id,
                    ),
                ),
            )
            validateResolvedMounts(
                service = service,
                mounts = mounts,
                expectedFixtureDirectory = fixtureDirectory,
                expectedDataDirectory = dataDirectory,
            )
        }
    }

    fun validateImageVolumeTargets(targets: Set<String>) {
        require(targets == setOf("/etc/stalwart", "/var/lib/stalwart")) {
            "Pinned Stalwart image volume targets differ from the reviewed boundary"
        }
    }

    fun parseResolvedMounts(output: String): List<StalwartResolvedMount> =
        output.lineSequence()
            .filter(String::isNotBlank)
            .map { line ->
                val fields = line.split('\t')
                require(fields.size == 4) {
                    "Docker mount inspection returned a malformed row"
                }
                val readWrite = when (fields[3]) {
                    "true" -> true
                    "false" -> false
                    else -> throw IllegalArgumentException(
                        "Docker mount inspection returned an invalid RW value",
                    )
                }
                StalwartResolvedMount(
                    type = fields[0],
                    source = Path.of(fields[1]).toAbsolutePath().normalize(),
                    destination = fields[2],
                    readWrite = readWrite,
                )
            }
            .toList()

    fun validateResolvedMounts(
        service: String,
        mounts: List<StalwartResolvedMount>,
        expectedFixtureDirectory: Path,
        expectedDataDirectory: Path,
    ) {
        require(service in services) {
            "Mount audit is restricted to Gate 0B services"
        }
        require(mounts.size == 2 && mounts.all { it.type == "bind" }) {
            "$service must have exactly two bind mounts and zero Docker volumes"
        }
        val mountsByDestination = mounts.associateBy(StalwartResolvedMount::destination)
        require(
            mountsByDestination.size == 2 &&
                mountsByDestination.keys == setOf("/etc/stalwart", "/var/lib/stalwart"),
        ) {
            "$service mount targets differ from the reviewed boundary"
        }
        val config = requireNotNull(mountsByDestination["/etc/stalwart"])
        val data = requireNotNull(mountsByDestination["/var/lib/stalwart"])
        require(
            existingDirectory(config.source, "$service config mount source") ==
                existingDirectory(expectedFixtureDirectory, "expected fixture directory") &&
                !config.readWrite,
        ) {
            "$service config mount is not the exact read-only fixture bind"
        }
        require(
            existingDirectory(data.source, "$service data mount source") ==
                existingDirectory(expectedDataDirectory, "expected gate data directory") &&
                data.readWrite,
        ) {
            "$service data mount is not the exact writable scratch bind"
        }
    }

    private fun run(command: List<String>): String {
        val process = ProcessBuilder(command)
            .redirectError(ProcessBuilder.Redirect.DISCARD)
            .start()
        if (!process.waitFor(10, TimeUnit.SECONDS)) {
            process.destroyForcibly()
            throw IllegalStateException("Gate Docker mount audit command timed out")
        }
        check(process.exitValue() == 0) {
            "Gate Docker mount audit command failed"
        }
        return process.inputStream.bufferedReader().use { it.readText() }
    }

    private fun existingDirectory(path: Path, label: String): Path =
        runCatching {
            require(Files.isDirectory(path) && !Files.isSymbolicLink(path)) {
                "$label is absent or symbolic"
            }
            path.toRealPath()
        }.getOrElse { failure ->
            throw IllegalArgumentException("$label is invalid", failure)
        }
}
