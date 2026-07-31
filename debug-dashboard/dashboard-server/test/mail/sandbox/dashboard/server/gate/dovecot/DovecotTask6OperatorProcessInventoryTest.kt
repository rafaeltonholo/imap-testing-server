package mail.sandbox.dashboard.server.gate.dovecot

import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.time.Duration
import java.util.ArrayDeque
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DovecotTask6OperatorProcessInventoryTest {
    @Test
    fun defaultRunnerApprovesOnlyTheFiveFixedCanonicalCommandShapes() {
        InventoryFixture().use { fixture ->
            listOf(
                fixture.composePsCommand,
                fixture.labelsCommand,
                fixture.containerNetworksCommand,
                fixture.networkCommand,
                fixture.topCommand,
            ).forEach { command ->
                assertTrue(
                    DovecotTask6OperatorProcessInventory
                        .isApprovedCommand(fixture.profile, command),
                )
            }

            listOf(
                listOf("docker") + fixture.composePsCommand.drop(1),
                fixture.composePsCommand + "--all",
                fixture.labelsCommand.dropLast(1) + "not-an-id",
                fixture.networkCommand.dropLast(1) + "not-a-network",
                fixture.topCommand.dropLast(1) + "pid,command",
                listOf(
                    fixture.docker.toString(),
                    "sh",
                    "-c",
                    fixture.topCommand.joinToString(" "),
                ),
            ).forEach { command ->
                assertFalse(
                    DovecotTask6OperatorProcessInventory
                        .isApprovedCommand(fixture.profile, command),
                )
            }
        }
    }

    @Test
    fun resolvesAndValidatesIdentityBeforeRunningOneExactInventoryCommand() {
        InventoryFixture().use { fixture ->
            val runner = RecordingInventoryRunner(
                fixture.successfulResults(topOutput = topOutput(fixture)),
            )

            val count = DovecotTask6OperatorProcessInventory(
                profile = fixture.profile,
                processRunner = runner,
            ).count()

            assertEquals(1, count)
            assertEquals(
                listOf(
                    fixture.composePsCommand,
                    fixture.labelsCommand,
                    fixture.containerNetworksCommand,
                    fixture.networkCommand,
                    fixture.topCommand,
                ),
                runner.requests.map { it.argv },
            )
            runner.requests.forEach { request ->
                assertEquals(fixture.root, request.workingDirectory)
                assertTrue(request.stdin.isEmpty())
                assertEquals(Duration.ofSeconds(10), request.timeout)
                assertEquals(64 * 1024, request.maximumOutputBytes)
                assertEquals(fixture.docker.toString(), request.argv.first())
                assertFalse(request.argv.any { it == "sh" || it == "bash" })
            }
        }
    }

    @Test
    fun requiresOneExactNewlineTerminatedLowercaseContainerId() {
        InventoryFixture().use { fixture ->
            listOf(
                "",
                "$CONTAINER_ID",
                "\n",
                "$CONTAINER_ID\n\n",
                "${CONTAINER_ID.uppercase()}\n",
                "${"a".repeat(63)}\n",
                "$CONTAINER_ID\n${"c".repeat(64)}\n",
                " $CONTAINER_ID\n",
            ).forEach { output ->
                val runner = RecordingInventoryRunner(
                    ArrayDeque(
                        listOf(
                            processResult(stdout = output),
                        ),
                    ),
                )

                assertInvalidInventory {
                    DovecotTask6OperatorProcessInventory(
                        fixture.profile,
                        runner,
                    ).count()
                }
                assertEquals(1, runner.requests.size)
            }
        }
    }

    @Test
    fun requiresExactComposeIdentityLabelsBeforeUsingTheContainerId() {
        InventoryFixture().use { fixture ->
            listOf(
                "{}\n",
                "null\n",
                "[]\n",
                "{\"com.docker.compose.project\":\"wrong\"," +
                    "\"com.docker.compose.service\":\"dovecot-operator\"," +
                    "\"com.docker.compose.container-number\":\"1\"}\n",
                "{\"com.docker.compose.project\":\"${fixture.profile.projectName}\"," +
                    "\"com.docker.compose.service\":\"dovecot\"," +
                    "\"com.docker.compose.container-number\":\"1\"}\n",
                "{\"com.docker.compose.project\":\"${fixture.profile.projectName}\"," +
                    "\"com.docker.compose.service\":\"dovecot-operator\"," +
                    "\"com.docker.compose.container-number\":\"2\"}\n",
                "{\"com.docker.compose.project\":\"${fixture.profile.projectName}\"," +
                    "\"com.docker.compose.service\":\"dovecot-operator\"," +
                    "\"com.docker.compose.container-number\":1}\n",
                "{\"com.docker.compose.project\":\"${fixture.profile.projectName}\"," +
                    "\"com.docker.compose.service\":\"dovecot-operator\"," +
                    "\"com.docker.compose.container-number\":\"1\"\n",
                "{\"com.docker.compose.project\":\"${fixture.profile.projectName}\"," +
                    "\"com.docker.compose.project\":\"ambiguous\"," +
                    "\"com.docker.compose.service\":\"dovecot-operator\"," +
                    "\"com.docker.compose.container-number\":\"1\"}\n",
            ).forEach { labels ->
                val runner = RecordingInventoryRunner(
                    ArrayDeque(
                        listOf(
                            processResult(stdout = "$CONTAINER_ID\n"),
                            processResult(stdout = labels),
                        ),
                    ),
                )

                assertInvalidInventory {
                    DovecotTask6OperatorProcessInventory(
                        fixture.profile,
                        runner,
                    ).count()
                }
                assertEquals(2, runner.requests.size)
            }
        }
    }

    @Test
    fun requiresOneExactOperatorNetworkAndOneExactNetworkId() {
        InventoryFixture().use { fixture ->
            val expectedName =
                "${fixture.profile.projectName}_operator-ingress"
            listOf(
                "{}\n",
                "null\n",
                "[]\n",
                "{\"wrong\":{\"NetworkID\":\"$NETWORK_ID\"}}\n",
                "{\"$expectedName\":{}}\n",
                "{\"$expectedName\":{\"NetworkID\":null}}\n",
                "{\"$expectedName\":{\"NetworkID\":\"short\"}}\n",
                "{\"$expectedName\":{\"NetworkID\":\"${NETWORK_ID.uppercase()}\"}}\n",
                "{\"$expectedName\":{\"NetworkID\":\"$NETWORK_ID\"}," +
                    "\"extra\":{\"NetworkID\":\"${"d".repeat(64)}\"}}\n",
                "{\"$expectedName\":{\"NetworkID\":\"${"d".repeat(64)}\"," +
                    "\"NetworkID\":\"$NETWORK_ID\"}}\n",
                "{\"$expectedName\":{\"NetworkID\":\"$NETWORK_ID\"}\n",
            ).forEach { networks ->
                val runner = RecordingInventoryRunner(
                    fixture.successfulResults(
                        topOutput = topOutput(fixture),
                        containerNetworks = networks,
                    ),
                )

                assertInvalidInventory {
                    DovecotTask6OperatorProcessInventory(
                        fixture.profile,
                        runner,
                    ).count()
                }
                assertEquals(3, runner.requests.size)
            }
        }
    }

    @Test
    fun requiresTheExactInternalNetworkWithOnlyTheValidatedOperator() {
        InventoryFixture().use { fixture ->
            val expectedName =
                "${fixture.profile.projectName}_operator-ingress"
            val otherId = "c".repeat(64)
            listOf(
                "{}\n",
                "null\n",
                "[]\n",
                "{\"Name\":\"wrong\",\"Id\":\"$NETWORK_ID\"," +
                    "\"Internal\":true,\"Containers\":{\"$CONTAINER_ID\":{}}}\n",
                "{\"Name\":\"$expectedName\",\"Id\":\"$NETWORK_ID\"," +
                    "\"Internal\":false,\"Containers\":{\"$CONTAINER_ID\":{}}}\n",
                "{\"Name\":\"$expectedName\",\"Id\":\"$otherId\"," +
                    "\"Internal\":true,\"Containers\":{\"$CONTAINER_ID\":{}}}\n",
                "{\"Name\":\"$expectedName\",\"Id\":\"$NETWORK_ID\"," +
                    "\"Internal\":true,\"Containers\":{}}\n",
                "{\"Name\":\"$expectedName\",\"Id\":\"$NETWORK_ID\"," +
                    "\"Internal\":true,\"Containers\":{\"$otherId\":{}}}\n",
                "{\"Name\":\"$expectedName\",\"Id\":\"$NETWORK_ID\"," +
                    "\"Internal\":true,\"Containers\":{\"$CONTAINER_ID\":{}," +
                    "\"$otherId\":{}}}\n",
                "{\"Name\":\"$expectedName\",\"Id\":\"$NETWORK_ID\"," +
                    "\"Internal\":true,\"Containers\":{\"$CONTAINER_ID\":" +
                    "{\"Name\":\"first\"},\"$CONTAINER_ID\":" +
                    "{\"Name\":\"second\"}}}\n",
                "{\"Name\":\"$expectedName\",\"Id\":\"$NETWORK_ID\"," +
                    "\"Internal\":\"true\",\"Containers\":{\"$CONTAINER_ID\":{}}}\n",
                "{\"Name\":\"$expectedName\",\"Id\":\"$NETWORK_ID\"," +
                    "\"Internal\":true,\"Containers\":{\"$CONTAINER_ID\":{}}\n",
            ).forEach { network ->
                val runner = RecordingInventoryRunner(
                    fixture.successfulResults(
                        topOutput = topOutput(fixture),
                        network = network,
                    ),
                )

                assertInvalidInventory {
                    DovecotTask6OperatorProcessInventory(
                        fixture.profile,
                        runner,
                    ).count()
                }
                assertEquals(4, runner.requests.size)
            }
        }
    }

    @Test
    fun countsZeroOneAndSixteenExactOpenSslRowsAmongOrdinaryProcesses() {
        InventoryFixture().use { fixture ->
            listOf(0, 1, 16).forEach { expected ->
                val rows = buildList {
                    add("7 /usr/sbin/dovecot -F")
                    repeat(expected) { index ->
                        add(
                            "${100 + index} " +
                                fixture.expectedOpenSslCommand,
                        )
                    }
                    add("900 dovecot/anvil")
                }
                val runner = RecordingInventoryRunner(
                    fixture.successfulResults(
                        topOutput = "PID COMMAND\n" +
                            rows.joinToString(
                                separator = "\n",
                                postfix = "\n",
                            ),
                    ),
                )

                assertEquals(
                    expected,
                    DovecotTask6OperatorProcessInventory(
                        fixture.profile,
                        runner,
                    ).count(),
                )
            }
        }
    }

    @Test
    fun rejectsHeaderPaddingOutsideTheExactLiteralHeader() {
        InventoryFixture().use { fixture ->
            val output =
                "PID                 COMMAND\n" +
                    "7                   /usr/sbin/dovecot -F\n" +
                    "123                 ${fixture.expectedOpenSslCommand}\n"
            val runner = RecordingInventoryRunner(
                fixture.successfulResults(topOutput = output),
            )

            assertInvalidInventory {
                DovecotTask6OperatorProcessInventory(
                    fixture.profile,
                    runner,
                ).count()
            }
        }
    }

    @Test
    fun rejectsMalformedTruncatedDefunctAndDuplicateProcessRows() {
        InventoryFixture().use { fixture ->
            val exact = fixture.expectedOpenSslCommand
            listOf(
                "",
                "PID COMMAND",
                "PID CMD\n",
                " PID COMMAND\n",
                "PID COMMAND \n",
                "PID COMMAND\n\n",
                "PID COMMAND\nabc /usr/sbin/dovecot -F\n",
                "PID COMMAND\n0 /usr/sbin/dovecot -F\n",
                "PID COMMAND\n01 /usr/sbin/dovecot -F\n",
                "PID COMMAND\n2147483648 /usr/sbin/dovecot -F\n",
                "PID COMMAND\n7\n",
                "PID COMMAND\n7  /usr/sbin/dovecot -F\n\n",
                "PID COMMAND\n7 /usr/sbin/dovecot -F\n7 $exact\n",
                "PID COMMAND\n7 [openssl] <defunct>\n",
                "PID COMMAND\n7 /usr/bin/openssl\n",
                "PID COMMAND\n7 /usr/bin/openssl s_client -quiet\n",
                "PID COMMAND\r\n7 $exact\r\n",
                "PID COMMAND\n7\u0000$exact\n",
            ).forEach { top ->
                val runner = RecordingInventoryRunner(
                    fixture.successfulResults(topOutput = top),
                )

                assertInvalidInventory {
                    DovecotTask6OperatorProcessInventory(
                        fixture.profile,
                        runner,
                    ).count()
                }
            }
        }
    }

    @Test
    fun rejectsEveryOpenSslLookingRowUnlessItsFullCommandIsExact() {
        InventoryFixture().use { fixture ->
            val exact = fixture.expectedOpenSslCommand
            listOf(
                "$exact -pass secret-canary",
                exact.removeSuffix(" localhost"),
                exact.replace("127.0.0.1:31993", "127.0.0.1:39999"),
                exact.replace("/usr/bin/openssl", "/bin/openssl"),
                "wrapper /usr/bin/openssl s_client",
                "[openssl] <defunct>",
                "openssl",
            ).forEach { command ->
                val runner = RecordingInventoryRunner(
                    fixture.successfulResults(
                        topOutput = "PID COMMAND\n77 $command\n",
                    ),
                )

                val failure = assertFailsWith<IllegalStateException> {
                    DovecotTask6OperatorProcessInventory(
                        fixture.profile,
                        runner,
                    ).count()
                }
                assertEquals("INVALID_INVENTORY", failure.message)
                assertFalse(failure.toString().contains("secret-canary"))
                assertEquals(null, failure.cause)
            }
        }
    }

    @Test
    fun rejectsMoreThanTheFixedSixteenProcessCapacity() {
        InventoryFixture().use { fixture ->
            val output = buildString {
                append("PID COMMAND\n")
                repeat(17) { index ->
                    append(100 + index)
                    append(' ')
                    append(fixture.expectedOpenSslCommand)
                    append('\n')
                }
            }
            val runner = RecordingInventoryRunner(
                fixture.successfulResults(topOutput = output),
            )

            assertInvalidInventory {
                DovecotTask6OperatorProcessInventory(
                    fixture.profile,
                    runner,
                ).count()
            }
        }
    }

    @Test
    fun mapsEveryCommandFailureToOneFixedRedactedDiagnostic() {
        InventoryFixture().use { fixture ->
            listOf(
                processResult(exitCode = 9, stdout = "secret-canary\n"),
                processResult(stderr = "secret-canary\n"),
                processResult(exitCode = null, timedOut = true),
                processResult(stdout = "x".repeat(64 * 1024 + 1)),
            ).forEach { failing ->
                val runner = RecordingInventoryRunner(
                    ArrayDeque(listOf(failing)),
                )

                val failure = assertFailsWith<IllegalStateException> {
                    DovecotTask6OperatorProcessInventory(
                        fixture.profile,
                        runner,
                    ).count()
                }

                assertEquals("INVALID_INVENTORY", failure.message)
                assertFalse(failure.toString().contains("secret-canary"))
                assertEquals(null, failure.cause)
            }

            val throwing = EligibilityProcessRunner {
                throw IllegalStateException(
                    "process overflow contained secret-canary",
                )
            }
            val failure = assertFailsWith<IllegalStateException> {
                DovecotTask6OperatorProcessInventory(
                    fixture.profile,
                    throwing,
                ).count()
            }
            assertEquals("INVALID_INVENTORY", failure.message)
            assertFalse(failure.toString().contains("secret-canary"))
            assertEquals(null, failure.cause)
        }
    }

    @Test
    fun rejectsMalformedUtf8AndWipesAllCapturedCommandOutput() {
        InventoryFixture().use { fixture ->
            val malformed = byteArrayOf(
                0xc3.toByte(),
                0x28,
                '\n'.code.toByte(),
            )
            val result = EligibilityProcessResult(
                exitCode = 0,
                timedOut = false,
                stdout = malformed,
                stderr = ByteArray(0),
            )
            val runner = RecordingInventoryRunner(
                ArrayDeque(listOf(result)),
            )

            assertInvalidInventory {
                DovecotTask6OperatorProcessInventory(
                    fixture.profile,
                    runner,
                ).count()
            }

            assertTrue(malformed.all { it == 0.toByte() })
        }
    }

    @Test
    fun redactsItsOwnStringRepresentation() {
        InventoryFixture().use { fixture ->
            val inventory = DovecotTask6OperatorProcessInventory(
                fixture.profile,
                RecordingInventoryRunner(
                    fixture.successfulResults(topOutput = topOutput(fixture)),
                ),
            )

            assertEquals(
                "DovecotTask6OperatorProcessInventory(fixed, redacted)",
                inventory.toString(),
            )
            assertFalse(inventory.toString().contains(fixture.root.toString()))
            assertFalse(inventory.toString().contains(CONTAINER_ID))
        }
    }

    private fun topOutput(fixture: InventoryFixture): String =
        "PID COMMAND\n42 ${fixture.expectedOpenSslCommand}\n"

    private fun assertInvalidInventory(block: () -> Unit) {
        val failure = assertFailsWith<IllegalStateException>(block = block)
        assertEquals("INVALID_INVENTORY", failure.message)
        assertEquals(null, failure.cause)
    }

    private class RecordingInventoryRunner(
        private val results: ArrayDeque<EligibilityProcessResult>,
    ) : EligibilityProcessRunner {
        val requests = mutableListOf<EligibilityProcessRequest>()

        override fun run(
            request: EligibilityProcessRequest,
        ): EligibilityProcessResult {
            requests += request
            return results.removeFirst()
        }
    }

    private class InventoryFixture : AutoCloseable {
        val root: Path = createTempDirectory("task6-inventory")
            .toRealPath()
        val docker: Path = root.resolve("docker")
        private val compose = root.resolve("docker-compose.yml")
        private val override = root.resolve("proof.yml")
        val profile: DovecotOperatorLaunchProfile

        init {
            Files.writeString(docker, "#!/bin/sh\nexit 0\n")
            Files.setPosixFilePermissions(
                docker,
                PosixFilePermissions.fromString("rwx------"),
            )
            Files.writeString(compose, "services: {}\n")
            Files.writeString(override, "services: {}\n")
            profile = DovecotOperatorLaunchProfile(
                dockerCli = docker,
                repositoryRoot = root,
                composeFiles = listOf(compose, override),
                projectName = "mail-sandbox-task5-proof",
            )
        }

        val composePrefix: List<String>
            get() = buildList {
                add(docker.toString())
                add("compose")
                add("--project-directory")
                add(root.toString())
                profile.composeFiles.forEach { file ->
                    add("-f")
                    add(file.toString())
                }
                add("--project-name")
                add(profile.projectName)
                add("--profile")
                add(profile.composeProfile)
            }

        val composePsCommand: List<String>
            get() = composePrefix + listOf(
                "ps",
                "--quiet",
                profile.service,
            )

        val labelsCommand: List<String>
            get() = listOf(
                docker.toString(),
                "inspect",
                "--format",
                "{{json .Config.Labels}}",
                CONTAINER_ID,
            )

        val containerNetworksCommand: List<String>
            get() = listOf(
                docker.toString(),
                "inspect",
                "--format",
                "{{json .NetworkSettings.Networks}}",
                CONTAINER_ID,
            )

        val networkCommand: List<String>
            get() = listOf(
                docker.toString(),
                "network",
                "inspect",
                "--format",
                "{{json .}}",
                NETWORK_ID,
            )

        val topCommand: List<String>
            get() = listOf(
                docker.toString(),
                "top",
                CONTAINER_ID,
                "-ww",
                "-eo",
                "pid,args",
            )

        val expectedOpenSslCommand: String
            get() {
                val opensslIndex =
                    profile.argv.indexOf("/usr/bin/openssl")
                check(opensslIndex >= 0)
                return profile.argv.drop(opensslIndex)
                    .joinToString(" ")
            }

        fun successfulResults(
            topOutput: String,
            containerNetworks: String =
                "{\"${profile.projectName}_operator-ingress\":" +
                    "{\"NetworkID\":\"$NETWORK_ID\"}}\n",
            network: String =
                "{\"Name\":\"${profile.projectName}_operator-ingress\"," +
                    "\"Id\":\"$NETWORK_ID\",\"Internal\":true," +
                    "\"Containers\":{\"$CONTAINER_ID\":{}}}\n",
        ): ArrayDeque<EligibilityProcessResult> =
            ArrayDeque(
                listOf(
                    processResult(stdout = "$CONTAINER_ID\n"),
                    processResult(
                        stdout =
                            "{\"com.docker.compose.project\":" +
                                "\"${profile.projectName}\"," +
                                "\"com.docker.compose.service\":" +
                                "\"${profile.service}\"," +
                                "\"com.docker.compose.container-number\":" +
                                "\"1\"}\n",
                    ),
                    processResult(stdout = containerNetworks),
                    processResult(stdout = network),
                    processResult(stdout = topOutput),
                ),
            )

        override fun close() {
            root.toFile().deleteRecursively()
        }
    }

    companion object {
        private const val CONTAINER_ID =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        private const val NETWORK_ID =
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

        private fun processResult(
            exitCode: Int? = 0,
            timedOut: Boolean = false,
            stdout: String = "",
            stderr: String = "",
        ): EligibilityProcessResult =
            EligibilityProcessResult(
                exitCode = exitCode,
                timedOut = timedOut,
                stdout = stdout.toByteArray(StandardCharsets.UTF_8),
                stderr = stderr.toByteArray(StandardCharsets.UTF_8),
            )
    }
}
