package mail.sandbox.dashboard.server.gate.dovecot

import java.io.IOException
import java.net.ConnectException
import java.net.Inet4Address
import java.net.InetAddress
import java.net.NoRouteToHostException
import java.net.SocketTimeoutException
import java.nio.charset.StandardCharsets
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
    fun runtimeTopologyAcceptsEmptyOperatorPublicationAndIgnoresUnboundExposedPorts() {
        runtimeTopology(includeUnboundPorts = true).requireExactIsolation()
    }

    @Test
    fun runtimeTopologyRetainsOperatorBridgeIpForNegativeProof() {
        assertFailsWith<IllegalStateException> {
            runtimeTopology(operatorIngressAddress = "")
                .requireExactIsolation()
        }
    }

    @Test
    fun remainingLiveProofsUseOnlyTheEnvironmentBoundLaunchProfile() {
        val sourceRoot = repositoryRoot().resolve(
            "debug-dashboard/dashboard-server/test/mail/sandbox/" +
                "dashboard/server/gate/dovecot",
        )
        val sources = listOf(
            "DovecotOperatorStartupLiveTest.kt",
            "DovecotIsolationLiveTest.kt",
            "DovecotOperatorRotationLiveTest.kt",
        ).associateWith { fileName ->
            Files.readString(sourceRoot.resolve(fileName))
        }
        sources.forEach { (fileName, source) ->
            assertEquals(
                1,
                Regex(
                    """val\s+launchProfile\s*=\s*""" +
                        """live\.operatorRuntime\.launchProfile""",
                ).findAll(source).count(),
                "$fileName must bind the validated runtime launch profile once",
            )
            assertEquals(
                1,
                Regex(
                    """Task6LaunchProfileEligibilityAdapter\s*""" +
                        """\(\s*launchProfile\s*\)""",
                ).findAll(source).count(),
                "$fileName must reuse one launch-profile eligibility adapter",
            )
            listOf(
                "DovecotDockerRouting",
                "JvmEligibilityProcessRunner",
                "DovecotPasswordHasher",
                "JvmDockerExecDovecotOperatorTransportFactory",
                "DovecotOperatorBoundedExchange(",
            ).forEach { forbidden ->
                assertFalse(
                    forbidden in source,
                    "$fileName retains ambient process routing: $forbidden",
                )
            }
            assertFalse(
                Regex("""DovecotOperatorRuntime\s*\.""")
                    .containsMatchIn(source),
                "$fileName must not construct another operator runtime",
            )
        }

        val startup = sources.getValue(
            "DovecotOperatorStartupLiveTest.kt",
        )
        assertTrue("live.operatorRuntime.probe()" in startup)
        assertTrue("live.operatorExchange" in startup)
        assertFalse("transportFactory()" in startup)

        listOf(
            "DovecotIsolationLiveTest.kt",
            "DovecotOperatorRotationLiveTest.kt",
        ).forEach { fileName ->
            assertEquals(
                1,
                Regex(
                    """live\.operatorRuntime\.transportFactory\s*\(\s*\)""",
                ).findAll(sources.getValue(fileName)).count(),
                "$fileName must reuse the runtime-owned transport factory",
            )
        }

        val isolation = sources.getValue("DovecotIsolationLiveTest.kt")
        assertTrue(
            "FixedTask6DockerTopology(launchProfile)" in isolation,
        )
        val topologySource = Files.readString(
            sourceRoot.resolve("DovecotTask6TopologyProof.kt"),
        )
        assertFalse(
            "constructor(profile: DovecotTask5ProofProfile)" in
                topologySource,
            "Topology must not create an implicit second proof runtime",
        )
    }

    @Test
    fun fixedTopologyUsesCanonicalLaunchProfileForEveryDockerCommand() =
        withTopologyLaunchFixture { fixture ->
            val observed = mutableListOf<ObservedProcessRequest>()
            val services = listOf(
                "dovecot",
                "dovecot-operator",
                "postfix",
                "oauth2-mock",
            )
            val containerIds = services.mapIndexed { index, service ->
                service to (index + 1).toString().repeat(64)
            }.toMap()
            val composePrefix = fixture.composePrefix()
            val expectedCommands = buildList {
                services.forEach { service ->
                    add(
                        composePrefix +
                            listOf("ps", "--quiet", service),
                    )
                    add(
                        listOf(
                            fixture.docker.toString(),
                            "inspect",
                            "--format",
                            "{{json .Config.Labels}}",
                            containerIds.getValue(service),
                        ),
                    )
                }
                services.forEach { service ->
                    add(
                        listOf(
                            fixture.docker.toString(),
                            "inspect",
                            "--format",
                            "{{json .NetworkSettings.Ports}}",
                            containerIds.getValue(service),
                        ),
                    )
                }
                services.forEach { service ->
                    add(
                        listOf(
                            fixture.docker.toString(),
                            "inspect",
                            "--format",
                            "{{json .NetworkSettings.Networks}}",
                            containerIds.getValue(service),
                        ),
                    )
                }
            }
            val responses = expectedCommands.associateWith { command ->
                when {
                    command.takeLast(3).take(2) ==
                        listOf("ps", "--quiet") ->
                        "${containerIds.getValue(command.last())}\n"
                    command[3] == "{{json .Config.Labels}}" -> {
                        val service = containerIds.entries.single {
                            it.value == command.last()
                        }.key
                        """{"com.docker.compose.project":"mail-sandbox-task5-proof","com.docker.compose.service":"$service","com.docker.compose.container-number":"1"}"""
                    }
                    command[3] == "{{json .NetworkSettings.Ports}}" ->
                        when (containerIds.entries.single {
                            it.value == command.last()
                        }.key) {
                            "dovecot" ->
                                """{"31993/tcp":[{"HostIp":"127.0.0.1","HostPort":"1993"}],"31995/tcp":[{"HostIp":"127.0.0.1","HostPort":"21995"}]}"""
                            "dovecot-operator" -> "{}"
                            "postfix" ->
                                """{"25/tcp":[{"HostIp":"127.0.0.1","HostPort":"21025"}]}"""
                            else ->
                                """{"8080/tcp":[{"HostIp":"127.0.0.1","HostPort":"28080"}]}"""
                        }
                    else -> {
                        val service = containerIds.entries.single {
                            it.value == command.last()
                        }.key
                        if (service == "dovecot-operator") {
                            """{"mail-sandbox-task5-proof_operator-ingress":{"IPAddress":"172.31.0.5"}}"""
                        } else {
                            """{"mail-sandbox-task5-proof_default":{"IPAddress":"172.31.0.4"}}"""
                        }
                    }
                }
            }
            val topology = FixedTask6DockerTopology(
                launchProfile = fixture.launchProfile,
                processRunner = EligibilityProcessRunner { request ->
                    observed += request.snapshot()
                    EligibilityProcessResult(
                        exitCode = 0,
                        timedOut = false,
                        stdout = requireNotNull(
                            responses[request.argv],
                        ).toByteArray(StandardCharsets.UTF_8),
                        stderr = ByteArray(0),
                    )
                },
            )

            topology.inspect().requireExactIsolation()

            assertEquals(expectedCommands, observed.map { it.argv })
            observed.forEach { request ->
                assertEquals(fixture.repository, request.workingDirectory)
                assertTrue(request.stdin.isEmpty())
                assertEquals(Duration.ofSeconds(10), request.timeout)
                assertEquals(64 * 1024, request.maximumOutputBytes)
                assertEquals(
                    fixture.docker.toString(),
                    request.argv.first(),
                )
                assertFalse(request.argv.contains("docker"))
            }
        }

    @Test
    fun fixedTopologyRejectsContainerIdWithoutOneExactTrailingNewline() =
        withTopologyLaunchFixture { fixture ->
            val id = "1".repeat(64)
            var callCount = 0
            val topology = FixedTask6DockerTopology(
                launchProfile = fixture.launchProfile,
                processRunner = EligibilityProcessRunner {
                    callCount += 1
                    EligibilityProcessResult(
                        exitCode = 0,
                        timedOut = false,
                        stdout = id.toByteArray(StandardCharsets.US_ASCII),
                        stderr = ByteArray(0),
                    )
                },
            )

            val failure = assertFailsWith<IllegalStateException> {
                topology.inspect()
            }

            assertEquals(
                "Fixed proof container identity is invalid",
                failure.message,
            )
            assertEquals(1, callCount)
        }

    @Test
    fun fixedTopologyValidatesExactComposeLabelsBeforeUsingContainerId() =
        withTopologyLaunchFixture { fixture ->
            val services = listOf(
                "dovecot",
                "dovecot-operator",
                "postfix",
                "oauth2-mock",
            )
            val containerIds = services.mapIndexed { index, service ->
                service to (index + 1).toString().repeat(64)
            }.toMap()
            val serviceById =
                containerIds.entries.associate { it.value to it.key }
            val observed = mutableListOf<List<String>>()
            val topology = FixedTask6DockerTopology(
                launchProfile = fixture.launchProfile,
                processRunner = EligibilityProcessRunner { request ->
                    observed += request.argv
                    val stdout =
                        if (request.argv.takeLast(3).take(2) ==
                            listOf("ps", "--quiet")
                        ) {
                            "${containerIds.getValue(request.argv.last())}\n"
                        } else {
                            val service =
                                serviceById.getValue(request.argv.last())
                            val reportedService =
                                if (service == "dovecot-operator") {
                                    "label-secret-canary"
                                } else {
                                    service
                                }
                            """{"com.docker.compose.project":"mail-sandbox-task5-proof","com.docker.compose.service":"$reportedService","com.docker.compose.container-number":"1"}"""
                        }
                    EligibilityProcessResult(
                        exitCode = 0,
                        timedOut = false,
                        stdout = stdout.toByteArray(StandardCharsets.UTF_8),
                        stderr = ByteArray(0),
                    )
                },
            )

            val failure = assertFailsWith<IllegalStateException> {
                topology.inspect()
            }

            assertEquals(
                "Fixed proof container identity labels are invalid",
                failure.message,
            )
            assertFalse(failure.toString().contains("canary"))
            assertEquals(
                listOf(
                    fixture.composePrefix() +
                        listOf("ps", "--quiet", "dovecot"),
                    listOf(
                        fixture.docker.toString(),
                        "inspect",
                        "--format",
                        "{{json .Config.Labels}}",
                        containerIds.getValue("dovecot"),
                    ),
                    fixture.composePrefix() +
                        listOf("ps", "--quiet", "dovecot-operator"),
                    listOf(
                        fixture.docker.toString(),
                        "inspect",
                        "--format",
                        "{{json .Config.Labels}}",
                        containerIds.getValue("dovecot-operator"),
                    ),
                ),
                observed,
            )
            assertFalse(
                observed.any { command ->
                    command.any { it.contains(".NetworkSettings.") }
                },
            )
        }

    @Test
    fun fixedTopologyRejectsNonStringComposeIdentityLabel() =
        withTopologyLaunchFixture { fixture ->
            val id = "1".repeat(64)
            var callCount = 0
            val topology = FixedTask6DockerTopology(
                launchProfile = fixture.launchProfile,
                processRunner = EligibilityProcessRunner {
                    callCount += 1
                    val stdout = when (callCount) {
                        1 -> "$id\n"
                        2 ->
                            """{"com.docker.compose.project":"mail-sandbox-task5-proof","com.docker.compose.service":"dovecot","com.docker.compose.container-number":1}"""
                        else -> error("Non-string identity label was accepted")
                    }
                    EligibilityProcessResult(
                        exitCode = 0,
                        timedOut = false,
                        stdout = stdout.toByteArray(StandardCharsets.UTF_8),
                        stderr = ByteArray(0),
                    )
                },
            )

            val failure = assertFailsWith<IllegalStateException> {
                topology.inspect()
            }

            assertEquals(
                "Fixed proof container identity labels are invalid",
                failure.message,
            )
            assertEquals(2, callCount)
        }

    @Test
    fun fixedTopologyRejectsDuplicateComposeIdentityLabel() =
        withTopologyLaunchFixture { fixture ->
            val id = "1".repeat(64)
            var callCount = 0
            val topology = FixedTask6DockerTopology(
                launchProfile = fixture.launchProfile,
                processRunner = EligibilityProcessRunner {
                    callCount += 1
                    val stdout = when (callCount) {
                        1 -> "$id\n"
                        2 ->
                            """{"com.docker.compose.project":"label-secret-canary","com.docker.compose.project":"mail-sandbox-task5-proof","com.docker.compose.service":"dovecot","com.docker.compose.container-number":"1"}"""
                        else -> error("Duplicate identity label was accepted")
                    }
                    EligibilityProcessResult(
                        exitCode = 0,
                        timedOut = false,
                        stdout = stdout.toByteArray(StandardCharsets.UTF_8),
                        stderr = ByteArray(0),
                    )
                },
            )

            val failure = assertFailsWith<IllegalStateException> {
                topology.inspect()
            }

            assertEquals(
                "Fixed proof container identity labels are invalid",
                failure.message,
            )
            assertFalse(failure.toString().contains("canary"))
            assertEquals(2, callCount)
        }

    @Test
    fun fixedTopologyRedactsMalformedInspectedPortsAndNetworks() =
        withTopologyLaunchFixture { fixture ->
            val canary = "inspect-topology-secret-canary"
            val actions = listOf<() -> Unit>(
                {
                    fixedTopologyWithInspectionDocuments(
                        fixture = fixture,
                        portDocuments = mapOf(
                            "dovecot" to """{"$canary":""",
                        ),
                    ).inspect()
                },
                {
                    fixedTopologyWithInspectionDocuments(
                        fixture = fixture,
                        networkDocuments = mapOf(
                            "dovecot-operator" to """{"$canary":""",
                        ),
                    ).inspect()
                },
                {
                    fixedTopologyWithInspectionDocuments(
                        fixture = fixture,
                        networkDocuments = mapOf(
                            "dovecot-operator" to
                                """{"mail-sandbox-task5-proof_operator-ingress":"$canary"}""",
                        ),
                    ).inspect()
                },
                {
                    fixedTopologyWithInspectionDocuments(
                        fixture = fixture,
                        networkDocuments = mapOf(
                            "dovecot-operator" to
                                """{"mail-sandbox-task5-proof_operator-ingress":{"IPAddress":{"$canary":true}}}""",
                        ),
                    ).inspect()
                },
                {
                    fixedTopologyWithInspectionDocuments(
                        fixture = fixture,
                        networkDocuments = mapOf(
                            "dovecot-operator" to
                                """{"mail-sandbox-task5-proof_operator-ingress":{"IPAddress":"$canary"}}""",
                        ),
                    ).inspect()
                },
            )

            actions.forEach { action ->
                assertFixedRedactedTopologyFailure(canary, action)
            }
        }

    @Test
    fun fixedTopologyRejectsDuplicateRootPortKeyHidingPublication() =
        withTopologyLaunchFixture { fixture ->
            val canary = "duplicate-port-secret-canary"
            val topology = fixedTopologyWithInspectionDocuments(
                fixture = fixture,
                portDocuments = mapOf(
                    "dovecot-operator" to
                        """{"31993/tcp":[{"HostIp":"$canary","HostPort":"2993"}],"31993/tcp":null}""",
                ),
            )

            assertFixedRedactedTopologyFailure(canary) {
                topology.inspect()
            }
        }

    @Test
    fun fixedTopologyRejectsDuplicateRootNetworkKey() =
        withTopologyLaunchFixture { fixture ->
            val canary = "duplicate-network-secret-canary"
            val operatorNetwork =
                "mail-sandbox-task5-proof_operator-ingress"
            val topology = fixedTopologyWithInspectionDocuments(
                fixture = fixture,
                networkDocuments = mapOf(
                    "dovecot-operator" to
                        """{"$operatorNetwork":{"IPAddress":"$canary"},"$operatorNetwork":{"IPAddress":"172.31.0.5"}}""",
                ),
            )

            assertFixedRedactedTopologyFailure(canary) {
                topology.inspect()
            }
        }

    @Test
    fun fixedTopologyRejectsDuplicateNestedNetworkKey() =
        withTopologyLaunchFixture { fixture ->
            val canary = "duplicate-nested-network-secret-canary"
            val operatorNetwork =
                "mail-sandbox-task5-proof_operator-ingress"
            val topology = fixedTopologyWithInspectionDocuments(
                fixture = fixture,
                networkDocuments = mapOf(
                    "dovecot-operator" to
                        """{"$operatorNetwork":{"IPAddress":"$canary","IPAddress":"172.31.0.5"}}""",
                ),
            )

            assertFixedRedactedTopologyFailure(canary) {
                topology.inspect()
            }
        }

    @Test
    fun runtimeTopologyRedactsEveryMalformedPortShape() {
        val canary = "runtime-port-secret-canary"
        val validPop3Binding =
            """"31995/tcp":[{"HostIp":"127.0.0.1","HostPort":"21995"}]"""
        val malformedDocuments = listOf(
            """"$canary"""",
            """{"31993/tcp":"$canary",$validPop3Binding}""",
            """{"31993/tcp":["$canary"],$validPop3Binding}""",
            """{"31993/tcp":[{"HostIp":{"$canary":true},"HostPort":"1993"}],$validPop3Binding}""",
            """{"31993/tcp":[{"HostIp":"127.0.0.1","HostPort":{"$canary":true}}],$validPop3Binding}""",
        )

        malformedDocuments.forEach { document ->
            val baseline = runtimeTopology()
            val malformed = baseline.copy(
                ports = baseline.ports +
                    (
                        "dovecot" to
                            Json.parseToJsonElement(document)
                        ),
            )

            assertFixedRedactedTopologyFailure(canary) {
                malformed.requireExactIsolation()
            }
        }
    }

    @Test
    fun runtimeTopologyRedactsEveryMalformedNetworkShape() {
        val canary = "runtime-network-secret-canary"
        val baseline = runtimeTopology()
        val malformed = listOf(
            baseline.copy(
                networks = baseline.networks +
                    (
                        "dovecot-operator" to
                            Json.parseToJsonElement(""""$canary"""")
                        ),
            ),
            baseline.copy(
                networks = baseline.networks - "dovecot",
            ),
            baseline.copy(
                networks = baseline.networks +
                    (
                        "dovecot" to
                            Json.parseToJsonElement(""""$canary"""")
                        ),
            ),
        )

        malformed.forEach { topology ->
            assertFixedRedactedTopologyFailure(canary) {
                topology.requireExactIsolation()
            }
        }
    }

    @Test
    fun runtimeTopologyKeepsSpecificSemanticIsolationDiagnostic() {
        val failure = assertFailsWith<IllegalStateException> {
            runtimeTopology(extraPublishedService = "dovecot-operator")
                .requireExactIsolation()
        }

        assertEquals(
            "Proof runtime has an unexpected protocol publication",
            failure.message,
        )
        assertEquals(null, failure.cause)
        assertTrue(failure.suppressed.isEmpty())
    }

    @Test
    fun fixedTopologyPassesBridgeIpToNegativeHelperThroughCanonicalCompose() =
        withTopologyLaunchFixture { fixture ->
            var observed: ObservedProcessRequest? = null
            val topology = FixedTask6DockerTopology(
                launchProfile = fixture.launchProfile,
                processRunner = EligibilityProcessRunner { request ->
                    observed = request.snapshot()
                    EligibilityProcessResult(
                        exitCode = 0,
                        timedOut = false,
                        stdout = "OK\n".toByteArray(StandardCharsets.US_ASCII),
                        stderr = ByteArray(0),
                    )
                },
            )
            val hostAddress = InetAddress.getByAddress(
                byteArrayOf(192.toByte(), 0, 2, 44),
            ) as Inet4Address

            topology.requireDefaultNetworkIsolation(
                operatorIngressAddress = "172.31.0.5",
                hostAddresses = listOf(hostAddress),
            )

            val request = requireNotNull(observed)
            assertEquals(
                fixture.composePrefix() +
                    listOf(
                        "exec",
                        "-T",
                        "--index",
                        "1",
                        "oauth2-mock",
                        "python",
                        "-I",
                        "/proof/network-isolation-check.py",
                    ),
                request.argv,
            )
            assertEquals(fixture.repository, request.workingDirectory)
            assertEquals(
                "operator 172.31.0.5\nhost 192.0.2.44\n",
                request.stdin.toString(StandardCharsets.US_ASCII),
            )
            assertEquals(Duration.ofSeconds(25), request.timeout)
            assertEquals(64 * 1024, request.maximumOutputBytes)
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
        operatorIngressAddress: String = "172.31.0.5",
    ): Task6RuntimeTopology {
        val ports = mapOf(
            "dovecot" to portDocument(
                service = "dovecot",
                expected = listOf(
                    "31993/tcp" to "1993",
                    "31995/tcp" to "21995",
                ),
                extraPublishedService = extraPublishedService,
                includeUnboundPorts = includeUnboundPorts,
            ),
            "dovecot-operator" to portDocument(
                service = "dovecot-operator",
                expected = emptyList(),
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
            operatorIngressAddress = operatorIngressAddress,
        )
    }

    private fun fixedTopologyWithInspectionDocuments(
        fixture: TopologyLaunchFixture,
        portDocuments: Map<String, String> = emptyMap(),
        networkDocuments: Map<String, String> = emptyMap(),
    ): FixedTask6DockerTopology {
        val services = listOf(
            "dovecot",
            "dovecot-operator",
            "postfix",
            "oauth2-mock",
        )
        val containerIds = services.mapIndexed { index, service ->
            service to (index + 1).toString().repeat(64)
        }.toMap()
        val serviceById =
            containerIds.entries.associate { it.value to it.key }
        return FixedTask6DockerTopology(
            launchProfile = fixture.launchProfile,
            processRunner = EligibilityProcessRunner { request ->
                val stdout = when {
                    request.argv.takeLast(3).take(2) ==
                        listOf("ps", "--quiet") ->
                        "${containerIds.getValue(request.argv.last())}\n"
                    request.argv[3] == "{{json .Config.Labels}}" -> {
                        val service =
                            serviceById.getValue(request.argv.last())
                        """{"com.docker.compose.project":"mail-sandbox-task5-proof","com.docker.compose.service":"$service","com.docker.compose.container-number":"1"}"""
                    }
                    request.argv[3] ==
                        "{{json .NetworkSettings.Ports}}" -> {
                        val service =
                            serviceById.getValue(request.argv.last())
                        portDocuments[service] ?: "{}"
                    }
                    else -> {
                        val service =
                            serviceById.getValue(request.argv.last())
                        networkDocuments[service] ?: if (
                            service == "dovecot-operator"
                        ) {
                            """{"mail-sandbox-task5-proof_operator-ingress":{"IPAddress":"172.31.0.5"}}"""
                        } else {
                            """{"mail-sandbox-task5-proof_default":{"IPAddress":"172.31.0.4"}}"""
                        }
                    }
                }
                EligibilityProcessResult(
                    exitCode = 0,
                    timedOut = false,
                    stdout = stdout.toByteArray(StandardCharsets.UTF_8),
                    stderr = ByteArray(0),
                )
            },
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

private fun assertFixedRedactedTopologyFailure(
    canary: String,
    action: () -> Unit,
) {
    val failure = assertFailsWith<IllegalStateException> {
        action()
    }
    assertEquals(
        "Dovecot Task 6 runtime topology is invalid",
        failure.message,
    )
    assertFalse(failure.message.orEmpty().contains(canary))
    assertFalse(failure.toString().contains(canary))
    assertEquals(null, failure.cause)
    assertTrue(failure.suppressed.isEmpty())
}

private data class ObservedProcessRequest(
    val argv: List<String>,
    val workingDirectory: Path,
    val stdin: ByteArray,
    val timeout: Duration,
    val maximumOutputBytes: Int,
)

private fun EligibilityProcessRequest.snapshot() =
    ObservedProcessRequest(
        argv = argv.toList(),
        workingDirectory = workingDirectory,
        stdin = stdin.copyOf(),
        timeout = timeout,
        maximumOutputBytes = maximumOutputBytes,
    )

private data class TopologyLaunchFixture(
    val repository: Path,
    val docker: Path,
    val launchProfile: DovecotOperatorLaunchProfile,
) {
    fun composePrefix(): List<String> =
        buildList {
            add(docker.toString())
            add("compose")
            add("--project-directory")
            add(repository.toString())
            launchProfile.composeFiles.forEach { composeFile ->
                add("-f")
                add(composeFile.toString())
            }
            add("--project-name")
            add(launchProfile.projectName)
            add("--profile")
            add(launchProfile.composeProfile)
        }
}

private inline fun withTopologyLaunchFixture(
    block: (TopologyLaunchFixture) -> Unit,
) {
    val workspace =
        Files.createTempDirectory("dovecot-task6-topology-").toRealPath()
    try {
        val repository =
            Files.createDirectory(
                workspace.resolve("mail-sandbox-task5-proof"),
            ).toRealPath()
        val compose =
            Files.writeString(
                repository.resolve("docker-compose.yml"),
                "services: {}\n",
            ).toRealPath()
        val override =
            Files.writeString(
                repository.resolve("compose.task5-proof.yml"),
                "services: {}\n",
            ).toRealPath()
        val docker =
            Files.createFile(workspace.resolve("docker")).toRealPath()
        check(docker.toFile().setExecutable(true, false))
        check(Files.isExecutable(docker))
        block(
            TopologyLaunchFixture(
                repository = repository,
                docker = docker,
                launchProfile = DovecotOperatorLaunchProfile(
                    dockerCli = docker,
                    repositoryRoot = repository,
                    composeFiles = listOf(compose, override),
                    projectName = "mail-sandbox-task5-proof",
                ),
            ),
        )
    } finally {
        check(workspace.toFile().deleteRecursively())
    }
}
