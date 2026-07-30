package mail.sandbox.dashboard.server.gate.dovecot

import java.io.ByteArrayInputStream
import java.io.OutputStream
import java.io.PrintStream
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.security.SecureRandom
import java.util.UUID
import kotlin.test.Test
import kotlin.test.assertEquals

class DovecotIsolationLiveTest {
    @Test
    fun masterCredentialAndOperatorIngressAreIsolatedFromEveryOtherPath() {
        val repositoryRoot = repositoryRoot()
        val live = DovecotLiveTestEnvironment.load(
            environment = System.getenv(),
            repositoryRoot = repositoryRoot,
        )
        live.awaitReady()
        val topology = FixedTask6DockerTopology(live.profile)
        val runtime = topology.inspect()
        runtime.requireExactIsolation()

        val hostAddresses = discoverTask6HostNonLoopbackIpv4()
        hostAddresses.forEach { address ->
            requireTask6TcpRejected(address, live.ordinaryImapsPort)
            requireTask6TcpRejected(address, live.operatorImapsPort)
        }
        topology.requireDefaultNetworkIsolation(
            operatorIngressAddress = runtime.operatorIngressAddress,
            hostAddresses = hostAddresses,
        )
        val protocol = DovecotIsolationProtocolProof.pinned(live.profile)

        val address =
            "task6-isolation-" +
                UUID.randomUUID().toString().replace("-", "") +
                "@local.test"
        val target = DovecotOperatorTarget.create(address)
        val eligibilityPaths = live.profile.eligibilityPaths()
        val eligibilityCli = EligibilityFileCli(
            pathsProvider = { eligibilityPaths },
            hasherFactory = { root ->
                DovecotPasswordHasher(
                    root,
                    JvmEligibilityProcessRunner(
                        dockerRouting =
                            DovecotDockerRouting.task5Proof(live.profile),
                    ),
                )
            },
        )
        val store = DovecotOperatorCredentialStore(
            paths = live.profile.operatorPaths(),
            generator = DovecotOperatorSecretGenerator {
                error("isolation proof must not generate an operator secret")
            },
            hasher = DovecotOperatorHashBoundary {
                error("isolation proof must not hash an operator secret")
            },
            verifier = ExistingDovecotOperatorHashVerifier(
                repositoryRoot,
                JvmEligibilityProcessRunner(
                    dockerRouting =
                        DovecotDockerRouting.task5Proof(live.profile),
                ),
            ),
        )
        val transportFactory =
            JvmJsseDovecotOperatorTransportFactory.task5Proof(
                live.profile,
            )
        val probe = DovecotOperatorProbe(
            transportFactory = transportFactory,
            requireMailboxRead = true,
        )
        var addAttempted = false
        var targetRemoved = false
        var primaryFailure: Throwable? = null
        try {
            require(address !in EligibilityFile(eligibilityPaths).list()) {
                "Disposable isolation target unexpectedly exists"
            }
            generateTargetPassword().use { targetPassword ->
                addAttempted = true
                addEligibleTarget(
                    cli = eligibilityCli,
                    address = address,
                    password = targetPassword,
                )

                assertEquals(
                    DovecotOperatorProbeResult.Success,
                    seedAndProbeTask6IsolationMailbox(
                        transportFactory = transportFactory,
                        target = target,
                        credentialSupplier = store::loadActive,
                    ),
                )
                store.loadActive().use { master ->
                    protocol.requireImapRejected(
                        live.operatorImapsPort,
                        task6MasterLogin(address, master.id),
                        targetPassword,
                    )
                    protocol.requireImapRejected(
                        live.operatorImapsPort,
                        task6InactiveMasterLogin(address, master.id),
                        master,
                    )
                    protocol.requireImapRejected(
                        live.operatorImapsPort,
                        "$address*absent-master",
                        targetPassword,
                    )
                    protocol.requireImapRejected(
                        live.ordinaryImapsPort,
                        task6MasterLogin(address, master.id),
                        master,
                    )
                    protocol.requirePop3Rejected(
                        live.ordinaryPop3sPort,
                        task6MasterLogin(address, master.id),
                        master,
                    )
                    protocol.requireSmtpRejected(
                        live.smtpPort,
                        task6MasterLogin(address, master.id),
                        master,
                    )
                    protocol.requireMasterOauthInactive(
                        live.oauthPort,
                        master,
                    )
                }

                store.loadActive().use { master ->
                    protocol.requireRawOperatorRejected(
                        live.operatorImapsPort,
                        "absent-${UUID.randomUUID()}@local.test",
                        master,
                    )
                    PROTECTED_TARGETS.forEach { protected ->
                        protocol.requireRawOperatorRejected(
                            live.operatorImapsPort,
                            protected,
                            master,
                        )
                    }
                    DovecotOperatorId.entries.forEach { id ->
                        protocol.requireRawOperatorRejected(
                            live.operatorImapsPort,
                            id.masterUsername,
                            master,
                        )
                    }
                }
                protocol.requireProtectedOauthDenied(live.oauthPort)

                removeEligibleTarget(eligibilityCli, address)
                targetRemoved = true
                awaitDovecotOperatorTargetRejection(
                    resultSupplier = {
                        probe.probe(target, store.loadActive())
                    },
                )
            }
        } catch (failure: Throwable) {
            primaryFailure = failure
            throw failure
        } finally {
            try {
                if (
                    addAttempted &&
                    !targetRemoved &&
                    address in EligibilityFile(eligibilityPaths).list()
                ) {
                    removeEligibleTarget(eligibilityCli, address)
                    awaitDovecotOperatorTargetRejection(
                        resultSupplier = {
                            probe.probe(target, store.loadActive())
                        },
                    )
                }
            } catch (cleanupFailure: Throwable) {
                val primary = primaryFailure
                if (primary != null) {
                    primary.addSuppressed(cleanupFailure)
                } else {
                    throw cleanupFailure
                }
            }
        }
    }

    private fun generateTargetPassword(): EligibilityPassword {
        val bytes = ByteArray(TARGET_PASSWORD_BYTES)
        try {
            bytes.indices.forEach { index ->
                bytes[index] = TARGET_PASSWORD_ALPHABET[
                    SECURE_RANDOM.nextInt(TARGET_PASSWORD_ALPHABET.length)
                ].code.toByte()
            }
            return EligibilityPassword.takeOwnership(bytes)
        } catch (failure: Throwable) {
            bytes.fill(0)
            throw failure
        }
    }

    private fun addEligibleTarget(
        cli: EligibilityFileCli,
        address: String,
        password: EligibilityPassword,
    ) {
        var input = ByteArray(0)
        try {
            password.withBytes { bytes ->
                input = ByteArray(bytes.size + 1)
                bytes.copyInto(input)
                input[input.lastIndex] = '\n'.code.toByte()
            }
            assertEquals(
                0,
                executeEligibility(cli, arrayOf("add", address), input),
                "Disposable isolation target add failed",
            )
        } finally {
            input.fill(0)
        }
    }

    private fun removeEligibleTarget(
        cli: EligibilityFileCli,
        address: String,
    ) {
        assertEquals(
            0,
            executeEligibility(
                cli,
                arrayOf("remove", address),
                ByteArray(0),
            ),
            "Disposable isolation target cleanup failed",
        )
    }

    private fun executeEligibility(
        cli: EligibilityFileCli,
        args: Array<String>,
        stdin: ByteArray,
    ): Int {
        val sink = PrintStream(
            OutputStream.nullOutputStream(),
            true,
            StandardCharsets.UTF_8,
        )
        return sink.use { output ->
            cli.execute(
                args,
                ByteArrayInputStream(stdin),
                output,
                output,
            )
        }
    }

    private fun repositoryRoot(): Path {
        val working = Path.of(System.getProperty("user.dir"))
            .toAbsolutePath()
            .normalize()
        val dashboard =
            if (working.fileName?.toString() == "dashboard-server") {
                requireNotNull(working.parent)
            } else {
                working
            }
        return requireNotNull(dashboard.parent).also {
            require(Files.isRegularFile(it.resolve("docker-compose.yml")))
        }
    }

    companion object {
        private const val TARGET_PASSWORD_BYTES = 48
        private const val TARGET_PASSWORD_ALPHABET =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
        private val SECURE_RANDOM = SecureRandom()
        private val PROTECTED_TARGETS = listOf(
            "dashboard-management@local.test",
            "dashboard-operator-a@local.test",
            "dashboard-operator-b@local.test",
        )
    }
}
