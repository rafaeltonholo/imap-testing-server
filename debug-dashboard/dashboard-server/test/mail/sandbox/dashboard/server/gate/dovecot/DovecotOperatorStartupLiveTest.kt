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
import kotlin.test.assertTrue

class DovecotOperatorStartupLiveTest {
    @Test
    fun isolatedTopologySupportsMasterLoginForAnEligibleDisposableTarget() {
        val repositoryRoot = repositoryRoot()
        val live = DovecotLiveTestEnvironment.load(
            environment = System.getenv(),
            repositoryRoot = repositoryRoot,
        )
        live.awaitReady()

        val address = disposableTargetAddress()
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
        val credentialStore = DovecotOperatorCredentialStore(
            paths = live.profile.operatorPaths(),
            hasher = DovecotOperatorHashBoundary {
                error("startup proof must not hash operator credentials")
            },
            verifier = ExistingDovecotOperatorHashVerifier(
                repositoryRoot,
                JvmEligibilityProcessRunner(
                    dockerRouting =
                        DovecotDockerRouting.task5Proof(live.profile),
                ),
            ),
            generator = DovecotOperatorSecretGenerator {
                error("startup proof must not bootstrap operator credentials")
            },
        )
        val probe = live.operatorRuntime.probe()
        var addAttempted = false
        var primaryFailure: Throwable? = null
        try {
            require(address !in EligibilityFile(eligibilityPaths).list()) {
                "Disposable proof target unexpectedly exists"
            }
            addAttempted = true
            val credentialBuffers = mutableListOf<ByteArray>()
            try {
                generateTargetPassword(credentialBuffers).use { targetPassword ->
                    addEligibleTarget(
                        cli = eligibilityCli,
                        address = address,
                        targetPassword = targetPassword,
                        retainedBuffers = credentialBuffers,
                    )
                    assertEquals(
                        DovecotOperatorProbeResult.AuthenticationFailure,
                        live.operatorExchange.authenticateBareTarget(
                            target = target,
                            password = targetPassword,
                        ),
                    )
                }
            } finally {
                assertTrue(
                    credentialBuffers.all { bytes ->
                        bytes.all { it == 0.toByte() }
                    },
                    "Bare-target LOGIN proof retained credential-bearing bytes",
                )
            }

            assertEquals(
                DovecotOperatorProbeResult.Success,
                live.operatorExchange.requireLoginOnlyCapability(),
            )
            assertEquals(
                DovecotOperatorProbeResult.AuthenticationFailure,
                live.operatorExchange.authenticatePlainAuthzidMaster(
                    target = target,
                    credential = credentialStore.loadActive(),
                ),
            )
            val credential = credentialStore.loadActive()
            val result = probe.probe(target, credential)

            assertEquals(DovecotOperatorProbeResult.Success, result)
            live.awaitReady(maxAttempts = 3, delayMillis = 100)
        } catch (failure: Throwable) {
            primaryFailure = failure
            throw failure
        } finally {
            try {
                if (
                    addAttempted &&
                    address in EligibilityFile(eligibilityPaths).list()
                ) {
                    removeEligibleTarget(eligibilityCli, address)
                }
                if (addAttempted) {
                    awaitDovecotOperatorTargetRejection(
                        resultSupplier = {
                            probe.probe(
                                target,
                                credentialStore.loadActive(),
                            )
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

    private fun generateTargetPassword(
        retainedBuffers: MutableList<ByteArray>,
    ): EligibilityPassword {
        val password = ByteArray(TARGET_PASSWORD_BYTES)
        retainedBuffers += password
        try {
            repeat(TARGET_PASSWORD_BYTES) { index ->
                password[index] = TARGET_PASSWORD_ALPHABET_BYTES[
                    SECURE_RANDOM.nextInt(TARGET_PASSWORD_ALPHABET_BYTES.size)
                ]
            }
            return EligibilityPassword.takeOwnership(password)
        } catch (failure: Throwable) {
            password.fill(0)
            throw failure
        }
    }

    private fun addEligibleTarget(
        cli: EligibilityFileCli,
        address: String,
        targetPassword: EligibilityPassword,
        retainedBuffers: MutableList<ByteArray>,
    ) {
        var input = ByteArray(0)
        try {
            targetPassword.withBytes { passwordBytes ->
                input = ByteArray(passwordBytes.size + 1)
                retainedBuffers += input
                passwordBytes.copyInto(input)
                input[input.lastIndex] = '\n'.code.toByte()
            }
            assertEquals(
                0,
                executeEligibility(
                    cli = cli,
                    args = arrayOf("add", address),
                    stdin = input,
                ),
                "Disposable eligibility add failed",
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
                cli = cli,
                args = arrayOf("remove", address),
                stdin = ByteArray(0),
            ),
            "Disposable eligibility cleanup failed",
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
                args = args,
                stdin = ByteArrayInputStream(stdin),
                stdout = output,
                stderr = output,
            )
        }
    }

    private fun disposableTargetAddress(): String =
        "task5-proof-" +
            UUID.randomUUID().toString().replace("-", "") +
            "@local.test"

    private fun repositoryRoot(): Path {
        val workingDirectory = Path.of(System.getProperty("user.dir"))
            .toAbsolutePath()
            .normalize()
        val dashboardRoot = if (
            workingDirectory.fileName?.toString() == "dashboard-server"
        ) {
            requireNotNull(workingDirectory.parent)
        } else {
            workingDirectory
        }
        return requireNotNull(dashboardRoot.parent).also { root ->
            require(Files.isRegularFile(root.resolve("docker-compose.yml")))
        }
    }

    companion object {
        private const val TARGET_PASSWORD_BYTES = 48
        private const val TARGET_PASSWORD_ALPHABET =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
        private val TARGET_PASSWORD_ALPHABET_BYTES =
            TARGET_PASSWORD_ALPHABET.toByteArray(StandardCharsets.US_ASCII)
        private val SECURE_RANDOM = SecureRandom()
    }
}
