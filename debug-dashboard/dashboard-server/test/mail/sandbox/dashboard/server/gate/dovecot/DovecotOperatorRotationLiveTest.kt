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
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class DovecotOperatorRotationLiveTest {
    @Test
    fun stageProbeSwitchRevokeUsesTheNewApplicationLeaseAndDrainsOldSessions() {
        val repositoryRoot = repositoryRoot()
        val live = DovecotLiveTestEnvironment.load(
            environment = System.getenv(),
            repositoryRoot = repositoryRoot,
        )
        live.awaitReady()
        val address =
            "task6-rotation-" +
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
        val operatorPaths = live.profile.operatorPaths()
        val store = DovecotOperatorCredentialStore(
            paths = operatorPaths,
            generator = SecureDovecotOperatorSecretGenerator(),
            hasher = ExistingDovecotOperatorHashBoundary(
                DovecotPasswordHasher(
                    repositoryRoot,
                    JvmEligibilityProcessRunner(
                        dockerRouting =
                            DovecotDockerRouting.task5Proof(live.profile),
                    ),
                ),
            ),
            verifier = ExistingDovecotOperatorHashVerifier(
                repositoryRoot,
                JvmEligibilityProcessRunner(
                    dockerRouting =
                        DovecotDockerRouting.task5Proof(live.profile),
                ),
            ),
        )
        val probe = DovecotOperatorProbe(
            transportFactory =
                JvmJsseDovecotOperatorTransportFactory.task5Proof(
                    live.profile,
                ),
            requireMailboxRead = true,
        )
        val oldId = store.loadActive().use { it.id }
        val leases = DovecotOperatorApplicationLeaseRegistry(oldId)
        var oldSessionClosed = false
        val oldLease = leases.acquire(oldId) {
            oldSessionClosed = true
        }
        val runtime = DovecotOperatorLeasedRotationRuntime(
            leases = leases,
            prober = probe::probe,
        )
        var targetAdded = false
        var primaryFailure: Throwable? = null
        try {
            require(address !in EligibilityFile(eligibilityPaths).list()) {
                "Disposable rotation target unexpectedly exists"
            }
            generateTargetPassword().use { password ->
                addEligibleTarget(eligibilityCli, address, password)
            }
            targetAdded = true

            val newId = store.rotateOrRecover(target, runtime)

            assertNotEquals(oldId, newId)
            assertFalse(oldLease.isOpen)
            assertTrue(oldSessionClosed)
            assertEquals(0, leases.openLeaseCount(oldId))
            assertEquals(newId, store.loadActive().use { it.id })
            assertEquals(
                DovecotOperatorProbeResult.Success,
                probe.probe(target, store.loadActive()),
            )
            assertFalse(
                Files.exists(
                    operatorPaths.slot(oldId),
                    java.nio.file.LinkOption.NOFOLLOW_LINKS,
                ),
            )
            assertFalse(
                Files.exists(
                    operatorPaths.rotationIntent,
                    java.nio.file.LinkOption.NOFOLLOW_LINKS,
                ),
            )
            assertTrue(
                Files.exists(
                    operatorPaths.slot(newId),
                    java.nio.file.LinkOption.NOFOLLOW_LINKS,
                ),
            )
            val masterLines = Files.readAllLines(
                operatorPaths.masterUsers,
                StandardCharsets.US_ASCII,
            )
            assertEquals(1, masterLines.size)
            assertTrue(
                masterLines.single().startsWith(
                    "${newId.masterUsername}:",
                ),
            )
        } catch (failure: Throwable) {
            primaryFailure = failure
            throw failure
        } finally {
            var cleanupFailure: Throwable? = null
            fun attemptCleanup(block: () -> Unit) {
                try {
                    block()
                } catch (failure: Throwable) {
                    val existing = cleanupFailure
                    if (existing == null) {
                        cleanupFailure = failure
                    } else if (existing !== failure) {
                        existing.addSuppressed(failure)
                    }
                }
            }
            attemptCleanup {
                if (
                    Files.exists(
                        operatorPaths.rotationIntent,
                        java.nio.file.LinkOption.NOFOLLOW_LINKS,
                    )
                ) {
                    store.recoverRotation(target, runtime)
                }
            }
            attemptCleanup {
                runtime.close()
            }
            attemptCleanup {
                if (
                    targetAdded &&
                    address in EligibilityFile(eligibilityPaths).list()
                ) {
                    removeEligibleTarget(eligibilityCli, address)
                }
            }
            if (targetAdded) {
                attemptCleanup {
                    awaitDovecotOperatorTargetRejection(
                        resultSupplier = {
                            probe.probe(target, store.loadActive())
                        },
                    )
                }
            }
            cleanupFailure?.let { failure ->
                val primary = primaryFailure
                if (primary != null) {
                    primary.addSuppressed(failure)
                } else {
                    throw failure
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
                executeEligibility(
                    cli,
                    arrayOf("add", address),
                    input,
                ),
                "Disposable rotation target add failed",
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
            "Disposable rotation target cleanup failed",
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

    private fun repositoryRoot(): Path {
        val working = Path.of(System.getProperty("user.dir"))
            .toAbsolutePath()
            .normalize()
        val dashboardRoot =
            if (working.fileName?.toString() == "dashboard-server") {
                requireNotNull(working.parent)
            } else {
                working
            }
        return requireNotNull(dashboardRoot.parent).also { root ->
            require(Files.isRegularFile(root.resolve("docker-compose.yml")))
        }
    }

    companion object {
        private const val TARGET_PASSWORD_BYTES = 48
        private const val TARGET_PASSWORD_ALPHABET =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
        private val SECURE_RANDOM = SecureRandom()
    }
}
