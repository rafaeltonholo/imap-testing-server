package mail.sandbox.dashboard.server.gate.dovecot

import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
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
        val launchProfile = live.operatorRuntime.launchProfile
        val eligibilityAdapter =
            Task6LaunchProfileEligibilityAdapter(launchProfile)
        val address =
            "task6-rotation-" +
                UUID.randomUUID().toString().replace("-", "") +
                "@local.test"
        val target = DovecotOperatorTarget.create(address)
        val eligibilityPaths = live.profile.eligibilityPaths()
        val eligibilityCli = EligibilityFileCli(
            pathsProvider = { eligibilityPaths },
            hasherFactory = { eligibilityAdapter },
        )
        val operatorPaths = live.profile.operatorPaths()
        val store = DovecotOperatorCredentialStore(
            paths = operatorPaths,
            generator = SecureDovecotOperatorSecretGenerator(),
            hasher = ExistingDovecotOperatorHashBoundary(
                eligibilityAdapter,
            ),
            verifier = eligibilityAdapter,
        )
        val transportFactory = live.operatorRuntime.transportFactory()
        val probe = DovecotOperatorProbe(
            transportFactory = transportFactory,
            requireMailboxRead = true,
        )
        task6DisposableEligibilityFixture(
            address = address,
            paths = eligibilityPaths,
            executor = eligibilityCli,
            rejectionProof = {
                awaitDovecotOperatorTargetRejection(
                    resultSupplier = {
                        probe.probe(target, store.loadActive())
                    },
                )
            },
        ).run {
            val oldId = store.loadActive().use { it.id }
            val runtime = DovecotOperatorLeasedRotationRuntime(
                leases = DovecotOperatorApplicationLeaseRegistry(oldId),
                prober = probe::probe,
            )
            val leases = runtime.applicationLeaseRegistry
            var heldOld:
                LeasedHeldDovecotOperatorImapSession? = null
            var primaryFailure: Throwable? = null
            try {
                val oldCredential = store.loadActive()
                val seedMessage = deterministicRotationMessage(target)
                val oldHolder = try {
                    check(oldCredential.id == oldId) {
                        "Dovecot operator active ID changed before session hold"
                    }
                    HeldDovecotOperatorImapSession.openAndSeedLeased(
                        leaseRegistry = leases,
                        transportFactory = transportFactory,
                        target = target,
                        credential = oldCredential,
                        message = seedMessage,
                    )
                } catch (failure: Throwable) {
                    oldCredential.close()
                    seedMessage.fill(0)
                    throw failure
                }
                heldOld = oldHolder
                val oldSession = oldHolder.session
                assertEquals(1, leases.openLeaseCount(oldId))
                oldSession.requireUsable()

                val newId = store.rotateOrRecover(target, runtime)

                assertNotEquals(oldId, newId)
                assertTrue(oldSession.isClosed)
                oldSession.requireClosedAndUnusable()
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
                    heldOld?.close()
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
}

internal fun deterministicRotationMessage(
    target: DovecotOperatorTarget,
): ByteArray =
    (
        "From: dashboard-rotation@local.test\r\n" +
            "To: ${target.address}\r\n" +
            "Date: Thu, 30 Jul 2026 12:00:00 +0000\r\n" +
            "Subject: Dovecot Task 6 rotation proof\r\n" +
            "Message-ID: <task6-rotation-read-proof.${target.address}>\r\n" +
            "MIME-Version: 1.0\r\n" +
            "Content-Type: text/plain; charset=UTF-8\r\n" +
            "\r\n" +
            "Deterministic Dovecot Task 6 mailbox read proof.\r\n"
        ).toByteArray(StandardCharsets.US_ASCII)
