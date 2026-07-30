package mail.sandbox.dashboard.server.gate.dovecot

import java.io.ByteArrayOutputStream
import java.io.OutputStream
import java.io.PrintStream
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermission
import java.nio.file.attribute.PosixFilePermissions
import java.time.Duration
import java.util.Collections
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread
import kotlin.io.path.createDirectories
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class DovecotOperatorCredentialStoreTest {
    @Test
    fun productionPathsAndTypedIdsAreFixedToTheRepositoryLayout() {
        val repositoryRoot = repositoryRoot()
        val paths = DovecotOperatorPaths.production()
        val proofPaths = DovecotOperatorPaths.task5Proof(repositoryRoot)

        assertEquals(repositoryRoot, paths.repositoryRoot)
        assertEquals(
            repositoryRoot.resolve("debug-dashboard/.runtime/secrets"),
            paths.secretsDirectory,
        )
        assertEquals(
            repositoryRoot.resolve(
                "debug-dashboard/.runtime/secrets/dovecot-operator-a",
            ),
            paths.slotA,
        )
        assertEquals(
            repositoryRoot.resolve(
                "debug-dashboard/.runtime/secrets/dovecot-operator-b",
            ),
            paths.slotB,
        )
        assertEquals(
            repositoryRoot.resolve(
                "debug-dashboard/.runtime/secrets/dovecot-operator-active",
            ),
            paths.active,
        )
        assertEquals(
            repositoryRoot.resolve(
                "debug-dashboard/.runtime/secrets/dovecot-operator-rotation",
            ),
            paths.rotationIntent,
        )
        assertEquals(
            repositoryRoot.resolve(
                "debug-dashboard/.runtime/secrets/dovecot-operator.lock",
            ),
            paths.lock,
        )
        assertEquals(
            repositoryRoot.resolve(
                "debug-dashboard/.runtime/dovecot-operator/master-users",
            ),
            paths.masterUsers,
        )
        assertEquals(
            repositoryRoot.resolve("debug-dashboard/.runtime/task5-proof"),
            proofPaths.runtimeRoot,
        )
        assertEquals(
            repositoryRoot.resolve(
                "debug-dashboard/.runtime/task5-proof/secrets",
            ),
            proofPaths.secretsDirectory,
        )
        assertEquals(
            repositoryRoot.resolve(
                "debug-dashboard/.runtime/task5-proof/dovecot-operator/master-users",
            ),
            proofPaths.masterUsers,
        )
        assertEquals("a", DovecotOperatorId.A.reference)
        assertEquals("dashboard-operator-a", DovecotOperatorId.A.masterUsername)
        assertEquals("b", DovecotOperatorId.B.reference)
        assertEquals("dashboard-operator-b", DovecotOperatorId.B.masterUsername)
    }

    @Test
    fun secretOwnsMutableBytesWipesOnCloseAndRedactsDiagnostics() {
        val canary = "operator-secret-canary"
        val owned = canary.toByteArray(StandardCharsets.US_ASCII)
        val secret = DovecotOperatorSecret.takeOwnership(owned)
        val alias = secret.withBytes { bytes ->
            assertContentEquals(canary.toByteArray(StandardCharsets.US_ASCII), bytes)
            bytes
        }

        assertFalse(secret.toString().contains(canary))
        secret.close()

        assertTrue(owned.all { it == 0.toByte() })
        assertTrue(alias.all { it == 0.toByte() })
        assertFailsWith<IllegalStateException> {
            secret.withBytes { }
        }
    }

    @Test
    fun secureGeneratorProducesOnlyBoundedLoginSafeAsciiAndClosesEveryBuffer() {
        repeat(16) {
            val secret = SecureDovecotOperatorSecretGenerator().generate()
            val alias = secret.withBytes { bytes ->
                assertEquals(48, bytes.size)
                assertTrue(
                    bytes.all { byte ->
                        byte.toInt().toChar() in
                            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
                    },
                )
                bytes
            }
            secret.close()
            assertTrue(alias.all { it == 0.toByte() })
        }
    }

    @Test
    fun emptyBootstrapPublishesSlotAThenOneMasterThenActiveLast() {
        val fixture = temporaryRepository()
        val canary = "InitialOperatorSecret0123456789-._~"
        val generated = canary.toByteArray(StandardCharsets.US_ASCII)
        val observedHashInput = AtomicReference<ByteArray>()
        val points = Collections.synchronizedList(
            mutableListOf<DovecotOperatorCommitPoint>(),
        )
        val store = DovecotOperatorCredentialStore(
            paths = fixture.paths,
            generator = DovecotOperatorSecretGenerator {
                DovecotOperatorSecret.takeOwnership(generated)
            },
            hasher = DovecotOperatorHashBoundary { secret ->
                assertTrue(
                    DovecotOperatorCommitPoint.StableLockAcquired in points,
                    "generation and hashing must occur under the stable lock",
                )
                secret.withBytes { observedHashInput.set(it.copyOf()) }
                HASH_A
            },
            verifier = MATCHING_VERIFIER,
            observer = DovecotOperatorStoreObserver { point, _ ->
                points += point
            },
        )

        assertEquals(DovecotOperatorId.A, store.bootstrap())

        assertTrue(generated.all { it == 0.toByte() })
        assertContentEquals(
            canary.toByteArray(StandardCharsets.US_ASCII),
            observedHashInput.get(),
        )
        observedHashInput.get().fill(0)
        assertEquals(canary, Files.readString(fixture.paths.slotA))
        assertFalse(Files.exists(fixture.paths.slotB, LinkOption.NOFOLLOW_LINKS))
        assertEquals(
            "dashboard-operator-a:$HASH_A\n",
            Files.readString(fixture.paths.masterUsers),
        )
        assertEquals("a", Files.readString(fixture.paths.active))
        assertEquals(
            listOf(
                DovecotOperatorCommitPoint.StableLockAcquired,
                DovecotOperatorCommitPoint.BeforeSlotReplace,
                DovecotOperatorCommitPoint.AfterSlotReplace,
                DovecotOperatorCommitPoint.BeforeMasterReplace,
                DovecotOperatorCommitPoint.AfterMasterReplace,
                DovecotOperatorCommitPoint.BeforeActiveReplace,
                DovecotOperatorCommitPoint.AfterActiveReplace,
                DovecotOperatorCommitPoint.FinalVerified,
            ),
            points,
        )
        assertOwnerOnlyDirectory(fixture.paths.secretsDirectory)
        assertOwnerOnlyDirectory(fixture.paths.operatorDirectory)
        listOf(
            fixture.paths.slotA,
            fixture.paths.active,
            fixture.paths.lock,
            fixture.paths.masterUsers,
        ).forEach(::assertOwnerOnlyFile)
        assertTrue(recognizedTemporaries(fixture.paths).isEmpty())
    }

    @Test
    fun consistentBootstrapIsIdempotentAndLoaderReturnsOnlyTheActiveMutableSecret() {
        val fixture = temporaryRepository()
        bootstrap(fixture, "active-secret")
        val store = DovecotOperatorCredentialStore(
            paths = fixture.paths,
            generator = DovecotOperatorSecretGenerator {
                error("consistent bootstrap must not generate another secret")
            },
            hasher = DovecotOperatorHashBoundary {
                error("consistent bootstrap must not hash another secret")
            },
            verifier = MATCHING_VERIFIER,
        )

        assertEquals(DovecotOperatorId.A, store.bootstrap())
        val credential = store.loadActive()
        val alias = credential.withSecretBytes { bytes ->
            assertContentEquals("active-secret".toByteArray(), bytes)
            bytes
        }
        assertEquals(DovecotOperatorId.A, credential.id)
        assertFalse(credential.toString().contains("active-secret"))
        credential.close()
        assertTrue(alias.all { it == 0.toByte() })
    }

    @Test
    fun rotationStagesProbesSwitchesDrainsAndRevokesAToBInExactOrder() {
        val fixture = temporaryRepository()
        bootstrap(fixture, "old-secret")
        val generated = "new-secret".toByteArray(StandardCharsets.US_ASCII)
        val events = mutableListOf<DovecotOperatorCommitPoint>()
        val runtimeEvents = mutableListOf<String>()
        var oldGenerationBlocked = false
        val runtime = object : DovecotOperatorRotationRuntime {
            override fun observePasswdFile(
                target: DovecotOperatorTarget,
                credential: DovecotOperatorCredential,
            ): DovecotOperatorProbeResult {
                runtimeEvents += "observe-${credential.id.reference}"
                return when (credential.id) {
                    DovecotOperatorId.A ->
                        if (oldGenerationBlocked) {
                            DovecotOperatorProbeResult.AuthenticationFailure
                        } else {
                            DovecotOperatorProbeResult.Success
                        }
                    DovecotOperatorId.B -> DovecotOperatorProbeResult.Success
                }
            }

            override fun activateApplication(
                credential: DovecotOperatorCredential,
            ) {
                runtimeEvents += "activate-${credential.id.reference}"
            }

            override fun verifyApplication(
                target: DovecotOperatorTarget,
                expectedId: DovecotOperatorId,
            ): DovecotOperatorProbeResult {
                runtimeEvents += "application-${expectedId.reference}"
                return DovecotOperatorProbeResult.Success
            }

            override fun blockAndDrain(id: DovecotOperatorId) {
                runtimeEvents += "drain-${id.reference}"
                oldGenerationBlocked = true
            }
        }
        val store = DovecotOperatorCredentialStore(
            paths = fixture.paths,
            generator = DovecotOperatorSecretGenerator {
                DovecotOperatorSecret.takeOwnership(generated)
            },
            hasher = DovecotOperatorHashBoundary { HASH_B },
            verifier = MATCHING_VERIFIER,
            observer = DovecotOperatorStoreObserver { point, _ ->
                events += point
            },
        )

        assertEquals(
            DovecotOperatorId.B,
            store.rotateOrRecover(
                target = DovecotOperatorTarget.create("rotation@local.test"),
                runtime = runtime,
            ),
        )

        assertTrue(generated.all { it == 0.toByte() })
        assertFalse(Files.exists(fixture.paths.slotA, LinkOption.NOFOLLOW_LINKS))
        assertEquals("new-secret", Files.readString(fixture.paths.slotB))
        assertEquals("b", Files.readString(fixture.paths.active))
        assertEquals(
            "dashboard-operator-b:$HASH_B\n",
            Files.readString(fixture.paths.masterUsers),
        )
        assertFalse(
            Files.exists(
                fixture.paths.rotationIntent,
                LinkOption.NOFOLLOW_LINKS,
            ),
        )
        assertEquals(
            listOf(
                "observe-b",
                "activate-b",
                "application-b",
                "drain-a",
                "observe-a",
                "observe-b",
            ),
            runtimeEvents,
        )
        assertEquals(
            listOf(
                DovecotOperatorCommitPoint.StableLockAcquired,
                DovecotOperatorCommitPoint.BeforeIntentReplace,
                DovecotOperatorCommitPoint.AfterIntentReplace,
                DovecotOperatorCommitPoint.BeforeSlotReplace,
                DovecotOperatorCommitPoint.AfterSlotReplace,
                DovecotOperatorCommitPoint.BeforeMasterReplace,
                DovecotOperatorCommitPoint.AfterMasterReplace,
                DovecotOperatorCommitPoint.StagedAccepted,
                DovecotOperatorCommitPoint.BeforeActiveReplace,
                DovecotOperatorCommitPoint.AfterActiveReplace,
                DovecotOperatorCommitPoint.ApplicationVerified,
                DovecotOperatorCommitPoint.DrainCompleted,
                DovecotOperatorCommitPoint.BeforeMasterReplace,
                DovecotOperatorCommitPoint.AfterMasterReplace,
                DovecotOperatorCommitPoint.OldRejected,
                DovecotOperatorCommitPoint.NewVerified,
                DovecotOperatorCommitPoint.BeforeSlotDelete,
                DovecotOperatorCommitPoint.AfterSlotDelete,
                DovecotOperatorCommitPoint.BeforeIntentDelete,
                DovecotOperatorCommitPoint.AfterIntentDelete,
                DovecotOperatorCommitPoint.FinalVerified,
            ),
            events,
        )
    }

    @Test
    fun consecutiveRotationsAlternateAToBAndBToA() {
        val fixture = temporaryRepository()
        bootstrap(fixture, "initial-a")
        val generated = ArrayDeque(
            listOf("rotated-b", "rotated-a").map {
                it.toByteArray(StandardCharsets.US_ASCII)
            },
        )
        val hashes = ArrayDeque(listOf(HASH_B, HASH_A))
        val runtime = object : DovecotOperatorRotationRuntime {
            private var rejectNext: DovecotOperatorId? = null

            override fun observePasswdFile(
                target: DovecotOperatorTarget,
                credential: DovecotOperatorCredential,
            ): DovecotOperatorProbeResult =
                if (credential.id == rejectNext) {
                    rejectNext = null
                    DovecotOperatorProbeResult.AuthenticationFailure
                } else {
                    DovecotOperatorProbeResult.Success
                }

            override fun activateApplication(
                credential: DovecotOperatorCredential,
            ) = Unit

            override fun verifyApplication(
                target: DovecotOperatorTarget,
                expectedId: DovecotOperatorId,
            ): DovecotOperatorProbeResult =
                DovecotOperatorProbeResult.Success

            override fun blockAndDrain(id: DovecotOperatorId) {
                rejectNext = id
            }
        }
        val store = DovecotOperatorCredentialStore(
            paths = fixture.paths,
            generator = DovecotOperatorSecretGenerator {
                DovecotOperatorSecret.takeOwnership(generated.removeFirst())
            },
            hasher = DovecotOperatorHashBoundary { hashes.removeFirst() },
            verifier = MATCHING_VERIFIER,
        )
        val target = DovecotOperatorTarget.create("alternating@local.test")

        assertEquals(DovecotOperatorId.B, store.rotateOrRecover(target, runtime))
        assertEquals(DovecotOperatorId.A, store.rotateOrRecover(target, runtime))

        assertEquals("a", Files.readString(fixture.paths.active))
        assertEquals("rotated-a", Files.readString(fixture.paths.slotA))
        assertFalse(Files.exists(fixture.paths.slotB, LinkOption.NOFOLLOW_LINKS))
        assertEquals(
            "dashboard-operator-a:$HASH_A\n",
            Files.readString(fixture.paths.masterUsers),
        )
        assertFalse(
            Files.exists(
                fixture.paths.rotationIntent,
                LinkOption.NOFOLLOW_LINKS,
            ),
        )
        assertTrue(generated.isEmpty())
        assertTrue(hashes.isEmpty())
    }

    @Test
    fun convergenceRetriesOnlyInverseResultsWithFreshWipedCredentials() {
        val fixture = temporaryRepository()
        bootstrap(fixture, "old-secret")
        val generated = "new-secret".toByteArray(StandardCharsets.US_ASCII)
        val sleeps = mutableListOf<Long>()
        val aliases = mutableListOf<ByteArray>()
        val staged = ArrayDeque(
            listOf(
                DovecotOperatorProbeResult.AuthenticationFailure,
                DovecotOperatorProbeResult.AuthenticationFailure,
                DovecotOperatorProbeResult.Success,
            ),
        )
        val application = ArrayDeque(
            listOf(
                DovecotOperatorProbeResult.AuthenticationFailure,
                DovecotOperatorProbeResult.Success,
            ),
        )
        val oldRejection = ArrayDeque(
            listOf(
                DovecotOperatorProbeResult.Success,
                DovecotOperatorProbeResult.Success,
                DovecotOperatorProbeResult.AuthenticationFailure,
            ),
        )
        val newVerification = ArrayDeque(
            listOf(
                DovecotOperatorProbeResult.AuthenticationFailure,
                DovecotOperatorProbeResult.Success,
            ),
        )
        var activated = false
        var drained = false
        val runtime = object : DovecotOperatorRotationRuntime {
            override fun observePasswdFile(
                target: DovecotOperatorTarget,
                credential: DovecotOperatorCredential,
            ): DovecotOperatorProbeResult {
                credential.withSecretBytes { aliases += it }
                return when {
                    credential.id == DovecotOperatorId.B && !activated ->
                        staged.removeFirst()
                    credential.id == DovecotOperatorId.A && drained ->
                        oldRejection.removeFirst()
                    credential.id == DovecotOperatorId.B && drained ->
                        newVerification.removeFirst()
                    else -> error("unexpected convergence phase")
                }
            }

            override fun activateApplication(
                credential: DovecotOperatorCredential,
            ) {
                assertEquals(DovecotOperatorId.B, credential.id)
                activated = true
            }

            override fun verifyApplication(
                target: DovecotOperatorTarget,
                expectedId: DovecotOperatorId,
            ): DovecotOperatorProbeResult = application.removeFirst()

            override fun blockAndDrain(id: DovecotOperatorId) {
                assertEquals(DovecotOperatorId.A, id)
                drained = true
            }
        }
        val store = DovecotOperatorCredentialStore(
            paths = fixture.paths,
            generator = DovecotOperatorSecretGenerator {
                DovecotOperatorSecret.takeOwnership(generated)
            },
            hasher = DovecotOperatorHashBoundary { HASH_B },
            verifier = MATCHING_VERIFIER,
            rotationSleeper =
                DovecotOperatorRotationSleeper(sleeps::add),
        )

        assertEquals(
            DovecotOperatorId.B,
            store.rotateOrRecover(
                DovecotOperatorTarget.create("retry@local.test"),
                runtime,
            ),
        )

        assertEquals(List(6) { 250L }, sleeps)
        assertEquals(8, aliases.size)
        assertTrue(aliases.all { bytes -> bytes.all { it == 0.toByte() } })
        assertTrue(generated.all { it == 0.toByte() })
        assertTrue(staged.isEmpty())
        assertTrue(application.isEmpty())
        assertTrue(oldRejection.isEmpty())
        assertTrue(newVerification.isEmpty())
    }

    @Test
    fun failedOldRejectionRetainsIntentAndBothRawSlotsForForwardRecovery() {
        val fixture = temporaryRepository()
        bootstrap(fixture, "old-secret")
        val generated = "new-secret".toByteArray(StandardCharsets.US_ASCII)
        val sleeps = mutableListOf<Long>()
        var drained = false
        val failure = assertFailsWith<IllegalStateException> {
            DovecotOperatorCredentialStore(
                paths = fixture.paths,
                generator = DovecotOperatorSecretGenerator {
                    DovecotOperatorSecret.takeOwnership(generated)
                },
                hasher = DovecotOperatorHashBoundary { HASH_B },
                verifier = MATCHING_VERIFIER,
                rotationSleeper =
                    DovecotOperatorRotationSleeper(sleeps::add),
            ).rotateOrRecover(
                target =
                    DovecotOperatorTarget.create("retained@local.test"),
                runtime = object : DovecotOperatorRotationRuntime {
                    override fun observePasswdFile(
                        target: DovecotOperatorTarget,
                        credential: DovecotOperatorCredential,
                    ): DovecotOperatorProbeResult =
                        if (
                            credential.id == DovecotOperatorId.A &&
                            drained
                        ) {
                            DovecotOperatorProbeResult.Success
                        } else {
                            DovecotOperatorProbeResult.Success
                        }

                    override fun activateApplication(
                        credential: DovecotOperatorCredential,
                    ) = Unit

                    override fun verifyApplication(
                        target: DovecotOperatorTarget,
                        expectedId: DovecotOperatorId,
                    ): DovecotOperatorProbeResult =
                        DovecotOperatorProbeResult.Success

                    override fun blockAndDrain(id: DovecotOperatorId) {
                        drained = true
                    }
                },
            )
        }

        assertTrue(
            failure.message.orEmpty().contains(
                "remained accepted",
                ignoreCase = true,
            ),
        )
        assertEquals(List(6) { 250L }, sleeps)
        assertTrue(generated.all { it == 0.toByte() })
        assertEquals("a:b", Files.readString(fixture.paths.rotationIntent))
        assertEquals("b", Files.readString(fixture.paths.active))
        assertEquals("old-secret", Files.readString(fixture.paths.slotA))
        assertEquals("new-secret", Files.readString(fixture.paths.slotB))
        assertEquals(
            "dashboard-operator-b:$HASH_B\n",
            Files.readString(fixture.paths.masterUsers),
        )

        assertEquals(
            DovecotOperatorId.B,
            loaderOnlyStore(fixture).recoverRotation(
                target =
                    DovecotOperatorTarget.create("retained@local.test"),
                runtime = RecordingRotationRuntime(),
            ),
        )
        assertFalse(Files.exists(fixture.paths.slotA, LinkOption.NOFOLLOW_LINKS))
        assertFalse(
            Files.exists(
                fixture.paths.rotationIntent,
                LinkOption.NOFOLLOW_LINKS,
            ),
        )
    }

    @Test
    fun recoveryRollsBackBeforeTheSwitchAndCompletesForwardAfterTheSwitch() {
        listOf(
            DovecotOperatorCommitPoint.AfterMasterReplace to
                DovecotOperatorId.A,
            DovecotOperatorCommitPoint.AfterActiveReplace to
                DovecotOperatorId.B,
        ).forEach { (crashPoint, expected) ->
            val fixture = temporaryRepository()
            bootstrap(fixture, "old-secret")
            val generated = "new-secret".toByteArray(StandardCharsets.US_ASCII)
            val target =
                DovecotOperatorTarget.create("recovery@local.test")
            val crashRuntime = RecordingRotationRuntime()
            val crashing = DovecotOperatorCredentialStore(
                paths = fixture.paths,
                generator = DovecotOperatorSecretGenerator {
                    DovecotOperatorSecret.takeOwnership(generated)
                },
                hasher = DovecotOperatorHashBoundary { HASH_B },
                verifier = MATCHING_VERIFIER,
                observer = DovecotOperatorStoreObserver { point, _ ->
                    if (point == crashPoint) throw SimulatedStoreFailure()
                },
            )
            assertFailsWith<SimulatedStoreFailure> {
                crashing.rotateOrRecover(target, crashRuntime)
            }

            val recoveryRuntime = RecordingRotationRuntime()
            val recovered = DovecotOperatorCredentialStore(
                paths = fixture.paths,
                generator = DovecotOperatorSecretGenerator {
                    error("recovery must not generate another credential")
                },
                hasher = DovecotOperatorHashBoundary {
                    error("recovery must not hash another credential")
                },
                verifier = MATCHING_VERIFIER,
            ).recoverRotation(target, recoveryRuntime)

            assertEquals(expected, recovered, crashPoint.name)
            assertFalse(
                Files.exists(
                    fixture.paths.rotationIntent,
                    LinkOption.NOFOLLOW_LINKS,
                ),
                crashPoint.name,
            )
            if (expected == DovecotOperatorId.A) {
                assertEquals("a", Files.readString(fixture.paths.active))
                assertEquals("old-secret", Files.readString(fixture.paths.slotA))
                assertFalse(
                    Files.exists(
                        fixture.paths.slotB,
                        LinkOption.NOFOLLOW_LINKS,
                    ),
                )
                assertEquals(
                    "dashboard-operator-a:$HASH_A\n",
                    Files.readString(fixture.paths.masterUsers),
                )
                assertEquals(emptyList(), recoveryRuntime.events)
            } else {
                assertEquals("b", Files.readString(fixture.paths.active))
                assertEquals("new-secret", Files.readString(fixture.paths.slotB))
                assertFalse(
                    Files.exists(
                        fixture.paths.slotA,
                        LinkOption.NOFOLLOW_LINKS,
                    ),
                )
                assertEquals(
                    "dashboard-operator-b:$HASH_B\n",
                    Files.readString(fixture.paths.masterUsers),
                )
                assertEquals(
                    listOf(
                        "activate-b",
                        "application-b",
                        "drain-a",
                        "observe-a",
                        "observe-b",
                    ),
                    recoveryRuntime.events,
                )
            }
            assertTrue(generated.all { it == 0.toByte() })
        }
    }

    @Test
    fun applicationLeaseRegistrySelectsTheNewIdAndForceClosesOldSessions() {
        val registry =
            DovecotOperatorApplicationLeaseRegistry(DovecotOperatorId.A)
        var oldTransportCloseCount = 0
        val oldLease = registry.acquire(DovecotOperatorId.A) {
            oldTransportCloseCount += 1
        }

        registry.activate(DovecotOperatorId.B)

        assertFailsWith<IllegalStateException> {
            registry.acquire(DovecotOperatorId.A) {}
        }
        val newLease = registry.acquire(DovecotOperatorId.B) {}
        assertTrue(oldLease.isOpen)
        assertTrue(newLease.isOpen)

        registry.blockAndDrain(DovecotOperatorId.A)

        assertFalse(oldLease.isOpen)
        assertTrue(newLease.isOpen)
        assertEquals(1, oldTransportCloseCount)
        assertEquals(0, registry.openLeaseCount(DovecotOperatorId.A))
        assertEquals(1, registry.openLeaseCount(DovecotOperatorId.B))
        newLease.close()
        assertEquals(0, registry.openLeaseCount(DovecotOperatorId.B))
    }

    @Test
    fun failedSessionCloseRemainsTrackedAndIsRetriedBeforeDrainCompletes() {
        val registry =
            DovecotOperatorApplicationLeaseRegistry(DovecotOperatorId.A)
        var closeAttempts = 0
        val lease = registry.acquire(DovecotOperatorId.A) {
            closeAttempts += 1
            if (closeAttempts == 1) {
                throw SimulatedStoreFailure()
            }
        }

        assertFailsWith<SimulatedStoreFailure> {
            registry.blockAndDrain(DovecotOperatorId.A)
        }
        assertTrue(lease.isOpen)
        assertEquals(1, registry.openLeaseCount(DovecotOperatorId.A))

        registry.blockAndDrain(DovecotOperatorId.A)

        assertFalse(lease.isOpen)
        assertEquals(2, closeAttempts)
        assertEquals(0, registry.openLeaseCount(DovecotOperatorId.A))
    }

    @Test
    fun applicationLeaseRegistryEnforcesAFixedTrackedLeaseLimit() {
        val registry =
            DovecotOperatorApplicationLeaseRegistry(DovecotOperatorId.A)
        val leases = (1..15).map {
            registry.acquire(DovecotOperatorId.A) {}
        }

        assertFailsWith<IllegalStateException> {
            registry.acquire(DovecotOperatorId.A) {}
        }
        val verification =
            registry.acquireVerification(DovecotOperatorId.A) {}
        assertFailsWith<IllegalStateException> {
            registry.acquireVerification(DovecotOperatorId.A) {}
        }
        assertEquals(16, registry.openLeaseCount(DovecotOperatorId.A))

        verification.close()
        leases.forEach(AutoCloseable::close)
        assertEquals(0, registry.openLeaseCount(DovecotOperatorId.A))
    }

    @Test
    fun reservedVerificationCapacityLetsAFullGenerationRotateAndDrain() {
        val fixture = temporaryRepository()
        bootstrap(fixture, "old-secret")
        val registry =
            DovecotOperatorApplicationLeaseRegistry(DovecotOperatorId.A)
        val closeCount = AtomicInteger()
        val oldLeases = (1..15).map {
            registry.acquire(DovecotOperatorId.A) {
                closeCount.incrementAndGet()
            }
        }
        assertFailsWith<IllegalStateException> {
            registry.acquire(DovecotOperatorId.A) {}
        }
        val maximumObservedLeases = AtomicInteger()
        val runtime = DovecotOperatorLeasedRotationRuntime(
            leases = registry,
            prober = { _, credential ->
                val total =
                    registry.openLeaseCount(DovecotOperatorId.A) +
                        registry.openLeaseCount(DovecotOperatorId.B)
                maximumObservedLeases.accumulateAndGet(total, ::maxOf)
                if (
                    credential.id == DovecotOperatorId.A &&
                    registry.activeId() == DovecotOperatorId.B
                ) {
                    DovecotOperatorProbeResult.AuthenticationFailure
                } else {
                    DovecotOperatorProbeResult.Success
                }
            },
        )
        val generated =
            "new-secret".toByteArray(StandardCharsets.US_ASCII)

        val rotated = DovecotOperatorCredentialStore(
            paths = fixture.paths,
            generator = DovecotOperatorSecretGenerator {
                DovecotOperatorSecret.takeOwnership(generated)
            },
            hasher = DovecotOperatorHashBoundary { HASH_B },
            verifier = MATCHING_VERIFIER,
        ).rotateOrRecover(
            target =
                DovecotOperatorTarget.create("full-capacity@local.test"),
            runtime = runtime,
        )

        assertEquals(DovecotOperatorId.B, rotated)
        assertEquals(16, maximumObservedLeases.get())
        assertEquals(15, closeCount.get())
        assertTrue(oldLeases.none { it.isOpen })
        assertEquals(0, registry.openLeaseCount(DovecotOperatorId.A))
        assertEquals(0, registry.openLeaseCount(DovecotOperatorId.B))
        assertTrue(generated.all { it == 0.toByte() })
        runtime.close()
    }

    @Test
    fun blockedSessionDrainHasAFixedDeadlineAndOnlyDaemonCloseWork() {
        val registry =
            DovecotOperatorApplicationLeaseRegistry(DovecotOperatorId.A)
        val callbackEntered = CountDownLatch(3)
        val callbackRelease = CountDownLatch(1)
        val callbacksFinished = CountDownLatch(3)
        val drainFinished = CountDownLatch(1)
        val callbackThreads =
            Collections.synchronizedList(mutableListOf<Thread>())
        val drainFailure = AtomicReference<Throwable?>()
        val elapsedNanos = AtomicLong()
        val leases = (1..3).map {
            registry.acquire(DovecotOperatorId.A) {
                callbackThreads += Thread.currentThread()
                callbackEntered.countDown()
                try {
                    while (callbackRelease.count > 0L) {
                        try {
                            callbackRelease.await()
                        } catch (_: InterruptedException) {
                            // Prove uncooperative closes cannot serialize timeouts.
                        }
                    }
                } finally {
                    callbacksFinished.countDown()
                }
            }
        }
        val started = System.nanoTime()
        val drainCaller = thread(
            start = true,
            isDaemon = true,
            name = "lease-drain-test-caller",
        ) {
            try {
                registry.blockAndDrain(DovecotOperatorId.A)
            } catch (failure: Throwable) {
                drainFailure.set(failure)
            } finally {
                elapsedNanos.set(System.nanoTime() - started)
                drainFinished.countDown()
            }
        }

        assertTrue(callbackEntered.await(1, TimeUnit.SECONDS))
        val returnedWithinBound =
            drainFinished.await(2, TimeUnit.SECONDS)
        try {
            assertTrue(returnedWithinBound)
            assertTrue(drainFailure.get() is IllegalStateException)
            assertTrue(elapsedNanos.get() < TimeUnit.SECONDS.toNanos(2))
            assertEquals(3, callbackThreads.size)
            assertEquals(3, callbackThreads.toSet().size)
            callbackThreads.forEach { callbackThread ->
                assertTrue(callbackThread.isDaemon)
                assertNotEquals(drainCaller, callbackThread)
            }
            assertTrue(leases.all { it.isOpen })
            assertEquals(3, registry.openLeaseCount(DovecotOperatorId.A))
        } finally {
            callbackRelease.countDown()
            assertTrue(callbacksFinished.await(1, TimeUnit.SECONDS))
            assertTrue(drainFinished.await(1, TimeUnit.SECONDS))
            drainCaller.join(1_000)
        }
        val releaseDeadline =
            System.nanoTime() + TimeUnit.SECONDS.toNanos(1)
        while (
            registry.openLeaseCount(DovecotOperatorId.A) > 0 &&
            System.nanoTime() < releaseDeadline
        ) {
            Thread.sleep(1)
        }
        assertEquals(0, registry.openLeaseCount(DovecotOperatorId.A))
        registry.blockAndDrain(DovecotOperatorId.A)
        assertTrue(leases.none { it.isOpen })
        assertEquals(0, registry.openLeaseCount(DovecotOperatorId.A))
    }

    @Test
    fun drainFailureStopsBeforeRevocationAndPreservesRecoverableState() {
        val fixture = temporaryRepository()
        bootstrap(fixture, "old-secret")
        val registry =
            DovecotOperatorApplicationLeaseRegistry(DovecotOperatorId.A)
        var closeAttempts = 0
        val oldLease = registry.acquire(DovecotOperatorId.A) {
            closeAttempts += 1
            if (closeAttempts == 1) {
                throw SimulatedStoreFailure()
            }
        }
        val runtime = DovecotOperatorLeasedRotationRuntime(
            leases = registry,
            prober = { _, _ -> DovecotOperatorProbeResult.Success },
        )
        val generated =
            "new-secret".toByteArray(StandardCharsets.US_ASCII)
        val failure = assertFailsWith<SimulatedStoreFailure> {
            DovecotOperatorCredentialStore(
                paths = fixture.paths,
                generator = DovecotOperatorSecretGenerator {
                    DovecotOperatorSecret.takeOwnership(generated)
                },
                hasher = DovecotOperatorHashBoundary { HASH_B },
                verifier = MATCHING_VERIFIER,
            ).rotateOrRecover(
                target =
                    DovecotOperatorTarget.create("drain@local.test"),
                runtime = runtime,
            )
        }

        assertFalse(failure.stackTraceToString().contains("new-secret"))
        assertTrue(generated.all { it == 0.toByte() })
        assertEquals("b", Files.readString(fixture.paths.active))
        assertEquals("a:b", Files.readString(fixture.paths.rotationIntent))
        assertEquals("old-secret", Files.readString(fixture.paths.slotA))
        assertEquals("new-secret", Files.readString(fixture.paths.slotB))
        assertEquals(
            "dashboard-operator-a:$HASH_A\n" +
                "dashboard-operator-b:$HASH_B\n",
            Files.readString(fixture.paths.masterUsers),
        )
        assertTrue(oldLease.isOpen)
        assertEquals(1, registry.openLeaseCount(DovecotOperatorId.A))

        registry.blockAndDrain(DovecotOperatorId.A)
        assertFalse(oldLease.isOpen)
        runtime.close()
    }

    @Test
    fun drainTimeoutStopsBeforeRevocationAndPreservesRecoverableState() {
        val fixture = temporaryRepository()
        bootstrap(fixture, "old-secret")
        val registry =
            DovecotOperatorApplicationLeaseRegistry(DovecotOperatorId.A)
        val callbackEntered = CountDownLatch(1)
        val callbackRelease = CountDownLatch(1)
        val callbackFinished = CountDownLatch(1)
        val oldLease = registry.acquire(DovecotOperatorId.A) {
            callbackEntered.countDown()
            try {
                while (callbackRelease.count > 0L) {
                    try {
                        callbackRelease.await()
                    } catch (_: InterruptedException) {
                        // Prove cancellation cannot bypass the durable timeout state.
                    }
                }
            } finally {
                callbackFinished.countDown()
            }
        }
        val runtime = DovecotOperatorLeasedRotationRuntime(
            leases = registry,
            prober = { _, _ -> DovecotOperatorProbeResult.Success },
        )
        val generated =
            "new-secret".toByteArray(StandardCharsets.US_ASCII)
        val started = System.nanoTime()
        val failure = assertFailsWith<IllegalStateException> {
            DovecotOperatorCredentialStore(
                paths = fixture.paths,
                generator = DovecotOperatorSecretGenerator {
                    DovecotOperatorSecret.takeOwnership(generated)
                },
                hasher = DovecotOperatorHashBoundary { HASH_B },
                verifier = MATCHING_VERIFIER,
            ).rotateOrRecover(
                target =
                    DovecotOperatorTarget.create("drain-timeout@local.test"),
                runtime = runtime,
            )
        }
        val elapsed = System.nanoTime() - started

        try {
            assertTrue(callbackEntered.await(1, TimeUnit.SECONDS))
            assertTrue(elapsed < TimeUnit.SECONDS.toNanos(2))
            assertFalse(failure.stackTraceToString().contains("new-secret"))
            assertTrue(generated.all { it == 0.toByte() })
            assertEquals("b", Files.readString(fixture.paths.active))
            assertEquals("a:b", Files.readString(fixture.paths.rotationIntent))
            assertEquals("old-secret", Files.readString(fixture.paths.slotA))
            assertEquals("new-secret", Files.readString(fixture.paths.slotB))
            assertEquals(
                "dashboard-operator-a:$HASH_A\n" +
                    "dashboard-operator-b:$HASH_B\n",
                Files.readString(fixture.paths.masterUsers),
            )
            assertTrue(oldLease.isOpen)
            assertEquals(1, registry.openLeaseCount(DovecotOperatorId.A))
        } finally {
            callbackRelease.countDown()
            assertTrue(callbackFinished.await(1, TimeUnit.SECONDS))
        }
        registry.blockAndDrain(DovecotOperatorId.A)
        assertFalse(oldLease.isOpen)
        runtime.close()
    }

    @Test
    fun onlyExplicitRecoveryCleansARecognizedOwnerOnlyAbandonedTemporary() {
        val fixture = temporaryRepository()
        bootstrap(fixture, "old-secret")
        val abandoned = fixture.paths.rotationIntent.resolveSibling(
            "${fixture.paths.rotationIntent.fileName}.tmp-" +
                "00000000-0000-0000-0000-000000000001",
        )
        writeOwnerOnly(abandoned, "a:b")
        val events = mutableListOf<DovecotOperatorCommitPoint>()
        val store = DovecotOperatorCredentialStore(
            paths = fixture.paths,
            generator = DovecotOperatorSecretGenerator {
                error("recovery must not generate")
            },
            hasher = DovecotOperatorHashBoundary {
                error("recovery must not hash")
            },
            verifier = MATCHING_VERIFIER,
            observer = DovecotOperatorStoreObserver { point, _ ->
                events += point
            },
        )

        assertFailsWith<IllegalStateException> { store.bootstrap() }
        assertTrue(Files.exists(abandoned, LinkOption.NOFOLLOW_LINKS))

        assertEquals(
            DovecotOperatorId.A,
            store.recoverRotation(
                target = DovecotOperatorTarget.create("recovery@local.test"),
                runtime = RecordingRotationRuntime(),
            ),
        )
        assertFalse(Files.exists(abandoned, LinkOption.NOFOLLOW_LINKS))
        assertEquals("a", Files.readString(fixture.paths.active))
        assertEquals(
            listOf(
                DovecotOperatorCommitPoint.StableLockAcquired,
                DovecotOperatorCommitPoint.StableLockAcquired,
                DovecotOperatorCommitPoint.BeforeTemporaryDelete,
                DovecotOperatorCommitPoint.AfterTemporaryDelete,
            ),
            events,
        )
    }

    @Test
    fun leasedRuntimeCopiesActivationAndVerifiesThroughTheSelectedGeneration() {
        val registry =
            DovecotOperatorApplicationLeaseRegistry(DovecotOperatorId.A)
        val probedIds = mutableListOf<DovecotOperatorId>()
        val probedAliases = mutableListOf<ByteArray>()
        val runtime = DovecotOperatorLeasedRotationRuntime(
            leases = registry,
            prober = { _, credential ->
                probedIds += credential.id
                credential.withSecretBytes { bytes ->
                    probedAliases += bytes
                }
                DovecotOperatorProbeResult.Success
            },
        )
        val activationBytes = "leased-new-secret".toByteArray()
        DovecotOperatorCredential(
            DovecotOperatorId.B,
            DovecotOperatorSecret.takeOwnership(activationBytes),
        ).use(runtime::activateApplication)

        assertTrue(activationBytes.all { it == 0.toByte() })
        assertEquals(
            DovecotOperatorProbeResult.Success,
            runtime.verifyApplication(
                target =
                    DovecotOperatorTarget.create("lease@local.test"),
                expectedId = DovecotOperatorId.B,
            ),
        )
        assertEquals(listOf(DovecotOperatorId.B), probedIds)
        assertTrue(
            probedAliases.single().all { it == 0.toByte() },
            "Application probe credential must be wiped after its lease",
        )
        assertEquals(0, registry.openLeaseCount(DovecotOperatorId.B))
        runtime.close()
    }

    @Test
    fun freshStoreRecoveryConvergesFromEveryObservedDurableBoundary() {
        val fixture = temporaryRepository()
        bootstrap(fixture, "old-secret")
        val snapshots = mutableListOf<OperatorStateSnapshot>()
        val generated = "new-secret".toByteArray(StandardCharsets.US_ASCII)
        val store = DovecotOperatorCredentialStore(
            paths = fixture.paths,
            generator = DovecotOperatorSecretGenerator {
                DovecotOperatorSecret.takeOwnership(generated)
            },
            hasher = DovecotOperatorHashBoundary { HASH_B },
            verifier = MATCHING_VERIFIER,
            observer = DovecotOperatorStoreObserver { point, _ ->
                snapshots += snapshot(point, fixture.paths)
            },
        )
        store.rotateOrRecover(
            target = DovecotOperatorTarget.create("snapshot@local.test"),
            runtime = RecordingRotationRuntime(),
        )

        assertRotationBoundarySnapshots(
            snapshots = snapshots,
            sourcePaths = fixture.paths,
            old = DovecotOperatorId.A,
            new = DovecotOperatorId.B,
            oldSecret = "old-secret",
            newSecret = "new-secret",
            oldHash = HASH_A,
            newHash = HASH_B,
        )
        assertTrue(generated.all { it == 0.toByte() })
    }

    @Test
    fun freshStoreRecoveryConvergesFromEveryBoundaryBToA() {
        val fixture = temporaryRepository()
        bootstrap(fixture, "initial-secret")
        val middle =
            "middle-secret".toByteArray(StandardCharsets.US_ASCII)
        DovecotOperatorCredentialStore(
            paths = fixture.paths,
            generator = DovecotOperatorSecretGenerator {
                DovecotOperatorSecret.takeOwnership(middle)
            },
            hasher = DovecotOperatorHashBoundary { HASH_B },
            verifier = MATCHING_VERIFIER,
        ).rotateOrRecover(
            target = DovecotOperatorTarget.create("snapshot@local.test"),
            runtime = RecordingRotationRuntime(),
        )
        assertTrue(middle.all { it == 0.toByte() })
        assertEquals("b", Files.readString(fixture.paths.active))

        val snapshots = mutableListOf<OperatorStateSnapshot>()
        val generated =
            "final-secret".toByteArray(StandardCharsets.US_ASCII)
        DovecotOperatorCredentialStore(
            paths = fixture.paths,
            generator = DovecotOperatorSecretGenerator {
                DovecotOperatorSecret.takeOwnership(generated)
            },
            hasher = DovecotOperatorHashBoundary { HASH_A },
            verifier = MATCHING_VERIFIER,
            observer = DovecotOperatorStoreObserver { point, _ ->
                snapshots += snapshot(point, fixture.paths)
            },
        ).rotateOrRecover(
            target = DovecotOperatorTarget.create("snapshot@local.test"),
            runtime = RecordingRotationRuntime(),
        )

        assertRotationBoundarySnapshots(
            snapshots = snapshots,
            sourcePaths = fixture.paths,
            old = DovecotOperatorId.B,
            new = DovecotOperatorId.A,
            oldSecret = "middle-secret",
            newSecret = "final-secret",
            oldHash = HASH_B,
            newHash = HASH_A,
        )
        assertTrue(generated.all { it == 0.toByte() })
    }

    @Test
    fun repeatedGeneratedSecretFailsBeforeHashingOrDurableRotationState() {
        val fixture = temporaryRepository()
        bootstrap(fixture, "same-secret")
        val generated = "same-secret".toByteArray(StandardCharsets.US_ASCII)
        var hashCalls = 0
        val failure = assertFailsWith<IllegalStateException> {
            DovecotOperatorCredentialStore(
                paths = fixture.paths,
                generator = DovecotOperatorSecretGenerator {
                    DovecotOperatorSecret.takeOwnership(generated)
                },
                hasher = DovecotOperatorHashBoundary {
                    hashCalls += 1
                    HASH_B
                },
                verifier = MATCHING_VERIFIER,
            ).rotateOrRecover(
                target = DovecotOperatorTarget.create("repeat@local.test"),
                runtime = RecordingRotationRuntime(),
            )
        }

        assertEquals(0, hashCalls)
        assertFalse(failure.stackTraceToString().contains("same-secret"))
        assertTrue(generated.all { it == 0.toByte() })
        assertFalse(
            Files.exists(
                fixture.paths.rotationIntent,
                LinkOption.NOFOLLOW_LINKS,
            ),
        )
        assertFalse(Files.exists(fixture.paths.slotB, LinkOption.NOFOLLOW_LINKS))
        assertEquals("a", Files.readString(fixture.paths.active))
        assertEquals(
            "dashboard-operator-a:$HASH_A\n",
            Files.readString(fixture.paths.masterUsers),
        )
    }

    @Test
    fun finalProjectionRequiresTheOriginalIntentToRemainUnchanged() {
        val fixture = temporaryRepository()
        bootstrap(fixture, "old-secret")
        val generated = "new-secret".toByteArray(StandardCharsets.US_ASCII)
        var oldBlocked = false
        val runtime = object : DovecotOperatorRotationRuntime {
            override fun observePasswdFile(
                target: DovecotOperatorTarget,
                credential: DovecotOperatorCredential,
            ): DovecotOperatorProbeResult = when (credential.id) {
                DovecotOperatorId.A ->
                    if (oldBlocked) {
                        DovecotOperatorProbeResult.AuthenticationFailure
                    } else {
                        DovecotOperatorProbeResult.Success
                    }
                DovecotOperatorId.B -> DovecotOperatorProbeResult.Success
            }

            override fun activateApplication(
                credential: DovecotOperatorCredential,
            ) = Unit

            override fun verifyApplication(
                target: DovecotOperatorTarget,
                expectedId: DovecotOperatorId,
            ): DovecotOperatorProbeResult =
                DovecotOperatorProbeResult.Success

            override fun blockAndDrain(id: DovecotOperatorId) {
                oldBlocked = true
                writeOwnerOnly(fixture.paths.rotationIntent, "b:a")
            }
        }
        val failure = assertFailsWith<IllegalStateException> {
            DovecotOperatorCredentialStore(
                paths = fixture.paths,
                generator = DovecotOperatorSecretGenerator {
                    DovecotOperatorSecret.takeOwnership(generated)
                },
                hasher = DovecotOperatorHashBoundary { HASH_B },
                verifier = MATCHING_VERIFIER,
            ).rotateOrRecover(
                DovecotOperatorTarget.create("intent@local.test"),
                runtime,
            )
        }

        assertFalse(failure.stackTraceToString().contains("new-secret"))
        assertTrue(generated.all { it == 0.toByte() })
        assertEquals(
            "b:a",
            Files.readString(fixture.paths.rotationIntent),
        )
    }

    @Test
    fun malformedImpossibleAndUnsafeRotationStatesFailClosed() {
        val arrangements = mutableListOf<Pair<String, (DovecotOperatorPaths) -> Unit>>(
            "duplicate-intent" to { paths ->
                writeOwnerOnly(paths.rotationIntent, "a:a")
            },
            "oversized-intent" to { paths ->
                writeOwnerOnly(paths.rotationIntent, "a:b\n")
            },
            "reversed-master" to { paths ->
                writeOwnerOnly(paths.rotationIntent, "a:b")
                writeOwnerOnly(paths.slotB, "new-secret")
                writeOwnerOnly(
                    paths.masterUsers,
                    "dashboard-operator-b:$HASH_B\n" +
                        "dashboard-operator-a:$HASH_A\n",
                )
            },
            "duplicate-master" to { paths ->
                writeOwnerOnly(paths.rotationIntent, "a:b")
                writeOwnerOnly(paths.slotB, "new-secret")
                writeOwnerOnly(
                    paths.masterUsers,
                    "dashboard-operator-a:$HASH_A\n" +
                        "dashboard-operator-a:$HASH_A\n",
                )
            },
            "three-masters" to { paths ->
                writeOwnerOnly(paths.rotationIntent, "a:b")
                writeOwnerOnly(paths.slotB, "new-secret")
                writeOwnerOnly(
                    paths.masterUsers,
                    "dashboard-operator-a:$HASH_A\n" +
                        "dashboard-operator-b:$HASH_B\n" +
                        "dashboard-operator-a:$HASH_A\n",
                )
            },
            "post-switch-old-master-only" to { paths ->
                writeOwnerOnly(paths.rotationIntent, "a:b")
                writeOwnerOnly(paths.slotB, "new-secret")
                writeOwnerOnly(paths.active, "b")
            },
            "post-switch-two-masters-without-old-raw" to { paths ->
                writeOwnerOnly(paths.rotationIntent, "a:b")
                writeOwnerOnly(paths.slotB, "new-secret")
                writeOwnerOnly(paths.active, "b")
                writeOwnerOnly(
                    paths.masterUsers,
                    "dashboard-operator-a:$HASH_A\n" +
                        "dashboard-operator-b:$HASH_B\n",
                )
                Files.delete(paths.slotA)
            },
            "pre-switch-two-masters-without-new-raw" to { paths ->
                writeOwnerOnly(paths.rotationIntent, "a:b")
                writeOwnerOnly(
                    paths.masterUsers,
                    "dashboard-operator-a:$HASH_A\n" +
                        "dashboard-operator-b:$HASH_B\n",
                )
            },
            "identical-old-and-new-raw-slots" to { paths ->
                writeOwnerOnly(paths.rotationIntent, "a:b")
                writeOwnerOnly(paths.slotB, "old-secret")
                writeOwnerOnly(
                    paths.masterUsers,
                    "dashboard-operator-a:$HASH_A\n" +
                        "dashboard-operator-b:$HASH_B\n",
                )
            },
        )
        if (supportsSymbolicLinks()) {
            arrangements += "symbolic-intent" to { paths ->
                val target = paths.rotationIntent.resolveSibling(
                    "external-intent",
                )
                writeOwnerOnly(target, "a:b")
                Files.createSymbolicLink(
                    paths.rotationIntent,
                    target.fileName,
                )
            }
        }

        arrangements.forEach { (label, arrange) ->
            val fixture = temporaryRepository()
            bootstrap(fixture, "old-secret")
            arrange(fixture.paths)
            val runtime = RecordingRotationRuntime()

            val failure = assertFailsWith<IllegalStateException>(label) {
                loaderOnlyStore(fixture).recoverRotation(
                    target =
                        DovecotOperatorTarget.create(
                            "corruption@local.test",
                        ),
                    runtime = runtime,
                )
            }

            assertTrue(runtime.events.isEmpty(), label)
            assertFalse(failure.stackTraceToString().contains("old-secret"))
            assertFalse(failure.stackTraceToString().contains("new-secret"))
        }

        if (supportsPosix(temporaryRepository().repositoryRoot)) {
            val wrongIntentMode = temporaryRepository()
            bootstrap(wrongIntentMode, "old-secret")
            writeOwnerOnly(wrongIntentMode.paths.rotationIntent, "a:b")
            Files.setPosixFilePermissions(
                wrongIntentMode.paths.rotationIntent,
                PosixFilePermissions.fromString("rw-r-----"),
            )
            assertFailsWith<IllegalStateException> {
                loaderOnlyStore(wrongIntentMode).recoverRotation(
                    DovecotOperatorTarget.create("mode@local.test"),
                    RecordingRotationRuntime(),
                )
            }

            listOf(
                "not-a-uuid",
                "00000000-0000-0000-0000-000000000001",
            ).forEachIndexed { index, suffix ->
                val unsafeTemporary = temporaryRepository()
                bootstrap(unsafeTemporary, "old-secret")
                val path = unsafeTemporary.paths.rotationIntent.resolveSibling(
                    "${unsafeTemporary.paths.rotationIntent.fileName}.tmp-$suffix",
                )
                writeOwnerOnly(path, "a:b")
                if (index == 1) {
                    Files.setPosixFilePermissions(
                        path,
                        PosixFilePermissions.fromString("rw-r-----"),
                    )
                }
                assertFailsWith<IllegalStateException> {
                    loaderOnlyStore(unsafeTemporary).recoverRotation(
                        DovecotOperatorTarget.create("temp@local.test"),
                        RecordingRotationRuntime(),
                    )
                }
                assertTrue(Files.exists(path, LinkOption.NOFOLLOW_LINKS))
            }
        }
    }

    @Test
    fun existingPartialUnknownAndMultipleIdentityStatesFailClosedWithoutGeneration() {
        val fixtures = listOf<(DovecotOperatorPaths) -> Unit>(
            { paths -> writeOwnerOnly(paths.slotA, "secret-a") },
            { paths -> writeOwnerOnly(paths.active, "a") },
            { paths -> writeOwnerOnly(paths.masterUsers, "dashboard-operator-a:$HASH_A\n") },
            { paths ->
                writeOwnerOnly(paths.slotA, "secret-a")
                writeOwnerOnly(paths.active, "a")
            },
            { paths ->
                writeOwnerOnly(paths.slotA, "secret-a")
                writeOwnerOnly(paths.masterUsers, "dashboard-operator-a:$HASH_A\n")
            },
            { paths ->
                writeOwnerOnly(paths.slotA, "secret-a")
                writeOwnerOnly(paths.active, "unknown")
                writeOwnerOnly(paths.masterUsers, "dashboard-operator-a:$HASH_A\n")
            },
            { paths ->
                writeOwnerOnly(paths.slotA, "secret-a")
                writeOwnerOnly(paths.active, "a")
                writeOwnerOnly(paths.masterUsers, "unknown-master:$HASH_A\n")
            },
            { paths ->
                writeOwnerOnly(paths.slotA, "secret-a")
                writeOwnerOnly(paths.active, "a")
                writeOwnerOnly(
                    paths.masterUsers,
                    "dashboard-operator-a:$HASH_A\n" +
                        "dashboard-operator-b:$HASH_B\n",
                )
            },
            { paths ->
                writeOwnerOnly(paths.slotA, "secret-a")
                writeOwnerOnly(paths.slotB, "secret-b")
                writeOwnerOnly(paths.active, "a")
                writeOwnerOnly(paths.masterUsers, "dashboard-operator-a:$HASH_A\n")
            },
        )

        fixtures.forEachIndexed { index, arrange ->
            val fixture = temporaryRepository()
            arrange(fixture.paths)
            val failure = assertFailsWith<IllegalStateException>("fixture $index") {
                DovecotOperatorCredentialStore(
                    paths = fixture.paths,
                    generator = DovecotOperatorSecretGenerator {
                        error("inconsistent state must not generate")
                    },
                    hasher = DovecotOperatorHashBoundary {
                        error("inconsistent state must not hash")
                    },
                    verifier = MATCHING_VERIFIER,
                ).bootstrap()
            }
            assertFalse(failure.stackTraceToString().contains("secret-a"))
            assertFalse(failure.stackTraceToString().contains("secret-b"))
        }
    }

    @Test
    fun symbolicWrongModeAndRecognizedTemporaryStatesFailClosed() {
        val wrongMode = temporaryRepository()
        bootstrap(wrongMode, "secret")
        if (supportsPosix(wrongMode.paths.active)) {
            Files.setPosixFilePermissions(
                wrongMode.paths.active,
                PosixFilePermissions.fromString("rw-r-----"),
            )
            assertFailsWith<IllegalStateException> {
                loaderOnlyStore(wrongMode).loadActive()
            }
        }

        if (supportsSymbolicLinks()) {
            val symbolic = temporaryRepository()
            bootstrap(symbolic, "secret")
            val real = symbolic.paths.slotA.resolveSibling("real-slot")
            Files.move(symbolic.paths.slotA, real)
            Files.createSymbolicLink(symbolic.paths.slotA, real.fileName)
            assertFailsWith<IllegalStateException> {
                loaderOnlyStore(symbolic).loadActive()
            }
        }

        val abandoned = temporaryRepository()
        ensureOwnedDirectories(abandoned.paths)
        writeOwnerOnly(
            abandoned.paths.secretsDirectory.resolve(
                "dovecot-operator-a.tmp-00000000-0000-0000-0000-000000000001",
            ),
            "partial",
        )
        assertFailsWith<IllegalStateException> {
            loaderOnlyStore(abandoned).bootstrap()
        }
    }

    @Test
    fun failureBeforeAtomicReplaceRetainsItsTemporaryUntilExplicitRecovery() {
        val fixture = temporaryRepository()
        val store = DovecotOperatorCredentialStore(
            paths = fixture.paths,
            generator = DovecotOperatorSecretGenerator {
                DovecotOperatorSecret.takeOwnership("secret".toByteArray())
            },
            hasher = DovecotOperatorHashBoundary { HASH_A },
            verifier = MATCHING_VERIFIER,
            observer = DovecotOperatorStoreObserver { point, _ ->
                if (point == DovecotOperatorCommitPoint.BeforeSlotReplace) {
                    throw SimulatedStoreFailure()
                }
            },
        )

        assertFailsWith<SimulatedStoreFailure> { store.bootstrap() }

        assertFalse(Files.exists(fixture.paths.slotA, LinkOption.NOFOLLOW_LINKS))
        assertFalse(Files.exists(fixture.paths.active, LinkOption.NOFOLLOW_LINKS))
        assertFalse(Files.exists(fixture.paths.masterUsers, LinkOption.NOFOLLOW_LINKS))
        assertEquals(1, recognizedTemporaries(fixture.paths).size)
        assertFailsWith<IllegalStateException> {
            loaderOnlyStore(fixture).bootstrap()
        }
        assertEquals(1, recognizedTemporaries(fixture.paths).size)

        assertFailsWith<IllegalStateException> {
            loaderOnlyStore(fixture).recoverRotation(
                DovecotOperatorTarget.create("recovery@local.test"),
                RecordingRotationRuntime(),
            )
        }
        assertTrue(recognizedTemporaries(fixture.paths).isEmpty())
    }

    @Test
    fun processLockSerializesGenerationHashPublishAndFinalVerification() {
        val fixture = temporaryRepository()
        val firstHasLock = CountDownLatch(1)
        val releaseFirst = CountDownLatch(1)
        val secondDone = CountDownLatch(1)
        val generations = AtomicInteger()
        val failures = Collections.synchronizedList(mutableListOf<Throwable>())
        val first = DovecotOperatorCredentialStore(
            paths = fixture.paths,
            generator = DovecotOperatorSecretGenerator {
                generations.incrementAndGet()
                DovecotOperatorSecret.takeOwnership("serialized-secret".toByteArray())
            },
            hasher = DovecotOperatorHashBoundary { HASH_A },
            verifier = MATCHING_VERIFIER,
            observer = DovecotOperatorStoreObserver { point, _ ->
                if (point == DovecotOperatorCommitPoint.StableLockAcquired) {
                    firstHasLock.countDown()
                    check(releaseFirst.await(5, TimeUnit.SECONDS))
                }
            },
        )
        val second = loaderOnlyStore(fixture)

        val firstThread = thread(name = "operator-store-first") {
            runCatching(first::bootstrap).exceptionOrNull()?.let(failures::add)
        }
        assertTrue(firstHasLock.await(5, TimeUnit.SECONDS))
        val secondThread = thread(name = "operator-store-second") {
            runCatching(second::bootstrap).exceptionOrNull()?.let(failures::add)
            secondDone.countDown()
        }
        assertFalse(secondDone.await(250, TimeUnit.MILLISECONDS))
        releaseFirst.countDown()
        firstThread.join(5_000)
        secondThread.join(5_000)

        assertFalse(firstThread.isAlive)
        assertFalse(secondThread.isAlive)
        assertTrue(failures.isEmpty(), failures.joinToString { it.stackTraceToString() })
        assertEquals(1, generations.get())
        assertEquals("a", Files.readString(fixture.paths.active))
    }

    @Test
    fun existingDovecotHasherAdapterUsesScopedCopyAndClosesIt() {
        val secretBytes = "hash-boundary-secret".toByteArray()
        val secret = DovecotOperatorSecret.takeOwnership(secretBytes)
        lateinit var observed: ByteArray
        lateinit var delegated: EligibilityPassword
        val adapter = ExistingDovecotOperatorHashBoundary(
            EligibilityPasswordHasher { password ->
                delegated = password
                password.withBytes { observed = it.copyOf() }
                HASH_A
            },
        )

        assertEquals(HASH_A, adapter.hash(secret))
        assertContentEquals("hash-boundary-secret".toByteArray(), observed)
        assertFailsWith<IllegalStateException> {
            delegated.withBytes { }
        }
        secret.close()
        assertTrue(secretBytes.all { it == 0.toByte() })
        observed.fill(0)
    }

    @Test
    fun consistentStateRequiresTheActiveSecretToVerifyAgainstTheMasterHash() {
        val fixture = temporaryRepository()
        bootstrap(fixture, "active-secret")
        val observedSecret = AtomicReference<ByteArray>()
        val store = DovecotOperatorCredentialStore(
            paths = fixture.paths,
            generator = DovecotOperatorSecretGenerator {
                error("verification must not generate")
            },
            hasher = DovecotOperatorHashBoundary {
                error("verification must not hash")
            },
            verifier = DovecotOperatorHashVerifier { secret, hash ->
                assertEquals(HASH_A, hash)
                secret.withBytes { observedSecret.set(it.copyOf()) }
                false
            },
        )

        assertFailsWith<IllegalStateException> { store.bootstrap() }
        assertFailsWith<IllegalStateException> { store.loadActive() }
        assertContentEquals("active-secret".toByteArray(), observedSecret.get())
        observedSecret.get().fill(0)
    }

    @Test
    fun fixedDovecotVerifierUsesNoShellOneSecretLineAndExactOutcomes() {
        val fixture = temporaryRepository()
        val requests = mutableListOf<EligibilityProcessRequest>()
        val results = ArrayDeque(
            listOf(
                EligibilityProcessResult(
                    exitCode = 0,
                    timedOut = false,
                    stdout = "$HASH_A (verified)\n".toByteArray(),
                    stderr = ByteArray(0),
                ),
                EligibilityProcessResult(
                    exitCode = 75,
                    timedOut = false,
                    stdout = ByteArray(0),
                    stderr = (
                        "Fatal: reverse password verification check failed: " +
                            "Password mismatch\n"
                        ).toByteArray(),
                ),
            ),
        )
        val verifier = ExistingDovecotOperatorHashVerifier(
            repositoryRoot = fixture.repositoryRoot,
            processRunner = EligibilityProcessRunner { request ->
                requests += request
                results.removeFirst()
            },
        )

        val firstBytes = "active-secret".toByteArray()
        val first = DovecotOperatorSecret.takeOwnership(firstBytes)
        assertTrue(verifier.verify(first, HASH_A))
        first.close()
        val secondBytes = "wrong-secret".toByteArray()
        val second = DovecotOperatorSecret.takeOwnership(secondBytes)
        assertFalse(verifier.verify(second, HASH_A))
        second.close()

        assertEquals(2, requests.size)
        requests.forEach { request ->
            assertEquals(
                listOf(
                    "docker",
                    "compose",
                    "exec",
                    "-T",
                    "dovecot",
                    "doveadm",
                    "pw",
                    "-t",
                    HASH_A,
                ),
                request.argv,
            )
            assertEquals(fixture.repositoryRoot, request.workingDirectory)
            assertEquals(Duration.ofSeconds(30), request.timeout)
            assertEquals(16 * 1024, request.maximumOutputBytes)
            assertTrue(request.stdin.all { it == 0.toByte() })
        }
        assertTrue(firstBytes.all { it == 0.toByte() })
        assertTrue(secondBytes.all { it == 0.toByte() })
    }

    @Test
    fun fixedDovecotVerifierRejectsEveryNonExactOutcomeAndInvalidHashBeforeRun() {
        val fixture = temporaryRepository()
        val canary = "verifier-secret-canary"
        val invalidInvocations = AtomicInteger()
        val invalidBytes = canary.toByteArray()
        val invalidSecret = DovecotOperatorSecret.takeOwnership(invalidBytes)
        assertFailsWith<IllegalArgumentException> {
            ExistingDovecotOperatorHashVerifier(
                repositoryRoot = fixture.repositoryRoot,
                processRunner = EligibilityProcessRunner {
                    invalidInvocations.incrementAndGet()
                    error("invalid hash must be rejected before process")
                },
            ).verify(invalidSecret, "{PLAIN}not-approved")
        }
        invalidSecret.close()
        assertEquals(0, invalidInvocations.get())
        assertTrue(invalidBytes.all { it == 0.toByte() })

        val malformedResults = listOf(
            EligibilityProcessResult(
                exitCode = null,
                timedOut = true,
                stdout = ByteArray(0),
                stderr = ByteArray(0),
            ),
            EligibilityProcessResult(
                exitCode = 1,
                timedOut = false,
                stdout = ByteArray(0),
                stderr = "failed".toByteArray(),
            ),
            EligibilityProcessResult(
                exitCode = 0,
                timedOut = false,
                stdout = "$HASH_A (verified)".toByteArray(),
                stderr = ByteArray(0),
            ),
            EligibilityProcessResult(
                exitCode = 0,
                timedOut = false,
                stdout = "$HASH_A (verified)\n".toByteArray(),
                stderr = "unexpected".toByteArray(),
            ),
            EligibilityProcessResult(
                exitCode = 75,
                timedOut = false,
                stdout = "unexpected".toByteArray(),
                stderr = (
                    "Fatal: reverse password verification check failed: " +
                        "Password mismatch\n"
                    ).toByteArray(),
            ),
            EligibilityProcessResult(
                exitCode = 75,
                timedOut = false,
                stdout = ByteArray(0),
                stderr = "Password mismatch\n".toByteArray(),
            ),
        )

        malformedResults.forEach { result ->
            val secretBytes = canary.toByteArray()
            val secret = DovecotOperatorSecret.takeOwnership(secretBytes)
            var request: EligibilityProcessRequest? = null
            val failure = assertFailsWith<IllegalStateException> {
                ExistingDovecotOperatorHashVerifier(
                    repositoryRoot = fixture.repositoryRoot,
                    processRunner = EligibilityProcessRunner { observed ->
                        request = observed
                        result
                    },
                ).verify(secret, HASH_A)
            }
            secret.close()
            assertFalse(failure.stackTraceToString().contains(canary))
            assertTrue(secretBytes.all { it == 0.toByte() })
            assertTrue(requireNotNull(request).stdin.all { it == 0.toByte() })
            assertTrue(result.stdout.all { it == 0.toByte() })
            assertTrue(result.stderr.all { it == 0.toByte() })
        }
    }

    @Test
    fun bootstrapCliAcceptsOnlyTheExactCommandAndPrintsNoCredentialMaterial() {
        val productionInvocations = AtomicInteger()
        val proofInvocations = AtomicInteger()
        val cli = DovecotOperatorCredentialStoreCli(
            environment = emptyMap(),
            storeFactory = {
                DovecotOperatorBootstrapper {
                    productionInvocations.incrementAndGet()
                    DovecotOperatorId.A
                }
            },
            task5ProofStoreFactory = {
                DovecotOperatorBootstrapper {
                    proofInvocations.incrementAndGet()
                    DovecotOperatorId.A
                }
            },
        )
        val stdout = ByteArrayOutputStream()
        val stderr = ByteArrayOutputStream()

        assertEquals(
            0,
            cli.execute(
                args = arrayOf("bootstrap"),
                stdout = PrintStream(stdout, true, StandardCharsets.UTF_8),
                stderr = PrintStream(stderr, true, StandardCharsets.UTF_8),
            ),
        )
        assertEquals(1, productionInvocations.get())
        assertEquals(0, proofInvocations.get())
        assertEquals("Dovecot operator credential bootstrap complete\n", stdout.toString())
        assertEquals("", stderr.toString())

        assertEquals(
            0,
            cli.execute(
                args = arrayOf("bootstrap-task5-proof"),
                stdout = PrintStream(stdout, true, StandardCharsets.UTF_8),
                stderr = PrintStream(stderr, true, StandardCharsets.UTF_8),
            ),
        )
        assertEquals(1, productionInvocations.get())
        assertEquals(1, proofInvocations.get())
        assertEquals(
            "Dovecot operator credential bootstrap complete\n".repeat(2),
            stdout.toString(),
        )
        assertEquals("", stderr.toString())

        listOf(
            emptyArray(),
            arrayOf("bootstrap", "--path", "/tmp/other"),
            arrayOf("bootstrap", "--slot", "b"),
            arrayOf("bootstrap-task5-proof", "--path", "/tmp/other"),
            arrayOf("rotate"),
        ).forEach { args ->
            val rejectedOut = ByteArrayOutputStream()
            val rejectedErr = ByteArrayOutputStream()
            assertNotEquals(
                0,
                cli.execute(
                    args = args,
                    stdout = PrintStream(rejectedOut),
                    stderr = PrintStream(rejectedErr),
                ),
            )
            assertEquals("", rejectedOut.toString())
            assertEquals("Dovecot operator credential command failed\n", rejectedErr.toString())
        }
        assertEquals(1, productionInvocations.get())
        assertEquals(1, proofInvocations.get())

        val proofSelected = DovecotOperatorCredentialStoreCli(
            environment = mapOf(
                "DOVECOT_LIVE_PROFILE" to "task5-proof",
            ),
            storeFactory = {
                error("proof selection must never reach normal authority")
            },
            task5ProofStoreFactory = {
                DovecotOperatorBootstrapper {
                    proofInvocations.incrementAndGet()
                    DovecotOperatorId.A
                }
            },
        )
        assertNotEquals(
            0,
            proofSelected.execute(
                args = arrayOf("bootstrap"),
                stdout = PrintStream(OutputStream.nullOutputStream()),
                stderr = PrintStream(OutputStream.nullOutputStream()),
            ),
        )
        assertEquals(
            0,
            proofSelected.execute(
                args = arrayOf("bootstrap-task5-proof"),
                stdout = PrintStream(OutputStream.nullOutputStream()),
                stderr = PrintStream(OutputStream.nullOutputStream()),
            ),
        )
        assertEquals(2, proofInvocations.get())
    }

    private fun bootstrap(
        fixture: OperatorFixture,
        secretText: String,
    ) {
        val owned = secretText.toByteArray(StandardCharsets.US_ASCII)
        DovecotOperatorCredentialStore(
            paths = fixture.paths,
            generator = DovecotOperatorSecretGenerator {
                DovecotOperatorSecret.takeOwnership(owned)
            },
            hasher = DovecotOperatorHashBoundary { HASH_A },
            verifier = MATCHING_VERIFIER,
        ).bootstrap()
        assertTrue(owned.all { it == 0.toByte() })
    }

    private fun loaderOnlyStore(fixture: OperatorFixture): DovecotOperatorCredentialStore =
        DovecotOperatorCredentialStore(
            paths = fixture.paths,
            generator = DovecotOperatorSecretGenerator {
                error("loader must not generate")
            },
            hasher = DovecotOperatorHashBoundary {
                error("loader must not hash")
            },
            verifier = MATCHING_VERIFIER,
        )

    private fun temporaryRepository(): OperatorFixture {
        val repositoryRoot = Files.createTempDirectory("operator-store-repository-")
            .toRealPath()
        val dashboardRoot = repositoryRoot.resolve("debug-dashboard")
        dashboardRoot.createDirectories()
        repositoryRoot.resolve("docker-compose.yml").writeText("services: {}\n")
        dashboardRoot.resolve("project.yaml").writeText("modules: []\n")
        return OperatorFixture(
            repositoryRoot = repositoryRoot,
            paths = DovecotOperatorPaths.testing(repositoryRoot),
        )
    }

    private fun ensureOwnedDirectories(paths: DovecotOperatorPaths) {
        if (Files.notExists(paths.runtimeRoot)) Files.createDirectory(paths.runtimeRoot)
        if (Files.notExists(paths.secretsDirectory)) {
            Files.createDirectory(paths.secretsDirectory)
        }
        if (Files.notExists(paths.operatorDirectory)) {
            Files.createDirectory(paths.operatorDirectory)
        }
        if (supportsPosix(paths.runtimeRoot)) {
            Files.setPosixFilePermissions(
                paths.runtimeRoot,
                PosixFilePermissions.fromString("rwx------"),
            )
            Files.setPosixFilePermissions(
                paths.secretsDirectory,
                PosixFilePermissions.fromString("rwx------"),
            )
            Files.setPosixFilePermissions(
                paths.operatorDirectory,
                PosixFilePermissions.fromString("rwx------"),
            )
        }
    }

    private fun writeOwnerOnly(
        path: Path,
        contents: String,
    ) {
        val paths = DovecotOperatorPaths.testing(
            requireNotNull(
                path.toAbsolutePath().normalize()
                    .parentSequence()
                    .firstOrNull { parent ->
                        Files.isRegularFile(
                            parent.resolve("docker-compose.yml"),
                            LinkOption.NOFOLLOW_LINKS,
                        )
                    },
            ),
        )
        ensureOwnedDirectories(paths)
        path.parent.createDirectories()
        Files.writeString(path, contents, StandardCharsets.US_ASCII)
        if (supportsPosix(path)) {
            Files.setPosixFilePermissions(
                path,
                PosixFilePermissions.fromString("rw-------"),
            )
        }
    }

    private fun Path.parentSequence(): Sequence<Path> = sequence {
        var current: Path? = this@parentSequence
        while (current != null) {
            yield(current)
            current = current.parent
        }
    }

    private fun recognizedTemporaries(paths: DovecotOperatorPaths): List<Path> =
        listOf(paths.secretsDirectory, paths.operatorDirectory)
            .filter { Files.isDirectory(it, LinkOption.NOFOLLOW_LINKS) }
            .flatMap { directory ->
                Files.list(directory).use { entries ->
                    entries.filter { path -> ".tmp-" in path.fileName.toString() }.toList()
                }
            }

    private fun assertRotationBoundarySnapshots(
        snapshots: List<OperatorStateSnapshot>,
        sourcePaths: DovecotOperatorPaths,
        old: DovecotOperatorId,
        new: DovecotOperatorId,
        oldSecret: String,
        newSecret: String,
        oldHash: String,
        newHash: String,
    ) {
        val expectations = rotationBoundaryExpectations(
            old = old,
            new = new,
            oldSecret = oldSecret,
            newSecret = newSecret,
            oldHash = oldHash,
            newHash = newHash,
        )
        val finalSecrets = mapOf(old to oldSecret, new to newSecret)
        val finalHashes = mapOf(old to oldHash, new to newHash)

        try {
            assertEquals(
                expectations.map { it.point },
                snapshots.map { it.point },
            )
            snapshots.zip(expectations).forEachIndexed { index, pair ->
                val (snapshot, expectation) = pair
                val context =
                    "snapshot $index at ${expectation.point} (${old.name}->${new.name})"
                assertSnapshotProjection(
                    snapshot = snapshot,
                    paths = sourcePaths,
                    expected = expectation,
                    context = context,
                )

                val recoveredFixture = temporaryRepository()
                restore(snapshot, recoveredFixture.paths)
                val recoveryRuntime = RecordingRotationRuntime()
                val recovered = DovecotOperatorCredentialStore(
                    paths = recoveredFixture.paths,
                    generator = DovecotOperatorSecretGenerator {
                        error("snapshot recovery must not generate")
                    },
                    hasher = DovecotOperatorHashBoundary {
                        error("snapshot recovery must not hash")
                    },
                    verifier = MATCHING_VERIFIER,
                ).recoverRotation(
                    target =
                        DovecotOperatorTarget.create(
                            "snapshot@local.test",
                        ),
                    runtime = recoveryRuntime,
                )

                val expectedId = expectation.recoveredId
                assertEquals(expectedId, recovered, context)
                assertEquals(
                    expectedId.reference,
                    Files.readString(recoveredFixture.paths.active),
                    context,
                )
                assertEquals(
                    finalSecrets.getValue(expectedId),
                    Files.readString(recoveredFixture.paths.slot(expectedId)),
                    context,
                )
                assertFalse(
                    Files.exists(
                        recoveredFixture.paths.slot(
                            if (expectedId == DovecotOperatorId.A) {
                                DovecotOperatorId.B
                            } else {
                                DovecotOperatorId.A
                            },
                        ),
                        LinkOption.NOFOLLOW_LINKS,
                    ),
                    context,
                )
                assertEquals(
                    "${expectedId.masterUsername}:" +
                        "${finalHashes.getValue(expectedId)}\n",
                    Files.readString(recoveredFixture.paths.masterUsers),
                    context,
                )
                assertFalse(
                    Files.exists(
                        recoveredFixture.paths.rotationIntent,
                        LinkOption.NOFOLLOW_LINKS,
                    ),
                    context,
                )
                assertTrue(
                    recognizedTemporaries(recoveredFixture.paths).isEmpty(),
                    context,
                )
                assertEquals(
                    expectation.recoveryEvents,
                    recoveryRuntime.events,
                    context,
                )
            }
        } finally {
            snapshots.forEach(OperatorStateSnapshot::close)
        }
    }

    private fun rotationBoundaryExpectations(
        old: DovecotOperatorId,
        new: DovecotOperatorId,
        oldSecret: String,
        newSecret: String,
        oldHash: String,
        newHash: String,
    ): List<RotationBoundaryExpectation> {
        val intent = "${old.reference}:${new.reference}"
        val oldSlots = mapOf(old to oldSecret)
        val bothSlots = mapOf(old to oldSecret, new to newSecret)
        val newSlots = mapOf(new to newSecret)
        val oldMaster = "${old.masterUsername}:$oldHash\n"
        val bothMasters =
            oldMaster + "${new.masterUsername}:$newHash\n"
        val newMaster = "${new.masterUsername}:$newHash\n"
        val fullRecoveryEvents = listOf(
            "activate-${new.reference}",
            "application-${new.reference}",
            "drain-${old.reference}",
            "observe-${old.reference}",
            "observe-${new.reference}",
        )
        val recoveryEventsWithoutOldRaw = listOf(
            "activate-${new.reference}",
            "application-${new.reference}",
            "drain-${old.reference}",
            "observe-${new.reference}",
        )
        val newSlotTarget = when (new) {
            DovecotOperatorId.A -> SnapshotTarget.SlotA
            DovecotOperatorId.B -> SnapshotTarget.SlotB
        }

        return listOf(
            RotationBoundaryExpectation(
                DovecotOperatorCommitPoint.StableLockAcquired,
                old,
                null,
                oldSlots,
                oldMaster,
                null,
                old,
                emptyList(),
            ),
            RotationBoundaryExpectation(
                DovecotOperatorCommitPoint.BeforeIntentReplace,
                old,
                null,
                oldSlots,
                oldMaster,
                SnapshotTemporaryExpectation(
                    SnapshotTarget.Intent,
                    intent,
                ),
                old,
                emptyList(),
            ),
            RotationBoundaryExpectation(
                DovecotOperatorCommitPoint.AfterIntentReplace,
                old,
                intent,
                oldSlots,
                oldMaster,
                null,
                old,
                emptyList(),
            ),
            RotationBoundaryExpectation(
                DovecotOperatorCommitPoint.BeforeSlotReplace,
                old,
                intent,
                oldSlots,
                oldMaster,
                SnapshotTemporaryExpectation(
                    newSlotTarget,
                    newSecret,
                ),
                old,
                emptyList(),
            ),
            RotationBoundaryExpectation(
                DovecotOperatorCommitPoint.AfterSlotReplace,
                old,
                intent,
                bothSlots,
                oldMaster,
                null,
                old,
                emptyList(),
            ),
            RotationBoundaryExpectation(
                DovecotOperatorCommitPoint.BeforeMasterReplace,
                old,
                intent,
                bothSlots,
                oldMaster,
                SnapshotTemporaryExpectation(
                    SnapshotTarget.Master,
                    bothMasters,
                ),
                old,
                emptyList(),
            ),
            RotationBoundaryExpectation(
                DovecotOperatorCommitPoint.AfterMasterReplace,
                old,
                intent,
                bothSlots,
                bothMasters,
                null,
                old,
                emptyList(),
            ),
            RotationBoundaryExpectation(
                DovecotOperatorCommitPoint.StagedAccepted,
                old,
                intent,
                bothSlots,
                bothMasters,
                null,
                old,
                emptyList(),
            ),
            RotationBoundaryExpectation(
                DovecotOperatorCommitPoint.BeforeActiveReplace,
                old,
                intent,
                bothSlots,
                bothMasters,
                SnapshotTemporaryExpectation(
                    SnapshotTarget.Active,
                    new.reference,
                ),
                old,
                emptyList(),
            ),
            RotationBoundaryExpectation(
                DovecotOperatorCommitPoint.AfterActiveReplace,
                new,
                intent,
                bothSlots,
                bothMasters,
                null,
                new,
                fullRecoveryEvents,
            ),
            RotationBoundaryExpectation(
                DovecotOperatorCommitPoint.ApplicationVerified,
                new,
                intent,
                bothSlots,
                bothMasters,
                null,
                new,
                fullRecoveryEvents,
            ),
            RotationBoundaryExpectation(
                DovecotOperatorCommitPoint.DrainCompleted,
                new,
                intent,
                bothSlots,
                bothMasters,
                null,
                new,
                fullRecoveryEvents,
            ),
            RotationBoundaryExpectation(
                DovecotOperatorCommitPoint.BeforeMasterReplace,
                new,
                intent,
                bothSlots,
                bothMasters,
                SnapshotTemporaryExpectation(
                    SnapshotTarget.Master,
                    newMaster,
                ),
                new,
                fullRecoveryEvents,
            ),
            RotationBoundaryExpectation(
                DovecotOperatorCommitPoint.AfterMasterReplace,
                new,
                intent,
                bothSlots,
                newMaster,
                null,
                new,
                fullRecoveryEvents,
            ),
            RotationBoundaryExpectation(
                DovecotOperatorCommitPoint.OldRejected,
                new,
                intent,
                bothSlots,
                newMaster,
                null,
                new,
                fullRecoveryEvents,
            ),
            RotationBoundaryExpectation(
                DovecotOperatorCommitPoint.NewVerified,
                new,
                intent,
                bothSlots,
                newMaster,
                null,
                new,
                fullRecoveryEvents,
            ),
            RotationBoundaryExpectation(
                DovecotOperatorCommitPoint.BeforeSlotDelete,
                new,
                intent,
                bothSlots,
                newMaster,
                null,
                new,
                fullRecoveryEvents,
            ),
            RotationBoundaryExpectation(
                DovecotOperatorCommitPoint.AfterSlotDelete,
                new,
                intent,
                newSlots,
                newMaster,
                null,
                new,
                recoveryEventsWithoutOldRaw,
            ),
            RotationBoundaryExpectation(
                DovecotOperatorCommitPoint.BeforeIntentDelete,
                new,
                intent,
                newSlots,
                newMaster,
                null,
                new,
                recoveryEventsWithoutOldRaw,
            ),
            RotationBoundaryExpectation(
                DovecotOperatorCommitPoint.AfterIntentDelete,
                new,
                null,
                newSlots,
                newMaster,
                null,
                new,
                emptyList(),
            ),
            RotationBoundaryExpectation(
                DovecotOperatorCommitPoint.FinalVerified,
                new,
                null,
                newSlots,
                newMaster,
                null,
                new,
                emptyList(),
            ),
        )
    }

    private fun assertSnapshotProjection(
        snapshot: OperatorStateSnapshot,
        paths: DovecotOperatorPaths,
        expected: RotationBoundaryExpectation,
        context: String,
    ) {
        val expectedFixed = mutableMapOf<String, String>()
        expectedFixed[relativePath(paths, paths.lock)] = ""
        expectedFixed[relativePath(paths, paths.active)] =
            expected.activeId.reference
        expected.intent?.let { intent ->
            expectedFixed[relativePath(paths, paths.rotationIntent)] = intent
        }
        expected.slots.forEach { (id, secret) ->
            expectedFixed[relativePath(paths, paths.slot(id))] = secret
        }
        expectedFixed[relativePath(paths, paths.masterUsers)] =
            expected.masterContents

        val temporaryFiles = snapshot.files.filterKeys { ".tmp-" in it }
        val fixedFiles = snapshot.files.filterKeys { ".tmp-" !in it }
        assertEquals(expectedFixed.keys, fixedFiles.keys, context)
        expectedFixed.forEach { (relative, contents) ->
            assertContentEquals(
                contents.toByteArray(StandardCharsets.US_ASCII),
                fixedFiles.getValue(relative),
                context,
            )
        }

        val expectedTemporary = expected.temporary
        if (expectedTemporary == null) {
            assertTrue(temporaryFiles.isEmpty(), context)
        } else {
            assertEquals(1, temporaryFiles.size, context)
            val (relative, contents) = temporaryFiles.entries.single()
            val target = expectedTemporary.target.path(paths)
            val prefix = "${relativePath(paths, target)}.tmp-"
            assertTrue(relative.startsWith(prefix), context)
            assertTrue(
                runCatching {
                    UUID.fromString(relative.removePrefix(prefix))
                }.isSuccess,
                context,
            )
            assertContentEquals(
                expectedTemporary.contents.toByteArray(
                    StandardCharsets.US_ASCII,
                ),
                contents,
                context,
            )
        }
    }

    private fun relativePath(
        paths: DovecotOperatorPaths,
        path: Path,
    ): String = paths.runtimeRoot.relativize(path).toString()

    private fun snapshot(
        point: DovecotOperatorCommitPoint,
        paths: DovecotOperatorPaths,
    ): OperatorStateSnapshot {
        val files = mutableMapOf<String, ByteArray>()
        if (Files.isDirectory(paths.runtimeRoot, LinkOption.NOFOLLOW_LINKS)) {
            Files.walk(paths.runtimeRoot).use { entries ->
                entries
                    .filter {
                        Files.isRegularFile(
                            it,
                            LinkOption.NOFOLLOW_LINKS,
                        )
                    }
                    .forEach { file ->
                        files[paths.runtimeRoot.relativize(file).toString()] =
                            Files.readAllBytes(file)
                    }
            }
        }
        return OperatorStateSnapshot(point, files)
    }

    private fun restore(
        snapshot: OperatorStateSnapshot,
        paths: DovecotOperatorPaths,
    ) {
        ensureOwnedDirectories(paths)
        snapshot.files.forEach { (relative, bytes) ->
            val target = paths.runtimeRoot.resolve(relative)
            target.parent.createDirectories()
            Files.write(target, bytes)
            if (supportsPosix(target)) {
                Files.setPosixFilePermissions(
                    target,
                    PosixFilePermissions.fromString("rw-------"),
                )
            }
        }
    }

    private fun assertOwnerOnlyDirectory(path: Path) {
        assertTrue(Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS))
        assertFalse(Files.isSymbolicLink(path))
        if (supportsPosix(path)) {
            assertEquals(
                PosixFilePermissions.fromString("rwx------"),
                Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS),
            )
        }
    }

    private fun assertOwnerOnlyFile(path: Path) {
        assertTrue(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS))
        assertFalse(Files.isSymbolicLink(path))
        if (supportsPosix(path)) {
            assertEquals(
                PosixFilePermissions.fromString("rw-------"),
                Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS),
            )
        }
    }

    private fun supportsPosix(path: Path): Boolean =
        path.fileSystem.supportedFileAttributeViews().contains("posix")

    private fun supportsSymbolicLinks(): Boolean {
        val root = Files.createTempDirectory("operator-symlink-probe-")
        return try {
            val target = Files.createFile(root.resolve("target"))
            val link = root.resolve("link")
            Files.createSymbolicLink(link, target.fileName)
            Files.isSymbolicLink(link)
        } catch (_: UnsupportedOperationException) {
            false
        } catch (_: SecurityException) {
            false
        }
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

    private data class OperatorFixture(
        val repositoryRoot: Path,
        val paths: DovecotOperatorPaths,
    )

    private data class RotationBoundaryExpectation(
        val point: DovecotOperatorCommitPoint,
        val activeId: DovecotOperatorId,
        val intent: String?,
        val slots: Map<DovecotOperatorId, String>,
        val masterContents: String,
        val temporary: SnapshotTemporaryExpectation?,
        val recoveredId: DovecotOperatorId,
        val recoveryEvents: List<String>,
    )

    private data class SnapshotTemporaryExpectation(
        val target: SnapshotTarget,
        val contents: String,
    )

    private enum class SnapshotTarget {
        SlotA,
        SlotB,
        Active,
        Intent,
        Master,
        ;

        fun path(paths: DovecotOperatorPaths): Path = when (this) {
            SlotA -> paths.slotA
            SlotB -> paths.slotB
            Active -> paths.active
            Intent -> paths.rotationIntent
            Master -> paths.masterUsers
        }
    }

    private class OperatorStateSnapshot(
        val point: DovecotOperatorCommitPoint,
        val files: Map<String, ByteArray>,
    ) : AutoCloseable {
        override fun close() {
            files.values.forEach { it.fill(0) }
        }
    }

    private class RecordingRotationRuntime :
        DovecotOperatorRotationRuntime {
        val events = mutableListOf<String>()
        private val blockedIds = mutableSetOf<DovecotOperatorId>()

        override fun observePasswdFile(
            target: DovecotOperatorTarget,
            credential: DovecotOperatorCredential,
        ): DovecotOperatorProbeResult {
            events += "observe-${credential.id.reference}"
            return if (credential.id in blockedIds) {
                DovecotOperatorProbeResult.AuthenticationFailure
            } else {
                DovecotOperatorProbeResult.Success
            }
        }

        override fun activateApplication(
            credential: DovecotOperatorCredential,
        ) {
            events += "activate-${credential.id.reference}"
        }

        override fun verifyApplication(
            target: DovecotOperatorTarget,
            expectedId: DovecotOperatorId,
        ): DovecotOperatorProbeResult {
            events += "application-${expectedId.reference}"
            return DovecotOperatorProbeResult.Success
        }

        override fun blockAndDrain(id: DovecotOperatorId) {
            events += "drain-${id.reference}"
            blockedIds += id
        }
    }

    private class SimulatedStoreFailure : RuntimeException()

    companion object {
        private const val HASH_A =
            "{ARGON2ID}\$argon2id\$v=19\$m=65536,t=3,p=1\$c2FsdA\$ZGlnZXN0"
        private const val HASH_B =
            "{ARGON2ID}\$argon2id\$v=19\$m=32768,t=4,p=2\$c2FsdDI\$ZGlnZXN0Mg"
        private val MATCHING_VERIFIER =
            DovecotOperatorHashVerifier { _, _ -> true }
    }
}
