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
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
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
    fun failureBeforeAtomicReplaceDurablyDeletesItsExactTemporary() {
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
