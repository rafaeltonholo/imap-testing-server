package mail.sandbox.dashboard.server.gate.dovecot

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.io.PrintStream
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.PosixFileAttributes
import java.nio.file.attribute.PosixFilePermissions
import java.time.Duration
import java.util.Collections
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.io.path.createDirectories
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class EligibilityFileTest {
    @Test
    fun repositoryConfigUsesTheFixedRuntimeDirectoryAndPasswdFileBoundary() {
        val repositoryRoot = repositoryRoot()
        val productionPaths = EligibilityPaths.production()
        val compose = Files.readString(repositoryRoot.resolve("docker-compose.yml"))
        val auth = Files.readString(repositoryRoot.resolve("config/10-auth.conf"))
        val doveadm = Files.readString(repositoryRoot.resolve("config/20-doveadm.conf"))
        val seed = Files.readString(repositoryRoot.resolve("config/users.seed"))
        val ignoreLines = Files.readAllLines(repositoryRoot.resolve(".gitignore"))

        assertEquals(
            repositoryRoot.resolve("debug-dashboard/.runtime/dovecot/users"),
            productionPaths.users,
        )
        assertEquals(
            repositoryRoot.resolve("debug-dashboard/.runtime/dovecot/users.lock"),
            productionPaths.lock,
        )
        assertTrue(
            Files.notExists(
                repositoryRoot.resolve("config/users"),
                LinkOption.NOFOLLOW_LINKS,
            ),
        )
        val seedAddresses = seed.removeSuffix("\n").split('\n')
        assertTrue(seed.endsWith("\n"))
        assertTrue(seedAddresses.isNotEmpty())
        assertEquals(seedAddresses.sorted(), seedAddresses)
        assertEquals(seedAddresses.size, seedAddresses.toSet().size)
        seedAddresses.forEach { address ->
            assertEquals(address, EligibilityAddress.requireCanonical(address))
            assertFalse(':' in address)
        }
        assertTrue(
            ignoreLines.containsAll(
                listOf(
                    "/config/users",
                    "debug-dashboard/.runtime/dovecot/",
                    "debug-dashboard/.runtime/dovecot-operator/",
                    "debug-dashboard/.runtime/secrets/",
                ),
            ),
        )
        assertTrue(
            compose.contains(
                "      - ./debug-dashboard/.runtime/dovecot:/etc/dovecot/runtime:ro",
            ),
        )
        assertFalse(compose.contains(".runtime/dovecot/users:"))
        assertFalse(compose.contains(".runtime/dovecot-operator:"))
        assertFalse(compose.contains(".runtime/secrets:"))
        assertFalse(auth.contains("userdb static"))
        assertTrue(
            auth.contains(
                """
                passdb passwd-file {
                  passwd_file_path = /etc/dovecot/runtime/users
                }

                passdb oauth2 {
                  mechanisms_filter = xoauth2 oauthbearer
                }

                userdb passwd-file {
                  passwd_file_path = /etc/dovecot/runtime/users
                  fields {
                    uid:default = 1000
                    gid:default = 1000
                    home:default = /srv/vmail/%{user}
                  }
                }
                """.trimIndent(),
            ),
        )
        assertEquals(
            """
            service doveadm {
              inet_listener http {
                port = 0
              }
            }
            """.trimIndent() + "\n",
            doveadm,
        )
    }

    @Test
    fun exactArgon2idEntriesCommentsAndBlankLinesRoundTripDeterministically() {
        val source = buildString {
            append("# managed Dovecot eligibility\n")
            append("\n")
            append("alpha@local.test:$HASH_A\n")
            append("  # retained annotation\n")
            append("beta+tag@sub.local.test:$HASH_B\n")
        }

        val document = EligibilityDocument.parse(source)

        assertEquals(
            listOf("alpha@local.test", "beta+tag@sub.local.test"),
            document.addresses(),
        )
        assertEquals(source, document.render())
        assertEquals(
            "alpha@local.test:$HASH_A",
            EligibilityEntry.parse("alpha@local.test:$HASH_A").render(),
        )
        assertFalse(EligibilityEntry.parse("alpha@local.test:$HASH_A").toString().contains(HASH_A))
    }

    @Test
    fun entryParserRejectsUnapprovedUnprefixedEmptyAndMalformedHashes() {
        listOf(
            "alpha@local.test:hash",
            "alpha@local.test:{PLAIN}password",
            "alpha@local.test:{SHA512-CRYPT}hash",
            "alpha@local.test:{argon2id}hash",
            "alpha@local.test:{ARGON2ID}",
            "alpha@local.test:{ARGON2ID}garbage",
            "alpha@local.test:{ARGON2ID}\$argon2id\$",
            "alpha@local.test:{ARGON2ID}\$argon2id\$\$m=65536,t=3,p=1\$salt\$hash",
            "alpha@local.test:{ARGON2ID}\$argon2id\$v=19\$\$salt\$hash",
            "alpha@local.test:{ARGON2ID}\$argon2id\$v=19\$m=65536,t=3,p=1\$\$hash",
            "alpha@local.test:{ARGON2ID}\$argon2id\$v=19\$m=65536,t=3,p=1\$salt\$",
            "alpha@local.test:{ARGON2ID}\$argon2id\$v=19\$m=1\$salt\$hash\$extra",
            "alpha@local.test:{ARGON2ID} ",
            "alpha@local.test:{ARGON2ID}hash with space",
            "alpha@local.test:{ARGON2ID}hash:tail",
            "alpha@local.test:{ARGON2ID}hash\u0000",
            "alpha@local.test:{ARGON2ID}hash\r",
        ).forEach { malformed ->
            assertFailsWith<IllegalArgumentException> {
                EligibilityEntry.parse(malformed)
            }
        }
    }

    @Test
    fun entryParserRejectsUnprovenArgon2idPhcVariants() {
        listOf(
            "{ARGON2ID}\$argon2id\$v=16\$m=65536,t=3,p=1\$c2FsdA\$ZGlnZXN0",
            "{ARGON2ID}\$argon2id\$v=20\$m=65536,t=3,p=1\$c2FsdA\$ZGlnZXN0",
            "{ARGON2ID}\$argon2id\$v=19\$arbitrary\$c2FsdA\$ZGlnZXN0",
            "{ARGON2ID}\$argon2id\$v=19\$t=3,m=65536,p=1\$c2FsdA\$ZGlnZXN0",
            "{ARGON2ID}\$argon2id\$v=19\$m=65536,p=1,t=3\$c2FsdA\$ZGlnZXN0",
            "{ARGON2ID}\$argon2id\$v=19\$memory=65536,t=3,p=1\$c2FsdA\$ZGlnZXN0",
            "{ARGON2ID}\$argon2id\$v=19\$m=65536,t=3,parallelism=1\$c2FsdA\$ZGlnZXN0",
            "{ARGON2ID}\$argon2id\$v=19\$m=65536,m=3,p=1\$c2FsdA\$ZGlnZXN0",
            "{ARGON2ID}\$argon2id\$v=19\$m=65536,t=3,p=1,x=2\$c2FsdA\$ZGlnZXN0",
            "{ARGON2ID}\$argon2id\$v=19\$m=0,t=3,p=1\$c2FsdA\$ZGlnZXN0",
            "{ARGON2ID}\$argon2id\$v=19\$m=65536,t=0,p=1\$c2FsdA\$ZGlnZXN0",
            "{ARGON2ID}\$argon2id\$v=19\$m=65536,t=3,p=0\$c2FsdA\$ZGlnZXN0",
            "{ARGON2ID}\$argon2id\$v=19\$m=-1,t=3,p=1\$c2FsdA\$ZGlnZXN0",
            "{ARGON2ID}\$argon2id\$v=19\$m=+1,t=3,p=1\$c2FsdA\$ZGlnZXN0",
            "{ARGON2ID}\$argon2id\$v=19\$m=99999999999999999999,t=3,p=1\$c2FsdA\$ZGlnZXN0",
            "{ARGON2ID}\$argon2id\$v=19\$m=65536,t=99999999999999999999,p=1\$c2FsdA\$ZGlnZXN0",
            "{ARGON2ID}\$argon2id\$v=19\$m=65536,t=3,p=99999999999999999999\$c2FsdA\$ZGlnZXN0",
            "{ARGON2ID}\$argon2id\$v=19\$m=65536,t=3,p=1\$salt-\$ZGlnZXN0",
            "{ARGON2ID}\$argon2id\$v=19\$m=65536,t=3,p=1\$salt_\$ZGlnZXN0",
            "{ARGON2ID}\$argon2id\$v=19\$m=65536,t=3,p=1\$salt=\$ZGlnZXN0",
            "{ARGON2ID}\$argon2id\$v=19\$m=65536,t=3,p=1\$A\$ZGlnZXN0",
            "{ARGON2ID}\$argon2id\$v=19\$m=65536,t=3,p=1\$AB\$ZGlnZXN0",
            "{ARGON2ID}\$argon2id\$v=19\$m=65536,t=3,p=1\$c2FsdA\$digest.",
            "{ARGON2ID}\$argon2id\$v=19\$m=65536,t=3,p=1\$c2FsdA\$digest_",
            "{ARGON2ID}\$argon2id\$v=19\$m=65536,t=3,p=1\$c2FsdA\$digest=",
            "{ARGON2ID}\$argon2id\$v=19\$m=65536,t=3,p=1\$c2FsdA\$A",
            "{ARGON2ID}\$argon2id\$v=19\$m=65536,t=3,p=1\$c2FsdA\$AAB",
            "{ARGON2ID}\$argon2id\$v=19\$m=65536,t=3,p=1\$c2FsdA\$ZGlnZXN0\$extra",
        ).forEach { malformedHash ->
            assertFailsWith<IllegalArgumentException>(malformedHash) {
                EligibilityEntry.create("alpha@local.test", malformedHash)
            }
        }
    }

    @Test
    fun parserRejectsDuplicateCanonicalAddresses() {
        val duplicate = buildString {
            append("alpha@local.test:$HASH_A\n")
            append("# unrelated\n")
            append("alpha@local.test:$HASH_B\n")
        }

        assertFailsWith<IllegalArgumentException> {
            EligibilityDocument.parse(duplicate)
        }
    }

    @Test
    fun canonicalAddressValidationRejectsUnsafeAddrSpecs() {
        listOf(
            "",
            "Alpha@local.test",
            "alpha@LOCAL.test",
            " alpha@local.test",
            "alpha@local.test ",
            "alpha @local.test",
            "alpha@ local.test",
            "Display Name <alpha@local.test>",
            "(comment)alpha@local.test",
            "\"alpha\"@local.test",
            "alpha:admin@local.test",
            "alpha;admin@local.test",
            "alpha/admin@local.test",
            "alpha\\admin@local.test",
            "../alpha@local.test",
            "alpha..beta@local.test",
            ".alpha@local.test",
            "alpha.@local.test",
            "alpha",
            "alpha@@local.test",
            "@local.test",
            "alpha@",
            "alpha@.local.test",
            "alpha@local.test.",
            "alpha@local..test",
            "alpha@-local.test",
            "alpha@local-.test",
            "alpha@local_test",
            "alpha@../local.test",
            "alpha@local/test",
            "alpha@local\\test",
            "alpha@local:test",
            "alpha@local test",
            "alpha@local.test\ninjected@local.test",
            "alpha@local.test\r",
            "alpha\u0000@local.test",
            "álpha@local.test",
        ).forEach { unsafe ->
            assertFailsWith<IllegalArgumentException> {
                EligibilityAddress.requireCanonical(unsafe)
            }
        }

        listOf(
            "alpha@local.test",
            "alpha.beta@sub.local.test",
            "alpha+tag@local.test",
            "a@localhost",
            "a1_b-2%tag@a1-b2.local",
        ).forEach { safe ->
            assertEquals(safe, EligibilityAddress.requireCanonical(safe))
        }
    }

    @Test
    fun addResetAndRemovePreserveEveryUnrelatedLineAndOrder() {
        val original = EligibilityDocument.parse(
            "# heading\n\nalpha@local.test:$HASH_A\n# tail\n",
        )

        val added = original.add(EligibilityEntry.create("beta@local.test", HASH_B))
        assertEquals(
            "# heading\n\nalpha@local.test:$HASH_A\n# tail\nbeta@local.test:$HASH_B\n",
            added.render(),
        )

        val reset = added.reset(EligibilityEntry.create("alpha@local.test", HASH_C))
        assertEquals(
            "# heading\n\nalpha@local.test:$HASH_C\n# tail\nbeta@local.test:$HASH_B\n",
            reset.render(),
        )

        val removed = reset.remove("alpha@local.test")
        assertEquals(
            "# heading\n\n# tail\nbeta@local.test:$HASH_B\n",
            removed.render(),
        )
        assertFailsWith<IllegalArgumentException> {
            original.add(EligibilityEntry.create("alpha@local.test", HASH_B))
        }
        assertFailsWith<IllegalArgumentException> {
            original.reset(EligibilityEntry.create("absent@local.test", HASH_B))
        }
        assertFailsWith<IllegalArgumentException> {
            original.remove("absent@local.test")
        }
    }

    @Test
    fun fixedPathsCreateOwnerOnlyDirectoryTargetLockAndTemporaryFiles() {
        val fixture = temporaryRepository()
        if (!supportsPosix(fixture.repositoryRoot)) return
        var temporaryAttributes: PosixFileAttributes? = null
        var targetBeforeAttributes: PosixFileAttributes? = null
        val file = EligibilityFile(
            fixture.paths,
            EligibilityFileObserver { point, target, temporary ->
                if (point == EligibilityFileCommitPoint.BeforeReplace) {
                    temporaryAttributes = Files.readAttributes(
                        requireNotNull(temporary),
                        PosixFileAttributes::class.java,
                        LinkOption.NOFOLLOW_LINKS,
                    )
                    if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) {
                        targetBeforeAttributes = Files.readAttributes(
                            target,
                            PosixFileAttributes::class.java,
                            LinkOption.NOFOLLOW_LINKS,
                        )
                    }
                }
            },
        )

        file.add("alpha@local.test", HASH_A)
        val firstTarget = Files.readAttributes(
            fixture.paths.users,
            PosixFileAttributes::class.java,
            LinkOption.NOFOLLOW_LINKS,
        )
        file.reset("alpha@local.test", HASH_B)
        val secondTarget = Files.readAttributes(
            fixture.paths.users,
            PosixFileAttributes::class.java,
            LinkOption.NOFOLLOW_LINKS,
        )

        assertEquals(
            PosixFilePermissions.fromString("rwx------"),
            Files.getPosixFilePermissions(fixture.paths.dovecotDirectory),
        )
        listOf(fixture.paths.users, fixture.paths.lock).forEach { path ->
            assertTrue(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS))
            assertFalse(Files.isSymbolicLink(path))
            assertEquals(
                PosixFilePermissions.fromString("rw-------"),
                Files.getPosixFilePermissions(path),
            )
        }
        assertEquals(
            PosixFilePermissions.fromString("rw-------"),
            requireNotNull(temporaryAttributes).permissions(),
        )
        assertEquals(firstTarget.owner(), requireNotNull(temporaryAttributes).owner())
        assertEquals(firstTarget.group(), requireNotNull(temporaryAttributes).group())
        assertEquals(requireNotNull(targetBeforeAttributes).owner(), secondTarget.owner())
        assertEquals(requireNotNull(targetBeforeAttributes).group(), secondTarget.group())
        assertEquals(requireNotNull(targetBeforeAttributes).permissions(), secondTarget.permissions())
    }

    @Test
    fun fixedPathValidationRejectsSymlinkComponentsAndNonRegularFiles() {
        if (!supportsSymbolicLinks()) return

        temporaryRepository().also { fixture ->
            val outside = Files.createTempDirectory("eligibility-outside-")
            Files.createSymbolicLink(fixture.paths.runtimeRoot, outside)
            assertFailsWith<IllegalStateException> {
                EligibilityFile(fixture.paths).list()
            }
        }
        temporaryRepository().also { fixture ->
            fixture.paths.runtimeRoot.createDirectories()
            val outside = Files.createTempDirectory("eligibility-outside-")
            Files.createSymbolicLink(fixture.paths.dovecotDirectory, outside)
            assertFailsWith<IllegalStateException> {
                EligibilityFile(fixture.paths).list()
            }
        }
        temporaryRepository().also { fixture ->
            fixture.paths.dovecotDirectory.createDirectories()
            val outside = Files.createTempFile("eligibility-outside-", ".txt")
            Files.createSymbolicLink(fixture.paths.users, outside)
            assertFailsWith<IllegalStateException> {
                EligibilityFile(fixture.paths).list()
            }
        }
        temporaryRepository().also { fixture ->
            fixture.paths.dovecotDirectory.createDirectories()
            Files.createDirectory(fixture.paths.lock)
            assertFailsWith<IllegalStateException> {
                EligibilityFile(fixture.paths).list()
            }
        }
        temporaryRepository().also { fixture ->
            fixture.paths.dovecotDirectory.createDirectories()
            Files.createDirectory(fixture.paths.users)
            assertFailsWith<IllegalStateException> {
                EligibilityFile(fixture.paths).list()
            }
        }
    }

    @Test
    fun wrongDirectoryFileLockAndRecognizedTemporaryModesFailClosed() {
        if (!supportsPosix(Path.of(System.getProperty("java.io.tmpdir")))) return

        temporaryRepository().also { fixture ->
            fixture.paths.dovecotDirectory.createDirectories()
            Files.setPosixFilePermissions(
                fixture.paths.dovecotDirectory,
                PosixFilePermissions.fromString("rwxr-xr-x"),
            )
            assertFailsWith<IllegalStateException> {
                EligibilityFile(fixture.paths).list()
            }
        }
        temporaryRepository().also { fixture ->
            val file = EligibilityFile(fixture.paths)
            file.add("alpha@local.test", HASH_A)
            Files.setPosixFilePermissions(
                fixture.paths.users,
                PosixFilePermissions.fromString("rw-r--r--"),
            )
            assertFailsWith<IllegalStateException> {
                file.list()
            }
        }
        temporaryRepository().also { fixture ->
            val file = EligibilityFile(fixture.paths)
            file.list()
            Files.setPosixFilePermissions(
                fixture.paths.lock,
                PosixFilePermissions.fromString("rw-r--r--"),
            )
            assertFailsWith<IllegalStateException> {
                file.list()
            }
        }
        temporaryRepository().also { fixture ->
            val file = EligibilityFile(fixture.paths)
            file.list()
            val abandoned = fixture.paths.users.resolveSibling(
                "users.tmp-${UUID.randomUUID()}",
            )
            Files.writeString(abandoned, "not trusted")
            Files.setPosixFilePermissions(
                abandoned,
                PosixFilePermissions.fromString("rw-r--r--"),
            )
            assertFailsWith<IllegalStateException> {
                file.list()
            }
            assertTrue(Files.exists(abandoned, LinkOption.NOFOLLOW_LINKS))
        }
    }

    @Test
    fun cleanupDeletesOnlyFixedRecognizableSecureAbandonedTemporaries() {
        val fixture = temporaryRepository()
        val file = EligibilityFile(fixture.paths)
        file.list()
        val recognized = fixture.paths.users.resolveSibling(
            "users.tmp-${UUID.randomUUID()}",
        )
        val unrelated = fixture.paths.users.resolveSibling("users.tmp-not-a-uuid")
        Files.writeString(recognized, "abandoned")
        Files.writeString(unrelated, "unrelated")
        makeOwnerOnly(recognized)
        makeOwnerOnly(unrelated)

        file.list()

        assertFalse(Files.exists(recognized, LinkOption.NOFOLLOW_LINKS))
        assertTrue(Files.isRegularFile(unrelated, LinkOption.NOFOLLOW_LINKS))
    }

    @Test
    fun failureBeforeReplaceLeavesOldTruthAndNextOpenCleansTemporary() {
        val fixture = temporaryRepository()
        EligibilityFile(fixture.paths).add("alpha@local.test", HASH_A)
        val interrupted = EligibilityFile(
            fixture.paths,
            EligibilityFileObserver { point, _, _ ->
                if (point == EligibilityFileCommitPoint.BeforeReplace) {
                    throw SimulatedEligibilityCrash()
                }
            },
        )

        assertFailsWith<SimulatedEligibilityCrash> {
            interrupted.reset("alpha@local.test", HASH_B)
        }
        assertEquals(
            "alpha@local.test:$HASH_A\n",
            Files.readString(fixture.paths.users),
        )
        assertEquals(1, recognizedTemporaries(fixture.paths).size)

        assertEquals(
            listOf("alpha@local.test"),
            EligibilityFile(fixture.paths).list(),
        )
        assertTrue(recognizedTemporaries(fixture.paths).isEmpty())
    }

    @Test
    fun failureAfterReplaceLeavesNewTruth() {
        val fixture = temporaryRepository()
        EligibilityFile(fixture.paths).add("alpha@local.test", HASH_A)
        val interrupted = EligibilityFile(
            fixture.paths,
            EligibilityFileObserver { point, _, _ ->
                if (point == EligibilityFileCommitPoint.AfterReplace) {
                    throw SimulatedEligibilityCrash()
                }
            },
        )

        assertFailsWith<SimulatedEligibilityCrash> {
            interrupted.reset("alpha@local.test", HASH_B)
        }

        assertEquals(
            "alpha@local.test:$HASH_B\n",
            Files.readString(fixture.paths.users),
        )
        assertEquals(
            listOf("alpha@local.test"),
            EligibilityFile(fixture.paths).list(),
        )
    }

    @Test
    fun postWriteVerificationDetectsTargetTamperingBeforeLockRelease() {
        val fixture = temporaryRepository()
        EligibilityFile(fixture.paths).add("alpha@local.test", HASH_A)
        val tampered = EligibilityFile(
            fixture.paths,
            EligibilityFileObserver { point, target, _ ->
                if (point == EligibilityFileCommitPoint.BeforePostWriteVerification) {
                    Files.writeString(target, "tampered")
                }
            },
        )

        assertFailsWith<IllegalStateException> {
            tampered.reset("alpha@local.test", HASH_B)
        }
    }

    @Test
    fun stableFileChannelLockSerializesProcessesThroughPostWriteVerification() {
        val fixture = temporaryRepository()
        val ready = fixture.repositoryRoot.resolve("worker-a.ready")
        val release = fixture.repositoryRoot.resolve("worker-a.release")
        val first = startWorker(
            fixture = fixture,
            address = "alpha@local.test",
            ready = ready,
            release = release,
        )
        try {
            awaitPath(ready)
            val secondReady = fixture.repositoryRoot.resolve("worker-b.ready")
            val second = startWorker(
                fixture = fixture,
                address = "beta@local.test",
                ready = secondReady,
            )
            try {
                awaitPath(secondReady)
                Thread.sleep(400)
                assertTrue(
                    second.isAlive,
                    "the second process must block on the stable OS-visible lock",
                )
                Files.writeString(release, "release")
                assertTrue(first.waitFor(10, TimeUnit.SECONDS))
                assertTrue(second.waitFor(10, TimeUnit.SECONDS))
                assertEquals(0, first.exitValue())
                assertEquals(0, second.exitValue())
            } finally {
                second.destroyForcibly()
            }
        } finally {
            first.destroyForcibly()
        }

        assertEquals(
            listOf("alpha@local.test", "beta@local.test"),
            EligibilityFile(fixture.paths).list(),
        )
    }

    @Test
    fun fixedHasherUsesNoShellExactArgvTwiceOverStdinAndClearsBuffers() {
        val fixture = temporaryRepository()
        val passwordBytes = "new-one-time-password".toByteArray(StandardCharsets.UTF_8)
        val processStdout = "$HASH_A\n".toByteArray(StandardCharsets.US_ASCII)
        val processStderr = "Enter new password: Retype new password:"
            .toByteArray(StandardCharsets.US_ASCII)
        var requestRef: EligibilityProcessRequest? = null
        val runner = EligibilityProcessRunner { request ->
            requestRef = request
            assertEquals(
                listOf(
                    "docker",
                    "compose",
                    "exec",
                    "-T",
                    "dovecot",
                    "doveadm",
                    "pw",
                    "-s",
                    "ARGON2ID",
                ),
                request.argv,
            )
            assertEquals(fixture.repositoryRoot, request.workingDirectory)
            assertEquals(Duration.ofSeconds(30), request.timeout)
            assertEquals(16 * 1024, request.maximumOutputBytes)
            assertContentEquals(
                "new-one-time-password\nnew-one-time-password\n"
                    .toByteArray(StandardCharsets.UTF_8),
                request.stdin,
            )
            EligibilityProcessResult(
                exitCode = 0,
                timedOut = false,
                stdout = processStdout,
                stderr = processStderr,
            )
        }
        val secret = EligibilityPassword.takeOwnership(passwordBytes)

        val hash = DovecotPasswordHasher(fixture.repositoryRoot, runner).hash(secret)
        secret.close()

        assertEquals(HASH_A, hash)
        assertTrue(passwordBytes.all { it == 0.toByte() })
        assertTrue(requireNotNull(requestRef).stdin.all { it == 0.toByte() })
        assertTrue(processStdout.all { it == 0.toByte() })
        assertTrue(processStderr.all { it == 0.toByte() })
        assertFalse(requireNotNull(requestRef).toString().contains("new-one-time-password"))
    }

    @Test
    fun fixedHasherRejectsMalformedFailedTimedOutAndOversizedResultsWithoutLeaks() {
        val secretCanary = "secret-canary"
        listOf(
            EligibilityProcessResult(
                exitCode = 0,
                timedOut = false,
                stdout = "{PLAIN}$secretCanary\n".toByteArray(),
                stderr = ByteArray(0),
            ),
            EligibilityProcessResult(
                exitCode = 1,
                timedOut = false,
                stdout = "$HASH_A\n".toByteArray(),
                stderr = secretCanary.toByteArray(),
            ),
            EligibilityProcessResult(
                exitCode = null,
                timedOut = true,
                stdout = ByteArray(0),
                stderr = ByteArray(0),
            ),
            EligibilityProcessResult(
                exitCode = 0,
                timedOut = false,
                stdout = ByteArray(16 * 1024 + 1) { 'a'.code.toByte() },
                stderr = ByteArray(0),
            ),
        ).forEach { result ->
            val passwordBytes = secretCanary.toByteArray()
            val secret = EligibilityPassword.takeOwnership(passwordBytes)
            val failure = assertFailsWith<IllegalStateException> {
                DovecotPasswordHasher(
                    temporaryRepository().repositoryRoot,
                    EligibilityProcessRunner { result },
                ).hash(secret)
            }
            secret.close()
            assertFalse(failure.message.orEmpty().contains(secretCanary))
            assertTrue(passwordBytes.all { it == 0.toByte() })
            assertTrue(result.stdout.all { it == 0.toByte() })
            assertTrue(result.stderr.all { it == 0.toByte() })
        }
    }

    @Test
    fun boundedProcessOutputCaptureWipesItsBackingAndLocalStorage() {
        val output = "provider-output".toByteArray(StandardCharsets.US_ASCII)
        lateinit var successfulBacking: ByteArray
        lateinit var successfulLocal: ByteArray
        val successfulCapture = EligibilityProcessOutputCapture(
            maximumBytes = 64,
            backingFactory = { size ->
                ByteArray(size).also { successfulBacking = it }
            },
            localBufferFactory = { size ->
                ByteArray(size).also { successfulLocal = it }
            },
        )
        val collected = successfulCapture.use { capture ->
            capture.readFrom(ByteArrayInputStream(output))
            capture.snapshot()
        }

        assertContentEquals(output, collected)
        assertTrue(successfulBacking.all { it == 0.toByte() })
        assertTrue(successfulLocal.all { it == 0.toByte() })
        collected.fill(0)
        output.fill(0)

        val canary = "unexpected-secret-output"
        lateinit var failedBacking: ByteArray
        lateinit var failedLocal: ByteArray
        val failedCapture = EligibilityProcessOutputCapture(
            maximumBytes = 4,
            backingFactory = { size ->
                ByteArray(size).also { failedBacking = it }
            },
            localBufferFactory = { size ->
                ByteArray(size).also { failedLocal = it }
            },
        )
        val failure = assertFailsWith<IllegalStateException> {
            failedCapture.use { capture ->
                capture.readFrom(ByteArrayInputStream(canary.toByteArray()))
            }
        }
        assertFalse(failure.message.orEmpty().contains(canary))
        assertTrue(failedBacking.all { it == 0.toByte() })
        assertTrue(failedLocal.all { it == 0.toByte() })
    }

    @Test
    fun processRunnerWipesClosedCaptureWhenReaderCompletesAfterCleanup() {
        val fixture = temporaryRepository()
        val canaryText = "late-reader-canary"
        val canary = canaryText.toByteArray(StandardCharsets.US_ASCII)
        val readStarted = CountDownLatch(1)
        val releaseRead = CountDownLatch(1)
        val readReturned = CountDownLatch(1)
        val lateStdout = LateCompletingInputStream(
            content = canary,
            readStarted = readStarted,
            releaseRead = releaseRead,
            readReturned = readReturned,
        )
        val process = LateCompletingOutputProcess(lateStdout, readStarted, canaryText)
        val backingBuffers = Collections.synchronizedList(mutableListOf<ByteArray>())
        val localBuffers = Collections.synchronizedList(mutableListOf<ByteArray>())
        val runner = JvmEligibilityProcessRunner(
            processFactory = { process },
            captureFactory = { maximumBytes ->
                EligibilityProcessOutputCapture(
                    maximumBytes = maximumBytes,
                    backingFactory = { size ->
                        ByteArray(size).also(backingBuffers::add)
                    },
                    localBufferFactory = { size ->
                        ByteArray(size).also(localBuffers::add)
                    },
                )
            },
        )
        val requestInput = "runner-input".toByteArray(StandardCharsets.US_ASCII)

        val failure = assertFailsWith<IllegalStateException> {
            runner.run(
                EligibilityProcessRequest(
                    argv = listOf(
                        "docker",
                        "compose",
                        "exec",
                        "-T",
                        "dovecot",
                        "doveadm",
                        "pw",
                        "-s",
                        "ARGON2ID",
                    ),
                    workingDirectory = fixture.repositoryRoot,
                    stdin = requestInput,
                    timeout = Duration.ofSeconds(1),
                    maximumOutputBytes = 64,
                ),
            )
        }

        assertTrue(process.destroyed)
        assertTrue(lateStdout.closed)
        assertFalse(failure.stackTraceToString().contains(canaryText))
        assertTrue(backingBuffers.isNotEmpty())
        assertTrue(backingBuffers.all { buffer -> buffer.isWiped() })

        releaseRead.countDown()
        assertTrue(readReturned.await(5, TimeUnit.SECONDS))
        awaitBuffersWiped(localBuffers)

        assertTrue(localBuffers.isNotEmpty())
        assertTrue(localBuffers.all { buffer -> buffer.isWiped() })
        assertTrue(backingBuffers.all { buffer -> buffer.isWiped() })
        requestInput.fill(0)
        canary.fill(0)
    }

    @Test
    fun cliSupportsOnlyFixedCommandsAndNeverAcceptsPathOrServiceOverrides() {
        val fixture = temporaryRepository()
        val cli = EligibilityFileCli(
            pathsProvider = { fixture.paths },
            hasherFactory = {
                EligibilityPasswordHasher { HASH_A }
            },
        )
        listOf(
            emptyArray(),
            arrayOf("add"),
            arrayOf("add", "alpha@local.test", "--path", "/tmp/users"),
            arrayOf("list", "--path", "/tmp/users"),
            arrayOf("seed", "--service", "other"),
            arrayOf("reset", "alpha@local.test", "--command", "id"),
            arrayOf("remove", "alpha@local.test", "extra"),
            arrayOf("--root", fixture.repositoryRoot.toString(), "list"),
            arrayOf("unknown"),
        ).forEach { args ->
            val stdout = ByteArrayOutputStream()
            val stderr = ByteArrayOutputStream()
            val exitCode = cli.execute(
                args = args,
                stdin = ByteArrayInputStream(ByteArray(0)),
                stdout = PrintStream(stdout, true, StandardCharsets.UTF_8),
                stderr = PrintStream(stderr, true, StandardCharsets.UTF_8),
            )
            assertNotEquals(0, exitCode)
            assertEquals("", stdout.toString(StandardCharsets.UTF_8))
        }
    }

    @Test
    fun seedUsesOnlyFixedAddressInventoryHashesWithFakeBoundaryAndRefusesOverwrite() {
        val fixture = temporaryRepository(
            seed = "alpha@local.test\nbeta@local.test\n",
        )
        val observedPasswords = mutableListOf<ByteArray>()
        val observedSecretObjects = mutableListOf<EligibilityPassword>()
        var invocation = 0
        val cli = EligibilityFileCli(
            pathsProvider = { fixture.paths },
            hasherFactory = {
                EligibilityPasswordHasher { password ->
                    observedSecretObjects += password
                    password.withBytes { observedPasswords += it.copyOf() }
                    invocation += 1
                    if (invocation == 1) HASH_A else HASH_B
                }
            },
        )
        val secretCanary = "new-seed-secret"
        val stdout = ByteArrayOutputStream()
        val stderr = ByteArrayOutputStream()

        val exitCode = cli.execute(
            args = arrayOf("seed"),
            stdin = ByteArrayInputStream("$secretCanary\n".toByteArray()),
            stdout = PrintStream(stdout, true, StandardCharsets.UTF_8),
            stderr = PrintStream(stderr, true, StandardCharsets.UTF_8),
        )

        assertEquals(0, exitCode)
        assertEquals("", stdout.toString(StandardCharsets.UTF_8))
        assertEquals("", stderr.toString(StandardCharsets.UTF_8))
        assertEquals(2, invocation)
        observedPasswords.forEach {
            assertContentEquals(secretCanary.toByteArray(), it)
            it.fill(0)
        }
        observedSecretObjects.forEach { secret ->
            assertFailsWith<IllegalStateException> {
                secret.withBytes { }
            }
        }
        assertEquals(
            "alpha@local.test:$HASH_A\nbeta@local.test:$HASH_B\n",
            Files.readString(fixture.paths.users),
        )
        assertFalse(Files.readString(fixture.paths.users).contains(secretCanary))

        val secondExit = cli.execute(
            args = arrayOf("seed"),
            stdin = ByteArrayInputStream("different-secret\n".toByteArray()),
            stdout = PrintStream(ByteArrayOutputStream()),
            stderr = PrintStream(ByteArrayOutputStream()),
        )
        assertNotEquals(0, secondExit)
        assertEquals(2, invocation)
    }

    @Test
    fun listPrintsSafeCanonicalAddressesOnly() {
        val fixture = temporaryRepository()
        EligibilityFile(fixture.paths).add("alpha@local.test", HASH_A)
        EligibilityFile(fixture.paths).add("beta@local.test", HASH_B)
        val stdout = ByteArrayOutputStream()
        val stderr = ByteArrayOutputStream()
        val exit = EligibilityFileCli(
            pathsProvider = { fixture.paths },
            hasherFactory = {
                error("list must not invoke the password hasher")
            },
        ).execute(
            args = arrayOf("list"),
            stdin = ByteArrayInputStream(ByteArray(0)),
            stdout = PrintStream(stdout, true, StandardCharsets.UTF_8),
            stderr = PrintStream(stderr, true, StandardCharsets.UTF_8),
        )

        assertEquals(0, exit)
        assertEquals(
            "alpha@local.test\nbeta@local.test\n",
            stdout.toString(StandardCharsets.UTF_8),
        )
        assertEquals("", stderr.toString(StandardCharsets.UTF_8))
        assertFalse(stdout.toString(StandardCharsets.UTF_8).contains("{ARGON2ID}"))
    }

    private fun temporaryRepository(
        seed: String = "",
    ): EligibilityFixture {
        val repositoryRoot = Files.createTempDirectory("eligibility-repository-")
            .toRealPath()
        val dashboardRoot = repositoryRoot.resolve("debug-dashboard")
        val config = repositoryRoot.resolve("config")
        dashboardRoot.createDirectories()
        config.createDirectories()
        repositoryRoot.resolve("docker-compose.yml").writeText("services: {}\n")
        dashboardRoot.resolve("project.yaml").writeText("modules: []\n")
        config.resolve("users.seed").writeText(seed)
        val paths = EligibilityPaths.testing(repositoryRoot)
        return EligibilityFixture(repositoryRoot, dashboardRoot, paths)
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

    private fun recognizedTemporaries(paths: EligibilityPaths): List<Path> {
        if (!Files.isDirectory(paths.dovecotDirectory, LinkOption.NOFOLLOW_LINKS)) {
            return emptyList()
        }
        val prefix = "users.tmp-"
        return Files.list(paths.dovecotDirectory).use { entries ->
            entries.filter { candidate ->
                val name = candidate.fileName.toString()
                if (!name.startsWith(prefix)) {
                    false
                } else {
                    runCatching {
                        UUID.fromString(name.removePrefix(prefix)).toString() ==
                            name.removePrefix(prefix)
                    }.getOrDefault(false)
                }
            }.toList()
        }
    }

    private fun startWorker(
        fixture: EligibilityFixture,
        address: String,
        ready: Path? = null,
        release: Path? = null,
    ): Process {
        val java = Path.of(
            System.getProperty("java.home"),
            "bin",
            if (System.getProperty("os.name").startsWith("Windows")) "java.exe" else "java",
        )
        val command = mutableListOf(
            java.toString(),
            "-cp",
            System.getProperty("java.class.path"),
            EligibilityFileProcessWorker::class.java.name,
            fixture.repositoryRoot.toString(),
            address,
            ready?.toString() ?: "-",
            release?.toString() ?: "-",
        )
        return ProcessBuilder(command)
            .redirectOutput(ProcessBuilder.Redirect.DISCARD)
            .redirectError(ProcessBuilder.Redirect.DISCARD)
            .start()
    }

    private fun awaitPath(path: Path) {
        val deadline = System.nanoTime() + Duration.ofSeconds(10).toNanos()
        while (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
            check(System.nanoTime() < deadline) {
                "timed out waiting for worker synchronization"
            }
            Thread.sleep(20)
        }
    }

    private fun awaitBuffersWiped(buffers: List<ByteArray>) {
        val deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos()
        while (buffers.any { buffer -> !buffer.isWiped() }) {
            check(System.nanoTime() < deadline) {
                "timed out waiting for process-output buffers to be wiped"
            }
            Thread.sleep(10)
        }
    }

    private fun ByteArray.isWiped(): Boolean = all { byte -> byte == 0.toByte() }

    private fun makeOwnerOnly(path: Path) {
        if (supportsPosix(path)) {
            Files.setPosixFilePermissions(
                path,
                PosixFilePermissions.fromString("rw-------"),
            )
        } else {
            path.toFile().setReadable(false, false)
            path.toFile().setWritable(false, false)
            path.toFile().setExecutable(false, false)
            path.toFile().setReadable(true, true)
            path.toFile().setWritable(true, true)
        }
    }

    private fun supportsPosix(path: Path): Boolean =
        path.fileSystem.supportedFileAttributeViews().contains("posix")

    private fun supportsSymbolicLinks(): Boolean {
        val root = Files.createTempDirectory("eligibility-symlink-probe-")
        return try {
            val target = Files.createFile(root.resolve("target"))
            val link = root.resolve("link")
            Files.createSymbolicLink(link, target)
            Files.isSymbolicLink(link)
        } catch (_: UnsupportedOperationException) {
            false
        } catch (_: SecurityException) {
            false
        }
    }

    private data class EligibilityFixture(
        val repositoryRoot: Path,
        val dashboardRoot: Path,
        val paths: EligibilityPaths,
    )

    private class LateCompletingInputStream(
        private val content: ByteArray,
        private val readStarted: CountDownLatch,
        private val releaseRead: CountDownLatch,
        private val readReturned: CountDownLatch,
    ) : InputStream() {
        @Volatile
        var closed: Boolean = false
            private set

        private var emitted = false

        override fun read(): Int {
            val oneByte = ByteArray(1)
            return try {
                val count = read(oneByte, 0, 1)
                if (count < 0) -1 else oneByte[0].toInt() and 0xff
            } finally {
                oneByte.fill(0)
            }
        }

        override fun read(
            target: ByteArray,
            offset: Int,
            length: Int,
        ): Int {
            if (emitted) return -1
            require(length >= content.size)
            content.copyInto(target, destinationOffset = offset)
            readStarted.countDown()
            while (true) {
                try {
                    if (releaseRead.await(20, TimeUnit.MILLISECONDS)) break
                } catch (_: InterruptedException) {
                    // Deliberately complete after runner cancellation to exercise late cleanup.
                }
            }
            emitted = true
            readReturned.countDown()
            return content.size
        }

        override fun close() {
            closed = true
        }
    }

    private class LateCompletingOutputProcess(
        private val stdout: LateCompletingInputStream,
        private val readStarted: CountDownLatch,
        private val exceptionCanary: String,
    ) : Process() {
        @Volatile
        private var alive = true

        @Volatile
        var destroyed: Boolean = false
            private set

        private val stdin = object : OutputStream() {
            override fun write(byte: Int) {
                write(byteArrayOf(byte.toByte()), 0, 1)
            }

            override fun write(
                source: ByteArray,
                offset: Int,
                length: Int,
            ) {
                check(readStarted.await(5, TimeUnit.SECONDS)) {
                    "late stdout reader did not start"
                }
                throw IOException(exceptionCanary)
            }
        }

        override fun getOutputStream(): OutputStream = stdin

        override fun getInputStream(): InputStream = stdout

        override fun getErrorStream(): InputStream = ByteArrayInputStream(ByteArray(0))

        override fun waitFor(): Int {
            while (alive) {
                Thread.sleep(10)
            }
            return 1
        }

        override fun waitFor(
            timeout: Long,
            unit: TimeUnit,
        ): Boolean = !alive

        override fun exitValue(): Int {
            check(!alive) { "process is still running" }
            return 1
        }

        override fun destroy() {
            destroyForcibly()
        }

        override fun destroyForcibly(): Process {
            destroyed = true
            alive = false
            stdout.close()
            return this
        }

        override fun isAlive(): Boolean = alive
    }

    private class SimulatedEligibilityCrash : RuntimeException()

    companion object {
        private const val HASH_A =
            "{ARGON2ID}\$argon2id\$v=19\$m=65536,t=3,p=1\$c2FsdEE\$aGFzaEE"
        private const val HASH_B =
            "{ARGON2ID}\$argon2id\$v=19\$m=65536,t=3,p=1\$c2FsdEI\$aGFzaEI"
        private const val HASH_C =
            "{ARGON2ID}\$argon2id\$v=19\$m=65536,t=3,p=1\$c2FsdEM\$aGFzaEM"
    }
}

object EligibilityFileProcessWorker {
    @JvmStatic
    fun main(args: Array<String>) {
        require(args.size == 4)
        val repositoryRoot = Path.of(args[0])
        val address = EligibilityAddress.requireCanonical(args[1])
        val ready = args[2].takeUnless { it == "-" }?.let(Path::of)
        val release = args[3].takeUnless { it == "-" }?.let(Path::of)
        val file = EligibilityFile(
            EligibilityPaths.testing(repositoryRoot),
            EligibilityFileObserver { point, _, _ ->
                if (
                    ready != null &&
                    release != null &&
                    point == EligibilityFileCommitPoint.PostWriteVerified
                ) {
                    Files.writeString(ready, "ready")
                    val deadline = System.nanoTime() + Duration.ofSeconds(10).toNanos()
                    while (!Files.exists(release, LinkOption.NOFOLLOW_LINKS)) {
                        check(System.nanoTime() < deadline)
                        Thread.sleep(20)
                    }
                }
            },
        )
        if (ready != null && release == null) {
            Files.writeString(ready, "attempting-mutation")
        }
        val hash = if (address.startsWith("alpha")) {
            "{ARGON2ID}\$argon2id\$v=19\$m=65536,t=3,p=1\$YQ\$YQ"
        } else {
            "{ARGON2ID}\$argon2id\$v=19\$m=65536,t=3,p=1\$Yg\$Yg"
        }
        file.add(address, hash)
    }
}
