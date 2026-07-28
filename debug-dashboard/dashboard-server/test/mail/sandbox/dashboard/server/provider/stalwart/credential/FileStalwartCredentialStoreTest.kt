package mail.sandbox.dashboard.server.provider.stalwart.credential

import java.io.ByteArrayOutputStream
import java.io.PrintStream
import java.lang.reflect.Modifier
import java.nio.ByteBuffer
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermission
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.streams.toList

class FileStalwartCredentialStoreTest {
    @Test
    fun productionPathsAreFixedAndFirstStartCreatesAnOwnerOnlyEmptyStore() {
        withRoot { dashboardRoot ->
            Files.writeString(dashboardRoot.resolve("project.yaml"), "modules: []\n")
            setOwnerOnlyFile(dashboardRoot.resolve("project.yaml"))
            val canonicalRoot = dashboardRoot.toRealPath()
            val paths = CredentialStorePaths.production(dashboardRoot)
            assertEquals(
                canonicalRoot.resolve(".runtime/stalwart/app-passwords.v1.enc"),
                paths.ciphertext,
            )
            assertEquals(
                canonicalRoot.resolve(".runtime/keys/stalwart-app-passwords.v1.key"),
                paths.key,
            )
            assertEquals(
                canonicalRoot.resolve(".runtime/stalwart/app-passwords.v1.lock"),
                paths.lock,
            )

            FileStalwartCredentialStore(paths).use { store ->
                val available = assertIs<CredentialStoreLoadResult.Available>(store.load())
                available.snapshot.use { snapshot ->
                    assertEquals(0L, snapshot.revision)
                    assertTrue(snapshot.records.isEmpty())
                    assertNotEquals(UUID(0, 0), snapshot.storeId)
                }
            }

            assertEquals(32L, Files.size(paths.key))
            assertTrue(Files.size(paths.ciphertext) > ENVELOPE_HEADER_SIZE)
            listOf(paths.runtimeRoot, paths.ciphertext.parent, paths.key.parent).forEach {
                assertOwnerOnlyDirectory(it)
            }
            listOf(paths.key, paths.ciphertext, paths.lock).forEach {
                assertOwnerOnlyFile(it)
            }
        }
    }

    @Test
    fun productionPathsRejectAProjectRootReachedThroughASymbolicAncestor() {
        withRoot { root ->
            val realParent = root.resolve("real-parent")
            val projectRoot = realParent.resolve("debug-dashboard")
            Files.createDirectories(projectRoot)
            setOwnerOnlyDirectory(realParent)
            setOwnerOnlyDirectory(projectRoot)
            Files.writeString(projectRoot.resolve("project.yaml"), "modules: []\n")
            val symbolicParent = root.resolve("symbolic-parent")
            Files.createSymbolicLink(symbolicParent, realParent.fileName)

            assertFailsWith<IllegalArgumentException> {
                CredentialStorePaths.production(
                    symbolicParent.resolve("debug-dashboard"),
                )
            }
            assertTrue(Files.isSymbolicLink(symbolicParent))
            assertFalse(Files.exists(projectRoot.resolve(".runtime")))
        }
    }

    @Test
    fun validFilesDecryptTheExactSnapshotAndUseFreshHeaderNonces() {
        withStore { paths, store ->
            val activeOwned = SECRET_ACTIVE.copyOf()
            val otherOwned = SECRET_OTHER.copyOf()
            val firstRecord = record(
                accountId = "account-immutable-1",
                address = "first@local.test",
                active = generation(7, activeOwned),
                other = generation(8, otherOwned),
                phase = CredentialPhase.Staged,
            )

            assertIs<CredentialStoreWriteResult.Written>(
                store.replace(
                    expectedRevision = 0,
                    records = mapOf(firstRecord.accountId to firstRecord),
                ),
            )
            val firstEnvelope = Files.readAllBytes(paths.ciphertext)
            assertContentEquals(ENVELOPE_MAGIC, firstEnvelope.copyOfRange(0, 8))
            assertEquals(1, firstEnvelope[8].toInt())

            val loaded = assertIs<CredentialStoreLoadResult.Available>(store.load())
            loaded.snapshot.use { snapshot ->
                assertEquals(1L, snapshot.revision)
                assertEquals(setOf("account-immutable-1"), snapshot.records.keys)
                assertRecord(
                    snapshot.records.getValue("account-immutable-1"),
                    expectedAddress = "first@local.test",
                    expectedPhase = CredentialPhase.Staged,
                    expectedActive = SECRET_ACTIVE,
                    expectedOther = SECRET_OTHER,
                )
            }

            val secondRecord = record(
                accountId = "account-immutable-1",
                address = "first@local.test",
                active = generation(8, SECRET_OTHER.copyOf()),
                other = generation(7, SECRET_ACTIVE.copyOf()),
                phase = CredentialPhase.Retiring,
            )
            assertIs<CredentialStoreWriteResult.Written>(
                store.replace(1, mapOf(secondRecord.accountId to secondRecord)),
            )
            val secondEnvelope = Files.readAllBytes(paths.ciphertext)
            assertContentEquals(
                firstEnvelope.copyOfRange(STORE_ID_OFFSET, NONCE_OFFSET),
                secondEnvelope.copyOfRange(STORE_ID_OFFSET, NONCE_OFFSET),
            )
            assertFalse(
                firstEnvelope.copyOfRange(NONCE_OFFSET, ENVELOPE_HEADER_SIZE).contentEquals(
                    secondEnvelope.copyOfRange(NONCE_OFFSET, ENVELOPE_HEADER_SIZE),
                ),
            )

            firstRecord.close()
            secondRecord.close()
            assertClearedRedacted(activeOwned)
            assertClearedRedacted(otherOwned)
        }
    }

    @Test
    fun secretBytesOwnAndClearTheirMutableBytesWithoutRevealingDiagnostics() {
        val owned = SECRET_ACTIVE.copyOf()
        val secret = SecretBytes.takeOwnership(owned)
        assertFalse(secret.toString().contains(SECRET_ACTIVE.toString(Charsets.UTF_8)))
        assertSecretEqualsRedacted(SECRET_ACTIVE, secret.copyForUse())

        secret.close()

        assertClearedRedacted(owned)
        val failure = assertFailsWith<IllegalStateException> {
            secret.copyForUse()
        }
        assertFalse(failure.toString().contains(SECRET_ACTIVE.toString(Charsets.UTF_8)))

        val rejectedOwned = SECRET_OTHER.copyOf()
        assertFailsWith<IllegalArgumentException> {
            CredentialGeneration(
                credentialId = "",
                description = "mail-sandbox/debug-dashboard/rejected",
                generation = 1,
                secret = SecretBytes.takeOwnership(rejectedOwned),
            )
        }
        assertClearedRedacted(rejectedOwned)
    }

    @Test
    fun credentialOwnersCannotBeCopiedAndRejectAliasedSecretOwnership() {
        val recordCopy = StalwartCredentialRecord::class.java.declaredMethods
            .single { it.name == "copy" }
        assertTrue(Modifier.isPrivate(recordCopy.modifiers))
        assertFalse(
            CredentialGeneration::class.java.declaredMethods.any { it.name == "copy" },
        )
        assertFalse(
            StalwartCredentialSnapshot::class.java.declaredMethods.any { it.name == "copy" },
        )

        val aliasedBytes = SECRET_ACTIVE.copyOf()
        val aliasedSecret = SecretBytes.takeOwnership(aliasedBytes)
        val active = CredentialGeneration(
            credentialId = "credential-active",
            description = "mail-sandbox/debug-dashboard/store/active",
            generation = 1,
            secret = aliasedSecret,
        )
        assertFailsWith<IllegalArgumentException> {
            CredentialGeneration(
                credentialId = "credential-other",
                description = "mail-sandbox/debug-dashboard/store/other",
                generation = 2,
                secret = aliasedSecret,
            )
        }
        assertSecretEqualsRedacted(SECRET_ACTIVE, active.secret.copyForUse())

        val firstRecord = record(
            accountId = "account",
            address = "account@local.test",
            active = active,
        )
        assertFailsWith<IllegalArgumentException> {
            StalwartCredentialRecord.takeOwnership(
                accountId = "other-account",
                addressAtCapture = "other@local.test",
                phase = CredentialPhase.Active,
                active = active,
                other = null,
            )
        }
        assertSecretEqualsRedacted(SECRET_ACTIVE, active.secret.copyForUse())
        firstRecord.close()
        assertClearedRedacted(aliasedBytes)
    }

    @Test
    fun everyDurablePhaseRequiresTheExactOwnedGenerationShape() {
        val activeWithoutGeneration = assertFailsWith<IllegalArgumentException> {
            StalwartCredentialRecord.takeOwnership(
                accountId = "account",
                addressAtCapture = "account@local.test",
                phase = CredentialPhase.Active,
                active = null,
                other = null,
            )
        }
        assertTrue(
            activeWithoutGeneration.message.orEmpty().contains("active", ignoreCase = true),
        )
        val removalWithoutActive = assertFailsWith<IllegalArgumentException> {
            StalwartCredentialRecord.takeOwnership(
                accountId = "account",
                addressAtCapture = "account@local.test",
                phase = CredentialPhase.RemovalPending,
                active = null,
                other = null,
            )
        }
        assertTrue(removalWithoutActive.message.orEmpty().contains("active", ignoreCase = true))

        listOf(CredentialPhase.Staged, CredentialPhase.Retiring).forEach { phase ->
            val active = generation(1, byteArrayOf(1))
            assertFailsWith<IllegalArgumentException> {
                StalwartCredentialRecord.takeOwnership(
                    accountId = "account",
                    addressAtCapture = "account@local.test",
                    phase = phase,
                    active = active,
                    other = null,
                )
            }
            assertFailsWith<IllegalStateException> { active.secret.copyForUse() }
        }
        val active = generation(1, byteArrayOf(1))
        val other = generation(2, byteArrayOf(2))
        assertFailsWith<IllegalArgumentException> {
            StalwartCredentialRecord.takeOwnership(
                accountId = "account",
                addressAtCapture = "account@local.test",
                phase = CredentialPhase.Active,
                active = active,
                other = other,
            )
        }
        assertFailsWith<IllegalStateException> { active.secret.copyForUse() }
        assertFailsWith<IllegalStateException> { other.secret.copyForUse() }
    }

    @Test
    fun firstStartHardLinkPublicationNeverOverwritesARacingTarget() {
        withRoot { root ->
            val paths = CredentialStorePaths.testing(root.resolve("runtime"))
            val sentinel = ByteArray(32) { 0x5a.toByte() }
            val store = FileStalwartCredentialStore(
                paths = paths,
                commitObserver = CredentialStoreCommitObserver { point, target ->
                    if (
                        point == CredentialStoreCommitPoint.BeforeFailIfExistsPublish &&
                        target == paths.key
                    ) {
                        Files.write(target, sentinel)
                        setOwnerOnlyFile(target)
                    }
                },
            )
            store.use {
                assertIs<CredentialStoreLoadResult.StoreUnavailable>(it.load())
            }
            assertBytesEqualRedacted(
                sentinel,
                Files.readAllBytes(paths.key),
                "racing initialization target",
            )
            assertFalse(Files.exists(paths.ciphertext, LinkOption.NOFOLLOW_LINKS))
        }
    }

    @Test
    fun loneFilesWrongKeysAndAuthenticatedCorruptionAreUnavailableAndUntouched() {
        val mutations = listOf<Pair<String, (CredentialStorePaths) -> Unit>>(
            "lone key" to { Files.delete(it.ciphertext) },
            "lone ciphertext" to { Files.delete(it.key) },
            "wrong key" to {
                Files.write(it.key, ByteArray(32).also(SecureRandom()::nextBytes))
            },
            "authentication tag" to {
                mutate(it.ciphertext) { bytes -> bytes[lastIndex(bytes)] =
                    (bytes[lastIndex(bytes)].toInt() xor 0x40).toByte()
                }
            },
            "header magic" to {
                mutate(it.ciphertext) { bytes -> bytes[0] = (bytes[0].toInt() xor 1).toByte() }
            },
            "unsupported version" to {
                mutate(it.ciphertext) { bytes -> bytes[8] = 2 }
            },
            "header identity binding" to {
                val original = Files.readAllBytes(it.ciphertext)
                mutate(it.ciphertext) { bytes ->
                    UUID.randomUUID().let { replacement ->
                        ByteBuffer.wrap(bytes, STORE_ID_OFFSET, 16)
                            .putLong(replacement.mostSignificantBits)
                            .putLong(replacement.leastSignificantBits)
                    }
                    assertFalse(original.contentEquals(bytes))
                }
            },
            "malformed truncated header" to {
                Files.write(it.ciphertext, ByteArray(ENVELOPE_HEADER_SIZE - 1))
            },
        )

        mutations.forEach { (label, mutateStore) ->
            withStore { paths, store ->
                store.close()
                mutateStore(paths)
                val before = captureExistingRegularBytes(paths)

                FileStalwartCredentialStore(paths).use { reopened ->
                    assertIs<CredentialStoreLoadResult.StoreUnavailable>(
                        reopened.load(),
                        label,
                    )
                }

                assertExistingRegularBytesUnchanged(before, label)
            }
        }
    }

    @Test
    fun authenticatedMalformedPayloadsAreUnavailableAndNeverRewritten() {
        withStore { paths, store ->
            val first = record(
                "account-aaa",
                "first@local.test",
                generation(1, byteArrayOf(1)),
            )
            val second = record(
                "account-bbb",
                "second@local.test",
                generation(2, byteArrayOf(2)),
            )
            assertIs<CredentialStoreWriteResult.Written>(
                store.replace(
                    0,
                    mapOf(first.accountId to first, second.accountId to second),
                ),
            )
            store.close()
            val validEnvelope = Files.readAllBytes(paths.ciphertext)
            val mutations = listOf<Pair<String, (ByteArray) -> ByteArray>>(
                "negative revision" to { payload ->
                    payload.apply { ByteBuffer.wrap(this).putLong(0, -1) }
                },
                "overflow revision" to { payload ->
                    payload.apply { ByteBuffer.wrap(this).putLong(0, Long.MAX_VALUE) }
                },
                "trailing bytes" to { payload -> payload + byteArrayOf(0) },
                "oversized string" to { payload ->
                    payload.apply { ByteBuffer.wrap(this).putInt(12, Int.MAX_VALUE) }
                },
                "unknown phase" to { payload ->
                    payload.apply {
                        this[payloadRecords(this).first().phaseOffset] = 127
                    }
                },
                "invalid phase shape" to { payload ->
                    payload.apply {
                        this[payloadRecords(this).first().phaseOffset] = 1
                    }
                },
                "duplicate Account ID" to { payload ->
                    payload.apply {
                        val records = payloadRecords(this)
                        val firstRange = records[0].accountIdRange
                        val secondRange = records[1].accountIdRange
                        check(firstRange.count() == secondRange.count())
                        copyInto(
                            destination = this,
                            destinationOffset = secondRange.first,
                            startIndex = firstRange.first,
                            endIndex = firstRange.last + 1,
                        )
                    }
                },
            )

            mutations.forEach { (label, mutation) ->
                Files.write(paths.ciphertext, validEnvelope)
                val malformed = authenticatedEnvelope(paths, mutation)
                Files.write(paths.ciphertext, malformed)
                val beforeLoad = Files.readAllBytes(paths.ciphertext)

                FileStalwartCredentialStore(paths).use { reopened ->
                    assertIs<CredentialStoreLoadResult.StoreUnavailable>(
                        reopened.load(),
                        label,
                    )
                }

                assertBytesEqualRedacted(
                    beforeLoad,
                    Files.readAllBytes(paths.ciphertext),
                    label,
                )
                malformed.fill(0)
            }
            first.close()
            second.close()
        }
    }

    @Test
    fun unreadableUnsafeSymbolicAndNonRegularPathsAreUnavailableWithoutMutation() {
        withStore { paths, store ->
            store.close()
            if (supportsPosix(paths.key)) {
                val before = Files.readAllBytes(paths.key)
                Files.setPosixFilePermissions(
                    paths.key,
                    setOf(PosixFilePermission.OWNER_WRITE),
                )
                FileStalwartCredentialStore(paths).use { reopened ->
                    assertIs<CredentialStoreLoadResult.StoreUnavailable>(reopened.load())
                }
                Files.setPosixFilePermissions(
                    paths.key,
                    PosixFilePermissions.fromString("rw-------"),
                )
                assertBytesEqualRedacted(before, Files.readAllBytes(paths.key), "key")
            }
        }

        withStore { paths, store ->
            store.close()
            if (supportsPosix(paths.ciphertext)) {
                Files.setPosixFilePermissions(
                    paths.ciphertext,
                    PosixFilePermissions.fromString("rw-r--r--"),
                )
                val before = Files.readAllBytes(paths.ciphertext)
                FileStalwartCredentialStore(paths).use { reopened ->
                    assertIs<CredentialStoreLoadResult.StoreUnavailable>(reopened.load())
                }
                assertBytesEqualRedacted(
                    before,
                    Files.readAllBytes(paths.ciphertext),
                    "ciphertext",
                )
            }
        }

        withRoot { root ->
            val paths = CredentialStorePaths.testing(root.resolve("runtime"))
            Files.createDirectories(paths.ciphertext)
            FileStalwartCredentialStore(paths).use { store ->
                assertIs<CredentialStoreLoadResult.StoreUnavailable>(store.load())
            }
            assertTrue(Files.isDirectory(paths.ciphertext, LinkOption.NOFOLLOW_LINKS))
        }

        withRoot { root ->
            val realRuntime = root.resolve("real-runtime")
            Files.createDirectories(realRuntime)
            setOwnerOnlyDirectory(realRuntime)
            val symbolicRuntime = root.resolve("runtime-link")
            Files.createSymbolicLink(symbolicRuntime, realRuntime)
            val paths = CredentialStorePaths.testing(symbolicRuntime)
            FileStalwartCredentialStore(paths).use { store ->
                assertIs<CredentialStoreLoadResult.StoreUnavailable>(store.load())
            }
            assertTrue(Files.isSymbolicLink(symbolicRuntime))
            assertTrue(Files.list(realRuntime).use { !it.findAny().isPresent })
        }

        withStore { paths, store ->
            store.close()
            val original = Files.readAllBytes(paths.key)
            val realKey = paths.key.resolveSibling("real-key")
            Files.move(paths.key, realKey)
            Files.createSymbolicLink(paths.key, realKey.fileName)
            FileStalwartCredentialStore(paths).use { reopened ->
                assertIs<CredentialStoreLoadResult.StoreUnavailable>(reopened.load())
            }
            assertTrue(Files.isSymbolicLink(paths.key))
            assertBytesEqualRedacted(original, Files.readAllBytes(realKey), "real key")
        }
    }

    @Test
    fun concurrentWritersSerializeAndRejectTheStaleRevision() {
        withStore { paths, store ->
            val first = record("account-one", "same@local.test", generation(1, byteArrayOf(1)))
            val second = record("account-two", "same@local.test", generation(1, byteArrayOf(2)))
            val start = CountDownLatch(1)
            val executor = Executors.newFixedThreadPool(2)
            val stores = listOf(
                FileStalwartCredentialStore(paths),
                FileStalwartCredentialStore(paths),
            )
            try {
                val futures = listOf(first, second).mapIndexed { index, candidate ->
                    executor.submit<CredentialStoreWriteResult> {
                        check(start.await(10, TimeUnit.SECONDS))
                        stores[index].replace(0, mapOf(candidate.accountId to candidate))
                    }
                }
                start.countDown()
                val results = futures.map { it.get(20, TimeUnit.SECONDS) }
                assertEquals(1, results.count { it is CredentialStoreWriteResult.Written })
                assertEquals(
                    1,
                    results.count { it is CredentialStoreWriteResult.RevisionMismatch },
                )

                val available = assertIs<CredentialStoreLoadResult.Available>(store.load())
                available.snapshot.use { snapshot ->
                    assertEquals(1L, snapshot.revision)
                    assertEquals(1, snapshot.records.size)
                    assertTrue(
                        snapshot.records.keys.single() == "account-one" ||
                            snapshot.records.keys.single() == "account-two",
                    )
                }
            } finally {
                stores.forEach(FileStalwartCredentialStore::close)
                executor.shutdownNow()
                first.close()
                second.close()
            }
        }
    }

    @Test
    fun interruptedReplaceShapesPreserveTheCommittedSnapshotAndCleanAbandonedTemps() {
        withStore { paths, store ->
            val first = record("account-one", "one@local.test", generation(1, byteArrayOf(1)))
            val second = record("account-two", "two@local.test", generation(2, byteArrayOf(2)))
            assertIs<CredentialStoreWriteResult.Written>(
                store.replace(0, mapOf(first.accountId to first)),
            )
            val revisionOne = Files.readAllBytes(paths.ciphertext)
            assertIs<CredentialStoreWriteResult.Written>(
                store.replace(1, mapOf(second.accountId to second)),
            )
            val revisionTwo = Files.readAllBytes(paths.ciphertext)
            store.close()

            val beforeReplaceTemp = abandonedSnapshot(paths, revisionTwo)
            Files.write(paths.ciphertext, revisionOne)
            FileStalwartCredentialStore(paths).use { reopened ->
                val loaded = assertIs<CredentialStoreLoadResult.Available>(reopened.load())
                loaded.snapshot.use { snapshot ->
                    assertEquals(1L, snapshot.revision)
                    assertEquals(setOf("account-one"), snapshot.records.keys)
                }
            }
            assertFalse(Files.exists(beforeReplaceTemp, LinkOption.NOFOLLOW_LINKS))

            val afterReplaceTemp = abandonedSnapshot(paths, revisionOne)
            Files.write(paths.ciphertext, revisionTwo)
            FileStalwartCredentialStore(paths).use { reopened ->
                val loaded = assertIs<CredentialStoreLoadResult.Available>(reopened.load())
                loaded.snapshot.use { snapshot ->
                    assertEquals(2L, snapshot.revision)
                    assertEquals(setOf("account-two"), snapshot.records.keys)
                }
            }
            assertFalse(Files.exists(afterReplaceTemp, LinkOption.NOFOLLOW_LINKS))
            first.close()
            second.close()
        }
    }

    @Test
    fun abandonedCleanupLeavesUnrecognizedSimilarFilesUntouched() {
        withStore { paths, store ->
            store.close()
            val unrelated = paths.ciphertext.resolveSibling(
                "${paths.ciphertext.fileName}.tmp-not-a-generated-store-uuid",
            )
            Files.write(unrelated, byteArrayOf(9, 8, 7))
            setOwnerOnlyFile(unrelated)

            FileStalwartCredentialStore(paths).use { reopened ->
                val loaded = assertIs<CredentialStoreLoadResult.Available>(reopened.load())
                loaded.snapshot.close()
            }

            assertContentEquals(byteArrayOf(9, 8, 7), Files.readAllBytes(unrelated))
        }
    }

    @Test
    fun injectedFaultsProveThePreAndPostReplaceDurabilityBoundaries() {
        withRoot { root ->
            val paths = CredentialStorePaths.testing(root.resolve("runtime"))
            FileStalwartCredentialStore(paths).use { initial ->
                val loaded = assertIs<CredentialStoreLoadResult.Available>(initial.load())
                loaded.snapshot.close()
                val first = record(
                    "account-one",
                    "one@local.test",
                    generation(1, byteArrayOf(1)),
                )
                assertIs<CredentialStoreWriteResult.Written>(
                    initial.replace(0, mapOf(first.accountId to first)),
                )
                first.close()
            }
            val revisionOne = Files.readAllBytes(paths.ciphertext)
            val beforeFault = SimulatedCrash()
            val beforeStore = FileStalwartCredentialStore(
                paths = paths,
                commitObserver = CredentialStoreCommitObserver { point, _ ->
                    if (point == CredentialStoreCommitPoint.BeforeReplace) throw beforeFault
                },
            )
            val second = record(
                "account-two",
                "two@local.test",
                generation(2, byteArrayOf(2)),
            )
            assertEquals(
                beforeFault,
                assertFailsWith<SimulatedCrash> {
                    beforeStore.replace(1, mapOf(second.accountId to second))
                },
            )
            beforeStore.close()
            assertBytesEqualRedacted(
                revisionOne,
                Files.readAllBytes(paths.ciphertext),
                "pre-replace snapshot",
            )
            assertEquals(1, abandonedSnapshots(paths).size)
            FileStalwartCredentialStore(paths).use { reopened ->
                val loaded = assertIs<CredentialStoreLoadResult.Available>(reopened.load())
                loaded.snapshot.use { snapshot ->
                    assertEquals(1L, snapshot.revision)
                    assertEquals(setOf("account-one"), snapshot.records.keys)
                }
            }
            assertTrue(abandonedSnapshots(paths).isEmpty())

            val afterFault = SimulatedCrash()
            val afterStore = FileStalwartCredentialStore(
                paths = paths,
                commitObserver = CredentialStoreCommitObserver { point, _ ->
                    if (point == CredentialStoreCommitPoint.AfterReplace) throw afterFault
                },
            )
            assertEquals(
                afterFault,
                assertFailsWith<SimulatedCrash> {
                    afterStore.replace(1, mapOf(second.accountId to second))
                },
            )
            afterStore.close()
            FileStalwartCredentialStore(paths).use { reopened ->
                val loaded = assertIs<CredentialStoreLoadResult.Available>(reopened.load())
                loaded.snapshot.use { snapshot ->
                    assertEquals(2L, snapshot.revision)
                    assertEquals(setOf("account-two"), snapshot.records.keys)
                }
            }
            second.close()
        }
    }

    @Test
    fun revisionMismatchAndAccountAddressReuseNeverOverwriteOrReattachByAddress() {
        withStore { paths, store ->
            val original = record(
                "deleted-account-id",
                "reused@local.test",
                generation(1, byteArrayOf(1)),
            )
            assertIs<CredentialStoreWriteResult.Written>(
                store.replace(0, mapOf(original.accountId to original)),
            )
            val beforeMismatch = Files.readAllBytes(paths.ciphertext)
            val mismatch = record(
                "other-account-id",
                "other@local.test",
                generation(2, byteArrayOf(2)),
            )
            assertEquals(
                CredentialStoreWriteResult.RevisionMismatch(actualRevision = 1),
                store.replace(0, mapOf(mismatch.accountId to mismatch)),
            )
            assertBytesEqualRedacted(
                beforeMismatch,
                Files.readAllBytes(paths.ciphertext),
                "revision mismatch",
            )

            val replacement = record(
                "new-account-id",
                "reused@local.test",
                generation(3, byteArrayOf(3)),
            )
            assertIs<CredentialStoreWriteResult.Written>(
                store.replace(1, mapOf(replacement.accountId to replacement)),
            )
            val loaded = assertIs<CredentialStoreLoadResult.Available>(store.load())
            loaded.snapshot.use { snapshot ->
                assertNull(snapshot.records["deleted-account-id"])
                assertEquals(
                    "new-account-id",
                    snapshot.records.getValue("new-account-id").accountId,
                )
                assertEquals(
                    "reused@local.test",
                    snapshot.records.getValue("new-account-id").addressAtCapture,
                )
            }
            original.close()
            mismatch.close()
            replacement.close()
        }
    }

    @Test
    fun changingTheAddressCapturedForAnExistingAccountIdRequiresExplicitRemoval() {
        withStore { paths, store ->
            val original = record(
                "immutable-account-id",
                "first@local.test",
                generation(1, byteArrayOf(1)),
            )
            assertIs<CredentialStoreWriteResult.Written>(
                store.replace(0, mapOf(original.accountId to original)),
            )
            val changed = record(
                "immutable-account-id",
                "second@local.test",
                generation(2, byteArrayOf(2)),
            )
            val before = Files.readAllBytes(paths.ciphertext)
            val failure = assertFailsWith<IllegalArgumentException> {
                store.replace(1, mapOf(changed.accountId to changed))
            }
            assertFalse(failure.message.orEmpty().contains("first@local.test"))
            assertFalse(failure.message.orEmpty().contains("second@local.test"))
            assertBytesEqualRedacted(
                before,
                Files.readAllBytes(paths.ciphertext),
                "address change",
            )

            assertIs<CredentialStoreWriteResult.Written>(store.replace(1, emptyMap()))
            assertIs<CredentialStoreWriteResult.Written>(
                store.replace(2, mapOf(changed.accountId to changed)),
            )
            original.close()
            changed.close()
        }
    }

    @Test
    fun invalidOrOverflowingExpectedRevisionsAreRejectedWithoutMutation() {
        withStore { paths, store ->
            val before = Files.readAllBytes(paths.ciphertext)
            listOf(-1L, Long.MAX_VALUE).forEach { invalid ->
                assertFailsWith<IllegalArgumentException> {
                    store.replace(invalid, emptyMap())
                }
                assertBytesEqualRedacted(
                    before,
                    Files.readAllBytes(paths.ciphertext),
                    "invalid revision",
                )
            }
        }
    }

    @Test
    fun theLastDecodableRevisionCannotAdvanceIntoTheReservedOverflowValue() {
        withStore { paths, store ->
            store.close()
            val nearOverflow = authenticatedEnvelope(paths) { payload ->
                payload.apply {
                    ByteBuffer.wrap(this).putLong(0, Long.MAX_VALUE - 1)
                }
            }
            Files.write(paths.ciphertext, nearOverflow)
            val before = Files.readAllBytes(paths.ciphertext)

            FileStalwartCredentialStore(paths).use { reopened ->
                val loaded = assertIs<CredentialStoreLoadResult.Available>(reopened.load())
                loaded.snapshot.use { snapshot ->
                    assertEquals(Long.MAX_VALUE - 1, snapshot.revision)
                }
                assertIs<CredentialStoreWriteResult.StoreUnavailable>(
                    reopened.replace(Long.MAX_VALUE - 1, emptyMap()),
                )
            }

            assertBytesEqualRedacted(
                before,
                Files.readAllBytes(paths.ciphertext),
                "overflow revision",
            )
            nearOverflow.fill(0)
        }
    }

    @Test
    fun plaintextCanaryIsExcludedFromCiphertextNamesExceptionsLogsAndDiagnostics() {
        withStore { paths, store ->
            val canaryText = "app_plaintext_canary_never_emit"
            val canary = canaryText.toByteArray()
            val record = record(
                "account-canary",
                "canary@local.test",
                generation(9, canary.copyOf()),
            )
            val capturedOut = ByteArrayOutputStream()
            val capturedErr = ByteArrayOutputStream()
            val previousOut = System.out
            val previousErr = System.err
            val write: CredentialStoreWriteResult
            try {
                System.setOut(PrintStream(capturedOut))
                System.setErr(PrintStream(capturedErr))
                write = store.replace(0, mapOf(record.accountId to record))
            } finally {
                System.setOut(previousOut)
                System.setErr(previousErr)
            }
            assertIs<CredentialStoreWriteResult.Written>(write)
            assertFalse(Files.readAllBytes(paths.ciphertext).containsSubsequence(canary))
            assertFalse(paths.toString().contains(canaryText))
            assertFalse(record.toString().contains(canaryText))
            assertFalse(write.toString().contains(canaryText))
            assertFalse(capturedOut.toString(Charsets.UTF_8).contains(canaryText))
            assertFalse(capturedErr.toString(Charsets.UTF_8).contains(canaryText))
            record.close()
            val closedFailure = assertFailsWith<IllegalStateException> {
                record.active?.secret?.copyForUse()
            }
            assertFalse(closedFailure.toString().contains(canaryText))
        }
    }

    @Test
    fun secretAssertionFailuresKeepTheComparedBytesOutOfDiagnostics() {
        val canaryText = "app_assertion_diagnostic_canary"
        val failure = assertFailsWith<AssertionError> {
            assertSecretEqualsRedacted(
                expected = byteArrayOf(0),
                actual = canaryText.toByteArray(),
            )
        }

        assertFalse(failure.toString().contains(canaryText))
        assertFalse(failure.message.orEmpty().contains("97, 112, 112"))
    }

    @Test
    fun explicitQuarantineMovesOnlyUnusableMaterialWithoutOverwriteOrDiscard() {
        withStore { paths, store ->
            store.close()
            mutate(paths.ciphertext) { bytes ->
                bytes[lastIndex(bytes)] = (bytes[lastIndex(bytes)].toInt() xor 1).toByte()
            }
            val originalKey = Files.readAllBytes(paths.key)
            val originalCiphertext = Files.readAllBytes(paths.ciphertext)
            Files.createDirectories(paths.quarantine)
            setOwnerOnlyDirectory(paths.quarantine)
            val sentinel = paths.quarantine.resolve("existing-do-not-overwrite")
            Files.write(sentinel, byteArrayOf(4, 5, 6))
            setOwnerOnlyFile(sentinel)

            FileStalwartCredentialStore(paths).use { reopened ->
                assertIs<CredentialStoreLoadResult.StoreUnavailable>(reopened.load())
                val quarantined = assertIs<CredentialStoreQuarantineResult.Quarantined>(
                    reopened.quarantineUnavailable(),
                )
                assertEquals(2, quarantined.files.size)
                assertFalse(Files.exists(paths.key, LinkOption.NOFOLLOW_LINKS))
                assertFalse(Files.exists(paths.ciphertext, LinkOption.NOFOLLOW_LINKS))
                val bytes = quarantined.files.map { Files.readAllBytes(it) }
                assertTrue(bytes.any { it.contentEquals(originalKey) })
                assertTrue(bytes.any { it.contentEquals(originalCiphertext) })
                quarantined.files.forEach {
                    assertEquals(paths.quarantine, it.parent)
                    assertOwnerOnlyFile(it)
                }
            }
            assertContentEquals(byteArrayOf(4, 5, 6), Files.readAllBytes(sentinel))

            FileStalwartCredentialStore(paths).use { fresh ->
                val available = assertIs<CredentialStoreLoadResult.Available>(fresh.load())
                available.snapshot.close()
            }
            assertEquals(3, Files.list(paths.quarantine).use { stream -> stream.count() })
        }

        withStore { _, store ->
            assertIs<CredentialStoreQuarantineResult.StoreAvailable>(
                store.quarantineUnavailable(),
            )
        }
    }

    @Test
    fun quarantineHardLinkPublicationNeverOverwritesARacingDestination() {
        withStore { paths, store ->
            store.close()
            mutate(paths.ciphertext) { bytes ->
                bytes[lastIndex(bytes)] = (bytes[lastIndex(bytes)].toInt() xor 1).toByte()
            }
            val originals = mapOf(
                paths.key to Files.readAllBytes(paths.key),
                paths.ciphertext to Files.readAllBytes(paths.ciphertext),
            )
            val sentinelBytes = byteArrayOf(4, 5, 6)
            lateinit var sentinelPath: Path
            val racingStore = FileStalwartCredentialStore(
                paths = paths,
                commitObserver = CredentialStoreCommitObserver { point, target ->
                    if (point == CredentialStoreCommitPoint.BeforeFailIfExistsPublish) {
                        sentinelPath = target
                        Files.write(target, sentinelBytes)
                        setOwnerOnlyFile(target)
                    }
                },
            )

            racingStore.use {
                assertIs<CredentialStoreQuarantineResult.StoreUnavailable>(
                    it.quarantineUnavailable(),
                )
            }

            originals.forEach { (source, expected) ->
                assertTrue(Files.exists(source, LinkOption.NOFOLLOW_LINKS))
                assertBytesEqualRedacted(
                    expected,
                    Files.readAllBytes(source),
                    "quarantine source after destination collision",
                )
            }
            assertBytesEqualRedacted(
                sentinelBytes,
                Files.readAllBytes(sentinelPath),
                "racing quarantine destination",
            )
            assertEquals(
                listOf(sentinelPath),
                Files.list(paths.quarantine).use { it.sorted().toList() },
            )
        }
    }

    @Test
    fun quarantinePreservesThePublishedDuplicateWhenInterruptedBeforeSourceDeletion() {
        withStore { paths, store ->
            store.close()
            mutate(paths.ciphertext) { bytes ->
                bytes[lastIndex(bytes)] = (bytes[lastIndex(bytes)].toInt() xor 1).toByte()
            }
            lateinit var published: Path
            val crash = SimulatedCrash()
            val interrupted = FileStalwartCredentialStore(
                paths = paths,
                commitObserver = CredentialStoreCommitObserver { point, target ->
                    if (point == CredentialStoreCommitPoint.AfterFailIfExistsPublish) {
                        published = target
                        throw crash
                    }
                },
            )

            interrupted.use {
                val partial =
                    assertIs<CredentialStoreQuarantineResult.PartiallyQuarantined>(
                        it.quarantineUnavailable(),
                    )
                assertEquals(listOf(published), partial.files)
            }

            assertTrue(Files.exists(paths.key, LinkOption.NOFOLLOW_LINKS))
            assertTrue(Files.exists(paths.ciphertext, LinkOption.NOFOLLOW_LINKS))
            assertTrue(
                Files.isSameFile(published, paths.key) ||
                    Files.isSameFile(published, paths.ciphertext),
            )
            assertOwnerOnlyFile(published)
            assertEquals(
                listOf(published),
                Files.list(paths.quarantine).use { it.sorted().toList() },
            )
        }
    }

    @Test
    fun quarantinePreservesEveryByteWhenInterruptedAfterTheFirstSourceDeletion() {
        withStore { paths, store ->
            store.close()
            mutate(paths.ciphertext) { bytes ->
                bytes[lastIndex(bytes)] = (bytes[lastIndex(bytes)].toInt() xor 1).toByte()
            }
            val originals = mapOf(
                paths.key to Files.readAllBytes(paths.key),
                paths.ciphertext to Files.readAllBytes(paths.ciphertext),
            )
            lateinit var published: Path
            val crash = SimulatedCrash()
            val interrupted = FileStalwartCredentialStore(
                paths = paths,
                commitObserver = CredentialStoreCommitObserver { point, target ->
                    if (point == CredentialStoreCommitPoint.AfterQuarantineSourceDelete) {
                        published = target
                        throw crash
                    }
                },
            )

            interrupted.use {
                val partial =
                    assertIs<CredentialStoreQuarantineResult.PartiallyQuarantined>(
                        it.quarantineUnavailable(),
                    )
                assertEquals(listOf(published), partial.files)
            }

            val remainingSources = originals.keys.filter {
                Files.exists(it, LinkOption.NOFOLLOW_LINKS)
            }
            assertEquals(1, remainingSources.size)
            val removedSource = originals.keys.single { it !in remainingSources }
            assertBytesEqualRedacted(
                originals.getValue(removedSource),
                Files.readAllBytes(published),
                "partially quarantined source",
            )
            val remainingSource = remainingSources.single()
            assertBytesEqualRedacted(
                originals.getValue(remainingSource),
                Files.readAllBytes(remainingSource),
                "remaining quarantine source",
            )
            assertOwnerOnlyFile(published)
            assertEquals(
                listOf(published),
                Files.list(paths.quarantine).use { it.sorted().toList() },
            )
        }
    }

    @Test
    fun aRecordMapWhoseKeyDisagreesWithItsImmutableAccountIdIsRejectedBeforeWrite() {
        withStore { paths, store ->
            val record = record(
                "immutable-account-id",
                "account@local.test",
                generation(1, byteArrayOf(1)),
            )
            val before = Files.readAllBytes(paths.ciphertext)
            val failure = assertFailsWith<IllegalArgumentException> {
                store.replace(0, mapOf("different-key" to record))
            }
            assertFalse(failure.message.orEmpty().contains("account@local.test"))
            assertBytesEqualRedacted(
                before,
                Files.readAllBytes(paths.ciphertext),
                "record key mismatch",
            )
            record.close()
        }
    }

    private fun withStore(
        block: (CredentialStorePaths, FileStalwartCredentialStore) -> Unit,
    ) {
        withRoot { root ->
            val paths = CredentialStorePaths.testing(root.resolve("runtime"))
            FileStalwartCredentialStore(paths).use { store ->
                val loaded = assertIs<CredentialStoreLoadResult.Available>(store.load())
                loaded.snapshot.close()
                block(paths, store)
            }
        }
    }

    private fun withRoot(block: (Path) -> Unit) {
        val canonicalTemporaryRoot =
            Path.of(System.getProperty("java.io.tmpdir")).toRealPath()
        val root = createTempDirectory(
            canonicalTemporaryRoot,
            "stalwart-credential-store-test",
        )
        try {
            setOwnerOnlyDirectory(root)
            block(root)
        } finally {
            deleteTree(root)
        }
    }

    private fun record(
        accountId: String,
        address: String,
        active: CredentialGeneration,
        other: CredentialGeneration? = null,
        phase: CredentialPhase = CredentialPhase.Active,
    ): StalwartCredentialRecord = StalwartCredentialRecord.takeOwnership(
        accountId = accountId,
        addressAtCapture = address,
        phase = phase,
        active = active,
        other = other,
    )

    private fun generation(
        number: Long,
        ownedSecret: ByteArray,
    ): CredentialGeneration = CredentialGeneration(
        credentialId = "credential-$number",
        description = "mail-sandbox/debug-dashboard/store/generation-$number",
        generation = number,
        secret = SecretBytes.takeOwnership(ownedSecret),
    )

    private fun assertRecord(
        actual: StalwartCredentialRecord,
        expectedAddress: String,
        expectedPhase: CredentialPhase,
        expectedActive: ByteArray,
        expectedOther: ByteArray?,
    ) {
        assertEquals(expectedAddress, actual.addressAtCapture)
        assertEquals(expectedPhase, actual.phase)
        assertSecretEqualsRedacted(expectedActive, actual.active?.secret?.copyForUse())
        if (expectedOther == null) {
            assertNull(actual.other)
        } else {
            assertSecretEqualsRedacted(expectedOther, actual.other?.secret?.copyForUse())
        }
    }

    private fun captureExistingRegularBytes(paths: CredentialStorePaths): Map<Path, ByteArray> =
        listOf(paths.key, paths.ciphertext, paths.lock)
            .filter { Files.isRegularFile(it, LinkOption.NOFOLLOW_LINKS) }
            .associateWith(Files::readAllBytes)

    private fun assertExistingRegularBytesUnchanged(
        expected: Map<Path, ByteArray>,
        label: String,
    ) {
        expected.forEach { (path, bytes) ->
            assertBytesEqualRedacted(bytes, Files.readAllBytes(path), label)
        }
    }

    private fun assertSecretEqualsRedacted(
        expected: ByteArray,
        actual: ByteArray?,
    ) {
        val compared = actual ?: throw AssertionError("Secret bytes differ (redacted)")
        try {
            assertTrue(
                MessageDigest.isEqual(expected, compared),
                "Secret bytes differ (redacted)",
            )
        } finally {
            compared.fill(0)
        }
    }

    private fun assertClearedRedacted(bytes: ByteArray) {
        assertTrue(bytes.all { it == 0.toByte() }, "Secret bytes were not cleared (redacted)")
    }

    private fun assertBytesEqualRedacted(
        expected: ByteArray,
        actual: ByteArray,
        label: String,
    ) {
        try {
            assertTrue(
                MessageDigest.isEqual(expected, actual),
                "$label bytes changed (redacted)",
            )
        } finally {
            actual.fill(0)
        }
    }

    private fun abandonedSnapshot(paths: CredentialStorePaths, bytes: ByteArray): Path {
        val temporary = paths.ciphertext.resolveSibling(
            "${paths.ciphertext.fileName}.tmp-${UUID.randomUUID()}",
        )
        Files.write(temporary, bytes)
        setOwnerOnlyFile(temporary)
        return temporary
    }

    private fun abandonedSnapshots(paths: CredentialStorePaths): List<Path> =
        Files.list(paths.ciphertext.parent).use { stream ->
            stream.filter {
                it.fileName.toString().startsWith("${paths.ciphertext.fileName}.tmp-")
            }.toList()
        }

    private fun authenticatedEnvelope(
        paths: CredentialStorePaths,
        mutation: (ByteArray) -> ByteArray,
    ): ByteArray {
        val key = Files.readAllBytes(paths.key)
        val envelope = Files.readAllBytes(paths.ciphertext)
        val header = envelope.copyOfRange(0, ENVELOPE_HEADER_SIZE)
        val nonce = header.copyOfRange(NONCE_OFFSET, ENVELOPE_HEADER_SIZE)
        val plaintext = crypt(
            mode = Cipher.DECRYPT_MODE,
            key = key,
            nonce = nonce,
            header = header,
            input = envelope.copyOfRange(ENVELOPE_HEADER_SIZE, envelope.size),
        )
        val mutated = mutation(plaintext)
        return try {
            val encrypted = crypt(
                mode = Cipher.ENCRYPT_MODE,
                key = key,
                nonce = nonce,
                header = header,
                input = mutated,
            )
            try {
                header + encrypted
            } finally {
                encrypted.fill(0)
            }
        } finally {
            if (mutated !== plaintext) mutated.fill(0)
            plaintext.fill(0)
            key.fill(0)
            envelope.fill(0)
            header.fill(0)
            nonce.fill(0)
        }
    }

    private fun crypt(
        mode: Int,
        key: ByteArray,
        nonce: ByteArray,
        header: ByteArray,
        input: ByteArray,
    ): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(mode, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        cipher.updateAAD(
            "mail-sandbox/stalwart-app-passwords-envelope/v1"
                .toByteArray(Charsets.US_ASCII),
        )
        cipher.updateAAD(header)
        return cipher.doFinal(input)
    }

    private fun payloadRecords(payload: ByteArray): List<PayloadRecordOffsets> {
        val buffer = ByteBuffer.wrap(payload)
        buffer.long
        val count = buffer.int
        return buildList {
            repeat(count) {
                val accountLength = buffer.int
                val accountRange = buffer.position() until buffer.position() + accountLength
                buffer.position(accountRange.last + 1)
                val addressLength = buffer.int
                buffer.position(buffer.position() + addressLength)
                val phaseOffset = buffer.position()
                buffer.get()
                skipPayloadGeneration(buffer)
                skipPayloadGeneration(buffer)
                add(PayloadRecordOffsets(accountRange, phaseOffset))
            }
        }
    }

    private fun skipPayloadGeneration(buffer: ByteBuffer) {
        if (buffer.get().toInt() == 0) return
        repeat(2) {
            val length = buffer.int
            buffer.position(buffer.position() + length)
        }
        buffer.long
        val secretLength = buffer.int
        buffer.position(buffer.position() + secretLength)
    }

    private fun mutate(path: Path, mutation: (ByteArray) -> Unit) {
        val bytes = Files.readAllBytes(path)
        mutation(bytes)
        Files.write(path, bytes)
        bytes.fill(0)
    }

    private fun lastIndex(bytes: ByteArray): Int = bytes.size - 1

    private fun assertOwnerOnlyDirectory(path: Path) {
        assertTrue(Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS))
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

    private fun setOwnerOnlyDirectory(path: Path) {
        if (supportsPosix(path)) {
            Files.setPosixFilePermissions(
                path,
                PosixFilePermissions.fromString("rwx------"),
            )
        }
    }

    private fun setOwnerOnlyFile(path: Path) {
        if (supportsPosix(path)) {
            Files.setPosixFilePermissions(
                path,
                PosixFilePermissions.fromString("rw-------"),
            )
        }
    }

    private fun supportsPosix(path: Path): Boolean =
        path.fileSystem.supportedFileAttributeViews().contains("posix")

    private fun deleteTree(root: Path) {
        if (!Files.exists(root, LinkOption.NOFOLLOW_LINKS)) return
        Files.walk(root).use { stream ->
            stream.sorted(Comparator.reverseOrder())
                .forEach(Files::deleteIfExists)
        }
    }

    private fun ByteArray.containsSubsequence(needle: ByteArray): Boolean {
        if (needle.isEmpty()) return true
        return indices.any { start ->
            start + needle.size <= size &&
                needle.indices.all { offset -> this[start + offset] == needle[offset] }
        }
    }

    private companion object {
        val ENVELOPE_MAGIC = "MSSTCRD1".toByteArray(Charsets.US_ASCII)
        const val STORE_ID_OFFSET = 9
        const val NONCE_OFFSET = 25
        const val ENVELOPE_HEADER_SIZE = 37
        val SECRET_ACTIVE = "app_active_plaintext_canary".toByteArray()
        val SECRET_OTHER = "app_other_plaintext_canary".toByteArray()
    }

    private class SimulatedCrash : RuntimeException("simulated durability interruption")

    private data class PayloadRecordOffsets(
        val accountIdRange: IntRange,
        val phaseOffset: Int,
    )
}
