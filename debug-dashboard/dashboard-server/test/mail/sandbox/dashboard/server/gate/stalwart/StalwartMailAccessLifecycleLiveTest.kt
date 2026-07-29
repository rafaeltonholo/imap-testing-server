package mail.sandbox.dashboard.server.gate.stalwart

import java.net.URI
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.Paths
import java.nio.file.StandardOpenOption
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import mail.sandbox.dashboard.server.provider.stalwart.credential.CredentialPhase
import mail.sandbox.dashboard.server.provider.stalwart.credential.CredentialStoreLoadResult
import mail.sandbox.dashboard.server.provider.stalwart.credential.CredentialStorePaths
import mail.sandbox.dashboard.server.provider.stalwart.credential.FileStalwartCredentialStore
import mail.sandbox.dashboard.server.provider.stalwart.credential.STALWART_REQUIRED_MAIL_CAPABILITIES
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartBorrowedSecret
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartCredentialLeaseRegistry
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartCredentialManagementRemote
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartCredentialOwnerRemote
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartCredentialProbeResult
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartCredentialRecord
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartCredentialStoreResetResult
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartDurableCredentialPhaseObserver
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartGlobalReservedInventory
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartMailAccessResult
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartMailAccessService
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartMailAccessState
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartMailAccount
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartMailCapability
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartMailLeaseAcquireResult
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartNormalPassword
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartRemoteCreateResult
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartRemoteMutationResult
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartRemoteRead
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartReservedCredential
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartReservedCredentialIdentity
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartReservedInventory

class StalwartMailAccessLifecycleLiveTest {
    @Test
    fun provesCompleteMailCredentialLifecycle() = runBlocking {
        StalwartMailAccessLiveHarness.lifecycle().use { harness ->
            harness.proveLifecycle()
        }
    }
}

/**
 * The live harness is test-only because it owns the disposable Gate paths and
 * fixture credentials. Production wiring cannot select these paths.
 */
internal class StalwartMailAccessLiveHarness private constructor(
    private val mode: HarnessMode,
    private val projectRoot: Path,
    private val environment: StalwartMailAccessLiveEnvironment,
    private val fixture: GateFixtureSecrets?,
    private val managementAccountId: String,
    private val transport: KtorGateHttpTransport,
    private val manager: GateJmapClient,
    private val management: GateStalwartCredentialManagementRemote,
    private val store: FileStalwartCredentialStore,
    private val firstAccount: StalwartMailAccount?,
    private val secondAccount: StalwartMailAccount?,
) : AutoCloseable {
    private val probe = GateStalwartMailCredentialProbeRemote(
        baseUrl = environment.live.baseUrl,
        transport = transport,
    )
    private val owner = GateStalwartCredentialOwnerRemote(
        baseUrl = environment.live.baseUrl,
        transport = transport,
    )
    private var storeClosed = false
    private var closed = false

    suspend fun proveLifecycle() {
        check(mode == HarnessMode.Lifecycle) {
            "Lifecycle proof used the wrong live harness mode"
        }
        val first = requireNotNull(firstAccount)
        val second = requireNotNull(secondAccount)
        val service = service(owner)
        var primaryFailure: Throwable? = null
        try {
            assertEquals(
                StalwartMailAccessState.EnrollmentRequired,
                service.project(first).state,
            )
            val protectedProjection = service.project(
                StalwartMailAccount(
                    accountId = managementAccountId,
                    address = GateBootstrap.MANAGEMENT_ADDRESS,
                ),
            )
            assertTrue(protectedProjection.actions.isEmpty())

            requireCompletedReady(
                service.enroll(first, normalPassword(first)),
            )
            assertEquals(1, owner.createCount)

            val lease = assertIs<StalwartMailLeaseAcquireResult.Acquired>(
                service.acquireMailLease(first),
            ).lease
            try {
                assertEquals(first.accountId, lease.accountId)
                assertEquals(1L, lease.generation)
                val leasedSecret = lease.withSecret(ByteArray::copyOf)
                StalwartBorrowedSecret.takeOwnership(leasedSecret).use { borrowed ->
                    assertAuthenticated(
                        probe.probe(
                            accountId = first.accountId,
                            address = first.address,
                            secret = borrowed,
                        ),
                    )
                }
            } finally {
                lease.close()
            }

            requireCompletedReady(
                service.rotate(first, normalPassword(first)),
            )
            assertEquals(2, owner.createCount)
            assertEquals(
                StalwartMailAccessState.Ready,
                service.project(first).state,
            )

            val activeBeforeRevocation = requireInventory(first).reserved
            assertEquals(1, activeBeforeRevocation.size)
            assertEquals(
                StalwartRemoteMutationResult.Verified,
                management.revokeReserved(
                    accountId = first.accountId,
                    expected = activeBeforeRevocation.toSet(),
                ),
            )
            assertEquals(
                StalwartMailAccessState.RecoveryRequired,
                service.project(first).state,
            )

            requireCompletedReady(
                service.repair(first, normalPassword(first)),
            )
            assertEquals(3, owner.createCount)
            assertEquals(
                StalwartMailAccessState.Ready,
                service.project(first).state,
            )

            requireCompleted(
                result = service.remove(first),
                expectedState = StalwartMailAccessState.EnrollmentRequired,
            )
            assertTrue(requireInventory(first).reserved.isEmpty())
            assertEquals(
                StalwartMailAccessState.EnrollmentRequired,
                service.project(first).state,
            )

            requireCompletedReady(
                service.enroll(first, normalPassword(first)),
            )
            requireCompletedReady(
                service.enroll(second, normalPassword(second)),
            )
            val retiredStoreId = currentStoreId()
            assertEquals(2, requireGlobalInventory().reserved.size)

            corruptCiphertext()
            assertEquals(
                StalwartMailAccessState.StoreUnavailable,
                service.project(first).state,
            )
            val reset = assertIs<StalwartCredentialStoreResetResult.Completed>(
                service.resetUnavailableStore(),
            )
            assertNotEquals(retiredStoreId, reset.storeId)
            assertTrue(requireGlobalInventory().reserved.isEmpty())
            requireFreshEmptyStore(reset.storeId)
            assertEquals(
                StalwartMailAccessState.EnrollmentRequired,
                service.project(first).state,
            )
        } catch (failure: Throwable) {
            primaryFailure = failure
            throw failure
        } finally {
            try {
                withContext(NonCancellable) {
                    teardown()
                }
            } catch (cleanupFailure: Throwable) {
                if (primaryFailure == null) {
                    throw cleanupFailure
                }
                primaryFailure.addSuppressed(cleanupFailure)
            }
        }
    }

    suspend fun prepareRestartPhase() {
        check(mode == HarnessMode.RestartPrepare) {
            "Restart preparation used the wrong live harness mode"
        }
        val account = requireNotNull(firstAccount)
        val selected = requireNotNull(environment.restartPhase)
        val targetPhase = selected.credentialPhase
        val boundary = DurableRestartBoundary(account.accountId, targetPhase)
        val service = service(
            ownerRemote = owner,
            observer = StalwartDurableCredentialPhaseObserver { accountId, phase ->
                boundary.reached(accountId, phase)
            },
        )

        requireCompletedReady(
            service.enroll(account, normalPassword(account)),
        )
        try {
            when (selected) {
                StalwartMailAccessRestartPhase.Staged,
                StalwartMailAccessRestartPhase.Retiring,
                -> service.rotate(account, normalPassword(account))
                StalwartMailAccessRestartPhase.RemovalPending ->
                    service.remove(account)
            }
            throw AssertionError(
                "Restart preparation did not stop at its durable phase",
            )
        } catch (reached: DurableRestartBoundaryReached) {
            assertEquals(targetPhase, reached.phase)
            assertEquals(account.accountId, reached.accountId)
        }
        requirePersistedRestartShape(
            expectedPhase = targetPhase,
            expectedAccount = account,
        )
        // Deliberately no remote cleanup or local deletion: the next JVM owns it.
    }

    suspend fun reconcileRestartPhase() {
        check(mode == HarnessMode.RestartReconcile) {
            "Restart reconciliation used the wrong live harness mode"
        }
        val selected = requireNotNull(environment.restartPhase)
        val expectedPhase = selected.credentialPhase
        val account = derivePersistedRestartAccount(expectedPhase)
        val forbiddenOwner = CreateForbiddenOwnerRemote()
        val service = service(forbiddenOwner)
        var primaryFailure: Throwable? = null
        try {
            val expectedState = when (selected) {
                StalwartMailAccessRestartPhase.Staged,
                StalwartMailAccessRestartPhase.Retiring,
                -> StalwartMailAccessState.Ready
                StalwartMailAccessRestartPhase.RemovalPending ->
                    StalwartMailAccessState.EnrollmentRequired
            }
            requireCompleted(
                result = service.reconcileAfterRestart(account),
                expectedState = expectedState,
            )
            assertEquals(0, forbiddenOwner.createCount)
            assertEquals(expectedState, service.project(account).state)
            when (expectedState) {
                StalwartMailAccessState.Ready -> {
                    assertEquals(1, requireInventory(account).reserved.size)
                    requireSingleActiveRecord(account)
                }
                StalwartMailAccessState.EnrollmentRequired -> {
                    assertTrue(requireInventory(account).reserved.isEmpty())
                    requireNoRecord(account)
                }
                else -> error("Restart expectation was not terminal")
            }
        } catch (failure: Throwable) {
            primaryFailure = failure
            throw failure
        } finally {
            try {
                withContext(NonCancellable) {
                    teardown()
                }
            } catch (cleanupFailure: Throwable) {
                if (primaryFailure == null) {
                    throw cleanupFailure
                }
                primaryFailure.addSuppressed(cleanupFailure)
            }
        }
    }

    private fun service(
        ownerRemote: StalwartCredentialOwnerRemote,
        observer: StalwartDurableCredentialPhaseObserver =
            StalwartDurableCredentialPhaseObserver { _, _ -> },
    ): StalwartMailAccessService =
        StalwartMailAccessService(
            store = store,
            management = management,
            owner = ownerRemote,
            probe = probe,
            leases = StalwartCredentialLeaseRegistry(),
            protectedAccountIds = setOf(managementAccountId),
            durablePhaseObserver = observer,
        )

    private fun normalPassword(account: StalwartMailAccount): StalwartNormalPassword {
        val retainedFixture = requireNotNull(fixture) {
            "Restart reconciliation retains no ordinary normal passwords"
        }
        val copy = when (account.address) {
            GateBootstrap.FIRST_USER_ADDRESS ->
                retainedFixture.firstUserPassword.copyOf()
            GateBootstrap.SECOND_USER_ADDRESS ->
                retainedFixture.secondUserPassword.copyOf()
            else -> throw IllegalArgumentException(
                "Normal password requested for an unknown Gate Account",
            )
        }
        return StalwartNormalPassword.takeOwnership(copy)
    }

    private suspend fun requireInventory(
        account: StalwartMailAccount,
    ): StalwartReservedInventory {
        val read = assertIs<StalwartRemoteRead.Available<StalwartReservedInventory>>(
            management.inventory(account.accountId),
        )
        assertEquals(account.accountId, read.value.accountId)
        return read.value
    }

    private suspend fun requireGlobalInventory():
        StalwartGlobalReservedInventory =
        assertIs<StalwartRemoteRead.Available<StalwartGlobalReservedInventory>>(
            management.globalInventory(),
        ).value

    private fun currentStoreId(): java.util.UUID {
        val loaded = assertIs<CredentialStoreLoadResult.Available>(store.load())
        loaded.snapshot.use { snapshot ->
            return snapshot.storeId
        }
    }

    private fun requireFreshEmptyStore(expectedStoreId: java.util.UUID) {
        val loaded = assertIs<CredentialStoreLoadResult.Available>(store.load())
        loaded.snapshot.use { snapshot ->
            assertEquals(expectedStoreId, snapshot.storeId)
            assertEquals(0L, snapshot.revision)
            assertTrue(snapshot.records.isEmpty())
        }
    }

    private suspend fun requirePersistedRestartShape(
        expectedPhase: CredentialPhase,
        expectedAccount: StalwartMailAccount,
    ) {
        val loaded = assertIs<CredentialStoreLoadResult.Available>(store.load())
        loaded.snapshot.use { snapshot ->
            assertEquals(1, snapshot.records.size)
            val record = requireNotNull(snapshot.records[expectedAccount.accountId])
            assertEquals(expectedAccount.address, record.addressAtCapture)
            assertEquals(expectedPhase, record.phase)
            val inventory = requireInventory(expectedAccount)
            when (expectedPhase) {
                CredentialPhase.Staged,
                CredentialPhase.Retiring,
                -> {
                    assertEquals(2, inventory.reserved.size)
                    assertRemoteMatchesRecord(snapshot.storeId, record, inventory)
                }
                CredentialPhase.RemovalPending -> {
                    assertTrue(inventory.reserved.isEmpty())
                    assertEquals(null, record.other)
                }
                CredentialPhase.Active ->
                    throw AssertionError("Active is not a prepared restart boundary")
            }
        }
    }

    private fun derivePersistedRestartAccount(
        expectedPhase: CredentialPhase,
    ): StalwartMailAccount {
        val loaded = assertIs<CredentialStoreLoadResult.Available>(store.load())
        loaded.snapshot.use { snapshot ->
            assertEquals(1, snapshot.records.size)
            val record = snapshot.records.values.single()
            assertEquals(expectedPhase, record.phase)
            return StalwartMailAccount(
                accountId = record.accountId,
                address = record.addressAtCapture,
            )
        }
    }

    private fun requireSingleActiveRecord(account: StalwartMailAccount) {
        val loaded = assertIs<CredentialStoreLoadResult.Available>(store.load())
        loaded.snapshot.use { snapshot ->
            val record = requireNotNull(snapshot.records[account.accountId])
            assertEquals(CredentialPhase.Active, record.phase)
            assertEquals(null, record.other)
            assertEquals(1, snapshot.records.size)
        }
    }

    private fun requireNoRecord(account: StalwartMailAccount) {
        val loaded = assertIs<CredentialStoreLoadResult.Available>(store.load())
        loaded.snapshot.use { snapshot ->
            assertTrue(account.accountId !in snapshot.records)
            assertTrue(snapshot.records.isEmpty())
        }
    }

    private fun assertRemoteMatchesRecord(
        storeId: java.util.UUID,
        record: StalwartCredentialRecord,
        inventory: StalwartReservedInventory,
    ) {
        val local = listOfNotNull(record.active, record.other)
        assertEquals(local.size, inventory.reserved.size)
        val remote = inventory.reserved.associateBy(StalwartReservedCredential::credentialId)
        local.forEach { generation ->
            val reserved = requireNotNull(remote[generation.credentialId])
            assertEquals(generation.description, reserved.description)
            assertEquals(
                StalwartReservedCredentialIdentity.Exact(
                    storeId = storeId,
                    generation = generation.generation,
                ),
                reserved.identity,
            )
        }
    }

    private fun corruptCiphertext() {
        val ciphertext = environment.credentialPaths.ciphertext
        require(
            Files.isRegularFile(ciphertext, LinkOption.NOFOLLOW_LINKS) &&
                !Files.isSymbolicLink(ciphertext) &&
                ciphertext.toRealPath(LinkOption.NOFOLLOW_LINKS) == ciphertext,
        ) {
            "Gate credential ciphertext is not the exact safe file"
        }
        FileChannel.open(
            ciphertext,
            StandardOpenOption.READ,
            StandardOpenOption.WRITE,
        ).use { channel ->
            val position = channel.size() - 1
            require(position > 0) { "Gate credential ciphertext is unexpectedly short" }
            val byte = ByteBuffer.allocate(1)
            try {
                channel.position(position)
                require(channel.read(byte) == 1) {
                    "Gate credential ciphertext could not be read exactly"
                }
                byte.flip()
                val corrupted = (byte.get(0).toInt() xor 1).toByte()
                byte.clear()
                byte.put(corrupted)
                byte.flip()
                channel.position(position)
                require(channel.write(byte) == 1) {
                    "Gate credential ciphertext could not be corrupted exactly"
                }
                channel.force(true)
            } finally {
                byte.array().fill(0)
            }
        }
    }

    private suspend fun teardown() {
        if (closed) return
        var remoteVerified = false
        try {
            cleanupEveryReserved(management)
            remoteVerified = true
        } finally {
            closeStore()
            try {
                if (remoteVerified) {
                    deleteCredentialRoot(
                        projectRoot = projectRoot,
                        paths = environment.credentialPaths,
                    )
                }
            } finally {
                closeExternalResources()
            }
        }
    }

    override fun close() {
        if (closed) return
        closeStore()
        closeExternalResources()
    }

    private fun closeStore() {
        if (storeClosed) return
        storeClosed = true
        store.close()
    }

    private fun closeExternalResources() {
        if (closed) return
        closed = true
        manager.close()
        transport.close()
        fixture?.close()
    }

    companion object {
        suspend fun lifecycle(): StalwartMailAccessLiveHarness =
            open(HarnessMode.Lifecycle)

        suspend fun restartPrepare(): StalwartMailAccessLiveHarness =
            open(HarnessMode.RestartPrepare)

        suspend fun restartReconcile(): StalwartMailAccessLiveHarness =
            open(HarnessMode.RestartReconcile)

        private suspend fun open(
            mode: HarnessMode,
        ): StalwartMailAccessLiveHarness {
            val systemEnvironment = System.getenv()
            val projectRoot = mailAccessDashboardProjectRoot()
            val liveEnvironment = when (mode) {
                HarnessMode.Lifecycle ->
                    StalwartMailAccessLiveEnvironment.lifecycle(
                        environment = systemEnvironment,
                        projectRoot = projectRoot,
                    )
                HarnessMode.RestartPrepare,
                HarnessMode.RestartReconcile,
                -> StalwartMailAccessLiveEnvironment.restart(
                    environment = systemEnvironment,
                    projectRoot = projectRoot,
                )
            }
            liveEnvironment.live.awaitReady()
            StalwartDockerMountAudit.assertReviewedLiveMounts(projectRoot)

            var fixture: GateFixtureSecrets? = null
            var transport: KtorGateHttpTransport? = null
            var manager: GateJmapClient? = null
            var store: FileStalwartCredentialStore? = null
            try {
                val loadedFixture = StalwartGateSecretFiles.readFixtureSecrets(
                    projectRoot = projectRoot,
                    environment = systemEnvironment,
                )
                fixture = loadedFixture
                val managementAccountId = loadedFixture.managementAccountId
                transport = KtorGateHttpTransport()
                manager = GateJmapClient(
                    baseUrl = liveEnvironment.live.baseUrl,
                    credential = GateCredential.bearer(
                        loadedFixture.managementApiKey,
                    ),
                    transport = transport,
                )
                requireManagementSession(
                    manager = manager,
                    expectedAccountId = managementAccountId,
                )
                val management = GateStalwartCredentialManagementRemote(
                    registry = manager,
                    managementAccountId = managementAccountId,
                    protectedAccountIds = setOf(managementAccountId),
                )

                val accounts = if (mode == HarnessMode.RestartReconcile) {
                    loadedFixture.close()
                    fixture = null
                    null to null
                } else {
                    resolveOrdinaryAccount(
                        baseUrl = liveEnvironment.live.baseUrl,
                        transport = transport,
                        address = GateBootstrap.FIRST_USER_ADDRESS,
                        password = loadedFixture.firstUserPassword,
                    ) to resolveOrdinaryAccount(
                        baseUrl = liveEnvironment.live.baseUrl,
                        transport = transport,
                        address = GateBootstrap.SECOND_USER_ADDRESS,
                        password = loadedFixture.secondUserPassword,
                    )
                }
                val firstResolved = accounts.first
                val secondResolved = accounts.second
                if (firstResolved != null && secondResolved != null) {
                    require(
                        setOf(
                            managementAccountId,
                            firstResolved.accountId,
                            secondResolved.accountId,
                        ).size == 3,
                    ) {
                        "Gate lifecycle identities are not distinct"
                    }
                }

                if (mode != HarnessMode.RestartReconcile) {
                    cleanupEveryReserved(management)
                    deleteCredentialRoot(projectRoot, liveEnvironment.credentialPaths)
                } else {
                    require(
                        Files.isDirectory(
                            liveEnvironment.credentialPaths.runtimeRoot,
                            LinkOption.NOFOLLOW_LINKS,
                        ) &&
                            !Files.isSymbolicLink(
                                liveEnvironment.credentialPaths.runtimeRoot,
                            ),
                    ) {
                        "Prepared Gate credential-store evidence is absent"
                    }
                }

                store = FileStalwartCredentialStore(
                    liveEnvironment.credentialPaths,
                )
                return StalwartMailAccessLiveHarness(
                    mode = mode,
                    projectRoot = projectRoot,
                    environment = liveEnvironment,
                    fixture = fixture,
                    managementAccountId = managementAccountId,
                    transport = transport,
                    manager = manager,
                    management = management,
                    store = store,
                    firstAccount = accounts.first,
                    secondAccount = accounts.second,
                )
            } catch (failure: Throwable) {
                store?.close()
                manager?.close()
                transport?.close()
                fixture?.close()
                throw failure
            }
        }
    }
}

private class CreateForbiddenOwnerRemote : StalwartCredentialOwnerRemote {
    private val creates = AtomicInteger()

    val createCount: Int
        get() = creates.get()

    override suspend fun createOwned(
        account: StalwartMailAccount,
        description: String,
        normalPassword: StalwartNormalPassword,
    ): StalwartRemoteCreateResult {
        creates.incrementAndGet()
        throw AssertionError(
            "Restart reconciliation attempted to create a credential",
        )
    }
}

private class DurableRestartBoundary(
    private val expectedAccountId: String,
    private val expectedPhase: CredentialPhase,
) {
    fun reached(accountId: String, phase: CredentialPhase) {
        if (accountId == expectedAccountId && phase == expectedPhase) {
            throw DurableRestartBoundaryReached(accountId, phase)
        }
    }
}

private class DurableRestartBoundaryReached(
    val accountId: String,
    val phase: CredentialPhase,
) : RuntimeException("Durable restart boundary reached")

private enum class HarnessMode {
    Lifecycle,
    RestartPrepare,
    RestartReconcile,
}

private val StalwartMailAccessRestartPhase.credentialPhase: CredentialPhase
    get() = when (this) {
        StalwartMailAccessRestartPhase.Staged -> CredentialPhase.Staged
        StalwartMailAccessRestartPhase.Retiring -> CredentialPhase.Retiring
        StalwartMailAccessRestartPhase.RemovalPending ->
            CredentialPhase.RemovalPending
    }

private fun requireCompletedReady(result: StalwartMailAccessResult) {
    requireCompleted(result, StalwartMailAccessState.Ready)
}

private fun requireCompleted(
    result: StalwartMailAccessResult,
    expectedState: StalwartMailAccessState,
) {
    val completed = assertIs<StalwartMailAccessResult.Completed>(result)
    assertEquals(expectedState, completed.projection.state)
}

private fun assertAuthenticated(result: StalwartCredentialProbeResult) {
    val authenticated = assertIs<StalwartCredentialProbeResult.Authenticated>(result)
    assertTrue(
        authenticated.capabilities.containsAll(
            STALWART_REQUIRED_MAIL_CAPABILITIES,
        ),
    )
}

private suspend fun cleanupEveryReserved(
    management: StalwartCredentialManagementRemote,
) {
    val initial =
        assertIs<StalwartRemoteRead.Available<StalwartGlobalReservedInventory>>(
            management.globalInventory(),
        ).value
    val accountShape = initial.accounts.associate {
        it.accountId to it.protectedIdentity
    }
    initial.accounts.forEach { account ->
        if (account.reserved.isNotEmpty()) {
            assertEquals(
                StalwartRemoteMutationResult.Verified,
                management.revokeReserved(
                    accountId = account.accountId,
                    expected = account.reserved.toSet(),
                ),
            )
        }
    }
    val verified =
        assertIs<StalwartRemoteRead.Available<StalwartGlobalReservedInventory>>(
            management.globalInventory(),
        ).value
    assertEquals(
        accountShape,
        verified.accounts.associate {
            it.accountId to it.protectedIdentity
        },
    )
    assertTrue(
        verified.reserved.isEmpty(),
        "Gate teardown did not prove the global reserved inventory empty",
    )
}

private fun deleteCredentialRoot(
    projectRoot: Path,
    paths: CredentialStorePaths,
) {
    val expected =
        projectRoot.resolve(".runtime/stalwart-gate0b/credential-store")
    require(paths.runtimeRoot == expected) {
        "Gate cleanup refused a non-gate credential root"
    }
    require(
        expected.parent.toRealPath() ==
            projectRoot.resolve(".runtime/stalwart-gate0b"),
    ) {
        "Gate cleanup parent is not the fixed canonical runtime"
    }
    if (!Files.exists(expected, LinkOption.NOFOLLOW_LINKS)) return
    require(
        Files.isDirectory(expected, LinkOption.NOFOLLOW_LINKS) &&
            !Files.isSymbolicLink(expected) &&
            expected.toRealPath() == expected,
    ) {
        "Gate cleanup refused an unsafe credential root"
    }
    val entries = Files.walk(expected).use { stream ->
        stream.toList()
    }
    entries.sortedByDescending(Path::getNameCount).forEach { entry ->
        require(entry.normalize().startsWith(expected)) {
            "Gate cleanup path escaped its credential root"
        }
        Files.delete(entry)
    }
}

private suspend fun requireManagementSession(
    manager: GateJmapClient,
    expectedAccountId: String,
) {
    val session = manager.discoverSession()
    require(
        session.apiUrl == URI("http://127.0.0.1:18443/jmap/") &&
            session.primaryAccountId == expectedAccountId &&
            session.username == GateBootstrap.MANAGEMENT_ADDRESS,
    ) {
        "Mail lifecycle management credential authenticated the wrong Account"
    }
}

private suspend fun resolveOrdinaryAccount(
    baseUrl: URI,
    transport: GateHttpTransport,
    address: String,
    password: CharArray,
): StalwartMailAccount =
    GateJmapClient(
        baseUrl = baseUrl,
        credential = GateCredential.basic(address, password),
        transport = transport,
    ).use { client ->
        val session = client.discoverSession()
        require(
            session.apiUrl == URI("http://127.0.0.1:18443/jmap/") &&
                session.username == address &&
                !session.primaryAccountId.isNullOrBlank(),
        ) {
            "Mail lifecycle normal credential authenticated the wrong Account"
        }
        StalwartMailAccount(
            accountId = requireNotNull(session.primaryAccountId),
            address = address,
        )
    }

private fun mailAccessDashboardProjectRoot(): Path {
    val working = Paths.get(System.getProperty("user.dir"))
        .toAbsolutePath()
        .normalize()
    val candidate = if (working.fileName?.toString() == "dashboard-server") {
        requireNotNull(working.parent)
    } else {
        working
    }
    require(
        candidate.fileName?.toString() == "debug-dashboard" &&
            Files.isRegularFile(
                candidate.resolve("project.yaml"),
                LinkOption.NOFOLLOW_LINKS,
            ),
    ) {
        "Live mail lifecycle must run from debug-dashboard or dashboard-server"
    }
    return candidate.toRealPath()
}
