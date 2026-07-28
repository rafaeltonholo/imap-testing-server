package mail.sandbox.dashboard.server.provider.stalwart.credential

import java.util.Collections
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.yield
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail

class StalwartMailAccessServiceTest {
    @Test
    fun stateProjectionCoversEnrollmentReadyRotationRecoveryAndRemoval() = runBlocking {
        val storeId = UUID.fromString("2ea9d9e3-98fe-477e-b3f9-5fbabf9de1e1")
        val account = StalwartMailAccount(
            accountId = "account-one",
            address = "gate-one@local.test",
        )
        val active = generationSpec(storeId, number = 1)
        val successor = generationSpec(storeId, number = 2)
        val management = FakeManagementRemote()
        val probe = FakeProbeRemote()
        val store = FakeCredentialStore()
        val service = service(store, management, probe)

        management.inventory = availableInventory(account.accountId)
        assertEquals(
            projection(
                StalwartMailAccessState.EnrollmentRequired,
                StalwartMailAccessAction.Enroll,
            ),
            service.project(account),
        )

        store.record = recordSpec(
            account = account,
            phase = CredentialPhase.Active,
            active = active,
        )
        management.inventory = availableInventory(
            account.accountId,
            reserved(active),
        )
        probe.results += active.secret.copyOf() to
            StalwartCredentialProbeResult.Authenticated(
                STALWART_REQUIRED_MAIL_CAPABILITIES,
            )
        assertEquals(
            projection(
                StalwartMailAccessState.Ready,
                StalwartMailAccessAction.Rotate,
                StalwartMailAccessAction.Remove,
            ),
            service.project(account),
        )

        probe.results.clear()
        probe.results += active.secret.copyOf() to
            StalwartCredentialProbeResult.Authenticated(
                STALWART_REQUIRED_MAIL_CAPABILITIES -
                    StalwartMailCapability.Submission,
            )
        assertEquals(
            projection(
                StalwartMailAccessState.RecoveryRequired,
                StalwartMailAccessAction.Repair,
            ),
            service.project(account),
        )

        store.record = recordSpec(
            account = account,
            phase = CredentialPhase.Staged,
            active = active,
            other = successor,
        )
        management.inventory = availableInventory(
            account.accountId,
            reserved(active),
            reserved(successor),
        )
        assertEquals(
            projection(StalwartMailAccessState.Rotating),
            service.project(account),
        )

        store.record = recordSpec(
            account = account,
            phase = CredentialPhase.Active,
            active = active,
        )
        management.inventory = availableInventory(account.accountId)
        assertEquals(
            projection(
                StalwartMailAccessState.RecoveryRequired,
                StalwartMailAccessAction.Repair,
            ),
            service.project(account),
        )

        store.record = recordSpec(
            account = account,
            phase = CredentialPhase.RemovalPending,
            active = active,
        )
        assertEquals(
            projection(
                StalwartMailAccessState.RemovalPending,
                StalwartMailAccessAction.Reconcile,
            ),
            service.project(account),
        )
    }

    @Test
    fun retiringProjectionStaysRotatingWhenOnlyTheSuccessorRemainsRemote() =
        runBlocking {
            val account = StalwartMailAccount(
                accountId = "retiring-projection",
                address = "retiring-projection@local.test",
            )
            val store = FakeCredentialStore()
            val old = generationSpec(store.storeId, 4)
            val successor = generationSpec(store.storeId, 5)
            store.record = recordSpec(
                account = account,
                phase = CredentialPhase.Retiring,
                active = successor,
                other = old,
            )
            val management = FakeManagementRemote().also {
                it.inventory = availableInventory(
                    account.accountId,
                    reserved(successor),
                )
            }
            val service = service(
                store = store,
                management = management,
                probe = FakeProbeRemote(),
            )

            assertEquals(
                projection(StalwartMailAccessState.Rotating),
                service.project(account),
            )

            management.inventory = availableInventory(
                account.accountId,
                reserved(old),
            )
            assertEquals(
                projection(
                    StalwartMailAccessState.RecoveryRequired,
                    StalwartMailAccessAction.Repair,
                ),
                service.project(account),
            )
        }

    @Test
    fun malformedMismatchedUncapturedAndOrphanReservedCredentialsNeedRecovery() =
        runBlocking {
            val storeId = UUID.fromString("94c97c02-2960-4550-8d43-15bbde1a27d4")
            val account = StalwartMailAccount(
                accountId = "account-two",
                address = "gate-two@local.test",
            )
            val active = generationSpec(storeId, number = 9)
            val management = FakeManagementRemote()
            val store = FakeCredentialStore().also {
                it.storeId = storeId
            }
            val service = service(store, management, FakeProbeRemote())
            val expected = projection(
                StalwartMailAccessState.RecoveryRequired,
                StalwartMailAccessAction.Repair,
            )

            management.inventory = availableInventory(
                account.accountId,
                StalwartReservedCredential(
                    credentialId = "orphan",
                    description = "mail-sandbox/debug-dashboard/not-a-generation",
                ),
            )
            assertEquals(expected, service.project(account))

            management.inventory = availableInventory(
                account.accountId,
                reserved(active).withCredentialId("uncaptured"),
            )
            assertEquals(expected, service.project(account))

            store.record = recordSpec(
                account = account,
                phase = CredentialPhase.Active,
                active = active,
            )
            management.inventory = availableInventory(
                account.accountId,
                StalwartReservedCredential(
                    credentialId = active.credentialId,
                    description =
                        "mail-sandbox/debug-dashboard/$storeId/${active.generation + 1}",
                ),
            )
            assertEquals(expected, service.project(account))

            management.inventory = availableInventory(
                account.accountId,
                reserved(active),
                StalwartReservedCredential(
                    credentialId = "unknown-reserved",
                    description =
                        "mail-sandbox/debug-dashboard/$storeId/${active.generation + 1}",
                ),
            )
            assertEquals(expected, service.project(account))
        }

    @Test
    fun unavailableStoreSupersedesEveryAccountAndProtectedIdentityHasNoAction() =
        runBlocking {
            val management = FakeManagementRemote().also {
                it.inventory = availableInventory("protected-account")
            }
            val store = FakeCredentialStore().also {
                it.available = false
            }
            val protectedAccount = StalwartMailAccount(
                accountId = "protected-account",
                address = "dashboard-management@local.test",
            )
            val service = service(
                store = store,
                management = management,
                probe = FakeProbeRemote(),
                protectedAccountIds = setOf(protectedAccount.accountId),
            )

            assertEquals(
                projection(StalwartMailAccessState.StoreUnavailable),
                service.project(protectedAccount),
            )
            assertEquals(0, management.inventoryCalls)

            store.available = true
            assertEquals(
                projection(StalwartMailAccessState.EnrollmentRequired),
                service.project(protectedAccount),
            )
            assertEquals(0, management.inventoryCalls)
        }

    @Test
    fun unavailableStoreSupersedesEnrollmentBeforeAnyRemoteMutation() =
        runBlocking {
            val account = StalwartMailAccount(
                accountId = "unavailable-enrollment",
                address = "unavailable-enrollment@local.test",
            )
            val store = FakeCredentialStore().also {
                it.available = false
            }
            val management = FakeManagementRemote()
            val owner = FakeOwnerRemote()
            val passwordChars = "unavailable-password".toCharArray()

            val result = service(
                store = store,
                management = management,
                probe = FakeProbeRemote(),
                owner = owner,
            ).enroll(
                account,
                StalwartNormalPassword.takeOwnership(passwordChars),
            )

            val reconciliation =
                assertIs<StalwartMailAccessResult.ReconciliationRequired>(result)
            assertEquals(
                projection(StalwartMailAccessState.StoreUnavailable),
                reconciliation.projection,
            )
            assertEquals(
                StalwartMailAccessReason.LocalStoreUnavailable,
                reconciliation.reason,
            )
            assertEquals(0, management.inventoryCalls)
            assertEquals(0, owner.createCalls)
            assertEquals(0, store.replaceCalls)
            assertTrue(passwordChars.all { it == '\u0000' })
        }

    @Test
    fun mailLeaseRequiresReadyAndWipesItsOwnedCopyExactlyOnce() {
        val registry = StalwartCredentialLeaseRegistry()
        val rejectedBytes = "not-ready-secret".encodeToByteArray()
        val rejectedMaterial = StalwartMailLeaseMaterial.takeOwnership(
            accountId = "different-account",
            generation = 1,
            secret = rejectedBytes,
        )
        assertIs<StalwartMailLeaseAcquireResult.Unavailable>(
            runBlocking {
                registry.acquireMail(
                    accountId = "account-one",
                ) {
                    rejectedMaterial
                }
            },
        )
        assertTrue(rejectedBytes.all { it == 0.toByte() })

        val unavailable = assertIs<StalwartMailLeaseAcquireResult.Unavailable>(
            runBlocking {
                registry.acquireMail(
                    accountId = "account-one",
                ) {
                    null
                }
            },
        )
        assertEquals(StalwartMailLeaseUnavailableReason.NotReady, unavailable.reason)

        val leasedBytes = "ready-secret".encodeToByteArray()
        val material = StalwartMailLeaseMaterial.takeOwnership(
            accountId = "account-one",
            generation = 2,
            secret = leasedBytes,
        )
        val acquired = assertIs<StalwartMailLeaseAcquireResult.Acquired>(
            runBlocking {
                registry.acquireMail(
                    accountId = "account-one",
                ) {
                    material
                }
            },
        )
        acquired.lease.use { lease ->
            lease.withSecret { borrowed ->
                assertContentEquals("ready-secret".encodeToByteArray(), borrowed)
                borrowed.fill(0)
            }
        }
        acquired.lease.close()
        acquired.lease.cancel()
        assertTrue(leasedBytes.all { it == 0.toByte() })
        assertFailsWith<IllegalStateException> {
            acquired.lease.withSecret { }
        }
    }

    @Test
    fun concurrentReadersDrainBeforeAWriterAndPendingWriterBlocksNewReaders() {
        val writerWaiting = CountDownLatch(1)
        val registry = StalwartCredentialLeaseRegistry(
            waiter = StalwartLeaseChangeWaiter { change, _ ->
                writerWaiting.countDown()
                change.await()
            },
        )
        val first = acquiredLease(registry, "account-one", 1)
        val second = acquiredLease(registry, "account-one", 1)
        val isolated = acquiredLease(registry, "account-two", 1)
        val executor = Executors.newSingleThreadExecutor()
        try {
            val writerFuture = executor.submit<StalwartExclusiveLeaseAcquireResult> {
                runBlocking {
                    registry.acquireExclusive("account-one")
                }
            }
            assertTrue(writerWaiting.await(5, TimeUnit.SECONDS))

            val supplierCalls = AtomicInteger()
            val blocked = runBlocking {
                registry.acquireMail("account-one") {
                    supplierCalls.incrementAndGet()
                    material("account-one", 1)
                }
            }
            assertEquals(
                StalwartMailLeaseAcquireResult.Unavailable(
                    StalwartMailLeaseUnavailableReason.MutationPending,
                ),
                blocked,
            )
            assertEquals(0, supplierCalls.get())

            val accountTwoStillWorks = acquiredLease(registry, "account-two", 1)
            accountTwoStillWorks.close()
            first.close()
            assertTrue(!writerFuture.isDone)
            second.close()

            val writer = assertIs<StalwartExclusiveLeaseAcquireResult.Acquired>(
                writerFuture.get(5, TimeUnit.SECONDS),
            )
            val blockedWhileActive = runBlocking {
                registry.acquireMail("account-one") {
                    fail("active writer must block the material supplier")
                }
            }
            assertIs<StalwartMailLeaseAcquireResult.Unavailable>(blockedWhileActive)
            writer.lease.close()
            acquiredLease(registry, "account-one", 2).close()
        } finally {
            first.close()
            second.close()
            isolated.close()
            executor.shutdownNow()
        }
    }

    @Test
    fun fakeThirtySecondDrainTimeoutClearsPendingWithoutStateMutation() =
        runBlocking {
            val now = AtomicLong(0)
            val waits = AtomicInteger()
            val registry = StalwartCredentialLeaseRegistry(
                nanoClock = StalwartLeaseNanoClock(now::get),
                waiter = StalwartLeaseChangeWaiter { _, remaining ->
                    waits.incrementAndGet()
                    now.addAndGet(remaining)
                },
            )
            val reader = acquiredLease(registry, "account-one", 1)

            assertIs<StalwartExclusiveLeaseAcquireResult.TimedOut>(
                registry.acquireExclusive("account-one"),
            )
            assertEquals(1, waits.get())

            val nextReader = acquiredLease(registry, "account-one", 1)
            nextReader.close()
            reader.close()
            assertIs<StalwartExclusiveLeaseAcquireResult.Acquired>(
                registry.acquireExclusive("account-one"),
            ).lease.close()
        }

    @Test
    fun sharedPermitExistsBeforeCurrentGenerationLoaderRuns() = runBlocking {
        val registry = StalwartCredentialLeaseRegistry()
        val acquired = assertIs<StalwartMailLeaseAcquireResult.Acquired>(
            registry.acquireMail("account-one") {
                assertIs<StalwartExclusiveLeaseAcquireResult.TimedOut>(
                    registry.acquireExclusive(
                        accountId = "account-one",
                        timeoutNanos = 0,
                    ),
                )
                material("account-one", 7)
            },
        )
        acquired.lease.close()
        assertIs<StalwartExclusiveLeaseAcquireResult.Acquired>(
            registry.acquireExclusive("account-one", timeoutNanos = 0),
        ).lease.close()
    }

    @Test
    fun globalBarrierDrainsEveryAccountAndBlocksAllNewLeaseSuppliers() {
        val globalWaiting = CountDownLatch(1)
        val registry = StalwartCredentialLeaseRegistry(
            waiter = StalwartLeaseChangeWaiter { change, _ ->
                globalWaiting.countDown()
                change.await()
            },
        )
        val first = acquiredLease(registry, "account-one", 1)
        val second = acquiredLease(registry, "account-two", 1)
        val executor = Executors.newSingleThreadExecutor()
        try {
            val globalFuture =
                executor.submit<StalwartGlobalExclusiveLeaseAcquireResult> {
                    runBlocking {
                        registry.acquireGlobalExclusive()
                    }
                }
            assertTrue(globalWaiting.await(5, TimeUnit.SECONDS))

            listOf("account-one", "account-three").forEach { accountId ->
                val blocked = runBlocking {
                    registry.acquireMail(accountId) {
                        fail("pending global writer must block every supplier")
                    }
                }
                assertIs<StalwartMailLeaseAcquireResult.Unavailable>(blocked)
            }

            first.close()
            assertTrue(!globalFuture.isDone)
            second.close()
            val global =
                assertIs<StalwartGlobalExclusiveLeaseAcquireResult.Acquired>(
                    globalFuture.get(5, TimeUnit.SECONDS),
                )
            val blocked = runBlocking {
                registry.acquireMail("account-four") {
                    fail("active global writer must block every supplier")
                }
            }
            assertIs<StalwartMailLeaseAcquireResult.Unavailable>(blocked)
            global.lease.close()
            acquiredLease(registry, "account-four", 1).close()
        } finally {
            first.close()
            second.close()
            executor.shutdownNow()
        }
    }

    @Test
    fun accountWriterSuspendsSoItsSingleDispatcherCanCloseTheReader() =
        runBlocking {
            val registry = StalwartCredentialLeaseRegistry()
            val reader = acquiredLease(registry, "single-account", 1)
            val dispatcher =
                Executors.newSingleThreadExecutor().asCoroutineDispatcher()
            var writer: Deferred<StalwartExclusiveLeaseAcquireResult>? = null
            try {
                writer = async(dispatcher) {
                    registry.acquireExclusive(
                        accountId = "single-account",
                        timeoutNanos = TimeUnit.MILLISECONDS.toNanos(500),
                    )
                }
                awaitMutationPending(registry, "single-account")
                val closer = async(dispatcher) {
                    reader.close()
                }

                val result = withTimeout(200) {
                    writer.await()
                }
                closer.await()
                assertIs<StalwartExclusiveLeaseAcquireResult.Acquired>(
                    result,
                ).lease.close()
            } finally {
                reader.close()
                try {
                    writer?.let { pending ->
                        val result = withTimeout(1_000) {
                            pending.await()
                        }
                        if (
                            result is
                            StalwartExclusiveLeaseAcquireResult.Acquired
                        ) {
                            result.lease.close()
                        }
                    }
                } finally {
                    dispatcher.close()
                }
            }
        }

    @Test
    fun globalWriterSuspendsSoItsSingleDispatcherCanCloseEveryReader() =
        runBlocking {
            val registry = StalwartCredentialLeaseRegistry()
            val reader = acquiredLease(registry, "single-global", 1)
            val dispatcher =
                Executors.newSingleThreadExecutor().asCoroutineDispatcher()
            var writer:
                Deferred<StalwartGlobalExclusiveLeaseAcquireResult>? = null
            try {
                writer = async(dispatcher) {
                    registry.acquireGlobalExclusive(
                        timeoutNanos = TimeUnit.MILLISECONDS.toNanos(500),
                    )
                }
                awaitMutationPending(registry, "global-blocked-reader")
                val closer = async(dispatcher) {
                    reader.close()
                }

                val result = withTimeout(200) {
                    writer.await()
                }
                closer.await()
                assertIs<StalwartGlobalExclusiveLeaseAcquireResult.Acquired>(
                    result,
                ).lease.close()
            } finally {
                reader.close()
                try {
                    writer?.let { pending ->
                        val result = withTimeout(1_000) {
                            pending.await()
                        }
                        if (
                            result is
                            StalwartGlobalExclusiveLeaseAcquireResult.Acquired
                        ) {
                            result.lease.close()
                        }
                    }
                } finally {
                    dispatcher.close()
                }
            }
        }

    @Test
    fun cancellingPendingAccountWriterRemovesItsBarrierPromptly() =
        runBlocking {
            val registry = StalwartCredentialLeaseRegistry()
            val reader = acquiredLease(registry, "cancel-account", 1)
            val dispatcher =
                Executors.newSingleThreadExecutor().asCoroutineDispatcher()
            val writer = async(dispatcher) {
                registry.acquireExclusive(
                    accountId = "cancel-account",
                    timeoutNanos = TimeUnit.MILLISECONDS.toNanos(500),
                )
            }
            try {
                awaitMutationPending(registry, "cancel-account")
                writer.cancel(
                    CancellationException("cancel pending Account writer"),
                )
                withTimeout(200) {
                    writer.join()
                }

                val admitted = assertIs<StalwartMailLeaseAcquireResult.Acquired>(
                    registry.acquireMail("cancel-account") {
                        material("cancel-account", 2)
                    },
                )
                admitted.lease.close()
            } finally {
                reader.close()
                try {
                    withTimeout(1_000) {
                        writer.join()
                    }
                } finally {
                    dispatcher.close()
                }
            }
        }

    @Test
    fun cancellingPendingGlobalWriterRemovesItsBarrierPromptly() =
        runBlocking {
            val registry = StalwartCredentialLeaseRegistry()
            val reader = acquiredLease(registry, "cancel-global", 1)
            val dispatcher =
                Executors.newSingleThreadExecutor().asCoroutineDispatcher()
            val writer = async(dispatcher) {
                registry.acquireGlobalExclusive(
                    timeoutNanos = TimeUnit.MILLISECONDS.toNanos(500),
                )
            }
            try {
                awaitMutationPending(registry, "global-cancel-blocked")
                writer.cancel(
                    CancellationException("cancel pending global writer"),
                )
                withTimeout(200) {
                    writer.join()
                }

                val admitted = assertIs<StalwartMailLeaseAcquireResult.Acquired>(
                    registry.acquireMail("global-after-cancel") {
                        material("global-after-cancel", 1)
                    },
                )
                admitted.lease.close()
            } finally {
                reader.close()
                try {
                    withTimeout(1_000) {
                        writer.join()
                    }
                } finally {
                    dispatcher.close()
                }
            }
        }

    @Test
    fun cancelledOrInterruptedLeaseHandoffsReleaseActivePermits() =
        runBlocking {
            lateinit var cancelAccountHandoff: () -> Unit
            val accountRegistry = StalwartCredentialLeaseRegistry(
                handoffObserver = StalwartLeaseHandoffObserver {
                    cancelAccountHandoff()
                },
            )
            val accountWriter = async {
                val operationContext = currentCoroutineContext()
                cancelAccountHandoff = {
                    operationContext.cancel(
                        CancellationException(
                            "cancel Account lease handoff",
                        ),
                    )
                }
                accountRegistry.acquireExclusive(
                    accountId = "cancel-account-handoff",
                    timeoutNanos = TimeUnit.MILLISECONDS.toNanos(500),
                )
            }
            accountWriter.join()
            assertTrue(accountWriter.isCancelled)
            assertIs<StalwartMailLeaseAcquireResult.Acquired>(
                accountRegistry.acquireMail("cancel-account-handoff") {
                    material("cancel-account-handoff", 1)
                },
            ).lease.close()

            lateinit var cancelGlobalHandoff: () -> Unit
            val globalRegistry = StalwartCredentialLeaseRegistry(
                handoffObserver = StalwartLeaseHandoffObserver {
                    cancelGlobalHandoff()
                },
            )
            val globalWriter = async {
                val operationContext = currentCoroutineContext()
                cancelGlobalHandoff = {
                    operationContext.cancel(
                        CancellationException(
                            "cancel global lease handoff",
                        ),
                    )
                }
                globalRegistry.acquireGlobalExclusive(
                    timeoutNanos = TimeUnit.MILLISECONDS.toNanos(500),
                )
            }
            globalWriter.join()
            assertTrue(globalWriter.isCancelled)
            assertIs<StalwartMailLeaseAcquireResult.Acquired>(
                globalRegistry.acquireMail("after-global-handoff") {
                    material("after-global-handoff", 1)
                },
            ).lease.close()

            val interruptedRegistry = StalwartCredentialLeaseRegistry(
                handoffObserver = StalwartLeaseHandoffObserver {
                    Thread.currentThread().interrupt()
                },
            )
            try {
                interruptedRegistry.acquireExclusive(
                    accountId = "interrupt-account-handoff",
                    timeoutNanos = TimeUnit.MILLISECONDS.toNanos(500),
                )
                fail("Interrupted Account handoff returned an active lease")
            } catch (_: InterruptedException) {
                assertTrue(Thread.currentThread().isInterrupted)
            } finally {
                Thread.interrupted()
            }
            assertIs<StalwartMailLeaseAcquireResult.Acquired>(
                interruptedRegistry.acquireMail("interrupt-account-handoff") {
                    material("interrupt-account-handoff", 1)
                },
            ).lease.close()
        }

    @Test
    fun globalBarrierAndTimedOutWriterRetainNoIdleAccountState() =
        runBlocking {
            val observedAccountCounts =
                Collections.synchronizedList(mutableListOf<Int>())
            val registry = StalwartCredentialLeaseRegistry(
                stateObserver = StalwartLeaseStateObserver { accountCount ->
                    observedAccountCounts += accountCount
                },
            )
            val reader = acquiredLease(registry, "tracked-reader", 1)
            val dispatcher =
                Executors.newSingleThreadExecutor().asCoroutineDispatcher()
            val global = async(dispatcher) {
                registry.acquireGlobalExclusive(
                    timeoutNanos = TimeUnit.MILLISECONDS.toNanos(500),
                )
            }
            try {
                awaitMutationPending(registry, "unknown-reader")
                assertEquals(1, observedAccountCounts.last())

                assertIs<StalwartExclusiveLeaseAcquireResult.TimedOut>(
                    registry.acquireExclusive(
                        accountId = "unknown-writer",
                        timeoutNanos = 0,
                    ),
                )
                assertTrue(2 in observedAccountCounts)
                assertEquals(1, observedAccountCounts.last())
            } finally {
                reader.close()
                try {
                    val result = withTimeout(1_000) {
                        global.await()
                    }
                    if (
                        result is
                        StalwartGlobalExclusiveLeaseAcquireResult.Acquired
                    ) {
                        result.lease.close()
                    }
                } finally {
                    dispatcher.close()
                }
            }
        }

    @Test
    fun drainDeadlineIncludesRegistrationAndEveryWaitIteration() = runBlocking {
        val now = AtomicLong(0)
        val timeoutNanos = TimeUnit.MILLISECONDS.toNanos(100)
        val registrationNanos = TimeUnit.MILLISECONDS.toNanos(60)
        val waitStepNanos = TimeUnit.MILLISECONDS.toNanos(15)
        val observedRemaining = mutableListOf<Long>()
        val registry = StalwartCredentialLeaseRegistry(
            nanoClock = StalwartLeaseNanoClock(now::get),
            pendingRegistrationObserver =
                StalwartLeasePendingRegistrationObserver {
                    now.addAndGet(registrationNanos)
                },
            waiter = StalwartLeaseChangeWaiter { _, remaining ->
                observedRemaining += remaining
                now.addAndGet(minOf(waitStepNanos, remaining))
            },
        )
        val reader = acquiredLease(registry, "deadline-account", 1)
        try {
            assertIs<StalwartExclusiveLeaseAcquireResult.TimedOut>(
                registry.acquireExclusive(
                    accountId = "deadline-account",
                    timeoutNanos = timeoutNanos,
                ),
            )
            assertEquals(
                listOf(
                    TimeUnit.MILLISECONDS.toNanos(40),
                    TimeUnit.MILLISECONDS.toNanos(25),
                    TimeUnit.MILLISECONDS.toNanos(10),
                ),
                observedRemaining,
            )
        } finally {
            reader.close()
        }
    }

    @Test
    fun interruptedLeaseDrainPropagatesWithoutReadingTheCredentialStore() {
        val account = StalwartMailAccount(
            accountId = "interrupted-account",
            address = "interrupted@local.test",
        )
        val store = FakeCredentialStore()
        val registry = StalwartCredentialLeaseRegistry(
            waiter = StalwartLeaseChangeWaiter { _, _ ->
                throw InterruptedException("interrupted credential drain")
            },
        )
        val reader = acquiredLease(registry, account.accountId, 1)
        val passwordChars = "interrupted-password".toCharArray()
        try {
            assertFailsWith<InterruptedException> {
                runBlocking {
                    service(
                        store = store,
                        management = FakeManagementRemote(),
                        probe = FakeProbeRemote(),
                        leases = registry,
                    ).enroll(
                        account,
                        StalwartNormalPassword.takeOwnership(passwordChars),
                    )
                }
            }
            assertTrue(Thread.currentThread().isInterrupted)
            assertEquals(0, store.loadCalls)
            assertTrue(passwordChars.all { it == '\u0000' })
        } finally {
            Thread.interrupted()
            reader.close()
        }
    }

    @Test
    fun enrollmentInventoriesCreatesCapturesDurablyBeforeProbeAndWipesInputs() =
        runBlocking {
            val events = mutableListOf<String>()
            val account = StalwartMailAccount(
                accountId = "enroll-account",
                address = "enroll@local.test",
            )
            val store = FakeCredentialStore(events = events)
            val management = FakeManagementRemote(events).also {
                it.inventory = availableInventory(account.accountId)
            }
            val createdBytes = "app_enrolled_secret".encodeToByteArray()
            val owner = FakeOwnerRemote(events).also {
                it.results += StalwartRemoteCreateResult.Created(
                    StalwartCreatedCredential(
                        credentialId = "enrolled-credential",
                        description =
                            "mail-sandbox/debug-dashboard/${store.storeId}/1",
                        secret = createdBytes,
                    ),
                )
            }
            val probe = FakeProbeRemote(events).also {
                it.results += "app_enrolled_secret".encodeToByteArray() to
                    StalwartCredentialProbeResult.Authenticated(
                        STALWART_REQUIRED_MAIL_CAPABILITIES,
                    )
            }
            val leases = StalwartCredentialLeaseRegistry()
            val service = service(
                store = store,
                management = management,
                probe = probe,
                owner = owner,
                leases = leases,
            )
            val passwordBytes = "request-password".toCharArray()
            val password = StalwartNormalPassword.takeOwnership(passwordBytes)

            val result = assertIs<StalwartMailAccessResult.Completed>(
                service.enroll(account, password),
            )

            assertEquals(
                projection(
                    StalwartMailAccessState.Ready,
                    StalwartMailAccessAction.Rotate,
                    StalwartMailAccessAction.Remove,
                ),
                result.projection,
            )
            assertEquals(
                listOf(
                    "inventory:enroll-account",
                    "create:enroll-account",
                    "persist:Active",
                    "probe:enroll-account",
                ),
                events,
            )
            assertEquals(1, owner.createCalls)
            assertEquals(1, store.replaceCalls)
            assertEquals(CredentialPhase.Active, store.record?.phase)
            assertTrue(passwordBytes.all { it == '\u0000' })
            assertTrue(createdBytes.all { it == 0.toByte() })
        }

    @Test
    fun lostCreateResponseCleansEveryFreshReservedCredentialAndNeverCreatesAgain() =
        runBlocking {
            val account = StalwartMailAccount(
                accountId = "lost-account",
                address = "lost@local.test",
            )
            val store = FakeCredentialStore()
            val orphan = StalwartReservedCredential(
                credentialId = "lost-created-id",
                description =
                    "mail-sandbox/debug-dashboard/${store.storeId}/1",
            )
            val management = FakeManagementRemote().also {
                it.inventoryResults += availableInventory(account.accountId)
                it.inventoryResults += availableInventory(account.accountId, orphan)
                it.mutationResult = StalwartRemoteMutationResult.Verified
            }
            val owner = FakeOwnerRemote().also {
                it.results += StalwartRemoteCreateResult.ResponseLost
            }
            val passwordBytes = "lost-password".toCharArray()
            val result = service(
                store = store,
                management = management,
                probe = FakeProbeRemote(),
                owner = owner,
            ).enroll(
                account,
                StalwartNormalPassword.takeOwnership(passwordBytes),
            )

            val reconciliation =
                assertIs<StalwartMailAccessResult.ReconciliationRequired>(result)
            assertEquals(
                StalwartMailAccessState.EnrollmentRequired,
                reconciliation.projection.state,
            )
            assertEquals(StalwartMailAccessReason.CaptureFailed, reconciliation.reason)
            assertEquals(1, owner.createCalls)
            assertEquals(listOf(setOf(orphan)), management.revocations)
            assertEquals(0, store.replaceCalls)
            assertTrue(passwordBytes.all { it == '\u0000' })
        }

    @Test
    fun postDispatchCreateCancellationCompletesOnlyUncertainCleanup() =
        runBlocking {
            val account = StalwartMailAccount(
                accountId = "cancelled-create",
                address = "cancelled-create@local.test",
            )
            val store = FakeCredentialStore()
            val orphan = StalwartReservedCredential(
                credentialId = "cancelled-created-id",
                description =
                    "mail-sandbox/debug-dashboard/${store.storeId}/1",
            )
            val management = FakeManagementRemote().also {
                it.inventoryResults += availableInventory(account.accountId)
                it.inventoryResults +=
                    availableInventory(account.accountId, orphan)
                it.mutationResult = StalwartRemoteMutationResult.Verified
                it.requireActiveAfterInventoryCall = 1
            }
            val cancellation =
                CancellationException("post-dispatch create cancellation")
            val owner = FakeOwnerRemote().also {
                it.results += StalwartRemoteCreateResult.ResponseLost
                it.cancellationAfterDispatch = cancellation
            }
            val passwordChars = "cancelled-create-password".toCharArray()

            val operation = launch {
                service(
                    store = store,
                    management = management,
                    probe = FakeProbeRemote(),
                    owner = owner,
                ).enroll(
                    account,
                    StalwartNormalPassword.takeOwnership(passwordChars),
                )
            }
            operation.join()

            assertTrue(operation.isCancelled)
            assertEquals(2, management.inventoryCalls)
            assertEquals(listOf(setOf(orphan)), management.revocations)
            assertEquals(0, store.replaceCalls)
            assertTrue(passwordChars.all { it == '\u0000' })
        }

    @Test
    fun cancelledCreatedEnrollmentValidationStillRevokesExactCredential() =
        runBlocking {
            val account = StalwartMailAccount(
                accountId = "cancelled-created-validation",
                address = "cancelled-created-validation@local.test",
            )
            val store = FakeCredentialStore()
            val invalidCreated = StalwartReservedCredential(
                credentialId = "cancelled-invalid-enrollment",
                description =
                    "mail-sandbox/debug-dashboard/${store.storeId}/2",
            )
            val management = FakeManagementRemote().also {
                it.inventoryResults += availableInventory(account.accountId)
                it.inventoryResults +=
                    availableInventory(account.accountId, invalidCreated)
                it.mutationResult = StalwartRemoteMutationResult.Verified
                it.requireActiveAfterInventoryCall = 1
            }
            val createdBytes =
                "app_cancelled_invalid_enrollment".encodeToByteArray()
            val cancellation =
                CancellationException("cancel definitive enrollment create")
            val owner = FakeOwnerRemote().also {
                it.results += StalwartRemoteCreateResult.Created(
                    StalwartCreatedCredential(
                        credentialId = invalidCreated.credentialId,
                        description = invalidCreated.description,
                        secret = createdBytes,
                    ),
                )
                it.cancellationAfterDispatch = cancellation
            }
            val passwordChars =
                "cancelled-created-validation-password".toCharArray()

            val operation = launch {
                service(
                    store = store,
                    management = management,
                    probe = FakeProbeRemote(),
                    owner = owner,
                ).enroll(
                    account,
                    StalwartNormalPassword.takeOwnership(passwordChars),
                )
            }
            operation.join()

            assertTrue(operation.isCancelled)
            assertEquals(2, management.inventoryCalls)
            assertEquals(
                listOf(setOf(invalidCreated)),
                management.revocations,
            )
            assertEquals(0, store.replaceCalls)
            assertTrue(passwordChars.all { it == '\u0000' })
            assertTrue(createdBytes.all { it == 0.toByte() })
        }

    @Test
    fun definitiveCreatedCleanupTimeoutFailsClosedAndWipesInputs() =
        runBlocking {
            val account = StalwartMailAccount(
                accountId = "created-cleanup-timeout",
                address = "created-cleanup-timeout@local.test",
            )
            val store = FakeCredentialStore()
            val invalidCreated = StalwartReservedCredential(
                credentialId = "created-cleanup-timeout-id",
                description =
                    "mail-sandbox/debug-dashboard/${store.storeId}/2",
            )
            val management = FakeManagementRemote().also {
                it.inventoryResults += availableInventory(account.accountId)
                it.inventoryResults +=
                    availableInventory(account.accountId, invalidCreated)
                it.delayAfterInventoryCall = 1
                it.inventoryDelayMillis = 200
            }
            val createdBytes =
                "app_created_cleanup_timeout".encodeToByteArray()
            val owner = FakeOwnerRemote().also {
                it.results += StalwartRemoteCreateResult.Created(
                    StalwartCreatedCredential(
                        credentialId = invalidCreated.credentialId,
                        description = invalidCreated.description,
                        secret = createdBytes,
                    ),
                )
            }
            val passwordChars =
                "created-cleanup-timeout-password".toCharArray()

            val result = service(
                store = store,
                management = management,
                probe = FakeProbeRemote(),
                owner = owner,
                definitiveCreatedCleanupTimeout = 10.milliseconds,
            ).enroll(
                account,
                StalwartNormalPassword.takeOwnership(passwordChars),
            )

            val reconciliation =
                assertIs<StalwartMailAccessResult.ReconciliationRequired>(
                    result,
                )
            assertEquals(
                StalwartMailAccessReason.CleanupUnproven,
                reconciliation.reason,
            )
            assertEquals(2, management.inventoryCalls)
            assertTrue(management.revocations.isEmpty())
            assertEquals(0, store.replaceCalls)
            assertTrue(passwordChars.all { it == '\u0000' })
            assertTrue(createdBytes.all { it == 0.toByte() })
        }

    @Test
    fun cancelledCreatedRotationValidationStillRevokesOnlySuccessor() =
        runBlocking {
            val account = StalwartMailAccount(
                accountId = "cancelled-rotation-validation",
                address = "cancelled-rotation-validation@local.test",
            )
            val store = FakeCredentialStore()
            val old = generationSpec(store.storeId, 1)
            store.record = recordSpec(account, CredentialPhase.Active, old)
            val invalidSuccessor = StalwartReservedCredential(
                credentialId = "cancelled-invalid-successor",
                description =
                    "mail-sandbox/debug-dashboard/${store.storeId}/3",
            )
            val management = FakeManagementRemote().also {
                it.inventory = availableInventory(
                    account.accountId,
                    reserved(old),
                )
                it.mutationResult = StalwartRemoteMutationResult.Verified
                it.requireActiveOnRevoke = true
            }
            val createdBytes =
                "app_cancelled_invalid_successor".encodeToByteArray()
            val cancellation =
                CancellationException("cancel definitive rotation create")
            val owner = FakeOwnerRemote().also {
                it.results += StalwartRemoteCreateResult.Created(
                    StalwartCreatedCredential(
                        credentialId = invalidSuccessor.credentialId,
                        description = invalidSuccessor.description,
                        secret = createdBytes,
                    ),
                )
                it.cancellationAfterDispatch = cancellation
            }
            val passwordChars =
                "cancelled-rotation-validation-password".toCharArray()

            val operation = launch {
                service(
                    store = store,
                    management = management,
                    probe = FakeProbeRemote(),
                    owner = owner,
                ).rotate(
                    account,
                    StalwartNormalPassword.takeOwnership(passwordChars),
                )
            }
            operation.join()

            assertTrue(operation.isCancelled)
            assertEquals(
                listOf(setOf(reserved(old), invalidSuccessor)),
                management.revocationExpectedInventories,
            )
            assertEquals(
                listOf(setOf(invalidSuccessor)),
                management.revocations,
            )
            assertEquals(
                old.credentialId,
                store.recordSpecs[account.accountId]?.active?.credentialId,
            )
            assertEquals(0, store.replaceCalls)
            assertTrue(passwordChars.all { it == '\u0000' })
            assertTrue(createdBytes.all { it == 0.toByte() })
        }

    @Test
    fun cancelledCreatedEnrollmentCasFailureStillCleansExactCredential() =
        runBlocking {
            val account = StalwartMailAccount(
                accountId = "cancelled-enrollment-cas",
                address = "cancelled-enrollment-cas@local.test",
            )
            val otherAccount = StalwartMailAccount(
                accountId = "cancelled-enrollment-other",
                address = "cancelled-enrollment-other@local.test",
            )
            val store = FakeCredentialStore().also {
                it.writeResults += CredentialStoreWriteResult.StoreUnavailable
            }
            val other = generationSpec(store.storeId, 7)
            val createdRemote = StalwartReservedCredential(
                credentialId = "cancelled-enrollment-created",
                description =
                    "mail-sandbox/debug-dashboard/${store.storeId}/1",
            )
            val management = FakeManagementRemote().also {
                it.inventoryResults += availableInventory(account.accountId)
                it.inventoryResults +=
                    availableInventory(account.accountId, createdRemote)
                it.mutationResult = StalwartRemoteMutationResult.Verified
                it.requireActiveAfterInventoryCall = 1
            }
            val createdBytes =
                "app_cancelled_enrollment_cas".encodeToByteArray()
            val owner = FakeOwnerRemote().also {
                it.results += StalwartRemoteCreateResult.Created(
                    StalwartCreatedCredential(
                        credentialId = createdRemote.credentialId,
                        description = createdRemote.description,
                        secret = createdBytes,
                    ),
                )
            }
            val cancellation =
                CancellationException("cancel failed enrollment CAS")
            val passwordChars =
                "cancelled-enrollment-cas-password".toCharArray()

            val operation = launch {
                val operationContext = currentCoroutineContext()
                store.beforeFirstReplace = {
                    it.putRecord(
                        recordSpec(
                            otherAccount,
                            CredentialPhase.Active,
                            other,
                        ),
                    )
                    it.revision += 1
                    operationContext.cancel(cancellation)
                }
                service(
                    store = store,
                    management = management,
                    probe = FakeProbeRemote(),
                    owner = owner,
                ).enroll(
                    account,
                    StalwartNormalPassword.takeOwnership(passwordChars),
                )
            }
            operation.join()

            assertTrue(operation.isCancelled)
            assertEquals(2, management.inventoryCalls)
            assertEquals(
                listOf(setOf(createdRemote)),
                management.revocations,
            )
            assertEquals(2, store.replaceCalls)
            assertEquals(
                setOf(otherAccount.accountId),
                store.recordSpecs.keys,
            )
            assertTrue(passwordChars.all { it == '\u0000' })
            assertTrue(createdBytes.all { it == 0.toByte() })
        }

    @Test
    fun cancelledCreatedRotationCasFailureStillRevokesOnlySuccessor() =
        runBlocking {
            val account = StalwartMailAccount(
                accountId = "cancelled-rotation-cas",
                address = "cancelled-rotation-cas@local.test",
            )
            val otherAccount = StalwartMailAccount(
                accountId = "cancelled-rotation-other",
                address = "cancelled-rotation-other@local.test",
            )
            val store = FakeCredentialStore().also {
                it.writeResults += CredentialStoreWriteResult.StoreUnavailable
            }
            val old = generationSpec(store.storeId, 1)
            val other = generationSpec(store.storeId, 9)
            store.record = recordSpec(account, CredentialPhase.Active, old)
            val successor = StalwartReservedCredential(
                credentialId = "cancelled-rotation-successor",
                description =
                    "mail-sandbox/debug-dashboard/${store.storeId}/2",
            )
            val management = FakeManagementRemote().also {
                it.inventory = availableInventory(
                    account.accountId,
                    reserved(old),
                )
                it.mutationResult = StalwartRemoteMutationResult.Verified
                it.requireActiveOnRevoke = true
            }
            val createdBytes =
                "app_cancelled_rotation_cas".encodeToByteArray()
            val owner = FakeOwnerRemote().also {
                it.results += StalwartRemoteCreateResult.Created(
                    StalwartCreatedCredential(
                        credentialId = successor.credentialId,
                        description = successor.description,
                        secret = createdBytes,
                    ),
                )
            }
            val cancellation =
                CancellationException("cancel failed rotation CAS")
            val passwordChars =
                "cancelled-rotation-cas-password".toCharArray()

            val operation = launch {
                val operationContext = currentCoroutineContext()
                store.beforeFirstReplace = {
                    it.putRecord(
                        recordSpec(
                            otherAccount,
                            CredentialPhase.Active,
                            other,
                        ),
                    )
                    it.revision += 1
                    operationContext.cancel(cancellation)
                }
                service(
                    store = store,
                    management = management,
                    probe = FakeProbeRemote(),
                    owner = owner,
                ).rotate(
                    account,
                    StalwartNormalPassword.takeOwnership(passwordChars),
                )
            }
            operation.join()

            assertTrue(operation.isCancelled)
            assertEquals(
                listOf(setOf(reserved(old), successor)),
                management.revocationExpectedInventories,
            )
            assertEquals(
                listOf(setOf(successor)),
                management.revocations,
            )
            assertEquals(
                old.credentialId,
                store.recordSpecs[account.accountId]?.active?.credentialId,
            )
            assertEquals(2, store.replaceCalls)
            assertEquals(
                setOf(account.accountId, otherAccount.accountId),
                store.recordSpecs.keys,
            )
            assertTrue(passwordChars.all { it == '\u0000' })
            assertTrue(createdBytes.all { it == 0.toByte() })
        }

    @Test
    fun captureFailureCleansRemoteAndAmbiguousCleanupStaysRecoveryRequired() =
        runBlocking {
            val account = StalwartMailAccount(
                accountId = "capture-account",
                address = "capture@local.test",
            )
            val store = FakeCredentialStore().also {
                it.writeResults += CredentialStoreWriteResult.StoreUnavailable
            }
            val remoteCredential = StalwartReservedCredential(
                credentialId = "capture-created-id",
                description =
                    "mail-sandbox/debug-dashboard/${store.storeId}/1",
            )
            val management = FakeManagementRemote().also {
                it.inventoryResults += availableInventory(account.accountId)
                it.inventoryResults +=
                    availableInventory(account.accountId, remoteCredential)
                it.mutationResult =
                    StalwartRemoteMutationResult.ReconciliationRequired
            }
            val createdBytes = "app_capture_secret".encodeToByteArray()
            val owner = FakeOwnerRemote().also {
                it.results += StalwartRemoteCreateResult.Created(
                    StalwartCreatedCredential(
                        credentialId = remoteCredential.credentialId,
                        description = remoteCredential.description,
                        secret = createdBytes,
                    ),
                )
            }
            val passwordBytes = "capture-password".toCharArray()

            val result = service(
                store = store,
                management = management,
                probe = FakeProbeRemote(),
                owner = owner,
            ).enroll(
                account,
                StalwartNormalPassword.takeOwnership(passwordBytes),
            )

            val reconciliation =
                assertIs<StalwartMailAccessResult.ReconciliationRequired>(result)
            assertEquals(
                StalwartMailAccessState.RecoveryRequired,
                reconciliation.projection.state,
            )
            assertEquals(StalwartMailAccessReason.CleanupUnproven, reconciliation.reason)
            assertEquals(1, owner.createCalls)
            assertEquals(1, store.replaceCalls)
            assertEquals(listOf(setOf(remoteCredential)), management.revocations)
            assertTrue(passwordBytes.all { it == '\u0000' })
            assertTrue(createdBytes.all { it == 0.toByte() })
        }

    @Test
    fun uncertainCaptureThatActuallyPersistedIsErasedOnlyByItsExactStamp() =
        runBlocking {
            val account = StalwartMailAccount(
                accountId = "uncertain-capture",
                address = "uncertain@local.test",
            )
            val store = FakeCredentialStore().also {
                it.applyThenUnavailableOnce = true
            }
            val remoteCredential = StalwartReservedCredential(
                credentialId = "uncertain-created",
                description =
                    "mail-sandbox/debug-dashboard/${store.storeId}/1",
            )
            val management = FakeManagementRemote().also {
                it.inventoryResults += availableInventory(account.accountId)
                it.inventoryResults +=
                    availableInventory(account.accountId, remoteCredential)
                it.mutationResult = StalwartRemoteMutationResult.Verified
            }
            val owner = FakeOwnerRemote().also {
                it.results += StalwartRemoteCreateResult.Created(
                    StalwartCreatedCredential(
                        credentialId = remoteCredential.credentialId,
                        description = remoteCredential.description,
                        secret = "app_uncertain_capture".encodeToByteArray(),
                    ),
                )
            }

            val result = service(
                store = store,
                management = management,
                probe = FakeProbeRemote(),
                owner = owner,
            ).enroll(
                account,
                StalwartNormalPassword.takeOwnership(
                    "uncertain-password".toCharArray(),
                ),
            )

            val reconciliation =
                assertIs<StalwartMailAccessResult.ReconciliationRequired>(result)
            assertEquals(
                StalwartMailAccessState.EnrollmentRequired,
                reconciliation.projection.state,
            )
            assertEquals(2, store.replaceCalls)
            assertTrue(store.recordSpecs.isEmpty())
            assertEquals(listOf(setOf(remoteCredential)), management.revocations)
        }

    @Test
    fun uncertainCaptureNeverErasesPubliclyMatchingRecordWithDifferentSecret() =
        runBlocking {
            val account = StalwartMailAccount(
                accountId = "uncertain-secret-race",
                address = "uncertain-secret-race@local.test",
            )
            val store = FakeCredentialStore().also {
                it.applyThenUnavailableOnce = true
            }
            val remoteCredential = StalwartReservedCredential(
                credentialId = "uncertain-secret-created",
                description =
                    "mail-sandbox/debug-dashboard/${store.storeId}/1",
            )
            val concurrentSecret =
                "app_concurrent_uncertain_secret".encodeToByteArray()
            val management = FakeManagementRemote().also {
                it.inventoryResults += availableInventory(account.accountId)
                it.inventoryResults +=
                    availableInventory(account.accountId, remoteCredential)
                it.mutationResult = StalwartRemoteMutationResult.Verified
                it.onRevoke = {
                    store.record = recordSpec(
                        account = account,
                        phase = CredentialPhase.Active,
                        active = GenerationSpec(
                            credentialId = remoteCredential.credentialId,
                            description = remoteCredential.description,
                            generation = 1,
                            secret = concurrentSecret,
                        ),
                    )
                    store.revision += 1
                }
            }
            val owner = FakeOwnerRemote().also {
                it.results += StalwartRemoteCreateResult.Created(
                    StalwartCreatedCredential(
                        credentialId = remoteCredential.credentialId,
                        description = remoteCredential.description,
                        secret = "app_uncertain_original".encodeToByteArray(),
                    ),
                )
            }

            val result = service(
                store = store,
                management = management,
                probe = FakeProbeRemote(),
                owner = owner,
            ).enroll(
                account,
                StalwartNormalPassword.takeOwnership(
                    "uncertain-secret-password".toCharArray(),
                ),
            )

            val reconciliation =
                assertIs<StalwartMailAccessResult.ReconciliationRequired>(result)
            assertEquals(
                StalwartMailAccessState.RecoveryRequired,
                reconciliation.projection.state,
            )
            assertEquals(
                StalwartMailAccessReason.CleanupUnproven,
                reconciliation.reason,
            )
            assertEquals(1, store.replaceCalls)
            assertEquals(
                remoteCredential.credentialId,
                store.record?.active?.credentialId,
            )
            assertContentEquals(
                concurrentSecret,
                store.record?.active?.secret,
            )
            assertEquals(listOf(setOf(remoteCredential)), management.revocations)
        }

    @Test
    fun lostResponseNeverErasesAnUnknownConcurrentLocalRecord() = runBlocking {
        val account = StalwartMailAccount(
            accountId = "lost-local-race",
            address = "lost-local-race@local.test",
        )
        val store = FakeCredentialStore()
        val concurrent = generationSpec(store.storeId, 7)
        val remoteCredential = StalwartReservedCredential(
            credentialId = "lost-local-created",
            description =
                "mail-sandbox/debug-dashboard/${store.storeId}/1",
        )
        val management = FakeManagementRemote().also {
            it.inventoryResults += availableInventory(account.accountId)
            it.inventoryResults +=
                availableInventory(account.accountId, remoteCredential)
            it.mutationResult = StalwartRemoteMutationResult.Verified
        }
        val owner = FakeOwnerRemote().also {
            it.onCreate = {
                store.putRecord(
                    recordSpec(
                        account,
                        CredentialPhase.Active,
                        concurrent,
                    ),
                )
                store.revision += 1
            }
            it.results += StalwartRemoteCreateResult.ResponseLost
        }

        val result = service(
            store = store,
            management = management,
            probe = FakeProbeRemote(),
            owner = owner,
        ).enroll(
            account,
            StalwartNormalPassword.takeOwnership(
                "lost-local-password".toCharArray(),
            ),
        )

        val reconciliation =
            assertIs<StalwartMailAccessResult.ReconciliationRequired>(result)
        assertEquals(
            StalwartMailAccessState.RecoveryRequired,
            reconciliation.projection.state,
        )
        assertEquals(0, store.replaceCalls)
        assertEquals(concurrent.credentialId, store.record?.active?.credentialId)
    }

    @Test
    fun drainTimeoutWipesPasswordAndMutatesNeitherRemoteNorStore() = runBlocking {
        val now = AtomicLong(0)
        val leases = StalwartCredentialLeaseRegistry(
            nanoClock = StalwartLeaseNanoClock(now::get),
            waiter = StalwartLeaseChangeWaiter { _, remaining ->
                now.addAndGet(remaining)
            },
        )
        val activeLease = acquiredLease(leases, "timeout-account", 1)
        val store = FakeCredentialStore()
        val account = StalwartMailAccount(
            accountId = "timeout-account",
            address = "timeout@local.test",
        )
        store.record = recordSpec(
            account = account,
            phase = CredentialPhase.Active,
            active = generationSpec(store.storeId, 1),
        )
        val management = FakeManagementRemote()
        val owner = FakeOwnerRemote()
        val passwordBytes = "timeout-password".toCharArray()
        try {
            val result = service(
                store = store,
                management = management,
                probe = FakeProbeRemote(),
                owner = owner,
                leases = leases,
            ).enroll(
                account,
                StalwartNormalPassword.takeOwnership(passwordBytes),
            )

            val failure = assertIs<StalwartMailAccessResult.RetryableFailure>(result)
            assertEquals(StalwartMailAccessReason.LeaseDrainTimedOut, failure.reason)
            assertEquals(
                StalwartMailAccessState.RecoveryRequired,
                failure.projection.state,
            )
            assertEquals(0, management.inventoryCalls)
            assertEquals(0, owner.createCalls)
            assertEquals(0, store.replaceCalls)
            assertTrue(passwordBytes.all { it == '\u0000' })
        } finally {
            activeLease.close()
        }
    }

    @Test
    fun crossAccountRevisionRaceMergesWithoutRepeatingRemoteCreate() = runBlocking {
        val account = StalwartMailAccount(
            accountId = "race-account-a",
            address = "race-a@local.test",
        )
        val otherAccount = StalwartMailAccount(
            accountId = "race-account-b",
            address = "race-b@local.test",
        )
        val store = FakeCredentialStore()
        val other = generationSpec(store.storeId, 5)
        store.beforeFirstReplace = {
            it.putRecord(
                recordSpec(
                    account = otherAccount,
                    phase = CredentialPhase.Active,
                    active = other,
                ),
            )
            it.revision += 1
        }
        val management = FakeManagementRemote().also {
            it.inventory = availableInventory(account.accountId)
        }
        val owner = FakeOwnerRemote().also {
            it.results += StalwartRemoteCreateResult.Created(
                StalwartCreatedCredential(
                    credentialId = "race-created-a",
                    description =
                        "mail-sandbox/debug-dashboard/${store.storeId}/1",
                    secret = "app_race_a".encodeToByteArray(),
                ),
            )
        }
        val probe = FakeProbeRemote().also {
            it.results += "app_race_a".encodeToByteArray() to
                StalwartCredentialProbeResult.Authenticated(
                    STALWART_REQUIRED_MAIL_CAPABILITIES,
                )
        }

        val result = service(
            store = store,
            management = management,
            probe = probe,
            owner = owner,
        ).enroll(
            account,
            StalwartNormalPassword.takeOwnership("race-password".toCharArray()),
        )

        assertIs<StalwartMailAccessResult.Completed>(result)
        assertEquals(1, owner.createCalls)
        assertEquals(2, store.replaceCalls)
        assertEquals(
            setOf(account.accountId, otherAccount.accountId),
            store.recordSpecs.keys,
        )
    }

    @Test
    fun repairBatchCleansEveryReservedCredentialThenCreatesAtMostOneReplacement() =
        runBlocking {
            val events = mutableListOf<String>()
            val account = StalwartMailAccount(
                accountId = "repair-account",
                address = "repair@local.test",
            )
            val store = FakeCredentialStore(events)
            val old = generationSpec(store.storeId, 1)
            store.record = recordSpec(account, CredentialPhase.Active, old)
            val orphan = StalwartReservedCredential(
                credentialId = "repair-orphan",
                description =
                    "mail-sandbox/debug-dashboard/${store.storeId}/2",
            )
            val management = FakeManagementRemote(events).also {
                it.inventory = availableInventory(
                    account.accountId,
                    reserved(old),
                    orphan,
                )
                it.mutationResult = StalwartRemoteMutationResult.Verified
            }
            val owner = FakeOwnerRemote(events).also {
                it.results += StalwartRemoteCreateResult.Created(
                    StalwartCreatedCredential(
                        credentialId = "repair-successor",
                        description =
                            "mail-sandbox/debug-dashboard/${store.storeId}/3",
                        secret = "app_repair_successor".encodeToByteArray(),
                    ),
                )
            }
            val probe = FakeProbeRemote(events).also {
                it.results += "app_repair_successor".encodeToByteArray() to
                    StalwartCredentialProbeResult.Authenticated(
                        STALWART_REQUIRED_MAIL_CAPABILITIES,
                    )
            }
            val passwordBytes = "repair-password".toCharArray()

            val result = service(
                store = store,
                management = management,
                probe = probe,
                owner = owner,
            ).repair(
                account,
                StalwartNormalPassword.takeOwnership(passwordBytes),
            )

            assertIs<StalwartMailAccessResult.Completed>(result)
            assertEquals(
                listOf(
                    "inventory:repair-account",
                    "revoke:repair-account",
                    "create:repair-account",
                    "persist:Active",
                    "probe:repair-account",
                ),
                events,
            )
            assertEquals(listOf(setOf(reserved(old), orphan)), management.revocations)
            assertEquals(1, owner.createCalls)
            assertEquals("repair-successor", store.record?.active?.credentialId)
            assertTrue(passwordBytes.all { it == '\u0000' })
        }

    @Test
    fun repairStopsAfterUnprovenBatchCleanupAndLeavesLocalBytesUnchanged() =
        runBlocking {
            val account = StalwartMailAccount(
                accountId = "repair-conflict",
                address = "repair-conflict@local.test",
            )
            val store = FakeCredentialStore()
            val old = generationSpec(store.storeId, 4)
            store.record = recordSpec(account, CredentialPhase.Active, old)
            val management = FakeManagementRemote().also {
                it.inventory = availableInventory(
                    account.accountId,
                    reserved(old),
                )
                it.mutationResult =
                    StalwartRemoteMutationResult.ReconciliationRequired
            }
            val owner = FakeOwnerRemote()
            val passwordBytes = "repair-conflict-password".toCharArray()

            val result = service(
                store = store,
                management = management,
                probe = FakeProbeRemote(),
                owner = owner,
            ).repair(
                account,
                StalwartNormalPassword.takeOwnership(passwordBytes),
            )

            val reconciliation =
                assertIs<StalwartMailAccessResult.ReconciliationRequired>(result)
            assertEquals(
                StalwartMailAccessState.RecoveryRequired,
                reconciliation.projection.state,
            )
            assertEquals(0, owner.createCalls)
            assertEquals(0, store.replaceCalls)
            assertEquals(old.credentialId, store.record?.active?.credentialId)
            assertTrue(passwordBytes.all { it == '\u0000' })
        }

    @Test
    fun removeRevokesBeforeLocalEraseAndDurablyKeepsRemovalPendingOnEraseFailure() =
        runBlocking {
            val events = mutableListOf<String>()
            val account = StalwartMailAccount(
                accountId = "remove-account",
                address = "remove@local.test",
            )
            val store = FakeCredentialStore(events)
            val active = generationSpec(store.storeId, 1)
            store.record = recordSpec(account, CredentialPhase.Active, active)
            store.writeResults += CredentialStoreWriteResult.Written(1)
            store.writeResults += CredentialStoreWriteResult.StoreUnavailable
            val management = FakeManagementRemote(events).also {
                it.inventory = availableInventory(
                    account.accountId,
                    reserved(active),
                )
                it.mutationResult = StalwartRemoteMutationResult.Verified
            }

            val result = service(
                store = store,
                management = management,
                probe = FakeProbeRemote(),
            ).remove(account)

            val reconciliation =
                assertIs<StalwartMailAccessResult.ReconciliationRequired>(result)
            assertEquals(
                StalwartMailAccessState.RemovalPending,
                reconciliation.projection.state,
            )
            assertEquals(
                listOf(
                    "inventory:remove-account",
                    "revoke:remove-account",
                    "persist:RemovalPending",
                ),
                events,
            )
            assertEquals(listOf(setOf(reserved(active))), management.revocations)
            assertEquals(2, store.replaceCalls)
            assertEquals(CredentialPhase.RemovalPending, store.record?.phase)
        }

    @Test
    fun successfulRemoveErasesOnlyAfterVerifiedRemoteAbsence() = runBlocking {
        val events = mutableListOf<String>()
        val account = StalwartMailAccount(
            accountId = "remove-success",
            address = "remove-success@local.test",
        )
        val store = FakeCredentialStore(events)
        val active = generationSpec(store.storeId, 1)
        store.record = recordSpec(account, CredentialPhase.Active, active)
        val management = FakeManagementRemote(events).also {
            it.inventory = availableInventory(
                account.accountId,
                reserved(active),
            )
            it.mutationResult = StalwartRemoteMutationResult.Verified
        }

        val result = service(
            store = store,
            management = management,
            probe = FakeProbeRemote(),
        ).remove(account)

        val completed = assertIs<StalwartMailAccessResult.Completed>(result)
        assertEquals(
            StalwartMailAccessState.EnrollmentRequired,
            completed.projection.state,
        )
        assertEquals(
            listOf(
                "inventory:remove-success",
                "revoke:remove-success",
                "persist:RemovalPending",
                "persist:Absent",
            ),
            events,
        )
        assertTrue(store.recordSpecs.isEmpty())
    }

    @Test
    fun rotationPersistsExactOrientationsBeforeProbeAndOldRevocation() =
        runBlocking {
            val events = mutableListOf<String>()
            val account = StalwartMailAccount(
                accountId = "rotate-success",
                address = "rotate-success@local.test",
            )
            val store = FakeCredentialStore(events)
            val old = generationSpec(store.storeId, 1)
            store.record = recordSpec(account, CredentialPhase.Active, old)
            val successor = StalwartReservedCredential(
                credentialId = "rotate-successor",
                description =
                    "mail-sandbox/debug-dashboard/${store.storeId}/2",
            )
            val management = FakeManagementRemote(events).also {
                it.inventoryResults +=
                    availableInventory(account.accountId, reserved(old))
                it.inventoryResults += availableInventory(
                    account.accountId,
                    reserved(old),
                    successor,
                )
                it.mutationResult = StalwartRemoteMutationResult.Verified
            }
            val successorBytes = "app_rotate_successor".encodeToByteArray()
            val owner = FakeOwnerRemote(events).also {
                it.results += StalwartRemoteCreateResult.Created(
                    StalwartCreatedCredential(
                        credentialId = successor.credentialId,
                        description = successor.description,
                        secret = successorBytes,
                    ),
                )
            }
            val probe = FakeProbeRemote(events).also {
                it.results += "app_rotate_successor".encodeToByteArray() to
                    StalwartCredentialProbeResult.Authenticated(
                        STALWART_REQUIRED_MAIL_CAPABILITIES,
                    )
                it.results += old.secret.copyOf() to
                    StalwartCredentialProbeResult.Rejected
            }
            val passwordBytes = "rotate-password".toCharArray()

            val result = service(
                store = store,
                management = management,
                probe = probe,
                owner = owner,
            ).rotate(
                account,
                StalwartNormalPassword.takeOwnership(passwordBytes),
            )

            assertIs<StalwartMailAccessResult.Completed>(result)
            assertEquals(
                listOf(
                    "inventory:rotate-success",
                    "create:rotate-success",
                    "persist:Staged",
                    "probe:rotate-success",
                    "persist:Retiring",
                    "inventory:rotate-success",
                    "revoke:rotate-success",
                    "probe:rotate-success",
                    "probe:rotate-success",
                    "persist:Active",
                ),
                events,
            )
            assertEquals(listOf(setOf(reserved(old))), management.revocations)
            assertEquals(
                listOf(setOf(reserved(old), successor)),
                management.revocationExpectedInventories,
            )
            assertEquals(CredentialPhase.Active, store.record?.phase)
            assertEquals(successor.credentialId, store.record?.active?.credentialId)
            assertEquals(2, store.record?.active?.generation)
            assertNull(store.record?.other)
            assertTrue(passwordBytes.all { it == '\u0000' })
            assertTrue(successorBytes.all { it == 0.toByte() })
        }

    @Test
    fun rotationQuotaAndUnknownRemoteLeaveTheActiveGenerationUntouched() =
        runBlocking {
            val account = StalwartMailAccount(
                accountId = "rotate-preflight",
                address = "rotate-preflight@local.test",
            )
            val old = generationSpec(STORE_ID, 4)
            val quotaStore = FakeCredentialStore().also {
                it.record = recordSpec(account, CredentialPhase.Active, old)
            }
            val quotaManagement = FakeManagementRemote().also {
                it.inventory = availableInventoryWithQuota(
                    accountId = account.accountId,
                    appPasswordCount = 4,
                    appPasswordLimit = 4,
                    credentials = arrayOf(reserved(old)),
                )
            }
            val quotaOwner = FakeOwnerRemote()
            val beforeQuota = quotaStore.record?.active?.secret?.copyOf()

            val quotaResult = service(
                store = quotaStore,
                management = quotaManagement,
                probe = FakeProbeRemote(),
                owner = quotaOwner,
            ).rotate(
                account,
                StalwartNormalPassword.takeOwnership(
                    "quota-rotation".toCharArray(),
                ),
            )

            val quotaFailure =
                assertIs<StalwartMailAccessResult.RetryableFailure>(quotaResult)
            assertEquals(
                StalwartMailAccessReason.CredentialQuotaFull,
                quotaFailure.reason,
            )
            assertEquals(0, quotaOwner.createCalls)
            assertEquals(0, quotaStore.replaceCalls)
            assertTrue(
                requireNotNull(beforeQuota).contentEquals(
                    requireNotNull(quotaStore.record?.active?.secret),
                ),
            )

            val unknownStore = FakeCredentialStore().also {
                it.record = recordSpec(account, CredentialPhase.Active, old)
            }
            val unknown = StalwartReservedCredential(
                credentialId = "unknown-reserved",
                description =
                    "mail-sandbox/debug-dashboard/${unknownStore.storeId}/9",
            )
            val unknownManagement = FakeManagementRemote().also {
                it.inventory = availableInventory(
                    account.accountId,
                    reserved(old),
                    unknown,
                )
            }
            val unknownOwner = FakeOwnerRemote()

            val unknownResult = service(
                store = unknownStore,
                management = unknownManagement,
                probe = FakeProbeRemote(),
                owner = unknownOwner,
            ).rotate(
                account,
                StalwartNormalPassword.takeOwnership(
                    "unknown-rotation".toCharArray(),
                ),
            )

            val reconciliation =
                assertIs<StalwartMailAccessResult.ReconciliationRequired>(
                    unknownResult,
                )
            assertEquals(
                StalwartMailAccessState.RecoveryRequired,
                reconciliation.projection.state,
            )
            assertEquals(0, unknownOwner.createCalls)
            assertEquals(0, unknownStore.replaceCalls)
            assertTrue(unknownManagement.revocations.isEmpty())
        }

    @Test
    fun rotationPreStageFailureCleansOnlyTheExactSuccessor() = runBlocking {
        val account = StalwartMailAccount(
            accountId = "rotate-pre-stage",
            address = "rotate-pre-stage@local.test",
        )
        val store = FakeCredentialStore()
        val old = generationSpec(store.storeId, 1)
        store.record = recordSpec(account, CredentialPhase.Active, old)
        store.writeResults += CredentialStoreWriteResult.StoreUnavailable
        val successor = StalwartReservedCredential(
            credentialId = "pre-stage-successor",
            description =
                "mail-sandbox/debug-dashboard/${store.storeId}/2",
        )
        val management = FakeManagementRemote().also {
            it.inventory = availableInventory(
                account.accountId,
                reserved(old),
            )
            it.mutationResult = StalwartRemoteMutationResult.Verified
        }
        val createdBytes = "app_pre_stage_successor".encodeToByteArray()
        val owner = FakeOwnerRemote().also {
            it.results += StalwartRemoteCreateResult.Created(
                StalwartCreatedCredential(
                    credentialId = successor.credentialId,
                    description = successor.description,
                    secret = createdBytes,
                ),
            )
        }

        val result = service(
            store = store,
            management = management,
            probe = FakeProbeRemote(),
            owner = owner,
        ).rotate(
            account,
            StalwartNormalPassword.takeOwnership(
                "pre-stage-password".toCharArray(),
            ),
        )

        assertIs<StalwartMailAccessResult.ReconciliationRequired>(result)
        assertEquals(listOf(setOf(successor)), management.revocations)
        assertEquals(
            listOf(setOf(reserved(old), successor)),
            management.revocationExpectedInventories,
        )
        assertEquals(1, owner.createCalls)
        assertEquals(1, store.replaceCalls)
        assertEquals(CredentialPhase.Active, store.record?.phase)
        assertEquals(old.credentialId, store.record?.active?.credentialId)
        assertTrue(createdBytes.all { it == 0.toByte() })
    }

    @Test
    fun rotationFinalCollapseFailureLeavesRetiringDurable() = runBlocking {
        val account = StalwartMailAccount(
            accountId = "rotate-final-failure",
            address = "rotate-final-failure@local.test",
        )
        val store = FakeCredentialStore()
        val old = generationSpec(store.storeId, 1)
        store.record = recordSpec(account, CredentialPhase.Active, old)
        store.writeResults += CredentialStoreWriteResult.Written(1)
        store.writeResults += CredentialStoreWriteResult.Written(2)
        store.writeResults += CredentialStoreWriteResult.StoreUnavailable
        val successor = StalwartReservedCredential(
            credentialId = "final-failure-successor",
            description =
                "mail-sandbox/debug-dashboard/${store.storeId}/2",
        )
        val management = FakeManagementRemote().also {
            it.inventoryResults +=
                availableInventory(account.accountId, reserved(old))
            it.inventoryResults += availableInventory(
                account.accountId,
                reserved(old),
                successor,
            )
            it.mutationResult = StalwartRemoteMutationResult.Verified
        }
        val owner = FakeOwnerRemote().also {
            it.results += StalwartRemoteCreateResult.Created(
                StalwartCreatedCredential(
                    credentialId = successor.credentialId,
                    description = successor.description,
                    secret = "app_final_failure".encodeToByteArray(),
                ),
            )
        }
        val probe = FakeProbeRemote().also {
            it.results += "app_final_failure".encodeToByteArray() to
                StalwartCredentialProbeResult.Authenticated(
                    STALWART_REQUIRED_MAIL_CAPABILITIES,
                )
            it.results += old.secret.copyOf() to
                StalwartCredentialProbeResult.Rejected
        }

        val result = service(
            store = store,
            management = management,
            probe = probe,
            owner = owner,
        ).rotate(
            account,
            StalwartNormalPassword.takeOwnership(
                "final-failure-password".toCharArray(),
            ),
        )

        val reconciliation =
            assertIs<StalwartMailAccessResult.ReconciliationRequired>(result)
        assertEquals(
            StalwartMailAccessState.Rotating,
            reconciliation.projection.state,
        )
        assertEquals(3, store.replaceCalls)
        assertEquals(CredentialPhase.Retiring, store.record?.phase)
        assertEquals(successor.credentialId, store.record?.active?.credentialId)
        assertEquals(old.credentialId, store.record?.other?.credentialId)
        assertEquals(listOf(setOf(reserved(old))), management.revocations)
    }

    @Test
    fun rotationGenerationOverflowFailsBeforeCreate() = runBlocking {
        val account = StalwartMailAccount(
            accountId = "rotate-overflow",
            address = "rotate-overflow@local.test",
        )
        val store = FakeCredentialStore()
        val old = generationSpec(store.storeId, Long.MAX_VALUE)
        store.record = recordSpec(account, CredentialPhase.Active, old)
        val management = FakeManagementRemote().also {
            it.inventory = availableInventory(
                account.accountId,
                reserved(old),
            )
        }
        val owner = FakeOwnerRemote()

        val result = service(
            store = store,
            management = management,
            probe = FakeProbeRemote(),
            owner = owner,
        ).rotate(
            account,
            StalwartNormalPassword.takeOwnership(
                "overflow-password".toCharArray(),
            ),
        )

        assertIs<StalwartMailAccessResult.ReconciliationRequired>(result)
        assertEquals(0, owner.createCalls)
        assertEquals(0, store.replaceCalls)
        assertTrue(management.revocations.isEmpty())
    }

    @Test
    fun restartPromotesValidStagedThenRetiresOldWithoutCreating() =
        runBlocking {
            val events = mutableListOf<String>()
            val account = StalwartMailAccount(
                accountId = "restart-staged-valid",
                address = "restart-staged-valid@local.test",
            )
            val store = FakeCredentialStore(events)
            val old = generationSpec(store.storeId, 1)
            val successor = generationSpec(store.storeId, 2)
            store.record = recordSpec(
                account,
                CredentialPhase.Staged,
                old,
                successor,
            )
            val management = FakeManagementRemote(events).also {
                it.inventoryResults += availableInventory(
                    account.accountId,
                    reserved(old),
                    reserved(successor),
                )
                it.inventoryResults += availableInventory(
                    account.accountId,
                    reserved(old),
                    reserved(successor),
                )
                it.mutationResult = StalwartRemoteMutationResult.Verified
            }
            val probe = FakeProbeRemote(events).also {
                it.results += successor.secret.copyOf() to
                    StalwartCredentialProbeResult.Authenticated(
                        STALWART_REQUIRED_MAIL_CAPABILITIES,
                    )
                it.results += old.secret.copyOf() to
                    StalwartCredentialProbeResult.Rejected
            }
            val owner = FakeOwnerRemote()

            val result = service(
                store = store,
                management = management,
                probe = probe,
                owner = owner,
            ).reconcileAfterRestart(account)

            assertIs<StalwartMailAccessResult.Completed>(result)
            assertEquals(
                listOf(
                    "inventory:restart-staged-valid",
                    "probe:restart-staged-valid",
                    "persist:Retiring",
                    "inventory:restart-staged-valid",
                    "revoke:restart-staged-valid",
                    "probe:restart-staged-valid",
                    "probe:restart-staged-valid",
                    "persist:Active",
                ),
                events,
            )
            assertEquals(0, owner.createCalls)
            assertEquals(listOf(setOf(reserved(old))), management.revocations)
            assertEquals(
                listOf(setOf(reserved(old), reserved(successor))),
                management.revocationExpectedInventories,
            )
            assertEquals(CredentialPhase.Active, store.record?.phase)
            assertEquals(successor.credentialId, store.record?.active?.credentialId)
            assertNull(store.record?.other)
        }

    @Test
    fun restartRevokesInvalidStagedSuccessorAndRestoresValidOld() =
        runBlocking {
            val events = mutableListOf<String>()
            val account = StalwartMailAccount(
                accountId = "restart-staged-invalid",
                address = "restart-staged-invalid@local.test",
            )
            val store = FakeCredentialStore(events)
            val old = generationSpec(store.storeId, 5)
            val successor = generationSpec(store.storeId, 6)
            store.record = recordSpec(
                account,
                CredentialPhase.Staged,
                old,
                successor,
            )
            val management = FakeManagementRemote(events).also {
                it.inventory = availableInventory(
                    account.accountId,
                    reserved(old),
                    reserved(successor),
                )
                it.mutationResult = StalwartRemoteMutationResult.Verified
            }
            val probe = FakeProbeRemote(events).also {
                it.results += successor.secret.copyOf() to
                    StalwartCredentialProbeResult.Rejected
                it.results += old.secret.copyOf() to
                    StalwartCredentialProbeResult.Authenticated(
                        STALWART_REQUIRED_MAIL_CAPABILITIES,
                    )
            }
            val owner = FakeOwnerRemote()

            val result = service(
                store = store,
                management = management,
                probe = probe,
                owner = owner,
            ).reconcileAfterRestart(account)

            assertIs<StalwartMailAccessResult.Completed>(result)
            assertEquals(
                listOf(
                    "inventory:restart-staged-invalid",
                    "probe:restart-staged-invalid",
                    "probe:restart-staged-invalid",
                    "revoke:restart-staged-invalid",
                    "persist:Active",
                ),
                events,
            )
            assertEquals(0, owner.createCalls)
            assertEquals(
                listOf(setOf(reserved(successor))),
                management.revocations,
            )
            assertEquals(
                listOf(setOf(reserved(old), reserved(successor))),
                management.revocationExpectedInventories,
            )
            assertEquals(CredentialPhase.Active, store.record?.phase)
            assertEquals(old.credentialId, store.record?.active?.credentialId)
        }

    @Test
    fun restartFinishesRetiringWhenOldIsAlreadyAbsent() = runBlocking {
        val account = StalwartMailAccount(
            accountId = "restart-retiring",
            address = "restart-retiring@local.test",
        )
        val store = FakeCredentialStore()
        val old = generationSpec(store.storeId, 8)
        val successor = generationSpec(store.storeId, 9)
        store.record = recordSpec(
            account,
            CredentialPhase.Retiring,
            successor,
            old,
        )
        val management = FakeManagementRemote().also {
            it.inventory = availableInventory(
                account.accountId,
                reserved(successor),
            )
        }
        val probe = FakeProbeRemote().also {
            it.results += old.secret.copyOf() to
                StalwartCredentialProbeResult.Rejected
            it.results += successor.secret.copyOf() to
                StalwartCredentialProbeResult.Authenticated(
                    STALWART_REQUIRED_MAIL_CAPABILITIES,
                )
        }
        val owner = FakeOwnerRemote()

        val result = service(
            store = store,
            management = management,
            probe = probe,
            owner = owner,
        ).reconcileAfterRestart(account)

        assertIs<StalwartMailAccessResult.Completed>(result)
        assertEquals(0, owner.createCalls)
        assertTrue(management.revocations.isEmpty())
        assertEquals(CredentialPhase.Active, store.record?.phase)
        assertEquals(successor.credentialId, store.record?.active?.credentialId)
    }

    @Test
    fun restartCompletesRemovalPendingOnlyAfterVerifiedRemoteAbsence() =
        runBlocking {
            val account = StalwartMailAccount(
                accountId = "restart-removal",
                address = "restart-removal@local.test",
            )
            val store = FakeCredentialStore()
            val removed = generationSpec(store.storeId, 3)
            store.record = recordSpec(
                account,
                CredentialPhase.RemovalPending,
                removed,
            )
            val management = FakeManagementRemote().also {
                it.inventory = availableInventory(account.accountId)
            }
            val owner = FakeOwnerRemote()

            val result = service(
                store = store,
                management = management,
                probe = FakeProbeRemote(),
                owner = owner,
            ).reconcileAfterRestart(account)

            val completed = assertIs<StalwartMailAccessResult.Completed>(result)
            assertEquals(
                StalwartMailAccessState.EnrollmentRequired,
                completed.projection.state,
            )
            assertEquals(0, owner.createCalls)
            assertTrue(store.recordSpecs.isEmpty())
        }

    @Test
    fun restartUnknownAndUnavailableRemoteStateFailClosedWithoutCreating() =
        runBlocking {
            val account = StalwartMailAccount(
                accountId = "restart-ambiguous",
                address = "restart-ambiguous@local.test",
            )
            val old = generationSpec(STORE_ID, 1)
            val successor = generationSpec(STORE_ID, 2)
            val unknownStore = FakeCredentialStore().also {
                it.record = recordSpec(
                    account,
                    CredentialPhase.Staged,
                    old,
                    successor,
                )
            }
            val unknown = StalwartReservedCredential(
                credentialId = "restart-unknown",
                description =
                    "mail-sandbox/debug-dashboard/${unknownStore.storeId}/11",
            )
            val unknownManagement = FakeManagementRemote().also {
                it.inventory = availableInventory(
                    account.accountId,
                    reserved(old),
                    reserved(successor),
                    unknown,
                )
            }
            val unknownOwner = FakeOwnerRemote()

            val unknownResult = service(
                store = unknownStore,
                management = unknownManagement,
                probe = FakeProbeRemote(),
                owner = unknownOwner,
            ).reconcileAfterRestart(account)

            assertIs<StalwartMailAccessResult.ReconciliationRequired>(
                unknownResult,
            )
            assertEquals(0, unknownOwner.createCalls)
            assertEquals(0, unknownStore.replaceCalls)
            assertTrue(unknownManagement.revocations.isEmpty())

            val unavailableStore = FakeCredentialStore().also {
                it.record = recordSpec(
                    account,
                    CredentialPhase.Retiring,
                    successor,
                    old,
                )
            }
            val unavailableManagement = FakeManagementRemote()
            val unavailableOwner = FakeOwnerRemote()

            val unavailableResult = service(
                store = unavailableStore,
                management = unavailableManagement,
                probe = FakeProbeRemote(),
                owner = unavailableOwner,
            ).reconcileAfterRestart(account)

            assertIs<StalwartMailAccessResult.ReconciliationRequired>(
                unavailableResult,
            )
            assertEquals(0, unavailableOwner.createCalls)
            assertEquals(0, unavailableStore.replaceCalls)
            assertTrue(unavailableManagement.revocations.isEmpty())
        }

    @Test
    fun restartWithNeitherValidGenerationKeepsStagedAndCreatesNothing() =
        runBlocking {
            val account = StalwartMailAccount(
                accountId = "restart-neither-valid",
                address = "restart-neither-valid@local.test",
            )
            val store = FakeCredentialStore()
            val old = generationSpec(store.storeId, 1)
            val successor = generationSpec(store.storeId, 2)
            store.record = recordSpec(
                account,
                CredentialPhase.Staged,
                old,
                successor,
            )
            val management = FakeManagementRemote().also {
                it.inventory = availableInventory(
                    account.accountId,
                    reserved(old),
                    reserved(successor),
                )
            }
            val owner = FakeOwnerRemote()

            val result = service(
                store = store,
                management = management,
                probe = FakeProbeRemote(),
                owner = owner,
            ).reconcileAfterRestart(account)

            val reconciliation =
                assertIs<StalwartMailAccessResult.ReconciliationRequired>(result)
            assertEquals(
                StalwartMailAccessState.Rotating,
                reconciliation.projection.state,
            )
            assertEquals(0, owner.createCalls)
            assertEquals(0, store.replaceCalls)
            assertTrue(management.revocations.isEmpty())
            assertEquals(CredentialPhase.Staged, store.record?.phase)
        }

    @Test
    fun globalResetCleansAllAccountsIncludingProtectedBeforeQuarantine() =
        runBlocking {
            val events = mutableListOf<String>()
            val store = FakeCredentialStore(events).also {
                it.available = false
                it.quarantineResult =
                    CredentialStoreQuarantineResult.Quarantined(emptyList())
                it.onQuarantine = {
                    it.available = true
                    it.storeId = FRESH_STORE_ID
                    it.revision = 0
                    it.record = null
                }
            }
            val ordinaryOne = StalwartReservedCredential(
                "reset-ordinary-one",
                "mail-sandbox/debug-dashboard/$STORE_ID/1",
            )
            val ordinaryTwo = StalwartReservedCredential(
                "reset-ordinary-two",
                "mail-sandbox/debug-dashboard/$STORE_ID/2",
            )
            val protected = StalwartReservedCredential(
                "reset-protected",
                "mail-sandbox/debug-dashboard/$STORE_ID/3",
            )
            val management = FakeManagementRemote(events).also {
                it.globalInventoryResults += availableGlobalInventory(
                    globalAccount(
                        "reset-ordinary",
                        false,
                        ordinaryOne,
                        ordinaryTwo,
                    ),
                    globalAccount(
                        "reset-management",
                        true,
                        protected,
                    ),
                )
                it.globalInventoryResults += availableGlobalInventory(
                    globalAccount(
                        accountId = "reset-ordinary",
                        protectedIdentity = false,
                    ),
                    globalAccount(
                        accountId = "reset-management",
                        protectedIdentity = true,
                    ),
                )
                it.mutationResult = StalwartRemoteMutationResult.Verified
            }

            val result = service(
                store = store,
                management = management,
                probe = FakeProbeRemote(),
            ).resetUnavailableStore()

            val completed =
                assertIs<StalwartCredentialStoreResetResult.Completed>(result)
            assertEquals(FRESH_STORE_ID, completed.storeId)
            assertEquals(
                listOf(
                    "global-inventory",
                    "revoke:reset-ordinary",
                    "revoke:reset-management",
                    "global-inventory",
                    "quarantine",
                ),
                events,
            )
            assertEquals(
                listOf(
                    setOf(ordinaryOne, ordinaryTwo),
                    setOf(protected),
                ),
                management.revocations,
            )
            assertEquals(2, management.globalInventoryCalls)
            assertEquals(1, store.quarantineCalls)
            assertEquals(2, store.loadCalls)
            assertTrue(store.recordSpecs.isEmpty())
        }

    @Test
    fun globalResetRequiresUnavailableStoreBeforeAnyRemoteCall() = runBlocking {
        val store = FakeCredentialStore()
        val management = FakeManagementRemote()

        val result = service(
            store = store,
            management = management,
            probe = FakeProbeRemote(),
        ).resetUnavailableStore()

        val reconciliation =
            assertIs<StalwartCredentialStoreResetResult.ReconciliationRequired>(
                result,
            )
        assertEquals(
            StalwartMailAccessReason.ResetNeedsManualRemediation,
            reconciliation.reason,
        )
        assertEquals(0, management.globalInventoryCalls)
        assertTrue(management.revocations.isEmpty())
        assertEquals(0, store.quarantineCalls)
    }

    @Test
    fun globalResetDrainTimeoutMakesZeroStoreAndRemoteCalls() = runBlocking {
        val now = AtomicLong(0)
        val leases = StalwartCredentialLeaseRegistry(
            nanoClock = StalwartLeaseNanoClock(now::get),
            waiter = StalwartLeaseChangeWaiter { _, remaining ->
                now.addAndGet(remaining)
            },
        )
        val activeLease = acquiredLease(leases, "global-reset-reader", 1)
        val store = FakeCredentialStore().also { it.available = false }
        val management = FakeManagementRemote()
        try {
            val result = service(
                store = store,
                management = management,
                probe = FakeProbeRemote(),
                leases = leases,
            ).resetUnavailableStore()

            val failure =
                assertIs<StalwartCredentialStoreResetResult.RetryableFailure>(
                    result,
                )
            assertEquals(
                StalwartMailAccessReason.LeaseDrainTimedOut,
                failure.reason,
            )
            assertEquals(0, store.loadCalls)
            assertEquals(0, store.quarantineCalls)
            assertEquals(0, management.globalInventoryCalls)
        } finally {
            activeLease.close()
        }
    }

    @Test
    fun globalResetUnprovenRemoteCleanupLeavesLocalStoreUntouched() =
        runBlocking {
            val account = StalwartMailAccount(
                accountId = "reset-local-canary",
                address = "reset-canary@local.test",
            )
            val store = FakeCredentialStore().also {
                it.record = recordSpec(
                    account,
                    CredentialPhase.Active,
                    generationSpec(it.storeId, 1),
                )
                it.available = false
                it.quarantineResult =
                    CredentialStoreQuarantineResult.Quarantined(emptyList())
            }
            val before = store.record?.active?.secret?.copyOf()
            val remote = StalwartReservedCredential(
                "reset-remote",
                "mail-sandbox/debug-dashboard/$STORE_ID/1",
            )
            val management = FakeManagementRemote().also {
                it.globalInventory = availableGlobalInventory(
                    globalAccount("reset-remote-account", false, remote),
                )
                it.mutationResult =
                    StalwartRemoteMutationResult.ReconciliationRequired
            }

            val result = service(
                store = store,
                management = management,
                probe = FakeProbeRemote(),
            ).resetUnavailableStore()

            val reconciliation =
                assertIs<StalwartCredentialStoreResetResult.ReconciliationRequired>(
                    result,
                )
            assertEquals(
                StalwartMailAccessReason.CleanupUnproven,
                reconciliation.reason,
            )
            assertEquals(0, store.quarantineCalls)
            assertEquals(1, store.loadCalls)
            assertTrue(
                requireNotNull(before).contentEquals(
                    requireNotNull(store.record?.active?.secret),
                ),
            )
        }

    @Test
    fun globalResetNeedsStableEmptyFinalInventoryBeforeLocalMutation() =
        runBlocking {
            val store = FakeCredentialStore().also {
                it.available = false
                it.quarantineResult =
                    CredentialStoreQuarantineResult.Quarantined(emptyList())
            }
            val remote = StalwartReservedCredential(
                "reset-still-present",
                "mail-sandbox/debug-dashboard/$STORE_ID/1",
            )
            val management = FakeManagementRemote().also {
                it.globalInventoryResults += availableGlobalInventory(
                    globalAccount("reset-stable", true, remote),
                )
                it.globalInventoryResults += availableGlobalInventory(
                    globalAccount("reset-stable", true, remote),
                )
                it.mutationResult = StalwartRemoteMutationResult.Verified
            }

            val result = service(
                store = store,
                management = management,
                probe = FakeProbeRemote(),
            ).resetUnavailableStore()

            assertIs<StalwartCredentialStoreResetResult.ReconciliationRequired>(
                result,
            )
            assertEquals(2, management.globalInventoryCalls)
            assertEquals(0, store.quarantineCalls)
        }

    @Test
    fun partialOrUnsafeQuarantineNeverClaimsResetOrInitializes() =
        runBlocking {
            val quarantineOutcomes = listOf(
                CredentialStoreQuarantineResult.PartiallyQuarantined(
                    emptyList(),
                ),
                CredentialStoreQuarantineResult.StoreUnavailable,
                CredentialStoreQuarantineResult.StoreAvailable,
            )
            quarantineOutcomes.forEach { outcome ->
                val store = FakeCredentialStore().also {
                    it.available = false
                    it.quarantineResult = outcome
                }
                val management = FakeManagementRemote().also {
                    it.globalInventoryResults += availableGlobalInventory()
                    it.globalInventoryResults += availableGlobalInventory()
                }

                val result = service(
                    store = store,
                    management = management,
                    probe = FakeProbeRemote(),
                ).resetUnavailableStore()

                val reconciliation =
                    assertIs<
                        StalwartCredentialStoreResetResult.ReconciliationRequired
                        >(result)
                assertEquals(
                    StalwartMailAccessReason.ResetNeedsManualRemediation,
                    reconciliation.reason,
                )
                assertEquals(1, store.quarantineCalls)
                assertEquals(
                    1,
                    store.loadCalls,
                    "Reset initialized after $outcome",
                )
            }
        }

    @Test
    fun sameAccountCasConflictIsNeverOverwrittenOrRetriedAsARemoteCreate() =
        runBlocking {
            val account = StalwartMailAccount(
                accountId = "same-account-race",
                address = "same-race@local.test",
            )
            val store = FakeCredentialStore()
            val concurrent = generationSpec(store.storeId, 8)
            store.beforeFirstReplace = {
                it.putRecord(
                    recordSpec(
                        account,
                        CredentialPhase.Active,
                        concurrent,
                    ),
                )
                it.revision += 1
            }
            val createdRemote = StalwartReservedCredential(
                credentialId = "same-race-created",
                description =
                    "mail-sandbox/debug-dashboard/${store.storeId}/1",
            )
            val management = FakeManagementRemote().also {
                it.inventoryResults += availableInventory(account.accountId)
                it.inventoryResults +=
                    availableInventory(account.accountId, createdRemote)
                it.mutationResult = StalwartRemoteMutationResult.Verified
            }
            val owner = FakeOwnerRemote().also {
                it.results += StalwartRemoteCreateResult.Created(
                    StalwartCreatedCredential(
                        credentialId = createdRemote.credentialId,
                        description = createdRemote.description,
                        secret = "app_same_race".encodeToByteArray(),
                    ),
                )
            }

            val result = service(
                store = store,
                management = management,
                probe = FakeProbeRemote(),
                owner = owner,
            ).enroll(
                account,
                StalwartNormalPassword.takeOwnership(
                    "same-race-password".toCharArray(),
                ),
            )

            val reconciliation =
                assertIs<StalwartMailAccessResult.ReconciliationRequired>(result)
            assertEquals(
                StalwartMailAccessState.RecoveryRequired,
                reconciliation.projection.state,
            )
            assertEquals(1, owner.createCalls)
            assertEquals(1, store.replaceCalls)
            assertEquals(concurrent.credentialId, store.record?.active?.credentialId)
            assertEquals(listOf(setOf(createdRemote)), management.revocations)
        }

    @Test
    fun secretOnlySameAccountCasConflictIsNeverOverwritten() = runBlocking {
        val account = StalwartMailAccount(
            accountId = "same-account-secret-race",
            address = "same-account-secret-race@local.test",
        )
        val store = FakeCredentialStore()
        val old = generationSpec(store.storeId, 1)
        val concurrentSecret = "app_concurrent_secret_only".encodeToByteArray()
        store.record = recordSpec(account, CredentialPhase.Active, old)
        store.beforeFirstReplace = {
            it.putRecord(
                recordSpec(
                    account = account,
                    phase = CredentialPhase.Active,
                    active = old.copy(secret = concurrentSecret),
                ),
            )
            it.revision += 1
        }
        val successor = StalwartReservedCredential(
            credentialId = "same-secret-successor",
            description =
                "mail-sandbox/debug-dashboard/${store.storeId}/2",
        )
        val management = FakeManagementRemote().also {
            it.inventory = availableInventory(
                account.accountId,
                reserved(old),
            )
            it.mutationResult = StalwartRemoteMutationResult.Verified
        }
        val owner = FakeOwnerRemote().also {
            it.results += StalwartRemoteCreateResult.Created(
                StalwartCreatedCredential(
                    credentialId = successor.credentialId,
                    description = successor.description,
                    secret = "app_same_secret_successor".encodeToByteArray(),
                ),
            )
        }

        val result = service(
            store = store,
            management = management,
            probe = FakeProbeRemote(),
            owner = owner,
        ).rotate(
            account,
            StalwartNormalPassword.takeOwnership(
                "same-secret-race-password".toCharArray(),
            ),
        )

        val reconciliation =
            assertIs<StalwartMailAccessResult.ReconciliationRequired>(result)
        assertEquals(
            StalwartMailAccessState.RecoveryRequired,
            reconciliation.projection.state,
        )
        assertEquals(
            StalwartMailAccessReason.CaptureFailed,
            reconciliation.reason,
        )
        assertEquals(1, owner.createCalls)
        assertEquals(1, store.replaceCalls)
        assertEquals(CredentialPhase.Active, store.record?.phase)
        assertContentEquals(concurrentSecret, store.record?.active?.secret)
        assertEquals(listOf(setOf(successor)), management.revocations)
    }

    private suspend fun awaitMutationPending(
        registry: StalwartCredentialLeaseRegistry,
        accountId: String,
    ) {
        withTimeout(1_000) {
            while (true) {
                when (
                    val attempt = registry.acquireMail(accountId) {
                        material(accountId, 1)
                    }
                ) {
                    is StalwartMailLeaseAcquireResult.Acquired -> {
                        attempt.lease.close()
                        yield()
                    }
                    is StalwartMailLeaseAcquireResult.Unavailable -> {
                        assertEquals(
                            StalwartMailLeaseUnavailableReason.MutationPending,
                            attempt.reason,
                        )
                        return@withTimeout
                    }
                }
            }
        }
    }

    private fun acquiredLease(
        registry: StalwartCredentialLeaseRegistry,
        accountId: String,
        generation: Long,
    ): StalwartMailCredentialLease =
        assertIs<StalwartMailLeaseAcquireResult.Acquired>(
            runBlocking {
                registry.acquireMail(accountId) {
                    material(accountId, generation)
                }
            },
        ).lease

    private fun material(
        accountId: String,
        generation: Long,
    ): StalwartMailLeaseMaterial =
        StalwartMailLeaseMaterial.takeOwnership(
            accountId = accountId,
            generation = generation,
            secret = "app_lease_$accountId-$generation".encodeToByteArray(),
        )

    private fun service(
        store: StalwartCredentialStore,
        management: StalwartCredentialManagementRemote,
        probe: StalwartMailCredentialProbeRemote,
        owner: StalwartCredentialOwnerRemote = RejectingOwnerRemote,
        leases: StalwartCredentialLeaseRegistry =
            StalwartCredentialLeaseRegistry(),
        protectedAccountIds: Set<String> = emptySet(),
        definitiveCreatedCleanupTimeout: Duration = 30.seconds,
    ): StalwartMailAccessService = StalwartMailAccessService(
        store = store,
        management = management,
        owner = owner,
        probe = probe,
        leases = leases,
        protectedAccountIds = protectedAccountIds,
        definitiveCreatedCleanupTimeout =
            definitiveCreatedCleanupTimeout,
    )

    private fun projection(
        state: StalwartMailAccessState,
        vararg actions: StalwartMailAccessAction,
    ): StalwartMailAccessProjection =
        StalwartMailAccessProjection(state, actions.toSet())

    private fun generationSpec(
        storeId: UUID,
        number: Long,
    ): GenerationSpec = GenerationSpec(
        credentialId = "credential-$number",
        description = "mail-sandbox/debug-dashboard/$storeId/$number",
        generation = number,
        secret = "app_generation_$number".encodeToByteArray(),
    )

    private fun recordSpec(
        account: StalwartMailAccount,
        phase: CredentialPhase,
        active: GenerationSpec,
        other: GenerationSpec? = null,
    ): RecordSpec = RecordSpec(account, phase, active, other)

    private fun reserved(spec: GenerationSpec): StalwartReservedCredential =
        StalwartReservedCredential(spec.credentialId, spec.description)

    private fun StalwartReservedCredential.withCredentialId(
        credentialId: String,
    ): StalwartReservedCredential =
        StalwartReservedCredential(credentialId, description)

    private fun availableInventory(
        accountId: String,
        vararg credentials: StalwartReservedCredential,
    ): StalwartRemoteRead<StalwartReservedInventory> =
        StalwartRemoteRead.Available(
            StalwartReservedInventory(
                accountId = accountId,
                reserved = credentials.toList(),
                appPasswordCount = credentials.size,
                appPasswordLimit = 4,
            ),
        )

    private fun availableInventoryWithQuota(
        accountId: String,
        appPasswordCount: Int,
        appPasswordLimit: Int?,
        vararg credentials: StalwartReservedCredential,
    ): StalwartRemoteRead<StalwartReservedInventory> =
        StalwartRemoteRead.Available(
            StalwartReservedInventory(
                accountId = accountId,
                reserved = credentials.toList(),
                appPasswordCount = appPasswordCount,
                appPasswordLimit = appPasswordLimit,
            ),
        )

    private fun globalAccount(
        accountId: String,
        protectedIdentity: Boolean,
        vararg credentials: StalwartReservedCredential,
    ): StalwartGlobalReservedAccount =
        StalwartGlobalReservedAccount(
            accountId = accountId,
            protectedIdentity = protectedIdentity,
            reserved = credentials.toList(),
        )

    private fun availableGlobalInventory(
        vararg accounts: StalwartGlobalReservedAccount,
    ): StalwartRemoteRead<StalwartGlobalReservedInventory> =
        StalwartRemoteRead.Available(
            StalwartGlobalReservedInventory(accounts.toList()),
        )

    private data class GenerationSpec(
        val credentialId: String,
        val description: String,
        val generation: Long,
        val secret: ByteArray,
    ) {
        fun deepCopy(): GenerationSpec = GenerationSpec(
            credentialId = credentialId,
            description = description,
            generation = generation,
            secret = secret.copyOf(),
        )

        fun clear() {
            secret.fill(0)
        }
    }

    private data class RecordSpec(
        val account: StalwartMailAccount,
        val phase: CredentialPhase,
        val active: GenerationSpec,
        val other: GenerationSpec?,
    ) {
        fun deepCopy(): RecordSpec = RecordSpec(
            account = account,
            phase = phase,
            active = active.deepCopy(),
            other = other?.deepCopy(),
        )

        fun clear() {
            active.clear()
            other?.clear()
        }
    }

    private class FakeCredentialStore(
        private val events: MutableList<String>? = null,
    ) : StalwartCredentialStore {
        var available = true
        var storeId: UUID = STORE_ID
        var revision = 0L
        val recordSpecs = linkedMapOf<String, RecordSpec>()
        val writeResults = mutableListOf<CredentialStoreWriteResult>()
        var beforeFirstReplace: ((FakeCredentialStore) -> Unit)? = null
        var applyThenUnavailableOnce = false
        var replaceCalls = 0
        var loadCalls = 0
        var quarantineCalls = 0
        var quarantineResult: CredentialStoreQuarantineResult =
            CredentialStoreQuarantineResult.StoreUnavailable
        var onQuarantine: ((FakeCredentialStore) -> Unit)? = null

        var record: RecordSpec?
            get() = recordSpecs.values.singleOrNull()
            set(value) {
                recordSpecs.values.forEach(RecordSpec::clear)
                recordSpecs.clear()
                value?.let(::putRecord)
            }

        fun putRecord(spec: RecordSpec) {
            recordSpecs.put(spec.account.accountId, spec.deepCopy())?.clear()
        }

        override fun load(): CredentialStoreLoadResult {
            loadCalls += 1
            if (!available) return CredentialStoreLoadResult.StoreUnavailable
            val records = recordSpecs.values.associate { spec ->
                spec.account.accountId to StalwartCredentialRecord.takeOwnership(
                        accountId = spec.account.accountId,
                        addressAtCapture = spec.account.address,
                        phase = spec.phase,
                        active = spec.active.toGeneration(),
                        other = spec.other?.toGeneration(),
                    )
            }
            return CredentialStoreLoadResult.Available(
                StalwartCredentialSnapshot(
                    storeId = storeId,
                    revision = revision,
                    records = records,
                ),
            )
        }

        override fun replace(
            expectedRevision: Long,
            records: Map<String, StalwartCredentialRecord>,
        ): CredentialStoreWriteResult {
            replaceCalls += 1
            if (replaceCalls == 1) {
                beforeFirstReplace?.also {
                    beforeFirstReplace = null
                    it(this)
                    return CredentialStoreWriteResult.RevisionMismatch(revision)
                }
            }
            val queued = writeResults.removeFirstOrNull()
            if (queued != null && queued !is CredentialStoreWriteResult.Written) {
                return queued
            }
            if (expectedRevision != revision) {
                return CredentialStoreWriteResult.RevisionMismatch(revision)
            }
            val captured = records.mapValues { (_, record) ->
                record.toSpec()
            }
            recordSpecs.values.forEach(RecordSpec::clear)
            recordSpecs.clear()
            captured.values.forEach(::putRecord)
            captured.values.forEach(RecordSpec::clear)
            revision += 1
            val targetPhase = records.values.lastOrNull()?.phase?.toString()
                ?: "Absent"
            events?.add("persist:$targetPhase")
            if (applyThenUnavailableOnce) {
                applyThenUnavailableOnce = false
                return CredentialStoreWriteResult.StoreUnavailable
            }
            return CredentialStoreWriteResult.Written(revision)
        }

        override fun quarantineUnavailable(): CredentialStoreQuarantineResult {
            quarantineCalls += 1
            events?.add("quarantine")
            onQuarantine?.invoke(this)
            return quarantineResult
        }

        override fun close() {
            recordSpecs.values.forEach(RecordSpec::clear)
            recordSpecs.clear()
        }

        private fun GenerationSpec.toGeneration(): CredentialGeneration =
            CredentialGeneration(
                credentialId = credentialId,
                description = description,
                generation = generation,
                secret = SecretBytes.takeOwnership(secret.copyOf()),
            )

        private fun StalwartCredentialRecord.toSpec(): RecordSpec =
            RecordSpec(
                account = StalwartMailAccount(accountId, addressAtCapture),
                phase = phase,
                active = requireNotNull(active).toSpec(),
                other = other?.toSpec(),
            )

        private fun CredentialGeneration.toSpec(): GenerationSpec {
            val copied = secret.copyForUse()
            return GenerationSpec(
                credentialId = credentialId,
                description = description,
                generation = generation,
                secret = copied,
            )
        }
    }

    private class FakeManagementRemote(
        private val events: MutableList<String>? = null,
    ) : StalwartCredentialManagementRemote {
        var inventory: StalwartRemoteRead<StalwartReservedInventory> =
            StalwartRemoteRead.Unavailable
        val inventoryResults =
            mutableListOf<StalwartRemoteRead<StalwartReservedInventory>>()
        var inventoryCalls = 0
        var mutationResult = StalwartRemoteMutationResult.Verified
        val revocations =
            mutableListOf<Set<StalwartReservedCredential>>()
        val revocationExpectedInventories =
            mutableListOf<Set<StalwartReservedCredential>>()
        var onRevoke: (() -> Unit)? = null
        var requireActiveAfterInventoryCall: Int? = null
        var requireActiveOnRevoke = false
        var delayAfterInventoryCall: Int? = null
        var inventoryDelayMillis = 0L
        var globalInventory:
            StalwartRemoteRead<StalwartGlobalReservedInventory> =
            StalwartRemoteRead.Unavailable
        val globalInventoryResults =
            mutableListOf<StalwartRemoteRead<StalwartGlobalReservedInventory>>()
        var globalInventoryCalls = 0

        override suspend fun inventory(
            accountId: String,
        ): StalwartRemoteRead<StalwartReservedInventory> {
            inventoryCalls += 1
            requireActiveAfterInventoryCall
                ?.takeIf { inventoryCalls > it }
                ?.let { currentCoroutineContext().ensureActive() }
            delayAfterInventoryCall
                ?.takeIf { inventoryCalls > it }
                ?.let { delay(inventoryDelayMillis) }
            events?.add("inventory:$accountId")
            return inventoryResults.removeFirstOrNull() ?: inventory
        }

        override suspend fun globalInventory():
            StalwartRemoteRead<StalwartGlobalReservedInventory> {
            globalInventoryCalls += 1
            events?.add("global-inventory")
            return globalInventoryResults.removeFirstOrNull()
                ?: globalInventory
        }

        override suspend fun revokeReserved(
            accountId: String,
            expected: Set<StalwartReservedCredential>,
            targets: Set<StalwartReservedCredential>,
        ): StalwartRemoteMutationResult {
            if (requireActiveOnRevoke) {
                currentCoroutineContext().ensureActive()
            }
            revocationExpectedInventories += expected
            revocations += targets
            events?.add("revoke:$accountId")
            onRevoke?.also {
                onRevoke = null
                it()
            }
            return mutationResult
        }
    }

    private class FakeProbeRemote(
        private val events: MutableList<String>? = null,
    ) : StalwartMailCredentialProbeRemote {
        val results =
            mutableListOf<Pair<ByteArray, StalwartCredentialProbeResult>>()

        override suspend fun probe(
            accountId: String,
            address: String,
            secret: StalwartBorrowedSecret,
        ): StalwartCredentialProbeResult {
            events?.add("probe:$accountId")
            return secret.withBytes { borrowed ->
                results.singleOrNull { (candidate, _) ->
                candidate.contentEquals(borrowed)
                }?.second ?: StalwartCredentialProbeResult.Rejected
            }
        }
    }

    private class FakeOwnerRemote(
        private val events: MutableList<String>? = null,
    ) : StalwartCredentialOwnerRemote {
        val results = mutableListOf<StalwartRemoteCreateResult>()
        var onCreate: (() -> Unit)? = null
        var cancellationAfterDispatch: CancellationException? = null
        var createCalls = 0

        override suspend fun createOwned(
            account: StalwartMailAccount,
            description: String,
            normalPassword: StalwartNormalPassword,
        ): StalwartRemoteCreateResult {
            createCalls += 1
            events?.add("create:${account.accountId}")
            normalPassword.withChars { password ->
                require(password.isNotEmpty()) { "Fake request password is absent" }
            }
            onCreate?.also {
                onCreate = null
                it()
            }
            cancellationAfterDispatch?.also {
                cancellationAfterDispatch = null
                currentCoroutineContext().cancel(it)
            }
            return results.removeFirstOrNull()
                ?: error("Unexpected owner credential create")
        }
    }

    private data object RejectingOwnerRemote : StalwartCredentialOwnerRemote {
        override suspend fun createOwned(
            account: StalwartMailAccount,
            description: String,
            normalPassword: StalwartNormalPassword,
        ): StalwartRemoteCreateResult =
            error("State projection must not create a credential")
    }

    private companion object {
        val STORE_ID: UUID =
            UUID.fromString("2ea9d9e3-98fe-477e-b3f9-5fbabf9de1e1")
        val FRESH_STORE_ID: UUID =
            UUID.fromString("6df88f6a-3ec8-4f1e-813b-0fd1e498a605")
    }
}
