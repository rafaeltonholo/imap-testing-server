package mail.sandbox.dashboard.server.gate.dovecot

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.OutputStream
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.util.Base64
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class DovecotHeldOperatorImapSessionTest {
    @Test
    fun leasedOpenFollowsTheRequiredLinearOrderBeforeReturning() {
        val events = mutableListOf<String>()
        val workers = DovecotBoundedOperationWorkers(maxOperations = 2)
        val leases =
            DovecotOperatorApplicationLeaseRegistry(DovecotOperatorId.A)
        val transport = ScriptedHeldOperatorTransport(
            (
                "* OK Dovecot ready\r\n" +
                    "+ VXNlcm5hbWU6\r\n" +
                    "+ UGFzc3dvcmQ6\r\n" +
                    "A001 OK authenticated\r\n" +
                    "+ OK continue\r\n" +
                    "A002 OK append completed\r\n"
                ).toByteArray(StandardCharsets.US_ASCII),
        )

        val held = HeldDovecotOperatorImapSession.openAndSeedLeased(
            leaseRegistry = leases,
            transportFactory = DovecotOperatorTransportFactory { register ->
                events += "transport-started"
                register(transport)
                events += "transport-registered"
                transport
            },
            target = DovecotOperatorTarget.create(
                "task6-leased-order@local.test",
            ),
            credential = DovecotOperatorCredential(
                id = DovecotOperatorId.A,
                secret = DovecotOperatorSecret.takeOwnership(
                    "leased-order-secret".toByteArray(
                        StandardCharsets.US_ASCII,
                    ),
                ),
            ),
            message = (
                "From: sender@local.test\r\n" +
                    "To: task6-leased-order@local.test\r\n" +
                    "Date: Thu, 30 Jul 2026 12:00:00 +0000\r\n" +
                    "Subject: Dovecot Task 6 leased order proof\r\n" +
                    "Message-ID: <task6-leased-order@local.test>\r\n" +
                    "MIME-Version: 1.0\r\n" +
                    "Content-Type: text/plain; charset=UTF-8\r\n" +
                    "\r\n" +
                    "Leased order proof.\r\n"
                ).toByteArray(StandardCharsets.US_ASCII),
            operationWorkers = workers,
            afterLeasedOpenStep = { step -> events += step.name },
        )

        assertEquals(
            listOf(
                "OperationAcquired",
                "LeaseReserved",
                "LeaseRecheckedBeforeTransport",
                "transport-started",
                "transport-registered",
                "SessionConstructed",
                "LeaseRecheckedBeforeBind",
                "LeaseBound",
                "LeaseRecheckedBeforeHandoff",
                "OperationHandedOff",
                "LeaseCommitted",
            ),
            events,
        )
        assertEquals(1, leases.openLeaseCount(DovecotOperatorId.A))
        assertFalse(held.session.isClosed)
        assertFalse(transport.closed)
        awaitWorkersReleased(workers)

        held.close()

        assertEquals(0, leases.openLeaseCount(DovecotOperatorId.A))
        assertTrue(held.session.isClosed)
        assertTrue(transport.closed)
        val abortCalls = transport.abortCalls
        val closeCalls = transport.closeCalls

        held.close()

        assertEquals(abortCalls, transport.abortCalls)
        assertEquals(closeCalls, transport.closeCalls)
        awaitWorkersReleased(workers)
    }

    @Test
    fun committedLeaseCloseDoesNotAcquireAnotherOperationSlot() {
        val workers = DovecotBoundedOperationWorkers(maxOperations = 1)
        val leases =
            DovecotOperatorApplicationLeaseRegistry(DovecotOperatorId.A)
        val transport = ScriptedHeldOperatorTransport(
            (
                "* OK Dovecot ready\r\n" +
                    "+ VXNlcm5hbWU6\r\n" +
                    "+ UGFzc3dvcmQ6\r\n" +
                    "A001 OK authenticated\r\n" +
                    "+ OK continue\r\n" +
                    "A002 OK append completed\r\n"
                ).toByteArray(StandardCharsets.US_ASCII),
        )
        val held = HeldDovecotOperatorImapSession.openAndSeedLeased(
            leaseRegistry = leases,
            transportFactory = DovecotOperatorTransportFactory { register ->
                register(transport)
                transport
            },
            target = DovecotOperatorTarget.create(
                "task6-direct-leased-close@local.test",
            ),
            credential = DovecotOperatorCredential(
                id = DovecotOperatorId.A,
                secret = DovecotOperatorSecret.takeOwnership(
                    "direct-leased-close-secret".toByteArray(
                        StandardCharsets.US_ASCII,
                    ),
                ),
            ),
            message = (
                "From: sender@local.test\r\n" +
                    "To: task6-direct-leased-close@local.test\r\n" +
                    "Date: Thu, 30 Jul 2026 12:00:00 +0000\r\n" +
                    "Subject: Dovecot Task 6 direct close proof\r\n" +
                    "Message-ID: <task6-direct-leased-close@local.test>\r\n" +
                    "MIME-Version: 1.0\r\n" +
                    "Content-Type: text/plain; charset=UTF-8\r\n" +
                    "\r\n" +
                    "Direct leased close proof.\r\n"
                ).toByteArray(StandardCharsets.US_ASCII),
            operationWorkers = workers,
        )
        val blocker = checkNotNull(
            workers.tryAcquire(
                System.nanoTime() + TimeUnit.SECONDS.toNanos(5),
            ),
        )

        try {
            assertEquals(1, workers.snapshot().activeOperations)

            held.close()

            assertTrue(held.session.isClosed)
            assertTrue(transport.closed)
            assertEquals(0, leases.openLeaseCount(DovecotOperatorId.A))
            assertEquals(1, workers.snapshot().activeOperations)
        } finally {
            blocker.abandon()
            blocker.awaitReleaseWithin(TimeUnit.SECONDS.toNanos(1))
            if (leases.openLeaseCount(DovecotOperatorId.A) != 0) {
                held.close()
            }
            awaitWorkersReleased(workers)
        }
    }

    @Test
    fun leasedCloseRetainsTheLeaseUntilExplicitAbortSucceeds() {
        val workers = DovecotBoundedOperationWorkers(maxOperations = 1)
        val leases =
            DovecotOperatorApplicationLeaseRegistry(DovecotOperatorId.A)
        val transport = ScriptedHeldOperatorTransport(
            transcript = (
                "* OK Dovecot ready\r\n" +
                    "+ VXNlcm5hbWU6\r\n" +
                    "+ UGFzc3dvcmQ6\r\n" +
                    "A001 OK authenticated\r\n" +
                    "+ OK continue\r\n" +
                    "A002 OK append completed\r\n"
                ).toByteArray(StandardCharsets.US_ASCII),
            failedAbortAttempts = 1,
        )
        val held = HeldDovecotOperatorImapSession.openAndSeedLeased(
            leaseRegistry = leases,
            transportFactory = DovecotOperatorTransportFactory { register ->
                register(transport)
                transport
            },
            target = DovecotOperatorTarget.create(
                "task6-leased-abort-retry@local.test",
            ),
            credential = DovecotOperatorCredential(
                id = DovecotOperatorId.A,
                secret = DovecotOperatorSecret.takeOwnership(
                    "leased-abort-retry-secret".toByteArray(
                        StandardCharsets.US_ASCII,
                    ),
                ),
            ),
            message = leasedMessage(
                "task6-leased-abort-retry@local.test",
                "leased abort retry",
            ),
            operationWorkers = workers,
        )

        assertFailsWith<IllegalStateException> {
            held.close()
        }

        assertEquals(1, transport.abortCalls)
        assertEquals(1, leases.openLeaseCount(DovecotOperatorId.A))
        assertFalse(held.session.isClosed)

        held.close()

        assertEquals(2, transport.abortCalls)
        assertEquals(0, leases.openLeaseCount(DovecotOperatorId.A))
        assertTrue(held.session.isClosed)
        awaitWorkersReleased(workers)
    }

    @Test
    fun failedUnboundCleanupDetachesForALaterDrainRetry() {
        val workers = DovecotBoundedOperationWorkers(maxOperations = 1)
        val leases =
            DovecotOperatorApplicationLeaseRegistry(DovecotOperatorId.A)
        val transport = ScriptedHeldOperatorTransport(
            transcript = (
                "* OK Dovecot ready\r\n" +
                    "+ VXNlcm5hbWU6\r\n" +
                    "+ UGFzc3dvcmQ6\r\n" +
                    "A001 OK authenticated\r\n" +
                    "+ OK continue\r\n" +
                    "A002 OK append completed\r\n"
                ).toByteArray(StandardCharsets.US_ASCII),
            failedAbortAttempts = 2,
        )
        val message = leasedMessage(
            "task6-unbound-cleanup-retry@local.test",
            "unbound cleanup retry",
        )
        val credential = DovecotOperatorCredential(
            id = DovecotOperatorId.A,
            secret = DovecotOperatorSecret.takeOwnership(
                "unbound-cleanup-retry-secret".toByteArray(
                    StandardCharsets.US_ASCII,
                ),
            ),
        )

        assertFailsWith<IllegalStateException> {
            HeldDovecotOperatorImapSession.openAndSeedLeased(
                leaseRegistry = leases,
                transportFactory =
                    DovecotOperatorTransportFactory { register ->
                        register(transport)
                        transport
                    },
                target = DovecotOperatorTarget.create(
                    "task6-unbound-cleanup-retry@local.test",
                ),
                credential = credential,
                message = message,
                operationWorkers = workers,
                afterLeasedOpenStep = { step ->
                    if (
                        step ==
                        HeldDovecotOperatorLeasedOpenStep
                            .SessionConstructed
                    ) {
                        error("Reject the unbound opening")
                    }
                },
            )
        }

        assertEquals(2, transport.abortCalls)
        assertEquals(1, leases.openLeaseCount(DovecotOperatorId.A))
        assertTrue(message.all { it == 0.toByte() })
        assertFailsWith<IllegalStateException> {
            credential.withSecretBytes { }
        }
        awaitWorkersReleased(workers)

        leases.blockAndDrain(DovecotOperatorId.A)

        assertEquals(3, transport.abortCalls)
        assertEquals(0, leases.openLeaseCount(DovecotOperatorId.A))
        awaitWorkersReleased(workers)
    }

    @Test
    fun leasedCloseUsesAbortAsTheSingleTerminationProof() {
        val workers = DovecotBoundedOperationWorkers(maxOperations = 1)
        val leases =
            DovecotOperatorApplicationLeaseRegistry(DovecotOperatorId.A)
        val transport = AbortProofHeldOperatorTransport()
        val held = HeldDovecotOperatorImapSession.openAndSeedLeased(
            leaseRegistry = leases,
            transportFactory = DovecotOperatorTransportFactory { register ->
                register(transport)
                transport
            },
            target = DovecotOperatorTarget.create(
                "task6-leased-abort-proof@local.test",
            ),
            credential = DovecotOperatorCredential(
                id = DovecotOperatorId.A,
                secret = DovecotOperatorSecret.takeOwnership(
                    "leased-abort-proof-secret".toByteArray(
                        StandardCharsets.US_ASCII,
                    ),
                ),
            ),
            message = leasedMessage(
                "task6-leased-abort-proof@local.test",
                "leased abort",
            ),
            operationWorkers = workers,
        )

        try {
            held.close()

            assertEquals(1, transport.abortCalls)
            assertEquals(0, transport.closeCalls)
            assertTrue(held.session.isClosed)
            assertEquals(0, leases.openLeaseCount(DovecotOperatorId.A))
        } finally {
            transport.allowClose()
            if (leases.openLeaseCount(DovecotOperatorId.A) != 0) {
                held.close()
            }
            awaitWorkersReleased(workers)
        }
    }

    @Test
    fun successfulLeasedAbortPreservesItsRestoredInterruption() {
        val workers = DovecotBoundedOperationWorkers(maxOperations = 1)
        val leases =
            DovecotOperatorApplicationLeaseRegistry(DovecotOperatorId.A)
        val transport = AbortProofHeldOperatorTransport(
            restoreInterruptOnAbort = true,
        )
        val held = HeldDovecotOperatorImapSession.openAndSeedLeased(
            leaseRegistry = leases,
            transportFactory = DovecotOperatorTransportFactory { register ->
                register(transport)
                transport
            },
            target = DovecotOperatorTarget.create(
                "task6-leased-abort-interrupt@local.test",
            ),
            credential = DovecotOperatorCredential(
                id = DovecotOperatorId.A,
                secret = DovecotOperatorSecret.takeOwnership(
                    "leased-abort-interrupt-secret".toByteArray(
                        StandardCharsets.US_ASCII,
                    ),
                ),
            ),
            message = leasedMessage(
                "task6-leased-abort-interrupt@local.test",
                "leased interrupt",
            ),
            operationWorkers = workers,
        )
        val closeFailure = AtomicReference<Throwable?>()
        val interruptRestored = AtomicBoolean()
        val closeCaller = Thread {
            try {
                held.close()
                interruptRestored.set(
                    Thread.currentThread().isInterrupted,
                )
            } catch (failure: Throwable) {
                closeFailure.set(failure)
                interruptRestored.set(
                    Thread.currentThread().isInterrupted,
                )
            } finally {
                Thread.interrupted()
            }
        }.also {
            it.isDaemon = true
            it.start()
        }

        closeCaller.join(2_000)

        assertFalse(closeCaller.isAlive)
        assertEquals(null, closeFailure.get())
        assertTrue(interruptRestored.get())
        assertTrue(held.session.isClosed)
        assertEquals(0, leases.openLeaseCount(DovecotOperatorId.A))
        assertEquals(1, transport.abortCalls)
        assertEquals(0, transport.closeCalls)
        awaitWorkersReleased(workers)
    }

    @Test
    fun failedHandoffCleanupPreservesItsSuccessfulAbortInterruption() {
        val workers = DovecotBoundedOperationWorkers(maxOperations = 1)
        val leases =
            DovecotOperatorApplicationLeaseRegistry(DovecotOperatorId.A)
        val transport = AbortProofHeldOperatorTransport(
            restoreInterruptOnAbort = true,
        )
        val message = leasedMessage(
            "task6-failed-handoff-interrupt@local.test",
            "failed handoff interrupt",
        )
        val credential = DovecotOperatorCredential(
            id = DovecotOperatorId.A,
            secret = DovecotOperatorSecret.takeOwnership(
                "failed-handoff-interrupt-secret".toByteArray(
                    StandardCharsets.US_ASCII,
                ),
            ),
        )
        val returned =
            AtomicReference<LeasedHeldDovecotOperatorImapSession?>()
        val failure = AtomicReference<Throwable?>()
        val interruptRestored = AtomicBoolean()
        val opener = Thread {
            try {
                returned.set(
                    HeldDovecotOperatorImapSession.openAndSeedLeased(
                        leaseRegistry = leases,
                        transportFactory =
                            DovecotOperatorTransportFactory { register ->
                                register(transport)
                                transport
                            },
                        target = DovecotOperatorTarget.create(
                            "task6-failed-handoff-interrupt@local.test",
                        ),
                        credential = credential,
                        message = message,
                        operationWorkers = workers,
                        afterLeasedOpenStep = { step ->
                            if (
                                step ==
                                HeldDovecotOperatorLeasedOpenStep
                                    .OperationHandedOff
                            ) {
                                error("Reject the handed-off opening")
                            }
                        },
                    ),
                )
            } catch (caught: Throwable) {
                failure.set(caught)
                interruptRestored.set(
                    Thread.currentThread().isInterrupted,
                )
            } finally {
                Thread.interrupted()
            }
        }.also {
            it.isDaemon = true
            it.start()
        }

        opener.join(2_000)

        assertFalse(opener.isAlive)
        assertEquals(null, returned.get())
        assertTrue(failure.get() is InterruptedException)
        assertEquals(
            "Held Dovecot operator seed proof was interrupted",
            failure.get()?.message,
        )
        assertTrue(interruptRestored.get())
        assertEquals(1, transport.abortCalls)
        assertEquals(0, transport.closeCalls)
        assertEquals(0, leases.openLeaseCount(DovecotOperatorId.A))
        assertTrue(message.all { it == 0.toByte() })
        assertFailsWith<IllegalStateException> {
            credential.withSecretBytes { }
        }
        awaitWorkersReleased(workers)
    }

    @Test
    fun interruptedAbortRetainsTheLeaseUntilTerminationIsProven() {
        val workers = DovecotBoundedOperationWorkers(maxOperations = 1)
        val leases =
            DovecotOperatorApplicationLeaseRegistry(DovecotOperatorId.A)
        val transport = ScriptedHeldOperatorTransport(
            transcript = (
                "* OK Dovecot ready\r\n" +
                    "+ VXNlcm5hbWU6\r\n" +
                    "+ UGFzc3dvcmQ6\r\n" +
                    "A001 OK authenticated\r\n" +
                    "+ OK continue\r\n" +
                    "A002 OK append completed\r\n"
                ).toByteArray(StandardCharsets.US_ASCII),
            interruptedAbortAttempts = 1,
        )
        val held = HeldDovecotOperatorImapSession.openAndSeedLeased(
            leaseRegistry = leases,
            transportFactory = DovecotOperatorTransportFactory { register ->
                register(transport)
                transport
            },
            target = DovecotOperatorTarget.create(
                "task6-leased-abort-interrupted@local.test",
            ),
            credential = DovecotOperatorCredential(
                id = DovecotOperatorId.A,
                secret = DovecotOperatorSecret.takeOwnership(
                    "leased-abort-interrupted-secret".toByteArray(
                        StandardCharsets.US_ASCII,
                    ),
                ),
            ),
            message = leasedMessage(
                "task6-leased-abort-interrupted@local.test",
                "interrupted abort",
            ),
            operationWorkers = workers,
        )
        val closeFailure = AtomicReference<Throwable?>()
        val interruptRestored = AtomicBoolean()
        val closeCaller = Thread {
            try {
                held.close()
            } catch (failure: Throwable) {
                closeFailure.set(failure)
                interruptRestored.set(
                    Thread.currentThread().isInterrupted,
                )
            } finally {
                Thread.interrupted()
            }
        }.also {
            it.isDaemon = true
            it.start()
        }

        closeCaller.join(2_000)

        assertFalse(closeCaller.isAlive)
        assertTrue(closeFailure.get() is IllegalStateException)
        assertTrue(interruptRestored.get())
        assertEquals(1, leases.openLeaseCount(DovecotOperatorId.A))
        assertFalse(held.session.isClosed)

        held.close()

        assertEquals(0, leases.openLeaseCount(DovecotOperatorId.A))
        assertTrue(held.session.isClosed)
        assertEquals(2, transport.abortCalls)
        awaitWorkersReleased(workers)
    }

    @Test
    fun capacityStartsSixteenTransportsRejectsSeventeenthAndDrains() {
        val workers = DovecotBoundedOperationWorkers(maxOperations = 1)
        val leases =
            DovecotOperatorApplicationLeaseRegistry(DovecotOperatorId.A)
        val processStarts = AtomicInteger()
        val holders =
            mutableListOf<LeasedHeldDovecotOperatorImapSession>()
        val transports = mutableListOf<AbortProofHeldOperatorTransport>()
        val rejectedMessage = leasedMessage(
            "task6-seventeenth-capacity@local.test",
            "seventeenth capacity",
        )
        val rejectedCredential = DovecotOperatorCredential(
            id = DovecotOperatorId.A,
            secret = DovecotOperatorSecret.takeOwnership(
                "seventeenth-capacity-secret".toByteArray(
                    StandardCharsets.US_ASCII,
                ),
            ),
        )

        try {
            (1..16).forEach { index ->
                val transport = AbortProofHeldOperatorTransport()
                transports += transport
                holders +=
                    HeldDovecotOperatorImapSession.openAndSeedLeased(
                        leaseRegistry = leases,
                        transportFactory =
                            DovecotOperatorTransportFactory { register ->
                                processStarts.incrementAndGet()
                                register(transport)
                                transport
                            },
                        target = DovecotOperatorTarget.create(
                            "task6-capacity-$index@local.test",
                        ),
                        credential = DovecotOperatorCredential(
                            id = DovecotOperatorId.A,
                            secret = DovecotOperatorSecret.takeOwnership(
                                "capacity-secret-$index".toByteArray(
                                    StandardCharsets.US_ASCII,
                                ),
                            ),
                        ),
                        message = leasedMessage(
                            "task6-capacity-$index@local.test",
                            "capacity $index",
                        ),
                        verificationLease = index == 16,
                        operationWorkers = workers,
                    )
            }

            assertEquals(16, processStarts.get())
            assertEquals(16, leases.openLeaseCount(DovecotOperatorId.A))

            assertFailsWith<IllegalStateException> {
                HeldDovecotOperatorImapSession.openAndSeedLeased(
                    leaseRegistry = leases,
                    transportFactory = DovecotOperatorTransportFactory {
                        processStarts.incrementAndGet()
                        error("Seventeenth opening started a transport")
                    },
                    target = DovecotOperatorTarget.create(
                        "task6-seventeenth-capacity@local.test",
                    ),
                    credential = rejectedCredential,
                    message = rejectedMessage,
                    operationWorkers = workers,
                )
            }
            assertEquals(16, processStarts.get())
            assertTrue(rejectedMessage.all { it == 0.toByte() })
            assertFailsWith<IllegalStateException> {
                rejectedCredential.withSecretBytes { }
            }

            leases.blockAndDrain(DovecotOperatorId.A)

            assertEquals(0, leases.openLeaseCount(DovecotOperatorId.A))
            assertTrue(holders.all { held -> held.session.isClosed })
            assertEquals(16, transports.sumOf { it.abortCalls })
            assertEquals(0, transports.sumOf { it.closeCalls })
        } finally {
            transports.forEach { transport -> transport.allowClose() }
            holders.forEach { held ->
                runCatching { held.close() }
            }
        }

        assertEquals(0, leases.openLeaseCount(DovecotOperatorId.A))
        awaitWorkersReleased(workers)
    }

    @Test
    fun rotationSeedMessageIdIsStableAndUniqueForEachDisposableTarget() {
        val firstTarget = DovecotOperatorTarget.create(
            "task6-rotation-first@local.test",
        )
        val secondTarget = DovecotOperatorTarget.create(
            "task6-rotation-second@local.test",
        )
        val firstMessage = deterministicRotationMessage(firstTarget)
        val repeatedFirstMessage = deterministicRotationMessage(firstTarget)
        val secondMessage = deterministicRotationMessage(secondTarget)

        try {
            assertContentEquals(firstMessage, repeatedFirstMessage)
            assertEquals(
                "<task6-rotation-read-proof." +
                    "task6-rotation-first@local.test>",
                messageId(firstMessage),
            )
            assertNotEquals(
                messageId(firstMessage),
                messageId(secondMessage),
            )
        } finally {
            firstMessage.fill(0)
            repeatedFirstMessage.fill(0)
            secondMessage.fill(0)
        }
    }

    @Test
    fun seedsTheMailboxProvesTheLiveSessionThenClosesItsTransport() {
        val message = (
            "From: sender@local.test\r\n" +
                "To: task6-held-session@local.test\r\n" +
                "Date: Thu, 30 Jul 2026 12:00:00 +0000\r\n" +
                "Subject: Dovecot Task 6 rotation proof\r\n" +
                "Message-ID: <task6-held-session@local.test>\r\n" +
                "MIME-Version: 1.0\r\n" +
                "Content-Type: text/plain; charset=UTF-8\r\n" +
                "\r\n" +
                "Deterministic Dovecot Task 6 mailbox read proof.\r\n"
            ).toByteArray(StandardCharsets.US_ASCII)
        val expectedMessage = message.copyOf()
        val target = DovecotOperatorTarget.create(
            "task6-held-session@local.test",
        )
        val credential = DovecotOperatorCredential(
            id = DovecotOperatorId.A,
            secret = DovecotOperatorSecret.takeOwnership(
                "held-session-secret".toByteArray(StandardCharsets.US_ASCII),
            ),
        )
        val transport = ScriptedHeldOperatorTransport(
            (
                "* OK Dovecot ready\r\n" +
                    "+ VXNlcm5hbWU6\r\n" +
                    "+ UGFzc3dvcmQ6\r\n" +
                    "A001 OK authenticated\r\n" +
                    "+ OK continue\r\n" +
                    "A002 OK append completed\r\n" +
                    "A003 OK noop completed\r\n"
                ).toByteArray(StandardCharsets.US_ASCII),
        )

        val session = HeldDovecotOperatorImapSession
            .openAndSeedUnleasedForDeterministicTransportTest(
            transportFactory = DovecotOperatorTransportFactory { register ->
                register(transport)
                transport
            },
            target = target,
            credential = credential,
            message = message,
        )
        session.requireUsable()

        assertContentEquals(
            heldSessionExpectedWrites(
                target = target,
                credentialId = DovecotOperatorId.A,
                secret = "held-session-secret",
                message = expectedMessage,
            ),
            transport.writtenBytes(),
        )
        assertTrue(message.all { it == 0.toByte() })
        assertFailsWith<IllegalStateException> {
            credential.withSecretBytes { }
        }
        assertFalse(session.isClosed)
        assertFalse(transport.closed)

        session.close()

        assertTrue(session.isClosed)
        assertTrue(transport.closed)
        session.requireClosedAndUnusable()
    }

    @Test
    fun invalidSeedStillWipesTheMessageAndClosesTheCredential() {
        val invalidMessage =
            "not-an-rfc5322-message".toByteArray(StandardCharsets.US_ASCII)
        val credential = DovecotOperatorCredential(
            id = DovecotOperatorId.A,
            secret = DovecotOperatorSecret.takeOwnership(
                "invalid-seed-secret".toByteArray(StandardCharsets.US_ASCII),
            ),
        )

        assertFailsWith<IllegalArgumentException> {
            HeldDovecotOperatorImapSession
                .openAndSeedUnleasedForDeterministicTransportTest(
                transportFactory = DovecotOperatorTransportFactory {
                    error("Invalid input must fail before opening transport")
                },
                target = DovecotOperatorTarget.create(
                    "task6-invalid-seed@local.test",
                ),
                credential = credential,
                message = invalidMessage,
            )
        }

        assertTrue(invalidMessage.all { it == 0.toByte() })
        assertFailsWith<IllegalStateException> {
            credential.withSecretBytes { }
        }
    }

    @Test
    fun rejectedUnregisteredTransportIsClosed() {
        val message = (
            "From: sender@local.test\r\n" +
                "To: task6-unregistered@local.test\r\n" +
                "Date: Thu, 30 Jul 2026 12:00:00 +0000\r\n" +
                "Subject: Dovecot Task 6 allocation proof\r\n" +
                "Message-ID: <task6-unregistered@local.test>\r\n" +
                "MIME-Version: 1.0\r\n" +
                "Content-Type: text/plain; charset=UTF-8\r\n" +
                "\r\n" +
                "Allocation proof.\r\n"
            ).toByteArray(StandardCharsets.US_ASCII)
        val credential = DovecotOperatorCredential(
            id = DovecotOperatorId.A,
            secret = DovecotOperatorSecret.takeOwnership(
                "unregistered-secret".toByteArray(StandardCharsets.US_ASCII),
            ),
        )
        val transport = ScriptedHeldOperatorTransport(ByteArray(0))

        assertFailsWith<IllegalStateException> {
            HeldDovecotOperatorImapSession
                .openAndSeedUnleasedForDeterministicTransportTest(
                transportFactory = DovecotOperatorTransportFactory {
                    transport
                },
                target = DovecotOperatorTarget.create(
                    "task6-unregistered@local.test",
                ),
                credential = credential,
                message = message,
            )
        }

        assertTrue(transport.closed)
        assertTrue(message.all { it == 0.toByte() })
        assertFailsWith<IllegalStateException> {
            credential.withSecretBytes { }
        }
    }

    @Test
    fun failedTransportCloseLeavesSessionUnusableButRetryable() {
        val message = (
            "From: sender@local.test\r\n" +
                "To: task6-close-retry@local.test\r\n" +
                "Date: Thu, 30 Jul 2026 12:00:00 +0000\r\n" +
                "Subject: Dovecot Task 6 close retry proof\r\n" +
                "Message-ID: <task6-close-retry@local.test>\r\n" +
                "MIME-Version: 1.0\r\n" +
                "Content-Type: text/plain; charset=UTF-8\r\n" +
                "\r\n" +
                "Close retry proof.\r\n"
            ).toByteArray(StandardCharsets.US_ASCII)
        val transport = ScriptedHeldOperatorTransport(
            transcript = (
                "* OK Dovecot ready\r\n" +
                    "+ VXNlcm5hbWU6\r\n" +
                    "+ UGFzc3dvcmQ6\r\n" +
                    "A001 OK authenticated\r\n" +
                    "+ OK continue\r\n" +
                    "A002 OK append completed\r\n"
                ).toByteArray(StandardCharsets.US_ASCII),
            failedCloseAttempts = 1,
        )
        val session = HeldDovecotOperatorImapSession
            .openAndSeedUnleasedForDeterministicTransportTest(
            transportFactory = DovecotOperatorTransportFactory { register ->
                register(transport)
                transport
            },
            target = DovecotOperatorTarget.create(
                "task6-close-retry@local.test",
            ),
            credential = DovecotOperatorCredential(
                id = DovecotOperatorId.A,
                secret = DovecotOperatorSecret.takeOwnership(
                    "close-retry-secret".toByteArray(
                        StandardCharsets.US_ASCII,
                    ),
                ),
            ),
            message = message,
        )

        assertFailsWith<IllegalStateException> {
            session.close()
        }
        assertFalse(session.isClosed)
        assertFalse(transport.closed)
        val writeCallsAfterFailedClose = transport.writeCalls

        assertFailsWith<IllegalStateException> {
            session.requireUsable()
        }

        assertEquals(writeCallsAfterFailedClose, transport.writeCalls)

        session.close()

        assertTrue(session.isClosed)
        assertTrue(transport.closed)
        assertEquals(2, transport.closeCalls)
    }

    @Test
    fun postCloseWriteSuccessAbandonsBeforeReleasingCleanupAuthority() {
        val workers = DovecotBoundedOperationWorkers(maxOperations = 1)
        val transport = MisbehavingClosedHeldTransport()
        val session = HeldDovecotOperatorImapSession
            .openAndSeedUnleasedForDeterministicTransportTest(
            transportFactory = DovecotOperatorTransportFactory { register ->
                register(transport)
                transport
            },
            target = DovecotOperatorTarget.create(
                "task6-post-close-cleanup@local.test",
            ),
            credential = DovecotOperatorCredential(
                id = DovecotOperatorId.A,
                secret = DovecotOperatorSecret.takeOwnership(
                    "post-close-cleanup-secret".toByteArray(
                        StandardCharsets.US_ASCII,
                    ),
                ),
            ),
            message = (
                "From: sender@local.test\r\n" +
                    "To: task6-post-close-cleanup@local.test\r\n" +
                    "Date: Thu, 30 Jul 2026 12:00:00 +0000\r\n" +
                    "Subject: Dovecot Task 6 post-close cleanup\r\n" +
                    "Message-ID: <task6-post-close-cleanup@local.test>\r\n" +
                    "MIME-Version: 1.0\r\n" +
                    "Content-Type: text/plain; charset=UTF-8\r\n" +
                    "\r\n" +
                    "Post-close cleanup proof.\r\n"
                ).toByteArray(StandardCharsets.US_ASCII),
            operationWorkers = workers,
        )
        session.close()
        assertEquals(1, transport.closeCalls)
        assertEquals(0, transport.abortCalls)

        assertFailsWith<IllegalStateException> {
            session.requireClosedAndUnusable()
        }

        awaitWorkersReleased(workers)
        assertEquals(1, transport.abortCalls)
        assertEquals(2, transport.closeCalls)
    }

    @Test
    fun usabilityAndExplicitCloseAreSerializedPerHeldSession() {
        val workers = DovecotBoundedOperationWorkers(maxOperations = 1)
        val transport = SerializingHeldOperatorTransport()
        val closeAttempted = CountDownLatch(1)
        val session = openSerializingSession(
            transport = transport,
            workers = workers,
            afterSessionLockContention = {
                if (
                    Thread.currentThread().name ==
                    "task6-serialized-close-contender"
                ) {
                    closeAttempted.countDown()
                }
            },
        )
        transport.blockNextWrite()
        val usabilityFailure = AtomicReference<Throwable?>()
        val usabilityFinished = CountDownLatch(1)
        val usabilityCaller = Thread {
            try {
                session.requireUsable(Duration.ofSeconds(2))
            } catch (failure: Throwable) {
                usabilityFailure.set(failure)
            } finally {
                usabilityFinished.countDown()
            }
        }.also {
            it.isDaemon = true
            it.start()
        }

        assertTrue(transport.blockedWriteStarted.await(1, TimeUnit.SECONDS))
        val closeFailure = AtomicReference<Throwable?>()
        val closeCaller = Thread(
            {
                try {
                    session.close(Duration.ofSeconds(2))
                } catch (failure: Throwable) {
                    closeFailure.set(failure)
                }
            },
            "task6-serialized-close-contender",
        ).also {
            it.isDaemon = true
            it.start()
        }

        try {
            assertTrue(closeAttempted.await(1, TimeUnit.SECONDS))
            assertEquals(
                0,
                transport.closeCalls,
                "Explicit close ran concurrently with the NOOP proof",
            )
        } finally {
            transport.releaseBlockedWrite()
            usabilityCaller.join(2_000)
            closeCaller.join(2_000)
        }

        assertFalse(usabilityCaller.isAlive)
        assertFalse(closeCaller.isAlive)
        assertEquals(null, usabilityFailure.get())
        assertEquals(null, closeFailure.get())
        assertEquals(1, transport.closeCalls)
        assertTrue(session.isClosed)
    }

    @Test
    fun concurrentCloseCallsRunTheTransportCloseExactlyOnce() {
        val workers = DovecotBoundedOperationWorkers(maxOperations = 1)
        val transport = SerializingHeldOperatorTransport(blockClose = true)
        val secondCloseAttempted = CountDownLatch(1)
        val session = openSerializingSession(
            transport = transport,
            workers = workers,
            afterSessionLockContention = {
                if (
                    Thread.currentThread().name ==
                    "task6-second-close-contender"
                ) {
                    secondCloseAttempted.countDown()
                }
            },
        )
        val firstFailure = AtomicReference<Throwable?>()
        val secondFailure = AtomicReference<Throwable?>()
        val first = Thread {
            try {
                session.close(Duration.ofSeconds(2))
            } catch (failure: Throwable) {
                firstFailure.set(failure)
            }
        }.also {
            it.isDaemon = true
            it.start()
        }

        assertTrue(transport.closeStarted.await(1, TimeUnit.SECONDS))
        val second = Thread(
            {
                try {
                    session.close(Duration.ofSeconds(2))
                } catch (failure: Throwable) {
                    secondFailure.set(failure)
                }
            },
            "task6-second-close-contender",
        ).also {
            it.isDaemon = true
            it.start()
        }

        try {
            assertTrue(secondCloseAttempted.await(1, TimeUnit.SECONDS))
            assertEquals(
                1,
                transport.closeCalls,
                "Concurrent close entered the transport twice",
            )
        } finally {
            transport.releaseBlockedClose()
            first.join(2_000)
            second.join(2_000)
        }

        assertFalse(first.isAlive)
        assertFalse(second.isAlive)
        assertEquals(null, firstFailure.get())
        assertEquals(null, secondFailure.get())
        assertEquals(1, transport.closeCalls)
        assertTrue(session.isClosed)
    }

    @Test
    fun postCloseProofWaitsForTheSerializedCloseOutcome() {
        val workers = DovecotBoundedOperationWorkers(maxOperations = 1)
        val transport = SerializingHeldOperatorTransport(blockClose = true)
        val proofAttempted = CountDownLatch(1)
        val session = openSerializingSession(
            transport = transport,
            workers = workers,
            afterSessionLockContention = {
                if (
                    Thread.currentThread().name ==
                    "task6-post-close-proof-contender"
                ) {
                    proofAttempted.countDown()
                }
            },
        )
        val closeFailure = AtomicReference<Throwable?>()
        val closeCaller = Thread {
            try {
                session.close(Duration.ofSeconds(2))
            } catch (failure: Throwable) {
                closeFailure.set(failure)
            }
        }.also {
            it.isDaemon = true
            it.start()
        }

        assertTrue(transport.closeStarted.await(1, TimeUnit.SECONDS))
        val proofFailure = AtomicReference<Throwable?>()
        val proofFinished = CountDownLatch(1)
        val proofCaller = Thread(
            {
                try {
                    session.requireClosedAndUnusable(Duration.ofSeconds(2))
                } catch (failure: Throwable) {
                    proofFailure.set(failure)
                } finally {
                    proofFinished.countDown()
                }
            },
            "task6-post-close-proof-contender",
        ).also {
            it.isDaemon = true
            it.start()
        }

        try {
            assertTrue(proofAttempted.await(1, TimeUnit.SECONDS))
            assertEquals(
                1L,
                proofFinished.count,
                "Post-close proof observed an in-progress close",
            )
        } finally {
            transport.releaseBlockedClose()
            closeCaller.join(2_000)
            proofCaller.join(2_000)
        }

        assertFalse(closeCaller.isAlive)
        assertFalse(proofCaller.isAlive)
        assertEquals(null, closeFailure.get())
        assertEquals(null, proofFailure.get())
        assertTrue(session.isClosed)
    }

    private fun openSerializingSession(
        transport: SerializingHeldOperatorTransport,
        workers: DovecotBoundedOperationWorkers,
        afterSessionLockContention: () -> Unit,
    ): HeldDovecotOperatorImapSession =
        HeldDovecotOperatorImapSession
            .openAndSeedUnleasedForDeterministicTransportTest(
            transportFactory = DovecotOperatorTransportFactory { register ->
                register(transport)
                transport
            },
            target = DovecotOperatorTarget.create(
                "task6-serialized-session@local.test",
            ),
            credential = DovecotOperatorCredential(
                id = DovecotOperatorId.A,
                secret = DovecotOperatorSecret.takeOwnership(
                    "serialized-session-secret".toByteArray(
                        StandardCharsets.US_ASCII,
                    ),
                ),
            ),
            message = (
                "From: sender@local.test\r\n" +
                    "To: task6-serialized-session@local.test\r\n" +
                    "Date: Thu, 30 Jul 2026 12:00:00 +0000\r\n" +
                    "Subject: Dovecot Task 6 serialization proof\r\n" +
                    "Message-ID: <task6-serialized-session@local.test>\r\n" +
                    "MIME-Version: 1.0\r\n" +
                    "Content-Type: text/plain; charset=UTF-8\r\n" +
                    "\r\n" +
                    "Serialization proof.\r\n"
                ).toByteArray(StandardCharsets.US_ASCII),
            operationWorkers = workers,
            afterSessionLockContention = afterSessionLockContention,
        )

    private fun awaitWorkersReleased(
        workers: DovecotBoundedOperationWorkers,
    ) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2)
        while (System.nanoTime() - deadline < 0L) {
            val snapshot = workers.snapshot()
            if (
                snapshot.activeOperations == 0 &&
                snapshot.abandonedOperations == 0 &&
                snapshot.activeActors == 0
            ) {
                return
            }
            Thread.yield()
        }
        assertEquals(
            DovecotBoundedOperationSnapshot(),
            workers.snapshot(),
        )
    }

    private fun leasedMessage(
        recipient: String,
        proof: String,
    ): ByteArray =
        (
            "From: sender@local.test\r\n" +
                "To: $recipient\r\n" +
                "Date: Thu, 30 Jul 2026 12:00:00 +0000\r\n" +
                "Subject: Dovecot Task 6 $proof proof\r\n" +
                "Message-ID: <task6-${proof.replace(' ', '-')}@local.test>\r\n" +
                "MIME-Version: 1.0\r\n" +
                "Content-Type: text/plain; charset=UTF-8\r\n" +
                "\r\n" +
                "Dovecot Task 6 $proof proof.\r\n"
            ).toByteArray(StandardCharsets.US_ASCII)

    private fun heldSessionExpectedWrites(
        target: DovecotOperatorTarget,
        credentialId: DovecotOperatorId,
        secret: String,
        message: ByteArray,
    ): ByteArray = ByteArrayOutputStream().use { expected ->
        expected.write("A001 AUTHENTICATE LOGIN\r\n".toByteArray())
        expected.write(
            Base64.getEncoder().encode(
                (
                    target.address +
                        "*" +
                        credentialId.masterUsername
                    ).toByteArray(StandardCharsets.US_ASCII),
            ),
        )
        expected.write("\r\n".toByteArray())
        expected.write(
            Base64.getEncoder().encode(
                secret.toByteArray(StandardCharsets.US_ASCII),
            ),
        )
        expected.write("\r\n".toByteArray())
        expected.write(
            (
                "A002 APPEND \"INBOX\" {${message.size}}\r\n"
                ).toByteArray(StandardCharsets.US_ASCII),
        )
        expected.write(message)
        expected.write("\r\n".toByteArray())
        expected.write("A003 NOOP\r\n".toByteArray())
        expected.toByteArray()
    }

    private fun messageId(message: ByteArray): String =
        message.toString(StandardCharsets.US_ASCII)
            .lineSequence()
            .single { line -> line.startsWith("Message-ID: ") }
            .removePrefix("Message-ID: ")
}

private class MisbehavingClosedHeldTransport :
    DovecotOperatorTransport {
    private val inputBytes = ByteArrayInputStream(
        (
            "* OK Dovecot ready\r\n" +
                "+ VXNlcm5hbWU6\r\n" +
                "+ UGFzc3dvcmQ6\r\n" +
                "A001 OK authenticated\r\n" +
                "+ OK continue\r\n" +
                "A002 OK append completed\r\n"
            ).toByteArray(StandardCharsets.US_ASCII),
    )
    private val closeCounter = AtomicInteger()
    private val abortCounter = AtomicInteger()

    val closeCalls: Int
        get() = closeCounter.get()

    val abortCalls: Int
        get() = abortCounter.get()

    override val input = inputBytes

    override val outputStream: OutputStream = object : OutputStream() {
        override fun write(value: Int) = Unit

        override fun write(
            bytes: ByteArray,
            offset: Int,
            length: Int,
        ) = Unit
    }

    override fun abort() {
        abortCounter.incrementAndGet()
    }

    override fun close() {
        closeCounter.incrementAndGet()
    }
}

private class SerializingHeldOperatorTransport(
    private val blockClose: Boolean = false,
) : DovecotOperatorTransport {
    private val inputBytes = ByteArrayInputStream(
        (
            "* OK Dovecot ready\r\n" +
                "+ VXNlcm5hbWU6\r\n" +
                "+ UGFzc3dvcmQ6\r\n" +
                "A001 OK authenticated\r\n" +
                "+ OK continue\r\n" +
                "A002 OK append completed\r\n" +
                "A003 OK noop completed\r\n"
            ).toByteArray(StandardCharsets.US_ASCII),
    )
    private val blockWrite = AtomicBoolean()
    private val releaseWrite = CountDownLatch(1)
    private val releaseClose = CountDownLatch(1)
    private val closeCounter = AtomicInteger()

    val blockedWriteStarted = CountDownLatch(1)
    val closeStarted = CountDownLatch(1)

    @Volatile
    private var closed = false

    val closeCalls: Int
        get() = closeCounter.get()

    override val input = inputBytes

    override val outputStream: OutputStream = object : OutputStream() {
        override fun write(value: Int) {
            write(byteArrayOf(value.toByte()), 0, 1)
        }

        override fun write(
            bytes: ByteArray,
            offset: Int,
            length: Int,
        ) {
            check(!closed) { "Serialized held transport is closed" }
            if (blockWrite.compareAndSet(true, false)) {
                blockedWriteStarted.countDown()
                releaseWrite.await()
            }
        }
    }

    fun blockNextWrite() {
        blockWrite.set(true)
    }

    fun releaseBlockedWrite() {
        releaseWrite.countDown()
    }

    fun releaseBlockedClose() {
        releaseClose.countDown()
    }

    override fun abort() {
        closed = true
    }

    override fun close() {
        closeCounter.incrementAndGet()
        closeStarted.countDown()
        if (blockClose) {
            while (true) {
                try {
                    releaseClose.await()
                    break
                } catch (_: InterruptedException) {
                    // The explicit test release owns transport close progress.
                }
            }
        }
        closed = true
    }
}

private class AbortProofHeldOperatorTransport(
    private val restoreInterruptOnAbort: Boolean = false,
) : DovecotOperatorTransport {
    private val transcript = ByteArrayInputStream(
        (
            "* OK Dovecot ready\r\n" +
                "+ VXNlcm5hbWU6\r\n" +
                "+ UGFzc3dvcmQ6\r\n" +
                "A001 OK authenticated\r\n" +
                "+ OK continue\r\n" +
                "A002 OK append completed\r\n"
            ).toByteArray(StandardCharsets.US_ASCII),
    )
    private val closeAllowed = AtomicBoolean()
    private val abortCounter = AtomicInteger()
    private val closeCounter = AtomicInteger()

    val abortCalls: Int
        get() = abortCounter.get()

    val closeCalls: Int
        get() = closeCounter.get()

    override val input = transcript

    override val outputStream: OutputStream = object : OutputStream() {
        override fun write(value: Int) = Unit

        override fun write(
            bytes: ByteArray,
            offset: Int,
            length: Int,
        ) = Unit
    }

    override fun abort() {
        abortCounter.incrementAndGet()
        if (restoreInterruptOnAbort) {
            Thread.currentThread().interrupt()
        }
    }

    override fun close() {
        closeCounter.incrementAndGet()
        check(closeAllowed.get()) {
            "Normal close rejected the successful abort outcome"
        }
    }

    fun allowClose() {
        closeAllowed.set(true)
    }
}

private class ScriptedHeldOperatorTransport(
    transcript: ByteArray,
    private val interruptedAbortAttempts: Int = 0,
    private val failedAbortAttempts: Int = 0,
    private val failedCloseAttempts: Int = 0,
) : DovecotOperatorTransport {
    private val inputBytes = ByteArrayInputStream(transcript)
    private val outputBytes = ByteArrayOutputStream()
    private val writeCounter = AtomicInteger()
    var closed = false
        private set

    var closeCalls = 0
        private set

    private val abortCounter = AtomicInteger()
    val abortCalls: Int
        get() = abortCounter.get()

    val writeCalls: Int
        get() = writeCounter.get()

    override val input = inputBytes
    override val outputStream: OutputStream = object : OutputStream() {
        override fun write(value: Int) {
            check(!closed) { "Held transport is closed" }
            writeCounter.incrementAndGet()
            outputBytes.write(value)
        }

        override fun write(
            bytes: ByteArray,
            offset: Int,
            length: Int,
        ) {
            check(!closed) { "Held transport is closed" }
            writeCounter.incrementAndGet()
            outputBytes.write(bytes, offset, length)
        }
    }

    fun writtenBytes(): ByteArray = outputBytes.toByteArray()

    override fun abort() {
        val attempt = abortCounter.incrementAndGet()
        if (attempt <= interruptedAbortAttempts) {
            Thread.currentThread().interrupt()
            throw InterruptedException(
                "Scripted held transport abort was interrupted",
            )
        }
        check(attempt > failedAbortAttempts) {
            "Scripted held transport abort failed"
        }
        close()
    }

    override fun close() {
        closeCalls += 1
        check(closeCalls > failedCloseAttempts) {
            "Scripted held transport close failed"
        }
        closed = true
        inputBytes.close()
        outputBytes.close()
    }
}
