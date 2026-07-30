package mail.sandbox.dashboard.server.gate.dovecot

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketAddress
import java.net.SocketException
import java.nio.charset.StandardCharsets
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

class DovecotOAuthProofValidatorTest {
    @Test
    fun preInterruptedHttpProofFailsBeforeSocketAllocation() {
        val socketAllocations = AtomicInteger()
        var interruptPreserved = false

        try {
            Thread.currentThread().interrupt()
            assertFailsWith<InterruptedException> {
                DovecotBoundedHttpProofClient(
                    port = 1,
                    timeoutMillis = 1_000,
                    maximumResponseBytes = 1024,
                    socketFactory = {
                        socketAllocations.incrementAndGet()
                        Socket()
                    },
                ).postForm("/introspect", ByteArray(0))
            }
            interruptPreserved = Thread.currentThread().isInterrupted
        } finally {
            Thread.interrupted()
        }

        assertTrue(interruptPreserved)
        assertEquals(0, socketAllocations.get())
    }

    @Test
    fun midOperationHttpInterruptionEscapesAndPreservesStatus() {
        val caller = Thread.currentThread()
        var interruptPreserved = false

        withLoopbackHttpServer(
            responseWriter = { output ->
                caller.interrupt()
                output.write(
                    (
                        "HTTP/1.0 200 OK\r\n" +
                            "Content-Length: 0\r\n" +
                            "\r\n"
                        ).toByteArray(StandardCharsets.US_ASCII),
                )
                output.flush()
            },
        ) { port ->
            try {
                assertFailsWith<InterruptedException> {
                    DovecotBoundedHttpProofClient(
                        port = port,
                        timeoutMillis = 1_000,
                        maximumResponseBytes = 1024,
                    ).postForm("/introspect", ByteArray(0))
                }
                interruptPreserved =
                    Thread.currentThread().isInterrupted
            } finally {
                Thread.interrupted()
            }
        }

        assertTrue(interruptPreserved)
    }

    @Test
    fun interruptedHttpHandoffReturnsNoResponseAndWipesOwnedBody() {
        val commitReached = CountDownLatch(1)
        val releaseCommit = CountDownLatch(1)
        val responseConstructed = AtomicBoolean()
        val bodyBuffer = AtomicReference<ByteArray?>()
        val workers = DovecotBoundedOperationWorkers(
            maxOperations = 1,
            beforeOwnershipCommit = {
                assertTrue(responseConstructed.get())
                commitReached.countDown()
                releaseCommit.awaitPreservingInterrupt()
            },
        )
        val socket = HandoffProofSocket(
            FIXED_BODY_RESPONSE_PREFIX + FIXED_BODY_BYTES,
        )
        val returned = AtomicReference<DovecotBoundedHttpResponse?>()
        val failure = AtomicReference<Throwable?>()
        val interruptPreserved = AtomicBoolean()
        val caller = Thread(
            {
                try {
                    returned.set(
                        DovecotBoundedHttpProofClient(
                            port = 1,
                            timeoutMillis = 5_000,
                            maximumResponseBytes = 1024,
                            socketFactory = { socket },
                            operationWorkers = workers,
                            responseBufferFactory = { size ->
                                ByteArray(size).also { allocated ->
                                    if (size == FIXED_BODY_SIZE) {
                                        bodyBuffer.set(allocated)
                                    }
                                }
                            },
                            afterResponseConstruction = {
                                responseConstructed.set(true)
                            },
                        ).postForm("/introspect", ByteArray(0)),
                    )
                } catch (caught: Throwable) {
                    failure.set(caught)
                    interruptPreserved.set(
                        Thread.currentThread().isInterrupted,
                    )
                } finally {
                    Thread.interrupted()
                }
            },
            "task6-interrupted-http-handoff-caller",
        ).also {
            it.isDaemon = true
            it.start()
        }

        try {
            assertTrue(commitReached.await(1, TimeUnit.SECONDS))
            assertEquals(
                DovecotBoundedOperationSnapshot(
                    activeOperations = 1,
                    peakActors = 1,
                ),
                workers.snapshot(),
            )

            caller.interrupt()
            releaseCommit.countDown()

            assertTrue(socket.cleanupCloseStarted.await(1, TimeUnit.SECONDS))
            caller.join(1_000)
            assertFalse(caller.isAlive)
            assertNull(returned.get())
            assertTrue(failure.get() is InterruptedException)
            assertEquals(
                "OAuth HTTP proof operation was interrupted",
                failure.get()?.message,
            )
            assertTrue(interruptPreserved.get())
            assertTrue(
                checkNotNull(bodyBuffer.get()).all { byte ->
                    byte == 0.toByte()
                },
            )
            assertEquals(3, socket.closeCalls)
            assertEquals(
                DovecotBoundedOperationSnapshot(
                    abandonedOperations = 1,
                    activeActors = 2,
                    peakActors = 2,
                ),
                workers.snapshot(),
            )
        } finally {
            releaseCommit.countDown()
            socket.releaseCleanup()
            caller.join(2_000)
        }

        awaitHttpWorkersReleased(workers)
    }

    @Test
    fun expiredHttpHandoffReturnsNoResponseAndWipesOwnedBody() {
        val clock = AtomicLong(System.nanoTime())
        val commitReached = CountDownLatch(1)
        val releaseCommit = CountDownLatch(1)
        val responseConstructed = AtomicBoolean()
        val bodyBuffer = AtomicReference<ByteArray?>()
        val workers = DovecotBoundedOperationWorkers(
            maxOperations = 1,
            nanoTime = clock::get,
            beforeOwnershipCommit = {
                assertTrue(responseConstructed.get())
                commitReached.countDown()
                releaseCommit.awaitPreservingInterrupt()
            },
        )
        val socket = HandoffProofSocket(
            FIXED_BODY_RESPONSE_PREFIX + FIXED_BODY_BYTES,
        )
        val returned = AtomicReference<DovecotBoundedHttpResponse?>()
        val failure = AtomicReference<Throwable?>()
        val caller = Thread(
            {
                try {
                    returned.set(
                        DovecotBoundedHttpProofClient(
                            port = 1,
                            timeoutMillis = 5_000,
                            maximumResponseBytes = 1024,
                            socketFactory = { socket },
                            operationWorkers = workers,
                            responseBufferFactory = { size ->
                                ByteArray(size).also { allocated ->
                                    if (size == FIXED_BODY_SIZE) {
                                        bodyBuffer.set(allocated)
                                    }
                                }
                            },
                            afterResponseConstruction = {
                                responseConstructed.set(true)
                            },
                        ).postForm("/introspect", ByteArray(0)),
                    )
                } catch (caught: Throwable) {
                    failure.set(caught)
                }
            },
            "task6-expired-http-handoff-caller",
        ).also {
            it.isDaemon = true
            it.start()
        }

        try {
            assertTrue(commitReached.await(1, TimeUnit.SECONDS))
            assertEquals(1, workers.snapshot().activeOperations)
            assertEquals(0, workers.snapshot().activeActors)

            clock.set(Long.MAX_VALUE)
            releaseCommit.countDown()

            assertTrue(socket.cleanupCloseStarted.await(1, TimeUnit.SECONDS))
            caller.join(1_000)
            assertFalse(caller.isAlive)
            assertNull(returned.get())
            assertTrue(failure.get() is IllegalStateException)
            assertEquals("OAuth HTTP proof failed", failure.get()?.message)
            assertEquals(null, failure.get()?.cause)
            assertTrue(
                checkNotNull(bodyBuffer.get()).all { byte ->
                    byte == 0.toByte()
                },
            )
            assertEquals(3, socket.closeCalls)
            assertEquals(
                DovecotBoundedOperationSnapshot(
                    abandonedOperations = 1,
                    activeActors = 2,
                    peakActors = 2,
                ),
                workers.snapshot(),
            )
        } finally {
            releaseCommit.countDown()
            socket.releaseCleanup()
            caller.join(2_000)
        }

        awaitHttpWorkersReleased(workers)
    }

    @Test
    fun blockedHttpBoundariesAndBlockedCancellationCloseCannotHoldTheCaller() {
        BlockingHttpBoundary.entries.forEach { boundary ->
            val workers = DovecotBoundedOperationWorkers(maxOperations = 1)
            val socket = BlockingProofSocket(boundary)
            val failure = AtomicReference<Throwable?>()
            val started = System.nanoTime()
            val caller = Thread(
                {
                    try {
                        DovecotBoundedHttpProofClient(
                            port = 1,
                            timeoutMillis = SHORT_HTTP_TIMEOUT_MILLIS,
                            maximumResponseBytes = 1024,
                            socketFactory = { socket },
                            operationWorkers = workers,
                        ).postForm(
                            "/introspect",
                            HTTP_BOUNDARY_REQUEST_BODY,
                        )
                    } catch (caught: Throwable) {
                        failure.set(caught)
                    }
                },
                "task6-blocked-http-${boundary.name.lowercase()}-caller",
            ).also {
                it.isDaemon = true
                it.start()
            }

            try {
                assertTrue(socket.ioStarted.await(1, TimeUnit.SECONDS))
                assertTrue(socket.allCloseCallsStarted.await(1, TimeUnit.SECONDS))
                caller.join(BOUNDED_HTTP_CALLER_MILLIS)

                assertFalse(
                    caller.isAlive,
                    "$boundary and blocked close held the HTTP caller",
                )
                assertTrue(
                    System.nanoTime() - started <
                        TimeUnit.MILLISECONDS.toNanos(
                            BOUNDED_HTTP_CALLER_MILLIS,
                        ),
                    "$boundary exceeded the HTTP caller deadline allowance",
                )
                assertTrue(failure.get() is IllegalStateException)
                assertEquals(
                    DovecotBoundedOperationSnapshot(
                        abandonedOperations = 1,
                        activeActors = 3,
                        peakActors = 3,
                    ),
                    workers.snapshot(),
                )
            } finally {
                socket.releaseIo.countDown()
                socket.releaseClose.countDown()
                caller.join(2_000)
            }

            awaitHttpWorkersReleased(workers)
            assertTrue(socket.ioExitedWithSocketException.await(1, TimeUnit.SECONDS))
        }
    }

    @Test
    fun fourBlockedHttpOperationsRejectAFifthBeforeAllocationAndRecover() {
        val operationCount = 4
        val allIoStarted = CountDownLatch(operationCount)
        val allCloseCallsStarted = CountDownLatch(operationCount * 2)
        val releaseIo = CountDownLatch(1)
        val releaseClose = CountDownLatch(1)
        val blocking = AtomicBoolean(true)
        val allocations = AtomicInteger()
        val sockets = Collections.synchronizedList(
            mutableListOf<BlockingProofSocket>(),
        )
        val workers =
            DovecotBoundedOperationWorkers(maxOperations = operationCount)
        val client = DovecotBoundedHttpProofClient(
            port = 1,
            timeoutMillis = SHORT_HTTP_TIMEOUT_MILLIS,
            maximumResponseBytes = 1024,
            socketFactory = {
                allocations.incrementAndGet()
                if (blocking.get()) {
                    BlockingProofSocket(
                        boundary = BlockingHttpBoundary.RequestHeaderWrite,
                        releaseIo = releaseIo,
                        releaseClose = releaseClose,
                        sharedIoStarted = allIoStarted,
                        sharedCloseStarted = allCloseCallsStarted,
                    ).also(sockets::add)
                } else {
                    ScriptedProofSocket(SUCCESS_RESPONSE)
                }
            },
            operationWorkers = workers,
        )
        val failures = List(operationCount) { AtomicReference<Throwable?>() }
        val callers = List(operationCount) { index ->
            Thread(
                {
                    try {
                        client.postForm("/introspect", ByteArray(0))
                    } catch (caught: Throwable) {
                        failures[index].set(caught)
                    }
                },
                "task6-capacity-http-caller-$index",
            ).also {
                it.isDaemon = true
                it.start()
            }
        }

        try {
            assertTrue(allIoStarted.await(2, TimeUnit.SECONDS))
            assertTrue(allCloseCallsStarted.await(2, TimeUnit.SECONDS))
            callers.forEach { caller -> caller.join(1_000) }

            assertTrue(callers.none(Thread::isAlive))
            assertTrue(
                failures.all { failure ->
                    failure.get() is IllegalStateException
                },
            )
            assertEquals(
                DovecotBoundedOperationSnapshot(
                    abandonedOperations = operationCount,
                    activeActors = operationCount * 3,
                    peakActors = operationCount * 3,
                ),
                workers.snapshot(),
            )

            val allocationsBeforeFifth = allocations.get()
            val actorsBeforeFifth = workers.snapshot().activeActors
            val fifthFailure = AtomicReference<Throwable?>()
            val fifthCaller = Thread(
                {
                    try {
                        client.postForm("/introspect", ByteArray(0))
                    } catch (caught: Throwable) {
                        fifthFailure.set(caught)
                    }
                },
                "task6-capacity-http-fifth-caller",
            ).also {
                it.isDaemon = true
                it.start()
            }
            fifthCaller.join(BOUNDED_HTTP_CALLER_MILLIS)
            assertFalse(
                fifthCaller.isAlive,
                "A fifth HTTP admission held its caller",
            )
            assertTrue(fifthFailure.get() is IllegalStateException)
            assertEquals(allocationsBeforeFifth, allocations.get())
            assertEquals(actorsBeforeFifth, workers.snapshot().activeActors)
        } finally {
            releaseIo.countDown()
            releaseClose.countDown()
            callers.forEach { caller -> caller.join(2_000) }
        }

        awaitHttpWorkersReleased(workers)
        assertEquals(operationCount, sockets.size)

        blocking.set(false)
        client.postForm("/introspect", ByteArray(0)).use { response ->
            assertEquals(200, response.status)
            assertEquals(0, response.body.size)
        }
        awaitHttpWorkersReleased(workers)
    }

    @Test
    fun defaultProbeHeldAndHttpShareOneProcessWideCapacityGate() {
        val workers = DovecotBoundedOperationWorkers.processWide
        awaitHttpWorkersReleased(workers)
        val deadline =
            System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        val reservations = List(4) {
            checkNotNull(workers.tryAcquire(deadline))
        }
        val fullSnapshot = workers.snapshot()
        val probeAllocations = AtomicInteger()
        val heldAllocations = AtomicInteger()
        val socketAllocations = AtomicInteger()
        val target = DovecotOperatorTarget.create(
            "task6-shared-capacity@local.test",
        )
        val probeCredential = httpTestCredential(
            "task6-shared-probe-secret",
        )
        val heldCredential = httpTestCredential(
            "task6-shared-held-secret",
        )
        val heldMessage = SHARED_CAPACITY_MESSAGE.copyOf()

        try {
            assertEquals(
                DovecotOperatorProbeResult.TransportFailure,
                DovecotOperatorProbe(
                    transportFactory =
                        DovecotOperatorTransportFactory {
                            probeAllocations.incrementAndGet()
                            error(
                                "Capacity-rejected probe allocated transport",
                            )
                        },
                ).probe(target, probeCredential),
            )
            assertFailsWith<IllegalStateException> {
                HeldDovecotOperatorImapSession.openAndSeed(
                    transportFactory =
                        DovecotOperatorTransportFactory {
                            heldAllocations.incrementAndGet()
                            error(
                                "Capacity-rejected Held proof " +
                                    "allocated transport",
                            )
                        },
                    target = target,
                    credential = heldCredential,
                    message = heldMessage,
                )
            }
            assertFailsWith<IllegalStateException> {
                DovecotBoundedHttpProofClient(
                    port = 1,
                    timeoutMillis = 1_000,
                    maximumResponseBytes = 1024,
                    socketFactory = {
                        socketAllocations.incrementAndGet()
                        error(
                            "Capacity-rejected HTTP proof allocated socket",
                        )
                    },
                ).postForm("/introspect", ByteArray(0))
            }

            assertEquals(0, probeAllocations.get())
            assertEquals(0, heldAllocations.get())
            assertEquals(0, socketAllocations.get())
            assertEquals(fullSnapshot, workers.snapshot())
            assertTrue(heldMessage.all { byte -> byte == 0.toByte() })
            assertCredentialClosed(probeCredential)
            assertCredentialClosed(heldCredential)
        } finally {
            reservations.forEach { operation ->
                assertTrue(operation.commitHandoff())
            }
        }
        awaitHttpWorkersReleased(workers)
    }

    @Test
    fun interruptedHttpSocketExceptionIsPromotedToRedactedInterruption() {
        val workers = DovecotBoundedOperationWorkers(maxOperations = 1)
        val socket = BlockingProofSocket(BlockingHttpBoundary.StatusRead)
        val failure = AtomicReference<Throwable?>()
        val workerFailure = AtomicReference<Throwable?>()
        val interruptPreserved = AtomicBoolean()
        val failureReachedClassification = CountDownLatch(1)
        val allowClassification = CountDownLatch(1)
        val completed = CountDownLatch(1)
        val caller = Thread(
            {
                try {
                    DovecotBoundedHttpProofClient(
                        port = 1,
                        timeoutMillis = 1_000,
                        maximumResponseBytes = 1024,
                        socketFactory = { socket },
                        operationWorkers = workers,
                        beforeFailureClassification = { caught ->
                            workerFailure.set(caught)
                            failureReachedClassification.countDown()
                            allowClassification.awaitPreservingInterrupt()
                        },
                    ).postForm("/introspect", ByteArray(0))
                } catch (caught: Throwable) {
                    failure.set(caught)
                } finally {
                    interruptPreserved.set(Thread.currentThread().isInterrupted)
                    Thread.interrupted()
                    completed.countDown()
                }
            },
            "task6-interrupted-http-socketexception-caller",
        ).also {
            it.isDaemon = true
            it.start()
        }

        try {
            assertTrue(socket.ioStarted.await(1, TimeUnit.SECONDS))
            socket.releaseIo.countDown()
            assertTrue(
                socket.ioExitedWithSocketException.await(1, TimeUnit.SECONDS),
            )
            assertTrue(
                failureReachedClassification.await(1, TimeUnit.SECONDS),
            )
            val surfaced = workerFailure.get()
            assertTrue(surfaced is SocketException)
            assertEquals(SOCKET_FAILURE_MARKER, surfaced.message)

            caller.interrupt()
            allowClassification.countDown()
            assertTrue(completed.await(1, TimeUnit.SECONDS))

            val caught = failure.get()
            assertTrue(caught is InterruptedException)
            assertEquals(
                "OAuth HTTP proof operation was interrupted",
                caught.message,
            )
            assertNull(caught.cause)
            assertTrue(caught.suppressed.isEmpty())
            assertFalse(caught.toString().contains(SOCKET_FAILURE_MARKER))
            assertTrue(interruptPreserved.get())
        } finally {
            socket.releaseIo.countDown()
            allowClassification.countDown()
            socket.releaseClose.countDown()
            caller.interrupt()
            caller.join(2_000)
        }
        awaitHttpWorkersReleased(workers)
    }

    @Test
    fun throwingHttpFailureClassificationHookCannotSkipCleanup() {
        val actorThreads = Collections.synchronizedList(
            mutableListOf<Thread>(),
        )
        val retainedRequestCopies = Collections.synchronizedList(
            mutableListOf<ByteArray>(),
        )
        val socket = RetainingMalformedStatusProofSocket(
            retainedRequestCopies,
        )
        val workers = DovecotBoundedOperationWorkers(
            maxOperations = 1,
            actorLauncher = DovecotBoundedActorLauncher { _, name, action ->
                Thread(action, name).also { actor ->
                    actor.isDaemon = true
                    actorThreads += actor
                    actor.start()
                }
            },
        )
        val classifiedFailure = AtomicReference<Throwable?>()
        val sentinel = HttpFailureClassificationSentinel()

        try {
            val caught = assertFailsWith<HttpFailureClassificationSentinel> {
                DovecotBoundedHttpProofClient(
                    port = 1,
                    timeoutMillis = 1_000,
                    maximumResponseBytes = 1024,
                    socketFactory = { socket },
                    operationWorkers = workers,
                    beforeFailureClassification = { failure ->
                        classifiedFailure.set(failure)
                        throw sentinel
                    },
                ).postForm(
                    path = "/introspect",
                    body = HTTP_BOUNDARY_REQUEST_BODY,
                )
            }

            assertSame(sentinel, caught)
            val parserFailure = classifiedFailure.get()
            assertTrue(parserFailure is IllegalStateException)
            assertEquals(
                "OAuth HTTP decimal field was invalid",
                parserFailure.message,
            )
            assertTrue(
                socket.allCloseCalls.await(1, TimeUnit.SECONDS),
                "HTTP cleanup did not run both socket close callbacks",
            )
            assertEquals(2, socket.closeCalls)

            val requestCopies = synchronized(retainedRequestCopies) {
                retainedRequestCopies.toList()
            }
            assertEquals(2, requestCopies.size)
            assertTrue(
                requestCopies.all { copy ->
                    copy.all { byte -> byte == 0.toByte() }
                },
                "HTTP worker-owned request copies were not wiped",
            )

            val launchedActors = synchronized(actorThreads) {
                actorThreads.toList()
            }
            assertEquals(3, launchedActors.size)
            launchedActors.forEach { actor ->
                actor.join(1_000)
                assertFalse(
                    actor.isAlive,
                    "HTTP ${actor.name} actor remained alive",
                )
            }
            assertEquals(
                DovecotBoundedOperationSnapshot(peakActors = 3),
                workers.snapshot(),
            )

            val recovered = checkNotNull(
                workers.tryAcquire(
                    System.nanoTime() + TimeUnit.SECONDS.toNanos(1),
                ),
            )
            assertTrue(recovered.commitHandoff())
        } finally {
            val launchedActors = synchronized(actorThreads) {
                actorThreads.toList()
            }
            launchedActors.forEach(Thread::interrupt)
            launchedActors.forEach { actor -> actor.join(1_000) }
            awaitHttpWorkersReleased(workers)
        }
    }

    @Test
    fun interruptionAfterSocketAllocationStillClosesTheOwnedSocket() {
        val allocated = CountDownLatch(1)
        val allowFactoryReturn = CountDownLatch(1)
        val socket = ScriptedProofSocket(SUCCESS_RESPONSE)
        val workers = DovecotBoundedOperationWorkers(maxOperations = 1)
        val failure = AtomicReference<Throwable?>()
        val interruptPreserved = AtomicBoolean()
        val completed = CountDownLatch(1)
        val caller = Thread(
            {
                try {
                    DovecotBoundedHttpProofClient(
                        port = 1,
                        timeoutMillis = 1_000,
                        maximumResponseBytes = 1024,
                        socketFactory = {
                            allocated.countDown()
                            allowFactoryReturn.awaitPreservingInterrupt()
                            socket
                        },
                        operationWorkers = workers,
                    ).postForm("/introspect", ByteArray(0))
                } catch (caught: Throwable) {
                    failure.set(caught)
                } finally {
                    interruptPreserved.set(Thread.currentThread().isInterrupted)
                    Thread.interrupted()
                    completed.countDown()
                }
            },
            "task6-interrupted-http-allocation-caller",
        ).also {
            it.isDaemon = true
            it.start()
        }

        try {
            assertTrue(allocated.await(1, TimeUnit.SECONDS))
            caller.interrupt()
            allowFactoryReturn.countDown()
            assertTrue(completed.await(1, TimeUnit.SECONDS))

            assertTrue(failure.get() is InterruptedException)
            assertTrue(interruptPreserved.get())
            assertTrue(socket.closed.await(1, TimeUnit.SECONDS))
        } finally {
            allowFactoryReturn.countDown()
            caller.interrupt()
            caller.join(2_000)
        }
        awaitHttpWorkersReleased(workers)
        assertEquals(
            DovecotBoundedOperationSnapshot(peakActors = 3),
            workers.snapshot(),
        )
    }

    @Test
    fun inactiveProofRequiresAnActualJsonBooleanFalse() {
        DovecotOAuthProofValidator.requireInactive(
            """{"active":false}""".toByteArray(StandardCharsets.UTF_8),
        )

        listOf(
            """{"active":"false"}""",
            """{"active":true}""",
            """{"active":0}""",
            """{"active":null}""",
            """{"active":false,"active":false}""",
            """{"\u0061ctive":true,"active":false}""",
            """{"scope":"imap"}""",
            """[]""",
            """not-json""",
        ).forEach { body ->
            assertFailsWith<IllegalStateException>(body) {
                DovecotOAuthProofValidator.requireInactive(
                    body.toByteArray(StandardCharsets.UTF_8),
                )
            }
        }
    }

    @Test
    fun denialRedirectParsesPercentDecodedUniqueQueryFields() {
        listOf(
            "http://127.0.0.1/callback?error=access_denied&state=task6",
            "http://127.0.0.1/callback?state=task6&" +
                "err%6Fr=access%5Fdenied",
        ).forEach(
            DovecotOAuthProofValidator::requireAccessDeniedRedirect,
        )

        listOf(
            "http://127.0.0.1/callback?noterror=access_denied",
            "http://127.0.0.1/callback?error=access_denied_extra",
            "http://127.0.0.1/callback?error=access_denied&code=",
            "http://127.0.0.1/callback?code=hidden&error=access_denied",
            "http://127.0.0.1/callback?error=access_denied&" +
                "error=access_denied",
            "http://127.0.0.1/callback?state=one&state=two&" +
                "error=access_denied",
            "http://127.0.0.1/callback?error%3Daccess_denied",
            "http://127.0.0.1/callback?error=access+denied",
            "http://127.0.0.1/callback?error=access%GGdenied",
            "http://127.0.0.1/callback#?error=access_denied",
            "http://attacker.invalid/callback?error=access_denied&state=task6",
            "http://127.0.0.1/other?error=access_denied&state=task6",
            "http://127.0.0.1:80/callback?error=access_denied&state=task6",
            "http://user@127.0.0.1/callback?error=access_denied&state=task6",
            "/callback?error=access_denied&state=task6",
            "http://127.0.0.1/callback?error=access_denied",
            "http://127.0.0.1/callback?error=access_denied&state=other",
            "http://127.0.0.1/callback?error=access_denied&state=task6#" +
                "code=leaked",
        ).forEach { location ->
            assertFailsWith<IllegalStateException>(location) {
                DovecotOAuthProofValidator.requireAccessDeniedRedirect(
                    location,
                )
            }
        }
    }

    @Test
    fun failedRealFixedLengthCollectorWipesItsInjectedOwnedBuffer() {
        val capturedBodyBuffer = AtomicReference<ByteArray?>()
        val bodyDestination = AtomicReference<ByteArray?>()
        val socket = FailingBodyProofSocket(bodyDestination)
        assertFailsWith<IllegalStateException> {
            DovecotBoundedHttpProofClient(
                port = 1,
                timeoutMillis = 1_000,
                maximumResponseBytes = 1024,
                socketFactory = { socket },
                operationWorkers =
                    DovecotBoundedOperationWorkers(maxOperations = 1),
                responseBufferFactory = { size ->
                    ByteArray(size) { BODY_BUFFER_SENTINEL }.also { buffer ->
                        if (size == FIXED_BODY_SIZE) {
                            capturedBodyBuffer.set(buffer)
                        }
                    }
                },
            ).postForm("/introspect", ByteArray(0))
        }

        val captured = checkNotNull(capturedBodyBuffer.get())
        assertTrue(captured === bodyDestination.get())
        assertTrue(captured.all { byte -> byte == 0.toByte() })
    }

    @Test
    fun normalRealFixedLengthCollectorTransfersAndWipesItsOwnedBuffer() {
        val capturedBodyBuffer = AtomicReference<ByteArray?>()
        val response = FIXED_BODY_RESPONSE_PREFIX + FIXED_BODY_BYTES

        DovecotBoundedHttpProofClient(
            port = 1,
            timeoutMillis = 1_000,
            maximumResponseBytes = 1024,
            socketFactory = { ScriptedProofSocket(response) },
            operationWorkers =
                DovecotBoundedOperationWorkers(maxOperations = 1),
            responseBufferFactory = { size ->
                ByteArray(size) { BODY_BUFFER_SENTINEL }.also { buffer ->
                    if (size == FIXED_BODY_SIZE) {
                        capturedBodyBuffer.set(buffer)
                    }
                }
            },
        ).postForm("/introspect", ByteArray(0)).use { httpResponse ->
            val captured = checkNotNull(capturedBodyBuffer.get())
            assertTrue(captured === httpResponse.body)
            assertContentEquals(FIXED_BODY_BYTES, httpResponse.body)
            assertFalse(captured.all { byte -> byte == 0.toByte() })
        }

        val captured = checkNotNull(capturedBodyBuffer.get())
        assertTrue(captured.all { byte -> byte == 0.toByte() })
    }

    @Test
    fun lateRealFixedLengthCollectorWipesItsInjectedOwnedBuffer() {
        val capturedBodyBuffer = AtomicReference<ByteArray?>()
        val bodyDestination = AtomicReference<ByteArray?>()
        val socket = LateBodyProofSocket(bodyDestination)
        val workers = DovecotBoundedOperationWorkers(maxOperations = 1)
        val failure = AtomicReference<Throwable?>()
        val caller = Thread(
            {
                try {
                    DovecotBoundedHttpProofClient(
                        port = 1,
                        timeoutMillis = SHORT_HTTP_TIMEOUT_MILLIS,
                        maximumResponseBytes = 1024,
                        socketFactory = { socket },
                        operationWorkers = workers,
                        responseBufferFactory = { size ->
                            ByteArray(size) { BODY_BUFFER_SENTINEL }.also { buffer ->
                                if (size == FIXED_BODY_SIZE) {
                                    capturedBodyBuffer.set(buffer)
                                }
                            }
                        },
                    ).postForm("/introspect", ByteArray(0))
                } catch (caught: Throwable) {
                    failure.set(caught)
                }
            },
            "task6-late-http-body-caller",
        ).also {
            it.isDaemon = true
            it.start()
        }

        try {
            assertTrue(socket.bodyReadStarted.await(1, TimeUnit.SECONDS))
            caller.join(BOUNDED_HTTP_CALLER_MILLIS)
            assertFalse(caller.isAlive, "A late HTTP body held its caller")
            assertTrue(failure.get() is IllegalStateException)
            assertFalse(
                checkNotNull(capturedBodyBuffer.get()).all { byte ->
                    byte == 0.toByte()
                },
            )
        } finally {
            socket.releaseBodyRead.countDown()
            caller.join(2_000)
        }

        awaitHttpWorkersReleased(workers)
        val captured = checkNotNull(capturedBodyBuffer.get())
        assertTrue(captured === bodyDestination.get())
        assertTrue(captured.all { byte -> byte == 0.toByte() })
    }

    @Test
    fun boundedHttpClientUsesOneDeadlineAcrossADripFedResponse() {
        withLoopbackHttpServer(
            responseWriter = { output ->
                output.write(
                    (
                        "HTTP/1.0 200 OK\r\n" +
                            "Content-Type: application/json\r\n" +
                            "\r\n"
                        ).toByteArray(StandardCharsets.US_ASCII),
                )
                output.flush()
                """{"active":false}"""
                    .toByteArray(StandardCharsets.US_ASCII)
                    .forEach { byte ->
                        output.write(byte.toInt())
                        output.flush()
                        Thread.sleep(25)
                    }
            },
        ) { port ->
            val started = System.nanoTime()

            assertFailsWith<IllegalStateException> {
                DovecotBoundedHttpProofClient(
                    port = port,
                    timeoutMillis = 80,
                    maximumResponseBytes = 1024,
                ).postForm("/introspect", ByteArray(0))
            }

            assertTrue(
                System.nanoTime() - started <
                    TimeUnit.MILLISECONDS.toNanos(
                        BOUNDED_HTTP_CALLER_MILLIS,
                    ),
            )
        }
    }

    @Test
    fun boundedHttpClientRejectsOversizedOrExcessiveHeaders() {
        val oversizedLocation = (
            "http://127.0.0.1/callback?error=access_denied&state=" +
                "x".repeat(3_000)
            )
        val excessiveHeaders = buildString {
            append("HTTP/1.0 200 OK\r\n")
            repeat(40) { index ->
                append("X-Proof-$index: value\r\n")
            }
            append("\r\n")
        }
        listOf(
            "HTTP/1.0 302 Found\r\n" +
                "Location: $oversizedLocation\r\n" +
                "\r\n",
            excessiveHeaders,
        ).forEach { response ->
            withLoopbackHttpServer(
                responseWriter = { output ->
                    output.write(
                        response.toByteArray(StandardCharsets.US_ASCII),
                    )
                    output.flush()
                },
            ) { port ->
                assertFailsWith<IllegalStateException>(response.take(32)) {
                    DovecotBoundedHttpProofClient(
                        port = port,
                        timeoutMillis = 1_000,
                        maximumResponseBytes = 1024,
                    ).postForm("/authorize", ByteArray(0))
                }
            }
        }
    }

    @Test
    fun boundedHttpClientParsesFixedStatusLocationAndCloseDelimitedBody() {
        val expectedBody =
            """{"active":false}""".toByteArray(StandardCharsets.US_ASCII)
        withLoopbackHttpServer(
            responseWriter = { output ->
                output.write(
                    (
                        "HTTP/1.0 302 Found\r\n" +
                            "Location: http://127.0.0.1/callback?" +
                            "error=access_denied&state=task6\r\n" +
                            "\r\n"
                        ).toByteArray(StandardCharsets.US_ASCII),
                )
                output.write(expectedBody)
                output.flush()
            },
        ) { port ->
            DovecotBoundedHttpProofClient(
                port = port,
                timeoutMillis = 1_000,
                maximumResponseBytes = 1024,
            ).postForm("/authorize", ByteArray(0)).use { response ->
                assertEquals(302, response.status)
                assertEquals(
                    "http://127.0.0.1/callback?" +
                        "error=access_denied&state=task6",
                    response.location,
                )
                assertContentEquals(expectedBody, response.body)
            }
        }
    }

    @Test
    fun boundedHttpClientRejectsContentLengthBeyondASmallConfiguredLimit() {
        withLoopbackHttpServer(
            responseWriter = { output ->
                output.write(
                    (
                        "HTTP/1.0 200 OK\r\n" +
                            "Content-Length: 9\r\n" +
                            "\r\n" +
                            "123456789"
                        ).toByteArray(StandardCharsets.US_ASCII),
                )
                output.flush()
            },
        ) { port ->
            assertFailsWith<IllegalStateException> {
                DovecotBoundedHttpProofClient(
                    port = port,
                    timeoutMillis = 1_000,
                    maximumResponseBytes = 1,
                ).postForm("/introspect", ByteArray(0))
            }
        }
    }

    private fun awaitHttpWorkersReleased(
        workers: DovecotBoundedOperationWorkers,
    ) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2)
        while (System.nanoTime() < deadline) {
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
            "Task 6 HTTP workers did not release",
        )
    }

    private fun httpTestCredential(
        secret: String,
    ): DovecotOperatorCredential =
        DovecotOperatorCredential(
            id = DovecotOperatorId.A,
            secret = DovecotOperatorSecret.takeOwnership(
                secret.toByteArray(StandardCharsets.US_ASCII),
            ),
        )

    private fun assertCredentialClosed(
        credential: DovecotOperatorCredential,
    ) {
        assertFailsWith<IllegalStateException> {
            credential.withSecretBytes { }
        }
    }

    private enum class BlockingHttpBoundary {
        Connect,
        RequestHeaderWrite,
        RequestBodyWrite,
        Flush,
        StatusRead,
        HeaderRead,
        FixedLengthBodyRead,
        CloseDelimitedBodyRead,
        Close,
    }

    private class BlockingProofSocket(
        private val boundary: BlockingHttpBoundary,
        val releaseIo: CountDownLatch = CountDownLatch(1),
        val releaseClose: CountDownLatch = CountDownLatch(1),
        private val sharedIoStarted: CountDownLatch? = null,
        private val sharedCloseStarted: CountDownLatch? = null,
    ) : Socket() {
        val ioStarted = CountDownLatch(1)
        val allCloseCallsStarted = CountDownLatch(2)
        val ioExitedWithSocketException = CountDownLatch(1)
        private val closeCalls = AtomicInteger()

        private val response =
            if (boundary == BlockingHttpBoundary.CloseDelimitedBodyRead) {
                CLOSE_DELIMITED_BODY_RESPONSE
            } else if (boundary == BlockingHttpBoundary.FixedLengthBodyRead) {
                FIXED_BODY_RESPONSE_PREFIX + FIXED_BODY_BYTES
            } else {
                SUCCESS_RESPONSE
            }
        private val bodyOffset =
            if (boundary == BlockingHttpBoundary.CloseDelimitedBodyRead) {
                CLOSE_DELIMITED_RESPONSE_PREFIX.size
            } else {
                FIXED_BODY_RESPONSE_PREFIX.size
            }
        private val input = object : InputStream() {
            private var offset = 0

            override fun read(): Int {
                if (
                    (
                        boundary == BlockingHttpBoundary.StatusRead &&
                            offset == 0
                        ) ||
                    (
                        boundary == BlockingHttpBoundary.HeaderRead &&
                            offset == HTTP_STATUS_LINE.size
                        ) ||
                    (
                        boundary ==
                            BlockingHttpBoundary.CloseDelimitedBodyRead &&
                            offset == bodyOffset
                        )
                ) {
                    blockIo()
                }
                if (offset == response.size) {
                    return -1
                }
                return response[offset++].toInt().and(0xff)
            }

            override fun read(
                bytes: ByteArray,
                offset: Int,
                length: Int,
            ): Int {
                if (
                    boundary == BlockingHttpBoundary.FixedLengthBodyRead &&
                    this.offset == bodyOffset
                ) {
                    blockIo()
                }
                if (length == 0) {
                    return 0
                }
                if (this.offset == response.size) {
                    return -1
                }
                val count = minOf(length, response.size - this.offset)
                response.copyInto(
                    destination = bytes,
                    destinationOffset = offset,
                    startIndex = this.offset,
                    endIndex = this.offset + count,
                )
                this.offset += count
                return count
            }
        }
        private val output = object : OutputStream() {
            private var writeCount = 0

            override fun write(value: Int) = Unit

            override fun write(
                bytes: ByteArray,
                offset: Int,
                length: Int,
            ) {
                writeCount += 1
                if (
                    (
                        boundary ==
                            BlockingHttpBoundary.RequestHeaderWrite &&
                            writeCount == 1
                        ) ||
                    (
                        boundary ==
                            BlockingHttpBoundary.RequestBodyWrite &&
                            writeCount == 2
                        )
                ) {
                    blockIo()
                }
            }

            override fun flush() {
                if (boundary == BlockingHttpBoundary.Flush) {
                    blockIo()
                }
            }
        }

        override fun connect(
            endpoint: SocketAddress,
            timeout: Int,
        ) {
            if (boundary == BlockingHttpBoundary.Connect) {
                blockIo()
            }
        }

        override fun setTcpNoDelay(on: Boolean) = Unit

        override fun setSoTimeout(timeout: Int) = Unit

        override fun getInputStream(): InputStream = input

        override fun getOutputStream(): OutputStream = output

        override fun close() {
            val call = closeCalls.incrementAndGet()
            if (boundary == BlockingHttpBoundary.Close && call == 1) {
                blockIo()
            }
            allCloseCallsStarted.countDown()
            sharedCloseStarted?.countDown()
            releaseClose.awaitPreservingInterrupt()
        }

        private fun blockIo(): Nothing {
            ioStarted.countDown()
            sharedIoStarted?.countDown()
            releaseIo.awaitPreservingInterrupt()
            ioExitedWithSocketException.countDown()
            throw SocketException(SOCKET_FAILURE_MARKER)
        }
    }

    private open class ScriptedProofSocket(
        response: ByteArray,
    ) : Socket() {
        private val input = ByteArrayInputStream(response)
        private val output = ByteArrayOutputStream()
        val closed = CountDownLatch(1)

        override fun connect(
            endpoint: SocketAddress,
            timeout: Int,
        ) = Unit

        override fun setTcpNoDelay(on: Boolean) = Unit

        override fun setSoTimeout(timeout: Int) = Unit

        override fun getInputStream(): InputStream = input

        override fun getOutputStream(): OutputStream = output

        override fun close() {
            closed.countDown()
        }
    }

    private class HandoffProofSocket(
        response: ByteArray,
    ) : Socket() {
        private val input = ByteArrayInputStream(response)
        private val output = ByteArrayOutputStream()
        private val closeCounter = AtomicInteger()
        private val cleanupRelease = CountDownLatch(1)

        val cleanupCloseStarted = CountDownLatch(2)

        val closeCalls: Int
            get() = closeCounter.get()

        override fun connect(
            endpoint: SocketAddress,
            timeout: Int,
        ) = Unit

        override fun setTcpNoDelay(on: Boolean) = Unit

        override fun setSoTimeout(timeout: Int) = Unit

        override fun getInputStream(): InputStream = input

        override fun getOutputStream(): OutputStream = output

        override fun close() {
            if (closeCounter.incrementAndGet() > 1) {
                cleanupCloseStarted.countDown()
                cleanupRelease.awaitPreservingInterrupt()
            }
        }

        fun releaseCleanup() {
            cleanupRelease.countDown()
        }
    }

    private class RetainingMalformedStatusProofSocket(
        private val retainedRequestCopies: MutableList<ByteArray>,
    ) : Socket() {
        val allCloseCalls = CountDownLatch(2)
        private val closeCounter = AtomicInteger()
        val closeCalls: Int
            get() = closeCounter.get()

        private val input = ByteArrayInputStream(
            "HTTP/1.0 X00 Bad\r\n".toByteArray(
                StandardCharsets.US_ASCII,
            ),
        )
        private val output = object : OutputStream() {
            override fun write(value: Int) = Unit

            override fun write(
                bytes: ByteArray,
                offset: Int,
                length: Int,
            ) {
                retainedRequestCopies += bytes
            }
        }

        override fun connect(
            endpoint: SocketAddress,
            timeout: Int,
        ) = Unit

        override fun setTcpNoDelay(on: Boolean) = Unit

        override fun setSoTimeout(timeout: Int) = Unit

        override fun getInputStream(): InputStream = input

        override fun getOutputStream(): OutputStream = output

        override fun close() {
            closeCounter.incrementAndGet()
            allCloseCalls.countDown()
        }
    }

    private class FailingBodyProofSocket(
        private val bodyDestination: AtomicReference<ByteArray?>,
    ) : Socket() {
        private val output = ByteArrayOutputStream()
        private val input = object : InputStream() {
            private var prefixOffset = 0
            private var deliveredBodyPrefix = false

            override fun read(): Int =
                if (prefixOffset < FIXED_BODY_RESPONSE_PREFIX.size) {
                    FIXED_BODY_RESPONSE_PREFIX[prefixOffset++]
                        .toInt()
                        .and(0xff)
                } else {
                    throw IOException(BODY_FAILURE_MARKER)
                }

            override fun read(
                bytes: ByteArray,
                offset: Int,
                length: Int,
            ): Int {
                check(prefixOffset == FIXED_BODY_RESPONSE_PREFIX.size)
                if (!deliveredBodyPrefix) {
                    deliveredBodyPrefix = true
                    bodyDestination.set(bytes)
                    bytes[offset] = 0x41
                    bytes[offset + 1] = 0x42
                    return 2
                }
                throw IOException(BODY_FAILURE_MARKER)
            }
        }

        override fun connect(
            endpoint: SocketAddress,
            timeout: Int,
        ) = Unit

        override fun setTcpNoDelay(on: Boolean) = Unit

        override fun setSoTimeout(timeout: Int) = Unit

        override fun getInputStream(): InputStream = input

        override fun getOutputStream(): OutputStream = output

        override fun close() = Unit
    }

    private class LateBodyProofSocket(
        private val bodyDestination: AtomicReference<ByteArray?>,
    ) : Socket() {
        val bodyReadStarted = CountDownLatch(1)
        val releaseBodyRead = CountDownLatch(1)
        private val output = ByteArrayOutputStream()
        private val input = object : InputStream() {
            private var prefixOffset = 0

            override fun read(): Int =
                if (prefixOffset < FIXED_BODY_RESPONSE_PREFIX.size) {
                    FIXED_BODY_RESPONSE_PREFIX[prefixOffset++]
                        .toInt()
                        .and(0xff)
                } else {
                    error("Late body fixture expected a bulk body read")
                }

            override fun read(
                bytes: ByteArray,
                offset: Int,
                length: Int,
            ): Int {
                check(prefixOffset == FIXED_BODY_RESPONSE_PREFIX.size)
                check(length >= FIXED_BODY_BYTES.size)
                bodyDestination.set(bytes)
                bodyReadStarted.countDown()
                releaseBodyRead.awaitPreservingInterrupt()
                FIXED_BODY_BYTES.copyInto(
                    destination = bytes,
                    destinationOffset = offset,
                )
                return FIXED_BODY_BYTES.size
            }
        }

        override fun connect(
            endpoint: SocketAddress,
            timeout: Int,
        ) = Unit

        override fun setTcpNoDelay(on: Boolean) = Unit

        override fun setSoTimeout(timeout: Int) = Unit

        override fun getInputStream(): InputStream = input

        override fun getOutputStream(): OutputStream = output

        override fun close() = Unit
    }

    private fun <T> withLoopbackHttpServer(
        responseWriter: (OutputStream) -> Unit,
        block: (Int) -> T,
    ): T {
        val loopback = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
        val server = ServerSocket(0, 1, loopback)
        val failure = AtomicReference<Throwable?>()
        val worker = thread(isDaemon = true, name = "task6-http-proof-server") {
            try {
                server.accept().use { socket ->
                    consumeRequestHeaders(socket.getInputStream())
                    responseWriter(socket.getOutputStream())
                }
            } catch (_: IOException) {
                // A deadline deliberately closes a drip-fed connection.
            } catch (unexpected: Throwable) {
                failure.set(unexpected)
            }
        }
        return try {
            block(server.localPort)
        } finally {
            server.close()
            worker.join(1_000)
            assertFalse(worker.isAlive)
            failure.get()?.let { throw it }
        }
    }

    private fun consumeRequestHeaders(input: InputStream) {
        var matched = 0
        repeat(8 * 1024) {
            val value = input.read()
            check(value >= 0) { "Task 6 HTTP test request ended early" }
            matched = if (value == HTTP_HEADER_END[matched].toInt()) {
                matched + 1
            } else if (value == HTTP_HEADER_END[0].toInt()) {
                1
            } else {
                0
            }
            if (matched == HTTP_HEADER_END.size) return
        }
        error("Task 6 HTTP test request headers exceeded their bound")
    }

    companion object {
        private const val SHORT_HTTP_TIMEOUT_MILLIS = 50
        private const val BOUNDED_HTTP_CALLER_MILLIS = 500L
        private const val SOCKET_FAILURE_MARKER =
            "task6-sensitive-socket-failure"
        private const val BODY_FAILURE_MARKER =
            "task6-sensitive-body-failure"
        private const val FIXED_BODY_SIZE = 5
        private const val BODY_BUFFER_SENTINEL: Byte = 0x5a
        private val HTTP_BOUNDARY_REQUEST_BODY =
            "proof=body".toByteArray(StandardCharsets.US_ASCII)
        private val HTTP_STATUS_LINE =
            "HTTP/1.0 200 OK\r\n".toByteArray(StandardCharsets.US_ASCII)
        private val FIXED_BODY_BYTES =
            "ABCDE".toByteArray(StandardCharsets.US_ASCII)
        private val SUCCESS_RESPONSE =
            (
                "HTTP/1.0 200 OK\r\n" +
                    "Content-Length: 0\r\n" +
                    "\r\n"
                ).toByteArray(StandardCharsets.US_ASCII)
        private val CLOSE_DELIMITED_RESPONSE_PREFIX =
            (
                "HTTP/1.0 200 OK\r\n" +
                    "\r\n"
                ).toByteArray(StandardCharsets.US_ASCII)
        private val CLOSE_DELIMITED_BODY_RESPONSE =
            CLOSE_DELIMITED_RESPONSE_PREFIX +
                "A".toByteArray(StandardCharsets.US_ASCII)
        private val FIXED_BODY_RESPONSE_PREFIX =
            (
                "HTTP/1.0 200 OK\r\n" +
                    "Content-Length: $FIXED_BODY_SIZE\r\n" +
                    "\r\n"
                ).toByteArray(StandardCharsets.US_ASCII)
        private val SHARED_CAPACITY_MESSAGE =
            (
                "From: sender@local.test\r\n" +
                    "To: task6-shared-capacity@local.test\r\n" +
                    "Date: Thu, 30 Jul 2026 12:00:00 +0000\r\n" +
                    "Subject: Task 6 shared capacity\r\n" +
                    "Message-ID: <task6-shared-capacity@local.test>\r\n" +
                    "MIME-Version: 1.0\r\n" +
                    "Content-Type: text/plain; charset=UTF-8\r\n" +
                    "\r\n" +
                    "Shared capacity proof.\r\n"
                ).toByteArray(StandardCharsets.US_ASCII)
        private val HTTP_HEADER_END =
            "\r\n\r\n".toByteArray(StandardCharsets.US_ASCII)
    }
}

private fun CountDownLatch.awaitPreservingInterrupt() {
    var interrupted = false
    while (count > 0L) {
        try {
            await()
        } catch (_: InterruptedException) {
            interrupted = true
        }
    }
    if (interrupted) {
        Thread.currentThread().interrupt()
    }
}

private class HttpFailureClassificationSentinel :
    RuntimeException("HTTP failure classification sentinel")
