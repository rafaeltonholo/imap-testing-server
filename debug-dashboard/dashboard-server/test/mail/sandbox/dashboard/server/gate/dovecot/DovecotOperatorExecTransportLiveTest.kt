package mail.sandbox.dashboard.server.gate.dovecot

import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.Test

class DovecotOperatorExecTransportLiveTest {
    @Test
    fun fixedExecTransportOwnsAndReapsEveryOperatorProcess() {
        val environment = System.getenv()
        if (!dovecotTask6ExecLiveProofSelected(environment)) return

        val repositoryRoot = repositoryRoot()
        val live = DovecotLiveTestEnvironment.load(
            environment = environment,
            repositoryRoot = repositoryRoot,
        )
        live.awaitReady()

        val launchProfile = live.operatorRuntime.launchProfile
        val inventory =
            DovecotTask6OperatorProcessInventory(launchProfile)
        val transportFactory =
            live.operatorRuntime.transportFactory()
        val eligibilityAdapter =
            Task6LaunchProfileEligibilityAdapter(launchProfile)
        val address =
            "task6-process-" +
                UUID.randomUUID().toString().replace("-", "") +
                "@local.test"
        val target = DovecotOperatorTarget.create(address)
        val eligibilityPaths = live.profile.eligibilityPaths()
        val eligibilityCli = EligibilityFileCli(
            pathsProvider = { eligibilityPaths },
            hasherFactory = { eligibilityAdapter },
        )
        val credentialStore = fixedCredentialStore(
            profile = live.profile,
            eligibilityAdapter = eligibilityAdapter,
        )
        val rejectionProbe = DovecotOperatorProbe(
            transportFactory = transportFactory,
        )
        var primaryFailure: Throwable? = null
        try {
            task6DisposableEligibilityFixture(
                address = address,
                paths = eligibilityPaths,
                executor = eligibilityCli,
                rejectionProof = {
                    awaitDovecotOperatorTargetRejection(
                        resultSupplier = {
                            rejectionProbe.probe(
                                target,
                                credentialStore.loadActive(),
                            )
                        },
                    )
                },
            ).run { targetPassword ->
                DovecotTask6ProcessProof(inventory).run(
                    LiveExecProcessScenarios(
                        transportFactory = transportFactory,
                        target = target,
                        targetPassword = targetPassword,
                        credentialSupplier =
                            credentialStore::loadActive,
                    ),
                )
            }
        } catch (failure: Throwable) {
            primaryFailure = failure
            throw failure
        } finally {
            val finalInventoryFailure = runCatching {
                check(inventory.count() == 0) {
                    FINAL_INVENTORY_FAILURE
                }
            }.exceptionOrNull()
            if (finalInventoryFailure != null) {
                val primary = primaryFailure
                if (primary != null) {
                    primary.addSuppressed(finalInventoryFailure)
                } else {
                    throw finalInventoryFailure
                }
            }
        }
    }

    private fun fixedCredentialStore(
        profile: DovecotTask5ProofProfile,
        eligibilityAdapter: Task6LaunchProfileEligibilityAdapter,
    ): DovecotOperatorCredentialStore =
        DovecotOperatorCredentialStore(
            paths = profile.operatorPaths(),
            hasher = DovecotOperatorHashBoundary {
                error(
                    "Process proof must not hash operator credentials",
                )
            },
            verifier = eligibilityAdapter,
            generator = DovecotOperatorSecretGenerator {
                error(
                    "Process proof must not generate operator credentials",
                )
            },
        )

    private fun repositoryRoot(): Path {
        val workingDirectory =
            Path.of(System.getProperty("user.dir"))
                .toAbsolutePath()
                .normalize()
        val dashboardRoot =
            if (
                workingDirectory.fileName?.toString() ==
                "dashboard-server"
            ) {
                requireNotNull(workingDirectory.parent)
            } else {
                workingDirectory
            }
        return requireNotNull(dashboardRoot.parent).also { root ->
            require(Files.isRegularFile(root.resolve("docker-compose.yml")))
        }
    }

    private companion object {
        const val FINAL_INVENTORY_FAILURE =
            "Dovecot Task 6 final operator process inventory was not zero"
    }
}

internal fun dovecotTask6ExecLiveProofSelected(
    environment: Map<String, String>,
): Boolean {
    val liveTests = environment["DOVECOT_LIVE_TESTS"] ?: return false
    require(
        liveTests == "1" &&
            environment["DOVECOT_LIVE_PROFILE"] == "task5-proof",
    ) {
        "The fixed Dovecot Task 6 live profile was not selected"
    }
    return true
}

internal class Task6OperatorTransportStartCounter(
    private val delegate: DovecotOperatorTransportFactory,
) : DovecotOperatorTransportFactory {
    private val starts = AtomicInteger()

    fun snapshot(): Int = starts.get()

    override fun open(
        registerAllocated: (DovecotOperatorTransport) -> Unit,
    ): DovecotOperatorTransport {
        starts.incrementAndGet()
        return delegate.open(registerAllocated)
    }
}

internal fun requireTask6SeventeenthRejectedWithoutTransportStart(
    startCount: () -> Int,
    attempt: () -> Unit,
) {
    val startsBefore = startCount()
    val failure = runCatching(attempt).exceptionOrNull()
    check(failure is IllegalStateException) {
        "The seventeenth operator process was not rejected"
    }
    check(startCount() == startsBefore) {
        "The seventeenth operator process started transport"
    }
}

private class LiveExecProcessScenarios(
    private val transportFactory: DovecotOperatorTransportFactory,
    private val target: DovecotOperatorTarget,
    private val targetPassword: EligibilityPassword,
    private val credentialSupplier: () -> DovecotOperatorCredential,
) : DovecotTask6ProcessScenarios {
    override fun runFinite(case: DovecotTask6FiniteProcessCase) {
        when (case) {
            DovecotTask6FiniteProcessCase.NormalClose ->
                requireNormalClose()
            DovecotTask6FiniteProcessCase.AuthenticationFailure ->
                requireAuthenticationFailure()
            DovecotTask6FiniteProcessCase.RegistrationFailure ->
                requireRegistrationFailure()
            DovecotTask6FiniteProcessCase.Timeout ->
                requireTimeout()
            DovecotTask6FiniteProcessCase.Interruption ->
                requireInterruption()
            DovecotTask6FiniteProcessCase.Abort ->
                requireAbort()
        }
    }

    override fun withHeldProcess(
        assertExactlyOne: () -> Unit,
    ) {
        val activeId = credentialSupplier().use { it.id }
        val leases =
            DovecotOperatorApplicationLeaseRegistry(activeId)
        val workers =
            DovecotBoundedOperationWorkers(maxOperations = 1)
        var held: LeasedHeldDovecotOperatorImapSession? = null
        var primaryFailure: Throwable? = null
        try {
            held = openHeld(
                index = 1,
                verificationLease = false,
                leases = leases,
                workers = workers,
            )
            check(leases.openLeaseCount(activeId) == 1) {
                "Held operator lease inventory was not exact"
            }
            assertExactlyOne()
        } catch (failure: Throwable) {
            primaryFailure = failure
            throw failure
        } finally {
            val cleanupFailure = cleanupHeldProcesses(
                holders = listOfNotNull(held),
                leases = leases,
                activeId = activeId,
                workers = workers,
            )
            if (cleanupFailure != null) {
                val primary = primaryFailure
                if (primary != null) {
                    primary.addSuppressed(cleanupFailure)
                } else {
                    throw cleanupFailure
                }
            }
        }
    }

    override fun withSaturatedProcesses(
        assertExactlySixteen: () -> Unit,
        assertNoSeventeenthStarted: () -> Unit,
    ) {
        val activeId = credentialSupplier().use { it.id }
        val leases =
            DovecotOperatorApplicationLeaseRegistry(activeId)
        val workers =
            DovecotBoundedOperationWorkers(maxOperations = 1)
        val countedTransportFactory =
            Task6OperatorTransportStartCounter(transportFactory)
        val held =
            mutableListOf<LeasedHeldDovecotOperatorImapSession>()
        var primaryFailure: Throwable? = null
        try {
            (1..16).forEach { index ->
                held += openHeld(
                    index = index,
                    verificationLease = index == 16,
                    leases = leases,
                    workers = workers,
                    transportFactory = countedTransportFactory,
                )
            }
            check(leases.openLeaseCount(activeId) == 16) {
                "Saturated operator lease inventory was not exact"
            }
            check(countedTransportFactory.snapshot() == 16) {
                "Saturated operator transport starts were not exact"
            }
            assertExactlySixteen()

            requireTask6SeventeenthRejectedWithoutTransportStart(
                startCount = countedTransportFactory::snapshot,
                attempt = {
                    openHeld(
                        index = 17,
                        verificationLease = false,
                        leases = leases,
                        workers = workers,
                        transportFactory = countedTransportFactory,
                    )
                },
            )
            check(countedTransportFactory.snapshot() == 16) {
                "Rejected operator process changed transport starts"
            }
            check(leases.openLeaseCount(activeId) == 16) {
                "Rejected operator process changed lease inventory"
            }
            assertNoSeventeenthStarted()

            leases.blockAndDrain(activeId)
            check(leases.openLeaseCount(activeId) == 0) {
                "Saturated operator leases did not drain"
            }
        } catch (failure: Throwable) {
            primaryFailure = failure
            throw failure
        } finally {
            val cleanupFailure = cleanupHeldProcesses(
                holders = held,
                leases = leases,
                activeId = activeId,
                workers = workers,
            )
            if (cleanupFailure != null) {
                val primary = primaryFailure
                if (primary != null) {
                    primary.addSuppressed(cleanupFailure)
                } else {
                    throw cleanupFailure
                }
            }
        }
    }

    private fun requireNormalClose() {
        withExchange(transportFactory) { exchange ->
            check(
                exchange.greetingReadiness() ==
                    DovecotOperatorProbeResult.Success,
            ) {
                "Normal operator process close did not succeed"
            }
        }
    }

    private fun requireAuthenticationFailure() {
        withExchange(transportFactory) { exchange ->
            check(
                exchange.authenticateBareTarget(
                    target = target,
                    password = targetPassword,
                ) ==
                    DovecotOperatorProbeResult.AuthenticationFailure,
            ) {
                "Operator authentication rejection was not exact"
            }
        }
    }

    private fun requireRegistrationFailure() {
        val failure = runCatching {
            transportFactory.open {
                throw IllegalStateException(
                    "Injected Task 6 registration failure",
                )
            }
        }.exceptionOrNull()
        check(
            failure is IOException &&
                failure.message ==
                "Dovecot operator process transport registration failed",
        ) {
            "Operator registration failure was not redacted"
        }
    }

    private fun requireTimeout() {
        val readEntered = CountDownLatch(1)
        val workers =
            DovecotBoundedOperationWorkers(maxOperations = 1)
        val watchdog = TriggeredTask6DeadlineWatchdog(readEntered)
        try {
            val result = DovecotOperatorBoundedExchange(
                transportFactory =
                    BlockingGreetingTransportFactory(
                        delegate = transportFactory,
                        readEntered = readEntered,
                    ),
                operationWorkers = workers,
                watchdog = watchdog,
            ).greetingReadiness()
            check(
                result == DovecotOperatorProbeResult.TransportFailure,
            ) {
                "Operator timeout did not fail transport"
            }
            check(
                readEntered.await(
                    LIVE_ACTOR_TIMEOUT_SECONDS,
                    TimeUnit.SECONDS,
                ),
            ) {
                "Operator timeout did not reach process I/O"
            }
        } finally {
            watchdog.close()
            awaitWorkersDrained(workers)
        }
    }

    private fun requireInterruption() {
        val readEntered = CountDownLatch(1)
        val workers =
            DovecotBoundedOperationWorkers(maxOperations = 1)
        val exchange = DovecotOperatorBoundedExchange(
            transportFactory =
                BlockingGreetingTransportFactory(
                    delegate = transportFactory,
                    readEntered = readEntered,
                ),
            operationWorkers = workers,
        )
        val result =
            AtomicReference<DovecotOperatorProbeResult?>()
        val failure = AtomicReference<Throwable?>()
        val interruptionRestored = AtomicBoolean()
        val caller = Thread(
            {
                try {
                    result.set(exchange.greetingReadiness())
                } catch (caught: Throwable) {
                    failure.set(caught)
                } finally {
                    interruptionRestored.set(
                        Thread.currentThread().isInterrupted,
                    )
                }
            },
            "task6-live-exec-interruption",
        ).also {
            it.isDaemon = true
            it.start()
        }
        try {
            check(
                readEntered.await(
                    LIVE_ACTOR_TIMEOUT_SECONDS,
                    TimeUnit.SECONDS,
                ),
            ) {
                "Operator interruption did not reach process I/O"
            }
            caller.interrupt()
            caller.join(
                TimeUnit.SECONDS.toMillis(
                    LIVE_ACTOR_TIMEOUT_SECONDS,
                ),
            )
            check(!caller.isAlive) {
                "Interrupted operator proof caller did not stop"
            }
            check(failure.get() == null) {
                "Interrupted operator proof threw unexpectedly"
            }
            check(
                result.get() ==
                    DovecotOperatorProbeResult.TransportFailure,
            ) {
                "Interrupted operator proof did not fail transport"
            }
            check(interruptionRestored.get()) {
                "Operator proof interruption was not restored"
            }
        } finally {
            if (caller.isAlive) {
                caller.interrupt()
                caller.join(
                    TimeUnit.SECONDS.toMillis(
                        LIVE_ACTOR_TIMEOUT_SECONDS,
                    ),
                )
            }
            awaitWorkersDrained(workers)
        }
    }

    private fun requireAbort() {
        withExchange(
            AbortAfterRegistrationTransportFactory(transportFactory),
        ) { exchange ->
            check(
                exchange.greetingReadiness() ==
                    DovecotOperatorProbeResult.TransportFailure,
            ) {
                "Aborted operator process did not fail transport"
            }
        }
    }

    private fun withExchange(
        factory: DovecotOperatorTransportFactory,
        block: (DovecotOperatorBoundedExchange) -> Unit,
    ) {
        val workers =
            DovecotBoundedOperationWorkers(maxOperations = 1)
        try {
            block(
                DovecotOperatorBoundedExchange(
                    transportFactory = factory,
                    operationWorkers = workers,
                ),
            )
        } finally {
            awaitWorkersDrained(workers)
        }
    }

    private fun openHeld(
        index: Int,
        verificationLease: Boolean,
        leases: DovecotOperatorApplicationLeaseRegistry,
        workers: DovecotBoundedOperationWorkers,
        transportFactory: DovecotOperatorTransportFactory =
            this.transportFactory,
    ): LeasedHeldDovecotOperatorImapSession {
        val credential = credentialSupplier()
        val message = task6ProcessProofMessage(target, index)
        return try {
            HeldDovecotOperatorImapSession.openAndSeedLeased(
                leaseRegistry = leases,
                transportFactory = transportFactory,
                target = target,
                credential = credential,
                message = message,
                verificationLease = verificationLease,
                operationWorkers = workers,
            )
        } catch (failure: Throwable) {
            credential.close()
            message.fill(0)
            throw failure
        }
    }

    private fun cleanupHeldProcesses(
        holders: List<LeasedHeldDovecotOperatorImapSession>,
        leases: DovecotOperatorApplicationLeaseRegistry,
        activeId: DovecotOperatorId,
        workers: DovecotBoundedOperationWorkers,
    ): Throwable? {
        var cleanupFailure: Throwable? = null

        fun attempt(block: () -> Unit) {
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

        holders.forEach { holder ->
            attempt(holder::close)
        }
        attempt {
            if (leases.openLeaseCount(activeId) != 0) {
                leases.blockAndDrain(activeId)
            }
        }
        attempt {
            awaitWorkersDrained(workers)
        }
        return cleanupFailure
    }
}

private class BlockingGreetingTransportFactory(
    private val delegate: DovecotOperatorTransportFactory,
    private val readEntered: CountDownLatch,
) : DovecotOperatorTransportFactory {
    override fun open(
        registerAllocated: (DovecotOperatorTransport) -> Unit,
    ): DovecotOperatorTransport {
        var wrapped: BlockingGreetingTransport? = null
        delegate.open { allocated ->
            check(wrapped == null) {
                "Operator process allocation was duplicated"
            }
            val candidate =
                BlockingGreetingTransport(allocated, readEntered)
            wrapped = candidate
            registerAllocated(candidate)
        }
        return checkNotNull(wrapped) {
            "Operator process allocation was absent"
        }
    }
}

private class BlockingGreetingTransport(
    private val delegate: DovecotOperatorTransport,
    private val readEntered: CountDownLatch,
) : DovecotOperatorTransport {
    private val releaseRead = CountDownLatch(1)
    private val blockingInput = object : InputStream() {
        override fun read(): Int {
            readEntered.countDown()
            var interrupted = false
            while (true) {
                try {
                    releaseRead.await()
                    break
                } catch (_: InterruptedException) {
                    interrupted = true
                }
            }
            if (interrupted) {
                Thread.currentThread().interrupt()
            }
            throw IOException(
                "Dovecot Task 6 blocking process read was cancelled",
            )
        }
    }

    override val input: InputStream
        get() = blockingInput

    override val outputStream: OutputStream
        get() = delegate.outputStream

    override fun abort() {
        releaseRead.countDown()
        delegate.abort()
    }

    override fun close() {
        releaseRead.countDown()
        delegate.close()
    }
}

private class AbortAfterRegistrationTransportFactory(
    private val delegate: DovecotOperatorTransportFactory,
) : DovecotOperatorTransportFactory {
    override fun open(
        registerAllocated: (DovecotOperatorTransport) -> Unit,
    ): DovecotOperatorTransport =
        delegate.open { allocated ->
            registerAllocated(allocated)
            allocated.abort()
        }
}

private class TriggeredTask6DeadlineWatchdog(
    private val readEntered: CountDownLatch,
) : DovecotOperatorProbeWatchdog, AutoCloseable {
    private val lock = Any()
    private var worker: Thread? = null

    override fun arm(onDeadline: () -> Unit): AutoCloseable {
        val actor = synchronized(lock) {
            check(worker == null) {
                "Task 6 deadline watchdog was already armed"
            }
            Thread(
                {
                    try {
                        if (
                            readEntered.await(
                                LIVE_ACTOR_TIMEOUT_SECONDS,
                                TimeUnit.SECONDS,
                            )
                        ) {
                            onDeadline()
                        }
                    } catch (_: InterruptedException) {
                        Thread.currentThread().interrupt()
                    }
                },
                "task6-live-exec-deadline",
            ).also {
                it.isDaemon = true
                worker = it
                it.start()
            }
        }
        return AutoCloseable {
            stop(actor)
        }
    }

    override fun close() {
        synchronized(lock) { worker }?.let(::stop)
    }

    private fun stop(actor: Thread) {
        actor.interrupt()
        actor.join(
            TimeUnit.SECONDS.toMillis(
                LIVE_ACTOR_TIMEOUT_SECONDS,
            ),
        )
        check(!actor.isAlive) {
            "Task 6 deadline watchdog did not stop"
        }
        synchronized(lock) {
            if (worker === actor) {
                worker = null
            }
        }
    }
}

private fun awaitWorkersDrained(
    workers: DovecotBoundedOperationWorkers,
) {
    val deadline =
        System.nanoTime() +
            TimeUnit.SECONDS.toNanos(
                LIVE_ACTOR_TIMEOUT_SECONDS,
            )
    while (System.nanoTime() < deadline) {
        val snapshot = workers.snapshot()
        if (
            snapshot.activeOperations == 0 &&
            snapshot.abandonedOperations == 0 &&
            snapshot.activeActors == 0
        ) {
            return
        }
        Thread.sleep(10)
    }
    error("Dovecot Task 6 process workers did not drain")
}

private fun task6ProcessProofMessage(
    target: DovecotOperatorTarget,
    index: Int,
): ByteArray {
    require(index in 1..17)
    return (
        "From: dashboard-process-proof@local.test\r\n" +
            "To: ${target.address}\r\n" +
            "Date: Thu, 30 Jul 2026 12:00:00 +0000\r\n" +
            "Subject: Dovecot Task 6 process proof $index\r\n" +
            "Message-ID: <task6-process-$index.${target.address}>\r\n" +
            "MIME-Version: 1.0\r\n" +
            "Content-Type: text/plain; charset=UTF-8\r\n" +
            "\r\n" +
            "Deterministic Dovecot Task 6 process proof.\r\n"
        ).toByteArray(StandardCharsets.US_ASCII)
}

private const val LIVE_ACTOR_TIMEOUT_SECONDS = 3L
