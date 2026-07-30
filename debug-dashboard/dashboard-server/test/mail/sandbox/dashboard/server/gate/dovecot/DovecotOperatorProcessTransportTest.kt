package mail.sandbox.dashboard.server.gate.dovecot

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.nio.file.Files
import java.nio.file.Path
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertSame
import kotlin.test.assertTrue

class DovecotOperatorProcessTransportTest {
    @Test
    fun processFactoryStartsExactlyOnceAndMapsChildStandardStreams() =
        withLaunchFixture { fixture ->
            val events = mutableListOf<String>()
            val process = ControlledTestProcess(
                events = events,
                waitResults = listOf(true),
            )
            var starts = 0
            var registered: DovecotOperatorTransport? = null
            val profile = fixture.profile()
            val factory = JvmDockerExecDovecotOperatorTransportFactory(
                profile = profile,
                starter = DovecotOperatorProcessStarter { actualProfile ->
                    starts += 1
                    assertSame(profile, actualProfile)
                    events += "start"
                    process
                },
            )

            val transport = factory.open { allocated ->
                events += "register"
                registered = allocated
            }
            val guardedInput = transport.input
            val guardedOutput = transport.outputStream

            assertEquals(1, starts)
            assertSame(transport, registered)
            assertFalse(process.childStdout === guardedInput)
            assertFalse(process.childStdin === guardedOutput)
            assertSame(guardedInput, transport.input)
            assertSame(guardedOutput, transport.outputStream)
            assertEquals(1, process.stdoutRequests)
            assertEquals(1, process.stdinRequests)
            assertEquals(
                listOf(
                    "start",
                    "child-stdin.acquire",
                    "child-stdout.acquire",
                    "register",
                ),
                events,
            )
        }

    @Test
    fun processFactoryRegistersAllocationBeforeAnyProtocolUse() =
        withLaunchFixture { fixture ->
            val process = ControlledTestProcess(
                events = mutableListOf(),
                waitResults = listOf(true),
            )
            var registrationCalls = 0
            val factory = JvmDockerExecDovecotOperatorTransportFactory(
                profile = fixture.profile(),
                starter = DovecotOperatorProcessStarter { process },
            )

            val transport = factory.open { allocated ->
                registrationCalls += 1
                assertEquals(0, process.childStdout.readCalls)
                assertEquals(0, process.childStdin.writeCalls)
                assertFalse(process.childStdout === allocated.input)
                assertFalse(process.childStdin === allocated.outputStream)
                assertSame(allocated.input, allocated.input)
                assertSame(
                    allocated.outputStream,
                    allocated.outputStream,
                )
            }

            assertEquals(1, registrationCalls)
            assertSame(transport.input, transport.input)
            assertSame(transport.outputStream, transport.outputStream)
            assertEquals(0, process.timedWaits.size)
            assertEquals(0, process.destroyCalls)
            assertEquals(0, process.destroyForciblyCalls)
        }

    @Test
    fun guardedProcessStreamsDelegateReadBulkWriteAndFlush() =
        withLaunchFixture { fixture ->
            val process = ControlledTestProcess(
                events = mutableListOf(),
                waitResults = listOf(true),
                stdoutContents = byteArrayOf(65, 66),
            )
            val transport =
                JvmDockerExecDovecotOperatorTransportFactory(
                    profile = fixture.profile(),
                    starter =
                        DovecotOperatorProcessStarter { process },
                ).open {}
            val guardedInput = transport.input
            val guardedOutput = transport.outputStream
            val received = ByteArray(2)

            assertEquals(
                2,
                guardedInput.read(received, 0, received.size),
            )
            guardedOutput.write(byteArrayOf(7, 8, 9), 1, 2)
            guardedOutput.flush()

            assertTrue(received.contentEquals(byteArrayOf(65, 66)))
            assertTrue(
                process.childStdin
                    .toByteArray()
                    .contentEquals(byteArrayOf(8, 9)),
            )
            assertEquals(1, process.childStdout.readCalls)
            assertEquals(1, process.childStdin.writeCalls)
            assertEquals(1, process.childStdin.flushCalls)
            assertSame(guardedInput, transport.input)
            assertSame(guardedOutput, transport.outputStream)

            transport.close()
        }

    @Test
    fun guardedProcessStreamFailuresAreFixedRedactedAndRestoreInterrupt() =
        withLaunchFixture { fixture ->
            val writeSecret =
                "raw stdin write leaked request-password"
            val readSecret =
                "raw stdout read leaked request-user"
            val process = ControlledTestProcess(
                events = mutableListOf(),
                waitResults = listOf(true),
                stdinOperationFailure =
                    IOException(writeSecret),
                stdoutOperationFailure =
                    InterruptedException(readSecret),
            )
            val transport =
                JvmDockerExecDovecotOperatorTransportFactory(
                    profile = fixture.profile(),
                    starter =
                        DovecotOperatorProcessStarter { process },
                ).open {}

            val writeFailure = assertFailsWith<IOException> {
                transport.outputStream.flush()
            }
            assertEquals(
                "Dovecot operator process stream operation failed",
                writeFailure.message,
            )
            assertEquals(null, writeFailure.cause)
            assertTrue(writeFailure.suppressed.isEmpty())
            assertFalse(writeFailure.toString().contains(writeSecret))

            try {
                val readFailure = assertFailsWith<IOException> {
                    transport.input.read()
                }
                assertTrue(Thread.currentThread().isInterrupted)
                assertEquals(
                    "Dovecot operator process stream operation failed",
                    readFailure.message,
                )
                assertEquals(null, readFailure.cause)
                assertTrue(readFailure.suppressed.isEmpty())
                assertFalse(readFailure.toString().contains(readSecret))
            } finally {
                Thread.interrupted()
            }

            transport.abort()
        }

    @Test
    fun processFactoryRedactsStarterFailureAndNeverRegisters() =
        withLaunchFixture { fixture ->
            val secret =
                "docker exec failed for request-password via hostile-context"
            var starts = 0
            var registrations = 0
            val factory = JvmDockerExecDovecotOperatorTransportFactory(
                profile = fixture.profile(),
                starter = DovecotOperatorProcessStarter {
                    starts += 1
                    throw AssertionError(secret)
                },
            )

            val failure = assertFailsWith<IOException> {
                factory.open {
                    registrations += 1
                }
            }

            assertEquals(1, starts)
            assertEquals(0, registrations)
            assertEquals(
                "Dovecot operator process transport start failed",
                failure.message,
            )
            assertEquals(null, failure.cause)
            assertTrue(failure.suppressed.isEmpty())
            assertFalse(failure.toString().contains(secret))
        }

    @Test
    fun processFactoryCleansAndReapsWhenRegistrationFails() =
        withLaunchFixture { fixture ->
            val events = mutableListOf<String>()
            val process = ControlledTestProcess(
                events = events,
                waitResults = listOf(true),
            )
            val secret =
                "registration rejected request-user and operator.example.test"
            val factory = JvmDockerExecDovecotOperatorTransportFactory(
                profile = fixture.profile(),
                starter = DovecotOperatorProcessStarter {
                    events += "start"
                    process
                },
            )

            val failure = assertFailsWith<IOException> {
                factory.open {
                    events += "register"
                    throw AssertionError(secret)
                }
            }

            assertEquals(
                "Dovecot operator process transport registration failed",
                failure.message,
            )
            assertEquals(null, failure.cause)
            assertTrue(failure.suppressed.isEmpty())
            assertFalse(failure.toString().contains(secret))
            assertEquals(1, process.childStdin.closeCalls)
            assertEquals(1, process.childStdout.closeCalls)
            assertEquals(
                listOf(500L to TimeUnit.MILLISECONDS),
                process.timedWaits,
            )
            assertEquals(0, process.destroyCalls)
            assertEquals(0, process.destroyForciblyCalls)
            assertEquals(0, process.stderrRequests)
            assertEquals(
                listOf(
                    "start",
                    "child-stdin.acquire",
                    "child-stdout.acquire",
                    "register",
                    "child-stdin.close",
                    "wait:500:MILLISECONDS",
                    "child-stdout.close",
                ),
                events,
            )
        }

    @Test
    fun normalCloseWaitsWithStdoutOpenAndRequiresNaturalZeroExit() =
        withLaunchFixture { fixture ->
            val events = mutableListOf<String>()
            val process = ControlledTestProcess(
                events = events,
                waitResults = listOf(true),
                configuredExitCode = 0,
            )
            val transport = JvmDockerExecDovecotOperatorTransportFactory(
                profile = fixture.profile(),
                starter = DovecotOperatorProcessStarter { process },
            ).open {}
            events.clear()

            transport.close()

            assertEquals(
                listOf(
                    "child-stdin.close",
                    "wait:500:MILLISECONDS",
                    "child-stdout.close",
                    "exitValue",
                ),
                events,
            )
            assertEquals(
                listOf(500L to TimeUnit.MILLISECONDS),
                process.timedWaits,
            )
            assertEquals(1, process.childStdin.closeCalls)
            assertEquals(1, process.childStdout.closeCalls)
            assertEquals(0, process.destroyCalls)
            assertEquals(0, process.destroyForciblyCalls)
        }

    @Test
    fun normalCloseReportsFixedRedactedFailureForNaturalNonzeroExit() =
        withLaunchFixture { fixture ->
            val events = mutableListOf<String>()
            val process = ControlledTestProcess(
                events = events,
                waitResults = listOf(true),
                configuredExitCode = 23,
            )
            val transport = JvmDockerExecDovecotOperatorTransportFactory(
                profile = fixture.profile(),
                starter = DovecotOperatorProcessStarter { process },
            ).open {}
            events.clear()

            val failure = assertFailsWith<IOException> {
                transport.close()
            }

            assertEquals(
                "Dovecot operator process transport close failed",
                failure.message,
            )
            assertEquals(null, failure.cause)
            assertTrue(failure.suppressed.isEmpty())
            assertFalse(failure.toString().contains("23"))
            assertEquals(
                listOf(
                    "child-stdin.close",
                    "wait:500:MILLISECONDS",
                    "child-stdout.close",
                    "exitValue",
                ),
                events,
            )
            assertEquals(0, process.stderrRequests)
            assertEquals(0, process.childStderrReadCalls)
        }

    @Test
    fun normalCloseDestroysAndReapsButFailsWhenNaturalWaitExpires() =
        withLaunchFixture { fixture ->
            val events = mutableListOf<String>()
            val process = ControlledTestProcess(
                events = events,
                waitResults = listOf(false, true),
                configuredExitCode = 143,
            )
            val transport = JvmDockerExecDovecotOperatorTransportFactory(
                profile = fixture.profile(),
                starter = DovecotOperatorProcessStarter { process },
            ).open {}
            events.clear()

            val failure = assertFailsWith<IOException> {
                transport.close()
            }

            assertEquals(
                "Dovecot operator process transport close failed",
                failure.message,
            )
            assertEquals(
                listOf(
                    "child-stdin.close",
                    "wait:500:MILLISECONDS",
                    "child-stdout.close",
                    "destroy",
                    "wait:250:MILLISECONDS",
                ),
                events,
            )
            assertEquals(
                listOf(
                    500L to TimeUnit.MILLISECONDS,
                    250L to TimeUnit.MILLISECONDS,
                ),
                process.timedWaits,
            )
            assertEquals(1, process.destroyCalls)
            assertEquals(0, process.destroyForciblyCalls)
            assertTrue(process.reaped)
        }

    @Test
    fun normalCloseForcesAndFinallyReapsWithinTheFixedOneSecondBudget() =
        withLaunchFixture { fixture ->
            val events = mutableListOf<String>()
            val process = ControlledTestProcess(
                events = events,
                waitResults = listOf(false, false, true),
                configuredExitCode = 137,
            )
            val transport = JvmDockerExecDovecotOperatorTransportFactory(
                profile = fixture.profile(),
                starter = DovecotOperatorProcessStarter { process },
            ).open {}
            events.clear()

            val failure = assertFailsWith<IOException> {
                transport.close()
            }

            assertEquals(
                "Dovecot operator process transport close failed",
                failure.message,
            )
            assertEquals(
                listOf(
                    "child-stdin.close",
                    "wait:500:MILLISECONDS",
                    "child-stdout.close",
                    "destroy",
                    "wait:250:MILLISECONDS",
                    "destroyForcibly",
                    "wait:250:MILLISECONDS",
                ),
                events,
            )
            assertEquals(
                listOf(
                    500L to TimeUnit.MILLISECONDS,
                    250L to TimeUnit.MILLISECONDS,
                    250L to TimeUnit.MILLISECONDS,
                ),
                process.timedWaits,
            )
            assertEquals(1, process.destroyCalls)
            assertEquals(1, process.destroyForciblyCalls)
            assertTrue(process.reaped)
        }

    @Test
    fun normalCloseFailsWhenForcedChildStillCannotBeReaped() =
        withLaunchFixture { fixture ->
            val events = mutableListOf<String>()
            val process = ControlledTestProcess(
                events = events,
                waitResults = listOf(false, false, false),
            )
            val transport = JvmDockerExecDovecotOperatorTransportFactory(
                profile = fixture.profile(),
                starter = DovecotOperatorProcessStarter { process },
            ).open {}
            events.clear()

            val failure = assertFailsWith<IOException> {
                transport.close()
            }

            assertEquals(
                "Dovecot operator process transport close failed",
                failure.message,
            )
            assertEquals(3, process.timedWaits.size)
            assertEquals(1, process.destroyCalls)
            assertEquals(1, process.destroyForciblyCalls)
            assertFalse(process.reaped)
        }

    @Test
    fun abortAcceptsForcedNonzeroExitAfterBoundedReaping() =
        withLaunchFixture { fixture ->
            val events = mutableListOf<String>()
            val process = ControlledTestProcess(
                events = events,
                waitResults = listOf(false, true),
                configuredExitCode = 137,
            )
            val transport = JvmDockerExecDovecotOperatorTransportFactory(
                profile = fixture.profile(),
                starter = DovecotOperatorProcessStarter { process },
            ).open {}
            events.clear()

            transport.abort()

            assertEquals(
                listOf(
                    "destroy",
                    "wait:250:MILLISECONDS",
                    "destroyForcibly",
                    "wait:250:MILLISECONDS",
                    "child-stdin.close",
                    "child-stdout.close",
                ),
                events,
            )
            assertTrue(process.reaped)
            assertEquals(0, process.stderrRequests)
            assertEquals(0, process.childStderrReadCalls)
        }

    @Test
    fun abortFailsRedactedWhenForcedChildCannotBeReaped() =
        withLaunchFixture { fixture ->
            val events = mutableListOf<String>()
            val process = ControlledTestProcess(
                events = events,
                waitResults = listOf(false, false),
            )
            val transport = JvmDockerExecDovecotOperatorTransportFactory(
                profile = fixture.profile(),
                starter = DovecotOperatorProcessStarter { process },
            ).open {}
            events.clear()

            val failure = assertFailsWith<IOException> {
                transport.abort()
            }

            assertEquals(
                "Dovecot operator process transport abort failed",
                failure.message,
            )
            assertEquals(null, failure.cause)
            assertTrue(failure.suppressed.isEmpty())
            assertEquals(2, process.timedWaits.size)
            assertEquals(1, process.destroyCalls)
            assertEquals(1, process.destroyForciblyCalls)
            assertFalse(process.reaped)
            assertEquals(0, process.childStdin.closeCalls)
            assertEquals(0, process.childStdout.closeCalls)
            assertEquals(
                listOf(
                    "destroy",
                    "wait:250:MILLISECONDS",
                    "destroyForcibly",
                    "wait:250:MILLISECONDS",
                ),
                events,
            )
            assertEquals(
                null,
                transport.terminalStreamReference("childStdin"),
            )
            assertEquals(
                null,
                transport.terminalStreamReference("childStdout"),
            )
        }

    @Test
    fun abortFailsRedactedWhenReapedChildStreamsDoNotClose() =
        withLaunchFixture { fixture ->
            val events = mutableListOf<String>()
            val process = ControlledTestProcess(
                events = events,
                waitResults = listOf(true),
                stdinCloseFailure =
                    IOException("stdin close request-password"),
                stdoutCloseFailure =
                    IOException("stdout close request-user"),
            )
            val transport = JvmDockerExecDovecotOperatorTransportFactory(
                profile = fixture.profile(),
                starter = DovecotOperatorProcessStarter { process },
            ).open {}
            events.clear()

            val failure = assertFailsWith<IOException> {
                transport.abort()
            }

            assertEquals(
                "Dovecot operator process transport abort failed",
                failure.message,
            )
            assertEquals(null, failure.cause)
            assertTrue(failure.suppressed.isEmpty())
            assertEquals(
                listOf(
                    "destroy",
                    "wait:250:MILLISECONDS",
                    "child-stdin.close",
                    "child-stdout.close",
                ),
                events,
            )
            assertEquals(1, process.childStdin.closeCalls)
            assertEquals(1, process.childStdout.closeCalls)
            assertTrue(process.reaped)
        }

    @Test
    fun registrationFailureForcesAndReapsBeforeReturningRedactedFailure() =
        withLaunchFixture { fixture ->
            val events = mutableListOf<String>()
            val process = ControlledTestProcess(
                events = events,
                waitResults = listOf(false, false, true),
                configuredExitCode = 137,
            )
            val factory = JvmDockerExecDovecotOperatorTransportFactory(
                profile = fixture.profile(),
                starter = DovecotOperatorProcessStarter {
                    events += "start"
                    process
                },
            )

            val failure = assertFailsWith<IOException> {
                factory.open {
                    events += "register"
                    throw IllegalStateException(
                        "request-password registration failure",
                    )
                }
            }

            assertEquals(
                "Dovecot operator process transport registration failed",
                failure.message,
            )
            assertEquals(
                listOf(
                    "start",
                    "child-stdin.acquire",
                    "child-stdout.acquire",
                    "register",
                    "child-stdin.close",
                    "wait:500:MILLISECONDS",
                    "child-stdout.close",
                    "destroy",
                    "wait:250:MILLISECONDS",
                    "destroyForcibly",
                    "wait:250:MILLISECONDS",
                ),
                events,
            )
            assertTrue(process.reaped)
            assertEquals(0, process.stderrRequests)
            assertEquals(0, process.childStderrReadCalls)
        }

    @Test
    fun concurrentCloseAndUnreapedAbortCanonicalizeOneTermination() =
        withLaunchFixture { fixture ->
            val firstWaitEntered = CountDownLatch(1)
            val releaseFirstWait = CountDownLatch(1)
            val process = ControlledTestProcess(
                events = mutableListOf(),
                waitResults = listOf(false, false, true),
                configuredExitCode = 137,
                firstWaitEntered = firstWaitEntered,
                releaseFirstWait = releaseFirstWait,
            )
            val transport = JvmDockerExecDovecotOperatorTransportFactory(
                profile = fixture.profile(),
                starter = DovecotOperatorProcessStarter { process },
            ).open {}
            val closeFailure = AtomicReference<Throwable?>()
            val abortFailure = AtomicReference<Throwable?>()
            val abortStarted = CountDownLatch(1)
            val closeCaller = Thread(
                {
                    try {
                        transport.close()
                    } catch (failure: Throwable) {
                        closeFailure.set(failure)
                    }
                },
                "dovecot-process-close-caller",
            )
            val abortCaller = Thread(
                {
                    abortStarted.countDown()
                    try {
                        transport.abort()
                    } catch (failure: Throwable) {
                        abortFailure.set(failure)
                    }
                },
                "dovecot-process-abort-caller",
            )

            try {
                closeCaller.start()
                assertTrue(
                    firstWaitEntered.await(
                        TEST_SAFETY_TIMEOUT_SECONDS,
                        TimeUnit.SECONDS,
                    ),
                )
                abortCaller.start()
                assertTrue(
                    abortStarted.await(
                        TEST_SAFETY_TIMEOUT_SECONDS,
                        TimeUnit.SECONDS,
                    ),
                )
                assertTrue(
                    abortCaller.awaitState(Thread.State.BLOCKED),
                    "Abort caller did not overlap the close lifecycle",
                )
                releaseFirstWait.countDown()
                closeCaller.join(TEST_SAFETY_TIMEOUT_MILLIS)
                abortCaller.join(TEST_SAFETY_TIMEOUT_MILLIS)

                assertFalse(closeCaller.isAlive)
                assertFalse(abortCaller.isAlive)
                assertTrue(closeFailure.get() is IOException)
                val rejectedAbort = abortFailure.get()
                assertTrue(rejectedAbort is IOException)
                assertEquals(
                    "Dovecot operator process transport abort failed",
                    rejectedAbort.message,
                )
                assertEquals(1, process.childStdin.closeCalls)
                assertEquals(0, process.childStdout.closeCalls)
                assertEquals(3, process.timedWaits.size)
                assertEquals(1, process.destroyCalls)
                assertEquals(1, process.destroyForciblyCalls)
                assertTrue(process.reaped)
                val outcome =
                    checkNotNull(transport.terminationOutcomeReference())
                assertEquals(
                    false,
                    outcome.privateFieldValue("reaped"),
                )
                assertEquals(
                    false,
                    outcome.privateFieldValue("naturalExit"),
                )
                assertEquals(
                    true,
                    outcome.privateFieldValue("terminationRequired"),
                )
                assertEquals(
                    false,
                    outcome.privateFieldValue("streamsClosed"),
                )
                assertEquals(
                    null,
                    outcome.privateFieldValue("exitCode"),
                )
            } finally {
                releaseFirstWait.countDown()
                closeCaller.join(TEST_SAFETY_TIMEOUT_MILLIS)
                abortCaller.join(TEST_SAFETY_TIMEOUT_MILLIS)
            }
        }

    @Test
    fun closeDefersRawStdinHeldByAnAdmittedProtocolWriter() =
        withLaunchFixture { fixture ->
            val events =
                Collections.synchronizedList(mutableListOf<String>())
            val process = BlockingPipeTestProcess(events)
            val transport = JvmDockerExecDovecotOperatorTransportFactory(
                profile = fixture.profile(),
                starter = DovecotOperatorProcessStarter { process },
            ).open {}
            val childStdin = transport.outputStream
            events.clear()
            val writerFailure = AtomicReference<Throwable?>()
            val closeFailure = AtomicReference<Throwable?>()
            val abortFailure = AtomicReference<Throwable?>()
            val closeStarted = CountDownLatch(1)
            val abortStarted = CountDownLatch(1)
            val writer = Thread(
                {
                    try {
                        childStdin.write(1)
                    } catch (failure: Throwable) {
                        writerFailure.set(failure)
                    }
                },
                "dovecot-blocking-pipe-writer",
            )
            val closeCaller = Thread(
                {
                    closeStarted.countDown()
                    try {
                        transport.close()
                    } catch (failure: Throwable) {
                        closeFailure.set(failure)
                    }
                },
                "dovecot-blocked-normal-close",
            )
            val abortCaller = Thread(
                {
                    abortStarted.countDown()
                    try {
                        transport.abort()
                    } catch (failure: Throwable) {
                        abortFailure.set(failure)
                    }
                },
                "dovecot-preemptive-abort",
            )

            try {
                writer.start()
                assertTrue(
                    process.writerEntered.await(
                        TEST_SAFETY_TIMEOUT_SECONDS,
                        TimeUnit.SECONDS,
                    ),
                )
                closeCaller.start()
                assertTrue(
                    closeStarted.await(
                        TEST_SAFETY_TIMEOUT_SECONDS,
                        TimeUnit.SECONDS,
                    ),
                )
                assertTrue(
                    process.destroyReached.await(
                        TEST_SAFETY_TIMEOUT_SECONDS,
                        TimeUnit.SECONDS,
                    ),
                    "Close did not bypass the admitted raw stdin write",
                )
                abortCaller.start()
                assertTrue(
                    abortStarted.await(
                        TEST_SAFETY_TIMEOUT_SECONDS,
                        TimeUnit.SECONDS,
                    ),
                )

                writer.join(TEST_SAFETY_TIMEOUT_MILLIS)
                closeCaller.join(TEST_SAFETY_TIMEOUT_MILLIS)
                abortCaller.join(TEST_SAFETY_TIMEOUT_MILLIS)

                assertFalse(writer.isAlive)
                assertFalse(closeCaller.isAlive)
                assertFalse(abortCaller.isAlive)
                assertEquals(null, writerFailure.get())
                assertTrue(closeFailure.get() is IOException)
                assertTrue(abortFailure.get() is IOException)
                assertEquals(1, process.destroyCalls)
                assertEquals(0, process.destroyForciblyCalls)
                assertTrue(process.reaped)
                val destroyIndex = events.indexOf("destroy")
                val stdinCloseIndex = events.indexOf("child-stdin.close")
                assertTrue(destroyIndex >= 0)
                assertTrue(stdinCloseIndex > destroyIndex)
            } finally {
                process.releaseAll()
                writer.interrupt()
                writer.join(TEST_SAFETY_TIMEOUT_MILLIS)
                closeCaller.join(TEST_SAFETY_TIMEOUT_MILLIS)
                abortCaller.join(TEST_SAFETY_TIMEOUT_MILLIS)
            }
        }

    @Test
    fun abortReapsBeforeDeferredStreamCleanupWhenDestroyReturnsAsynchronously() =
        assertAbortReapsBeforeDeferredStreamCleanup(
            destroyFailure = null,
            secret = null,
        )

    @Test
    fun abortReapsBeforeDeferredStreamCleanupWhenDestroyThrowsSecretError() {
        val secret = "destroy request-password async failure"

        assertAbortReapsBeforeDeferredStreamCleanup(
            destroyFailure = AssertionError(secret),
            secret = secret,
        )
    }

    @Test
    fun unreapedAbortFailsWithoutEnteringContendedStreamCleanup() =
        withLaunchFixture { fixture ->
            val events =
                Collections.synchronizedList(mutableListOf<String>())
            val process =
                UnreapedAbortBlockingPipeTestProcess(events)
            val transport =
                JvmDockerExecDovecotOperatorTransportFactory(
                    profile = fixture.profile(),
                    starter =
                        DovecotOperatorProcessStarter { process },
                ).open {}
            val childStdin = transport.outputStream
            events.clear()
            val writerFailure = AtomicReference<Throwable?>()
            val closeFailure = AtomicReference<Throwable?>()
            val abortFailure = AtomicReference<Throwable?>()
            val closeStarted = CountDownLatch(1)
            val closeFinished = CountDownLatch(1)
            val abortFinished = CountDownLatch(1)
            val writer = Thread(
                {
                    try {
                        childStdin.write(1)
                    } catch (failure: Throwable) {
                        writerFailure.set(failure)
                    }
                },
                "dovecot-unreaped-abort-blocking-writer",
            )
            val abortCaller = Thread(
                {
                    try {
                        transport.abort()
                    } catch (failure: Throwable) {
                        abortFailure.set(failure)
                    } finally {
                        abortFinished.countDown()
                    }
                },
                "dovecot-unreaped-abort-caller",
            )
            val closeCaller = Thread(
                {
                    closeStarted.countDown()
                    try {
                        transport.close()
                    } catch (failure: Throwable) {
                        closeFailure.set(failure)
                    } finally {
                        closeFinished.countDown()
                    }
                },
                "dovecot-unreaped-abort-close-owner",
            )

            try {
                writer.start()
                assertTrue(
                    process.writerEntered.await(
                        TEST_SAFETY_TIMEOUT_SECONDS,
                        TimeUnit.SECONDS,
                    ),
                )
                abortCaller.start()
                assertTrue(
                    process.finalWaitEntered.await(
                        TEST_SAFETY_TIMEOUT_SECONDS,
                        TimeUnit.SECONDS,
                    ),
                    "Abort did not enter its final bounded reap attempt",
                )

                closeCaller.start()
                assertTrue(
                    closeStarted.await(
                        TEST_SAFETY_TIMEOUT_SECONDS,
                        TimeUnit.SECONDS,
                    ),
                )
                assertTrue(
                    closeCaller.awaitState(Thread.State.BLOCKED),
                    "Close did not wait for abort handshake acknowledgement",
                )
                assertEquals(0, process.childStdin.closeAttempts)
                assertEquals(0, process.childStdout.closeCalls)
                assertEquals(null, transport.terminationOutcomeReference())

                process.releaseFinalWait()
                assertTrue(
                    awaitCallersOrCloseAttempt(
                        closeFinished = closeFinished,
                        abortFinished = abortFinished,
                        closeAttempted =
                            process.childStdin.closeAttempted,
                    ),
                    "Callers neither completed nor attempted stream cleanup",
                )
                assertEquals(
                    1L,
                    process.childStdin.closeAttempted.count,
                    "Unreaped abort entered child stdin cleanup",
                )
                assertEquals(
                    0L,
                    closeFinished.count,
                    "Close did not return its bounded failure",
                )
                assertEquals(
                    0L,
                    abortFinished.count,
                    "Abort did not return its bounded failure",
                )
                closeCaller.join(TEST_SAFETY_TIMEOUT_MILLIS)
                abortCaller.join(TEST_SAFETY_TIMEOUT_MILLIS)

                assertFalse(closeCaller.isAlive)
                assertFalse(abortCaller.isAlive)
                assertTrue(writer.isAlive)
                val rejectedClose = closeFailure.get()
                assertTrue(rejectedClose is IOException)
                assertEquals(
                    "Dovecot operator process transport close failed",
                    rejectedClose.message,
                )
                assertEquals(null, rejectedClose.cause)
                assertTrue(rejectedClose.suppressed.isEmpty())
                val rejectedAbort = abortFailure.get()
                assertTrue(rejectedAbort is IOException)
                assertEquals(
                    "Dovecot operator process transport abort failed",
                    rejectedAbort.message,
                )
                assertEquals(null, rejectedAbort.cause)
                assertTrue(rejectedAbort.suppressed.isEmpty())
                assertFalse(process.reaped)
                assertEquals(0, process.exitValueCalls)
                assertEquals(0, process.childStdin.closeAttempts)
                assertEquals(0, process.childStdout.closeCalls)
                assertEquals(1, process.destroyCalls)
                assertEquals(1, process.destroyForciblyCalls)
                assertEquals(
                    listOf(
                        250L to TimeUnit.MILLISECONDS,
                        250L to TimeUnit.MILLISECONDS,
                    ),
                    process.timedWaits,
                )
                assertEquals(
                    listOf(
                        "destroy",
                        "wait:250:MILLISECONDS",
                        "destroyForcibly",
                        "wait:250:MILLISECONDS",
                    ),
                    events.filterNot {
                        event -> event.startsWith("writer.")
                    },
                )
                assertEquals(
                    null,
                    transport.terminalStreamReference("childStdin"),
                )
                assertEquals(
                    null,
                    transport.terminalStreamReference("childStdout"),
                )
                assertFailsWith<IllegalStateException> {
                    transport.input
                }
                assertFailsWith<IllegalStateException> {
                    transport.outputStream
                }

                val outcome =
                    checkNotNull(transport.terminationOutcomeReference())
                assertEquals(
                    false,
                    outcome.privateFieldValue("reaped"),
                )
                assertEquals(
                    false,
                    outcome.privateFieldValue("naturalExit"),
                )
                assertEquals(
                    false,
                    outcome.privateFieldValue("streamsClosed"),
                )
                assertEquals(
                    true,
                    outcome.privateFieldValue("terminationRequired"),
                )
                assertEquals(
                    null,
                    outcome.privateFieldValue("exitCode"),
                )

                val completedLifecycle = events.toList()
                repeat(2) {
                    val repeatedClose = assertFailsWith<IOException> {
                        transport.close()
                    }
                    assertEquals(
                        "Dovecot operator process transport close failed",
                        repeatedClose.message,
                    )
                    val repeatedAbort = assertFailsWith<IOException> {
                        transport.abort()
                    }
                    assertEquals(
                        "Dovecot operator process transport abort failed",
                        repeatedAbort.message,
                    )
                }
                assertEquals(completedLifecycle, events)
                assertEquals(0, process.childStdin.closeAttempts)
                assertEquals(0, process.childStdout.closeCalls)
                assertEquals(1, process.destroyCalls)
                assertEquals(1, process.destroyForciblyCalls)
                assertEquals(2, process.timedWaits.size)
            } finally {
                process.releaseFinalWait()
                process.releaseWriter()
                writer.join(TEST_SAFETY_TIMEOUT_MILLIS)
                closeCaller.join(TEST_SAFETY_TIMEOUT_MILLIS)
                abortCaller.join(TEST_SAFETY_TIMEOUT_MILLIS)
            }

            assertFalse(writer.isAlive)
            assertFalse(closeCaller.isAlive)
            assertFalse(abortCaller.isAlive)
            assertEquals(null, writerFailure.get())
        }

    @Test
    fun unreapedAbortAcknowledgedBeforeStdinAuthorizationSkipsLifecycleClose() =
        withLaunchFixture { fixture ->
            val events =
                Collections.synchronizedList(mutableListOf<String>())
            val rawStdin =
                RecordingOutputStream("child-stdin", events)
            val rawStdout =
                RecordingInputStream("child-stdout", events)
            val process = GuardedAdmissionTestProcess(
                events = events,
                childStdin = rawStdin,
                childStdout = rawStdout,
                waitMode =
                    GuardedAdmissionWaitMode.GatedUnreaped,
            )
            val stdinAuthorizationEntered = CountDownLatch(1)
            val releaseStdinAuthorization = CountDownLatch(1)
            val transport =
                JvmDockerExecDovecotOperatorTransportFactory(
                    profile = fixture.profile(),
                    starter =
                        DovecotOperatorProcessStarter { process },
                    beforeLifecycleCloseAuthorization = { direction ->
                        check(
                            direction ==
                                DovecotOperatorProcessStreamDirection.Stdin,
                        ) {
                            "Unexpected stdout lifecycle authorization"
                        }
                        stdinAuthorizationEntered.countDown()
                        check(
                            releaseStdinAuthorization.await(
                                TEST_SAFETY_TIMEOUT_SECONDS,
                                TimeUnit.SECONDS,
                            ),
                        ) {
                            "Stdin lifecycle authorization was not released"
                        }
                    },
                ).open {}
            val staleInput = transport.input
            val staleOutput = transport.outputStream
            events.clear()
            val closeFailure = AtomicReference<Throwable?>()
            val abortFailure = AtomicReference<Throwable?>()
            val closeFinished = CountDownLatch(1)
            val abortFinished = CountDownLatch(1)
            val closeCaller = Thread(
                {
                    try {
                        transport.close()
                    } catch (failure: Throwable) {
                        closeFailure.set(failure)
                    } finally {
                        closeFinished.countDown()
                    }
                },
                "dovecot-pre-stdin-authorization-close",
            )
            val abortCaller = Thread(
                {
                    try {
                        transport.abort()
                    } catch (failure: Throwable) {
                        abortFailure.set(failure)
                    } finally {
                        abortFinished.countDown()
                    }
                },
                "dovecot-pre-stdin-authorization-abort",
            )

            try {
                closeCaller.start()
                assertTrue(
                    stdinAuthorizationEntered.await(
                        TEST_SAFETY_TIMEOUT_SECONDS,
                        TimeUnit.SECONDS,
                    ),
                    "Close did not reach stdin authorization",
                )
                assertEquals(0, rawStdin.closeCalls)
                assertEquals(0, rawStdout.closeCalls)
                assertTrue(process.timedWaits.isEmpty())

                abortCaller.start()
                assertTrue(
                    process.finalProcessWaitEntered.await(
                        TEST_SAFETY_TIMEOUT_SECONDS,
                        TimeUnit.SECONDS,
                    ),
                    "Abort did not enter its final bounded reap attempt",
                )
                process.releaseFinalWait()
                assertTrue(
                    abortCaller.awaitState(Thread.State.BLOCKED),
                    "Abort did not acknowledge before waiting for lifecycle",
                )
                assertEquals(1L, closeFinished.count)
                assertEquals(1L, abortFinished.count)
                assertEquals(
                    null,
                    transport.terminationOutcomeReference(),
                )

                releaseStdinAuthorization.countDown()
                assertTrue(
                    closeFinished.await(
                        TEST_SAFETY_TIMEOUT_SECONDS,
                        TimeUnit.SECONDS,
                    ),
                    "Close did not return its bounded failure",
                )
                assertTrue(
                    abortFinished.await(
                        TEST_SAFETY_TIMEOUT_SECONDS,
                        TimeUnit.SECONDS,
                    ),
                    "Abort did not return its bounded failure",
                )
                closeCaller.join(TEST_SAFETY_TIMEOUT_MILLIS)
                abortCaller.join(TEST_SAFETY_TIMEOUT_MILLIS)

                assertFalse(closeCaller.isAlive)
                assertFalse(abortCaller.isAlive)
                val rejectedClose = closeFailure.get()
                assertTrue(rejectedClose is IOException)
                assertEquals(
                    "Dovecot operator process transport close failed",
                    rejectedClose.message,
                )
                assertEquals(null, rejectedClose.cause)
                assertTrue(rejectedClose.suppressed.isEmpty())
                val rejectedAbort = abortFailure.get()
                assertTrue(rejectedAbort is IOException)
                assertEquals(
                    "Dovecot operator process transport abort failed",
                    rejectedAbort.message,
                )
                assertEquals(null, rejectedAbort.cause)
                assertTrue(rejectedAbort.suppressed.isEmpty())

                assertEquals(0, rawStdin.closeCalls)
                assertEquals(0, rawStdout.closeCalls)
                val stdinDirection =
                    checkNotNull(
                        staleOutput.privateFieldValue("direction"),
                    )
                assertEquals(
                    "Open",
                    stdinDirection
                        .privateFieldValue("closeState")
                        .toString(),
                )
                val stdoutDirection =
                    checkNotNull(
                        staleInput.privateFieldValue("direction"),
                    )
                assertEquals(
                    "Open",
                    stdoutDirection
                        .privateFieldValue("closeState")
                        .toString(),
                )
                assertEquals(1, process.destroyCalls)
                assertEquals(1, process.destroyForciblyCalls)
                assertEquals(
                    listOf(
                        250L to TimeUnit.MILLISECONDS,
                        250L to TimeUnit.MILLISECONDS,
                    ),
                    process.timedWaits,
                )

                val outcome =
                    checkNotNull(transport.terminationOutcomeReference())
                assertEquals(
                    false,
                    outcome.privateFieldValue("reaped"),
                )
                assertEquals(
                    false,
                    outcome.privateFieldValue("naturalExit"),
                )
                assertEquals(
                    true,
                    outcome.privateFieldValue("terminationRequired"),
                )
                assertEquals(
                    false,
                    outcome.privateFieldValue("streamsClosed"),
                )
                assertEquals(
                    null,
                    outcome.privateFieldValue("exitCode"),
                )
                assertEquals(
                    null,
                    transport.terminalStreamReference("childStdin"),
                )
                assertEquals(
                    null,
                    transport.terminalStreamReference("childStdout"),
                )

                val completedLifecycle = events.toList()
                repeat(2) {
                    val repeatedClose = assertFailsWith<IOException> {
                        transport.close()
                    }
                    assertEquals(
                        "Dovecot operator process transport close failed",
                        repeatedClose.message,
                    )
                    val repeatedAbort = assertFailsWith<IOException> {
                        transport.abort()
                    }
                    assertEquals(
                        "Dovecot operator process transport abort failed",
                        repeatedAbort.message,
                    )
                    assertSame(
                        outcome,
                        transport.terminationOutcomeReference(),
                    )
                }
                assertEquals(completedLifecycle, events)
                assertEquals(0, rawStdin.closeCalls)
                assertEquals(0, rawStdout.closeCalls)
                assertEquals(1, process.destroyCalls)
                assertEquals(1, process.destroyForciblyCalls)
                assertEquals(2, process.timedWaits.size)
            } finally {
                releaseStdinAuthorization.countDown()
                process.releaseAll()
                closeCaller.join(TEST_SAFETY_TIMEOUT_MILLIS)
                abortCaller.join(TEST_SAFETY_TIMEOUT_MILLIS)
            }
        }

    @Test
    fun unreapedAbortAcknowledgedDuringNaturalWaitSkipsStdoutAuthorization() =
        withLaunchFixture { fixture ->
            val events =
                Collections.synchronizedList(mutableListOf<String>())
            val rawStdin =
                RecordingOutputStream("child-stdin", events)
            val rawStdout =
                AdmissionBlockingInputStream("child-stdout", events)
            val process = GuardedAdmissionTestProcess(
                events = events,
                childStdin = rawStdin,
                childStdout = rawStdout,
                waitMode =
                    GuardedAdmissionWaitMode
                        .GatedNaturalThenUnreapedAbort,
            )
            val transport =
                JvmDockerExecDovecotOperatorTransportFactory(
                    profile = fixture.profile(),
                    starter =
                        DovecotOperatorProcessStarter { process },
                ).open {}
            val staleInput = transport.input
            events.clear()
            val readResult = AtomicReference<Int?>()
            val readerFailure = AtomicReference<Throwable?>()
            val closeFailure = AtomicReference<Throwable?>()
            val abortFailure = AtomicReference<Throwable?>()
            val closeFinished = CountDownLatch(1)
            val abortFinished = CountDownLatch(1)
            val reader = Thread(
                {
                    try {
                        readResult.set(staleInput.read())
                    } catch (failure: Throwable) {
                        readerFailure.set(failure)
                    }
                },
                "dovecot-natural-wait-stdout-reader",
            )
            val closeCaller = Thread(
                {
                    try {
                        transport.close()
                    } catch (failure: Throwable) {
                        closeFailure.set(failure)
                    } finally {
                        closeFinished.countDown()
                    }
                },
                "dovecot-natural-wait-close",
            )
            val abortCaller = Thread(
                {
                    try {
                        transport.abort()
                    } catch (failure: Throwable) {
                        abortFailure.set(failure)
                    } finally {
                        abortFinished.countDown()
                    }
                },
                "dovecot-natural-wait-abort",
            )

            try {
                reader.start()
                assertTrue(
                    rawStdout.operationEntered.await(
                        TEST_SAFETY_TIMEOUT_SECONDS,
                        TimeUnit.SECONDS,
                    ),
                    "Reader was not admitted before close",
                )
                closeCaller.start()
                assertTrue(
                    process.firstProcessWaitEntered.await(
                        TEST_SAFETY_TIMEOUT_SECONDS,
                        TimeUnit.SECONDS,
                    ),
                    "Close did not enter its natural process wait",
                )
                assertEquals(1, rawStdin.closeCalls)
                assertEquals(0, rawStdout.closeAttempts)

                abortCaller.start()
                assertTrue(
                    process.finalProcessWaitEntered.await(
                        TEST_SAFETY_TIMEOUT_SECONDS,
                        TimeUnit.SECONDS,
                    ),
                    "Abort did not enter its final bounded reap attempt",
                )
                process.releaseFinalWait()
                assertTrue(
                    abortCaller.awaitState(Thread.State.BLOCKED),
                    "Abort did not acknowledge before waiting for lifecycle",
                )
                assertEquals(1L, closeFinished.count)
                assertEquals(1L, abortFinished.count)
                assertEquals(
                    null,
                    transport.terminationOutcomeReference(),
                )

                process.releaseNaturalWait()
                assertTrue(
                    closeFinished.await(
                        TEST_SAFETY_TIMEOUT_SECONDS,
                        TimeUnit.SECONDS,
                    ),
                    "Close did not return its bounded failure",
                )
                assertTrue(
                    abortFinished.await(
                        TEST_SAFETY_TIMEOUT_SECONDS,
                        TimeUnit.SECONDS,
                    ),
                    "Abort did not return its bounded failure",
                )
                closeCaller.join(TEST_SAFETY_TIMEOUT_MILLIS)
                abortCaller.join(TEST_SAFETY_TIMEOUT_MILLIS)

                assertFalse(closeCaller.isAlive)
                assertFalse(abortCaller.isAlive)
                assertTrue(reader.isAlive)
                val rejectedClose = closeFailure.get()
                assertTrue(rejectedClose is IOException)
                assertEquals(
                    "Dovecot operator process transport close failed",
                    rejectedClose.message,
                )
                assertEquals(null, rejectedClose.cause)
                assertTrue(rejectedClose.suppressed.isEmpty())
                val rejectedAbort = abortFailure.get()
                assertTrue(rejectedAbort is IOException)
                assertEquals(
                    "Dovecot operator process transport abort failed",
                    rejectedAbort.message,
                )
                assertEquals(null, rejectedAbort.cause)
                assertTrue(rejectedAbort.suppressed.isEmpty())

                assertEquals(1, rawStdin.closeCalls)
                assertEquals(0, rawStdout.closeAttempts)
                assertEquals(
                    1L,
                    rawStdout.closeAttempted.count,
                )
                val stdoutDirection =
                    checkNotNull(
                        staleInput.privateFieldValue("direction"),
                    )
                assertEquals(
                    "Open",
                    stdoutDirection
                        .privateFieldValue("closeState")
                        .toString(),
                )
                assertEquals(1, process.destroyCalls)
                assertEquals(1, process.destroyForciblyCalls)
                assertEquals(0, process.exitValueCalls)
                assertEquals(
                    listOf(
                        500L to TimeUnit.MILLISECONDS,
                        250L to TimeUnit.MILLISECONDS,
                        250L to TimeUnit.MILLISECONDS,
                    ),
                    process.timedWaits,
                )

                val outcome =
                    checkNotNull(transport.terminationOutcomeReference())
                assertEquals(
                    false,
                    outcome.privateFieldValue("reaped"),
                )
                assertEquals(
                    false,
                    outcome.privateFieldValue("naturalExit"),
                )
                assertEquals(
                    true,
                    outcome.privateFieldValue("terminationRequired"),
                )
                assertEquals(
                    false,
                    outcome.privateFieldValue("streamsClosed"),
                )
                assertEquals(
                    null,
                    outcome.privateFieldValue("exitCode"),
                )
                assertEquals(
                    null,
                    transport.terminalStreamReference("childStdin"),
                )
                assertEquals(
                    null,
                    transport.terminalStreamReference("childStdout"),
                )

                val completedLifecycle = events.toList()
                repeat(2) {
                    val repeatedClose = assertFailsWith<IOException> {
                        transport.close()
                    }
                    assertEquals(
                        "Dovecot operator process transport close failed",
                        repeatedClose.message,
                    )
                    val repeatedAbort = assertFailsWith<IOException> {
                        transport.abort()
                    }
                    assertEquals(
                        "Dovecot operator process transport abort failed",
                        repeatedAbort.message,
                    )
                    assertSame(
                        outcome,
                        transport.terminationOutcomeReference(),
                    )
                }
                assertEquals(completedLifecycle, events)
                assertEquals(0, rawStdout.closeAttempts)

                rawStdout.releaseOperation()
                reader.join(TEST_SAFETY_TIMEOUT_MILLIS)
                assertFalse(reader.isAlive)
                assertEquals(null, readerFailure.get())
                assertEquals(65, readResult.get())
                assertEquals(0, rawStdout.closeAttempts)
                assertEquals(
                    1L,
                    rawStdout.closeAttempted.count,
                )

                val readerReleased = events.toList()
                repeat(2) {
                    assertFailsWith<IOException> {
                        transport.close()
                    }
                    assertFailsWith<IOException> {
                        transport.abort()
                    }
                }
                assertEquals(readerReleased, events)
                assertEquals(0, rawStdout.closeAttempts)
                assertEquals(1, process.destroyCalls)
                assertEquals(1, process.destroyForciblyCalls)
                assertEquals(3, process.timedWaits.size)
            } finally {
                process.releaseAll()
                rawStdout.releaseOperation()
                reader.join(TEST_SAFETY_TIMEOUT_MILLIS)
                closeCaller.join(TEST_SAFETY_TIMEOUT_MILLIS)
                abortCaller.join(TEST_SAFETY_TIMEOUT_MILLIS)
            }

            assertFalse(reader.isAlive)
            assertFalse(closeCaller.isAlive)
            assertFalse(abortCaller.isAlive)
        }

    @Test
    fun unreapedAbortDuringClaimedStdoutCloseCanonicalizesCachedOutcome() =
        withLaunchFixture { fixture ->
            val events =
                Collections.synchronizedList(mutableListOf<String>())
            val rawStdin =
                RecordingOutputStream("child-stdin", events)
            val rawStdout =
                AdmissionBlockingInputStream("child-stdout", events)
            val process = GuardedAdmissionTestProcess(
                events = events,
                childStdin = rawStdin,
                childStdout = rawStdout,
                waitMode =
                    GuardedAdmissionWaitMode
                        .GatedNaturalThenUnreapedAbort,
            )
            val transport =
                JvmDockerExecDovecotOperatorTransportFactory(
                    profile = fixture.profile(),
                    starter =
                        DovecotOperatorProcessStarter { process },
                ).open {}
            events.clear()
            val closeFailure = AtomicReference<Throwable?>()
            val abortFailure = AtomicReference<Throwable?>()
            val closeFinished = CountDownLatch(1)
            val abortFinished = CountDownLatch(1)
            val closeCaller = Thread(
                {
                    try {
                        transport.close()
                    } catch (failure: Throwable) {
                        closeFailure.set(failure)
                    } finally {
                        closeFinished.countDown()
                    }
                },
                "dovecot-claimed-stdout-close",
            )
            val abortCaller = Thread(
                {
                    try {
                        transport.abort()
                    } catch (failure: Throwable) {
                        abortFailure.set(failure)
                    } finally {
                        abortFinished.countDown()
                    }
                },
                "dovecot-claimed-stdout-abort",
            )

            try {
                synchronized(rawStdout) {
                    closeCaller.start()
                    assertTrue(
                        process.firstProcessWaitEntered.await(
                            TEST_SAFETY_TIMEOUT_SECONDS,
                            TimeUnit.SECONDS,
                        ),
                        "Close did not enter its natural process wait",
                    )
                    process.releaseNaturalWait()
                    assertTrue(
                        rawStdout.closeAttempted.await(
                            TEST_SAFETY_TIMEOUT_SECONDS,
                            TimeUnit.SECONDS,
                        ),
                        "Claimed stdout close did not reach the raw stream",
                    )
                    assertEquals(1, rawStdout.closeAttempts)
                    assertEquals(1L, closeFinished.count)

                    abortCaller.start()
                    assertTrue(
                        process.finalProcessWaitEntered.await(
                            TEST_SAFETY_TIMEOUT_SECONDS,
                            TimeUnit.SECONDS,
                        ),
                        "Abort did not enter its final bounded reap attempt",
                    )
                    process.releaseFinalWait()
                    assertTrue(
                        abortCaller.awaitState(Thread.State.BLOCKED),
                        "Abort did not acknowledge before lifecycle caching",
                    )
                    assertEquals(1L, abortFinished.count)
                    assertEquals(
                        null,
                        transport.terminationOutcomeReference(),
                    )
                }

                assertTrue(
                    closeFinished.await(
                        TEST_SAFETY_TIMEOUT_SECONDS,
                        TimeUnit.SECONDS,
                    ),
                    "Close did not return after raw stdout close",
                )
                assertTrue(
                    abortFinished.await(
                        TEST_SAFETY_TIMEOUT_SECONDS,
                        TimeUnit.SECONDS,
                    ),
                    "Abort did not return after lifecycle caching",
                )
                closeCaller.join(TEST_SAFETY_TIMEOUT_MILLIS)
                abortCaller.join(TEST_SAFETY_TIMEOUT_MILLIS)

                assertFalse(closeCaller.isAlive)
                assertFalse(abortCaller.isAlive)
                val outcome =
                    checkNotNull(transport.terminationOutcomeReference())
                assertEquals(
                    false,
                    outcome.privateFieldValue("reaped"),
                )
                assertEquals(
                    false,
                    outcome.privateFieldValue("naturalExit"),
                )
                assertEquals(
                    true,
                    outcome.privateFieldValue("terminationRequired"),
                )
                assertEquals(
                    false,
                    outcome.privateFieldValue("streamsClosed"),
                )
                assertEquals(
                    null,
                    outcome.privateFieldValue("exitCode"),
                )

                val rejectedClose = closeFailure.get()
                assertTrue(rejectedClose is IOException)
                assertEquals(
                    "Dovecot operator process transport close failed",
                    rejectedClose.message,
                )
                val rejectedAbort = abortFailure.get()
                assertTrue(rejectedAbort is IOException)
                assertEquals(
                    "Dovecot operator process transport abort failed",
                    rejectedAbort.message,
                )
                assertEquals(1, rawStdin.closeCalls)
                assertEquals(1, rawStdout.closeAttempts)
                assertEquals(1, process.destroyCalls)
                assertEquals(1, process.destroyForciblyCalls)
                assertEquals(
                    listOf(
                        500L to TimeUnit.MILLISECONDS,
                        250L to TimeUnit.MILLISECONDS,
                        250L to TimeUnit.MILLISECONDS,
                    ),
                    process.timedWaits,
                )

                val completedLifecycle = events.toList()
                repeat(2) {
                    assertFailsWith<IOException> {
                        transport.close()
                    }
                    assertFailsWith<IOException> {
                        transport.abort()
                    }
                    assertSame(
                        outcome,
                        transport.terminationOutcomeReference(),
                    )
                }
                assertEquals(completedLifecycle, events)
                assertEquals(1, rawStdin.closeCalls)
                assertEquals(1, rawStdout.closeAttempts)
                assertEquals(1, process.destroyCalls)
                assertEquals(1, process.destroyForciblyCalls)
                assertEquals(3, process.timedWaits.size)
            } finally {
                process.releaseAll()
                closeCaller.join(TEST_SAFETY_TIMEOUT_MILLIS)
                abortCaller.join(TEST_SAFETY_TIMEOUT_MILLIS)
            }
        }

    @Test
    fun closeFirstBlockedStdinWriteFailsBeforeDeferredCloseAfterUnreapedAbort() =
        withLaunchFixture { fixture ->
            val events =
                Collections.synchronizedList(mutableListOf<String>())
            val rawStdin =
                AdmissionBlockingOutputStream("child-stdin", events)
            val rawStdout =
                RecordingInputStream("child-stdout", events)
            val process = GuardedAdmissionTestProcess(
                events = events,
                childStdin = rawStdin,
                childStdout = rawStdout,
                waitMode =
                    GuardedAdmissionWaitMode.GatedUnreaped,
            )
            val transport =
                JvmDockerExecDovecotOperatorTransportFactory(
                    profile = fixture.profile(),
                    starter =
                        DovecotOperatorProcessStarter { process },
                ).open {}
            val staleOutput = transport.outputStream
            events.clear()
            val writerFailure = AtomicReference<Throwable?>()
            val closeFailure = AtomicReference<Throwable?>()
            val abortFailure = AtomicReference<Throwable?>()
            val closeFinished = CountDownLatch(1)
            val abortFinished = CountDownLatch(1)
            val writer = Thread(
                {
                    try {
                        staleOutput.write(1)
                    } catch (failure: Throwable) {
                        writerFailure.set(failure)
                    }
                },
                "dovecot-guarded-stdin-writer",
            )
            val closeCaller = Thread(
                {
                    try {
                        transport.close()
                    } catch (failure: Throwable) {
                        closeFailure.set(failure)
                    } finally {
                        closeFinished.countDown()
                    }
                },
                "dovecot-guarded-stdin-close",
            )
            val abortCaller = Thread(
                {
                    try {
                        transport.abort()
                    } catch (failure: Throwable) {
                        abortFailure.set(failure)
                    } finally {
                        abortFinished.countDown()
                    }
                },
                "dovecot-guarded-stdin-abort",
            )

            try {
                writer.start()
                assertTrue(
                    rawStdin.operationEntered.await(
                        TEST_SAFETY_TIMEOUT_SECONDS,
                        TimeUnit.SECONDS,
                    ),
                )
                closeCaller.start()
                assertTrue(
                    awaitEither(
                        process.firstProcessWaitEntered,
                        rawStdin.closeAttempted,
                    ),
                    "Close neither deferred stdin nor attempted raw close",
                )
                assertEquals(
                    1L,
                    rawStdin.closeAttempted.count,
                    "Close attempted raw stdin while write was admitted",
                )
                assertEquals(0L, process.firstProcessWaitEntered.count)
                assertEquals(0, rawStdin.closeAttempts)

                assertTrue(
                    process.finalProcessWaitEntered.await(
                        TEST_SAFETY_TIMEOUT_SECONDS,
                        TimeUnit.SECONDS,
                    ),
                    "Close did not enter its final reap attempt",
                )
                abortCaller.start()
                val staleFailure = assertFailsWith<IOException> {
                    staleOutput.flush()
                }
                assertEquals(
                    "Dovecot operator process transport is closed",
                    staleFailure.message,
                )
                assertEquals(null, staleFailure.cause)
                assertTrue(staleFailure.suppressed.isEmpty())

                process.releaseFinalWait()
                assertTrue(
                    closeFinished.await(
                        TEST_SAFETY_TIMEOUT_SECONDS,
                        TimeUnit.SECONDS,
                    ),
                    "Close did not fail before writer release",
                )
                assertTrue(
                    abortFinished.await(
                        TEST_SAFETY_TIMEOUT_SECONDS,
                        TimeUnit.SECONDS,
                    ),
                    "Abort did not fail before writer release",
                )
                closeCaller.join(TEST_SAFETY_TIMEOUT_MILLIS)
                abortCaller.join(TEST_SAFETY_TIMEOUT_MILLIS)

                assertFalse(closeCaller.isAlive)
                assertFalse(abortCaller.isAlive)
                assertTrue(writer.isAlive)
                val rejectedClose = closeFailure.get()
                assertTrue(rejectedClose is IOException)
                assertEquals(
                    "Dovecot operator process transport close failed",
                    rejectedClose.message,
                )
                assertEquals(null, rejectedClose.cause)
                assertTrue(rejectedClose.suppressed.isEmpty())
                val rejectedAbort = abortFailure.get()
                assertTrue(rejectedAbort is IOException)
                assertEquals(
                    "Dovecot operator process transport abort failed",
                    rejectedAbort.message,
                )
                assertEquals(null, rejectedAbort.cause)
                assertTrue(rejectedAbort.suppressed.isEmpty())
                assertEquals(0, rawStdin.closeAttempts)
                assertEquals(1, rawStdout.closeCalls)
                assertEquals(1, process.destroyCalls)
                assertEquals(1, process.destroyForciblyCalls)
                assertEquals(
                    listOf(
                        250L to TimeUnit.MILLISECONDS,
                        250L to TimeUnit.MILLISECONDS,
                    ),
                    process.timedWaits,
                )
                val outcome =
                    checkNotNull(transport.terminationOutcomeReference())
                assertEquals(
                    false,
                    outcome.privateFieldValue("reaped"),
                )
                assertEquals(
                    false,
                    outcome.privateFieldValue("naturalExit"),
                )
                assertEquals(
                    true,
                    outcome.privateFieldValue("terminationRequired"),
                )
                assertEquals(
                    false,
                    outcome.privateFieldValue("streamsClosed"),
                )
                assertEquals(
                    null,
                    outcome.privateFieldValue("exitCode"),
                )

                val terminalEvents = events.toList()
                repeat(2) {
                    assertFailsWith<IOException> {
                        transport.close()
                    }
                    assertFailsWith<IOException> {
                        transport.abort()
                    }
                }
                assertEquals(terminalEvents, events)
                assertEquals(0, rawStdin.closeAttempts)

                rawStdin.releaseOperation()
                writer.join(TEST_SAFETY_TIMEOUT_MILLIS)
                assertFalse(writer.isAlive)
                assertEquals(null, writerFailure.get())
                assertEquals(1, rawStdin.closeAttempts)
                assertSame(
                    outcome,
                    transport.terminationOutcomeReference(),
                )
                assertEquals(
                    false,
                    outcome.privateFieldValue("streamsClosed"),
                )
                val deferredEvents = events.toList()
                repeat(2) {
                    assertFailsWith<IOException> {
                        transport.close()
                    }
                    assertFailsWith<IOException> {
                        transport.abort()
                    }
                }
                assertEquals(deferredEvents, events)
                assertEquals(1, rawStdin.closeAttempts)
                assertEquals(1, process.destroyCalls)
                assertEquals(1, process.destroyForciblyCalls)
                assertEquals(2, process.timedWaits.size)
            } finally {
                process.releaseAll()
                rawStdin.releaseOperation()
                writer.join(TEST_SAFETY_TIMEOUT_MILLIS)
                closeCaller.join(TEST_SAFETY_TIMEOUT_MILLIS)
                abortCaller.join(TEST_SAFETY_TIMEOUT_MILLIS)
            }
        }

    @Test
    fun blockedStdoutReadFailsCloseBeforeItsDeferredRawClose() =
        withLaunchFixture { fixture ->
            val events =
                Collections.synchronizedList(mutableListOf<String>())
            val rawStdin =
                RecordingOutputStream("child-stdin", events)
            val rawStdout =
                AdmissionBlockingInputStream("child-stdout", events)
            val process = GuardedAdmissionTestProcess(
                events = events,
                childStdin = rawStdin,
                childStdout = rawStdout,
                waitMode =
                    GuardedAdmissionWaitMode.NaturalZero,
            )
            val transport =
                JvmDockerExecDovecotOperatorTransportFactory(
                    profile = fixture.profile(),
                    starter =
                        DovecotOperatorProcessStarter { process },
                ).open {}
            val staleInput = transport.input
            events.clear()
            val readResult = AtomicReference<Int?>()
            val readerFailure = AtomicReference<Throwable?>()
            val closeFailure = AtomicReference<Throwable?>()
            val closeFinished = CountDownLatch(1)
            val reader = Thread(
                {
                    try {
                        readResult.set(staleInput.read())
                    } catch (failure: Throwable) {
                        readerFailure.set(failure)
                    }
                },
                "dovecot-guarded-stdout-reader",
            )
            val closeCaller = Thread(
                {
                    try {
                        transport.close()
                    } catch (failure: Throwable) {
                        closeFailure.set(failure)
                    } finally {
                        closeFinished.countDown()
                    }
                },
                "dovecot-guarded-stdout-close",
            )

            try {
                reader.start()
                assertTrue(
                    rawStdout.operationEntered.await(
                        TEST_SAFETY_TIMEOUT_SECONDS,
                        TimeUnit.SECONDS,
                    ),
                )
                closeCaller.start()
                assertTrue(
                    awaitEither(
                        closeFinished,
                        rawStdout.closeAttempted,
                    ),
                    "Close neither finished nor attempted raw stdout close",
                )
                assertEquals(
                    1L,
                    rawStdout.closeAttempted.count,
                    "Close attempted raw stdout while read was admitted",
                )
                assertEquals(
                    0L,
                    closeFinished.count,
                    "Close did not fail before reader release",
                )
                closeCaller.join(TEST_SAFETY_TIMEOUT_MILLIS)

                val rejectedClose = closeFailure.get()
                assertTrue(rejectedClose is IOException)
                assertEquals(
                    "Dovecot operator process transport close failed",
                    rejectedClose.message,
                )
                assertEquals(null, rejectedClose.cause)
                assertTrue(rejectedClose.suppressed.isEmpty())
                val staleFailure = assertFailsWith<IOException> {
                    staleInput.read(ByteArray(0), 0, 0)
                }
                assertEquals(
                    "Dovecot operator process transport is closed",
                    staleFailure.message,
                )
                assertEquals(null, staleFailure.cause)
                assertTrue(staleFailure.suppressed.isEmpty())
                assertTrue(reader.isAlive)
                assertEquals(1, rawStdin.closeCalls)
                assertEquals(0, rawStdout.closeAttempts)
                assertEquals(1, process.timedWaits.size)
                assertEquals(0, process.destroyCalls)
                assertEquals(0, process.destroyForciblyCalls)

                val outcome =
                    checkNotNull(transport.terminationOutcomeReference())
                assertEquals(
                    true,
                    outcome.privateFieldValue("reaped"),
                )
                assertEquals(
                    true,
                    outcome.privateFieldValue("naturalExit"),
                )
                assertEquals(
                    false,
                    outcome.privateFieldValue("terminationRequired"),
                )
                assertEquals(
                    false,
                    outcome.privateFieldValue("streamsClosed"),
                )
                assertEquals(
                    0,
                    outcome.privateFieldValue("exitCode"),
                )

                rawStdout.releaseOperation()
                reader.join(TEST_SAFETY_TIMEOUT_MILLIS)
                assertFalse(reader.isAlive)
                assertEquals(null, readerFailure.get())
                assertEquals(65, readResult.get())
                assertEquals(1, rawStdout.closeAttempts)
                assertSame(
                    outcome,
                    transport.terminationOutcomeReference(),
                )
                assertEquals(
                    false,
                    outcome.privateFieldValue("streamsClosed"),
                )
                val deferredEvents = events.toList()
                repeat(2) {
                    assertFailsWith<IOException> {
                        transport.close()
                    }
                }
                assertEquals(deferredEvents, events)
                assertEquals(1, rawStdout.closeAttempts)
                assertEquals(1, process.timedWaits.size)
            } finally {
                rawStdout.releaseOperation()
                reader.join(TEST_SAFETY_TIMEOUT_MILLIS)
                closeCaller.join(TEST_SAFETY_TIMEOUT_MILLIS)
            }
        }

    @Test
    fun staleWrapperCloseAfterAbortSealCannotRequestRawClose() =
        withLaunchFixture { fixture ->
            val events =
                Collections.synchronizedList(mutableListOf<String>())
            val process = SealedAbortLifecycleTestProcess(events)
            val transport =
                JvmDockerExecDovecotOperatorTransportFactory(
                    profile = fixture.profile(),
                    starter =
                        DovecotOperatorProcessStarter { process },
                ).open {}
            val staleInput = transport.input
            val staleOutput = transport.outputStream
            events.clear()
            val abortFailure = AtomicReference<Throwable?>()
            val abortCaller = Thread(
                {
                    try {
                        transport.abort()
                    } catch (failure: Throwable) {
                        abortFailure.set(failure)
                    }
                },
                "dovecot-sealed-wrapper-abort",
            )

            try {
                abortCaller.start()
                assertTrue(
                    process.waitEntered.await(
                        TEST_SAFETY_TIMEOUT_SECONDS,
                        TimeUnit.SECONDS,
                    ),
                    "Abort did not seal before its bounded wait",
                )

                listOf<AutoCloseable>(
                    staleOutput,
                    staleInput,
                ).forEach { staleStream ->
                    val failure = assertFailsWith<IOException> {
                        staleStream.close()
                    }
                    assertEquals(
                        "Dovecot operator process transport is closed",
                        failure.message,
                    )
                    assertEquals(null, failure.cause)
                    assertTrue(failure.suppressed.isEmpty())
                }
                assertEquals(0, process.childStdin.closeCalls)
                assertEquals(0, process.childStdout.closeCalls)

                process.releaseWait()
                abortCaller.join(TEST_SAFETY_TIMEOUT_MILLIS)

                assertFalse(abortCaller.isAlive)
                assertEquals(null, abortFailure.get())
                assertEquals(1, process.childStdin.closeCalls)
                assertEquals(1, process.childStdout.closeCalls)
                assertEquals(
                    listOf(
                        "destroy",
                        "wait:250:MILLISECONDS",
                        "child-stdin.close",
                        "child-stdout.close",
                    ),
                    events,
                )
            } finally {
                process.releaseWait()
                abortCaller.join(TEST_SAFETY_TIMEOUT_MILLIS)
            }
        }

    @Test
    fun wrapperCloseWithAdmittedWriteFailsThenClosesExactlyOnce() =
        withLaunchFixture { fixture ->
            val events =
                Collections.synchronizedList(mutableListOf<String>())
            val rawStdin =
                AdmissionBlockingOutputStream("child-stdin", events)
            val process = GuardedAdmissionTestProcess(
                events = events,
                childStdin = rawStdin,
                childStdout =
                    RecordingInputStream("child-stdout", events),
                waitMode =
                    GuardedAdmissionWaitMode.NaturalZero,
            )
            val transport =
                JvmDockerExecDovecotOperatorTransportFactory(
                    profile = fixture.profile(),
                    starter =
                        DovecotOperatorProcessStarter { process },
                ).open {}
            val output = transport.outputStream
            val writerFailure = AtomicReference<Throwable?>()
            val writer = Thread(
                {
                    try {
                        output.write(1)
                    } catch (failure: Throwable) {
                        writerFailure.set(failure)
                    }
                },
                "dovecot-public-close-admitted-writer",
            )

            try {
                writer.start()
                assertTrue(
                    rawStdin.operationEntered.await(
                        TEST_SAFETY_TIMEOUT_SECONDS,
                        TimeUnit.SECONDS,
                    ),
                )

                repeat(2) {
                    val failure = assertFailsWith<IOException> {
                        output.close()
                    }
                    assertEquals(
                        "Dovecot operator process stream close failed",
                        failure.message,
                    )
                    assertEquals(null, failure.cause)
                    assertTrue(failure.suppressed.isEmpty())
                }
                assertEquals(0, rawStdin.closeAttempts)

                rawStdin.releaseOperation()
                writer.join(TEST_SAFETY_TIMEOUT_MILLIS)

                assertFalse(writer.isAlive)
                assertEquals(null, writerFailure.get())
                assertEquals(1, rawStdin.closeAttempts)
                val staleFailure = assertFailsWith<IOException> {
                    output.flush()
                }
                assertEquals(
                    "Dovecot operator process transport is closed",
                    staleFailure.message,
                )

                transport.close()
                assertEquals(1, rawStdin.closeAttempts)
            } finally {
                rawStdin.releaseOperation()
                writer.join(TEST_SAFETY_TIMEOUT_MILLIS)
            }
        }

    private fun assertAbortReapsBeforeDeferredStreamCleanup(
        destroyFailure: Throwable?,
        secret: String?,
    ) = withLaunchFixture { fixture ->
        val events =
            Collections.synchronizedList(mutableListOf<String>())
        val process = AsyncDestroyBlockingPipeTestProcess(
            events = events,
            destroyFailure = destroyFailure,
        )
        val transport = JvmDockerExecDovecotOperatorTransportFactory(
            profile = fixture.profile(),
            starter = DovecotOperatorProcessStarter { process },
        ).open {}
        val childStdin = transport.outputStream
        events.clear()
        val writerFailure = AtomicReference<Throwable?>()
        val closeFailure = AtomicReference<Throwable?>()
        val abortFailure = AtomicReference<Throwable?>()
        val writer = Thread(
            {
                try {
                    childStdin.write(1)
                } catch (failure: Throwable) {
                    writerFailure.set(failure)
                }
            },
            "dovecot-async-destroy-blocking-writer",
        )
        val closeCaller = Thread(
            {
                try {
                    transport.close()
                } catch (failure: Throwable) {
                    closeFailure.set(failure)
                }
            },
            "dovecot-async-destroy-close-owner",
        )
        val abortCaller = Thread(
            {
                try {
                    transport.abort()
                } catch (failure: Throwable) {
                    abortFailure.set(failure)
                }
            },
            "dovecot-async-destroy-abort-caller",
        )

        try {
            writer.start()
            assertTrue(
                process.writerEntered.await(
                    TEST_SAFETY_TIMEOUT_SECONDS,
                    TimeUnit.SECONDS,
                ),
            )
            abortCaller.start()

            assertTrue(
                process.finalReapAttempted.await(
                    TEST_SAFETY_TIMEOUT_SECONDS,
                    TimeUnit.SECONDS,
                ),
                "Abort did not reap before deferred stream cleanup",
            )
            abortCaller.join(TEST_SAFETY_TIMEOUT_MILLIS)
            assertFalse(abortCaller.isAlive)
            assertEquals(1, process.destroyCalls)
            assertEquals(1, process.destroyForciblyCalls)
            assertEquals(
                listOf(
                    250L to TimeUnit.MILLISECONDS,
                    250L to TimeUnit.MILLISECONDS,
                ),
                process.timedWaits,
            )
            assertTrue(writer.isAlive)
            assertEquals(0, process.childStdin.closeCalls)
            assertEquals(1, process.childStdout.closeCalls)

            closeCaller.start()
            closeCaller.join(TEST_SAFETY_TIMEOUT_MILLIS)
            assertFalse(closeCaller.isAlive)
        } finally {
            process.releaseWriter()
            writer.join(TEST_SAFETY_TIMEOUT_MILLIS)
            closeCaller.join(TEST_SAFETY_TIMEOUT_MILLIS)
            abortCaller.join(TEST_SAFETY_TIMEOUT_MILLIS)
        }

        assertFalse(writer.isAlive)
        assertFalse(closeCaller.isAlive)
        assertFalse(abortCaller.isAlive)
        assertEquals(null, writerFailure.get())
        val rejectedClose = closeFailure.get()
        assertTrue(rejectedClose is IOException)
        assertEquals(
            "Dovecot operator process transport close failed",
            rejectedClose.message,
        )
        assertEquals(null, rejectedClose.cause)
        assertTrue(rejectedClose.suppressed.isEmpty())
        val rejectedAbort = abortFailure.get()
        assertTrue(rejectedAbort is IOException)
        assertEquals(
            "Dovecot operator process transport abort failed",
            rejectedAbort.message,
        )
        assertEquals(null, rejectedAbort.cause)
        assertTrue(rejectedAbort.suppressed.isEmpty())
        secret?.let { redactedSecret ->
            assertFalse(rejectedClose.toString().contains(redactedSecret))
            assertFalse(rejectedAbort.toString().contains(redactedSecret))
            assertFalse(transport.toString().contains(redactedSecret))
        }
        assertTrue(process.reaped)
        assertEquals(0, process.exitValueCalls)
        assertEquals(1, process.childStdin.closeCalls)
        assertEquals(1, process.childStdout.closeCalls)
        assertEquals(
            listOf(
                "destroy",
                "wait:250:MILLISECONDS",
                "destroyForcibly",
                "wait:250:MILLISECONDS",
                "child-stdout.close",
                "child-stdin.close",
            ),
            events.filterNot { event -> event.startsWith("writer.") },
        )
        assertFailsWith<IllegalStateException> {
            transport.input
        }
        assertFailsWith<IllegalStateException> {
            transport.outputStream
        }
        assertEquals(
            null,
            transport.terminalStreamReference("childStdin"),
        )
        assertEquals(
            null,
            transport.terminalStreamReference("childStdout"),
        )

        val completedLifecycle = events.toList()
        repeat(2) {
            val repeatedClose = assertFailsWith<IOException> {
                transport.close()
            }
            assertEquals(
                "Dovecot operator process transport close failed",
                repeatedClose.message,
            )
            val repeatedAbort = assertFailsWith<IOException> {
                transport.abort()
            }
            assertEquals(
                "Dovecot operator process transport abort failed",
                repeatedAbort.message,
            )
        }
        assertEquals(completedLifecycle, events)
        assertEquals(1, process.destroyCalls)
        assertEquals(1, process.destroyForciblyCalls)
        assertEquals(2, process.timedWaits.size)
        assertEquals(1, process.childStdin.closeCalls)
        assertEquals(1, process.childStdout.closeCalls)
    }

    @Test
    fun closeFirstNaturalZeroWaitsForAbortHandshakeAcknowledgementBeforeCachingOutcome() =
        withLaunchFixture { fixture ->
            val events =
                Collections.synchronizedList(mutableListOf<String>())
            val process = TwoPhaseAbortTestProcess(events)
            val transport = JvmDockerExecDovecotOperatorTransportFactory(
                profile = fixture.profile(),
                starter = DovecotOperatorProcessStarter { process },
            ).open {}
            events.clear()
            val closeFailure = AtomicReference<Throwable?>()
            val abortFailure = AtomicReference<Throwable?>()
            val closeFinished = CountDownLatch(1)
            val abortFinished = CountDownLatch(1)
            val closeCaller = Thread(
                {
                    try {
                        transport.close()
                    } catch (failure: Throwable) {
                        closeFailure.set(failure)
                    } finally {
                        events += "close.finished"
                        closeFinished.countDown()
                    }
                },
                "dovecot-close-before-abort-signal",
            )
            val abortCaller = Thread(
                {
                    try {
                        transport.abort()
                    } catch (failure: Throwable) {
                        abortFailure.set(failure)
                    } finally {
                        events += "abort.finished"
                        abortFinished.countDown()
                    }
                },
                "dovecot-two-phase-abort-signal",
            )

            try {
                closeCaller.start()
                assertTrue(
                    process.firstWaitEntered.await(
                        TEST_SAFETY_TIMEOUT_SECONDS,
                        TimeUnit.SECONDS,
                    ),
                )
                abortCaller.start()
                assertTrue(
                    process.destroyEntered.await(
                        TEST_SAFETY_TIMEOUT_SECONDS,
                        TimeUnit.SECONDS,
                    ),
                )

                process.releaseNaturalWait()
                assertTrue(
                    closeCaller.awaitState(Thread.State.BLOCKED),
                    "Normal close did not wait for abort acknowledgement",
                )
                assertEquals(1L, closeFinished.count)
                assertEquals(null, transport.terminationOutcomeReference())
                assertEquals(0, process.destroyCalls)
                assertEquals(1L, process.exitValueReached.count)
                assertEquals(0, process.childStdout.closeCalls)

                process.releaseDestroy()
                assertTrue(
                    process.destroyEffectCompleted.await(
                        TEST_SAFETY_TIMEOUT_SECONDS,
                        TimeUnit.SECONDS,
                    ),
                )
                assertTrue(
                    process.exitValueReached.await(
                        TEST_SAFETY_TIMEOUT_SECONDS,
                        TimeUnit.SECONDS,
                    ),
                )
                closeCaller.join(TEST_SAFETY_TIMEOUT_MILLIS)
                abortCaller.join(TEST_SAFETY_TIMEOUT_MILLIS)

                assertFalse(closeCaller.isAlive)
                assertFalse(abortCaller.isAlive)
                assertEquals(0L, closeFinished.count)
                assertEquals(0L, abortFinished.count)
                val rejectedClose = closeFailure.get()
                assertTrue(rejectedClose is IOException)
                assertEquals(
                    "Dovecot operator process transport close failed",
                    rejectedClose.message,
                )
                assertEquals(null, rejectedClose.cause)
                assertTrue(rejectedClose.suppressed.isEmpty())
                assertEquals(null, abortFailure.get())
                assertTrue(process.reaped)
                assertEquals(0, process.exitCode)
                assertEquals(1, process.exitValueCalls)
                assertEquals(1, process.childStdin.closeCalls)
                assertEquals(1, process.childStdout.closeCalls)
                assertEquals(
                    listOf(
                        500L to TimeUnit.MILLISECONDS,
                        250L to TimeUnit.MILLISECONDS,
                    ),
                    process.timedWaits,
                )
                assertEquals(1, process.destroyCalls)
                assertEquals(0, process.destroyForciblyCalls)
                val destroyIndex = events.indexOf("destroy")
                val closeFinishedIndex = events.indexOf("close.finished")
                assertTrue(destroyIndex >= 0)
                assertTrue(closeFinishedIndex > destroyIndex)

                val completedLifecycle = events.toList()
                repeat(2) {
                    val repeatedClose = assertFailsWith<IOException> {
                        transport.close()
                    }
                    assertEquals(
                        "Dovecot operator process transport close failed",
                        repeatedClose.message,
                    )
                    transport.abort()
                }
                assertEquals(completedLifecycle, events)
                assertEquals(1, process.childStdin.closeCalls)
                assertEquals(1, process.childStdout.closeCalls)
                assertEquals(2, process.timedWaits.size)
                assertEquals(1, process.destroyCalls)
                assertEquals(0, process.destroyForciblyCalls)
            } finally {
                process.releaseAll()
                closeCaller.join(TEST_SAFETY_TIMEOUT_MILLIS)
                abortCaller.join(TEST_SAFETY_TIMEOUT_MILLIS)
            }
        }

    @Test
    fun abortFirstNaturalZeroOutcomeIsCachedAndRejectedByConcurrentClose() =
        withLaunchFixture { fixture ->
            val firstWaitEntered = CountDownLatch(1)
            val releaseFirstWait = CountDownLatch(1)
            val events = mutableListOf<String>()
            val process = ControlledTestProcess(
                events = events,
                waitResults = listOf(true),
                configuredExitCode = 0,
                firstWaitEntered = firstWaitEntered,
                releaseFirstWait = releaseFirstWait,
            )
            val transport = JvmDockerExecDovecotOperatorTransportFactory(
                profile = fixture.profile(),
                starter = DovecotOperatorProcessStarter { process },
            ).open {}
            events.clear()
            val abortFailure = AtomicReference<Throwable?>()
            val closeFailure = AtomicReference<Throwable?>()
            val closeStarted = CountDownLatch(1)
            val abortCaller = Thread(
                {
                    try {
                        transport.abort()
                    } catch (failure: Throwable) {
                        abortFailure.set(failure)
                    }
                },
                "dovecot-process-abort-first-caller",
            )
            val closeCaller = Thread(
                {
                    closeStarted.countDown()
                    try {
                        transport.close()
                    } catch (failure: Throwable) {
                        closeFailure.set(failure)
                    }
                },
                "dovecot-process-close-second-caller",
            )

            try {
                abortCaller.start()
                assertTrue(
                    firstWaitEntered.await(
                        TEST_SAFETY_TIMEOUT_SECONDS,
                        TimeUnit.SECONDS,
                    ),
                )
                closeCaller.start()
                assertTrue(
                    closeStarted.await(
                        TEST_SAFETY_TIMEOUT_SECONDS,
                        TimeUnit.SECONDS,
                    ),
                )
                assertTrue(
                    closeCaller.awaitState(Thread.State.BLOCKED),
                    "Close caller did not overlap the abort lifecycle",
                )
                releaseFirstWait.countDown()
                abortCaller.join(TEST_SAFETY_TIMEOUT_MILLIS)
                closeCaller.join(TEST_SAFETY_TIMEOUT_MILLIS)

                assertFalse(abortCaller.isAlive)
                assertFalse(closeCaller.isAlive)
                assertEquals(null, abortFailure.get())
                val rejectedClose = closeFailure.get()
                assertTrue(rejectedClose is IOException)
                assertEquals(
                    "Dovecot operator process transport close failed",
                    rejectedClose.message,
                )
                assertEquals(null, rejectedClose.cause)
                assertEquals(
                    listOf(
                        "destroy",
                        "wait:250:MILLISECONDS",
                        "child-stdin.close",
                        "child-stdout.close",
                    ),
                    events,
                )
                assertEquals(1, process.timedWaits.size)
                assertEquals(1, process.destroyCalls)
                assertEquals(0, process.destroyForciblyCalls)
            } finally {
                releaseFirstWait.countDown()
                abortCaller.join(TEST_SAFETY_TIMEOUT_MILLIS)
                closeCaller.join(TEST_SAFETY_TIMEOUT_MILLIS)
            }
        }

    @Test
    fun repeatedSuccessfulTerminationCallsNeverRerunProcessLifecycle() =
        withLaunchFixture { fixture ->
            val events = mutableListOf<String>()
            val process = ControlledTestProcess(
                events = events,
                waitResults = listOf(true),
            )
            val transport = JvmDockerExecDovecotOperatorTransportFactory(
                profile = fixture.profile(),
                starter = DovecotOperatorProcessStarter { process },
            ).open {}
            events.clear()

            transport.close()
            val firstLifecycle = events.toList()
            transport.close()
            transport.abort()
            transport.abort()

            assertEquals(firstLifecycle, events)
            assertEquals(1, process.timedWaits.size)
            assertEquals(1, process.childStdin.closeCalls)
            assertEquals(1, process.childStdout.closeCalls)
        }

    @Test
    fun failedCloseRemainsFailedAndPermanentlyRejectsStreamGetters() =
        withLaunchFixture { fixture ->
            val events = mutableListOf<String>()
            val process = ControlledTestProcess(
                events = events,
                waitResults = listOf(true),
                configuredExitCode = 19,
            )
            val transport = JvmDockerExecDovecotOperatorTransportFactory(
                profile = fixture.profile(),
                starter = DovecotOperatorProcessStarter { process },
            ).open {}
            events.clear()

            val firstFailure = assertFailsWith<IOException> {
                transport.close()
            }
            val firstLifecycle = events.toList()
            val repeatedFailure = assertFailsWith<IOException> {
                transport.close()
            }
            val inputFailure = assertFailsWith<IllegalStateException> {
                transport.input
            }
            val outputFailure = assertFailsWith<IllegalStateException> {
                transport.outputStream
            }

            assertEquals(
                "Dovecot operator process transport close failed",
                firstFailure.message,
            )
            assertEquals(firstFailure.message, repeatedFailure.message)
            assertEquals(firstLifecycle, events)
            assertEquals(
                "Dovecot operator process transport is closed",
                inputFailure.message,
            )
            assertEquals(inputFailure.message, outputFailure.message)
            assertEquals(null, repeatedFailure.cause)
            assertTrue(repeatedFailure.suppressed.isEmpty())
        }

    @Test
    fun failedAbortRemainsFailedWithoutRerunningTermination() =
        withLaunchFixture { fixture ->
            val events = mutableListOf<String>()
            val process = ControlledTestProcess(
                events = events,
                waitResults = listOf(false, false),
            )
            val transport = JvmDockerExecDovecotOperatorTransportFactory(
                profile = fixture.profile(),
                starter = DovecotOperatorProcessStarter { process },
            ).open {}
            events.clear()

            val firstFailure = assertFailsWith<IOException> {
                transport.abort()
            }
            val firstLifecycle = events.toList()
            val repeatedFailure = assertFailsWith<IOException> {
                transport.abort()
            }

            assertEquals(
                "Dovecot operator process transport abort failed",
                firstFailure.message,
            )
            assertEquals(firstFailure.message, repeatedFailure.message)
            assertEquals(firstLifecycle, events)
            assertEquals(
                listOf(
                    "destroy",
                    "wait:250:MILLISECONDS",
                    "destroyForcibly",
                    "wait:250:MILLISECONDS",
                ),
                events,
            )
            assertEquals(2, process.timedWaits.size)
            assertEquals(1, process.destroyCalls)
            assertEquals(1, process.destroyForciblyCalls)
            assertEquals(0, process.childStdin.closeCalls)
            assertEquals(0, process.childStdout.closeCalls)
        }

    @Test
    fun abortReapsBeforeRestoringCallerInterruptFlag() =
        withLaunchFixture { fixture ->
            val events = mutableListOf<String>()
            val process = ControlledTestProcess(
                events = events,
                waitResults = listOf(true),
                configuredExitCode = 137,
                honorCallerInterrupt = true,
            )
            val transport = JvmDockerExecDovecotOperatorTransportFactory(
                profile = fixture.profile(),
                starter = DovecotOperatorProcessStarter { process },
            ).open {}
            events.clear()

            try {
                Thread.currentThread().interrupt()

                transport.abort()

                assertTrue(Thread.currentThread().isInterrupted)
                assertEquals(
                    listOf(
                        "destroy",
                        "wait:250:MILLISECONDS",
                        "destroyForcibly",
                        "wait:250:MILLISECONDS",
                        "child-stdin.close",
                        "child-stdout.close",
                    ),
                    events,
                )
                assertTrue(process.reaped)
            } finally {
                Thread.interrupted()
            }
        }

    @Test
    fun processStreamMappingFailureIsCleanedAndRedacted() =
        withLaunchFixture { fixture ->
            val secret =
                "openssl stream request-password mapping failure"
            val process = ControlledTestProcess(
                events = mutableListOf(),
                waitResults = listOf(true),
                stdoutAcquisitionFailure =
                    AssertionError(secret),
            )
            var registrations = 0
            val factory = JvmDockerExecDovecotOperatorTransportFactory(
                profile = fixture.profile(),
                starter = DovecotOperatorProcessStarter { process },
            )

            val failure = assertFailsWith<IOException> {
                factory.open {
                    registrations += 1
                }
            }

            assertEquals(0, registrations)
            assertEquals(
                "Dovecot operator process transport allocation failed",
                failure.message,
            )
            assertEquals(null, failure.cause)
            assertTrue(failure.suppressed.isEmpty())
            assertFalse(failure.toString().contains(secret))
            assertEquals(1, process.childStdin.closeCalls)
            assertEquals(
                listOf(500L to TimeUnit.MILLISECONDS),
                process.timedWaits,
            )
            assertTrue(process.reaped)
        }

    @Test
    fun processTransportUsesFixedRedactedDescriptionsAndNeverReadsStderr() =
        withLaunchFixture { fixture ->
            val stderrSecret =
                "docker openssl stderr request-user request-password"
            val process = ControlledTestProcess(
                events = mutableListOf(),
                waitResults = listOf(true),
                configuredExitCode = 31,
                stderrContents =
                    stderrSecret.toByteArray(Charsets.UTF_8),
            )
            val factory = JvmDockerExecDovecotOperatorTransportFactory(
                profile = fixture.profile(),
                starter = DovecotOperatorProcessStarter { process },
            )
            val transport = factory.open {}

            val failure = assertFailsWith<IOException> {
                transport.close()
            }

            assertEquals(
                "JvmDockerExecDovecotOperatorTransportFactory(fixed, redacted)",
                factory.toString(),
            )
            assertEquals(
                "JvmDockerExecDovecotOperatorTransport(redacted)",
                transport.toString(),
            )
            assertEquals(0, process.stderrRequests)
            assertEquals(0, process.childStderrReadCalls)
            assertFalse(failure.toString().contains(stderrSecret))
            assertFalse(factory.toString().contains(fixture.repository.toString()))
            assertFalse(transport.toString().contains(stderrSecret))
        }

    @Test
    fun processTransportCreatesNoThreadWorkerOrExecutor() {
        val source = Files.readString(processTransportSource())

        assertFalse(
            Regex("""\bThread\s*\(""").containsMatchIn(source),
            "Process transport must not construct a thread",
        )
        assertFalse("ExecutorService" in source)
        assertFalse("Executors." in source)
        assertFalse("CompletableFuture" in source)
        assertFalse("CoroutineScope" in source)
    }

    @Test
    fun registrationInterruptedExceptionIsRestoredAfterRedactedCleanup() =
        withLaunchFixture { fixture ->
            val process = ControlledTestProcess(
                events = mutableListOf(),
                waitResults = listOf(true),
            )
            var retained: DovecotOperatorTransport? = null
            val factory = JvmDockerExecDovecotOperatorTransportFactory(
                profile = fixture.profile(),
                starter = DovecotOperatorProcessStarter { process },
            )

            try {
                val failure = assertFailsWith<IOException> {
                    factory.open { allocated ->
                        retained = allocated
                        throwDirectInterruptedException("registration")
                    }
                }
                val interruptRestored =
                    Thread.currentThread().isInterrupted
                Thread.interrupted()

                assertTrue(interruptRestored)
                assertEquals(
                    "Dovecot operator process transport registration failed",
                    failure.message,
                )
                assertEquals(null, failure.cause)
                assertTrue(failure.suppressed.isEmpty())
                assertTrue(retained != null)
                assertTrue(process.reaped)
            } finally {
                Thread.interrupted()
            }
        }

    @Test
    fun streamCloseInterruptedExceptionsAreRestoredBeforeAbortFails() =
        withLaunchFixture { fixture ->
            val events = mutableListOf<String>()
            val process = ControlledTestProcess(
                events = events,
                waitResults = listOf(true),
                stdinCloseFailure =
                    InterruptedException("child stdin request-password"),
                stdoutCloseFailure =
                    InterruptedException("child stdout request-user"),
            )
            val transport = JvmDockerExecDovecotOperatorTransportFactory(
                profile = fixture.profile(),
                starter = DovecotOperatorProcessStarter { process },
            ).open {}
            events.clear()

            try {
                val failure = assertFailsWith<IOException> {
                    transport.abort()
                }
                val interruptRestored =
                    Thread.currentThread().isInterrupted
                Thread.interrupted()

                assertTrue(interruptRestored)
                assertEquals(
                    "Dovecot operator process transport abort failed",
                    failure.message,
                )
                assertEquals(null, failure.cause)
                assertTrue(failure.suppressed.isEmpty())
                assertEquals(
                    listOf(
                        "destroy",
                        "wait:250:MILLISECONDS",
                        "child-stdin.close",
                        "child-stdout.close",
                    ),
                    events,
                )
                assertEquals(1, process.childStdin.closeCalls)
                assertEquals(1, process.childStdout.closeCalls)
                assertTrue(process.reaped)
            } finally {
                Thread.interrupted()
            }
        }

    @Test
    fun everyOtherCaughtInterruptedExceptionRestoresCallerFlag() {
        val unrestored = mutableListOf<DirectInterruptionPoint>()
        DirectInterruptionPoint.entries.forEach { interruptionPoint ->
            try {
                withLaunchFixture { fixture ->
                    val failure = when (interruptionPoint) {
                        DirectInterruptionPoint.Starter ->
                            assertFailsWith<IOException> {
                                JvmDockerExecDovecotOperatorTransportFactory(
                                    profile = fixture.profile(),
                                    starter = DovecotOperatorProcessStarter {
                                        throwDirectInterruptedException(
                                            "starter",
                                        )
                                    },
                                ).open {}
                            }
                        DirectInterruptionPoint.StreamMapping -> {
                            val process = ControlledTestProcess(
                                events = mutableListOf(),
                                waitResults = listOf(true),
                                stdoutAcquisitionFailure =
                                    InterruptedException(
                                        "mapping request-password",
                                    ),
                            )
                            assertFailsWith<IOException> {
                                JvmDockerExecDovecotOperatorTransportFactory(
                                    profile = fixture.profile(),
                                    starter =
                                        DovecotOperatorProcessStarter {
                                            process
                                        },
                                ).open {}
                            }
                        }
                        DirectInterruptionPoint.Destroy -> {
                            val process = ControlledTestProcess(
                                events = mutableListOf(),
                                waitResults = listOf(false, true),
                                destroyFailure =
                                    InterruptedException(
                                        "destroy request-password",
                                    ),
                            )
                            val transport =
                                JvmDockerExecDovecotOperatorTransportFactory(
                                    profile = fixture.profile(),
                                    starter =
                                        DovecotOperatorProcessStarter {
                                            process
                                        },
                                ).open {}
                            transport.abort()
                            null
                        }
                        DirectInterruptionPoint.DestroyForcibly -> {
                            val process = ControlledTestProcess(
                                events = mutableListOf(),
                                waitResults = listOf(false, true),
                                destroyForciblyFailure =
                                    InterruptedException(
                                        "force request-password",
                                    ),
                            )
                            val transport =
                                JvmDockerExecDovecotOperatorTransportFactory(
                                    profile = fixture.profile(),
                                    starter =
                                        DovecotOperatorProcessStarter {
                                            process
                                        },
                                ).open {}
                            transport.abort()
                            null
                        }
                        DirectInterruptionPoint.ExitValue -> {
                            val process = ControlledTestProcess(
                                events = mutableListOf(),
                                waitResults = listOf(true),
                                exitValueFailure =
                                    InterruptedException(
                                        "exit request-password",
                                    ),
                            )
                            val transport =
                                JvmDockerExecDovecotOperatorTransportFactory(
                                    profile = fixture.profile(),
                                    starter =
                                        DovecotOperatorProcessStarter {
                                            process
                                        },
                                ).open {}
                            assertFailsWith<IOException> {
                                transport.close()
                            }
                        }
                    }
                    val interruptRestored =
                        Thread.currentThread().isInterrupted
                    Thread.interrupted()

                    if (!interruptRestored) {
                        unrestored += interruptionPoint
                    }
                    failure?.let { caught ->
                        assertEquals(null, caught.cause)
                        assertTrue(caught.suppressed.isEmpty())
                        assertFalse(
                            caught.toString().contains("request-password"),
                        )
                    }
                }
            } finally {
                Thread.interrupted()
            }
        }
        assertEquals(
            emptyList(),
            unrestored,
            "Interrupt was not restored for $unrestored",
        )
    }

    @Test
    fun failedRegistrationCleanupCachesUnreapedOutcomeForRetainedTransport() =
        withLaunchFixture { fixture ->
            val events = mutableListOf<String>()
            val process = ControlledTestProcess(
                events = events,
                waitResults = listOf(false, false, false),
                stdinCloseFailure =
                    IOException("stdin close request-password"),
                stdoutCloseFailure =
                    IOException("stdout close request-user"),
            )
            var retained: DovecotOperatorTransport? = null
            val factory = JvmDockerExecDovecotOperatorTransportFactory(
                profile = fixture.profile(),
                starter = DovecotOperatorProcessStarter {
                    events += "start"
                    process
                },
            )

            val registrationFailure = assertFailsWith<IOException> {
                factory.open { allocated ->
                    events += "register"
                    retained = allocated
                    throw IllegalStateException(
                        "registration request-password",
                    )
                }
            }
            val retainedTransport = checkNotNull(retained)

            assertEquals(
                "Dovecot operator process transport registration failed",
                registrationFailure.message,
            )
            assertEquals(null, registrationFailure.cause)
            assertTrue(registrationFailure.suppressed.isEmpty())
            assertEquals(
                listOf(
                    "start",
                    "child-stdin.acquire",
                    "child-stdout.acquire",
                    "register",
                    "child-stdin.close",
                    "child-stdout.close",
                    "destroy",
                    "wait:250:MILLISECONDS",
                    "destroyForcibly",
                    "wait:250:MILLISECONDS",
                ),
                events,
            )
            assertEquals(1, process.childStdin.closeCalls)
            assertEquals(1, process.childStdout.closeCalls)
            assertEquals(
                listOf(
                    250L to TimeUnit.MILLISECONDS,
                    250L to TimeUnit.MILLISECONDS,
                ),
                process.timedWaits,
            )
            assertEquals(1, process.destroyCalls)
            assertEquals(1, process.destroyForciblyCalls)
            assertFalse(process.reaped)
            assertFailsWith<IllegalStateException> {
                retainedTransport.input
            }
            assertFailsWith<IllegalStateException> {
                retainedTransport.outputStream
            }
            assertEquals(
                null,
                retainedTransport.terminalStreamReference("childStdin"),
            )
            assertEquals(
                null,
                retainedTransport.terminalStreamReference("childStdout"),
            )

            val lifecycleEvents = events.toList()
            repeat(2) {
                val closeFailure = assertFailsWith<IOException> {
                    retainedTransport.close()
                }
                assertEquals(
                    "Dovecot operator process transport close failed",
                    closeFailure.message,
                )
                assertEquals(null, closeFailure.cause)
                val abortFailure = assertFailsWith<IOException> {
                    retainedTransport.abort()
                }
                assertEquals(
                    "Dovecot operator process transport abort failed",
                    abortFailure.message,
                )
                assertEquals(null, abortFailure.cause)
            }

            assertEquals(lifecycleEvents, events)
            assertEquals(2, process.timedWaits.size)
            assertEquals(1, process.destroyCalls)
            assertEquals(1, process.destroyForciblyCalls)
            assertEquals(1, process.childStdin.closeCalls)
            assertEquals(1, process.childStdout.closeCalls)
        }

    @Test
    fun registrationCleanupCachesReapedStreamCloseFailureForRetainedTransport() =
        withLaunchFixture { fixture ->
            val events = mutableListOf<String>()
            val process = ControlledTestProcess(
                events = events,
                waitResults = listOf(true),
                stdinCloseFailure =
                    IOException("stdin close request-password"),
                stdoutCloseFailure =
                    IOException("stdout close request-user"),
            )
            var retained: DovecotOperatorTransport? = null
            val factory = JvmDockerExecDovecotOperatorTransportFactory(
                profile = fixture.profile(),
                starter = DovecotOperatorProcessStarter {
                    events += "start"
                    process
                },
            )

            val registrationFailure = assertFailsWith<IOException> {
                factory.open { allocated ->
                    events += "register"
                    retained = allocated
                    throw IllegalStateException(
                        "registration request-password",
                    )
                }
            }
            val retainedTransport = checkNotNull(retained)

            assertEquals(
                "Dovecot operator process transport registration failed",
                registrationFailure.message,
            )
            assertEquals(null, registrationFailure.cause)
            assertTrue(registrationFailure.suppressed.isEmpty())
            assertEquals(
                listOf(
                    "start",
                    "child-stdin.acquire",
                    "child-stdout.acquire",
                    "register",
                    "child-stdin.close",
                    "child-stdout.close",
                    "destroy",
                    "wait:250:MILLISECONDS",
                ),
                events,
            )
            assertTrue(process.reaped)
            assertEquals(1, process.childStdin.closeCalls)
            assertEquals(1, process.childStdout.closeCalls)
            assertFailsWith<IllegalStateException> {
                retainedTransport.input
            }
            assertFailsWith<IllegalStateException> {
                retainedTransport.outputStream
            }

            val lifecycleEvents = events.toList()
            repeat(2) {
                val closeFailure = assertFailsWith<IOException> {
                    retainedTransport.close()
                }
                assertEquals(
                    "Dovecot operator process transport close failed",
                    closeFailure.message,
                )
                assertEquals(null, closeFailure.cause)
                assertTrue(closeFailure.suppressed.isEmpty())

                val abortFailure = assertFailsWith<IOException> {
                    retainedTransport.abort()
                }
                assertEquals(
                    "Dovecot operator process transport abort failed",
                    abortFailure.message,
                )
                assertEquals(null, abortFailure.cause)
                assertTrue(abortFailure.suppressed.isEmpty())
            }

            assertEquals(lifecycleEvents, events)
            assertEquals(1, process.timedWaits.size)
            assertEquals(
                listOf(250L to TimeUnit.MILLISECONDS),
                process.timedWaits,
            )
            assertEquals(1, process.destroyCalls)
            assertEquals(0, process.destroyForciblyCalls)
            assertEquals(1, process.childStdin.closeCalls)
            assertEquals(1, process.childStdout.closeCalls)
        }

    @Test
    fun normalCloseContinuesAfterInterruptedDestroyWaitAndRestoresFlag() =
        withLaunchFixture { fixture ->
            val events = mutableListOf<String>()
            val process = ControlledTestProcess(
                events = events,
                waitResults = listOf(false, true),
                waitFailures = mapOf(
                    2 to InterruptedException(
                        "destroy wait request-password",
                    ),
                ),
                configuredExitCode = 137,
            )
            val transport = JvmDockerExecDovecotOperatorTransportFactory(
                profile = fixture.profile(),
                starter = DovecotOperatorProcessStarter { process },
            ).open {}
            events.clear()

            try {
                val failure = assertFailsWith<IOException> {
                    transport.close()
                }
                val interruptRestored =
                    Thread.currentThread().isInterrupted
                Thread.interrupted()

                assertTrue(interruptRestored)
                assertEquals(
                    "Dovecot operator process transport close failed",
                    failure.message,
                )
                assertEquals(null, failure.cause)
                assertTrue(failure.suppressed.isEmpty())
                assertEquals(
                    listOf(
                        "child-stdin.close",
                        "wait:500:MILLISECONDS",
                        "child-stdout.close",
                        "destroy",
                        "wait:250:MILLISECONDS",
                        "destroyForcibly",
                        "wait:250:MILLISECONDS",
                    ),
                    events,
                )
                assertEquals(
                    listOf(
                        500L to TimeUnit.MILLISECONDS,
                        250L to TimeUnit.MILLISECONDS,
                        250L to TimeUnit.MILLISECONDS,
                    ),
                    process.timedWaits,
                )
                assertEquals(1, process.destroyCalls)
                assertEquals(1, process.destroyForciblyCalls)
                assertTrue(process.reaped)
            } finally {
                Thread.interrupted()
            }
        }

    @Test
    fun registrationCleanupRestoresInterruptFromFinalReapAttempt() =
        withLaunchFixture { fixture ->
            val events = mutableListOf<String>()
            val process = ControlledTestProcess(
                events = events,
                waitResults = listOf(false, false),
                waitFailures = mapOf(
                    3 to InterruptedException(
                        "final reap request-password",
                    ),
                ),
            )
            val factory = JvmDockerExecDovecotOperatorTransportFactory(
                profile = fixture.profile(),
                starter = DovecotOperatorProcessStarter {
                    events += "start"
                    process
                },
            )

            try {
                val failure = assertFailsWith<IOException> {
                    factory.open {
                        events += "register"
                        throw IllegalStateException(
                            "registration request-user",
                        )
                    }
                }
                val interruptRestored =
                    Thread.currentThread().isInterrupted
                Thread.interrupted()

                assertTrue(interruptRestored)
                assertEquals(
                    "Dovecot operator process transport registration failed",
                    failure.message,
                )
                assertEquals(null, failure.cause)
                assertTrue(failure.suppressed.isEmpty())
                assertEquals(
                    listOf(
                        "start",
                        "child-stdin.acquire",
                        "child-stdout.acquire",
                        "register",
                        "child-stdin.close",
                        "wait:500:MILLISECONDS",
                        "child-stdout.close",
                        "destroy",
                        "wait:250:MILLISECONDS",
                        "destroyForcibly",
                        "wait:250:MILLISECONDS",
                    ),
                    events,
                )
                assertEquals(
                    listOf(
                        500L to TimeUnit.MILLISECONDS,
                        250L to TimeUnit.MILLISECONDS,
                        250L to TimeUnit.MILLISECONDS,
                    ),
                    process.timedWaits,
                )
                assertEquals(1, process.destroyCalls)
                assertEquals(1, process.destroyForciblyCalls)
                assertFalse(process.reaped)
            } finally {
                Thread.interrupted()
            }
        }

    @Test
    fun launchProfileRetainsCanonicalPathsInOrderAndFixesOperatorIdentity() =
        withLaunchFixture { fixture ->
            val suppliedComposeFiles =
                mutableListOf(fixture.compose, fixture.composeOverride)

            val profile = fixture.profile(
                composeFiles = suppliedComposeFiles,
            )
            suppliedComposeFiles.clear()

            assertEquals(fixture.docker, profile.dockerCli)
            assertEquals(fixture.repository, profile.repositoryRoot)
            assertEquals(
                listOf(fixture.compose, fixture.composeOverride),
                profile.composeFiles,
            )
            assertEquals("mail-sandbox-test_1", profile.projectName)
            assertEquals(
                "unix:///var/run/docker.sock",
                profile.dockerHost,
            )
            assertEquals("dovecot-operator", profile.service)
            assertEquals("dovecot-operator", profile.composeProfile)
            assertFailsWith<UnsupportedOperationException> {
                (profile.composeFiles as MutableList<Path>).clear()
            }
        }

    @Test
    fun launchProfileRejectsEveryNonCanonicalOrNonExecutableDockerPath() =
        withLaunchFixture { fixture ->
            val nonExecutable = Files.createFile(
                fixture.workspace.resolve("docker-not-executable"),
            ).toRealPath()
            check(nonExecutable.toFile().setExecutable(false, false))
            val nested = Files.createDirectory(
                fixture.workspace.resolve("docker-path-segment"),
            )
            val nonCanonical =
                nested.resolve("..").resolve(fixture.docker.fileName)
            val symbolicLink =
                fixture.workspace.resolve("docker-symbolic-link")
            Files.createSymbolicLink(symbolicLink, fixture.docker)

            listOf(
                Path.of("docker"),
                fixture.workspace.resolve("missing-docker"),
                fixture.repository,
                nonExecutable,
                nonCanonical,
                symbolicLink,
            ).forEach { invalidDocker ->
                assertFailsWith<IllegalArgumentException>(
                    "Docker path should be rejected: $invalidDocker",
                ) {
                    fixture.profile(dockerCli = invalidDocker)
                }
            }
        }

    @Test
    fun launchProfileRejectsEveryNonCanonicalOrSymbolicRepositoryRoot() =
        withLaunchFixture { fixture ->
            val nested = Files.createDirectory(
                fixture.repository.resolve("root-path-segment"),
            )
            val nonCanonical = nested.resolve("..")
            val symbolicLink =
                fixture.workspace.resolve("repository-symbolic-link")
            Files.createSymbolicLink(symbolicLink, fixture.repository)

            listOf(
                Path.of("repository"),
                fixture.workspace.resolve("missing-repository"),
                fixture.compose,
                nonCanonical,
                symbolicLink,
            ).forEach { invalidRepository ->
                assertFailsWith<IllegalArgumentException>(
                    "Repository root should be rejected: $invalidRepository",
                ) {
                    DovecotOperatorLaunchProfile(
                        dockerCli = fixture.docker,
                        repositoryRoot = invalidRepository,
                        composeFiles = listOf(fixture.compose),
                        projectName = "mail-sandbox-test_1",
                    )
                }
            }
        }

    @Test
    fun launchProfileRejectsImplicitOrUntrustedComposeFiles() =
        withLaunchFixture { fixture ->
            val composeDirectory =
                Files.createDirectory(fixture.repository.resolve("compose-dir"))
            val nested =
                Files.createDirectory(
                    fixture.repository.resolve("compose-path-segment"),
                )
            val nonCanonical =
                nested.resolve("..").resolve(fixture.compose.fileName)
            val symbolicLink =
                fixture.repository.resolve("compose-symbolic-link.yml")
            Files.createSymbolicLink(symbolicLink, fixture.compose)
            val outside =
                Files.createFile(fixture.workspace.resolve("outside-compose.yml"))
                    .toRealPath()

            val invalidLists = listOf(
                emptyList(),
                listOf(Path.of("compose.yml")),
                listOf(fixture.repository.resolve("missing-compose.yml")),
                listOf(composeDirectory),
                listOf(nonCanonical),
                listOf(symbolicLink),
                listOf(outside),
            )

            invalidLists.forEach { invalidComposeFiles ->
                assertFailsWith<IllegalArgumentException>(
                    "Compose files should be rejected: $invalidComposeFiles",
                ) {
                    fixture.profile(composeFiles = invalidComposeFiles)
                }
            }
        }

    @Test
    fun launchProfileAcceptsOnlyStrictComposeProjectNames() =
        withLaunchFixture { fixture ->
            listOf(
                "a",
                "0",
                "mail-sandbox",
                "mail_sandbox_1",
                "9project-",
            ).forEach { validProject ->
                assertEquals(
                    validProject,
                    fixture.profile(projectName = validProject).projectName,
                )
            }

            listOf(
                "",
                "-project",
                "_project",
                "Project",
                "project.name",
                "project name",
                "project/name",
                "project\nname",
            ).forEach { invalidProject ->
                assertFailsWith<IllegalArgumentException>(
                    "Project should be rejected: $invalidProject",
                ) {
                    fixture.profile(projectName = invalidProject)
                }
            }
        }

    @Test
    fun argvIsTheExactFixedNonShellDockerComposeExecList() =
        withLaunchFixture { fixture ->
            val profile = fixture.profile(
                composeFiles = listOf(
                    fixture.compose,
                    fixture.composeOverride,
                ),
            )

            assertEquals(expectedArgv(fixture), profile.argv)
            assertEquals(2, profile.argv.count { it == "-f" })
            assertEquals(1, profile.argv.count { it == "--project-directory" })
            assertEquals(1, profile.argv.count { it == "--project-name" })
            assertEquals(1, profile.argv.count { it == "--profile" })
            assertFailsWith<UnsupportedOperationException> {
                (profile.argv as MutableList<String>).clear()
            }

            val shellTokens = setOf(
                "sh",
                "bash",
                "zsh",
                "/bin/sh",
                "/bin/bash",
                "/bin/zsh",
                "-c",
            )
            assertTrue(profile.argv.none(shellTokens::contains))
            assertTrue(
                profile.argv.none { argument ->
                    "`" in argument ||
                        "$(" in argument ||
                        "\${" in argument
                },
            )
            listOf(
                "request-user",
                "dev@local.test",
                "request-password",
                "operator.example.test",
                "2993",
                "/usr/bin/curl",
                "--request-flag",
            ).forEach { untrustedValue ->
                assertFalse(
                    profile.argv.any { untrustedValue in it },
                    "argv contains untrusted value $untrustedValue",
                )
            }
        }

    @Test
    fun sanitizedEnvironmentDiscardsEveryInheritedEntryAndFixesRouting() =
        withLaunchFixture { fixture ->
            val profile = fixture.profile()
            val inherited = linkedMapOf(
                "HOME" to "/hostile/home",
                "PATH" to "/hostile/bin",
                "XDG_CONFIG_HOME" to "/hostile/xdg",
                "COMPOSE_FILE" to "hostile-compose.yml",
                "COMPOSE_PROJECT_NAME" to "hostile-project",
                "COMPOSE_PROFILES" to "hostile-profile",
                "COMPOSE_DISABLE_ENV_FILE" to "0",
                "DOCKER_HOST" to "tcp://hostile.example.test:2375",
                "DOCKER_CONTEXT" to "hostile-context",
                "DOCKER_CONFIG" to "/hostile/config",
                "DOCKER_CLI_PLUGIN_EXTRA_DIRS" to "/hostile/plugins",
                "DOCKER_TLS_VERIFY" to "1",
                "DOVECOT_USER" to "request-user",
                "DOVECOT_PASSWORD" to "request-password",
                "LD_PRELOAD" to "/hostile/lib.so",
                "DYLD_INSERT_LIBRARIES" to "/hostile/lib.dylib",
                "JAVA_TOOL_OPTIONS" to "-javaagent:/hostile/agent.jar",
                "UNRELATED_SECRET" to "must-not-cross-boundary",
            )

            val sanitized = profile.sanitizedEnvironment(inherited)
            inherited.clear()

            assertEquals(
                mapOf(
                    "COMPOSE_DISABLE_ENV_FILE" to "1",
                    "DOCKER_HOST" to "unix:///var/run/docker.sock",
                ),
                sanitized,
            )
            assertEquals(
                setOf("COMPOSE_DISABLE_ENV_FILE"),
                sanitized.keys.filter { it.startsWith("COMPOSE_") }.toSet(),
            )
            assertEquals(
                setOf("DOCKER_HOST"),
                sanitized.keys.filter { it.startsWith("DOCKER_") }.toSet(),
            )
            assertTrue(
                sanitized.keys.none { it.startsWith("DOVECOT_") },
            )
            assertFailsWith<UnsupportedOperationException> {
                (sanitized as MutableMap<String, String>).clear()
            }
        }

    @Test
    fun jvmStarterConfiguresOneExactProcessBuilderWithoutExecutingDocker() =
        withLaunchFixture { fixture ->
            val profile = fixture.profile(
                composeFiles = listOf(
                    fixture.compose,
                    fixture.composeOverride,
                ),
            )
            val inherited = linkedMapOf(
                "HOME" to "/hostile/home",
                "PATH" to "/hostile/bin",
                "XDG_CONFIG_HOME" to "/hostile/xdg",
                "COMPOSE_FILE" to "hostile-compose.yml",
                "DOCKER_HOST" to "tcp://hostile.example.test:2375",
                "DOCKER_CONFIG" to "/hostile/config",
                "DOCKER_CLI_PLUGIN_EXTRA_DIRS" to "/hostile/plugins",
                "DOVECOT_PASSWORD" to "request-password",
                "LD_PRELOAD" to "/hostile/lib.so",
                "DYLD_INSERT_LIBRARIES" to "/hostile/lib.dylib",
                "JAVA_TOOL_OPTIONS" to "-javaagent:/hostile/agent.jar",
                "UNRELATED_SECRET" to "must-not-cross-boundary",
            )
            val expectedProcess = UnstartedTestProcess()
            var launches = 0
            lateinit var capturedBuilder: ProcessBuilder
            val starter: DovecotOperatorProcessStarter =
                JvmDovecotOperatorProcessStarter(
                    inheritedEnvironment = { inherited },
                    builderLauncher = { builder ->
                        launches += 1
                        capturedBuilder = builder
                        expectedProcess
                    },
                )

            val actualProcess = starter.start(profile)

            assertSame(expectedProcess, actualProcess)
            assertEquals(1, launches)
            assertEquals(expectedArgv(fixture), capturedBuilder.command())
            assertEquals(
                fixture.repository.toFile(),
                capturedBuilder.directory(),
            )
            assertEquals(
                ProcessBuilder.Redirect.DISCARD,
                capturedBuilder.redirectError(),
            )
            assertEquals(
                ProcessBuilder.Redirect.PIPE,
                capturedBuilder.redirectInput(),
            )
            assertEquals(
                ProcessBuilder.Redirect.PIPE,
                capturedBuilder.redirectOutput(),
            )
            assertFalse(capturedBuilder.redirectErrorStream())
            assertEquals(
                mapOf(
                    "COMPOSE_DISABLE_ENV_FILE" to "1",
                    "DOCKER_HOST" to "unix:///var/run/docker.sock",
                ),
                capturedBuilder.environment(),
            )
        }

    private fun expectedArgv(fixture: LaunchFixture): List<String> =
        listOf(
            fixture.docker.toString(),
            "compose",
            "--project-directory",
            fixture.repository.toString(),
            "-f",
            fixture.compose.toString(),
            "-f",
            fixture.composeOverride.toString(),
            "--project-name",
            "mail-sandbox-test_1",
            "--profile",
            "dovecot-operator",
            "exec",
            "-T",
            "--index",
            "1",
            "dovecot-operator",
            "/usr/bin/openssl",
            "s_client",
            "-quiet",
            "-no_ign_eof",
            "-nocommands",
            "-4",
            "-min_protocol",
            "TLSv1.2",
            "-max_protocol",
            "TLSv1.3",
            "-verify_return_error",
            "-verify_hostname",
            "localhost",
            "-no-CApath",
            "-no-CAstore",
            "-CAfile",
            "/etc/dovecot/ssl/tls.crt",
            "-connect",
            "127.0.0.1:31993",
            "-servername",
            "localhost",
        )
}

private data class LaunchFixture(
    val workspace: Path,
    val repository: Path,
    val docker: Path,
    val compose: Path,
    val composeOverride: Path,
) {
    fun profile(
        dockerCli: Path = docker,
        repositoryRoot: Path = repository,
        composeFiles: List<Path> = listOf(compose),
        projectName: String = "mail-sandbox-test_1",
    ): DovecotOperatorLaunchProfile =
        DovecotOperatorLaunchProfile(
            dockerCli = dockerCli,
            repositoryRoot = repositoryRoot,
            composeFiles = composeFiles,
            projectName = projectName,
        )
}

private inline fun withLaunchFixture(
    block: (LaunchFixture) -> Unit,
) {
    val workspace =
        Files.createTempDirectory("dovecot-operator-launch").toRealPath()
    try {
        val repository =
            Files.createDirectory(workspace.resolve("repository")).toRealPath()
        val docker =
            Files.createFile(workspace.resolve("docker")).toRealPath()
        check(docker.toFile().setExecutable(true, true))
        val compose =
            Files.createFile(repository.resolve("docker-compose.yml"))
                .toRealPath()
        val composeOverride =
            Files.createFile(repository.resolve("compose.override.yml"))
                .toRealPath()
        block(
            LaunchFixture(
                workspace = workspace,
                repository = repository,
                docker = docker,
                compose = compose,
                composeOverride = composeOverride,
            ),
        )
    } finally {
        check(workspace.toFile().deleteRecursively())
    }
}

private class UnstartedTestProcess : Process() {
    override fun getOutputStream(): OutputStream = ByteArrayOutputStream()

    override fun getInputStream(): InputStream =
        ByteArrayInputStream(ByteArray(0))

    override fun getErrorStream(): InputStream =
        ByteArrayInputStream(ByteArray(0))

    override fun waitFor(): Int =
        error("The test process must never be awaited")

    override fun waitFor(
        timeout: Long,
        unit: TimeUnit,
    ): Boolean =
        error("The test process must never be awaited")

    override fun exitValue(): Int =
        error("The test process was not started")

    override fun destroy() =
        error("The test process must never be destroyed")
}

private class ControlledTestProcess(
    private val events: MutableList<String>,
    waitResults: List<Boolean>,
    private val configuredExitCode: Int = 0,
    private val firstWaitEntered: CountDownLatch? = null,
    private val releaseFirstWait: CountDownLatch? = null,
    private val honorCallerInterrupt: Boolean = false,
    private val waitFailures: Map<Int, Throwable> = emptyMap(),
    private val stdoutAcquisitionFailure: Throwable? = null,
    stdinOperationFailure: Throwable? = null,
    stdoutOperationFailure: Throwable? = null,
    stdinCloseFailure: Throwable? = null,
    stdoutCloseFailure: Throwable? = null,
    private val destroyFailure: Throwable? = null,
    private val destroyForciblyFailure: Throwable? = null,
    private val exitValueFailure: Throwable? = null,
    stdoutContents: ByteArray = ByteArray(0),
    stderrContents: ByteArray = ByteArray(0),
) : Process() {
    val childStdin =
        RecordingOutputStream(
            label = "child-stdin",
            events = events,
            operationFailure = stdinOperationFailure,
            closeFailure = stdinCloseFailure,
        )
    val childStdout =
        RecordingInputStream(
            label = "child-stdout",
            events = events,
            contents = stdoutContents,
            operationFailure = stdoutOperationFailure,
            closeFailure = stdoutCloseFailure,
        )
    private val childStderr =
        RecordingInputStream("child-stderr", events, stderrContents)
    private val remainingWaitResults = ArrayDeque(waitResults)

    var stdinRequests = 0
        private set
    var stdoutRequests = 0
        private set
    var stderrRequests = 0
        private set
    val timedWaits = mutableListOf<Pair<Long, TimeUnit>>()
    var destroyCalls = 0
        private set
    var destroyForciblyCalls = 0
        private set
    var reaped = false
        private set
    val childStderrReadCalls: Int
        get() = childStderr.readCalls

    private var exited = false

    override fun getOutputStream(): OutputStream {
        stdinRequests += 1
        events += "child-stdin.acquire"
        return childStdin
    }

    override fun getInputStream(): InputStream {
        stdoutRequests += 1
        events += "child-stdout.acquire"
        throwInjectedFailure(stdoutAcquisitionFailure)
        return childStdout
    }

    override fun getErrorStream(): InputStream {
        stderrRequests += 1
        events += "child-stderr.acquire"
        return childStderr
    }

    override fun waitFor(): Int =
        error("Unbounded process wait is forbidden")

    override fun waitFor(
        timeout: Long,
        unit: TimeUnit,
    ): Boolean {
        timedWaits += timeout to unit
        events += "wait:$timeout:${unit.name}"
        if (timedWaits.size == 1) {
            firstWaitEntered?.countDown()
            releaseFirstWait?.let { release ->
                check(
                    release.await(
                        TEST_SAFETY_TIMEOUT_SECONDS,
                        TimeUnit.SECONDS,
                    ),
                ) {
                    "Timed process wait was not released"
                }
            }
        }
        if (honorCallerInterrupt && Thread.interrupted()) {
            throw InterruptedException(
                "controlled process interruption request-password",
            )
        }
        throwInjectedFailure(waitFailures[timedWaits.size])
        val completed = remainingWaitResults.removeFirstOrNull()
            ?: error("Unexpected timed process wait")
        if (completed) {
            exited = true
            reaped = true
        }
        return completed
    }

    override fun exitValue(): Int {
        events += "exitValue"
        throwInjectedFailure(exitValueFailure)
        check(exited) {
            "The controlled process has not exited"
        }
        return configuredExitCode
    }

    override fun destroy() {
        destroyCalls += 1
        events += "destroy"
        throwInjectedFailure(destroyFailure)
    }

    override fun destroyForcibly(): Process {
        destroyForciblyCalls += 1
        events += "destroyForcibly"
        throwInjectedFailure(destroyForciblyFailure)
        return this
    }
}

private class RecordingInputStream(
    private val label: String,
    private val events: MutableList<String>,
    contents: ByteArray = ByteArray(0),
    private val operationFailure: Throwable? = null,
    private val closeFailure: Throwable? = null,
) : ByteArrayInputStream(contents) {
    var readCalls = 0
        private set
    var closeCalls = 0
        private set

    override fun read(): Int {
        readCalls += 1
        throwInjectedFailure(operationFailure)
        return super.read()
    }

    override fun read(
        bytes: ByteArray,
        offset: Int,
        length: Int,
    ): Int {
        readCalls += 1
        throwInjectedFailure(operationFailure)
        return super.read(bytes, offset, length)
    }

    override fun close() {
        closeCalls += 1
        events += "$label.close"
        throwInjectedFailure(closeFailure)
        super.close()
    }
}

private class BlockingPipeTestProcess(
    private val events: MutableList<String>,
) : Process() {
    private val writerRelease = CountDownLatch(1)
    val writerEntered = CountDownLatch(1)
    val destroyReached = CountDownLatch(1)
    private val childStdin =
        BlockingPipeOutputStream(
            events = events,
            writerEntered = writerEntered,
            writerRelease = writerRelease,
        )
    private val childStdout =
        RecordingInputStream("child-stdout", events)
    private val childStderr =
        RecordingInputStream("child-stderr", events)

    @Volatile
    private var destroyed = false

    @Volatile
    var reaped = false
        private set

    var destroyCalls = 0
        private set
    var destroyForciblyCalls = 0
        private set

    override fun getOutputStream(): OutputStream {
        events += "child-stdin.acquire"
        return childStdin
    }

    override fun getInputStream(): InputStream {
        events += "child-stdout.acquire"
        return childStdout
    }

    override fun getErrorStream(): InputStream {
        events += "child-stderr.acquire"
        return childStderr
    }

    override fun waitFor(): Int =
        error("Unbounded process wait is forbidden")

    override fun waitFor(
        timeout: Long,
        unit: TimeUnit,
    ): Boolean {
        events += "wait:$timeout:${unit.name}"
        if (destroyed) {
            reaped = true
            return true
        }
        return false
    }

    override fun exitValue(): Int {
        events += "exitValue"
        check(reaped) {
            "The blocking-pipe process was not reaped"
        }
        return 137
    }

    override fun destroy() {
        destroyCalls += 1
        events += "destroy"
        destroyed = true
        destroyReached.countDown()
        writerRelease.countDown()
    }

    override fun destroyForcibly(): Process {
        destroyForciblyCalls += 1
        events += "destroyForcibly"
        destroyed = true
        destroyReached.countDown()
        writerRelease.countDown()
        return this
    }

    fun releaseAll() {
        writerRelease.countDown()
    }
}

private class TwoPhaseAbortTestProcess(
    private val events: MutableList<String>,
) : Process() {
    private val releaseNaturalWait = CountDownLatch(1)
    private val releaseDestroy = CountDownLatch(1)
    val firstWaitEntered = CountDownLatch(1)
    val destroyEntered = CountDownLatch(1)
    val destroyEffectCompleted = CountDownLatch(1)
    val exitValueReached = CountDownLatch(1)
    val childStdin =
        RecordingOutputStream("child-stdin", events)
    val childStdout =
        RecordingInputStream("child-stdout", events)
    private val childStderr =
        RecordingInputStream("child-stderr", events)
    val timedWaits = mutableListOf<Pair<Long, TimeUnit>>()

    @Volatile
    var reaped = false
        private set

    val exitCode = 0
    var exitValueCalls = 0
        private set
    var destroyCalls = 0
        private set
    var destroyForciblyCalls = 0
        private set

    override fun getOutputStream(): OutputStream {
        events += "child-stdin.acquire"
        return childStdin
    }

    override fun getInputStream(): InputStream {
        events += "child-stdout.acquire"
        return childStdout
    }

    override fun getErrorStream(): InputStream {
        events += "child-stderr.acquire"
        return childStderr
    }

    override fun waitFor(): Int =
        error("Unbounded process wait is forbidden")

    override fun waitFor(
        timeout: Long,
        unit: TimeUnit,
    ): Boolean {
        timedWaits += timeout to unit
        events += "wait:$timeout:${unit.name}"
        firstWaitEntered.countDown()
        check(
            releaseNaturalWait.await(
                TEST_SAFETY_TIMEOUT_SECONDS,
                TimeUnit.SECONDS,
            ),
        ) {
            "Natural process wait was not released"
        }
        reaped = true
        events += "wait.complete"
        return true
    }

    override fun exitValue(): Int {
        exitValueCalls += 1
        events += "exitValue"
        check(reaped) {
            "The two-phase process was not reaped"
        }
        exitValueReached.countDown()
        return exitCode
    }

    override fun destroy() {
        destroyEntered.countDown()
        check(
            releaseDestroy.await(
                TEST_SAFETY_TIMEOUT_SECONDS,
                TimeUnit.SECONDS,
            ),
        ) {
            "Abort destroy was not released"
        }
        destroyCalls += 1
        events += "destroy"
        destroyEffectCompleted.countDown()
    }

    override fun destroyForcibly(): Process {
        destroyForciblyCalls += 1
        events += "destroyForcibly"
        return this
    }

    fun releaseNaturalWait() {
        releaseNaturalWait.countDown()
    }

    fun releaseDestroy() {
        releaseDestroy.countDown()
    }

    fun releaseAll() {
        releaseNaturalWait.countDown()
        releaseDestroy.countDown()
    }
}

private class AsyncDestroyBlockingPipeTestProcess(
    private val events: MutableList<String>,
    private val destroyFailure: Throwable?,
) : Process() {
    private val writerRelease = CountDownLatch(1)
    val writerEntered = CountDownLatch(1)
    val finalReapAttempted = CountDownLatch(1)
    val childStdin =
        BlockingPipeOutputStream(
            events = events,
            writerEntered = writerEntered,
            writerRelease = writerRelease,
        )
    val childStdout =
        RecordingInputStream("child-stdout", events)
    private val childStderr =
        RecordingInputStream("child-stderr", events)
    val timedWaits =
        Collections.synchronizedList(
            mutableListOf<Pair<Long, TimeUnit>>(),
        )

    @Volatile
    var reaped = false
        private set

    var destroyCalls = 0
        private set
    var destroyForciblyCalls = 0
        private set
    var exitValueCalls = 0
        private set

    override fun getOutputStream(): OutputStream {
        events += "child-stdin.acquire"
        return childStdin
    }

    override fun getInputStream(): InputStream {
        events += "child-stdout.acquire"
        return childStdout
    }

    override fun getErrorStream(): InputStream {
        events += "child-stderr.acquire"
        return childStderr
    }

    override fun waitFor(): Int =
        error("Unbounded process wait is forbidden")

    @Synchronized
    override fun waitFor(
        timeout: Long,
        unit: TimeUnit,
    ): Boolean {
        timedWaits += timeout to unit
        events += "wait:$timeout:${unit.name}"
        return when (timedWaits.size) {
            1 -> false
            2 -> {
                reaped = true
                finalReapAttempted.countDown()
                true
            }
            else -> error("Unexpected timed process wait")
        }
    }

    override fun exitValue(): Int {
        exitValueCalls += 1
        events += "exitValue"
        return 0
    }

    override fun destroy() {
        destroyCalls += 1
        events += "destroy"
        throwInjectedFailure(destroyFailure)
    }

    override fun destroyForcibly(): Process {
        destroyForciblyCalls += 1
        events += "destroyForcibly"
        return this
    }

    fun releaseWriter() {
        writerRelease.countDown()
    }
}

private enum class GuardedAdmissionWaitMode {
    NaturalZero,
    GatedUnreaped,
    GatedNaturalThenUnreapedAbort,
}

private class SealedAbortLifecycleTestProcess(
    private val events: MutableList<String>,
) : Process() {
    private val waitRelease = CountDownLatch(1)
    val waitEntered = CountDownLatch(1)
    val childStdin =
        RecordingOutputStream("child-stdin", events)
    val childStdout =
        RecordingInputStream("child-stdout", events)

    override fun getOutputStream(): OutputStream {
        events += "child-stdin.acquire"
        return childStdin
    }

    override fun getInputStream(): InputStream {
        events += "child-stdout.acquire"
        return childStdout
    }

    override fun getErrorStream(): InputStream =
        error("Child stderr must never be acquired")

    override fun waitFor(): Int =
        error("Unbounded process wait is forbidden")

    override fun waitFor(
        timeout: Long,
        unit: TimeUnit,
    ): Boolean {
        check(timeout == 250L && unit == TimeUnit.MILLISECONDS)
        events += "wait:$timeout:${unit.name}"
        waitEntered.countDown()
        check(
            waitRelease.await(
                TEST_SAFETY_TIMEOUT_SECONDS,
                TimeUnit.SECONDS,
            ),
        ) {
            "Abort wait was not released"
        }
        return true
    }

    override fun exitValue(): Int =
        error("Abort must not read the process exit code")

    override fun destroy() {
        events += "destroy"
    }

    override fun destroyForcibly(): Process =
        error("Reaped abort must not force the process")

    fun releaseWait() {
        waitRelease.countDown()
    }
}

private class GuardedAdmissionTestProcess(
    private val events: MutableList<String>,
    val childStdin: OutputStream,
    val childStdout: InputStream,
    private val waitMode: GuardedAdmissionWaitMode,
) : Process() {
    private val childStderr =
        RecordingInputStream("child-stderr", events)
    private val naturalWaitRelease = CountDownLatch(1)
    private val finalWaitRelease = CountDownLatch(1)
    private val waitStateLock = Any()
    private var abortWaitCalls = 0
    val firstProcessWaitEntered = CountDownLatch(1)
    val finalProcessWaitEntered = CountDownLatch(1)
    val timedWaits =
        Collections.synchronizedList(
            mutableListOf<Pair<Long, TimeUnit>>(),
        )

    @Volatile
    var reaped = false
        private set

    var destroyCalls = 0
        private set
    var destroyForciblyCalls = 0
        private set
    var exitValueCalls = 0
        private set

    override fun getOutputStream(): OutputStream {
        events += "child-stdin.acquire"
        return childStdin
    }

    override fun getInputStream(): InputStream {
        events += "child-stdout.acquire"
        return childStdout
    }

    override fun getErrorStream(): InputStream {
        events += "child-stderr.acquire"
        return childStderr
    }

    override fun waitFor(): Int =
        error("Unbounded process wait is forbidden")

    override fun waitFor(
        timeout: Long,
        unit: TimeUnit,
    ): Boolean {
        timedWaits += timeout to unit
        events += "wait:$timeout:${unit.name}"
        firstProcessWaitEntered.countDown()
        return when (timeout) {
            500L ->
                when (waitMode) {
                    GuardedAdmissionWaitMode.NaturalZero -> {
                        reaped = true
                        true
                    }
                    GuardedAdmissionWaitMode.GatedUnreaped ->
                        false
                    GuardedAdmissionWaitMode
                        .GatedNaturalThenUnreapedAbort -> {
                        check(
                            naturalWaitRelease.await(
                                TEST_SAFETY_TIMEOUT_SECONDS,
                                TimeUnit.SECONDS,
                            ),
                        ) {
                            "Natural process wait was not released"
                        }
                        reaped = true
                        true
                    }
                }
            250L -> {
                check(
                    waitMode !=
                        GuardedAdmissionWaitMode.NaturalZero,
                ) {
                    "Unexpected abort wait for natural process"
                }
                val waitCall = synchronized(waitStateLock) {
                    abortWaitCalls += 1
                    abortWaitCalls
                }
                if (waitCall == 1) {
                    false
                } else {
                    check(waitCall == 2) {
                        "Unexpected additional abort wait"
                    }
                    finalProcessWaitEntered.countDown()
                    check(
                        finalWaitRelease.await(
                            TEST_SAFETY_TIMEOUT_SECONDS,
                            TimeUnit.SECONDS,
                        ),
                    ) {
                        "Final abort wait was not released"
                    }
                    false
                }
            }
            else -> error("Unexpected process wait timeout")
        }
    }

    override fun exitValue(): Int {
        exitValueCalls += 1
        events += "exitValue"
        check(reaped) {
            "The guarded-admission process has not exited"
        }
        return 0
    }

    override fun destroy() {
        destroyCalls += 1
        events += "destroy"
    }

    override fun destroyForcibly(): Process {
        destroyForciblyCalls += 1
        events += "destroyForcibly"
        return this
    }

    fun releaseNaturalWait() {
        naturalWaitRelease.countDown()
    }

    fun releaseFinalWait() {
        finalWaitRelease.countDown()
    }

    fun releaseAll() {
        naturalWaitRelease.countDown()
        finalWaitRelease.countDown()
    }
}

private class AdmissionBlockingOutputStream(
    private val label: String,
    private val events: MutableList<String>,
) : OutputStream() {
    private val operationRelease = CountDownLatch(1)
    val operationEntered = CountDownLatch(1)
    val closeAttempted = CountDownLatch(1)

    @Volatile
    var closeAttempts = 0
        private set

    override fun write(value: Int) {
        synchronized(this) {
            events += "$label.write.enter"
            operationEntered.countDown()
            check(
                operationRelease.await(
                    TEST_SAFETY_TIMEOUT_SECONDS,
                    TimeUnit.SECONDS,
                ),
            ) {
                "Guarded output operation was not released"
            }
            events += "$label.write.exit"
        }
    }

    override fun close() {
        closeAttempts += 1
        closeAttempted.countDown()
        synchronized(this) {
            events += "$label.close"
        }
    }

    fun releaseOperation() {
        operationRelease.countDown()
    }
}

private class AdmissionBlockingInputStream(
    private val label: String,
    private val events: MutableList<String>,
) : InputStream() {
    private val operationRelease = CountDownLatch(1)
    val operationEntered = CountDownLatch(1)
    val closeAttempted = CountDownLatch(1)

    @Volatile
    var closeAttempts = 0
        private set

    override fun read(): Int =
        synchronized(this) {
            events += "$label.read.enter"
            operationEntered.countDown()
            check(
                operationRelease.await(
                    TEST_SAFETY_TIMEOUT_SECONDS,
                    TimeUnit.SECONDS,
                ),
            ) {
                "Guarded input operation was not released"
            }
            events += "$label.read.exit"
            65
        }

    override fun read(
        bytes: ByteArray,
        offset: Int,
        length: Int,
    ): Int {
        if (length == 0) return 0
        val value = read()
        if (value < 0) return value
        bytes[offset] = value.toByte()
        return 1
    }

    override fun close() {
        closeAttempts += 1
        closeAttempted.countDown()
        synchronized(this) {
            events += "$label.close"
        }
    }

    fun releaseOperation() {
        operationRelease.countDown()
    }
}

private class UnreapedAbortBlockingPipeTestProcess(
    private val events: MutableList<String>,
) : Process() {
    private val writerRelease = CountDownLatch(1)
    private val finalWaitRelease = CountDownLatch(1)
    val writerEntered = CountDownLatch(1)
    val finalWaitEntered = CountDownLatch(1)
    val childStdin =
        CloseAttemptBlockingPipeOutputStream(
            events = events,
            writerEntered = writerEntered,
            writerRelease = writerRelease,
        )
    val childStdout =
        RecordingInputStream("child-stdout", events)
    private val childStderr =
        RecordingInputStream("child-stderr", events)
    val timedWaits =
        Collections.synchronizedList(
            mutableListOf<Pair<Long, TimeUnit>>(),
        )

    @Volatile
    var reaped = false
        private set

    var destroyCalls = 0
        private set
    var destroyForciblyCalls = 0
        private set
    var exitValueCalls = 0
        private set

    override fun getOutputStream(): OutputStream {
        events += "child-stdin.acquire"
        return childStdin
    }

    override fun getInputStream(): InputStream {
        events += "child-stdout.acquire"
        return childStdout
    }

    override fun getErrorStream(): InputStream {
        events += "child-stderr.acquire"
        return childStderr
    }

    override fun waitFor(): Int =
        error("Unbounded process wait is forbidden")

    @Synchronized
    override fun waitFor(
        timeout: Long,
        unit: TimeUnit,
    ): Boolean {
        timedWaits += timeout to unit
        events += "wait:$timeout:${unit.name}"
        return when (timedWaits.size) {
            1 -> false
            2 -> {
                finalWaitEntered.countDown()
                check(
                    finalWaitRelease.await(
                        TEST_SAFETY_TIMEOUT_SECONDS,
                        TimeUnit.SECONDS,
                    ),
                ) {
                    "Final process wait was not released"
                }
                false
            }
            else -> error("Unexpected timed process wait")
        }
    }

    override fun exitValue(): Int {
        exitValueCalls += 1
        events += "exitValue"
        return 0
    }

    override fun destroy() {
        destroyCalls += 1
        events += "destroy"
    }

    override fun destroyForcibly(): Process {
        destroyForciblyCalls += 1
        events += "destroyForcibly"
        return this
    }

    fun releaseFinalWait() {
        finalWaitRelease.countDown()
    }

    fun releaseWriter() {
        writerRelease.countDown()
    }
}

private class CloseAttemptBlockingPipeOutputStream(
    private val events: MutableList<String>,
    private val writerEntered: CountDownLatch,
    private val writerRelease: CountDownLatch,
) : OutputStream() {
    val closeAttempted = CountDownLatch(1)

    @Volatile
    var closeAttempts = 0
        private set

    override fun write(value: Int) {
        synchronized(this) {
            events += "writer.enter"
            writerEntered.countDown()
            check(
                writerRelease.await(
                    TEST_SAFETY_TIMEOUT_SECONDS,
                    TimeUnit.SECONDS,
                ),
            ) {
                "Blocking pipe writer was not released"
            }
            events += "writer.exit"
        }
    }

    override fun close() {
        closeAttempts += 1
        closeAttempted.countDown()
        synchronized(this) {
            events += "child-stdin.close"
        }
    }
}

private class BlockingPipeOutputStream(
    private val events: MutableList<String>,
    private val writerEntered: CountDownLatch,
    private val writerRelease: CountDownLatch,
) : OutputStream() {
    var closeCalls = 0
        private set

    @Synchronized
    override fun write(value: Int) {
        events += "writer.enter"
        writerEntered.countDown()
        check(
            writerRelease.await(
                TEST_SAFETY_TIMEOUT_SECONDS,
                TimeUnit.SECONDS,
            ),
        ) {
            "Blocking pipe writer was not released"
        }
        events += "writer.exit"
    }

    @Synchronized
    override fun close() {
        closeCalls += 1
        events += "child-stdin.close"
    }
}

private fun processTransportSource(): Path {
    val workingDirectory =
        Path.of(System.getProperty("user.dir"))
            .toAbsolutePath()
            .normalize()
    val dashboardRoot = when (workingDirectory.fileName?.toString()) {
        "dashboard-server" -> workingDirectory.parent
        "debug-dashboard" -> workingDirectory
        else -> error("Unexpected Kotlin test working directory")
    }
    return dashboardRoot.resolve(
        "dashboard-server/src/mail/sandbox/dashboard/server/gate/dovecot/" +
            "DovecotOperatorProcessTransport.kt",
    )
}

private class RecordingOutputStream(
    private val label: String,
    private val events: MutableList<String>,
    private val operationFailure: Throwable? = null,
    private val closeFailure: Throwable? = null,
) : ByteArrayOutputStream() {
    var writeCalls = 0
        private set
    var flushCalls = 0
        private set
    var closeCalls = 0
        private set

    override fun write(value: Int) {
        writeCalls += 1
        throwInjectedFailure(operationFailure)
        super.write(value)
    }

    override fun write(
        bytes: ByteArray,
        offset: Int,
        length: Int,
    ) {
        writeCalls += 1
        throwInjectedFailure(operationFailure)
        super.write(bytes, offset, length)
    }

    override fun flush() {
        flushCalls += 1
        throwInjectedFailure(operationFailure)
        super.flush()
    }

    override fun close() {
        closeCalls += 1
        events += "$label.close"
        throwInjectedFailure(closeFailure)
        super.close()
    }
}

private enum class DirectInterruptionPoint {
    Starter,
    StreamMapping,
    Destroy,
    DestroyForcibly,
    ExitValue,
}

private fun throwDirectInterruptedException(operation: String): Nothing {
    Thread.currentThread().interrupt()
    check(Thread.interrupted()) {
        "Direct interruption was not established for $operation"
    }
    throw InterruptedException(
        "Dovecot process $operation interrupted request-password",
    )
}

private fun throwInjectedFailure(failure: Throwable?) {
    if (failure == null) return
    if (failure is InterruptedException) {
        Thread.currentThread().interrupt()
        check(Thread.interrupted()) {
            "Injected interruption was not established"
        }
    }
    throw failure
}

private fun Thread.awaitState(expected: Thread.State): Boolean {
    val deadline =
        System.nanoTime() +
            TimeUnit.SECONDS.toNanos(TEST_SAFETY_TIMEOUT_SECONDS)
    while (System.nanoTime() - deadline < 0L) {
        if (state == expected) return true
        Thread.yield()
    }
    return state == expected
}

private fun awaitEither(
    first: CountDownLatch,
    second: CountDownLatch,
): Boolean {
    val deadline =
        System.nanoTime() +
            TimeUnit.SECONDS.toNanos(TEST_SAFETY_TIMEOUT_SECONDS)
    while (System.nanoTime() - deadline < 0L) {
        if (first.count == 0L || second.count == 0L) {
            return true
        }
        Thread.yield()
    }
    return first.count == 0L || second.count == 0L
}

private fun awaitCallersOrCloseAttempt(
    closeFinished: CountDownLatch,
    abortFinished: CountDownLatch,
    closeAttempted: CountDownLatch,
): Boolean {
    val deadline =
        System.nanoTime() +
            TimeUnit.SECONDS.toNanos(TEST_SAFETY_TIMEOUT_SECONDS)
    while (System.nanoTime() - deadline < 0L) {
        if (
            closeAttempted.count == 0L ||
            (
                closeFinished.count == 0L &&
                    abortFinished.count == 0L
            )
        ) {
            return true
        }
        Thread.yield()
    }
    return closeAttempted.count == 0L ||
        (
            closeFinished.count == 0L &&
                abortFinished.count == 0L
        )
}

private fun DovecotOperatorTransport.terminalStreamReference(
    fieldName: String,
): Any? {
    val field = javaClass.getDeclaredField(fieldName)
    check(field.trySetAccessible()) {
        "Unable to inspect terminal stream reference"
    }
    return field.get(this)
}

private fun Any.privateFieldValue(fieldName: String): Any? {
    val field = javaClass.getDeclaredField(fieldName)
    check(field.trySetAccessible()) {
        "Unable to inspect private field"
    }
    return field.get(this)
}

private fun DovecotOperatorTransport.terminationOutcomeReference(): Any? {
    val field = javaClass.getDeclaredField("terminationOutcome")
    check(field.trySetAccessible()) {
        "Unable to inspect terminal outcome reference"
    }
    return field.get(this)
}

private const val TEST_SAFETY_TIMEOUT_SECONDS = 10L
private const val TEST_SAFETY_TIMEOUT_MILLIS = 10_000L
