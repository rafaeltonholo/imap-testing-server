package mail.sandbox.dashboard.server.gate.dovecot

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.nio.file.Files
import java.nio.file.Path
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

            assertEquals(1, starts)
            assertSame(transport, registered)
            assertSame(process.childStdout, transport.input)
            assertSame(process.childStdin, transport.outputStream)
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
                assertSame(process.childStdout, allocated.input)
                assertSame(process.childStdin, allocated.outputStream)
            }

            assertEquals(1, registrationCalls)
            assertSame(process.childStdout, transport.input)
            assertSame(process.childStdin, transport.outputStream)
            assertEquals(0, process.timedWaits.size)
            assertEquals(0, process.destroyCalls)
            assertEquals(0, process.destroyForciblyCalls)
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
                waitResults = listOf(false, false, true),
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
    fun abortFailsRedactedWhenForcedChildCannotBeReaped() =
        withLaunchFixture { fixture ->
            val process = ControlledTestProcess(
                events = mutableListOf(),
                waitResults = listOf(false, false, false),
            )
            val transport = JvmDockerExecDovecotOperatorTransportFactory(
                profile = fixture.profile(),
                starter = DovecotOperatorProcessStarter { process },
            ).open {}

            val failure = assertFailsWith<IOException> {
                transport.abort()
            }

            assertEquals(
                "Dovecot operator process transport abort failed",
                failure.message,
            )
            assertEquals(null, failure.cause)
            assertTrue(failure.suppressed.isEmpty())
            assertEquals(3, process.timedWaits.size)
            assertEquals(1, process.destroyCalls)
            assertEquals(1, process.destroyForciblyCalls)
            assertFalse(process.reaped)
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
    fun concurrentCloseAndAbortExecuteOneTerminationWithModeSpecificResults() =
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

            closeCaller.start()
            assertTrue(firstWaitEntered.await(1, TimeUnit.SECONDS))
            abortCaller.start()
            assertTrue(abortStarted.await(1, TimeUnit.SECONDS))
            releaseFirstWait.countDown()
            closeCaller.join(2_000)
            abortCaller.join(2_000)

            assertFalse(closeCaller.isAlive)
            assertFalse(abortCaller.isAlive)
            assertTrue(closeFailure.get() is IOException)
            assertEquals(null, abortFailure.get())
            assertEquals(1, process.childStdin.closeCalls)
            assertEquals(1, process.childStdout.closeCalls)
            assertEquals(3, process.timedWaits.size)
            assertEquals(1, process.destroyCalls)
            assertEquals(1, process.destroyForciblyCalls)
            assertTrue(process.reaped)
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
                waitResults = listOf(false, false, false),
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
            assertEquals(3, process.timedWaits.size)
            assertEquals(1, process.destroyCalls)
            assertEquals(1, process.destroyForciblyCalls)
        }

    @Test
    fun abortReapsBeforeRestoringCallerInterruptFlag() =
        withLaunchFixture { fixture ->
            val events = mutableListOf<String>()
            val process = ControlledTestProcess(
                events = events,
                waitResults = listOf(false, true),
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
    private val stdoutAcquisitionFailure: Throwable? = null,
    stderrContents: ByteArray = ByteArray(0),
) : Process() {
    val childStdin = RecordingOutputStream("child-stdin", events)
    val childStdout = RecordingInputStream("child-stdout", events)
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
        stdoutAcquisitionFailure?.let { throw it }
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
                check(release.await(1, TimeUnit.SECONDS)) {
                    "Timed process wait was not released"
                }
            }
        }
        if (honorCallerInterrupt && Thread.interrupted()) {
            throw InterruptedException(
                "controlled process interruption request-password",
            )
        }
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
        check(exited) {
            "The controlled process has not exited"
        }
        return configuredExitCode
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
}

private class RecordingInputStream(
    private val label: String,
    private val events: MutableList<String>,
    contents: ByteArray = ByteArray(0),
) : ByteArrayInputStream(contents) {
    var readCalls = 0
        private set
    var closeCalls = 0
        private set

    override fun read(): Int {
        readCalls += 1
        return super.read()
    }

    override fun read(
        bytes: ByteArray,
        offset: Int,
        length: Int,
    ): Int {
        readCalls += 1
        return super.read(bytes, offset, length)
    }

    override fun close() {
        closeCalls += 1
        events += "$label.close"
        super.close()
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
) : ByteArrayOutputStream() {
    var writeCalls = 0
        private set
    var closeCalls = 0
        private set

    override fun write(value: Int) {
        writeCalls += 1
        super.write(value)
    }

    override fun write(
        bytes: ByteArray,
        offset: Int,
        length: Int,
    ) {
        writeCalls += 1
        super.write(bytes, offset, length)
    }

    override fun close() {
        closeCalls += 1
        events += "$label.close"
        super.close()
    }
}
