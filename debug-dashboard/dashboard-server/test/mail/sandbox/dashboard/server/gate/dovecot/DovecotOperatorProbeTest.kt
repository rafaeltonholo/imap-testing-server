package mail.sandbox.dashboard.server.gate.dovecot

import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.nio.charset.StandardCharsets
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DovecotOperatorProbeTest {
    @Test
    fun fullMailboxReadModeSearchesAndFetchesAMessageIdLiteral() {
        val messageIdLiteral =
            "Message-ID: <task6-probe@local.test>\r\n\r\n"
        lateinit var retainingInput: RetainingBulkReadInputStream
        val response =
            (
                "* OK Dovecot ready\r\n" +
                    "+ VXNlcm5hbWU6\r\n" +
                    "+ UGFzc3dvcmQ6\r\n" +
                    "A001 OK Logged in\r\n" +
                    "* LIST (\\HasNoChildren) \".\" INBOX\r\n" +
                    "A002 OK List completed\r\n" +
                    "* 1 EXISTS\r\n" +
                    "A003 OK [READ-ONLY] Examine completed\r\n" +
                    "* SEARCH 7 9\r\n" +
                    "A004 OK Search completed\r\n" +
                    "* 1 FETCH (UID 7 " +
                    "BODY[HEADER.FIELDS (MESSAGE-ID)] " +
                    "{${messageIdLiteral.length}}\r\n" +
                    messageIdLiteral +
                    ")\r\n" +
                    "A005 OK Fetch completed\r\n"
                ).toByteArray(StandardCharsets.US_ASCII)
        assertTrue(
            response.toString(StandardCharsets.US_ASCII)
                .contains("* 1 EXISTS\r\n"),
            "A successful full-read transcript must declare a non-empty INBOX",
        )
        val fixture = probeFixture(
            response = response,
            secret = "read-probe-secret",
            requireMailboxRead = true,
            inputFactory = { response ->
                RetainingBulkReadInputStream(response).also {
                    retainingInput = it
                }
            },
        )

        assertEquals(
            DovecotOperatorProbeResult.Success,
            fixture.probe.probe(TARGET, fixture.credential),
        )
        assertEquals(
            "A005 UID FETCH 7 " +
                "(BODY.PEEK[HEADER.FIELDS (MESSAGE-ID)])\r\n",
            fixture.transport.output.snapshots.last()
                .toString(StandardCharsets.US_ASCII),
        )
        assertEquals(7, fixture.transport.output.snapshots.size)
        assertTrue(retainingInput.references.isNotEmpty())
        assertTrue(
            retainingInput.references.all { bytes ->
                bytes.all { it == 0.toByte() }
            },
        )
        assertClosedAndWiped(fixture, "read-probe-secret")
    }

    @Test
    fun fullMailboxReadModeRejectsAnEmptyOrMalformedSearchResult() {
        listOf(
            "* SEARCH\r\nA004 OK Search completed\r\n",
            "* SEARCH 0\r\nA004 OK Search completed\r\n",
            "* SEARCH 7 7\r\nA004 OK Search completed\r\n",
            "A004 OK Search completed\r\n",
        ).forEachIndexed { index, searchResponse ->
            val fixture = probeFixture(
                response = (
                    successfulReadPrefix() + searchResponse
                    ).toByteArray(StandardCharsets.US_ASCII),
                secret = "empty-search-secret-$index",
                requireMailboxRead = true,
            )

            assertEquals(
                DovecotOperatorProbeResult.ProtocolFailure,
                fixture.probe.probe(TARGET, fixture.credential),
            )
            assertEquals(
                "A004 UID SEARCH ALL\r\n",
                fixture.transport.output.snapshots.last()
                    .toString(StandardCharsets.US_ASCII),
            )
            assertClosedAndWiped(
                fixture,
                "empty-search-secret-$index",
            )
        }
    }

    @Test
    fun fullMailboxReadModeRejectsMissingMalformedAndOversizedFetches() {
        val validSearch =
            "* SEARCH 7\r\nA004 OK Search completed\r\n"
        val malformedLiteral =
            "Subject: not-a-message-id\r\n\r\n"
        val validLiteral =
            "Message-ID: <valid@local.test>\r\n\r\n"
        val malformedMessageIds = listOf(
            "Message-ID: <a..b@local.test>\r\n\r\n",
            "Message-ID: <a()@local.test>\r\n\r\n",
            "Message-ID: <.a@local.test>\r\n\r\n",
            "Message-ID: <a@local.test.>\r\n\r\n",
        )
        val fetchResponses = listOf(
            "A005 OK No fetch emitted\r\n",
            (
                "* 1 FETCH (UID 8 " +
                    "BODY[HEADER.FIELDS (MESSAGE-ID)] {42}\r\n"
                ),
            (
                "* 1 FETCH (UID 7 " +
                    "BODY[HEADER.FIELDS (MESSAGE-ID)] {1025}\r\n"
                ),
            (
                "* 0 FETCH (UID 7 " +
                    "BODY[HEADER.FIELDS (MESSAGE-ID)] " +
                    "{${validLiteral.length}}\r\n" +
                    validLiteral +
                    ")\r\n" +
                    "A005 OK Fetch completed\r\n"
                ),
            (
                "* 1 FETCH (UID 7 " +
                    "BODY[HEADER.FIELDS (MESSAGE-ID)] " +
                    "{${malformedLiteral.length}}\r\n" +
                    malformedLiteral +
                    ")\r\n" +
                    "A005 OK Fetch completed\r\n"
                ),
        ) + malformedMessageIds.map { literal ->
            (
                "* 1 FETCH (UID 7 " +
                    "BODY[HEADER.FIELDS (MESSAGE-ID)] " +
                    "{${literal.length}}\r\n" +
                    literal +
                    ")\r\n" +
                    "A005 OK Fetch completed\r\n"
                )
        }
        fetchResponses.forEachIndexed { index, fetchResponse ->
            val fixture = probeFixture(
                response = (
                    successfulReadPrefix() +
                        validSearch +
                        fetchResponse
                    ).toByteArray(StandardCharsets.US_ASCII),
                secret = "invalid-fetch-secret-$index",
                requireMailboxRead = true,
            )

            assertEquals(
                DovecotOperatorProbeResult.ProtocolFailure,
                fixture.probe.probe(TARGET, fixture.credential),
            )
            assertClosedAndWiped(
                fixture,
                "invalid-fetch-secret-$index",
            )
        }
    }

    @Test
    fun fullMailboxReadModeTreatsATruncatedLiteralAsTransportFailure() {
        val fixture = probeFixture(
            response = (
                successfulReadPrefix() +
                    "* SEARCH 7\r\n" +
                    "A004 OK Search completed\r\n" +
                    "* 1 FETCH (UID 7 " +
                    "BODY[HEADER.FIELDS (MESSAGE-ID)] {42}\r\n" +
                    "Message-ID: <truncated@local.test>"
                ).toByteArray(StandardCharsets.US_ASCII),
            secret = "truncated-fetch-secret",
            requireMailboxRead = true,
        )

        assertEquals(
            DovecotOperatorProbeResult.TransportFailure,
            fixture.probe.probe(TARGET, fixture.credential),
        )
        assertClosedAndWiped(fixture, "truncated-fetch-secret")
    }

    @Test
    fun fragmentedAuthenticateLoginChallengesUseOnlyTheCombinedUsernameForm() {
        val canary = "ProbeSecret-._~012345"
        val fixture = probeFixture(
            response = (
                "* OK Dovecot ready\r\n" +
                    "+ VXNlcm5hbWU6\r\n" +
                    "+ UGFzc3dvcmQ6\r\n" +
                    "A001 OK Logged in\r\n" +
                    "* LIST (\\HasNoChildren) \".\" INBOX\r\n" +
                    "A002 OK List completed\r\n"
                ).toByteArray(),
            secret = canary,
            inputFactory = ::OneByteAtATimeInputStream,
        )
        fixture.transport.beforeAbort = {
            assertTrue(
                fixture.secretBytes.all { byte -> byte == 0.toByte() },
                "credential must be wiped before transport abort",
            )
        }

        val result = fixture.probe.probe(TARGET, fixture.credential)

        assertEquals(DovecotOperatorProbeResult.Success, result)
        assertEquals(
            "A001 AUTHENTICATE LOGIN\r\n",
            fixture.transport.output.snapshots[0].toString(StandardCharsets.US_ASCII),
        )
        assertEquals(
            "cHJvYmUtdGFyZ2V0QGxvY2FsLnRlc3QqZGFzaGJvYXJkLW9wZXJhdG9yLWE=\r\n",
            fixture.transport.output.snapshots[1].toString(StandardCharsets.US_ASCII),
        )
        assertEquals(
            "UHJvYmVTZWNyZXQtLl9+MDEyMzQ1\r\n",
            fixture.transport.output.snapshots[2].toString(StandardCharsets.US_ASCII),
        )
        assertEquals(
            "A002 LIST \"\" \"INBOX\"\r\n",
            fixture.transport.output.snapshots[3].toString(StandardCharsets.US_ASCII),
        )
        assertEquals(4, fixture.transport.output.snapshots.size)
        assertClosedAndWiped(fixture, canary)
    }

    @Test
    fun authenticateLoginRequiresExactChallengesAndNeverFallsBackToPlain() {
        listOf(
            (
                "* OK ready\r\n" +
                    "+ UGFzc3dvcmQ6\r\n"
                ) to 1,
            (
                "* OK ready\r\n" +
                    "+ VXNlcm5hbWU6\r\n" +
                    "+ bm90LXRoZS1wYXNzd29yZC1wcm9tcHQ=\r\n"
                ) to 2,
        ).forEachIndexed { index, (response, expectedWrites) ->
            val fixture = probeFixture(
                response = response.toByteArray(),
                secret = "challenge-sequence-secret-$index",
            )

            assertEquals(
                DovecotOperatorProbeResult.ProtocolFailure,
                fixture.probe.probe(TARGET, fixture.credential),
            )
            assertEquals(expectedWrites, fixture.transport.output.snapshots.size)
            assertTrue(
                fixture.transport.output.snapshots.none { command ->
                    command.toString(StandardCharsets.US_ASCII)
                        .contains("AUTHENTICATE PLAIN")
                },
            )
            assertClosedAndWiped(
                fixture,
                "challenge-sequence-secret-$index",
            )
        }
    }

    @Test
    fun authenticateLoginNoIsAuthenticationFailureAndBadIsProtocolFailure() {
        listOf(
            "A001 NO Authentication failed\r\n" to
                DovecotOperatorProbeResult.AuthenticationFailure,
            "A001 BAD Invalid command\r\n" to
                DovecotOperatorProbeResult.ProtocolFailure,
        ).forEach { (completion, expected) ->
            val canary = "Canary-${expected.name}"
            val fixture = probeFixture(
                response = (
                    "* OK ready\r\n" +
                        "+ VXNlcm5hbWU6\r\n" +
                        "+ UGFzc3dvcmQ6\r\n" +
                        completion
                    ).toByteArray(),
                secret = canary,
            )

            val result = fixture.probe.probe(TARGET, fixture.credential)

            assertEquals(expected, result)
            assertFalse(result.toString().contains(canary))
            assertClosedAndWiped(fixture, canary)
        }
    }

    @Test
    fun listNoAndBadAreProtocolFailuresWhileTruncationIsTransportFailure() {
        listOf(
            "* OK ready\r\n" +
                "+ VXNlcm5hbWU6\r\n" +
                "+ UGFzc3dvcmQ6\r\n" +
                "A001 OK login\r\n" +
                "A002 NO list denied\r\n",
            "* OK ready\r\n" +
                "+ VXNlcm5hbWU6\r\n" +
                "+ UGFzc3dvcmQ6\r\n" +
                "A001 OK login\r\n" +
                "A002 BAD malformed\r\n",
        ).forEachIndexed { index, response ->
            val canary = "MissingCompletionCanary$index"
            val fixture = probeFixture(
                response = response.toByteArray(),
                secret = canary,
            )

            assertEquals(
                DovecotOperatorProbeResult.ProtocolFailure,
                fixture.probe.probe(TARGET, fixture.credential),
            )
            assertClosedAndWiped(fixture, canary)
        }
    }

    @Test
    fun oversizedLinesAreProtocolFailuresAndTruncationIsTransportFailure() {
        val oversizedCanary = "OversizedTranscriptCanary"
        val oversized = ByteArray(16 * 1024 + 3) { 'x'.code.toByte() }.also { bytes ->
            bytes[bytes.lastIndex - 1] = '\r'.code.toByte()
            bytes[bytes.lastIndex] = '\n'.code.toByte()
        }
        val oversizedFixture = probeFixture(
            response = oversized,
            secret = oversizedCanary,
        )
        val oversizedResult = oversizedFixture.probe.probe(
            TARGET,
            oversizedFixture.credential,
        )
        assertEquals(
            DovecotOperatorProbeResult.ProtocolFailure,
            oversizedResult,
        )
        assertFalse(oversizedResult.toString().contains(oversizedCanary))
        assertClosedAndWiped(oversizedFixture, oversizedCanary)

        val unterminatedCanary = "UnterminatedTranscriptCanary"
        val unterminated = probeFixture(
            response = "* OK unterminated transcript canary".toByteArray(),
            secret = unterminatedCanary,
        )
        assertEquals(
            DovecotOperatorProbeResult.TransportFailure,
            unterminated.probe.probe(TARGET, unterminated.credential),
        )
        assertClosedAndWiped(unterminated, unterminatedCanary)

        val truncated = probeFixture(
            response = (
                "* OK ready\r\n" +
                    "+ VXNlcm5hbWU6\r\n" +
                    "+ UGFzc3dvcmQ6\r\n" +
                    "A001 OK login\r\n" +
                    "* LIST () \".\" INBOX\r\n"
                ).toByteArray(),
            secret = "truncated-response-secret",
        )
        assertEquals(
            DovecotOperatorProbeResult.TransportFailure,
            truncated.probe.probe(TARGET, truncated.credential),
        )
        assertClosedAndWiped(truncated, "truncated-response-secret")
        oversized.fill(0)
    }

    @Test
    fun taggedListOkWithoutAnInboxListingIsProtocolFailure() {
        val fixture = probeFixture(
            response = (
                "* OK ready\r\n" +
                    "+ VXNlcm5hbWU6\r\n" +
                    "+ UGFzc3dvcmQ6\r\n" +
                    "A001 OK login\r\n" +
                    "A002 OK no listing emitted\r\n"
                ).toByteArray(),
            secret = "missing-inbox-list-secret",
        )

        assertEquals(
            DovecotOperatorProbeResult.ProtocolFailure,
            fixture.probe.probe(TARGET, fixture.credential),
        )
        assertClosedAndWiped(fixture, "missing-inbox-list-secret")
    }

    @Test
    fun totalDeadlineAndTransportErrorsAreTypedTransportFailures() {
        val deadlineFixture = probeFixture(
            response = (
                "* OK ready\r\n" +
                    "+ VXNlcm5hbWU6\r\n" +
                    "+ UGFzc3dvcmQ6\r\n" +
                    "A001 OK login\r\n" +
                    "A002 OK list\r\n"
                ).toByteArray(),
            secret = "deadline-secret",
            clock = DovecotOperatorProbeClock {
                DEADLINE_CLOCK.addAndGet(1_000_000_000L)
            },
        )
        assertEquals(
            DovecotOperatorProbeResult.TransportFailure,
            deadlineFixture.probe.probe(TARGET, deadlineFixture.credential),
        )
        assertClosedAndWiped(deadlineFixture, "deadline-secret")

        val transportSecretBytes = "transport-secret".toByteArray()
        val transportCredential = DovecotOperatorCredential(
            DovecotOperatorId.A,
            DovecotOperatorSecret.takeOwnership(transportSecretBytes),
        )
        val transportResult = DovecotOperatorProbe(
            transportFactory = DovecotOperatorTransportFactory { _ ->
                throw IOException("server-transcript-canary")
            },
        ).probe(TARGET, transportCredential)
        assertEquals(DovecotOperatorProbeResult.TransportFailure, transportResult)
        assertFalse(transportResult.toString().contains("server-transcript-canary"))
        assertTrue(transportSecretBytes.all { it == 0.toByte() })

        val clockSecretBytes = "clock-secret".toByteArray()
        val clockCredential = DovecotOperatorCredential(
            DovecotOperatorId.A,
            DovecotOperatorSecret.takeOwnership(clockSecretBytes),
        )
        assertEquals(
            DovecotOperatorProbeResult.TransportFailure,
            DovecotOperatorProbe(
                transportFactory = DovecotOperatorTransportFactory { _ ->
                    error("transport must not open after clock failure")
                },
                clock = DovecotOperatorProbeClock {
                    error("clock-failure-canary")
                },
            ).probe(TARGET, clockCredential),
        )
        assertTrue(clockSecretBytes.all { it == 0.toByte() })
    }

    @Test
    fun responseLineCountIsBoundedAndTransportAlwaysCloses() {
        val response = buildString {
            append("* OK ready\r\n")
            append("+ VXNlcm5hbWU6\r\n")
            append("+ UGFzc3dvcmQ6\r\n")
            append("A001 OK login\r\n")
            repeat(65) { append("* CAPABILITY IMAP4rev1\r\n") }
        }.toByteArray()
        val fixture = probeFixture(response = response, secret = "line-bound-secret")

        assertEquals(
            DovecotOperatorProbeResult.ProtocolFailure,
            fixture.probe.probe(TARGET, fixture.credential),
        )
        assertClosedAndWiped(fixture, "line-bound-secret")
        response.fill(0)
    }

    @Test
    fun targetTypeRejectsNoncanonicalAndProtectedTargetsBeforeTransport() {
        listOf(
            "Probe@Target.test",
            " target@local.test",
            "dashboard-operator-a@local.test",
            "dashboard-management+tag@local.test",
        ).forEach { invalid ->
            assertFailsWith<IllegalArgumentException> {
                DovecotOperatorTarget.create(invalid)
            }
        }
    }

    @Test
    fun watchdogAbortsABlockedWriteAndCleanupNeverWritesLogout() {
        val writeStarted = CountDownLatch(1)
        val releaseWrite = CountDownLatch(1)
        val retained = mutableListOf<ByteArray>()
        val transport = object : DovecotOperatorTransport {
            @Volatile
            var closed = false

            override val input: InputStream =
                ByteArrayInputStream("* OK ready\r\n".toByteArray())
            override val outputStream: OutputStream = object : OutputStream() {
                override fun write(value: Int) {
                    error("probe must use bounded command arrays")
                }

                override fun write(
                    bytes: ByteArray,
                    offset: Int,
                    length: Int,
                ) {
                    retained += bytes
                    writeStarted.countDown()
                    check(releaseWrite.await(2, TimeUnit.SECONDS))
                    throw IOException("aborted")
                }
            }

            override fun abort() {
                closed = true
                releaseWrite.countDown()
            }

            override fun close() {
                check(closed) { "probe must force abort before close" }
            }
        }
        val credentialBytes = "blocked-write-secret".toByteArray()
        val credential = DovecotOperatorCredential(
            DovecotOperatorId.A,
            DovecotOperatorSecret.takeOwnership(credentialBytes),
        )
        val probe = DovecotOperatorProbe(
            transportFactory = DovecotOperatorTransportFactory { register ->
                register(transport)
                transport
            },
            watchdog = DovecotOperatorProbeWatchdog { onDeadline ->
                val thread = Thread(
                    {
                        check(writeStarted.await(2, TimeUnit.SECONDS))
                        onDeadline()
                    },
                    "test-probe-watchdog",
                ).also {
                    it.isDaemon = true
                    it.start()
                }
                AutoCloseable {
                    thread.join(2_000)
                }
            },
        )

        assertEquals(
            DovecotOperatorProbeResult.TransportFailure,
            probe.probe(TARGET, credential),
        )
        assertTrue(transport.closed)
        assertTrue(credentialBytes.all { it == 0.toByte() })
        assertTrue(retained.isNotEmpty())
        assertTrue(retained.all { bytes -> bytes.all { it == 0.toByte() } })
    }

    @Test
    fun watchdogCancelsBlockedOpenAndLateTransportSelfAborts() {
        val openStarted = CountDownLatch(1)
        val transport = RecordingTransport(
            ByteArrayInputStream("* OK ready\r\n".toByteArray()),
        )
        val credentialBytes = "blocked-open-secret".toByteArray()
        val credential = DovecotOperatorCredential(
            DovecotOperatorId.A,
            DovecotOperatorSecret.takeOwnership(credentialBytes),
        )
        val probe = DovecotOperatorProbe(
            transportFactory = DovecotOperatorTransportFactory { register ->
                register(transport)
                openStarted.countDown()
                try {
                    CountDownLatch(1).await(10, TimeUnit.SECONDS)
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                }
                transport
            },
            watchdog = DovecotOperatorProbeWatchdog { onDeadline ->
                val thread = Thread(
                    {
                        check(openStarted.await(2, TimeUnit.SECONDS))
                        onDeadline()
                    },
                    "test-open-watchdog",
                ).also {
                    it.isDaemon = true
                    it.start()
                }
                AutoCloseable {
                    thread.join(2_000)
                }
            },
        )

        assertEquals(
            DovecotOperatorProbeResult.TransportFailure,
            probe.probe(TARGET, credential),
        )
        val abortDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2)
        while (!transport.closed && System.nanoTime() < abortDeadline) {
            Thread.sleep(10)
        }
        assertTrue(transport.closed)
        assertTrue(credentialBytes.all { it == 0.toByte() })
        assertTrue(transport.output.snapshots.isEmpty())
    }

    @Test
    fun callerInterruptionCancelsBlockedOpenAndRestoresInterruptStatus() {
        val openStarted = CountDownLatch(1)
        val transport = RecordingTransport(
            ByteArrayInputStream("* OK ready\r\n".toByteArray()),
        )
        val credentialBytes = "interrupted-open-secret".toByteArray()
        val credential = DovecotOperatorCredential(
            DovecotOperatorId.A,
            DovecotOperatorSecret.takeOwnership(credentialBytes),
        )
        val probe = DovecotOperatorProbe(
            transportFactory = DovecotOperatorTransportFactory { register ->
                openStarted.countDown()
                try {
                    CountDownLatch(1).await(10, TimeUnit.SECONDS)
                } catch (_: InterruptedException) {
                    // Simulate an allocation that completes after cancellation.
                }
                register(transport)
                transport
            },
        )
        val result = AtomicReference<DovecotOperatorProbeResult>()
        val interruptRestored = AtomicBoolean()
        val caller = Thread(
            {
                result.set(probe.probe(TARGET, credential))
                interruptRestored.set(Thread.currentThread().isInterrupted)
            },
            "test-interrupted-probe-caller",
        )

        caller.start()
        assertTrue(openStarted.await(2, TimeUnit.SECONDS))
        caller.interrupt()
        caller.join(2_000)

        assertFalse(caller.isAlive)
        assertEquals(DovecotOperatorProbeResult.TransportFailure, result.get())
        assertTrue(interruptRestored.get())
        val abortDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2)
        while (!transport.closed && System.nanoTime() < abortDeadline) {
            Thread.sleep(10)
        }
        assertTrue(transport.closed)
        assertTrue(credentialBytes.all { it == 0.toByte() })
        assertTrue(transport.output.snapshots.isEmpty())
    }

    private fun probeFixture(
        response: ByteArray,
        secret: String,
        inputFactory: (ByteArray) -> InputStream = ::ByteArrayInputStream,
        clock: DovecotOperatorProbeClock = DovecotOperatorProbeClock(System::nanoTime),
        requireMailboxRead: Boolean = false,
    ): ProbeFixture {
        val transport = RecordingTransport(inputFactory(response))
        val secretBytes = secret.toByteArray(StandardCharsets.US_ASCII)
        val credential = DovecotOperatorCredential(
            DovecotOperatorId.A,
            DovecotOperatorSecret.takeOwnership(secretBytes),
        )
        return ProbeFixture(
            probe = DovecotOperatorProbe(
                transportFactory = DovecotOperatorTransportFactory { register ->
                    register(transport)
                    transport
                },
                clock = clock,
                requireMailboxRead = requireMailboxRead,
            ),
            transport = transport,
            credential = credential,
            secretBytes = secretBytes,
        )
    }

    private fun assertClosedAndWiped(
        fixture: ProbeFixture,
        canary: String,
    ) {
        assertTrue(fixture.transport.closed)
        assertTrue(fixture.secretBytes.all { it == 0.toByte() })
        assertTrue(
            fixture.transport.output.references.all { bytes ->
                bytes.all { it == 0.toByte() }
            },
        )
        fixture.transport.output.snapshots.forEach { snapshot ->
            snapshot.fill(0)
        }
        assertFalse(fixture.transport.toString().contains(canary))
    }

    private class OneByteAtATimeInputStream(
        bytes: ByteArray,
    ) : ByteArrayInputStream(bytes) {
        override fun read(
            target: ByteArray,
            offset: Int,
            length: Int,
        ): Int = super.read(target, offset, minOf(length, 1))
    }

    private class RetainingBulkReadInputStream(
        bytes: ByteArray,
    ) : ByteArrayInputStream(bytes) {
        val references = mutableListOf<ByteArray>()

        override fun read(
            target: ByteArray,
            offset: Int,
            length: Int,
        ): Int {
            references += target
            return super.read(target, offset, length)
        }
    }

    private class RecordingTransport(
        override val input: InputStream,
    ) : DovecotOperatorTransport {
        val output = RecordingOutputStream()

        @Volatile
        var closed = false
            private set
        var beforeAbort: () -> Unit = {}

        override val outputStream: OutputStream
            get() = output

        override fun abort() {
            beforeAbort()
            close()
        }

        override fun close() {
            if (closed) return
            closed = true
            input.close()
            output.close()
        }

        override fun toString(): String = "RecordingTransport(redacted)"
    }

    private class RecordingOutputStream : OutputStream() {
        val references = mutableListOf<ByteArray>()
        val snapshots = mutableListOf<ByteArray>()
        var beforeWrite: () -> Unit = {}

        override fun write(value: Int) {
            error("probe must write bounded command arrays directly")
        }

        override fun write(
            bytes: ByteArray,
            offset: Int,
            length: Int,
        ) {
            beforeWrite()
            assertEquals(0, offset)
            assertEquals(bytes.size, length)
            references += bytes
            snapshots += bytes.copyOf()
        }
    }

    private data class ProbeFixture(
        val probe: DovecotOperatorProbe,
        val transport: RecordingTransport,
        val credential: DovecotOperatorCredential,
        val secretBytes: ByteArray,
    )

    companion object {
        private val TARGET = DovecotOperatorTarget.create("probe-target@local.test")
        private val DEADLINE_CLOCK = AtomicLong()

        private fun successfulReadPrefix(): String =
            "* OK Dovecot ready\r\n" +
                "+ VXNlcm5hbWU6\r\n" +
                "+ UGFzc3dvcmQ6\r\n" +
                "A001 OK Logged in\r\n" +
                "* LIST (\\HasNoChildren) \".\" INBOX\r\n" +
                "A002 OK List completed\r\n" +
                "* 1 EXISTS\r\n" +
                "A003 OK [READ-ONLY] Examine completed\r\n"
    }
}
